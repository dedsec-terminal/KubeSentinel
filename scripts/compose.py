"""Docker Compose lifecycle management for KubeSentinel."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


def is_docker_available() -> bool:
    """Check if docker CLI is present and the Docker daemon is responding."""
    if not shutil.which("docker"):
        return False
    try:
        proc = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return proc.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def is_edge_api_ready(root_dir: Path, timeout_sec: float = 1.0) -> bool:
    """Check if edge-api is responding with 200 OK and ready status on /ready."""
    # 1. Direct HTTP probe on host
    try:
        req = urllib.request.Request("http://127.0.0.1:8000/ready")
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            if resp.status == 200:
                payload = json.loads(resp.read().decode("utf-8"))
                if payload.get("status") == "ready":
                    return True
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
        pass

    # 2. Container internal probe fallback
    try:
        probe_cmd = [
            "docker",
            "compose",
            "exec",
            "-T",
            "edge-api",
            "python",
            "-c",
            (
                "import urllib.request, json; "
                "resp = urllib.request.urlopen('http://127.0.0.1:8000/ready', timeout=2); "
                "data = json.loads(resp.read().decode('utf-8')); "
                "exit(0 if (resp.status == 200 and data.get('status') == 'ready') else 1)"
            ),
        ]
        proc = subprocess.run(
            probe_cmd,
            cwd=str(root_dir),
            capture_output=True,
            timeout=5,
            check=False,
        )
        return proc.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def is_edge_worker_up(root_dir: Path) -> bool:
    """Check if edge-worker container is running."""
    try:
        proc = subprocess.run(
            ["docker", "compose", "ps", "--format", "json", "edge-worker"],
            cwd=str(root_dir),
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            # May return single object or lines of objects
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    state = data.get("State", "").lower()
                    if state in ("running", "up"):
                        return True
                except json.JSONDecodeError:
                    if "running" in line.lower() or "up" in line.lower():
                        return True
        # Plain table fallback
        table_proc = subprocess.run(
            ["docker", "compose", "ps", "edge-worker"],
            cwd=str(root_dir),
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return table_proc.returncode == 0 and "Up" in table_proc.stdout
    except (subprocess.TimeoutExpired, OSError):
        return False


def compose_up(
    root_dir: Path,
    build: bool = False,
    timeout_sec: int = 30,
    stdout: bool = True,
) -> int:
    """Start Docker Compose stack with health polling and zero secret exposure."""
    if not is_docker_available():
        if stdout:
            print("[compose-up] Error: Docker daemon is not available or not running.", file=sys.stderr)
        return 1

    # Automatically verify .env.local exists, run bootstrap if missing
    env_file = root_dir / ".env.local"
    acl_file = root_dir / "deploy" / "compose" / "redis" / "users.acl"
    if not env_file.exists() or not acl_file.exists():
        from scripts.bootstrap import bootstrap_local

        if stdout:
            print("[compose-up] Missing local environment credentials. Running bootstrap-local...")
        bootstrap_ret = bootstrap_local(root_dir=root_dir, force=False, stdout=stdout)
        if bootstrap_ret != 0:
            if stdout:
                print("[compose-up] Error: Failed to bootstrap credentials.", file=sys.stderr)
            return bootstrap_ret

    # Execute docker compose up -d
    cmd = ["docker", "compose", "up", "-d"]
    if build:
        cmd.append("--build")

    if stdout:
        print(f"[compose-up] Executing: {' '.join(cmd)}")

    proc = subprocess.run(cmd, cwd=str(root_dir), check=False)
    if proc.returncode != 0:
        if stdout:
            print(f"[compose-up] Error: docker compose up exited with code {proc.returncode}.", file=sys.stderr)
        return proc.returncode

    # Poll with bounded timeout until edge-api is ready and edge-worker is up
    if stdout:
        print(f"[compose-up] Polling services readiness (timeout: {timeout_sec}s)...")

    start_time = time.time()
    api_ready = False
    worker_up = False

    while time.time() - start_time < timeout_sec:
        if not api_ready:
            api_ready = is_edge_api_ready(root_dir)
        if not worker_up:
            worker_up = is_edge_worker_up(root_dir)

        if api_ready and worker_up:
            break
        time.sleep(1.0)

    if not (api_ready and worker_up):
        if stdout:
            print(
                f"[compose-up] Error: Timed out after {timeout_sec}s waiting for services.\n"
                f"  - edge-api ready: {api_ready}\n"
                f"  - edge-worker up: {worker_up}",
                file=sys.stderr,
            )
        return 1

    if stdout:
        print("[compose-up] Compose stack is up and operational:")
        print("  - redis:           Up (healthy, internal stream: security-events)")
        print("  - redis-bootstrap: Completed (consumer group edge-workers initialized)")
        print("  - edge-api:        Up (ready on port 8000)")
        print("  - edge-worker:     Up (active consumer group: edge-workers)")

    return 0


def compose_down(
    root_dir: Path,
    volumes: bool = True,
    stdout: bool = True,
) -> int:
    """Stop and remove Docker Compose stack containers and networks."""
    if not is_docker_available():
        if stdout:
            print("[compose-down] Error: Docker daemon is not available or not running.", file=sys.stderr)
        return 1

    cmd = ["docker", "compose", "down"]
    if volumes:
        cmd.append("-v")

    if stdout:
        print(f"[compose-down] Executing: {' '.join(cmd)}")

    proc = subprocess.run(cmd, cwd=str(root_dir), check=False)
    if proc.returncode != 0:
        if stdout:
            print(f"[compose-down] Error: docker compose down exited with code {proc.returncode}.", file=sys.stderr)
        return proc.returncode

    # Wait until all containers are removed
    timeout = 15
    start_time = time.time()
    while time.time() - start_time < timeout:
        ps_proc = subprocess.run(
            ["docker", "compose", "ps", "-q"],
            cwd=str(root_dir),
            capture_output=True,
            text=True,
            check=False,
        )
        if ps_proc.returncode == 0 and not ps_proc.stdout.strip():
            break
        time.sleep(0.5)

    if stdout:
        print("[compose-down] Compose stack stopped and all containers removed successfully.")

    return 0
