"""Deterministic end-to-end smoke verification for KubeSentinel Milestone B."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from scripts.compose import compose_up, is_docker_available, is_edge_api_ready, is_edge_worker_up


def get_bootstrap_password(root_dir: Path) -> str:
    """Retrieve bootstrap password from .env.local."""
    env_file = root_dir / ".env.local"
    if not env_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {env_file}")
    text = env_file.read_text(encoding="utf-8")
    match = re.search(r"REDIS_BOOTSTRAP_PASSWORD=(\S+)", text)
    if not match:
        raise ValueError("REDIS_BOOTSTRAP_PASSWORD missing from .env.local")
    return match.group(1)


def send_smoke_event(root_dir: Path, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    """Send HTTP POST to http://127.0.0.1:8000/events with payload and return status code + JSON response."""
    endpoint = "http://127.0.0.1:8000/events"
    body_bytes = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}

    # 1. Try host direct HTTP POST
    try:
        req = urllib.request.Request(endpoint, data=body_bytes, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return resp.status, data
    except (urllib.error.URLError, TimeoutError, OSError):
        pass

    # 2. Container internal HTTP client fallback
    exec_cmd = [
        "docker",
        "compose",
        "exec",
        "-T",
        "edge-api",
        "python",
        "-c",
        (
            "import sys, urllib.request, json; "
            "req = urllib.request.Request('http://127.0.0.1:8000/events', data=sys.stdin.read().encode('utf-8'), headers={'Content-Type': 'application/json'}); "
            "res = urllib.request.urlopen(req); "
            "print(res.status); "
            "print(res.read().decode('utf-8'))"
        ),
    ]
    proc = subprocess.run(
        exec_cmd,
        input=json.dumps(payload),
        cwd=str(root_dir),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        raise RuntimeError(f"Failed to send event via container exec: {proc.stderr}")

    parts = proc.stdout.strip().split("\n", 1)
    status_code = int(parts[0].strip())
    resp_data = json.loads(parts[1].strip())
    return status_code, resp_data


def poll_worker_log(
    root_dir: Path,
    stream_id: str,
    event_id: str,
    timeout_sec: int = 15,
) -> dict[str, Any] | None:
    """Poll edge-worker container logs for matching structured JSON record."""
    start_time = time.time()
    while time.time() - start_time < timeout_sec:
        proc = subprocess.run(
            ["docker", "compose", "logs", "edge-worker"],
            cwd=str(root_dir),
            capture_output=True,
            text=True,
            check=False,
        )
        for raw_line in proc.stdout.splitlines():
            line = raw_line.strip()
            if " | " in line:
                line = line.partition(" | ")[2].strip()
            if not line.startswith("{") or not line.endswith("}"):
                continue
            try:
                record = json.loads(line)
                if (
                    record.get("log_type") == "security_event_processed"
                    and record.get("processing_status") == "success"
                    and str(record.get("redis_stream_id")) == stream_id
                    and str(record.get("event_id")) == event_id
                ):
                    return record
            except json.JSONDecodeError:
                continue
        time.sleep(0.5)

    return None


def verify_redis_xack(root_dir: Path, stream: str, stream_id: str) -> tuple[bool, int, str]:
    """Inspect Redis Pending Entries List (PEL) for group edge-workers to confirm entry is cleared."""
    bootstrap_pw = get_bootstrap_password(root_dir)

    # 1. Query XPENDING summary
    pel_proc = subprocess.run(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "redis",
            "redis-cli",
            "--no-auth-warning",
            "--user",
            "bootstrap",
            "-a",
            bootstrap_pw,
            "XPENDING",
            stream,
            "edge-workers",
        ],
        cwd=str(root_dir),
        capture_output=True,
        text=True,
        check=False,
    )
    if pel_proc.returncode != 0:
        return False, -1, f"XPENDING query failed: {pel_proc.stderr.strip()}"

    pending_count = 0
    lines = [line.strip() for line in pel_proc.stdout.splitlines() if line.strip()]
    if lines:
        match = re.search(r"(\d+)", lines[0])
        if match:
            pending_count = int(match.group(1))

    # 2. Query XINFO GROUPS
    info_proc = subprocess.run(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "redis",
            "redis-cli",
            "--no-auth-warning",
            "--user",
            "bootstrap",
            "-a",
            bootstrap_pw,
            "XINFO",
            "GROUPS",
            stream,
        ],
        cwd=str(root_dir),
        capture_output=True,
        text=True,
        check=False,
    )
    if info_proc.returncode == 0:
        info_lines = [line.strip() for line in info_proc.stdout.splitlines() if line.strip()]
        if "pending" in info_lines:
            idx = info_lines.index("pending")
            if idx + 1 < len(info_lines) and info_lines[idx + 1].isdigit():
                pending_count = int(info_lines[idx + 1])

    # 3. Check specific stream_id in PEL range
    range_proc = subprocess.run(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "redis",
            "redis-cli",
            "--no-auth-warning",
            "--user",
            "bootstrap",
            "-a",
            bootstrap_pw,
            "XPENDING",
            stream,
            "edge-workers",
            stream_id,
            stream_id,
            "1",
        ],
        cwd=str(root_dir),
        capture_output=True,
        text=True,
        check=False,
    )
    if range_proc.returncode == 0 and stream_id in range_proc.stdout:
        return False, pending_count, f"Stream ID {stream_id} remains in pending entries list"

    return pending_count == 0, pending_count, ""


def run_smoke(
    root_dir: Path,
    timeout_sec: int = 30,
    stdout: bool = True,
) -> int:
    """Execute deterministic Milestone B smoke test end-to-end."""
    if not is_docker_available():
        if stdout:
            print("[smoke] Error: Docker daemon is not available or not running.", file=sys.stderr)
        return 1

    # Step 1: Verify stack is ready or run compose-up
    if not (is_edge_api_ready(root_dir) and is_edge_worker_up(root_dir)):
        if stdout:
            print("[smoke] Stack is not currently ready. Bringing up Compose stack...")
        up_code = compose_up(root_dir=root_dir, build=False, timeout_sec=timeout_sec, stdout=stdout)
        if up_code != 0:
            if stdout:
                print("[smoke] Error: Failed to bring up stack for smoke test.", file=sys.stderr)
            return up_code
    else:
        if stdout:
            print("[smoke] Stack readiness verified (edge-api ready, edge-worker running).")

    # Step 2: Unique event payload
    test_uuid = str(uuid.uuid4())
    payload = {
        "event_type": "smoke_verification",
        "severity": "info",
        "source": "kubesentinel-smoke-cli",
        "message": f"Milestone B deterministic smoke test {test_uuid}",
    }

    # Step 3: Send HTTP POST to http://127.0.0.1:8000/events
    if stdout:
        print("[smoke] Sending HTTP POST to http://127.0.0.1:8000/events...")
    try:
        http_status, correlation = send_smoke_event(root_dir, payload)
    except (urllib.error.URLError, TimeoutError, OSError, RuntimeError, json.JSONDecodeError) as exc:
        if stdout:
            print(f"[smoke] Error during HTTP POST: {exc}", file=sys.stderr)
        return 1

    if http_status != 202:
        if stdout:
            print(f"[smoke] Error: Expected HTTP 202 Accepted, got HTTP {http_status}: {correlation}", file=sys.stderr)
        return 1

    event_id = correlation.get("event_id")
    stream = correlation.get("stream")
    stream_id = correlation.get("stream_id")

    if not event_id or not stream or not stream_id:
        if stdout:
            print(f"[smoke] Error: Incomplete correlation response: {correlation}", file=sys.stderr)
        return 1

    if stdout:
        print(f"[smoke] Received HTTP 202 Accepted -> event_id={event_id}, stream={stream}, stream_id={stream_id}")

    # Step 4: Poll edge-worker container logs
    if stdout:
        print(f"[smoke] Polling edge-worker container logs for stream_id={stream_id}...")

    worker_log = poll_worker_log(root_dir, stream_id=stream_id, event_id=event_id, timeout_sec=15)
    if worker_log is None:
        if stdout:
            print(
                f"[smoke] Error: Timeout waiting for edge-worker log matching stream_id={stream_id}, event_id={event_id}.",
                file=sys.stderr,
            )
        return 1

    if stdout:
        print(f"[smoke] Worker structured JSON log verified (status: {worker_log.get('processing_status')}).")

    # Step 5: Verify XACK was executed (PEL cleared)
    if stdout:
        print("[smoke] Inspecting Redis PEL for consumer group edge-workers...")

    pel_cleared, pending_count, pel_err = verify_redis_xack(root_dir, stream=stream, stream_id=stream_id)
    if not pel_cleared:
        if stdout:
            print(
                f"[smoke] Error: Redis XACK verification failed. Pending entries: {pending_count}. Detail: {pel_err}",
                file=sys.stderr,
            )
        return 1

    if stdout:
        print(f"[smoke] Redis XACK verified: {pending_count} pending entries in PEL.")

    # Step 6: Output clean summary of the verified trace
    if stdout:
        print("\n" + "=" * 70)
        print("KubeSentinel Milestone B Smoke Verification -- Trace Summary")
        print("=" * 70)
        print(f"[1] HTTP POST Ingest:       HTTP 202 Accepted -> event_id={event_id}")
        print(f"[2] Redis Streams Delivery:  Stream={stream}, stream_id={stream_id}")
        print(f"[3] Worker JSON Log:        Worker={worker_log.get('worker')}, status={worker_log.get('processing_status')}")
        print(f"    Message:                {worker_log.get('message')}")
        print("[4] Redis XACK Verified:    0 pending entries (PEL cleared)")
        print("=" * 70)
        print("Milestone B deterministic end-to-end smoke verification PASSED.\n")

    return 0
