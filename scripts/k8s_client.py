"""Unified Kubernetes client utility supporting direct host kubectl and containerized cluster execution."""

from __future__ import annotations

import base64
import json
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib import error as urllib_error
from urllib import request

ROOT = Path(__file__).resolve().parents[1]
SERVER_CONTAINER = "k3d-kubesentinel-server-0"
HELM_IMAGE = "alpine/helm:4.3.0@sha256:a6cf54599ccb99d90cf0712b30f03fdb3cab062e6b94e0418cc4db7e8a1464b2"

_USE_CONTAINER_KUBECTL: bool | None = None


def is_native_kubectl_available() -> bool:
    """Check whether native host kubectl can communicate with the cluster."""
    global _USE_CONTAINER_KUBECTL
    if _USE_CONTAINER_KUBECTL is not None:
        return not _USE_CONTAINER_KUBECTL

    kubectl = shutil.which("kubectl")
    if not kubectl:
        _USE_CONTAINER_KUBECTL = True
        return False

    try:
        # Fast pre-flight check: query configured server endpoint and test socket connectivity
        cfg_res = subprocess.run(
            [kubectl, "config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}"],
            capture_output=True,
            text=True,
            timeout=1.5,
            check=False,
            cwd=ROOT,
        )
        server_endpoint = cfg_res.stdout.strip()
        if server_endpoint:
            from urllib.parse import urlparse
            parsed = urlparse(server_endpoint)
            host = parsed.hostname or "127.0.0.1"
            port = parsed.port or 6443
            # If firewall blocks port, socket connection fails fast (0.2s) instead of 20s hang
            with socket.create_connection((host, port), timeout=0.2):
                pass

        res = subprocess.run(
            [kubectl, "cluster-info", "--request-timeout=1s"],
            capture_output=True,
            text=True,
            timeout=1.5,
            check=False,
            cwd=ROOT,
        )
        if res.returncode == 0:
            _USE_CONTAINER_KUBECTL = False
            return True
    except (subprocess.SubprocessError, OSError, TimeoutError, ValueError):
        pass

    _USE_CONTAINER_KUBECTL = True
    return False


def run_kubectl(
    args: list[str],
    input_text: str | None = None,
    check: bool = False,
    timeout: float = 120.0,
) -> subprocess.CompletedProcess[str]:
    """Execute kubectl command with native host execution or instant containerized fallback."""
    if is_native_kubectl_available():
        kubectl = shutil.which("kubectl")
        res = subprocess.run(
            [kubectl] + args,  # type: ignore[operator]
            input=input_text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=timeout,
            cwd=ROOT,
        )
        if check and res.returncode != 0:
            raise RuntimeError(f"kubectl failed ({res.returncode}): {res.stderr}")
        return res

    # Fast direct container execution inside server-0
    exec_cmd = [
        "docker",
        "exec",
        "-i",
        "-e",
        "KUBECONFIG=/etc/rancher/k3s/k3s.yaml",
        SERVER_CONTAINER,
        "kubectl",
    ] + args
    res = subprocess.run(
        exec_cmd,
        input=input_text,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=timeout,
        cwd=ROOT,
    )
    if check and res.returncode != 0:
        raise RuntimeError(f"kubectl inside {SERVER_CONTAINER} failed ({res.returncode}): {res.stderr}")
    return res


def run_helm(
    args: list[str],
    input_text: str | None = None,
    check: bool = False,
    timeout: float = 120.0,
) -> subprocess.CompletedProcess[str]:
    """Execute Helm on the host or in a pinned helper beside the k3s server."""
    helm = shutil.which("helm")
    if helm and is_native_kubectl_available():
        res = subprocess.run(
            [helm] + args,
            input=input_text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=timeout,
            cwd=ROOT,
        )
        if check and res.returncode != 0:
            raise RuntimeError(f"helm failed ({res.returncode}): {res.stderr}")
        return res

    docker = shutil.which("docker")
    if not docker:
        raise RuntimeError("Helm requires either a reachable host kubeconfig or Docker helper fallback")

    with tempfile.TemporaryDirectory(prefix="kubesentinel-helm-") as temp_dir:
        kubeconfig = Path(temp_dir) / "k3s.yaml"
        copy_res = subprocess.run(
            [docker, "cp", f"{SERVER_CONTAINER}:/etc/rancher/k3s/k3s.yaml", str(kubeconfig)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=30.0,
            cwd=ROOT,
        )
        if copy_res.returncode != 0:
            message = f"Unable to copy the cluster kubeconfig for Helm: {copy_res.stderr}"
            if check:
                raise RuntimeError(message)
            return subprocess.CompletedProcess(copy_res.args, copy_res.returncode, copy_res.stdout, message)

        helper_cmd = [
            docker,
            "run",
            "--rm",
            "--network",
            f"container:{SERVER_CONTAINER}",
            "-i",
            "-e",
            "KUBECONFIG=/tmp/k3s.yaml",
            "-v",
            f"{kubeconfig}:/tmp/k3s.yaml:ro",
            HELM_IMAGE,
        ] + args
        res = subprocess.run(
            helper_cmd,
            input=input_text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=timeout,
            cwd=ROOT,
        )
        if check and res.returncode != 0:
            raise RuntimeError(f"Helm helper failed ({res.returncode}): {res.stderr}")
        return res


def apply_yaml(content: str) -> subprocess.CompletedProcess[str]:
    """Apply YAML content to the cluster via stdin."""
    return run_kubectl(["apply", "-f", "-"], input_text=content, check=True)


def apply_file(path: Path) -> subprocess.CompletedProcess[str]:
    """Apply a YAML manifest file to the cluster."""
    content = path.read_text(encoding="utf-8")
    return apply_yaml(content)


def get_json(args: list[str]) -> Any:
    """Run kubectl command with JSON output format and parse returned JSON."""
    res = run_kubectl(args + ["-o", "json"], check=True)
    return json.loads(res.stdout)


def send_http_to_edge_api(
    namespace: str,
    payload: dict[str, Any],
    local_port: int = 8000,
    timeout_sec: float = 10.0,
) -> tuple[int, dict[str, Any]]:
    """Send HTTP POST /events to edge-api in target namespace with container execution fallback."""
    body_str = json.dumps(payload)
    kubectl = shutil.which("kubectl")

    # Attempt 1: Port-forward via native host kubectl if native kubectl works
    if is_native_kubectl_available() and kubectl:
        pf_proc = subprocess.Popen(
            [kubectl, "port-forward", "-n", namespace, "svc/edge-api", f"{local_port}:8000"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            start = time.monotonic()
            connected = False
            while time.monotonic() - start < 3.0:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if s.connect_ex(("127.0.0.1", local_port)) == 0:
                        connected = True
                        break
                time.sleep(0.2)

            if connected:
                req = request.Request(
                    f"http://127.0.0.1:{local_port}/events",
                    data=body_str.encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with request.urlopen(req, timeout=timeout_sec) as resp:
                    resp_data = json.loads(resp.read().decode("utf-8"))
                    return resp.status, resp_data
        except (subprocess.SubprocessError, OSError, TimeoutError, urllib_error.URLError):
            pass
        finally:
            pf_proc.terminate()
            pf_proc.wait()

    # Attempt 2: Direct cluster execution inside edge-api pod via kubectl exec
    b64_payload = base64.b64encode(body_str.encode("utf-8")).decode("ascii")
    script = (
        "import sys, base64, urllib.request; "
        "data = base64.b64decode(sys.argv[1]); "
        "req = urllib.request.Request('http://127.0.0.1:8000/events', data=data, headers={'Content-Type': 'application/json'}); "
        "res = urllib.request.urlopen(req); "
        "print(res.status); "
        "print(res.read().decode('utf-8'))"
    )
    res = run_kubectl(
        [
            "exec",
            "-n",
            namespace,
            "deployment/edge-api",
            "--",
            "python",
            "-c",
            script,
            b64_payload,
        ],
        check=True,
        timeout=timeout_sec,
    )
    lines = res.stdout.strip().splitlines()
    status_code = int(lines[0].strip())
    resp_data = json.loads(lines[1].strip())
    return status_code, resp_data
