"""Lifecycle management for local single-node k3d cluster scoped to kubesentinel."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

CLUSTER_NAME = "kubesentinel"
PINNED_K3S_IMAGE = "rancher/k3s:v1.35.5-k3s1"
ROOT = Path(__file__).resolve().parents[1]


def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    print(f"--> {' '.join(cmd)}")
    res = subprocess.run(cmd, capture_output=True, text=True, check=False, cwd=ROOT)
    if res.stdout:
        print(res.stdout.strip())
    if res.stderr and res.returncode != 0:
        print(f"ERROR: {res.stderr.strip()}", file=sys.stderr)
    if check and res.returncode != 0:
        raise RuntimeError(f"Command failed ({res.returncode}): {' '.join(cmd)}")
    return res


def cluster_exists(name: str = CLUSTER_NAME) -> bool:
    """Check if k3d cluster with given name exists."""
    k3d = shutil.which("k3d")
    if not k3d:
        return False
    res = subprocess.run([k3d, "cluster", "list", "-o", "json"], capture_output=True, text=True, check=False)
    if res.returncode != 0:
        return False
    try:
        clusters = json.loads(res.stdout)
        if isinstance(clusters, list):
            return any(c.get("name") == name for c in clusters)
    except json.JSONDecodeError:
        pass
    # Fallback to text check
    res_text = subprocess.run([k3d, "cluster", "list"], capture_output=True, text=True, check=False)
    return name in res_text.stdout


def cluster_create(
    name: str = CLUSTER_NAME,
    image: str = PINNED_K3S_IMAGE,
    import_images: bool = True,
) -> int:
    """Create single-node k3d cluster with pinned k3s image and disabled Traefik/ServiceLB/metrics-server."""
    if name != CLUSTER_NAME:
        print(f"Safety constraint: cluster-create only permitted for '{CLUSTER_NAME}'", file=sys.stderr)
        return 1

    k3d = shutil.which("k3d")
    if not k3d:
        print("k3d CLI not found on PATH.", file=sys.stderr)
        return 1

    if cluster_exists(name):
        print(f"Cluster '{name}' already exists. Skipping creation.")
        return 0

    print(f"Creating pinned k3d cluster '{name}' with image {image}...")
    create_cmd = [
        k3d,
        "cluster",
        "create",
        name,
        "--image",
        image,
        "--servers",
        "1",
        "--k3s-arg",
        "--disable=traefik@server:0",
        "--k3s-arg",
        "--disable=servicelb@server:0",
        "--k3s-arg",
        "--disable=metrics-server@server:0",
        "--wait",
    ]
    res = _run(create_cmd, check=False)
    if res.returncode != 0:
        return res.returncode

    if import_images:
        print("Importing local container images into k3d cluster...")
        import_cmd = [
            k3d,
            "image",
            "import",
            "kubesentinel-edge-api:latest",
            "kubesentinel-edge-worker:latest",
            "redis:7.4.2-alpine",
            "-c",
            name,
        ]
        _run(import_cmd, check=False)

    print(f"k3d cluster '{name}' successfully created and initialized.")
    return 0


def cluster_start(name: str = CLUSTER_NAME) -> int:
    """Start stopped k3d cluster."""
    if name != CLUSTER_NAME:
        print(f"Safety constraint: cluster-start only permitted for '{CLUSTER_NAME}'", file=sys.stderr)
        return 1
    k3d = shutil.which("k3d")
    if not k3d:
        return 1
    res = _run([k3d, "cluster", "start", name], check=False)
    return res.returncode


def cluster_stop(name: str = CLUSTER_NAME) -> int:
    """Stop running k3d cluster."""
    if name != CLUSTER_NAME:
        print(f"Safety constraint: cluster-stop only permitted for '{CLUSTER_NAME}'", file=sys.stderr)
        return 1
    k3d = shutil.which("k3d")
    if not k3d:
        return 1
    res = _run([k3d, "cluster", "stop", name], check=False)
    return res.returncode


def cluster_delete(name: str = CLUSTER_NAME) -> int:
    """Delete k3d cluster."""
    if name != CLUSTER_NAME:
        print(f"Safety constraint: cluster-delete only permitted for '{CLUSTER_NAME}'", file=sys.stderr)
        return 1
    k3d = shutil.which("k3d")
    if not k3d:
        return 1
    res = _run([k3d, "cluster", "delete", name], check=False)
    return res.returncode
