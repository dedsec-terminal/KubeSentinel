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


def _image_variants(image: str) -> set[str]:
    """Return common containerd aliases for a Docker image reference."""
    variants = {image}
    if image.startswith("docker.io/"):
        variants.add(image.removeprefix("docker.io/"))
    else:
        variants.add(f"docker.io/{image}")
    reference = image.split("@", 1)[0]
    repository, separator, tag = reference.rpartition(":")
    if separator and "/" not in repository:
        variants.add(f"docker.io/library/{repository}:{tag}")
    return variants


def _existing_cluster_images(name: str) -> set[str]:
    """Read image references already loaded in the k3d node, failing open."""
    docker = shutil.which("docker")
    if not docker:
        return set()
    server = f"k3d-{name}-server-0"
    try:
        res = subprocess.run(
            [docker, "exec", server, "ctr", "-n", "k8s.io", "images", "list", "-q"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=15.0,
            cwd=ROOT,
        )
    except (OSError, subprocess.SubprocessError):
        return set()
    if res.returncode != 0:
        return set()
    return {line.strip() for line in res.stdout.splitlines() if line.strip()}


def import_images_into_cluster(images: list[str], name: str = CLUSTER_NAME) -> int:
    """Import images one at a time so k3d cannot mask a partial bulk import."""
    k3d = shutil.which("k3d")
    if not k3d:
        print("k3d CLI not found on PATH.", file=sys.stderr)
        return 1

    existing = _existing_cluster_images(name)
    for image in images:
        if existing.intersection(_image_variants(image)):
            print(f"Skipping {image}; already present in k3d cluster '{name}'.")
            continue
        print(f"Importing {image} into k3d cluster '{name}'...")
        res = _run([k3d, "image", "import", image, "-c", name], check=False)
        if res.returncode != 0:
            print(f"ERROR: Failed to import {image} into cluster '{name}'.", file=sys.stderr)
            return res.returncode
    return 0


def pull_images(images: list[str]) -> int:
    """Ensure pinned third-party images exist in the host Docker cache."""
    docker = shutil.which("docker")
    if not docker:
        print("docker CLI not found on PATH.", file=sys.stderr)
        return 1

    for image in images:
        inspect = subprocess.run(
            [docker, "image", "inspect", image],
            capture_output=True,
            text=True,
            check=False,
            cwd=ROOT,
        )
        if inspect.returncode == 0:
            continue
        print(f"Pulling pinned dependency image {image}...")
        res = _run([docker, "pull", image], check=False)
        if res.returncode != 0:
            print(f"ERROR: Failed to pull dependency image {image}.", file=sys.stderr)
            return res.returncode
    return 0


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
        rc = import_images_into_cluster([
            "kubesentinel-edge-api:latest",
            "kubesentinel-edge-worker:latest",
            "redis:7.4.2-alpine",
        ], name=name)
        if rc != 0:
            return rc

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
