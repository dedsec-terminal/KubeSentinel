"""Deploy Central Observability and Runtime Security components in sequence."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.deploy_observability import deploy_observability as deploy_elastic_stack
from scripts.k8s_client import run_kubectl


def _apply_manifest(path: Path) -> bool:
    if not path.is_file():
        print(f"ERROR: Manifest not found: {path}", file=sys.stderr)
        return False
    content = path.read_text(encoding="utf-8")
    res = run_kubectl(["apply", "-f", "-"], input_text=content)
    if res.returncode != 0:
        print(f"ERROR applying {path.name}: {res.stderr}", file=sys.stderr)
        return False
    return True


def observability_deploy(timeout_sec: int = 180) -> int:
    """Deploy Elasticsearch, Kibana, Fluent Bit, and Falco in validated sequence."""
    print("=== Deploying Central Observability & Runtime Security Stack ===")

    # Step 1: Namespaces
    print("\n--- Step 1: Namespaces ---")
    for ns_file in ["observability.yaml", "security-agents.yaml"]:
        p = ROOT / "kubernetes" / "namespaces" / ns_file
        if not _apply_manifest(p):
            return 1
    print("Namespaces confirmed.")

    # Step 2: Elasticsearch, Kibana, credentials, mappings, and data views.
    # Keep this sequence in one implementation so both observability entry points
    # create the Secret before dependent pods start and synchronize kibana_system.
    print("\n--- Step 2: Elasticsearch & Kibana ---")
    if deploy_elastic_stack(timeout_sec=timeout_sec) != 0:
        return 1

    # Step 3: Fluent Bit
    print("\n--- Step 3: Fluent Bit ---")
    fb_dir = ROOT / "kubernetes" / "observability" / "fluent-bit"
    fb_manifests = [
        "storage.yaml",
        "serviceaccount.yaml",
        "clusterrole.yaml",
        "clusterrolebinding.yaml",
        "configmap.yaml",
        "daemonset.yaml",
    ]
    for f in fb_manifests:
        if not _apply_manifest(fb_dir / f):
            return 1

    print("Waiting for Fluent Bit rollout...")
    res = run_kubectl([
        "rollout", "status", "daemonset/fluent-bit",
        "-n", "observability", f"--timeout={timeout_sec}s",
    ], timeout=float(timeout_sec + 30))
    if res.returncode != 0:
        print(f"ERROR: Fluent Bit rollout failed: {res.stderr}", file=sys.stderr)
        return 1
    print("Fluent Bit DaemonSet is ready.")

    # Step 4: Falco Runtime Security
    print("\n--- Step 4: Falco Runtime Security ---")
    falco_manifest = ROOT / "kubernetes" / "security-agents" / "falco" / "rendered-falco.yaml"
    if not _apply_manifest(falco_manifest):
        return 1

    print("Waiting for Falco rollout...")
    res = run_kubectl([
        "rollout", "status", "daemonset/falco",
        "-n", "security-agents", f"--timeout={timeout_sec}s",
    ], timeout=float(timeout_sec + 30))
    if res.returncode != 0:
        print(f"ERROR: Falco rollout failed: {res.stderr}", file=sys.stderr)
        return 1
    print("Falco DaemonSet is ready.")

    # Step 5: NetworkPolicies
    print("\n--- Step 5: NetworkPolicies ---")
    net_dir = ROOT / "kubernetes" / "network"
    for np in ["observability-policy.yaml", "security-agents-policy.yaml"]:
        if (net_dir / np).is_file():
            _apply_manifest(net_dir / np)
    print("NetworkPolicies applied for observability and security-agents.")

    print("\n[SUCCESS] Observability and runtime security components deployed successfully.")
    return 0


def main() -> int:
    return observability_deploy()


if __name__ == "__main__":
    sys.exit(main())
