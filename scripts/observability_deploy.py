"""Deploy Central Observability and Runtime Security components in sequence."""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.k8s_client import run_kubectl
from scripts.setup_es_templates import (
    get_es_credentials,
    setup_elasticsearch_templates,
    setup_kibana_data_views,
)


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

    # Step 2: Elasticsearch
    print("\n--- Step 2: Elasticsearch ---")
    es_dir = ROOT / "kubernetes" / "observability" / "elasticsearch"
    for f in ["service.yaml", "deployment.yaml"]:
        if not _apply_manifest(es_dir / f):
            return 1

    print(f"Waiting for Elasticsearch rollout (timeout: {timeout_sec}s)...")
    res = run_kubectl([
        "rollout", "status", "deployment/elasticsearch",
        "-n", "observability", f"--timeout={timeout_sec}s",
    ])
    if res.returncode != 0:
        print(f"ERROR: Elasticsearch rollout failed: {res.stderr}", file=sys.stderr)
        return 1
    print("Elasticsearch deployment is ready.")

    # Step 3: Index Templates & Mappings
    print("\n--- Step 3: Elasticsearch Index Templates ---")
    username, password = get_es_credentials()
    retries = 10
    templates_ok = False
    for i in range(retries):
        try:
            if username and password and setup_elasticsearch_templates("http://localhost:9200", username, password):
                templates_ok = True
                print("Index templates registered: ['kubesentinel-app', 'kubesentinel-falco']")
                break
        except (RuntimeError, OSError, ValueError) as e:
            print(f"Retry {i + 1}/{retries} waiting for ES: {e}")
        time.sleep(3)

    if not templates_ok:
        print("WARNING: Could not verify all index templates immediately.", file=sys.stderr)

    # Step 4: Kibana
    print("\n--- Step 4: Kibana ---")
    kibana_dir = ROOT / "kubernetes" / "observability" / "kibana"
    for f in ["service.yaml", "deployment.yaml"]:
        if not _apply_manifest(kibana_dir / f):
            return 1

    print(f"Waiting for Kibana rollout (timeout: {timeout_sec}s)...")
    res = run_kubectl([
        "rollout", "status", "deployment/kibana",
        "-n", "observability", f"--timeout={timeout_sec}s",
    ])
    if res.returncode != 0:
        print(f"ERROR: Kibana rollout failed: {res.stderr}", file=sys.stderr)
        return 1
    print("Kibana deployment is ready.")

    try:
        if username and password and setup_kibana_data_views("http://localhost:5601", username, password):
            print("Kibana data views configured successfully.")
    except (RuntimeError, OSError, ValueError) as e:
        print(f"Note: Kibana data views setup note: {e}")

    # Step 5: Fluent Bit
    print("\n--- Step 5: Fluent Bit ---")
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
    ])
    if res.returncode != 0:
        print(f"ERROR: Fluent Bit rollout failed: {res.stderr}", file=sys.stderr)
        return 1
    print("Fluent Bit DaemonSet is ready.")

    # Step 6: Falco Runtime Security
    print("\n--- Step 6: Falco Runtime Security ---")
    falco_manifest = ROOT / "kubernetes" / "security-agents" / "falco" / "rendered-falco.yaml"
    if not _apply_manifest(falco_manifest):
        return 1

    print("Waiting for Falco rollout...")
    res = run_kubectl([
        "rollout", "status", "daemonset/falco",
        "-n", "security-agents", f"--timeout={timeout_sec}s",
    ])
    if res.returncode != 0:
        print(f"ERROR: Falco rollout failed: {res.stderr}", file=sys.stderr)
        return 1
    print("Falco DaemonSet is ready.")

    # Step 7: NetworkPolicies
    print("\n--- Step 7: NetworkPolicies ---")
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
