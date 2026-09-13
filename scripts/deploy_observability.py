"""Deterministic, idempotent deployment orchestration for Elasticsearch and Kibana."""

from __future__ import annotations

import secrets
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.k8s_client import apply_file, apply_yaml, run_kubectl
from scripts.setup_es_templates import (
    get_es_credentials,
    request_es,
    request_kibana,
    setup_elasticsearch_templates,
    setup_kibana_data_views,
)

OBS_DIR = ROOT / "kubernetes" / "observability"


def load_or_create_es_credentials() -> tuple[str, str]:
    """Retrieve existing Elasticsearch credentials or generate strong random password."""
    username, password = get_es_credentials()
    if password:
        return username, password

    # Generate a strong 32-char cryptographically secure password
    username = "elastic"
    password = secrets.token_urlsafe(24)

    env_local = ROOT / ".env.local"
    content = ""
    if env_local.is_file():
        content = env_local.read_text(encoding="utf-8")

    lines = [line for line in content.splitlines() if not line.startswith("ELASTICSEARCH_")]
    lines.append("")
    lines.append("# Elasticsearch Credentials")
    lines.append(f"ELASTICSEARCH_USERNAME={username}")
    lines.append(f"ELASTICSEARCH_PASSWORD={password}")
    env_local.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("--> Generated new Elasticsearch credentials and appended to .env.local")

    return username, password


def deploy_es_secret(username: str, password: str) -> None:
    """Apply elasticsearch-credentials Kubernetes Secret in observability namespace."""
    secret_yaml = f"""apiVersion: v1
kind: Secret
metadata:
  name: elasticsearch-credentials
  namespace: observability
  labels:
    app.kubernetes.io/name: elasticsearch
    app.kubernetes.io/part-of: kubesentinel
    app.kubernetes.io/component: credentials
type: Opaque
stringData:
  username: "{username}"
  kibana_username: "kibana_system"
  password: "{password}"
"""
    apply_yaml(secret_yaml)
    print("Applied elasticsearch-credentials Secret in observability namespace")


def deploy_observability(timeout_sec: int = 180) -> int:
    """Deploy Elasticsearch and Kibana, wait for rollout, and register index templates & data views."""
    print("=== Step 1: Observability Credentials ===")
    username, password = load_or_create_es_credentials()
    deploy_es_secret(username, password)

    print("\n=== Step 2: Elasticsearch Deployment & Service ===")
    apply_file(OBS_DIR / "elasticsearch" / "service.yaml")
    apply_file(OBS_DIR / "elasticsearch" / "deployment.yaml")

    print(f"Waiting for Elasticsearch deployment rollout (timeout: {timeout_sec}s)...")
    res = run_kubectl(
        [
            "rollout",
            "status",
            "deployment/elasticsearch",
            "-n",
            "observability",
            f"--timeout={timeout_sec}s",
        ],
        check=False,
        timeout=float(timeout_sec + 30),
    )
    if res.returncode != 0:
        print(f"ERROR: Elasticsearch rollout failed: {res.stderr}", file=sys.stderr)
        return 1

    print("\n=== Step 3: Elasticsearch Health Check ===")
    healthy = False
    start_time = time.monotonic()
    while time.monotonic() - start_time < 90:
        code, health = request_es("_cluster/health", username=username, password=password)
        if code == 200 and isinstance(health, dict):
            status = health.get("status")
            print(f"Elasticsearch cluster health: {status} (nodes: {health.get('number_of_nodes')})")
            healthy = True
            break
        print("Waiting for Elasticsearch cluster health endpoint...")
        time.sleep(3)

    if not healthy:
        print("ERROR: Elasticsearch health check timed out.", file=sys.stderr)
        return 1

    # Synchronize kibana_system password with the secret
    print("--> Synchronizing kibana_system user password in Elasticsearch...")
    code, _ = request_es(
        "_security/user/kibana_system/_password",
        method="POST",
        data={"password": password},
        username=username,
        password=password,
    )
    if code not in (200, 204):
        print(f"WARNING: Setting kibana_system password returned status {code}")
    else:
        print("kibana_system password configured successfully.")

    print("\n=== Step 4: Kibana Deployment & Service ===")
    apply_file(OBS_DIR / "kibana" / "service.yaml")
    apply_file(OBS_DIR / "kibana" / "deployment.yaml")

    print(f"Waiting for Kibana deployment rollout (timeout: {timeout_sec}s)...")
    res = run_kubectl(
        [
            "rollout",
            "status",
            "deployment/kibana",
            "-n",
            "observability",
            f"--timeout={timeout_sec}s",
        ],
        check=False,
        timeout=float(timeout_sec + 30),
    )
    if res.returncode != 0:
        print(f"ERROR: Kibana rollout failed: {res.stderr}", file=sys.stderr)
        return 1

    print("\n=== Step 5: Kibana Health Check ===")
    kibana_ready = False
    start_time = time.monotonic()
    while time.monotonic() - start_time < 90:
        code, status_res = request_kibana("api/status", username=username, password=password)
        if code == 200 and isinstance(status_res, dict):
            state = status_res.get("status", {}).get("overall", {}).get("level", "available")
            print(f"Kibana status: {state}")
            kibana_ready = True
            break
        print("Waiting for Kibana status endpoint...")
        time.sleep(4)

    if not kibana_ready:
        print("ERROR: Kibana status check timed out.", file=sys.stderr)
        return 1

    print("\n=== Step 6: Register Index Templates ===")
    templates_ok = setup_elasticsearch_templates("http://localhost:9200", username, password)
    if not templates_ok:
        print("ERROR: Index templates setup failed.", file=sys.stderr)
        return 1

    print("\n=== Step 7: Register Kibana Data Views ===")
    views_ok = setup_kibana_data_views("http://localhost:5601", username, password)
    if not views_ok:
        print("ERROR: Kibana data views setup failed.", file=sys.stderr)
        return 1

    print("\n[PASS] Elasticsearch & Kibana deployed, healthy, and configured successfully!")
    return 0


if __name__ == "__main__":
    sys.exit(deploy_observability())
