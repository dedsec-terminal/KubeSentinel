"""Deterministic, idempotent Kubernetes deployment orchestration for KubeSentinel."""

from __future__ import annotations

import sys
from pathlib import Path

from scripts.k8s_client import apply_file, apply_yaml, run_kubectl

ROOT = Path(__file__).resolve().parents[1]
K8S_DIR = ROOT / "kubernetes"


def load_or_create_secrets() -> tuple[str, str, str]:
    """Read secrets from .env.local, generating via bootstrap_local if necessary."""
    env_local = ROOT / ".env.local"
    if not env_local.is_file():
        from scripts.bootstrap import bootstrap_local

        print("--> Generating development credentials via bootstrap-local...")
        bootstrap_local(ROOT)

    producer_pw = ""
    consumer_pw = ""
    bootstrap_pw = ""

    for line in env_local.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip("'\"")
            if k == "REDIS_PRODUCER_PASSWORD":
                producer_pw = v
            elif k == "REDIS_CONSUMER_PASSWORD":
                consumer_pw = v
            elif k == "REDIS_BOOTSTRAP_PASSWORD":
                bootstrap_pw = v

    if not (producer_pw and consumer_pw and bootstrap_pw):
        raise ValueError("Incomplete credentials in .env.local")

    return producer_pw, consumer_pw, bootstrap_pw


def deploy_secrets(producer_pw: str, consumer_pw: str, bootstrap_pw: str) -> None:
    """Create or update Kubernetes Secrets for Redis ACL and client credentials."""
    # 1. users.acl secret in kubesentinel-system
    acl_yaml = f"""apiVersion: v1
kind: Secret
metadata:
  name: redis-acl-secret
  namespace: kubesentinel-system
type: Opaque
stringData:
  users.acl: |
    user default off
    user producer on >{producer_pw} resetchannels -@all +auth +ping +xadd ~security-events
    user consumer on >{consumer_pw} resetchannels -@all +auth +ping +xreadgroup +xack ~security-events
    user bootstrap on >{bootstrap_pw} resetchannels -@all +auth +ping +xgroup +xinfo +xpending ~security-events
"""
    apply_yaml(acl_yaml)
    print("redis-acl-secret applied in kubesentinel-system")

    # 2. redis-auth-secret in kubesentinel-system
    auth_system_yaml = f"""apiVersion: v1
kind: Secret
metadata:
  name: redis-auth-secret
  namespace: kubesentinel-system
type: Opaque
stringData:
  REDIS_CONSUMER_PASSWORD: "{consumer_pw}"
  REDIS_BOOTSTRAP_PASSWORD: "{bootstrap_pw}"
"""
    apply_yaml(auth_system_yaml)
    print("redis-auth-secret applied in kubesentinel-system")

    # 3. redis-auth-secret in edge namespaces
    for ns in ("edge-pune", "edge-mumbai", "edge-bangalore"):
        auth_edge_yaml = f"""apiVersion: v1
kind: Secret
metadata:
  name: redis-auth-secret
  namespace: {ns}
type: Opaque
stringData:
  REDIS_PRODUCER_PASSWORD: "{producer_pw}"
"""
        apply_yaml(auth_edge_yaml)
        print(f"redis-auth-secret applied in {ns}")


def k8s_deploy(timeout_sec: int = 120) -> int:
    """Deploy all KubeSentinel manifests in dependency order and wait for readiness."""
    print("=== Step 1: Namespaces ===")
    for ns_file in sorted((K8S_DIR / "namespaces").glob("*.yaml")):
        print(f"Applying namespace manifest {ns_file.name}...")
        apply_file(ns_file)

    print("=== Step 2: RBAC ServiceAccounts ===")
    for rbac_file in sorted((K8S_DIR / "rbac").glob("*.yaml")):
        print(f"Applying RBAC manifest {rbac_file.name}...")
        apply_file(rbac_file)

    print("=== Step 3: Secrets & Credentials ===")
    producer_pw, consumer_pw, bootstrap_pw = load_or_create_secrets()
    deploy_secrets(producer_pw, consumer_pw, bootstrap_pw)

    print("=== Step 4: ConfigMaps ===")
    for cfg_file in sorted((K8S_DIR / "config").glob("*.yaml")):
        print(f"Applying config manifest {cfg_file.name}...")
        apply_file(cfg_file)
    apply_file(K8S_DIR / "redis" / "redis-configmap.yaml")

    print("=== Step 5: Redis Service & Deployment ===")
    apply_file(K8S_DIR / "redis" / "redis-service.yaml")
    apply_file(K8S_DIR / "redis" / "redis-deployment.yaml")

    print(f"Waiting for Redis deployment to become available (timeout: {timeout_sec}s)...")
    run_kubectl(
        [
            "rollout",
            "status",
            "deployment/redis",
            "-n",
            "kubesentinel-system",
            f"--timeout={timeout_sec}s",
        ],
        check=True,
    )

    print("=== Step 6: Redis Bootstrap Job ===")
    # Remove previous completed job if present
    run_kubectl(
        [
            "delete",
            "job",
            "redis-bootstrap",
            "-n",
            "kubesentinel-system",
            "--ignore-not-found",
        ],
        check=False,
    )
    apply_file(K8S_DIR / "redis" / "redis-bootstrap.yaml")
    print("Waiting for redis-bootstrap Job completion...")
    run_kubectl(
        [
            "wait",
            "--for=condition=complete",
            f"--timeout={timeout_sec}s",
            "job/redis-bootstrap",
            "-n",
            "kubesentinel-system",
        ],
        check=True,
    )

    print("=== Step 7: Workloads (edge-api & edge-worker) ===")
    for workload_file in sorted((K8S_DIR / "workloads").glob("*.yaml")):
        print(f"Applying workload manifest {workload_file.name}...")
        apply_file(workload_file)

    print(f"Waiting for edge-api deployments to become available (timeout: {timeout_sec}s)...")
    for ns in ("edge-pune", "edge-mumbai", "edge-bangalore"):
        run_kubectl(
            [
                "rollout",
                "status",
                "deployment/edge-api",
                "-n",
                ns,
                f"--timeout={timeout_sec}s",
            ],
            check=True,
        )

    print(f"Waiting for edge-worker deployment to become available (timeout: {timeout_sec}s)...")
    run_kubectl(
        [
            "rollout",
            "status",
            "deployment/edge-worker",
            "-n",
            "kubesentinel-system",
            f"--timeout={timeout_sec}s",
        ],
        check=True,
    )

    print("\n[PASS] All KubeSentinel Kubernetes workloads deployed and healthy!")
    return 0


if __name__ == "__main__":
    sys.exit(k8s_deploy())
