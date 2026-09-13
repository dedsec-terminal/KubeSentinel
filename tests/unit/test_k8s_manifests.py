"""Unit tests for Kubernetes manifests, PSA labels, RBAC configurations, and CLI."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
K8S_DIR = ROOT / "kubernetes"


def test_manifest_directory_structure() -> None:
    """Verify all expected manifest directories and files exist."""
    assert (K8S_DIR / "namespaces").is_dir()
    assert (K8S_DIR / "rbac").is_dir()
    assert (K8S_DIR / "config").is_dir()
    assert (K8S_DIR / "redis").is_dir()
    assert (K8S_DIR / "workloads").is_dir()
    assert (K8S_DIR / "security").is_dir()

    expected_files = [
        K8S_DIR / "namespaces" / "kubesentinel-system.yaml",
        K8S_DIR / "namespaces" / "edge-pune.yaml",
        K8S_DIR / "namespaces" / "edge-mumbai.yaml",
        K8S_DIR / "namespaces" / "edge-bangalore.yaml",
        K8S_DIR / "namespaces" / "observability.yaml",
        K8S_DIR / "rbac" / "edge-api-sa.yaml",
        K8S_DIR / "rbac" / "edge-worker-sa.yaml",
        K8S_DIR / "rbac" / "redis-sa.yaml",
        K8S_DIR / "redis" / "redis-deployment.yaml",
        K8S_DIR / "redis" / "redis-service.yaml",
        K8S_DIR / "redis" / "redis-bootstrap.yaml",
        K8S_DIR / "redis" / "redis-configmap.yaml",
        K8S_DIR / "workloads" / "edge-api-pune.yaml",
        K8S_DIR / "workloads" / "edge-api-mumbai.yaml",
        K8S_DIR / "workloads" / "edge-api-bangalore.yaml",
        K8S_DIR / "workloads" / "edge-worker.yaml",
        K8S_DIR / "security" / "psa-negative-pod.yaml",
    ]
    for ef in expected_files:
        assert ef.is_file(), f"Missing expected manifest: {ef}"


def test_namespace_psa_labels() -> None:
    """Verify namespace manifests contain exact required PSA labels."""
    restricted_ns = ["kubesentinel-system", "edge-pune", "edge-mumbai", "edge-bangalore"]
    for ns_name in restricted_ns:
        path = K8S_DIR / "namespaces" / f"{ns_name}.yaml"
        content = path.read_text(encoding="utf-8")
        assert "pod-security.kubernetes.io/enforce: restricted" in content
        assert "pod-security.kubernetes.io/audit: restricted" in content
        assert "pod-security.kubernetes.io/warn: restricted" in content

    obs_path = K8S_DIR / "namespaces" / "observability.yaml"
    obs_content = obs_path.read_text(encoding="utf-8")
    assert "pod-security.kubernetes.io/enforce: baseline" in obs_content
    assert "pod-security.kubernetes.io/audit: baseline" in obs_content
    assert "pod-security.kubernetes.io/warn: baseline" in obs_content

    sec_path = K8S_DIR / "namespaces" / "security-agents.yaml"
    if sec_path.is_file():
        sec_content = sec_path.read_text(encoding="utf-8")
        assert "pod-security.kubernetes.io/enforce: privileged" in sec_content
        assert "pod-security.kubernetes.io/audit: privileged" in sec_content
        assert "pod-security.kubernetes.io/warn: privileged" in sec_content


def test_service_accounts_disable_automount() -> None:
    """Verify all ServiceAccounts explicitly set automountServiceAccountToken: false."""
    for rbac_file in (K8S_DIR / "rbac").glob("*.yaml"):
        content = rbac_file.read_text(encoding="utf-8")
        assert "kind: ServiceAccount" in content
        assert "automountServiceAccountToken: false" in content


def test_deployment_hardening_and_resources() -> None:
    """Verify all Deployments enforce restricted container security contexts and resource limits."""
    deployment_files = [
        K8S_DIR / "redis" / "redis-deployment.yaml",
        K8S_DIR / "workloads" / "edge-api-pune.yaml",
        K8S_DIR / "workloads" / "edge-api-mumbai.yaml",
        K8S_DIR / "workloads" / "edge-api-bangalore.yaml",
        K8S_DIR / "workloads" / "edge-worker.yaml",
    ]

    for df in deployment_files:
        content = df.read_text(encoding="utf-8")
        assert "kind: Deployment" in content
        assert "runAsNonRoot: true" in content
        assert "readOnlyRootFilesystem: true" in content
        assert "allowPrivilegeEscalation: false" in content
        assert "RuntimeDefault" in content
        assert re.search(r"drop:\s*\n\s*-\s*ALL", content)
        assert "resources:" in content
        assert "requests:" in content
        assert "limits:" in content


def test_edge_api_downward_api_fields() -> None:
    """Verify edge-api workloads map Downward API fieldRefs for pod, node, and namespace."""
    for site in ("pune", "mumbai", "bangalore"):
        path = K8S_DIR / "workloads" / f"edge-api-{site}.yaml"
        content = path.read_text(encoding="utf-8")
        assert "name: KUBERNETES_POD_NAME" in content
        assert "fieldPath: metadata.name" in content
        assert "name: KUBERNETES_NAMESPACE" in content
        assert "fieldPath: metadata.namespace" in content
        assert "name: KUBERNETES_NODE_NAME" in content
        assert "fieldPath: spec.nodeName" in content


def test_psa_negative_fixture() -> None:
    """Verify PSA negative test fixture defines forbidden security configurations."""
    path = K8S_DIR / "security" / "psa-negative-pod.yaml"
    content = path.read_text(encoding="utf-8")
    assert "kind: Pod" in content
    assert "hostPID: true" in content
    assert "privileged: true" in content
    assert "allowPrivilegeEscalation: true" in content
    assert "SYS_ADMIN" in content


def test_network_policy_manifests() -> None:
    """Verify all NetworkPolicy manifests exist and define required policyTypes and ports."""
    net_dir = K8S_DIR / "network"
    assert net_dir.is_dir()

    expected_files = [
        "default-deny.yaml",
        "allow-dns.yaml",
        "redis-policy.yaml",
        "edge-api-policy.yaml",
        "edge-worker-policy.yaml",
    ]
    for filename in expected_files:
        path = net_dir / filename
        assert path.is_file(), f"Missing NetworkPolicy manifest: {filename}"
        content = path.read_text(encoding="utf-8")
        assert "kind: NetworkPolicy" in content
        assert "policyTypes:" in content

    # Verify default-deny covers Ingress and Egress
    default_deny = (net_dir / "default-deny.yaml").read_text(encoding="utf-8")
    assert "- Ingress" in default_deny
    assert "- Egress" in default_deny

    # Verify allow-dns scopes to port 53 UDP/TCP
    allow_dns = (net_dir / "allow-dns.yaml").read_text(encoding="utf-8")
    assert "port: 53" in allow_dns
    assert "protocol: UDP" in allow_dns
    assert "protocol: TCP" in allow_dns

    # Verify redis-policy scopes to port 6379
    redis_policy = (net_dir / "redis-policy.yaml").read_text(encoding="utf-8")
    assert "port: 6379" in redis_policy
    assert "protocol: TCP" in redis_policy


def test_kyverno_policies() -> None:
    """Verify all 9 Kyverno policies exist, are ClusterPolicies, and enforce required rules."""
    policy_dir = ROOT / "policies" / "kyverno"
    assert policy_dir.is_dir()

    expected_policies = [
        "disallow-privileged.yaml",
        "require-run-as-non-root.yaml",
        "disallow-privilege-escalation.yaml",
        "require-drop-all-capabilities.yaml",
        "require-runtime-default-seccomp.yaml",
        "require-resource-requests-limits.yaml",
        "disallow-host-path.yaml",
        "disallow-host-network.yaml",
        "disallow-latest-tag.yaml",
    ]
    for pol_file in expected_policies:
        path = policy_dir / pol_file
        assert path.is_file(), f"Missing Kyverno policy: {pol_file}"
        content = path.read_text(encoding="utf-8")
        assert "kind: ClusterPolicy" in content
        assert "validationFailureAction: Enforce" in content
        assert "edge-pune" in content
        assert "edge-mumbai" in content
        assert "edge-bangalore" in content
        assert "kubesentinel-system" in content


def test_kyverno_fixtures() -> None:
    """Verify positive and negative Kyverno test fixtures exist."""
    fixtures_dir = ROOT / "tests" / "kyverno"
    assert (fixtures_dir / "pass" / "valid-pod.yaml").is_file()
    assert (fixtures_dir / "fail" / "disallow-latest-tag-fail.yaml").is_file()
    assert (fixtures_dir / "fail" / "missing-resources-fail.yaml").is_file()
    assert (fixtures_dir / "fail" / "privileged-container-fail.yaml").is_file()
    assert (fixtures_dir / "fail" / "host-network-fail.yaml").is_file()
    assert (fixtures_dir / "fail" / "host-path-fail.yaml").is_file()


def test_production_workloads_no_latest_tag() -> None:
    """Verify all production workload manifests use explicit version tags, never :latest."""
    workload_files = [
        K8S_DIR / "workloads" / "edge-api-pune.yaml",
        K8S_DIR / "workloads" / "edge-api-mumbai.yaml",
        K8S_DIR / "workloads" / "edge-api-bangalore.yaml",
        K8S_DIR / "workloads" / "edge-worker.yaml",
        K8S_DIR / "redis" / "redis-deployment.yaml",
    ]
    for wf in workload_files:
        content = wf.read_text(encoding="utf-8")
        assert ":latest" not in content, f"Disallowed :latest tag found in {wf.name}"
