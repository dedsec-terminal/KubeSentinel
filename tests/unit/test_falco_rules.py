"""Unit tests for Falco configuration, custom detection rules, and namespace specifications."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HELM_VALUES_PATH = ROOT / "helm" / "third-party" / "falco-values.yaml"
K8S_VALUES_PATH = ROOT / "kubernetes" / "security-agents" / "falco" / "values.yaml"
NAMESPACE_PATH = ROOT / "kubernetes" / "namespaces" / "security-agents.yaml"
RENDERED_MANIFEST_PATH = ROOT / "kubernetes" / "security-agents" / "falco" / "rendered-falco.yaml"


def test_falco_values_files_exist() -> None:
    """Verify Falco values files exist in both canonical locations."""
    assert HELM_VALUES_PATH.is_file(), f"Missing {HELM_VALUES_PATH}"
    assert K8S_VALUES_PATH.is_file(), f"Missing {K8S_VALUES_PATH}"


def test_falco_namespace_psa_privileged() -> None:
    """Verify security-agents namespace manifest exists with PSA privileged profile."""
    assert NAMESPACE_PATH.is_file(), f"Missing {NAMESPACE_PATH}"
    content = NAMESPACE_PATH.read_text(encoding="utf-8")

    assert "kind: Namespace" in content
    assert "name: security-agents" in content
    assert "pod-security.kubernetes.io/enforce: privileged" in content
    assert "pod-security.kubernetes.io/audit: privileged" in content
    assert "pod-security.kubernetes.io/warn: privileged" in content

    # Verify documentation/annotation explaining privileged necessity
    assert "privileged" in content.lower()
    assert "ebpf" in content.lower() or "kernel" in content.lower()


def test_falco_values_configuration() -> None:
    """Verify driver, resources, JSON output, and version pinning in values."""
    content = HELM_VALUES_PATH.read_text(encoding="utf-8")

    # Pinned image and version
    assert "repository: falcosecurity/falco" in content
    assert 'tag: "0.44.1"' in content or "tag: 0.44.1" in content
    assert "pullPolicy: IfNotPresent" in content

    # Driver settings
    assert "kind: modern_ebpf" in content

    # Resources sizing
    assert re.search(r"requests:\s*\n\s*cpu:\s*100m\s*\n\s*memory:\s*128Mi", content)
    assert re.search(r"limits:\s*\n\s*cpu:\s*500m\s*\n\s*memory:\s*256Mi", content)

    # Output settings
    assert "json_output: true" in content
    assert "json_include_output_property: true" in content
    assert re.search(r"stdout_output:\s*\n\s*enabled:\s*true", content)

    # falcoctl disabled to protect offline k3d execution
    assert re.search(r"install:\s*\n\s*enabled:\s*false", content)
    assert re.search(r"follow:\s*\n\s*enabled:\s*false", content)


def test_custom_rule_structure_and_mitre_mapping() -> None:
    """Verify custom Falco rule 'Unexpected shell in KubeSentinel edge workload'."""
    content = HELM_VALUES_PATH.read_text(encoding="utf-8")

    assert "rules-kubesentinel.yaml" in content
    assert "Unexpected shell in KubeSentinel edge workload" in content

    # Check monitored namespaces
    assert "edge-pune" in content
    assert "edge-mumbai" in content
    assert "edge-bangalore" in content
    assert "kubesentinel-system" in content

    # Check condition elements
    assert "spawned_process" in content
    assert "container" in content
    assert "proc.name in (sh, bash, ash, zsh)" in content

    # Priority and ATT&CK tags
    assert "priority: WARNING" in content or "priority: CRITICAL" in content
    assert "T1059.004" in content
    assert "mitre_execution" in content
    assert "kubesentinel" in content

    # Output string metadata fields
    assert "%user.name" in content
    assert "%proc.name" in content
    assert "%container.name" in content
    assert "%k8s_pod=%k8s.pod.name" in content or "%k8s.pod.name" in content
    assert "%k8s_ns=%k8s.ns.name" in content or "%k8s.ns.name" in content


def test_rule_condition_simulation() -> None:
    """Simulate rule matching logic against synthetic process events."""
    monitored_namespaces = {"edge-pune", "edge-mumbai", "edge-bangalore", "kubesentinel-system"}
    monitored_shells = {"sh", "bash", "ash", "zsh"}
    allowed_parents: set[str] = set()

    def evaluate_rule(event: dict[str, str | bool | None]) -> bool:
        if not event.get("spawned_process"):
            return False
        if not event.get("container"):
            return False
        if event.get("k8s_ns") not in monitored_namespaces:
            return False
        if event.get("proc_name") not in monitored_shells:
            return False
        return event.get("proc_pname") not in allowed_parents

    # 1. Shell executed in edge-pune -> Should trigger
    assert evaluate_rule({
        "spawned_process": True,
        "container": True,
        "k8s_ns": "edge-pune",
        "proc_name": "sh",
        "proc_pname": "containerd-shim",
    }) is True

    # 2. Bash executed in kubesentinel-system -> Should trigger
    assert evaluate_rule({
        "spawned_process": True,
        "container": True,
        "k8s_ns": "kubesentinel-system",
        "proc_name": "bash",
        "proc_pname": "runc",
    }) is True

    # 3. Non-shell process (e.g. edge-worker python script) -> Should NOT trigger
    assert evaluate_rule({
        "spawned_process": True,
        "container": True,
        "k8s_ns": "kubesentinel-system",
        "proc_name": "python",
        "proc_pname": "tini",
    }) is False

    # 4. Host process (container == False) -> Should NOT trigger
    assert evaluate_rule({
        "spawned_process": True,
        "container": False,
        "k8s_ns": "edge-pune",
        "proc_name": "sh",
        "proc_pname": "systemd",
    }) is False

    # 5. Shell in unmonitored namespace (e.g. kube-system) -> Should NOT trigger
    assert evaluate_rule({
        "spawned_process": True,
        "container": True,
        "k8s_ns": "kube-system",
        "proc_name": "sh",
        "proc_pname": "containerd",
    }) is False


def test_rendered_manifest_integrity() -> None:
    """Verify rendered manifest contains DaemonSet, ServiceAccount, and ConfigMaps."""
    assert RENDERED_MANIFEST_PATH.is_file(), f"Missing {RENDERED_MANIFEST_PATH}"
    content = RENDERED_MANIFEST_PATH.read_text(encoding="utf-8")

    assert "kind: ServiceAccount" in content
    assert "kind: ConfigMap" in content
    assert "kind: DaemonSet" in content
    assert "image: docker.io/falcosecurity/falco:0.44.1" in content
    assert "privileged: true" in content

    # Verify resource bounds in DaemonSet
    assert "cpu: 100m" in content
    assert "memory: 128Mi" in content
    assert "cpu: 500m" in content
    assert "memory: 256Mi" in content
