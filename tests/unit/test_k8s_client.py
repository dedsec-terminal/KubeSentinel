"""Unit tests for host/container Kubernetes and Helm execution paths."""

from __future__ import annotations

from subprocess import CompletedProcess

import pytest

from scripts import k8s_client


def test_run_helm_uses_host_when_native_kubectl_is_reachable(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[list[str], dict]] = []

    monkeypatch.setattr(k8s_client, "is_native_kubectl_available", lambda: True)
    monkeypatch.setattr(k8s_client.shutil, "which", lambda name: "helm.exe" if name == "helm" else None)

    def fake_run(cmd: list[str], **kwargs: object) -> CompletedProcess[str]:
        calls.append((cmd, kwargs))
        return CompletedProcess(cmd, 0, "helm version", "")

    monkeypatch.setattr(k8s_client.subprocess, "run", fake_run)
    result = k8s_client.run_helm(["version"], timeout=7)

    assert result.returncode == 0
    assert calls[0][0] == ["helm.exe", "version"]
    assert calls[0][1]["timeout"] == 7


def test_run_helm_uses_pinned_container_helper_when_host_route_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    monkeypatch.setattr(k8s_client, "is_native_kubectl_available", lambda: False)
    monkeypatch.setattr(
        k8s_client.shutil,
        "which",
        lambda name: "docker.exe" if name == "docker" else None,
    )

    def fake_run(cmd: list[str], **kwargs: object) -> CompletedProcess[str]:
        calls.append(cmd)
        return CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(k8s_client.subprocess, "run", fake_run)
    result = k8s_client.run_helm(["list", "-A"], input_text="", timeout=11)

    assert result.returncode == 0
    assert calls[0][0:3] == ["docker.exe", "cp", "k3d-kubesentinel-server-0:/etc/rancher/k3s/k3s.yaml"]
    helper = calls[1]
    assert helper[0:2] == ["docker.exe", "run"]
    assert "container:k3d-kubesentinel-server-0" in helper
    assert k8s_client.HELM_IMAGE in helper
    assert helper[-2:] == ["list", "-A"]


def test_run_helm_helper_failure_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(k8s_client, "is_native_kubectl_available", lambda: False)
    monkeypatch.setattr(
        k8s_client.shutil,
        "which",
        lambda name: "docker.exe" if name == "docker" else None,
    )

    def fake_run(cmd: list[str], **kwargs: object) -> CompletedProcess[str]:
        if cmd[1] == "cp":
            return CompletedProcess(cmd, 0, "", "")
        return CompletedProcess(cmd, 17, "", "chart unavailable")

    monkeypatch.setattr(k8s_client.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="Helm helper failed"):
        k8s_client.run_helm(["list"], check=True)
