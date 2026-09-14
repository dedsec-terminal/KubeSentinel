"""Unit tests for the ordered observability deployment wrapper."""

from __future__ import annotations

from subprocess import CompletedProcess

import pytest

from scripts import observability_deploy


def test_observability_deploy_delegates_credentialed_stack_and_passes_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    applied: list[str] = []
    stack_timeouts: list[int] = []
    kubectl_calls: list[tuple[list[str], float | None]] = []

    monkeypatch.setattr(
        observability_deploy,
        "_apply_manifest",
        lambda path: applied.append(path.name) or True,
    )
    monkeypatch.setattr(
        observability_deploy,
        "deploy_elastic_stack",
        lambda timeout_sec: stack_timeouts.append(timeout_sec) or 0,
    )

    def fake_kubectl(args: list[str], **kwargs: object) -> CompletedProcess[str]:
        kubectl_calls.append((args, kwargs.get("timeout")))
        return CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(observability_deploy, "run_kubectl", fake_kubectl)
    result = observability_deploy.observability_deploy(timeout_sec=300)

    assert result == 0
    assert stack_timeouts == [300]
    assert "daemonset.yaml" in applied
    assert "rendered-falco.yaml" in applied
    assert kubectl_calls
    assert all(timeout == 330.0 for _args, timeout in kubectl_calls)


def test_observability_deploy_stops_when_credentialed_stack_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    applied: list[str] = []
    monkeypatch.setattr(
        observability_deploy,
        "_apply_manifest",
        lambda path: applied.append(path.name) or True,
    )
    monkeypatch.setattr(observability_deploy, "deploy_elastic_stack", lambda timeout_sec: 1)

    assert observability_deploy.observability_deploy(timeout_sec=180) == 1
    assert "daemonset.yaml" not in applied
