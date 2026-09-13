from types import SimpleNamespace

from scripts import kubesentinel
from scripts.validate import doctor


def test_doctor_subcommand_forwards_json_flag(monkeypatch) -> None:
    monkeypatch.setattr(doctor, "main", lambda argv: 7 if argv == ["--json"] else 0)

    assert kubesentinel.main(["doctor", "--json"]) == 7


def test_serve_subcommand_uses_local_uvicorn(monkeypatch) -> None:
    calls: list[tuple[list[str], object, bool]] = []

    def run(command, *, cwd, check):
        calls.append((command, cwd, check))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(kubesentinel.subprocess, "run", run)

    assert kubesentinel.main(["serve"]) == 0
    command, cwd, check = calls[0]
    assert command[:3] == [kubesentinel.sys.executable, "-m", "uvicorn"]
    assert command[3:] == [
        "edge_api.main:app",
        "--host",
        "127.0.0.1",
        "--port",
        "8000",
    ]
    assert cwd == kubesentinel.ROOT
    assert check is False


def test_cluster_subcommands_dispatch(monkeypatch) -> None:
    from scripts import cluster

    monkeypatch.setattr(cluster, "cluster_create", lambda import_images=True: 41)
    monkeypatch.setattr(cluster, "cluster_start", lambda: 42)
    monkeypatch.setattr(cluster, "cluster_stop", lambda: 43)
    monkeypatch.setattr(cluster, "cluster_delete", lambda: 44)

    assert kubesentinel.main(["cluster-create"]) == 41
    assert kubesentinel.main(["cluster-start"]) == 42
    assert kubesentinel.main(["cluster-stop"]) == 43
    assert kubesentinel.main(["cluster-delete"]) == 44


def test_k8s_subcommands_dispatch(monkeypatch) -> None:
    from scripts import k8s_deploy, k8s_smoke, k8s_validate

    monkeypatch.setattr(k8s_deploy, "k8s_deploy", lambda timeout_sec=120: 51)
    monkeypatch.setattr(k8s_validate, "run_k8s_validate", lambda as_json=False: 52)
    monkeypatch.setattr(k8s_smoke, "run_k8s_smoke", lambda timeout_sec=45: 53)

    assert kubesentinel.main(["k8s-deploy"]) == 51
    assert kubesentinel.main(["k8s-validate"]) == 52
    assert kubesentinel.main(["k8s-smoke"]) == 53


def test_security_subcommands_dispatch(monkeypatch) -> None:
    from scripts import kyverno_validate, network_validate

    monkeypatch.setattr(network_validate, "main", lambda argv: 61 if argv == ["--json"] else 0)
    monkeypatch.setattr(kyverno_validate, "main", lambda argv: 62 if argv == ["--json"] else 0)

    assert kubesentinel.main(["network-validate", "--json"]) == 61
    assert kubesentinel.main(["kyverno-validate", "--json"]) == 62


def test_observability_subcommands_dispatch(monkeypatch) -> None:
    from scripts import (
        falco_validate,
        observability_deploy,
        observability_validate,
        telemetry_smoke,
    )

    monkeypatch.setattr(observability_deploy, "observability_deploy", lambda timeout_sec=180: 71)
    monkeypatch.setattr(observability_validate, "run_observability_validate", lambda as_json=False: 72)
    monkeypatch.setattr(telemetry_smoke, "run_telemetry_smoke", lambda timeout_sec=45: 73)
    monkeypatch.setattr(falco_validate, "run_falco_validate", lambda as_json=False: 74)

    assert kubesentinel.main(["observability-deploy"]) == 71
    assert kubesentinel.main(["observability-validate"]) == 72
    assert kubesentinel.main(["telemetry-smoke"]) == 73
    assert kubesentinel.main(["falco-validate"]) == 74
