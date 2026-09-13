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
