from __future__ import annotations

import json
import subprocess

from scripts.validate import doctor

AVAILABLE_TOOLS = {
    "docker",
    "git",
    "k3d",
    "kubectl",
    "powershell.exe",
    "python",
    "wsl.exe",
}


def which(tool: str) -> str | None:
    return f"C:\\tools\\{tool}" if tool in AVAILABLE_TOOLS else None


def package_version(package: str) -> str:
    return doctor.EXPECTED_PACKAGES[package]


def make_runner(
    overrides: dict[tuple[str, ...], tuple[int, str, str]] | None = None,
):
    calls: list[tuple[str, ...]] = []
    responses = {
        ("python", "--version"): (0, "Python 3.14.2", ""),
        ("git", "--version"): (0, "git version 2.47.1.windows.2", ""),
        ("docker", "--version"): (0, "Docker version 29.7.2", ""),
        ("docker", "info", "--format", "{{.ServerVersion}}"): (0, "29.7.2", ""),
        (
            "docker",
            "info",
            "--format",
            "{{.NCPU}} CPUs / {{.MemTotal}} bytes",
        ): (0, "6 CPUs / 6213980160 bytes", ""),
        ("kubectl", "version", "--client", "--output=json"): (
            0,
            '{"clientVersion":{"gitVersion":"v1.36.1"}}',
            "",
        ),
        ("kubectl", "config", "current-context"): (1, "", "not set"),
        ("k3d", "version"): (0, "k3d version v5.9.0", ""),
        ("k3d", "cluster", "list", "--no-headers"): (0, "", ""),
        ("wsl.exe", "--status"): (0, "Default Version: 2", ""),
        ("wsl.exe", "--list", "--verbose"): (0, "Ubuntu-24.04 Stopped 2", ""),
    }
    responses.update(overrides or {})

    def runner(args: list[str], timeout: float = 8) -> tuple[int, str, str]:
        del timeout
        command = tuple(args)
        calls.append(command)
        if command[:3] == ("powershell.exe", "-NoProfile", "-Command"):
            return 0, "16400000,3000000", ""
        return responses.get(command, (0, "ok", ""))

    return calls, runner


def by_name(checks: list[dict[str, str]], name: str) -> dict[str, str]:
    return next(check for check in checks if check["name"] == name)


def collect(runner, probe=lambda _port: False, **kwargs):
    return doctor.collect_checks(
        runner=runner,
        probe=probe,
        environ={"ComSpec": "powershell.exe"},
        which=which,
        package_version=package_version,
        system_name="Windows",
        python_version=(3, 14),
        **kwargs,
    )


def test_expected_milestone_a_absences_are_non_fatal() -> None:
    calls, runner = make_runner()

    checks = collect(runner)

    assert by_name(checks, "Helm")["status"] == doctor.WARN
    assert by_name(checks, "Make")["status"] == doctor.SKIP
    assert by_name(checks, "kind")["status"] == doctor.SKIP
    assert by_name(checks, "Kubernetes context")["status"] == doctor.WARN
    assert by_name(checks, "Kubernetes cluster")["status"] == doctor.WARN
    assert by_name(checks, "k3d clusters")["status"] == doctor.WARN
    assert by_name(checks, "kubectl")["detail"] == "v1.36.1"
    assert doctor.exit_code(checks) == 0
    assert ("kubectl", "version", "--client", "--output=json") in calls
    assert ("k3d", "version") in calls
    assert ("k3d", "cluster", "list", "--no-headers") in calls


def test_missing_required_tool_causes_failure() -> None:
    _calls, runner = make_runner()

    def missing_docker(tool: str) -> str | None:
        return None if tool == "docker" else which(tool)

    checks = doctor.collect_checks(
        runner=runner,
        probe=lambda _port: False,
        environ={"ComSpec": "powershell.exe"},
        which=missing_docker,
        package_version=package_version,
        system_name="Windows",
        python_version=(3, 14),
    )

    assert by_name(checks, "Docker CLI")["status"] == doctor.FAIL
    assert by_name(checks, "Docker daemon")["status"] == doctor.FAIL
    assert doctor.exit_code(checks) == 1


def test_required_tool_timeout_is_reported_as_failure() -> None:
    _calls, runner = make_runner({("k3d", "version"): (124, "", "timeout")})

    checks = collect(runner)

    k3d = by_name(checks, "k3d")
    assert k3d["status"] == doctor.FAIL
    assert "timed out" in k3d["detail"]
    assert doctor.exit_code(checks) == 1


def test_occupied_future_port_warns_without_failing() -> None:
    _calls, runner = make_runner()

    checks = collect(runner, probe=lambda port: port == 9200)

    assert by_name(checks, "Port 9200")["status"] == doctor.WARN
    assert doctor.exit_code(checks) == 0


def test_unsupported_python_version_fails() -> None:
    _calls, runner = make_runner()

    checks = doctor.collect_checks(
        runner=runner,
        probe=lambda _port: False,
        environ={"ComSpec": "powershell.exe"},
        which=which,
        package_version=package_version,
        system_name="Windows",
        python_version=(3, 15),
    )

    assert by_name(checks, "Python")["status"] == doctor.FAIL
    assert doctor.exit_code(checks) == 1


def test_json_output_includes_summary_and_success_exit(monkeypatch, capsys) -> None:
    checks = [
        {"name": "required", "status": doctor.PASS, "detail": "ok"},
        {"name": "future", "status": doctor.WARN, "detail": "deferred"},
    ]
    monkeypatch.setattr(doctor, "collect_checks", lambda: checks)

    assert doctor.main(["--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["checks"] == checks
    assert payload["summary"] == {"PASS": 1, "WARN": 1, "FAIL": 0, "SKIP": 0}


def test_json_output_returns_failure_exit(monkeypatch, capsys) -> None:
    checks = [{"name": "required", "status": doctor.FAIL, "detail": "missing"}]
    monkeypatch.setattr(doctor, "collect_checks", lambda: checks)

    assert doctor.main(["--json"]) == 1
    assert json.loads(capsys.readouterr().out)["summary"]["FAIL"] == 1


def test_run_command_distinguishes_timeout(monkeypatch) -> None:
    def raise_timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd=["slow"], timeout=1)

    monkeypatch.setattr(doctor.subprocess, "run", raise_timeout)

    assert doctor.run_command(["slow"], timeout=1) == (124, "", "timeout")
