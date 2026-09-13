"""Host and tool readiness checks for KubeSentinel (standard library only)."""

from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import subprocess
import sys
from collections.abc import Callable
from importlib import metadata
from pathlib import Path
from typing import Any

PASS, WARN, FAIL, SKIP = "PASS", "WARN", "FAIL", "SKIP"
Runner = Callable[..., Any]
SELECTED_CLUSTER_TOOL = "k3d"
EXPECTED_K3D_VERSION = "5.9.0"
EXPECTED_PACKAGES = {"fastapi": "0.141.1", "uvicorn": "0.52.4"}
PORTS = (6379, 6443, 8000, 8080, 9200, 5601)
COMMAND_TIMEOUT = 20


def _clean_output(value: str | None) -> str:
    """Normalize command output, including UTF-16-like WSL output on Windows."""
    return (value or "").replace("\ufeff", "").replace("\x00", "").strip()


def run_command(args: list[str], timeout: float = COMMAND_TIMEOUT) -> tuple[int, str, str]:
    """Run a bounded command without raising for missing tools or timeouts."""
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                           check=False, encoding="utf-8", errors="replace")
        return p.returncode, _clean_output(p.stdout), _clean_output(p.stderr)
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except OSError as exc:
        return 127, "", str(exc)


def _result(name: str, status: str, detail: str = "") -> dict[str, str]:
    return {"name": name, "status": status, "detail": detail}


def _detail(code: int, stdout: str, stderr: str) -> str:
    if code == 124:
        return "command timed out"
    output = _clean_output(stdout or stderr)
    if not output:
        return "unusable"
    if output.startswith("{"):
        try:
            payload = json.loads(output)
            client_version = payload.get("clientVersion", {}).get("gitVersion")
            if client_version:
                return client_version
        except (AttributeError, json.JSONDecodeError):
            pass
    return " ".join(output.split())[:240]


def _tool(
    name: str,
    command: str,
    runner: Runner,
    args: list[str] | None = None,
    *,
    required: bool = False,
    which: Callable[[str], str | None] = shutil.which,
) -> dict[str, str]:
    path = which(command)
    if not path:
        return _result(name, FAIL if required else WARN, "not found")
    code, out, err = runner(
        [command] + (args or ["--version"]), timeout=COMMAND_TIMEOUT
    )
    status = PASS if code == 0 else (FAIL if required else WARN)
    return _result(name, status, _detail(code, out, err))


def collect_checks(
    runner: Runner = run_command,
    probe: Callable[[int], Any] | None = None,
    environ: dict[str, str] | None = None,
    which: Callable[[str], str | None] | None = None,
    package_version: Callable[[str], str] | None = None,
    system_name: str | None = None,
    python_version: tuple[int, int] | None = None,
) -> list[dict[str, str]]:
    """Collect live readiness results without treating deferred components as failures."""
    env = os.environ if environ is None else environ
    which_fn = shutil.which if which is None else which
    version_fn = metadata.version if package_version is None else package_version
    system = platform.system() if system_name is None else system_name
    active_python = sys.version_info[:2] if python_version is None else python_version
    checks: list[dict[str, str]] = []

    shell = env.get("SHELL") or env.get("ComSpec", "unknown shell")
    platform_detail = f"{system} {platform.release()} ({platform.version()}) / {shell}"
    checks.append(_result("Platform", PASS, platform_detail))
    checks.append(
        _result(
            "WSL context",
            PASS if env.get("WSL_DISTRO_NAME") else SKIP,
            env.get("WSL_DISTRO_NAME", "native host process; not running inside WSL"),
        )
    )
    if system == "Windows":
        wsl_command = "wsl.exe" if which_fn("wsl.exe") else "wsl"
        if which_fn(wsl_command):
            status_code, status_out, status_err = runner(
                [wsl_command, "--status"], timeout=COMMAND_TIMEOUT
            )
            list_code, list_out, list_err = runner(
                [wsl_command, "--list", "--verbose"], timeout=COMMAND_TIMEOUT
            )
            status = PASS if status_code == 0 and list_code == 0 else WARN
            detail = _detail(
                status_code or list_code,
                f"{status_out} {list_out}",
                f"{status_err} {list_err}",
            )
            checks.append(_result("WSL2 availability", status, detail))
        else:
            checks.append(_result("WSL2 availability", WARN, "wsl.exe not found"))

    python_check = _tool(
        "Python", "python", runner, ["--version"], required=True, which=which_fn
    )
    if python_check["status"] == PASS and not ((3, 11) <= active_python < (3, 15)):
        python_check = _result(
            "Python",
            FAIL,
            f"unsupported {active_python[0]}.{active_python[1]}; requires >=3.11,<3.15",
        )
    checks.append(python_check)
    checks.append(_tool("Git", "git", runner, ["--version"], required=True, which=which_fn))

    docker_cli = _tool(
        "Docker CLI", "docker", runner, ["--version"], required=True, which=which_fn
    )
    checks.append(docker_cli)
    if docker_cli["status"] == PASS:
        code, out, err = runner(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            timeout=COMMAND_TIMEOUT,
        )
        checks.append(
            _result("Docker daemon", PASS if code == 0 else FAIL, _detail(code, out, err))
        )
    else:
        checks.append(_result("Docker daemon", FAIL, "Docker CLI unavailable"))

    kubectl_check = _tool(
        "kubectl",
        "kubectl",
        runner,
        ["version", "--client", "--output=json"],
        which=which_fn,
    )
    checks.append(kubectl_check)
    checks.append(
        _tool("Helm", "helm", runner, ["version", "--short"], which=which_fn)
    )

    k3d_check = _tool(
        "k3d", "k3d", runner, ["version"], required=True, which=which_fn
    )
    if k3d_check["status"] == PASS and f"v{EXPECTED_K3D_VERSION}" not in k3d_check["detail"]:
        k3d_check = _result(
            "k3d",
            FAIL,
            f"unexpected version; expected v{EXPECTED_K3D_VERSION}: {k3d_check['detail']}",
        )
    checks.append(k3d_check)
    if k3d_check["status"] == PASS:
        code, out, err = runner(
            ["k3d", "cluster", "list", "--no-headers"], timeout=COMMAND_TIMEOUT
        )
        if code != 0:
            checks[-1] = _result("k3d", FAIL, _detail(code, out, err))
            checks.append(_result("k3d clusters", SKIP, "cluster listing unavailable"))
        else:
            detail = "none (expected in Milestone A)" if not out else _detail(code, out, err)
            checks.append(_result("k3d clusters", WARN, detail))
    else:
        checks.append(_result("k3d clusters", SKIP, "selected tool unavailable"))
    checks.append(_result("kind", SKIP, f"not selected; {SELECTED_CLUSTER_TOOL} is selected"))

    if which_fn("make"):
        checks.append(_tool("Make", "make", runner, ["--version"], which=which_fn))
    else:
        checks.append(_result("Make", SKIP, "optional convenience tool; not installed"))

    for package_name, expected_version in EXPECTED_PACKAGES.items():
        try:
            installed_version = version_fn(package_name)
        except metadata.PackageNotFoundError:
            checks.append(_result(f"runtime:{package_name}", FAIL, "not installed"))
        else:
            status = PASS if installed_version == expected_version else FAIL
            detail = (
                installed_version
                if status == PASS
                else f"expected {expected_version}; found {installed_version}"
            )
            checks.append(_result(f"runtime:{package_name}", status, detail))

    if kubectl_check["status"] == PASS:
        code, out, err = runner(
            ["kubectl", "config", "current-context"], timeout=COMMAND_TIMEOUT
        )
        has_context = code == 0 and bool(out)
        context_detail = out if has_context else "none (expected in Milestone A)"
        checks.append(_result("Kubernetes context", PASS if has_context else WARN, context_detail))
        if has_context:
            code, out, err = runner(
                ["kubectl", "cluster-info"], timeout=COMMAND_TIMEOUT
            )
            checks.append(
                _result(
                    "Kubernetes cluster",
                    PASS if code == 0 else WARN,
                    _detail(code, out, err),
                )
            )
        else:
            checks.append(
                _result("Kubernetes cluster", WARN, "none (expected in Milestone A)")
            )
    else:
        checks.extend(
            (
                _result("Kubernetes context", WARN, "kubectl unavailable"),
                _result("Kubernetes cluster", WARN, "kubectl unavailable"),
            )
        )

    try:
        free_disk = shutil.disk_usage(Path.cwd()).free
        status = PASS if free_disk >= 10 * 1024**3 else WARN
        checks.append(_result("Host disk", status, f"{free_disk / 1024**3:.1f} GiB free"))
    except OSError:
        checks.append(_result("Host disk", WARN, "resource probe unavailable"))

    powershell = "powershell.exe" if which_fn("powershell.exe") else "powershell"
    if system == "Windows" and which_fn(powershell):
        command = (
            "$os=Get-CimInstance Win32_OperatingSystem; "
            "'{0},{1}' -f $os.TotalVisibleMemorySize,$os.FreePhysicalMemory"
        )
        code, out, err = runner(
            [powershell, "-NoProfile", "-Command", command], timeout=COMMAND_TIMEOUT
        )
        try:
            total_kib, free_kib = (int(value) for value in out.split(",", maxsplit=1))
            total_gib = total_kib / (1024 * 1024)
            free_gib = free_kib / (1024 * 1024)
            status = PASS if free_gib >= 2 else WARN
            detail = f"{total_gib:.1f} GiB total / {free_gib:.1f} GiB free"
            checks.append(_result("Host RAM", status, detail))
        except (TypeError, ValueError):
            checks.append(_result("Host RAM", WARN, _detail(code, out, err)))
    else:
        checks.append(_result("Host RAM", WARN, "resource probe unavailable"))

    if docker_cli["status"] == PASS:
        code, out, err = runner(
            ["docker", "info", "--format", "{{.NCPU}} CPUs / {{.MemTotal}} bytes"],
            timeout=COMMAND_TIMEOUT,
        )
        checks.append(
            _result("Docker resources", PASS if code == 0 and out else WARN, _detail(code, out, err))
        )
    else:
        checks.append(_result("Docker resources", WARN, "resource limits indeterminate"))

    for port in PORTS:
        if probe is not None:
            occupied = bool(probe(port))
        else:
            with socket.socket() as sock:
                sock.settimeout(0.25)
                occupied = sock.connect_ex(("127.0.0.1", port)) == 0
        status = WARN if occupied else PASS
        detail = "occupied; informational for Milestone A" if occupied else "available"
        checks.append(_result(f"Port {port}", status, detail))

    checks.extend(
        _result(component, SKIP, "deferred beyond Milestone A")
        for component in ("Redis", "Elastic", "Fluent Bit", "Falco", "Kyverno")
    )
    return checks


def summarize(checks: list[dict[str, str]]) -> dict[str, int]:
    """Count results by status for stable human and JSON reporting."""
    return {
        status: sum(check["status"] == status for check in checks)
        for status in (PASS, WARN, FAIL, SKIP)
    }


def exit_code(checks: list[dict[str, str]]) -> int:
    """Return nonzero only when a prerequisite failure is present."""
    return 1 if any(check["status"] == FAIL for check in checks) else 0


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="kubesentinel-doctor")
    parser.add_argument("--json", action="store_true")
    ns = parser.parse_args(argv)
    checks = collect_checks()
    summary = summarize(checks)
    if ns.json:
        print(json.dumps({"checks": checks, "summary": summary}, sort_keys=True))
    else:
        for check in checks:
            print(f"{check['status']:<4} {check['name']}: {check['detail']}")
        print(
            "SUMMARY "
            + " ".join(f"{status}={summary[status]}" for status in (PASS, WARN, FAIL, SKIP))
        )
    return exit_code(checks)


if __name__ == "__main__":
    raise SystemExit(main())
