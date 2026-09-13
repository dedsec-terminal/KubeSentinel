"""Automated tests for KubeSentinel CLI compose-up, compose-down, and smoke commands."""

from __future__ import annotations

import io
import subprocess
import sys
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

import pytest

from scripts import compose, kubesentinel, smoke
from scripts.compose import is_docker_available

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[2]


# =====================================================================
# Unit & Functional Argument Tests
# =====================================================================


def test_cli_compose_up_help() -> None:
    """Verify compose-up --help displays usage and expected arguments."""
    out = io.StringIO()
    with redirect_stdout(out), pytest.raises(SystemExit) as exc_info:
        kubesentinel.main(["compose-up", "--help"])

    assert exc_info.value.code == 0
    content = out.getvalue()
    assert "compose-up" in content
    assert "--build" in content
    assert "--timeout" in content


def test_cli_compose_down_help() -> None:
    """Verify compose-down --help displays usage and expected volume options."""
    out = io.StringIO()
    with redirect_stdout(out), pytest.raises(SystemExit) as exc_info:
        kubesentinel.main(["compose-down", "--help"])

    assert exc_info.value.code == 0
    content = out.getvalue()
    assert "compose-down" in content
    assert "--volumes" in content or "-v" in content
    assert "--no-volumes" in content


def test_cli_smoke_help() -> None:
    """Verify smoke --help displays usage and expected timeout option."""
    out = io.StringIO()
    with redirect_stdout(out), pytest.raises(SystemExit) as exc_info:
        kubesentinel.main(["smoke", "--help"])

    assert exc_info.value.code == 0
    content = out.getvalue()
    assert "smoke" in content
    assert "--timeout" in content


def test_compose_up_subcommand_delegation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify compose-up subcommand parses arguments and delegates to scripts.compose.compose_up."""
    calls: list[dict[str, Any]] = []

    def mock_compose_up(root_dir: Path, build: bool = False, timeout_sec: int = 30) -> int:
        calls.append({"root_dir": root_dir, "build": build, "timeout_sec": timeout_sec})
        return 0

    monkeypatch.setattr(compose, "compose_up", mock_compose_up)

    ret = kubesentinel.main(["compose-up", "--build", "--timeout", "45"])
    assert ret == 0
    assert len(calls) == 1
    assert calls[0]["root_dir"] == ROOT
    assert calls[0]["build"] is True
    assert calls[0]["timeout_sec"] == 45


def test_compose_down_subcommand_delegation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify compose-down subcommand parses arguments and delegates to scripts.compose.compose_down."""
    calls: list[dict[str, Any]] = []

    def mock_compose_down(root_dir: Path, volumes: bool = True) -> int:
        calls.append({"root_dir": root_dir, "volumes": volumes})
        return 0

    monkeypatch.setattr(compose, "compose_down", mock_compose_down)

    ret = kubesentinel.main(["compose-down", "--no-volumes"])
    assert ret == 0
    assert len(calls) == 1
    assert calls[0]["root_dir"] == ROOT
    assert calls[0]["volumes"] is False


def test_smoke_subcommand_delegation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify smoke subcommand parses arguments and delegates to scripts.smoke.run_smoke."""
    calls: list[dict[str, Any]] = []

    def mock_run_smoke(root_dir: Path, timeout_sec: int = 30) -> int:
        calls.append({"root_dir": root_dir, "timeout_sec": timeout_sec})
        return 0

    monkeypatch.setattr(smoke, "run_smoke", mock_run_smoke)

    ret = kubesentinel.main(["smoke", "--timeout", "20"])
    assert ret == 0
    assert len(calls) == 1
    assert calls[0]["root_dir"] == ROOT
    assert calls[0]["timeout_sec"] == 20


# =====================================================================
# Live Integration Test: compose-up -> smoke -> compose-down
# =====================================================================


def test_live_compose_lifecycle_and_smoke() -> None:
    """Execute live kubesentinel compose-up, smoke, and compose-down end-to-end."""
    if not is_docker_available():
        pytest.skip("Docker daemon not available for live compose lifecycle testing.")

    try:
        # 1. Start compose stack
        up_res = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "kubesentinel.py"), "compose-up"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        assert up_res.returncode == 0, f"compose-up failed:\n{up_res.stderr}\n{up_res.stdout}"
        assert "Compose stack is up and operational" in up_res.stdout

        # 2. Run deterministic smoke test
        smoke_res = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "kubesentinel.py"), "smoke"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        assert smoke_res.returncode == 0, f"smoke failed:\n{smoke_res.stderr}\n{smoke_res.stdout}"
        assert "Milestone B deterministic end-to-end smoke verification PASSED" in smoke_res.stdout
        assert "HTTP 202 Accepted" in smoke_res.stdout
        assert "0 pending entries (PEL cleared)" in smoke_res.stdout

    finally:
        # 3. Clean teardown with compose-down
        down_res = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "kubesentinel.py"), "compose-down"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        assert down_res.returncode == 0, f"compose-down failed:\n{down_res.stderr}\n{down_res.stdout}"
        assert "Compose stack stopped" in down_res.stdout
