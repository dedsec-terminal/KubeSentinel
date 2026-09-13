"""Unit tests for KubeSentinel Lifecycle Orchestration (setup & teardown)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.kubesentinel import main
from scripts.lifecycle import (
    check_port_free,
    preflight_checks,
    run_teardown,
)


def test_setup_cli_help(capsys: pytest.CaptureFixture) -> None:
    """Verify setup subcommand help output."""
    with pytest.raises(SystemExit) as exc:
        main(["setup", "--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "setup" in captured.out
    assert "--timeout" in captured.out
    assert "--skip-build" in captured.out


def test_teardown_cli_help(capsys: pytest.CaptureFixture) -> None:
    """Verify teardown subcommand help output."""
    with pytest.raises(SystemExit) as exc:
        main(["teardown", "--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "teardown" in captured.out
    assert "--purge-secrets" in captured.out
    assert "--keep-cluster" in captured.out


def test_demo_cli_help(capsys: pytest.CaptureFixture) -> None:
    """Verify demo subcommand help output."""
    with pytest.raises(SystemExit) as exc:
        main(["demo", "--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "demo" in captured.out


def test_check_port_free() -> None:
    """Verify port availability check function returns boolean."""
    # High unassigned ephemeral port should generally be free
    result = check_port_free(59999)
    assert isinstance(result, bool)


def test_preflight_checks() -> None:
    """Verify preflight check runs and reports structured checks."""
    res = preflight_checks()
    assert "passed" in res
    assert "details" in res
    check_names = [d["check"] for d in res["details"]]
    assert any("docker" in name for name in check_names)
    assert any("disk" in name for name in check_names)


def test_teardown_mocked(tmp_path: Path) -> None:
    """Verify run_teardown safely invokes cluster and compose cleanup."""
    with (
        patch("scripts.lifecycle.cluster_exists", return_value=True),
        patch("scripts.lifecycle.cluster_delete", return_value=0) as mock_delete,
        patch("scripts.compose.compose_down", return_value=0) as mock_compose,
        patch("scripts.lifecycle.ROOT", tmp_path),
    ):
        rc = run_teardown(purge_secrets=False, keep_cluster=False)
        assert rc == 0
        mock_delete.assert_called_once_with("kubesentinel")
        mock_compose.assert_called_once()


def test_teardown_keep_cluster_mocked(tmp_path: Path) -> None:
    """Verify run_teardown stops cluster when --keep-cluster is requested."""
    with (
        patch("scripts.lifecycle.cluster_exists", return_value=True),
        patch("scripts.lifecycle.cluster_stop", return_value=0) as mock_stop,
        patch("scripts.compose.compose_down", return_value=0),
        patch("scripts.lifecycle.ROOT", tmp_path),
    ):
        rc = run_teardown(purge_secrets=False, keep_cluster=True)
        assert rc == 0
        mock_stop.assert_called_once_with("kubesentinel")


def test_teardown_purge_secrets_mocked(tmp_path: Path) -> None:
    """Verify run_teardown removes local secret files when purge_secrets=True."""
    dummy_env = tmp_path / ".env.local"
    dummy_acl = tmp_path / "users.acl"
    dummy_env.write_text("DUMMY_SECRET=123", encoding="utf-8")
    dummy_acl.write_text("user default off", encoding="utf-8")

    with (
        patch("scripts.lifecycle.cluster_exists", return_value=False),
        patch("scripts.compose.compose_down", return_value=0),
        patch("scripts.lifecycle.ROOT", tmp_path),
    ):
        rc = run_teardown(purge_secrets=True)
        assert rc == 0
        assert not dummy_env.exists()
