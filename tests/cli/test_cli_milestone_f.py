"""Unit tests for KubeSentinel Milestone F CLI additions."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from scripts.kubesentinel import main
from simulations.base import SimulationResult


def test_cli_simulate_help(capsys: pytest.CaptureFixture) -> None:
    """Verify simulate subcommand help output."""
    with pytest.raises(SystemExit) as exc:
        main(["simulate", "--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "simulate" in captured.out
    assert "redis-unauthorized" in captured.out
    assert "shell" in captured.out


def test_cli_detection_validate_help(capsys: pytest.CaptureFixture) -> None:
    """Verify detection-validate subcommand help output."""
    with pytest.raises(SystemExit) as exc:
        main(["detection-validate", "--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "detection-validate" in captured.out
    assert "--no-es" in captured.out
    assert "--json" in captured.out


def test_cli_simulate_invalid_scenario() -> None:
    """Verify simulate rejects unknown scenario name."""
    with pytest.raises(SystemExit) as exc:
        main(["simulate", "invalid-scenario-xyz"])
    assert exc.value.code != 0


def test_cli_simulate_mock_single_scenario(capsys: pytest.CaptureFixture) -> None:
    """Verify simulate runs single scenario and formats output."""
    mock_result = SimulationResult(
        scenario="shell",
        status="PASS",
        control_type="detection",
        summary="Mocked shell pass",
        details={},
        duration_sec=0.42,
        metadata_path="simulations/shell/metadata.yaml",
    )

    with patch("simulations.runner.run_simulation", return_value=mock_result) as mock_run:
        code = main(["simulate", "shell"])
        assert code == 0
        mock_run.assert_called_once_with("shell", timeout_sec=30.0)

    captured = capsys.readouterr()
    assert "[PASS]" in captured.out
    assert "shell" in captured.out
    assert "Summary: Total=1 PASS=1 FAIL=0" in captured.out


def test_cli_simulate_mock_all_scenarios(capsys: pytest.CaptureFixture) -> None:
    """Verify simulate runs all scenarios when 'all' is passed."""
    mock_results = [
        SimulationResult(
            scenario=scen,
            status="PASS",
            control_type="prevention",
            summary=f"Mocked {scen} pass",
            details={},
            duration_sec=0.1,
            metadata_path=f"simulations/{scen}/metadata.yaml",
        )
        for scen in ["shell", "redis-unauthorized", "rbac-denial", "insecure-deployment", "lateral-access"]
    ]

    with patch("simulations.runner.run_all_simulations", return_value=mock_results) as mock_run:
        code = main(["simulate", "all"])
        assert code == 0
        mock_run.assert_called_once_with(timeout_sec=30.0)

    captured = capsys.readouterr()
    assert "Summary: Total=5 PASS=5 FAIL=0" in captured.out


def test_cli_simulate_json_output(capsys: pytest.CaptureFixture) -> None:
    """Verify simulate --json emits machine-readable JSON."""
    mock_result = SimulationResult(
        scenario="rbac-denial",
        status="PASS",
        control_type="prevention",
        summary="Mocked RBAC pass",
        details={"status_code": 403},
        duration_sec=0.5,
        metadata_path="simulations/rbac_denial/metadata.yaml",
    )

    with patch("simulations.runner.run_simulation", return_value=mock_result):
        code = main(["simulate", "rbac-denial", "--json"])
        assert code == 0

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["scenario"] == "rbac-denial"
    assert data[0]["status"] == "PASS"


def test_cli_simulate_failure_exit_code(capsys: pytest.CaptureFixture) -> None:
    """Verify simulate returns 1 when a scenario fails."""
    mock_result = SimulationResult(
        scenario="shell",
        status="FAIL",
        control_type="detection",
        summary="Mocked failure",
        details={},
        duration_sec=1.0,
        metadata_path="simulations/shell/metadata.yaml",
    )

    with patch("simulations.runner.run_simulation", return_value=mock_result):
        code = main(["simulate", "shell"])
        assert code == 1

    captured = capsys.readouterr()
    assert "[FAIL]" in captured.out
    assert "Summary: Total=1 PASS=0 FAIL=1" in captured.out


def test_cli_detection_validate_offline(capsys: pytest.CaptureFixture) -> None:
    """Verify detection-validate --no-es passes offline."""
    code = main(["detection-validate", "--no-es"])
    assert code == 0
    captured = capsys.readouterr()
    assert "Detection Rules (3 rules):" in captured.out
    assert "Tuning Study Artifacts:" in captured.out
    assert "Summary: Total=5 PASS=5 FAIL=0" in captured.out


def test_cli_detection_validate_json_offline(capsys: pytest.CaptureFixture) -> None:
    """Verify detection-validate --no-es --json emits valid JSON."""
    code = main(["detection-validate", "--no-es", "--json"])
    assert code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["passed"] is True
    assert len(data["detections"]) >= 3
    assert data["tuning_metrics"]["valid"] is True
    assert data["tuning_documentation"]["valid"] is True
