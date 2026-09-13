"""Unit tests for KubeSentinel Milestone F simulation package."""

from __future__ import annotations

from pathlib import Path

import pytest

from simulations.base import BaseSimulation, SimulationResult
from simulations.metadata import (
    REQUIRED_METADATA_FIELDS,
    load_scenario_metadata,
    validate_all_metadata,
)
from simulations.runner import (
    CANONICAL_SCENARIOS,
    get_simulation,
    list_simulations,
)

ROOT = Path(__file__).resolve().parents[2]


def test_list_simulations() -> None:
    """Verify list_simulations returns all 5 canonical scenarios in order."""
    scenarios = list_simulations()
    expected = [
        "shell",
        "redis-unauthorized",
        "rbac-denial",
        "insecure-deployment",
        "lateral-access",
    ]
    assert scenarios == expected
    assert len(scenarios) == 5


@pytest.mark.parametrize("scenario_name", CANONICAL_SCENARIOS)
def test_get_simulation_instances(scenario_name: str) -> None:
    """Verify get_simulation instantiates correct BaseSimulation instances."""
    sim = get_simulation(scenario_name)
    assert isinstance(sim, BaseSimulation)
    assert sim.scenario_name == scenario_name
    assert sim.metadata_file.is_file()
    assert sim.control_type in ("prevention", "detection")


def test_get_simulation_invalid_name() -> None:
    """Verify get_simulation raises ValueError for unknown scenarios."""
    with pytest.raises(ValueError, match="Unknown simulation scenario"):
        get_simulation("non-existent-scenario")


@pytest.mark.parametrize("scenario_name", CANONICAL_SCENARIOS)
def test_scenario_metadata_integrity(scenario_name: str) -> None:
    """Verify all scenario metadata files exist and contain all 10 required fields."""
    meta = load_scenario_metadata(scenario_name)
    assert isinstance(meta, dict)

    for field in REQUIRED_METADATA_FIELDS:
        assert field in meta, f"Missing required field '{field}' in scenario '{scenario_name}'"
        val = meta[field]
        assert val is not None, f"Field '{field}' is None in scenario '{scenario_name}'"
        if isinstance(val, (str, list, dict)):
            assert len(val) > 0, f"Field '{field}' is empty in scenario '{scenario_name}'"

    # MITRE ATT&CK sub-fields (id and name)
    attack = meta["mitre_attack"]
    assert str(attack.get("id", "")).startswith("T")
    assert bool(attack.get("name"))

    # Control type must be prevention or detection
    assert meta["control_type"] in ("prevention", "detection")

    # Controls tested must be a list
    assert isinstance(meta["controls_tested"], list)
    assert len(meta["controls_tested"]) > 0


def test_validate_all_metadata_passes() -> None:
    """Verify validate_all_metadata reports PASS for all 5 scenarios."""
    results = validate_all_metadata()
    assert len(results) == 5
    for r in results:
        assert r["status"] == "PASS", f"Scenario {r['scenario']} failed metadata validation: {r['detail']}"


def test_simulation_result_dataclass() -> None:
    """Verify SimulationResult dataclass behavior and serialization."""
    res = SimulationResult(
        scenario="shell",
        status="PASS",
        control_type="detection",
        summary="Test summary",
        details={"test_key": "test_val"},
        duration_sec=1.23,
        metadata_path="simulations/shell/metadata.yaml",
    )
    d = res.to_dict()
    assert d["scenario"] == "shell"
    assert d["status"] == "PASS"
    assert d["control_type"] == "detection"
    assert d["summary"] == "Test summary"
    assert d["details"] == {"test_key": "test_val"}
    assert d["duration_sec"] == 1.23
    assert d["metadata_path"] == "simulations/shell/metadata.yaml"


def test_insecure_deployment_fixture_exists() -> None:
    """Verify insecure deployment violating manifest fixture exists and contains required violations."""
    fixture_path = (
        ROOT
        / "simulations"
        / "insecure_deployment"
        / "fixtures"
        / "violating-workload.yaml"
    )
    assert fixture_path.is_file(), f"Fixture not found at {fixture_path}"
    content = fixture_path.read_text(encoding="utf-8")
    assert "sim-insecure-workload" in content
    assert "kubesentinel-edge-api:latest" in content  # Violates disallow-latest-tag
    assert "resources:" not in content  # Violates require-resource-requests-limits
