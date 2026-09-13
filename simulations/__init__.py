"""KubeSentinel Milestone F Controlled Simulations Package."""

from __future__ import annotations

from typing import Any

from simulations.base import BaseSimulation, SimulationResult


def run_simulation(scenario_name: str, timeout_sec: float = 30.0) -> SimulationResult:
    """Execute a single security simulation scenario by name."""
    from simulations.runner import run_simulation as _run_simulation

    return _run_simulation(scenario_name, timeout_sec=timeout_sec)


def run_all_simulations(timeout_sec: float = 30.0) -> list[SimulationResult]:
    """Execute all canonical security simulation scenarios."""
    from simulations.runner import run_all_simulations as _run_all_simulations

    return _run_all_simulations(timeout_sec=timeout_sec)


def list_simulations() -> list[str]:
    """Return list of canonical simulation scenario names."""
    from simulations.runner import list_simulations as _list_simulations

    return _list_simulations()


def load_scenario_metadata(scenario_name: str) -> dict[str, Any]:
    """Load and parse machine-readable metadata for a scenario."""
    from simulations.metadata import load_scenario_metadata as _load

    return _load(scenario_name)


def validate_all_metadata() -> list[dict[str, Any]]:
    """Validate all 5 scenario metadata files against required fields."""
    from simulations.metadata import validate_all_metadata as _val

    return _val()


__all__ = [
    "BaseSimulation",
    "SimulationResult",
    "list_simulations",
    "load_scenario_metadata",
    "run_all_simulations",
    "run_simulation",
    "validate_all_metadata",
]
