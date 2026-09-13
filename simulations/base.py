"""Base classes and data models for KubeSentinel security simulations."""

from __future__ import annotations

import abc
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass
class SimulationResult:
    """Standard result structure for all KubeSentinel simulation runs."""

    scenario: str
    status: str  # "PASS" or "FAIL"
    control_type: str  # "detection" or "prevention"
    summary: str
    details: dict[str, Any]
    duration_sec: float
    metadata_path: str

    def to_dict(self) -> dict[str, Any]:
        """Convert simulation result to dictionary."""
        return asdict(self)


class BaseSimulation(abc.ABC):
    """Abstract base class for all security simulation scenarios."""

    scenario_name: str
    control_type: str  # "detection" or "prevention"

    @property
    @abc.abstractmethod
    def metadata_file(self) -> Path:
        """Return the path to the scenario metadata YAML file."""
        raise NotImplementedError

    @abc.abstractmethod
    def run(self, timeout_sec: float = 30.0) -> SimulationResult:
        """Execute the simulation scenario and return the result."""
        raise NotImplementedError
