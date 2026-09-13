"""Central simulation dispatcher and runner API for KubeSentinel Milestone F."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from simulations.base import BaseSimulation, SimulationResult
from simulations.insecure_deployment.runner import InsecureDeploymentSimulation
from simulations.lateral_access.runner import LateralAccessSimulation
from simulations.rbac_denial.runner import RbacDenialSimulation
from simulations.redis_unauthorized.runner import RedisUnauthorizedSimulation
from simulations.shell.runner import ShellSimulation

SIMULATION_REGISTRY: dict[str, type[BaseSimulation]] = {
    "shell": ShellSimulation,
    "redis-unauthorized": RedisUnauthorizedSimulation,
    "redis_unauthorized": RedisUnauthorizedSimulation,
    "rbac-denial": RbacDenialSimulation,
    "rbac_denial": RbacDenialSimulation,
    "insecure-deployment": InsecureDeploymentSimulation,
    "insecure_deployment": InsecureDeploymentSimulation,
    "lateral-access": LateralAccessSimulation,
    "lateral_access": LateralAccessSimulation,
}

CANONICAL_SCENARIOS = [
    "shell",
    "redis-unauthorized",
    "rbac-denial",
    "insecure-deployment",
    "lateral-access",
]


def list_simulations() -> list[str]:
    """Return the ordered list of canonical simulation scenario names."""
    return list(CANONICAL_SCENARIOS)


def get_simulation(name: str) -> BaseSimulation:
    """Instantiate a simulation scenario runner by name."""
    norm_name = name.strip().lower()
    cls = SIMULATION_REGISTRY.get(norm_name)
    if not cls:
        raise ValueError(
            f"Unknown simulation scenario '{name}'. Available scenarios: {', '.join(CANONICAL_SCENARIOS)}"
        )
    return cls()


def run_simulation(scenario_name: str, timeout_sec: float = 30.0) -> SimulationResult:
    """Execute a single security simulation scenario by name."""
    sim = get_simulation(scenario_name)
    return sim.run(timeout_sec=timeout_sec)


def run_all_simulations(timeout_sec: float = 30.0) -> list[SimulationResult]:
    """Execute all 5 canonical security simulation scenarios in sequence."""
    results: list[SimulationResult] = []
    for name in CANONICAL_SCENARIOS:
        sim = get_simulation(name)
        res = sim.run(timeout_sec=timeout_sec)
        results.append(res)
    return results


def load_scenario_metadata(scenario_name: str) -> dict:
    """Load machine-readable metadata for a scenario."""
    from simulations.metadata import load_scenario_metadata as _load

    return _load(scenario_name)


def validate_all_metadata() -> list[dict]:
    """Validate all 5 scenario metadata files against required fields."""
    from simulations.metadata import validate_all_metadata as _val

    return _val()


def main(argv: list[str] | None = None) -> int:
    """CLI handler for simulation execution."""
    parser = argparse.ArgumentParser(
        prog="kubesentinel-simulate",
        description="Execute controlled security simulations for KubeSentinel Milestone F.",
    )
    parser.add_argument(
        "scenario",
        nargs="?",
        default="all",
        choices=CANONICAL_SCENARIOS + ["all"],
        help="Scenario to execute (default: all)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit simulation results as machine-readable JSON",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Timeout in seconds per scenario (default: 30.0)",
    )

    args = parser.parse_args(argv)

    if args.scenario == "all":
        results = run_all_simulations(timeout_sec=args.timeout)
    else:
        results = [run_simulation(args.scenario, timeout_sec=args.timeout)]

    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        print("\n=======================================================")
        print(" KubeSentinel Milestone F: Controlled Simulations")
        print("=======================================================\n")
        for r in results:
            tag = f"[{r.status}]".ljust(8)
            scen = r.scenario.ljust(22)
            ctrl = f"({r.control_type})".ljust(14)
            print(f"{tag} {scen} {ctrl} {r.summary} ({r.duration_sec}s)")

        total = len(results)
        passed = sum(1 for r in results if r.status == "PASS")
        failed = sum(1 for r in results if r.status == "FAIL")
        print(f"\nSummary: Total={total} PASS={passed} FAIL={failed}\n")

    return 1 if any(r.status == "FAIL" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
