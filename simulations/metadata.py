"""Metadata loader and schema validator for KubeSentinel security simulations."""

from __future__ import annotations

from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_METADATA_FIELDS = [
    "scenario",
    "description",
    "hypothesis",
    "controls_tested",
    "control_type",
    "mitre_attack",
    "expected_result",
    "observed_result",
    "cleanup",
    "limitations",
]

SCENARIO_DIRS = {
    "shell": "shell",
    "redis-unauthorized": "redis_unauthorized",
    "redis_unauthorized": "redis_unauthorized",
    "rbac-denial": "rbac_denial",
    "rbac_denial": "rbac_denial",
    "insecure-deployment": "insecure_deployment",
    "insecure_deployment": "insecure_deployment",
    "lateral-access": "lateral_access",
    "lateral_access": "lateral_access",
}


def parse_metadata_yaml(path: Path | str) -> dict[str, Any]:
    """Parse a simulation metadata.yaml file into a structured dictionary without external dependencies."""
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"Metadata file not found: {file_path}")

    content = file_path.read_text(encoding="utf-8")
    data: dict[str, Any] = {}
    current_list: str | None = None
    current_dict: str | None = None

    for raw_line in content.splitlines():
        line = raw_line.rstrip()
        if not line or line.startswith("#"):
            continue

        # Handle list item under current list key (indent: 2 spaces, starts with '- ')
        if line.startswith("  - "):
            if current_list is not None:
                val = line[4:].strip().strip("\"'")
                data[current_list].append(val)
            continue

        # Handle nested dictionary entry under current dict key (indent: 2 spaces, key: val)
        if line.startswith("  ") and not line.startswith("    ") and current_dict is not None and ":" in line:
            k, v = line.strip().split(":", 1)
            k = k.strip()
            v = v.strip().strip("\"'")
            data[current_dict][k] = v
            continue

        # Top-level key-value or start of section
        current_list = None
        current_dict = None

        if ":" in line:
            k, v = line.split(":", 1)
            key = k.strip()
            val = v.strip().strip("\"'")

            if not val:
                # Distinguish list header vs dictionary header
                if key == "controls_tested":
                    data[key] = []
                    current_list = key
                elif key == "mitre_attack":
                    data[key] = {}
                    current_dict = key
                else:
                    data[key] = {}
                    current_dict = key
            else:
                data[key] = val

    return data


def load_scenario_metadata(scenario_name: str) -> dict[str, Any]:
    """Load and parse metadata for a scenario by name."""
    norm_name = scenario_name.strip().lower()
    sub_dir = SCENARIO_DIRS.get(norm_name)
    if not sub_dir:
        raise ValueError(f"Unknown scenario: {scenario_name}")
    meta_path = ROOT / "simulations" / sub_dir / "metadata.yaml"
    return parse_metadata_yaml(meta_path)


def validate_all_metadata() -> list[dict[str, Any]]:
    """Validate all 5 simulation scenario metadata files against required fields and constraints.

    Returns a list of validation check results (check, status, detail).
    """
    results: list[dict[str, Any]] = []
    canonical_scenarios = [
        ("shell", "shell"),
        ("redis-unauthorized", "redis_unauthorized"),
        ("rbac-denial", "rbac_denial"),
        ("insecure-deployment", "insecure_deployment"),
        ("lateral-access", "lateral_access"),
    ]

    for scenario_name, dir_name in canonical_scenarios:
        meta_path = ROOT / "simulations" / dir_name / "metadata.yaml"
        if not meta_path.is_file():
            results.append({
                "scenario": scenario_name,
                "check": f"metadata_exists:{scenario_name}",
                "status": "FAIL",
                "detail": f"metadata.yaml not found at {meta_path}",
            })
            continue

        try:
            data = parse_metadata_yaml(meta_path)
        except (OSError, ValueError, KeyError, IndexError) as exc:
            results.append({
                "scenario": scenario_name,
                "check": f"metadata_parse:{scenario_name}",
                "status": "FAIL",
                "detail": f"Failed to parse metadata.yaml: {exc}",
            })
            continue

        # Verify all required fields exist and are non-empty
        missing = [f for f in REQUIRED_METADATA_FIELDS if f not in data or not data[f]]
        if missing:
            results.append({
                "scenario": scenario_name,
                "check": f"metadata_required_fields:{scenario_name}",
                "status": "FAIL",
                "detail": f"Missing or empty required fields: {', '.join(missing)}",
            })
            continue

        # Verify control_type is valid
        control_type = data.get("control_type")
        if control_type not in ("prevention", "detection"):
            results.append({
                "scenario": scenario_name,
                "check": f"metadata_control_type:{scenario_name}",
                "status": "FAIL",
                "detail": f"Invalid control_type '{control_type}', expected 'prevention' or 'detection'",
            })
            continue

        # Verify mitre_attack structure
        mitre = data.get("mitre_attack", {})
        if not isinstance(mitre, dict) or not mitre.get("id") or not mitre.get("name"):
            results.append({
                "scenario": scenario_name,
                "check": f"metadata_mitre_attack:{scenario_name}",
                "status": "FAIL",
                "detail": f"Invalid mitre_attack structure: {mitre}",
            })
            continue

        # Verify controls_tested is a non-empty list
        controls = data.get("controls_tested", [])
        if not isinstance(controls, list) or len(controls) == 0:
            results.append({
                "scenario": scenario_name,
                "check": f"metadata_controls_tested:{scenario_name}",
                "status": "FAIL",
                "detail": f"controls_tested must be a non-empty list: {controls}",
            })
            continue

        results.append({
            "scenario": scenario_name,
            "check": f"metadata_valid:{scenario_name}",
            "status": "PASS",
            "detail": f"Metadata valid ({data.get('control_type')}, MITRE {mitre.get('id')}, controls: {', '.join(controls)})",
        })

    return results
