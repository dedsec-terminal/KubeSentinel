"""Unit tests for KubeSentinel Milestone F detection content and validation."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from detections.elastic.validator import (
    FIELDS_PATH,
    RULES_DIR,
    SCHEMA_PATH,
    load_fields_catalog,
    load_schema,
    parse_yaml,
    validate_detections,
)

ROOT = Path(__file__).resolve().parents[2]


def test_schema_json_is_valid_draft7() -> None:
    """Verify that schema.json exists and is a valid JSON Schema Draft 7."""
    assert SCHEMA_PATH.is_file()
    schema = load_schema()
    assert isinstance(schema, dict)
    jsonschema.Draft7Validator.check_schema(schema)
    assert schema.get("$schema") == "http://json-schema.org/draft-07/schema#"


def test_fields_catalog_loading() -> None:
    """Verify FIELDS.md exists and load_fields_catalog extracts documented fields."""
    assert FIELDS_PATH.is_file()
    catalog = load_fields_catalog()
    assert isinstance(catalog, set)
    assert len(catalog) >= 15

    # Check key Falco and App fields
    essential_fields = [
        "output_fields.k8s_ns_name",
        "output_fields.container_name",
        "output_fields.proc_cmdline",
        "output_fields.user_uid",
        "rule",
        "priority",
        "event_id",
        "severity",
        "edge_site",
        "service",
        "log_type",
    ]
    for ef in essential_fields:
        assert ef in catalog, f"Essential field '{ef}' missing from FIELDS.md catalog"


def test_parse_yaml_structures() -> None:
    """Verify built-in parse_yaml parser handles scalars, folded blocks, and nested lists."""
    sample_yaml = """
id: test-rule
severity: high
query: >
  rule:"test" AND field:value
tags:
  - T1059
  - test
mitre_attack:
  - tactic: execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
"""
    parsed = parse_yaml(sample_yaml)
    assert parsed["id"] == "test-rule"
    assert parsed["severity"] == "high"
    assert "rule:\"test\" AND field:value" in parsed["query"]
    assert parsed["tags"] == ["T1059", "test"]
    assert len(parsed["mitre_attack"]) == 1
    assert parsed["mitre_attack"][0]["tactic"] == "execution"
    assert parsed["mitre_attack"][0]["technique_id"] == "T1059"


def test_all_detection_rules_conform_to_schema() -> None:
    """Verify that all YAML detection rules in detections/elastic/rules/ pass schema validation."""
    schema = load_schema()
    rule_files = list(RULES_DIR.glob("*.yaml"))
    assert len(rule_files) >= 3, f"Expected at least 3 detection rules, found {len(rule_files)}"

    for rf in rule_files:
        data = parse_yaml(rf.read_text(encoding="utf-8"))
        jsonschema.validate(instance=data, schema=schema)
        assert data["id"]
        assert data["severity"] in ("low", "medium", "high", "critical")
        assert data["status"] in ("production", "validated", "experimental", "hunting")
        assert data["language"] in ("kql", "lucene", "eql", "esql")
        assert isinstance(data.get("mitre_attack", []), list)


def test_mitre_mappings_are_evidence_scoped() -> None:
    """Only the behavior-specific shell rule carries an ATT&CK mapping."""
    rules = {
        path.name: parse_yaml(path.read_text(encoding="utf-8"))
        for path in RULES_DIR.glob("*.yaml")
    }

    assert "mitre_attack" not in rules["high-severity-app-event.yaml"]
    assert "mitre_attack" not in rules["falco-runtime-alerts-general.yaml"]
    assert rules["unexpected-shell.yaml"]["mitre_attack"] == [
        {
            "tactic": "execution",
            "technique_id": "T1059.004",
            "technique_name": "Command and Scripting Interpreter: Unix Shell",
        }
    ]


def test_all_detection_rules_required_fields_documented() -> None:
    """Verify that every required_fields entry in all rules is documented in FIELDS.md."""
    catalog = load_fields_catalog()
    rule_files = list(RULES_DIR.glob("*.yaml"))

    for rf in rule_files:
        data = parse_yaml(rf.read_text(encoding="utf-8"))
        req_fields = data.get("required_fields", [])
        assert len(req_fields) > 0, f"Rule {rf.name} has no required_fields declared"
        for field in req_fields:
            assert field in catalog, f"Rule {rf.name} uses undocumented field '{field}'"


def test_validate_detections_offline() -> None:
    """Verify validate_detections passes offline (without Elasticsearch queries)."""
    passed, results = validate_detections(check_es=False)
    assert passed is True
    assert len(results) >= 3
    for r in results:
        assert r["schema_valid"] is True
        assert r["fields_valid"] is True
        assert len(r["errors"]) == 0


def test_schema_rejection_invalid_rule() -> None:
    """Verify the schema rejects invalid severity and missing core metadata."""
    schema = load_schema()
    invalid_data = {
        "id": "invalid-rule",
        "name": "Invalid Rule",
        "description": "Missing required fields",
        "severity": "ultra-critical",  # Invalid enum
        "status": "production",
        "index": "kubesentinel-falco-*",
        "language": "lucene",
        "query": "*",
        "required_fields": ["rule"],
        # Missing hypothesis, investigation guidance, and other core metadata.
    }
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=invalid_data, schema=schema)


def test_tuning_metrics_artifact_validity() -> None:
    """Verify that docs/detection-tuning/tuning_metrics.json exists and adheres to schema."""
    metrics_path = ROOT / "docs" / "detection-tuning" / "tuning_metrics.json"
    assert metrics_path.is_file(), "tuning_metrics.json does not exist"

    data = json.loads(metrics_path.read_text(encoding="utf-8"))
    required_keys = [
        "v1_query",
        "v2_query",
        "total_v1_events",
        "total_v2_events",
        "total_controlled_scenarios",
        "controlled_scenarios_retained_by_v2",
        "controlled_retention_rate_pct",
        "total_benign_maintenance_events",
        "benign_maintenance_suppressed_by_v2",
        "benign_suppression_rate_pct",
        "lab_noise_reduction_pct",
        "overall_candidate_reduction_pct",
    ]
    for k in required_keys:
        assert k in data, f"Missing key '{k}' in tuning_metrics.json"

    assert data["controlled_retention_rate_pct"] == 100.0
    assert data["benign_suppression_rate_pct"] == 100.0
    assert data["total_controlled_scenarios"] > 0
    assert data["total_benign_maintenance_events"] > 0


def test_tuning_study_documentation_exists() -> None:
    """Verify that docs/detection-tuning/shell-detection.md exists and contains expected sections."""
    doc_path = ROOT / "docs" / "detection-tuning" / "shell-detection.md"
    assert doc_path.is_file(), "shell-detection.md does not exist"

    content = doc_path.read_text(encoding="utf-8")
    assert "Unexpected Shell in KubeSentinel Edge Workload" in content
    assert "Baseline Rule (V1)" in content
    assert "Tuned Rule (V2)" in content
    assert "Empirical Detection Tuning" in content
    assert "100.0%" in content
