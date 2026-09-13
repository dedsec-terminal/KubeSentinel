"""Automated validation tests for telemetry sample fixtures."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from edge_common.events import load_security_event_schema
from edge_common.models import SecurityEvent
from pydantic import ValidationError

SAMPLES_DIR = Path(__file__).resolve().parents[2] / "telemetry" / "samples"
VALID_DIR = SAMPLES_DIR / "valid"
INVALID_DIR = SAMPLES_DIR / "invalid"


def get_valid_fixture_paths() -> list[Path]:
    """Retrieve all valid sample fixture paths."""
    files = sorted(VALID_DIR.glob("*.json"))
    assert len(files) >= 5, f"Expected at least 5 valid fixtures, found {len(files)}"
    return files


def get_invalid_fixture_paths() -> list[Path]:
    """Retrieve all invalid sample fixture paths."""
    files = sorted(INVALID_DIR.glob("*.json"))
    assert len(files) >= 12, f"Expected at least 12 invalid fixtures, found {len(files)}"
    return files


@pytest.fixture(scope="module")
def schema() -> dict[str, Any]:
    """Load canonical schema once for all sample tests."""
    return load_security_event_schema()


@pytest.mark.parametrize(
    "fixture_path",
    get_valid_fixture_paths(),
    ids=lambda p: p.name,
)
def test_valid_sample_fixtures_pass_validation(fixture_path: Path, schema: dict[str, Any]) -> None:
    """Ensure all valid fixtures pass both jsonschema and Pydantic validation."""
    content = fixture_path.read_text(encoding="utf-8")
    data = json.loads(content)

    # 1. Validate against draft 2020-12 JSON Schema
    jsonschema.validate(instance=data, schema=schema)

    # 2. Validate against canonical Pydantic model
    event = SecurityEvent.model_validate(data)
    assert event.schema_version == "1.0"
    assert event.edge_site in ("pune", "mumbai", "bangalore")


@pytest.mark.parametrize(
    "fixture_path",
    get_invalid_fixture_paths(),
    ids=lambda p: p.name,
)
def test_invalid_sample_fixtures_fail_validation(
    fixture_path: Path,
    schema: dict[str, Any],
) -> None:
    """Ensure all invalid fixtures fail both jsonschema and Pydantic validation."""
    content = fixture_path.read_text(encoding="utf-8")
    data = json.loads(content)

    # 1. Must fail jsonschema validation
    with pytest.raises(jsonschema.exceptions.ValidationError):
        jsonschema.validate(instance=data, schema=schema)

    # 2. Must fail Pydantic validation
    with pytest.raises(ValidationError):
        SecurityEvent.model_validate(data)


def test_invalid_fixture_specific_failure_reasons(schema: dict[str, Any]) -> None:
    """Assert detailed failure rationales for each cataloged negative fixture."""
    # 1. Missing event_id
    data = json.loads((INVALID_DIR / "invalid_missing_event_id.json").read_text(encoding="utf-8"))
    with pytest.raises(jsonschema.exceptions.ValidationError) as exc:
        jsonschema.validate(instance=data, schema=schema)
    assert "event_id" in str(exc.value)

    # 2. Naive timestamp
    data = json.loads((INVALID_DIR / "invalid_timestamp_naive.json").read_text(encoding="utf-8"))
    with pytest.raises(ValidationError) as exc_pydantic:
        SecurityEvent.model_validate(data)
    assert "timezone" in str(exc_pydantic.value).lower()

    # 3. Malformed timestamp
    data = json.loads(
        (INVALID_DIR / "invalid_timestamp_malformed.json").read_text(encoding="utf-8")
    )
    with pytest.raises(jsonschema.exceptions.ValidationError):
        jsonschema.validate(instance=data, schema=schema)

    # 4. Unsupported severity
    data = json.loads(
        (INVALID_DIR / "invalid_unsupported_severity.json").read_text(encoding="utf-8")
    )
    with pytest.raises(jsonschema.exceptions.ValidationError) as exc:
        jsonschema.validate(instance=data, schema=schema)
    assert "urgent" in str(exc.value)

    # 5. Invalid edge site
    data = json.loads((INVALID_DIR / "invalid_edge_site.json").read_text(encoding="utf-8"))
    with pytest.raises(jsonschema.exceptions.ValidationError) as exc:
        jsonschema.validate(instance=data, schema=schema)
    assert "delhi" in str(exc.value)

    # 6. Malformed metadata string
    data = json.loads(
        (INVALID_DIR / "invalid_malformed_metadata_string.json").read_text(encoding="utf-8")
    )
    with pytest.raises(jsonschema.exceptions.ValidationError) as exc:
        jsonschema.validate(instance=data, schema=schema)
    assert "object" in str(exc.value)

    # 7. Missing schema_version
    data = json.loads(
        (INVALID_DIR / "invalid_missing_schema_version.json").read_text(encoding="utf-8")
    )
    with pytest.raises(jsonschema.exceptions.ValidationError) as exc:
        jsonschema.validate(instance=data, schema=schema)
    assert "schema_version" in str(exc.value)

    # 8. Unexpected schema_version
    data = json.loads(
        (INVALID_DIR / "invalid_unexpected_schema_version.json").read_text(encoding="utf-8")
    )
    with pytest.raises(jsonschema.exceptions.ValidationError) as exc:
        jsonschema.validate(instance=data, schema=schema)
    assert "1.0" in str(exc.value)

    # 9. Bad UUID
    data = json.loads((INVALID_DIR / "invalid_bad_uuid.json").read_text(encoding="utf-8"))
    with pytest.raises(ValidationError):
        SecurityEvent.model_validate(data)

    # 10. Fake K8s pod string
    data = json.loads((INVALID_DIR / "invalid_fake_k8s_pod.json").read_text(encoding="utf-8"))
    with pytest.raises(jsonschema.exceptions.ValidationError) as exc:
        jsonschema.validate(instance=data, schema=schema)
    assert "null" in str(exc.value)
    with pytest.raises(ValidationError):
        SecurityEvent.model_validate(data)

    # 11. Extra property forbidden
    data = json.loads((INVALID_DIR / "invalid_extra_property.json").read_text(encoding="utf-8"))
    with pytest.raises(jsonschema.exceptions.ValidationError) as exc:
        jsonschema.validate(instance=data, schema=schema)
    assert "admin_override" in str(exc.value)
    with pytest.raises(ValidationError):
        SecurityEvent.model_validate(data)

    # 12. Empty source string
    data = json.loads((INVALID_DIR / "invalid_empty_source.json").read_text(encoding="utf-8"))
    with pytest.raises(jsonschema.exceptions.ValidationError):
        jsonschema.validate(instance=data, schema=schema)
    with pytest.raises(ValidationError):
        SecurityEvent.model_validate(data)
