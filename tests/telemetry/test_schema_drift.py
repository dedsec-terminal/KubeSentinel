"""Automated schema drift detection between Pydantic models and JSON Schema."""

from __future__ import annotations

import json
from typing import get_args
from uuid import uuid4

import jsonschema
import pytest
from edge_common.events import (
    create_security_event,
    deserialize_security_event,
    load_security_event_schema,
    serialize_security_event,
)
from edge_common.models import (
    EdgeSite,
    SecurityEvent,
    SecurityEventCreate,
    Severity,
)
from pydantic import ValidationError


def test_schema_properties_match_pydantic_fields() -> None:
    """Ensure exact bidirectional property parity between JSON schema and Pydantic model."""
    schema = load_security_event_schema()
    schema_props = set(schema["properties"].keys())
    pydantic_fields = set(SecurityEvent.model_fields.keys())

    assert pydantic_fields == schema_props, (
        f"Schema drift detected! Symmetric difference: {pydantic_fields ^ schema_props}"
    )


def test_schema_required_fields_match_pydantic_required_fields() -> None:
    """Ensure required fields in JSON schema match fields without defaults in Pydantic."""
    schema = load_security_event_schema()
    schema_required = set(schema["required"])

    pydantic_required = {
        name for name, field in SecurityEvent.model_fields.items() if field.is_required()
    }

    assert schema_required == pydantic_required, (
        f"Required fields mismatch! Symmetric difference: {schema_required ^ pydantic_required}"
    )


def test_enum_and_const_parity() -> None:
    """Ensure enum and constant values in schema exactly match Python typing definitions."""
    schema = load_security_event_schema()
    props = schema["properties"]

    assert set(props["edge_site"]["enum"]) == set(get_args(EdgeSite))
    assert set(props["severity"]["enum"]) == set(get_args(Severity))
    assert props["schema_version"]["const"] == "1.0"
    assert props["namespace"]["const"] == "local-compose"
    assert props["service"]["const"] == "edge-api"


def test_additional_properties_forbidden() -> None:
    """Ensure both schema and Pydantic models forbid unexpected additional fields."""
    schema = load_security_event_schema()
    assert schema.get("additionalProperties") is False, (
        "JSON Schema must specify additionalProperties: false"
    )
    assert SecurityEvent.model_config.get("extra") == "forbid", (
        "SecurityEvent must configure extra='forbid'"
    )
    assert SecurityEventCreate.model_config.get("extra") == "forbid", (
        "SecurityEventCreate must configure extra='forbid'"
    )


def test_kubernetes_fields_strictly_null_typed() -> None:
    """Ensure Kubernetes fields are constrained to null in both schema and model."""
    schema = load_security_event_schema()
    props = schema["properties"]

    for k8s_field in ("pod", "container", "node"):
        assert props[k8s_field] == {"type": "null"}, (
            f"Field {k8s_field} in JSON Schema must be typed as null only"
        )

    # In Pydantic, passing a string to pod must fail validation
    valid_payload = SecurityEventCreate(
        event_type="test_event",
        severity="info",
        source="test-source",
        message="test-message",
    )
    event = create_security_event(valid_payload, edge_site="pune")
    event_dict = json.loads(event.model_dump_json())

    # Passing a string to pod must fail Pydantic validation
    event_dict["pod"] = "fake-pod-string"
    with pytest.raises(ValidationError):
        SecurityEvent.model_validate(event_dict)


def test_roundtrip_serialization_and_jsonschema_validation() -> None:
    """Ensure events created via factory validate against JSON Schema and deserialize cleanly."""
    schema = load_security_event_schema()
    create_payload = SecurityEventCreate(
        event_type="roundtrip_verification",
        severity="medium",
        source="test-runner",
        destination="10.0.0.1:8000",
        message="Verifying roundtrip serialization and schema conformance",
        metadata={"run_id": str(uuid4()), "active": True, "count": 42},
    )
    event = create_security_event(create_payload, edge_site="bangalore")

    # Serialize
    serialized = serialize_security_event(event)
    data = json.loads(serialized)

    # Validate against JSON Schema
    jsonschema.validate(instance=data, schema=schema)

    # Deserialize back
    deserialized = deserialize_security_event(serialized)
    assert deserialized.event_id == event.event_id
    assert deserialized.edge_site == "bangalore"
    assert deserialized.metadata["count"] == 42
