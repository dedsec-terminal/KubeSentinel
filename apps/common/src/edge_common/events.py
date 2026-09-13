"""Event serialization, deserialization, and factory helpers."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from edge_common.models import EdgeSite, SecurityEvent, SecurityEventCreate


def find_schema_path() -> Path:
    """Find canonical JSON Schema path across local development and container runtime."""
    # 1. Relative to repository root from package source
    try:
        p = Path(__file__).resolve().parents[4] / "telemetry" / "schemas" / "security-event.schema.json"
        if p.is_file():
            return p
    except IndexError:
        pass
    # 2. Current working directory
    cwd_p = Path.cwd() / "telemetry" / "schemas" / "security-event.schema.json"
    if cwd_p.is_file():
        return cwd_p
    # 3. Parent traversal from cwd
    for parent in Path.cwd().parents:
        candidate = parent / "telemetry" / "schemas" / "security-event.schema.json"
        if candidate.is_file():
            return candidate
    return Path("telemetry") / "schemas" / "security-event.schema.json"


SCHEMA_PATH = find_schema_path()


def load_security_event_schema() -> dict[str, Any]:
    """Load canonical JSON Schema from disk."""
    path = find_schema_path()
    if not path.is_file():
        raise FileNotFoundError(f"Security event schema not found at {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def create_security_event(
    payload: SecurityEventCreate,
    *,
    edge_site: EdgeSite,
    namespace: str = "local-compose",
    service: str = "edge-api",
) -> SecurityEvent:
    """Construct trusted canonical security event from validated input and server context."""
    return SecurityEvent(
        schema_version="1.0",
        timestamp=datetime.now(UTC),
        event_id=uuid4(),
        edge_site=edge_site,
        namespace=namespace,  # type: ignore[arg-type]
        service=service,      # type: ignore[arg-type]
        event_type=payload.event_type,
        severity=payload.severity,
        source=payload.source,
        destination=payload.destination,
        message=payload.message,
        metadata=payload.metadata,
    )


def serialize_security_event(event: SecurityEvent) -> str:
    """Serialize canonical event to JSON string for Redis Stream entry."""
    return event.model_dump_json()


def deserialize_security_event(raw: str | bytes | dict[str, Any]) -> SecurityEvent:
    """Deserialize raw payload into validated SecurityEvent."""
    if isinstance(raw, (str, bytes)):
        return SecurityEvent.model_validate_json(raw)
    return SecurityEvent.model_validate(raw)
