"""Shared edge telemetry models and serialization utilities."""

from edge_common.events import (
    create_security_event,
    deserialize_security_event,
    load_security_event_schema,
    serialize_security_event,
)
from edge_common.models import (
    EdgeSite,
    EventCorrelationResponse,
    SecurityEvent,
    SecurityEventCreate,
    Severity,
    WorkerStructuredLog,
)

__all__ = [
    "EdgeSite",
    "EventCorrelationResponse",
    "SecurityEvent",
    "SecurityEventCreate",
    "Severity",
    "WorkerStructuredLog",
    "create_security_event",
    "deserialize_security_event",
    "load_security_event_schema",
    "serialize_security_event",
]
