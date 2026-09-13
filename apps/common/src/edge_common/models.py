"""Pydantic models for KubeSentinel security event contracts."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

EdgeSite = Literal["pune", "mumbai", "bangalore"]
Severity = Literal["info", "low", "medium", "high", "critical"]


class SecurityEventCreate(BaseModel):
    """Untrusted payload provided by external callers to POST /events.

    Rejects server-managed metadata fields (schema_version, timestamp, event_id,
    edge_site, namespace, service, pod, container, node) via extra='forbid'.
    """

    model_config = ConfigDict(extra="forbid")

    event_type: str = Field(
        ...,
        min_length=3,
        max_length=64,
        pattern=r"^[a-z0-9]+(_[a-z0-9]+)*$",
        description="Structured snake_case event type identifier",
    )
    severity: Severity = Field(..., description="Standard 5-level severity classification")
    source: str = Field(..., min_length=1, max_length=256, description="Originating entity or IP")
    destination: str | None = Field(
        default=None,
        max_length=256,
        description="Optional destination service, host, or resource",
    )
    message: str = Field(..., min_length=1, max_length=1024, description="Concise description")
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured key-value context preserving nested objects",
    )


class SecurityEvent(BaseModel):
    """Canonical security event model adhering to telemetry/schemas/security-event.schema.json.

    All 11 core contract fields are required without defaults.
    Optional Kubernetes fields must remain omitted or None.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = Field(...)
    timestamp: datetime = Field(...)
    event_id: UUID = Field(...)
    edge_site: EdgeSite = Field(...)
    namespace: Literal["local-compose"] = Field(...)
    service: Literal["edge-api"] = Field(...)
    event_type: str = Field(..., min_length=3, max_length=64, pattern=r"^[a-z0-9]+(_[a-z0-9]+)*$")
    severity: Severity = Field(...)
    source: str = Field(..., min_length=1, max_length=256)
    destination: str | None = Field(default=None, max_length=256)
    message: str = Field(..., min_length=1, max_length=1024)
    metadata: dict[str, Any] = Field(...)
    pod: None = None
    container: None = None
    node: None = None

    @field_validator("timestamp")
    @classmethod
    def validate_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Timestamp must be timezone-aware (UTC)")
        return value.astimezone(UTC)


class EventCorrelationResponse(BaseModel):
    """Response returned upon HTTP 202 Accepted ingestion."""

    status: Literal["accepted"] = "accepted"
    event_id: str
    stream: str
    stream_id: str


class WorkerStructuredLog(BaseModel):
    """Structured machine-readable log emitted by edge-worker upon processing."""

    log_type: Literal["security_event_processed", "security_event_processing_error"]
    processing_status: Literal["success", "error"]
    redis_stream_id: str
    worker: str
    processed_at: str
    event: dict[str, Any] | None = None
    error_type: str | None = None
    error_detail: str | None = None
    raw_payload_preview: str | None = None
