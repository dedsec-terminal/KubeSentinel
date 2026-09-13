"""Unit tests for edge-api lifecycle and event ingestion endpoints."""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock

import pytest
from edge_api.config import get_redis_client
from edge_api.main import app
from httpx import ASGITransport, AsyncClient, Response
from redis.exceptions import ConnectionError as RedisConnectionError


class MockRedisClient:
    """Configurable Redis mock for deterministic testing."""

    def __init__(
        self,
        healthy: bool = True,
        xadd_stream_id: str = "1789246370665-0",
        fail_xadd: bool = False,
    ) -> None:
        self.healthy = healthy
        self.xadd_stream_id = xadd_stream_id
        self.fail_xadd = fail_xadd
        self.xadd_calls: list[dict[str, Any]] = []

    def ping(self) -> bool:
        if not self.healthy:
            raise RedisConnectionError("Redis connection refused")
        return True

    def xadd(
        self,
        name: str,
        fields: dict[str, Any],
        maxlen: int | None = None,
        approximate: bool = True,
    ) -> str:
        if not self.healthy or self.fail_xadd:
            raise RedisConnectionError("Connection dropped during write")
        self.xadd_calls.append(
            {
                "name": name,
                "fields": fields,
                "maxlen": maxlen,
                "approximate": approximate,
            }
        )
        return self.xadd_stream_id


@pytest.fixture(autouse=True)
def clean_dependency_overrides() -> Generator[None, None, None]:
    """Ensure clean dependency overrides per test."""
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()


def request(method: str, path: str, **kwargs: object) -> Response:
    async def perform_request() -> Response:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(perform_request())


def test_approved_routes_exist() -> None:
    """Verify strictly approved Milestone B edge-api routes exist."""
    assert {route.path for route in app.routes} == {"/health", "/ready", "/events"}


def test_unknown_route_is_not_found() -> None:
    """Unknown paths return 404 Not Found."""
    response = request("GET", "/unknown")
    assert response.status_code == 404


def test_health_returns_exact_body_independently_of_redis() -> None:
    """GET /health is pure in-memory liveness and succeeds even if Redis is failing."""
    # Force redis dependency to raise an exception if it were called
    broken_client = MockRedisClient(healthy=False)
    app.dependency_overrides[get_redis_client] = lambda: broken_client

    response = request("GET", "/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "edge-api", "version": "0.1.0"}


def test_ready_returns_200_when_redis_available() -> None:
    """GET /ready returns 200 OK when non-mutating ping check succeeds."""
    mock_client = MockRedisClient(healthy=True)
    app.dependency_overrides[get_redis_client] = lambda: mock_client

    response = request("GET", "/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready", "service": "edge-api", "version": "0.1.0"}


def test_ready_returns_503_when_redis_unavailable() -> None:
    """GET /ready returns HTTP 503 without credential leakage when Redis is unavailable."""
    mock_client = MockRedisClient(healthy=False)
    app.dependency_overrides[get_redis_client] = lambda: mock_client

    response = request("GET", "/ready")
    assert response.status_code == 503
    assert response.json() == {"status": "not_ready", "detail": "Redis connection unavailable"}


def test_ready_returns_503_when_ping_returns_false() -> None:
    """GET /ready returns 503 if ping unexpectedly returns False."""
    mock_client = MagicMock()
    mock_client.ping.return_value = False
    app.dependency_overrides[get_redis_client] = lambda: mock_client

    response = request("GET", "/ready")
    assert response.status_code == 503
    assert response.json() == {"status": "not_ready", "detail": "Redis connection unavailable"}


def test_post_events_with_valid_payload_returns_202_accepted() -> None:
    """POST /events validates, constructs canonical event, streams to Redis, and returns 202."""
    mock_client = MockRedisClient(healthy=True, xadd_stream_id="1789246370665-0")
    app.dependency_overrides[get_redis_client] = lambda: mock_client

    payload = {
        "event_type": "security_simulation",
        "severity": "high",
        "source": "10.0.0.42",
        "destination": "internal.service.local",
        "message": "Simulated security event probe",
        "metadata": {"simulation_run": "sim-001", "step": 3},
    }

    response = request("POST", "/events", json=payload)
    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "accepted"
    # Must have valid UUID format
    parsed_uuid = uuid.UUID(data["event_id"])
    assert str(parsed_uuid) == data["event_id"]
    assert data["stream"] == "security-events"
    assert data["stream_id"] == "1789246370665-0"

    # Verify XADD was executed with bounded retention and canonical serialized event
    assert len(mock_client.xadd_calls) == 1
    call = mock_client.xadd_calls[0]
    assert call["name"] == "security-events"
    assert call["maxlen"] == 10000
    assert call["approximate"] is True

    stored_event = json.loads(call["fields"]["event"])
    assert stored_event["schema_version"] == "1.0"
    assert stored_event["event_id"] == data["event_id"]
    assert stored_event["edge_site"] == "pune"
    assert stored_event["namespace"] == "local-compose"
    assert stored_event["service"] == "edge-api"
    assert stored_event["event_type"] == "security_simulation"
    assert stored_event["severity"] == "high"
    assert stored_event["source"] == "10.0.0.42"
    assert stored_event["destination"] == "internal.service.local"
    assert stored_event["message"] == "Simulated security event probe"
    assert stored_event["metadata"] == {"simulation_run": "sim-001", "step": 3}
    # Kubernetes fields must remain null
    assert stored_event.get("pod") is None
    assert stored_event.get("container") is None
    assert stored_event.get("node") is None


def test_post_events_with_optional_destination_omitted() -> None:
    """POST /events succeeds with destination omitted and default empty metadata."""
    mock_client = MockRedisClient(healthy=True, xadd_stream_id="1789246370665-1")
    app.dependency_overrides[get_redis_client] = lambda: mock_client

    payload = {
        "event_type": "service_request",
        "severity": "info",
        "source": "gateway",
        "message": "Gateway ping event",
    }

    response = request("POST", "/events", json=payload)
    assert response.status_code == 202
    assert response.json()["status"] == "accepted"


@pytest.mark.parametrize(
    "missing_field",
    ["event_type", "severity", "source", "message"],
)
def test_post_events_missing_required_field_returns_422(missing_field: str) -> None:
    """POST /events returns 422 Unprocessable Entity when required field is missing."""
    mock_client = MockRedisClient(healthy=True)
    app.dependency_overrides[get_redis_client] = lambda: mock_client

    valid_payload = {
        "event_type": "service_request",
        "severity": "low",
        "source": "client-1",
        "message": "Valid test message",
    }
    invalid_payload = {k: v for k, v in valid_payload.items() if k != missing_field}

    response = request("POST", "/events", json=invalid_payload)
    assert response.status_code == 422


def test_post_events_disallowed_enum_returns_422() -> None:
    """POST /events returns 422 when severity is not one of 5 canonical levels."""
    mock_client = MockRedisClient(healthy=True)
    app.dependency_overrides[get_redis_client] = lambda: mock_client

    payload = {
        "event_type": "service_request",
        "severity": "catastrophic",  # invalid enum
        "source": "client-1",
        "message": "Test event",
    }
    response = request("POST", "/events", json=payload)
    assert response.status_code == 422


@pytest.mark.parametrize(
    ("extra_field", "extra_value"),
    [
        ("pod", "fake-pod-0"),
        ("container", "edge-api"),
        ("node", "worker-node-1"),
        ("schema_version", "1.0"),
        ("timestamp", "2026-09-13T00:00:00Z"),
        ("event_id", "550e8400-e29b-41d4-a716-446655440000"),
        ("edge_site", "mumbai"),
        ("namespace", "production"),
        ("service", "other-service"),
        ("unauthorized_field", "value"),
    ],
)
def test_post_events_forbidden_extra_fields_returns_422(
    extra_field: str,
    extra_value: Any,
) -> None:
    """POST /events rejects untrusted callers attempting to inject server-managed or extra fields."""
    mock_client = MockRedisClient(healthy=True)
    app.dependency_overrides[get_redis_client] = lambda: mock_client

    payload = {
        "event_type": "service_request",
        "severity": "info",
        "source": "client-1",
        "message": "Test event",
        extra_field: extra_value,
    }
    response = request("POST", "/events", json=payload)
    assert response.status_code == 422


def test_post_events_returns_503_when_redis_fails() -> None:
    """POST /events returns 503 without credential leakage when Redis XADD fails."""
    failing_client = MockRedisClient(healthy=True, fail_xadd=True)
    app.dependency_overrides[get_redis_client] = lambda: failing_client

    payload = {
        "event_type": "service_request",
        "severity": "info",
        "source": "client-1",
        "message": "Test event",
    }
    response = request("POST", "/events", json=payload)
    assert response.status_code == 503
    assert response.json() == {"detail": "Redis service unavailable"}
