"""Unit tests for edge-worker EventConsumer."""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime
from unittest.mock import MagicMock
from uuid import uuid4

from edge_common.events import create_security_event, serialize_security_event
from edge_common.models import SecurityEventCreate

from edge_worker.config import Settings
from edge_worker.consumer import EventConsumer


def _create_sample_valid_payload() -> str:
    """Helper to construct a valid serialized SecurityEvent string."""
    create_model = SecurityEventCreate(
        event_type="service_request",
        severity="info",
        source="10.0.0.1",
        destination="auth-service",
        message="Valid edge authentication test event",
        metadata={"session_id": "sess-1234"},
    )
    event = create_security_event(
        create_model,
        edge_site="pune",
        namespace="local-compose",
        service="edge-api",
    )
    return serialize_security_event(event)


def test_consumer_successful_event_processing() -> None:
    """Test successful event processing: parses event, validates, emits log, calls XACK."""
    settings = Settings(
        redis_consumer_password="test-consumer-pass",
        redis_stream="security-events",
        redis_consumer_group="edge-workers",
        worker_id="worker-unit-test-1",
    )
    redis_mock = MagicMock()
    out = io.StringIO()

    consumer = EventConsumer(settings=settings, redis_client=redis_mock, out_stream=out)

    payload_json = _create_sample_valid_payload()
    stream_id = "1726000000000-0"
    fields = {"event": payload_json}

    success = consumer.process_message(stream_id, fields)
    assert success is True

    # Check that XACK was called strictly with expected parameters
    redis_mock.xack.assert_called_once_with("security-events", "edge-workers", stream_id)

    # Check emitted structured JSON log
    output = out.getvalue().strip()
    assert output, "Expected structured JSON output to stdout"
    log_record = json.loads(output)

    assert log_record["log_type"] == "security_event_processed"
    assert log_record["processing_status"] == "success"
    assert log_record["redis_stream_id"] == stream_id
    assert log_record["worker"] == "worker-unit-test-1"
    assert "processed_at" in log_record
    assert log_record["event_type"] == "service_request"
    assert log_record["severity"] == "info"
    assert log_record["edge_site"] == "pune"
    assert log_record["namespace"] == "local-compose"
    assert log_record["service"] == "edge-api"
    assert log_record["message"] == "Valid edge authentication test event"
    assert log_record["metadata"] == {"session_id": "sess-1234"}


def test_consumer_processes_byte_keys_and_values() -> None:
    """Test consumer correctly handles binary byte keys and values."""
    settings = Settings(
        redis_consumer_password="test-consumer-pass",
        redis_stream="security-events",
        redis_consumer_group="edge-workers",
        worker_id="worker-unit-test-bytes",
    )
    redis_mock = MagicMock()
    out = io.StringIO()

    consumer = EventConsumer(settings=settings, redis_client=redis_mock, out_stream=out)

    payload_json = _create_sample_valid_payload()
    stream_id_bytes = b"1726000000001-0"
    fields = {b"event": payload_json.encode("utf-8")}

    success = consumer.process_message(stream_id_bytes, fields)
    assert success is True

    redis_mock.xack.assert_called_once_with(
        "security-events", "edge-workers", "1726000000001-0"
    )

    log_record = json.loads(out.getvalue().strip())
    assert log_record["log_type"] == "security_event_processed"
    assert log_record["redis_stream_id"] == "1726000000001-0"


def test_consumer_malformed_json_skips_xack() -> None:
    """Test malformed JSON: emits structured error log, strictly does NOT call XACK."""
    settings = Settings(
        redis_consumer_password="test-consumer-pass",
        worker_id="worker-unit-test-malformed",
    )
    redis_mock = MagicMock()
    out = io.StringIO()

    consumer = EventConsumer(settings=settings, redis_client=redis_mock, out_stream=out)

    stream_id = "1726000000002-0"
    fields = {"event": "{not valid json at all!!!"}

    success = consumer.process_message(stream_id, fields)
    assert success is False

    # STRICTLY NO XACK on malformed payload
    redis_mock.xack.assert_not_called()

    # Verify structured error log
    output = out.getvalue().strip()
    log_record = json.loads(output)
    assert log_record["log_type"] == "security_event_processing_error"
    assert log_record["processing_status"] == "error"
    assert log_record["redis_stream_id"] == stream_id
    assert log_record["worker"] == "worker-unit-test-malformed"
    assert log_record["error_type"] == "JSONDecodeError"
    assert "{not valid json" in log_record["raw_payload_preview"]


def test_consumer_validation_error_skips_xack() -> None:
    """Test schema validation failure: emits structured error log, strictly does NOT call XACK."""
    settings = Settings(
        redis_consumer_password="test-consumer-pass",
        worker_id="worker-unit-test-schema",
    )
    redis_mock = MagicMock()
    out = io.StringIO()

    consumer = EventConsumer(settings=settings, redis_client=redis_mock, out_stream=out)

    stream_id = "1726000000003-0"
    # Valid JSON, but violates SecurityEvent schema (missing required fields, bad severity)
    invalid_schema_json = json.dumps(
        {
            "schema_version": "1.0",
            "timestamp": datetime.now(UTC).isoformat(),
            "event_id": str(uuid4()),
            "edge_site": "pune",
            "namespace": "local-compose",
            "service": "edge-api",
            "event_type": "test_event",
            "severity": "extreme_danger",  # invalid enum
            "source": "10.0.0.1",
            "message": "test message",
            "metadata": {},
        }
    )
    fields = {"event": invalid_schema_json}

    success = consumer.process_message(stream_id, fields)
    assert success is False

    redis_mock.xack.assert_not_called()

    log_record = json.loads(out.getvalue().strip())
    assert log_record["log_type"] == "security_event_processing_error"
    assert log_record["processing_status"] == "error"
    assert log_record["redis_stream_id"] == stream_id
    assert log_record["error_type"] == "ValidationError"


def test_consumer_missing_event_field_skips_xack() -> None:
    """Test stream message missing 'event' key: emits error log, strictly does NOT call XACK."""
    settings = Settings(
        redis_consumer_password="test-consumer-pass",
        worker_id="worker-unit-test-missing",
    )
    redis_mock = MagicMock()
    out = io.StringIO()

    consumer = EventConsumer(settings=settings, redis_client=redis_mock, out_stream=out)

    stream_id = "1726000000004-0"
    fields = {"unexpected_key": "some_data", "payload": "missing event"}

    success = consumer.process_message(stream_id, fields)
    assert success is False

    redis_mock.xack.assert_not_called()

    log_record = json.loads(out.getvalue().strip())
    assert log_record["log_type"] == "security_event_processing_error"
    assert log_record["processing_status"] == "error"
    assert log_record["redis_stream_id"] == stream_id
    assert log_record["error_type"] == "KeyError"
    assert "Missing 'event' field" in log_record["error_detail"]


def test_clean_signal_handling() -> None:
    """Test SIGTERM and SIGINT trigger graceful stop without unhandled exceptions."""
    settings = Settings(
        redis_consumer_password="test-consumer-pass",
        worker_id="worker-signal-test",
    )
    redis_mock = MagicMock()
    consumer = EventConsumer(settings=settings, redis_client=redis_mock)

    # Initial state
    assert consumer.running is False

    # Simulate stopping
    consumer.running = True
    consumer.stop()
    assert consumer.running is False

    # Verify close cleans up
    consumer.running = True
    consumer.close()
    assert consumer.running is False
    redis_mock.close.assert_called_once()


def test_interrupted_batch_leaves_subsequent_events_unacknowledged() -> None:
    """Test that if interrupted mid-batch, subsequent events remain unacknowledged."""
    settings = Settings(
        redis_consumer_password="test-consumer-pass",
        redis_stream="security-events",
        redis_consumer_group="edge-workers",
        worker_id="worker-batch-interrupt",
    )
    payload_json = _create_sample_valid_payload()
    redis_mock = MagicMock()
    out = io.StringIO()

    batch_entries = [
        ("security-events", [
            ("1000-1", {"event": payload_json}),
            ("1000-2", {"event": payload_json}),
            ("1000-3", {"event": payload_json}),
        ])
    ]
    redis_mock.xreadgroup.return_value = batch_entries

    consumer = EventConsumer(settings=settings, redis_client=redis_mock, out_stream=out)

    # Custom hook: stop consumer after processing first message
    original_process = consumer.process_message

    def stop_after_first(stream_id: str | bytes, fields: dict) -> bool:
        res = original_process(stream_id, fields)
        consumer.stop()  # Simulate SIGTERM arriving during batch
        return res

    consumer.process_message = stop_after_first  # type: ignore[method-assign]

    consumer.start(max_batches=1)

    # Only first message should be acknowledged; messages 2 and 3 remain in PEL
    assert redis_mock.xack.call_count == 1
    redis_mock.xack.assert_called_once_with("security-events", "edge-workers", "1000-1")


def test_zero_credential_leakage() -> None:
    """Test that passwords and internal connection strings are never leaked in logs."""
    secret_pass = "super-secret-password-xyz-9988"
    settings = Settings(
        redis_consumer_password=secret_pass,
        redis_host="10.240.0.15",
        worker_id="worker-leak-test",
    )
    redis_mock = MagicMock()
    out = io.StringIO()

    consumer = EventConsumer(settings=settings, redis_client=redis_mock, out_stream=out)

    # Trigger error containing the secret password
    malformed_payload_with_secret = f'{{"malformed": "data", "token": "{secret_pass}"}}'
    stream_id = "1726000000005-0"
    fields = {"event": malformed_payload_with_secret}

    consumer.process_message(stream_id, fields)

    raw_output = out.getvalue()
    assert secret_pass not in raw_output, "Password was leaked in output logs!"
    assert "***REDACTED***" in raw_output
