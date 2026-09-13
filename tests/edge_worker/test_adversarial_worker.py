"""Adversarial stress-testing suite for edge-worker stream consumption."""

from __future__ import annotations

import io
import json
import signal
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from edge_common.events import create_security_event, serialize_security_event
from edge_common.models import SecurityEventCreate

from edge_worker.config import Settings
from edge_worker.consumer import EventConsumer
from edge_worker.main import run


def _valid_event_dict() -> dict:
    """Construct valid canonical SecurityEvent dictionary."""
    return {
        "schema_version": "1.0",
        "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "event_id": str(uuid4()),
        "edge_site": "pune",
        "namespace": "local-compose",
        "service": "edge-api",
        "event_type": "security_test_event",
        "severity": "info",
        "source": "10.0.0.1",
        "destination": "auth-service",
        "message": "Adversarial verification event",
        "metadata": {"session_id": "test-session-123"},
    }


# ============================================================================
# 1. Adversarial Malformed Payload Tests
# ============================================================================


@pytest.mark.parametrize(
    "malformed_payload,scenario_desc",
    [
        (b"\x00\x01\xfe\xff binary junk", "Non-JSON binary bytes"),
        (b"\x80\x81\x82 invalid utf8", "Invalid UTF-8 binary bytes"),
        ("", "Empty string"),
        ("   ", "Whitespace only"),
        ("Plain unformatted text string", "Plain non-JSON text"),
        (
            '{"schema_version": "1.0", "event_id":',
            "Truncated JSON missing closing brace/value",
        ),
        (
            '{"schema_version": "1.0", "event_id": "123"',
            "Truncated JSON missing closing brace",
        ),
        ("{", "Single opening brace"),
    ],
)
def test_adversarial_malformed_syntax_skips_xack(
    malformed_payload: str | bytes,
    scenario_desc: str,
) -> None:
    """Adversarial: Non-JSON / truncated bytes must emit error log and NEVER call XACK."""
    settings = Settings(
        redis_consumer_password="adversarial-test-pass",
        redis_stream="security-events",
        redis_consumer_group="edge-workers",
        worker_id="adv-worker-syntax",
    )
    redis_mock = MagicMock()
    out = io.StringIO()
    consumer = EventConsumer(
        settings=settings, redis_client=redis_mock, out_stream=out
    )

    stream_id = f"adv-syntax-{uuid4().hex[:6]}"
    fields = {"event": malformed_payload}

    success = consumer.process_message(stream_id, fields)

    assert (
        success is False
    ), f"Expected failure for {scenario_desc}, got success=True"
    redis_mock.xack.assert_not_called()

    output = out.getvalue().strip()
    assert (
        output
    ), f"Expected structured JSON error log on stdout for {scenario_desc}"
    record = json.loads(output)
    assert record["log_type"] == "security_event_processing_error"
    assert record["processing_status"] == "error"
    assert record["redis_stream_id"] == stream_id
    assert "error_type" in record
    assert "error_detail" in record


@pytest.mark.parametrize(
    "missing_field",
    [
        "schema_version",
        "timestamp",
        "event_id",
        "edge_site",
        "namespace",
        "service",
        "event_type",
        "severity",
        "source",
        "message",
        "metadata",
    ],
)
def test_adversarial_missing_required_fields_skips_xack(
    missing_field: str,
) -> None:
    """Adversarial: Omitting any of the 11 required contract fields must reject and NEVER call XACK."""
    payload_dict = _valid_event_dict()
    del payload_dict[missing_field]

    settings = Settings(
        redis_consumer_password="adversarial-test-pass",
        worker_id="adv-worker-missing-field",
    )
    redis_mock = MagicMock()
    out = io.StringIO()
    consumer = EventConsumer(
        settings=settings, redis_client=redis_mock, out_stream=out
    )

    stream_id = f"adv-missing-{missing_field}"
    fields = {"event": json.dumps(payload_dict)}

    success = consumer.process_message(stream_id, fields)

    assert (
        success is False
    ), f"Expected validation failure when omitting required field: {missing_field}"
    redis_mock.xack.assert_not_called()

    record = json.loads(out.getvalue().strip())
    assert record["log_type"] == "security_event_processing_error"
    assert record["processing_status"] == "error"
    assert record["error_type"] == "ValidationError"
    assert record["redis_stream_id"] == stream_id


@pytest.mark.parametrize(
    "invalid_site",
    ["delhi", "tokyo", "mumbai-central", "pune1", "", "null", "NEW_DELHI"],
)
def test_adversarial_invalid_edge_sites_skips_xack(invalid_site: str) -> None:
    """Adversarial: Unauthorized or spoofed edge sites must be rejected without XACK."""
    payload_dict = _valid_event_dict()
    payload_dict["edge_site"] = invalid_site

    settings = Settings(
        redis_consumer_password="adversarial-test-pass",
        worker_id="adv-worker-invalid-site",
    )
    redis_mock = MagicMock()
    out = io.StringIO()
    consumer = EventConsumer(
        settings=settings, redis_client=redis_mock, out_stream=out
    )

    stream_id = f"adv-site-{invalid_site}"
    fields = {"event": json.dumps(payload_dict)}

    success = consumer.process_message(stream_id, fields)

    assert (
        success is False
    ), f"Expected validation failure for invalid site '{invalid_site}'"
    redis_mock.xack.assert_not_called()

    record = json.loads(out.getvalue().strip())
    assert record["log_type"] == "security_event_processing_error"
    assert record["error_type"] == "ValidationError"


@pytest.mark.parametrize(
    "bad_timestamp,desc",
    [
        ("2026-09-13T10:00:00", "Naive timestamp missing timezone"),
        ("not-a-timestamp", "Arbitrary non-date string"),
        ("2026-13-45T99:99:99Z", "Out of bounds date time"),
        ("2026-09-13", "Date only without time/tz"),
        ("Sun, 13 Sep 2026 10:00:00 GMT", "RFC2822 non-ISO format"),
        ("", "Empty timestamp string"),
        ("null", "String literal null"),
    ],
)
def test_adversarial_non_utc_timestamps_skips_xack(
    bad_timestamp: str | int,
    desc: str,
) -> None:
    """Adversarial: Non-UTC or malformed timestamps must be rejected without XACK."""
    payload_dict = _valid_event_dict()
    payload_dict["timestamp"] = bad_timestamp

    settings = Settings(
        redis_consumer_password="adversarial-test-pass",
        worker_id="adv-worker-bad-ts",
    )
    redis_mock = MagicMock()
    out = io.StringIO()
    consumer = EventConsumer(
        settings=settings, redis_client=redis_mock, out_stream=out
    )

    stream_id = "adv-ts-stream-id"
    fields = {"event": json.dumps(payload_dict)}

    success = consumer.process_message(stream_id, fields)

    assert (
        success is False
    ), f"Expected validation failure for timestamp '{bad_timestamp}' ({desc})"
    redis_mock.xack.assert_not_called()

    record = json.loads(out.getvalue().strip())
    assert record["log_type"] == "security_event_processing_error"
    assert record["error_type"] == "ValidationError"


@pytest.mark.parametrize(
    "extra_key,extra_val,desc",
    [
        (
            "disallowed_field",
            "malicious_injection",
            "Arbitrary disallowed field",
        ),
        ("pod", "fake-pod-name", "Fake Kubernetes pod field"),
        ("container", "fake-container-name", "Fake Kubernetes container field"),
        ("node", "fake-node-name", "Fake Kubernetes node field"),
        ("attacker_token", "leaked_cred", "Injected token field"),
    ],
)
def test_adversarial_disallowed_and_fake_k8s_fields_skips_xack(
    extra_key: str,
    extra_val: str,
    desc: str,
) -> None:
    """Adversarial: Injected extra fields or fake Kubernetes objects must fail validation and skip XACK."""
    payload_dict = _valid_event_dict()
    payload_dict[extra_key] = extra_val

    settings = Settings(
        redis_consumer_password="adversarial-test-pass",
        worker_id="adv-worker-extra-fields",
    )
    redis_mock = MagicMock()
    out = io.StringIO()
    consumer = EventConsumer(
        settings=settings, redis_client=redis_mock, out_stream=out
    )

    stream_id = f"adv-extra-{extra_key}"
    fields = {"event": json.dumps(payload_dict)}

    success = consumer.process_message(stream_id, fields)

    assert (
        success is False
    ), f"Expected validation failure for extra field '{extra_key}' ({desc})"
    redis_mock.xack.assert_not_called()

    record = json.loads(out.getvalue().strip())
    assert record["log_type"] == "security_event_processing_error"
    assert record["error_type"] == "ValidationError"


# ============================================================================
# 2. Adversarial Missing "event" Key in Redis Entry Tests
# ============================================================================


@pytest.mark.parametrize(
    "fields_without_event,scenario",
    [
        ({"message": "missing event key"}, "String dict with 'message' only"),
        (
            {"payload": '{"valid": "json"}', "data": "random"},
            "Dict with 'payload' and 'data'",
        ),
        ({}, "Empty fields dict"),
        (
            {b"not_event": b"some binary data"},
            "Bytes dict with non-event key",
        ),
        (
            {"EVENT": '{"uppercase": "key"}'},
            "Case-mismatched uppercase 'EVENT'",
        ),
    ],
)
def test_adversarial_missing_event_key_skips_xack(
    fields_without_event: dict,
    scenario: str,
) -> None:
    """Adversarial: Redis entries missing 'event' key must emit KeyError log and skip XACK."""
    settings = Settings(
        redis_consumer_password="adversarial-test-pass",
        worker_id="adv-worker-missing-key",
    )
    redis_mock = MagicMock()
    out = io.StringIO()
    consumer = EventConsumer(
        settings=settings, redis_client=redis_mock, out_stream=out
    )

    stream_id = f"adv-no-event-key-{uuid4().hex[:6]}"

    success = consumer.process_message(stream_id, fields_without_event)

    assert (
        success is False
    ), f"Expected failure when 'event' key is missing: {scenario}"
    redis_mock.xack.assert_not_called()

    record = json.loads(out.getvalue().strip())
    assert record["log_type"] == "security_event_processing_error"
    assert record["processing_status"] == "error"
    assert record["error_type"] == "KeyError"
    assert "Missing 'event' field" in record["error_detail"]


# ============================================================================
# 3. Credential Security & Redaction Stress Tests
# ============================================================================


def test_adversarial_credential_security_zero_leakage() -> None:
    """Adversarial: Secret passwords must NEVER leak into stdout logs or error details."""
    super_secret = "ULTRA_CONFIDENTIAL_P@SSW0RD_#99887766!"
    settings = Settings(
        redis_consumer_password=super_secret,
        worker_id="adv-worker-leak-check",
    )
    redis_mock = MagicMock()
    out = io.StringIO()
    consumer = EventConsumer(
        settings=settings, redis_client=redis_mock, out_stream=out
    )

    # 1. Payload contains password in malformed JSON
    malformed_json = (
        f'{{"auth": "{super_secret}", "invalid_syntax": missing_quote'
    )
    consumer.process_message("id-leak-1", {"event": malformed_json})

    # 2. Payload contains password in invalid schema field
    bad_schema = json.dumps(
        {
            "schema_version": "1.0",
            "severity": super_secret,  # invalid severity containing password
            "message": f"Login failed for token {super_secret}",
        }
    )
    consumer.process_message("id-leak-2", {"event": bad_schema})

    # 3. Stream fields missing 'event' key but dictionary key contains password
    missing_key_dict = {f"auth_key_{super_secret}": super_secret}
    consumer.process_message("id-leak-3", missing_key_dict)

    # 4. Long payload with password crossing boundary
    long_prefix = "A" * 120
    boundary_payload = f'{{"secret": "{long_prefix}{super_secret}"'
    consumer.process_message("id-leak-4", {"event": boundary_payload})

    # 5. Raw binary with password
    binary_payload = (
        f"binary_prefix_{super_secret}_binary_suffix".encode()
        + b"\x00\xff"
    )
    consumer.process_message("id-leak-5", {"event": binary_payload})

    all_emitted_logs = out.getvalue()

    # The raw secret MUST NEVER appear anywhere in stdout
    assert (
        super_secret not in all_emitted_logs
    ), f"FATAL LEAK: Found unredacted secret '{super_secret}' in logs!"

    # Verify that redactions occurred
    assert "***REDACTED***" in all_emitted_logs

    # Verify each line is valid JSON
    for line in all_emitted_logs.strip().splitlines():
        if line.strip():
            record = json.loads(line)
            assert record["processing_status"] == "error"
            assert super_secret not in json.dumps(record)


# ============================================================================
# 4. Clean Signal Handling & Graceful Termination Tests
# ============================================================================


def test_adversarial_sigterm_and_sigint_clean_shutdown() -> None:
    """Adversarial: Signal handlers must cleanly set running=False and exit with 0 unhandled exceptions."""
    settings = Settings(
        redis_consumer_password="adv-signal-pass",
        worker_id="adv-worker-signals",
    )
    redis_mock = MagicMock()

    consumer = EventConsumer(settings=settings, redis_client=redis_mock)
    consumer.register_signal_handlers()

    # Simulate SIGTERM arrival
    consumer.running = True
    sigterm_handler = signal.getsignal(signal.SIGTERM)
    assert callable(
        sigterm_handler
    ), "SIGTERM handler must be registered and callable"
    sigterm_handler(signal.SIGTERM, None)
    assert (
        consumer.running is False
    ), "SIGTERM handler must set consumer.running = False"

    # Simulate SIGINT arrival
    consumer.running = True
    sigint_handler = signal.getsignal(signal.SIGINT)
    assert callable(
        sigint_handler
    ), "SIGINT handler must be registered and callable"
    sigint_handler(signal.SIGINT, None)
    assert (
        consumer.running is False
    ), "SIGINT handler must set consumer.running = False"

    # Verify stop() and close() behavior
    consumer.running = True
    consumer.close()
    assert consumer.running is False
    redis_mock.close.assert_called_once()


def test_adversarial_signal_during_idle_blocking() -> None:
    """Adversarial: Signal arriving during blocking XREADGROUP call terminates loop gracefully."""
    settings = Settings(
        redis_consumer_password="adv-signal-pass",
        worker_id="adv-worker-idle-block",
    )
    redis_mock = MagicMock()

    # Simulate xreadgroup blocking, then being interrupted by signal handler setting running=False
    call_count = 0

    def mock_xreadgroup(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return []  # first call times out / empty
        # Second call: simulate signal arrival
        consumer.stop()
        return []

    redis_mock.xreadgroup.side_effect = mock_xreadgroup
    consumer = EventConsumer(settings=settings, redis_client=redis_mock)

    # Start consumer without batch limit; must exit cleanly when stopped
    consumer.start()

    assert consumer.running is False
    assert call_count == 2
    redis_mock.xack.assert_not_called()


def test_adversarial_main_run_handles_keyboard_interrupt() -> None:
    """Adversarial: main.run() must handle KeyboardInterrupt without unhandled exceptions."""
    with (
        patch("edge_worker.main.load_settings") as mock_load,
        patch("edge_worker.main.create_redis_client") as mock_client,
        patch("edge_worker.main.EventConsumer") as mock_consumer_cls,
    ):
        mock_settings = MagicMock()
        mock_load.return_value = mock_settings
        mock_redis = MagicMock()
        mock_client.return_value = mock_redis
        mock_consumer = MagicMock()
        mock_consumer.start.side_effect = KeyboardInterrupt()
        mock_consumer_cls.return_value = mock_consumer

        # Should execute cleanly and NOT re-raise KeyboardInterrupt
        run()

        mock_consumer.close.assert_called_once()


# ============================================================================
# 5. PEL Retention & Mid-Batch Interruption Tests
# ============================================================================


def test_adversarial_mid_batch_interruption_leaves_unprocessed_in_pel() -> None:
    """Adversarial: When a batch of 5 messages is interrupted after message 2, messages 3-5 are NOT acknowledged."""
    settings = Settings(
        redis_consumer_password="adv-pass",
        redis_stream="security-events",
        redis_consumer_group="edge-workers",
        worker_id="adv-worker-mid-batch",
    )
    valid_payload = serialize_security_event(
        create_security_event(
            SecurityEventCreate(
                event_type="service_request",
                severity="info",
                source="10.0.0.1",
                message="Valid batch event",
            ),
            edge_site="pune",
        )
    )

    batch_messages = [
        ("batch-id-1", {"event": valid_payload}),
        ("batch-id-2", {"event": valid_payload}),
        ("batch-id-3", {"event": valid_payload}),
        ("batch-id-4", {"event": valid_payload}),
        ("batch-id-5", {"event": valid_payload}),
    ]

    redis_mock = MagicMock()
    redis_mock.xreadgroup.return_value = [("security-events", batch_messages)]

    out = io.StringIO()
    consumer = EventConsumer(
        settings=settings, redis_client=redis_mock, out_stream=out
    )

    processed_stream_ids: list[str] = []
    original_process = consumer.process_message

    def hook_process(stream_id: str | bytes, fields: dict) -> bool:
        sid_str = stream_id.decode() if isinstance(stream_id, bytes) else str(stream_id)
        processed_stream_ids.append(sid_str)
        res = original_process(stream_id, fields)
        # Simulate SIGTERM after message 2
        if sid_str == "batch-id-2":
            consumer.stop()
        return res

    consumer.process_message = hook_process  # type: ignore[method-assign]

    consumer.start(max_batches=1)

    # Exactly 2 messages processed and acknowledged
    assert processed_stream_ids == ["batch-id-1", "batch-id-2"]
    assert redis_mock.xack.call_count == 2
    redis_mock.xack.assert_any_call(
        "security-events", "edge-workers", "batch-id-1"
    )
    redis_mock.xack.assert_any_call(
        "security-events", "edge-workers", "batch-id-2"
    )

    # Messages 3, 4, 5 were NEVER acknowledged (remain pending in PEL)
    all_xack_calls = [c[0][2] for c in redis_mock.xack.call_args_list]
    assert "batch-id-3" not in all_xack_calls
    assert "batch-id-4" not in all_xack_calls
    assert "batch-id-5" not in all_xack_calls
