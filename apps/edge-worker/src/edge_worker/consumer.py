"""Redis Streams event consumer with structured JSON logging and XACK lifecycle."""

from __future__ import annotations

import json
import signal
import sys
import time
from datetime import UTC, datetime
from typing import Any, TextIO

import redis
from edge_common.events import deserialize_security_event
from redis.exceptions import RedisError

from edge_worker.config import Settings, create_redis_client, load_settings


class EventConsumer:
    """Stream consumer reading from Redis Streams via consumer group.

    Enforces strict post-processing acknowledgement (XACK after successful emission),
    retains malformed entries in the Pending Entries List (PEL), handles SIGTERM/SIGINT
    cleanly without data loss or unhandled exceptions, and prevents credential leakage.
    """

    def __init__(
        self,
        settings: Settings | None = None,
        redis_client: redis.Redis | None = None,
        out_stream: TextIO | None = None,
    ) -> None:
        self.settings = settings or load_settings()
        self.redis = redis_client or create_redis_client(self.settings)
        self.out = out_stream or sys.stdout
        self.running = False
        self.worker_id = self.settings.worker_id
        self.stream = self.settings.redis_stream
        self.group = self.settings.redis_consumer_group
        self.block_ms = self.settings.block_timeout_ms
        self.batch_size = self.settings.batch_size

    def register_signal_handlers(self) -> None:
        """Register signal handlers for SIGINT and SIGTERM to trigger graceful shutdown."""

        def _handle_signal(signum: int, frame: Any) -> None:
            self.running = False

        try:
            signal.signal(signal.SIGINT, _handle_signal)
            signal.signal(signal.SIGTERM, _handle_signal)
        except (ValueError, AttributeError):
            # In multi-threaded environments or non-main threads, signal registration may fail
            pass

    def stop(self) -> None:
        """Signal the consumer to stop processing subsequent messages."""
        self.running = False

    def close(self) -> None:
        """Cleanly close connection resources."""
        self.stop()
        try:
            self.redis.close()
        except (RedisError, OSError):
            return

    def _sanitize(self, text: str) -> str:
        """Strip secrets and sensitive credentials from log text."""
        password = self.settings.redis_consumer_password
        if password and len(password) > 0:
            text = text.replace(password, "***REDACTED***")
        return text

    def _safe_preview(self, data: Any) -> str:
        """Generate safe, truncated preview string of raw payload (max 128 chars)."""
        if data is None:
            return ""
        if isinstance(data, bytes):
            text = data.decode("utf-8", errors="replace")
        elif isinstance(data, str):
            text = data
        else:
            text = str(data)
        text = self._sanitize(text)
        return text[:128]

    def _emit_json(self, record: dict[str, Any]) -> None:
        """Emit single-line unbuffered structured JSON to stdout."""
        line = json.dumps(record, separators=(",", ":"))
        self.out.write(line + "\n")
        self.out.flush()

    def process_message(
        self,
        stream_id: str | bytes,
        fields: dict[Any, Any],
    ) -> bool:
        """Process a single stream entry.

        Validates against SecurityEvent schema.
        On success: emits structured JSON log, then calls XACK. Returns True.
        On error: emits error log, skips XACK (retains in PEL). Returns False.
        """
        stream_id_str = (
            stream_id.decode("utf-8") if isinstance(stream_id, bytes) else str(stream_id)
        )
        now_utc = datetime.now(UTC).isoformat().replace("+00:00", "Z")

        # Extract payload from "event" or b"event" key
        raw_event = fields.get("event")
        if raw_event is None:
            raw_event = fields.get(b"event")

        if raw_event is None:
            error_type = "KeyError"
            error_detail = "Missing 'event' field in stream message payload"
            preview = self._safe_preview(fields)
            self._emit_json(
                {
                    "log_type": "security_event_processing_error",
                    "processing_status": "error",
                    "redis_stream_id": stream_id_str,
                    "worker": self.worker_id,
                    "processed_at": now_utc,
                    "error_type": error_type,
                    "error_detail": error_detail,
                    "raw_payload_preview": preview,
                }
            )
            # STRICTLY SKIP XACK on missing event field
            return False

        try:
            if isinstance(raw_event, (str, bytes)):
                parsed_json = json.loads(raw_event)
                event = deserialize_security_event(parsed_json)
            else:
                event = deserialize_security_event(raw_event)
        except (ValueError, TypeError, KeyError) as exc:
            error_type = exc.__class__.__name__
            error_detail = self._sanitize(str(exc))
            preview = self._safe_preview(raw_event)
            self._emit_json(
                {
                    "log_type": "security_event_processing_error",
                    "processing_status": "error",
                    "redis_stream_id": stream_id_str,
                    "worker": self.worker_id,
                    "processed_at": now_utc,
                    "error_type": error_type,
                    "error_detail": error_detail,
                    "raw_payload_preview": preview,
                }
            )
            # STRICTLY SKIP XACK on malformed or invalid payload
            return False

        # Success path: emit valid structured JSON log
        event_dict = event.model_dump(mode="json")
        log_record = {
            "log_type": "security_event_processed",
            "processing_status": "success",
            "redis_stream_id": stream_id_str,
            "worker": self.worker_id,
            "processed_at": now_utc,
            **event_dict,
        }
        self._emit_json(log_record)

        # STRICTLY AFTER emitting log, execute XACK
        self.redis.xack(self.stream, self.group, stream_id_str)
        return True

    def start(
        self,
        max_batches: int | None = None,
        max_messages: int | None = None,
    ) -> None:
        """Run the main stream consumption loop.

        Blocks efficiently using Redis BLOCK without busy-looping.
        Implements bounded exponential backoff on transient Redis connection errors.
        Terminates cleanly on self.running = False (SIGTERM/SIGINT) without data loss.
        """
        self.running = True
        self.register_signal_handlers()

        backoff = 0.5
        max_backoff = 5.0
        batches_count = 0
        messages_count = 0

        while self.running:
            if max_batches is not None and batches_count >= max_batches:
                break
            if max_messages is not None and messages_count >= max_messages:
                break

            try:
                entries = self.redis.xreadgroup(
                    groupname=self.group,
                    consumername=self.worker_id,
                    streams={self.stream: ">"},
                    count=self.batch_size,
                    block=self.block_ms,
                )
                backoff = 0.5  # reset on successful execution
                if not entries:
                    continue

                batches_count += 1
                for _stream_name, stream_entries in entries:
                    for stream_id, fields in stream_entries:
                        if not self.running:
                            # Interrupted by signal: do not process or acknowledge remaining messages
                            break
                        self.process_message(stream_id, fields)
                        messages_count += 1
                        if max_messages is not None and messages_count >= max_messages:
                            break
                    if not self.running:
                        break

            except (redis.ConnectionError, redis.TimeoutError, RedisError, OSError):
                if not self.running:
                    break
                time.sleep(backoff)
                backoff = min(backoff * 2, max_backoff)


__all__ = ["EventConsumer"]
