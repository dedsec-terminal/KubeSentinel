"""Integration tests for edge-worker stream processing against a live containerized Redis 7.4 instance."""

from __future__ import annotations

import io
import json
import re
import shutil
import subprocess
import time
import uuid
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest
from edge_common.events import create_security_event, serialize_security_event
from edge_common.models import SecurityEventCreate
from edge_worker.config import Settings
from edge_worker.consumer import EventConsumer

from scripts.bootstrap import bootstrap_local

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[2]
REDIS_IMAGE = "redis:7.4.2-alpine"


def is_docker_available() -> bool:
    """Check if docker CLI is present and the Docker daemon is responding."""
    if not shutil.which("docker"):
        return False
    try:
        proc = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return proc.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def get_or_create_credentials() -> dict[str, str]:
    """Retrieve passwords from .env.local, bootstrapping if not present."""
    env_file = ROOT / ".env.local"
    acl_file = ROOT / "deploy" / "compose" / "redis" / "users.acl"
    if not env_file.exists() or not acl_file.exists():
        bootstrap_local(root_dir=ROOT, force=False, stdout=False)

    env_text = env_file.read_text(encoding="utf-8")
    passwords: dict[str, str] = {}
    for key in ("PRODUCER", "CONSUMER", "BOOTSTRAP"):
        match = re.search(rf"REDIS_{key}_PASSWORD=(\S+)", env_text)
        if match:
            passwords[key.lower()] = match.group(1)

    assert len(passwords) == 3, f"Missing passwords in {env_file}"
    return passwords


class ContainerRedisAdapter:
    """Redis client proxy that executes commands directly inside the live container via docker exec."""

    def __init__(self, container_name: str, username: str, password: str) -> None:
        self.container_name = container_name
        self.username = username
        self.password = password

    def _exec(self, *args: str) -> str:
        cmd = ["docker", "exec", self.container_name, "redis-cli"]
        if self.username and self.password:
            cmd.extend(["--user", self.username, "-a", self.password])
        cmd.extend(args)
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            raise RuntimeError(f"redis-cli error ({proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}")
        return proc.stdout.strip()

    def xadd(
        self,
        stream: str,
        fields: dict[str, Any],
        maxlen: int | None = None,
        approximate: bool = True,
    ) -> str:
        cmd = ["XADD", stream]
        if maxlen is not None:
            cmd.extend(["MAXLEN", "~" if approximate else "=", str(maxlen)])
        cmd.append("*")
        for k, v in fields.items():
            cmd.extend([str(k), str(v)])
        output = self._exec(*cmd)
        lines = [line.strip() for line in output.splitlines() if line.strip() and not line.startswith("Warning:")]
        return lines[-1] if lines else ""

    def xreadgroup(
        self,
        groupname: str,
        consumername: str,
        streams: dict[str, str],
        count: int = 10,
        block: int = 2000,
    ) -> list[tuple[str, list[tuple[str, dict[str, str]]]]]:
        stream_name = next(iter(streams.keys()))
        stream_id_target = streams[stream_name]
        cmd = [
            "--raw",
            "XREADGROUP",
            "GROUP",
            groupname,
            consumername,
            "COUNT",
            str(count),
            "BLOCK",
            str(block),
            "STREAMS",
            stream_name,
            stream_id_target,
        ]
        raw_output = self._exec(*cmd)
        lines = [line.strip() for line in raw_output.splitlines() if line.strip() and not line.startswith("Warning:")]
        if not lines:
            return []

        # Parse raw redis-cli lines into stream structure:
        # line 0: stream name
        # line 1: stream_id
        # line 2: field key (e.g. "event")
        # line 3: field value
        idx = 0
        stream_key = lines[idx]
        idx += 1
        stream_entries: list[tuple[str, dict[str, str]]] = []
        while idx + 2 < len(lines):
            entry_id = lines[idx]
            field_name = lines[idx + 1]
            field_val = lines[idx + 2]
            stream_entries.append((entry_id, {field_name: field_val}))
            idx += 3

        return [(stream_key, stream_entries)]

    def xack(self, stream: str, group: str, *stream_ids: str) -> int:
        cmd = ["XACK", stream, group, *stream_ids]
        raw_output = self._exec(*cmd)
        lines = [line.strip() for line in raw_output.splitlines() if line.strip() and not line.startswith("Warning:")]
        try:
            return int(lines[-1])
        except (ValueError, IndexError):
            return 0

    def xpending(self, stream: str, group: str) -> dict[str, Any]:
        cmd = ["--raw", "XPENDING", stream, group]
        raw_output = self._exec(*cmd)
        lines = [line.strip() for line in raw_output.splitlines() if line.strip() and not line.startswith("Warning:")]
        if not lines:
            return {"pending": 0, "min": None, "max": None}
        try:
            count = int(lines[0])
        except (ValueError, IndexError):
            count = 0
        min_id = lines[1] if len(lines) > 1 and count > 0 else None
        max_id = lines[2] if len(lines) > 2 and count > 0 else None
        return {"pending": count, "min": min_id, "max": max_id}

    def xpending_range(
        self,
        stream: str,
        group: str,
        min_id: str,
        max_id: str,
        count: int,
    ) -> list[dict[str, Any]]:
        cmd = ["--raw", "XPENDING", stream, group, min_id, max_id, str(count)]
        raw_output = self._exec(*cmd)
        lines = [line.strip() for line in raw_output.splitlines() if line.strip() and not line.startswith("Warning:")]
        entries = []
        idx = 0
        while idx + 3 < len(lines):
            entry = {
                "message_id": lines[idx],
                "consumer": lines[idx + 1],
                "idle_time": lines[idx + 2],
                "times_delivered": int(lines[idx + 3]) if lines[idx + 3].isdigit() else 1,
            }
            entries.append(entry)
            idx += 4
        return entries

    def close(self) -> None:
        pass


@pytest.fixture(scope="module")
def worker_redis_fixture() -> Generator[dict[str, Any], None, None]:
    """Spin up live containerized Redis 7.4 with ACL identities for stream tests."""
    if not is_docker_available():
        pytest.skip("Docker daemon is not available for Redis integration testing")

    passwords = get_or_create_credentials()
    admin_password = uuid.uuid4().hex
    passwords["admin"] = admin_password

    # Write temporary ACL configuration inside repository directory (D: drive)
    test_acl_file = ROOT / f".tmp_test_acl_{uuid.uuid4().hex[:8]}.acl"
    redis_conf = ROOT / "deploy" / "compose" / "redis" / "redis.conf"

    assert redis_conf.exists(), f"Configuration missing: {redis_conf}"

    test_acl_file.write_text(
        f"""user default off
user producer on >{passwords['producer']} resetkeys ~security-events resetchannels -@all +auth +ping +xadd
user consumer on >{passwords['consumer']} resetkeys ~security-events resetchannels -@all +auth +ping +xreadgroup +xack
user bootstrap on >{passwords['bootstrap']} resetkeys ~security-events resetchannels -@all +auth +ping +xgroup +xinfo
user testadmin on >{admin_password} resetkeys ~* resetchannels +@all
""",
        encoding="utf-8",
    )

    container_name = f"test-worker-redis-{uuid.uuid4().hex[:8]}"
    conf_mount = f"{redis_conf.resolve()}:/usr/local/etc/redis/redis.conf:ro"
    acl_mount = f"{test_acl_file.resolve()}:/etc/redis/users.acl:ro"

    run_cmd = [
        "docker",
        "run",
        "-d",
        "--name",
        container_name,
        "-v",
        conf_mount,
        "-v",
        acl_mount,
        REDIS_IMAGE,
        "redis-server",
        "/usr/local/etc/redis/redis.conf",
    ]

    proc = subprocess.run(run_cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        test_acl_file.unlink(missing_ok=True)
        pytest.fail(f"Failed to start Redis test container: {proc.stderr}")

    # Poll container health until responsive
    ready = False
    start_time = time.time()
    while time.time() - start_time < 15:
        ping_proc = subprocess.run(
            ["docker", "exec", container_name, "redis-cli", "--user", "testadmin", "-a", admin_password, "ping"],
            capture_output=True,
            text=True,
            check=False,
        )
        if ping_proc.returncode == 0 and "PONG" in ping_proc.stdout:
            ready = True
            break
        time.sleep(0.5)

    if not ready:
        logs_proc = subprocess.run(["docker", "logs", container_name], capture_output=True, text=True, check=False)
        subprocess.run(["docker", "rm", "-f", container_name], check=False)
        test_acl_file.unlink(missing_ok=True)
        pytest.fail(f"Redis test container failed to become ready:\n{logs_proc.stdout}\n{logs_proc.stderr}")

    # Idempotently create consumer group 'edge-workers' on 'security-events' via bootstrap identity
    subprocess.run(
        [
            "docker",
            "exec",
            container_name,
            "redis-cli",
            "--user",
            "bootstrap",
            "-a",
            passwords["bootstrap"],
            "XGROUP",
            "CREATE",
            "security-events",
            "edge-workers",
            "$",
            "MKSTREAM",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    fixture_info = {
        "container": container_name,
        "passwords": passwords,
    }

    try:
        yield fixture_info
    finally:
        subprocess.run(["docker", "rm", "-f", container_name], check=False)
        test_acl_file.unlink(missing_ok=True)


def test_worker_consumes_and_acknowledges_valid_stream_event(
    worker_redis_fixture: dict[str, Any],
) -> None:
    """Live integration: Producer writes valid event, worker processes, logs, and XACKs (0 PEL)."""
    container = worker_redis_fixture["container"]
    passwords = worker_redis_fixture["passwords"]

    producer_client = ContainerRedisAdapter(container, "producer", passwords["producer"])
    consumer_client = ContainerRedisAdapter(container, "consumer", passwords["consumer"])
    admin_client = ContainerRedisAdapter(container, "testadmin", passwords["admin"])

    # 1. Produce valid event with producer credentials
    event_model = SecurityEventCreate(
        event_type="service_request",
        severity="info",
        source="192.168.1.50",
        destination="auth-service",
        message="Live stream end-to-end integration event",
        metadata={"build": "m4-verify"},
    )
    canonical_event = create_security_event(
        event_model,
        edge_site="pune",
        namespace="local-compose",
        service="edge-api",
    )
    serialized_payload = serialize_security_event(canonical_event)

    stream_id = producer_client.xadd(
        "security-events",
        {"event": serialized_payload},
        maxlen=10000,
        approximate=True,
    )
    assert stream_id != ""
    assert re.match(r"^\d+-\d+$", stream_id)

    # 2. Instantiate EventConsumer with consumer identity
    worker_out = io.StringIO()
    settings = Settings(
        redis_consumer_password=passwords["consumer"],
        redis_stream="security-events",
        redis_consumer_group="edge-workers",
        worker_id="integration-worker-live-1",
        block_timeout_ms=1000,
        batch_size=5,
    )
    consumer = EventConsumer(
        settings=settings,
        redis_client=consumer_client,  # type: ignore[arg-type]
        out_stream=worker_out,
    )

    # 3. Consume the message
    consumer.start(max_messages=1)
    consumer.close()

    # 4. Verify log emission
    logs = [
        json.loads(line)
        for line in worker_out.getvalue().strip().splitlines()
        if line.strip()
    ]
    assert len(logs) >= 1
    target_log = next((l for l in logs if l.get("redis_stream_id") == stream_id), None)
    assert target_log is not None
    assert target_log["log_type"] == "security_event_processed"
    assert target_log["processing_status"] == "success"
    assert target_log["event_id"] == str(canonical_event.event_id)
    assert target_log["message"] == "Live stream end-to-end integration event"

    # 5. Verify XACK removed event from the PEL (0 pending)
    pending_info = admin_client.xpending("security-events", "edge-workers")
    assert pending_info["pending"] == 0, f"Expected 0 pending entries after XACK, got: {pending_info}"


def test_worker_leaves_malformed_payload_in_pel(
    worker_redis_fixture: dict[str, Any],
) -> None:
    """Live integration: Producer writes malformed event, worker skips XACK, entry remains in PEL."""
    container = worker_redis_fixture["container"]
    passwords = worker_redis_fixture["passwords"]

    producer_client = ContainerRedisAdapter(container, "producer", passwords["producer"])
    consumer_client = ContainerRedisAdapter(container, "consumer", passwords["consumer"])
    admin_client = ContainerRedisAdapter(container, "testadmin", passwords["admin"])

    # 1. Produce malformed event (invalid JSON syntax)
    malformed_payload = '{"schema_version": "1.0", "invalid": "corrupt_data"'
    malformed_id = producer_client.xadd(
        "security-events",
        {"event": malformed_payload},
        maxlen=10000,
        approximate=True,
    )
    assert malformed_id != ""

    # 2. Worker consumes entry
    worker_out = io.StringIO()
    settings = Settings(
        redis_consumer_password=passwords["consumer"],
        redis_stream="security-events",
        redis_consumer_group="edge-workers",
        worker_id="integration-worker-malformed",
        block_timeout_ms=1000,
        batch_size=5,
    )
    consumer = EventConsumer(
        settings=settings,
        redis_client=consumer_client,  # type: ignore[arg-type]
        out_stream=worker_out,
    )

    consumer.start(max_messages=1)
    consumer.close()

    # 3. Verify error log was emitted
    logs = [
        json.loads(line)
        for line in worker_out.getvalue().strip().splitlines()
        if line.strip()
    ]
    assert len(logs) >= 1
    target_log = next((l for l in logs if l.get("redis_stream_id") == malformed_id), None)
    assert target_log is not None
    assert target_log["log_type"] == "security_event_processing_error"
    assert target_log["processing_status"] == "error"
    assert target_log["error_type"] == "JSONDecodeError"

    # 4. STRICTLY verify that XACK was skipped and entry remains in PEL
    pending_info = admin_client.xpending("security-events", "edge-workers")
    assert pending_info["pending"] >= 1, (
        f"Malformed entry should NOT be acknowledged; expected >=1 in PEL, got: {pending_info}"
    )

    # Inspect PEL entries via XPENDING range
    pel_entries = admin_client.xpending_range("security-events", "edge-workers", "-", "+", 10)
    matching_pel = [e for e in pel_entries if e["message_id"] == malformed_id]
    assert len(matching_pel) == 1
    assert matching_pel[0]["consumer"] == "integration-worker-malformed"
    assert matching_pel[0]["times_delivered"] >= 1


def test_worker_leaves_missing_event_key_in_pel(
    worker_redis_fixture: dict[str, Any],
) -> None:
    """Live integration: Producer writes stream entry missing 'event' key; entry remains in PEL."""
    container = worker_redis_fixture["container"]
    passwords = worker_redis_fixture["passwords"]

    producer_client = ContainerRedisAdapter(container, "producer", passwords["producer"])
    consumer_client = ContainerRedisAdapter(container, "consumer", passwords["consumer"])
    admin_client = ContainerRedisAdapter(container, "testadmin", passwords["admin"])

    # 1. Produce entry with missing "event" key
    missing_key_id = producer_client.xadd(
        "security-events",
        {"garbage_key": "unrelated_payload"},
        maxlen=10000,
        approximate=True,
    )
    assert missing_key_id != ""

    # 2. Worker consumes entry
    worker_out = io.StringIO()
    settings = Settings(
        redis_consumer_password=passwords["consumer"],
        redis_stream="security-events",
        redis_consumer_group="edge-workers",
        worker_id="integration-worker-missing-key",
        block_timeout_ms=1000,
        batch_size=5,
    )
    consumer = EventConsumer(
        settings=settings,
        redis_client=consumer_client,  # type: ignore[arg-type]
        out_stream=worker_out,
    )

    consumer.start(max_messages=1)
    consumer.close()

    # 3. Verify error log
    logs = [
        json.loads(line)
        for line in worker_out.getvalue().strip().splitlines()
        if line.strip()
    ]
    target_log = next((l for l in logs if l.get("redis_stream_id") == missing_key_id), None)
    assert target_log is not None
    assert target_log["log_type"] == "security_event_processing_error"
    assert target_log["error_type"] == "KeyError"

    # 4. Entry remains in PEL
    pel_entries = admin_client.xpending_range("security-events", "edge-workers", "-", "+", 10)
    matching_pel = [e for e in pel_entries if e["message_id"] == missing_key_id]
    assert len(matching_pel) == 1
    assert matching_pel[0]["consumer"] == "integration-worker-missing-key"
