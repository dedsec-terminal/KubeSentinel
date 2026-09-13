"""Adversarial live integration tests against containerized Redis 7.4 instance."""

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
            raise RuntimeError(
                f"redis-cli error ({proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}"
            )
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
        lines = [
            line.strip()
            for line in output.splitlines()
            if line.strip() and not line.startswith("Warning:")
        ]
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
        lines = [
            line.strip()
            for line in raw_output.splitlines()
            if line.strip() and not line.startswith("Warning:")
        ]
        if not lines:
            return []

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
        lines = [
            line.strip()
            for line in raw_output.splitlines()
            if line.strip() and not line.startswith("Warning:")
        ]
        try:
            return int(lines[-1])
        except (ValueError, IndexError):
            return 0

    def xpending(self, stream: str, group: str) -> dict[str, Any]:
        cmd = ["--raw", "XPENDING", stream, group]
        raw_output = self._exec(*cmd)
        lines = [
            line.strip()
            for line in raw_output.splitlines()
            if line.strip() and not line.startswith("Warning:")
        ]
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
        lines = [
            line.strip()
            for line in raw_output.splitlines()
            if line.strip() and not line.startswith("Warning:")
        ]
        entries = []
        idx = 0
        while idx + 3 < len(lines):
            entry = {
                "message_id": lines[idx],
                "consumer": lines[idx + 1],
                "idle_time": lines[idx + 2],
                "times_delivered": int(lines[idx + 3])
                if lines[idx + 3].isdigit()
                else 1,
            }
            entries.append(entry)
            idx += 4
        return entries

    def close(self) -> None:
        pass


@pytest.fixture(scope="module")
def adversarial_redis_fixture() -> Generator[dict[str, Any], None, None]:
    """Spin up live containerized Redis 7.4 with ACL identities for adversarial testing."""
    if not is_docker_available():
        pytest.skip("Docker daemon is not available for Redis integration testing")

    passwords = get_or_create_credentials()
    admin_password = uuid.uuid4().hex
    passwords["admin"] = admin_password

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

    container_name = f"test-adv-redis-{uuid.uuid4().hex[:8]}"
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

    ready = False
    start_time = time.time()
    while time.time() - start_time < 15:
        ping_proc = subprocess.run(
            [
                "docker",
                "exec",
                container_name,
                "redis-cli",
                "--user",
                "testadmin",
                "-a",
                admin_password,
                "ping",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if ping_proc.returncode == 0 and "PONG" in ping_proc.stdout:
            ready = True
            break
        time.sleep(0.5)

    if not ready:
        logs_proc = subprocess.run(
            ["docker", "logs", container_name],
            capture_output=True,
            text=True,
            check=False,
        )
        subprocess.run(["docker", "rm", "-f", container_name], check=False)
        test_acl_file.unlink(missing_ok=True)
        pytest.fail(
            f"Redis container failed to become ready:\n{logs_proc.stdout}\n{logs_proc.stderr}"
        )

    # Create consumer group 'edge-workers' via bootstrap identity
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


def test_adversarial_live_stream_batch_mixed_payloads(
    adversarial_redis_fixture: dict[str, Any],
) -> None:
    """Live adversarial test: Feed mixture of valid, malformed, extra-field, and missing-key entries.

    Verify strictly:
    1. Valid entries are acknowledged and removed from PEL.
    2. Malformed entries and missing-event entries are NOT acknowledged and remain in PEL.
    3. Error logs are emitted for all invalid entries with stream ID.
    4. Zero credential leakage under live execution.
    """
    container = adversarial_redis_fixture["container"]
    passwords = adversarial_redis_fixture["passwords"]

    producer = ContainerRedisAdapter(container, "producer", passwords["producer"])
    consumer_adapter = ContainerRedisAdapter(
        container, "consumer", passwords["consumer"]
    )
    admin = ContainerRedisAdapter(container, "testadmin", passwords["admin"])

    # 1. Valid event
    valid_event = create_security_event(
        SecurityEventCreate(
            event_type="adv_valid_event",
            severity="low",
            source="192.168.1.100",
            message="Valid event in mixed batch",
        ),
        edge_site="mumbai",
    )
    valid_payload_1 = serialize_security_event(valid_event)
    id_valid_1 = producer.xadd("security-events", {"event": valid_payload_1})

    # 2. Malformed JSON syntax
    id_bad_json = producer.xadd(
        "security-events", {"event": '{"schema_version": "1.0", broken_json'}
    )

    # 3. Missing required field (event_id missing)
    event_dict_no_id = json.loads(valid_payload_1)
    del event_dict_no_id["event_id"]
    id_missing_field = producer.xadd(
        "security-events", {"event": json.dumps(event_dict_no_id)}
    )

    # 4. Invalid edge site (delhi)
    event_dict_bad_site = json.loads(valid_payload_1)
    event_dict_bad_site["edge_site"] = "delhi"
    id_bad_site = producer.xadd(
        "security-events", {"event": json.dumps(event_dict_bad_site)}
    )

    # 5. Missing "event" key entirely
    id_no_event_key = producer.xadd(
        "security-events", {"wrong_key": "unrelated_payload"}
    )

    # 6. Extra disallowed field (injection attempt)
    event_dict_extra = json.loads(valid_payload_1)
    event_dict_extra["attacker_payload"] = "malicious"
    id_extra_field = producer.xadd(
        "security-events", {"event": json.dumps(event_dict_extra)}
    )

    # 7. Another valid event
    valid_event_2 = create_security_event(
        SecurityEventCreate(
            event_type="adv_valid_second",
            severity="critical",
            source="10.10.10.10",
            message="Second valid event in batch",
        ),
        edge_site="bangalore",
    )
    valid_payload_2 = serialize_security_event(valid_event_2)
    id_valid_2 = producer.xadd("security-events", {"event": valid_payload_2})

    total_injected = 7
    invalid_ids = {
        id_bad_json,
        id_missing_field,
        id_bad_site,
        id_no_event_key,
        id_extra_field,
    }
    valid_ids = {id_valid_1, id_valid_2}

    # 2. Consume all 7 messages
    worker_out = io.StringIO()
    settings = Settings(
        redis_consumer_password=passwords["consumer"],
        redis_stream="security-events",
        redis_consumer_group="edge-workers",
        worker_id="adv-live-worker",
        block_timeout_ms=1000,
        batch_size=10,
    )
    consumer = EventConsumer(
        settings=settings,
        redis_client=consumer_adapter,  # type: ignore[arg-type]
        out_stream=worker_out,
    )

    consumer.start(max_messages=total_injected)
    consumer.close()

    # 3. Analyze emitted logs
    logs = [
        json.loads(line)
        for line in worker_out.getvalue().strip().splitlines()
        if line.strip()
    ]
    assert len(logs) == total_injected, f"Expected {total_injected} log records, got {len(logs)}"

    # Check valid event logs
    for v_id in valid_ids:
        log = next((l for l in logs if l.get("redis_stream_id") == v_id), None)
        assert log is not None
        assert log["log_type"] == "security_event_processed"
        assert log["processing_status"] == "success"

    # Check error event logs
    for inv_id in invalid_ids:
        log = next((l for l in logs if l.get("redis_stream_id") == inv_id), None)
        assert log is not None
        assert log["log_type"] == "security_event_processing_error"
        assert log["processing_status"] == "error"

    # 4. Strictly check live Redis PEL (Pending Entries List)
    pending_info = admin.xpending("security-events", "edge-workers")
    assert (
        pending_info["pending"] == len(invalid_ids)
    ), f"Expected exactly {len(invalid_ids)} pending in PEL, got: {pending_info}"

    pel_entries = admin.xpending_range(
        "security-events", "edge-workers", "-", "+", 20
    )
    pel_ids = {e["message_id"] for e in pel_entries}

    assert pel_ids == invalid_ids, f"PEL mismatch! Expected {invalid_ids}, got {pel_ids}"
    assert (
        len(pel_ids.intersection(valid_ids)) == 0
    ), "Valid events must be removed from PEL after XACK!"


def test_adversarial_live_stream_mid_batch_interruption(
    adversarial_redis_fixture: dict[str, Any],
) -> None:
    """Live adversarial test: Mid-batch SIGINT simulation leaves unconsumed messages in PEL."""
    container = adversarial_redis_fixture["container"]
    passwords = adversarial_redis_fixture["passwords"]

    producer = ContainerRedisAdapter(container, "producer", passwords["producer"])
    consumer_adapter = ContainerRedisAdapter(
        container, "consumer", passwords["consumer"]
    )
    admin = ContainerRedisAdapter(container, "testadmin", passwords["admin"])

    # Clear pending by acknowledging old entries or use new group
    # Inject 3 new valid messages
    ids = []
    for i in range(3):
        ev = create_security_event(
            SecurityEventCreate(
                event_type="batch_signal_event",
                severity="info",
                source="127.0.0.1",
                message=f"Batch signal event {i}",
            ),
            edge_site="pune",
        )
        msg_id = producer.xadd(
            "security-events", {"event": serialize_security_event(ev)}
        )
        ids.append(msg_id)

    # Initial pending count before reading new messages
    initial_pending = admin.xpending("security-events", "edge-workers")["pending"]

    # Consumer that processes message 0, then halts immediately
    worker_out = io.StringIO()
    settings = Settings(
        redis_consumer_password=passwords["consumer"],
        redis_stream="security-events",
        redis_consumer_group="edge-workers",
        worker_id="adv-interrupt-worker",
        block_timeout_ms=1000,
        batch_size=10,
    )
    consumer = EventConsumer(
        settings=settings,
        redis_client=consumer_adapter,  # type: ignore[arg-type]
        out_stream=worker_out,
    )

    original_process = consumer.process_message

    def interrupt_after_first(stream_id: str | bytes, fields: dict) -> bool:
        res = original_process(stream_id, fields)
        sid = stream_id.decode() if isinstance(stream_id, bytes) else str(stream_id)
        if sid == ids[0]:
            consumer.stop()  # trigger clean stop
        return res

    consumer.process_message = interrupt_after_first  # type: ignore[method-assign]
    consumer.start(max_batches=1)
    consumer.close()

    # Verify that only the first message was acknowledged
    # ids[1] and ids[2] were delivered in the batch read, but NEVER processed or acknowledged
    # Therefore, ids[1] and ids[2] remain in the PEL!
    new_pending = admin.xpending("security-events", "edge-workers")["pending"]
    assert new_pending == initial_pending + 2, (
        f"Expected 2 additional messages in PEL, got new={new_pending}, initial={initial_pending}"
    )

    pel_entries = admin.xpending_range(
        "security-events", "edge-workers", "-", "+", 50
    )
    pel_ids = {e["message_id"] for e in pel_entries}
    assert ids[0] not in pel_ids, f"Processed message {ids[0]} should be acknowledged!"
    assert ids[1] in pel_ids, f"Unprocessed message {ids[1]} must remain in PEL!"
    assert ids[2] in pel_ids, f"Unprocessed message {ids[2]} must remain in PEL!"
