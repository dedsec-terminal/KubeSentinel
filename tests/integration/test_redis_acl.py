"""Integration tests for Redis ACL enforcement against a live containerized Redis 7.4 instance."""

from __future__ import annotations

import re
import shutil
import subprocess
import time
import uuid
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest

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


@pytest.fixture(scope="module")
def redis_container() -> Generator[dict[str, Any], None, None]:
    """Spin up a live Redis container with redis.conf and users.acl for ACL testing."""
    if not is_docker_available():
        pytest.skip("Docker daemon is not available for Redis integration testing")

    passwords = get_or_create_credentials()
    container_name = f"test-redis-acl-{uuid.uuid4().hex[:8]}"

    redis_conf = ROOT / "deploy" / "compose" / "redis" / "redis.conf"
    users_acl = ROOT / "deploy" / "compose" / "redis" / "users.acl"

    assert redis_conf.exists(), f"Configuration missing: {redis_conf}"
    assert users_acl.exists(), f"ACL file missing: {users_acl}"

    # Convert Windows paths for Docker volume mounts
    conf_mount = f"{redis_conf.resolve()}:/usr/local/etc/redis/redis.conf:ro"
    acl_mount = f"{users_acl.resolve()}:/etc/redis/users.acl:ro"

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
        pytest.fail(f"Failed to start Redis test container: {proc.stderr}")

    # Poll container health until responsive
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
                "producer",
                "-a",
                passwords["producer"],
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
        pytest.fail(f"Redis container failed to become ready:\n{logs_proc.stdout}\n{logs_proc.stderr}")

    fixture_data = {
        "container": container_name,
        "passwords": passwords,
    }

    try:
        yield fixture_data
    finally:
        subprocess.run(["docker", "rm", "-f", container_name], check=False)


def run_redis(container: str, user: str | None, password: str | None, *args: str) -> tuple[int, str, str]:
    """Execute redis-cli inside the container with given credentials."""
    cmd = ["docker", "exec", container, "redis-cli"]
    if user and password:
        cmd.extend(["--user", user, "-a", password])
    cmd.extend(args)
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def test_default_user_is_disabled(redis_container: dict[str, Any]) -> None:
    """Validate that default/anonymous connections are rejected."""
    container = redis_container["container"]
    _code, stdout, stderr = run_redis(container, None, None, "PING")
    output = stdout + stderr
    assert "WRONGPASS" in output or "NOAUTH" in output, (
        f"Expected auth rejection for default user, got: {output}"
    )


def test_invalid_credentials_rejected(redis_container: dict[str, Any]) -> None:
    """Validate that bad passwords or unknown users fail authentication."""
    container = redis_container["container"]
    _code, stdout, stderr = run_redis(container, "producer", "incorrect-password", "PING")
    output = stdout + stderr
    assert "WRONGPASS" in output or "AUTH failed" in output

    _code, stdout, stderr = run_redis(container, "nonexistent", "some-password", "PING")
    output = stdout + stderr
    assert "WRONGPASS" in output or "AUTH failed" in output


def test_producer_allowed_ping_and_xadd_on_security_events(redis_container: dict[str, Any]) -> None:
    """Validate producer identity can authenticate, ping, and add entries to security-events."""
    container = redis_container["container"]
    pw = redis_container["passwords"]["producer"]

    # Allowed: PING
    code, stdout, _stderr = run_redis(container, "producer", pw, "PING")
    assert code == 0
    assert "PONG" in stdout

    # Allowed: XADD on security-events
    code, stdout, _stderr = run_redis(
        container,
        "producer",
        pw,
        "XADD",
        "security-events",
        "*",
        "event",
        '{"event_id": "test-1"}',
    )
    assert code == 0
    # Output should be a valid Redis stream ID (e.g. 1789247334163-0)
    assert re.match(r"^\d+-\d+$", stdout), f"Expected stream ID, got: {stdout}"


def test_producer_denied_xreadgroup(redis_container: dict[str, Any]) -> None:
    """Validate producer identity cannot read from stream (least-privilege)."""
    container = redis_container["container"]
    pw = redis_container["passwords"]["producer"]

    _code, stdout, stderr = run_redis(
        container,
        "producer",
        pw,
        "XREADGROUP",
        "GROUP",
        "edge-workers",
        "worker-1",
        "COUNT",
        "1",
        "STREAMS",
        "security-events",
        ">",
    )
    output = stdout + stderr
    assert "NOPERM" in output
    assert "xreadgroup" in output.lower()


def test_producer_denied_other_keys(redis_container: dict[str, Any]) -> None:
    """Validate producer identity cannot access streams other than security-events."""
    container = redis_container["container"]
    pw = redis_container["passwords"]["producer"]

    _code, stdout, stderr = run_redis(
        container,
        "producer",
        pw,
        "XADD",
        "unauthorized-stream",
        "*",
        "event",
        "unauthorized",
    )
    output = stdout + stderr
    assert "NOPERM" in output


def test_producer_denied_admin_commands(redis_container: dict[str, Any]) -> None:
    """Validate producer identity cannot execute administrative commands."""
    container = redis_container["container"]
    pw = redis_container["passwords"]["producer"]

    for admin_cmd in (["FLUSHALL"], ["CONFIG", "GET", "port"], ["KEYS", "*"]):
        _code, stdout, stderr = run_redis(container, "producer", pw, *admin_cmd)
        output = stdout + stderr
        assert "NOPERM" in output, f"Admin command {admin_cmd} was not denied: {output}"


def test_bootstrap_creates_consumer_group(redis_container: dict[str, Any]) -> None:
    """Validate bootstrap identity can create the consumer group idempotently."""
    container = redis_container["container"]
    boot_pw = redis_container["passwords"]["bootstrap"]

    # Create consumer group edge-workers
    code, stdout, stderr = run_redis(
        container,
        "bootstrap",
        boot_pw,
        "XGROUP",
        "CREATE",
        "security-events",
        "edge-workers",
        "$",
        "MKSTREAM",
    )
    output = stdout + stderr
    # Either OK (first time) or BUSYGROUP (if already created)
    assert "OK" in output or "BUSYGROUP" in output

    # Allowed: XINFO GROUPS security-events
    code, stdout, stderr = run_redis(
        container,
        "bootstrap",
        boot_pw,
        "XINFO",
        "GROUPS",
        "security-events",
    )
    assert code == 0
    assert "edge-workers" in stdout


def test_consumer_allowed_ping_xreadgroup_and_xack(redis_container: dict[str, Any]) -> None:
    """Validate consumer identity can authenticate, read from stream group, and acknowledge."""
    container = redis_container["container"]
    prod_pw = redis_container["passwords"]["producer"]
    cons_pw = redis_container["passwords"]["consumer"]
    boot_pw = redis_container["passwords"]["bootstrap"]

    # Ensure group exists
    run_redis(container, "bootstrap", boot_pw, "XGROUP", "CREATE", "security-events", "edge-workers", "0", "MKSTREAM")

    # Allowed: PING
    code, stdout, _stderr = run_redis(container, "consumer", cons_pw, "PING")
    assert code == 0
    assert "PONG" in stdout

    # Write a test entry with producer
    _code, stream_id, _stderr = run_redis(
        container,
        "producer",
        prod_pw,
        "XADD",
        "security-events",
        "*",
        "event",
        '{"test_ack": true}',
    )
    assert re.match(r"^\d+-\d+$", stream_id)

    # Allowed: XREADGROUP
    code, stdout, _stderr = run_redis(
        container,
        "consumer",
        cons_pw,
        "XREADGROUP",
        "GROUP",
        "edge-workers",
        "test-worker-1",
        "COUNT",
        "10",
        "STREAMS",
        "security-events",
        ">",
    )
    assert code == 0
    assert "security-events" in stdout
    assert "test_ack" in stdout

    # Allowed: XACK
    code, stdout, _stderr = run_redis(
        container,
        "consumer",
        cons_pw,
        "XACK",
        "security-events",
        "edge-workers",
        stream_id,
    )
    assert code == 0
    # XACK returns the number of acknowledged entries (>= 1)
    assert stdout in ("1", ":1") or stdout.endswith("1")


def test_consumer_denied_xadd(redis_container: dict[str, Any]) -> None:
    """Validate consumer identity cannot publish to stream (least-privilege)."""
    container = redis_container["container"]
    cons_pw = redis_container["passwords"]["consumer"]

    _code, stdout, stderr = run_redis(
        container,
        "consumer",
        cons_pw,
        "XADD",
        "security-events",
        "*",
        "event",
        "consumer-should-not-write",
    )
    output = stdout + stderr
    assert "NOPERM" in output
    assert "xadd" in output.lower()


def test_consumer_denied_admin_commands(redis_container: dict[str, Any]) -> None:
    """Validate consumer identity cannot execute administrative commands."""
    container = redis_container["container"]
    cons_pw = redis_container["passwords"]["consumer"]

    for admin_cmd in (["FLUSHALL"], ["CONFIG", "GET", "maxmemory"], ["KEYS", "*"]):
        _code, stdout, stderr = run_redis(container, "consumer", cons_pw, *admin_cmd)
        output = stdout + stderr
        assert "NOPERM" in output, f"Admin command {admin_cmd} was not denied: {output}"
