"""Unit tests for edge-worker configuration and Redis client creation."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from edge_worker.config import (
    Settings,
    create_redis_client,
    find_env_local,
    load_settings,
    parse_env_file,
)


def test_settings_defaults() -> None:
    """Test default settings when no environment variables or file are present."""
    with patch.dict(os.environ, {}, clear=True):
        settings = load_settings(env_file=Path("nonexistent.env"))
        assert settings.redis_host == "127.0.0.1"
        assert settings.redis_port == 6379
        assert settings.redis_consumer_password == ""
        assert settings.redis_stream == "security-events"
        assert settings.redis_consumer_group == "edge-workers"
        assert settings.worker_id.startswith("worker-")
        assert settings.block_timeout_ms == 2000
        assert settings.batch_size == 10


def test_env_var_loading() -> None:
    """Test environment variable loading into settings."""
    custom_env = {
        "REDIS_HOST": "redis.cluster.local",
        "REDIS_PORT": "6380",
        "REDIS_CONSUMER_PASSWORD": "super-consumer-pass",
        "REDIS_STREAM": "custom-stream",
        "REDIS_CONSUMER_GROUP": "custom-group",
        "WORKER_ID": "worker-custom-42",
        "BLOCK_TIMEOUT_MS": "5000",
        "BATCH_SIZE": "25",
    }
    with patch.dict(os.environ, custom_env, clear=True):
        settings = load_settings(env_file=Path("nonexistent.env"))
        assert settings.redis_host == "redis.cluster.local"
        assert settings.redis_port == 6380
        assert settings.redis_consumer_password == "super-consumer-pass"
        assert settings.redis_stream == "custom-stream"
        assert settings.redis_consumer_group == "custom-group"
        assert settings.worker_id == "worker-custom-42"
        assert settings.block_timeout_ms == 5000
        assert settings.batch_size == 25


def test_env_local_fallback(tmp_path: Path) -> None:
    """Test loading configuration from .env.local file."""
    env_file = tmp_path / ".env.local"
    env_file.write_text(
        """
        REDIS_HOST=file-host
        REDIS_PORT=6381
        REDIS_CONSUMER_PASSWORD=from-file-pass
        REDIS_STREAM=file-stream
        REDIS_CONSUMER_GROUP=file-group
        WORKER_ID=worker-from-file
        BLOCK_TIMEOUT_MS=1500
        BATCH_SIZE=5
        """,
        encoding="utf-8",
    )
    with patch.dict(os.environ, {}, clear=True):
        settings = load_settings(env_file=env_file)
        assert settings.redis_host == "file-host"
        assert settings.redis_port == 6381
        assert settings.redis_consumer_password == "from-file-pass"
        assert settings.redis_stream == "file-stream"
        assert settings.redis_consumer_group == "file-group"
        assert settings.worker_id == "worker-from-file"
        assert settings.block_timeout_ms == 1500
        assert settings.batch_size == 5


def test_env_var_precedence_over_file(tmp_path: Path) -> None:
    """Environment variables take precedence over file settings."""
    env_file = tmp_path / ".env.local"
    env_file.write_text(
        "REDIS_HOST=file-host\nREDIS_CONSUMER_PASSWORD=file-pass\n",
        encoding="utf-8",
    )
    with patch.dict(
        os.environ,
        {"REDIS_HOST": "env-host", "REDIS_CONSUMER_PASSWORD": "env-pass"},
        clear=True,
    ):
        settings = load_settings(env_file=env_file)
        assert settings.redis_host == "env-host"
        assert settings.redis_consumer_password == "env-pass"


def test_fallback_aliases(tmp_path: Path) -> None:
    """Test fallback alias environment variables (REDIS_PASSWORD, CONSUMER_GROUP, STREAM_NAME)."""
    with patch.dict(
        os.environ,
        {
            "REDIS_PASSWORD": "fallback-pass",
            "CONSUMER_GROUP": "fallback-group",
            "STREAM_NAME": "fallback-stream",
            "CONSUMER_ID": "worker-fallback-1",
        },
        clear=True,
    ):
        settings = load_settings(env_file=Path("nonexistent.env"))
        assert settings.redis_consumer_password == "fallback-pass"
        assert settings.redis_consumer_group == "fallback-group"
        assert settings.redis_stream == "fallback-stream"
        assert settings.worker_id == "worker-fallback-1"


def test_missing_password_behavior() -> None:
    """Test that missing or empty password triggers proper validation error."""
    settings = Settings(redis_consumer_password="")
    with pytest.raises(ValueError, match="REDIS_CONSUMER_PASSWORD must be configured"):
        settings.validate_secrets()

    with patch.dict(os.environ, {}, clear=True):
        with pytest.raises(ValueError, match="REDIS_CONSUMER_PASSWORD must be configured"):
            load_settings(env_file=Path("nonexistent.env"), require_password=True)

        with pytest.raises(ValueError, match="REDIS_CONSUMER_PASSWORD must be configured"):
            create_redis_client(settings)


def test_create_redis_client_configuration() -> None:
    """Verify create_redis_client configures consumer credentials and suppresses CLIENT SETINFO."""
    settings = Settings(
        redis_host="10.10.0.5",
        redis_port=6389,
        redis_consumer_password="consumer-test-pass",
        redis_stream="security-events",
        redis_consumer_group="edge-workers",
    )
    client = create_redis_client(settings)
    pool = client.connection_pool
    kwargs = pool.connection_kwargs

    assert kwargs["host"] == "10.10.0.5"
    assert kwargs["port"] == 6389
    assert kwargs["username"] == "consumer"
    assert kwargs["password"] == "consumer-test-pass"
    assert kwargs["decode_responses"] is True
    # lib_name and lib_version must be None to prevent CLIENT SETINFO NOPERM
    assert kwargs.get("lib_name") is None
    assert kwargs.get("lib_version") is None


def test_invalid_numeric_values_fall_back(tmp_path: Path) -> None:
    """Invalid integer values safely fallback to defaults."""
    env_file = tmp_path / ".env.local"
    env_file.write_text(
        "REDIS_PORT=bad\nBLOCK_TIMEOUT_MS=invalid\nBATCH_SIZE=nan\n",
        encoding="utf-8",
    )
    with patch.dict(os.environ, {}, clear=True):
        settings = load_settings(env_file=env_file)
        assert settings.redis_port == 6379
        assert settings.block_timeout_ms == 2000
        assert settings.batch_size == 10


def test_find_env_local(tmp_path: Path) -> None:
    """Test find_env_local finds .env.local in start_dir or parent."""
    sub_dir = tmp_path / "app" / "worker"
    sub_dir.mkdir(parents=True)
    env_file = tmp_path / ".env.local"
    env_file.write_text("REDIS_HOST=found-host\n", encoding="utf-8")

    found = find_env_local(start_dir=sub_dir)
    assert found is not None
    assert found.resolve() == env_file.resolve()


def test_parse_env_file() -> None:
    """Test parsing nonexistent or empty env files."""
    assert parse_env_file(None) == {}
    assert parse_env_file(Path("does_not_exist_file.env")) == {}
