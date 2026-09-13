"""Unit tests for edge-api configuration and Redis client creation."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

from edge_api.config import (
    Settings,
    create_redis_client,
    find_env_local,
    get_redis_client,
    get_settings,
    load_settings,
    parse_env_file,
)


def test_settings_defaults() -> None:
    """Test default settings when no environment variables or file are present."""
    with patch.dict(os.environ, {}, clear=True):
        settings = load_settings(env_file=Path("nonexistent.env"))
        assert settings.redis_host == "127.0.0.1"
        assert settings.redis_port == 6379
        assert settings.redis_producer_password == ""
        assert settings.redis_stream == "security-events"
        assert settings.edge_site == "pune"
        assert settings.namespace == "local-compose"
        assert settings.service == "edge-api"


def test_get_settings_dependency() -> None:
    """Verify get_settings returns a Settings instance."""
    s = get_settings()
    assert isinstance(s, Settings)


def test_parse_env_file(tmp_path: Path) -> None:
    """Test parsing .env file format with comments and quotes."""
    env_file = tmp_path / "test.env"
    env_file.write_text(
        """# Sample comment
REDIS_HOST="redis.internal"
REDIS_PORT=6380
REDIS_PRODUCER_PASSWORD='secret-password'
EDGE_SITE=mumbai
EMPTY_LINE=
""",
        encoding="utf-8",
    )
    parsed = parse_env_file(env_file)
    assert parsed["REDIS_HOST"] == "redis.internal"
    assert parsed["REDIS_PORT"] == "6380"
    assert parsed["REDIS_PRODUCER_PASSWORD"] == "secret-password"
    assert parsed["EDGE_SITE"] == "mumbai"
    assert parsed["EMPTY_LINE"] == ""


def test_parse_nonexistent_env_file() -> None:
    """Test that parsing nonexistent or None path returns empty dict."""
    assert parse_env_file(None) == {}
    assert parse_env_file(Path("does_not_exist.env")) == {}


def test_env_var_precedence_over_file(tmp_path: Path) -> None:
    """Environment variables take precedence over .env file values."""
    env_file = tmp_path / ".env.local"
    env_file.write_text(
        "REDIS_HOST=from-file\nREDIS_PORT=6379\nEDGE_SITE=mumbai\n",
        encoding="utf-8",
    )

    with patch.dict(
        os.environ,
        {"REDIS_HOST": "from-env", "EDGE_SITE": "bangalore"},
        clear=True,
    ):
        settings = load_settings(env_file=env_file)
        assert settings.redis_host == "from-env"
        assert settings.redis_port == 6379
        assert settings.edge_site == "bangalore"


def test_invalid_port_falls_back_to_default(tmp_path: Path) -> None:
    """Invalid integer for port falls back safely to 6379."""
    env_file = tmp_path / ".env.local"
    env_file.write_text("REDIS_PORT=invalid\n", encoding="utf-8")
    with patch.dict(os.environ, {}, clear=True):
        settings = load_settings(env_file=env_file)
        assert settings.redis_port == 6379


def test_find_env_local(tmp_path: Path) -> None:
    """Test find_env_local finds .env.local in start_dir or parent."""
    sub_dir = tmp_path / "subdir" / "nested"
    sub_dir.mkdir(parents=True)
    env_file = tmp_path / ".env.local"
    env_file.write_text("EDGE_SITE=pune\n", encoding="utf-8")

    found = find_env_local(start_dir=sub_dir)
    assert found is not None
    assert found.resolve() == env_file.resolve()


def test_create_redis_client_configuration() -> None:
    """Verify create_redis_client configures producer credentials and suppresses CLIENT SETINFO."""
    settings = Settings(
        redis_host="10.0.0.1",
        redis_port=6389,
        redis_producer_password="test-password-123",
        redis_stream="security-events",
        edge_site="pune",
    )
    client = create_redis_client(settings)
    pool = client.connection_pool
    kwargs = pool.connection_kwargs

    assert kwargs["host"] == "10.0.0.1"
    assert kwargs["port"] == 6389
    assert kwargs["username"] == "producer"
    assert kwargs["password"] == "test-password-123"
    assert kwargs["decode_responses"] is True
    # lib_name and lib_version must be None or driver_info None to avoid CLIENT SETINFO NOPERM
    assert kwargs.get("lib_name") is None
    assert kwargs.get("lib_version") is None


def test_get_redis_client_dependency() -> None:
    """Verify get_redis_client produces a client without error."""
    client = get_redis_client()
    assert client.connection_pool.connection_kwargs["username"] == "producer"
