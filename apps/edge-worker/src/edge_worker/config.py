"""Configuration and Redis client management for edge-worker."""

from __future__ import annotations

import os
import socket
import uuid
import warnings
from pathlib import Path
from typing import Any

import redis
from pydantic import BaseModel, ConfigDict, Field

warnings.filterwarnings("ignore", category=DeprecationWarning, message=".*lib_name.*")
warnings.filterwarnings("ignore", category=DeprecationWarning, message=".*lib_version.*")


def find_env_local(start_dir: Path | None = None) -> Path | None:
    """Locate .env.local file in start directory, ancestors, or project root."""
    cwd = (start_dir or Path.cwd()).resolve()
    candidate = cwd / ".env.local"
    if candidate.is_file():
        return candidate
    for parent in cwd.parents:
        candidate = parent / ".env.local"
        if candidate.is_file():
            return candidate
    # Fallback to repository root relative to this module
    try:
        root_candidate = Path(__file__).resolve().parents[4] / ".env.local"
        if root_candidate.is_file():
            return root_candidate
    except IndexError:
        pass
    return None


def parse_env_file(path: Path | None) -> dict[str, str]:
    """Parse environment variables from a dotenv formatted file."""
    if path is None or not path.is_file():
        return {}
    results: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip()
            if (v.startswith('"') and v.endswith('"')) or (
                v.startswith("'") and v.endswith("'")
            ):
                v = v[1:-1]
            results[k] = v
    return results


def _default_worker_id() -> str:
    """Generate default worker identifier based on host and uuid suffix."""
    host = socket.gethostname() or "worker"
    return f"worker-{host}-{uuid.uuid4().hex[:6]}"


class Settings(BaseModel):
    """Configuration settings for edge-worker service."""

    model_config = ConfigDict(extra="ignore")

    redis_host: str = Field(default="127.0.0.1")
    redis_port: int = Field(default=6379)
    redis_consumer_password: str = Field(default="")
    redis_stream: str = Field(default="security-events")
    redis_consumer_group: str = Field(default="edge-workers")
    worker_id: str = Field(default_factory=_default_worker_id)
    block_timeout_ms: int = Field(default=2000)
    batch_size: int = Field(default=10)

    def validate_secrets(self) -> None:
        """Validate that required secrets are present and non-empty."""
        if not self.redis_consumer_password or not self.redis_consumer_password.strip():
            raise ValueError(
                "Missing required secret: REDIS_CONSUMER_PASSWORD must be configured"
            )


def load_settings(
    env_file: Path | None = None,
    require_password: bool = False,
    **overrides: Any,
) -> Settings:
    """Load configuration from environment variables with .env.local fallback."""
    env_path = env_file if env_file is not None else find_env_local()
    file_vars = parse_env_file(env_path)

    def resolve(key: str, default: Any, *fallback_keys: str) -> Any:
        if key in overrides and overrides[key] is not None:
            return overrides[key]
        for fk in fallback_keys:
            if fk in overrides and overrides[fk] is not None:
                return overrides[fk]

        if key in os.environ and os.environ[key] != "":
            return os.environ[key]
        for fk in fallback_keys:
            if fk in os.environ and os.environ[fk] != "":
                return os.environ[fk]

        if key in file_vars and file_vars[key] != "":
            return file_vars[key]
        for fk in fallback_keys:
            if fk in file_vars and file_vars[fk] != "":
                return file_vars[fk]

        return default

    redis_port_raw = resolve("REDIS_PORT", 6379)
    try:
        redis_port = int(redis_port_raw)
    except (ValueError, TypeError):
        redis_port = 6379

    block_timeout_raw = resolve("BLOCK_TIMEOUT_MS", 2000)
    try:
        block_timeout_ms = int(block_timeout_raw)
    except (ValueError, TypeError):
        block_timeout_ms = 2000

    batch_size_raw = resolve("BATCH_SIZE", 10)
    try:
        batch_size = int(batch_size_raw)
    except (ValueError, TypeError):
        batch_size = 10

    worker_id_val = resolve("WORKER_ID", None, "CONSUMER_ID")
    worker_id = worker_id_val if worker_id_val else _default_worker_id()

    settings = Settings(
        redis_host=resolve("REDIS_HOST", "127.0.0.1"),
        redis_port=redis_port,
        redis_consumer_password=resolve(
            "REDIS_CONSUMER_PASSWORD", "", "REDIS_PASSWORD"
        ),
        redis_stream=resolve("REDIS_STREAM", "security-events", "STREAM_NAME"),
        redis_consumer_group=resolve(
            "REDIS_CONSUMER_GROUP", "edge-workers", "CONSUMER_GROUP"
        ),
        worker_id=worker_id,
        block_timeout_ms=block_timeout_ms,
        batch_size=batch_size,
    )

    if require_password:
        settings.validate_secrets()

    return settings


def create_redis_client(
    settings: Settings | None = None,
    require_password: bool = True,
) -> redis.Redis:
    """Create Redis client configured with consumer ACL credentials.

    lib_name=None and lib_version=None prevent CLIENT SETINFO calls
    which trigger NOPERM logs under consumer ACL.
    """
    s = settings or load_settings()
    if require_password:
        s.validate_secrets()

    return redis.Redis(
        host=s.redis_host,
        port=s.redis_port,
        username="consumer",
        password=s.redis_consumer_password,
        decode_responses=True,
        lib_name=None,
        lib_version=None,
        socket_timeout=5.0,
        socket_connect_timeout=5.0,
    )


__all__ = [
    "Settings",
    "create_redis_client",
    "find_env_local",
    "load_settings",
    "parse_env_file",
]
