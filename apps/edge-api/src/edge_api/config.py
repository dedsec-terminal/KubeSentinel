"""Configuration and Redis client management for edge-api."""

from __future__ import annotations

import os
import warnings
from pathlib import Path
from typing import Any

import redis
from edge_common.models import EdgeSite
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


class Settings(BaseModel):
    """Configuration settings for edge-api service."""

    model_config = ConfigDict(extra="ignore")

    redis_host: str = Field(default="127.0.0.1")
    redis_port: int = Field(default=6379)
    redis_producer_password: str = Field(default="")
    redis_stream: str = Field(default="security-events")
    edge_site: EdgeSite = Field(default="pune")
    namespace: str = Field(default="local-compose")
    service: str = Field(default="edge-api")
    pod_name: str | None = Field(default=None)
    node_name: str | None = Field(default=None)
    k8s_namespace: str | None = Field(default=None)


def load_settings(
    env_file: Path | None = None,
    **overrides: Any,
) -> Settings:
    """Load configuration from environment variables with .env.local fallback."""
    env_path = env_file if env_file is not None else find_env_local()
    file_vars = parse_env_file(env_path)

    def resolve(key: str, default: Any) -> Any:
        if key in overrides and overrides[key] is not None:
            return overrides[key]
        if key in os.environ and os.environ[key] != "":
            return os.environ[key]
        if key in file_vars and file_vars[key] != "":
            return file_vars[key]
        return default

    redis_port_raw = resolve("REDIS_PORT", 6379)
    try:
        redis_port = int(redis_port_raw)
    except (ValueError, TypeError):
        redis_port = 6379

    pod_name = overrides.get("pod_name") or resolve(
        "KUBERNETES_POD_NAME", resolve("POD_NAME", None)
    )
    node_name = overrides.get("node_name") or resolve(
        "KUBERNETES_NODE_NAME", resolve("NODE_NAME", None)
    )
    k8s_namespace = overrides.get("k8s_namespace") or resolve(
        "KUBERNETES_NAMESPACE", resolve("POD_NAMESPACE", None)
    )

    return Settings(
        redis_host=resolve("REDIS_HOST", "127.0.0.1"),
        redis_port=redis_port,
        redis_producer_password=resolve("REDIS_PRODUCER_PASSWORD", ""),
        redis_stream=resolve("REDIS_STREAM", "security-events"),
        edge_site=overrides.get("edge_site") or resolve("EDGE_SITE", "pune"),
        namespace=resolve("NAMESPACE", "local-compose"),
        service=resolve("SERVICE", "edge-api"),
        pod_name=pod_name,
        node_name=node_name,
        k8s_namespace=k8s_namespace,
    )


def get_settings() -> Settings:
    """FastAPI dependency returning application settings."""
    return load_settings()


def create_redis_client(settings: Settings | None = None) -> redis.Redis:
    """Create Redis client configured with producer ACL credentials.

    lib_name=None and lib_version=None prevent CLIENT SETINFO calls
    which trigger NOPERM logs under producer ACL.
    """
    s = settings or get_settings()
    return redis.Redis(
        host=s.redis_host,
        port=s.redis_port,
        username="producer",
        password=s.redis_producer_password,
        decode_responses=True,
        lib_name=None,
        lib_version=None,
        socket_timeout=5.0,
        socket_connect_timeout=5.0,
    )


def get_redis_client() -> redis.Redis:
    """FastAPI dependency returning Redis client for edge-api."""
    return create_redis_client()


__all__ = [
    "Settings",
    "create_redis_client",
    "find_env_local",
    "get_redis_client",
    "get_settings",
    "load_settings",
    "parse_env_file",
]
