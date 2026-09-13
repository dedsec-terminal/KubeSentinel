"""Unit tests for Downward API metadata enrichment in edge-api."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from edge_api.config import get_redis_client, get_settings, load_settings
from edge_api.main import app
from httpx import ASGITransport, AsyncClient


class MockRedisClient:
    """Mock Redis client capturing xadd calls."""

    def __init__(self) -> None:
        self.xadd_calls: list[dict[str, Any]] = []

    def ping(self) -> bool:
        return True

    def xadd(
        self,
        name: str,
        fields: dict[str, Any],
        maxlen: int | None = None,
        approximate: bool = True,
    ) -> str:
        self.xadd_calls.append(
            {
                "name": name,
                "fields": fields,
                "maxlen": maxlen,
                "approximate": approximate,
            }
        )
        return "1789246370665-0"


def test_settings_with_downward_api_env_vars() -> None:
    """Verify settings resolve Kubernetes Downward API environment variables."""
    k8s_env = {
        "KUBERNETES_POD_NAME": "edge-api-pune-7d84b6f98-xyz",
        "KUBERNETES_NODE_NAME": "k3d-kubesentinel-server-0",
        "KUBERNETES_NAMESPACE": "edge-pune",
        "EDGE_SITE": "pune",
    }
    with patch.dict(os.environ, k8s_env, clear=True):
        settings = load_settings(env_file=Path("nonexistent.env"))
        assert settings.pod_name == "edge-api-pune-7d84b6f98-xyz"
        assert settings.node_name == "k3d-kubesentinel-server-0"
        assert settings.k8s_namespace == "edge-pune"
        assert settings.edge_site == "pune"


def test_settings_fallback_compose() -> None:
    """Verify settings fallback cleanly when Downward API environment variables are absent."""
    with patch.dict(os.environ, {"EDGE_SITE": "pune"}, clear=True):
        settings = load_settings(env_file=Path("nonexistent.env"))
        assert settings.pod_name is None
        assert settings.node_name is None
        assert settings.k8s_namespace is None
        assert settings.namespace == "local-compose"


@pytest.mark.anyio
async def test_create_event_with_downward_api_enrichment() -> None:
    """Verify POST /events enriches event metadata with truthful Downward API attributes."""
    mock_redis = MockRedisClient()
    k8s_settings = load_settings(
        env_file=Path("nonexistent.env"),
        pod_name="edge-api-mumbai-9f44c1d-abc",
        node_name="k3d-kubesentinel-server-0",
        k8s_namespace="edge-mumbai",
        edge_site="mumbai",
    )

    app.dependency_overrides[get_redis_client] = lambda: mock_redis
    app.dependency_overrides[get_settings] = lambda: k8s_settings

    payload = {
        "event_type": "security_simulation",
        "severity": "high",
        "source": "10.42.0.5",
        "destination": "10.42.0.1",
        "message": "Downward API enrichment test",
        "metadata": {"simulation_id": "sim-001"},
    }

    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),  # type: ignore[arg-type]
            base_url="http://test",
        ) as client:
            resp = await client.post("/events", json=payload)
            assert resp.status_code == 202
            data = resp.json()
            assert data["status"] == "accepted"

        assert len(mock_redis.xadd_calls) == 1
        stored_event_raw = mock_redis.xadd_calls[0]["fields"]["event"]
        stored_event = json.loads(stored_event_raw)

        # Enriched metadata checks
        meta = stored_event["metadata"]
        assert meta["simulation_id"] == "sim-001"
        assert meta["pod_name"] == "edge-api-mumbai-9f44c1d-abc"
        assert meta["node_name"] == "k3d-kubesentinel-server-0"
        assert meta["k8s_namespace"] == "edge-mumbai"
        assert meta["container_name"] == "edge-api"
        assert meta["k8s"]["pod_name"] == "edge-api-mumbai-9f44c1d-abc"
        assert meta["k8s"]["container_name"] == "edge-api"
        assert meta["k8s"]["node_name"] == "k3d-kubesentinel-server-0"

        # Contract invariants preserved
        assert stored_event["pod"] is None
        assert stored_event["container"] is None
        assert stored_event["node"] is None
        assert stored_event["edge_site"] == "mumbai"
    finally:
        app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_create_event_without_downward_api_fallback() -> None:
    """Verify POST /events preserves standard metadata when Downward API is absent."""
    mock_redis = MockRedisClient()
    compose_settings = load_settings(
        env_file=Path("nonexistent.env"),
        pod_name=None,
        node_name=None,
        k8s_namespace=None,
        edge_site="pune",
    )

    app.dependency_overrides[get_redis_client] = lambda: mock_redis
    app.dependency_overrides[get_settings] = lambda: compose_settings

    payload = {
        "event_type": "security_simulation",
        "severity": "low",
        "source": "172.18.0.2",
        "message": "Compose fallback test",
        "metadata": {"custom_key": "custom_val"},
    }

    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),  # type: ignore[arg-type]
            base_url="http://test",
        ) as client:
            resp = await client.post("/events", json=payload)
            assert resp.status_code == 202

        assert len(mock_redis.xadd_calls) == 1
        stored_event_raw = mock_redis.xadd_calls[0]["fields"]["event"]
        stored_event = json.loads(stored_event_raw)

        meta = stored_event["metadata"]
        assert meta == {"custom_key": "custom_val"}
        assert "pod_name" not in meta
        assert "container_name" not in meta
        assert "k8s" not in meta
        assert stored_event["pod"] is None
        assert stored_event["container"] is None
        assert stored_event["node"] is None
    finally:
        app.dependency_overrides.clear()
