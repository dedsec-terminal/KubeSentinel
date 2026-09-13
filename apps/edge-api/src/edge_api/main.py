"""HTTP health, readiness, and security event ingestion endpoints for edge-api."""

from __future__ import annotations

from typing import Annotated, Any, Literal

import redis
from edge_common.events import create_security_event, serialize_security_event
from edge_common.models import EventCorrelationResponse, SecurityEventCreate
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from redis.exceptions import RedisError

from edge_api.config import Settings, get_redis_client, get_settings


class ServiceStatus(BaseModel):
    """Status payload returned by the service lifecycle endpoints."""

    status: Literal["ok", "ready"]
    service: Literal["edge-api"]
    version: str


app = FastAPI(
    title="KubeSentinel Edge API",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@app.get("/health", response_model=ServiceStatus)
def health() -> ServiceStatus:
    """Pure in-memory liveness probe."""
    return ServiceStatus(status="ok", service="edge-api", version="0.1.0")


@app.get("/ready", response_model=ServiceStatus)
def ready(
    client: Annotated[redis.Redis, Depends(get_redis_client)],
) -> Any:
    """Non-mutating readiness probe verifying Redis connectivity via producer identity."""
    try:
        if not client.ping():
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"status": "not_ready", "detail": "Redis connection unavailable"},
            )
    except (RedisError, OSError):
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "not_ready", "detail": "Redis connection unavailable"},
        )
    return ServiceStatus(status="ready", service="edge-api", version="0.1.0")


@app.post(
    "/events",
    response_model=EventCorrelationResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def create_event(
    payload: SecurityEventCreate,
    client: Annotated[redis.Redis, Depends(get_redis_client)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> EventCorrelationResponse:
    """Ingest security event, enrich with server metadata, and stream to Redis."""
    event = create_security_event(
        payload,
        edge_site=settings.edge_site,
        namespace=settings.namespace,
        service=settings.service,
    )
    serialized_json = serialize_security_event(event)

    try:
        raw_stream_id = client.xadd(
            settings.redis_stream,
            {"event": serialized_json},
            maxlen=10000,
            approximate=True,
        )
    except (RedisError, OSError):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Redis service unavailable",
        ) from None

    stream_id = (
        raw_stream_id.decode("utf-8")
        if isinstance(raw_stream_id, bytes)
        else str(raw_stream_id)
    )

    return EventCorrelationResponse(
        status="accepted",
        event_id=str(event.event_id),
        stream=settings.redis_stream,
        stream_id=stream_id,
    )
