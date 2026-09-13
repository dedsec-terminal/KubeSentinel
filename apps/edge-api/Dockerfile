# Stage 1: Build virtual environment and wheels
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir pip==26.2.1 setuptools==84.0.0 wheel==0.46.3

WORKDIR /build
COPY apps/edge-api/requirements.txt /build/requirements.txt
RUN pip install --no-cache-dir -r /build/requirements.txt

COPY apps/common /build/common
RUN pip install --no-cache-dir /build/common

# Stage 2: Hardened Runtime
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH="/app"

RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 10001 appuser && \
    useradd -u 10001 -g 10001 -s /sbin/nologin -M appuser

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY --chown=10001:10001 apps/edge-api/src/edge_api /app/edge_api
COPY --chown=10001:10001 apps/common/src/edge_common /app/edge_common
COPY --chown=10001:10001 telemetry /app/telemetry

RUN rm -rf \
    /usr/local/lib/python3.11/site-packages/pip* \
    /usr/local/lib/python3.11/site-packages/setuptools* \
    /usr/local/lib/python3.11/site-packages/wheel* \
    /opt/venv/lib/python3.11/site-packages/pip* \
    /opt/venv/lib/python3.11/site-packages/setuptools* \
    /opt/venv/lib/python3.11/site-packages/wheel* \
    /opt/venv/lib/python3.11/site-packages/jaraco* \
    /opt/venv/lib/python3.11/site-packages/msgpack*

USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"]

CMD ["uvicorn", "edge_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
