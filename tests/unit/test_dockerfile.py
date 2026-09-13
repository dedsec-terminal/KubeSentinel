"""Automated validation tests for edge-api and edge-worker Dockerfiles."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EDGE_API_DOCKERFILE = ROOT / "apps" / "edge-api" / "Dockerfile"
EDGE_WORKER_DOCKERFILE = ROOT / "apps" / "edge-worker" / "Dockerfile"


def test_dockerfiles_exist_on_disk() -> None:
    """Verify both service Dockerfiles exist at canonical repository paths."""
    assert EDGE_API_DOCKERFILE.is_file(), f"Missing {EDGE_API_DOCKERFILE}"
    assert EDGE_WORKER_DOCKERFILE.is_file(), f"Missing {EDGE_WORKER_DOCKERFILE}"


def test_multistage_and_base_image_pinning() -> None:
    """Verify multi-stage build structure and python:3.11-slim base image."""
    for path in (EDGE_API_DOCKERFILE, EDGE_WORKER_DOCKERFILE):
        content = path.read_text(encoding="utf-8")
        lines = [line.strip() for line in content.splitlines()]

        from_lines = [line for line in lines if line.startswith("FROM ")]
        assert len(from_lines) == 2, f"{path} must define exactly two build stages (multi-stage)"

        # Builder stage
        assert "FROM python:3.11-slim AS builder" in from_lines[0]
        # Runtime stage
        assert from_lines[1].startswith("FROM python:3.11-slim AS ")


def test_unbuffered_and_bytecode_environment_flags() -> None:
    """Verify unbuffered stdout and bytecode suppression environment variables."""
    for path in (EDGE_API_DOCKERFILE, EDGE_WORKER_DOCKERFILE):
        content = path.read_text(encoding="utf-8")
        assert "PYTHONDONTWRITEBYTECODE=1" in content
        assert "PYTHONUNBUFFERED=1" in content


def test_non_root_user_and_workdir() -> None:
    """Verify non-root user 10001:10001 creation and enforcement."""
    for path in (EDGE_API_DOCKERFILE, EDGE_WORKER_DOCKERFILE):
        content = path.read_text(encoding="utf-8")

        # Must create non-root user with UID 10001 and GID 10001
        assert "10001" in content
        assert re.search(r"useradd.*-u\s+10001", content)
        assert re.search(r"groupadd.*-g\s+10001", content)

        # Must enforce non-root execution
        assert "USER 10001:10001" in content

        # Working directory must be /app
        assert "WORKDIR /app" in content


def test_virtualenv_and_source_isolation() -> None:
    """Verify virtualenv build in builder stage and copy into runtime."""
    for path in (EDGE_API_DOCKERFILE, EDGE_WORKER_DOCKERFILE):
        content = path.read_text(encoding="utf-8")

        assert "python -m venv /opt/venv" in content
        assert "COPY --from=builder /opt/venv /opt/venv" in content
        assert "edge_common" in content


def test_edge_api_specific_port_and_cmd() -> None:
    """Verify edge-api exposes port 8000 and starts uvicorn server."""
    content = EDGE_API_DOCKERFILE.read_text(encoding="utf-8")

    assert "EXPOSE 8000" in content
    assert 'CMD ["uvicorn", "edge_api.main:app", "--host", "0.0.0.0", "--port", "8000"]' in content


def test_edge_worker_cmd_and_no_exposed_ports() -> None:
    """Verify edge-worker starts worker loop and does not expose ports."""
    content = EDGE_WORKER_DOCKERFILE.read_text(encoding="utf-8")

    assert 'CMD ["python", "-m", "edge_worker.main"]' in content
    assert "EXPOSE" not in content
