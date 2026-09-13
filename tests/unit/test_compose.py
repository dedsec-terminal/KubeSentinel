"""Automated validation tests for docker-compose.yml orchestration and hardening."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = ROOT / "docker-compose.yml"


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    """Lightweight, self-contained YAML parser for docker-compose.yml structure.

    Avoids external third-party dependencies while providing deterministic parsing
    for mapping hierarchies, string scalars, booleans, and lists.
    """
    lines = text.splitlines()
    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any] | list[Any]]] = [(-1, root)]
    current_key: str | None = None

    for raw_line in lines:
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(raw_line) - len(raw_line.lstrip(" "))

        # Pop stack levels deeper or equal to current indent
        while stack and stack[-1][0] >= indent:
            stack.pop()

        parent = stack[-1][1]

        if stripped.startswith("- "):
            val_str = stripped[2:].strip()
            # Unquote if quoted
            if (val_str.startswith('"') and val_str.endswith('"')) or (
                val_str.startswith("'") and val_str.endswith("'")
            ):
                val: Any = val_str[1:-1]
            elif val_str.lower() == "true":
                val = True
            elif val_str.lower() == "false":
                val = False
            else:
                val = val_str

            if isinstance(parent, list):
                parent.append(val)
            elif isinstance(parent, dict) and current_key:
                lst: list[Any] = [val]
                parent[current_key] = lst
                stack.append((indent, lst))
        elif ":" in stripped:
            key, _, val_part = stripped.partition(":")
            key = key.strip()
            val_str = val_part.strip()

            if val_str:
                if (val_str.startswith('"') and val_str.endswith('"')) or (
                    val_str.startswith("'") and val_str.endswith("'")
                ):
                    val = val_str[1:-1]
                elif val_str.lower() == "true":
                    val = True
                elif val_str.lower() == "false":
                    val = False
                elif val_str.isdigit():
                    val = int(val_str)
                elif val_str.startswith("[") and val_str.endswith("]"):
                    items = [
                        item.strip().strip("'\"")
                        for item in val_str[1:-1].split(",")
                        if item.strip()
                    ]
                    val = items
                else:
                    val = val_str

                if isinstance(parent, dict):
                    parent[key] = val
                    current_key = key
            else:
                new_dict: dict[str, Any] = {}
                if isinstance(parent, dict):
                    parent[key] = new_dict
                    stack.append((indent, new_dict))
                    current_key = key

    return root


def get_compose_data() -> dict[str, Any]:
    """Retrieve compose structure via docker compose config JSON or fallback parser."""
    assert COMPOSE_FILE.is_file(), f"Missing compose file at {COMPOSE_FILE}"
    content = COMPOSE_FILE.read_text(encoding="utf-8")

    # If docker CLI is installed, docker compose config --format json provides exact schema
    if shutil.which("docker"):
        try:
            res = subprocess.run(
                ["docker", "compose", "config", "--format", "json"],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                return json.loads(res.stdout)
        except (subprocess.SubprocessError, json.JSONDecodeError, OSError):
            return _parse_simple_yaml(content)

    return _parse_simple_yaml(content)


def test_compose_file_exists() -> None:
    """Verify docker-compose.yml exists at repository root."""
    assert COMPOSE_FILE.is_file()


def test_compose_contains_expected_services() -> None:
    """Verify docker-compose.yml defines all four required services."""
    data = get_compose_data()
    services = data.get("services", {})
    assert set(services.keys()) == {"redis", "redis-bootstrap", "edge-api", "edge-worker"}


def test_port_exposure_isolation() -> None:
    """Verify strict port isolation: only edge-api publishes host port 8000."""
    data = get_compose_data()
    services = data.get("services", {})

    # Redis must have NO host port publishing (internal network only)
    redis_ports = services.get("redis", {}).get("ports")
    assert not redis_ports, "Redis must not publish any host ports (zero host port 6379 exposure)"

    # redis-bootstrap must have no published ports
    bootstrap_ports = services.get("redis-bootstrap", {}).get("ports")
    assert not bootstrap_ports, "redis-bootstrap must not publish any ports"

    # edge-worker must have no published ports
    worker_ports = services.get("edge-worker", {}).get("ports")
    assert not worker_ports, "edge-worker must not publish any ports"

    # edge-api must expose host port 8000
    api_ports = services.get("edge-api", {}).get("ports", [])
    assert api_ports, "edge-api must publish port 8000"

    port_found = False
    for p in api_ports:
        if isinstance(p, dict):
            if str(p.get("published")) == "8000" or str(p.get("target")) == "8000":
                port_found = True
        elif isinstance(p, str) and ("8000:8000" in p or "8000" in p):
            port_found = True
    assert port_found, "edge-api must publish port 8000:8000"


def test_container_hardening_attributes_across_all_services() -> None:
    """Verify all services enforce read_only, cap_drop ALL, and no-new-privileges."""
    data = get_compose_data()
    services = data.get("services", {})

    for name, svc in services.items():
        # read_only: true
        assert svc.get("read_only") is True, f"Service {name} must set read_only: true"

        # cap_drop: ALL
        cap_drop = svc.get("cap_drop", [])
        assert "ALL" in cap_drop, f"Service {name} must drop ALL capabilities"

        # security_opt: no-new-privileges:true
        sec_opt = svc.get("security_opt", [])
        assert any(
            "no-new-privileges:true" in opt or "no-new-privileges" in opt for opt in sec_opt
        ), f"Service {name} must enforce no-new-privileges:true"


def test_startup_dependencies_and_independent_edge_worker() -> None:
    """Verify startup order and Mandatory Amendment #1 (edge-worker independent of edge-api)."""
    data = get_compose_data()
    services = data.get("services", {})

    # redis-bootstrap depends on redis service_healthy
    bootstrap_deps = services.get("redis-bootstrap", {}).get("depends_on", {})
    assert "redis" in bootstrap_deps
    assert bootstrap_deps["redis"].get("condition") == "service_healthy"

    # edge-api depends on redis healthy and redis-bootstrap completed
    api_deps = services.get("edge-api", {}).get("depends_on", {})
    assert "redis" in api_deps
    assert api_deps["redis"].get("condition") == "service_healthy"
    assert "redis-bootstrap" in api_deps
    assert api_deps["redis-bootstrap"].get("condition") == "service_completed_successfully"

    # edge-worker depends on redis healthy and redis-bootstrap completed
    worker_deps = services.get("edge-worker", {}).get("depends_on", {})
    assert "redis" in worker_deps
    assert worker_deps["redis"].get("condition") == "service_healthy"
    assert "redis-bootstrap" in worker_deps
    assert worker_deps["redis-bootstrap"].get("condition") == "service_completed_successfully"

    # CRITICAL USER AMENDMENT #1: edge-worker must NOT depend on edge-api
    assert "edge-api" not in worker_deps, (
        "CRITICAL AMENDMENT #1 VIOLATION: edge-worker must NOT depend on edge-api readiness! "
        "Both edge-api and edge-worker are independent Redis clients."
    )


def test_redis_exact_patch_tag_pinning() -> None:
    """Verify Redis services use exact verified patch tag redis:7.4.2-alpine."""
    data = get_compose_data()
    services = data.get("services", {})

    redis_img = services.get("redis", {}).get("image")
    assert redis_img == "redis:7.4.2-alpine", (
        f"Redis image must be pinned to exact official patch tag redis:7.4.2-alpine, got {redis_img}"
    )

    bootstrap_img = services.get("redis-bootstrap", {}).get("image")
    assert bootstrap_img == "redis:7.4.2-alpine", (
        f"redis-bootstrap image must be redis:7.4.2-alpine, got {bootstrap_img}"
    )


def test_bridge_network_configuration() -> None:
    """Verify internal kubesentinel-net bridge network is defined and attached."""
    data = get_compose_data()
    networks = data.get("networks", {})
    assert "kubesentinel-net" in networks
    assert networks["kubesentinel-net"].get("driver") == "bridge"

    services = data.get("services", {})
    for name, svc in services.items():
        svc_nets = svc.get("networks", {})
        assert "kubesentinel-net" in svc_nets, f"Service {name} must attach to kubesentinel-net"


def test_docker_compose_config_clean_exit() -> None:
    """Verify docker compose config passes cleanly with zero syntax/schema errors."""
    if not shutil.which("docker"):
        return

    result = subprocess.run(
        ["docker", "compose", "config"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"docker compose config failed:\n{result.stderr}"
