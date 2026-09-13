"""Runner for Scenario 5: Cross-Namespace Lateral Access (NetworkPolicy)."""

from __future__ import annotations

import time
from pathlib import Path

from scripts.k8s_client import run_kubectl
from simulations.base import BaseSimulation, SimulationResult


class LateralAccessSimulation(BaseSimulation):
    """Verifies cross-namespace lateral network isolation enforced by NetworkPolicy:

    Attempts a controlled lateral TCP and HTTP request from edge-pune edge-api to
    edge-mumbai edge-api (edge-api.edge-mumbai.svc.cluster.local:8000). Confirms that
    default-deny and namespace isolation block the lateral flow within a bounded timeout.
    """

    scenario_name = "lateral-access"
    control_type = "prevention"

    def __init__(
        self,
        source_namespace: str = "edge-pune",
        source_workload: str = "deployment/edge-api",
        target_service: str = "edge-api.edge-mumbai.svc.cluster.local",
        target_port: int = 8000,
    ) -> None:
        self.source_namespace = source_namespace
        self.source_workload = source_workload
        self.target_service = target_service
        self.target_port = target_port

    @property
    def metadata_file(self) -> Path:
        return Path(__file__).resolve().parent / "metadata.yaml"

    def run(self, timeout_sec: float = 30.0) -> SimulationResult:
        start_time = time.monotonic()

        # In-pod script testing TCP socket connect and HTTP request
        py_probe_code = f"""
import json
import socket
import urllib.error
import urllib.request

results = {{}}

# 1. TCP Socket probe
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2.5)
try:
    s.connect(('{self.target_service}', {self.target_port}))
    results['tcp_probe'] = 'UNEXPECTED_CONNECTED'
except Exception as e:
    results['tcp_probe'] = f'BLOCKED:{{type(e).__name__}}:{{e}}'
finally:
    s.close()

# 2. HTTP probe
req = urllib.request.Request('http://{self.target_service}:{self.target_port}/events')
try:
    urllib.request.urlopen(req, timeout=2.5)
    results['http_probe'] = 'UNEXPECTED_CONNECTED'
except Exception as e:
    results['http_probe'] = f'BLOCKED:{{type(e).__name__}}:{{e}}'

print(json.dumps(results))
"""

        res = run_kubectl(
            [
                "exec",
                "-n",
                self.source_namespace,
                self.source_workload,
                "--",
                "python",
                "-c",
                py_probe_code,
            ],
            timeout=10.0,
        )

        duration = time.monotonic() - start_time

        if res.returncode != 0:
            return SimulationResult(
                scenario=self.scenario_name,
                status="FAIL",
                control_type=self.control_type,
                summary=f"Failed to execute lateral probe inside {self.source_namespace}: {res.stderr.strip()}",
                details={"stderr": res.stderr.strip()},
                duration_sec=round(duration, 3),
                metadata_path=str(self.metadata_file),
            )

        import json

        try:
            data = json.loads(res.stdout.strip())
        except json.JSONDecodeError:
            return SimulationResult(
                scenario=self.scenario_name,
                status="FAIL",
                control_type=self.control_type,
                summary=f"Invalid JSON returned by probe: {res.stdout}",
                details={"stdout": res.stdout, "stderr": res.stderr},
                duration_sec=round(duration, 3),
                metadata_path=str(self.metadata_file),
            )

        tcp_blocked = "BLOCKED:" in data.get("tcp_probe", "")
        http_blocked = "BLOCKED:" in data.get("http_probe", "")
        all_blocked = tcp_blocked and http_blocked

        summary = (
            f"Cross-namespace lateral access from {self.source_namespace} to "
            f"{self.target_service}:{self.target_port} was blocked by NetworkPolicy"
            if all_blocked
            else f"Lateral access isolation failed (tcp_blocked={tcp_blocked}, http_blocked={http_blocked})"
        )

        return SimulationResult(
            scenario=self.scenario_name,
            status="PASS" if all_blocked else "FAIL",
            control_type=self.control_type,
            summary=summary,
            details={
                "source": f"{self.source_namespace}/{self.source_workload}",
                "target": f"{self.target_service}:{self.target_port}",
                "tcp_probe_result": data.get("tcp_probe"),
                "http_probe_result": data.get("http_probe"),
                "network_drop_alert_fabricated": False,
                "telemetry_gap": {
                    "network_drop_indexed": False,
                    "reason": "NetworkPolicy drops packets at the network datapath without emitting indexed event logs to Elasticsearch; this is a pure preventive segmentation control.",
                },
            },
            duration_sec=round(duration, 3),
            metadata_path=str(self.metadata_file),
        )
