"""Runner for Scenario 1: Shell Execution in Edge Workload Pod."""

from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Any

from scripts.k8s_client import run_kubectl
from scripts.setup_es_templates import get_es_credentials, request_es
from simulations.base import BaseSimulation, SimulationResult


class ShellSimulation(BaseSimulation):
    """Executes a safe shell command in an edge workload pod and verifies Falco detection in Elasticsearch."""

    scenario_name = "shell"
    control_type = "detection"

    def __init__(self, target_namespace: str = "edge-pune", target_deployment: str = "deployment/edge-api") -> None:
        self.target_namespace = target_namespace
        self.target_deployment = target_deployment

    @property
    def metadata_file(self) -> Path:
        return Path(__file__).resolve().parent / "metadata.yaml"

    def run(self, timeout_sec: float = 30.0) -> SimulationResult:
        start_time = time.monotonic()
        marker = f"kubesentinel-sim-shell-{uuid.uuid4().hex[:8]}"

        # 1. Trigger controlled shell execution
        exec_res = run_kubectl(
            [
                "exec",
                "-n",
                self.target_namespace,
                self.target_deployment,
                "--",
                "sh",
                "-c",
                f"echo {marker}",
            ],
            timeout=10.0,
        )

        if exec_res.returncode != 0:
            duration = time.monotonic() - start_time
            return SimulationResult(
                scenario=self.scenario_name,
                status="FAIL",
                control_type=self.control_type,
                summary=f"Failed to execute controlled shell in {self.target_namespace}: {exec_res.stderr.strip()}",
                details={"marker": marker, "stderr": exec_res.stderr.strip(), "returncode": exec_res.returncode},
                duration_sec=round(duration, 3),
                metadata_path=str(self.metadata_file),
            )

        # 2. Query Elasticsearch for Falco alert matching marker
        username, password = get_es_credentials()
        alert_doc: dict[str, Any] = {}
        hit_meta: dict[str, Any] = {}
        doc_found = False

        # Bounded polling for Elasticsearch ingestion via Fluent Bit
        search_timeout = min(timeout_sec - (time.monotonic() - start_time), 25.0)
        poll_start = time.monotonic()

        while time.monotonic() - poll_start < search_timeout:
            # Query by exact match on marker string
            search_query = {
                "query": {
                    "match_phrase": {
                        "output_fields.proc_cmdline": marker,
                    }
                }
            }
            code, search_res = request_es(
                "kubesentinel-falco-*/_search",
                method="POST",
                data=search_query,
                username=username,
                password=password,
            )

            if code == 200 and isinstance(search_res, dict):
                hits = search_res.get("hits", {}).get("hits", [])
                if hits:
                    hit_meta = hits[0]
                    alert_doc = hit_meta.get("_source", {})
                    doc_found = True
                    break

            time.sleep(1.5)

        duration = time.monotonic() - start_time

        if not doc_found:
            return SimulationResult(
                scenario=self.scenario_name,
                status="FAIL",
                control_type=self.control_type,
                summary=f"Falco alert with marker {marker} not found in Elasticsearch within {timeout_sec}s",
                details={
                    "marker": marker,
                    "target_namespace": self.target_namespace,
                    "target_deployment": self.target_deployment,
                },
                duration_sec=round(duration, 3),
                metadata_path=str(self.metadata_file),
            )

        output_fields = alert_doc.get("output_fields", {})
        rule = alert_doc.get("rule")
        priority = alert_doc.get("priority")
        ns_detected = output_fields.get("k8s_ns_name") or output_fields.get("k8s.ns.name")
        pod_detected = output_fields.get("k8s_pod_name") or output_fields.get("k8s.pod.name")

        return SimulationResult(
            scenario=self.scenario_name,
            status="PASS",
            control_type=self.control_type,
            summary=f"Falco detected shell in {ns_detected} (rule: '{rule}', priority: '{priority}') and indexed in Elasticsearch",
            details={
                "marker": marker,
                "rule": rule,
                "priority": priority,
                "source": alert_doc.get("source"),
                "namespace": ns_detected,
                "pod": pod_detected,
                "proc_cmdline": output_fields.get("proc_cmdline"),
                "es_index": hit_meta.get("_index"),
                "es_doc_id": hit_meta.get("_id"),
                "timestamp": alert_doc.get("@timestamp") or alert_doc.get("timestamp"),
            },
            duration_sec=round(duration, 3),
            metadata_path=str(self.metadata_file),
        )
