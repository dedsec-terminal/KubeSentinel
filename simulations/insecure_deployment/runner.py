"""Runner for Scenario 4: Insecure Workload Admission Rejection (Kyverno)."""

from __future__ import annotations

import time
from pathlib import Path

from scripts.k8s_client import run_kubectl
from simulations.base import BaseSimulation, SimulationResult


class InsecureDeploymentSimulation(BaseSimulation):
    """Verifies Policy-as-Code admission control enforcement:

    Attempts to deploy a non-compliant workload manifest that violates container security policies
    (such as ':latest' tag and missing resource limits). Verifies that the Kyverno validating webhook
    rejects admission and that the workload is never created.
    """

    scenario_name = "insecure-deployment"
    control_type = "prevention"

    def __init__(self, target_namespace: str = "edge-pune", deployment_name: str = "sim-insecure-workload") -> None:
        self.target_namespace = target_namespace
        self.deployment_name = deployment_name

    @property
    def metadata_file(self) -> Path:
        return Path(__file__).resolve().parent / "metadata.yaml"

    @property
    def fixture_file(self) -> Path:
        return Path(__file__).resolve().parent / "fixtures" / "violating-workload.yaml"

    def run(self, timeout_sec: float = 30.0) -> SimulationResult:
        start_time = time.monotonic()
        fixture_content = self.fixture_file.read_text(encoding="utf-8")

        try:
            # 1. Attempt admission of non-compliant workload
            apply_res = run_kubectl(["apply", "-f", "-"], input_text=fixture_content, timeout=15.0)

            duration = time.monotonic() - start_time
            err_output = (apply_res.stderr or apply_res.stdout).strip()

            # Kyverno validating admission webhook denial check
            rejected_by_webhook = (
                apply_res.returncode != 0
                and ("validate.kyverno.svc" in err_output or "admission webhook" in err_output)
            )

            # Detect specific policies triggered
            policies_detected: list[str] = []
            for pol in [
                "disallow-latest-tag",
                "require-resource-requests-limits",
                "disallow-privilege-escalation",
                "require-drop-all-capabilities",
                "require-run-as-non-root",
                "require-runtime-default-seccomp",
            ]:
                if pol in err_output:
                    policies_detected.append(pol)

            # 2. Verify workload was NOT created in the cluster
            check_res = run_kubectl(
                ["get", "deployment", self.deployment_name, "-n", self.target_namespace],
                timeout=5.0,
            )
            workload_not_created = (
                check_res.returncode != 0
                and "NotFound" in (check_res.stderr or check_res.stdout)
            )

            all_passed = rejected_by_webhook and workload_not_created and len(policies_detected) > 0

            summary = (
                f"Kyverno admission webhook blocked non-compliant deployment '{self.deployment_name}' "
                f"(violated policies: {', '.join(policies_detected)})"
                if all_passed
                else f"Admission rejection check failed: returncode={apply_res.returncode}, output={err_output[:200]}"
            )

            return SimulationResult(
                scenario=self.scenario_name,
                status="PASS" if all_passed else "FAIL",
                control_type=self.control_type,
                summary=summary,
                details={
                    "deployment_name": self.deployment_name,
                    "target_namespace": self.target_namespace,
                    "admission_rejected": rejected_by_webhook,
                    "policies_triggered": policies_detected,
                    "workload_not_created": workload_not_created,
                    "rejection_message": err_output,
                    "telemetry_gap": {
                        "rejection_logs_indexed": False,
                        "reason": "Kyverno admission rejections are recorded synchronously by the API server and in controller webhook logs; they are not streamed to Elasticsearch.",
                    },
                },
                duration_sec=round(duration, 3),
                metadata_path=str(self.metadata_file),
            )
        finally:
            # Strict cleanup: ensure any accidental creation is removed
            run_kubectl(
                ["delete", "deployment", self.deployment_name, "-n", self.target_namespace, "--ignore-not-found=true"],
                timeout=10.0,
            )
