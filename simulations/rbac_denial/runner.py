"""Runner for Scenario 3: Kubernetes RBAC Authorization Denial."""

from __future__ import annotations

import time
from pathlib import Path

from scripts.k8s_client import run_kubectl
from simulations.base import BaseSimulation, SimulationResult


class RbacDenialSimulation(BaseSimulation):
    """Verifies RBAC least-privilege boundary enforcement:

    A low-privilege workload ServiceAccount attempting an unauthorized API operation
    (e.g., listing secrets in kube-system) receives an explicit HTTP 403 Forbidden response.
    """

    scenario_name = "rbac-denial"
    control_type = "prevention"

    def __init__(
        self,
        service_account: str = "edge-api-sa",
        namespace: str = "edge-pune",
        target_resource: str = "/api/v1/namespaces/kube-system/secrets",
    ) -> None:
        self.service_account = service_account
        self.namespace = namespace
        self.target_resource = target_resource
        self.sa_identifier = f"system:serviceaccount:{namespace}:{service_account}"

    @property
    def metadata_file(self) -> Path:
        return Path(__file__).resolve().parent / "metadata.yaml"

    def run(self, timeout_sec: float = 30.0) -> SimulationResult:
        start_time = time.monotonic()

        # 1. Authorization check via kubectl auth can-i
        can_i_res = run_kubectl(
            [
                "auth",
                "can-i",
                "list",
                "secrets",
                "-n",
                "kube-system",
                f"--as={self.sa_identifier}",
            ],
            timeout=10.0,
        )
        can_i_output = (can_i_res.stdout or can_i_res.stderr).strip().lower()
        can_i_denied = "no" in can_i_output

        # 2. Direct API request against target resource
        api_res = run_kubectl(
            [
                "get",
                "--raw",
                self.target_resource,
                f"--as={self.sa_identifier}",
            ],
            timeout=10.0,
        )

        duration = time.monotonic() - start_time
        err_msg = api_res.stderr.strip() or api_res.stdout.strip()

        # Check for HTTP 403 Forbidden denial
        is_forbidden = api_res.returncode != 0 and ("Forbidden" in err_msg or "403" in err_msg)

        all_passed = is_forbidden and can_i_denied

        summary = (
            f"Low-privilege ServiceAccount {self.sa_identifier} denied access to {self.target_resource} "
            f"(HTTP 403 Forbidden)"
            if all_passed
            else f"RBAC denial check failed: {err_msg}"
        )

        return SimulationResult(
            scenario=self.scenario_name,
            status="PASS" if all_passed else "FAIL",
            control_type=self.control_type,
            summary=summary,
            details={
                "service_account": self.sa_identifier,
                "target_resource": self.target_resource,
                "http_status": 403 if is_forbidden else 200,
                "forbidden_verified": is_forbidden,
                "can_i_denied": can_i_denied,
                "api_error_message": err_msg,
                "telemetry_gap": {
                    "audit_logging_indexed": False,
                    "reason": "Kubernetes API audit logs are not configured for Fluent Bit ingestion into Elasticsearch; RBAC denial is enforced synchronously at the control plane API server.",
                },
            },
            duration_sec=round(duration, 3),
            metadata_path=str(self.metadata_file),
        )
