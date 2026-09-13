"""Runner for Scenario 2: Redis Unauthorized Access (NetworkPolicy vs Redis ACL)."""

from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Any

from scripts.k8s_client import run_kubectl
from scripts.k8s_deploy import load_or_create_secrets
from simulations.base import BaseSimulation, SimulationResult


class RedisUnauthorizedSimulation(BaseSimulation):
    """Demonstrates two distinct controls protecting Redis:

    1. Network-layer prevention: NetworkPolicy blocks unauthorized TCP access to Redis port 6379.
    2. Data-layer prevention: Redis ACL rejects unauthorized authentication and unauthorized commands
       on the permitted network path.
    """

    scenario_name = "redis-unauthorized"
    control_type = "prevention"

    def __init__(
        self,
        authorized_namespace: str = "edge-pune",
        authorized_workload: str = "deployment/edge-api",
        probe_namespace: str = "observability",
    ) -> None:
        self.authorized_namespace = authorized_namespace
        self.authorized_workload = authorized_workload
        self.probe_namespace = probe_namespace

    @property
    def metadata_file(self) -> Path:
        return Path(__file__).resolve().parent / "metadata.yaml"

    def _test_network_policy_tcp_block(self) -> tuple[bool, str]:
        """Part A: Verify NetworkPolicy blocks an unauthorized workload from connecting to Redis port 6379."""
        probe_id = uuid.uuid4().hex[:6]
        probe_name = f"sim-redis-unauth-{probe_id}"

        # PSA Restricted/Baseline-compliant probe manifest in observability namespace
        pod_manifest = f"""
apiVersion: v1
kind: Pod
metadata:
  name: {probe_name}
  namespace: {self.probe_namespace}
  labels:
    app: unauthorized-redis-probe
spec:
  restartPolicy: Never
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    runAsGroup: 10001
    fsGroup: 10001
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: probe
      image: kubesentinel-edge-api:latest
      imagePullPolicy: IfNotPresent
      command: ["python", "-c", "import socket; s = socket.socket(); s.settimeout(2.0); \\ntry:\\n    s.connect(('redis.kubesentinel-system.svc.cluster.local', 6379))\\n    print('UNEXPECTED_CONNECTED')\\nexcept Exception as e:\\n    print(f'BLOCKED:{{type(e).__name__}}')\\n"]
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
"""
        try:
            run_kubectl(["delete", "pod", "-n", self.probe_namespace, probe_name, "--ignore-not-found=true"])
            apply_res = run_kubectl(["apply", "-f", "-"], input_text=pod_manifest)
            if apply_res.returncode != 0:
                return False, f"Failed to schedule probe pod: {apply_res.stderr.strip()}"

            # Wait up to 6 seconds for probe execution
            start = time.monotonic()
            logs = ""
            while time.monotonic() - start < 6.0:
                log_res = run_kubectl(["logs", "-n", self.probe_namespace, probe_name])
                logs = (log_res.stdout or log_res.stderr).strip()
                if "BLOCKED:" in logs or "UNEXPECTED_CONNECTED" in logs:
                    break
                time.sleep(1.0)

            if "BLOCKED:" in logs:
                reason = logs.split("BLOCKED:")[1].strip()
                return True, f"Blocked by NetworkPolicy ({reason})"
            if "UNEXPECTED_CONNECTED" in logs:
                return False, "Unauthorized probe connected to Redis (NetworkPolicy ingress bypassed)"
            return False, f"Probe produced unexpected output: {logs}"
        finally:
            run_kubectl(["delete", "pod", "-n", self.probe_namespace, probe_name, "--ignore-not-found=true"])

    def _test_redis_acl_rejection(self) -> tuple[bool, dict[str, Any]]:
        """Part B: Verify Redis ACL enforcement on an authorized network path (from edge-api)."""
        producer_pw, _, _ = load_or_create_secrets()

        # In-pod script testing authentication failure and unauthorized command execution
        py_test_code = f"""
import redis
import sys

results = {{}}

# B1: Invalid credentials rejection
r_bad = redis.Redis(
    host='redis.kubesentinel-system.svc.cluster.local',
    port=6379,
    username='producer',
    password='invalid-password-simulation',
    socket_timeout=1.5,
)
try:
    r_bad.ping()
    results['bad_auth'] = 'UNEXPECTED_SUCCESS'
except Exception as e:
    results['bad_auth'] = f'REJECTED:{{type(e).__name__}}:{{e}}'

# B2: Valid producer credentials - authorized PING and unauthorized commands
r_prod = redis.Redis(
    host='redis.kubesentinel-system.svc.cluster.local',
    port=6379,
    username='producer',
    password='{producer_pw}',
    socket_timeout=1.5,
)
try:
    r_prod.ping()
    results['producer_ping'] = 'ALLOWED'
except Exception as e:
    results['producer_ping'] = f'FAILED:{{e}}'

# Producer attempting administrative CONFIG GET (must be rejected with NOPERM)
try:
    r_prod.config_get('*')
    results['unauthorized_config'] = 'UNEXPECTED_SUCCESS'
except Exception as e:
    results['unauthorized_config'] = f'REJECTED:{{type(e).__name__}}:{{e}}'

# Producer attempting consumer XREADGROUP (must be rejected with NOPERM)
try:
    r_prod.xreadgroup('edge-workers', 'sim-client', {{'security-events': '>'}})
    results['unauthorized_xread'] = 'UNEXPECTED_SUCCESS'
except Exception as e:
    results['unauthorized_xread'] = f'REJECTED:{{type(e).__name__}}:{{e}}'

import json
print(json.dumps(results))
"""

        res = run_kubectl(
            [
                "exec",
                "-n",
                self.authorized_namespace,
                self.authorized_workload,
                "--",
                "python",
                "-c",
                py_test_code,
            ],
            timeout=20.0,
        )

        if res.returncode != 0:
            return False, {"error": res.stderr.strip() or res.stdout.strip()}

        import json

        try:
            data = json.loads(res.stdout.strip())
        except json.JSONDecodeError:
            return False, {"error": f"Failed to parse ACL test JSON: {res.stdout}"}

        bad_auth_rejected = "REJECTED:AuthenticationError" in data.get("bad_auth", "")
        producer_ping_ok = data.get("producer_ping") == "ALLOWED"
        config_rejected = "REJECTED:NoPermissionError" in data.get("unauthorized_config", "")
        xread_rejected = "REJECTED:NoPermissionError" in data.get("unauthorized_xread", "")

        acl_ok = bad_auth_rejected and producer_ping_ok and config_rejected and xread_rejected
        return acl_ok, data

    def run(self, timeout_sec: float = 30.0) -> SimulationResult:
        start_time = time.monotonic()

        # Step 1: Network-layer prevention check
        net_ok, net_detail = self._test_network_policy_tcp_block()

        # Step 2: Data-layer ACL prevention check
        acl_ok, acl_detail = self._test_redis_acl_rejection()

        duration = time.monotonic() - start_time
        all_passed = net_ok and acl_ok

        summary = (
            "Dual Redis controls verified: NetworkPolicy TCP block from unauthorized pod "
            "and Redis ACL authentication/least-privilege rejection on authorized path"
            if all_passed
            else f"Redis unauthorized simulation failed (network_ok={net_ok}, acl_ok={acl_ok})"
        )

        return SimulationResult(
            scenario=self.scenario_name,
            status="PASS" if all_passed else "FAIL",
            control_type=self.control_type,
            summary=summary,
            details={
                "network_layer_prevention": {
                    "control": "NetworkPolicy",
                    "probe_namespace": self.probe_namespace,
                    "status": "PASS" if net_ok else "FAIL",
                    "detail": net_detail,
                },
                "data_layer_prevention": {
                    "control": "Redis ACL",
                    "path_namespace": self.authorized_namespace,
                    "path_workload": self.authorized_workload,
                    "status": "PASS" if acl_ok else "FAIL",
                    "results": acl_detail,
                },
            },
            duration_sec=round(duration, 3),
            metadata_path=str(self.metadata_file),
        )
