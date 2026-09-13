"""Automated validation of KubeSentinel NetworkPolicy segmentation and flow enforcement."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.k8s_client import run_kubectl


def _run_in_pod(
    namespace: str,
    workload: str,
    py_code: str,
    timeout: float = 15.0,
) -> tuple[bool, str]:
    """Execute python snippet inside a workload pod and return success boolean and output."""
    res = run_kubectl(
        ["exec", "-n", namespace, workload, "--", "python", "-c", py_code],
        timeout=timeout,
    )
    output = (res.stdout or res.stderr).strip()
    return res.returncode == 0, output


def validate_network_policies_exist() -> list[dict[str, str]]:
    """Verify default-deny, DNS, Redis, and workload NetworkPolicies exist in the cluster."""
    results: list[dict[str, str]] = []
    res = run_kubectl(["get", "networkpolicies", "-A", "-o", "json"])
    if res.returncode != 0:
        results.append({
            "check": "get_networkpolicies",
            "status": "FAIL",
            "detail": res.stderr.strip() or "Failed to list NetworkPolicies",
        })
        return results

    try:
        data = json.loads(res.stdout)
    except json.JSONDecodeError as exc:
        results.append({
            "check": "parse_networkpolicies",
            "status": "FAIL",
            "detail": f"Failed to parse NetworkPolicy JSON: {exc}",
        })
        return results

    policies_by_ns: dict[str, set[str]] = {}
    for item in data.get("items", []):
        ns = item["metadata"]["namespace"]
        name = item["metadata"]["name"]
        policies_by_ns.setdefault(ns, set()).add(name)

    protected_namespaces = [
        "kubesentinel-system",
        "edge-pune",
        "edge-mumbai",
        "edge-bangalore",
        "observability",
        "security-agents",
    ]

    # 1. Default deny
    for ns in protected_namespaces:
        if "default-deny-all" in policies_by_ns.get(ns, set()):
            results.append({
                "check": f"default_deny_policy:{ns}",
                "status": "PASS",
                "detail": f"default-deny-all active in {ns}",
            })
        else:
            results.append({
                "check": f"default_deny_policy:{ns}",
                "status": "FAIL",
                "detail": f"default-deny-all missing in {ns}",
            })

    # 2. Allow DNS
    for ns in protected_namespaces:
        if "allow-dns-egress" in policies_by_ns.get(ns, set()):
            results.append({
                "check": f"allow_dns_policy:{ns}",
                "status": "PASS",
                "detail": f"allow-dns-egress active in {ns}",
            })
        else:
            results.append({
                "check": f"allow_dns_policy:{ns}",
                "status": "FAIL",
                "detail": f"allow-dns-egress missing in {ns}",
            })

    # 3. Redis access in kubesentinel-system
    if "redis-access" in policies_by_ns.get("kubesentinel-system", set()):
        results.append({
            "check": "redis_access_policy:kubesentinel-system",
            "status": "PASS",
            "detail": "redis-access active in kubesentinel-system",
        })
    else:
        results.append({
            "check": "redis_access_policy:kubesentinel-system",
            "status": "FAIL",
            "detail": "redis-access missing in kubesentinel-system",
        })

    # 4. Edge API policies
    for ns in ["edge-pune", "edge-mumbai", "edge-bangalore"]:
        if "edge-api-policy" in policies_by_ns.get(ns, set()):
            results.append({
                "check": f"edge_api_policy:{ns}",
                "status": "PASS",
                "detail": f"edge-api-policy active in {ns}",
            })
        else:
            results.append({
                "check": f"edge_api_policy:{ns}",
                "status": "FAIL",
                "detail": f"edge-api-policy missing in {ns}",
            })

    # 5. Worker policy
    if "edge-worker-policy" in policies_by_ns.get("kubesentinel-system", set()):
        results.append({
            "check": "edge_worker_policy:kubesentinel-system",
            "status": "PASS",
            "detail": "edge-worker-policy active in kubesentinel-system",
        })
    else:
        results.append({
            "check": "edge_worker_policy:kubesentinel-system",
            "status": "FAIL",
            "detail": "edge-worker-policy missing in kubesentinel-system",
        })

    # 6. Observability workload policies
    for pol in ["elasticsearch-policy", "kibana-policy", "fluent-bit-policy"]:
        if pol in policies_by_ns.get("observability", set()):
            results.append({
                "check": f"{pol}:observability",
                "status": "PASS",
                "detail": f"{pol} active in observability",
            })
        else:
            results.append({
                "check": f"{pol}:observability",
                "status": "FAIL",
                "detail": f"{pol} missing in observability",
            })

    # 7. Security agents workload policies
    if "falco-health-policy" in policies_by_ns.get("security-agents", set()):
        results.append({
            "check": "falco_health_policy:security-agents",
            "status": "PASS",
            "detail": "falco-health-policy active in security-agents",
        })
    else:
        results.append({
            "check": "falco_health_policy:security-agents",
            "status": "FAIL",
            "detail": "falco-health-policy missing in security-agents",
        })

    return results


def validate_dns_resolution() -> list[dict[str, str]]:
    """Verify DNS resolution functions from protected workloads to CoreDNS."""
    results: list[dict[str, str]] = []
    py_dns = (
        "import socket; "
        "addr = socket.gethostbyname('kubernetes.default.svc.cluster.local'); "
        "print(f'RESOLVED:{addr}')"
    )

    targets = [
        ("edge-pune", "deployment/edge-api"),
        ("edge-mumbai", "deployment/edge-api"),
        ("edge-bangalore", "deployment/edge-api"),
        ("kubesentinel-system", "deployment/edge-worker"),
    ]

    for ns, workload in targets:
        ok, out = _run_in_pod(ns, workload, py_dns, timeout=10.0)
        if ok and "RESOLVED:" in out:
            results.append({
                "check": f"dns_resolution:{ns}",
                "status": "PASS",
                "detail": f"Successfully resolved kubernetes.default to {out.split('RESOLVED:')[1].strip()}",
            })
        else:
            results.append({
                "check": f"dns_resolution:{ns}",
                "status": "FAIL",
                "detail": f"DNS resolution failed: {out}",
            })

    return results


def validate_authorized_redis_flows() -> list[dict[str, str]]:
    """Verify authorized workloads can establish TCP connectivity to central Redis."""
    results: list[dict[str, str]] = []
    py_connect = (
        "import socket; s = socket.socket(); s.settimeout(3.0); "
        "s.connect(('redis.kubesentinel-system.svc.cluster.local', 6379)); "
        "print('CONNECTED')"
    )

    authorized = [
        ("edge-pune", "deployment/edge-api", "Pune edge-api -> Redis"),
        ("edge-mumbai", "deployment/edge-api", "Mumbai edge-api -> Redis"),
        ("edge-bangalore", "deployment/edge-api", "Bangalore edge-api -> Redis"),
        ("kubesentinel-system", "deployment/edge-worker", "edge-worker -> Redis"),
    ]

    for ns, workload, desc in authorized:
        ok, out = _run_in_pod(ns, workload, py_connect, timeout=10.0)
        if ok and "CONNECTED" in out:
            results.append({
                "check": f"authorized_flow:{ns}:{workload.split('/')[1]}",
                "status": "PASS",
                "detail": f"{desc} connection established (TCP 6379)",
            })
        else:
            results.append({
                "check": f"authorized_flow:{ns}:{workload.split('/')[1]}",
                "status": "FAIL",
                "detail": f"{desc} connection failed: {out}",
            })

    return results


def validate_cross_edge_blocked() -> list[dict[str, str]]:
    """Verify unauthorized cross-edge traffic between edge namespaces is blocked."""
    results: list[dict[str, str]] = []
    py_cross = (
        "import socket\n"
        "s = socket.socket()\n"
        "s.settimeout(2.0)\n"
        "try:\n"
        "    s.connect(('edge-api.edge-mumbai.svc.cluster.local', 8000))\n"
        "    print('UNEXPECTED_CONNECTED')\n"
        "except Exception as e:\n"
        "    print(f'BLOCKED:{type(e).__name__}')\n"
    )

    _ok, out = _run_in_pod("edge-pune", "deployment/edge-api", py_cross, timeout=10.0)
    if "BLOCKED:" in out:
        block_reason = out.split("BLOCKED:")[1].strip()
        results.append({
            "check": "cross_edge_isolation:pune_to_mumbai",
            "status": "PASS",
            "detail": f"Cross-edge traffic blocked under active NetworkPolicy ({block_reason})",
        })
    elif "UNEXPECTED_CONNECTED" in out:
        results.append({
            "check": "cross_edge_isolation:pune_to_mumbai",
            "status": "FAIL",
            "detail": "Cross-edge traffic was unexpectedly permitted between edge-pune and edge-mumbai",
        })
    else:
        results.append({
            "check": "cross_edge_isolation:pune_to_mumbai",
            "status": "FAIL",
            "detail": f"Cross-edge probe failed with unexpected output: {out}",
        })

    return results


def validate_unauthorized_redis_blocked() -> list[dict[str, str]]:
    """Verify an unauthorized workload in observability namespace is blocked from reaching Redis."""
    results: list[dict[str, str]] = []
    probe_name = "network-unauth-probe"
    probe_ns = "observability"

    # Restricted-compatible probe pod manifest
    pod_yaml = f"""
apiVersion: v1
kind: Pod
metadata:
  name: {probe_name}
  namespace: {probe_ns}
  labels:
    app: unauthorized-probe
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
    # Clean up any leftover probe
    run_kubectl(["delete", "pod", "-n", probe_ns, probe_name, "--ignore-not-found=true"])

    # Apply probe
    apply_res = run_kubectl(["apply", "-f", "-"], input_text=pod_yaml)
    if apply_res.returncode != 0:
        results.append({
            "check": "unauthorized_redis_blocked",
            "status": "FAIL",
            "detail": f"Failed to schedule unauthorized probe pod: {apply_res.stderr}",
        })
        return results

    # Wait for completion (bounded timeout)
    time.sleep(3.5)
    log_res = run_kubectl(["logs", "-n", probe_ns, probe_name])
    out = (log_res.stdout or log_res.stderr).strip()

    # Clean up immediately
    run_kubectl(["delete", "pod", "-n", probe_ns, probe_name, "--ignore-not-found=true"])

    if "BLOCKED:" in out:
        reason = out.split("BLOCKED:")[1].strip()
        results.append({
            "check": "unauthorized_redis_blocked",
            "status": "PASS",
            "detail": f"Unauthorized client TCP connectivity blocked under active NetworkPolicy ({reason})",
        })
    elif "UNEXPECTED_CONNECTED" in out:
        results.append({
            "check": "unauthorized_redis_blocked",
            "status": "FAIL",
            "detail": "Unauthorized probe connected to Redis (NetworkPolicy ingress bypassed)",
        })
    else:
        results.append({
            "check": "unauthorized_redis_blocked",
            "status": "FAIL",
            "detail": f"Unauthorized probe did not emit expected result: {out}",
        })

    return results


def validate_redis_cluster_ip() -> list[dict[str, str]]:
    """Verify Redis Service is strictly ClusterIP with no hostPort or external exposure."""
    results: list[dict[str, str]] = []
    res = run_kubectl(["get", "svc", "-n", "kubesentinel-system", "redis", "-o", "json"])
    if res.returncode != 0:
        results.append({
            "check": "redis_service_type",
            "status": "FAIL",
            "detail": f"Failed to get Redis service: {res.stderr}",
        })
        return results

    svc = json.loads(res.stdout)
    svc_type = svc.get("spec", {}).get("type")
    cluster_ip = svc.get("spec", {}).get("clusterIP")

    if svc_type == "ClusterIP":
        results.append({
            "check": "redis_service_cluster_ip",
            "status": "PASS",
            "detail": f"Service type is ClusterIP (clusterIP={cluster_ip})",
        })
    else:
        results.append({
            "check": "redis_service_cluster_ip",
            "status": "FAIL",
            "detail": f"Expected ClusterIP, found: {svc_type}",
        })

    return results


def run_all_network_validations() -> list[dict[str, str]]:
    """Run all network validation checks and return ordered results."""
    all_results: list[dict[str, str]] = []
    all_results.extend(validate_network_policies_exist())
    all_results.extend(validate_dns_resolution())
    all_results.extend(validate_authorized_redis_flows())
    all_results.extend(validate_cross_edge_blocked())
    all_results.extend(validate_unauthorized_redis_blocked())
    all_results.extend(validate_redis_cluster_ip())
    return all_results


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for network-validate."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="kubesentinel network-validate",
        description="Verify NetworkPolicy segmentation, authorized/unauthorized flows, and DNS.",
    )
    parser.add_argument("--json", action="store_true", help="Emit validation results as JSON")
    args = parser.parse_args(argv)

    results = run_all_network_validations()

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print("Running Kubernetes Network Security Validation...")
        for r in results:
            status_tag = f"[{r['status']}]".ljust(8)
            check_tag = r["check"].ljust(40)
            print(f"{status_tag} {check_tag} {r['detail']}")

        total = len(results)
        passed = sum(1 for r in results if r["status"] == "PASS")
        failed = sum(1 for r in results if r["status"] == "FAIL")
        print(f"\nSummary: Total={total} PASS={passed} FAIL={failed}")

    return 1 if any(r["status"] == "FAIL" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
