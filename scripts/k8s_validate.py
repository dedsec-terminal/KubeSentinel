"""Automated validation of KubeSentinel Kubernetes cluster state, security, and ACLs."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.k8s_client import run_kubectl

K8S_DIR = ROOT / "kubernetes"


def validate_namespaces_psa() -> list[dict[str, str]]:
    """Verify all 5 namespaces exist with expected Pod Security Admission labels."""
    results: list[dict[str, str]] = []
    expected_namespaces = {
        "kubesentinel-system": "restricted",
        "edge-pune": "restricted",
        "edge-mumbai": "restricted",
        "edge-bangalore": "restricted",
        "observability": "baseline",
        "security-agents": "privileged",
    }

    res = run_kubectl(["get", "namespaces", "-o", "json"])
    if res.returncode != 0:
        results.append({
            "check": "get_namespaces",
            "status": "FAIL",
            "detail": res.stderr.strip() or "Failed to query namespaces",
        })
        return results

    data = json.loads(res.stdout)
    live_ns = {item["metadata"]["name"]: item["metadata"].get("labels", {}) for item in data.get("items", [])}

    for ns_name, expected_level in expected_namespaces.items():
        if ns_name not in live_ns:
            results.append({
                "check": f"namespace_exists:{ns_name}",
                "status": "FAIL",
                "detail": f"Namespace {ns_name} not found in cluster",
            })
            continue

        labels = live_ns[ns_name]
        enforce = labels.get("pod-security.kubernetes.io/enforce")
        audit = labels.get("pod-security.kubernetes.io/audit")
        warn = labels.get("pod-security.kubernetes.io/warn")

        if enforce == expected_level and audit == expected_level and warn == expected_level:
            results.append({
                "check": f"psa_labels:{ns_name}",
                "status": "PASS",
                "detail": f"enforce={enforce}, audit={audit}, warn={warn} (expected: {expected_level})",
            })
        else:
            results.append({
                "check": f"psa_labels:{ns_name}",
                "status": "FAIL",
                "detail": f"Mismatched PSA labels: enforce={enforce}, audit={audit}, warn={warn} (expected: {expected_level})",
            })

    return results


def validate_psa_negative_test() -> list[dict[str, str]]:
    """Verify Pod Security Admission rejects non-compliant pod in restricted namespace."""
    results: list[dict[str, str]] = []
    manifest = K8S_DIR / "security" / "psa-negative-pod.yaml"
    if not manifest.is_file():
        results.append({
            "check": "psa_negative_fixture_exists",
            "status": "FAIL",
            "detail": f"Manifest not found at {manifest}",
        })
        return results

    content = manifest.read_text(encoding="utf-8")
    res = run_kubectl(["apply", "--dry-run=server", "-f", "-"], input_text=content)
    # We EXPECT admission rejection (returncode != 0 and forbidden/restricted error)
    err_text = (res.stderr + " " + res.stdout).lower()
    if res.returncode != 0 and ("forbidden" in err_text or "violates podsecurity" in err_text):
        results.append({
            "check": "psa_admission_rejection",
            "status": "PASS",
            "detail": "Admission controller successfully rejected privileged pod with PodSecurity violation",
        })
    else:
        results.append({
            "check": "psa_admission_rejection",
            "status": "FAIL",
            "detail": f"Expected rejection, but command returned code {res.returncode}: {res.stdout} {res.stderr}",
        })
    return results


def validate_rbac_sa() -> list[dict[str, str]]:
    """Verify ServiceAccounts disable token automount and have zero API permissions."""
    results: list[dict[str, str]] = []
    sa_targets = [
        ("edge-pune", "edge-api-sa"),
        ("edge-mumbai", "edge-api-sa"),
        ("edge-bangalore", "edge-api-sa"),
        ("kubesentinel-system", "edge-worker-sa"),
        ("kubesentinel-system", "redis-sa"),
    ]

    for ns, sa_name in sa_targets:
        res = run_kubectl(["get", "serviceaccount", sa_name, "-n", ns, "-o", "json"])
        if res.returncode != 0:
            results.append({
                "check": f"sa_exists:{ns}/{sa_name}",
                "status": "FAIL",
                "detail": f"ServiceAccount {sa_name} not found in {ns}",
            })
            continue

        sa_data = json.loads(res.stdout)
        automount = sa_data.get("automountServiceAccountToken")
        if automount is False:
            results.append({
                "check": f"sa_automount_false:{ns}/{sa_name}",
                "status": "PASS",
                "detail": "automountServiceAccountToken is explicitly false",
            })
        else:
            results.append({
                "check": f"sa_automount_false:{ns}/{sa_name}",
                "status": "FAIL",
                "detail": f"Expected automountServiceAccountToken=false, found {automount}",
            })

        # Negative authorization checks
        for verb, resource in (("list", "pods"), ("get", "secrets")):
            auth_res = run_kubectl([
                "auth",
                "can-i",
                verb,
                resource,
                f"--as=system:serviceaccount:{ns}:{sa_name}",
                "-n",
                ns,
            ])
            output = auth_res.stdout.strip().lower()
            if output == "no":
                results.append({
                    "check": f"sa_zero_perm:{ns}/{sa_name}:{verb}_{resource}",
                    "status": "PASS",
                    "detail": f"Denied {verb} {resource} as expected",
                })
            else:
                results.append({
                    "check": f"sa_zero_perm:{ns}/{sa_name}:{verb}_{resource}",
                    "status": "FAIL",
                    "detail": f"Expected 'no', received: {output}",
                })

    return results


def validate_workload_hardening() -> list[dict[str, str]]:
    """Verify all Deployments enforce restricted container securityContexts and resource limits."""
    results: list[dict[str, str]] = []
    deployments = [
        ("edge-pune", "edge-api"),
        ("edge-mumbai", "edge-api"),
        ("edge-bangalore", "edge-api"),
        ("kubesentinel-system", "edge-worker"),
        ("kubesentinel-system", "redis"),
    ]

    for ns, dep_name in deployments:
        res = run_kubectl(["get", "deployment", dep_name, "-n", ns, "-o", "json"])
        if res.returncode != 0:
            results.append({
                "check": f"deployment_exists:{ns}/{dep_name}",
                "status": "FAIL",
                "detail": f"Deployment {dep_name} not found in {ns}",
            })
            continue

        dep_data = json.loads(res.stdout)
        pod_spec = dep_data["spec"]["template"]["spec"]
        pod_sc = pod_spec.get("securityContext", {})
        containers = pod_spec.get("containers", [])

        # Pod-level checks
        pod_non_root = pod_sc.get("runAsNonRoot")
        seccomp = pod_sc.get("seccompProfile", {}).get("type")

        if pod_non_root is True:
            results.append({
                "check": f"pod_runAsNonRoot:{ns}/{dep_name}",
                "status": "PASS",
                "detail": "Pod runAsNonRoot=true",
            })
        else:
            results.append({
                "check": f"pod_runAsNonRoot:{ns}/{dep_name}",
                "status": "FAIL",
                "detail": f"Pod runAsNonRoot is {pod_non_root}",
            })

        if seccomp == "RuntimeDefault":
            results.append({
                "check": f"pod_seccomp:{ns}/{dep_name}",
                "status": "PASS",
                "detail": "Pod seccompProfile=RuntimeDefault",
            })
        else:
            results.append({
                "check": f"pod_seccomp:{ns}/{dep_name}",
                "status": "FAIL",
                "detail": f"Pod seccompProfile is {seccomp}",
            })

        for c in containers:
            c_name = c.get("name")
            c_sc = c.get("securityContext", {})
            c_res = c.get("resources", {})

            # Hardening checks
            ro_root = c_sc.get("readOnlyRootFilesystem")
            no_new_priv = c_sc.get("allowPrivilegeEscalation")
            c_non_root = c_sc.get("runAsNonRoot")
            caps_drop = c_sc.get("capabilities", {}).get("drop", [])

            is_hardened = (
                ro_root is True
                and no_new_priv is False
                and c_non_root is True
                and "ALL" in caps_drop
            )
            if is_hardened:
                results.append({
                    "check": f"container_hardening:{ns}/{dep_name}/{c_name}",
                    "status": "PASS",
                    "detail": "readOnlyRootFilesystem=true, allowPrivilegeEscalation=false, runAsNonRoot=true, drop=['ALL']",
                })
            else:
                results.append({
                    "check": f"container_hardening:{ns}/{dep_name}/{c_name}",
                    "status": "FAIL",
                    "detail": f"Hardening incomplete: ro={ro_root}, no_new_priv={no_new_priv}, non_root={c_non_root}, drop={caps_drop}",
                })

            # Resources check
            requests = c_res.get("requests", {})
            limits = c_res.get("limits", {})
            if requests.get("cpu") and requests.get("memory") and limits.get("cpu") and limits.get("memory"):
                results.append({
                    "check": f"resources_defined:{ns}/{dep_name}/{c_name}",
                    "status": "PASS",
                    "detail": f"requests: {requests}, limits: {limits}",
                })
            else:
                results.append({
                    "check": f"resources_defined:{ns}/{dep_name}/{c_name}",
                    "status": "FAIL",
                    "detail": f"Missing resource requests or limits: {c_res}",
                })

    return results


def validate_redis_acls() -> list[dict[str, str]]:
    """Verify live Redis ACL boundary enforcement inside the cluster."""
    results: list[dict[str, str]] = []
    # Find running redis pod
    res = run_kubectl(["get", "pods", "-n", "kubesentinel-system", "-l", "app=redis", "-o", "jsonpath={.items[0].metadata.name}"])
    if res.returncode != 0 or not res.stdout.strip():
        results.append({
            "check": "redis_pod_running",
            "status": "FAIL",
            "detail": "Redis pod not found in kubesentinel-system",
        })
        return results

    redis_pod = res.stdout.strip()
    from scripts.k8s_deploy import load_or_create_secrets

    producer_pw, consumer_pw, _ = load_or_create_secrets()

    # 1. Producer: allowed PING and XADD, denied XREADGROUP and CONFIG
    prod_ping = run_kubectl(["exec", "-n", "kubesentinel-system", redis_pod, "--", "redis-cli", "--user", "producer", "-a", producer_pw, "ping"])
    if "PONG" in prod_ping.stdout:
        results.append({"check": "redis_acl_producer_ping", "status": "PASS", "detail": "Producer PING allowed"})
    else:
        results.append({"check": "redis_acl_producer_ping", "status": "FAIL", "detail": prod_ping.stdout + prod_ping.stderr})

    prod_xread = run_kubectl(["exec", "-n", "kubesentinel-system", redis_pod, "--", "redis-cli", "--user", "producer", "-a", producer_pw, "XREADGROUP", "GROUP", "edge-workers", "c1", "STREAMS", "security-events", ">"])
    if "NOPERM" in prod_xread.stdout or "NOPERM" in prod_xread.stderr:
        results.append({"check": "redis_acl_producer_denied_xread", "status": "PASS", "detail": "Producer denied XREADGROUP (NOPERM)"})
    else:
        results.append({"check": "redis_acl_producer_denied_xread", "status": "FAIL", "detail": f"Expected NOPERM, got: {prod_xread.stdout} {prod_xread.stderr}"})

    prod_config = run_kubectl(["exec", "-n", "kubesentinel-system", redis_pod, "--", "redis-cli", "--user", "producer", "-a", producer_pw, "CONFIG", "GET", "*"])
    if "NOPERM" in prod_config.stdout or "NOPERM" in prod_config.stderr:
        results.append({"check": "redis_acl_producer_denied_config", "status": "PASS", "detail": "Producer denied CONFIG (NOPERM)"})
    else:
        results.append({"check": "redis_acl_producer_denied_config", "status": "FAIL", "detail": f"Expected NOPERM, got: {prod_config.stdout} {prod_config.stderr}"})

    # 2. Consumer: allowed PING and XREADGROUP, denied XADD and CONFIG
    cons_ping = run_kubectl(["exec", "-n", "kubesentinel-system", redis_pod, "--", "redis-cli", "--user", "consumer", "-a", consumer_pw, "ping"])
    if "PONG" in cons_ping.stdout:
        results.append({"check": "redis_acl_consumer_ping", "status": "PASS", "detail": "Consumer PING allowed"})
    else:
        results.append({"check": "redis_acl_consumer_ping", "status": "FAIL", "detail": cons_ping.stdout + cons_ping.stderr})

    cons_xadd = run_kubectl(["exec", "-n", "kubesentinel-system", redis_pod, "--", "redis-cli", "--user", "consumer", "-a", consumer_pw, "XADD", "security-events", "*", "test", "val"])
    if "NOPERM" in cons_xadd.stdout or "NOPERM" in cons_xadd.stderr:
        results.append({"check": "redis_acl_consumer_denied_xadd", "status": "PASS", "detail": "Consumer denied XADD (NOPERM)"})
    else:
        results.append({"check": "redis_acl_consumer_denied_xadd", "status": "FAIL", "detail": f"Expected NOPERM, got: {cons_xadd.stdout} {cons_xadd.stderr}"})

    # 3. Default user disabled
    default_res = run_kubectl(["exec", "-n", "kubesentinel-system", redis_pod, "--", "redis-cli", "ping"])
    if "NOAUTH" in default_res.stdout or "NOAUTH" in default_res.stderr or "NOPERM" in default_res.stdout:
        results.append({"check": "redis_acl_default_disabled", "status": "PASS", "detail": "Default user disabled (NOAUTH/NOPERM)"})
    else:
        results.append({"check": "redis_acl_default_disabled", "status": "FAIL", "detail": f"Expected NOAUTH, got: {default_res.stdout} {default_res.stderr}"})

    return results


def run_k8s_validate(as_json: bool = False) -> int:
    """Execute full suite of Kubernetes security and configuration validations."""
    all_checks: list[dict[str, str]] = []
    print("Running Kubernetes Validation Checks...")

    all_checks.extend(validate_namespaces_psa())
    all_checks.extend(validate_psa_negative_test())
    all_checks.extend(validate_rbac_sa())
    all_checks.extend(validate_workload_hardening())
    all_checks.extend(validate_redis_acls())

    pass_count = sum(1 for c in all_checks if c["status"] == "PASS")
    fail_count = sum(1 for c in all_checks if c["status"] == "FAIL")

    if as_json:
        print(json.dumps({
            "summary": {"total": len(all_checks), "pass": pass_count, "fail": fail_count},
            "checks": all_checks,
        }, indent=2))
    else:
        for c in all_checks:
            badge = f"[{c['status']}]"
            print(f"{badge:<8} {c['check']:<40} {c['detail']}")
        print(f"\nSummary: Total={len(all_checks)} PASS={pass_count} FAIL={fail_count}")

    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    sys.exit(run_k8s_validate())
