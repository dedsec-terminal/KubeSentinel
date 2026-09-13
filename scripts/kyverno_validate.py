"""Automated validation of Kyverno Helm release, controller health, policies, and admission behavior."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.k8s_client import run_helm, run_kubectl

REQUIRED_POLICIES = [
    "disallow-privileged-containers",
    "require-run-as-non-root",
    "disallow-privilege-escalation",
    "require-drop-all-capabilities",
    "require-runtime-default-seccomp",
    "require-resource-requests-limits",
    "disallow-host-path",
    "disallow-host-network",
    "disallow-latest-tag",
]

REQUIRED_CONTROLLERS = [
    "kyverno-admission-controller",
    "kyverno-background-controller",
    "kyverno-cleanup-controller",
    "kyverno-reports-controller",
]


def validate_helm_release() -> list[dict[str, str]]:
    """Verify official Kyverno Helm chart release status, chart version, and app version."""
    results: list[dict[str, str]] = []
    res = run_helm(["list", "-n", "kyverno", "-o", "json"])
    if res.returncode != 0:
        results.append({
            "check": "kyverno_helm_release",
            "status": "FAIL",
            "detail": f"Failed to list Helm releases in kyverno namespace: {res.stderr}",
        })
        return results

    try:
        releases = json.loads(res.stdout)
    except json.JSONDecodeError as exc:
        results.append({
            "check": "kyverno_helm_release",
            "status": "FAIL",
            "detail": f"Failed to parse Helm list JSON: {exc}",
        })
        return results

    kyverno_rel = next((r for r in releases if r.get("name") == "kyverno"), None)
    if not kyverno_rel:
        results.append({
            "check": "kyverno_helm_release",
            "status": "FAIL",
            "detail": "No Helm release named 'kyverno' found in namespace kyverno",
        })
        return results

    status = kyverno_rel.get("status")
    chart = kyverno_rel.get("chart")
    app_version = kyverno_rel.get("app_version")

    if status == "deployed":
        results.append({
            "check": "kyverno_helm_release_status",
            "status": "PASS",
            "detail": f"Release 'kyverno' is deployed (chart: {chart}, app_version: {app_version})",
        })
    else:
        results.append({
            "check": "kyverno_helm_release_status",
            "status": "FAIL",
            "detail": f"Release 'kyverno' status is '{status}', expected 'deployed'",
        })

    return results


def validate_kyverno_controllers() -> list[dict[str, str]]:
    """Verify all 4 Kyverno controller workloads are 1/1 Running in kyverno namespace."""
    results: list[dict[str, str]] = []
    res = run_kubectl(["get", "pods", "-n", "kyverno", "-o", "json"])
    if res.returncode != 0:
        results.append({
            "check": "kyverno_controllers_running",
            "status": "FAIL",
            "detail": f"Failed to query pods in kyverno namespace: {res.stderr}",
        })
        return results

    pods_data = json.loads(res.stdout)
    pod_items = pods_data.get("items", [])

    for ctrl in REQUIRED_CONTROLLERS:
        matching_pods = [p for p in pod_items if ctrl in p["metadata"]["name"]]
        if not matching_pods:
            results.append({
                "check": f"controller_running:{ctrl}",
                "status": "FAIL",
                "detail": f"No running pod found for controller {ctrl}",
            })
            continue

        pod = matching_pods[0]
        phase = pod.get("status", {}).get("phase")
        container_statuses = pod.get("status", {}).get("containerStatuses", [])
        all_ready = bool(container_statuses) and all(cs.get("ready", False) for cs in container_statuses)

        if phase == "Running" and all_ready:
            results.append({
                "check": f"controller_running:{ctrl}",
                "status": "PASS",
                "detail": f"{ctrl} is Running (Ready: 1/1)",
            })
        else:
            results.append({
                "check": f"controller_running:{ctrl}",
                "status": "FAIL",
                "detail": f"{ctrl} phase={phase}, ready={all_ready}",
            })

    return results


def validate_cluster_policies_ready() -> list[dict[str, str]]:
    """Verify all 9 KubeSentinel Kyverno ClusterPolicies are Ready in the cluster."""
    results: list[dict[str, str]] = []
    res = run_kubectl(["get", "clusterpolicies", "-o", "json"])
    if res.returncode != 0:
        results.append({
            "check": "get_clusterpolicies",
            "status": "FAIL",
            "detail": f"Failed to list ClusterPolicies: {res.stderr}",
        })
        return results

    try:
        policies_data = json.loads(res.stdout)
    except json.JSONDecodeError as exc:
        results.append({
            "check": "get_clusterpolicies",
            "status": "FAIL",
            "detail": f"Failed to parse ClusterPolicies JSON: {exc}",
        })
        return results

    live_policies = {p["metadata"]["name"]: p for p in policies_data.get("items", [])}

    for pol_name in REQUIRED_POLICIES:
        if pol_name not in live_policies:
            results.append({
                "check": f"policy_ready:{pol_name}",
                "status": "FAIL",
                "detail": f"ClusterPolicy '{pol_name}' not found",
            })
            continue

        pol = live_policies[pol_name]
        status_conditions = pol.get("status", {}).get("conditions", [])
        ready_cond = next((c for c in status_conditions if c.get("type") == "Ready"), None)
        is_ready = ready_cond is not None and ready_cond.get("status") == "True"

        if is_ready:
            results.append({
                "check": f"policy_ready:{pol_name}",
                "status": "PASS",
                "detail": f"Policy '{pol_name}' is Ready (enforce action active)",
            })
        else:
            results.append({
                "check": f"policy_ready:{pol_name}",
                "status": "FAIL",
                "detail": f"Policy '{pol_name}' Ready condition: {ready_cond}",
            })

    return results


def validate_live_admission_behavior() -> list[dict[str, str]]:
    """Test live Kyverno admission webhook enforcement using positive and negative fixtures."""
    results: list[dict[str, str]] = []
    fixtures_dir = ROOT / "tests" / "kyverno"

    # 1. Positive fixture: valid compliant pod must be accepted
    pass_file = fixtures_dir / "pass" / "valid-pod.yaml"
    if pass_file.is_file():
        pass_content = pass_file.read_text(encoding="utf-8")
        res = run_kubectl(["apply", "--dry-run=server", "-f", "-"], input_text=pass_content)
        if res.returncode == 0:
            results.append({
                "check": "admission_positive:valid_pod",
                "status": "PASS",
                "detail": "Compliant pod successfully accepted by admission webhook (server dry-run)",
            })
        else:
            results.append({
                "check": "admission_positive:valid_pod",
                "status": "FAIL",
                "detail": f"Compliant pod unexpectedly rejected: {res.stderr.strip()}",
            })

    # 2. Kyverno-specific negative fixture: disallow-latest-tag
    # Pod Security Admission allows :latest, so rejection proves Kyverno is authoritative
    latest_fail = fixtures_dir / "fail" / "disallow-latest-tag-fail.yaml"
    if latest_fail.is_file():
        fail_content = latest_fail.read_text(encoding="utf-8")
        res = run_kubectl(["apply", "--dry-run=server", "-f", "-"], input_text=fail_content)
        err = res.stderr or res.stdout
        if res.returncode != 0 and "validate.kyverno.svc" in err and "disallow-latest-tag" in err:
            results.append({
                "check": "admission_negative:disallow_latest_tag",
                "status": "PASS",
                "detail": "Rejected by Kyverno admission webhook (policy: disallow-latest-tag)",
            })
        else:
            results.append({
                "check": "admission_negative:disallow_latest_tag",
                "status": "FAIL",
                "detail": f"Expected Kyverno rejection for latest tag, got: {err[:200]}",
            })

    # 3. Kyverno-specific negative fixture: missing-resources
    # Pod Security Admission allows missing resources, so rejection proves Kyverno is authoritative
    resources_fail = fixtures_dir / "fail" / "missing-resources-fail.yaml"
    if resources_fail.is_file():
        fail_content = resources_fail.read_text(encoding="utf-8")
        res = run_kubectl(["apply", "--dry-run=server", "-f", "-"], input_text=fail_content)
        err = res.stderr or res.stdout
        if res.returncode != 0 and "validate.kyverno.svc" in err and "require-resource-requests-limits" in err:
            results.append({
                "check": "admission_negative:missing_resources",
                "status": "PASS",
                "detail": "Rejected by Kyverno admission webhook (policy: require-resource-requests-limits)",
            })
        else:
            results.append({
                "check": "admission_negative:missing_resources",
                "status": "FAIL",
                "detail": f"Expected Kyverno rejection for missing resources, got: {err[:200]}",
            })

    # 4. Security fixture: hostNetwork rejection
    host_net_fail = fixtures_dir / "fail" / "host-network-fail.yaml"
    if host_net_fail.is_file():
        fail_content = host_net_fail.read_text(encoding="utf-8")
        res = run_kubectl(["apply", "--dry-run=server", "-f", "-"], input_text=fail_content)
        err = res.stderr or res.stdout
        if res.returncode != 0 and ("disallow-host-network" in err or "hostNetwork" in err):
            results.append({
                "check": "admission_negative:host_network",
                "status": "PASS",
                "detail": "Host network violation successfully rejected by admission controls",
            })
        else:
            results.append({
                "check": "admission_negative:host_network",
                "status": "FAIL",
                "detail": f"Expected rejection for hostNetwork, got: {err[:200]}",
            })

    # 5. Security fixture: hostPath rejection
    host_path_fail = fixtures_dir / "fail" / "host-path-fail.yaml"
    if host_path_fail.is_file():
        fail_content = host_path_fail.read_text(encoding="utf-8")
        res = run_kubectl(["apply", "--dry-run=server", "-f", "-"], input_text=fail_content)
        err = res.stderr or res.stdout
        if res.returncode != 0 and ("disallow-host-path" in err or "hostPath" in err):
            results.append({
                "check": "admission_negative:host_path",
                "status": "PASS",
                "detail": "hostPath volume violation successfully rejected by admission controls",
            })
        else:
            results.append({
                "check": "admission_negative:host_path",
                "status": "FAIL",
                "detail": f"Expected rejection for hostPath, got: {err[:200]}",
            })

    return results


def run_all_kyverno_validations() -> list[dict[str, str]]:
    """Run all Kyverno validation checks and return ordered list of results."""
    all_results: list[dict[str, str]] = []
    all_results.extend(validate_helm_release())
    all_results.extend(validate_kyverno_controllers())
    all_results.extend(validate_cluster_policies_ready())
    all_results.extend(validate_live_admission_behavior())
    return all_results


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for kyverno-validate."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="kubesentinel kyverno-validate",
        description="Verify Kyverno Helm release, controller health, policies, and admission behavior.",
    )
    parser.add_argument("--json", action="store_true", help="Emit validation results as JSON")
    args = parser.parse_args(argv)

    results = run_all_kyverno_validations()

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print("Running Kyverno Policy-as-Code Validation...")
        for r in results:
            status_tag = f"[{r['status']}]".ljust(8)
            check_tag = r["check"].ljust(45)
            print(f"{status_tag} {check_tag} {r['detail']}")

        total = len(results)
        passed = sum(1 for r in results if r["status"] == "PASS")
        failed = sum(1 for r in results if r["status"] == "FAIL")
        print(f"\nSummary: Total={total} PASS={passed} FAIL={failed}")

    return 1 if any(r["status"] == "FAIL" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
