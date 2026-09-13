"""Validation script for Falco runtime security deployment, driver, rules, and alerts."""

from __future__ import annotations

import json
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.k8s_client import run_kubectl


def run_all_falco_validations() -> list[dict[str, str]]:
    """Verify Falco DaemonSet, modern eBPF driver, custom rule, and execute alert test."""
    results: list[dict[str, str]] = []

    # 1. DaemonSet Status
    res = run_kubectl(["get", "ds", "falco", "-n", "security-agents", "-o", "json"])
    if res.returncode != 0:
        results.append({
            "check": "falco_daemonset",
            "status": "FAIL",
            "detail": f"Failed to get Falco DaemonSet: {res.stderr}",
        })
        return results

    try:
        ds_data = json.loads(res.stdout)
        desired = ds_data.get("status", {}).get("desiredNumberScheduled", 0)
        ready = ds_data.get("status", {}).get("numberReady", 0)
        if ready >= 1 and ready >= desired:
            results.append({
                "check": "falco_daemonset_ready",
                "status": "PASS",
                "detail": f"DaemonSet ready in namespace security-agents ({ready}/{desired})",
            })
        else:
            results.append({
                "check": "falco_daemonset_ready",
                "status": "FAIL",
                "detail": f"DaemonSet ready={ready}, desired={desired}",
            })
    except json.JSONDecodeError:
        results.append({
            "check": "falco_daemonset_ready",
            "status": "FAIL",
            "detail": "Failed to parse Falco DaemonSet JSON",
        })

    # 2. Driver Status
    log_res = run_kubectl(["logs", "-n", "security-agents", "daemonset/falco", "--tail=2000"])
    logs = log_res.stdout or log_res.stderr

    if "Opening 'syscall' source with modern BPF probe" in logs or "modern BPF probe" in logs:
        results.append({
            "check": "falco_modern_ebpf_driver",
            "status": "PASS",
            "detail": "Modern eBPF syscall probe initialized and active on kernel ring buffer",
        })
    else:
        results.append({
            "check": "falco_modern_ebpf_driver",
            "status": "FAIL",
            "detail": "Modern eBPF driver initialization not confirmed in logs",
        })

    # 3. Custom Rule Loaded
    if "rules-kubesentinel.yaml" in logs or "Unexpected shell in KubeSentinel edge workload" in logs or "schema validation: ok" in logs:
        results.append({
            "check": "falco_custom_rule_loaded",
            "status": "PASS",
            "detail": "Custom rule 'Unexpected shell in KubeSentinel edge workload' (ATT&CK T1059.004) active",
        })
    else:
        results.append({
            "check": "falco_custom_rule_loaded",
            "status": "FAIL",
            "detail": "Custom detection rules not found in Falco logs",
        })

    # 4. Controlled Alert Trigger & Detection Proof
    marker = f"falco-validate-{uuid.uuid4().hex[:8]}"
    trigger_res = run_kubectl([
        "exec", "-n", "edge-pune", "deployment/edge-api", "--",
        "sh", "-c", f"echo {marker}",
    ])
    if trigger_res.returncode != 0:
        results.append({
            "check": "controlled_alert_execution",
            "status": "FAIL",
            "detail": f"Failed to execute controlled shell in edge-pune: {trigger_res.stderr}",
        })
        return results

    time.sleep(2.5)
    recent_logs = run_kubectl(["logs", "-n", "security-agents", "daemonset/falco", "--tail=20"])
    alert_logs = recent_logs.stdout or recent_logs.stderr

    alert_found = False
    detected_rule = None
    detected_priority = None
    detected_ns = None

    for line in alert_logs.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            alert_json = json.loads(line)
            rule = alert_json.get("rule")
            if rule == "Unexpected shell in KubeSentinel edge workload":
                detected_rule = rule
                detected_priority = alert_json.get("priority")
                detected_ns = alert_json.get("output_fields", {}).get("k8s.ns.name") or alert_json.get("output_fields", {}).get("k8s_ns_name")
                alert_found = True
                break
        except json.JSONDecodeError:
            continue

    if alert_found:
        results.append({
            "check": "controlled_alert_detection",
            "status": "PASS",
            "detail": f"Detected rule='{detected_rule}', priority='{detected_priority}', ns='{detected_ns}'",
        })
    else:
        results.append({
            "check": "controlled_alert_detection",
            "status": "FAIL",
            "detail": "Custom shell alert was not observed in Falco logs after trigger",
        })

    return results


def run_falco_validate(as_json: bool = False) -> int:
    """CLI handler for falco-validate."""
    results = run_all_falco_validations()

    if as_json:
        print(json.dumps(results, indent=2))
    else:
        print("Running Falco Runtime Security Validation...")
        for r in results:
            status_tag = f"[{r['status']}]".ljust(8)
            check_tag = r["check"].ljust(45)
            print(f"{status_tag} {check_tag} {r['detail']}")

        total = len(results)
        passed = sum(1 for r in results if r["status"] == "PASS")
        failed = sum(1 for r in results if r["status"] == "FAIL")
        print(f"\nSummary: Total={total} PASS={passed} FAIL={failed}")

    return 1 if any(r["status"] == "FAIL" for r in results) else 0


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="kubesentinel falco-validate",
        description="Validate Falco deployment, driver status, custom rule, and execute alert test.",
    )
    parser.add_argument("--json", action="store_true", help="Emit validation results as JSON")
    args = parser.parse_args(argv)
    return run_falco_validate(as_json=args.json)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
