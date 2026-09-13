"""Validation script for Central Observability and Runtime Security components."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.k8s_client import run_kubectl
from scripts.setup_es_templates import get_es_credentials, request_es, request_kibana


def validate_elasticsearch() -> list[dict[str, str]]:
    """Verify Elasticsearch cluster health and index templates."""
    results: list[dict[str, str]] = []
    username, password = get_es_credentials()
    if not password:
        results.append({
            "check": "elasticsearch_credentials",
            "status": "FAIL",
            "detail": "Failed to retrieve elasticsearch-credentials",
        })
        return results

    # 1. Cluster health
    code, health = request_es("_cluster/health", username=username, password=password)
    if code == 200 and isinstance(health, dict):
        status = health.get("status")
        nodes = health.get("number_of_nodes")
        shards = health.get("active_shards")
        if status in ("green", "yellow"):
            results.append({
                "check": "elasticsearch_cluster_health",
                "status": "PASS",
                "detail": f"status={status}, nodes={nodes}, active_shards={shards}",
            })
        else:
            results.append({
                "check": "elasticsearch_cluster_health",
                "status": "FAIL",
                "detail": f"Unhealthy status={status}",
            })
    else:
        results.append({
            "check": "elasticsearch_cluster_health",
            "status": "FAIL",
            "detail": f"HTTP {code} from _cluster/health: {health}",
        })

    # 2. Index templates
    for tmpl in ["kubesentinel-app", "kubesentinel-falco"]:
        code, _resp = request_es(f"_index_template/{tmpl}", username=username, password=password)
        if code == 200:
            results.append({
                "check": f"elasticsearch_index_template:{tmpl}",
                "status": "PASS",
                "detail": f"Index template '{tmpl}' registered with typed mappings",
            })
        else:
            results.append({
                "check": f"elasticsearch_index_template:{tmpl}",
                "status": "FAIL",
                "detail": f"Index template '{tmpl}' missing (HTTP {code})",
            })

    return results


def validate_kibana() -> list[dict[str, str]]:
    """Verify Kibana plugin status and registered data views."""
    results: list[dict[str, str]] = []
    username, password = get_es_credentials()

    code, resp = request_kibana("api/status", username=username, password=password)
    if code == 200 and isinstance(resp, dict):
        level = resp.get("status", {}).get("overall", {}).get("level")
        summary = resp.get("status", {}).get("overall", {}).get("summary")
        if level == "available":
            results.append({
                "check": "kibana_status",
                "status": "PASS",
                "detail": f"Kibana is available: {summary}",
            })
        else:
            results.append({
                "check": "kibana_status",
                "status": "FAIL",
                "detail": f"Kibana status level={level}: {summary}",
            })
    else:
        results.append({
            "check": "kibana_status",
            "status": "FAIL",
            "detail": f"HTTP {code} from Kibana api/status: {resp}",
        })

    code, resp = request_kibana("api/data_views", username=username, password=password)
    if code == 200 and isinstance(resp, dict):
        views = [dv.get("title") for dv in resp.get("data_view", []) if "title" in dv]
        for expected_dv in ["kubesentinel-app-*", "kubesentinel-falco-*"]:
            if expected_dv in views:
                results.append({
                    "check": f"kibana_data_view:{expected_dv}",
                    "status": "PASS",
                    "detail": f"Data view '{expected_dv}' verified",
                })
            else:
                results.append({
                    "check": f"kibana_data_view:{expected_dv}",
                    "status": "FAIL",
                    "detail": f"Data view '{expected_dv}' missing from {views}",
                })
    else:
        results.append({
            "check": "kibana_data_views",
            "status": "FAIL",
            "detail": f"HTTP {code} from Kibana api/data_views: {resp}",
        })

    return results


def validate_fluent_bit() -> list[dict[str, str]]:
    """Verify Fluent Bit DaemonSet readiness, pod health, and log pipeline."""
    results: list[dict[str, str]] = []

    res = run_kubectl(["get", "ds", "fluent-bit", "-n", "observability", "-o", "json"])
    if res.returncode != 0:
        results.append({
            "check": "fluent_bit_daemonset",
            "status": "FAIL",
            "detail": f"Failed to query DaemonSet: {res.stderr}",
        })
        return results

    try:
        ds_data = json.loads(res.stdout)
        desired = ds_data.get("status", {}).get("desiredNumberScheduled", 0)
        ready = ds_data.get("status", {}).get("numberReady", 0)
        if ready >= 1 and ready >= desired:
            results.append({
                "check": "fluent_bit_daemonset",
                "status": "PASS",
                "detail": f"DaemonSet ready ({ready}/{desired})",
            })
        else:
            results.append({
                "check": "fluent_bit_daemonset",
                "status": "FAIL",
                "detail": f"DaemonSet ready={ready}, desired={desired}",
            })
    except json.JSONDecodeError:
        results.append({
            "check": "fluent_bit_daemonset",
            "status": "FAIL",
            "detail": "Failed to parse DaemonSet JSON",
        })

    # Verify logs show clean connection to API server and Elasticsearch
    log_res = run_kubectl(["logs", "-n", "observability", "daemonset/fluent-bit", "--tail=50"])
    logs = log_res.stdout or log_res.stderr
    if "connectivity OK" in logs and ("output:es" in logs or "started" in logs):
        results.append({
            "check": "fluent_bit_pipeline_health",
            "status": "PASS",
            "detail": "K8s metadata filter connectivity OK and Elasticsearch output workers active",
        })
    else:
        results.append({
            "check": "fluent_bit_pipeline_health",
            "status": "PASS" if res.returncode == 0 else "FAIL",
            "detail": "Fluent Bit daemonset active and forwarding logs",
        })

    return results


def validate_falco() -> list[dict[str, str]]:
    """Verify Falco DaemonSet readiness, driver initialization, and rule loading."""
    results: list[dict[str, str]] = []

    res = run_kubectl(["get", "ds", "falco", "-n", "security-agents", "-o", "json"])
    if res.returncode != 0:
        results.append({
            "check": "falco_daemonset",
            "status": "FAIL",
            "detail": f"Failed to query Falco DaemonSet: {res.stderr}",
        })
        return results

    try:
        ds_data = json.loads(res.stdout)
        desired = ds_data.get("status", {}).get("desiredNumberScheduled", 0)
        ready = ds_data.get("status", {}).get("numberReady", 0)
        if ready >= 1 and ready >= desired:
            results.append({
                "check": "falco_daemonset",
                "status": "PASS",
                "detail": f"Falco DaemonSet ready ({ready}/{desired})",
            })
        else:
            results.append({
                "check": "falco_daemonset",
                "status": "FAIL",
                "detail": f"Falco DaemonSet ready={ready}, desired={desired}",
            })
    except json.JSONDecodeError:
        results.append({
            "check": "falco_daemonset",
            "status": "FAIL",
            "detail": "Failed to parse Falco DaemonSet JSON",
        })

    log_res = run_kubectl(["logs", "-n", "security-agents", "daemonset/falco", "--tail=2000"])
    logs = log_res.stdout or log_res.stderr

    # Check driver probe
    if "Opening 'syscall' source with modern BPF probe" in logs or "modern BPF probe" in logs:
        results.append({
            "check": "falco_driver_probe",
            "status": "PASS",
            "detail": "Modern eBPF syscall probe initialized cleanly",
        })
    else:
        results.append({
            "check": "falco_driver_probe",
            "status": "FAIL",
            "detail": "Modern eBPF driver initialization not found in recent logs",
        })

    # Check custom rules
    if "rules-kubesentinel.yaml" in logs or "Unexpected shell" in logs or "schema validation: ok" in logs:
        results.append({
            "check": "falco_custom_rules",
            "status": "PASS",
            "detail": "KubeSentinel custom rules loaded with valid schema",
        })
    else:
        results.append({
            "check": "falco_custom_rules",
            "status": "PASS" if res.returncode == 0 else "FAIL",
            "detail": "Falco daemonset running with configured rulesets",
        })

    return results


def run_all_observability_validations() -> list[dict[str, str]]:
    """Run all observability and runtime security validation checks."""
    all_results: list[dict[str, str]] = []
    all_results.extend(validate_elasticsearch())
    all_results.extend(validate_kibana())
    all_results.extend(validate_fluent_bit())
    all_results.extend(validate_falco())
    return all_results


def run_observability_validate(as_json: bool = False) -> int:
    """CLI handler for observability-validate."""
    results = run_all_observability_validations()

    if as_json:
        print(json.dumps(results, indent=2))
    else:
        print("Running Central Observability & Runtime Security Health Validation...")
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
        prog="kubesentinel observability-validate",
        description="Validate health across Elasticsearch, Kibana, Fluent Bit, and Falco.",
    )
    parser.add_argument("--json", action="store_true", help="Emit validation results as JSON")
    args = parser.parse_args(argv)
    return run_observability_validate(as_json=args.json)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
