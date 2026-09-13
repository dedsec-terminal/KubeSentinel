"""Empirical Detection Tuning & Evaluation Engine for KubeSentinel Milestone F.

Compares Baseline Rule (V1) vs Tuned Rule (V2) for Unexpected Shell detection
against live Elasticsearch telemetry in kubesentinel-falco-*.
"""

from __future__ import annotations

import json
import sys
import time
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.k8s_client import run_kubectl
from scripts.setup_es_templates import get_es_credentials, request_es

# V1: Broad Baseline Rule
# Matches any Unexpected Shell Falco alert in the cluster without maintenance exclusions or workload scope refinement.
V1_QUERY = 'rule:"Unexpected shell in KubeSentinel edge workload"'

# V2: Tuned Rule
# Refines namespace, container, user UID, and explicitly excludes authorized diagnostic/maintenance patterns.
# Note: output_fields.proc_cmdline.keyword is used because standard analyzer on text tokenizes on hyphens,
# whereas .keyword preserves exact sub-string wildcard matching across hyphenated commands (*diag-maintenance*).
V2_QUERY = (
    'rule:"Unexpected shell in KubeSentinel edge workload" '
    'AND output_fields.k8s_ns_name.keyword:("edge-pune" OR "edge-mumbai" OR "edge-bangalore") '
    'AND output_fields.container_name.keyword:"edge-api" '
    'AND output_fields.user_uid:10001 '
    'AND NOT output_fields.proc_cmdline.keyword:(*diag-maintenance* OR *healthcheck*)'
)


def run_es_query(query_string: str, size: int = 100) -> dict[str, Any]:
    """Execute Lucene query string against kubesentinel-falco-* index in Elasticsearch."""
    username, password = get_es_credentials()
    payload = {
        "query": {
            "query_string": {
                "query": query_string,
            }
        },
        "size": size,
    }
    code, res = request_es(
        "kubesentinel-falco-*/_search",
        method="POST",
        data=payload,
        username=username,
        password=password,
    )
    if code != 200 or not isinstance(res, dict):
        raise RuntimeError(f"Elasticsearch query failed (HTTP {code}): {res}")
    return res


def get_hits_for_query(query_string: str) -> list[dict[str, Any]]:
    """Return list of hits for given query."""
    res = run_es_query(query_string, size=200)
    return res.get("hits", {}).get("hits", [])


def generate_benign_maintenance_event(
    namespace: str = "edge-pune",
    command_pattern: str = "echo kubesentinel-diag-maintenance",
    timeout_sec: float = 25.0,
) -> dict[str, Any]:
    """Execute a controlled benign diagnostic/maintenance shell command and wait for Falco ingestion."""
    marker = f"{command_pattern}-{uuid.uuid4().hex[:6]}"
    cmd = ["exec", "-n", namespace, "deployment/edge-api", "--", "sh", "-c", marker]

    start_time = time.monotonic()
    res = run_kubectl(cmd, timeout=10.0)
    if res.returncode != 0:
        raise RuntimeError(f"Failed to execute maintenance command in {namespace}: {res.stderr}")

    # Poll Elasticsearch until the event is ingested
    username, password = get_es_credentials()
    poll_start = time.monotonic()
    while time.monotonic() - poll_start < timeout_sec:
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
                return {
                    "marker": marker,
                    "namespace": namespace,
                    "doc_id": hits[0]["_id"],
                    "source": hits[0]["_source"],
                    "elapsed_sec": round(time.monotonic() - start_time, 2),
                }
        time.sleep(1.0)

    raise TimeoutError(f"Maintenance event '{marker}' was not ingested within {timeout_sec}s")


def evaluate_tuning() -> dict[str, Any]:
    """Perform comparative evaluation of V1 vs V2 rules on current live Elasticsearch data."""
    v1_hits = get_hits_for_query(V1_QUERY)
    v2_hits = get_hits_for_query(V2_QUERY)

    v1_count = len(v1_hits)
    v2_count = len(v2_hits)

    # Classify events based on proc_cmdline
    controlled_scenario_hits = []
    benign_maintenance_hits = []
    other_hits = []

    for hit in v1_hits:
        src = hit["_source"]
        cmdline = src.get("output_fields", {}).get("proc_cmdline", "")
        if "diag-maintenance" in cmdline or "healthcheck" in cmdline:
            benign_maintenance_hits.append(hit)
        elif any(k in cmdline for k in ("kubesentinel-sim-shell", "falco-validate", "falco-proof", "falco-e2e", "falco-test", "falco-runtime")):
            controlled_scenario_hits.append(hit)
        else:
            other_hits.append(hit)

    # Verify retention of controlled scenarios in V2
    v2_ids = {h["_id"] for h in v2_hits}
    controlled_retained = [h for h in controlled_scenario_hits if h["_id"] in v2_ids]
    benign_suppressed = [h for h in benign_maintenance_hits if h["_id"] not in v2_ids]
    benign_captured_by_v2 = [h for h in benign_maintenance_hits if h["_id"] in v2_ids]

    retention_rate = (len(controlled_retained) / len(controlled_scenario_hits) * 100.0) if controlled_scenario_hits else 100.0
    suppression_rate = (len(benign_suppressed) / len(benign_maintenance_hits) * 100.0) if benign_maintenance_hits else 0.0

    # Noise reduction percentage in local lab environment
    # Noise = benign candidate events flagged by V1
    noise_reduction_pct = 0.0
    if len(benign_maintenance_hits) > 0:
        noise_reduction_pct = (len(benign_suppressed) / len(benign_maintenance_hits)) * 100.0

    overall_reduction_pct = 0.0
    if v1_count > 0:
        overall_reduction_pct = ((v1_count - v2_count) / v1_count) * 100.0

    metrics = {
        "v1_query": V1_QUERY,
        "v2_query": V2_QUERY,
        "total_v1_events": v1_count,
        "total_v2_events": v2_count,
        "total_controlled_scenarios": len(controlled_scenario_hits),
        "controlled_scenarios_retained_by_v2": len(controlled_retained),
        "controlled_retention_rate_pct": retention_rate,
        "total_benign_maintenance_events": len(benign_maintenance_hits),
        "benign_maintenance_suppressed_by_v2": len(benign_suppressed),
        "benign_maintenance_captured_by_v2": len(benign_captured_by_v2),
        "benign_suppression_rate_pct": suppression_rate,
        "lab_noise_reduction_pct": noise_reduction_pct,
        "overall_candidate_reduction_pct": round(overall_reduction_pct, 2),
    }

    out_file = Path(__file__).resolve().parent / "tuning_metrics.json"
    out_file.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


if __name__ == "__main__":
    print("Executing evaluation against live Elasticsearch...")
    metrics = evaluate_tuning()
    print(json.dumps(metrics, indent=2))
    print(f"Metrics saved to: {Path(__file__).resolve().parent / 'tuning_metrics.json'}")
