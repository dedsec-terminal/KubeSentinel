"""End-to-end dual telemetry verification: Application events and Falco runtime security alerts."""

from __future__ import annotations

import json
import subprocess
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.k8s_client import run_kubectl
from scripts.setup_es_templates import get_es_credentials, request_es


def _post_edge_event(namespace: str, payload: dict) -> tuple[int, dict]:
    """Submit JSON event payload to edge-api container inside cluster."""
    body_json = json.dumps(payload)
    py_script = (
        "import urllib.request, sys, json; "
        "req = urllib.request.Request('http://127.0.0.1:8000/events', data=sys.argv[1].encode('utf-8'), "
        "headers={'Content-Type': 'application/json'}); "
        "res = urllib.request.urlopen(req); "
        "print(res.status); print(res.read().decode('utf-8'))"
    )
    cmd = [
        "docker", "exec", "-i", "-e", "KUBECONFIG=/etc/rancher/k3s/k3s.yaml", "k3d-kubesentinel-server-0",
        "kubectl", "exec", "-n", namespace, "deployment/edge-api", "--",
        "python", "-c", py_script, body_json,
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    lines = res.stdout.strip().splitlines()
    status_code = int(lines[0])
    resp_obj = json.loads(lines[1])
    return status_code, resp_obj


def verify_application_telemetry_proof(username: str, password: str, timeout_sec: int = 45) -> bool:
    """Proof 1: HTTP POST /events -> Redis -> edge-worker -> Fluent Bit -> Elasticsearch kubesentinel-app-*."""
    print("\n=======================================================")
    print(" [PROOF 1] Application Telemetry Pipeline Verification")
    print("=======================================================")

    test_uuid = str(uuid.uuid4())
    print(f"Generating synthetic security event: {test_uuid}")
    payload = {
        "event_type": "security_simulation",
        "severity": "critical",
        "source": "telemetry-smoke-pune",
        "destination": "central-siem",
        "message": f"Milestone E dual telemetry proof event {test_uuid}",
        "metadata": {
            "proof": "application_telemetry",
            "proof_id": test_uuid,
            "site": "pune",
        },
    }

    status_code, resp = _post_edge_event("edge-pune", payload)
    if status_code != 202:
        print(f"ERROR: Expected HTTP 202 from edge-api, got {status_code}: {resp}", file=sys.stderr)
        return False

    event_id = resp.get("event_id")
    stream_id = resp.get("stream_id")
    print(f"HTTP 202 Accepted: event_id={event_id}, redis_stream_id={stream_id}")
    print("Waiting for edge-worker processing & Fluent Bit ingestion into Elasticsearch...")

    start_time = time.monotonic()
    doc_found = False
    source_doc: dict = {}
    hit_meta: dict = {}

    while time.monotonic() - start_time < timeout_sec:
        query = f"kubesentinel-app-*/_search?q=event_id:{event_id}&pretty"
        code, search_res = request_es(query, username=username, password=password)
        if code == 200 and isinstance(search_res, dict):
            hits = search_res.get("hits", {}).get("hits", [])
            if hits:
                hit_meta = hits[0]
                source_doc = hit_meta.get("_source", {})
                doc_found = True
                break
        time.sleep(2)

    if not doc_found:
        print(f"ERROR: Event {event_id} not found in kubesentinel-app-* within {timeout_sec}s.", file=sys.stderr)
        return False

    print("\nDocument successfully indexed in Elasticsearch:")
    print(f"  Index:   {hit_meta.get('_index')}")
    print(f"  Doc ID:  {hit_meta.get('_id')}")

    required_fields = [
        "event_id",
        "edge_site",
        "severity",
        "log_type",
        "processing_status",
        "redis_stream_id",
        "worker",
        "timestamp",
        "processed_at",
        "kubernetes",
    ]

    missing = [f for f in required_fields if source_doc.get(f) is None]
    if missing:
        print(f"ERROR: Missing required fields in document: {missing}", file=sys.stderr)
        return False

    for f in required_fields:
        val = source_doc.get(f)
        val_str = json.dumps(val)[:60] + "..." if isinstance(val, dict) else str(val)
        print(f"  [OK] {f}: {val_str}")

    kube_meta = source_doc.get("kubernetes", {})
    pod_name = kube_meta.get("pod_name")
    if not pod_name or "edge-worker" not in pod_name:
        print(f"ERROR: Expected kubernetes.pod_name to contain 'edge-worker', got: {pod_name}", file=sys.stderr)
        return False

    print(f"  [OK] kubernetes.pod_name: {pod_name}")
    print(f"  [OK] kubernetes.namespace_name: {kube_meta.get('namespace_name')}")

    assert source_doc.get("event_id") == event_id
    assert source_doc.get("edge_site") == "pune"
    assert source_doc.get("severity") == "critical"
    assert source_doc.get("log_type") == "security_event_processed"
    assert source_doc.get("processing_status") == "success"

    print("\n[PASS] Proof 1 verified: End-to-end application telemetry ingestion confirmed.")
    return True


def verify_runtime_security_telemetry_proof(username: str, password: str, timeout_sec: int = 45) -> bool:
    """Proof 2: Controlled runtime execution -> Falco JSON alert -> Fluent Bit -> Elasticsearch kubesentinel-falco-*."""
    print("\n=======================================================")
    print(" [PROOF 2] Runtime Security Telemetry Pipeline Verification")
    print("=======================================================")

    marker = f"falco-proof-{uuid.uuid4().hex[:8]}"
    print(f"Triggering controlled shell execution with marker: {marker}")

    res = run_kubectl([
        "exec", "-n", "edge-pune", "deployment/edge-api", "--",
        "sh", "-c", f"echo {marker}",
    ])
    if res.returncode != 0:
        print(f"ERROR: Failed to execute shell in edge-pune: {res.stderr}", file=sys.stderr)
        return False

    print("Command executed successfully. Waiting for Falco detection & Fluent Bit forwarding to ES...")
    start_time = time.monotonic()
    alert_doc: dict = {}
    hit_meta: dict = {}
    doc_found = False

    while time.monotonic() - start_time < timeout_sec:
        query = f"kubesentinel-falco-*/_search?q={marker}&pretty"
        code, search_res = request_es(query, username=username, password=password)
        if code == 200 and isinstance(search_res, dict):
            hits = search_res.get("hits", {}).get("hits", [])
            for h in hits:
                s = h.get("_source", {})
                rule = s.get("rule")
                cmdline = s.get("output_fields", {}).get("proc_cmdline", "") or s.get("output", "")
                if rule == "Unexpected shell in KubeSentinel edge workload" and marker in cmdline:
                    alert_doc = s
                    hit_meta = h
                    doc_found = True
                    break
        if doc_found:
            break
        time.sleep(2)

    if not doc_found:
        print(f"ERROR: Falco alert with marker {marker} not found in kubesentinel-falco-* within {timeout_sec}s.", file=sys.stderr)
        return False

    print("\nFalco Alert Document successfully indexed in Elasticsearch:")
    print(f"  Index:   {hit_meta.get('_index')}")
    print(f"  Doc ID:  {hit_meta.get('_id')}")

    out_fields = alert_doc.get("output_fields", {})
    ns_detected = out_fields.get("k8s_ns_name") or out_fields.get("k8s.ns.name")
    pod_detected = out_fields.get("k8s_pod_name") or out_fields.get("k8s.pod.name")

    print(f"  [OK] rule:         {alert_doc.get('rule')}")
    print(f"  [OK] priority:     {alert_doc.get('priority')}")
    print(f"  [OK] source:       {alert_doc.get('source')}")
    print(f"  [OK] namespace:    {ns_detected}")
    print(f"  [OK] pod:          {pod_detected}")
    print(f"  [OK] proc_cmdline: {out_fields.get('proc_cmdline')}")
    print(f"  [OK] @timestamp:   {alert_doc.get('@timestamp')}")

    assert alert_doc.get("rule") == "Unexpected shell in KubeSentinel edge workload"
    assert alert_doc.get("priority") == "Warning"
    assert ns_detected == "edge-pune"
    assert marker in (out_fields.get("proc_cmdline") or "")

    print("\n[PASS] Proof 2 verified: End-to-end runtime security telemetry alert ingestion confirmed.")
    return True


def run_telemetry_smoke(timeout_sec: int = 45) -> int:
    """Execute dual end-to-end telemetry verification."""
    print("Starting KubeSentinel Milestone E Dual End-to-End Telemetry Smoke Test...")
    username, password = get_es_credentials()
    if not password:
        print("ERROR: Could not retrieve Elasticsearch credentials.", file=sys.stderr)
        return 1

    p1_ok = verify_application_telemetry_proof(username=username, password=password, timeout_sec=timeout_sec)
    if not p1_ok:
        print("FAIL: Proof 1 (Application Telemetry) failed.", file=sys.stderr)
        return 1

    p2_ok = verify_runtime_security_telemetry_proof(username=username, password=password, timeout_sec=timeout_sec)
    if not p2_ok:
        print("FAIL: Proof 2 (Runtime Security Telemetry) failed.", file=sys.stderr)
        return 1

    print("\n=======================================================")
    print(" [SUMMARY] DUAL TELEMETRY SMOKE TEST: ALL PROOFS PASSED")
    print("=======================================================")
    return 0


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="kubesentinel telemetry-smoke",
        description="Execute dual end-to-end telemetry verification (App & Falco).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=45,
        help="Timeout in seconds per proof (default: 45)",
    )
    args = parser.parse_args(argv)
    return run_telemetry_smoke(timeout_sec=args.timeout)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
