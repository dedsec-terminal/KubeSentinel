"""Validation script for Fluent Bit telemetry ingestion into Elasticsearch."""

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

from scripts.setup_es_templates import get_es_credentials, request_es


def post_event_in_pod(namespace: str, event_data: dict) -> tuple[int, dict]:
    """Post event payload to edge-api container inside cluster."""
    body_json = json.dumps(event_data)
    py_script = (
        "import urllib.request, sys, json; "
        "req = urllib.request.Request('http://127.0.0.1:8000/events', data=sys.argv[1].encode('utf-8'), "
        "headers={'Content-Type': 'application/json'}); "
        "res = urllib.request.urlopen(req); "
        "print(res.status); print(res.read().decode('utf-8'))"
    )
    cmd = [
        "docker", "exec", "-i", "k3d-kubesentinel-server-0",
        "kubectl", "exec", "-n", namespace, "deployment/edge-api", "--",
        "python", "-c", py_script, body_json,
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    lines = res.stdout.strip().splitlines()
    status_code = int(lines[0])
    resp_obj = json.loads(lines[1])
    return status_code, resp_obj


def validate_fluentbit_ingestion(timeout_sec: int = 30) -> int:
    """Validate that Fluent Bit collects edge-worker logs and parses discrete fields into ES."""
    username, password = get_es_credentials()
    if not password:
        print("ERROR: Could not retrieve Elasticsearch credentials.", file=sys.stderr)
        return 1

    test_id = str(uuid.uuid4())
    print(f"=== Triggering test event: {test_id} on edge-api-pune ===")
    payload = {
        "event_type": "security_simulation",
        "severity": "critical",
        "source": "fluentbit-validator-pune",
        "destination": "central-siem",
        "message": f"Milestone E Fluent Bit validation event {test_id}",
        "metadata": {
            "validator_id": test_id,
            "site": "pune",
            "component": "fluent-bit-pipeline",
        },
    }

    status, resp = post_event_in_pod("edge-pune", payload)
    if status != 202:
        print(f"ERROR: Expected HTTP 202, got {status}: {resp}", file=sys.stderr)
        return 1

    event_id = resp.get("event_id")
    stream_id = resp.get("stream_id")
    print(f"Event accepted: event_id={event_id}, stream_id={stream_id}")

    print("Waiting for edge-worker processing & Fluent Bit shipping to Elasticsearch...")
    start_time = time.monotonic()
    doc_found = False
    source_doc: dict = {}

    while time.monotonic() - start_time < timeout_sec:
        query = f"kubesentinel-app-*/_search?q=event_id:{event_id}&pretty"
        code, search_res = request_es(query, username=username, password=password)
        if code == 200 and isinstance(search_res, dict):
            hits = search_res.get("hits", {}).get("hits", [])
            if hits:
                source_doc = hits[0].get("_source", {})
                doc_found = True
                break
        time.sleep(2)

    if not doc_found:
        print(f"ERROR: Document with event_id={event_id} not found in Elasticsearch within {timeout_sec}s.", file=sys.stderr)
        return 1

    print("\n=== Document Verified in Elasticsearch ===")
    print(f"Index: {hits[0].get('_index')}")
    print(f"ID:    {hits[0].get('_id')}")

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

    missing = []
    for field in required_fields:
        val = source_doc.get(field)
        if val is None:
            missing.append(field)
        else:
            print(f"  [OK] {field}: {val if not isinstance(val, dict) else json.dumps(val)[:60] + '...'}")

    if missing:
        print(f"\nERROR: Missing discrete fields: {missing}", file=sys.stderr)
        return 1

    # Check kubernetes metadata nested fields
    kube_meta = source_doc.get("kubernetes", {})
    kube_required = ["pod_name", "namespace_name", "container_name"]
    missing_kube = [k for k in kube_required if not kube_meta.get(k)]
    if missing_kube:
        print(f"ERROR: Missing kubernetes metadata: {missing_kube}", file=sys.stderr)
        return 1

    print(f"  [OK] kubernetes.pod_name: {kube_meta.get('pod_name')}")
    print(f"  [OK] kubernetes.namespace_name: {kube_meta.get('namespace_name')}")
    print(f"  [OK] kubernetes.container_name: {kube_meta.get('container_name')}")

    assert source_doc.get("log_type") == "security_event_processed", f"Invalid log_type: {source_doc.get('log_type')}"
    assert source_doc.get("processing_status") == "success", f"Invalid processing_status: {source_doc.get('processing_status')}"
    assert source_doc.get("edge_site") == "pune", f"Invalid edge_site: {source_doc.get('edge_site')}"
    assert source_doc.get("severity") == "critical", f"Invalid severity: {source_doc.get('severity')}"

    print("\n[PASS] Fluent Bit log collection, JSON decoding, Kubernetes enrichment, and ES ingestion verified!")
    return 0


if __name__ == "__main__":
    sys.exit(validate_fluentbit_ingestion())
