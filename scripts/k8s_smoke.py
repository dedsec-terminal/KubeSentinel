"""End-to-end multi-site smoke verification across Pune, Mumbai, Bangalore in Kubernetes."""

from __future__ import annotations

import json
import sys
import time
import uuid
from pathlib import Path

from scripts.k8s_client import run_kubectl, send_http_to_edge_api

ROOT = Path(__file__).resolve().parents[1]


def run_k8s_smoke(timeout_sec: int = 45) -> int:
    """Execute multi-site trace across Pune, Mumbai, Bangalore edge APIs and central worker."""
    sites = [
        ("edge-pune", "pune", 8021),
        ("edge-mumbai", "mumbai", 8022),
        ("edge-bangalore", "bangalore", 8023),
    ]

    injected_events: dict[str, dict[str, str]] = {}
    print("=== Step 1: Ingesting events across edge sites ===")

    for ns, site_name, local_port in sites:
        event_id_trace = str(uuid.uuid4())
        payload = {
            "event_type": "security_simulation",
            "severity": "high",
            "source": f"edge-sensor-{site_name}-01",
            "destination": "central-siem",
            "message": f"Milestone C multi-site smoke event from {site_name}",
            "metadata": {
                "trace_id": event_id_trace,
                "site": site_name,
            },
        }

        print(f"\nSending HTTP POST /events to {ns} (site: {site_name})...")
        status_code, resp_data = send_http_to_edge_api(
            namespace=ns,
            payload=payload,
            local_port=local_port,
            timeout_sec=15.0,
        )

        if status_code != 202:
            print(f"Expected HTTP 202, got {status_code} for {ns}: {resp_data}", file=sys.stderr)
            return 1

        print(f"[{site_name.upper()}] HTTP 202 Accepted: event_id={resp_data['event_id']}, stream_id={resp_data['stream_id']}")
        injected_events[site_name] = {
            "ns": ns,
            "event_id": resp_data["event_id"],
            "stream_id": resp_data["stream_id"],
            "trace_id": event_id_trace,
        }

    print("\n=== Step 2: Verifying central worker processing and Downward API metadata ===")
    start_time = time.monotonic()
    all_processed = False
    verified_logs: dict[str, dict[str, str]] = {}

    while time.monotonic() - start_time < timeout_sec:
        log_res = run_kubectl(["logs", "deployment/edge-worker", "-n", "kubesentinel-system", "--tail=100"])
        for line in log_res.stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            if record.get("log_type") == "security_event_processed":
                record_event_id = record.get("event_id")
                for site_name, meta in injected_events.items():
                    if meta["event_id"] == record_event_id:
                        event_meta = record.get("metadata", {})
                        verified_logs[site_name] = {
                            "stream_id": record.get("redis_stream_id"),
                            "pod_name": event_meta.get("pod_name", ""),
                            "node_name": event_meta.get("node_name", ""),
                            "k8s_namespace": event_meta.get("k8s_namespace", ""),
                            "container_name": event_meta.get("container_name", ""),
                        }

        if len(verified_logs) == len(sites):
            all_processed = True
            break
        time.sleep(1)

    if not all_processed:
        print(f"Timeout waiting for edge-worker logs. Verified {len(verified_logs)}/{len(sites)}", file=sys.stderr)
        return 1

    for site_name, log_info in verified_logs.items():
        print(f"\n[VERIFIED {site_name.upper()}]")
        print(f"  Stream ID:      {log_info['stream_id']}")
        print(f"  Pod Name:       {log_info['pod_name']}")
        print(f"  Node Name:      {log_info['node_name']}")
        print(f"  K8s Namespace:  {log_info['k8s_namespace']}")
        print(f"  Container Name: {log_info['container_name']}")

        # Validate Downward API metadata correctness
        if not log_info["pod_name"]:
            print(f"ERROR: Missing pod_name in metadata for {site_name}", file=sys.stderr)
            return 1
        if log_info["container_name"] != "edge-api":
            print(f"ERROR: Expected container_name 'edge-api', found {log_info['container_name']}", file=sys.stderr)
            return 1
        if not log_info["node_name"]:
            print(f"ERROR: Missing node_name in metadata for {site_name}", file=sys.stderr)
            return 1

    print("\n=== Step 3: Verifying Redis Stream Acknowledgment (XACK) ===")
    res = run_kubectl(["get", "pods", "-n", "kubesentinel-system", "-l", "app=redis", "-o", "jsonpath={.items[0].metadata.name}"])
    redis_pod = res.stdout.strip()
    from scripts.k8s_deploy import load_or_create_secrets

    _, _, bootstrap_pw = load_or_create_secrets()

    xpending_res = run_kubectl([
        "exec",
        "-n",
        "kubesentinel-system",
        redis_pod,
        "--",
        "redis-cli",
        "--raw",
        "--user",
        "bootstrap",
        "-a",
        bootstrap_pw,
        "XPENDING",
        "security-events",
        "edge-workers",
    ])
    print(f"Redis XPENDING output:\n{xpending_res.stdout.strip()}")
    # With --raw, the first line of XPENDING output is the integer pending count
    lines = xpending_res.stdout.strip().splitlines()
    if lines and lines[0].strip() == "0":
        print("\n[PASS] All messages successfully acknowledged via XACK (PEL pending count: 0)!")
    else:
        print(f"Warning: Expected 0 pending messages, got: {xpending_res.stdout}", file=sys.stderr)
        return 1

    print("\n[PASS] Multi-site end-to-end smoke verification PASSED across Pune, Mumbai, Bangalore!")
    return 0


if __name__ == "__main__":
    sys.exit(run_k8s_smoke())
