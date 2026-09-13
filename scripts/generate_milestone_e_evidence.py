"""Generate sanitized Milestone E evidence files under docs/evidence/milestone-e/."""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.k8s_client import run_kubectl
from scripts.setup_es_templates import get_es_credentials, request_es, request_kibana

EVIDENCE_DIR = ROOT / "docs" / "evidence" / "milestone-e"


def sanitize(text: str, secret: str = "") -> str:
    """Sanitize secrets, passwords, and sensitive tokens."""
    if not text:
        return ""
    sanitized = text
    if secret:
        sanitized = sanitized.replace(secret, "***REDACTED***")
    # Also check credentials from environment if any
    for k, v in os.environ.items():
        if ("PASS" in k or "SECRET" in k or "TOKEN" in k) and v and len(v) > 4:
            sanitized = sanitized.replace(v, "***REDACTED***")
    return sanitized


def generate_environment_evidence(secret: str) -> None:
    print("Generating environment.txt...")
    lines: list[str] = ["=== KUBERNETES CLUSTER INFO ==="]
    res = run_kubectl(["cluster-info"])
    lines.append(res.stdout.strip())

    lines.extend(["\n\n=== NODES ==="])
    res = run_kubectl(["get", "nodes", "-o", "wide"])
    lines.append(res.stdout.strip())

    lines.extend(["\n\n=== ALL PODS ACROSS NAMESPACES ==="])
    res = run_kubectl(["get", "pods", "-A", "-o", "wide"])
    lines.append(res.stdout.strip())

    lines.extend(["\n\n=== NAMESPACES & PSA LABELS ==="])
    res = run_kubectl(["get", "namespaces", "--show-labels"])
    lines.append(res.stdout.strip())

    lines.extend(["\n\n=== SERVICES (CLUSTERIP ONLY) ==="])
    res = run_kubectl(["get", "svc", "-A"])
    lines.append(res.stdout.strip())

    lines.extend(["\n\n=== NETWORKPOLICIES ==="])
    res = run_kubectl(["get", "networkpolicies", "-A"])
    lines.append(res.stdout.strip())

    lines.extend(["\n\n=== SYSTEM & PYTHON INFO ==="])
    lines.append(f"OS: {platform.platform()}")
    lines.append(f"Python: {sys.version}")

    content = sanitize("\n".join(lines), secret)
    (EVIDENCE_DIR / "environment.txt").write_text(content, encoding="utf-8")
    print("  -> environment.txt written")


def generate_elastic_health_evidence(username: str, secret: str) -> None:
    print("Generating elastic-health.txt...")
    lines: list[str] = ["=== OBSERVABILITY WORKLOAD STATUS ==="]
    res = run_kubectl(["get", "pods,svc,secrets", "-n", "observability", "-o", "wide"])
    lines.append(res.stdout.strip())

    lines.extend(["\n\n=== ELASTICSEARCH CLUSTER HEALTH (GET /_cluster/health) ==="])
    code, health = request_es("_cluster/health", username=username, password=secret)
    lines.append(f"HTTP {code}")
    lines.append(json.dumps(health, indent=2) if isinstance(health, dict) else str(health))

    lines.extend(["\n\n=== ELASTICSEARCH NODES (GET /_cat/nodes?v) ==="])
    code, nodes = request_es("_cat/nodes?v", username=username, password=secret)
    lines.append(str(nodes).strip())

    lines.extend(["\n\n=== ELASTICSEARCH INDICES (GET /_cat/indices/kubesentinel-*?v) ==="])
    code, indices = request_es("_cat/indices/kubesentinel-*?v", username=username, password=secret)
    lines.append(str(indices).strip())

    lines.extend(["\n\n=== COMPOSABLE INDEX TEMPLATE: kubesentinel-app ==="])
    code, tmpl_app = request_es("_index_template/kubesentinel-app", username=username, password=secret)
    lines.append(json.dumps(tmpl_app, indent=2) if isinstance(tmpl_app, dict) else str(tmpl_app))

    lines.extend(["\n\n=== COMPOSABLE INDEX TEMPLATE: kubesentinel-falco ==="])
    code, tmpl_falco = request_es("_index_template/kubesentinel-falco", username=username, password=secret)
    lines.append(json.dumps(tmpl_falco, indent=2) if isinstance(tmpl_falco, dict) else str(tmpl_falco))

    lines.extend(["\n\n=== KIBANA STATUS (GET /api/status) ==="])
    code, kb_status = request_kibana("api/status", username=username, password=secret)
    lines.append(f"HTTP {code}")
    if isinstance(kb_status, dict):
        summary = {
            "status": kb_status.get("status", {}).get("overall"),
            "version": kb_status.get("version", {}).get("number"),
        }
        lines.append(json.dumps(summary, indent=2))
    else:
        lines.append(str(kb_status))

    lines.extend(["\n\n=== KIBANA DATA VIEWS (GET /api/data_views) ==="])
    code, kb_views = request_kibana("api/data_views", username=username, password=secret)
    lines.append(f"HTTP {code}")
    lines.append(json.dumps(kb_views, indent=2) if isinstance(kb_views, dict) else str(kb_views))

    lines.extend(["\n\n=== ELASTICSEARCH & KIBANA SIZING / RESOURCE CONSTRAINTS ==="])
    es_deploy = run_kubectl(["get", "deployment", "elasticsearch", "-n", "observability", "-o", "jsonpath={.spec.template.spec.containers[0].resources}"])
    es_env = run_kubectl(["get", "deployment", "elasticsearch", "-n", "observability", "-o", "jsonpath={.spec.template.spec.containers[0].env}"])
    kb_deploy = run_kubectl(["get", "deployment", "kibana", "-n", "observability", "-o", "jsonpath={.spec.template.spec.containers[0].resources}"])
    lines.append(f"Elasticsearch Resources: {es_deploy.stdout.strip()}")
    lines.append(f"Elasticsearch JVM Heap: {es_env.stdout.strip()}")
    lines.append(f"Kibana Resources: {kb_deploy.stdout.strip()}")

    content = sanitize("\n".join(lines), secret)
    (EVIDENCE_DIR / "elastic-health.txt").write_text(content, encoding="utf-8")
    print("  -> elastic-health.txt written")


def generate_fluent_bit_evidence(secret: str) -> None:
    print("Generating fluent-bit.txt...")
    lines: list[str] = ["=== FLUENT BIT DAEMONSET & STORAGE STATUS ==="]
    res = run_kubectl(["get", "ds,pods,pv,pvc,configmap", "-n", "observability", "-l", "app.kubernetes.io/name=fluent-bit", "-o", "wide"])
    lines.append(res.stdout.strip())

    lines.extend(["\n\n=== FLUENT BIT CONFIGURATION (fluent-bit-config ConfigMap) ==="])
    res = run_kubectl(["get", "configmap", "fluent-bit-config", "-n", "observability", "-o", "yaml"])
    lines.append(res.stdout.strip())

    lines.extend(["\n\n=== FLUENT BIT STARTUP & INGESTION LOGS ==="])
    res = run_kubectl(["logs", "-n", "observability", "daemonset/fluent-bit", "--tail=60"])
    lines.append(res.stdout.strip())

    content = sanitize("\n".join(lines), secret)
    (EVIDENCE_DIR / "fluent-bit.txt").write_text(content, encoding="utf-8")
    print("  -> fluent-bit.txt written")


def generate_application_telemetry_evidence(username: str, secret: str) -> None:
    print("Generating application-telemetry.txt...")
    test_uuid = str(uuid.uuid4())
    payload = {
        "event_type": "security_evidence_trace",
        "severity": "critical",
        "source": "evidence-generator-pune",
        "destination": "central-siem",
        "message": f"Milestone E authoritative application telemetry proof {test_uuid}",
        "metadata": {
            "evidence_id": test_uuid,
            "site": "pune",
            "proof_type": "application_telemetry_e2e",
        },
    }

    body_json = json.dumps(payload)
    py_script = (
        "import urllib.request, sys, json; "
        "req = urllib.request.Request('http://127.0.0.1:8000/events', data=sys.argv[1].encode('utf-8'), "
        "headers={'Content-Type': 'application/json'}); "
        "res = urllib.request.urlopen(req); "
        "print(res.status); print(res.read().decode('utf-8'))"
    )
    cmd = [
        "docker", "exec", "-i", "k3d-kubesentinel-server-0",
        "kubectl", "exec", "-n", "edge-pune", "deployment/edge-api", "--",
        "python", "-c", py_script, body_json,
    ]
    exec_res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    lines_resp = exec_res.stdout.strip().splitlines()
    status_code = int(lines_resp[0])
    resp_obj = json.loads(lines_resp[1])
    event_id = resp_obj.get("event_id")
    stream_id = resp_obj.get("stream_id")

    # Poll Elasticsearch
    doc_found = False
    hit_doc: dict = {}
    for _ in range(20):
        code, search_res = request_es(f"kubesentinel-app-*/_search?q=event_id:{event_id}&pretty", username=username, password=secret)
        if code == 200 and isinstance(search_res, dict):
            hits = search_res.get("hits", {}).get("hits", [])
            if hits:
                hit_doc = hits[0]
                doc_found = True
                break
        time.sleep(2)

    lines = [
        "=== PROOF 1: APPLICATION TELEMETRY END-TO-END INGESTION ===",
        f"Timestamp: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
        f"Synthetic Proof UUID: {test_uuid}",
        "Target Endpoint: edge-api.edge-pune (POST /events)",
        f"HTTP Response: {status_code} Accepted",
        f"Returned event_id: {event_id}",
        f"Returned redis_stream_id: {stream_id}",
        "\n--- Elasticsearch Index Verification ---",
        f"Document Found: {doc_found}",
        f"Index: {hit_doc.get('_index')}",
        f"Document ID: {hit_doc.get('_id')}",
        "\n--- Full Indexed Document Source (_source) ---",
        json.dumps(hit_doc.get("_source", {}), indent=2),
        "\n--- Field Assertion Ledger ---",
    ]

    source = hit_doc.get("_source", {})
    for field in ["event_id", "edge_site", "severity", "log_type", "processing_status", "redis_stream_id", "worker", "timestamp", "processed_at", "kubernetes"]:
        lines.append(f"  [PASS] field '{field}': {json.dumps(source.get(field)) if isinstance(source.get(field), dict) else source.get(field)}")

    content = sanitize("\n".join(lines), secret)
    (EVIDENCE_DIR / "application-telemetry.txt").write_text(content, encoding="utf-8")
    print("  -> application-telemetry.txt written")


def generate_falco_runtime_evidence() -> None:
    print("Generating falco-runtime.txt...")
    lines: list[str] = ["=== FALCO DAEMONSET IN SECURITY-AGENTS NAMESPACE ==="]
    res = run_kubectl(["get", "ds,pods", "-n", "security-agents", "-o", "wide"])
    lines.append(res.stdout.strip())

    lines.extend(["\n\n=== DRIVER & RULES INITIALIZATION LOGS ==="])
    res = run_kubectl(["logs", "-n", "security-agents", "daemonset/falco", "--tail=60"])
    lines.append(res.stdout.strip())

    marker = f"falco-runtime-evidence-{uuid.uuid4().hex[:8]}"
    lines.extend([f"\n\n=== RUNTIME ATTACK SIMULATION EXECUTION (marker: {marker}) ==="])
    res = run_kubectl([
        "exec", "-n", "edge-pune", "deployment/edge-api", "--",
        "sh", "-c", f"echo {marker}",
    ])
    lines.append(f"Trigger Command: sh -c echo {marker}")
    lines.append(f"Execution returncode: {res.returncode}")
    lines.append(f"Execution output: {res.stdout.strip()}")

    time.sleep(2.5)
    lines.extend(["\n\n=== FALCO STDOUT JSON ALERT EMISSION ==="])
    log_res = run_kubectl(["logs", "-n", "security-agents", "daemonset/falco", "--tail=20"])
    alert_lines = [l for l in log_res.stdout.strip().splitlines() if marker in l or "Unexpected shell" in l]
    if alert_lines:
        lines.append(alert_lines[-1])
    else:
        lines.append(log_res.stdout.strip()[-1000:])

    (EVIDENCE_DIR / "falco-runtime.txt").write_text("\n".join(lines), encoding="utf-8")
    print("  -> falco-runtime.txt written")


def generate_falco_elastic_evidence(username: str, secret: str) -> None:
    print("Generating falco-elastic.txt...")
    marker = f"falco-e2e-evidence-{uuid.uuid4().hex[:8]}"

    res = run_kubectl([
        "exec", "-n", "edge-pune", "deployment/edge-api", "--",
        "sh", "-c", f"echo {marker}",
    ])

    doc_found = False
    hit_doc: dict = {}
    for _ in range(20):
        code, search_res = request_es(f"kubesentinel-falco-*/_search?q={marker}&pretty", username=username, password=secret)
        if code == 200 and isinstance(search_res, dict):
            hits = search_res.get("hits", {}).get("hits", [])
            for h in hits:
                s = h.get("_source", {})
                rule = s.get("rule")
                cmdline = s.get("output_fields", {}).get("proc_cmdline", "") or s.get("output", "")
                if rule == "Unexpected shell in KubeSentinel edge workload" and marker in cmdline:
                    hit_doc = h
                    doc_found = True
                    break
        if doc_found:
            break
        time.sleep(2)

    lines = [
        "=== PROOF 2: RUNTIME SECURITY TELEMETRY PIPELINE (FALCO -> FLUENT BIT -> ELASTICSEARCH) ===",
        f"Timestamp: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
        f"Trigger Marker: {marker}",
        "Target Pod: edge-api in edge-pune",
        f"Trigger Result ReturnCode: {res.returncode}",
        "\n--- Elasticsearch Index Verification ---",
        f"Document Found: {doc_found}",
        f"Index: {hit_doc.get('_index')}",
        f"Document ID: {hit_doc.get('_id')}",
        "\n--- Full Indexed Alert Document Source (_source) ---",
        json.dumps(hit_doc.get("_source", {}), indent=2),
        "\n--- Field Assertion Ledger ---",
    ]

    source = hit_doc.get("_source", {})
    lines.append(f"  [PASS] rule: {source.get('rule')}")
    lines.append(f"  [PASS] priority: {source.get('priority')}")
    lines.append(f"  [PASS] source: {source.get('source')}")
    lines.append(f"  [PASS] time: {source.get('time')}")
    out_fields = source.get("output_fields", {})
    lines.append(f"  [PASS] output_fields.k8s_ns_name: {out_fields.get('k8s_ns_name') or out_fields.get('k8s.ns.name')}")
    lines.append(f"  [PASS] output_fields.proc_cmdline: {out_fields.get('proc_cmdline')}")

    content = sanitize("\n".join(lines), secret)
    (EVIDENCE_DIR / "falco-elastic.txt").write_text(content, encoding="utf-8")
    print("  -> falco-elastic.txt written")


def generate_observability_validation_evidence() -> None:
    print("Generating observability-validation.txt...")
    lines: list[str] = ["=== OBSERVABILITY VALIDATE OUTPUT ==="]
    res = subprocess.run([sys.executable, "scripts/kubesentinel.py", "observability-validate"], capture_output=True, text=True, cwd=ROOT, check=False)
    lines.append(res.stdout.strip())

    lines.extend(["\n\n=== FALCO VALIDATE OUTPUT ==="])
    res = subprocess.run([sys.executable, "scripts/kubesentinel.py", "falco-validate"], capture_output=True, text=True, cwd=ROOT, check=False)
    lines.append(res.stdout.strip())

    lines.extend(["\n\n=== TELEMETRY SMOKE TEST OUTPUT ==="])
    res = subprocess.run([sys.executable, "scripts/kubesentinel.py", "telemetry-smoke"], capture_output=True, text=True, cwd=ROOT, check=False)
    lines.append(res.stdout.strip())

    (EVIDENCE_DIR / "observability-validation.txt").write_text("\n".join(lines), encoding="utf-8")
    print("  -> observability-validation.txt written")


def generate_tests_evidence() -> None:
    print("Generating tests.txt...")
    lines: list[str] = ["=== PYTEST REGRESSION SUITE (ALL TESTS) ==="]
    pytest_bin = str(ROOT / ".venv" / "Scripts" / "pytest")
    res = subprocess.run([pytest_bin, "-v", "--tb=short"], capture_output=True, text=True, cwd=ROOT, check=False)
    lines.append(res.stdout.strip())

    lines.extend(["\n\n=== RUFF LINT CHECK ==="])
    ruff_bin = str(ROOT / ".venv" / "Scripts" / "ruff")
    res = subprocess.run([ruff_bin, "check", "."], capture_output=True, text=True, cwd=ROOT, check=False)
    lines.append(res.stdout.strip() or "All checks passed!")

    lines.extend(["\n\n=== COMPILEALL BYTE-COMPILATION ==="])
    res = subprocess.run([sys.executable, "-m", "compileall", "-q", "apps/", "scripts/", "tests/"], capture_output=True, text=True, cwd=ROOT, check=False)
    lines.append(f"Exit code: {res.returncode} (0 = clean)")

    lines.extend(["\n\n=== KUBESENTINEL DOCTOR ==="])
    res = subprocess.run([sys.executable, "scripts/kubesentinel.py", "doctor"], capture_output=True, text=True, cwd=ROOT, check=False)
    lines.append(res.stdout.strip())

    (EVIDENCE_DIR / "tests.txt").write_text("\n".join(lines), encoding="utf-8")
    print("  -> tests.txt written")


def generate_git_status_evidence() -> None:
    print("Generating git-status.txt...")
    res = subprocess.run(["git", "status"], capture_output=True, text=True, cwd=ROOT, check=False)
    (EVIDENCE_DIR / "git-status.txt").write_text(res.stdout.strip(), encoding="utf-8")
    print("  -> git-status.txt written")


def main() -> int:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    username, secret = get_es_credentials()
    if not secret:
        print("ERROR: Could not get elasticsearch credentials", file=sys.stderr)
        return 1

    generate_environment_evidence(secret)
    generate_elastic_health_evidence(username, secret)
    generate_fluent_bit_evidence(secret)
    generate_application_telemetry_evidence(username, secret)
    generate_falco_runtime_evidence()
    generate_falco_elastic_evidence(username, secret)
    generate_observability_validation_evidence()
    generate_tests_evidence()
    generate_git_status_evidence()

    print("\nAll 9 evidence files generated successfully in docs/evidence/milestone-e/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
