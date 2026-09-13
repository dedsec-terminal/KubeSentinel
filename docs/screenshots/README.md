# KubeSentinel Screenshot Capture Guide

This directory contains instructions and asset placeholders for manual screenshot captures from KubeSentinel's live cluster, Kibana dashboards, and terminal execution sessions.

These instructions support consistent, privacy-conscious screenshots for project documentation and technical writeups.

---

## 1. Required Visual Assets & Placeholders

| Asset Filename | Suggested Dimensions | Subject Matter | Source Component |
| :--- | :--- | :--- | :--- |
| `01_canonical_demo_terminal.png` | 1920x1080 | Complete 8-step execution of `python scripts/kubesentinel.py demo` | Terminal (Windows Terminal / PowerShell) |
| `02_kibana_falco_runtime_alert.png` | 1920x1080 | Kibana Discover view of `kubesentinel-falco-*` showing triggered shell detection | Kibana (`http://localhost:5601`) |
| `03_kibana_app_telemetry_stream.png` | 1920x1080 | Kibana Discover view of `kubesentinel-app-*` showing dual-site application events | Kibana (`http://localhost:5601`) |
| `04_elasticsearch_indices_summary.png` | 1600x900 | Kibana Stack Management -> Index Management showing doc counts & store sizes | Kibana (`http://localhost:5601`) |
| `05_kyverno_admission_rejection.png` | 1400x800 | Terminal output showing Kyverno rejecting non-compliant privileged pod | Terminal (`kubectl apply`) |
| `06_empirical_tuning_comparison.png` | 1600x900 | Visual breakdown of V1 baseline vs. V2 tuned query noise reduction (100% lab noise suppression) | Terminal / Markdown report |

---

## 2. Step-by-Step Capture Instructions

### Prerequisite: Live Cluster & Kibana Access

Ensure the KubeSentinel cluster is running and healthy:
```powershell
python scripts/kubesentinel.py demo
```

To access Kibana:
1. Kibana is deployed in the `observability` namespace and bound to port `5601` on the host:
   - **URL**: [http://localhost:5601](http://localhost:5601)
2. In the Kibana left navigation, navigate to **Discover**.
3. Verify the two configured index patterns:
   - `kubesentinel-falco-*` (Runtime kernel syscall security alerts)
   - `kubesentinel-app-*` (Edge application security telemetry)

---

### Screenshot 1: Canonical 8-Step Demo (`01_canonical_demo_terminal.png`)
1. Open a clean PowerShell or Windows Terminal window with a dark background theme (e.g. Campbell, One Half Dark).
2. Set font size to 13pt or 14pt for crisp readability.
3. Run:
   ```powershell
   python scripts/kubesentinel.py demo
   ```
4. Capture the full window showing all 8 steps:
   - `[HEALTH]` Cluster & Pod Health
   - `[TELEMETRY]` Normal Event Flow
   - `[DETECTION]` Runtime Detection
   - `[PREVENTION]` Network Prevention
   - `[PREVENTION]` RBAC Prevention
   - `[PREVENTION]` Admission Prevention
   - `[PREVENTION]` Lateral Prevention
   - `[RESULT]` Detection & Hunting Query Summary

---

### Screenshot 2: Kibana Falco Runtime Shell Detection (`02_kibana_falco_runtime_alert.png`)
1. In Kibana Discover, select the `kubesentinel-falco-*` index pattern.
2. Enter the Lucene search query:
   ```lucene
   rule:"Unexpected shell in KubeSentinel edge workload"
   ```
3. Set the time picker to **Today** or **Last 24 Hours**.
4. Add the following columns to the table view:
   - `rule`
   - `priority`
   - `output_fields.k8s_ns_name`
   - `output_fields.k8s_pod_name`
   - `output_fields.proc_cmdline`
   - `output_fields.user_uid`
5. Expand a single alert document to display the full structured JSON payload.
6. Capture the screen highlighting the process command line and namespace isolation.

---

### Screenshot 3: Kibana Application Telemetry Stream (`03_kibana_app_telemetry_stream.png`)
1. In Kibana Discover, select the `kubesentinel-app-*` index pattern.
2. Enter the query:
   ```lucene
   log_type:"security_event_processed"
   ```
3. Add the following columns:
   - `edge_site`
   - `event_id`
   - `severity`
   - `service`
   - `redis_stream_id`
   - `worker`
4. Capture the table displaying events ingested from `pune`, `mumbai`, and `bangalore`.

---

### Screenshot 4: Elasticsearch Index Management (`04_elasticsearch_indices_summary.png`)
1. In Kibana, open the hamburger menu and go to **Management** -> **Stack Management**.
2. Click **Index Management** under Data.
3. Filter by `kubesentinel-`.
4. Capture the table showing active indices, document counts, and primary store sizes.

---

### Screenshot 5: Kyverno Admission Prevention (`05_kyverno_admission_rejection.png`)
1. In terminal, run:
   ```powershell
   python scripts/kubesentinel.py simulate insecure-deployment
   ```
2. Or submit the controlled fixture directly:
   ```powershell
   kubectl apply -f simulations/insecure_deployment/fixtures/violating-workload.yaml
   ```
3. Capture the terminal showing the admission webhook rejection with the explicit Kyverno policy rule violation.

---

## 3. Image Optimization Standards
- **Format**: PNG (lossless).
- **Aspect Ratio**: 16:9 preferred for full-screen dashboards.
- **Sensitive Data**: Verify that no host-specific personal file paths or non-synthetic secrets are visible in screenshot crops.
