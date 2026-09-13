# KubeSentinel Elasticsearch Telemetry Field Catalog & Gap Analysis

## 1. Executive Summary & Discovery Methodology

This document details the authoritative field catalog for KubeSentinel Elasticsearch indices (`kubesentinel-falco-*` and `kubesentinel-app-*`), discovered directly from the live single-node Elasticsearch cluster running in the `observability` namespace of the `kubesentinel` k3d cluster.

### Discovery Details
- **Cluster**: `k3d-kubesentinel-server-0` (v1.35.5+k3s1)
- **Elasticsearch Deployment**: `observability/deployment/elasticsearch` (8.17.3, single node)
- **Active Indices Inspected**:
  - `kubesentinel-falco-2026.09.13` (58 documents indexed, store size ~695.5 KB)
  - `kubesentinel-app-2026.09.13` (8,437+ documents indexed, store size ~4.5 MB)
- **Collector & Shipping Pipeline**:
  - `falco` (DaemonSet, `security-agents`, modern eBPF probe) -> container stdout / CRI log -> `fluent-bit` DaemonSet -> `kubesentinel-falco-*`
  - `edge-worker` (Deployment, `kubesentinel-system`, Redis Stream consumer) -> stdout JSON -> Docker container log -> `fluent-bit` DaemonSet -> `kubesentinel-app-*`

---

## 2. `kubesentinel-falco-*` Field Catalog

The `kubesentinel-falco-*` index stores kernel syscall runtime security alerts emitted by Falco via the modern eBPF driver, formatted as structured JSON and ingested by Fluent Bit.

| Field Path | Elasticsearch Type | Source Component | Description | Sample Value from Live Index |
| :--- | :--- | :--- | :--- | :--- |
| `@timestamp` | `date` | `fluent-bit` | Ingestion timestamp when Fluent Bit parsed and indexed the record into Elasticsearch. | `2026-09-13T17:10:50.096Z` |
| `time` | `date` | `falco` | UTC timestamp when the kernel syscall event occurred. | `2026-09-13T16:07:31.427406053Z` |
| `rule` | `keyword` | `falco` | Exact name of the triggered Falco security rule. | `Unexpected shell in KubeSentinel edge workload` |
| `priority` | `keyword` | `falco` | Falco alert priority level (`Emergency`, `Alert`, `Critical`, `Error`, `Warning`, `Notice`, `Informational`, `Debug`). | `Warning` |
| `severity` | `keyword` | `falco` | Mapped alert severity keyword. | `Warning` |
| `source` | `keyword` | `falco` | Event source engine (`syscall` or `k8s_audit`). | `syscall` |
| `tags` | `text` / `keyword` | `falco` | List of category, MITRE technique, and context tags associated with the rule. | `["T1059.004", "container", "kubesentinel", "mitre_execution"]` |
| `output` | `text` | `falco` | Human-readable formatted alert message rendered by Falco output format template. | `16:07:31.427406053: Warning Unexpected shell spawned in KubeSentinel edge container...` |
| `output_fields.proc_cmdline` | `text` (`.keyword`) | `falco` | Full process command line with all arguments. | `sh -c echo kubesentinel-sim-shell-c2d27254` |
| `output_fields.proc_name` | `text` (`.keyword`) | `falco` | Name of the process binary invoked (`comm`). | `sh` |
| `output_fields.proc_exepath` | `text` (`.keyword`) | `falco` | Full filesystem path to the executed binary. | `/bin/sh` |
| `output_fields.proc_pname` | `text` (`.keyword`) | `falco` | Name of the parent process. | `containerd-shim` |
| `output_fields.proc_tty` | `long` | `falco` | TTY number assigned to the process (0 if non-interactive). | `0` |
| `output_fields.user_uid` | `long` | `falco` | Operating system user ID executing the process (UID 10001 for non-root edge apps). | `10001` |
| `output_fields.user_name` | `text` (`.keyword`) | `falco` | Username resolved from `/etc/passwd` inside the container or `<NA>` if unmapped. | `<NA>` |
| `output_fields.user_loginuid` | `long` | `falco` | User login UID set by pam/audit subsystem (-1 if unset). | `-1` |
| `output_fields.container_id` | `text` (`.keyword`) | `falco` | 12-character container ID where the event originated. | `2e822ee84040` |
| `output_fields.container_name` | `text` (`.keyword`) | `falco` | Kubernetes container name. | `edge-api` |
| `output_fields.container_image_repository` | `text` (`.keyword`) | `falco` | Container image repository URI. | `docker.io/library/kubesentinel-edge-api` |
| `output_fields.container_image_tag` | `text` (`.keyword`) | `falco` | Container image tag. | `0.2.0` |
| `output_fields.k8s_ns_name` | `text` (`.keyword`) | `falco` | Target Kubernetes namespace where the pod runs. | `edge-pune` |
| `output_fields.k8s_pod_name` | `text` (`.keyword`) | `falco` | Target Kubernetes pod name. | `edge-api-7db6db7d68-ft6jq` |
| `output_fields.evt_type` | `text` (`.keyword`) | `falco` | Syscall event type (e.g. `execve`, `connect`, `openat`). | `execve` |
| `output_fields.evt_time` | `long` | `falco` | Monotonic nanosecond timestamp of the syscall. | `1789315651427406053` |
| `output_fields.fd_name` | `text` (`.keyword`) | `falco` | Socket connection string or file descriptor name. | `10.42.0.53:60012->10.43.0.1:443` |
| `output_fields.fd_lport` | `long` | `falco` | Local network socket port. | `60012` |
| `output_fields.fd_rport` | `long` | `falco` | Remote network socket port. | `443` |
| `output_fields.fd_type` | `text` (`.keyword`) | `falco` | File descriptor type (e.g. `ipv4`, `file`). | `ipv4` |
| `output_fields.fd_l4proto` | `text` (`.keyword`) | `falco` | Layer 4 protocol (`tcp`, `udp`). | `tcp` |
| `kubernetes.pod_name` | `text` (`.keyword`) | `fluent-bit` | Name of the pod emitting the log (Falco daemonset pod). | `falco-945s5` |
| `kubernetes.namespace_name` | `text` (`.keyword`) | `fluent-bit` | Namespace of the collector pod. | `security-agents` |
| `kubernetes.host` | `text` (`.keyword`) | `fluent-bit` | Kubernetes node hosting the pod. | `k3d-kubesentinel-server-0` |

---

## 3. `kubesentinel-app-*` Field Catalog

The `kubesentinel-app-*` index stores application security events emitted by edge workloads (`edge-api` via Redis Streams `security-events`), consumed and validated by `edge-worker`, and ingested as structured JSON by Fluent Bit.

| Field Path | Elasticsearch Type | Source Component | Description | Sample Value from Live Index |
| :--- | :--- | :--- | :--- | :--- |
| `@timestamp` | `date` | `fluent-bit` | Timestamp when Fluent Bit ingested the JSON record into Elasticsearch. | `2026-09-13T16:54:47.796Z` |
| `timestamp` | `date` | `edge-api` | Original event creation UTC RFC3339 timestamp generated by edge API. | `2026-09-13T16:54:47.622282Z` |
| `event_id` | `keyword` | `edge-api` | Unique UUID assigned to the security event. | `0f22ba13-8b57-498d-b1c0-537267441916` |
| `schema_version` | `keyword` | `edge-api` | Security event schema version contract (`1.0`). | `1.0` |
| `edge_site` | `keyword` | `edge-api` | Regional edge facility origin (`pune`, `mumbai`, `bangalore`). | `pune` |
| `namespace` | `keyword` | `edge-api` | Environment or cluster namespace label. | `local-compose` |
| `service` | `keyword` | `edge-api` | Originating edge service component. | `edge-api` |
| `event_type` | `keyword` | `edge-api` | Categorical classification of the event. | `security_simulation` |
| `severity` | `keyword` | `edge-api` | Normalized event severity (`critical`, `high`, `medium`, `low`, `info`). | `critical` |
| `source` | `keyword` | `edge-api` | Ingest identity or sensor identifier. | `telemetry-smoke-pune` |
| `destination` | `keyword` | `edge-api` | Target downstream consumer or SIEM destination. | `central-siem` |
| `message` | `text` | `edge-api` | Human-readable event description. | `Application telemetry proof event 782b2197...` |
| `log_type` | `keyword` | `edge-worker` | Operational log classification emitted by the worker. | `security_event_processed` |
| `processing_status` | `keyword` | `edge-worker` | Stream processing status (`success` or `error`). | `success` |
| `redis_stream_id` | `keyword` | `edge-worker` | Redis Stream message ID from `security-events`. | `1789318487723-0` |
| `worker` | `keyword` | `edge-worker` | Worker process identifier. | `central-edge-worker-1` |
| `processed_at` | `date` | `edge-worker` | UTC RFC3339 timestamp when worker executed `XACK`. | `2026-09-13T16:54:47.730196Z` |
| `metadata` | `object` (`dynamic`) | `edge-api` | Structured key-value object containing contextual event data. | `{"proof": "application_telemetry", "site": "pune", ...}` |
| `metadata.proof` | `text` (`.keyword`) | `edge-api` | Proof category tag inside metadata. | `application_telemetry` |
| `metadata.proof_id` | `text` (`.keyword`) | `edge-api` | Correlation ID for verification proofs. | `782b2197-56b7-45a7-b003-1945734ec0b3` |
| `metadata.site` | `text` (`.keyword`) | `edge-api` | Redundant site identifier inside metadata. | `pune` |
| `kubernetes.pod_name` | `text` (`.keyword`) | `fluent-bit` | Name of the pod emitting the worker log. | `edge-worker-7555fb84b7-d2pnj` |
| `kubernetes.namespace_name` | `text` (`.keyword`) | `fluent-bit` | Namespace of the worker pod. | `kubesentinel-system` |
| `kubernetes.container_name` | `text` (`.keyword`) | `fluent-bit` | Container name inside the pod. | `edge-worker` |

---

## 4. Query & Filter Recommendations

1. **Exact Matching on Text vs Keyword**:
   - Fields defined with both `text` and `keyword` subfields (e.g. `output_fields.k8s_ns_name` and `output_fields.k8s_ns_name.keyword`) should use the `.keyword` subfield when exact phrase or case-sensitive matching is required in Lucene:
     `output_fields.k8s_ns_name.keyword:("edge-pune" OR "edge-mumbai" OR "edge-bangalore")`
   - Explicit `keyword` type fields (e.g. `rule`, `priority`, `severity`, `log_type`, `processing_status`) can be matched directly:
     `rule:"Unexpected shell in KubeSentinel edge workload"`
2. **Date Range Filtering**:
   - Always use `@timestamp` for ingestion ordering or `time` / `timestamp` for event occurrence time:
     `@timestamp:[now-24h TO now]`
3. **Existence Queries**:
   - To distinguish parsed security events from raw web server access logs in `kubesentinel-app-*`, filter for `_exists_:event_id` or `log_type:security_event_processed`.

---

## 5. Telemetry Gap Analysis & Preventive Control Assessment

In accordance with strict integrity mandates, we conducted an empirical assessment of all 5 controlled simulation scenarios against live Elasticsearch data. A critical architectural finding is that **preventive security controls do not generate SIEM alerts unless a specialized audit forwarding pipeline is deployed**.

The table below honestly documents what is indexed versus what represents a telemetry gap:

| Scenario | Control Layer | Control Mechanism | Indexed in Elasticsearch? | Telemetry Gap Rationale & Root Cause |
| :--- | :--- | :--- | :--- | :--- |
| **Scenario 1**: Shell Execution in Edge Workload | **Detective** (Kernel Syscall) | Falco eBPF probe -> container stdout / CRI log -> Fluent Bit | **YES** (`kubesentinel-falco-*`) | Falco observes `execve` syscalls through its eBPF ring buffer and writes JSON for Fluent Bit to collect. Indexed with process and container context. |
| **Scenario 2**: Unauthorized Redis Access | **Preventive** (Network & Data Layer) | (A) NetworkPolicy TCP Drop<br>(B) Redis ACL Denial (`WRONGPASS`, `NOPERM`) | **NO** | 1. NetworkPolicy drops packets in Linux kernel netfilter/iptables without a packet drop logger (NFLOG/eBPF daemon).<br>2. Redis logs ACL rejections to memory/stdout, but Redis server logs are not parsed into structured events or forwarded to a dedicated security index. |
| **Scenario 3**: Kubernetes RBAC Denial | **Preventive** (API Server Authorization) | Kubernetes API Server returns HTTP 403 Forbidden | **NO** | k3s API server audit logging is disabled by default (`--audit-log-path` not configured). The 403 Forbidden response is returned synchronously to the caller; no audit log is sent to Fluent Bit or Elasticsearch. |
| **Scenario 4**: Insecure Deployment Admission | **Preventive** (Admission Controller Webhook) | Kyverno validating admission webhook rejects manifest | **NO** | Kyverno evaluates admission requests synchronously before etcd persistence. Rejected resources are never created. Kyverno webhook rejections are logged to controller stdout as transient debug logs, not indexed as security events. |
| **Scenario 5**: Cross-Namespace Lateral Access | **Preventive** (Network Layer) | NetworkPolicy egress/ingress default-deny | **NO** | Packets are silently dropped by the Flannel/iptables CNI layer at the network boundary. No network flow telemetry (e.g. NetFlow, Cilium Hubble) is configured to index dropped packets. |

### Defensive Architecture Takeaway: Prevention vs. Detection

1. **Detective Controls** (e.g. Falco, Application Error Handlers):
   - Allow execution to begin, observe behavior at runtime, and generate structured telemetry intended for SOC triage, threat hunting, and alerting in Elasticsearch.
2. **Preventive Controls** (e.g. NetworkPolicy, Kyverno, Kubernetes RBAC, Redis ACLs):
   - Invariant enforcement mechanisms that halt unauthorized actions at the cluster boundary or protocol layer before execution occurs.
   - **Do not invent or fabricate detections for preventive controls**: A search for "Kyverno rejection" or "NetworkPolicy block" in Elasticsearch will return 0 hits because no telemetry pipeline is ingesting those control planes. Documenting this gap defends architectural credibility during forensic review.

---

## 6. Defensible MITRE ATT&CK Mapping & Rule Classification

To maintain high forensic integrity and avoid threat-intel over-claiming, KubeSentinel's detection rules are categorized conservatively based on observable evidentiary telemetry:

| Rule ID | Index | ATT&CK Mapping | Operational Role | Defensibility Assessment |
| :--- | :--- | :--- | :--- | :--- |
| `kubesentinel-falco-unexpected-shell` | `kubesentinel-falco-*` | **Execution**: `T1059.004` (Unix Shell) | High-Fidelity Alert | **Direct Match**: Specifically alerts on `sh`/`bash` invocations within container workloads. Evidentiary proof is directly captured in `output_fields.proc_cmdline`. |
| `kubesentinel-falco-runtime-alerts-general` | `kubesentinel-falco-*` | None | Broad Hunt | Aggregates heterogeneous elevated-priority runtime alerts. A technique is assigned only after an analyst narrows the result to a specific Falco rule and behavior. |
| `kubesentinel-app-high-severity-event` | `kubesentinel-app-*` | None | Operational Triage | Monitors high/critical application events and stream-processing errors. Severity and processing state alone do not substantiate an exploit, denial of service, or other ATT&CK technique. |
