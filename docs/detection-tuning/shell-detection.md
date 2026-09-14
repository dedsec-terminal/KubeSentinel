# Empirical Detection Tuning Study: Unexpected Shell in KubeSentinel Edge Workload

## 1. Summary

Broad runtime rules often catch both suspicious behavior and routine diagnostics. This study shows how KubeSentinel narrows an unexpected-shell query using fields that exist in the lab's Falco telemetry.

The study compares a baseline query (**V1**) with a tuned query (**V2**) against controlled telemetry in `kubesentinel-falco-*`.

### Key Empirical Findings

- **Baseline Rule (V1)**: Evaluated 33 candidate events. It matched all 25 controlled shell events and all 8 benign diagnostic or maintenance candidates.
- **Tuned Rule (V2)**: Refined using workload scope criteria (`edge-api` container, non-root UID 10001, target regional edge namespaces `edge-pune`, `edge-mumbai`, `edge-bangalore`) and explicit exclusion of authorized maintenance/diagnostic command patterns (`*diag-maintenance*`, `*healthcheck*`).
- **Controlled Scenario Retention**: V2 retained **100.0% (25/25)** of controlled shell events.
- **Maintenance Candidate Suppression**: V2 suppressed **100.0% (8/8)** of controlled benign maintenance events.
- **Lab Triage Noise Reduction**: V2 suppressed all 8 maintenance candidates, producing a **24.24% reduction in candidate volume** without dropping a controlled event.

> **Defensible Terminology Note**: All metrics reported in this study represent observations derived strictly from controlled scenarios within the local KubeSentinel development/lab environment. These metrics evaluate *candidate events in lab telemetry*, *maintenance context candidate suppression*, *controlled scenario retention*, and *reduction in lab triage noise*. They do not constitute unverified claims of "enterprise production false-positive rates".

---

## 2. Threat Hypothesis & Detection Objective

### 2.1 Threat Actor Profile & Attack Technique

- **Adversary Objective**: Post-Exploitation Execution & Interactive Reconnaissance.
- **MITRE ATT&CK Mapping**:
  - **Tactic**: Execution (`TA0002`)
  - **Technique**: Command and Scripting Interpreter: Unix Shell (`T1059.004`)

### 2.2 Attack Scenario & Hypothesis

In a hardened edge environment, application microservices such as `edge-api` run Python under a restricted, non-root user (UID 10001) with a read-only root filesystem and dropped Linux capabilities (`CAP_DROP: ALL`).

Under standard operational conditions, the application container binary runs as PID 1 or under a supervisor process and never spawns an interactive shell or invokes shell script interpreters (`/bin/sh`, `/bin/bash`, `/bin/ash`, `/bin/zsh`).

If an adversary achieves Remote Code Execution (RCE) via an unauthenticated API endpoint, exploits an application dependency, or gains unauthorized access through a compromised cluster identity (`kubectl exec`), the initial post-exploitation activity almost universally involves spawning a shell to:
1. Probe local file permissions and environment variables for credentials.
2. Attempt lateral network access or Redis database exploitation.
3. Establish interactive command-and-control (C2) channels.

### 2.3 Detective Control Architecture

KubeSentinel implements an asynchronous detective control plane:
1. **Linux Kernel Syscall Interception**: The `falco` DaemonSet deployed in namespace `security-agents` utilizes the modern eBPF driver to monitor `execve` and `execveat` syscalls from the kernel ring buffer.
2. **Kubernetes Metadata Enrichment**: The eBPF probe associates syscalls with container runtime metadata (`container_id`, `container_name`, `k8s.pod.name`, `k8s.ns.name`, `user.uid`).
3. **Structured Event Shipping**: Falco emits structured JSON alerts to container stdout, which the node runtime records in CRI logs.
4. **DaemonSet Log Forwarding**: The `fluent-bit` DaemonSet in namespace `observability` parses the JSON payload, applies CRI and Kubernetes metadata filters, and forwards the document over HTTP to Elasticsearch.
5. **SIEM Indexing**: Telemetry is indexed in `kubesentinel-falco-*` under explicit mappings (defined in `detections/elastic/FIELDS.md`).

The detection objective is to alert high-priority SOC analysts to any shell execution inside edge workloads while avoiding alerts triggered by authorized maintenance or health checks.

---

## 3. Baseline Rule Definition (V1 Rule)

### 3.1 V1 Specification

The initial detection rule represents a broad, unconstrained signature designed to catch any shell activity flagged by the Falco engine across the cluster.

```lucene
rule:"Unexpected shell in KubeSentinel edge workload"
```

- **Target Index Pattern**: `kubesentinel-falco-*`
- **Query Language**: Lucene Query Syntax
- **Severity**: High
- **Scope**: All pods emitting the custom Falco rule `Unexpected shell in KubeSentinel edge workload`.

### 3.2 Live Execution against Elasticsearch

Executing V1 against live Elasticsearch data in `kubesentinel-falco-*`:

```json
{
  "query": {
    "query_string": {
      "query": "rule:\"Unexpected shell in KubeSentinel edge workload\""
    }
  }
}
```

- **HTTP Status**: `200 OK`
- **Candidate Events Matched**: **33 documents**
- **Controlled Scenarios Captured**: **25 documents** (100% of controlled shell events)
- **Benign Maintenance Events Captured**: **8 documents**

### 3.3 Deficiencies of the V1 Baseline Rule

1. **Absence of Workload Scope Filtering**: V1 relies solely on the Falco rule string. It does not enforce that the container is `edge-api`, nor does it verify that the process was executed by the application UID (`user_uid: 10001`).
2. **Zero Maintenance Exclusion Logic**: V1 contains no clause to distinguish between an unauthorized interactive shell and an authorized administrative diagnostic run or container health check script.
3. **Triage Burden**: Every legitimate maintenance command executed by an SRE or automated health monitoring system generates a high-severity alert, creating alert fatigue.

---

## 4. Controlled Benign Candidate Activity Formulation

### 4.1 Operational Context in Kubernetes Edge Environments

In production Kubernetes operations, platform engineers, SREs, and cluster monitoring agents routinely perform diagnostic verifications and health checks inside container pods:
- Inspecting network connectivity to regional gateway endpoints.
- Verifying container persistent storage mounts and ephemeral `/tmp` volume status.
- Running liveness and readiness diagnostic checks.
- Conducting memory and CPU utilization audits during maintenance windows.

When container images contain a shell utility (e.g. `/bin/sh`), diagnostic automation or manual triage commands frequently wrap one-shot inspection commands in `sh -c "<diagnostic-command>"`.

Under the V1 baseline rule, every one of these routine operations triggers a full security alert in Elasticsearch.

### 4.2 Controlled Benign Telemetry Generation

To empirically evaluate rule selectivity, we executed 8 distinct controlled benign maintenance and diagnostic commands across all three edge workload namespaces (`edge-pune`, `edge-mumbai`, `edge-bangalore`):

| Event ID / Document ID | Target Namespace | Target Pod / Container | Executed Command Line (`output_fields.proc_cmdline`) | Operational Context |
| :--- | :--- | :--- | :--- | :--- |
| `89TLm6ABBprAIohfPkf9` | `edge-pune` | `edge-api-...` / `edge-api` | `sh -c echo kubesentinel-diag-maintenance-netprobe-9fb2a4` | SRE network probe |
| `-NTLm6ABBprAIohfWkdA` | `edge-pune` | `edge-api-...` / `edge-api` | `sh -c echo kubesentinel-diag-maintenance-storage-check-e2b86a` | Ephemeral disk check |
| `ANTLm6ABBprAIohfdUiS` | `edge-pune` | `edge-api-...` / `edge-api` | `sh -c echo kubesentinel-healthcheck-probe-liveness-ff90fd` | Healthcheck liveness probe |
| `CdTLm6ABBprAIohflEjS` | `edge-mumbai` | `edge-api-...` / `edge-api` | `sh -c echo kubesentinel-diag-maintenance-cpu-audit-1a4cd2` | CPU audit routine |
| `DtTLm6ABBprAIohfsEgq` | `edge-mumbai` | `edge-api-...` / `edge-api` | `sh -c echo kubesentinel-healthcheck-probe-readiness-5c52ed` | Readiness probe check |
| `F9TLm6ABBprAIohfy0h_` | `edge-bangalore` | `edge-api-...` / `edge-api` | `sh -c echo kubesentinel-diag-maintenance-sync-verify-b715ec` | Edge sync verification |
| `H9TLm6ABBprAIohf6ki_` | `edge-bangalore` | `edge-api-...` / `edge-api` | `sh -c echo kubesentinel-healthcheck-probe-status-4aca03` | Node status healthcheck |
| `KdTMm6ABBprAIohfDUjp` | `edge-bangalore` | `edge-api-...` / `edge-api` | `sh -c echo kubesentinel-diag-maintenance-memory-audit-103405` | Memory audit routine |

### 4.3 Observation Under Baseline Rule (V1)

When querying Elasticsearch with V1:
- All 8 diagnostic and health check events triggered alerts.
- Alert priority is `Warning`; the current rule tags the behavior as `["T1059.004", "container", "kubesentinel", "mitre_execution"]`.
- The SOC analyst has no automated way under V1 to filter these routine operational events, creating substantial triage burden.

---

## 5. Tuned Rule Formulation (V2 Rule) & Field Rationale

### 5.1 V2 Specification

The V2 tuned rule refines detection criteria by enforcing strict namespace, container, and user boundaries, while adding an explicit exclusion pattern for authorized maintenance commands:

```lucene
rule:"Unexpected shell in KubeSentinel edge workload"
AND output_fields.k8s_ns_name.keyword:("edge-pune" OR "edge-mumbai" OR "edge-bangalore")
AND output_fields.container_name.keyword:"edge-api"
AND output_fields.user_uid:10001
AND NOT output_fields.proc_cmdline.keyword:(*diag-maintenance* OR *healthcheck*)
```

### 5.2 Field Rationale & Mapping Alignment

Each clause in V2 is grounded directly in the discovered fields cataloged in `detections/elastic/FIELDS.md`:

1. **`rule:"Unexpected shell in KubeSentinel edge workload"`**:
   - *Rationale*: Anchors the query directly to alerts generated by the custom Falco runtime rule, filtering out unrelated Falco rules (e.g. `Contact K8S API Server From Container`).
   - *Type*: `keyword`.

2. **`output_fields.k8s_ns_name.keyword:("edge-pune" OR "edge-mumbai" OR "edge-bangalore")`**:
   - *Rationale*: Restricts scope to authorized regional edge namespaces. Excludes cluster infrastructure namespaces (`kube-system`, `kyverno`, `observability`, `security-agents`).
   - *Tokenization Note*: The `.keyword` subfield is mandatory because standard analyzers treat the hyphen in `edge-pune` as a delimiter, splitting the token into `edge` and `pune`. The `.keyword` subfield guarantees exact string matching.

3. **`output_fields.container_name.keyword:"edge-api"`**:
   - *Rationale*: Targets the external-facing edge microservice container. Prevents false correlation with sidecars, logging containers, or infrastructure pods.
   - *Type*: `text` with `.keyword` subfield.

4. **`output_fields.user_uid:10001`**:
   - *Rationale*: KubeSentinel's hardened workloads enforce `runAsNonRoot: true` with non-root UID 10001 (`edge-api`). Any unexpected shell spawned within the workload container runs under this UID.
   - *Type*: `long`.

5. **`NOT output_fields.proc_cmdline.keyword:(*diag-maintenance* OR *healthcheck*)`**:
   - *Rationale*: Explicitly suppresses legitimate, authorized maintenance and health check commands matching approved naming conventions.
   - *Lucene tokenization detail*:
     In Elasticsearch mappings, `output_fields.proc_cmdline` is mapped as `text` with a `.keyword` subfield.
     - If queried against `output_fields.proc_cmdline` (the `text` field), the standard analyzer splits hyphens into discrete tokens: `[sh, c, echo, kubesentinel, diag, maintenance, netprobe]`. A wildcard expression `*diag-maintenance*` fails because `*` cannot match across token boundaries.
     - Querying `output_fields.proc_cmdline.keyword` evaluates the entire un-tokenized command string, allowing exact character-sequence wildcard evaluation (`*diag-maintenance*` and `*healthcheck*`).
     - Empirical testing verified that querying `.keyword` successfully matches and suppresses 100% (8/8) of the benign candidate events.

---

## 6. Empirical Comparative Evaluation & Metrics

### 6.1 Empirical Comparison Table

The comparative evaluation was executed against live Elasticsearch data in `kubesentinel-falco-2026.09.13`:

| Evaluation Metric | Baseline Rule (V1) | Tuned Rule (V2) | Tuning Delta / Operational Impact |
| :--- | :---: | :---: | :--- |
| **Lucene Query Syntax** | `rule:"Unexpected shell in..."` | Multi-field scoped with maintenance exclusion | Validated Lucene syntax, 0 parse errors |
| **Elasticsearch Query Execution** | `200 OK` (0 errors) | `200 OK` (0 errors) | Zero syntax or execution errors |
| **Total Candidate Events Evaluated** | 33 | 25 | -8 events (-24.24% volume reduction) |
| **Controlled Attack Scenarios Present** | 25 | 25 | Baseline controlled telemetry |
| **Controlled Scenarios Retained** | **25** | **25** | **100.0% retention** (zero controlled events missed) |
| **Controlled Scenario Retention Rate** | **100.0%** | **100.0%** | **0.0% regression in attack sensitivity** |
| **Benign Maintenance Events Present** | 8 | 8 | Baseline ground-truth benign telemetry |
| **Benign Events Flagged as Alerts** | **8** | **0** | **-8 false alarms eliminated** |
| **Benign Maintenance Suppression Rate** | **0.0%** | **100.0%** | **100.0% suppression of benign events** |
| **Lab Triage Noise Reduction** | Baseline (0.0%) | **100.0%** | **Eliminates 100% of lab maintenance noise** |
| **Overall Lab Volume Reduction** | Baseline (0.0%) | **24.24%** | Eight fewer candidate alerts |

### 6.2 Analysis of Retained Controlled Attack Scenarios

The final committed metrics artifact records 25 controlled shell events produced by the simulation and validation workflows. None matched the `*diag-maintenance*` or `*healthcheck*` exclusions, so V2 retained all 25. An earlier command capture under `docs/evidence/milestone-f/` records 23 events; the final metrics snapshot was written later in the validation sequence and is the value used in the published project record.

### 6.3 Analysis of Suppressed Benign Maintenance Scenarios

All 8 benign maintenance and diagnostic commands were suppressed by V2:
- 5 diagnostic commands matching `*diag-maintenance*` (`netprobe`, `storage-check`, `cpu-audit`, `sync-verify`, `memory-audit`).
- 3 health check commands matching `*healthcheck*` (`liveness`, `readiness`, `status`).

Under V1, each of these events produced an actionable alert requiring manual triage. Under V2, these 8 alerts were filtered out upstream, achieving **100% suppression of maintenance triage noise**.

---

## 7. Operational Guidance & Limitations in Non-Lab Environments

### 7.1 Evasion Risks of Substring Command-Line Whitelisting

While command-line exclusions (`NOT output_fields.proc_cmdline.keyword:(*diag-maintenance* OR *healthcheck*)`) provide immediate noise reduction in controlled environments, security teams must understand their inherent evasion risks:
1. **Adversary Mimicry**: An adversary with internal knowledge of SIEM exclusion patterns can append the exclusion string to a malicious command (e.g. `sh -c "cat /etc/shadow # diag-maintenance"` or naming an exploit script `/tmp/healthcheck.sh`).
2. **Defensive Countermeasures**:
   - **Parent Process Verification**: Rather than whitelisting based on command line alone, require that the parent process (`output_fields.proc_pname`) matches an approved orchestration agent or systemd supervisor, not an interactive shell or `containerd-shim` spawned via `kubectl exec`.
   - **Strict Pathing & Hash Enforcement**: If diagnostic scripts are executed, invoke compiled native binaries from read-only paths rather than arbitrary shell strings.
   - **Audit Correlation**: Correlate diagnostic events against Kubernetes API server audit logs to verify whether an authorized maintenance window or scheduled CronJob was active.

### 7.2 Stronger Image-Level Mitigation

The most robust architectural solution to unexpected shell execution is **eliminating the shell binary entirely from the container image**:
1. **Distroless & Scratch Images**: Migrating from minimal Linux base images (Debian, Alpine) to distroless images (e.g. `gcr.io/distroless/python3-debian12`) removes `/bin/sh`, `/bin/bash`, and all shell interpreters.
2. **Impact on Threat Modeling**: If no shell binary exists inside the container:
   - Syscall rule `proc.name in (sh, bash, ash, zsh)` becomes an absolute invariant; any attempt to invoke a shell fails at the OS layer (`No such file or directory`).
   - SRE diagnostic access must be conducted via ephemeral debug containers (`kubectl debug`) utilizing separate, dedicated diagnostic pods, isolating diagnostic telemetry from production workload monitoring.

### 7.3 Conclusion

The empirical tuning study demonstrates that grounding detection engineering in real telemetry fields, understanding analyzer tokenization (text vs keyword), and applying disciplined workload scoping transforms a noisy detection into a high-fidelity security signal. In the KubeSentinel lab environment, V2 achieved a **100.0% reduction in lab maintenance noise** while maintaining **100.0% controlled attack scenario retention**.
