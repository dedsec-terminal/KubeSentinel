# Security Policy

## 1. Scope & Purpose

KubeSentinel is a local Kubernetes security engineering and detection lab. It is designed for hands-on learning, policy evaluation, controlled security testing, and detection validation.

The lab intentionally includes controlled scenarios such as unexpected shell execution, unauthorized Redis access, RBAC denial, non-compliant deployment admission, and cross-namespace lateral movement.

All passwords, tokens, and cryptographic keys bundled in repository fixtures, test suites, and documentation (such as `.env.example`, `docker-compose.yml`, and testing certificates) are **strictly synthetic dummy credentials** for local container orchestration and integration testing.

---

## 2. Reporting Security Vulnerabilities

We take the security of this project seriously. If you discover a potential security vulnerability in KubeSentinel's application code, policies, or deployment templates, please report it responsibly.

### How to Report
- Use a [private GitHub security advisory](https://github.com/dedsec-terminal/KubeSentinel/security/advisories/new). Do not include sensitive vulnerability details in a public issue.
- **Include**:
  1. A description of the vulnerability and its potential impact.
  2. Step-by-step reproduction instructions or a minimal proof-of-concept (PoC).
  3. The specific component, file, or configuration affected.
  4. Any proposed remediation or patch.

Reports are reviewed on a best-effort basis. Confirmed fixes are tested against the relevant local validation path before disclosure.

Please do **NOT** disclose vulnerabilities publicly via GitHub Issues, Discussions, or social media until the maintainers have addressed the issue.

---

## 3. Secret & Credential Handling Policy

### Credential Handling
- KubeSentinel enforces a strict zero-credential-leak policy.
- Local runtime secrets (such as `.env.local`, live Redis ACL passwords, or Elasticsearch credentials generated dynamically) are gitignored and must never be committed to source control.
- The security workflow uses Trivy's repository scanning alongside explicit tracked-file checks to help detect accidental secret exposure.

### Reporting Accidental Secret Exposure
If you identify any real or potentially active credential committed to this repository:
1. Immediately submit a private GitHub security advisory.
2. Do not attempt to use or validate the exposed credential against external cloud services.
3. The maintainers will revoke/rotate the affected secret and purge it from Git history using `git filter-repo` or BFG Repo-Cleaner.

---

## 4. Implemented Security Controls & Defenses

KubeSentinel deploys defense-in-depth security controls across multiple layers:

| Layer | Control Mechanism | Operational Role |
| :--- | :--- | :--- |
| **Cluster Admission** | Kubernetes Pod Security Admission (PSA `restricted`) | Blocks non-compliant, privileged, or root containers from running in edge and system namespaces. |
| **Policy Engine** | Kyverno Admission Controller (`enforce` mode) | Blocks host access, privilege escalation, root execution, missing resource bounds, missing seccomp, retained capabilities, and mutable image tags. |
| **Network Isolation** | Kubernetes NetworkPolicy (default-deny) | Enforces strict east-west microsegmentation; prevents cross-namespace lateral movement between regional edge sites. |
| **Data Plane** | Redis ACL Least-Privilege Users | Restricts `edge-api` to `XADD` only and `edge-worker` to `XREADGROUP`/`XACK`; completely isolates administrative commands. |
| **Workload Hardening** | Hardened Multi-Stage Dockerfiles | Enforces non-root execution (UID 10001), read-only root filesystems, and drops all Linux capabilities (`cap_drop: ALL`). |
| **Runtime Detection** | Falco Modern eBPF Kernel Probe | Observes container syscalls and produces structured alerts, including the scoped unexpected-shell rule. |
| **Telemetry & SIEM** | Fluent Bit + Elasticsearch + Kibana | Centralized dual-index ingestion (`kubesentinel-app-*` and `kubesentinel-falco-*`) with automated detection rules and empirical tuning. |

---

## 5. Documented Security Exceptions & Limitations

To facilitate legitimate system observability and security monitoring, specific narrowly scoped exceptions are granted in the cluster:

1. **Falco DaemonSet (`security-agents` namespace)**:
   - Requires `privileged: true`, `hostPID: true`, and access to Linux kernel tracepoints/eBPF subsystems to intercept system calls cluster-wide.
   - The `security-agents` namespace is exempted from PSA `restricted` and labeled with `pod-security.kubernetes.io/enforce: privileged`.
2. **Fluent Bit DaemonSet (`observability` namespace)**:
   - Requires read-only access to node CRI logs under `/var/log/containers` and their backing pod-log paths so it can forward container output to Elasticsearch.
   - The `observability` namespace is labeled with `pod-security.kubernetes.io/enforce: baseline`.
3. **Kyverno Controllers (`kyverno` namespace)**:
   - The upstream controller namespace uses the `privileged` Pod Security profile so the pinned Helm release can operate without weakening application namespaces.
   - KubeSentinel application workloads remain subject to `restricted` Pod Security Admission and Kyverno enforcement.
4. **Local Lab Boundary**:
   - The local environment operates inside a single-node k3d container (`k3d-kubesentinel-server-0`).
   - Regional edge sites (`edge-pune`, `edge-mumbai`, `edge-bangalore`) are simulated as logically isolated Kubernetes namespaces rather than physically separated geographic edge devices.
