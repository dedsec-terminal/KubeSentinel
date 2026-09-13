# KubeSentinel Security Model & Implemented Controls (V1.0.0)

## 1. Executive Summary

KubeSentinel applies defense in depth across container build, Kubernetes admission, workload identity, network access, runtime monitoring, and telemetry processing. Each control has a defined boundary and a corresponding validation path:

1. **Cluster Admission**: Kubernetes Pod Security Admission (PSA `restricted`) paired with Kyverno policy-as-code admission controller (9 `ClusterPolicies` in `Enforce` mode).
2. **Network Isolation**: Native Kubernetes `NetworkPolicy` objects enforcing default-deny ingress/egress and east-west microsegmentation between regional edge sites.
3. **Identity & Access**: Zero-permission ServiceAccounts with token automount explicitly disabled (`automountServiceAccountToken: false`).
4. **Data Plane Access**: Least-privilege Redis 7.4.2 ACL identities (`producer`, `consumer`, `bootstrap`) over ClusterIP networking.
5. **Workload Hardening**: Multi-stage minimal container images running as non-root (UID `10001:10001`), immutable root filesystems (`readOnlyRootFilesystem: true`), dropped capabilities (`drop: ["ALL"]`), and `RuntimeDefault` seccomp profiles.
6. **Kernel Runtime Detection**: Falco 0.44.1 uses the `modern_ebpf` driver to observe system calls and alert on scoped process execution behavior.
7. **Telemetry Ingestion & SIEM**: Fluent Bit daemonset parsing structured JSON and routing logs into dedicated Elasticsearch indices (`kubesentinel-app-*` and `kubesentinel-falco-*`).
8. **Supply Chain & Delivery**: Pinned GitHub Actions CI workflows, container vulnerability scanning (Trivy), IaC scanning (Checkov), and CycloneDX/SPDX SBOM generation.

---

## 2. Pod Security Admission (PSA) Matrix

Kubernetes Pod Security Admission is evaluated dynamically by the Kubernetes API server across all seven cluster namespaces:

| Namespace | PSA Mode | Assigned Level | Security Controls Enforced | Privileged Exceptions |
| :--- | :--- | :--- | :--- | :--- |
| `edge-pune` | enforce, audit, warn | **restricted** | Non-root, drop ALL caps, read-only rootfs, RuntimeDefault seccomp, no host namespaces | None |
| `edge-mumbai` | enforce, audit, warn | **restricted** | Non-root, drop ALL caps, read-only rootfs, RuntimeDefault seccomp, no host namespaces | None |
| `edge-bangalore` | enforce, audit, warn | **restricted** | Non-root, drop ALL caps, read-only rootfs, RuntimeDefault seccomp, no host namespaces | None |
| `kubesentinel-system` | enforce, audit, warn | **restricted** | Non-root, drop ALL caps, read-only rootfs, RuntimeDefault seccomp, no host namespaces | None |
| `observability` | enforce, audit, warn | **baseline** | Prevents known privilege escalations; permits host volume mounts for log shipping | None |
| `kyverno` | enforce, audit, warn | **privileged** | Admission controller webhook infrastructure | Webhook registration |
| `security-agents` | enforce, audit, warn | **privileged** | Explicit exception: Falco kernel eBPF tracepoint attachment | **Documented Exception**: `hostPID: true`, `privileged: true`, eBPF subsystem access |

---

## 3. Network Microsegmentation (NetworkPolicies)

Packet filtering is enforced by the CNI network policy engine with declarative rules:

```mermaid
flowchart TD
    DNS["CoreDNS (kube-system:53 UDP/TCP)"]
    Pune["edge-pune (edge-api)"]
    Mumbai["edge-mumbai (edge-api)"]
    Bangalore["edge-bangalore (edge-api)"]
    Redis["kubesentinel-system (redis:6379)"]
    Worker["kubesentinel-system (edge-worker)"]
    Obs["observability (unauthorized)"]

    Pune -.->|UDP/TCP 53 Allowed| DNS
    Mumbai -.->|UDP/TCP 53 Allowed| DNS
    Bangalore -.->|UDP/TCP 53 Allowed| DNS
    Worker -.->|UDP/TCP 53 Allowed| DNS

    Pune -->|TCP 6379 Allowed (producer)| Redis
    Mumbai -->|TCP 6379 Allowed (producer)| Redis
    Bangalore -->|TCP 6379 Allowed (producer)| Redis
    Worker -->|TCP 6379 Allowed (consumer)| Redis

    Pune -.->|TCP 8000 blocked| Mumbai
    Mumbai -.->|TCP 8000 blocked| Bangalore
    Obs -.->|TCP 6379 blocked| Redis
```

1. **Default-Deny Ingress and Egress**: All edge namespaces and the system namespace block all incoming and outgoing connections by default (`kubernetes/network/default-deny.yaml`).
2. **Narrowly Scoped DNS Resolution**: Workloads are permitted outbound egress strictly to CoreDNS pods in `kube-system` on port 53 (`kubernetes/network/allow-dns.yaml`).
3. **Authorized Redis Access**: Only `edge-api` pods in edge namespaces and `edge-worker`/`redis-bootstrap` pods in `kubesentinel-system` are allowed ingress to Redis on TCP 6379. All other cluster pods (including `observability`) are dropped.
4. **Cross-Edge Isolation**: Traffic attempting to traverse between edge sites (e.g. Pune attempting to call Mumbai on port 8000) is dropped by both source egress and destination ingress policies.

---

## 4. Policy-as-Code Admission Enforcement (Kyverno)

Kyverno chart 3.9.1 (application v1.19.1) runs with nine declarative `ClusterPolicy` definitions in `Enforce` mode:

| # | Policy Name | Enforcement Target | Rule Objective |
| :--- | :--- | :--- | :--- |
| 1 | `disallow-privileged-containers` | Container `securityContext` | Prohibits `privileged: true` |
| 2 | `require-run-as-non-root` | Pod & Container `securityContext` | Requires `runAsNonRoot: true` |
| 3 | `disallow-privilege-escalation` | Container `securityContext` | Blocks `allowPrivilegeEscalation: true` |
| 4 | `require-drop-all-capabilities` | Container `securityContext.capabilities` | Mandates `drop: ["ALL"]` |
| 5 | `require-runtime-default-seccomp` | Pod / Container `seccompProfile` | Requires `RuntimeDefault` |
| 6 | `require-resource-requests-limits` | Container `resources` | Requires explicit CPU and memory requests and limits |
| 7 | `disallow-host-path` | Pod `volumes` | Disallows `hostPath` volume mounts |
| 8 | `disallow-host-network` | Pod `spec` | Disallows `hostNetwork: true` |
| 9 | `disallow-latest-tag` | Container `image` | Rejects mutable `:latest` tags or missing tags |

---

## 5. Workload Identity & RBAC Hardening

Application ServiceAccounts follow strict least-privilege standards:
- **Token Automounting Disabled**: `automountServiceAccountToken: false` is configured on `edge-api-sa`, `edge-worker-sa`, and `redis-sa`, preventing secret token exfiltration from `/var/run/secrets/kubernetes.io/serviceaccount/token`.
- **Zero API Permissions**: No Roles or ClusterRoles are bound to application ServiceAccounts. When evaluated via `kubectl auth can-i`, calls to list pods or retrieve secrets return `no` (HTTP 403 Forbidden).

---

## 6. Container Hardening Invariants

All application containers (`edge-api`, `edge-worker`) enforce the following security invariants in their deployment manifests:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  runAsGroup: 10001
  fsGroup: 10001
  seccompProfile:
    type: RuntimeDefault
containers:
  - name: edge-api
    image: edge-api:1.0.0
    securityContext:
      runAsNonRoot: true
      runAsUser: 10001
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
      seccompProfile:
        type: RuntimeDefault
    resources:
      requests:
        cpu: "20m"
        memory: "48Mi"
      limits:
        cpu: "150m"
        memory: "128Mi"
```

---

## 7. Data Plane Redis ACL Security

Redis enforces least-privilege command access via native ACL configurations:

| User Identity | Permitted Commands & Keys | Intended Microservice | Denied Operations |
| :--- | :--- | :--- | :--- |
| **`default`** | `off` | None (Disabled) | All commands disabled |
| **`producer`** | `+auth +ping +xadd ~security-events` | `edge-api` | Denied `XREADGROUP`, `GET`, `SET`, `CONFIG`, admin |
| **`consumer`** | `+auth +ping +xreadgroup +xack ~security-events` | `edge-worker` | Denied `XADD`, `SET`, `CONFIG`, admin |
| **`bootstrap`** | `+auth +ping +xgroup +xinfo +xpending ~security-events` | `redis-bootstrap` | Used solely by ephemeral bootstrap Job |

---

## 8. Runtime Threat Detection (Falco Modern eBPF)

- **Probe Mechanism**: Falco 0.44+ with `modern_ebpf` engine attached to kernel tracepoints (`sys_enter`, `sys_exit`).
- **Detection Scope**: Monitors container syscall activity cluster-wide, alerting on unexpected shell spawns (`/bin/sh`, `/bin/bash`), sensitive file probes, or suspicious process trees.
- **Forensic Context**: Emits structured JSON alerts capturing container name, pod name, namespace, process command line, and user UID.
- **SIEM Shipping**: Fluent Bit forwards alerts to `kubesentinel-falco-*` in Elasticsearch.

---

## 9. Supply Chain & CI/CD Security Controls

- **Fast CI Workflow**: Least privilege (`contents: read`), pinned action commit SHAs with version comments, zero `pull_request_target`.
- **Static Security Scanning**: Automated Trivy vulnerability scanning (filesystem, IaC, images) and Checkov configuration scanning. Enforces 0 fixable `HIGH` and `CRITICAL` findings in project code.
- **Software Bill of Materials (SBOM)**: Generation of CycloneDX and SPDX JSON SBOMs with SHA-256 integrity checksums for all application images.
- **Secret Hygiene**: Strict zero-leak guarantee; live credentials and runtime environment files are gitignored.

---

## 10. Honest Disclosures & Architectural Boundaries

1. **Prevention vs. Detection Telemetry Gap**:
   - Preventative controls (NetworkPolicy, Kyverno, Kubernetes RBAC, Redis ACLs) block unauthorized actions at the kernel or API boundary.
   - Standard Kubernetes does not emit Elasticsearch documents for dropped packets or 403 Forbidden responses. KubeSentinel does not create fake detection rules for unindexed preventive events.
2. **Privileged Collector Exception**:
   - Falco requires host privileges (`hostPID: true`, eBPF access) in `security-agents` to trace kernel syscalls. This exception is scoped strictly to `security-agents` and documented in security scanner configurations.
3. **Local Single-Node Lab**:
   - The entire architecture runs inside a single-node k3d cluster (`k3d-kubesentinel-server-0`), simulating regional edge sites as isolated namespaces.
