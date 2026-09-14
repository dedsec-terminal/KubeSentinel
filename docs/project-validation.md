# KubeSentinel Project Validation

**Validation date:** September 2026
**Status:** Public validation record
**License:** Apache-2.0
**Validated environment:** Windows 11, WSL2, Docker Desktop, and a single-node k3d cluster

## Summary

KubeSentinel is a local Kubernetes security lab with hardened edge services, authenticated Redis Streams, admission and network controls, centralized application and runtime telemetry, controlled security scenarios, and detection-engineering exercises.

The project is intended for repeatable local learning and testing. Running it locally avoids cloud-resource charges and trial limits. It is not a production reference architecture, and local results do not automatically generalize to multi-node or internet-facing environments.

## Included Capabilities

### Application and Event Pipeline

- Three logical edge namespaces (`edge-pune`, `edge-mumbai`, and `edge-bangalore`).
- FastAPI edge services publishing versioned events to `security-events` with Redis ACL authentication.
- A central `edge-worker` consumer group with validation, structured output, and `XACK` handling.
- Separate Redis producer, consumer, and bootstrap identities with the default user disabled.

### Kubernetes Security Controls

- Pod Security Admission profiles for application and infrastructure namespaces.
- Dedicated ServiceAccounts, disabled automatic token mounts, and a zero-permission RBAC baseline.
- Default-deny NetworkPolicies with explicit DNS, application, Redis, and observability flows.
- Nine Kyverno admission policies covering privileged settings, host access, root execution, resource bounds, seccomp, capabilities, and mutable image tags.
- Non-root containers with read-only root filesystems, dropped capabilities, seccomp, and explicit resource requests and limits.

### Observability and Runtime Detection

- Fluent Bit collection with Kubernetes metadata enrichment and separate application and Falco routes.
- Elasticsearch index templates and Kibana data views for `kubesentinel-app-*` and `kubesentinel-falco-*`.
- Falco `modern_ebpf` runtime monitoring in the isolated `security-agents` namespace.
- A documented privileged collector exception for Falco; application workloads remain under restricted policies.

### Detection Engineering

- Five controlled scenarios: shell execution, unauthorized Redis access, RBAC denial, insecure deployment rejection, and cross-edge lateral access.
- A scoped unexpected-shell rule mapped to MITRE ATT&CK `T1059.004`.
- Generic application-severity triage and broad Falco hunting content without unsupported single-technique mappings.
- A final controlled tuning snapshot of 33 candidates: 25/25 controlled shell events retained, 8/8 benign maintenance candidates suppressed, and a 24.24% reduction in candidate volume.

### Lifecycle and Supply Chain

- Canonical `setup`, `demo`, and `teardown` commands with PowerShell wrappers.
- GitHub Actions workflows for CI, security scanning, and reproducible SBOM generation.
- Ruff, pytest, compile checks, YAML validation, Helm validation, Hadolint, Trivy, and Checkov integration.
- CycloneDX and SPDX SBOM generation with SHA-256 metadata under the ignored `artifacts/sbom/` output directory.

## Recorded Local Validation

A complete local integration validation was executed once against the local lab:

| Check | Result |
| --- | ---: |
| Full pytest suite | 287/287 passed |
| CI-safe pytest suite | 265/265 passed; 22 deselected |
| Ruff / compileall | 0 findings / 0 errors |
| Environment doctor | 21 PASS, 2 WARN, 0 FAIL, 8 SKIP |
| Kubernetes baseline | 48/48 passed |
| NetworkPolicy validation | 32/32 passed |
| Kyverno admission validation | 19/19 passed |
| Observability validation | 11/11 passed |
| Falco runtime validation | 4/4 passed |
| Telemetry smoke test | Passed |
| Detection validation | 5/5 passed |
| Controlled simulations | 5/5 passed |
| Canonical demo | 8/8 steps passed in 56.09 seconds |

Additional unit coverage added afterward brings the current repository test count to 298. Sanitized command captures from earlier milestones remain under `docs/evidence/`; they are historical snapshots and may show smaller intermediate test or tuning datasets than the recorded validation run.

## Evidence Boundaries

- Shell execution is detected by Falco and indexed in Elasticsearch.
- Redis network and ACL failures, RBAC denial, Kyverno rejection, and lateral-access blocking are prevention results observed at their enforcement boundaries.
- The lab does not ingest Kubernetes audit logs, CNI flow/drop telemetry, Redis authentication rejection logs, or Kyverno PolicyReports into Elasticsearch.
- Detection and tuning figures come from controlled synthetic local data, not production traffic.

## Known Limitations

- The validated cluster has one k3d server node; edge locations are namespace-level simulations.
- Elasticsearch uses a resource-conscious single-node configuration without high availability or production retention guarantees.
- Falco needs host-level privileges for eBPF collection; the exception is scoped to `security-agents` and documented in scanner configuration.
- The validated platform is Windows 11 with WSL2 and Docker Desktop. Other platforms may work but were not part of the recorded validation.
- The lab uses local open-source components, so no cloud subscription or trial is required.

## Reproduce the Lab

```powershell
python scripts/kubesentinel.py setup
python scripts/kubesentinel.py demo
python scripts/kubesentinel.py teardown
```

See the [README](../README.md), [architecture](architecture.md), [security model](security-model.md), [demo guide](demo-guide.md), and [detection study](detection-tuning/shell-detection.md) for details.
