# KubeSentinel Kyverno Policy-as-Code Architecture

## Overview
KubeSentinel uses [Kyverno](https://kyverno.io/) for admission policy as code. Nine declarative `ClusterPolicy` objects validate workloads entering the application namespaces and reject configurations that violate the lab's hardening requirements.

## Installation & Infrastructure Architecture

- **Deployment Mechanism**: Official Helm chart `kyverno/kyverno`.
- **Pinned Versions**: Chart `3.9.1`, Application `v1.19.1`.
- **Namespace**: `kyverno` (dedicated third-party infrastructure namespace).
- **Resource Constraints**: Tailored for resource-conscious local laboratory environments via `helm/third-party/kyverno-values.yaml`:
  - Exactly 1 replica per controller workload (`admissionController`, `backgroundController`, `cleanupController`, `reportsController`).
  - Conservative CPU (10m–20m requests, 100m–200m limits) and memory (48Mi–96Mi requests, 128Mi–256Mi limits).
  - Total controller footprint under ~300Mi RAM.

### Third-Party Controller Security vs Application Workload Security
Kyverno controllers require broad cluster-level read/watch and webhook management privileges to function as a Kubernetes dynamic admission controller. The `kyverno` namespace is configured with standard cluster-level controller RBAC and `privileged` Pod Security Admission. In contrast, KubeSentinel application workloads continue to operate under `restricted` PSA and strict zero-privilege RBAC.

## Project Policies (9 Enforced Controls)

All project policies are located in `policies/kyverno/` and configured with `validationFailureAction: Enforce`. Each policy rule uses explicit namespace scoping (`edge-pune`, `edge-mumbai`, `edge-bangalore`, `kubesentinel-system`), ensuring system namespaces (`kube-system`, `kyverno`) remain unaffected:

1. **`disallow-privileged-containers`**: Rejects `securityContext.privileged: true` on ephemeral, init, and app containers.
2. **`require-run-as-non-root`**: Mandates `runAsNonRoot: true` at the pod or container security context.
3. **`disallow-privilege-escalation`**: Enforces `allowPrivilegeEscalation: false` across all containers.
4. **`require-drop-all-capabilities`**: Requires container `capabilities.drop` to include `ALL`.
5. **`require-runtime-default-seccomp`**: Requires `seccompProfile.type: RuntimeDefault` at pod or container scope.
6. **`require-resource-requests-limits`**: Requires explicit CPU and memory `requests` and `limits` on every container.
7. **`disallow-host-path`**: Prohibits mounting host filesystem paths (`volumes[*].hostPath`).
8. **`disallow-host-network`**: Rejects `hostNetwork: true`.
9. **`disallow-latest-tag`**: Disallows containers using `:latest` image tags, enforcing explicit release tags or digest pinning.

## Separation: Pod Security Admission (PSA) vs Kyverno

KubeSentinel implements defense-in-depth across admission layers:

| Layer | Implementation | Scope | Evaluated Controls |
|---|---|---|---|
| **Layer 1: Pod Security Standards (PSA)** | Native Kubernetes admission controller | Namespace labels (`restricted`) | Linux kernel isolation: root user, capabilities, host namespaces, seccomp |
| **Layer 2: Policy-as-Code (Kyverno)** | ValidatingAdmissionWebhook | `ClusterPolicy` objects | Image tag hygiene (`:latest` ban), resource requests/limits, duplicate defense-in-depth checks |

When both controls apply (e.g. `privileged: true`), Kubernetes PSA rejects the resource during initial standard admission evaluation. For policies outside PSA's domain (e.g., prohibiting `:latest` images and requiring CPU/memory limits), Kyverno acts as the authoritative rejecting controller via its dynamic webhook (`validate.kyverno.svc-fail`), providing distinct validation guarantees.
