# Milestone C: Technical Verification Matrix

This matrix documents the verification status for 48 technical checks covering the Kubernetes foundation and secure workload deployment.

| # | Category | Technical Check | Verification Method | Evidence File | Status |
|---|---|---|---|---|---|
| 1 | Cluster Lifecycle | k3d single-node cluster `kubesentinel` created successfully | `python scripts/kubesentinel.py cluster-create` | `cluster-info.txt` | PASS |
| 2 | Cluster Lifecycle | k3s image pinned to exact patch tag `rancher/k3s:v1.35.5-k3s1` | `kubectl version`, `crictl info` | `cluster-info.txt` | PASS |
| 3 | Cluster Lifecycle | Traefik ingress controller explicitly disabled (`--disable=traefik@server:0`) | `k8s-validate`, `kubectl get pods -n kube-system` | `cluster-info.txt` | PASS |
| 4 | Cluster Lifecycle | ServiceLB explicitly disabled (`--disable=servicelb@server:0`) | `kubectl get pods -n kube-system` | `cluster-info.txt` | PASS |
| 5 | Cluster Lifecycle | Metrics-server explicitly disabled (`--disable=metrics-server@server:0`) | `kubectl get pods -n kube-system` | `cluster-info.txt` | PASS |
| 6 | Cluster Lifecycle | CLI cluster lifecycle subcommands implemented (`cluster-create`, `cluster-start`, `cluster-stop`, `cluster-delete`) | `tests/validate/test_cli.py` | `tests.txt` | PASS |
| 7 | Namespaces & PSA | Namespace `kubesentinel-system` created with PSA `enforce: restricted` | `k8s-validate` | `k8s-validate.txt` | PASS |
| 8 | Namespaces & PSA | Namespace `edge-pune` created with PSA `enforce: restricted` | `k8s-validate` | `k8s-validate.txt` | PASS |
| 9 | Namespaces & PSA | Namespace `edge-mumbai` created with PSA `enforce: restricted` | `k8s-validate` | `k8s-validate.txt` | PASS |
| 10 | Namespaces & PSA | Namespace `edge-bangalore` created with PSA `enforce: restricted` | `k8s-validate` | `k8s-validate.txt` | PASS |
| 11 | Namespaces & PSA | Namespace `observability` created with PSA `enforce: baseline` | `k8s-validate` | `k8s-validate.txt` | PASS |
| 12 | Namespaces & PSA | All namespaces define matching `audit` and `warn` PSA labels | `k8s-validate` | `k8s-validate.txt` | PASS |
| 13 | RBAC Hardening | Dedicated ServiceAccount `edge-api-sa` in `edge-pune` with `automountServiceAccountToken: false` | `k8s-validate` | `rbac-validation.txt` | PASS |
| 14 | RBAC Hardening | Dedicated ServiceAccount `edge-api-sa` in `edge-mumbai` with `automountServiceAccountToken: false` | `k8s-validate` | `rbac-validation.txt` | PASS |
| 15 | RBAC Hardening | Dedicated ServiceAccount `edge-api-sa` in `edge-bangalore` with `automountServiceAccountToken: false` | `k8s-validate` | `rbac-validation.txt` | PASS |
| 16 | RBAC Hardening | Dedicated ServiceAccount `edge-worker-sa` in `kubesentinel-system` with `automountServiceAccountToken: false` | `k8s-validate` | `rbac-validation.txt` | PASS |
| 17 | RBAC Hardening | Dedicated ServiceAccount `redis-sa` in `kubesentinel-system` with `automountServiceAccountToken: false` | `k8s-validate` | `rbac-validation.txt` | PASS |
| 18 | RBAC Hardening | Zero cluster API permissions for workload ServiceAccounts (denied `list pods`, `get secrets`) | `kubectl auth can-i` via `k8s-validate` | `rbac-validation.txt` | PASS |
| 19 | PSA Negative Test | Disallowed negative fixture manifest `psa-negative-pod.yaml` created under `kubernetes/security/` | `tests/unit/test_k8s_manifests.py` | `tests.txt` | PASS |
| 20 | PSA Negative Test | Negative fixture specifies disallowed privileged security context & hostPID | `tests/unit/test_k8s_manifests.py` | `tests.txt` | PASS |
| 21 | PSA Negative Test | Admission controller rejects non-compliant pod upon dry-run server admission | `kubectl apply --dry-run=server` | `psa-negative.txt` | PASS |
| 22 | PSA Negative Test | Automated verification in `k8s-validate` asserts admission rejection | `python scripts/kubesentinel.py k8s-validate` | `k8s-validate.txt` | PASS |
| 23 | Central Redis | Central Redis deployed in `kubesentinel-system` with pinned image `redis:7.4.2-alpine` | `k8s-deploy` | `cluster-info.txt` | PASS |
| 24 | Central Redis | Redis ClusterIP Service created on port 6379 (`redis.kubesentinel-system.svc.cluster.local`) | `k8s-deploy` | `k8s-deploy.txt` | PASS |
| 25 | Central Redis | Redis port 6379 is internal-only; not exposed via NodePort or LoadBalancer | `k8s-validate` | `k8s-validate.txt` | PASS |
| 26 | Central Redis | Redis ACL Secret generated and mounted to `/etc/redis/users.acl` | `k8s-deploy` | `k8s-deploy.txt` | PASS |
| 27 | Central Redis | Default unrestricted Redis user is disabled (`user default off`) | `k8s-validate` | `k8s-validate.txt` | PASS |
| 28 | Central Redis | Producer and Consumer identities enforced with least privilege (producer denied XREADGROUP/CONFIG; consumer denied XADD) | `k8s-validate` | `k8s-validate.txt` | PASS |
| 29 | Redis Bootstrap | Dedicated bootstrap Job `redis-bootstrap` executes with `bootstrap` ACL credentials | `k8s-deploy` | `k8s-deploy.txt` | PASS |
| 30 | Redis Bootstrap | Bootstrap Job creates consumer group `edge-workers` idempotently (handling BUSYGROUP) | `kubectl logs job/redis-bootstrap` | `cluster-info.txt` | PASS |
| 31 | Redis Bootstrap | Bootstrap Job condition `Complete` verified before workload rollout | `k8s-deploy` | `k8s-deploy.txt` | PASS |
| 32 | Redis Bootstrap | Bootstrap credentials isolated to `kubesentinel-system` and not leaked to edge sites | `k8s-deploy`, `k8s-validate` | `k8s-deploy.txt` | PASS |
| 33 | Multi-Site edge-api | Deployments created across 3 distinct edge namespaces (`edge-pune`, `edge-mumbai`, `edge-bangalore`) | `k8s-deploy` | `k8s-deploy.txt` | PASS |
| 34 | Multi-Site edge-api | Edge APIs execute as non-root user 10001:10001 (`runAsNonRoot: true`) | `k8s-validate` | `k8s-validate.txt` | PASS |
| 35 | Multi-Site edge-api | Edge API pods enforce `readOnlyRootFilesystem: true` with writable `/tmp` emptyDir | `k8s-validate` | `k8s-validate.txt` | PASS |
| 36 | Multi-Site edge-api | Edge API drops ALL capabilities (`capabilities: { drop: ["ALL"] }`) and sets `allowPrivilegeEscalation: false` | `k8s-validate` | `k8s-validate.txt` | PASS |
| 37 | Multi-Site edge-api | Edge API pods apply `seccompProfile: { type: "RuntimeDefault" }` | `k8s-validate` | `k8s-validate.txt` | PASS |
| 38 | Multi-Site edge-api | Explicit CPU and memory resource requests (20m/48Mi) and limits (150m/128Mi) enforced | `k8s-validate` | `k8s-validate.txt` | PASS |
| 39 | Downward API | Downward API exposes `pod_name` (`metadata.name`), `node_name` (`spec.nodeName`), and `k8s_namespace` (`metadata.namespace`) | `tests/edge_api/test_downward_api.py` | `tests.txt` | PASS |
| 40 | Downward API | Server injects trusted `container_name: "edge-api"` constant into telemetry metadata | `tests/edge_api/test_downward_api.py` | `tests.txt` | PASS |
| 41 | Downward API | Graceful fallback preserved for local Docker Compose (omits k8s fields when absent) | `tests/edge_api/test_downward_api.py` | `tests.txt` | PASS |
| 42 | Central edge-worker | Central `edge-worker` deployed in `kubesentinel-system` consuming from central Redis Streams | `k8s-deploy` | `cluster-info.txt` | PASS |
| 43 | Central edge-worker | Worker processes stream events and emits structured single-line JSON records containing Downward API metadata | `k8s-smoke` | `k8s-smoke.txt` | PASS |
| 44 | Stream Lifecycle | Worker executes `XACK` strictly after processing; Redis PEL pending count is 0 | `k8s-smoke` | `k8s-smoke.txt` | PASS |
| 45 | CLI Orchestration | CLI subcommands `k8s-deploy`, `k8s-validate`, `k8s-smoke` implemented in `scripts/kubesentinel.py` | `tests/validate/test_cli.py` | `tests.txt` | PASS |
| 46 | Quality & Gates | 100% passing test suite across unit, integration, and manifest validation (189 passed) | `pytest -v` | `tests.txt` | PASS |
| 47 | Quality & Gates | Static analysis clean: Ruff (0 findings) and `compileall` (0 errors) | `ruff check .`, `compileall` | `lint.txt` | PASS |
| 48 | Security & Hygiene | Clean system diagnostics (`doctor`: 0 FAIL); zero committed secrets; `.env.local` verified in `.gitignore` | `scripts/kubesentinel.py doctor`, `git check-ignore` | `doctor.txt`, `git-status.txt` | PASS |
