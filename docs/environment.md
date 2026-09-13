# Environment & Prerequisites — KubeSentinel

## 1. Validated Environment Baseline

The development and execution environment is verified via `python scripts/kubesentinel.py doctor`:

- **Operating System**: Microsoft Windows 11 Home Single Language (Build 26200), PowerShell 7.6.1.
- **WSL2 Runtime**: Kernel 6.18.33.1-microsoft-standard-WSL2, Ubuntu-24.04, `networkingMode=Mirrored`, `hostAddressLoopback=true`.
- **Docker Desktop**: Version 4.90.0 (Engine 29.7.2), Context `desktop-linux`, allocated 6 CPUs and 5.79 GiB memory.
- **Python**: 3.14.2 in isolated repository virtual environment (`.venv`).
- **Git**: 2.47.1.windows.2.
- **kubectl**: v1.36.1.
- **k3d**: v5.9.0.
- **k3s Cluster**: Single-node k3d cluster `kubesentinel` running pinned `rancher/k3s:v1.35.5-k3s1`.

---

## 2. Kubernetes Cluster Specification

To operate within host RAM constraints (~2.6 GiB free host memory tier), the k3d cluster is configured with minimal overhead:

- **Cluster Name**: `kubesentinel`
- **Node Count**: 1 control-plane server node (`k3d-kubesentinel-server-0`), 0 agent nodes.
- **Pinned k3s Image**: `rancher/k3s:v1.35.5-k3s1`.
- **Disabled Default Controllers**:
  - Traefik ingress controller (`--disable=traefik@server:0`)
  - ServiceLB / Klipper LB (`--disable=servicelb@server:0`)
  - Metrics Server (`--disable=metrics-server@server:0`)
- **Container Runtime**: containerd (bundled inside k3s node container).
- **Core DNS**: CoreDNS running with lightweight resource footprint.

---

## 3. Workload Sizing & Resource Allocations

All deployments enforce conservative resource requests and limits:

| Workload | Namespace | Replicas | CPU Request | CPU Limit | Memory Request | Memory Limit |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `redis` | `kubesentinel-system` | 1 | 20m | 100m | 32Mi | 128Mi |
| `edge-worker` | `kubesentinel-system` | 1 | 20m | 150m | 48Mi | 128Mi |
| `edge-api` | `edge-pune` | 1 | 20m | 150m | 48Mi | 128Mi |
| `edge-api` | `edge-mumbai` | 1 | 20m | 150m | 48Mi | 128Mi |
| `edge-api` | `edge-bangalore` | 1 | 20m | 150m | 48Mi | 128Mi |

---

## 4. Container Images

- `rancher/k3s:v1.35.5-k3s1` — Pinned Kubernetes cluster image.
- `redis:7.4.2-alpine` — Pinned patch version for Central Redis.
- `kubesentinel-edge-api:0.2.0` — Multi-stage hardened build (non-root UID 10001).
- `kubesentinel-edge-worker:0.2.0` — Multi-stage hardened build (non-root UID 10001).

---

## 5. Kubernetes CLI Orchestration

All cluster and deployment tasks are automated via `scripts/kubesentinel.py`:

```powershell
# 1. Inspect environment readiness
.\.venv\Scripts\python.exe scripts/kubesentinel.py doctor

# 2. Cluster lifecycle
.\.venv\Scripts\python.exe scripts/kubesentinel.py cluster-create
.\.venv\Scripts\python.exe scripts/kubesentinel.py cluster-start
.\.venv\Scripts\python.exe scripts/kubesentinel.py cluster-stop
.\.venv\Scripts\python.exe scripts/kubesentinel.py cluster-delete

# 3. Kubernetes deployment
.\.venv\Scripts\python.exe scripts/kubesentinel.py k8s-deploy

# 4. Security & compliance validation
.\.venv\Scripts\python.exe scripts/kubesentinel.py k8s-validate

# 5. Multi-site end-to-end smoke verification
.\.venv\Scripts\python.exe scripts/kubesentinel.py k8s-smoke
```
