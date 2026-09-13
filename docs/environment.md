# Environment & Prerequisites — KubeSentinel

## 1. Observed Environment Baseline (Milestone B)

The local development environment has been validated and verified via `python scripts/kubesentinel.py doctor`:

- **Operating System**: Microsoft Windows 11 Home Single Language (Build 26200), PowerShell 7.6.1.
- **WSL2 Runtime**: Kernel 6.18.33.1-microsoft-standard-WSL2, Default Distribution Ubuntu-24.04, `networkingMode=Mirrored`, `hostAddressLoopback=true`.
- **Docker Desktop**: Version 4.90.0 (Engine 29.7.2), Context `desktop-linux`, containerd snapshotter active, allocated 6 CPUs and 5.79 GiB memory.
- **Python**: 3.14.2 in isolated repository virtual environment (`.venv`).
- **Git**: 2.47.1.windows.2.
- **kubectl**: v1.36.1 (client present).
- **k3d**: v5.9.0 (installed via Scoop; cluster creation strictly deferred beyond Milestone B).

---

## 2. Installed Software & Dependencies

### Python Virtual Environment (`.venv`)
The project utilizes Python 3.14.2 with dependencies pinned in `pyproject.toml`:
- `fastapi==0.141.1` — Async REST API framework.
- `uvicorn==0.52.4` — High-performance ASGI web server.
- `redis==8.1.0` — Official Python Redis client library supporting Redis Streams and ACLs.
- `jsonschema==4.26.0` — JSON Schema Draft 2020-12 validation suite.
- `pydantic==2.13.5` — Data validation and settings management.
- `pytest==9.1.1` — Testing framework for unit and integration suites.
- `httpx==0.28.1` — Async HTTP client for test probes and smoke tests.
- `ruff==0.16.7` — High-speed Python linter and code formatter.

### Container Images
- `redis:7.4.2-alpine` (official verified patch tag, digest: `sha256:02419de7eddf55aa5bcf49efb74e88fa8d931b4d77c07eff8a6b2144472b6952`).
- `python:3.11-slim` (minimal hardened base for multi-stage application builds).

---

## 3. Network & Port Allocations

| Port | Service | Scope | Host Address | Access Policy |
| :--- | :--- | :--- | :--- | :--- |
| **8000** | `edge-api` | Public Ingestion | `127.0.0.1:8000` | Mapped via Compose ingress |
| **6379** | `redis` | Internal Bridge | `redis:6379` | **Unmapped to host** (Least-privilege network isolation) |
| **6443** | Kubernetes API | Deferred (Milestone C) | N/A | Reserved |
| **9200** | Elasticsearch | Deferred (Milestone E) | N/A | Reserved |
| **5601** | Kibana | Deferred (Milestone E) | N/A | Reserved |

---

## 4. Docker Compose Environment Setup

The local multi-container stack is orchestrated via `docker-compose.yml` on internal bridge network `kubesentinel-net`:

### Service Inventory
1. **`redis`**:
   - Runs `redis:7.4.2-alpine` as unprivileged user `999:1000`.
   - Mounts `redis.conf` and generated `users.acl` as read-only volumes.
   - Root filesystem is `read_only: true` with isolated `16MB` tmpfs on `/tmp`.
   - Healthcheck monitors connection using `producer` ACL identity.
2. **`redis-bootstrap`**:
   - Ephemeral one-shot container running as unprivileged user `999:1000`.
   - Runs after `redis` is healthy; creates consumer group `edge-workers` via `MKSTREAM`.
   - Exits with status 0 upon completion.
3. **`edge-api`**:
   - Runs `apps/edge-api/Dockerfile` as non-root user `10001:10001`.
   - Depends on `redis` (healthy) and `redis-bootstrap` (completed successfully).
   - Root filesystem `read_only: true` with isolated `64MB` tmpfs on `/tmp`.
   - Exposes port 8000 to host.
4. **`edge-worker`**:
   - Runs `apps/edge-worker/Dockerfile` as non-root user `10001:10001`.
   - Depends on `redis` (healthy) and `redis-bootstrap` (completed successfully).
   - Root filesystem `read_only: true` with isolated `64MB` tmpfs on `/tmp`.
   - Consumes stream entries and emits single-line JSON logs to stdout.

---

## 5. Canonical CLI Usage

All local development, stack lifecycle, and verification tasks are executed via `scripts/kubesentinel.py`:

```powershell
# 1. Inspect host environment readiness
.\.venv\Scripts\python.exe scripts/kubesentinel.py doctor
# Optional JSON output:
.\.venv\Scripts\python.exe scripts/kubesentinel.py doctor --json

# 2. Bootstrap local secrets and Redis ACLs (generates .env.local and users.acl)
.\.venv\Scripts\python.exe scripts/kubesentinel.py bootstrap-local
# Force overwrite existing credentials:
.\.venv\Scripts\python.exe scripts/kubesentinel.py bootstrap-local --force

# 3. Launch Docker Compose stack in detached mode (polls until ready)
.\.venv\Scripts\python.exe scripts/kubesentinel.py compose-up
# Rebuild images during launch:
.\.venv\Scripts\python.exe scripts/kubesentinel.py compose-up --build

# 4. Execute deterministic end-to-end smoke verification
.\.venv\Scripts\python.exe scripts/kubesentinel.py smoke

# 5. Stop and tear down Docker Compose stack (removes containers and volumes)
.\.venv\Scripts\python.exe scripts/kubesentinel.py compose-down

# 6. Run lint and code style checks
.\.venv\Scripts\python.exe scripts/kubesentinel.py lint

# 7. Run automated unit and integration tests (177 tests)
.\.venv\Scripts\python.exe scripts/kubesentinel.py test
```
