# Project: KubeSentinel Milestone B
# Scope Document: D:\KubeSentinel\.agents\orchestrator_b\PROJECT.md

## Mission
Implement and locally validate the complete vertical application data path (`edge-api → authenticated Redis Streams → edge-worker → structured JSON output → XACK`) using Docker Compose, hardened containers, and least-privilege Redis ACLs before any Kubernetes deployment begins.

## Architecture
The application runs locally under Docker Compose on an internal bridge network (`kubesentinel-net`):
1. **Redis 7.4 Service**: Official pinned patch tag (e.g. `redis:7.4.2-alpine`), listening on internal port 6379 with protected mode. Zero host port exposure. Authenticated with strict ACLs (`users.acl`).
2. **Bootstrap Init Service**: Ephemeral container running as `bootstrap` user; idempotently creates consumer group `edge-workers` on stream `security-events` via `MKSTREAM`; exits 0.
3. **Edge-API Service**: FastAPI application running as non-root (10001:10001) with `read_only: true` rootfs, `cap_drop: ALL`. Exposes port 8000 to host.
   - `GET /health`: In-memory liveness probe (returns 200 OK).
   - `GET /ready`: Non-mutating readiness probe (executes `redis.ping()` using `producer` ACL identity).
   - `POST /events`: Ingests caller payload, injects trusted identity, authenticates as `producer`, executes `XADD` on stream `security-events`, returns 202 Accepted with correlation IDs.
4. **Edge-Worker Service**: Background stream consumer running as non-root (10001:10001) with `read_only: true` rootfs, `cap_drop: ALL`.
   - Authenticates as `consumer` ACL identity.
   - Joins consumer group `edge-workers`.
   - Blocks on `XREADGROUP`.
   - Validates event payload against canonical schema.
   - On success: emits unbuffered single-line JSON log to stdout and executes `XACK`.
   - On malformed payload: emits structured error log to stdout, does NOT acknowledge (`XACK` skipped), zero credential leak.
   - Signal handling: clean shutdown on `SIGTERM`/`SIGINT`, leaving unprocessed items pending/recoverable.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| F1 | Security Event Contract | JSON Schema Draft 2020-12 at `telemetry/schemas/security-event.schema.json` with version 1.0, UTC ISO8601, UUID, enums, null-only k8s fields | M1 | Spec §6, R1 |
| F2 | Valid/Invalid Fixtures | 5 valid and 12 invalid test fixtures under `telemetry/samples/` with automated pytest suite | M1 | Spec §7, R1 |
| F3 | Shared Models & Validation | `apps/common/src/edge_common` with Pydantic models (`SecurityEventCreate`, `SecurityEvent`), UTC stamping, UUID generation | M1 | Spec §8, R2 |
| F4 | Dependency & Pythonpath Setup | Pinned `redis==8.1.0`, `jsonschema==4.26.0` in `pyproject.toml` and `.venv`, configured search paths | M1 | Spec §8, R2 |
| F5 | Schema Drift Prevention | Automated pytest suite `tests/telemetry/test_schema_drift.py` verifying bidirectional parity | M1 | Spec §8, R2 |
| F6 | Redis Configuration & ACLs | `redis.conf` and `users.acl` template with least-privilege identities (`producer`, `consumer`, `bootstrap`), default user disabled | M2 | Spec §9-10, R3 |
| F7 | Secret Handling & Bootstrap CLI | `python scripts/kubesentinel.py bootstrap-local` generates `.env.local` and `users.acl`, protected by `.gitignore` | M2 | Spec §10, R3 |
| F8 | Zero Redis Host Port Exposure | Compose configuration ensuring Redis port 6379 is purely internal | M2 | Spec §9, R3 |
| F9 | ACL Least-Privilege Verification | Tests verifying producer denied XREADGROUP/admin, consumer denied XADD/admin, bad credentials rejected | M2 | Spec §10, R3 |
| F10 | Edge API `POST /events` | Validates input, injects trusted metadata, executes `XADD` to `security-events`, returns 202 Accepted | M3 | Spec §11, R4 |
| F11 | Edge API `GET /ready` & `GET /health` | Pure liveness on `/health`; non-mutating `PING` readiness via `producer` identity on `/ready` with safe 503 | M3 | Spec §11, R4, User Amend |
| F12 | Edge API Unit & Mock Tests | Updated route tests, validation tests, correlation response tests, error handling tests | M3 | Spec §11, R4 |
| F13 | Edge Worker Application | `apps/edge-worker/` package `edge_worker` (`src` layout) with consumer group consumption | M4 | Spec §12, R5 |
| F14 | Worker Structured JSON Logging | Single-line JSON log to stdout on success (`log_type`, `processing_status: success`, `redis_stream_id`, etc.) | M4 | Spec §12, R5 |
| F15 | Strict Ack-After-Processing | `XACK` executed strictly after successful processing and logging | M4 | Spec §12, R5 |
| F16 | Malformed Payload Handling | Error log emitted, stream ID included, `XACK` skipped, no credential leakage | M4 | Spec §12, R5 |
| F17 | Clean Signal Shutdown | Graceful `SIGTERM`/`SIGINT` handling, zero unhandled exceptions, unacknowledged events left pending | M4 | Spec §12, R5, User Amend |
| F18 | Hardened Multi-Stage Dockerfiles | `apps/edge-api/Dockerfile` and `apps/edge-worker/Dockerfile` with non-root 10001:10001 | M5 | Spec §13, R6 |
| F19 | Hardened Docker Compose | `docker-compose.yml` with `read_only: true`, `cap_drop: ALL`, `no-new-privileges: true`, `/tmp` tmpfs | M5 | Spec §13, R6 |
| F20 | Startup Dependency Ordering | Redis healthy -> bootstrap completes -> edge-api & edge-worker start independently | M5 | Spec §13, R6, User Amend |
| F21 | Canonical CLI Extensions | `kubesentinel.py` commands: `bootstrap-local`, `compose-up`, `compose-down`, `smoke` | M6 | Spec §14, R7 |
| F22 | Real Redis Integration Tests | Automated pytest suite exercising live containerized Redis with ACL authentication and stream operations | M6 | Spec §15, R7 |
| F23 | Local E2E Smoke Verification | Trace single event HTTP POST -> Redis Stream -> Worker -> JSON log -> verified XACK | M6 | Spec §14-15, R7 |
| F24 | Milestone B Evidence Collection | Complete sanitized logs in `docs/evidence/milestone-b/` (doctor, versions, tests, lint, compose, etc.) | M7 | Spec §15, R7 |
| F25 | Documentation Updates | Updated README.md, architecture.md, security-model.md, redis-security.md, environment.md | M7 | Spec §15, R7 |
| F26 | All 28 Exit Criteria Gate Pass | Independent verification of all 28 exit criteria against actual files and command execution | M7 | Spec §16, Exit Gate |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Event Contract, Schemas & Shared Models | F1, F2, F3, F4, F5 | none | DONE |
| M2 | Redis ACLs, Configuration & Local Bootstrap | F6, F7, F8, F9 | M1 | DONE |
| M3 | Edge API Event Ingest & Readiness Probe | F10, F11, F12 | M1, M2 | DONE |
| M4 | Edge Worker Consumer & Structured Logging | F13, F14, F15, F16, F17 | M1, M2 | DONE |
| M5 | Container Hardening & Docker Compose | F18, F19, F20 | M2, M3, M4 | DONE |
| M6 | Deterministic Integration Tests & CLI | F21, F22, F23 | M5 | DONE |
| M7 | Exit-Gate Audit, Evidence & Victory Verification | F24, F25, F26 | M6 | DONE |

## Interface Contracts
### Untrusted Caller ↔ Edge-API (`POST /events`)
- **Request Body**:
  ```json
  {
    "event_type": "string (3..64 chars, snake_case)",
    "severity": "info | low | medium | high | critical",
    "source": "string (1..256 chars)",
    "destination": "string (optional, max 256) | null",
    "message": "string (1..1024 chars)",
    "metadata": { "arbitrary": "object" }
  }
  ```
  Forbidden fields: `schema_version`, `timestamp`, `event_id`, `edge_site`, `namespace`, `service`, `pod`, `container`, `node` (rejected with 422 Unprocessable Entity).
- **Response**: HTTP 202 Accepted
  ```json
  {
    "status": "accepted",
    "event_id": "UUIDv4",
    "stream": "security-events",
    "stream_id": "string (e.g. 1789246370665-0)"
  }
  ```

### Edge-API ↔ Redis Streams (`security-events`)
- **Authentication**: `AUTH producer <password>`
- **Command**: `XADD security-events MAXLEN ~ 10000 * event <serialized_json_canonical_security_event>`
- **Permissions**: Allowed `+auth +ping +xadd` on `security-events`. Denied `xreadgroup`, admin.

### Edge-Worker ↔ Redis Streams (`security-events`)
- **Authentication**: `AUTH consumer <password>`
- **Command**: `XREADGROUP GROUP edge-workers <worker_id> BLOCK 2000 COUNT 10 STREAMS security-events >`
- **Acknowledgment**: `XACK security-events edge-workers <stream_id>`
- **Permissions**: Allowed `+auth +ping +xreadgroup +xack` on `security-events`. Denied `xadd`, admin.

### Bootstrap Service ↔ Redis
- **Authentication**: `AUTH bootstrap <password>`
- **Command**: `XGROUP CREATE security-events edge-workers $ MKSTREAM`
- **Permissions**: Allowed `+auth +ping +xgroup +xinfo` on `security-events`.

### Edge-Worker ↔ Stdout (Logging Contract)
- **Successful Processing**: Single-line unbuffered JSON record to stdout:
  ```json
  {
    "log_type": "security_event_processed",
    "processing_status": "success",
    "redis_stream_id": "1789246370665-0",
    "worker": "worker-1",
    "processed_at": "2026-09-13T02:20:00Z",
    "schema_version": "1.0",
    "event_id": "UUID",
    "edge_site": "pune",
    "namespace": "local-compose",
    "service": "edge-api",
    "event_type": "...",
    "severity": "...",
    "source": "...",
    "destination": null,
    "message": "...",
    "metadata": {}
  }
  ```
- **Malformed Event**: Single-line JSON error record to stdout (NO XACK):
  ```json
  {
    "log_type": "security_event_processing_error",
    "processing_status": "error",
    "redis_stream_id": "1789246370665-0",
    "worker": "worker-1",
    "processed_at": "2026-09-13T02:20:00Z",
    "error_type": "ValidationError",
    "error_detail": "...",
    "raw_payload_preview": "..."
  }
  ```

## Code Layout
- `telemetry/schemas/security-event.schema.json`: Canonical JSON Schema
- `telemetry/samples/valid/*.json`: Valid test fixtures
- `telemetry/samples/invalid/*.json`: Invalid test fixtures with failure rationales
- `apps/common/src/edge_common/`: Shared models, validation, serialization
- `apps/edge-api/src/edge_api/`: Edge API FastAPI service (`POST /events`, `GET /ready`)
- `apps/edge-worker/src/edge_worker/`: Edge worker consumer package
- `deploy/compose/`: Docker Compose deployment files and Redis configuration
  - `deploy/compose/redis/redis.conf`: Redis server config
  - `deploy/compose/redis/users.acl`: Generated ACL file (git-ignored)
- `docker-compose.yml`: Local multi-container orchestrator
- `scripts/kubesentinel.py`: Unified CLI (`bootstrap-local`, `compose-up`, `compose-down`, `smoke`)
- `tests/`: Deterministic unit and integration test suite
  - `tests/telemetry/`: Schema drift and fixture tests
  - `tests/edge_api/`: API route, validation, and readiness tests
  - `tests/edge_worker/`: Worker consumption, validation, logging, and ack tests
  - `tests/integration/`: Live Redis ACL and end-to-end stream integration tests
- `docs/evidence/milestone-b/`: Sanitized execution evidence files
