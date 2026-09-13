# Original User Request

## Initial Request — 2026-09-12T20:48:28Z

# Teamwork Project Prompt — Draft

> Status: Launched  
> Goal: Craft prompt → get user approval → delegate to teamwork_preview  
> Requested team: Use the multi-agent team to separate responsibilities where useful, for example: implementation; Redis/security review; test/integration verification; final exit-gate audit (Success Auditor). Avoid multiple agents concurrently editing the same files unless the orchestrator has an explicit conflict-safe reason. At the end, the Success Auditor must verify every Milestone B exit-gate item against actual files and command results before declaring PASS.

KubeSentinel Milestone B implements and locally validates the complete vertical application data path (`edge-api → authenticated Redis Streams → edge-worker → structured JSON output → XACK`) using Docker Compose, hardened containers, and least-privilege Redis ACLs before any Kubernetes deployment begins.

Working directory: D:\KubeSentinel  
Integrity mode: development

---

## Team Directive & Execution Rules

Use the multi-agent team to separate responsibilities:
- **Implementation Team**: Build event contract, shared models, Redis ACLs/bootstrap, `edge-api`, `edge-worker`, Dockerfiles, and `docker-compose.yml`.
- **Redis & Security Reviewer**: Independently challenge Redis ACL least privilege, credential generation, secret isolation (`.gitignore`), Docker container hardening (non-root, read-only rootfs, drop capabilities), and ensure zero Redis host port exposure.
- **Test & Integration Team**: Validate deterministic unit tests, JSON Schema drift tests, real Redis integration tests against containerized Redis, consumer group acknowledgment semantics (`XACK`), malformed payload rejection, and local end-to-end smoke verification.
- **Success Auditor**: Perform the final exit-gate audit, independently validating all 28 exit criteria against actual files and command execution results before declaring PASS.

**Guardrails**:
- Work strictly inside `D:\KubeSentinel`. Do not clone, move, or duplicate the repository.
- Milestone A baseline must remain functional and unmodified unless explicitly extended.
- Do NOT create a Kubernetes cluster, install Helm, or deploy Elastic/Kibana/Fluent Bit/Falco/Kyverno.
- Do NOT replace real integration tests with mocks.
- Avoid multiple agents concurrently editing the same files.

---

## Requirements

### R1. Security Event Contract & Fixtures
- Define versioned primary schema at `telemetry/schemas/security-event.schema.json` using a modern, supported JSON Schema draft.
- Include core fields: `schema_version` ("1.0"), `timestamp` (UTC RFC3339/ISO-8601 with tz), `event_id` (UUID), `edge_site` (`pune`, `mumbai`, `bangalore`), `namespace` (truthful local Compose value, e.g. `local-compose`), `service` (`edge-api`), `event_type`, `severity` (`info`, `low`, `medium`, `high`, `critical`), `source`, optional/nullable `destination`, `message`, and structured object `metadata`. Optional Kubernetes fields (`pod`, `container`, `node`) must remain omitted or null (no fake Kubernetes data).
- Provide meaningful valid and invalid test fixtures under `telemetry/samples/valid/` and `telemetry/samples/invalid/` with automated validation tests and explicit failure rationales.

### R2. Shared Event Serialization & Validation Logic
- Implement shared Python logic (e.g. `apps/common` or minimal shared package) for event modeling (Pydantic), validation, serialization, UTC timestamping, and UUID generation without monorepo over-engineering.
- Pin official Python Redis client and any required schema validation dependency compatible with Python 3.14.2 inside `.venv`.
- Enforce schema drift prevention between Pydantic models and committed JSON Schema.

### R3. Authenticated Redis Streams & ACL Security
- Deploy an official, pinned Redis container image (e.g. `redis:7.4-alpine` or similar stable release; no `redis:latest`).
- Configure Redis Streams (stream key: `security-events`) with bounded retention (approximate `MAXLEN ~10000`).
- Enforce strict Redis ACL authentication with least-privilege identities:
  - `producer` (`edge-api`): permitted only authentication, ping, and `XADD` to `security-events`. No read access, no admin.
  - `consumer` (`edge-worker`): permitted only authentication, ping, `XREADGROUP`, and `XACK`. No `XADD`, no admin.
  - `bootstrap/admin`: used strictly by an idempotent setup step to create the consumer group (`edge-workers` via `MKSTREAM`). Never used at runtime.
- Redis must not be published to the host by default in Docker Compose; application containers communicate via the internal Compose bridge network.
- Secure local secrets via `.env.example` and generated `.env.local` / ACL files protected by `.gitignore`. Provide canonical CLI bootstrap (`python scripts/kubesentinel.py bootstrap-local`).

### R4. Edge-API `POST /events` & Real Readiness Probe
- Preserve `GET /health` as pure liveness (does not fail if Redis is down).
- Upgrade `GET /ready` to perform an actual operational check against Redis using the `producer` ACL identity. Return 503 without credential leakage on connection failure.
- Implement `POST /events` returning `202 Accepted` with correlation payload (`status`, `event_id`, `stream`, `stream_id`). Untrusted callers provide content (`event_type`, `severity`, `source`, `destination`, `message`, `metadata`), while server configuration injects trusted infrastructure identity (`schema_version`, `timestamp`, `event_id`, `edge_site`, `namespace`, `service`). Real `XADD` execution is required; return 5xx if Redis fails.

### R5. Edge-Worker Consumer Group & Structured JSON Logging
- Create `apps/edge-worker/` with importable package `edge_worker` (`src` layout).
- Join/consume stream `security-events` via consumer group `edge-workers` using `consumer` ACL credentials.
- Block efficiently without busy-loops; handle shutdown signals (`SIGTERM`/`SIGINT`) cleanly; use bounded backoff for transient disconnects.
- Validate received payloads against the event contract.
- On valid events: emit one single-line unbuffered structured JSON log record preserving all event fields and adding processing metadata (`log_type`, `processing_status`, `redis_stream_id`, `worker`, `processed_at`), then execute `XACK`.
- On malformed events: emit structured processing error log with stream ID; do NOT acknowledge as successful; do NOT leak credentials.

### R6. Docker Hardening & Compose Development Environment
- Containerize `edge-api` and `edge-worker` with minimal, non-root multi-stage Dockerfiles.
- Define `docker-compose.yml` orchestrating Redis, bootstrap init, `edge-api`, and `edge-worker`.
- Apply container hardening: non-root user, `read_only: true` root filesystem, `cap_drop: ALL`, `no-new-privileges: true`, and temporary writable mounts (`/tmp`) only where needed.
- Enforce explicit service dependency ordering (Redis healthy → bootstrap complete / consumer group created → `edge-api` ready → `edge-worker` consuming).
- Expose only `edge-api` port 8000 to the host; keep Redis internal.

### R7. Deterministic Integration Tests, Canonical CLI & Evidence
- Extend `scripts/kubesentinel.py` with canonical commands: `bootstrap-local`, `compose-up`, `compose-down`, `smoke`.
- Implement automated unit tests and real Redis integration tests validating:
  - Producer allowed `XADD`, denied `XREADGROUP`/admin.
  - Consumer allowed `XREADGROUP`/`XACK`, denied `XADD`/admin.
  - Invalid credentials rejected.
  - Host port 6379 closed/unpublished.
  - End-to-end trace: HTTP request → canonical event → Redis `XADD` → consumer group delivery → worker processing → JSON log → `XACK`.
- Update documentation (`README.md`, `docs/architecture.md`, `docs/environment.md`, `docs/security-model.md`, `docs/redis-security.md`).
- Capture real sanitized command output in `docs/evidence/milestone-b/`.

---

## Acceptance Criteria

### Environment & Foundation Integrity
- [ ] Existing Milestone A functionality remains intact and functional.
- [ ] Environment doctor reports zero `FAIL` (`python scripts/kubesentinel.py doctor`).
- [ ] Kubernetes cluster count remains zero (no clusters created).
- [ ] All code passes `python -m ruff check .` and `python -m compileall`.

### Event Contract & Schema
- [ ] Event schema exists at `telemetry/schemas/security-event.schema.json` with version `1.0`.
- [ ] All valid fixtures under `telemetry/samples/valid/` pass validation.
- [ ] All invalid fixtures under `telemetry/samples/invalid/` fail with expected validation errors.
- [ ] Schema drift test verifies compatibility between Pydantic models and JSON Schema.

### Edge API & Redis Streams
- [ ] `GET /health` succeeds independently of Redis availability.
- [ ] `GET /ready` validates live Redis connectivity using `producer` credentials; returns 503 on failure without credential leakage.
- [ ] `POST /events` validates input, populates trusted metadata, executes real `XADD` to `security-events`, and returns `202 Accepted` with correlation IDs.
- [ ] `POST /events` returns appropriate 5xx error if Redis is unavailable.

### Redis Security & ACL Verification
- [ ] Redis requires authentication; default unrestricted access is disabled.
- [ ] Separate `producer`, `consumer`, and `bootstrap/admin` ACL users are configured with least-privilege commands/keys.
- [ ] Producer can execute `XADD` on `security-events` but is denied `XREADGROUP` and administrative commands.
- [ ] Consumer can execute `XREADGROUP` and `XACK` but is denied `XADD` and administrative commands.
- [ ] Redis port 6379 is not published to the host in standard Docker Compose.
- [ ] Generated credentials in `.env.local` and ACL files are verified excluded by `.gitignore`.

### Edge Worker & Stream Processing
- [ ] `edge-worker` connects using `consumer` ACL identity and joins consumer group `edge-workers`.
- [ ] Worker processes stream entries, deserializes, and validates events against schema.
- [ ] Successfully processed events emit machine-readable structured JSON to stdout.
- [ ] `XACK` is executed strictly after successful processing.
- [ ] Malformed stream entries emit error logs and are not falsely acknowledged as successful.
- [ ] Worker handles graceful shutdown (`SIGTERM`/`SIGINT`) without data loss or unhandled exceptions.

### Container Hardening & Docker Compose
- [ ] `edge-api` and `edge-worker` Dockerfiles build cleanly and execute as non-root users.
- [ ] Docker Compose applies `read_only: true`, `cap_drop: ALL`, and `no-new-privileges: true`.
- [ ] Compose stack starts reliably in proper dependency order (`Redis` → `bootstrap` → `edge-api` → `edge-worker`).

### End-to-End Verification & Evidence
- [ ] End-to-end smoke test traces a single event via HTTP POST through Redis to worker structured log and verified `XACK`.
- [ ] All unit and integration test suites pass (`pytest`).
- [ ] Complete sanitized evidence ledger captured in `docs/evidence/milestone-b/` with zero credential leaks.
- [ ] Comprehensive Milestone B completion report generated, halting cleanly before Milestone C.

## Follow-up — 2026-09-12T20:48:45Z

The user has provided the complete, authoritative 44-section master specification for Milestone B below. Incorporate this directly into your execution and verification:

# KubeSentinel Milestone B — Event Contract, Redis Streams, Worker, and Local Integration

Milestone A is complete and its exit gate passed.
Work only inside the existing repository: `D:\KubeSentinel`
Do not create another repository.
The current repository is the authoritative starting point. Inspect the actual files before changing anything and preserve working Milestone A behavior unless this milestone explicitly extends it.

Milestone B must implement the first real end-to-end KubeSentinel application data path:
`edge-api → Redis Streams → edge-worker → structured JSON output`
This milestone should prove the application/event architecture locally with Docker Compose before Kubernetes deployment begins.
Do not proceed into Kubernetes workload deployment, Elastic, Fluent Bit, Falco, Kyverno, detections, attack simulations, Helm packaging, or CI/CD.
Stop after the Milestone B completion report.

---

# 1. CURRENT VERIFIED BASELINE
Milestone A verified:
- Repository: `D:\KubeSentinel`
- Git branch: `main`, no remote, no commits
- Docker Desktop: 4.90.0, Engine: 29.7.2, context: `desktop-linux`, WSL2 Linux/amd64
- Python: 3.14.2, Git: 2.47.1, kubectl: 1.36.1, k3d: 5.9.0 (k3d works with Docker)
- No Kubernetes cluster or context exists
- Host RAM: 15.71 GiB (~1.9-2.9 GiB free). D: drive ample free space.
- Milestone A doctor: 18-19 PASS / 4-5 WARN / 0 FAIL / 8 SKIP
- Milestone A pytest: 15 passed, Ruff: clean, compileall: clean
- Existing API: `GET /health` and `GET /ready`. There is intentionally no `/events` endpoint yet.

---

# 2. MILESTONE B SCOPE
Implement:
1. environment revalidation;
2. versioned security-event contract;
3. valid/invalid telemetry fixtures;
4. shared event validation/serialization logic;
5. real Redis Streams integration;
6. Redis ACL-based authentication;
7. `POST /events` in edge-api;
8. real readiness behavior;
9. new edge-worker application;
10. consumer group operation and acknowledgements;
11. hardened Docker images for edge-api and edge-worker;
12. Docker Compose development environment;
13. deterministic Redis integration tests;
14. end-to-end local smoke validation;
15. Milestone B documentation and evidence.

The required final working path is:
HTTP request → edge-api validates event → edge-api executes real Redis XADD → Redis Stream stores event → edge-worker reads through consumer group → edge-worker validates event → edge-worker emits structured JSON log → edge-worker executes XACK. No fake transports or placeholder integrations.

---

# 3. OUT OF SCOPE
Do NOT implement or install: Kubernetes cluster creation; Kubernetes manifests; Deployments/Services; Helm; Elastic; Kibana; Fluent Bit; Falco; Kyverno; NetworkPolicy; Kubernetes RBAC/Pod Security; Elastic detections; KQL; attack simulations; GitHub Actions; Trivy; Checkov; SBOM; Redis TLS; Prometheus; Grafana; OpenTelemetry; Tetragon; Cosign; cloud infrastructure. k3d may be checked by doctor, but DO NOT create a cluster.

---

# 4. START WITH ENVIRONMENT REVALIDATION
Before modifying code: Run existing doctor. Verify Docker daemon, Docker Compose, Python, k3d, free RAM, disk, Git status, ports 6379 & 8000. Do not destroy unrelated containers. If Docker unhealthy, stop.

---

# 5. GIT / WORKFLOW
Milestone A intentionally created no commits. If isolated worktree/delegation requires a Git commit, create a local baseline commit: `chore: complete milestone a foundation`. Do NOT create a remote, push, tag, or create GitHub repo.

---

# 6. EVENT CONTRACT
Primary schema: `telemetry/schemas/security-event.schema.json`
Core fields:
- `schema_version`: "1.0"
- `timestamp`: UTC RFC3339/ISO-8601 with tz (no naive timestamps)
- `event_id`: UUID
- `edge_site`: `pune`, `mumbai`, `bangalore` (Docker Compose uses `EDGE_SITE=pune`; do not accept arbitrary spoofed site from untrusted caller)
- `namespace`: `local-compose`
- `service`: `edge-api`
- `event_type`: constrained string convention (e.g. `service_request`, `authentication_attempt`, `security_simulation`)
- `severity`: `info`, `low`, `medium`, `high`, `critical`
- `source`: String
- `destination`: Nullable or optional string
- `message`: Human-readable concise event description
- `metadata`: JSON object (nested values remain structured)
Optional Kubernetes fields (`pod`, `container`, `node`) must remain omitted or null.

---

# 7. FIXTURES
Create `telemetry/samples/valid/` and `telemetry/samples/invalid/`.
Valid examples: basic edge API event, optional destination, structured metadata, at least 2 edge sites.
Invalid examples: missing event_id, invalid timestamp, unsupported severity, invalid edge_site, malformed metadata, missing required field, unexpected schema version.
Every fixture must have a documented reason. Add automated validation tests.

---

# 8. SHARED EVENT CODE & DEPENDENCIES
Avoid duplicating event logic in edge-api and edge-worker. Create minimal internal shared Python package/module (e.g. `common` or `edge_common`).
Provide event model (Pydantic), serialization, deserialization, validation, UTC timestamping, UUID creation, edge-site validation.
Pin official Python Redis client (`redis`) compatible with Python 3.14 inside `.venv`.
Pin any schema validator (e.g. `jsonschema`) if needed for fixture/schema tests. Document added packages. Enforce schema drift prevention between model and JSON schema.

---

# 9. REDIS SERVER & STREAMS
Use official pinned image (e.g. `redis:7.4-alpine`, no `redis:latest`).
Redis must not be exposed publicly (no port 6379 host publishing in standard Compose).
Stream: `security-events`.
Store event using `XADD` as `event=<serialized JSON>`.
Bounded retention: approximate MAXLEN ~10000.
Consumer group: `edge-workers` created idempotently via `MKSTREAM` during bootstrap.

---

# 10. REDIS ACLs & SECRET HANDLING
Separate least-privilege identities:
- `producer` (`edge-api`): permitted only authentication, ping, `XADD` to `security-events`. No read, no admin.
- `consumer` (`edge-worker`): permitted only authentication, ping, `XREADGROUP`, `XACK`. No `XADD`, no admin.
- `bootstrap/admin`: used strictly by bootstrap step to initialize consumer group. Never used at runtime.
No `+@all` for producer or consumer.
Local secret handling: `.env.example` with placeholders; ignored `.env.local` and generated ACL files protected by `.gitignore`.
CLI command: `python scripts/kubesentinel.py bootstrap-local` generates random development passwords and ACL configuration. Never print raw secrets in logs or commit them.

---

# 11. EDGE API CHANGES
- Preserve `GET /health` (pure liveness, does not fail if Redis down).
- Extend `GET /ready` (verifies Redis connection using producer credentials; returns 503 without credential leak on failure).
- Add `POST /events`: caller provides content (`event_type`, `severity`, `source`, optional `destination`, `message`, optional `metadata`). Server injects trusted fields (`schema_version`, `timestamp`, `event_id`, `edge_site`, `namespace`, `service`). Executes real `XADD`. Returns HTTP 202 Accepted with correlation JSON (`status`, `event_id`, `stream`, `stream_id`). Returns 5xx if Redis down.

---

# 12. EDGE WORKER
Create `apps/edge-worker/` with package `edge_worker` (`src` layout).
- Connect using consumer ACL identity;
- Join consumer group `edge-workers`;
- Block efficiently (no busy loop);
- Handle shutdown signals cleanly (`SIGTERM`/`SIGINT`);
- Bounded retry/backoff on disconnect;
- Validate event;
- Emit one structured JSON log record to stdout (including `log_type`, `processing_status`, `redis_stream_id`, `worker`, `processed_at`);
- Execute `XACK` only after successful processing.
- If malformed: emit structured processing-error log with stream ID; do NOT acknowledge as successful; do NOT leak credentials.

---

# 13. DOCKER IMAGES & COMPOSE HARDENING
- Containerize `edge-api` and `edge-worker` with multi-stage non-root Dockerfiles.
- Hardening: non-root user, `read_only: true`, `cap_drop: ALL`, `no-new-privileges: true`, tmpfs `/tmp` where needed.
- `docker-compose.yml`: Redis, bootstrap init, `edge-api` (port 8000 exposed to host), `edge-worker` (no exposed ports). Redis internal only.
- Startup ordering: Redis healthy → bootstrap init complete → edge-api ready → edge-worker consuming.

---

# 14. CLI & LOCAL SMOKE TEST
Extend `scripts/kubesentinel.py`:
- `bootstrap-local`
- `compose-up`
- `compose-down`
- `smoke` (deterministic end-to-end trace with bounded polling)
Keep existing `doctor`, `test`, `lint`, `serve`.

---

# 15. TESTS & EVIDENCE
- Unit tests: event creation, UUID/tz, serialization/validation, API POST validation, correlation response, readiness success/failure, worker processing, worker ack-after-process, malformed handling, config parsing, missing secret handling.
- Schema drift tests between Pydantic and JSON Schema.
- Real Redis integration tests against actual containerized Redis (ACL permissions & denials, XADD, XREADGROUP, XACK).
- Sanitize evidence in `docs/evidence/milestone-b/` (`environment.txt`, `versions.txt`, `commands.md`, `tests.txt`, `lint.txt`, `docker-build.txt`, `compose-validation.txt`, `redis-acl-tests.txt`, `event-flow.txt`, `git-status.txt`).

---

# 16. EXIT GATE
Verify all 28 exit-gate criteria. All tests green, doctor 0 FAIL, ruff clean, compileall clean, no clusters created. Produce the full Milestone B report and stop before Milestone C.

## USER AMENDMENT (Four Pre-Execution Corrections)
Before execution, apply these four corrections to the approved Milestone B scope:

1. Compose startup dependency must be:
Redis healthy -> bootstrap completes -> edge-api and edge-worker start independently.
Do not make edge-worker depend on edge-api readiness. Both are independent Redis clients after bootstrap has created the consumer group.

2. `GET /ready` must perform a non-mutating Redis connectivity/authentication check using the producer identity, such as PING. Do not use XADD as a readiness probe because health checks must not create synthetic security events.

3. Redis must use an exact official patch-level image tag verified to exist at implementation time, rather than a floating tag such as `redis:7.4-alpine`. Record the selected image version and resolved digest in Milestone B evidence. Do not guess or fabricate the digest.

4. Replace the worker graceful-shutdown requirement "without data loss" with:
"The worker handles SIGTERM/SIGINT cleanly, never acknowledges an event before successful processing, exits without unhandled exceptions, and leaves any interrupted/unprocessed event pending/recoverable rather than falsely acknowledging it as successful."

All other Milestone B requirements and exit gates remain unchanged.
