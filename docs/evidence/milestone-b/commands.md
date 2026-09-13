# Milestone B Commands Ledger

The following canonical commands were executed during Milestone B implementation and verification:

```powershell
# 1. Baseline Environment Health Doctor
.\.venv\Scripts\python.exe scripts\kubesentinel.py doctor
.\.venv\Scripts\python.exe scripts\kubesentinel.py doctor --json

# 2. Local Secret & Redis ACL Bootstrap
.\.venv\Scripts\python.exe scripts\kubesentinel.py bootstrap-local

# 3. Code Style & Syntax Validation
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m compileall -q apps scripts tests telemetry

# 4. Unit & Integration Test Suite (177 tests)
.\.venv\Scripts\python.exe -m pytest -v

# 5. Redis ACL Specific Integration Verification
.\.venv\Scripts\python.exe -m pytest tests/integration/test_redis_acl.py -v

# 6. Docker Hardening & Image Builds
docker build -t kubesentinel-edge-api:0.2.0 -f apps/edge-api/Dockerfile .
docker build -t kubesentinel-edge-worker:0.2.0 -f apps/edge-worker/Dockerfile .
docker compose config

# 7. End-to-End Compose Lifecycle & Smoke Verification
.\.venv\Scripts\python.exe scripts\kubesentinel.py compose-up
.\.venv\Scripts\python.exe scripts\kubesentinel.py smoke
.\.venv\Scripts\python.exe scripts\kubesentinel.py compose-down
```
