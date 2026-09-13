# Milestone C Command Ledger

This ledger documents the exact CLI commands implemented, executed, and verified during KubeSentinel Milestone C.

## 1. Pinned k3d Cluster Lifecycle
```bash
# Create pinned k3d single-node cluster (v1.35.5-k3s1) with Traefik, ServiceLB, and metrics-server disabled
python scripts/kubesentinel.py cluster-create

# Check cluster status and nodes
python scripts/kubesentinel.py cluster-start
python scripts/kubesentinel.py cluster-stop
# python scripts/kubesentinel.py cluster-delete  (available for teardown)
```

## 2. Kubernetes Manifest Deployment
```bash
# Deploys namespaces, RBAC, secrets, ConfigMaps, Redis, bootstrap Job, edge-api (3 sites), and edge-worker
python scripts/kubesentinel.py k8s-deploy
```

## 3. Automated Validation & Compliance Check
```bash
# Validates 5 namespaces PSA labels, PSA negative rejection fixture, 5 ServiceAccounts (automount=false, 0 perms), 5 workloads container hardening, Redis ACL rules
python scripts/kubesentinel.py k8s-validate
```

## 4. Multi-Site End-to-End Smoke Verification
```bash
# Ingests events across Pune, Mumbai, Bangalore edge APIs, validates ingestion into Redis Streams,
# verifies edge-worker consumption and Downward API metadata enrichment, and verifies XACK PEL clearance
python scripts/kubesentinel.py k8s-smoke
```

## 5. Test Suite & Static Analysis
```bash
# Full pytest suite (189 tests covering unit, integration, downward API, manifests, CLI)
pytest -v

# Static analysis and linting
python -m ruff check .
python -m compileall -q apps scripts tests telemetry

# System health and environment diagnostics
python scripts/kubesentinel.py doctor
```
