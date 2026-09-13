# Milestone D Command Ledger

This ledger documents the exact CLI commands implemented, executed, and verified during KubeSentinel Milestone D.

## 1. Network Security & Policies
```bash
# Apply native Kubernetes NetworkPolicy manifests
docker exec -i k3d-kubesentinel-server-0 kubectl apply -f /d/KubeSentinel/kubernetes/network/

# Run complete NetworkPolicy automated validation suite (24 checks: default-deny, DNS, Redis, cross-edge)
python scripts/kubesentinel.py network-validate
```

## 2. Kyverno Admission Controller & Helm Lifecycle
```bash
# Verify Helm installation and repository status
helm version
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update

# Deploy Kyverno v3.9.1 via Helm into kyverno namespace with resource-constrained values
helm upgrade --install kyverno kyverno/kyverno --version 3.9.1 -n kyverno --create-namespace -f helm/third-party/kyverno-values.yaml

# Check Kyverno controller pods and deployments
docker exec -i k3d-kubesentinel-server-0 kubectl get pods -n kyverno -o wide
docker exec -i k3d-kubesentinel-server-0 kubectl get deployments -n kyverno -o wide
```

## 3. Kyverno Policy-as-Code Enforcement
```bash
# Apply 9 declarative security ClusterPolicies (Enforce mode)
docker exec -i k3d-kubesentinel-server-0 kubectl apply -f /d/KubeSentinel/policies/kyverno/

# Inspect ClusterPolicies status
docker exec -i k3d-kubesentinel-server-0 kubectl get clusterpolicies -o wide

# Run comprehensive Kyverno automated validation suite (19 checks: policy readiness, webhook negative/positive tests)
python scripts/kubesentinel.py kyverno-validate
```

## 4. Workload Image Hygiene (No :latest in Production)
```bash
# Import explicit versioned images into k3d cluster
k3d image import kubesentinel-edge-api:0.2.0 -c kubesentinel
k3d image import kubesentinel-edge-worker:0.2.0 -c kubesentinel

# Roll out versioned workloads across edge sites and system
docker exec -i k3d-kubesentinel-server-0 kubectl apply -f /d/KubeSentinel/kubernetes/workloads/
docker exec -i k3d-kubesentinel-server-0 kubectl rollout status deployment/edge-api -n edge-pune
docker exec -i k3d-kubesentinel-server-0 kubectl rollout status deployment/edge-api -n edge-mumbai
docker exec -i k3d-kubesentinel-server-0 kubectl rollout status deployment/edge-api -n edge-bangalore
docker exec -i k3d-kubesentinel-server-0 kubectl rollout status deployment/edge-worker -n kubesentinel-system
```

## 5. Automated Regression & Exit Gate Verification
```bash
# Full pytest test suite (including unit, manifests, CLI tests)
pytest -v

# Static analysis and linting
ruff check .
python -m compileall -q apps scripts tests telemetry policies

# Diagnostics & End-to-End Pipeline Smoke Test
python scripts/kubesentinel.py doctor
python scripts/kubesentinel.py k8s-validate
python scripts/kubesentinel.py network-validate
python scripts/kubesentinel.py kyverno-validate
python scripts/kubesentinel.py k8s-smoke
```
