"""Script to generate all Milestone D evidence files in docs/evidence/milestone-d/."""

from __future__ import annotations

import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = ROOT / "docs" / "evidence" / "milestone-d"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.k8s_client import run_helm, run_kubectl


def write_file(filename: str, content: str) -> None:
    path = EVIDENCE_DIR / filename
    path.write_text(content.strip() + "\n", encoding="utf-8")
    print(f"[+] Wrote {path}")


def generate_environment() -> None:
    lines = ["=== KUBERNETES CLUSTER INFO ==="]
    res = run_kubectl(["cluster-info"])
    lines.append(res.stdout or res.stderr)

    lines.append("\n=== NODES ===")
    res = run_kubectl(["get", "nodes", "-o", "wide"])
    lines.append(res.stdout or res.stderr)

    lines.append("\n=== NAMESPACES ===")
    res = run_kubectl(["get", "ns", "--show-labels"])
    lines.append(res.stdout or res.stderr)

    lines.append("\n=== SYSTEM & PYTHON INFO ===")
    lines.append(f"OS: {platform.platform()}")
    lines.append(f"Python: {sys.version}")

    write_file("environment.txt", "\n".join(lines))


def generate_helm_kyverno() -> None:
    lines = ["=== HELM VERSION ==="]
    res = run_helm(["version"])
    lines.append(res.stdout or res.stderr)

    lines.append("\n=== HELM RELEASES ===")
    res = run_helm(["list", "-A"])
    lines.append(res.stdout or res.stderr)

    lines.append("\n=== HELM KYVERNO VALUES ===")
    res = run_helm(["get", "values", "kyverno", "-n", "kyverno"])
    lines.append(res.stdout or res.stderr)

    lines.append("\n=== KYVERNO PODS ===")
    res = run_kubectl(["get", "pods", "-n", "kyverno", "-o", "wide"])
    lines.append(res.stdout or res.stderr)

    lines.append("\n=== KYVERNO DEPLOYMENTS ===")
    res = run_kubectl(["get", "deployments", "-n", "kyverno", "-o", "wide"])
    lines.append(res.stdout or res.stderr)

    write_file("helm-kyverno.txt", "\n".join(lines))


def generate_network_policies() -> None:
    lines = ["=== NETWORK POLICIES (ALL NAMESPACES) ==="]
    res = run_kubectl(["get", "networkpolicies", "-A", "-o", "wide"])
    lines.append(res.stdout or res.stderr)

    for ns in ["kubesentinel-system", "edge-pune", "edge-mumbai", "edge-bangalore"]:
        lines.append(f"\n=== POLICIES IN {ns} ===")
        res = run_kubectl(["get", "networkpolicy", "-n", ns, "-o", "yaml"])
        lines.append(res.stdout or res.stderr)

    write_file("network-policies.txt", "\n".join(lines))


def generate_network_validation() -> None:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "network_validate.py")],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    output = proc.stdout + ("\nSTDERR:\n" + proc.stderr if proc.stderr else "")
    write_file("network-validation.txt", output)


def generate_kyverno_policies() -> None:
    lines = ["=== CLUSTER POLICIES ==="]
    res = run_kubectl(["get", "clusterpolicies", "-o", "wide"])
    lines.append(res.stdout or res.stderr)

    lines.append("\n=== CLUSTER POLICY DETAILS ===")
    res = run_kubectl(["get", "clusterpolicies", "-o", "custom-columns=NAME:.metadata.name,ACTION:.spec.validationFailureAction,BACKGROUND:.spec.background,READY:.status.ready"])
    lines.append(res.stdout or res.stderr)

    write_file("kyverno-policies.txt", "\n".join(lines))


def generate_kyverno_admission_tests() -> None:
    lines = ["=== KYVERNO ADMISSION TEST RESULTS ===", ""]

    # Positive test
    valid_pod = ROOT / "tests" / "kyverno" / "pass" / "valid-pod.yaml"
    lines.append(f"--- POSITIVE TEST: {valid_pod.name} ---")
    valid_content = valid_pod.read_text(encoding="utf-8")
    res = run_kubectl(["apply", "--dry-run=server", "-f", "-"], input_text=valid_content)
    lines.append(f"Return code: {res.returncode}")
    lines.append(f"STDOUT: {res.stdout.strip()}")
    lines.append(f"STDERR: {res.stderr.strip()}")
    lines.append("")

    # Negative tests
    fail_dir = ROOT / "tests" / "kyverno" / "fail"
    for fail_file in sorted(fail_dir.glob("*.yaml")):
        lines.append(f"--- NEGATIVE TEST: {fail_file.name} ---")
        fail_content = fail_file.read_text(encoding="utf-8")
        res = run_kubectl(["apply", "--dry-run=server", "-f", "-"], input_text=fail_content)
        lines.append(f"Return code: {res.returncode}")
        if res.stdout.strip():
            lines.append(f"STDOUT: {res.stdout.strip()}")
        if res.stderr.strip():
            lines.append(f"STDERR: {res.stderr.strip()}")
        lines.append("")

    write_file("kyverno-admission-tests.txt", "\n".join(lines))


def generate_security_regression() -> None:
    lines = ["=== SECURITY REGRESSION VALIDATION ===", ""]

    lines.append("1. POD SECURITY ADMISSION (PSA) LABELS:")
    res = run_kubectl(["get", "ns", "-o", "custom-columns=NAME:.metadata.name,ENFORCE:.metadata.labels.pod-security\\.kubernetes\\.io/enforce,WARN:.metadata.labels.pod-security\\.kubernetes\\.io/warn,AUDIT:.metadata.labels.pod-security\\.kubernetes\\.io/audit"])
    lines.append(res.stdout or res.stderr)

    lines.append("\n2. PSA NEGATIVE REJECTION TEST:")
    psa_neg = ROOT / "kubernetes" / "security" / "psa-negative-pod.yaml"
    psa_content = psa_neg.read_text(encoding="utf-8")
    res = run_kubectl(["apply", "--dry-run=server", "-f", "-"], input_text=psa_content)
    lines.append(f"Return code: {res.returncode}")
    lines.append(res.stderr or res.stdout)

    lines.append("\n3. SERVICEACCOUNT AUTOMOUNT TOKEN STATUS:")
    lines.append("NAMESPACE            NAME             AUTOMOUNT")
    for sa, ns in [
        ("edge-api-sa", "edge-pune"),
        ("edge-api-sa", "edge-mumbai"),
        ("edge-api-sa", "edge-bangalore"),
        ("edge-worker-sa", "kubesentinel-system"),
        ("redis-sa", "kubesentinel-system"),
    ]:
        sa_res = run_kubectl(["get", "sa", "-n", ns, sa, "-o", "jsonpath={.automountServiceAccountToken}"])
        automount = sa_res.stdout.strip()
        lines.append(f"{ns:<20} {sa:<16} {automount}")

    lines.append("\n4. RBAC LEAST-PRIVILEGE AUDIT (can-i):")
    for sa, ns in [
        ("edge-api-sa", "edge-pune"),
        ("edge-api-sa", "edge-mumbai"),
        ("edge-api-sa", "edge-bangalore"),
        ("edge-worker-sa", "kubesentinel-system"),
        ("redis-sa", "kubesentinel-system"),
    ]:
        lines.append(f"ServiceAccount {sa} in {ns}:")
        for verb, resource in [("list", "pods"), ("get", "secrets"), ("create", "pods"), ("delete", "services")]:
            can_i = run_kubectl(["auth", "can-i", verb, resource, f"--as=system:serviceaccount:{ns}:{sa}", "-n", ns])
            result = can_i.stdout.strip()
            lines.append(f"  can-i {verb} {resource}: {result}")

    lines.append("\n5. REDIS CLUSTERIP & PORT EXPOSURE:")
    res = run_kubectl(["get", "svc", "-n", "kubesentinel-system", "redis", "-o", "wide"])
    lines.append(res.stdout or res.stderr)

    write_file("security-regression.txt", "\n".join(lines))


def generate_tests_output() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-v"],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    output = proc.stdout + ("\nSTDERR:\n" + proc.stderr if proc.stderr else "")
    write_file("tests.txt", output)


def generate_git_status() -> None:
    proc = subprocess.run(
        ["git", "status"],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    write_file("git-status.txt", proc.stdout)


def main() -> None:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    print("Generating Milestone D Evidence Artifacts...")
    generate_environment()
    generate_helm_kyverno()
    generate_network_policies()
    generate_network_validation()
    generate_kyverno_policies()
    generate_kyverno_admission_tests()
    generate_security_regression()
    generate_tests_output()
    generate_git_status()
    print("[SUCCESS] All Milestone D evidence files generated successfully.")


if __name__ == "__main__":
    main()
