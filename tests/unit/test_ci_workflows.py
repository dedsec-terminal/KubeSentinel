"""Automated validation tests for GitHub Actions CI/CD workflows and security scanner configurations."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS_DIR = ROOT / ".github" / "workflows"
CI_WORKFLOW = WORKFLOWS_DIR / "ci.yml"
SECURITY_WORKFLOW = WORKFLOWS_DIR / "security.yml"
TRIVYIGNORE_FILE = ROOT / ".trivyignore"
CHECKOV_FILE = ROOT / ".checkov.yaml"


def test_workflow_files_exist() -> None:
    """Verify both CI and security scanning workflow files exist."""
    assert CI_WORKFLOW.is_file(), f"Missing CI workflow at {CI_WORKFLOW}"
    assert SECURITY_WORKFLOW.is_file(), f"Missing security workflow at {SECURITY_WORKFLOW}"
    assert TRIVYIGNORE_FILE.is_file(), f"Missing .trivyignore at {TRIVYIGNORE_FILE}"
    assert CHECKOV_FILE.is_file(), f"Missing .checkov.yaml at {CHECKOV_FILE}"


def test_workflow_triggers_and_safety() -> None:
    """Verify workflows trigger on PR and push to main, with zero pull_request_target."""
    for wf in (CI_WORKFLOW, SECURITY_WORKFLOW):
        content = wf.read_text(encoding="utf-8")
        assert "pull_request:" in content
        assert "branches: [main]" in content or "- main" in content
        assert "pull_request_target" not in content, f"Unsafe pull_request_target found in {wf.name}"


def test_workflow_least_privilege_permissions() -> None:
    """Verify workflow permissions are explicitly set to minimum (contents: read)."""
    for wf in (CI_WORKFLOW, SECURITY_WORKFLOW):
        content = wf.read_text(encoding="utf-8")
        assert "permissions:" in content
        assert "contents: read" in content


def test_all_third_party_actions_pinned_with_shas() -> None:
    """Verify every third-party action is pinned to an immutable 40-character commit SHA with a version comment."""
    sha_pattern = re.compile(r"uses:\s*([\w\-]+/[\w\-]+)@([a-f0-9]{40})\s*#\s*(v[\d\.]+)")

    for wf in (CI_WORKFLOW, SECURITY_WORKFLOW):
        lines = wf.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("uses:"):
                # Must not use mutable tags or branches (@main, @v4, etc.)
                match = sha_pattern.search(stripped)
                assert match is not None, (
                    f"Line {i} in {wf.name} does not pin action to 40-char SHA with version comment:\n  {stripped}"
                )
                action_name, sha, version = match.groups()
                assert len(sha) == 40, f"Invalid SHA length ({len(sha)}) for {action_name}"
                assert version.startswith("v"), f"Missing version prefix 'v' in comment for {action_name}"


def test_ci_workflow_required_steps() -> None:
    """Verify CI workflow contains all required linting, compilation, and validation steps."""
    content = CI_WORKFLOW.read_text(encoding="utf-8")

    # Quality and test commands
    assert "python -m ruff check ." in content
    assert "python -m compileall" in content
    assert "git diff --check" in content
    assert "scripts/kubesentinel.py detection-validate --no-es" in content
    assert 'pytest -m "not integration"' in content

    # Manifest and policy validation
    assert "policies/kyverno" in content
    assert "tests/unit/test_k8s_manifests.py" in content
    assert "tests/unit/test_falco_rules.py" in content
    assert "helm template" in content

    # Dockerfile linting
    assert "hadolint" in content
    assert "apps/edge-api/Dockerfile" in content
    assert "apps/edge-worker/Dockerfile" in content


def test_security_workflow_scanners_and_images() -> None:
    """Verify security workflow configures Trivy fs/config/image scans and Checkov."""
    content = SECURITY_WORKFLOW.read_text(encoding="utf-8")

    # Trivy scans
    assert "aquasecurity/trivy-action" in content
    assert 'scan-type: "fs"' in content
    assert 'scan-type: "config"' in content
    assert "trivyignores: \".trivyignore\"" in content
    assert "ignore-unfixed: true" in content

    # Checkov IaC scan
    assert "bridgecrewio/checkov-action" in content
    assert 'config_file: ".checkov.yaml"' in content

    # Image scans for edge-api and edge-worker
    assert "kubesentinel/edge-api:1.0.0" in content
    assert "kubesentinel/edge-worker:1.0.0" in content


def test_security_workflow_generates_and_uploads_sboms() -> None:
    """Verify the security workflow uses the canonical CLI to publish both documented SBOM formats."""
    content = SECURITY_WORKFLOW.read_text(encoding="utf-8")

    assert "python scripts/kubesentinel.py sbom" in content
    assert "--build --tag 1.0.0 --format cyclonedx" in content
    assert "--tag 1.0.0 --format spdx-json" in content
    assert "actions/upload-artifact@" in content
    assert "path: artifacts/sbom/" in content
    assert "if-no-files-found: error" in content
    assert "docker push" not in content


def test_trivyignore_and_checkov_documented_exceptions() -> None:
    """Verify .trivyignore and .checkov.yaml document scoped exceptions for Falco and Fluent Bit."""
    trivy_content = TRIVYIGNORE_FILE.read_text(encoding="utf-8")
    checkov_content = CHECKOV_FILE.read_text(encoding="utf-8")

    # Falco modern_ebpf exceptions
    assert "falco" in trivy_content.lower()
    assert "ebpf" in trivy_content.lower()
    assert "privileged" in trivy_content.lower()
    assert "AVD-KSV-0012" in trivy_content or "KSV012" in trivy_content

    # Fluent Bit exceptions
    assert "fluent" in trivy_content.lower()
    assert "/var/log" in trivy_content

    # Checkov configuration
    assert "skip-check:" in checkov_content
    assert "CKV_K8S_16" in checkov_content  # Privileged
    assert "CKV_K8S_17" in checkov_content  # hostPath
    assert "skip-path:" in checkov_content
    assert "psa-negative-pod.yaml" in checkov_content
