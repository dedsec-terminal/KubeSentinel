"""Generate sanitized Milestone F evidence files under docs/evidence/milestone-f/."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.setup_es_templates import get_es_credentials

EVIDENCE_DIR = ROOT / "docs" / "evidence" / "milestone-f"


def sanitize(text: str, extra_secrets: list[str] | None = None) -> str:
    """Sanitize secrets, passwords, and sensitive tokens from command outputs."""
    if not text:
        return ""
    sanitized = text

    # Strip ES password if available
    try:
        _, es_pass = get_es_credentials()
        if es_pass and len(es_pass) >= 4:
            sanitized = sanitized.replace(es_pass, "***REDACTED***")
    except (subprocess.SubprocessError, OSError, RuntimeError, ValueError) as exc:
        sanitized = sanitized.replace(str(exc), "")

    if extra_secrets:
        for s in extra_secrets:
            if s and len(s) >= 4:
                sanitized = sanitized.replace(s, "***REDACTED***")

    # Check environment variables
    for k, v in os.environ.items():
        if any(w in k.upper() for w in ("PASS", "SECRET", "TOKEN", "KEY")) and v and len(v) >= 4:
            sanitized = sanitized.replace(v, "***REDACTED***")

    return sanitized


def run_cmd(args: list[str], timeout_sec: float = 120.0) -> tuple[int, str]:
    """Execute a CLI command and return exit code and combined sanitized output."""
    proc = subprocess.run(
        args,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout_sec,
        check=False,
    )
    return proc.returncode, sanitize(proc.stdout)


def generate_all_evidence() -> None:
    """Generate all 9 required evidence files for Milestone F."""
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    python_exe = sys.executable

    print("\n=======================================================")
    print(" KubeSentinel Milestone F Evidence Collection Generator")
    print("=======================================================\n")

    # 1. simulation-shell.txt
    print("1/9 Generating simulation-shell.txt...")
    code, out = run_cmd([python_exe, "scripts/kubesentinel.py", "simulate", "shell"], timeout_sec=45.0)
    (EVIDENCE_DIR / "simulation-shell.txt").write_text(out.strip() + "\n", encoding="utf-8")
    print(f"    -> Status: {'PASS' if code == 0 else 'FAIL'} (exit {code})")

    # 2. simulation-redis.txt
    print("2/9 Generating simulation-redis.txt...")
    code, out = run_cmd([python_exe, "scripts/kubesentinel.py", "simulate", "redis-unauthorized"], timeout_sec=45.0)
    (EVIDENCE_DIR / "simulation-redis.txt").write_text(out.strip() + "\n", encoding="utf-8")
    print(f"    -> Status: {'PASS' if code == 0 else 'FAIL'} (exit {code})")

    # 3. simulation-rbac.txt
    print("3/9 Generating simulation-rbac.txt...")
    code, out = run_cmd([python_exe, "scripts/kubesentinel.py", "simulate", "rbac-denial"], timeout_sec=30.0)
    (EVIDENCE_DIR / "simulation-rbac.txt").write_text(out.strip() + "\n", encoding="utf-8")
    print(f"    -> Status: {'PASS' if code == 0 else 'FAIL'} (exit {code})")

    # 4. simulation-kyverno.txt
    print("4/9 Generating simulation-kyverno.txt...")
    code, out = run_cmd([python_exe, "scripts/kubesentinel.py", "simulate", "insecure-deployment"], timeout_sec=30.0)
    (EVIDENCE_DIR / "simulation-kyverno.txt").write_text(out.strip() + "\n", encoding="utf-8")
    print(f"    -> Status: {'PASS' if code == 0 else 'FAIL'} (exit {code})")

    # 5. simulation-lateral.txt
    print("5/9 Generating simulation-lateral.txt...")
    code, out = run_cmd([python_exe, "scripts/kubesentinel.py", "simulate", "lateral-access"], timeout_sec=30.0)
    (EVIDENCE_DIR / "simulation-lateral.txt").write_text(out.strip() + "\n", encoding="utf-8")
    print(f"    -> Status: {'PASS' if code == 0 else 'FAIL'} (exit {code})")

    # 6. detection-validation.txt
    print("6/9 Generating detection-validation.txt...")
    code, out = run_cmd([python_exe, "scripts/kubesentinel.py", "detection-validate"], timeout_sec=30.0)
    (EVIDENCE_DIR / "detection-validation.txt").write_text(out.strip() + "\n", encoding="utf-8")
    print(f"    -> Status: {'PASS' if code == 0 else 'FAIL'} (exit {code})")

    # 7. tuning-study.txt
    print("7/9 Generating tuning-study.txt...")
    code, out = run_cmd([python_exe, "docs/detection-tuning/eval_tuning.py"], timeout_sec=30.0)
    metrics_path = ROOT / "docs" / "detection-tuning" / "tuning_metrics.json"
    metrics_json = metrics_path.read_text(encoding="utf-8") if metrics_path.is_file() else "{}"
    tuning_content = (
        "=== EMPIRICAL DETECTION TUNING EVALUATION ENGINE ===\n\n"
        f"{out.strip()}\n\n"
        "=== COMMITTED TUNING METRICS ARTIFACT (tuning_metrics.json) ===\n\n"
        f"{metrics_json.strip()}\n"
    )
    (EVIDENCE_DIR / "tuning-study.txt").write_text(sanitize(tuning_content) + "\n", encoding="utf-8")
    print(f"    -> Status: {'PASS' if code == 0 else 'FAIL'} (exit {code})")

    # 8. tests.txt
    print("8/9 Generating tests.txt (Full Pytest Suite)...")
    code, out = run_cmd([python_exe, "-m", "pytest", "-v"], timeout_sec=120.0)
    (EVIDENCE_DIR / "tests.txt").write_text(out.strip() + "\n", encoding="utf-8")
    print(f"    -> Status: {'PASS' if code == 0 else 'FAIL'} (exit {code})")

    # 9. git-status.txt
    print("9/9 Generating git-status.txt...")
    code, out = run_cmd(["git", "status"], timeout_sec=15.0)
    (EVIDENCE_DIR / "git-status.txt").write_text(out.strip() + "\n", encoding="utf-8")
    print(f"    -> Status: {'PASS' if code == 0 else 'FAIL'} (exit {code})")

    print("\n-------------------------------------------------------")
    print(f"All Milestone F evidence files written to: {EVIDENCE_DIR}")
    print("-------------------------------------------------------\n")


if __name__ == "__main__":
    generate_all_evidence()
