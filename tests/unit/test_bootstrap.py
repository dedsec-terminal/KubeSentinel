"""Unit tests for KubeSentinel bootstrap-local credential and ACL generation."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from scripts.bootstrap import (
    bootstrap_local,
    generate_passwords,
    render_env_local,
    render_users_acl,
)


def test_generate_passwords_distinct_and_secure() -> None:
    """Validate that generated passwords are non-empty, distinct, and adequately long."""
    passwords = generate_passwords()
    assert set(passwords.keys()) == {"producer", "consumer", "bootstrap"}
    for role, password in passwords.items():
        assert isinstance(password, str)
        assert len(password) >= 32, f"Password for {role} too short"
    # Ensure all passwords are mutually distinct
    assert len(set(passwords.values())) == 3


def test_render_env_local_contains_required_variables() -> None:
    """Validate that rendered .env.local content includes all documented variables."""
    sample_passwords = {
        "producer": "test-prod-secret-value-1234567890",
        "consumer": "test-cons-secret-value-1234567890",
        "bootstrap": "test-boot-secret-value-1234567890",
    }
    content = render_env_local(sample_passwords)
    lines = content.splitlines()

    # Verify password variables are populated
    assert f"REDIS_PRODUCER_PASSWORD={sample_passwords['producer']}" in lines
    assert f"REDIS_CONSUMER_PASSWORD={sample_passwords['consumer']}" in lines
    assert f"REDIS_BOOTSTRAP_PASSWORD={sample_passwords['bootstrap']}" in lines

    # Verify standard network and context variables
    assert "REDIS_HOST=redis" in lines
    assert "REDIS_PORT=6379" in lines
    assert "REDIS_STREAM=security-events" in lines
    assert "REDIS_CONSUMER_GROUP=edge-workers" in lines
    assert "EDGE_SITE=pune" in lines
    assert "NAMESPACE=local-compose" in lines
    assert "SERVICE=edge-api" in lines


def test_render_users_acl_format_and_directives() -> None:
    """Validate exact Redis ACL least-privilege syntax, key patterns, and command sets."""
    sample_passwords = {
        "producer": "prod_pw_abc",
        "consumer": "cons_pw_def",
        "bootstrap": "boot_pw_ghi",
    }
    content = render_users_acl(sample_passwords)
    lines = [line.strip() for line in content.strip().splitlines() if line.strip()]

    assert len(lines) == 4
    # Rule 1: Default user disabled
    assert lines[0] == "user default off"

    # Rule 2: Producer least-privilege
    prod_line = lines[1]
    assert prod_line.startswith("user producer on >prod_pw_abc ")
    assert "resetkeys" in prod_line
    assert "~security-events" in prod_line
    assert "resetchannels" in prod_line
    assert "-@all" in prod_line
    assert "+auth" in prod_line
    assert "+ping" in prod_line
    assert "+xadd" in prod_line
    assert "+xreadgroup" not in prod_line
    assert "+xack" not in prod_line

    # Rule 3: Consumer least-privilege
    cons_line = lines[2]
    assert cons_line.startswith("user consumer on >cons_pw_def ")
    assert "resetkeys" in cons_line
    assert "~security-events" in cons_line
    assert "resetchannels" in cons_line
    assert "-@all" in cons_line
    assert "+auth" in cons_line
    assert "+ping" in cons_line
    assert "+xreadgroup" in cons_line
    assert "+xack" in cons_line
    assert "+xadd" not in cons_line

    # Rule 4: Bootstrap least-privilege
    boot_line = lines[3]
    assert boot_line.startswith("user bootstrap on >boot_pw_ghi ")
    assert "resetkeys" in boot_line
    assert "~security-events" in boot_line
    assert "resetchannels" in boot_line
    assert "-@all" in boot_line
    assert "+auth" in boot_line
    assert "+ping" in boot_line
    assert "+xgroup" in boot_line
    assert "+xinfo" in boot_line


def test_bootstrap_local_file_creation(tmp_path: Path) -> None:
    """Validate that bootstrap_local creates files with correct content and permissions."""
    code = bootstrap_local(root_dir=tmp_path, force=False, stdout=False)
    assert code == 0

    env_file = tmp_path / ".env.local"
    acl_file = tmp_path / "deploy" / "compose" / "redis" / "users.acl"

    assert env_file.exists()
    assert acl_file.exists()

    env_text = env_file.read_text(encoding="utf-8")
    acl_text = acl_file.read_text(encoding="utf-8")

    # Extract passwords from env_text
    prod_match = re.search(r"REDIS_PRODUCER_PASSWORD=(\S+)", env_text)
    cons_match = re.search(r"REDIS_CONSUMER_PASSWORD=(\S+)", env_text)
    boot_match = re.search(r"REDIS_BOOTSTRAP_PASSWORD=(\S+)", env_text)

    assert prod_match and cons_match and boot_match
    prod_pw = prod_match.group(1)
    cons_pw = cons_match.group(1)
    boot_pw = boot_match.group(1)

    # Cross-validate that ACL file uses the exact generated passwords
    assert f"user producer on >{prod_pw}" in acl_text
    assert f"user consumer on >{cons_pw}" in acl_text
    assert f"user bootstrap on >{boot_pw}" in acl_text


def test_bootstrap_local_refuses_overwrite_without_force(tmp_path: Path) -> None:
    """Validate conflict detection when credentials already exist."""
    # First invocation succeeds
    assert bootstrap_local(root_dir=tmp_path, force=False, stdout=False) == 0

    env_file = tmp_path / ".env.local"
    original_env = env_file.read_text(encoding="utf-8")

    # Second invocation without force returns error code 1 and leaves content untouched
    assert bootstrap_local(root_dir=tmp_path, force=False, stdout=False) == 1
    assert env_file.read_text(encoding="utf-8") == original_env


def test_bootstrap_local_overwrites_with_force(tmp_path: Path) -> None:
    """Validate that passing force=True replaces existing credentials."""
    assert bootstrap_local(root_dir=tmp_path, force=False, stdout=False) == 0
    env_file = tmp_path / ".env.local"
    first_env = env_file.read_text(encoding="utf-8")

    # Re-run with force
    assert bootstrap_local(root_dir=tmp_path, force=True, stdout=False) == 0
    second_env = env_file.read_text(encoding="utf-8")

    # Passwords should be freshly generated and therefore distinct
    assert first_env != second_env


def test_cli_bootstrap_local_no_secret_leak(tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify CLI execution never exposes raw secrets to stdout or stderr."""
    import scripts.kubesentinel as cli_module

    monkeypatch.setattr(cli_module, "ROOT", tmp_path)
    exit_code = cli_module.main(["bootstrap-local"])
    assert exit_code == 0

    captured = capsys.readouterr()
    stdout = captured.out
    stderr = captured.err

    # Read generated passwords to verify absence from stdout/stderr
    env_text = (tmp_path / ".env.local").read_text(encoding="utf-8")
    for match in re.finditer(r"REDIS_\w+_PASSWORD=(\S+)", env_text):
        password = match.group(1)
        assert password not in stdout, "Security leak: raw password printed to stdout!"
        assert password not in stderr, "Security leak: raw password printed to stderr!"
