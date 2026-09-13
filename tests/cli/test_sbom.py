"""Unit tests for KubeSentinel SBOM generation and supply chain artifacts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.kubesentinel import main
from scripts.sbom import (
    _generate_python_fallback_cyclonedx,
    _generate_python_fallback_spdx,
    compute_sha256,
    generate_all_sboms,
)


def test_sbom_cli_help(capsys: pytest.CaptureFixture) -> None:
    """Verify sbom subcommand help output."""
    with pytest.raises(SystemExit) as exc:
        main(["sbom", "--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "sbom" in captured.out
    assert "--format" in captured.out
    assert "cyclonedx" in captured.out


def test_build_images_cli_help(capsys: pytest.CaptureFixture) -> None:
    """Verify build-images subcommand help output."""
    with pytest.raises(SystemExit) as exc:
        main(["build-images", "--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "build-images" in captured.out
    assert "--tag" in captured.out


def test_compute_sha256(tmp_path: Path) -> None:
    """Verify compute_sha256 returns accurate hex hash."""
    test_file = tmp_path / "test.txt"
    content = b"KubeSentinel Milestone G Supply Chain Integrity"
    test_file.write_bytes(content)

    expected = hashlib.sha256(content).hexdigest()
    actual = compute_sha256(test_file)
    assert actual == expected


def test_python_fallback_cyclonedx(tmp_path: Path) -> None:
    """Verify Python fallback produces valid CycloneDX 1.5 JSON."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("fastapi==0.141.1\nredis==8.1.0\n", encoding="utf-8")

    bom = _generate_python_fallback_cyclonedx("edge-api", "1.0.0", req_file)
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"
    assert "metadata" in bom
    assert bom["metadata"]["component"]["name"] == "edge-api:1.0.0"

    names = [c["name"] for c in bom["components"]]
    assert "fastapi" in names
    assert "redis" in names
    assert "edge-common" in names
    assert "python" in names


def test_python_fallback_spdx(tmp_path: Path) -> None:
    """Verify Python fallback produces valid SPDX 2.3 JSON."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("pydantic==2.13.5\n", encoding="utf-8")

    spdx = _generate_python_fallback_spdx("edge-worker", "1.0.0", req_file)
    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert spdx["dataLicense"] == "CC0-1.0"
    assert "packages" in spdx

    pkg_names = [p["name"] for p in spdx["packages"]]
    assert "pydantic" in pkg_names
    assert "edge-worker:1.0.0" in pkg_names


def test_generate_all_sboms(tmp_path: Path) -> None:
    """Verify generate_all_sboms creates SBOMs, metadata.json, and checksums.sha256."""
    with patch("scripts.sbom.build_images", return_value=0):
        rc = generate_all_sboms(output_dir=tmp_path, format_type="cyclonedx", build_first=False)
        assert rc == 0

    api_sbom = tmp_path / "edge-api-sbom.json"
    worker_sbom = tmp_path / "edge-worker-sbom.json"
    meta_file = tmp_path / "metadata.json"
    checksums_file = tmp_path / "checksums.sha256"

    assert api_sbom.is_file()
    assert worker_sbom.is_file()
    assert meta_file.is_file()
    assert checksums_file.is_file()

    # Validate metadata
    meta = json.loads(meta_file.read_text(encoding="utf-8"))
    assert meta["format"] == "cyclonedx"
    assert "edge-api" in meta["artifacts"]
    assert "edge-worker" in meta["artifacts"]
    assert meta["total_components"] > 0

    # Validate checksums file
    checksum_lines = checksums_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(checksum_lines) == 3
    for line in checksum_lines:
        hash_val, filename = line.split("  ")
        assert len(hash_val) == 64
        assert (tmp_path / filename).is_file()
