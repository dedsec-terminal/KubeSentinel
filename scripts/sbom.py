"""Deterministic image build and Software Bill of Materials (SBOM) generation for KubeSentinel."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SBOM_DIR = ROOT / "artifacts" / "sbom"
DEFAULT_TAG = "1.0.0"

IMAGE_SPECS = {
    "edge-api": {
        "dockerfile": "apps/edge-api/Dockerfile",
        "app_dir": "apps/edge-api",
        "req_file": "apps/edge-api/requirements.txt",
        "tags": [
            "edge-api:{tag}",
            "kubesentinel-edge-api:{tag}",
            "kubesentinel-edge-api:0.2.0",
            "kubesentinel-edge-api:latest",
        ],
    },
    "edge-worker": {
        "dockerfile": "apps/edge-worker/Dockerfile",
        "app_dir": "apps/edge-worker",
        "req_file": "apps/edge-worker/requirements.txt",
        "tags": [
            "edge-worker:{tag}",
            "kubesentinel-edge-worker:{tag}",
            "kubesentinel-edge-worker:0.2.0",
            "kubesentinel-edge-worker:latest",
        ],
    },
}


def compute_sha256(file_path: Path) -> str:
    """Compute hex SHA-256 hash of a file."""
    h = hashlib.sha256()
    with file_path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def find_scanner() -> tuple[str | None, str | None]:
    """Find available SBOM CLI tool (syft or trivy)."""
    syft = shutil.which("syft")
    if syft:
        return "syft", syft

    trivy = shutil.which("trivy")
    if not trivy:
        # Check standard Windows tool paths
        for candidate in (
            Path(r"D:\Tools\bin\trivy.exe"),
            Path(r"C:\ProgramData\chocolatey\bin\trivy.exe"),
            Path(r"C:\Users\Dedse\scoop\shims\trivy.exe"),
        ):
            if candidate.is_file():
                trivy = str(candidate)
                break

    if trivy:
        return "trivy", trivy

    return None, None


def build_images(tag: str = DEFAULT_TAG, no_cache: bool = False) -> int:
    """Build deterministic, pinned container images for edge-api and edge-worker."""
    docker = shutil.which("docker")
    if not docker:
        print("ERROR: docker CLI not found on PATH.", file=sys.stderr)
        return 1

    print(f"=== Building KubeSentinel Container Images (tag: {tag}) ===")
    for app_name, spec in IMAGE_SPECS.items():
        dockerfile = ROOT / spec["dockerfile"]
        if not dockerfile.is_file():
            print(f"ERROR: Dockerfile not found: {dockerfile}", file=sys.stderr)
            return 1

        cmd = [docker, "build", "-f", str(dockerfile)]
        if no_cache:
            cmd.append("--no-cache")

        for tag_tpl in spec["tags"]:
            cmd.extend(["-t", tag_tpl.format(tag=tag)])
        cmd.append(str(ROOT))

        print(f"\n--> Building {app_name} ({spec['dockerfile']})...")
        res = subprocess.run(cmd, cwd=ROOT, check=False)
        if res.returncode != 0:
            print(f"ERROR: Failed to build {app_name} (exit {res.returncode})", file=sys.stderr)
            return res.returncode
        print(f"[+] Successfully built {app_name}:{tag}")

    print("\n[SUCCESS] All application container images built and tagged.")
    return 0


def _generate_python_fallback_cyclonedx(app_name: str, tag: str, req_file: Path) -> dict[str, Any]:
    """Pure-Python fallback to construct a standard CycloneDX 1.5 JSON SBOM."""
    serial_number = f"urn:uuid:{uuid.uuid4()}"
    timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    components: list[dict[str, Any]] = [
        {
            "type": "operating-system",
            "name": "debian",
            "version": "12-slim",
            "description": "Base OS Debian 12 (bookworm) slim from python:3.11-slim",
            "purl": "pkg:deb/debian/base-files@12",
        },
        {
            "type": "platform",
            "name": "python",
            "version": "3.11",
            "description": "Python runtime environment",
            "purl": "pkg:generic/python@3.11",
        },
    ]

    # Parse requirements.txt
    if req_file.is_file():
        for line in req_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "==" in line:
                pkg, ver = line.split("==", 1)
                pkg = pkg.strip()
                ver = ver.strip()
                components.append({
                    "type": "library",
                    "name": pkg,
                    "version": ver,
                    "purl": f"pkg:pypi/{pkg}@{ver}",
                    "scope": "required",
                })
            else:
                components.append({
                    "type": "library",
                    "name": line,
                    "scope": "required",
                })

    # Common shared package
    components.append({
        "type": "library",
        "name": "edge-common",
        "version": "0.1.0",
        "description": "Shared edge domain models, event serialization, and schemas",
        "purl": "pkg:pypi/edge-common@0.1.0",
        "scope": "required",
    })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial_number,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "KubeSentinel",
                    "name": "kubesentinel-sbom-engine",
                    "version": "1.0.0",
                }
            ],
            "component": {
                "type": "container",
                "name": f"{app_name}:{tag}",
                "version": tag,
            },
        },
        "components": components,
    }


def _generate_python_fallback_spdx(app_name: str, tag: str, req_file: Path) -> dict[str, Any]:
    """Pure-Python fallback to construct a standard SPDX 2.3 JSON document."""
    timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc_namespace = f"http://spdx.org/spdxdocs/{app_name}-{tag}-{uuid.uuid4()}"

    packages: list[dict[str, Any]] = [
        {
            "SPDXID": "SPDXRef-RootPackage",
            "name": f"{app_name}:{tag}",
            "versionInfo": tag,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
        },
        {
            "SPDXID": "SPDXRef-Package-python",
            "name": "python",
            "versionInfo": "3.11",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
        },
    ]

    if req_file.is_file():
        idx = 1
        for line in req_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "==" in line:
                pkg, ver = line.split("==", 1)
                packages.append({
                    "SPDXID": f"SPDXRef-Package-{pkg.strip().replace('_', '-')}-{idx}",
                    "name": pkg.strip(),
                    "versionInfo": ver.strip(),
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": f"pkg:pypi/{pkg.strip()}@{ver.strip()}",
                        }
                    ],
                })
                idx += 1

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{app_name}:{tag}",
        "documentNamespace": doc_namespace,
        "creationInfo": {
            "created": timestamp,
            "creators": ["Tool: kubesentinel-sbom-engine-1.0.0"],
        },
        "packages": packages,
    }


def generate_single_sbom(
    app_name: str,
    tag: str,
    output_file: Path,
    format_type: str = "cyclonedx",
) -> dict[str, Any]:
    """Generate SBOM for a single application image using Syft, Trivy, or Python fallback."""
    image_tag = f"{app_name}:{tag}"
    scanner_type, scanner_bin = find_scanner()
    generated = False
    generator_used = "python-fallback"

    output_file.parent.mkdir(parents=True, exist_ok=True)

    if scanner_type == "syft" and scanner_bin:
        fmt_flag = "cyclonedx-json" if format_type == "cyclonedx" else "spdx-json"
        cmd = [scanner_bin, "packages", image_tag, "-o", f"{fmt_flag}={output_file}"]
        print(f"--> Generating {format_type} SBOM with Syft: {image_tag} -> {output_file.name}")
        res = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=60)
        if res.returncode == 0 and output_file.is_file() and output_file.stat().st_size > 0:
            generated = True
            generator_used = "syft"

    if not generated and scanner_type == "trivy" and scanner_bin:
        fmt_flag = "cyclonedx" if format_type == "cyclonedx" else "spdx-json"
        cmd = [
            scanner_bin,
            "image",
            "--format",
            fmt_flag,
            "--offline-scan",
            "--skip-db-update",
            "--skip-check-update",
            "--output",
            str(output_file),
            image_tag,
        ]
        print(f"--> Generating {format_type} SBOM with Trivy: {image_tag} -> {output_file.name}")
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=60)
            if res.returncode == 0 and output_file.is_file() and output_file.stat().st_size > 0:
                generated = True
                generator_used = "trivy"
        except (subprocess.SubprocessError, OSError) as e:
            print(f"Note: Trivy scan encountered exception: {e}", file=sys.stderr)

    if not generated:
        print(f"--> Generating {format_type} SBOM with Python fallback for {image_tag}...")
        spec = IMAGE_SPECS.get(app_name, {})
        req_file = ROOT / spec.get("req_file", f"apps/{app_name}/requirements.txt")
        if format_type == "cyclonedx":
            sbom_data = _generate_python_fallback_cyclonedx(app_name, tag, req_file)
        else:
            sbom_data = _generate_python_fallback_spdx(app_name, tag, req_file)

        output_file.write_text(json.dumps(sbom_data, indent=2), encoding="utf-8")
        generator_used = "python-fallback"

    # Count packages/components
    count = 0
    try:
        data = json.loads(output_file.read_text(encoding="utf-8"))
        if format_type == "cyclonedx":
            count = len(data.get("components", []))
        else:
            count = len(data.get("packages", []))
    except (json.JSONDecodeError, OSError):
        pass

    sha256 = compute_sha256(output_file)

    return {
        "app": app_name,
        "image": image_tag,
        "output_file": output_file.name,
        "output_path": str(output_file),
        "format": format_type,
        "generator": generator_used,
        "component_count": count,
        "sha256": sha256,
    }


def generate_all_sboms(
    output_dir: Path | None = None,
    format_type: str = "cyclonedx",
    build_first: bool = False,
    tag: str = DEFAULT_TAG,
    as_json: bool = False,
) -> int:
    """Generate SBOMs for edge-api and edge-worker with SHA-256 checksums and metadata."""
    if output_dir is None:
        output_dir = DEFAULT_SBOM_DIR
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if build_first:
        build_rc = build_images(tag=tag)
        if build_rc != 0:
            return build_rc

    results: list[dict[str, Any]] = []
    ext = "json"

    for app_name in ("edge-api", "edge-worker"):
        target_file = output_dir / f"{app_name}-sbom.{ext}"
        res = generate_single_sbom(app_name, tag, target_file, format_type=format_type)
        results.append(res)

    total_components = sum(r["component_count"] for r in results)
    timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    metadata = {
        "generated_at": timestamp,
        "format": format_type,
        "tag": tag,
        "total_components": total_components,
        "artifacts": {r["app"]: r for r in results},
    }

    meta_file = output_dir / "metadata.json"
    meta_file.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    meta_sha256 = compute_sha256(meta_file)

    checksums_file = output_dir / "checksums.sha256"
    checksum_lines = [f"{r['sha256']}  {r['output_file']}" for r in results]
    checksum_lines.append(f"{meta_sha256}  {meta_file.name}")
    checksums_file.write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")

    if as_json:
        print(json.dumps(metadata, indent=2))
        return 0

    print("\n" + "=" * 70)
    print(" KubeSentinel Supply Chain: SBOM Generation Report")
    print("=" * 70)
    print(f"Output Directory: {output_dir}")
    print(f"Format:           {format_type}")
    print(f"Tag:              {tag}")
    print(f"Timestamp (UTC):  {timestamp}")
    print("-" * 70)
    for r in results:
        print(f"  [{r['generator'].upper()}] {r['image']}")
        print(f"       File:       {r['output_file']}")
        print(f"       Components: {r['component_count']}")
        print(f"       SHA-256:    {r['sha256']}")
    print("-" * 70)
    print(f"Checksums Manifest: {checksums_file.name}")
    print(f"Total Components:   {total_components}")
    print("=" * 70 + "\n")

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="KubeSentinel Image Build and SBOM Generator")
    parser.add_argument(
        "--format",
        choices=["cyclonedx", "spdx-json"],
        default="cyclonedx",
        help="SBOM output format (default: cyclonedx)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_SBOM_DIR,
        help="Output directory for SBOM artifacts (default: artifacts/sbom)",
    )
    parser.add_argument(
        "--build",
        action="store_true",
        help="Build container images before generating SBOMs",
    )
    parser.add_argument(
        "--tag",
        default=DEFAULT_TAG,
        help=f"Image version tag to build/scan (default: {DEFAULT_TAG})",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit summary as JSON",
    )
    args = parser.parse_args(argv)

    return generate_all_sboms(
        output_dir=args.output_dir,
        format_type=args.format,
        build_first=args.build,
        tag=args.tag,
        as_json=args.json,
    )


if __name__ == "__main__":
    sys.exit(main())
