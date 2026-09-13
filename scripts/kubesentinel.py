"""Canonical KubeSentinel CLI."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def run_detection_validate(as_json: bool = False, check_es: bool = True) -> int:
    """Validate detection rules, schema, fields, live ES queries, and tuning study artifacts."""
    from detections.elastic.validator import execute_es_query, validate_detections

    passed_detections, detection_results = validate_detections(check_es=check_es)

    tuning_dir = ROOT / "docs" / "detection-tuning"
    metrics_file = tuning_dir / "tuning_metrics.json"
    study_doc = tuning_dir / "shell-detection.md"

    tuning_result: dict[str, Any] = {
        "artifact": "tuning_metrics.json",
        "valid": False,
        "metrics": {},
        "es_valid": not check_es,
        "errors": [],
    }

    doc_result: dict[str, Any] = {
        "artifact": "shell-detection.md",
        "valid": False,
        "errors": [],
    }

    if not metrics_file.is_file():
        tuning_result["errors"].append(f"Tuning metrics file not found: {metrics_file}")
    else:
        try:
            data = json.loads(metrics_file.read_text(encoding="utf-8"))
            required_keys = [
                "v1_query",
                "v2_query",
                "total_v1_events",
                "total_v2_events",
                "total_controlled_scenarios",
                "controlled_scenarios_retained_by_v2",
                "controlled_retention_rate_pct",
                "total_benign_maintenance_events",
                "benign_maintenance_suppressed_by_v2",
                "benign_suppression_rate_pct",
                "lab_noise_reduction_pct",
                "overall_candidate_reduction_pct",
            ]
            missing_keys = [k for k in required_keys if k not in data]
            if missing_keys:
                tuning_result["errors"].append(f"Missing required tuning keys: {missing_keys}")
            else:
                tuning_result["valid"] = True
                tuning_result["metrics"] = data

                if check_es:
                    try:
                        v1_code, _ = execute_es_query("kubesentinel-falco-*", data["v1_query"])
                        v2_code, _ = execute_es_query("kubesentinel-falco-*", data["v2_query"])
                        if v1_code == 200 and v2_code == 200:
                            tuning_result["es_valid"] = True
                        else:
                            tuning_result["errors"].append(
                                f"Tuning ES queries failed: V1 HTTP {v1_code}, V2 HTTP {v2_code}"
                            )
                    except (subprocess.SubprocessError, OSError, TimeoutError, RuntimeError) as err:
                        tuning_result["errors"].append(f"Tuning ES query exception: {err}")
        except (json.JSONDecodeError, OSError, KeyError, TypeError, ValueError) as err:
            tuning_result["errors"].append(f"Failed to parse tuning_metrics.json: {err}")

    if not study_doc.is_file():
        doc_result["errors"].append(f"Tuning study doc not found: {study_doc}")
    else:
        content = study_doc.read_text(encoding="utf-8")
        if len(content.strip()) < 200:
            doc_result["errors"].append("Tuning study doc is empty or truncated")
        else:
            doc_result["valid"] = True

    tuning_passed = (
        tuning_result["valid"]
        and (tuning_result["es_valid"] or not check_es)
        and doc_result["valid"]
    )
    overall_passed = passed_detections and tuning_passed

    if as_json:
        payload = {
            "passed": overall_passed,
            "detections": detection_results,
            "tuning_metrics": tuning_result,
            "tuning_documentation": doc_result,
        }
        print(json.dumps(payload, indent=2))
        return 0 if overall_passed else 1

    print("=" * 65)
    print(" KubeSentinel Milestone F: Detection & Tuning Validator")
    print("=" * 65)

    print(f"\nDetection Rules ({len(detection_results)} rules):")
    for r in detection_results:
        status = "PASS" if not r["errors"] else "FAIL"
        print(f"\n  [{status}] {r['rule_file']} ({r['rule_id']})")
        print(f"         Schema: {'VALID' if r['schema_valid'] else 'INVALID'}")
        print(f"         Fields: {'VALID' if r['fields_valid'] else 'INVALID'}")
        if check_es:
            print(f"         Query Execution: {'PASS' if r['es_valid'] else 'FAIL'} ({r['es_hits']} live hits)")
        if r["errors"]:
            for err in r["errors"]:
                print(f"         ERROR: {err}")

    print("\nTuning Study Artifacts:")
    m_status = "PASS" if tuning_result["valid"] and tuning_result.get("es_valid", True) else "FAIL"
    print(f"\n  [{m_status}] docs/detection-tuning/tuning_metrics.json")
    if tuning_result["valid"]:
        m = tuning_result["metrics"]
        print(f"         Controlled Retention: {m.get('controlled_retention_rate_pct')}% ({m.get('controlled_scenarios_retained_by_v2')}/{m.get('total_controlled_scenarios')} retained)")
        print(f"         Benign Suppression: {m.get('benign_suppression_rate_pct')}% ({m.get('benign_maintenance_suppressed_by_v2')}/{m.get('total_benign_maintenance_events')} suppressed)")
        print(f"         Lab Noise Reduction: {m.get('lab_noise_reduction_pct')}% (Overall Reduction: {m.get('overall_candidate_reduction_pct')}%)")
        if check_es:
            print(f"         Live V1/V2 Query Execution: {'PASS' if tuning_result['es_valid'] else 'FAIL'}")
    if tuning_result["errors"]:
        for err in tuning_result["errors"]:
            print(f"         ERROR: {err}")

    d_status = "PASS" if doc_result["valid"] else "FAIL"
    print(f"\n  [{d_status}] docs/detection-tuning/shell-detection.md")
    if doc_result["errors"]:
        for err in doc_result["errors"]:
            print(f"         ERROR: {err}")

    total_checks = len(detection_results) + 2
    passed_checks = (
        sum(1 for r in detection_results if not r["errors"])
        + (1 if m_status == "PASS" else 0)
        + (1 if d_status == "PASS" else 0)
    )

    print("\n" + "-" * 65)
    print(f"Summary: Total={total_checks} PASS={passed_checks} FAIL={total_checks - passed_checks}")
    print("-" * 65 + "\n")

    return 0 if overall_passed else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="kubesentinel")
    subcommands = parser.add_subparsers(dest="command", required=True)
    doctor_parser = subcommands.add_parser("doctor")
    doctor_parser.add_argument("--json", action="store_true")
    bootstrap_parser = subcommands.add_parser("bootstrap-local")
    bootstrap_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing .env.local and users.acl credentials",
    )
    compose_up_parser = subcommands.add_parser("compose-up")
    compose_up_parser.add_argument(
        "--build",
        action="store_true",
        help="Build container images before starting",
    )
    compose_up_parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Timeout in seconds to wait for services to become ready (default: 30)",
    )

    compose_down_parser = subcommands.add_parser("compose-down")
    compose_down_parser.add_argument(
        "-v",
        "--volumes",
        action="store_true",
        default=True,
        help="Remove named volumes declared in the volumes section (default: True)",
    )
    compose_down_parser.add_argument(
        "--no-volumes",
        action="store_false",
        dest="volumes",
        help="Do not remove volumes",
    )

    smoke_parser = subcommands.add_parser("smoke")
    smoke_parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Timeout in seconds for smoke test verification (default: 30)",
    )

    cluster_create_parser = subcommands.add_parser("cluster-create")
    cluster_create_parser.add_argument(
        "--no-import",
        action="store_false",
        dest="import_images",
        help="Do not import local container images into the cluster",
    )
    subcommands.add_parser("cluster-start")
    subcommands.add_parser("cluster-stop")
    subcommands.add_parser("cluster-delete")

    k8s_deploy_parser = subcommands.add_parser("k8s-deploy")
    k8s_deploy_parser.add_argument(
        "--timeout",
        type=int,
        default=120,
        help="Timeout in seconds for deployment readiness (default: 120)",
    )

    k8s_validate_parser = subcommands.add_parser("k8s-validate")
    k8s_validate_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit validation results as JSON",
    )

    k8s_smoke_parser = subcommands.add_parser("k8s-smoke")
    k8s_smoke_parser.add_argument(
        "--timeout",
        type=int,
        default=45,
        help="Timeout in seconds for multi-site smoke verification (default: 45)",
    )

    network_validate_parser = subcommands.add_parser("network-validate")
    network_validate_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit validation results as JSON",
    )

    kyverno_validate_parser = subcommands.add_parser("kyverno-validate")
    kyverno_validate_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit validation results as JSON",
    )

    obs_deploy_parser = subcommands.add_parser("observability-deploy")
    obs_deploy_parser.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="Timeout in seconds for observability deployment readiness (default: 180)",
    )

    obs_validate_parser = subcommands.add_parser("observability-validate")
    obs_validate_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit validation results as JSON",
    )

    telemetry_smoke_parser = subcommands.add_parser("telemetry-smoke")
    telemetry_smoke_parser.add_argument(
        "--timeout",
        type=int,
        default=45,
        help="Timeout in seconds for telemetry smoke verification (default: 45)",
    )

    falco_validate_parser = subcommands.add_parser("falco-validate")
    falco_validate_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit validation results as JSON",
    )

    simulate_parser = subcommands.add_parser("simulate")
    simulate_parser.add_argument(
        "scenario",
        nargs="?",
        default="all",
        choices=[
            "shell",
            "redis-unauthorized",
            "rbac-denial",
            "insecure-deployment",
            "lateral-access",
            "all",
        ],
        help="Scenario to execute (default: all)",
    )
    simulate_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit simulation results as machine-readable JSON",
    )
    simulate_parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Timeout in seconds per scenario (default: 30.0)",
    )

    detection_validate_parser = subcommands.add_parser("detection-validate")
    detection_validate_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit validation results as JSON",
    )
    detection_validate_parser.add_argument(
        "--no-es",
        action="store_true",
        help="Skip live Elasticsearch query execution",
    )

    setup_parser = subcommands.add_parser(
        "setup",
        help="Canonical idempotent cluster, workload, and policy setup",
    )
    setup_parser.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="Timeout in seconds for deployment and pod readiness (default: 180)",
    )
    setup_parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip rebuilding container images if already built",
    )
    setup_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit setup summary as JSON",
    )

    teardown_parser = subcommands.add_parser(
        "teardown",
        help="Canonical safe teardown and resource cleanup",
    )
    teardown_parser.add_argument(
        "--purge-secrets",
        action="store_true",
        help="Purge local secrets (.env.local, users.acl) instead of retaining them",
    )
    teardown_parser.add_argument(
        "--keep-cluster",
        action="store_true",
        help="Stop k3d cluster rather than deleting it",
    )
    teardown_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit teardown summary as JSON",
    )

    build_images_parser = subcommands.add_parser(
        "build-images",
        help="Build container images for edge-api and edge-worker",
    )
    build_images_parser.add_argument(
        "--tag",
        default="1.0.0",
        help="Version tag to apply to built images (default: 1.0.0)",
    )
    build_images_parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Build images without using Docker layer cache",
    )

    sbom_parser = subcommands.add_parser(
        "sbom",
        help="Generate Software Bill of Materials (SBOM) for application images",
    )
    sbom_parser.add_argument(
        "--format",
        choices=["cyclonedx", "spdx-json"],
        default="cyclonedx",
        help="SBOM format (default: cyclonedx)",
    )
    sbom_parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "artifacts" / "sbom",
        help="Output directory for SBOMs (default: artifacts/sbom)",
    )
    sbom_parser.add_argument(
        "--build",
        action="store_true",
        help="Build images before generating SBOMs",
    )
    sbom_parser.add_argument(
        "--tag",
        default="1.0.0",
        help="Image tag to scan (default: 1.0.0)",
    )
    sbom_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit summary as JSON",
    )

    subcommands.add_parser(
        "demo",
        help="Run canonical 8-step interactive demonstration",
    )

    for name in ("test", "lint", "serve"):
        subcommands.add_parser(name)

    args = parser.parse_args(argv)
    if args.command == "doctor":
        from scripts.validate.doctor import main as doctor_main

        return doctor_main(["--json"] if args.json else [])

    if args.command == "bootstrap-local":
        from scripts.bootstrap import bootstrap_local

        return bootstrap_local(root_dir=ROOT, force=args.force)

    if args.command == "compose-up":
        from scripts.compose import compose_up

        return compose_up(root_dir=ROOT, build=args.build, timeout_sec=args.timeout)

    if args.command == "compose-down":
        from scripts.compose import compose_down

        return compose_down(root_dir=ROOT, volumes=args.volumes)

    if args.command == "smoke":
        from scripts.smoke import run_smoke

        return run_smoke(root_dir=ROOT, timeout_sec=args.timeout)

    if args.command == "cluster-create":
        from scripts.cluster import cluster_create

        return cluster_create(import_images=args.import_images)

    if args.command == "cluster-start":
        from scripts.cluster import cluster_start

        return cluster_start()

    if args.command == "cluster-stop":
        from scripts.cluster import cluster_stop

        return cluster_stop()

    if args.command == "cluster-delete":
        from scripts.cluster import cluster_delete

        return cluster_delete()

    if args.command == "k8s-deploy":
        from scripts.k8s_deploy import k8s_deploy

        return k8s_deploy(timeout_sec=args.timeout)

    if args.command == "k8s-validate":
        from scripts.k8s_validate import run_k8s_validate

        return run_k8s_validate(as_json=args.json)

    if args.command == "k8s-smoke":
        from scripts.k8s_smoke import run_k8s_smoke

        return run_k8s_smoke(timeout_sec=args.timeout)

    if args.command == "network-validate":
        from scripts.network_validate import main as network_validate_main

        return network_validate_main(["--json"] if args.json else [])

    if args.command == "kyverno-validate":
        from scripts.kyverno_validate import main as kyverno_validate_main

        return kyverno_validate_main(["--json"] if args.json else [])

    if args.command == "observability-deploy":
        from scripts.observability_deploy import observability_deploy

        return observability_deploy(timeout_sec=args.timeout)

    if args.command == "observability-validate":
        from scripts.observability_validate import run_observability_validate

        return run_observability_validate(as_json=args.json)

    if args.command == "telemetry-smoke":
        from scripts.telemetry_smoke import run_telemetry_smoke

        return run_telemetry_smoke(timeout_sec=args.timeout)

    if args.command == "falco-validate":
        from scripts.falco_validate import run_falco_validate

        return run_falco_validate(as_json=args.json)

    if args.command == "simulate":
        from simulations.runner import run_all_simulations, run_simulation

        scenario = args.scenario
        if scenario == "all":
            results = run_all_simulations(timeout_sec=args.timeout)
        else:
            results = [run_simulation(scenario, timeout_sec=args.timeout)]

        if args.json:
            print(json.dumps([r.to_dict() for r in results], indent=2))
        else:
            print("\n=======================================================")
            print(" KubeSentinel Milestone F: Controlled Simulations")
            print("=======================================================\n")
            for r in results:
                tag = f"[{r.status}]".ljust(8)
                scen = r.scenario.ljust(22)
                ctrl = f"({r.control_type})".ljust(14)
                print(f"{tag} {scen} {ctrl} {r.summary} ({r.duration_sec}s)")

            total = len(results)
            passed = sum(1 for r in results if r.status == "PASS")
            failed = sum(1 for r in results if r.status == "FAIL")
            print(f"\nSummary: Total={total} PASS={passed} FAIL={failed}\n")

        return 1 if any(r.status == "FAIL" for r in results) else 0

    if args.command == "detection-validate":
        return run_detection_validate(as_json=args.json, check_es=not args.no_es)

    if args.command == "setup":
        from scripts.lifecycle import run_setup

        return run_setup(timeout_sec=args.timeout, skip_build=args.skip_build, as_json=args.json)

    if args.command == "teardown":
        from scripts.lifecycle import run_teardown

        return run_teardown(purge_secrets=args.purge_secrets, keep_cluster=args.keep_cluster, as_json=args.json)

    if args.command == "build-images":
        from scripts.sbom import build_images

        return build_images(tag=args.tag, no_cache=args.no_cache)

    if args.command == "sbom":
        from scripts.sbom import generate_all_sboms

        return generate_all_sboms(
            output_dir=args.output_dir,
            format_type=args.format,
            build_first=args.build,
            tag=args.tag,
            as_json=args.json,
        )

    if args.command == "demo":
        from scripts.demo import run_demo

        return run_demo(args)

    commands = {
        "test": [sys.executable, "-m", "pytest"],
        "lint": [sys.executable, "-m", "ruff", "check", "."],
        "serve": [
            sys.executable,
            "-m",
            "uvicorn",
            "edge_api.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            "8000",
        ],
    }
    return subprocess.run(commands[args.command], cwd=ROOT, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
