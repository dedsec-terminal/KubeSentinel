"""Canonical KubeSentinel CLI."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


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
