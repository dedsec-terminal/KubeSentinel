"""Generate controlled benign diagnostic/maintenance activity in edge workloads.

Demonstrates that broad baseline detection (V1) creates alert fatigue by flagging
routine maintenance commands, while tuned detection (V2) successfully suppresses them.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

TUNING_DIR = Path(__file__).resolve().parent
if str(TUNING_DIR) not in sys.path:
    sys.path.insert(0, str(TUNING_DIR))

from eval_tuning import generate_benign_maintenance_event

BENIGN_COMMANDS = [
    ("edge-pune", "echo kubesentinel-diag-maintenance-netprobe"),
    ("edge-pune", "echo kubesentinel-diag-maintenance-storage-check"),
    ("edge-pune", "echo kubesentinel-healthcheck-probe-liveness"),
    ("edge-mumbai", "echo kubesentinel-diag-maintenance-cpu-audit"),
    ("edge-mumbai", "echo kubesentinel-healthcheck-probe-readiness"),
    ("edge-bangalore", "echo kubesentinel-diag-maintenance-sync-verify"),
    ("edge-bangalore", "echo kubesentinel-healthcheck-probe-status"),
    ("edge-bangalore", "echo kubesentinel-diag-maintenance-memory-audit"),
]


def generate_all_benign_events() -> list[dict]:
    results = []
    print(f"Generating {len(BENIGN_COMMANDS)} controlled benign maintenance events...")
    for ns, cmd in BENIGN_COMMANDS:
        print(f"--> Triggering benign diagnostic in {ns}: {cmd}...")
        res = generate_benign_maintenance_event(namespace=ns, command_pattern=cmd, timeout_sec=25.0)
        print(f"    [INGESTED] doc_id: {res['doc_id']} (took {res['elapsed_sec']}s)")
        results.append(res)
        time.sleep(1.0)
    print(f"All {len(results)} benign maintenance events successfully generated and indexed.")
    return results


if __name__ == "__main__":
    generated = generate_all_benign_events()
    print(f"Summary: Generated {len(generated)} events.")
