"""Generate a MITRE ATT&CK Navigator JSON layer from KubeSentinel detection rules."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from detections.elastic.validator import RULES_DIR, parse_yaml

STATUS_COLORS = {
    "production": "#1b7f3a",
    "validated": "#2ea043",
    "experimental": "#d29922",
    "hunting": "#1f6feb",
}


def build_attack_layer(rules_dir: Path = RULES_DIR) -> dict[str, Any]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for rf in sorted(rules_dir.glob("*.yaml")):
        rule = parse_yaml(rf.read_text(encoding="utf-8"))
        status = rule.get("status", "experimental")
        score = 100 if status in ("production", "validated") else 50
        comment = f"{rule['id']} ({status}): {rule['name']}"
        for mapping in rule.get("mitre_attack", []):
            key = (mapping["technique_id"], mapping["tactic"])
            if key not in merged:
                merged[key] = {
                    "techniqueID": mapping["technique_id"],
                    "tactic": mapping["tactic"],
                    "color": STATUS_COLORS.get(status, "#6e7681"),
                    "score": score,
                    "comment": comment,
                    "enabled": True,
                    "metadata": [{"name": "rule_id", "value": rule["id"]}, {"name": "status", "value": status}],
                }
            else:
                entry = merged[key]
                if score > entry["score"]:
                    entry["score"] = score
                    entry["color"] = STATUS_COLORS.get(status, entry["color"])
                entry["comment"] += f" | {comment}"
                entry["metadata"].extend([
                    {"name": "rule_id", "value": rule["id"]},
                    {"name": "status", "value": status},
                ])
    return {
        "name": "KubeSentinel Lab Detections",
        "versions": {"attack": "15", "navigator": "5.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "MITRE ATT&CK techniques evidenced by KubeSentinel detection rules (controlled local-lab scope).",
        "techniques": list(merged.values()),
        "legendItems": [
            {"label": "Production", "color": STATUS_COLORS["production"]},
            {"label": "Validated lab rule", "color": STATUS_COLORS["validated"]},
            {"label": "Experimental", "color": STATUS_COLORS["experimental"]},
            {"label": "Hunting", "color": STATUS_COLORS["hunting"]},
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Exit non-zero if committed layer differs.")
    args = parser.parse_args()
    layer = build_attack_layer()
    rendered = json.dumps(layer, indent=2) + "\n"
    out_path = RULES_DIR.parent / "attack-navigator-layer.json"
    if args.check:
        if not out_path.is_file() or out_path.read_text(encoding="utf-8") != rendered:
            print(f"[ERROR] {out_path} is out of date; run generate_attack_layer.py.", file=sys.stderr)
            return 1
        print(f"OK: {out_path.name} matches rules ({len(layer['techniques'])} technique(s)).")
        return 0
    out_path.write_text(rendered, encoding="utf-8")
    print(f"Wrote {out_path} ({len(layer['techniques'])} mapped technique(s)).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
