"""Validation module for KubeSentinel Elasticsearch detection rules.

Validates detection YAML files against schema.json, checks required fields against FIELDS.md,
and executes queries against live Elasticsearch to verify query syntax and zero-error execution.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import jsonschema

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DETECTIONS_DIR = ROOT / "detections" / "elastic"
SCHEMA_PATH = DETECTIONS_DIR / "schema.json"
RULES_DIR = DETECTIONS_DIR / "rules"
FIELDS_PATH = DETECTIONS_DIR / "FIELDS.md"


def parse_yaml(text: str) -> dict[str, Any]:
    """Parse detection rule YAML into a dictionary.

    Uses PyYAML if available; otherwise falls back to a clean built-in parser
    designed specifically for KubeSentinel detection definition structures.
    """
    try:
        import yaml  # type: ignore[import-not-found]

        return yaml.safe_load(text)
    except ImportError:
        pass

    lines = text.splitlines()
    data: dict[str, Any] = {}
    i = 0

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue

        m = re.match(r"^([a-zA-Z0-9_-]+):\s*(.*)$", line)
        if m:
            key = m.group(1)
            rest = m.group(2).strip()

            # Handle block scalars (folded '>' or literal '|')
            if rest in ("|", ">", "|-", ">-", "|+", ">+"):
                block_mode = rest
                block_lines: list[str] = []
                i += 1
                while i < len(lines):
                    sub_line = lines[i]
                    if not sub_line.strip():
                        block_lines.append("")
                        i += 1
                        continue
                    indent = len(sub_line) - len(sub_line.lstrip())
                    if indent >= 2:
                        block_lines.append(sub_line.strip())
                        i += 1
                    else:
                        break

                if ">" in block_mode:
                    data[key] = " ".join(block_lines).strip()
                else:
                    data[key] = "\n".join(block_lines).strip()
                continue

            # Handle list or nested structure
            if not rest:
                i += 1
                items: list[Any] = []
                while i < len(lines):
                    sub_line = lines[i]
                    sub_stripped = sub_line.strip()
                    if not sub_stripped or sub_stripped.startswith("#"):
                        i += 1
                        continue
                    indent = len(sub_line) - len(sub_line.lstrip())
                    if indent < 2:
                        break

                    if sub_stripped.startswith("- "):
                        item_content = sub_stripped[2:].strip()
                        # Check if item is a dictionary entry (e.g. - tactic: execution)
                        if ":" in item_content and not (
                            item_content.startswith(('"', "'")) and item_content.endswith(('"', "'"))
                        ):
                            sub_dict: dict[str, str] = {}
                            k, v = item_content.split(":", 1)
                            sub_dict[k.strip()] = v.strip().strip("\"'")
                            i += 1
                            while i < len(lines):
                                next_line = lines[i]
                                next_stripped = next_line.strip()
                                if not next_stripped or next_stripped.startswith("#"):
                                    i += 1
                                    continue
                                next_indent = len(next_line) - len(next_line.lstrip())
                                if (
                                    next_indent >= 4
                                    and ":" in next_stripped
                                    and not next_stripped.startswith("-")
                                ):
                                    nk, nv = next_stripped.split(":", 1)
                                    sub_dict[nk.strip()] = nv.strip().strip("\"'")
                                    i += 1
                                else:
                                    break
                            items.append(sub_dict)
                            continue
                        else:
                            items.append(item_content.strip("\"'"))
                            i += 1
                    else:
                        break
                data[key] = items
                continue

            # Simple scalar
            val = rest
            if (val.startswith('"') and val.endswith('"')) or (
                val.startswith("'") and val.endswith("'")
            ):
                val = val[1:-1]
            data[key] = val
            i += 1
            continue

        i += 1

    return data


def load_schema() -> dict[str, Any]:
    """Load the detection JSON Schema."""
    if not SCHEMA_PATH.is_file():
        raise FileNotFoundError(f"Schema not found: {SCHEMA_PATH}")
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def load_fields_catalog() -> set[str]:
    """Extract all documented field paths from FIELDS.md."""
    if not FIELDS_PATH.is_file():
        raise FileNotFoundError(f"FIELDS.md not found: {FIELDS_PATH}")

    content = FIELDS_PATH.read_text(encoding="utf-8")
    fields = set()

    # Match fields in table rows: | `field_path` | ...
    table_matches = re.findall(r"\|\s*`([a-zA-Z0-9_.-]+)`\s*\|", content)
    for f in table_matches:
        fields.add(f.strip())

    # Match inline code snippets in markdown
    inline_matches = re.findall(r"`([a-zA-Z0-9_.-]+)`", content)
    for f in inline_matches:
        if "." in f or f in (
            "rule",
            "priority",
            "severity",
            "output",
            "source",
            "tags",
            "time",
            "timestamp",
            "event_id",
            "edge_site",
            "namespace",
            "service",
            "event_type",
            "message",
            "log_type",
            "processing_status",
            "redis_stream_id",
            "worker",
            "processed_at",
            "schema_version",
            "metadata",
        ):
            fields.add(f.strip())

    return fields


def execute_es_query(
    index_pattern: str,
    query_string: str,
    timeout_sec: float = 15.0,
) -> tuple[int, dict[str, Any] | str]:
    """Execute query string against live Elasticsearch via internal cluster execution."""
    from scripts.setup_es_templates import _curl_in_pod, get_es_credentials

    username, password = get_es_credentials()
    payload = {
        "query": {
            "query_string": {
                "query": query_string,
            }
        },
        "size": 5,
    }
    url = f"http://localhost:9200/{index_pattern}/_search"
    return _curl_in_pod(
        namespace="observability",
        deployment="elasticsearch",
        target_url=url,
        method="POST",
        data=payload,
        username=username,
        password=password,
        timeout=timeout_sec,
    )


def validate_detections(
    check_es: bool = True,
) -> tuple[bool, list[dict[str, Any]]]:
    """Validate all detection rules in detections/elastic/rules/ against schema, FIELDS.md, and ES.

    Parameters
    ----------
    check_es : bool
        Whether to execute queries against live Elasticsearch cluster.

    Returns
    -------
    tuple[bool, list[dict[str, Any]]]
        (all_passed, list_of_rule_results)
    """
    schema = load_schema()
    catalog_fields = load_fields_catalog()
    rule_files = sorted(RULES_DIR.glob("*.yaml"))

    if not rule_files:
        return False, [{"error": f"No YAML rules found in {RULES_DIR}"}]

    all_passed = True
    results: list[dict[str, Any]] = []

    for rule_file in rule_files:
        rule_result: dict[str, Any] = {
            "rule_id": "",
            "rule_file": rule_file.name,
            "schema_valid": False,
            "fields_valid": False,
            "es_valid": not check_es,
            "es_hits": 0,
            "errors": [],
        }

        try:
            content = rule_file.read_text(encoding="utf-8")
            rule_data = parse_yaml(content)
            rule_result["rule_id"] = rule_data.get("id", rule_file.stem)

            # 1. Schema validation
            jsonschema.validate(instance=rule_data, schema=schema)
            rule_result["schema_valid"] = True
        except jsonschema.ValidationError as ve:
            rule_result["errors"].append(f"Schema validation error: {ve.message}")
            all_passed = False
        except (ValueError, KeyError, TypeError, OSError) as e:
            rule_result["errors"].append(f"YAML parsing error: {e}")
            all_passed = False

        # 2. Required fields validation against FIELDS.md
        if rule_result["schema_valid"]:
            req_fields = rule_data.get("required_fields", [])
            missing_fields = []
            for rf in req_fields:
                if rf not in catalog_fields:
                    missing_fields.append(rf)

            if missing_fields:
                rule_result["errors"].append(
                    f"Required fields not documented in FIELDS.md: {missing_fields}"
                )
                all_passed = False
            else:
                rule_result["fields_valid"] = True

        # 3. Live Elasticsearch query execution
        if check_es and rule_result["schema_valid"]:
            idx = rule_data.get("index", "")
            q = rule_data.get("query", "")
            try:
                code, resp = execute_es_query(idx, q)
                if code == 200 and isinstance(resp, dict):
                    hits = resp.get("hits", {}).get("total", {})
                    hit_count = hits.get("value", 0) if isinstance(hits, dict) else hits
                    rule_result["es_valid"] = True
                    rule_result["es_hits"] = hit_count
                else:
                    err_msg = (
                        resp.get("error", {}).get("reason", str(resp))
                        if isinstance(resp, dict)
                        else str(resp)
                    )
                    rule_result["errors"].append(
                        f"Elasticsearch query failed (HTTP {code}): {err_msg}"
                    )
                    all_passed = False
            except (subprocess.SubprocessError, OSError, TimeoutError, RuntimeError) as es_err:
                rule_result["errors"].append(f"Elasticsearch execution exception: {es_err}")
                all_passed = False

        results.append(rule_result)

    return all_passed, results


def main() -> int:
    """CLI entrypoint for detection validator."""
    check_es = "--no-es" not in sys.argv
    print("=" * 65)
    print(" KubeSentinel Milestone F: Elastic Detection Content Validator")
    print("=" * 65)

    try:
        passed, results = validate_detections(check_es=check_es)
    except (FileNotFoundError, jsonschema.SchemaError, RuntimeError) as e:
        print(f"[FATAL] Validator failed to initialize: {e}")
        return 1

    print(f"\nDiscovered {len(results)} detection rule(s):")
    for r in results:
        status = "PASS" if not r["errors"] else "FAIL"
        print(f"\n  [{status}] {r['rule_file']} ({r['rule_id']})")
        print(f"         Schema: {'VALID' if r['schema_valid'] else 'INVALID'}")
        print(f"         Fields: {'VALID' if r['fields_valid'] else 'INVALID'}")
        if check_es:
            print(f"         Query Execution: {'PASS' if r['es_valid'] else 'FAIL'} ({r['es_hits']} live hits)")
        if r["errors"]:
            for err in r["errors"]:
                print(f"         ERROR: {err}")

    print("\n" + "-" * 65)
    total = len(results)
    passed_count = sum(1 for r in results if not r["errors"])
    print(f"Summary: Total={total} PASS={passed_count} FAIL={total - passed_count}")
    print("-" * 65)

    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
