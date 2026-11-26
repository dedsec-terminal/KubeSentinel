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
CORPUS_PATH = DETECTIONS_DIR / "fixtures" / "corpus.json"
SUPPORTED_LANGUAGES = {"lucene"}


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
    """Extract documented Elasticsearch field paths (and .keyword subfields) from FIELDS.md tables."""
    if not FIELDS_PATH.is_file():
        raise FileNotFoundError(f"FIELDS.md not found: {FIELDS_PATH}")

    content = FIELDS_PATH.read_text(encoding="utf-8")
    fields: set[str] = set()
    row_re = re.compile(r"^\|\s*`([@a-zA-Z0-9_.-]+)`\s*\|\s*([^|]+)\|")
    for line in content.splitlines():
        m = row_re.match(line.strip())
        if not m:
            continue
        field_name = m.group(1).strip()
        field_type = m.group(2).strip()
        fields.add(field_name)
        if ".keyword" in field_type and not field_name.endswith(".keyword"):
            fields.add(f"{field_name}.keyword")
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
                "default_operator": "AND",
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


def evaluate_rule_corpus(rule_data: dict[str, Any], corpus: dict[str, Any]) -> dict[str, Any]:
    """Evaluate a supported Lucene rule against its labeled positive/negative corpus fixtures."""
    from detections.elastic.lucene_eval import UnsupportedQueryError, evaluate_lucene

    rule_id = rule_data.get("id", "")
    lang = rule_data.get("language", "")
    entry = corpus.get("rules", {}).get(rule_id)
    if lang not in SUPPORTED_LANGUAGES:
        return {"status": "failed", "corpus_size": 0, "errors": [f"Unsupported query language {lang!r}; supported: {sorted(SUPPORTED_LANGUAGES)}"]}
    if not isinstance(entry, dict):
        return {"status": "failed", "corpus_size": 0, "errors": [f"Rule {rule_id!r} has no fixtures in labeled corpus."]}

    must_match = entry.get("must_match", [])
    must_not_match = entry.get("must_not_match", [])
    if not must_match or not must_not_match:
        return {
            "status": "failed",
            "corpus_size": len(must_match) + len(must_not_match),
            "errors": [f"Rule {rule_id!r} must declare at least 1 must_match and 1 must_not_match fixture."],
        }
    errors: list[str] = []
    query = rule_data.get("query", "")
    try:
        for case in must_match:
            if not evaluate_lucene(query, case["doc"]):
                errors.append(f"Fixture {case['fixture_id']!r} expected match but did not match.")
        for case in must_not_match:
            if evaluate_lucene(query, case["doc"]):
                errors.append(f"Fixture {case['fixture_id']!r} expected exclusion but matched.")
    except UnsupportedQueryError as exc:
        errors.append(f"Offline Lucene evaluator rejected query: {exc}")
    return {
        "status": "failed" if errors else "passed",
        "corpus_size": len(must_match) + len(must_not_match),
        "errors": errors,
    }


def validate_detections(
    check_es: bool = True,
) -> tuple[bool, list[dict[str, Any]]]:
    """Validate all detection rules in detections/elastic/rules/ against schema, FIELDS.md, fixtures, and ES."""
    schema = load_schema()
    catalog_fields = load_fields_catalog()
    if not CORPUS_PATH.is_file():
        raise FileNotFoundError(f"Labeled detection corpus not found: {CORPUS_PATH}")
    corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
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
            "fixture_status": "skipped",
            "corpus_size": 0,
            "es_status": "skipped" if not check_es else "failed",
            "es_valid": None if not check_es else False,
            "es_hits": None if not check_es else 0,
            "errors": [],
        }

        try:
            content = rule_file.read_text(encoding="utf-8")
            rule_data = parse_yaml(content)
            rule_result["rule_id"] = rule_data.get("id", rule_file.stem)

            # 1. Schema validation
            jsonschema.validate(instance=rule_data, schema=schema)
            if rule_data.get("language") not in SUPPORTED_LANGUAGES:
                raise ValueError(
                    f"Unsupported query language {rule_data.get('language')!r}; supported: {sorted(SUPPORTED_LANGUAGES)}"
                )
            rule_result["schema_valid"] = True
        except jsonschema.ValidationError as ve:
            rule_result["errors"].append(f"Schema validation error: {ve.message}")
            all_passed = False
        except (ValueError, KeyError, TypeError, OSError) as e:
            rule_result["errors"].append(f"YAML/language validation error: {e}")
            all_passed = False

        # 2. Required fields and query fields validation against FIELDS.md
        if rule_result["schema_valid"]:
            from detections.elastic.lucene_eval import UnsupportedQueryError, _tokenize

            req_fields = rule_data.get("required_fields", [])
            missing_fields = [rf for rf in req_fields if rf not in catalog_fields]
            try:
                query_tokens = _tokenize(rule_data.get("query", ""))
                query_fields = sorted({
                    tok.split(":", 1)[0]
                    for tok in query_tokens
                    if ":" in tok and not tok.startswith('"')
                })
                undoc_query_fields = [qf for qf in query_fields if qf not in catalog_fields]
                syntax_error = None
            except UnsupportedQueryError as syn_exc:
                undoc_query_fields = []
                syntax_error = str(syn_exc)

            if missing_fields or undoc_query_fields or syntax_error:
                if missing_fields:
                    rule_result["errors"].append(
                        f"Required fields not documented in FIELDS.md: {missing_fields}"
                    )
                if undoc_query_fields:
                    rule_result["errors"].append(
                        f"Query fields not documented in FIELDS.md: {undoc_query_fields}"
                    )
                if syntax_error:
                    rule_result["errors"].append(f"Query syntax error: {syntax_error}")
                all_passed = False
            else:
                rule_result["fields_valid"] = True

            # 2b. Labeled offline corpus validation (always required)
            fx = evaluate_rule_corpus(rule_data, corpus)
            rule_result["fixture_status"] = fx["status"]
            rule_result["corpus_size"] = fx["corpus_size"]
            if fx["errors"]:
                rule_result["errors"].extend(fx["errors"])
                all_passed = False

        # 3. Live Elasticsearch query execution
        if check_es and rule_result["schema_valid"]:
            idx = rule_data.get("index", "")
            q = rule_data.get("query", "")
            try:
                code, resp = execute_es_query(idx, q)
                if code == 200 and isinstance(resp, dict):
                    shards = resp.get("_shards")
                    hits_obj = resp.get("hits")
                    shards_ok = (
                        isinstance(shards, dict)
                        and isinstance(shards.get("total"), int)
                        and not isinstance(shards.get("total"), bool)
                        and shards["total"] > 0
                        and isinstance(shards.get("successful"), int)
                        and not isinstance(shards.get("successful"), bool)
                        and shards["successful"] == shards["total"]
                        and isinstance(shards.get("failed"), int)
                        and not isinstance(shards.get("failed"), bool)
                        and shards["failed"] == 0
                    )
                    total_obj = hits_obj.get("total") if isinstance(hits_obj, dict) else None
                    if isinstance(total_obj, dict):
                        total_val = total_obj.get("value")
                        hits_ok = (
                            isinstance(total_val, int)
                            and not isinstance(total_val, bool)
                            and total_val >= 0
                            and total_obj.get("relation") in ("eq", "gte")
                        )
                        hit_count = total_val
                    else:
                        hits_ok = isinstance(total_obj, int) and not isinstance(total_obj, bool) and total_obj >= 0
                        hit_count = total_obj

                    if resp.get("timed_out") is False and resp.get("terminated_early") is not True and shards_ok and hits_ok:
                        rule_result["es_valid"] = True
                        rule_result["es_status"] = "passed"
                        rule_result["es_hits"] = hit_count
                    else:
                        rule_result["errors"].append(
                            f"Elasticsearch query returned partial or malformed response: timed_out={resp.get('timed_out')!r}, _shards={shards!r}"
                        )
                        all_passed = False
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
    as_json = "--json" in sys.argv
    try:
        passed, results = validate_detections(check_es=check_es)
    except (FileNotFoundError, jsonschema.SchemaError, RuntimeError) as e:
        if as_json:
            print(json.dumps({"passed": False, "error": str(e)}, indent=2))
        else:
            print(f"[FATAL] Validator failed to initialize: {e}")
        return 1

    if as_json:
        print(json.dumps({"passed": passed, "results": results}, indent=2))
        return 0 if passed else 1

    print("=" * 65)
    print(" KubeSentinel Milestone F: Elastic Detection Content Validator")
    print("=" * 65)
    print(f"\nDiscovered {len(results)} detection rule(s):")
    for r in results:
        status = "PASS" if not r["errors"] else "FAIL"
        print(f"\n  [{status}] {r['rule_file']} ({r['rule_id']})")
        print(f"         Schema: {'VALID' if r['schema_valid'] else 'INVALID'}")
        print(f"         Fields: {'VALID' if r['fields_valid'] else 'INVALID'}")
        print(f"         Corpus: {r['fixture_status'].upper()} ({r['corpus_size']} synthetic doc(s))")
        print(f"         Query Execution: {r['es_status'].upper()}" + (f" ({r['es_hits']} live hits)" if r["es_hits"] is not None else ""))
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
