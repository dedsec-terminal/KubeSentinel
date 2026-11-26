"""Offline Lucene subset evaluator for KubeSentinel labeled detection fixtures."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

FIELDS_PATH = Path(__file__).resolve().with_name("FIELDS.md")

TOKEN_RE = re.compile(
    r'\s*('
    r'\(|\)'
    r'|\bAND\b|\bOR\b|\bNOT\b'
    r'|[@a-zA-Z0-9_.-]+:"(?:\\.|[^"\\])*"'
    r'|[@a-zA-Z0-9_.-]+:\('
    r'|[@a-zA-Z0-9_.-]+:[^\s()"]+'
    r'|"(?:\\.|[^"\\])*"'
    r'|[^\s()"]+'
    r')'
)


def _load_keyword_fields() -> set[str]:
    """Load documented keyword-mapped fields from FIELDS.md."""
    keywords: set[str] = set()
    if not FIELDS_PATH.is_file():
        return keywords
    row_re = re.compile(r"^\|\s*`([@a-zA-Z0-9_.-]+)`\s*\|\s*([^|]+)\|")
    for line in FIELDS_PATH.read_text(encoding="utf-8").splitlines():
        m = row_re.match(line.strip())
        if not m:
            continue
        fname, ftype = m.group(1).strip(), m.group(2).strip().strip("`").casefold()
        if fname.endswith(".keyword") or ftype.startswith("keyword"):
            keywords.add(fname)
    return keywords


KEYWORD_FIELDS = _load_keyword_fields()


class UnsupportedQueryError(ValueError):
    """Raised when a query uses syntax outside the supported Lucene subset."""


def _lookup_field(doc: dict[str, Any], field_path: str) -> list[Any]:
    """Resolve dotted field paths (supporting Elasticsearch .keyword suffix aliases)."""
    clean_path = field_path.removesuffix(".keyword")
    cur: Any = doc
    for part in clean_path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return []
    if isinstance(cur, list):
        return cur
    return [cur]


def _match_field_value(doc: dict[str, Any], field_path: str, pattern: str) -> bool:
    if field_path == "_exists_":
        raise UnsupportedQueryError("_exists_ operator is outside the supported Lucene subset.")
    values = _lookup_field(doc, field_path)
    if not values:
        return False
    is_quoted = pattern.startswith('"') and pattern.endswith('"')
    raw = pattern[1:-1] if is_quoted else pattern
    if is_quoted:
        raw = raw.replace('\\"', '"').replace('\\\\', '\\')
    case_sensitive = field_path.endswith(".keyword") or field_path in KEYWORD_FIELDS
    if "*" in raw:
        flags = 0 if case_sensitive else re.IGNORECASE
        regex = re.compile("^" + re.escape(raw).replace(r"\*", ".*") + "$", flags)
        return any(bool(regex.match(str(v))) for v in values)
    target = raw if case_sensitive else raw.casefold()
    for v in values:
        sval = str(v) if case_sensitive else str(v).casefold()
        if case_sensitive or is_quoted:
            if sval == target:
                return True
        else:
            if sval == target or target in re.split(r"[^a-z0-9_.-]+", sval):
                return True
    return False


def _tokenize(query: str) -> list[str]:
    pos = 0
    tokens: list[str] = []
    while pos < len(query):
        if query[pos].isspace():
            pos += 1
            continue
        m = TOKEN_RE.match(query, pos)
        if not m:
            raise UnsupportedQueryError(f"Unsupported Lucene syntax near: {query[pos:pos + 24]!r}")
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


def evaluate_lucene(query: str, doc: dict[str, Any]) -> bool:
    """Evaluate a Lucene boolean/field query against a single document."""
    tokens = _tokenize(query)
    idx = 0

    def peek() -> str | None:
        return tokens[idx] if idx < len(tokens) else None

    def consume() -> str:
        nonlocal idx
        tok = tokens[idx]
        idx += 1
        return tok

    def parse_or(scoped_field: str | None = None) -> bool:
        val = parse_and(scoped_field)
        while peek() == "OR":
            consume()
            rhs = parse_and(scoped_field)
            val = val or rhs
        return val

    def parse_and(scoped_field: str | None = None) -> bool:
        val = parse_not(scoped_field)
        while peek() == "AND":
            consume()
            rhs = parse_not(scoped_field)
            val = val and rhs
        return val

    def parse_not(scoped_field: str | None = None) -> bool:
        if peek() == "NOT":
            consume()
            return not parse_not(scoped_field)
        return parse_atom(scoped_field)

    def parse_atom(scoped_field: str | None = None) -> bool:
        tok = peek()
        if tok is None:
            raise UnsupportedQueryError("Unexpected end of query")
        if tok == "(":
            consume()
            val = parse_or(scoped_field)
            if peek() != ")":
                raise UnsupportedQueryError("Unmatched '(' in query")
            consume()
            return val
        if tok.endswith(":("):
            consume()
            field = tok[:-2]
            val = parse_or(field)
            if peek() != ")":
                raise UnsupportedQueryError(f"Unmatched ':(' for field {field}")
            consume()
            return val
        consume()
        if tok in ("AND", "OR", "NOT"):
            raise UnsupportedQueryError(f"Unexpected boolean operator {tok!r}")
        if ":" in tok and not tok.startswith('"'):
            field, pat = tok.split(":", 1)
            return _match_field_value(doc, field, pat)
        if scoped_field:
            return _match_field_value(doc, scoped_field, tok)
        raise UnsupportedQueryError(f"Bare term without field scope not supported: {tok!r}")

    result = parse_or()
    if idx != len(tokens):
        raise UnsupportedQueryError(f"Unexpected trailing token {tokens[idx]!r}")
    return result
