"""Frieren must recognize DuckDB SQL errors as SQLi — a DuckDB version() leak surfaced as
`{"errors":[{"message":"Invalid Input Error: v1.4.2"}]}` and was previously missed.

Covers: the shared signature set (sqli.yaml -> sqli_agent / sqli_probe), the active-scan analyzer
regex, and the passive GraphQL analyzer flagging SQL errors in errors[]."""

from __future__ import annotations

import json


def test_sqli_yaml_has_duckdb_signatures():
    from dast.payloads.loader import get_signatures
    sigs = [s.lower() for s in get_signatures("sqli", "error_signatures")]
    for term in ("invalid input error", "binder error", "conversion error", "duckdb"):
        assert term in sigs, f"missing DuckDB signature: {term}"


def test_active_and_probe_regexes_match_duckdb():
    from dast.ai.response_analyzer import _SQL_ERROR_RE
    from dast.tools.sqli_probe_tools import _error_re
    assert _SQL_ERROR_RE.search("Invalid Input Error: v1.4.2")
    assert _error_re().search("Invalid Input Error: v1.4.2")
    # regex-fragment signatures still work (joined unescaped)
    assert _error_re().search("you have an error in your sql syntax near X")
    # benign bodies do not match
    assert not _error_re().search('{"data":{"ok":true}}')


class _Entry:
    """Minimal ProxyEntry stand-in covering the fields _analyze reads."""
    def __init__(self, resp, req=b'{"query":"query{x}"}'):
        self.request_body = req
        self.response_body = resp if isinstance(resp, bytes) else resp.encode()
        self.method = "POST"
        self.path = "/reports/graphql/"
        self.request_headers = {}
        self.response_headers = {}
        self.status_code = 200
        self.url = "https://app.example.com/reports/graphql/"
        self.host = "app.example.com"


def _sqli_findings(resp_body):
    from dast.plugins.graphql_analyzer import _analyze
    return [f for f in _analyze(_Entry(resp_body)) if f.get("attack_type") == "sqli"]


def test_passive_flags_duckdb_sql_error_in_errors():
    body = json.dumps({"data": None, "errors": [
        {"message": "Invalid Input Error: v1.4.2", "path": ["genericMutation"]}]})
    findings = _sqli_findings(body)
    assert len(findings) == 1
    f = findings[0]
    assert f["cwe"] == "CWE-89" and f["severity"] == "high"
    assert "v1.4.2" in f["evidence"]


def test_passive_no_false_positive_on_clean_or_schema_error():
    assert _sqli_findings(json.dumps({"data": {"ok": True}})) == []
    # an ordinary GraphQL schema error is not a SQL error
    assert _sqli_findings(json.dumps({"errors": [{"message": "Cannot query field 'x' on type 'Y'"}]})) == []
