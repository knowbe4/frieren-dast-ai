"""
Flow tests: HTTP evidence auto-population and SARIF export quality.

Covers:
  1. session_store.add_finding() auto-populates raw_request/raw_response from the
     parent ProxyEntry when the finding dict lacks them.
  2. Findings that already carry raw HTTP are not overwritten.
  3. SARIF rule IDs are specific (passive rule YAML id, active slug, fallback).
  4. SARIF results include raw HTTP in relatedLocations and message.markdown.
  5. CORS same-site false positive suppression.
  6. Match & Replace rule application on request headers/body/url.
  7. ProxySettings persists match_replace rules through to_dict().
"""

from __future__ import annotations

import json

import pytest

from dast.proxy.session_store import SessionStore, _format_raw_request, _format_raw_response
from dast.report.sarif import build_sarif, _make_rule_id, _cwe_uri


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_store() -> SessionStore:
    return SessionStore()


def _add_entry(store: SessionStore, *, method="GET", url="https://api.example.com/users",
               req_headers=None, req_body=None, resp_status=200,
               resp_headers=None, resp_body=None) -> str:
    entry_id = store.new_entry(
        method, url,
        req_headers or {"host": "api.example.com", "accept": "application/json"},
        req_body,
    )
    store.complete_entry(
        entry_id,
        status=resp_status,
        response_headers=resp_headers or {"content-type": "application/json"},
        response_body=resp_body or b'{"ok": true}',
        duration_ms=42.0,
    )
    return entry_id


# ── 1. auto-populate raw_request / raw_response ───────────────────────────────

class TestAutoPopulateHTTPEvidence:
    def test_finding_without_raw_gets_populated(self):
        store = _make_store()
        eid = _add_entry(store, resp_body=b"hello")
        finding = {
            "title": "Test Finding",
            "severity": "medium",
            "attack_type": "xss",
            "cwe": "CWE-79",
            "evidence": "reflected payload",
        }
        store.add_finding(eid, finding, "vulnerable")

        entry = store.get_entry(eid)
        f = entry.findings[0]
        assert f["raw_request"], "raw_request should be auto-populated"
        assert f["raw_response"], "raw_response should be auto-populated"
        assert "GET /users HTTP/1.1" in f["raw_request"]
        assert "HTTP/1.1 200" in f["raw_response"]
        assert "hello" in f["raw_response"]

    def test_finding_with_existing_raw_not_overwritten(self):
        store = _make_store()
        eid = _add_entry(store)
        custom_req = "GET /custom HTTP/1.1\r\nHost: custom.example.com\r\n\r\n"
        custom_resp = "HTTP/1.1 302\r\nLocation: https://evil.com\r\n\r\n"
        finding = {
            "title": "Custom Evidence Finding",
            "severity": "high",
            "attack_type": "ssrf",
            "raw_request": custom_req,
            "raw_response": custom_resp,
        }
        store.add_finding(eid, finding, "vulnerable")

        entry = store.get_entry(eid)
        f = entry.findings[0]
        assert f["raw_request"] == custom_req, "existing raw_request must not be overwritten"
        assert f["raw_response"] == custom_resp, "existing raw_response must not be overwritten"

    def test_passive_finding_without_response_not_populated(self):
        """Entry with no response body (e.g. incomplete) should not crash."""
        store = _make_store()
        # Create entry but don't complete it (no response yet)
        eid = store.new_entry(
            "GET", "https://api.example.com/ping",
            {"host": "api.example.com"}, None,
        )
        finding = {
            "title": "Incomplete Entry Finding",
            "severity": "info",
            "attack_type": "passive",
        }
        store.add_finding(eid, finding, "safe")
        entry = store.get_entry(eid)
        # Should not raise; raw_request may be populated but raw_response should be absent
        # (no response_status set)
        assert "title" in entry.findings[0]

    def test_request_body_included_in_raw_request(self):
        store = _make_store()
        eid = _add_entry(
            store,
            method="POST",
            url="https://api.example.com/login",
            req_headers={"host": "api.example.com", "content-type": "application/json"},
            req_body=b'{"username":"admin","password":"hunter2"}',
        )
        finding = {"title": "Credential Exposure", "severity": "high", "attack_type": "passive"}
        store.add_finding(eid, finding, "vulnerable")

        f = store.get_entry(eid).findings[0]
        assert "hunter2" in f["raw_request"]

    def test_set_cookie_preserved_in_raw_response(self):
        store = _make_store()
        eid = _add_entry(
            store,
            resp_headers={
                "content-type": "text/html",
                "set-cookie": ["session=abc123; HttpOnly; Secure", "tracker=xyz; SameSite=Lax"],
            },
        )
        finding = {"title": "Cookie Analysis", "severity": "low", "attack_type": "passive"}
        store.add_finding(eid, finding, "safe")

        f = store.get_entry(eid).findings[0]
        assert "set-cookie: session=abc123" in f["raw_response"]
        assert "set-cookie: tracker=xyz" in f["raw_response"]


# ── 2. _format_raw_request / _format_raw_response helpers ────────────────────

class TestFormatHelpers:
    def test_format_request_includes_path_and_query(self):
        store = _make_store()
        eid = store.new_entry(
            "GET", "https://api.example.com/search?q=test&page=2",
            {"host": "api.example.com"}, None,
        )
        entry = store.get_entry(eid)
        raw = _format_raw_request(entry)
        assert "GET /search?q=test&page=2 HTTP/1.1" in raw
        assert "Host: api.example.com" in raw

    def test_format_response_shows_status(self):
        store = _make_store()
        eid = _add_entry(store, resp_status=404, resp_body=b"Not Found")
        entry = store.get_entry(eid)
        raw = _format_raw_response(entry)
        assert "HTTP/1.1 404" in raw
        assert "Not Found" in raw


# ── 3. SARIF rule ID derivation ───────────────────────────────────────────────

class TestSarifRuleId:
    def test_passive_finding_uses_yaml_rule_id(self):
        f = {"title": "Missing HSTS", "attack_type": "passive", "rule_id": "missing-hsts"}
        assert _make_rule_id(f) == "missing-hsts"

    def test_cors_rule_id_preserved(self):
        f = {
            "title": "CORS Reflected Origin",
            "attack_type": "passive",
            "rule_id": "cors-reflected-origin-with-credentials",
        }
        assert _make_rule_id(f) == "cors-reflected-origin-with-credentials"

    def test_active_finding_gets_type_plus_slug(self):
        f = {"title": "Reflected XSS", "attack_type": "xss"}
        assert _make_rule_id(f) == "DAST-XSS-ReflectedXss"

    def test_sqli_finding_slug(self):
        f = {"title": "Time-Based Blind SQL Injection", "attack_type": "sqli"}
        assert _make_rule_id(f) == "DAST-SQLI-TimeBasedBlindSqlInjection"

    def test_passive_without_rule_id_falls_back_to_title_slug(self):
        f = {"title": "Cookie Missing HttpOnly", "attack_type": "passive"}
        assert _make_rule_id(f) == "DAST-PASSIVE-CookieMissingHttponly"

    def test_unknown_attack_type_fallback(self):
        f = {"attack_type": "unknown"}
        assert _make_rule_id(f) == "DAST-UNKNOWN"

    def test_cwe_uri_returns_mitre_link(self):
        assert _cwe_uri("CWE-79") == "https://cwe.mitre.org/data/definitions/79.html"
        assert _cwe_uri("CWE-319") == "https://cwe.mitre.org/data/definitions/319.html"

    def test_cwe_uri_fallback_on_empty(self):
        assert _cwe_uri("") == "https://owasp.org/www-project-top-ten/"

    def test_cwe_uri_fallback_on_non_numeric(self):
        assert _cwe_uri("CWE-abc") == "https://owasp.org/www-project-top-ten/"


# ── 4. SARIF build: evidence in output ────────────────────────────────────────

class _FakeEntry:
    method = "POST"
    url = "https://api.example.com/login"
    host = "api.example.com"

    def __init__(self, findings):
        self.findings = findings


class TestSarifBuild:
    def _build(self, findings):
        entry = _FakeEntry(findings)
        return build_sarif([entry])

    def test_passive_rule_id_in_sarif(self):
        doc = self._build([{
            "title": "Missing HSTS",
            "severity": "medium",
            "cwe": "CWE-319",
            "attack_type": "passive",
            "rule_id": "missing-hsts",
            "evidence": "No Strict-Transport-Security header",
        }])
        rules = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
        results = doc["runs"][0]["results"]
        assert "missing-hsts" in rules
        assert results[0]["ruleId"] == "missing-hsts"

    def test_passive_message_uses_evidence_not_parameter(self):
        doc = self._build([{
            "title": "Missing HSTS",
            "severity": "medium",
            "attack_type": "passive",
            "rule_id": "missing-hsts",
            "evidence": "No Strict-Transport-Security header",
        }])
        msg = doc["runs"][0]["results"][0]["message"]["text"]
        assert "No Strict-Transport-Security header" in msg
        assert "parameter" not in msg.lower()

    def test_active_message_includes_parameter_and_payload(self):
        doc = self._build([{
            "title": "Reflected XSS",
            "severity": "high",
            "attack_type": "xss",
            "parameter": "q",
            "payload": "<script>alert(1)</script>",
        }])
        msg = doc["runs"][0]["results"][0]["message"]["text"]
        assert "parameter: q" in msg
        assert "<script>" in msg

    def test_raw_http_in_related_locations(self):
        doc = self._build([{
            "title": "SQL Injection",
            "severity": "high",
            "attack_type": "sqli",
            "raw_request": "GET /search?q=1' HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            "raw_response": "HTTP/1.1 500\r\nContent-Type: text/plain\r\n\r\nSQL error",
        }])
        related = doc["runs"][0]["results"][0]["relatedLocations"]
        assert any("Request" in r["message"]["text"] for r in related)
        assert any("Response" in r["message"]["text"] for r in related)
        req_loc = next(r for r in related if "Request" in r["message"]["text"] and "exploit" not in r["message"]["text"].lower())
        assert "1'" in req_loc["properties"]["snippet"]

    def test_raw_http_in_markdown(self):
        doc = self._build([{
            "title": "Reflected XSS",
            "severity": "high",
            "attack_type": "xss",
            "evidence": "payload reflected",
            "raw_request": "GET /?q=<script> HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            "raw_response": "HTTP/1.1 200\r\n\r\n<script>",
        }])
        markdown = doc["runs"][0]["results"][0]["message"]["markdown"]
        assert "```http" in markdown
        assert "<script>" in markdown
        assert "Request" in markdown
        assert "Response" in markdown

    def test_probe_pair_in_related_locations(self):
        doc = self._build([{
            "title": "CSRF Token Bypass",
            "severity": "high",
            "attack_type": "csrf",
            "raw_request": "POST /transfer HTTP/1.1\r\n\r\namount=100",
            "raw_response": "HTTP/1.1 200\r\n\r\nok",
            "probe_request": "POST /transfer HTTP/1.1\r\n\r\namount=999",
            "probe_response": "HTTP/1.1 200\r\n\r\ntransferred",
        }])
        related = doc["runs"][0]["results"][0]["relatedLocations"]
        texts = [r["message"]["text"] for r in related]
        assert any("exploit proof" in t.lower() for t in texts)

    def test_helpuri_points_to_cwe(self):
        doc = self._build([{
            "title": "SQL Injection",
            "severity": "high",
            "attack_type": "sqli",
            "cwe": "CWE-89",
        }])
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert "89" in rule["helpUri"]
        assert "cwe.mitre.org" in rule["helpUri"]

    def test_multiple_findings_distinct_rules(self):
        doc = self._build([
            {"title": "Missing HSTS", "severity": "medium", "attack_type": "passive", "rule_id": "missing-hsts"},
            {"title": "Missing CSP", "severity": "medium", "attack_type": "passive", "rule_id": "missing-csp"},
            {"title": "Reflected XSS", "severity": "high", "attack_type": "xss"},
        ])
        rules = [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]]
        assert len(rules) == len(set(rules)), "rule IDs must be unique"
        assert "missing-hsts" in rules
        assert "missing-csp" in rules
        assert "DAST-XSS-ReflectedXss" in rules

    def test_no_findings_produces_empty_sarif(self):
        doc = self._build([])
        assert doc["runs"][0]["results"] == []
        assert doc["runs"][0]["tool"]["driver"]["rules"] == []

    def test_sarif_schema_and_version(self):
        doc = self._build([])
        assert doc["version"] == "2.1.0"
        assert "sarif-schema" in doc["$schema"]


# ── 5. CORS same-site FP suppression ─────────────────────────────────────────

class TestCorsSameSite:
    def _make_entry_cls(self, url, origin, acao="", acac="true"):
        class E:
            request_headers = {"origin": origin}
            response_headers = {
                "access-control-allow-origin": acao or origin,
                "access-control-allow-credentials": acac,
                "content-type": "application/json",
            }
            response_status = 200
            response_body = None
            request_body = None
            method = "GET"
            host = url.split("/")[2]
            path = "/"
        E.url = url
        return E()

    def _run_cors_rule(self, entry):
        from dast.plugins.passive_scanner import _load_all_rules, _eval_cors
        rules = _load_all_rules()
        cors_rule = next(
            (r for r in rules if r.get("match", {}).get("cors_mode") == "reflected_with_credentials"),
            None,
        )
        assert cors_rule, "cors-reflected-origin-with-credentials rule not found"
        return _eval_cors(cors_rule, entry)

    def test_same_site_reflection_not_flagged(self):
        entry = self._make_entry_cls(
            "https://api.console.example.com/api/session",
            "https://console.example.com",
        )
        result = self._run_cors_rule(entry)
        assert result is None, "Same-site origin reflection must NOT be flagged"

    def test_cross_site_reflection_is_flagged(self):
        entry = self._make_entry_cls(
            "https://api.example.com/data",
            "https://evil.com",
        )
        result = self._run_cors_rule(entry)
        assert result is not None, "Cross-site origin reflection MUST be flagged"

    def test_subdomain_same_site_not_flagged(self):
        entry = self._make_entry_cls(
            "https://api.app.example.com/data",
            "https://app.example.com",
        )
        result = self._run_cors_rule(entry)
        assert result is None, "Subdomain same-site reflection must NOT be flagged"

    def test_lookalike_domain_flagged(self):
        entry = self._make_entry_cls(
            "https://api.example.com/data",
            "https://example.evil.com",
        )
        result = self._run_cors_rule(entry)
        assert result is not None, "Lookalike domain must be flagged"


# ── 6. Match & Replace ────────────────────────────────────────────────────────

class TestMatchReplace:
    def _settings(self, rules):
        from dast.proxy.proxy_settings import ProxySettings
        import tempfile, os
        # Use a fresh settings file so tests don't contaminate each other
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f:
            tmp = f.name
        try:
            ps = ProxySettings.__new__(ProxySettings)
            import threading
            ps._lock = threading.Lock()
            ps._bypass = set()
            ps._hidden_ext = set()
            ps._scope_rules = []
            ps._match_replace = []
            ps._on_change = None
            for r in rules:
                ps._match_replace.append({
                    "enabled": r.get("enabled", True),
                    "scope": r["scope"],
                    "type": r["type"],
                    "match": r["match"],
                    "replace": r["replace"],
                    "comment": r.get("comment", ""),
                })
            return ps
        finally:
            os.unlink(tmp)

    def test_header_replacement_request(self):
        ps = self._settings([{
            "scope": "request", "type": "header",
            "match": r"authorization: .*", "replace": "authorization: Bearer newtoken",
        }])
        url, hdrs, body = ps.apply_to_request(
            "https://api.example.com/data",
            {"authorization": "Bearer oldtoken", "accept": "application/json"},
            None,
        )
        assert hdrs["authorization"] == "Bearer newtoken"
        assert hdrs["accept"] == "application/json"

    def test_body_replacement_request(self):
        ps = self._settings([{
            "scope": "request", "type": "body",
            "match": r"password=\w+", "replace": "password=REDACTED",
        }])
        _, _, body = ps.apply_to_request(
            "https://api.example.com/login",
            {"content-type": "application/x-www-form-urlencoded"},
            b"username=admin&password=hunter2",
        )
        assert b"REDACTED" in body
        assert b"hunter2" not in body

    def test_url_replacement(self):
        ps = self._settings([{
            "scope": "request", "type": "url",
            "match": r"/v1/", "replace": "/v2/",
        }])
        url, _, _ = ps.apply_to_request(
            "https://api.example.com/v1/users",
            {}, None,
        )
        assert "/v2/users" in url

    def test_response_header_replacement(self):
        ps = self._settings([{
            "scope": "response", "type": "header",
            "match": r"x-frame-options: .*", "replace": "x-frame-options: SAMEORIGIN",
        }])
        hdrs, _ = ps.apply_to_response(
            {"x-frame-options": "ALLOW-FROM https://evil.com", "content-type": "text/html"},
            b"<html></html>",
        )
        assert hdrs["x-frame-options"] == "SAMEORIGIN"

    def test_disabled_rule_not_applied(self):
        ps = self._settings([{
            "scope": "request", "type": "body",
            "match": r"secret", "replace": "REDACTED",
            "enabled": False,
        }])
        _, _, body = ps.apply_to_request(
            "https://api.example.com/data",
            {}, b"my secret value",
        )
        assert b"secret" in body

    def test_response_scope_not_applied_to_request(self):
        ps = self._settings([{
            "scope": "response", "type": "header",
            "match": r"authorization: .*", "replace": "authorization: REMOVED",
        }])
        _, hdrs, _ = ps.apply_to_request(
            "https://api.example.com/data",
            {"authorization": "Bearer token"}, None,
        )
        assert hdrs["authorization"] == "Bearer token"

    def test_both_scope_applies_to_request_and_response(self):
        ps = self._settings([{
            "scope": "both", "type": "body",
            "match": r"internal", "replace": "FILTERED",
        }])
        _, _, req_body = ps.apply_to_request("https://x.com/", {}, b"internal data")
        _, resp_body  = ps.apply_to_response({}, b"internal data")
        assert b"FILTERED" in req_body
        assert b"FILTERED" in resp_body


# ── 7. ProxySettings to_dict includes match_replace ──────────────────────────

class TestProxySettingsMatchReplaceToDict:
    def test_to_dict_includes_match_replace(self):
        from dast.proxy.proxy_settings import ProxySettings
        import threading
        ps = ProxySettings.__new__(ProxySettings)
        ps._lock = threading.Lock()
        ps._bypass = set()
        ps._hidden_ext = set()
        ps._scope_rules = []
        ps._bind_host = "127.0.0.1"
        ps._bind_port = 0
        ps._match_replace = [
            {"enabled": True, "scope": "request", "type": "header",
             "match": "X-Old: .*", "replace": "X-New: value", "comment": ""},
        ]
        d = ps.to_dict()
        assert "match_replace" in d
        assert len(d["match_replace"]) == 1
        assert d["match_replace"][0]["match"] == "X-Old: .*"
