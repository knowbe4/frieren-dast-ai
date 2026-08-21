"""
Tests for the deterministic-detection hardening work:

1. New passive rules (expanded secrets, CSP + transport hardening, verbose
   error/debug consoles, insecure/mixed-content forms) fire on a positive
   sample and stay silent on a safe sample.
2. The runtime aggressive-rule toggle: `aggressive: true` rules are skipped
   by default and evaluated only after `set_aggressive_rules(True)`.
3. Regression guard for the previously-dead deterministic agents
   (OpenRedirectAgent, MFABypassAgent) whose findings raised TypeError from
   invalid AgentFinding kwargs and were swallowed by run_safe().
"""

from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass, field
from typing import Dict, List, Optional



# ── shared helpers (mirror tests/unit/test_passive_rules_extended.py) ────────

@dataclass
class _FakeEntry:
    url: str = "https://example.com/"
    path: str = "/"
    method: str = "GET"
    host: str = "example.com"
    id: str = "entry-1"
    response_status: Optional[int] = 200
    status_code: Optional[int] = 200
    response_headers: Dict = field(default_factory=dict)
    response_body: Optional[bytes] = b""
    request_headers: Dict = field(default_factory=dict)
    request_body: Optional[bytes] = b""
    content_type: str = "text/html"


def _entry(
    url: str = "https://example.com/",
    path: str = "/",
    method: str = "GET",
    status: int = 200,
    resp_headers: Optional[Dict] = None,
    resp_body: bytes = b"",
    content_type: str = "text/html",
) -> _FakeEntry:
    host = url.split("/")[2].split(":")[0] if "//" in url else "example.com"
    headers = dict(resp_headers or {})
    if "content-type" not in headers:
        headers["content-type"] = content_type
    return _FakeEntry(
        url=url, path=path, method=method, host=host,
        response_status=status, status_code=status,
        response_headers=headers, response_body=resp_body,
        content_type=content_type,
    )


def _run_rule(entry: _FakeEntry, rule_id: str) -> List:
    """Evaluate a single rule by id (bypasses the aggressive gate — that lives
    in on_entry and is tested separately)."""
    from dast.plugins.passive_scanner import _eval_rule, _load_all_rules, _conditions_match
    fired_hosts: Dict = {}
    for rule in _load_all_rules():
        if rule.get("id") == rule_id:
            if _conditions_match(rule, entry, fired_hosts):
                return _eval_rule(rule, entry)
    return []


# ── expanded secret detectors ────────────────────────────────────────────────

class TestExpandedSecrets:
    def test_openai_key_fires(self):
        body = b'{"key": "sk-proj-abcDEF0123456789abcDEF0123456789abcd"}'
        assert _run_rule(_entry(resp_body=body, content_type="application/json"), "openai-api-key")

    def test_anthropic_key_fires(self):
        body = b'{"key": "sk-ant-api03-abcDEF0123456789abcDEF0123"}'
        assert _run_rule(_entry(resp_body=body, content_type="application/json"), "anthropic-api-key")

    def test_gitlab_pat_fires(self):
        body = b'token=glpat-abcDEF0123456789abcd'
        assert _run_rule(_entry(resp_body=body), "gitlab-pat")

    def test_sendgrid_key_fires(self):
        body = ("SG." + "A" * 22 + "." + "B" * 43).encode()
        assert _run_rule(_entry(resp_body=body), "sendgrid-api-key")

    def test_npm_token_fires(self):
        body = b'//registry.npmjs.org/:_authToken=npm_abcDEF0123456789abcDEF0123456789abcd'
        assert _run_rule(_entry(resp_body=body), "npm-access-token")

    def test_azure_connection_string_fires(self):
        secret = "A" * 80
        body = f'DefaultEndpointsProtocol=https;AccountKey={secret}==;'.encode()
        assert _run_rule(_entry(resp_body=body), "azure-storage-connection-string")

    def test_google_oauth_secret_fires(self):
        body = b'client_secret=GOCSPX-abcDEF0123456789abcd'
        assert _run_rule(_entry(resp_body=body), "google-oauth-client-secret")

    def test_no_false_positive_on_plain_text(self):
        body = b'{"message": "hello world, nothing secret here"}'
        for rid in ("openai-api-key", "anthropic-api-key", "gitlab-pat",
                    "sendgrid-api-key", "npm-access-token",
                    "azure-storage-connection-string", "google-oauth-client-secret"):
            assert _run_rule(_entry(resp_body=body, content_type="application/json"), rid) == [], rid


# ── CSP + transport hardening ─────────────────────────────────────────────────

class TestCspTransportHardening:
    def test_csp_wildcard_script_src_fires(self):
        e = _entry(resp_headers={"content-security-policy": "script-src 'self' *"})
        assert _run_rule(e, "csp-wildcard-script-src")

    def test_csp_wildcard_not_fired_on_strict_policy(self):
        e = _entry(resp_headers={"content-security-policy": "script-src 'self'"})
        assert _run_rule(e, "csp-wildcard-script-src") == []

    def test_csp_data_uri_script_fires(self):
        e = _entry(resp_headers={"content-security-policy": "script-src 'self' data:"})
        assert _run_rule(e, "csp-data-uri-script")

    def test_csp_http_source_fires(self):
        e = _entry(resp_headers={"content-security-policy": "script-src 'self' http://cdn.example.com"})
        assert _run_rule(e, "csp-http-source")

    def test_csp_http_source_not_fired_on_https_only(self):
        e = _entry(resp_headers={"content-security-policy": "script-src 'self' https://cdn.example.com"})
        assert _run_rule(e, "csp-http-source") == []

    def test_hsts_no_include_subdomains_fires(self):
        e = _entry(resp_headers={"strict-transport-security": "max-age=31536000"})
        assert _run_rule(e, "hsts-no-include-subdomains")

    def test_hsts_include_subdomains_no_fire(self):
        e = _entry(resp_headers={"strict-transport-security": "max-age=31536000; includeSubDomains"})
        assert _run_rule(e, "hsts-no-include-subdomains") == []

    def test_referrer_policy_unsafe_fires(self):
        e = _entry(resp_headers={"referrer-policy": "unsafe-url"})
        assert _run_rule(e, "referrer-policy-unsafe")

    def test_referrer_policy_safe_no_fire(self):
        e = _entry(resp_headers={"referrer-policy": "no-referrer"})
        assert _run_rule(e, "referrer-policy-unsafe") == []

    def test_xfo_invalid_fires(self):
        e = _entry(resp_headers={"x-frame-options": "ALLOW-FROM https://x.com"})
        assert _run_rule(e, "x-frame-options-invalid")

    def test_xfo_valid_deny_no_fire(self):
        e = _entry(resp_headers={"x-frame-options": "DENY"})
        assert _run_rule(e, "x-frame-options-invalid") == []

    def test_xfo_valid_sameorigin_no_fire(self):
        e = _entry(resp_headers={"x-frame-options": "SAMEORIGIN"})
        assert _run_rule(e, "x-frame-options-invalid") == []

    def test_cookie_samesite_none_without_secure_fires(self):
        e = _entry(resp_headers={"set-cookie": "sid=abc; SameSite=None; HttpOnly"})
        assert _run_rule(e, "cookie-samesite-none-without-secure")

    def test_cookie_samesite_none_with_secure_no_fire(self):
        e = _entry(resp_headers={"set-cookie": "sid=abc; SameSite=None; Secure; HttpOnly"})
        assert _run_rule(e, "cookie-samesite-none-without-secure") == []


# ── verbose errors / debug consoles ──────────────────────────────────────────

class TestVerboseErrors:
    def test_werkzeug_debugger_fires(self):
        e = _entry(resp_body=b"<title>Werkzeug Debugger</title> The debugger caught an exception")
        assert _run_rule(e, "werkzeug-debugger-console")

    def test_rails_better_errors_fires(self):
        e = _entry(resp_body=b'<div class="better_errors">BetterErrors</div>')
        assert _run_rule(e, "rails-better-errors")

    def test_symfony_profiler_fires(self):
        e = _entry(resp_body=b'<div class="sf-toolbar" id="sf-minitoolbar">/_profiler/</div>')
        assert _run_rule(e, "symfony-profiler")

    def test_laravel_whoops_fires(self):
        e = _entry(resp_body=b"Whoops, looks like something went wrong")
        assert _run_rule(e, "laravel-whoops")

    def test_express_stack_trace_fires(self):
        e = _entry(resp_body=b"    at Object.<anonymous> (/app/node_modules/express/index.js:42:13)",
                   content_type="text/plain")
        assert _run_rule(e, "express-stack-trace")

    def test_go_panic_fires(self):
        e = _entry(resp_body=b"panic: runtime error\n\ngoroutine 1 [running]:", content_type="text/plain")
        assert _run_rule(e, "go-panic")

    def test_no_false_positive_on_normal_html(self):
        e = _entry(resp_body=b"<html><body>Welcome</body></html>")
        for rid in ("werkzeug-debugger-console", "rails-better-errors",
                    "symfony-profiler", "laravel-whoops"):
            assert _run_rule(e, rid) == [], rid


# ── insecure / mixed-content forms ────────────────────────────────────────────

class TestInsecureForms:
    def test_password_form_over_http_fires(self):
        e = _entry(url="http://example.com/login",
                   resp_body=b'<form><input type="password" name="pw"></form>')
        assert _run_rule(e, "password-form-over-http")

    def test_password_form_over_https_no_fire(self):
        e = _entry(url="https://example.com/login",
                   resp_body=b'<form><input type="password" name="pw"></form>')
        assert _run_rule(e, "password-form-over-http") == []

    def test_form_action_http_on_https_fires(self):
        e = _entry(url="https://example.com/login",
                   resp_body=b'<form action="http://example.com/submit"><input></form>')
        assert _run_rule(e, "form-action-http-on-https-page")

    def test_form_action_https_no_fire(self):
        e = _entry(url="https://example.com/login",
                   resp_body=b'<form action="https://example.com/submit"><input></form>')
        assert _run_rule(e, "form-action-http-on-https-page") == []


# ── aggressive-rule runtime gate (driven through on_entry) ────────────────────

class _FakeStore:
    def __init__(self):
        self.passive_fired_hosts: Dict = {}
        self.findings: List[dict] = []

    def add_finding(self, entry_id: str, finding: dict, scan_result: str) -> None:
        self.findings.append(finding)


class TestAggressiveGate:
    def teardown_method(self):
        from dast.plugins.passive_scanner import set_aggressive_rules
        set_aggressive_rules(False)  # never leak state to other tests

    def _run_on_entry(self, entry) -> List[str]:
        from dast.plugins.passive_scanner import PassiveScannerPlugin
        store = _FakeStore()
        asyncio.run(PassiveScannerPlugin().on_entry(entry, store))
        return [f.get("rule_id") for f in store.findings]

    def test_aggressive_rule_skipped_by_default(self):
        from dast.plugins.passive_scanner import set_aggressive_rules
        set_aggressive_rules(False)
        # CSP present but missing base-uri -> csp-missing-base-uri (aggressive)
        e = _entry(resp_headers={"content-security-policy": "default-src 'self'"})
        assert "csp-missing-base-uri" not in self._run_on_entry(e)

    def test_aggressive_rule_fires_when_enabled(self):
        from dast.plugins.passive_scanner import set_aggressive_rules
        set_aggressive_rules(True)
        e = _entry(resp_headers={"content-security-policy": "default-src 'self'"})
        assert "csp-missing-base-uri" in self._run_on_entry(e)

    def test_non_aggressive_rule_fires_regardless(self):
        from dast.plugins.passive_scanner import set_aggressive_rules
        set_aggressive_rules(False)
        # csp-wildcard-script-src is NOT aggressive; must still fire
        e = _entry(resp_headers={"content-security-policy": "script-src 'self' *"})
        assert "csp-wildcard-script-src" in self._run_on_entry(e)


# ── regression: previously-dead deterministic agents ──────────────────────────

class _FakeResponse:
    def __init__(self, status_code=302, headers=None, text="", url=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self.url = url


class TestDeadAgentRegression:
    def test_no_agent_passes_unknown_agentfinding_kwarg(self):
        """Static guard: every AgentFinding(...) call in dast/agents uses only
        real dataclass fields (this is what silently killed open_redirect/mfa)."""
        import ast
        import glob
        from dast.ai.agent_base import AgentFinding

        valid = set(inspect.signature(AgentFinding).parameters)
        offenders = []
        for path in glob.glob("dast/agents/*.py"):
            with open(path) as fh:
                tree = ast.parse(fh.read())
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Name)
                        and node.func.id == "AgentFinding"):
                    for kw in node.keywords:
                        if kw.arg and kw.arg not in valid:
                            offenders.append((path, node.lineno, kw.arg))
        assert offenders == [], f"AgentFinding called with unknown kwargs: {offenders}"

    def test_open_redirect_agent_returns_finding(self):
        """Drive OpenRedirectAgent against a stub client that redirects to the
        canary host; a finding must be returned (constructor no longer raises)."""
        from dast.agents.open_redirect_agent import OpenRedirectAgent, _CANARY_HOST
        from dast.scanners.active_checks import CheckTarget

        async def fake_send(client, method, url, headers, body, payload=None):
            return _FakeResponse(
                status_code=302,
                headers={"location": f"https://{_CANARY_HOST}/probe"},
                text="",
                url=url,
            )

        import dast.agents.open_redirect_agent as ora
        original_send = ora._send
        original_fmt = ora._fmt_http_pair
        ora._send = fake_send
        ora._fmt_http_pair = lambda resp: ("raw-request", "raw-response")
        try:
            target = CheckTarget(
                url="https://victim.example.com/go?next=/home",
                method="GET",
                headers={},
                body=None,
                params=[{"name": "next", "value": "/home", "type": "query"}],
            )
            findings = asyncio.run(OpenRedirectAgent().run(target, client=None))
        finally:
            ora._send = original_send
            ora._fmt_http_pair = original_fmt

        assert findings, "OpenRedirectAgent must return a finding on canary redirect"
        assert findings[0].attack_type == "open_redirect"
        assert findings[0].bypass_validation is True

    def test_mfa_finding_construction_does_not_raise(self):
        """The three MFA findings previously raised TypeError (baseline_response,
        missing url/request_method). Constructing them with the fixed fields must work."""
        from dast.ai.agent_base import AgentFinding
        f = AgentFinding(
            title="MFA Endpoint Missing Rate Limiting",
            severity="high",
            cwe="CWE-307",
            attack_type="mfa_bypass",
            evidence="e",
            payload="000000",
            parameter="otp",
            url="https://example.com/verify",
            request_method="POST",
            raw_request="req",
            raw_response="resp",
            probe_request="preq",
            probe_response="presp",
            confirmed=False,
        )
        assert f.attack_type == "mfa_bypass"
