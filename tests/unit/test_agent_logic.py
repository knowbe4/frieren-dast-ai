"""
Unit tests for agent logic, FP filter, red-team validator, and passive scanner confirmed field.

All tests run without network — agents are tested via their helper functions,
not via run() which requires a live HTTP client.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from unittest.mock import MagicMock

import pytest


# ── shared fakes ──────────────────────────────────────────────────────────

@dataclass
class _FakeFinding:
    title: str = "Test Finding"
    severity: str = "high"
    cwe: str = "CWE-89"
    attack_type: str = "sqli"
    evidence: str = ""
    payload: str = "'"
    parameter: str = "id"
    url: str = "https://example.com/api"
    request_method: str = "GET"
    confirmed: bool = True
    bypass_validation: bool = False
    reasoning: str = ""
    raw_response_snippet: str = ""
    browser_confirmed: Optional[bool] = None
    browser_confirm_reason: str = ""
    raw_request: str = ""
    raw_response: str = ""
    probe_request: str = ""
    probe_response: str = ""


@dataclass
class _FakeTarget:
    url: str = "https://example.com/api"
    method: str = "GET"
    headers: Dict = field(default_factory=dict)
    body: Optional[str] = None
    params: List = field(default_factory=list)


# ── fp_filter tests ───────────────────────────────────────────────────────

class TestFpFilter:
    def test_xss_in_json_response_discarded(self):
        from dast.ai.fp_filter import check
        finding = _FakeFinding(attack_type="xss")
        target = _FakeTarget(headers={"content-type": "application/json"})
        reason = check(finding, target)
        assert reason is not None
        assert "JSON" in reason

    def test_xss_in_html_response_passes(self):
        from dast.ai.fp_filter import check
        finding = _FakeFinding(attack_type="xss")
        target = _FakeTarget(headers={"content-type": "text/html"})
        reason = check(finding, target)
        assert reason is None

    def test_graphql_enum_error_discarded_for_any_attack_type(self):
        from dast.ai.fp_filter import check
        # _fp_graphql_enum_rejection reads raw_response + raw_response_snippet + evidence.
        # Payload must also appear in combined to confirm it was echoed, not acted on.
        for attack in ("xss", "sqli", "ssrf", "lfi"):
            finding = _FakeFinding(
                attack_type=attack,
                payload="<script>",
                raw_response='{"errors": [{"message": "Expected X to be one of: A, B, <script>"}]}',
            )
            reason = check(finding, _FakeTarget())
            assert reason is not None, f"Expected discard for {attack} on GraphQL enum error"

    def test_ssti_payload_echoed_discarded(self):
        from dast.ai.fp_filter import check
        finding = _FakeFinding(
            attack_type="ssti",
            payload="${7*7}",
            raw_response="The expression ${7*7} was stored",
        )
        reason = check(finding, _FakeTarget())
        assert reason is not None
        assert "echoed" in reason.lower()

    def test_ssti_evaluated_passes(self):
        from dast.ai.fp_filter import check
        finding = _FakeFinding(
            attack_type="ssti",
            payload="${7*7}",
            raw_response="Result: 49",
        )
        reason = check(finding, _FakeTarget())
        assert reason is None

    def test_open_redirect_to_own_domain_discarded(self):
        from dast.ai.fp_filter import check
        finding = _FakeFinding(
            attack_type="open_redirect",
            evidence="Redirected to https://safe.example.com/home",
        )
        reason = check(finding, _FakeTarget())
        assert reason is not None

    def test_open_redirect_to_evil_passes(self):
        from dast.ai.fp_filter import check
        finding = _FakeFinding(
            attack_type="open_redirect",
            evidence="Redirected to https://evil.example.com/steal",
        )
        reason = check(finding, _FakeTarget())
        assert reason is None

    def test_ssrf_localhost_blocked_discarded(self):
        from dast.ai.fp_filter import check
        finding = _FakeFinding(
            attack_type="ssrf",
            evidence="Probe returned 403 blocked by SSRF mitigation",
        )
        reason = check(finding, _FakeTarget())
        assert reason is not None

    def test_lfi_no_file_content_discarded(self):
        from dast.ai.fp_filter import check
        finding = _FakeFinding(
            attack_type="lfi",
            raw_response_snippet="Error: file not found",
        )
        reason = check(finding, _FakeTarget())
        assert reason is not None

    def test_lfi_with_passwd_content_passes(self):
        from dast.ai.fp_filter import check
        finding = _FakeFinding(
            attack_type="lfi",
            raw_response_snippet="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:",
        )
        reason = check(finding, _FakeTarget())
        assert reason is None


# red_team._pattern_confidence and validate() tests moved to
# test_red_team_validate.py for locality with the rest of the red-team suite.


# ── auth_agent helper tests ───────────────────────────────────────────────

class TestAuthAgentHelpers:
    def test_body_similarity_identical(self):
        from dast.agents.auth_agent import _body_similarity
        assert _body_similarity("hello world", "hello world") == 1.0

    def test_body_similarity_empty_both(self):
        from dast.agents.auth_agent import _body_similarity
        assert _body_similarity("", "") == 1.0

    def test_body_similarity_one_empty(self):
        from dast.agents.auth_agent import _body_similarity
        assert _body_similarity("hello", "") == 0.0

    def test_body_similarity_different(self):
        from dast.agents.auth_agent import _body_similarity
        ratio = _body_similarity("aaaa", "bbbb")
        assert ratio == 0.0

    def test_responses_look_equivalent_login_marker(self):
        from dast.agents.auth_agent import _responses_look_equivalent
        authed = '{"user": "alice", "token": "abc123"}'
        unauthed = "Please log in to continue"
        assert _responses_look_equivalent(authed, unauthed) is False

    def test_responses_look_equivalent_similar_content(self):
        from dast.agents.auth_agent import _responses_look_equivalent
        authed = '{"user": "alice", "data": [1, 2, 3]}'
        unauthed = '{"user": "alice", "data": [1, 2, 3]}'
        assert _responses_look_equivalent(authed, unauthed) is True

    def test_responses_look_equivalent_unauthorized_text(self):
        from dast.agents.auth_agent import _responses_look_equivalent
        authed = '{"resource": "secret"}'
        unauthed = "401 Unauthorized"
        assert _responses_look_equivalent(authed, unauthed) is False


# ── discovery_agent helper tests ─────────────────────────────────────────

class TestDiscoveryAgentSsti:
    def test_ssti_hit_detects_evaluated(self):
        from dast.agents.discovery_agent import _ssti_hit
        assert _ssti_hit("${7*7}", "49", "The result is: 49.") is True

    def test_ssti_hit_rejects_echoed_payload(self):
        from dast.agents.discovery_agent import _ssti_hit
        # Server echoed the payload verbatim — not evaluated
        assert _ssti_hit("${7*7}", "49", "You entered: ${7*7}") is False

    def test_ssti_hit_rejects_substring_in_larger_number(self):
        from dast.agents.discovery_agent import _ssti_hit
        # "49" inside a UUID/larger number must not trigger
        assert _ssti_hit("${7*7}", "49", "ref=abc1490xyz") is False

    def test_ssti_hit_finds_eval_in_complex_response(self):
        from dast.agents.discovery_agent import _ssti_hit
        body = '<html><body><p>Evaluation result: 49</p></body></html>'
        assert _ssti_hit("{{7*7}}", "49", body) is True


# ── mfa_agent helper tests ────────────────────────────────────────────────

class TestMfaAgentHelpers:
    def test_find_otp_param_json(self):
        from dast.agents.mfa_agent import _find_otp_param
        assert _find_otp_param('{"otp": "123456"}') == "otp"

    def test_find_otp_param_code(self):
        from dast.agents.mfa_agent import _find_otp_param
        assert _find_otp_param('{"code": "123456", "email": "a@b.com"}') == "code"

    def test_find_otp_param_totp(self):
        from dast.agents.mfa_agent import _find_otp_param
        assert _find_otp_param('{"totp_code": "123456"}') == "totp_code"

    def test_find_otp_param_not_found(self):
        from dast.agents.mfa_agent import _find_otp_param
        assert _find_otp_param('{"email": "a@b.com", "password": "secret"}') is None

    def test_replace_otp(self):
        from dast.agents.mfa_agent import _replace_otp
        result = _replace_otp('{"otp": "123456"}', "otp", "000000")
        import json
        assert json.loads(result)["otp"] == "000000"

    def test_remove_param(self):
        from dast.agents.mfa_agent import _remove_param
        result = _remove_param('{"otp": "123456", "email": "a@b.com"}', "otp")
        import json
        parsed = json.loads(result)
        assert "otp" not in parsed
        assert "email" in parsed

    def test_status_changed_to_success(self):
        from dast.agents.mfa_agent import _status_changed_to_success
        assert _status_changed_to_success(401, 200) is True
        assert _status_changed_to_success(200, 200) is False
        assert _status_changed_to_success(200, 403) is False


# ── passive scanner confirmed field tests ────────────────────────────────

class TestPassiveScannerConfirmed:
    def _run_rule_by_id(self, entry, rule_id):
        from dast.plugins.passive_scanner import _eval_rule, _load_all_rules, _conditions_match
        fired_hosts = {}
        for rule in _load_all_rules():
            if rule.get("id") == rule_id:
                if _conditions_match(rule, entry, fired_hosts):
                    return _eval_rule(rule, entry)
        return []

    def _make_entry(self, **kwargs):
        from dataclasses import dataclass as dc, field as f

        @dc
        class E:
            url: str = "https://example.com/"
            path: str = "/"
            method: str = "GET"
            host: str = "example.com"
            response_status: Optional[int] = 200
            response_headers: Dict = f(default_factory=dict)
            response_body: Optional[bytes] = b""
            request_headers: Dict = f(default_factory=dict)
            content_type: str = "text/html"

        defaults = dict(
            url="https://example.com/",
            path="/",
            method="GET",
            host="example.com",
            response_status=200,
            response_headers={"content-type": "text/html"},
            response_body=b"",
            request_headers={},
            content_type="text/html",
        )
        defaults.update(kwargs)
        return E(**defaults)

    def test_apache_cve_rule_is_not_confirmed(self):
        entry = self._make_entry(
            response_headers={
                "content-type": "text/html",
                "server": "Apache/2.4.51 (Ubuntu)",
            }
        )
        findings = self._run_rule_by_id(entry, "http2-apache-continuation-flood")
        assert findings, "Rule should fire on vulnerable Apache version"
        # confirmed must be False — version range is a suspicion, not proof
        confirmed = findings[0][8]
        assert confirmed is False, f"Expected confirmed=False, got {confirmed}"

    def test_envoy_cve_rule_is_not_confirmed(self):
        entry = self._make_entry(
            response_headers={
                "content-type": "text/html",
                "server": "envoy/1.29.1",
            }
        )
        findings = self._run_rule_by_id(entry, "http2-envoy-continuation-flood")
        assert findings
        assert findings[0][8] is False

    def test_cors_wildcard_is_not_confirmed(self):
        entry = self._make_entry(
            response_headers={"access-control-allow-origin": "*"},
        )
        findings = self._run_rule_by_id(entry, "cors-wildcard-origin")
        assert findings
        assert findings[0][8] is False

    def test_secret_finding_is_confirmed_by_default(self):
        entry = self._make_entry(
            response_body=b'{"token": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"}',
        )
        from dast.plugins.passive_scanner import _eval_rule, _load_all_rules, _conditions_match
        fired_hosts = {}
        for rule in _load_all_rules():
            if "github" in rule.get("id", "").lower():
                if _conditions_match(rule, entry, fired_hosts):
                    findings = _eval_rule(rule, entry)
                    if findings:
                        assert findings[0][8] is True
                        return
        pytest.skip("GitHub token rule not found")


# ── session refresh worker tests ──────────────────────────────────────────

class TestSessionRefreshWorker:
    def _make_entry(self, status=200, location="", body="", source="proxy"):
        e = MagicMock()
        e.source = source
        e.status_code = status
        e.response_headers = {"location": location} if location else {}
        e.response_body = body.encode() if body else b""
        return e

    def test_detects_401(self):
        from dast.session.refresh_worker import _is_expiry_signal
        entry = self._make_entry(status=401)
        assert _is_expiry_signal(entry) is True

    def test_detects_redirect_to_login(self):
        from dast.session.refresh_worker import _is_expiry_signal
        entry = self._make_entry(status=302, location="https://app.example.com/login")
        assert _is_expiry_signal(entry) is True

    def test_detects_session_expired_in_body(self):
        from dast.session.refresh_worker import _is_expiry_signal
        entry = self._make_entry(status=200, body='{"error": "Session expired, please log in again"}')
        assert _is_expiry_signal(entry) is True

    def test_normal_200_is_not_expiry(self):
        from dast.session.refresh_worker import _is_expiry_signal
        entry = self._make_entry(status=200, body='{"data": "some result"}')
        assert _is_expiry_signal(entry) is False

    def test_agent_source_skipped(self):
        from dast.session.refresh_worker import _is_expiry_signal
        # 401 from an agent probe must NOT trigger re-auth
        entry = self._make_entry(status=401, source="agent")
        assert _is_expiry_signal(entry) is False

    def test_redirect_to_non_login_is_not_expiry(self):
        from dast.session.refresh_worker import _is_expiry_signal
        entry = self._make_entry(status=302, location="https://app.example.com/dashboard")
        assert _is_expiry_signal(entry) is False
