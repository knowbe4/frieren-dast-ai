"""
Unit tests for the generic HTTP reproduction path (_validate_http).

Covers the Phase-3 upgrades:
  - Full method/body reproduction: a POST/PUT PoC is replayed with its actual
    method, headers and body (not silently downgraded to a GET proof URL).
  - Schema-forced verdict: the reproduction verdict flows through
    H1_VERDICT_SCHEMA (typed reproduced/confidence/severity), not the legacy
    free-text regex parser.
  - Payload safety still gates the body: a destructive body payload is
    neutralised before anything is sent.

The real httpx client and LLM gateway are stubbed so the tests are hermetic.
"""

from __future__ import annotations

import httpx
import pytest

from dast.hackerone import validator
from dast.hackerone.parser import H1Report


class _FakeResponse:
    def __init__(self, status_code=200, text="", url="https://api.acme-corp.com/v1", headers=None):
        self.status_code = status_code
        self.text = text
        self.url = url
        self.headers = headers or {"Content-Type": "application/json"}


class _FakeClient:
    """Captures the outbound request instead of sending it."""

    captured: dict = {}

    def __init__(self, response: _FakeResponse, **kwargs):
        self._response = response
        _FakeClient.captured = {"client_kwargs": kwargs}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def request(self, method, url, content=None):
        _FakeClient.captured["method"] = method
        _FakeClient.captured["url"] = url
        _FakeClient.captured["content"] = content
        return self._response

    async def get(self, url):  # legacy path guard — should NOT be hit anymore
        _FakeClient.captured["method"] = "GET-legacy"
        _FakeClient.captured["url"] = url
        return self._response


def _patch_client(monkeypatch, response: _FakeResponse):
    monkeypatch.setattr(
        httpx, "AsyncClient", lambda **kw: _FakeClient(response, **kw)
    )


def _patch_verdict(monkeypatch, verdict: dict, captured: dict):
    def fake_invoke_json(system, user, **kwargs):
        captured["schema"] = kwargs.get("schema")
        captured["user"] = user
        return verdict

    monkeypatch.setattr("dast.ai.bedrock_client.invoke_json", fake_invoke_json)


@pytest.mark.asyncio
async def test_post_body_reproduced_and_confirmed(monkeypatch):
    resp = _FakeResponse(status_code=200, text='{"balance": 999999}')
    _patch_client(monkeypatch, resp)
    verdict_capture: dict = {}
    _patch_verdict(
        monkeypatch,
        {
            "reproduced": True,
            "confidence": 0.97,
            "severity": "high",
            "exploit_scenario": "Attacker escalates via id field.",
            "reasoning": "Response reflects the injected id, confirming IDOR.",
        },
        verdict_capture,
    )

    report = H1Report(
        vuln_type="idor",
        proof_url="https://api.acme-corp.com/v1/transfer",
        payload="42",
        http_method="POST",
        request_headers={"Content-Type": "application/json", "Authorization": "Bearer x"},
        request_body='{"account_id": 42}',
        summary="IDOR on transfer endpoint.",
    )

    result = await validator._validate_http(report, proxy_port=8080, cookies={})

    # The POST method and body were sent verbatim.
    assert _FakeClient.captured["method"] == "POST"
    assert _FakeClient.captured["content"] == b'{"account_id": 42}'
    # Auth header stripped (the session supplies auth); Content-Type kept.
    ckw = _FakeClient.captured["client_kwargs"]
    assert "Authorization" not in ckw["headers"]
    assert ckw["headers"]["Content-Type"] == "application/json"
    # Schema-forced verdict path was used.
    assert verdict_capture["schema"] is not None
    assert result.status == "confirmed"
    assert "high" in result.evidence


@pytest.mark.asyncio
async def test_low_confidence_not_confirmed(monkeypatch):
    resp = _FakeResponse(status_code=200, text="nothing interesting")
    _patch_client(monkeypatch, resp)
    _patch_verdict(
        monkeypatch,
        {
            "reproduced": False,
            "confidence": 0.30,
            "severity": "info",
            "exploit_scenario": "",
            "reasoning": "No evidence of reflection.",
        },
        {},
    )

    report = H1Report(
        vuln_type="xss",
        proof_url="https://api.acme-corp.com/v1/search?q=test",
        payload="test",
        http_method="GET",
        summary="Reflected XSS.",
    )

    result = await validator._validate_http(report, proxy_port=8080, cookies={})
    assert result.status == "needs_manual"


@pytest.mark.asyncio
async def test_destructive_body_payload_neutralised(monkeypatch):
    # A destructive SQLi body payload must be rewritten to a safe variant before
    # it is sent — the raw DROP TABLE must never reach the target.
    resp = _FakeResponse(status_code=200, text="ok")
    _patch_client(monkeypatch, resp)
    _patch_verdict(
        monkeypatch,
        {
            "reproduced": False, "confidence": 0.1, "severity": "info",
            "exploit_scenario": "", "reasoning": "safe probe, no error",
        },
        {},
    )

    destructive = "1; DROP TABLE users--"
    report = H1Report(
        vuln_type="sqli",
        proof_url="https://api.acme-corp.com/v1/items",
        payload=destructive,
        http_method="POST",
        request_body='{"filter": "1; DROP TABLE users--"}',
        summary="SQLi via filter.",
    )

    result = await validator._validate_http(report, proxy_port=8080, cookies={})

    content = _FakeClient.captured.get("content")
    if content is not None:
        # If anything was sent, the destructive statement must be gone.
        assert b"DROP TABLE" not in content
    else:
        # Otherwise it was blocked outright (also acceptable, also safe).
        assert result.status == "needs_manual"


@pytest.mark.asyncio
async def test_profile_auth_extracts_cookies(monkeypatch):
    # A resolved profile session's storage_state cookies are flattened into a
    # {name: value} map ready for re-validation.
    from dast.proxy.api import hackerone_routes

    async def fake_reauth(host, proxy_port):
        assert host == "api.acme-corp.com"
        return {"cookies": [
            {"name": "session", "value": "abc"},
            {"name": "csrf", "value": "xyz"},
            {"name": "broken"},  # no value — skipped
        ]}

    monkeypatch.setattr(
        "dast.session.profile_reauth.reauth_from_profile", fake_reauth
    )
    report = H1Report(proof_url="https://api.acme-corp.com/v1/users/1", vuln_type="idor")
    cookies = await hackerone_routes._try_profile_auth(report, proxy_port=8080)
    assert cookies == {"session": "abc", "csrf": "xyz"}


@pytest.mark.asyncio
async def test_profile_auth_no_match_returns_empty(monkeypatch):
    from dast.proxy.api import hackerone_routes

    async def fake_reauth(host, proxy_port):
        return None

    monkeypatch.setattr(
        "dast.session.profile_reauth.reauth_from_profile", fake_reauth
    )
    report = H1Report(proof_url="https://api.acme-corp.com/x", vuln_type="idor")
    assert await hackerone_routes._try_profile_auth(report, proxy_port=8080) == {}


def test_persist_finding_creates_entry_and_finding():
    from dast.proxy.api import hackerone_routes
    from dast.hackerone.validator import ValidationResult

    class _FakeStore:
        def __init__(self):
            self.entries = {}
            self.findings = []

        def new_entry(self, method, url, request_headers, request_body, source):
            eid = "e1"
            self.entries[eid] = {"method": method, "url": url, "source": source}
            return eid

        def add_finding(self, entry_id, finding, scan_result):
            self.findings.append((entry_id, finding, scan_result))

    class _FakeCtx:
        def __init__(self, store):
            self.store = store

    store = _FakeStore()
    ctx = _FakeCtx(store)
    report = H1Report(
        vuln_type="idor",
        proof_url="https://api.acme-corp.com/v1/users/42",
        payload="42",
        http_method="POST",
        request_body='{"id": 42}',
    )
    result = ValidationResult(
        job_id="j1", status="confirmed", vuln_type="idor",
        proof_url="https://api.acme-corp.com/v1/users/42", payload="42",
        evidence="reflected id 42", severity="high",
    )
    hackerone_routes._persist_finding(ctx, report, result)

    assert store.entries["e1"]["method"] == "POST"
    assert store.entries["e1"]["source"] == "agent"
    assert len(store.findings) == 1
    _, finding, scan_result = store.findings[0]
    assert scan_result == "vulnerable"
    assert finding["attack_type"] == "idor"
    assert finding["severity"] == "high"
    assert finding["cwe"] == "CWE-639"


@pytest.mark.asyncio
async def test_auth_wall_returns_needs_auth(monkeypatch):
    resp = _FakeResponse(status_code=401, text="Please log in", url="https://api.acme-corp.com/login")
    _patch_client(monkeypatch, resp)
    _patch_verdict(monkeypatch, {"reproduced": False, "confidence": 0.0, "severity": "info",
                                 "exploit_scenario": "", "reasoning": ""}, {})

    report = H1Report(
        vuln_type="idor",
        proof_url="https://api.acme-corp.com/v1/users/1",
        payload="1",
        http_method="GET",
        summary="IDOR.",
    )

    result = await validator._validate_http(report, proxy_port=8080, cookies={})
    assert result.status == "needs_auth"
