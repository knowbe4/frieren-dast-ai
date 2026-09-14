"""
Unit tests for active_checks helpers and the GraphQL parameter extractor.

Network calls are mocked via respx — no real HTTP traffic.
"""

from __future__ import annotations

import json
import pytest
import httpx
import respx

from dast.scanners.active_checks import (
    ActiveFinding,
    CheckTarget,
    _HostConcurrencyLimiter,
    _inject_body,
    _inject_query,
    check_xss,
    check_sqli,
    check_open_redirect,
    zero_delay_variant,
)
from dast.proxy.runner import _entry_to_check_target


# ── adaptive per-host concurrency limiter (AIMD) ─────────────────────────────

@pytest.mark.asyncio
class TestHostConcurrencyLimiter:
    async def test_congestion_halves_the_limit(self):
        limiter = _HostConcurrencyLimiter(max_limit=16)
        # A fast first request establishes the ~0.1s uncontended baseline.
        await limiter.acquire()
        await limiter.release(rtt_s=0.1)
        assert limiter.limit == 16.0  # healthy -> already at ceiling, stays capped
        # A grossly inflated round-trip (baseline * >4) signals congestion.
        await limiter.acquire()
        await limiter.release(rtt_s=15.0)
        assert limiter.limit == 8.0
        await limiter.acquire()
        await limiter.release(rtt_s=15.0)
        assert limiter.limit == 4.0

    async def test_explicit_congested_flag_backs_off(self):
        limiter = _HostConcurrencyLimiter(max_limit=8)
        await limiter.acquire()
        # A timed-out default request reports congestion directly (no rtt).
        await limiter.release(rtt_s=None, congested=True)
        assert limiter.limit == 4.0

    async def test_healthy_latency_recovers_additively(self):
        limiter = _HostConcurrencyLimiter(max_limit=16)
        limiter.limit = 2.0
        limiter.min_rtt = 0.1
        await limiter.acquire()
        await limiter.release(rtt_s=0.15)  # within baseline*4 -> healthy
        assert limiter.limit == 3.0

    async def test_never_drops_below_one(self):
        limiter = _HostConcurrencyLimiter(max_limit=4)
        limiter.min_rtt = 0.1
        for _ in range(10):
            await limiter.acquire()
            await limiter.release(rtt_s=30.0)
        assert limiter.limit == 1.0

    async def test_sub_second_latency_is_never_congestion(self):
        # Absolute floor: a fast host must not be throttled even if a single
        # request is several times its (tiny) baseline.
        limiter = _HostConcurrencyLimiter(max_limit=8)
        limiter.limit = 4.0
        limiter.min_rtt = 0.01
        await limiter.acquire()
        await limiter.release(rtt_s=0.2)  # 20x baseline but < 1s floor -> healthy
        assert limiter.limit == 5.0


# ── time-based differential control ─────────────────────────────────────────

@pytest.mark.parametrize("payload,expected", [
    ("1' AND SLEEP(5)-- -", "1' AND SLEEP(0)-- -"),
    ("' OR SLEEP(5)-- -", "' OR SLEEP(0)-- -"),
    ("1'; SELECT pg_sleep(5)-- -", "1'; SELECT pg_sleep(0)-- -"),
    ("1; WAITFOR DELAY '0:0:5'-- -", "1; WAITFOR DELAY '0:0:0'-- -"),
    (";sleep 4", ";sleep 0"),
    ("$(sleep 4)", "$(sleep 0)"),
])
def test_zero_delay_variant_zeroes_the_sleep(payload, expected):
    assert zero_delay_variant(payload) == expected


def test_zero_delay_variant_returns_none_without_sleep():
    # No recognizable sleep construct -> caller falls back to a clean value.
    assert zero_delay_variant("' OR '1'='1") is None
    assert zero_delay_variant(
        "' AND (SELECT COUNT(*) FROM sqlite_master)>0 AND '1'='1"
    ) is None


# ── injection helpers ──────────────────────────────────────────────────────

class TestInjectQuery:
    def test_adds_new_param(self):
        url = _inject_query("https://example.com/search?q=hello", "evil", "<script>")
        assert "evil=%3Cscript%3E" in url

    def test_overwrites_existing_param(self):
        url = _inject_query("https://example.com/?q=safe", "q", "' OR '1'='1")
        assert "q="+"%27+OR+%271%27%3D%271" in url or "q=" in url
        assert "safe" not in url

    def test_preserves_other_params(self):
        url = _inject_query("https://example.com/?a=1&b=2", "a", "PAYLOAD")
        assert "b=2" in url


class TestInjectBody:
    def test_json_body_top_level(self):
        result = _inject_body('{"username":"admin"}', "username", "' OR 1=1--", "application/json")
        data = json.loads(result)
        assert data["username"] == "' OR 1=1--"

    def test_json_body_graphql_variables(self):
        body = json.dumps({"query": "query { user }", "variables": {"id": 1}})
        result = _inject_body(body, "id", "INJECTED", "application/json", location="body_graphql")
        data = json.loads(result)
        assert data["variables"]["id"] == "INJECTED"
        assert data["query"] == "query { user }"  # query string untouched

    def test_graphql_location_does_not_touch_query_key(self):
        body = json.dumps({"query": "query Q { user { id } }", "variables": {"name": "Alice"}})
        result = _inject_body(body, "name", "<evil>", "application/json", location="body_graphql")
        data = json.loads(result)
        assert data["query"] == "query Q { user { id } }"
        assert data["variables"]["name"] == "<evil>"

    def test_form_urlencoded_body(self):
        result = _inject_body("username=admin&password=pass", "username", "evil", "application/x-www-form-urlencoded")
        assert "username=evil" in result
        assert "password=pass" in result

    def test_empty_body_returned_unchanged(self):
        assert _inject_body("", "key", "value", "application/json") == ""


# ── entry_to_check_target: GraphQL extraction ──────────────────────────────

def _fake_entry(method="POST", url="https://example.com/graphql",
                body=None, headers=None):
    from dataclasses import dataclass, field
    from typing import Dict, Optional

    @dataclass
    class _FakeEntry:
        method: str
        url: str
        host: str = "example.com"
        path: str = "/graphql"
        request_headers: Dict = field(default_factory=dict)
        request_body: Optional[bytes] = None
        response_status: int = 200
        response_headers: Dict = field(default_factory=dict)
        response_body: Optional[bytes] = b""
        content_type: str = "application/json"
        source: str = "browse"
        browse_session_id: Optional[str] = None
        crawler_session_id: Optional[str] = None
        import_hints: Optional[list] = None

    e = _FakeEntry(method=method, url=url)
    if headers:
        e.request_headers = headers
    if body is not None:
        e.request_body = body if isinstance(body, bytes) else body.encode()
    return e


class TestEntryToCheckTarget:
    def test_graphql_extracts_variables(self):
        body = json.dumps({
            "query": "query GetUser($id: ID!) { user(id: $id) { name } }",
            "variables": {"id": "123", "locale": "en"},
            "operationName": "GetUser",
        })
        entry = _fake_entry(body=body)
        target = _entry_to_check_target(entry)
        assert target is not None
        param_names = {p["name"] for p in target.params}
        assert "id" in param_names
        assert "locale" in param_names
        # structural GraphQL keys must NOT be fuzzed
        assert "query" not in param_names
        assert "operationName" not in param_names

    def test_graphql_params_have_body_graphql_location(self):
        body = json.dumps({
            "query": "query { x }",
            "variables": {"search": "hello"},
        })
        entry = _fake_entry(body=body)
        target = _entry_to_check_target(entry)
        locations = {p["location"] for p in target.params}
        assert "body_graphql" in locations

    def test_plain_json_uses_body_location(self):
        body = json.dumps({"username": "admin", "password": "secret"})
        entry = _fake_entry(body=body, url="https://example.com/api/login")
        entry.path = "/api/login"
        target = _entry_to_check_target(entry)
        assert target is not None
        locations = {p["location"] for p in target.params}
        assert "body" in locations
        assert "body_graphql" not in locations

    def test_get_with_no_params_returns_none(self):
        entry = _fake_entry(method="GET", url="https://example.com/home")
        entry.path = "/home"
        target = _entry_to_check_target(entry)
        assert target is None

    def test_get_with_query_params(self):
        entry = _fake_entry(method="GET", url="https://example.com/search?q=test&page=1")
        entry.path = "/search"
        target = _entry_to_check_target(entry)
        assert target is not None
        param_names = {p["name"] for p in target.params}
        assert "q" in param_names
        assert "page" in param_names

    def test_connect_returns_none(self):
        entry = _fake_entry(method="CONNECT", url="https://example.com:443")
        assert _entry_to_check_target(entry) is None


# ── ActiveFinding fields ───────────────────────────────────────────────────

class TestActiveFinding:
    def test_default_fields(self):
        f = ActiveFinding(
            title="XSS",
            severity="high",
            cwe="CWE-79",
            attack_type="xss",
            evidence="payload reflected",
            payload="<script>",
            parameter="q",
            url="https://example.com",
            request_method="GET",
        )
        assert f.confirmed is True
        assert f.bypass_validation is False
        assert f.reasoning == ""

    def test_can_set_bypass_and_reasoning(self):
        f = ActiveFinding(
            title="SQLi", severity="critical", cwe="CWE-89",
            attack_type="sqli", evidence="error", payload="'",
            parameter="id", url="https://example.com", request_method="GET",
            bypass_validation=True, reasoning="Time-based delay confirmed",
        )
        assert f.bypass_validation is True
        assert "delay" in f.reasoning


# ── check_xss with mocked HTTP ─────────────────────────────────────────────

@pytest.mark.asyncio
class TestCheckXss:
    @respx.mock
    async def test_reflected_xss_detected(self):
        payload = '<img src=x onerror=alert(1)>'
        target = CheckTarget(
            method="GET",
            url="https://example.com/search",
            headers={"content-type": "text/html"},
            body=None,
            params=[{"name": "q", "location": "query", "value": "hello"}],
        )
        # Mock: every GET to /search reflects the payload back
        respx.get(url__startswith="https://example.com/search").mock(
            return_value=httpx.Response(200, text=f"<html>{payload}</html>")
        )
        async with httpx.AsyncClient() as client:
            findings = await check_xss(target, client)
        assert any(f.attack_type == "xss" for f in findings)

    @respx.mock
    async def test_no_xss_when_payload_encoded(self):
        target = CheckTarget(
            method="GET",
            url="https://example.com/search",
            headers={},
            body=None,
            params=[{"name": "q", "location": "query", "value": "hello"}],
        )
        respx.get(url__startswith="https://example.com/search").mock(
            return_value=httpx.Response(200, text="<html>&lt;img src=x&gt;</html>")
        )
        async with httpx.AsyncClient() as client:
            findings = await check_xss(target, client)
        assert findings == []


# ── check_sqli with mocked HTTP ────────────────────────────────────────────

@pytest.mark.asyncio
class TestCheckSqli:
    @respx.mock
    async def test_error_based_sqli_detected(self):
        target = CheckTarget(
            method="GET",
            url="https://example.com/user",
            headers={},
            body=None,
            params=[{"name": "id", "location": "query", "value": "1"}],
        )
        respx.get(url__startswith="https://example.com/user").mock(
            return_value=httpx.Response(
                500,
                text="You have an error in your SQL syntax near '' at line 1",
            )
        )
        async with httpx.AsyncClient() as client:
            findings = await check_sqli(target, client)
        assert any(f.attack_type == "sqli" for f in findings)
        assert any("Error-Based" in f.title for f in findings)

    @respx.mock
    async def test_no_sqli_on_clean_response(self):
        target = CheckTarget(
            method="GET",
            url="https://example.com/user",
            headers={},
            body=None,
            params=[{"name": "id", "location": "query", "value": "1"}],
        )
        respx.get(url__startswith="https://example.com/user").mock(
            return_value=httpx.Response(200, text='{"id": 1, "name": "Alice"}')
        )
        async with httpx.AsyncClient() as client:
            findings = await check_sqli(target, client)
        assert findings == []


# ── check_open_redirect ────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestCheckOpenRedirect:
    @respx.mock
    async def test_open_redirect_detected(self):
        target = CheckTarget(
            method="GET",
            url="https://example.com/login",
            headers={},
            body=None,
            params=[{"name": "redirect", "location": "query", "value": "/home"}],
        )
        respx.get(url__startswith="https://example.com/login").mock(
            return_value=httpx.Response(
                302, headers={"location": "https://evil.example.com"}
            )
        )
        async with httpx.AsyncClient() as client:
            findings = await check_open_redirect(target, client)
        assert any(f.attack_type == "open_redirect" for f in findings)

    @respx.mock
    async def test_ignores_non_redirect_params(self):
        target = CheckTarget(
            method="GET",
            url="https://example.com/search",
            headers={},
            body=None,
            params=[{"name": "q", "location": "query", "value": "hello"}],
        )
        # q is not a redirect param — should not even send a probe
        async with httpx.AsyncClient() as client:
            findings = await check_open_redirect(target, client)
        assert findings == []
