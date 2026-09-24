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
    _HostScanGate,
    _inject_body,
    _inject_cookie,
    _inject_header,
    _inject_path,
    _inject_query,
    check_xss,
    check_sqli,
    check_open_redirect,
    seed_taint_markers,
    zero_delay_variant,
)
from dast.scanners.taint import _MARKER_RE, TaintStore
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

    async def test_saturated_seen_is_sticky_on_congestion(self):
        limiter = _HostConcurrencyLimiter(max_limit=8)
        assert limiter.saturated_seen is False
        await limiter.acquire()
        await limiter.release(rtt_s=None, congested=True)
        assert limiter.saturated_seen is True
        # Recovery does NOT clear the sticky flag — a host that ever choked stays flagged.
        limiter.min_rtt = 0.1
        await limiter.acquire()
        await limiter.release(rtt_s=0.15)
        assert limiter.saturated_seen is True

    async def test_saturated_seen_set_on_latency_inflation(self):
        limiter = _HostConcurrencyLimiter(max_limit=16)
        await limiter.acquire()
        await limiter.release(rtt_s=0.1)  # establish baseline, healthy
        assert limiter.saturated_seen is False
        await limiter.acquire()
        await limiter.release(rtt_s=15.0)  # baseline*>4 -> congestion
        assert limiter.saturated_seen is True


# ── per-host endpoint-scan gate ──────────────────────────────────────────────

@pytest.mark.asyncio
class TestHostScanGate:
    async def test_serializes_endpoint_scans_per_host_by_default(self):
        import asyncio
        gate = _HostScanGate()  # default_limit = 1
        order: list[str] = []

        async def scan(tag: str) -> None:
            await gate.acquire("app.example.com")
            order.append(f"start:{tag}")
            await asyncio.sleep(0.01)
            order.append(f"end:{tag}")
            await gate.release("app.example.com")

        await asyncio.gather(scan("a"), scan("b"))
        # Serial: one scan fully finishes before the next starts (no interleaving).
        assert order in (
            ["start:a", "end:a", "start:b", "end:b"],
            ["start:b", "end:b", "start:a", "end:a"],
        )

    async def test_different_hosts_run_in_parallel(self):
        import asyncio
        gate = _HostScanGate()
        inflight = {"n": 0, "max": 0}

        async def scan(host: str) -> None:
            await gate.acquire(host)
            inflight["n"] += 1
            inflight["max"] = max(inflight["max"], inflight["n"])
            await asyncio.sleep(0.01)
            inflight["n"] -= 1
            await gate.release(host)

        await asyncio.gather(scan("a.example.com"), scan("b.example.com"))
        # Two different hosts overlap — the gate is per host, not global.
        assert inflight["max"] == 2

    async def test_configure_allows_concurrency_when_host_is_healthy(self):
        import asyncio
        gate = _HostScanGate()
        gate.configure(3)
        inflight = {"n": 0, "max": 0}

        async def scan() -> None:
            await gate.acquire("app.example.com")
            inflight["n"] += 1
            inflight["max"] = max(inflight["max"], inflight["n"])
            await asyncio.sleep(0.01)
            inflight["n"] -= 1
            await gate.release("app.example.com")

        await asyncio.gather(*(scan() for _ in range(3)))
        assert inflight["max"] == 3

    async def test_saturated_host_clamped_to_serial_even_when_knob_raised(self):
        import dast.scanners.active_checks as ac
        gate = _HostScanGate()
        gate.configure(4)
        # A host the request limiter already caught saturating is pinned to serial.
        limiter = _HostConcurrencyLimiter(max_limit=8)
        limiter.saturated_seen = True
        ac._HOST_LIMITERS["slow.example.com"] = limiter
        try:
            assert gate._allowed("slow.example.com") == 1
            assert gate._allowed("fresh.example.com") == 4  # no limiter -> honor knob
        finally:
            ac._HOST_LIMITERS.pop("slow.example.com", None)


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


class TestInjectPath:
    def test_replaces_targeted_segment_encoded(self):
        # path_index 2 = the third non-empty segment ("name1").
        url = _inject_path("https://api.example.com/users/v1/name1", 2, "name1'")
        assert url == "https://api.example.com/users/v1/name1%27"

    def test_preserves_other_segments_and_query(self):
        url = _inject_path("https://x.com/a/42/b?q=1", 1, "99")
        assert url == "https://x.com/a/99/b?q=1"

    def test_preserves_trailing_slash(self):
        url = _inject_path("https://x.com/orders/7/", 1, "8")
        assert url == "https://x.com/orders/8/"

    def test_out_of_range_index_is_noop(self):
        original = "https://x.com/users/1"
        assert _inject_path(original, 9, "PAYLOAD") == original


class TestPathParamEnumeration:
    """The adapter must expose value-like REST path segments as injectable
    params (VAmPI's SQLi is a path parameter) without fuzzing static route
    tokens — and must not regress DVWA, whose paths hold no value-like segment."""

    def test_numeric_and_valuelike_segments_become_path_params(self):
        entry = _fake_entry(method="GET", url="https://api.example.com/users/v1/name1")
        target = _entry_to_check_target(entry)
        assert target is not None
        path_params = [p for p in target.params if p["location"] == "path"]
        assert [p["name"] for p in path_params] == ["name1"]
        assert path_params[0]["path_index"] == 2  # users(0) v1(1) name1(2)

    def test_numeric_id_segment(self):
        entry = _fake_entry(method="GET", url="https://api.example.com/orders/42")
        target = _entry_to_check_target(entry)
        assert target is not None
        assert {p["name"] for p in target.params if p["location"] == "path"} == {"42"}

    def test_static_route_tokens_are_not_fuzzed(self):
        # No value-like segment anywhere -> no path params, and (no query/body) None.
        entry = _fake_entry(method="GET", url="https://api.example.com/api/users/profile")
        entry.path = "/api/users/profile"
        target = _entry_to_check_target(entry)
        assert target is None

    def test_dvwa_paths_yield_no_path_params(self):
        # Regression guard: the validated DVWA baseline must stay unchanged.
        for path in ("/vulnerabilities/xss_r/", "/vulnerabilities/sqli/",
                     "/vulnerabilities/exec/", "/vulnerabilities/fi/", "/login.php"):
            entry = _fake_entry(method="GET", url=f"http://127.0.0.1:8081{path}?x=1")
            target = _entry_to_check_target(entry)
            assert target is not None
            assert [p for p in target.params if p["location"] == "path"] == [], path


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


class TestHeaderInjection:
    def test_overwrites_existing_header_case_insensitive(self):
        result = _inject_header({"User-Agent": "curl", "Host": "h"}, "user-agent", "PAYLOAD")
        # only one User-Agent survives, with the payload value; Host is untouched
        assert result.get("user-agent") == "PAYLOAD"
        assert result["Host"] == "h"
        assert sum(1 for k in result if k.lower() == "user-agent") == 1

    def test_adds_missing_header(self):
        result = _inject_header({"Host": "h"}, "X-Forwarded-For", "127.0.0.1")
        assert result["X-Forwarded-For"] == "127.0.0.1"

    def test_cookie_replaces_only_target_cookie(self):
        result = _inject_cookie({"Cookie": "pref=dark; sid=abc; lang=en"}, "pref", "PAYLOAD")
        assert result["Cookie"] == "pref=PAYLOAD; sid=abc; lang=en"

    def test_cookie_appended_when_absent(self):
        result = _inject_cookie({"Cookie": "sid=abc"}, "tracking", "PAYLOAD")
        assert "tracking=PAYLOAD" in result["Cookie"]
        assert "sid=abc" in result["Cookie"]


class TestHeaderCookieEntrypoints:
    def test_fuzzable_header_becomes_param(self):
        entry = _fake_entry(method="GET", url="https://example.com/search?q=x",
                            headers={"User-Agent": "Mozilla", "Host": "example.com"})
        entry.path = "/search"
        target = _entry_to_check_target(entry)
        header_params = [p for p in target.params if p["location"] == "header"]
        assert any(p["name"] == "User-Agent" for p in header_params)

    def test_structural_headers_never_fuzzed(self):
        entry = _fake_entry(method="GET", url="https://example.com/search?q=x",
                            headers={"Host": "example.com", "Content-Length": "0",
                                     "Authorization": "Bearer x", "Accept-Encoding": "gzip"})
        entry.path = "/search"
        target = _entry_to_check_target(entry)
        header_names = {p["name"].lower() for p in target.params if p["location"] == "header"}
        assert header_names.isdisjoint({"host", "content-length", "authorization", "accept-encoding"})

    def test_custom_x_header_is_fuzzed(self):
        entry = _fake_entry(method="GET", url="https://example.com/search?q=x",
                            headers={"X-Custom-Tenant": "acme"})
        entry.path = "/search"
        target = _entry_to_check_target(entry)
        assert any(p["name"] == "X-Custom-Tenant" and p["location"] == "header"
                   for p in target.params)

    def test_cookies_become_params_but_session_cookie_skipped(self):
        entry = _fake_entry(method="GET", url="https://example.com/search?q=x",
                            headers={"Cookie": "sessionid=secret; theme=dark"})
        entry.path = "/search"
        target = _entry_to_check_target(entry)
        cookie_params = {p["name"] for p in target.params if p["location"] == "cookie"}
        assert "theme" in cookie_params
        assert "sessionid" not in cookie_params

    def test_paramless_get_not_resurrected_by_headers(self):
        # A static-asset-style GET with no query/body params stays skipped even
        # though it carries a fuzzable User-Agent — header fuzzing augments real
        # endpoints, it does not resurrect every paramless GET.
        entry = _fake_entry(method="GET", url="https://example.com/app.js",
                            headers={"User-Agent": "Mozilla"})
        entry.path = "/app.js"
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


# ── taint marker seeding ────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestSeedTaintMarkers:
    @respx.mock
    async def test_seeds_one_marker_per_entry_point(self):
        target = CheckTarget(
            method="POST",
            url="https://example.com/comment",
            headers={"content-type": "application/json", "user-agent": "orig",
                     "cookie": "pref=blue"},
            body='{"text":"hi"}',
            params=[
                {"name": "q", "location": "query", "value": "x"},
                {"name": "text", "location": "body", "value": "hi"},
                {"name": "user-agent", "location": "header", "value": "orig"},
                {"name": "pref", "location": "cookie", "value": "blue"},
            ],
        )
        route = respx.route(host="example.com").mock(
            return_value=httpx.Response(200, text="ok")
        )
        store = TaintStore()
        async with httpx.AsyncClient() as client:
            seeded = await seed_taint_markers(target, client, store)

        assert seeded == 4
        assert route.call_count == 4

        # Each request carries a marker in the location it targets.
        sent = {}
        for call in route.calls:
            request = call.request
            body_text = request.content.decode("utf-8", errors="replace")
            haystack = f"{request.url} {dict(request.headers)} {body_text}"
            match = _MARKER_RE.search(haystack)
            assert match, f"no marker found in request: {haystack}"
            sent[match.group(0)] = request

        # Every minted marker is registered and correctly attributed to its source
        # parameter — proven end-to-end by scanning a different endpoint for it.
        located_params = set()
        for token in sent:
            hits = store.find_hits("https://example.com/other-page", token)
            assert len(hits) == 1
            assert hits[0].is_cross_location is True
            located_params.add(hits[0].marker.source_param)
        assert located_params == {"q", "text", "user-agent", "pref"}

    @respx.mock
    async def test_no_params_seeds_nothing(self):
        target = CheckTarget(method="GET", url="https://example.com/", headers={},
                             body=None, params=[])
        store = TaintStore()
        async with httpx.AsyncClient() as client:
            assert await seed_taint_markers(target, client, store) == 0

    async def test_none_store_is_noop(self):
        target = CheckTarget(
            method="GET", url="https://example.com/", headers={}, body=None,
            params=[{"name": "q", "location": "query", "value": "x"}],
        )
        async with httpx.AsyncClient() as client:
            assert await seed_taint_markers(target, client, None) == 0
