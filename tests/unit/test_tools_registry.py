"""
Unit tests for the shared tool layer (dast/tools/) and the MCP conversion.

Covers the Phase-4 invariants:
  - the registry advertises every built-in tool with a valid JSON Schema,
  - run_tool routes to handlers and degrades unknown/failed calls to structured
    {"ok": False, ...} (never raises),
  - scope is enforced BEFORE any request is sent,
  - send_request refuses destructive payloads (offers a safe variant),
  - get_history reads the in-process store when present,
  - tool_definitions() produces MCP-shaped dicts without importing ``mcp``.
"""

from __future__ import annotations

import httpx
import pytest

import dast.tools as tools
from dast.tools import ToolContext, run_tool


class _Scope:
    def __init__(self, allow: bool = True):
        self.allow = allow

    def is_in_scope(self, url: str) -> bool:
        return self.allow


# ── registry ──────────────────────────────────────────────────────────────────

def test_registry_lists_builtin_tools():
    names = {t.name for t in tools.all_tools()}
    assert {"send_request", "get_history", "content_discovery",
            "param_mining", "triage_report", "validate_chain", "list_login_profiles",
            "get_findings", "record_finding", "oob_generate", "oob_poll",
            "url_encode", "url_decode", "base64_encode", "base64_decode",
            "html_encode", "html_decode", "graphql_introspect"} <= names


def test_every_tool_has_object_schema_and_handler():
    for t in tools.all_tools():
        assert t.input_schema.get("type") == "object", t.name
        assert callable(t.handler), t.name


@pytest.mark.asyncio
async def test_run_tool_unknown_degrades():
    ctx = ToolContext(settings=_Scope())
    result = await run_tool(ctx, "does_not_exist", {})
    assert result["ok"] is False
    assert "unknown tool" in result["error"]


@pytest.mark.asyncio
async def test_run_tool_never_raises_on_handler_error(monkeypatch):
    ctx = ToolContext(settings=_Scope(True))
    # Force the send path to blow up after scope passes.
    def boom(**kw):
        raise RuntimeError("kaboom")
    monkeypatch.setattr(httpx, "AsyncClient", boom)
    result = await run_tool(ctx, "send_request",
                            {"url": "https://api.acme-corp.com/x"})
    assert result["ok"] is False
    assert "request failed" in result["error"]


# ── send_request scope + safety ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_send_request_out_of_scope_blocked(monkeypatch):
    # A store-less (MCP) caller may ask the dashboard operator for an interactive
    # approval on an out-of-scope target. Stub that out so this test stays
    # hermetic and deterministic: with no operator approval, out-of-scope must be
    # a hard block. (Without the stub the test would long-poll a real dashboard if
    # one happened to be running on 127.0.0.1:8088, making the outcome depend on
    # the developer's environment.)
    async def _deny(ctx, url, method):
        return False

    monkeypatch.setattr("dast.tools.approval.request_approval", _deny)
    ctx = ToolContext(settings=_Scope(allow=False))
    result = await run_tool(ctx, "send_request",
                            {"url": "https://evil.example.com/x"})
    assert result["ok"] is False
    assert "out of scope" in result["error"]


@pytest.mark.asyncio
async def test_send_request_refuses_destructive_body():
    ctx = ToolContext(settings=_Scope(True))
    result = await run_tool(ctx, "send_request", {
        "method": "POST",
        "url": "https://api.acme-corp.com/items",
        "body": "1; DROP TABLE users--",
    })
    assert result["ok"] is False
    assert "destructive" in result["error"]
    assert "safe_variant" in result


@pytest.mark.asyncio
async def test_send_request_success(monkeypatch):
    class _Resp:
        status_code = 200
        text = "hello"
        url = "https://api.acme-corp.com/x"
        headers = {"Content-Type": "text/plain"}

    class _Client:
        def __init__(self, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def request(self, method, url, headers=None, content=None):
            return _Resp()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _Client(**kw))
    ctx = ToolContext(settings=_Scope(True))
    result = await run_tool(ctx, "send_request",
                            {"url": "https://api.acme-corp.com/x"})
    assert result["ok"] is True
    assert result["status"] == 200
    assert result["body"] == "hello"


@pytest.mark.asyncio
async def test_send_request_injects_csrf_from_jar(monkeypatch):
    # A cookie-authed Rails/SPA endpoint 403s without X-CSRF-Token + X-Requested-With.
    # The raw send_request tool path must inject them from the jar's CSRF cookie
    # (parity with the copilot engine's _apply_session_auth).
    captured: dict = {}

    class _Resp:
        status_code = 200
        text = "{}"
        url = "https://api.acme-corp.com/graphql"
        headers = {"Content-Type": "application/json"}

    class _Client:
        def __init__(self, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def request(self, method, url, headers=None, content=None):
            captured["headers"] = headers
            return _Resp()

    class _Store:
        def get_cookies_for_host(self, host):
            return [{"name": "CSRF-TOKEN", "value": "tok123"},
                    {"name": "_session", "value": "s"}]

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _Client(**kw))
    ctx = ToolContext(settings=_Scope(True), store=_Store())
    result = await run_tool(ctx, "send_request", {
        "url": "https://api.acme-corp.com/graphql", "method": "POST",
        "body": '{"query": "query { me { id } }"}',
    })
    assert result["ok"] is True
    sent = {k.lower(): v for k, v in captured["headers"].items()}
    assert sent.get("x-csrf-token") == "tok123"
    assert sent.get("x-requested-with") == "XMLHttpRequest"
    assert "csrf-token=tok123" in sent.get("cookie", "").lower()


class _CaptureClient:
    """httpx.AsyncClient stub that records the outgoing headers."""
    captured: dict = {}

    def __init__(self, **kw): pass
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False

    async def request(self, method, url, headers=None, content=None):
        _CaptureClient.captured = dict(headers or {})

        class _Resp:
            status_code = 200
            text = "{}"
            headers = {"Content-Type": "application/json"}
        _Resp.url = url
        return _Resp()


@pytest.mark.asyncio
async def test_send_request_strips_hand_pasted_token(monkeypatch):
    # A raw bearer/JWT pasted into Authorization must be stripped (not forwarded) and
    # flagged — auth is auto-injected; the model must not hand-paste secrets. Built at
    # runtime so no static eyJ... literal sits in the source (gitleaks flags that).
    import base64 as _b64, json as _json
    def _seg(o):
        return _b64.urlsafe_b64encode(_json.dumps(o).encode()).rstrip(b"=").decode()
    _jwt = f"{_seg({'alg': 'HS256'})}.{_seg({'sub': '1', 'account_id': 7})}.{_seg('sigvalue1234567890')}"

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _CaptureClient(**kw))
    ctx = ToolContext(settings=_Scope(True))  # no store/session -> nothing re-attached
    result = await run_tool(ctx, "send_request", {
        "url": "https://api.acme-corp.com/x", "method": "GET",
        "headers": {"Authorization": f"Bearer {_jwt}", "Accept": "application/json"},
    })
    assert result["ok"] is True
    sent = {k.lower(): v for k, v in _CaptureClient.captured.items()}
    assert "authorization" not in sent          # stripped, not forwarded upstream
    assert sent.get("accept") == "application/json"
    assert "note" in result and "stripped" in result["note"].lower()
    assert _jwt not in str(result)              # the token value never echoed back


@pytest.mark.asyncio
async def test_send_request_attaches_subapp_bearer_from_session(monkeypatch):
    # The copilot engine's per-sub-app Bearer selection is reused by the tool: a
    # /modstore request gets modstore's token, /customercontent gets ccm's.
    class _Session:
        def _capture_bearer_tokens(self, store, host): pass
        def _select_bearer(self, host, path):
            return {"token": "MOD" if "/modstore" in path else "CCM", "exp": None}

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _CaptureClient(**kw))
    ctx = ToolContext(settings=_Scope(True), store=object())
    ctx._session = _Session()

    r1 = await run_tool(ctx, "send_request", {
        "url": "https://app.acme-corp.com/modstore/graphql", "method": "POST",
        "body": '{"query":"{me}"}'})
    assert r1["ok"] is True
    assert _CaptureClient.captured.get("Authorization") == "Bearer MOD"
    assert "MOD" not in str(r1)  # token never surfaced in the tool result

    await run_tool(ctx, "send_request", {
        "url": "https://app.acme-corp.com/customercontent/graphql", "method": "POST",
        "body": '{"query":"{me}"}'})
    assert _CaptureClient.captured.get("Authorization") == "Bearer CCM"


@pytest.mark.asyncio
async def test_send_request_attaches_bearer_from_history(monkeypatch):
    # No copilot session attached: resolve the Bearer from proxy history.
    class _Store:
        def get_cookies_for_host(self, host): return []
        def all_entries(self):
            return [{"host": "api.acme-corp.com", "path": "/graphql",
                     "request_headers": {"Authorization": "Bearer HIST"}}]

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _CaptureClient(**kw))
    ctx = ToolContext(settings=_Scope(True), store=_Store())
    result = await run_tool(ctx, "send_request", {
        "url": "https://api.acme-corp.com/graphql", "method": "POST", "body": "{}"})
    assert result["ok"] is True
    assert _CaptureClient.captured.get("Authorization") == "Bearer HIST"


@pytest.mark.asyncio
async def test_send_request_preserves_caller_authorization(monkeypatch):
    # A caller-supplied Authorization is never overridden (and resolution is skipped).
    class _Session:
        def _capture_bearer_tokens(self, store, host):
            raise AssertionError("must not resolve when the caller set Authorization")
        def _select_bearer(self, host, path):
            raise AssertionError("must not resolve when the caller set Authorization")

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _CaptureClient(**kw))
    ctx = ToolContext(settings=_Scope(True), store=object())
    ctx._session = _Session()
    result = await run_tool(ctx, "send_request", {
        "url": "https://app.acme-corp.com/modstore/graphql", "method": "POST",
        "body": "{}", "headers": {"Authorization": "Bearer CALLER"}})
    assert result["ok"] is True
    assert _CaptureClient.captured.get("Authorization") == "Bearer CALLER"


@pytest.mark.asyncio
async def test_send_request_surfaces_all_set_cookies(monkeypatch):
    # Multiple Set-Cookie headers (e.g. CloudFront signed cookies) must be surfaced
    # as a list, not collapsed by dict(resp.headers). A cookie set on a redirect hop
    # must also be included, since follow_redirects hides it from the final response.
    hop = httpx.Response(
        302,
        headers=[("set-cookie", "CloudFront-Policy=abc"),
                 ("set-cookie", "CloudFront-Signature=def"),
                 ("location", "https://api.acme-corp.com/final")],
        request=httpx.Request("GET", "https://api.acme-corp.com/spa/session"),
    )

    class _Resp:
        status_code = 200
        text = "ok"
        url = "https://api.acme-corp.com/final"
        headers = httpx.Headers([("set-cookie", "CloudFront-Key-Pair-Id=ghi"),
                                 ("content-type", "text/plain")])
        history = [hop]

    class _Client:
        def __init__(self, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def request(self, method, url, headers=None, content=None):
            return _Resp()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _Client(**kw))
    ctx = ToolContext(settings=_Scope(True))
    result = await run_tool(ctx, "send_request",
                            {"url": "https://api.acme-corp.com/spa/session"})

    assert result["ok"] is True
    cookies = result["set_cookies"]
    # All three CloudFront cookies present, across the redirect hop and the final hop.
    joined = "; ".join(cookies)
    assert "CloudFront-Policy=abc" in joined
    assert "CloudFront-Signature=def" in joined
    assert "CloudFront-Key-Pair-Id=ghi" in joined
    assert result["redirects"] == [
        {"status": 302, "url": "https://api.acme-corp.com/spa/session"},
    ]


@pytest.mark.asyncio
async def test_send_request_omits_set_cookies_when_none(monkeypatch):
    class _Resp:
        status_code = 200
        text = "ok"
        url = "https://api.acme-corp.com/x"
        headers = httpx.Headers([("content-type", "text/plain")])
        history: list = []

    class _Client:
        def __init__(self, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def request(self, method, url, headers=None, content=None):
            return _Resp()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _Client(**kw))
    ctx = ToolContext(settings=_Scope(True))
    result = await run_tool(ctx, "send_request", {"url": "https://api.acme-corp.com/x"})
    assert result["ok"] is True
    assert "set_cookies" not in result
    assert "redirects" not in result


@pytest.mark.asyncio
async def test_send_request_reports_raw_reflection_past_truncation(monkeypatch):
    # An injected value that reflects UNENCODED deep in a large body is invisible
    # in the truncated `body`, so send_request must surface it as a reflection
    # signal — the decisive evidence for reflected XSS.
    marker = "<script>alert('FrierenXSS123')</script>"
    big_body = ("x" * 510_000) + f"Hello {marker}, welcome" + ("y" * 500)

    class _Resp:
        status_code = 200
        text = big_body
        url = "https://api.acme-corp.com/xss?name=" + marker
        headers = {"Content-Type": "text/html"}

    class _Client:
        def __init__(self, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def request(self, method, url, headers=None, content=None):
            return _Resp()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _Client(**kw))
    ctx = ToolContext(settings=_Scope(True))
    result = await run_tool(ctx, "send_request",
                            {"url": "https://api.acme-corp.com/xss?name=" + marker})

    assert result["ok"] is True
    assert marker not in result["body"]  # reflection lives past the 500K-char slice
    reflections = result["reflections"]
    assert len(reflections) == 1
    hit = reflections[0]
    assert hit["parameter"] == "name"
    assert hit["location"] == "query"
    assert hit["reflected_raw"] is True
    assert hit["html_escaped_also_present"] is False
    assert marker in hit["context"]


@pytest.mark.asyncio
async def test_send_request_reports_html_escaped_reflection(monkeypatch):
    # A value that comes back HTML-escaped is a reflection but NOT raw — the caller
    # needs both booleans to tell an XSS sink from a safely-encoded echo.
    injected = "<b>probe</b>"

    class _Resp:
        status_code = 200
        text = "search results for &lt;b&gt;probe&lt;/b&gt; here"
        url = "https://api.acme-corp.com/s?q=" + injected
        headers = {"Content-Type": "text/html"}

    class _Client:
        def __init__(self, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def request(self, method, url, headers=None, content=None):
            return _Resp()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _Client(**kw))
    ctx = ToolContext(settings=_Scope(True))
    result = await run_tool(ctx, "send_request",
                            {"url": "https://api.acme-corp.com/s?q=" + injected})

    hit = result["reflections"][0]
    assert hit["reflected_raw"] is False
    assert hit["html_escaped_also_present"] is True


@pytest.mark.asyncio
async def test_send_request_no_reflection_field_when_absent(monkeypatch):
    class _Resp:
        status_code = 200
        text = "nothing echoed back"
        url = "https://api.acme-corp.com/x?token=abcdef12345"
        headers = {"Content-Type": "text/html"}

    class _Client:
        def __init__(self, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def request(self, method, url, headers=None, content=None):
            return _Resp()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _Client(**kw))
    ctx = ToolContext(settings=_Scope(True))
    result = await run_tool(ctx, "send_request",
                            {"url": "https://api.acme-corp.com/x?token=abcdef12345"})
    assert result["ok"] is True
    assert "reflections" not in result


# ── get_history in-process store path ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_history_reads_store():
    class _Entry:
        def __init__(self, host):
            self._host = host
        def to_dict(self):
            return {"host": self._host, "method": "GET", "url": f"https://{self._host}/"}

    class _Store:
        def all_entries(self):
            return [_Entry("a.acme-corp.com"), _Entry("b.other.com")]

    ctx = ToolContext(settings=_Scope(True), store=_Store())
    result = await run_tool(ctx, "get_history", {"host": "acme-corp.com"})
    assert result["ok"] is True
    assert result["count"] == 1
    assert result["entries"][0]["host"] == "a.acme-corp.com"


class _HistEntry:
    def __init__(self, eid, method, path, source):
        self._d = {"id": eid, "method": method, "path": path, "host": "h.acme-corp.com",
                   "url": f"https://h.acme-corp.com{path}", "source": source}
    def to_dict(self, include_bodies=False):
        d = dict(self._d)
        if include_bodies:
            d["request_body"] = "x=1"
        return d


class _HistStore:
    def __init__(self):
        self._entries = [
            _HistEntry("1", "GET",  "/a", "proxy"),
            _HistEntry("2", "POST", "/compose/send", "copilot"),
            _HistEntry("3", "GET",  "/probe", "scan"),
        ]
    def all_entries(self):
        return list(self._entries)
    def get_entry(self, eid):
        return next((e for e in self._entries if e._d["id"] == eid), None)


@pytest.mark.asyncio
async def test_get_history_method_path_source_filters():
    ctx = ToolContext(settings=_Scope(True), store=_HistStore())
    result = await run_tool(ctx, "get_history",
                            {"method": "post", "path": "/compose", "source": "copilot"})
    assert result["ok"] is True
    assert result["count"] == 1
    assert result["entries"][0]["id"] == "2"


@pytest.mark.asyncio
async def test_get_history_newest_first_ordering():
    ctx = ToolContext(settings=_Scope(True), store=_HistStore())
    newest = await run_tool(ctx, "get_history", {"limit": 1})
    assert newest["entries"][0]["id"] == "3"  # last appended = most recent
    oldest = await run_tool(ctx, "get_history", {"limit": 1, "newest_first": False})
    assert oldest["entries"][0]["id"] == "1"


@pytest.mark.asyncio
async def test_get_history_entry_id_lookup():
    ctx = ToolContext(settings=_Scope(True), store=_HistStore())
    result = await run_tool(ctx, "get_history", {"entry_id": "2"})
    assert result["ok"] is True
    assert result["entry"]["id"] == "2"
    assert result["entry"]["request_body"] == "x=1"  # full detail with bodies
    missing = await run_tool(ctx, "get_history", {"entry_id": "999"})
    assert missing["ok"] is False


# ── recon tools delegate to the scanners (mocked) ───────────────────────────────

@pytest.mark.asyncio
async def test_content_discovery_delegates(monkeypatch):
    async def fake_run(**kwargs):
        return [{"path": "/admin", "status": 200}]
    monkeypatch.setattr(
        "dast.scanners.content_discovery.run_content_discovery", fake_run
    )
    ctx = ToolContext(settings=_Scope(True))
    result = await run_tool(ctx, "content_discovery",
                            {"url": "https://api.acme-corp.com/"})
    assert result["ok"] is True
    assert result["count"] == 1
    assert result["hits"][0]["path"] == "/admin"


@pytest.mark.asyncio
async def test_param_mining_out_of_scope_blocked():
    ctx = ToolContext(settings=_Scope(allow=False))
    result = await run_tool(ctx, "param_mining",
                            {"url": "https://evil.example.com/"})
    assert result["ok"] is False
    assert "out of scope" in result["error"]


# ── triage_report delegates to the H1 engine (mocked) ───────────────────────────

@pytest.mark.asyncio
async def test_triage_report_delegates(monkeypatch):
    from dast.triage.parser import H1Report
    from dast.triage.validator import ValidationResult

    def fake_parse(text):
        return H1Report(vuln_type="idor",
                        proof_url="https://api.acme-corp.com/v1/users/1", payload="1")

    async def fake_validate(report, proxy_port=8080, cookies=None):
        return ValidationResult(job_id="j", status="confirmed", vuln_type="idor",
                                proof_url=report.proof_url, payload="1",
                                evidence="reflected", severity="high")

    monkeypatch.setattr("dast.triage.parser.parse_report", fake_parse)
    monkeypatch.setattr("dast.triage.validator.validate", fake_validate)
    ctx = ToolContext(settings=_Scope(True))
    result = await run_tool(ctx, "triage_report", {"report_text": "idor on users"})
    assert result["ok"] is True
    assert result["confirmed"] is True
    assert result["severity"] == "high"


# ── list_login_profiles is secret-free ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_login_profiles_redacted(monkeypatch):
    class _Profile:
        def to_public_dict(self):
            return {"slug": "acme", "credentials": [{"secret_set": True}], "session_set": False}

    monkeypatch.setattr("dast.profiles.store.list_profiles", lambda: [_Profile()])
    ctx = ToolContext(settings=_Scope(True))
    result = await run_tool(ctx, "list_login_profiles", {})
    assert result["ok"] is True
    prof = result["profiles"][0]
    assert prof["slug"] == "acme"
    # No plaintext secret ever surfaces — only *_set booleans.
    assert "secret" not in prof["credentials"][0]
    assert prof["credentials"][0]["secret_set"] is True


# ── get_findings (read-only, both paths) ────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_findings_reads_store():
    class _Entry:
        def __init__(self, host, findings):
            self._d = {"id": "e1", "host": host, "url": f"https://{host}/x",
                       "path": "/x", "method": "GET", "status": 200,
                       "source": "proxy", "scan_result": "vulnerable",
                       "findings": findings}
        def to_dict(self):
            return self._d

    class _Store:
        def in_scope_entries(self):
            return [
                _Entry("a.acme-corp.com", [{"title": "XSS", "severity": "high"}]),
                _Entry("b.acme-corp.com", [{"title": "SQLi", "severity": "critical"}]),
            ]

    ctx = ToolContext(settings=_Scope(True), store=_Store())
    result = await run_tool(ctx, "get_findings", {"severity": "critical"})
    assert result["ok"] is True
    assert result["count"] == 1
    row = result["findings"][0]
    assert row["title"] == "SQLi"
    # Finding is joined with its parent-entry context.
    assert row["host"] == "b.acme-corp.com"
    assert row["url"] == "https://b.acme-corp.com/x"
    assert row["entry_id"] == "e1"


@pytest.mark.asyncio
async def test_get_findings_http_fallback(monkeypatch):
    rows = [{"title": "XSS", "severity": "high", "host": "a.acme-corp.com"}]

    class _Resp:
        def raise_for_status(self): pass
        def json(self): return rows

    class _Client:
        def __init__(self, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, url): return _Resp()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _Client(**kw))
    ctx = ToolContext(settings=_Scope(True))  # no store -> HTTP path
    result = await run_tool(ctx, "get_findings", {})
    assert result["ok"] is True
    assert result["count"] == 1
    assert result["findings"][0]["title"] == "XSS"


# ── record_finding (write, both paths) ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_record_finding_writes_store():
    class _Store:
        def __init__(self):
            self.calls = []
        def record_manual_finding(self, finding, url, method="GET"):
            self.calls.append((finding, url, method))
            return "e-42"

    store = _Store()
    ctx = ToolContext(settings=_Scope(True), store=store)
    result = await run_tool(ctx, "record_finding", {
        "title": "Missing access control on ldapToken",
        "severity": "high", "url": "https://acme-corp.com/graphql",
        "method": "POST", "evidence": "Both fields PRESENT with HTTP 200.",
        "attack_type": "broken-access-control", "cwe": "CWE-284",
    })
    assert result["ok"] is True
    assert result["entry_id"] == "e-42"
    finding, url, method = store.calls[0]
    assert url == "https://acme-corp.com/graphql" and method == "POST"
    assert finding["title"] == "Missing access control on ldapToken"
    assert finding["severity"] == "high"
    assert finding["confirmed"] is True
    assert finding["validated_by"] == ["copilot"]


@pytest.mark.asyncio
async def test_record_finding_requires_core_fields():
    ctx = ToolContext(settings=_Scope(True), store=object())
    # Missing url
    r1 = await run_tool(ctx, "record_finding",
                        {"title": "x", "severity": "high", "evidence": "e"})
    assert r1["ok"] is False and "url" in r1["error"]
    # Missing evidence
    r2 = await run_tool(ctx, "record_finding",
                        {"title": "x", "severity": "high", "url": "https://acme-corp.com/"})
    assert r2["ok"] is False and "evidence" in r2["error"]


@pytest.mark.asyncio
async def test_record_finding_invalid_severity_defaults_medium():
    class _Store:
        def __init__(self): self.finding = None
        def record_manual_finding(self, finding, url, method="GET"):
            self.finding = finding
            return "e1"

    store = _Store()
    ctx = ToolContext(settings=_Scope(True), store=store)
    result = await run_tool(ctx, "record_finding", {
        "title": "t", "severity": "spicy", "url": "https://acme-corp.com/x",
        "evidence": "observed",
    })
    assert result["ok"] is True
    assert store.finding["severity"] == "medium"


@pytest.mark.asyncio
async def test_record_finding_http_fallback(monkeypatch):
    posted = {}

    class _Resp:
        def raise_for_status(self): pass
        def json(self): return {"ok": True, "entry_id": "srv-1"}

    class _Client:
        def __init__(self, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, json=None):
            posted["url"] = url
            posted["json"] = json
            return _Resp()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _Client(**kw))
    ctx = ToolContext(settings=_Scope(True))  # no store -> HTTP path
    result = await run_tool(ctx, "record_finding", {
        "title": "t", "severity": "critical", "url": "https://acme-corp.com/x",
        "evidence": "observed",
    })
    assert result["ok"] is True
    assert result["entry_id"] == "srv-1"
    assert posted["url"].endswith("/api/findings/manual")
    assert posted["json"]["finding"]["title"] == "t"


# ── encoders (pure) ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_encoders_roundtrip():
    ctx = ToolContext(settings=_Scope(True))
    enc = await run_tool(ctx, "url_encode", {"text": "a b&c=1"})
    assert enc["ok"] is True and enc["result"] == "a%20b%26c%3D1"
    dec = await run_tool(ctx, "url_decode", {"text": enc["result"]})
    assert dec["result"] == "a b&c=1"
    b64 = await run_tool(ctx, "base64_encode", {"text": "hi"})
    assert b64["result"] == "aGk="
    assert (await run_tool(ctx, "base64_decode", {"text": "aGk="}))["result"] == "hi"


@pytest.mark.asyncio
async def test_encoder_missing_text():
    ctx = ToolContext(settings=_Scope(True))
    result = await run_tool(ctx, "url_encode", {})
    assert result["ok"] is False
    assert "text is required" in result["error"]


# ── OOB tools go through the dashboard (mocked) ─────────────────────────────────

@pytest.mark.asyncio
async def test_oob_generate_and_poll(monkeypatch):
    class _Resp:
        def __init__(self, payload, status=200):
            self._p = payload
            self.status_code = status
        def raise_for_status(self): pass
        def json(self): return self._p

    class _Client:
        def __init__(self, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, json=None):
            return _Resp({"session_id": "abc123", "oob_url": "http://x.oast.pro"})
        async def get(self, url):
            return _Resp({"oob_url": "http://x.oast.pro",
                          "callbacks": [{"type": "http", "raw": "GET /abc123"}]})

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _Client(**kw))
    ctx = ToolContext(settings=_Scope(True))
    gen = await run_tool(ctx, "oob_generate", {})
    assert gen["ok"] is True and gen["id"] == "abc123"
    poll = await run_tool(ctx, "oob_poll", {"id": "abc123"})
    assert poll["ok"] is True
    assert poll["hit"] is True
    assert poll["count"] == 1


@pytest.mark.asyncio
async def test_oob_poll_requires_id():
    ctx = ToolContext(settings=_Scope(True))
    result = await run_tool(ctx, "oob_poll", {})
    assert result["ok"] is False
    assert "id is required" in result["error"]


# ── send_request out-of-scope approval (MCP path) ───────────────────────────────

@pytest.mark.asyncio
async def test_send_request_out_of_scope_denied_without_approval(monkeypatch):
    # MCP path (store=None): approval declines -> still blocked.
    async def fake_approval(ctx, url, method):
        return False
    monkeypatch.setattr("dast.tools.approval.request_approval", fake_approval)
    ctx = ToolContext(settings=_Scope(allow=False))  # store is None
    result = await run_tool(ctx, "send_request", {"url": "https://evil.example.com/x"})
    assert result["ok"] is False
    assert "out of scope" in result["error"]


@pytest.mark.asyncio
async def test_send_request_out_of_scope_allowed_by_approval(monkeypatch):
    # MCP path: approval grants -> the send is attempted (mocked to succeed).
    async def fake_approval(ctx, url, method):
        return True
    monkeypatch.setattr("dast.tools.approval.request_approval", fake_approval)

    class _Resp:
        status_code = 200
        text = "ok"
        url = "https://newtarget.example.com/x"
        headers = {"Content-Type": "text/plain"}

    class _Client:
        def __init__(self, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def request(self, method, url, headers=None, content=None): return _Resp()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _Client(**kw))
    ctx = ToolContext(settings=_Scope(allow=False))
    result = await run_tool(ctx, "send_request", {"url": "https://newtarget.example.com/x"})
    assert result["ok"] is True
    assert result["status"] == 200


# ── validate_chain scope + args ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_validate_chain_requires_input():
    ctx = ToolContext(settings=_Scope(True))
    result = await run_tool(ctx, "validate_chain", {})
    assert result["ok"] is False
    assert "chain" in result["error"] and "report_text" in result["error"]


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_spec", [
    {"name": "c", "steps": ["https://api.acme-corp.com/x"]},
    {"name": "c", "steps": [{"name": "s", "url": "https://api.acme-corp.com/x",
                             "extract": ["token"]}]},
    {"name": "c", "steps": [{"name": "s", "url": "https://api.acme-corp.com/x",
                             "assertions": ["status_eq 200"]}]},
])
async def test_validate_chain_rejects_bare_string_elements(bad_spec):
    # A bare string where an object is expected must degrade to a readable
    # "invalid chain spec" error, not a Python AttributeError.
    ctx = ToolContext(store=object(), settings=_Scope(True))
    result = await run_tool(ctx, "validate_chain", {"chain": bad_spec})
    assert result["ok"] is False
    assert "invalid chain spec" in result["error"]
    assert "must be an object" in result["error"]


@pytest.mark.asyncio
async def test_validate_chain_out_of_scope_blocked():
    # store set (in-process) so no interactive approval is attempted.
    ctx = ToolContext(store=object(), settings=_Scope(False))
    spec = {"name": "c", "vuln_type": "x",
            "steps": [{"name": "s", "url": "https://evil.example.com/x"}]}
    result = await run_tool(ctx, "validate_chain", {"chain": spec})
    assert result["ok"] is False
    assert "out of scope" in result["error"]


def test_validate_chain_schema_specifies_steps_and_requires_one_of():
    # The schema must describe chain.steps concretely (so an LLM builds a valid
    # spec instead of an empty {}), and forbid empty args via anyOf so a caller
    # cannot satisfy it with neither report_text nor chain.
    from dast.tools.chain_tools import _VALIDATE_CHAIN_SCHEMA

    props = _VALIDATE_CHAIN_SCHEMA["properties"]
    assert "report_text" in props and "chain" in props
    steps = props["chain"]["properties"]["steps"]
    assert steps["type"] == "array"
    step_item = steps["items"]
    assert step_item["required"] == ["name", "url"]
    assert "extract" in step_item["properties"]
    assert "assertions" in step_item["properties"]
    branches = _VALIDATE_CHAIN_SCHEMA["anyOf"]
    assert {"required": ["report_text"]} in branches
    assert {"required": ["chain"]} in branches


# ── graphql_introspect (dedicated introspection path, both callers) ─────────────

@pytest.mark.asyncio
async def test_graphql_introspect_out_of_scope_blocked():
    # store set (in-process) so no interactive approval is attempted.
    ctx = ToolContext(store=object(), settings=_Scope(False))
    result = await run_tool(ctx, "graphql_introspect",
                            {"url": "https://evil.example.com/graphql"})
    assert result["ok"] is False
    assert "out of scope" in result["error"]


@pytest.mark.asyncio
async def test_graphql_introspect_reads_store(monkeypatch):
    class _Store:
        def __init__(self):
            self.graphql_schemas = {}

    seen: dict = {}

    async def fake_introspect(endpoint, headers, store, name="GraphQL Introspection",
                              proxy_url=None):
        seen["proxy_url"] = proxy_url
        store.graphql_schemas[endpoint] = {
            "introspected": True,
            "queries": {"me": {}, "user": {}},
            "mutations": {"login": {}},
        }
        return None  # success

    monkeypatch.setattr(
        "dast.plugins.graphql_introspection._introspect", fake_introspect
    )
    store = _Store()
    ctx = ToolContext(settings=_Scope(True), store=store)
    result = await run_tool(ctx, "graphql_introspect",
                            {"url": "https://api.acme-corp.com/graphql"})
    assert result["ok"] is True
    # Introspection is routed through the proxy (the "everything via Frieren" contract).
    assert seen["proxy_url"] == ctx.proxy_url
    assert result["query_count"] == 2
    assert result["mutation_count"] == 1
    assert result["queries"] == ["me", "user"]
    assert result["mutations"] == ["login"]


@pytest.mark.asyncio
async def test_graphql_introspect_disabled_surfaces_error(monkeypatch):
    class _Store:
        def __init__(self):
            self.graphql_schemas = {}

    async def fake_introspect(endpoint, headers, store, name="GraphQL Introspection"):
        return "Introspection disabled on this endpoint"

    monkeypatch.setattr(
        "dast.plugins.graphql_introspection._introspect", fake_introspect
    )
    ctx = ToolContext(settings=_Scope(True), store=_Store())
    result = await run_tool(ctx, "graphql_introspect",
                            {"url": "https://api.acme-corp.com/graphql"})
    assert result["ok"] is False
    assert "disabled" in result["error"]


@pytest.mark.asyncio
async def test_graphql_introspect_http_fallback(monkeypatch):
    posted = {}

    class _Resp:
        def raise_for_status(self): pass
        def json(self):
            return {"ok": True, "schema": {"introspected": True,
                    "queries": {"me": {}}, "mutations": {}}}

    class _Client:
        def __init__(self, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, json=None):
            posted["url"] = url
            posted["json"] = json
            return _Resp()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _Client(**kw))
    ctx = ToolContext(settings=_Scope(True))  # no store -> HTTP path
    result = await run_tool(ctx, "graphql_introspect",
                            {"url": "https://api.acme-corp.com/graphql"})
    assert result["ok"] is True
    assert result["queries"] == ["me"]
    assert posted["url"].endswith("/api/graphql/introspect")
    assert posted["json"]["endpoint"] == "https://api.acme-corp.com/graphql"


@pytest.mark.asyncio
async def test_graphql_type_info_reads_root_query_args():
    # The root Query type must resolve (fields + arg signatures), not 404 as
    # "type 'Query' not found" with total_fields=0.
    class _Store:
        def __init__(self):
            self.graphql_schemas = {
                "https://api.acme-corp.com/graphql": {
                    "introspected": True,
                    "queries": {"account": {"args": [{"name": "id", "type": "ID"}],
                                            "return_type": "Account"}},
                    "mutations": {},
                    "input_types": {}, "object_types": {}, "union_types": {},
                    "enum_types": {},
                    "root_types": {
                        "Query": {
                            "kind": "OBJECT", "role": "query",
                            "fields": [{"name": "account",
                                        "args": [{"name": "id", "type": "ID"}],
                                        "return_type": "Account"}],
                        },
                    },
                }
            }

    ctx = ToolContext(settings=_Scope(True), store=_Store())
    result = await run_tool(ctx, "graphql_type_info",
                            {"url": "https://api.acme-corp.com/graphql", "type_name": "Query"})
    assert result["ok"] is True
    assert result["role"] == "query"
    assert result["total_fields"] == 1
    assert result["fields"][0]["name"] == "account"
    assert result["fields"][0]["args"][0]["name"] == "id"
    assert result["fields"][0]["return_type"] == "Account"


# ── MCP conversion (pure, no mcp import) ────────────────────────────────────────

def test_tool_definitions_shape():
    from dast.mcp import tool_definitions
    defs = tool_definitions()
    assert len(defs) == len(tools.all_tools())
    for d in defs:
        assert set(d) == {"name", "description", "inputSchema"}
        assert d["inputSchema"]["type"] == "object"
    names = {d["name"] for d in defs}
    assert "send_request" in names


# ── copilot_ask (message-passing primitive; exposed over MCP) ────────────────────

def test_copilot_ask_registered_and_tagged():
    tool = tools.get_tool("copilot_ask")
    assert tool is not None
    # Tagged "copilot" so the copilot engine excludes it from its own menu; the tag
    # does NOT hide it from the registry or MCP.
    assert "copilot" in (tool.tags or [])
    assert "message" in tool.input_schema.get("required", [])


def test_copilot_ask_exposed_over_mcp():
    from dast.mcp import tool_definitions
    names = {d["name"] for d in tool_definitions()}
    assert "copilot_ask" in names  # external MCP clients can drive the copilot


@pytest.mark.asyncio
async def test_copilot_ask_requires_message():
    result = await run_tool(ToolContext(settings=_Scope(True)), "copilot_ask", {})
    assert result["ok"] is False
    assert "message" in result["error"]


# ── crawl (orchestration primitive over the crawl worker) ───────────────────────

class _CrawlEntry:
    def __init__(self, method: str, url: str, source: str = "proxy"):
        self.method = method
        self.url = url
        self.source = source


class _CrawlStore:
    """Fake store whose in-scope history grows when a crawl job is 'run'."""

    def __init__(self, before, after):
        self._before = list(before)
        self._after = list(after)
        self._crawled = False

    def in_scope_entries(self):
        return list(self._after) if self._crawled else list(self._before)

    def mark_crawled(self):
        self._crawled = True


def test_crawl_registered_and_tagged():
    tool = tools.get_tool("crawl")
    assert tool is not None
    assert "recon" in (tool.tags or [])
    assert tool.input_schema.get("required") == ["url"]


@pytest.mark.asyncio
async def test_crawl_out_of_scope_blocked():
    ctx = ToolContext(settings=_Scope(allow=False))
    result = await run_tool(ctx, "crawl", {"url": "https://evil.example.com/"})
    assert result["ok"] is False
    assert "out of scope" in result["error"]


@pytest.mark.asyncio
async def test_crawl_not_available_without_queue():
    # In-scope but no crawl_queue (MCP / triage context) → graceful refusal.
    ctx = ToolContext(settings=_Scope(True), store=_CrawlStore([], []))
    result = await run_tool(ctx, "crawl", {"url": "https://api.acme-corp.com/"})
    assert result["ok"] is False
    assert "not available" in result["error"]


@pytest.mark.asyncio
async def test_crawl_enqueues_and_returns_new_endpoints():
    import asyncio

    before = [_CrawlEntry("GET", "https://api.acme-corp.com/")]
    after = before + [
        _CrawlEntry("GET", "https://api.acme-corp.com/users"),
        _CrawlEntry("POST", "https://api.acme-corp.com/login"),
        _CrawlEntry("GET", "https://api.acme-corp.com/app.js"),  # static asset → filtered
    ]
    store = _CrawlStore(before, after)
    queue: asyncio.Queue = asyncio.Queue()

    async def worker():
        job = await queue.get()
        store.mark_crawled()
        job["done_event"].set()

    ctx = ToolContext(settings=_Scope(True), store=store, crawl_queue=queue)
    worker_task = asyncio.create_task(worker())
    result = await run_tool(ctx, "crawl", {"url": "https://api.acme-corp.com/"})
    await worker_task

    assert result["ok"] is True
    assert result["timed_out"] is False
    urls = {e["url"] for e in result["endpoints"]}
    assert "https://api.acme-corp.com/users" in urls
    assert "https://api.acme-corp.com/login" in urls
    assert "https://api.acme-corp.com/app.js" not in urls  # static asset filtered
    assert result["discovered_count"] == 2


@pytest.mark.asyncio
async def test_crawl_session_safe_caps_click_budget():
    import asyncio

    from dast.tools import crawl_tools

    store = _CrawlStore([], [])
    queue: asyncio.Queue = asyncio.Queue()
    jobs = []

    async def worker():
        job = await queue.get()
        jobs.append(job)
        store.mark_crawled()
        job["done_event"].set()

    ctx = ToolContext(settings=_Scope(True), store=store, crawl_queue=queue, session_safe=True)
    worker_task = asyncio.create_task(worker())
    result = await run_tool(ctx, "crawl", {
        "url": "https://api.acme-corp.com/", "max_clicks": 300,
        "extra_seeds": ["https://api.acme-corp.com/other"],
    })
    await worker_task

    assert result["ok"] is True
    assert jobs[0]["max_clicks"] == crawl_tools._SESSION_SAFE_MAX_CLICKS
    assert jobs[0]["extra_seeds"] is None  # extra seeds dropped in session-safe mode


# ── verify_reflection (payload-survival classification) ─────────────────────────

def test_verify_reflection_classify_raw():
    from dast.tools.verify_tools import _classify
    r = _classify("<div><script>alert(1)</script></div>", "<script>alert(1)</script>")
    assert r["classification"] == "rendered_raw"
    assert r["raw_payload_present"] is True
    assert "<script" in r["dangerous_tokens_raw"]
    assert r["evidence"]


def test_verify_reflection_classify_encoded():
    from dast.tools.verify_tools import _classify
    r = _classify("<div>&lt;script&gt;alert(1)&lt;/script&gt;</div>", "<script>alert(1)</script>")
    assert r["classification"] == "encoded"
    assert r["raw_payload_present"] is False
    assert r["html_encoded_present"] is True


def test_verify_reflection_classify_stripped():
    from dast.tools.verify_tools import _classify
    r = _classify("<div>hello world</div>", "<script>alert(1)</script>")
    assert r["classification"] == "stripped"
    assert r["dangerous_tokens_raw"] == []


@pytest.mark.asyncio
async def test_verify_reflection_out_of_scope_blocked():
    ctx = ToolContext(settings=_Scope(allow=False))
    result = await run_tool(ctx, "verify_reflection",
                            {"url": "https://evil.example.com/p/1", "payload": "<script>"})
    assert result["ok"] is False
    assert "out of scope" in result["error"]


# ── match_replace tool (copilot-scoped M&R rules) ───────────────────────────────

class _FakeSettings:
    def __init__(self):
        self._rules = []
    def get_match_replace(self):
        return list(self._rules)
    def add_match_replace(self, rule):
        self._rules.append(dict(rule))
    def remove_match_replace(self, idx):
        if 0 <= idx < len(self._rules): self._rules.pop(idx)


@pytest.mark.asyncio
async def test_match_replace_add_list_clear_lifecycle():
    settings = _FakeSettings()
    ctx = ToolContext(settings=settings)

    # Add a copilot rule
    r = await run_tool(ctx, "match_replace", {
        "action": "add", "scope": "request", "type": "body",
        "match": "BodyHtml=[^&]+", "replace": "BodyHtml=<script>alert(1)</script>",
        "comment": "inject XSS",
    })
    assert r["ok"] is True
    assert r["index"] == 0

    # List — rule should be tagged
    r = await run_tool(ctx, "match_replace", {"action": "list"})
    assert r["count"] == 1
    assert r["rules"][0]["copilot"] is True
    assert "copilot_session" in settings._rules[0]["comment"]

    # Clear — should remove copilot rules
    r = await run_tool(ctx, "match_replace", {"action": "clear"})
    assert r["ok"] is True and r["removed"] == 1
    assert settings._rules == []


@pytest.mark.asyncio
async def test_match_replace_does_not_remove_operator_rules():
    settings = _FakeSettings()
    settings._rules.append({"comment": "operator's own rule", "enabled": True})
    ctx = ToolContext(settings=settings)

    await run_tool(ctx, "match_replace", {"action": "add", "match": "x", "replace": "y"})
    assert len(settings._rules) == 2

    r = await run_tool(ctx, "match_replace", {"action": "clear"})
    assert r["removed"] == 1
    assert len(settings._rules) == 1
    assert settings._rules[0]["comment"] == "operator's own rule"


# ── browser_* tools (agent browser-driving) ─────────────────────────────────────

class _FakeBrowser:
    def __init__(self):
        self.calls = []
    async def navigate(self, url, timeout_ms=20000):
        self.calls.append(("navigate", url)); return {"ok": True, "url": url, "status": 200, "title": "T"}
    async def snapshot(self):
        self.calls.append(("snapshot",)); return {"ok": True, "url": "u", "title": "T", "forms": [], "buttons": [], "links": []}
    async def fill(self, selector, value, timeout_ms=10000):
        self.calls.append(("fill", selector, value)); return {"ok": True, "selector": selector}
    async def click(self, selector, timeout_ms=10000, expect_nav=False):
        self.calls.append(("click", selector, expect_nav)); return {"ok": True, "selector": selector, "url": "u"}
    async def extract(self, selector, attribute="value"):
        self.calls.append(("extract", selector, attribute)); return {"ok": True, "value": "tok123"}


@pytest.mark.asyncio
async def test_browser_tools_not_available_without_browser():
    ctx = ToolContext(settings=_Scope(True))  # no browser attached
    for name, args in [("browser_navigate", {"url": "https://api.acme-corp.com/"}),
                       ("browser_snapshot", {}), ("browser_fill", {"selector": "#x", "value": "y"})]:
        r = await run_tool(ctx, name, args)
        assert r["ok"] is False and "not available" in r["error"]


@pytest.mark.asyncio
async def test_browser_navigate_scope_gated_and_drives():
    b = _FakeBrowser()
    ctx = ToolContext(settings=_Scope(True), browser=b)
    oos = await run_tool(ToolContext(settings=_Scope(False), browser=b), "browser_navigate",
                         {"url": "https://evil.example.com/"})
    assert oos["ok"] is False and "out of scope" in oos["error"]
    ok = await run_tool(ctx, "browser_navigate", {"url": "https://api.acme-corp.com/login"})
    assert ok["ok"] is True and ok["status"] == 200
    assert ("navigate", "https://api.acme-corp.com/login") in b.calls


@pytest.mark.asyncio
async def test_browser_fill_click_extract_delegate():
    b = _FakeBrowser()
    ctx = ToolContext(settings=_Scope(True), browser=b)
    assert (await run_tool(ctx, "browser_fill", {"selector": "#tbEmail", "value": "a@b.c"}))["ok"]
    assert (await run_tool(ctx, "browser_click", {"selector": "#btnContinue", "expect_navigation": True}))["ok"]
    ex = await run_tool(ctx, "browser_extract", {"selector": "#token", "attribute": "value"})
    assert ex["ok"] and ex["value"] == "tok123"
    assert ("fill", "#tbEmail", "a@b.c") in b.calls
    assert ("click", "#btnContinue", True) in b.calls
    # selector required
    assert (await run_tool(ctx, "browser_fill", {"value": "x"}))["ok"] is False


# ── idor_probe (deterministic BOLA/IDOR differential runner) ────────────────────

class _FakeResp:
    def __init__(self, status, text=""):
        self.status_code = status
        self.text = text


class _FakeHttpClient:
    """Returns queued responses per (METHOD, url); pops in call order so a url read
    twice (read, then post-delete read) can return different statuses."""
    def __init__(self, routes):
        self._routes = {k: list(v) for k, v in routes.items()}
        self.calls = []
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False
    async def request(self, method, url, headers=None, content=None):
        self.calls.append((method.upper(), url, dict(headers or {})))
        q = self._routes.get((method.upper(), url))
        if not q:
            return _FakeResp(599, "no route")
        return q.pop(0) if len(q) > 1 else q[0]


class _IdorStore:
    def __init__(self):
        self.recorded = []
        self.cookies = [{"name": "SESS", "value": "abc"}]
    def get_cookies_for_host(self, host):
        return list(self.cookies)
    def record_manual_finding(self, finding, url, method="GET"):
        self.recorded.append((finding, url, method))
        return "entry-idor-1"


def _idor_routes(base, marker, control_present=True, delete_present=True):
    routes = {
        ("POST", f"{base}/save/probe"): [_FakeResp(200, "")],
        ("GET", f"{base}/load/probe"): [_FakeResp(200, f'[{{"v":"{marker}"}}]'),
                                        _FakeResp(500, "Failed to load form data.")],
    }
    if control_present:
        routes[("GET", f"{base}/load/never")] = [_FakeResp(500, "Failed to load form data.")]
    if delete_present:
        routes[("DELETE", f"{base}/delete/probe")] = [_FakeResp(200, "")]
    return routes


@pytest.mark.asyncio
async def test_idor_probe_confirmed_records_finding(monkeypatch):
    import httpx
    base = "https://api.acme-corp.com/t"
    marker = "frieren-123"
    client = _FakeHttpClient(_idor_routes(base, marker))
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: client)

    store = _IdorStore()
    ctx = ToolContext(settings=_Scope(True), store=store, source_label="copilot")
    result = await run_tool(ctx, "idor_probe", {
        "write_url": f"{base}/save/probe", "read_url": f"{base}/load/probe",
        "control_read_url": f"{base}/load/never", "delete_url": f"{base}/delete/probe",
        "marker": marker, "write_body": f'[{{"v":"{marker}"}}]',
    })

    assert result["ok"] is True
    assert result["confirmed"] is True
    assert len(result["steps"]) == 5
    assert [s["status"] for s in result["steps"]] == [200, 200, 500, 200, 500]
    # finding recorded with the step chain
    assert len(store.recorded) == 1
    finding = store.recorded[0][0]
    assert finding["attack_type"] == "broken-access-control"
    assert len(finding["steps"]) == 5
    # cookies from the jar were attached to every sub-request
    assert all("SESS=abc" in c[2].get("cookie", "") for c in client.calls)


@pytest.mark.asyncio
async def test_idor_probe_echo_not_confirmed(monkeypatch):
    import httpx
    base = "https://api.acme-corp.com/t"
    marker = "frieren-123"
    routes = _idor_routes(base, marker, delete_present=False)
    # Control ALSO returns the marker => echo/public, must NOT confirm.
    routes[("GET", f"{base}/load/never")] = [_FakeResp(200, f'[{{"v":"{marker}"}}]')]
    client = _FakeHttpClient(routes)
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: client)

    store = _IdorStore()
    ctx = ToolContext(settings=_Scope(True), store=store)
    result = await run_tool(ctx, "idor_probe", {
        "write_url": f"{base}/save/probe", "read_url": f"{base}/load/probe",
        "control_read_url": f"{base}/load/never",
        "marker": marker, "write_body": f'[{{"v":"{marker}"}}]',
    })
    assert result["ok"] is True
    assert result["confirmed"] is False
    assert "echo" in result["verdict"].lower() or "public" in result["verdict"].lower()
    assert store.recorded == []  # nothing recorded when not confirmed


@pytest.mark.asyncio
async def test_idor_probe_out_of_scope_blocked():
    ctx = ToolContext(settings=_Scope(allow=False))
    result = await run_tool(ctx, "idor_probe", {
        "write_url": "https://evil.example.com/save/x", "read_url": "https://evil.example.com/load/x",
        "marker": "m", "write_body": "m",
    })
    assert result["ok"] is False
    assert "out of scope" in result["error"]


# ── run_scan (orchestration primitive over the scan pipeline) ───────────────────

class _ScanEntry:
    def __init__(self, method, url, host, source="proxy"):
        self.id = f"e-{method}-{url}"
        self.method = method
        self.url = url
        self.host = host
        self.source = source
        self.ai_queued = False
        self.queued_for_scan = False
        self.scan_result = None
        self.findings = []


class _ScanStore:
    def __init__(self, entries, ai_mode=True):
        self._entries = {e.id: e for e in entries}
        self._order = [e.id for e in entries]
        self.ai_mode = ai_mode

    def all_entries(self):
        return [self._entries[i] for i in self._order]

    def get_entry(self, entry_id):
        return self._entries.get(entry_id)


def test_run_scan_registered_and_tagged():
    tool = tools.get_tool("run_scan")
    assert tool is not None
    assert "active" in (tool.tags or [])
    assert tool.input_schema.get("required") == ["url"]


@pytest.mark.asyncio
async def test_run_scan_out_of_scope_blocked():
    ctx = ToolContext(settings=_Scope(allow=False))
    result = await run_tool(ctx, "run_scan", {"url": "https://evil.example.com/x"})
    assert result["ok"] is False
    assert "out of scope" in result["error"]


@pytest.mark.asyncio
async def test_run_scan_not_available_without_queue():
    store = _ScanStore([])
    ctx = ToolContext(settings=_Scope(True), store=store)  # no scan_queue/state
    result = await run_tool(ctx, "run_scan", {"url": "https://api.acme-corp.com/x"})
    assert result["ok"] is False
    assert "not available" in result["error"]


@pytest.mark.asyncio
async def test_run_scan_no_matching_history_entry():
    from dast.proxy.scan_queue_state import ScanQueueState
    import asyncio

    store = _ScanStore([])
    ctx = ToolContext(settings=_Scope(True), store=store,
                      scan_queue=asyncio.Queue(), scan_queue_state=ScanQueueState())
    result = await run_tool(ctx, "run_scan", {"url": "https://api.acme-corp.com/x"})
    assert result["ok"] is False
    assert "no matching request" in result["error"]


@pytest.mark.asyncio
async def test_run_scan_enqueues_awaits_and_returns_findings():
    from dast.proxy.scan_queue_state import ScanQueueState
    import asyncio

    entry = _ScanEntry("GET", "https://api.acme-corp.com/users?id=1", "api.acme-corp.com")
    store = _ScanStore([entry], ai_mode=True)
    queue: asyncio.Queue = asyncio.Queue()
    qs = ScanQueueState()

    async def scan_worker():
        entry_id = await queue.get()
        # Simulate the real worker attaching a finding and finishing the entry.
        target = store.get_entry(entry_id)
        target.findings.append({
            "title": "Reflected XSS", "attack_type": "xss", "parameter": "id",
            "severity": "high", "raw_request": "x" * 9000,  # trimmed out
        })
        target.scan_result = "vulnerable"
        qs.finish(entry_id, 1, "vulnerable")

    ctx = ToolContext(settings=_Scope(True), store=store,
                      scan_queue=queue, scan_queue_state=qs)
    worker_task = asyncio.create_task(scan_worker())
    result = await run_tool(ctx, "run_scan", {"url": "https://api.acme-corp.com/users?id=1"})
    await worker_task

    assert result["ok"] is True
    assert result["status"] == "vulnerable"
    assert result["findings_count"] == 1
    assert result["agents_ran"] is True
    assert result["timed_out"] is False
    assert entry.ai_queued is True  # dedup bypassed for a deliberate re-scan
    finding = result["findings"][0]
    assert finding["title"] == "Reflected XSS"
    assert "raw_request" not in finding  # large blobs trimmed


@pytest.mark.asyncio
async def test_run_scan_runs_agents_even_when_ai_mode_off():
    # An EXPLICIT run_scan sets ai_queued, and the scan worker runs the full arsenal on an
    # ai_queued entry regardless of ambient ai_mode — so a session_safe run (ambient ai_mode
    # OFF) still gets real agents. The tool reports agents_ran=True accordingly.
    from dast.proxy.scan_queue_state import ScanQueueState
    import asyncio

    entry = _ScanEntry("GET", "https://api.acme-corp.com/x?q=1", "api.acme-corp.com")
    store = _ScanStore([entry], ai_mode=False)  # ambient AI off — but explicit scan still runs agents
    queue: asyncio.Queue = asyncio.Queue()
    qs = ScanQueueState()

    async def scan_worker():
        entry_id = await queue.get()
        store.get_entry(entry_id).scan_result = "safe"
        qs.finish(entry_id, 0, "safe")

    ctx = ToolContext(settings=_Scope(True), store=store,
                      scan_queue=queue, scan_queue_state=qs)
    worker_task = asyncio.create_task(scan_worker())
    result = await run_tool(ctx, "run_scan", {"url": "https://api.acme-corp.com/x?q=1"})
    await worker_task

    assert result["ok"] is True
    assert result["agents_ran"] is True        # explicit scan runs agents via ai_queued
    assert entry.ai_queued is True


# ── browser_login_adaptive (deterministic-first, LLM-fallback) ─────────────────

class _FakeLoginBrowser:
    """Minimal AgentBrowser stand-in for the adaptive-login tool wiring."""

    def __init__(self, login_result: dict):
        self._login_result = login_result
        self._url = login_result.get("url", "")

    async def login(self, url: str, email: str, password: str) -> dict:
        return self._login_result

    async def snapshot(self) -> dict:
        return {"url": self._url, "title": "", "forms": [], "buttons": [], "links": []}

    async def navigate(self, url: str) -> dict:
        self._url = url
        return {"ok": True, "url": url}

    async def export_cookies(self) -> dict:
        return {"session": "abc"}


def test_registry_lists_adaptive_login():
    names = {t.name for t in tools.all_tools()}
    assert "browser_login_adaptive" in names


@pytest.mark.asyncio
async def test_adaptive_login_browser_unavailable():
    ctx = ToolContext(settings=_Scope(True))  # no browser
    result = await run_tool(ctx, "browser_login_adaptive", {
        "url": "https://app.acme-corp.com/login", "email": "a@b.com", "password": "x"})
    assert result["ok"] is False
    assert "not available" in result["error"]


@pytest.mark.asyncio
async def test_adaptive_login_out_of_scope_blocked():
    ctx = ToolContext(settings=_Scope(allow=False),
                      browser=_FakeLoginBrowser({"logged_in": True, "url": "x"}))
    result = await run_tool(ctx, "browser_login_adaptive", {
        "url": "https://evil.example.com/login", "email": "a@b.com", "password": "x"})
    assert result["ok"] is False
    assert "out of scope" in result["error"]


@pytest.mark.asyncio
async def test_adaptive_login_deterministic_success():
    browser = _FakeLoginBrowser({"logged_in": True, "url": "https://app.acme-corp.com/dashboard"})
    ctx = ToolContext(settings=_Scope(True), browser=browser)
    result = await run_tool(ctx, "browser_login_adaptive", {
        "url": "https://app.acme-corp.com/login", "email": "a@b.com", "password": "x"})
    assert result["ok"] is True
    assert result["engine"] == "deterministic"
    assert result["llm_steps"] == 0


# ── session tools: save/list/activate + run_multiuser_idor ─────────────────────

class _FakeNamedSession:
    def __init__(self, name, role, cookies, auth_headers):
        self.name = name; self.role = role
        self.cookies = cookies; self.auth_headers = auth_headers


class _FakeSessionStore:
    def __init__(self, jar_cookies=None, named=None):
        self._jar = jar_cookies or {}            # host -> list[cookie dict]
        self.named_sessions = dict(named or {})

    def get_cookies_for_host(self, host):
        return self._jar.get(host, [])

    def entries_newest_first(self):
        return []

    def save_named_session_from_playwright(self, name, role, playwright_cookies, auth_headers=None):
        s = _FakeNamedSession(name, role,
                              {c["name"]: c for c in playwright_cookies if c.get("name")},
                              auth_headers or {})
        self.named_sessions[name] = s
        return s

    def get_named_sessions(self):
        return list(self.named_sessions.values())


def test_registry_lists_session_tools():
    names = {t.name for t in tools.all_tools()}
    assert {"save_login_session", "list_login_sessions", "activate_login_profile",
            "run_multiuser_idor"}.issubset(names)


@pytest.mark.asyncio
async def test_save_login_session_persists_named_session():
    store = _FakeSessionStore(jar_cookies={"app.acme-corp.com": [
        {"name": "sid", "value": "secret-value", "domain": "app.acme-corp.com"}]})
    ctx = ToolContext(settings=_Scope(True), store=store)
    result = await run_tool(ctx, "save_login_session",
                            {"name": "tenant_a", "host": "app.acme-corp.com", "role": "admin"})
    assert result["ok"] is True
    assert result["cookies"] == 1 and result["role"] == "admin"
    assert "tenant_a" in store.named_sessions
    # secret-free: no cookie values in the result
    assert "secret-value" not in str(result)


@pytest.mark.asyncio
async def test_save_login_session_out_of_scope_blocked():
    ctx = ToolContext(settings=_Scope(False), store=_FakeSessionStore())
    result = await run_tool(ctx, "save_login_session", {"name": "x", "host": "evil.example.com"})
    assert result["ok"] is False and "out of scope" in result["error"]


@pytest.mark.asyncio
async def test_save_login_session_no_cookies():
    ctx = ToolContext(settings=_Scope(True), store=_FakeSessionStore())
    result = await run_tool(ctx, "save_login_session", {"name": "x", "host": "app.acme-corp.com"})
    assert result["ok"] is False and "no cookies" in result["error"]


@pytest.mark.asyncio
async def test_list_login_sessions_secret_free():
    store = _FakeSessionStore(named={
        "a": _FakeNamedSession("a", "admin", {"sid": {"name": "sid", "value": "SEKRET", "domain": "x.com"}}, {}),
    })
    ctx = ToolContext(settings=_Scope(True), store=store)
    result = await run_tool(ctx, "list_login_sessions", {})
    assert result["ok"] is True and result["count"] == 1
    assert result["sessions"][0]["name"] == "a" and result["sessions"][0]["cookies"] == 1
    assert "SEKRET" not in str(result)


@pytest.mark.asyncio
async def test_run_multiuser_idor_requires_two_sessions():
    store = _FakeSessionStore(named={
        "a": _FakeNamedSession("a", "admin", {}, {})})  # only one
    ctx = ToolContext(settings=_Scope(True), store=store)
    result = await run_tool(ctx, "run_multiuser_idor", {"url": "https://app.acme-corp.com/x"})
    assert result["ok"] is False
    assert ">=2" in result["error"] or "2 saved" in result["error"]


# ── session tools: external-MCP HTTP fallback (store=None) ─────────────────────

class _FakeDashResp:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPError(f"HTTP {self.status_code}")


class _FakeDashClient:
    """Routes dashboard GET/POST to a handler(method, path, json) -> _FakeDashResp,
    so the store-less (MCP) tool path can be tested without a live dashboard."""

    def __init__(self, handler, **kw):
        self._handler = handler
        self.calls: list = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    @staticmethod
    def _path(url):
        from urllib.parse import urlparse
        return urlparse(url).path

    async def get(self, url, params=None):
        p = self._path(url)
        self.calls.append(("GET", p, params))
        return self._handler("GET", p, params)

    async def post(self, url, json=None):
        p = self._path(url)
        self.calls.append(("POST", p, json))
        return self._handler("POST", p, json)


@pytest.mark.asyncio
async def test_list_login_sessions_http_fallback(monkeypatch):
    def handler(method, path, body):
        assert method == "GET" and path == "/api/named-sessions"
        return _FakeDashResp(200, [{"name": "tenant_a", "role": "admin", "cookie_count": 4}])
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _FakeDashClient(handler, **kw))
    ctx = ToolContext(settings=_Scope(True))  # store=None → HTTP fallback (MCP path)
    result = await run_tool(ctx, "list_login_sessions", {})
    assert result["ok"] is True and result["count"] == 1
    assert result["sessions"][0]["name"] == "tenant_a"
    assert result["sessions"][0]["cookies"] == 4


@pytest.mark.asyncio
async def test_save_login_session_http_fallback(monkeypatch):
    def handler(method, path, body):
        if path == "/api/profiles/quick-capture":
            assert body["name"] == "tenant_a" and body["privilege_level"] == "admin"
            return _FakeDashResp(200, {"slug": "tenant_a",
                                       "captured": {"host": body["host"], "cookies": 5, "auth_headers": 2}})
        if path.endswith("/activate"):
            assert path == "/api/profiles/tenant_a/activate"
            return _FakeDashResp(200, {"named_session": "tenant_a", "cookies_imported": 5})
        raise AssertionError(f"unexpected path {path}")
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _FakeDashClient(handler, **kw))
    ctx = ToolContext(settings=_Scope(True))  # store=None
    result = await run_tool(ctx, "save_login_session",
                            {"name": "tenant_a", "host": "app.acme-corp.com", "role": "admin"})
    assert result["ok"] is True
    assert result["cookies"] == 5 and result["auth_headers"] == 2
    assert result["name"] == "tenant_a"


@pytest.mark.asyncio
async def test_save_login_session_http_fallback_no_cookies(monkeypatch):
    def handler(method, path, body):
        return _FakeDashResp(404, {"error": "no cookies found in proxy jar"})
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _FakeDashClient(handler, **kw))
    ctx = ToolContext(settings=_Scope(True))  # store=None
    result = await run_tool(ctx, "save_login_session", {"name": "x", "host": "app.acme-corp.com"})
    assert result["ok"] is False and "no cookies" in result["error"]


@pytest.mark.asyncio
async def test_save_login_session_http_fallback_still_scope_gated(monkeypatch):
    def boom(**kw):
        raise AssertionError("dashboard must not be called for an out-of-scope host")
    monkeypatch.setattr(httpx, "AsyncClient", boom)
    ctx = ToolContext(settings=_Scope(False))  # store=None AND out of scope
    result = await run_tool(ctx, "save_login_session", {"name": "x", "host": "evil.example.com"})
    assert result["ok"] is False and "out of scope" in result["error"]


@pytest.mark.asyncio
async def test_activate_login_profile_http_fallback(monkeypatch):
    def handler(method, path, body):
        assert method == "POST" and path == "/api/profiles/tenant_a/activate"
        return _FakeDashResp(200, {"activated": True, "cookies_imported": 7, "named_session": "tenant_a"})
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _FakeDashClient(handler, **kw))
    ctx = ToolContext(settings=_Scope(True))  # store=None
    result = await run_tool(ctx, "activate_login_profile", {"slug": "tenant_a"})
    assert result["ok"] is True and result["cookies_imported"] == 7
    assert result["named_session"] == "tenant_a"


@pytest.mark.asyncio
async def test_activate_login_profile_http_fallback_missing(monkeypatch):
    def handler(method, path, body):
        return _FakeDashResp(404, {"error": "profile not found"})
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _FakeDashClient(handler, **kw))
    ctx = ToolContext(settings=_Scope(True))  # store=None
    result = await run_tool(ctx, "activate_login_profile", {"slug": "nope"})
    assert result["ok"] is False and "no login profile" in result["error"]


@pytest.mark.asyncio
async def test_run_multiuser_idor_external_mcp_is_in_process_only():
    # store=None + scan_queue=None is exactly the external MCP ToolContext.
    ctx = ToolContext(settings=_Scope(True))
    result = await run_tool(ctx, "run_multiuser_idor", {"url": "https://app.acme-corp.com/x"})
    assert result["ok"] is False
    assert "in-process" in result["error"]


# ── code_* tools: thin wrappers over the existing code-analysis subsystem ──────

def test_registry_lists_code_tools():
    names = {t.name for t in tools.all_tools()}
    assert {"code_search", "code_file", "code_list", "code_lookup_path"}.issubset(names)


@pytest.mark.asyncio
async def test_code_search_reads_dashboard(monkeypatch):
    def handler(method, path, params):
        assert method == "GET" and path == "/api/code/search"
        assert params and params.get("q") == "integrations"
        return _FakeDashResp(200, [{"analysis_id": "a1", "file_path": "app/controllers/integrations_controller.rb",
                                    "language": "ruby", "preview": "def index", "content_length": 1200}])
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _FakeDashClient(handler, **kw))
    ctx = ToolContext(settings=_Scope(True))
    result = await run_tool(ctx, "code_search", {"query": "integrations"})
    assert result["ok"] is True and result["count"] == 1
    assert result["matches"][0]["file_path"].endswith("integrations_controller.rb")


@pytest.mark.asyncio
async def test_code_search_requires_query():
    ctx = ToolContext(settings=_Scope(True))
    result = await run_tool(ctx, "code_search", {"query": "  "})
    assert result["ok"] is False and "query is required" in result["error"]


@pytest.mark.asyncio
async def test_code_file_reads_dashboard(monkeypatch):
    def handler(method, path, params):
        assert path == "/api/code/file"
        return _FakeDashResp(200, {"path": "a.rb", "language": "ruby", "content": "class A; end"})
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _FakeDashClient(handler, **kw))
    ctx = ToolContext(settings=_Scope(True))
    result = await run_tool(ctx, "code_file", {"analysis_id": "a1", "path": "a.rb"})
    assert result["ok"] is True and result["content"] == "class A; end"


@pytest.mark.asyncio
async def test_code_file_not_found(monkeypatch):
    def handler(method, path, params):
        return _FakeDashResp(404, {"error": "file not found"})
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _FakeDashClient(handler, **kw))
    ctx = ToolContext(settings=_Scope(True))
    result = await run_tool(ctx, "code_file", {"analysis_id": "a1", "path": "missing.rb"})
    assert result["ok"] is False and "not found" in result["error"]


@pytest.mark.asyncio
async def test_code_list_reads_dashboard(monkeypatch):
    def handler(method, path, params):
        assert path == "/api/code/list"
        return _FakeDashResp(200, [{"analysis_id": "a1", "status": "scanned", "files_scanned": 42}])
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _FakeDashClient(handler, **kw))
    ctx = ToolContext(settings=_Scope(True))
    result = await run_tool(ctx, "code_list", {})
    assert result["ok"] is True and result["count"] == 1 and result["analyses"][0]["analysis_id"] == "a1"


@pytest.mark.asyncio
async def test_save_login_session_stores_credentials_for_relogin(monkeypatch):
    store = _FakeSessionStore(jar_cookies={"app.acme-corp.com": [
        {"name": "sid", "value": "secret-cookie", "domain": "app.acme-corp.com"}]})
    saved = {}
    import dast.profiles.store as pstore
    monkeypatch.setattr(pstore, "load_profile", lambda slug: None)
    monkeypatch.setattr(pstore, "save_profile", lambda profile: saved.setdefault("profile", profile))
    ctx = ToolContext(settings=_Scope(True), store=store)
    result = await run_tool(ctx, "save_login_session", {
        "name": "tenant_a", "host": "app.acme-corp.com", "role": "user",
        "username": "qa@x.com", "password": "hunter2",
        "auth_url": "https://app.acme-corp.com/login"})
    assert result["ok"] is True and result["credentials_stored"] is True
    assert "hunter2" not in str(result)  # secret-free result
    prof = saved["profile"]
    assert prof.auth_url == "https://app.acme-corp.com/login"
    assert prof.credentials and prof.credentials[0].username == "qa@x.com"
    assert prof.credentials[0].secret == "hunter2"


@pytest.mark.asyncio
async def test_save_login_session_without_creds_skips_profile(monkeypatch):
    store = _FakeSessionStore(jar_cookies={"app.acme-corp.com": [
        {"name": "sid", "value": "v", "domain": "app.acme-corp.com"}]})
    called = {"save": False}
    import dast.profiles.store as pstore
    monkeypatch.setattr(pstore, "load_profile", lambda slug: None)
    monkeypatch.setattr(pstore, "save_profile", lambda p: called.__setitem__("save", True))
    ctx = ToolContext(settings=_Scope(True), store=store)
    result = await run_tool(ctx, "save_login_session", {"name": "x", "host": "app.acme-corp.com"})
    assert result["ok"] is True and result["credentials_stored"] is False
    assert called["save"] is False


@pytest.mark.asyncio
async def test_code_lookup_path_falls_back_to_search(monkeypatch):
    # In the test process no analyses are loaded, so lookup_code_for_path returns "" and the
    # tool falls back to a dashboard search on the last real path segment.
    def handler(method, path, params):
        assert path == "/api/code/search"
        assert params and params.get("q") == "integrations"
        return _FakeDashResp(200, [{"analysis_id": "a1", "file_path": "integrations_controller.rb",
                                    "preview": "def show"}])
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _FakeDashClient(handler, **kw))
    ctx = ToolContext(settings=_Scope(True))
    result = await run_tool(ctx, "code_lookup_path",
                            {"url_path": "/app/backend/integrations/11111111-2222-3333-4444-555555555555"})
    assert result["ok"] is True
    assert result["count"] == 1 and "integrations" in result.get("note", "")
