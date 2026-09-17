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
async def test_send_request_reports_raw_reflection_past_truncation(monkeypatch):
    # An injected value that reflects UNENCODED deep in a large body is invisible
    # in the truncated `body`, so send_request must surface it as a reflection
    # signal — the decisive evidence for reflected XSS.
    marker = "<script>alert('FrierenXSS123')</script>"
    big_body = ("x" * 9000) + f"Hello {marker}, welcome" + ("y" * 500)

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
    assert marker not in result["body"]  # reflection lives past the 8000-char slice
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
    from dast.hackerone.parser import H1Report
    from dast.hackerone.validator import ValidationResult

    def fake_parse(text):
        return H1Report(vuln_type="idor",
                        proof_url="https://api.acme-corp.com/v1/users/1", payload="1")

    async def fake_validate(report, proxy_port=8080, cookies=None):
        return ValidationResult(job_id="j", status="confirmed", vuln_type="idor",
                                proof_url=report.proof_url, payload="1",
                                evidence="reflected", severity="high")

    monkeypatch.setattr("dast.hackerone.parser.parse_report", fake_parse)
    monkeypatch.setattr("dast.hackerone.validator.validate", fake_validate)
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
        async def post(self, url):
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
async def test_run_scan_reports_agents_not_run_when_ai_mode_off():
    from dast.proxy.scan_queue_state import ScanQueueState
    import asyncio

    entry = _ScanEntry("GET", "https://api.acme-corp.com/x?q=1", "api.acme-corp.com")
    store = _ScanStore([entry], ai_mode=False)  # AI off, proxied entry → deterministic only
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
    assert result["agents_ran"] is False
    assert "note" in result
