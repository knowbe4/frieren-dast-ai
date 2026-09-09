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
            "get_findings", "oob_generate", "oob_poll",
            "url_encode", "url_decode", "base64_encode", "base64_decode",
            "html_encode", "html_decode"} <= names


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
async def test_send_request_out_of_scope_blocked():
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
