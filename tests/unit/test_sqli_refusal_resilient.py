"""Unit tests for the refusal-resilient SQLi work:

- Part 1: the deterministic `sqli_probe` tool confirms a SQLi from a SQL-error differential,
  extracts a version() proof, records a finding, and imports NO LLM client.
- Part 2: `generate_payloads` falls back to static YAML seeds when the LLM is safety-blocked.
- Part 3: `LoginProfile` round-trips the per-profile downgrade opt-in; it is off by default.
"""

from __future__ import annotations

import json

import ast
import os

import pytest


# ── Part 1: sqli_probe ───────────────────────────────────────────────────────

def test_sqli_probe_module_has_no_llm_dependency():
    """The whole point is refusal-immunity: the tool must not import bedrock_client."""
    path = os.path.join(os.path.dirname(__file__), "..", "..",
                        "dast", "tools", "sqli_probe_tools.py")
    tree = ast.parse(open(path).read())
    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
        elif isinstance(node, ast.Import):
            imported.extend(a.name for a in node.names)
    assert not any("bedrock" in m for m in imported), f"LLM import leaked in: {imported}"


def test_sqli_probe_registered():
    import dast.tools  # noqa: F401 — registers tools
    from dast.tools import base
    assert "sqli_probe" in base._REGISTRY
    assert base._REGISTRY["sqli_probe"].input_schema["required"] == ["url", "injection_point"]


def test_inject_path_nested_and_toplevel():
    from dast.tools.sqli_probe_tools import _inject_path
    body = {"query": "m", "variables": {"v": {"purchasedCourseId": 1, "contentTitle": "orig"}}}
    out = _inject_path(body, "v.contentTitle", "PAYLOAD")
    assert out["variables"]["v"]["contentTitle"] == "PAYLOAD"
    assert out["variables"]["v"]["purchasedCourseId"] == 1          # sibling preserved
    assert body["variables"]["v"]["contentTitle"] == "orig"          # template not mutated
    # missing intermediate is created; plain (no dot) sets a top-level variable
    assert _inject_path({}, "a.b", "x")["variables"]["a"]["b"] == "x"
    assert _inject_path({"variables": {}}, "top", "y")["variables"]["top"] == "y"


def test_extract_duckdb_version():
    from dast.tools.sqli_probe_tools import _extract_duckdb_version
    assert _extract_duckdb_version('{"errors":[{"message":"Invalid Input Error: v1.4.2"}]}') == "v1.4.2"
    assert _extract_duckdb_version('{"data":{"ok":true}}') is None
    assert _extract_duckdb_version("not json") is None


class _FakeResp:
    def __init__(self, text, status=200):
        self.text = text
        self.status_code = status


class _FakeStore:
    def __init__(self):
        self.recorded = []

    def get_cookies_for_host(self, host):
        return [{"name": "_knowbe4_session_new", "value": "x"}]

    def record_manual_finding(self, finding, url, method="GET"):
        self.recorded.append((finding, url, method))
        return "entry-1"


class _FakeCtx:
    def __init__(self, store):
        self.store = store
        self.source_label = "copilot"
        self.proxy_port = 8080

    @property
    def proxy_url(self):
        return "http://127.0.0.1:8080"

    def is_in_scope(self, url):
        return True


@pytest.mark.asyncio
async def test_sqli_probe_confirms_error_based_and_records(monkeypatch):
    from dast.tools import sqli_probe_tools as spt

    # Deterministic error signature: a benign baseline, a SQL error for the breaking payload.
    sql_error = "You have an error in your SQL syntax near ''1'='1'"

    class _FakeClient:
        def __init__(self, *a, **k):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False
        async def request(self, method, url, headers=None, content=None):
            body = (content or b"").decode("utf-8", "ignore")
            # Baseline benign value -> clean 200; any error-based payload -> SQL error body.
            if "sqli_probe_baseline" in body:
                return _FakeResp('{"data": {"ok": true}}', 200)
            return _FakeResp(sql_error, 200)

    import httpx
    monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)
    # Skip the extraction engine (its own request budget) — not needed to prove confirmation.
    async def _no_facts(send, payload, dbms_hints=None):
        return None
    monkeypatch.setattr(spt, "extract_db_facts", _no_facts)

    store = _FakeStore()
    ctx = _FakeCtx(store)
    result = await spt._sqli_probe(ctx, {
        "url": "https://app.example.com/reports/graphql/",
        "injection_point": "title",
        "injection_location": "graphql_var",
        "body": '{"query":"mutation($title:String){x(title:$title)}",'
                '"variables":{"title":"hi"},"operationName":null}',
    })
    assert result["ok"] is True
    assert result["confirmed"] is True
    assert result["technique"] == "error-based"
    assert len(store.recorded) == 1
    finding = store.recorded[0][0]
    assert finding["attack_type"] == "sqli" and finding["confirmed"] is True
    assert finding["validated_by"] == ["sqli_probe"]


@pytest.mark.asyncio
async def test_sqli_probe_attaches_subapp_bearer_and_xrw(monkeypatch):
    """The probe must carry the sub-app Bearer + X-Requested-With (not just a cookie), so a
    Bearer-authed sub-app like /reports/graphql does not 403."""
    from dast.tools import sqli_probe_tools as spt
    import httpx

    captured = {}

    class _CapClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def request(self, method, url, headers=None, content=None):
            captured["headers"] = headers or {}
            return _FakeResp('{"data": {"ok": true}}', 200)

    monkeypatch.setattr(httpx, "AsyncClient", _CapClient)

    class _Engine:
        async def _ensure_fresh_bearer(self, store, host, path, browser=None):
            return {"token": "subapp.jwt.token"}  # exp None -> fresh

    class _StoreWithCookies:
        def get_cookies_for_host(self, host):
            return [{"name": "_knowbe4_session_new", "value": "s"}]

    class _CtxWithSession(_FakeCtx):
        def __init__(self, store):
            super().__init__(store)
            self._session = _Engine()

    await spt._sqli_probe(_CtxWithSession(_StoreWithCookies()), {
        "url": "https://app.example.com/reports/graphql",
        "injection_point": "title",
        "injection_location": "graphql_var",
        "body": '{"query":"q","variables":{"title":"hi"}}',
    })
    hdrs = {k.lower(): v for k, v in (captured.get("headers") or {}).items()}
    assert hdrs.get("authorization") == "Bearer subapp.jwt.token"
    assert hdrs.get("x-requested-with") == "XMLHttpRequest"
    assert "cookie" in hdrs  # jar cookie still attached


@pytest.mark.asyncio
async def test_sqli_probe_nested_graphql_var_with_duckdb_version(monkeypatch):
    """Inject into a NESTED variable (v.contentTitle) and extract the DuckDB version() leak."""
    from dast.tools import sqli_probe_tools as spt
    import httpx

    class _BodyAwareClient:
        def __init__(self, *a, **k):
            self.sent = []
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False
        async def request(self, method, url, headers=None, content=None):
            body = json.loads((content or b"{}").decode("utf-8"))
            injected = ((body.get("variables") or {}).get("v") or {}).get("contentTitle", "")
            self.sent.append(injected)
            if "sqli_probe_baseline" in injected:
                return _FakeResp('{"data":{"exportCsvReport":{"errors":[]}}}', 200)
            if "error(version())" in injected:          # the DuckDB version-leak payload
                return _FakeResp('{"data":null,"errors":[{"message":"Invalid Input Error: v1.4.2"}]}', 200)
            # any other (quote-breaking) payload: a NEW DuckDB parse error, no version
            return _FakeResp('{"data":null,"errors":[{"message":"Parser Error: syntax error"}]}', 200)

    monkeypatch.setattr(httpx, "AsyncClient", _BodyAwareClient)
    store = _FakeStore()
    result = await spt._sqli_probe(_FakeCtx(store), {
        "url": "https://app.example.com/reports/graphql",
        "injection_point": "v.contentTitle",
        "injection_location": "graphql_var",
        "body": '{"query":"mutation($v:InteractionsInput!){exportCsvReport(input:$v){errors}}",'
                '"variables":{"v":{"purchasedCourseId":1,"sortDirection":"ASC","contentTitle":"x"}}}',
    })
    assert result["ok"] and result["confirmed"] is True
    assert result["facts"].get("version") == "v1.4.2"
    assert "DuckDB version leak" in result["technique"]
    # finding recorded with the injection point + extracted version
    assert store.recorded and store.recorded[0][0]["parameter"] == "v.contentTitle"
    assert store.recorded[0][0]["extracted_data"]["version"] == "v1.4.2"


@pytest.mark.asyncio
async def test_sqli_probe_not_confirmed_on_clean_responses(monkeypatch):
    from dast.tools import sqli_probe_tools as spt
    import httpx

    class _CleanClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def request(self, method, url, headers=None, content=None):
            return _FakeResp('{"data": {"ok": true}}', 200)

    monkeypatch.setattr(httpx, "AsyncClient", _CleanClient)
    store = _FakeStore()
    result = await spt._sqli_probe(_FakeCtx(store), {
        "url": "https://app.example.com/reports/graphql/",
        "injection_point": "title",
        "injection_location": "graphql_var",
        "body": '{"query":"q","variables":{"title":"hi"}}',
    })
    assert result["ok"] is True and result["confirmed"] is False
    assert store.recorded == []


# ── Part 2: deterministic seed fallback ──────────────────────────────────────

def test_generate_payloads_falls_back_to_seeds_on_safety_block(monkeypatch):
    from dast.ai import payload_generator as pg
    from dast.ai import bedrock_client
    from dast.models import Endpoint, EndpointParameter

    def _blocked(*a, **k):
        raise bedrock_client.AiContentBlockedError("upstream rejected")
    monkeypatch.setattr(pg.bedrock_client, "invoke_json", _blocked)

    endpoint = Endpoint(url="https://t/x", method="POST",
                        parameters=[EndpointParameter(name="q", location="query")])
    out = pg.generate_payloads(endpoint, ["sqli"])
    assert out, "expected deterministic seeds, got none"
    assert all(p.attack_type == "sqli" for p in out)
    assert all(p.injection_point == "q" for p in out)


# ── Part 3: per-profile downgrade opt-in ─────────────────────────────────────

def test_profile_downgrade_optin_roundtrips_and_defaults_off():
    from dast.profiles.models import LoginProfile

    p = LoginProfile(slug="x", name="x")
    assert p.allow_model_downgrade is False and p.downgrade_model == ""
    assert p.to_public_dict()["allow_model_downgrade"] is False

    p2 = LoginProfile(slug="y", name="y", allow_model_downgrade=True,
                      downgrade_model="claude-opus-4-6")
    restored = LoginProfile.from_storage_dict(p2.to_storage_dict())
    assert restored.allow_model_downgrade is True
    assert restored.downgrade_model == "claude-opus-4-6"
    assert restored.to_public_dict()["downgrade_model"] == "claude-opus-4-6"
