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


def test_path_exists_and_string_var_paths():
    from dast.tools.sqli_probe_tools import _path_exists, _string_var_paths
    body = {"operationName": "Rpt",
            "variables": {"v": {"contentTitle": "x", "purchasedCourseId": 1},
                          "reportConfig": {"filters": {"createdAtStart": "2026"}}}}
    assert _path_exists(body, "v.contentTitle") is True
    assert _path_exists(body, "v.purchasedCourseId") is True   # exists (non-string still "exists")
    assert _path_exists(body, "v.missing") is False
    assert _path_exists(body, "contentTitle") is False          # wrong depth
    # Only STRING leaves are suggested as candidates (not the int field).
    paths = _string_var_paths(body)
    assert "v.contentTitle" in paths
    assert "reportConfig.filters.createdAtStart" in paths
    assert "v.purchasedCourseId" not in paths


@pytest.mark.asyncio
async def test_sqli_probe_rejects_absent_injection_path(monkeypatch):
    """A false-negative guard: injecting a graphql_var path the operation does not have must fail
    loudly (naming the op + its string fields), not return a misleading NOT CONFIRMED."""
    from dast.tools import sqli_probe_tools as spt
    store = _FakeStore()
    result = await spt._sqli_probe(_FakeCtx(store), {
        "url": "https://app.example.com/reports/graphql",
        "injection_point": "v.contentTitle",            # absent in this op
        "injection_location": "graphql_var",
        "body": '{"operationName":"RiskScore","query":"query RiskScore($reportConfig:C!){r}",'
                '"variables":{"reportConfig":{"filters":{"createdAtStart":"2026"}}}}',
    })
    assert result["ok"] is False
    assert "false negative" in result["error"]
    assert result["operation"] == "RiskScore"
    assert "reportConfig.filters.createdAtStart" in result["available_string_fields"]
    assert store.recorded == []


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


# ── Part 1b: DBMS-aware impact facts + scope-bypass + severity (Unit 1) ──────

def test_detect_dbms():
    from dast.tools.sqli_probe_tools import _detect_dbms
    assert _detect_dbms("Parser Error: syntax error at or near \"'\"") == "DuckDB"
    assert _detect_dbms("Invalid Input Error: v1.4.2") == "DuckDB"
    assert _detect_dbms("error at com.mysql.jdbc.Driver near syntax") == "MySQL"
    assert _detect_dbms("totally benign response") == "unknown"


def test_severity_for():
    from dast.tools.sqli_probe_tools import _severity_for
    assert _severity_for("DuckDB", "true")[0] == "high"       # read beyond scope
    assert _severity_for("DuckDB", "unknown")[0] == "medium"  # embedded, scope unproven
    assert _severity_for("DuckDB", "false")[0] == "low"       # only in-scope data
    assert _severity_for("SQLite", "false")[0] == "low"       # embedded too
    assert _severity_for("MySQL", "unknown")[0] == "high"     # networked RDBMS
    assert _severity_for("unknown", "unknown")[0] == "medium"


def test_extract_labeled_leak():
    from dast.tools.sqli_probe_tools import _extract_labeled_leak
    body = '{"errors":[{"message":"Invalid Input Error: COLS=id,email,name"}]}'
    assert _extract_labeled_leak(body, "COLS") == "id,email,name"
    assert _extract_labeled_leak(body, "RC") is None
    assert _extract_labeled_leak("not json", "COLS") is None


class _DuckFactsClient:
    """Body-aware fake: confirms via a DuckDB parser error, then answers each labeled fact leak.
    `scoped` is the SRC (in-scope) count returned for the scope differential."""
    def __init__(self, *a, scoped="10", **k):
        self.scoped = scoped

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def request(self, method, url, headers=None, content=None):
        body = json.loads((content or b"{}").decode("utf-8"))
        injected = ((body.get("variables") or {}).get("v") or {}).get("contentTitle", "")
        if "sqli_probe_baseline" in injected:
            return _FakeResp('{"data":{"exportCsvReport":{"errors":[]}}}', 200)
        if "error(version())" in injected:
            return _FakeResp('{"errors":[{"message":"Invalid Input Error: v1.4.2"}]}', 200)
        if "TBLS=" in injected:
            return _FakeResp('{"errors":[{"message":"Invalid Input Error: '
                             'TBLS=users,accounts,courses"}]}', 200)
        if "SRC=" in injected:   # must precede the RC check ("RC=" is a substring of "SRC=")
            return _FakeResp('{"errors":[{"message":"Invalid Input Error: SRC=%s"}]}' % self.scoped, 200)
        if "RC=" in injected:
            return _FakeResp('{"errors":[{"message":"Invalid Input Error: RC=49"}]}', 200)
        if "COLS=" in injected:
            return _FakeResp('{"errors":[{"message":"Invalid Input Error: COLS=id,email,name"}]}', 200)
        return _FakeResp('{"errors":[{"message":"Parser Error: syntax error"}]}', 200)


@pytest.mark.asyncio
async def test_sqli_probe_facts_and_scope_bypass_true(monkeypatch):
    """With target_table + scope_where, the probe leaks schema/count metadata (NO PII values),
    decides scope_bypass=true when total > scoped, and calibrates severity to high."""
    from dast.tools import sqli_probe_tools as spt
    import httpx

    async def _no_facts(send, payload, dbms_hints=None):
        return None
    monkeypatch.setattr(spt, "extract_db_facts", _no_facts)
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _DuckFactsClient(scoped="10"))

    store = _FakeStore()
    result = await spt._sqli_probe(_FakeCtx(store), {
        "url": "https://app.example.com/reports/graphql",
        "injection_point": "v.contentTitle",
        "injection_location": "graphql_var",
        "target_table": "users",
        "scope_where": "account_id=1",
        "body": '{"query":"mutation($v:In!){exportCsvReport(input:$v){errors}}",'
                '"variables":{"v":{"purchasedCourseId":1,"contentTitle":"x"}}}',
    })
    assert result["ok"] and result["confirmed"] is True
    assert result["dbms"] == "DuckDB"
    facts = result["facts"]
    assert facts["reachable_tables"] == "users,accounts,courses"
    assert facts["row_count"] == "49"
    assert facts["columns"] == "id,email,name"       # NAMES only — no column values
    assert facts["scoped_row_count"] == "10"
    assert result["scope_bypass"] == "true"          # 10 in-scope < 49 total => reads beyond scope
    assert result["severity"] == "high"
    # No PII leaked: every fact value is a name list or an integer count.
    assert "@" not in json.dumps(facts)
    rec = store.recorded[0][0]
    assert rec["severity"] == "high" and rec["dbms"] == "DuckDB" and rec["scope_bypass"] == "true"


@pytest.mark.asyncio
async def test_sqli_probe_scope_bypass_false_lowers_severity(monkeypatch):
    """When the in-scope count equals the total, the read stays within scope => low severity."""
    from dast.tools import sqli_probe_tools as spt
    import httpx

    async def _no_facts(send, payload, dbms_hints=None):
        return None
    monkeypatch.setattr(spt, "extract_db_facts", _no_facts)
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _DuckFactsClient(scoped="49"))

    store = _FakeStore()
    result = await spt._sqli_probe(_FakeCtx(store), {
        "url": "https://app.example.com/reports/graphql",
        "injection_point": "v.contentTitle",
        "injection_location": "graphql_var",
        "target_table": "users",
        "scope_where": "account_id=1",
        "body": '{"query":"q","variables":{"v":{"contentTitle":"x"}}}',
    })
    assert result["scope_bypass"] == "false"
    assert result["severity"] == "low"


@pytest.mark.asyncio
async def test_sqli_probe_severity_override_respected(monkeypatch):
    """An explicit severity arg still wins over the DBMS/scope calibration."""
    from dast.tools import sqli_probe_tools as spt
    import httpx

    async def _no_facts(send, payload, dbms_hints=None):
        return None
    monkeypatch.setattr(spt, "extract_db_facts", _no_facts)
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _DuckFactsClient(scoped="49"))

    store = _FakeStore()
    result = await spt._sqli_probe(_FakeCtx(store), {
        "url": "https://app.example.com/reports/graphql",
        "injection_point": "v.contentTitle",
        "injection_location": "graphql_var",
        "severity": "critical",
        "body": '{"query":"q","variables":{"v":{"contentTitle":"x"}}}',
    })
    assert result["severity"] == "critical"


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
