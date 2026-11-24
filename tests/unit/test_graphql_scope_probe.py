"""Unit tests for the deterministic ``graphql_scope_probe`` tool.

A FAKE httpx transport returns canned responses with varying record counts to simulate
the scope-bypass differential: baseline returns N records, some enum variants return
MORE (bypass) or FEWER/EQUAL (safe). No real network or proxy is involved.

Tests cover:
  - Count extraction heuristic (pagination, relay, nodes, edges, top-level array)
  - Bypass flagging when a variant returns more records than baseline
  - No false positive when all variants return <= baseline
  - Auto-detection of enum arguments from schema
  - Error on missing schema / unknown operation
  - Finding recording on detected bypass
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock

import httpx
import pytest

from dast.tools.graphql_scope_probe_tools import (
    _extract_count,
    _find_enum_arguments,
    _build_query_with_enum,
    _graphql_scope_probe,
    _resolve_count_path,
)


# ---------------------------------------------------------------------------
# Fixtures: fake schema, context, and transport
# ---------------------------------------------------------------------------

_SCHEMA = {
    "introspected": True,
    "queries": {
        "users": {
            "args": [
                {"name": "per", "type": "Int", "wrapper": None},
                {"name": "permissionScope", "type": "GroupPermissionScopes", "wrapper": None},
            ],
            "return_type": "UserConnection",
        },
        "groups": {
            "args": [
                {"name": "permissionScope", "type": "GroupPermissionScopes", "wrapper": None},
            ],
            "return_type": "GroupConnection",
        },
        "campaigns": {
            "args": [
                {"name": "limit", "type": "Int", "wrapper": None},
            ],
            "return_type": "CampaignList",
        },
    },
    "mutations": {},
    "enum_types": {
        "GroupPermissionScopes": {
            "values": ["PHISHING", "TRAINING", "USERS"],
        },
    },
    "object_types": {
        "UserConnection": {
            "fields": [
                {"name": "pagination", "type": "Pagination"},
                {"name": "nodes", "type": "User"},
            ],
        },
        "Pagination": {
            "fields": [
                {"name": "totalCount", "type": "Int"},
                {"name": "page", "type": "Int"},
            ],
        },
        "User": {
            "fields": [
                {"name": "id", "type": "ID"},
                {"name": "email", "type": "String"},
            ],
        },
        "GroupConnection": {
            "fields": [
                {"name": "totalCount", "type": "Int"},
                {"name": "nodes", "type": "Group"},
            ],
        },
        "Group": {
            "fields": [
                {"name": "id", "type": "ID"},
                {"name": "name", "type": "String"},
            ],
        },
        "CampaignList": {
            "fields": [
                {"name": "edges", "type": "CampaignEdge"},
            ],
        },
        "CampaignEdge": {
            "fields": [
                {"name": "node", "type": "Campaign"},
            ],
        },
        "Campaign": {
            "fields": [
                {"name": "id", "type": "ID"},
            ],
        },
    },
    "input_types": {},
    "union_types": {},
}

_URL = "https://training.example.com/graphql"


class _FakeStore:
    def __init__(self, schema: Optional[dict] = None) -> None:
        self.graphql_schemas: Dict[str, Any] = {}
        if schema:
            self.graphql_schemas[_URL] = schema
        self.recorded: List[tuple] = []
        self._cookies: Dict[str, list] = {}

    def get_cookies_for_host(self, host: str) -> list:
        return self._cookies.get(host, [])

    def record_manual_finding(self, finding, url, method="POST"):
        self.recorded.append((finding, url, method))
        return f"entry-scope-{len(self.recorded)}"


class _FakeSettings:
    def is_in_scope(self, url: str) -> bool:
        return "example.com" in url


class _FakeContext:
    def __init__(self, store: Optional[_FakeStore] = None) -> None:
        self.store = store or _FakeStore(_SCHEMA)
        self.settings = _FakeSettings()
        self.proxy_port = 8080
        self.source_label = "test"
        self.browser = None
        self._session = None

    def get_settings(self):
        return self.settings

    def is_in_scope(self, url: str) -> bool:
        return self.settings.is_in_scope(url)

    @property
    def proxy_url(self) -> str:
        return f"http://127.0.0.1:{self.proxy_port}"


# ---------------------------------------------------------------------------
# Count extraction tests
# ---------------------------------------------------------------------------

class TestExtractCount:
    def test_pagination_total_count(self):
        resp = {"data": {"users": {"pagination": {"totalCount": 129}, "nodes": []}}}
        assert _extract_count(resp, "users") == 129

    def test_relay_total_count(self):
        resp = {"data": {"users": {"totalCount": 42}}}
        assert _extract_count(resp, "users") == 42

    def test_nodes_array(self):
        resp = {"data": {"users": {"nodes": [{"id": 1}, {"id": 2}, {"id": 3}]}}}
        assert _extract_count(resp, "users") == 3

    def test_edges_array(self):
        resp = {"data": {"users": {"edges": [{"node": {"id": 1}}, {"node": {"id": 2}}]}}}
        assert _extract_count(resp, "users") == 2

    def test_top_level_array(self):
        resp = {"data": {"users": [{"id": 1}]}}
        assert _extract_count(resp, "users") == 1

    def test_no_data(self):
        assert _extract_count({}, "users") is None
        assert _extract_count({"data": {}}, "users") is None
        assert _extract_count({"data": {"users": "not_dict_or_list"}}, "users") is None

    def test_pagination_takes_precedence_over_nodes(self):
        resp = {"data": {"users": {
            "pagination": {"totalCount": 100},
            "nodes": [{"id": 1}],
        }}}
        assert _extract_count(resp, "users") == 100


class TestResolveCountPath:
    def test_dot_path(self):
        resp = {"data": {"users": {"pagination": {"totalCount": 55}}}}
        assert _resolve_count_path(resp, "data.users.pagination.totalCount") == 55

    def test_missing_key(self):
        assert _resolve_count_path({}, "data.users.totalCount") is None

    def test_array_length(self):
        resp = {"data": {"users": {"nodes": [1, 2, 3]}}}
        assert _resolve_count_path(resp, "data.users.nodes") == 3


# ---------------------------------------------------------------------------
# Schema helper tests
# ---------------------------------------------------------------------------

class TestFindEnumArguments:
    def test_finds_enum_args(self):
        enums = _find_enum_arguments(_SCHEMA, "query", "users")
        assert len(enums) == 1
        assert enums[0]["name"] == "permissionScope"
        assert enums[0]["type"] == "GroupPermissionScopes"
        assert set(enums[0]["values"]) == {"PHISHING", "TRAINING", "USERS"}

    def test_no_enum_args(self):
        enums = _find_enum_arguments(_SCHEMA, "query", "campaigns")
        assert enums == []

    def test_unknown_operation(self):
        enums = _find_enum_arguments(_SCHEMA, "query", "nonexistent")
        assert enums == []


class TestBuildQueryWithEnum:
    def test_baseline_omits_enum(self):
        result = _build_query_with_enum(_SCHEMA, "query", "users", "permissionScope", None)
        assert "permissionScope" not in result["query"]
        # Optional args (like `per`) are also omitted — only required + target enum included
        assert "per" not in result["query"]
        assert result["variables"] == {}

    def test_variant_includes_enum(self):
        result = _build_query_with_enum(_SCHEMA, "query", "users", "permissionScope", "TRAINING")
        assert "permissionScope" in result["query"]
        found_training = any(v == "TRAINING" for v in result["variables"].values())
        assert found_training
        # Only the enum arg should be in the query (optional `per` is excluded)
        assert "per:" not in result["query"]
        assert len(result["variables"]) == 1

    def test_required_args_kept(self):
        """Required (NON_NULL) non-target args are still included in the query."""
        schema = {**_SCHEMA, "queries": {**_SCHEMA["queries"], "filtered": {
            "args": [
                {"name": "accountId", "type": "Int", "wrapper": "NON_NULL"},
                {"name": "scope", "type": "GroupPermissionScopes", "wrapper": None},
                {"name": "search", "type": "String", "wrapper": None},
            ],
            "return_type": "UserConnection",
        }}}
        result = _build_query_with_enum(schema, "query", "filtered", "scope", "TRAINING")
        assert "accountId" in result["query"]
        assert "scope" in result["query"]
        assert "search" not in result["query"]
        assert len(result["variables"]) == 2


# ---------------------------------------------------------------------------
# Full handler tests (mocked HTTP transport)
# ---------------------------------------------------------------------------

def _make_response(data: dict, status: int = 200) -> httpx.Response:
    body = json.dumps(data).encode()
    return httpx.Response(status_code=status, content=body,
                          headers={"content-type": "application/json"})


class _MockTransport(httpx.AsyncBaseTransport):
    """Returns canned GraphQL responses based on whether the query includes an enum value."""

    def __init__(self, baseline_count: int, variant_counts: Dict[str, int],
                 error_values: Optional[set] = None) -> None:
        self.baseline_count = baseline_count
        self.variant_counts = variant_counts
        self.error_values = error_values or set()
        self.requests: List[dict] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        self.requests.append(body)

        # Check if any variable matches an enum value
        variables = body.get("variables", {})
        for val in variables.values():
            if isinstance(val, str) and val in self.error_values:
                return _make_response({"errors": [{"message": f"crash on {val}"}]})
            if isinstance(val, str) and val in self.variant_counts:
                count = self.variant_counts[val]
                return _make_response({
                    "data": {"users": {"pagination": {"totalCount": count}, "nodes": []}}
                })

        # Baseline (no enum value matched)
        return _make_response({
            "data": {"users": {"pagination": {"totalCount": self.baseline_count}, "nodes": []}}
        })


@pytest.fixture
def ctx():
    return _FakeContext()


@pytest.mark.asyncio
async def test_bypass_detected(ctx, monkeypatch):
    """When TRAINING returns more records than baseline, it's flagged."""
    transport = _MockTransport(
        baseline_count=0,
        variant_counts={"TRAINING": 129, "PHISHING": 0, "USERS": 0},
    )
    monkeypatch.setattr("httpx.AsyncClient.__init__", lambda self, **kw: None)

    async def fake_aenter(self):
        self._transport = transport
        return self

    async def fake_aexit(self, *a):
        pass

    async def fake_request(self, method, url, **kw):
        req = httpx.Request(method, url, content=kw.get("content", b""))
        return await transport.handle_async_request(req)

    monkeypatch.setattr("httpx.AsyncClient.__aenter__", fake_aenter)
    monkeypatch.setattr("httpx.AsyncClient.__aexit__", fake_aexit)
    monkeypatch.setattr("httpx.AsyncClient.request", fake_request)
    monkeypatch.setattr("dast.scanners.noise_governor.acquire", AsyncMock(return_value=None))

    result = await _graphql_scope_probe(ctx, {
        "url": _URL,
        "operation": "users",
        "enum_argument": "permissionScope",
    })

    assert result["ok"] is True
    assert result["verdict"] == "SCOPE_BYPASS_DETECTED"
    assert result["bypasses_found"] >= 1
    flagged_values = {f["value"] for f in result["flagged"]}
    assert "TRAINING" in flagged_values
    assert "PHISHING" not in flagged_values

    # Finding should be recorded
    assert len(ctx.store.recorded) == 1
    finding = ctx.store.recorded[0][0]
    assert finding["attack_type"] == "bfla"
    assert finding["cwe"] == "CWE-863"
    assert "permissionScope" in finding["parameter"]


@pytest.mark.asyncio
async def test_no_bypass(ctx, monkeypatch):
    """When all variants return <= baseline, no bypass is flagged."""
    transport = _MockTransport(
        baseline_count=10,
        variant_counts={"TRAINING": 5, "PHISHING": 10, "USERS": 0},
    )
    monkeypatch.setattr("httpx.AsyncClient.__init__", lambda self, **kw: None)

    async def fake_aenter(self):
        self._transport = transport
        return self

    async def fake_aexit(self, *a):
        pass

    async def fake_request(self, method, url, **kw):
        req = httpx.Request(method, url, content=kw.get("content", b""))
        return await transport.handle_async_request(req)

    monkeypatch.setattr("httpx.AsyncClient.__aenter__", fake_aenter)
    monkeypatch.setattr("httpx.AsyncClient.__aexit__", fake_aexit)
    monkeypatch.setattr("httpx.AsyncClient.request", fake_request)
    monkeypatch.setattr("dast.scanners.noise_governor.acquire", AsyncMock(return_value=None))

    result = await _graphql_scope_probe(ctx, {
        "url": _URL,
        "operation": "users",
    })

    assert result["ok"] is True
    assert result["verdict"] == "NO_BYPASS"
    assert result["bypasses_found"] == 0
    assert len(ctx.store.recorded) == 0


@pytest.mark.asyncio
async def test_no_schema(ctx):
    """Missing schema returns a clear error."""
    ctx.store.graphql_schemas.clear()
    result = await _graphql_scope_probe(ctx, {
        "url": _URL,
        "operation": "users",
    })
    assert result["ok"] is False
    assert "no cached schema" in result["error"]


@pytest.mark.asyncio
async def test_unknown_operation(ctx):
    """Unknown operation returns suggestions."""
    result = await _graphql_scope_probe(ctx, {
        "url": _URL,
        "operation": "nonexistent",
    })
    assert result["ok"] is False
    assert "not found" in result["error"]


@pytest.mark.asyncio
async def test_no_enum_args(ctx):
    """Operation with no enum args returns early."""
    result = await _graphql_scope_probe(ctx, {
        "url": _URL,
        "operation": "campaigns",
    })
    assert result["ok"] is True
    assert result["result"] == "no_enum_args"


@pytest.mark.asyncio
async def test_out_of_scope():
    """Out-of-scope URL is rejected."""
    ctx = _FakeContext()
    result = await _graphql_scope_probe(ctx, {
        "url": "https://evil.com/graphql",
        "operation": "users",
    })
    assert result["ok"] is False
    assert "out of scope" in result["error"]


@pytest.mark.asyncio
async def test_no_record_flag(ctx, monkeypatch):
    """record=False skips finding creation."""
    transport = _MockTransport(
        baseline_count=0,
        variant_counts={"TRAINING": 129, "PHISHING": 0, "USERS": 0},
    )
    monkeypatch.setattr("httpx.AsyncClient.__init__", lambda self, **kw: None)

    async def fake_aenter(self):
        self._transport = transport
        return self

    async def fake_aexit(self, *a):
        pass

    async def fake_request(self, method, url, **kw):
        req = httpx.Request(method, url, content=kw.get("content", b""))
        return await transport.handle_async_request(req)

    monkeypatch.setattr("httpx.AsyncClient.__aenter__", fake_aenter)
    monkeypatch.setattr("httpx.AsyncClient.__aexit__", fake_aexit)
    monkeypatch.setattr("httpx.AsyncClient.request", fake_request)
    monkeypatch.setattr("dast.scanners.noise_governor.acquire", AsyncMock(return_value=None))

    result = await _graphql_scope_probe(ctx, {
        "url": _URL,
        "operation": "users",
        "record": False,
    })

    assert result["verdict"] == "SCOPE_BYPASS_DETECTED"
    assert len(ctx.store.recorded) == 0


@pytest.mark.asyncio
async def test_multiple_bypasses(ctx, monkeypatch):
    """Multiple enum values returning more than baseline are all flagged."""
    transport = _MockTransport(
        baseline_count=0,
        variant_counts={"TRAINING": 129, "PHISHING": 50, "USERS": 0},
    )
    monkeypatch.setattr("httpx.AsyncClient.__init__", lambda self, **kw: None)

    async def fake_aenter(self):
        self._transport = transport
        return self

    async def fake_aexit(self, *a):
        pass

    async def fake_request(self, method, url, **kw):
        req = httpx.Request(method, url, content=kw.get("content", b""))
        return await transport.handle_async_request(req)

    monkeypatch.setattr("httpx.AsyncClient.__aenter__", fake_aenter)
    monkeypatch.setattr("httpx.AsyncClient.__aexit__", fake_aexit)
    monkeypatch.setattr("httpx.AsyncClient.request", fake_request)
    monkeypatch.setattr("dast.scanners.noise_governor.acquire", AsyncMock(return_value=None))

    result = await _graphql_scope_probe(ctx, {
        "url": _URL,
        "operation": "users",
    })

    assert result["verdict"] == "SCOPE_BYPASS_DETECTED"
    assert result["bypasses_found"] == 2
    flagged_values = {f["value"] for f in result["flagged"]}
    assert flagged_values == {"TRAINING", "PHISHING"}
