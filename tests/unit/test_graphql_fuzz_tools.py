"""
Unit tests for the schema-free graphql_fuzz tool and its coverage integration.

The network-driving fuzz loop (run_fuzz_job) is covered by
test_graphql_variable_fuzzer.py; here we cover operation discovery from captured
traffic, the tested-ops write-back / resumability, read-only refusal, and the
captured-GraphQL coverage dimension.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

from dast.proxy.api.copilot_service import CopilotService
from dast.tools.base import run_tool
from dast.tools.context import ToolContext
from dast.tools.graphql_fuzz_tools import _captured_operations, _op_key


def _gql_entry(url, query, variables, op_name=None):
    body = {"query": query, "variables": variables}
    if op_name:
        body["operationName"] = op_name
    return SimpleNamespace(
        method="POST",
        url=url,
        host=url.split("/")[2],
        path="/" + url.split("/", 3)[3] if url.count("/") >= 3 else "/graphql",
        request_body=json.dumps(body).encode("utf-8"),
        request_headers={"cookie": "s=1", "content-type": "application/json"},
    )


class _Store:
    def __init__(self, entries):
        self._entries = entries
        self.graphql_tested_ops = {}
        self.graphql_schemas = {}

    def in_scope_entries(self):
        return self._entries


def test_op_key_uses_operation_name_else_hash():
    assert _op_key({"operationName": "GetUser", "query": "query { me }"}) == "GetUser"
    anon = _op_key({"query": "query  {   me  }"})
    assert anon.startswith("anon:")
    # whitespace-insensitive
    assert anon == _op_key({"query": "query { me }"})


def test_captured_operations_dedups_and_skips_varless():
    url = "https://api.example.com/graphql"
    store = _Store([
        _gql_entry(url, "query($id:ID!){u(id:$id){x}}", {"id": "1"}, "GetU"),
        _gql_entry(url, "query($id:ID!){u(id:$id){x}}", {"id": "2"}, "GetU"),  # dup op
        _gql_entry(url, "query{ping}", {}),                                     # no vars -> skipped
    ])
    ops = _captured_operations(store, url)
    assert [k for k, _b, _h in ops] == ["GetU"]
    # auth headers are carried through for the fuzz requests
    assert ops[0][2].get("cookie") == "s=1"


def test_graphql_fuzz_blocked_in_read_only():
    result = asyncio.run(run_tool(ToolContext(read_only=True), "graphql_fuzz",
                                  {"url": "https://api.example.com/graphql"}))
    assert result["ok"] is False and result.get("read_only") is True


def test_graphql_fuzz_no_captured_ops_is_ok_noop():
    store = _Store([])
    ctx = ToolContext()
    ctx.store = store
    ctx.is_in_scope = lambda url: True  # type: ignore[method-assign]
    result = asyncio.run(run_tool(ctx, "graphql_fuzz", {"url": "https://api.example.com/graphql"}))
    assert result["ok"] is True
    assert result["operations_fuzzed"] == 0 and result["operations_remaining"] == 0


def test_captured_graphql_coverage_dimension():
    url = "https://api.example.com/graphql"
    store = _Store([_gql_entry(url, "query($id:ID!){u(id:$id){x}}", {"id": "1"}, "GetU")])
    service = CopilotService(SimpleNamespace(proxy_port=8080, dashboard_port=8088,
                                             store=store, settings=None,
                                             broadcast_copilot=None))
    cov = service._surface_coverage(["api.example.com"])
    assert cov["gql_captured_total"] == 1
    assert cov["gql_captured_untested"] == ["GetU"]
    assert cov["has_surface"] is True and cov["complete"] is False

    # Mark it fuzzed -> coverage closes.
    store.graphql_tested_ops[url] = {"fuzz:GetU"}
    cov2 = service._surface_coverage(["api.example.com"])
    assert cov2["gql_captured_tested"] == 1
    assert cov2["gql_captured_untested"] == []
    assert cov2["complete"] is True
