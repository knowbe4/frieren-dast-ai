"""Unit tests for the GraphQL IDOR agent."""

from __future__ import annotations

import json
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dast.agents.graphql_agent import (
    GraphqlIdorAgent,
    _data_differs,
    _data_is_meaningful,
    _gql_data,
    _gql_errors,
    _inject_variable,
    _is_id_param,
    _neighbour_values,
)
from dast.scanners.active_checks import CheckTarget


# ── helpers ────────────────────────────────────────────────────────────────

def _target(variables: dict, query: str = "query Q($id: ID!) { node(id: $id) { id name } }") -> CheckTarget:
    body = json.dumps({"query": query, "variables": variables})
    params = [
        {"name": k, "location": "body_graphql", "value": str(v)}
        for k, v in variables.items()
    ]
    return CheckTarget(
        method="POST",
        url="https://example.com/graphql",
        headers={"content-type": "application/json"},
        body=body,
        params=params,
    )


def _resp(data: Optional[dict] = None, errors: Optional[list] = None) -> MagicMock:
    payload = {}
    if data is not None:
        payload["data"] = data
    if errors is not None:
        payload["errors"] = errors
    m = MagicMock()
    m.json.return_value = payload
    m.status_code = 200
    return m


# ── unit: helper functions ─────────────────────────────────────────────────

class TestIsIdParam:
    def test_numeric_id(self):
        assert _is_id_param("id", "123")

    def test_userId(self):
        assert _is_id_param("userId", "456")

    def test_uuid_field(self):
        assert _is_id_param("user_id", "550e8400-e29b-41d4-a716-446655440000")

    def test_non_id_name(self):
        assert not _is_id_param("username", "alice")

    def test_non_id_value(self):
        assert not _is_id_param("id", "not-a-number")

    def test_name_field_ignored(self):
        assert not _is_id_param("name", "Alice")


class TestNeighbourValues:
    def test_numeric_neighbours(self):
        vals = _neighbour_values("10")
        assert "9" in vals
        assert "11" in vals

    def test_numeric_no_negative(self):
        vals = _neighbour_values("1")
        assert all(int(v) > 0 for v in vals)

    def test_uuid_neighbours(self):
        original = "550e8400-e29b-41d4-a716-446655440000"
        vals = _neighbour_values(original)
        assert len(vals) > 0
        assert original not in vals

    def test_unknown_format_returns_empty(self):
        assert _neighbour_values("abc-xyz") == []


class TestGqlHelpers:
    def test_errors_extracted(self):
        resp = {"errors": [{"message": "Not authorized"}]}
        assert _gql_errors(resp) == ["Not authorized"]

    def test_no_errors(self):
        resp = {"data": {"user": {"id": "1"}}}
        assert _gql_errors(resp) == []

    def test_data_null_returns_none(self):
        assert _gql_data({"data": None}) is None

    def test_data_all_null_returns_none(self):
        assert _gql_data({"data": {"user": None}}) is None

    def test_data_meaningful(self):
        assert _data_is_meaningful({"user": {"id": "1", "name": "Alice"}})

    def test_data_not_meaningful_null(self):
        assert not _data_is_meaningful({"user": None})

    def test_data_not_meaningful_empty(self):
        assert not _data_is_meaningful({})

    def test_data_differs_true(self):
        a = {"user": {"id": "1", "name": "Alice"}}
        b = {"user": {"id": "2", "name": "Bob"}}
        assert _data_differs(a, b)

    def test_data_differs_false(self):
        a = {"user": {"id": "1", "name": "Alice"}}
        assert not _data_differs(a, a)


class TestInjectVariable:
    def test_injects_correctly(self):
        body = json.dumps({"query": "{ q }", "variables": {"id": "1"}})
        result = _inject_variable(body, "id", "2")
        assert json.loads(result)["variables"]["id"] == "2"

    def test_missing_variable_returns_none(self):
        body = json.dumps({"query": "{ q }", "variables": {"id": "1"}})
        assert _inject_variable(body, "other", "2") is None

    def test_no_variables_key_returns_none(self):
        body = json.dumps({"query": "{ q }"})
        assert _inject_variable(body, "id", "2") is None


# ── integration: agent run ─────────────────────────────────────────────────

class TestGraphqlIdorAgent:
    @pytest.mark.asyncio
    async def test_idor_detected_when_data_differs(self):
        target = _target({"id": "100"})
        baseline_data = {"node": {"id": "100", "name": "Alice", "email": "alice@example.com"}}
        probe_data    = {"node": {"id": "101", "name": "Bob",   "email": "bob@example.com"}}

        responses = [_resp(data=baseline_data), _resp(data=probe_data)]
        call_count = 0

        async def fake_send(client, method, url, headers, body):
            nonlocal call_count
            r = responses[min(call_count, len(responses) - 1)]
            call_count += 1
            return r

        with patch("dast.agents.graphql_agent._send", side_effect=fake_send):
            findings = await GraphqlIdorAgent().run(target, MagicMock())

        assert len(findings) == 1
        assert findings[0].cwe == "CWE-639"
        assert findings[0].parameter == "id"
        # first neighbour tried is 100-1=99; either neighbour confirms the IDOR
        assert any(v in findings[0].payload for v in ("99", "101", "98", "102"))

    @pytest.mark.asyncio
    async def test_no_finding_when_probe_has_errors(self):
        target = _target({"id": "100"})
        baseline_data = {"node": {"id": "100", "name": "Alice"}}

        responses = [
            _resp(data=baseline_data),
            _resp(errors=[{"message": "Not authorized to access this node"}]),
        ]
        call_count = 0

        async def fake_send(client, method, url, headers, body):
            nonlocal call_count
            r = responses[min(call_count, len(responses) - 1)]
            call_count += 1
            return r

        with patch("dast.agents.graphql_agent._send", side_effect=fake_send):
            findings = await GraphqlIdorAgent().run(target, MagicMock())

        assert findings == []

    @pytest.mark.asyncio
    async def test_no_finding_when_data_null(self):
        target = _target({"id": "100"})
        baseline_data = {"node": {"id": "100", "name": "Alice"}}

        responses = [_resp(data=baseline_data), _resp(data={"node": None})]
        call_count = 0

        async def fake_send(client, method, url, headers, body):
            nonlocal call_count
            r = responses[min(call_count, len(responses) - 1)]
            call_count += 1
            return r

        with patch("dast.agents.graphql_agent._send", side_effect=fake_send):
            findings = await GraphqlIdorAgent().run(target, MagicMock())

        assert findings == []

    @pytest.mark.asyncio
    async def test_no_finding_when_data_identical(self):
        target = _target({"id": "100"})
        data = {"node": {"id": "100", "name": "Alice"}}

        async def fake_send(client, method, url, headers, body):
            return _resp(data=data)

        with patch("dast.agents.graphql_agent._send", side_effect=fake_send):
            findings = await GraphqlIdorAgent().run(target, MagicMock())

        assert findings == []

    @pytest.mark.asyncio
    async def test_skips_non_graphql_params(self):
        target = CheckTarget(
            method="POST",
            url="https://example.com/api",
            headers={"content-type": "application/json"},
            body=json.dumps({"name": "Alice", "age": 30}),
            params=[
                {"name": "name", "location": "body", "value": "Alice"},
                {"name": "age",  "location": "body", "value": "30"},
            ],
        )

        async def fake_send(client, method, url, headers, body):
            return _resp(data={"ok": True})

        with patch("dast.agents.graphql_agent._send", side_effect=fake_send):
            findings = await GraphqlIdorAgent().run(target, MagicMock())

        assert findings == []

    @pytest.mark.asyncio
    async def test_skips_when_no_id_params(self):
        target = _target({"query_text": "hello", "limit": "10"})

        async def fake_send(client, method, url, headers, body):
            return _resp(data={"results": []})

        with patch("dast.agents.graphql_agent._send", side_effect=fake_send):
            findings = await GraphqlIdorAgent().run(target, MagicMock())

        assert findings == []

    @pytest.mark.asyncio
    async def test_skips_when_baseline_has_errors(self):
        target = _target({"id": "100"})

        async def fake_send(client, method, url, headers, body):
            return _resp(errors=[{"message": "Endpoint not found"}])

        with patch("dast.agents.graphql_agent._send", side_effect=fake_send):
            findings = await GraphqlIdorAgent().run(target, MagicMock())

        assert findings == []
