"""Unit tests for IDOR — deterministic scanner and AI agent."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from dast.scanners.active_checks import (
    CheckTarget,
    _idor_confirmed,
    _idor_inject_path,
    _idor_neighbour,
    check_idor,
)


# ── helpers ────────────────────────────────────────────────────────────────

def _target(
    url: str = "https://api.example.com/users/123",
    method: str = "GET",
    params: list = None,
    body: str = None,
    headers: dict = None,
) -> CheckTarget:
    return CheckTarget(
        method=method,
        url=url,
        headers=headers or {"content-type": "application/json"},
        body=body,
        params=params or [],
    )


def _resp(status: int = 200, text: str = '{"id":1,"name":"Alice"}') -> MagicMock:
    m = MagicMock()
    m.status_code = status
    m.text = text
    return m


# ── unit: helpers ──────────────────────────────────────────────────────────

class TestIdorNeighbour:
    def test_numeric(self):
        assert _idor_neighbour("123") == "124"

    def test_numeric_one(self):
        assert _idor_neighbour("1") == "2"

    def test_uuid(self):
        original = "550e8400-e29b-41d4-a716-446655440000"
        result = _idor_neighbour(original)
        assert result is not None
        assert result != original
        assert len(result) == 36

    def test_non_id_returns_none(self):
        assert _idor_neighbour("alice") is None

    def test_empty_returns_none(self):
        assert _idor_neighbour("") is None


class TestIdorInjectPath:
    def test_numeric_path(self):
        result = _idor_inject_path("https://api.example.com/users/123/profile", "123", "124")
        assert "/users/124/profile" in result

    def test_trailing_slash(self):
        result = _idor_inject_path("https://api.example.com/orders/99/", "99", "100")
        assert "/orders/100/" in result

    def test_no_match_unchanged(self):
        url = "https://api.example.com/users/other"
        result = _idor_inject_path(url, "999", "1000")
        assert result == url


class TestIdorConfirmed:
    def test_confirmed_json_diff(self):
        baseline = '{"id":1,"name":"Alice","email":"a@example.com"}'
        probe    = '{"id":2,"name":"Bob","email":"b@example.com"}'
        assert _idor_confirmed(200, baseline, 200, probe)

    def test_not_confirmed_identical(self):
        body = '{"id":1,"name":"Alice"}'
        assert not _idor_confirmed(200, body, 200, body)

    def test_not_confirmed_401(self):
        baseline = '{"id":1,"name":"Alice"}'
        probe    = '{"error":"Unauthorized"}'
        assert not _idor_confirmed(200, baseline, 401, probe)

    def test_not_confirmed_403(self):
        baseline = '{"id":1,"name":"Alice"}'
        probe    = '{"error":"Forbidden"}'
        assert not _idor_confirmed(200, baseline, 403, probe)

    def test_not_confirmed_404(self):
        assert not _idor_confirmed(200, '{"id":1}', 404, 'Not found')

    def test_not_confirmed_500(self):
        assert not _idor_confirmed(200, '{"id":1}', 500, 'Internal error')

    def test_not_confirmed_empty_probe(self):
        assert not _idor_confirmed(200, '{"id":1}', 200, '')

    def test_not_confirmed_graphql_errors(self):
        baseline = '{"data":{"user":{"id":"1","name":"Alice"}}}'
        probe    = '{"errors":[{"message":"Not authorized"}]}'
        assert not _idor_confirmed(200, baseline, 200, probe)


# ── integration: check_idor scanner ───────────────────────────────────────

class TestCheckIdorScanner:
    @pytest.mark.asyncio
    async def test_query_param_idor(self):
        target = _target(
            url="https://api.example.com/profile?userId=10",
            params=[{"name": "userId", "location": "query", "value": "10"}],
        )
        baseline = _resp(200, '{"id":10,"name":"Alice","email":"a@x.com"}')
        probe    = _resp(200, '{"id":11,"name":"Bob","email":"b@x.com"}')

        responses = iter([baseline, probe])
        async def fake_send(client, method, url, headers, body):
            return next(responses)

        with patch("dast.scanners.active_checks._send", side_effect=fake_send):
            findings = await check_idor(target, MagicMock())

        assert len(findings) == 1
        assert findings[0].cwe == "CWE-639"
        assert findings[0].parameter == "userId"

    @pytest.mark.asyncio
    async def test_post_json_body_idor(self):
        body = json.dumps({"accountId": "42", "action": "view"})
        target = _target(
            url="https://api.example.com/account/data",
            method="POST",
            body=body,
            params=[
                {"name": "accountId", "location": "body", "value": "42"},
                {"name": "action",    "location": "body", "value": "view"},
            ],
        )
        baseline = _resp(200, '{"accountId":42,"balance":1000,"owner":"Alice"}')
        probe    = _resp(200, '{"accountId":43,"balance":2500,"owner":"Bob"}')

        responses = iter([baseline, probe])
        async def fake_send(client, method, url, headers, body_sent):
            return next(responses)

        with patch("dast.scanners.active_checks._send", side_effect=fake_send):
            findings = await check_idor(target, MagicMock())

        assert len(findings) == 1
        assert "accountId" in findings[0].parameter

    @pytest.mark.asyncio
    async def test_path_id_idor(self):
        target = _target(url="https://api.example.com/orders/500")
        baseline = _resp(200, '{"orderId":500,"total":99,"customer":"Alice"}')
        probe    = _resp(200, '{"orderId":501,"total":150,"customer":"Bob"}')

        responses = iter([baseline, probe])
        async def fake_send(client, method, url, headers, body):
            return next(responses)

        with patch("dast.scanners.active_checks._send", side_effect=fake_send):
            findings = await check_idor(target, MagicMock())

        assert len(findings) == 1
        assert "path:" in findings[0].parameter

    @pytest.mark.asyncio
    async def test_no_finding_when_403(self):
        target = _target(
            url="https://api.example.com/profile?userId=10",
            params=[{"name": "userId", "location": "query", "value": "10"}],
        )
        baseline = _resp(200, '{"id":10,"name":"Alice"}')
        probe    = _resp(403, '{"error":"Forbidden"}')

        responses = iter([baseline, probe])
        async def fake_send(client, method, url, headers, body):
            return next(responses)

        with patch("dast.scanners.active_checks._send", side_effect=fake_send):
            findings = await check_idor(target, MagicMock())

        assert findings == []

    @pytest.mark.asyncio
    async def test_no_finding_when_data_identical(self):
        target = _target(
            url="https://api.example.com/profile?userId=10",
            params=[{"name": "userId", "location": "query", "value": "10"}],
        )
        body = '{"id":10,"name":"Alice"}'
        baseline = _resp(200, body)
        probe    = _resp(200, body)

        responses = iter([baseline, probe])
        async def fake_send(client, method, url, headers, body_sent):
            return next(responses)

        with patch("dast.scanners.active_checks._send", side_effect=fake_send):
            findings = await check_idor(target, MagicMock())

        assert findings == []

    @pytest.mark.asyncio
    async def test_graphql_variables_idor(self):
        body = json.dumps({"query": "query { user(id: $id) { name } }", "variables": {"id": "10"}})
        target = _target(
            url="https://api.example.com/graphql",
            method="POST",
            body=body,
            params=[{"name": "id", "location": "body_graphql", "value": "10"}],
        )
        baseline = _resp(200, '{"data":{"user":{"id":"10","name":"Alice"}}}')
        probe    = _resp(200, '{"data":{"user":{"id":"11","name":"Bob"}}}')

        responses = iter([baseline, probe])
        async def fake_send(client, method, url, headers, body_sent):
            return next(responses)

        with patch("dast.scanners.active_checks._send", side_effect=fake_send):
            findings = await check_idor(target, MagicMock())

        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_graphql_errors_not_finding(self):
        body = json.dumps({"query": "query { user(id: $id) { name } }", "variables": {"id": "10"}})
        target = _target(
            url="https://api.example.com/graphql",
            method="POST",
            body=body,
            params=[{"name": "id", "location": "body_graphql", "value": "10"}],
        )
        baseline = _resp(200, '{"data":{"user":{"id":"10","name":"Alice"}}}')
        probe    = _resp(200, '{"errors":[{"message":"Not authorized to access user 11"}]}')

        responses = iter([baseline, probe])
        async def fake_send(client, method, url, headers, body_sent):
            return next(responses)

        with patch("dast.scanners.active_checks._send", side_effect=fake_send):
            findings = await check_idor(target, MagicMock())

        assert findings == []

    @pytest.mark.asyncio
    async def test_skips_non_id_params(self):
        target = _target(
            url="https://api.example.com/search?q=hello&page=2",
            params=[
                {"name": "q",    "location": "query", "value": "hello"},
                {"name": "page", "location": "query", "value": "2"},
            ],
        )
        async def fake_send(client, method, url, headers, body):
            return _resp(200, '{"results":[]}')

        with patch("dast.scanners.active_checks._send", side_effect=fake_send):
            findings = await check_idor(target, MagicMock())

        assert findings == []
