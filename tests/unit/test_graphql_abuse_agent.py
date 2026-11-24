"""GraphQL abuse agent tests (4-A).

Fake transport responds by the SHAPE of the query body (introspection ladder,
alias count, batch array, GET query-string, depth bomb) — the agent must map
each shape to the right finding with the right severity/confirmation.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import dast.agents  # noqa: F401 — populates the Coordinator registry
import pytest

from dast.ai.coordinator import Coordinator
from dast.scanners.active_checks import CheckTarget


def _target(url="https://example.com/graphql", body='{"query":"query { user { name } }"}'):
    return CheckTarget(
        method="POST", url=url,
        headers={"content-type": "application/json"},
        body=body, params=[{"name": "query", "location": "body_graphql", "value": "user"}],
    )


def _resp(payload, url="https://example.com/graphql"):
    text = payload if isinstance(payload, str) else json.dumps(payload)
    return SimpleNamespace(
        status_code=200, text=text, headers={}, content=text.encode(),
        request=SimpleNamespace(method="POST", url=url, headers={}, content=text.encode()),
    )


def _install(monkeypatch, responder):
    import dast.agents.graphql_abuse_agent as mod

    calls: list = []

    async def fake_send(client, method, url, headers, body, **kw):
        calls.append({"url": url, "method": method, "body": body or ""})
        return responder(body or "", url, method, len(calls))

    monkeypatch.setattr(mod, "_send", fake_send)
    return calls


def _default_responder(body, url, method, n):
    if 'fields {' in body:  # full introspection
        return _resp({"data": {"__schema": {"queryType": {"name": "Query"},
                                            "types": [{"kind": "OBJECT", "name": "User"}]}}})
    if "__schema" in body:  # reduced/minimal — server blocks these but serves errors
        return _resp({"errors": [{"message": "introspection disabled"}]})
    if "nonexistentfieldzzz" in body:
        return _resp({"errors": [{"message": 'Cannot query field "nonexistentfieldzzz". Did you mean "user"?'}, ]})
    if "a0:" in body:  # alias overload answered with all aliases
        return _resp({"data": {f"a{i}": "Query" for i in range(60)}})
    if body.startswith('[{"query"'):  # batch accepted
        return _resp([{"data": {"__typename": "Query"}},
                      {"data": {"__typename": "Query"}}])
    if "user { user" in body or " {  { " in body or "depth" in body:
        return _resp({"errors": [{"message": "query exceeds maximum depth of 10"}]})
    if url.startswith("https://example.com/graphql?query="):
        return _resp({"data": {"__typename": "Query"}})
    return _resp({"data": {"__typename": "Query"}})


@pytest.fixture(autouse=True)
def _fresh_registry():
    from dast.ai import provider_health

    provider_health.reset()
    yield
    provider_health.reset()


@pytest.mark.asyncio
async def test_full_introspection_enabled(monkeypatch):
    from dast.agents.graphql_abuse_agent import GraphqlAbuseAgent

    _install(monkeypatch, _default_responder)
    findings = await GraphqlAbuseAgent().run(_target(), MagicMock(), None)

    intros = [f for f in findings if "Introspection" in f.title]
    assert intros and intros[0].severity == "medium"
    assert intros[0].confirmed is True


@pytest.mark.asyncio
async def test_minimal_introspection_still_leaks(monkeypatch):
    from dast.agents.graphql_abuse_agent import GraphqlAbuseAgent

    def responder(body, url, method, n):
        if 'fields {' in body:
            return _resp({"errors": [{"message": "introspection disabled"}]})
        if "__schema" in body:  # reduced AND minimal leak the type names
            return _resp({"data": {"__schema": {"types": [{"name": "User"}]}}})
        if "nonexistentfieldzzz" in body:
            return _resp({"errors": [{"message": 'Did you mean "user"?'}, ]})
        return _default_responder(body, url, method, n)

    _install(monkeypatch, responder)
    findings = await GraphqlAbuseAgent().run(_target(), MagicMock(), None)

    intros = [f for f in findings if "Introspection" in f.title]
    assert intros and intros[0].severity == "low"


@pytest.mark.asyncio
async def test_field_suggestion_disclosure(monkeypatch):
    from dast.agents.graphql_abuse_agent import GraphqlAbuseAgent

    _install(monkeypatch, _default_responder)
    findings = await GraphqlAbuseAgent().run(_target(), MagicMock(), None)

    sug = [f for f in findings if "Field-Suggestion" in f.title]
    assert sug and 'user' in sug[0].evidence and 'Did you mean' in sug[0].evidence


@pytest.mark.asyncio
async def test_alias_overload_and_batching(monkeypatch):
    from dast.agents.graphql_abuse_agent import GraphqlAbuseAgent

    _install(monkeypatch, _default_responder)
    findings = await GraphqlAbuseAgent().run(_target(), MagicMock(), None)

    assert any("Alias Overload" in f.title for f in findings)
    assert any("Batch" in f.title for f in findings)


@pytest.mark.asyncio
async def test_get_query_is_mechanism_finding_unconfirmed(monkeypatch):
    from dast.agents.graphql_abuse_agent import GraphqlAbuseAgent

    _install(monkeypatch, _default_responder)
    findings = await GraphqlAbuseAgent().run(_target(), MagicMock(), None)

    get_f = [f for f in findings if "via GET" in f.title]
    assert get_f and get_f[0].confirmed is False


@pytest.mark.asyncio
async def test_non_graphql_target_runs_nothing(monkeypatch):
    from dast.agents.graphql_abuse_agent import GraphqlAbuseAgent

    calls = _install(monkeypatch, _default_responder)
    plain = CheckTarget(method="GET", url="https://example.com/items",
                        headers={}, body=None, params=[])
    findings = await GraphqlAbuseAgent().run(plain, MagicMock(), None)
    assert findings == []
    assert calls == []  # gate skipped everything


def test_registered_and_dispatch_sibling():
    assert "graphql_abuse" in Coordinator._registry
    # the IDOR sibling must still exist — the two agents OWN complementary halves
    assert "graphql_idor" in Coordinator._registry
