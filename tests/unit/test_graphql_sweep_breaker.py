"""Tests for the graphql_sweep accumulating-failure breaker: a schema whose
operations are nearly all auth-blocked must stop the sweep early rather than firing
every operation (the 403-flood the operator caught)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import dast.tools.graphql_sweep_tools as sweep
from dast.tools.graphql_sweep_tools import _graphql_sweep

URL = "https://app.example.com/graphql"


def _store(num_queries: int):
    return SimpleNamespace(
        graphql_schemas={URL: {
            "introspected": True,
            "queries": {f"q{i}": {"args": [], "return_type": ""} for i in range(num_queries)},
            "mutations": {},
        }},
        graphql_tested_ops={},
    )


def _ctx(store):
    return SimpleNamespace(store=store, is_in_scope=lambda url: True)


@pytest.mark.asyncio
async def test_sweep_stops_early_on_uniform_auth_block(monkeypatch):
    # One op succeeds so the all-5-canary abort does NOT fire; the rest are blocked,
    # so the accumulating breaker must stop the sweep well before all 100 ops.
    async def _mostly_blocked(ctx, url, schema, kind, field_name, semaphore):
        return {"classification": "ok" if field_name == "q0" else "auth_blocked"}

    monkeypatch.setattr(sweep, "_probe_operation", _mostly_blocked)
    result = await _graphql_sweep(_ctx(_store(100)), {"url": URL, "kinds": ["query"]})

    assert result["stopped_early"] is True
    assert result["operations_tested_now"] < 100     # did NOT fire them all
    assert "auth-blocked" in result["note"]


@pytest.mark.asyncio
async def test_sweep_completes_when_operations_succeed(monkeypatch):
    async def _all_ok(*a, **k):
        return {"classification": "ok"}

    monkeypatch.setattr(sweep, "_probe_operation", _all_ok)
    result = await _graphql_sweep(_ctx(_store(30)), {"url": URL, "kinds": ["query"]})

    assert result.get("stopped_early") is not True
    assert result["operations_tested_now"] == 30
