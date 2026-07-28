"""
Unit tests for the "AI disabled by default" principle on the always-on
background workers and the GraphQL analyzer.

The regression these lock in: in manual mode (the default, ai_mode=False) NO
automatic LLM call may fire on proxy traffic. AppContextWorker and
ThreatModelWorker run continuously regardless of scan state, and the GraphQL
analyzer's on_entry routes ambiguous findings through the LLM — all three must
stay silent until the user explicitly enables AI mode, and resume once it is on.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import List

import pytest

from dast.discovery.app_context import AppContextWorker
from dast.discovery.threat_model import ThreatModelWorker
import dast.plugins.graphql_analyzer as gql


@dataclass
class _Entry:
    host: str = "app.example.com"
    method: str = "GET"
    source: str = "proxy"
    url: str = "https://app.example.com/api/users"
    path: str = "/api/users"
    response_status: int = 200
    request_body: bytes = b""
    response_body: bytes = b""
    request_headers: dict = field(default_factory=dict)
    response_headers: dict = field(default_factory=dict)


@dataclass
class _Store:
    ai_mode: bool = False
    _entries: List[_Entry] = field(default_factory=list)

    def all_entries(self) -> List[_Entry]:
        return list(self._entries)


def _many_entries(n: int = 40) -> List[_Entry]:
    # Distinct paths so a diverse sample and the entry-count thresholds are met.
    return [_Entry(url=f"https://app.example.com/api/r{i}", path=f"/api/r{i}") for i in range(n)]


# ── AppContextWorker ────────────────────────────────────────────────────────

def test_app_context_worker_no_llm_in_manual_mode(monkeypatch):
    store = _Store(ai_mode=False, _entries=_many_entries())
    worker = AppContextWorker(store, engine=None)

    calls = {"n": 0}

    async def _spy(host, entries):
        calls["n"] += 1

    monkeypatch.setattr(worker, "_analyse", _spy)
    asyncio.run(worker._check_all_hosts())
    assert calls["n"] == 0, "AppContextWorker must not analyse in manual mode"


def test_app_context_worker_analyses_in_ai_mode(monkeypatch):
    store = _Store(ai_mode=True, _entries=_many_entries())
    worker = AppContextWorker(store, engine=None)

    calls = {"n": 0}

    async def _spy(host, entries):
        calls["n"] += 1

    monkeypatch.setattr(worker, "_analyse", _spy)
    asyncio.run(worker._check_all_hosts())
    assert calls["n"] >= 1, "AppContextWorker must resume analysis once AI mode is on"


# ── ThreatModelWorker ───────────────────────────────────────────────────────

def test_threat_model_worker_no_llm_in_manual_mode(monkeypatch):
    store = _Store(ai_mode=False, _entries=_many_entries())
    worker = ThreatModelWorker(store, engine=None)

    calls = {"n": 0}

    async def _spy(host, entries):
        calls["n"] += 1

    monkeypatch.setattr(worker, "_analyse", _spy)
    asyncio.run(worker._check_all_hosts())
    assert calls["n"] == 0, "ThreatModelWorker must not analyse in manual mode"


def test_threat_model_worker_analyses_in_ai_mode(monkeypatch):
    store = _Store(ai_mode=True, _entries=_many_entries())
    worker = ThreatModelWorker(store, engine=None)

    calls = {"n": 0}

    async def _spy(host, entries):
        calls["n"] += 1

    monkeypatch.setattr(worker, "_analyse", _spy)
    asyncio.run(worker._check_all_hosts())
    assert calls["n"] >= 1, "ThreatModelWorker must resume analysis once AI mode is on"


# ── GraphQL analyzer (on_entry) ─────────────────────────────────────────────

@dataclass
class _GqlEntry:
    """Minimal ProxyEntry stand-in that triggers a needs-AI GraphQL finding
    (a mutation with no CSRF header, HTTP 200)."""
    id: str = "e1"
    host: str = "api.example.com"
    method: str = "POST"
    source: str = "proxy"
    url: str = "https://api.example.com/graphql"
    path: str = "/graphql"
    status_code: int = 200
    response_status: int = 200
    request_body: bytes = b'{"query":"mutation { deleteUser(id: 1) { ok } }"}'
    response_body: bytes = b'{"data":{"deleteUser":{"ok":true}}}'
    request_headers: dict = field(default_factory=lambda: {"content-type": "application/json"})
    response_headers: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)


@dataclass
class _GqlStore:
    ai_mode: bool = False
    added: list = field(default_factory=list)

    def all_entries(self):
        return []

    def add_finding(self, entry_id, finding, verdict):
        self.added.append((finding, verdict))


def _run_on_entry(store, monkeypatch):
    entry = _GqlEntry()

    async def _boom(*a, **k):
        raise AssertionError("LLM validation must not run in manual mode")

    monkeypatch.setattr(gql, "_llm_validate_finding", _boom)
    monkeypatch.setattr(gql, "log_event", lambda *a, **k: None)
    plugin = gql.GraphQLAnalyzerPlugin()
    asyncio.run(plugin.on_entry(entry, store))
    return store


def test_graphql_analyzer_no_llm_in_manual_mode(monkeypatch):
    store = _run_on_entry(_GqlStore(ai_mode=False), monkeypatch)
    # Finding still surfaced as plain passive — never dropped, never AI-stamped.
    assert store.added, "needs-AI GraphQL finding must still surface in manual mode"
    finding, _ = store.added[0]
    assert finding["title"] == "GraphQL Mutation Without CSRF Token"
    assert finding["validated_by"] == ["passive"]


def test_graphql_analyzer_calls_llm_in_ai_mode(monkeypatch):
    store = _GqlStore(ai_mode=True)
    entry = _GqlEntry()
    calls = {"n": 0}

    async def _fake_validate(f, *a, **k):
        calls["n"] += 1
        out = dict(f)
        out["confirmed"] = True
        out["validated_by"] = ["passive+ai"]
        return out

    monkeypatch.setattr(gql, "_llm_validate_finding", _fake_validate)
    monkeypatch.setattr(gql, "log_event", lambda *a, **k: None)
    plugin = gql.GraphQLAnalyzerPlugin()
    asyncio.run(plugin.on_entry(entry, store))
    assert calls["n"] == 1, "GraphQL analyzer must route needs-AI findings to the LLM in AI mode"
