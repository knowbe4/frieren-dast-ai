"""Unit tests for the chain inventor (5-B-4).

No network, no real LLM: ``invent_candidates`` is monkeypatched (the LLM pass
returns a canned candidate spec), ``ChainEngine`` is replaced by a fake whose
verdict the test controls, and the ToolContext is a lightweight double with a
fake store. Focus: the mandatory-impact gate, the confirmed→finding and
refuted→ruled_out bookkeeping, the >=2-findings gate, and the tool surface.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from dast.ai import chain_inventor
from dast.ai.chain_inventor import (
    chain_has_impact_assertion,
    run_inventor,
)
from dast.chains.models import Chain


# ── fixtures ─────────────────────────────────────────────────────────────────

def _finding_row(url, title="Finding", severity="high", attack_type="idor"):
    return {"url": url, "host": "shop.test", "path": "/api/x", "method": "GET",
            "title": title, "severity": severity, "attack_type": attack_type,
            "dismissed": False}


class _FakeEntry:
    def __init__(self, findings):
        self._findings = findings

    def to_dict(self):
        return {"id": "e1", "url": "https://shop.test/api/x", "host": "shop.test",
                "path": "/api/x", "method": "GET", "findings": self._findings}


class _FakeStore:
    def __init__(self, entries):
        self._entries = entries
        self.recorded = []

    def all_entries(self):
        return self._entries

    def record_manual_finding(self, finding, url, method="GET"):
        self.recorded.append((finding, url, method))
        return "e2"


def _ctx(entries=None, in_scope=True):
    ctx = SimpleNamespace(
        store=_FakeStore(entries or []),
        is_in_scope=lambda url: in_scope,
        proxy_url="http://127.0.0.1:8080",
        dashboard_base_url="http://127.0.0.1:8088",
    )
    return ctx


def _candidate(name="ssrf-metadata", vuln_type="attack_chain",
               impact_on_last=True):
    """A 2-step chain spec: bind a token, then read an admin endpoint."""
    assertions = [{"kind": "body_contains", "needle": "secret-data"}] \
        if impact_on_last else [{"kind": "status_eq", "value": 200}]
    return {
        "name": name,
        "vuln_type": vuln_type,
        "description": "chain proof",
        "rationale": "idor + info leak compound",
        "steps": [
            {"name": "bind", "method": "GET",
             "url": "https://shop.test/api/session",
             "extract": [{"kind": "json", "var": "tok", "expr": "token"}]},
            {"name": "impact", "method": "GET",
             "url": "https://shop.test/admin/export?t={{tok}}",
             "assertions": assertions},
        ],
    }


class _FakeResult:
    def __init__(self, status, evidence="proof", name="c", vuln_type="attack_chain"):
        self.status = status
        self.evidence = evidence
        self.name = name
        self.vuln_type = vuln_type


@pytest.fixture(autouse=True)
def _isolate_ledger():
    """Tests must not pollute (or depend on) the global coverage ledger."""
    from dast.coverage import ledger
    saved_entries = dict(ledger._entries)
    saved_history = {k: list(v) for k, v in ledger._history.items()}
    ledger._entries.clear()
    ledger._history.clear()
    yield
    ledger._entries.clear()
    ledger._entries.update(saved_entries)
    ledger._history.clear()
    ledger._history.update(saved_history)


# ── the mandatory-impact gate ────────────────────────────────────────────────

def test_impact_gate_accepts_final_step_assertion():
    chain = Chain.from_dict(_candidate())
    assert chain_has_impact_assertion(chain) is True


def test_impact_gate_accepts_step_before_control():
    spec = _candidate()
    spec["steps"].append({
        "name": "control", "method": "GET", "url": "https://shop.test/admin/export",
        "send_cookies": [],
        "assertions": [{"kind": "status_in", "values": [401, 403]}],
    })
    chain = Chain.from_dict(spec)
    assert chain_has_impact_assertion(chain) is True


def test_impact_gate_refuses_status_only():
    chain = Chain.from_dict(_candidate(impact_on_last=False))
    assert chain_has_impact_assertion(chain) is False


# ── run_inventor mechanics ───────────────────────────────────────────────────

def _patch_inventor(monkeypatch, candidates, verdict):
    monkeypatch.setattr(chain_inventor, "invent_candidates",
                        lambda findings, endpoints, host: candidates)

    class _FakeEngine:
        def __init__(self, sender, is_in_scope, initial_cookies=None):
            pass

        async def run(self, chain):
            return _FakeResult(verdict, name=chain.name, vuln_type=chain.vuln_type)

    import dast.chains.engine as engine_mod
    monkeypatch.setattr(engine_mod, "ChainEngine", _FakeEngine)


def test_confirmed_chain_becomes_recorded_finding(monkeypatch):
    entries = [_FakeEntry([
        {"title": "SSRF", "severity": "high", "attack_type": "ssrf"},
        {"title": "IDOR", "severity": "high", "attack_type": "idor"},
    ])]
    ctx = _ctx(entries=entries)
    _patch_inventor(monkeypatch, [_candidate()], "confirmed")

    out = asyncio.run(run_inventor(ctx))

    assert out["ok"] is True
    assert out["host"] == "shop.test"
    assert len(out["confirmed"]) == 1
    assert out["confirmed"][0]["recorded"] is True
    finding, url, _method = ctx.store.recorded[0]
    assert finding["attack_type"] == "chain"
    assert "Attack Chain Confirmed" in finding["title"]
    assert url.startswith("https://shop.test/")
    assert out["ruled_out"] == []


def test_refuted_chain_is_ruled_out_in_ledger(monkeypatch):
    entries = [_FakeEntry([
        {"title": "SSRF", "severity": "high", "attack_type": "ssrf"},
        {"title": "IDOR", "severity": "high", "attack_type": "idor"},
    ])]
    ctx = _ctx(entries=entries)
    _patch_inventor(monkeypatch, [_candidate(name="dead-chain")], "refuted")

    out = asyncio.run(run_inventor(ctx))

    assert out["ok"] is True
    assert out["confirmed"] == []
    assert len(out["ruled_out"]) == 1
    assert out["ruled_out"][0]["status"] == "refuted"

    from dast.coverage import ledger
    areas = [e.risk_area for e in ledger._entries.values()]
    assert "chain" in areas
    outcomes = [e.outcome for e in ledger._entries.values()]
    assert "ruled_out" in outcomes


def test_out_of_scope_candidate_blocked(monkeypatch):
    entries = [_FakeEntry([
        {"title": "A", "severity": "high", "attack_type": "ssrf"},
        {"title": "B", "severity": "high", "attack_type": "idor"},
    ])]
    ctx = _ctx(entries=entries, in_scope=False)
    _patch_inventor(monkeypatch, [_candidate()], "confirmed")

    out = asyncio.run(run_inventor(ctx))
    assert out["confirmed"] == []
    assert out["ruled_out"][0]["status"] == "blocked"


def test_needs_two_findings(monkeypatch):
    entries = [_FakeEntry([{"title": "Only one", "severity": "low",
                            "attack_type": "info"}])]
    ctx = _ctx(entries=entries)
    monkeypatch.setattr(chain_inventor, "invent_candidates",
                        lambda *a, **k: [_candidate()])

    out = asyncio.run(run_inventor(ctx))
    assert out["ok"] is False
    assert ">=2 findings" in out["error"]


def test_no_candidates_is_a_clean_noop(monkeypatch):
    entries = [_FakeEntry([
        {"title": "A", "severity": "high", "attack_type": "ssrf"},
        {"title": "B", "severity": "high", "attack_type": "idor"},
    ])]
    ctx = _ctx(entries=entries)
    monkeypatch.setattr(chain_inventor, "invent_candidates",
                        lambda *a, **k: [])

    out = asyncio.run(run_inventor(ctx))
    assert out == {"ok": True, "host": "shop.test", "tried": 0,
                   "confirmed": [], "ruled_out": []}


# ── tool surface ─────────────────────────────────────────────────────────────

def test_invent_chain_tool_registered():
    import dast.tools  # noqa: F401 — register everything
    from dast.tools.base import get_tool
    tool = get_tool("invent_chain")
    assert tool is not None
    assert tool.handler is not None
    assert "findings" in tool.description
