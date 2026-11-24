"""record_coverage copilot tool tests (4-E): the 3-H follow-up — the LLM-facing
entry into the coverage ledger, with the same validation contract as the
machine-observed writer (evidence required for no_issue_found, reason required
for ruled_out/not_applicable, outcome enum, one-line normalized fields)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from dast.coverage import ledger
from dast.tools.coverage_tools import _record_coverage


@pytest.fixture(autouse=True)
def _isolate():
    ledger.reset()
    yield
    ledger.reset()


def _ctx():
    return SimpleNamespace()


@pytest.mark.asyncio
async def test_records_no_issue_found_with_evidence():
    r = await _record_coverage(_ctx(), {
        "url": "https://app.example.com/api/users",
        "risk_area": "sqli",
        "outcome": "no_issue_found",
        "evidence": "8 probes, no signal",
    })
    assert r["ok"] is True
    assert r["recorded"]["outcome"] == "no_issue_found"
    assert r["recorded"]["host"] == "app.example.com"


@pytest.mark.asyncio
async def test_no_issue_found_without_evidence_is_rejected():
    r = await _record_coverage(_ctx(), {
        "url": "https://app.example.com/api/users",
        "risk_area": "sqli",
        "outcome": "no_issue_found",
    })
    assert r["ok"] is False and "evidence" in r["error"]


@pytest.mark.asyncio
async def test_needs_follow_up_requires_reason():
    r = await _record_coverage(_ctx(), {
        "url": "https://app.example.com/api/users",
        "risk_area": "sqli",
        "outcome": "needs_follow_up",
    })
    assert r["ok"] is False and "reason" in r["error"]


@pytest.mark.asyncio
async def test_invalid_outcome_rejected():
    r = await _record_coverage(_ctx(), {
        "url": "https://app.example.com/api/users",
        "risk_area": "sqli",
        "outcome": "clean",
    })
    assert r["ok"] is False and "outcome" in r["error"]


@pytest.mark.asyncio
async def test_reported_records_the_finding_as_evidence():
    r = await _record_coverage(_ctx(), {
        "url": "https://app.example.com/api/users",
        "risk_area": "jwt",
        "outcome": "reported",
        "evidence": "alg:none accepted (critical)",
    })
    assert r["recorded"]["outcome"] == "reported"


def test_tool_registered_for_the_copilot():
    from dast.tools.base import _REGISTRY

    assert "record_coverage" in _REGISTRY
