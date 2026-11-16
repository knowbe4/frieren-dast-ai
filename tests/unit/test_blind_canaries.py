"""Unit tests for the blind canaries (`_run_blind_canary_probe` + its wiring).

The echo canaries can only fire when a target REPLAYS the payload — blind classes
(SQLi/CMDi time-based, SSRF/XXE OOB) produce no in-band signal, so the canary gate
excluded them from no-LLM dispatch on every endpoint. These tests pin: the time
oracle (scaled SLEEP vs zero-delay control), the tokened OOB probes, and the
end-to-end effect — a blind signal dispatches the agent in no-LLM mode.
"""

from __future__ import annotations

import re
from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import unquote_plus

import pytest

from dast.ai.coordinator import Coordinator, _run_blind_canary_probe
from dast.ai.agent_base import VulnAgent
from dast.scanners.active_checks import CheckTarget


def _resp(text="", elapsed=0.0):
    m = MagicMock()
    m.status_code = 200
    m.text = text
    m.elapsed = timedelta(seconds=elapsed)
    return m


def _target(method="GET", url="https://app.test/search", body=None):
    return CheckTarget(
        method=method, url=url, headers={"content-type": "application/json"},
        body=body, params=[{"name": "q", "location": "query", "value": "abc"}],
    )


class _FakeCollaborator:
    """Real-API fake (host/port + issue_token + sync was_hit). `hit_on_send`
    registers the token when a payload carrying it is sent — simulating the
    target's parser/HTTP client calling back."""

    def __init__(self):
        self.host = "127.0.0.1"
        self.port = 9999
        self._hits = set()
        self._issued = []

    def issue_token(self):
        token = f"dast{900000 + len(self._issued)}"
        self._issued.append(token)
        return token

    def was_hit(self, token):
        return token in self._hits or any(h.startswith(f"{token}/") for h in self._hits)


@pytest.fixture(autouse=True)
def _no_oob_settle_wait(monkeypatch):
    monkeypatch.setattr("asyncio.sleep", AsyncMock(return_value=None))


# ── time-based blind canary (sqli / cmdi) ────────────────────────────────────

def _install_sleeping_send(monkeypatch, *, sleeps: bool):
    """Fake transport: responses to SLEEP-bearing requests are delayed by the
    requested amount (+50ms jitter) when `sleeps`, otherwise constant 50ms."""

    async def fake_send(client, method, url, headers, body, payload=None, timeout=None):
        haystack = unquote_plus(url) + unquote_plus(body or "") + (payload or "")
        m = re.search(r"(?:SLEEP|sleep)\s*\(?(\d+)", haystack)
        requested = int(m.group(1)) if m else 0
        return _resp(elapsed=0.05 + (requested if sleeps else 0))

    monkeypatch.setattr("dast.scanners.active_checks._send", fake_send)


@pytest.mark.asyncio
async def test_sqli_time_canary_fires_on_real_delay(monkeypatch):
    _install_sleeping_send(monkeypatch, sleeps=True)
    hit = await _run_blind_canary_probe(MagicMock(), _target(), _target().params[0], "sqli")
    assert hit is True


@pytest.mark.asyncio
async def test_sqli_time_canary_ignores_constant_latency(monkeypatch):
    """Constantly slow responses (no differential) are NOT a signal."""
    _install_sleeping_send(monkeypatch, sleeps=False)
    hit = await _run_blind_canary_probe(MagicMock(), _target(), _target().params[0], "sqli")
    assert hit is False


@pytest.mark.asyncio
async def test_cmdi_time_canary_fires_on_real_delay(monkeypatch):
    _install_sleeping_send(monkeypatch, sleeps=True)
    hit = await _run_blind_canary_probe(MagicMock(), _target(), _target().params[0], "cmdi")
    assert hit is True


# ── OOB blind canaries (ssrf / xxe) ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_ssrf_oob_canary_confirms_via_token(monkeypatch):
    collaborator = _FakeCollaborator()

    async def fake_send(client, method, url, headers, body, payload=None, timeout=None):
        m = re.search(r"http://127\.0\.0\.1:9999/(dast\d+)", unquote_plus(url) + (body or ""))
        if m:
            collaborator._hits.add(m.group(1))  # the target called back
        return _resp()

    monkeypatch.setattr("dast.scanners.active_checks._send", fake_send)
    hit = await _run_blind_canary_probe(
        MagicMock(), _target(), _target().params[0], "ssrf", collaborator)
    assert hit is True
    assert collaborator._issued  # a token was issued and embedded


@pytest.mark.asyncio
async def test_xxe_oob_canary_wraps_collaborator_in_external_dtd(monkeypatch):
    collaborator = _FakeCollaborator()
    seen_bodies = []

    async def fake_send(client, method, url, headers, body, payload=None, timeout=None):
        seen_bodies.append(unquote_plus(body or "") + unquote_plus(url))
        m = re.search(r"http://127\.0\.0\.1:9999/(dast\d+)", seen_bodies[-1])
        if m:
            collaborator._hits.add(m.group(1))
        return _resp()

    monkeypatch.setattr("dast.scanners.active_checks._send", fake_send)
    hit = await _run_blind_canary_probe(
        MagicMock(), _target(), _target().params[0], "xxe", collaborator)
    assert hit is True
    assert any("<!DOCTYPE" in b and "ENTITY % d SYSTEM" in b for b in seen_bodies)


@pytest.mark.asyncio
async def test_oob_canary_without_collaborator_is_false():
    hit = await _run_blind_canary_probe(
        MagicMock(), _target(), _target().params[0], "ssrf", collaborator=None)
    assert hit is False


@pytest.mark.asyncio
async def test_oob_canary_silent_target_is_no_signal(monkeypatch):
    collaborator = _FakeCollaborator()  # target never calls back

    async def fake_send(client, method, url, headers, body, payload=None, timeout=None):
        return _resp()

    monkeypatch.setattr("dast.scanners.active_checks._send", fake_send)
    hit = await _run_blind_canary_probe(
        MagicMock(), _target(), _target().params[0], "ssrf", collaborator)
    assert hit is False


# ── end-to-end: a blind signal dispatches the agent in no-LLM mode ───────────

class _SqliAgent(VulnAgent):
    name = "Sqli"
    attack_type = "sqli"
    description = ""

    async def run(self, target, client, collaborator=None):
        return []


@pytest.mark.asyncio
async def test_blind_signal_dispatches_sqli_in_no_llm_mode():
    """THE regression this fixes: echo canary misses, blind canary fires → sqli
    runs. Before the blind canaries, sqli was canary-gated out of no-LLM dispatch
    entirely on any endpoint whose target didn't echo SQL errors."""
    target = _target()  # string param -> sqli is a candidate
    with __import__("tests.unit.test_coordinator_run", fromlist=["_Registry"])._Registry():
        Coordinator.register(_SqliAgent)
        with patch("dast.ai.coordinator._run_canary_probe", new=AsyncMock(return_value=False)), \
             patch("dast.ai.coordinator._run_blind_canary_probe", new=AsyncMock(return_value=True)), \
             patch("dast.scanners.active_checks._send", new=AsyncMock(return_value=_resp())):
            out = await Coordinator.run(target, MagicMock(), use_llm_planner=False,
                                        budget_seconds=5.0, return_outcome=True)

    assert "sqli" in out.agents_ran


@pytest.mark.asyncio
async def test_no_signal_at_all_keeps_sqli_gated_out():
    target = _target()
    with __import__("tests.unit.test_coordinator_run", fromlist=["_Registry"])._Registry():
        Coordinator.register(_SqliAgent)
        with patch("dast.ai.coordinator._run_canary_probe", new=AsyncMock(return_value=False)), \
             patch("dast.ai.coordinator._run_blind_canary_probe", new=AsyncMock(return_value=False)), \
             patch("dast.scanners.active_checks._send", new=AsyncMock(return_value=_resp())):
            out = await Coordinator.run(target, MagicMock(), use_llm_planner=False,
                                        budget_seconds=5.0, return_outcome=True)

    assert "sqli" not in out.agents_ran
