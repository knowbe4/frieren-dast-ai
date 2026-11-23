"""CORS agent tests (4-A): dast/agents/cors_agent.py.

The agent sends ONE crafted-Origin probe per endpoint (cost discipline) and
only reports when the attacker origin is REFLECTED with credentials —
reflections without credentials and same-site origins are never findings.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from dast.ai.coordinator import Coordinator
from dast.scanners.active_checks import CheckTarget


def _target(url="https://app.example.com/api/user", method="GET"):
    return CheckTarget(
        method=method, url=url,
        headers={"authorization": "Bearer x", "cookie": "sid=1"},
        body=None, params=[],
    )


def _resp(acao=None, acac=None, body="{}"):
    headers = {}
    if acao is not None:
        headers["access-control-allow-origin"] = acao
    if acac is not None:
        headers["access-control-allow-credentials"] = acac

    return SimpleNamespace(
        status_code=200, text=body, headers=headers, content=body.encode())


@pytest.fixture(autouse=True)
def _no_disk_and_fresh_registry():
    from dast.ai import provider_health

    provider_health.reset()
    yield
    provider_health.reset()


def _install(monkeypatch, resp):
    import dast.agents.cors_agent as mod

    calls = []

    async def fake_send(client, method, url, headers, body, **kw):
        calls.append({"url": url, "headers": dict(headers)})
        resp.request = SimpleNamespace(method=method, url=url, headers=dict(headers))
        return resp

    monkeypatch.setattr(mod, "_send", fake_send)
    return calls


@pytest.mark.asyncio
async def test_reflected_origin_with_credentials_is_critical(monkeypatch):
    from dast.agents.cors_agent import CorsAgent

    calls = _install(monkeypatch, _resp(acao="https://evil-attacker.test", acac="true"))
    findings = await CorsAgent().run(_target(), MagicMock(), None)

    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].cwe == "CWE-942"
    assert findings[0].confirmed is True
    # exactly one probe (cost discipline), carrying the crafted origin
    assert len(calls) == 1
    assert calls[0]["headers"]["origin"] == "https://evil-attacker.test"
    # internal scanner headers are not forwarded
    assert "x-dast-source" not in calls[0]["headers"]


@pytest.mark.asyncio
async def test_reflection_without_credentials_is_not_a_finding(monkeypatch):
    from dast.agents.cors_agent import CorsAgent

    _install(monkeypatch, _resp(acao="https://evil-attacker.test", acac="false"))
    findings = await CorsAgent().run(_target(), MagicMock(), None)
    assert findings == []


@pytest.mark.asyncio
async def test_no_reflection_returns_immediately(monkeypatch):
    from dast.agents.cors_agent import CorsAgent

    calls = _install(monkeypatch, _resp(acao="https://app.example.com", acac="true"))
    findings = await CorsAgent().run(_target(), MagicMock(), None)
    assert findings == []
    assert len(calls) == 1  # short-circuit: no extra probes


def test_cors_registered_and_dispatchable():
    assert "cors" in Coordinator._registry
    assert Coordinator._registry["cors"].name == "CORS Agent"
