"""HPP agent + rate-limit trust agent tests (4-A).

HPP reports only on a REAL differential (canary reflected, or materially
different response vs the single-value baseline). Trust findings are the
MECHANISM (XFF reflection / path normalization gap) — never a demonstrated
bypass under load.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import dast.agents  # noqa: F401 — populates the Coordinator registry
from dast.ai.coordinator import Coordinator
from dast.scanners.active_checks import CheckTarget


def _target(url="https://example.com/api/profile", method="GET",
            params=None, body=None):
    return CheckTarget(
        method=method, url=url,
        headers={"cookie": "sid=1"},
        body=body, params=params or [],
    )


def _resp(status=200, body="ok", url="https://example.com/api/profile"):
    return SimpleNamespace(
        status_code=status, text=body, headers={}, content=body.encode(),
        request=SimpleNamespace(method="GET", url=url, headers={}, content=b""),
    )


def _patch_send(monkeypatch, module_name, responder):
    """Replace the module's _send with ``responder(url, call_number)`` and
    return the calls list for assertions."""
    import importlib

    mod = importlib.import_module(module_name)
    calls: list = []

    async def fake_send(client, method, url, headers, body, **kw):
        calls.append({"url": url, "headers": dict(headers), "method": method})
        return responder(url, len(calls))

    monkeypatch.setattr(mod, "_send", fake_send)
    return calls


@pytest.fixture(autouse=True)
def _fresh_registry():
    from dast.ai import provider_health

    provider_health.reset()
    yield
    provider_health.reset()


# ── HPP agent ────────────────────────────────────────────────────────────────

class TestHppAgent:
    def test_registered(self):
        assert "hpp" in Coordinator._registry

    @pytest.mark.asyncio
    async def test_canary_reflection_confirms(self, monkeypatch):
        from dast.agents.hpp_agent import HppAgent, _CANARY

        def responder(url, n):
            if _CANARY in url:
                return _resp(200, f'{{"role": "{_CANARY}"}}')  # escalated value reflected
            return _resp(200, '{"role": "user"}')

        calls = _patch_send(monkeypatch, "dast.agents.hpp_agent", responder)
        target = _target(params=[{"name": "role", "location": "query", "value": "user"}])
        findings = await HppAgent().run(target, MagicMock(), None)

        assert len(findings) == 1
        assert findings[0].cwe == "CWE-436"
        assert findings[0].confirmed is True
        # both occurrences reached the server
        assert any(c["url"].count("role=") == 2 for c in calls)

    @pytest.mark.asyncio
    async def test_status_differential_only_is_unconfirmed(self, monkeypatch):
        from dast.agents.hpp_agent import HppAgent, _CANARY

        def responder(url, n):
            if _CANARY in url:
                return _resp(400, "bad request")  # different status, no reflection
            return _resp(200, '{"role": "user"}')

        _patch_send(monkeypatch, "dast.agents.hpp_agent", responder)
        target = _target(params=[{"name": "role", "location": "query", "value": "user"}])
        findings = await HppAgent().run(target, MagicMock(), None)

        assert len(findings) == 1
        assert findings[0].confirmed is False

    @pytest.mark.asyncio
    async def test_no_differential_no_finding(self, monkeypatch):
        from dast.agents.hpp_agent import HppAgent

        _patch_send(monkeypatch, "dast.agents.hpp_agent",
                    lambda url, n: _resp(200, '{"role": "user"}'))
        target = _target(params=[{"name": "role", "location": "query", "value": "user"}])
        findings = await HppAgent().run(target, MagicMock(), None)
        assert findings == []

    @pytest.mark.asyncio
    async def test_unrelated_params_are_not_probed(self, monkeypatch):
        from dast.agents.hpp_agent import HppAgent

        calls = _patch_send(monkeypatch, "dast.agents.hpp_agent",
                            lambda url, n: _resp(200, "ok"))
        target = _target(params=[{"name": "theme", "location": "query", "value": "dark"}])
        findings = await HppAgent().run(target, MagicMock(), None)
        assert findings == []
        assert calls == []  # the name gate skipped everything — no baseline either


# ── rate-limit trust agent ───────────────────────────────────────────────────

class TestRateLimitTrustAgent:
    def test_registered(self):
        assert "rate_limit_trust" in Coordinator._registry

    @pytest.mark.asyncio
    async def test_xff_reflection_is_a_low_trust_finding(self, monkeypatch):
        from dast.agents.rate_limit_trust_agent import RateLimitTrustAgent, _SPOOF_IP

        def responder(url, n):
            if n == 1:  # XFF probe
                return _resp(200, f'{{"client_ip": "{_SPOOF_IP}"}}')  # reflected
            return _resp(200, "ok")

        _patch_send(monkeypatch, "dast.agents.rate_limit_trust_agent", responder)
        findings = await RateLimitTrustAgent().run(_target(), MagicMock(), None)

        assert len(findings) == 1
        assert findings[0].cwe == "CWE-345"
        assert findings[0].severity == "low"
        assert findings[0].confirmed is True

    @pytest.mark.asyncio
    async def test_path_variant_differential_is_reported_unconfirmed(self, monkeypatch):
        from dast.agents.rate_limit_trust_agent import RateLimitTrustAgent

        def responder(url, n):
            if n == 1:  # XFF probe — no reflection
                return _resp(200, "ok")
            if url.endswith("/API/PROFILE"):
                return _resp(404, "not found")  # variant answers differently
            return _resp(200, "ok")

        _patch_send(monkeypatch, "dast.agents.rate_limit_trust_agent", responder)
        findings = await RateLimitTrustAgent().run(_target(), MagicMock(), None)

        assert len(findings) == 1
        assert findings[0].cwe == "CWE-436"
        assert findings[0].confirmed is False

    @pytest.mark.asyncio
    async def test_no_signal_no_finding(self, monkeypatch):
        from dast.agents.rate_limit_trust_agent import RateLimitTrustAgent

        _patch_send(monkeypatch, "dast.agents.rate_limit_trust_agent",
                    lambda url, n: _resp(200, "ok"))
        findings = await RateLimitTrustAgent().run(_target(), MagicMock(), None)
        assert findings == []
