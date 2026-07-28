"""
Unit tests for Coordinator.run() / _run_inner() — the full per-endpoint
orchestration: budget/timeout, early aborts, baseline check, agent execution,
and red-team validation wiring.

_plan and _run_canary_probe are mocked throughout so no Bedrock/HTTP calls are
made for planning; _send (used by _baseline_check and canary probes) and
red_team.validate are mocked per-test as needed.
"""

from __future__ import annotations

import asyncio

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.ai.coordinator import Coordinator, _activity_log
from dast.scanners.active_checks import CheckTarget


def _target(url="https://example.com/api", method="GET", params=None, body=None):
    return CheckTarget(
        method=method,
        url=url,
        headers={"content-type": "application/json"},
        body=body,
        params=params or [{"name": "id", "location": "query", "value": "1"}],
    )


def _finding(**kw):
    defaults = dict(
        title="Reflected XSS",
        severity="high",
        cwe="CWE-79",
        attack_type="xss",
        evidence="payload reflected",
        payload="<script>",
        parameter="id",
        url="https://example.com/api",
        request_method="GET",
        bypass_validation=False,
        reasoning="",
    )
    defaults.update(kw)
    return AgentFinding(**defaults)


class _Registry:
    """Context manager: swap Coordinator._registry for the duration of a test."""

    def __enter__(self):
        self._original = dict(Coordinator._registry)
        Coordinator._registry.clear()
        return self

    def __exit__(self, *exc):
        Coordinator._registry.clear()
        Coordinator._registry.update(self._original)


def _resp(status=200, text="{}", content_type="application/json"):
    m = MagicMock()
    m.status_code = status
    m.text = text
    m.headers = {"content-type": content_type}
    return m


# ── budget / timeout ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_run_returns_empty_and_logs_nothing_when_budget_exceeded():
    class _SlowAgent(VulnAgent):
        name = "Slow"
        attack_type = "_slow_budget_test"
        description = ""
        async def run(self, target, client, collaborator=None):
            await asyncio.sleep(10)
            return []

    _activity_log.clear()
    with _Registry():
        Coordinator.register(_SlowAgent)
        with patch.object(Coordinator, "_plan", new=AsyncMock(return_value=(["_slow_budget_test"], "reason", False))), \
             patch("dast.ai.coordinator._run_canary_probe", new=AsyncMock(return_value=False)):
            client = MagicMock()
            result = await Coordinator.run(_target(), client, budget_seconds=0.05)

    assert result == []
    assert len(_activity_log) == 0


@pytest.mark.asyncio
async def test_run_completes_within_explicit_budget():
    class _FastAgent(VulnAgent):
        name = "Fast"
        attack_type = "_fast_budget_test"
        description = ""
        async def run(self, target, client, collaborator=None):
            return []

    _activity_log.clear()
    with _Registry():
        Coordinator.register(_FastAgent)
        with patch.object(Coordinator, "_plan", new=AsyncMock(return_value=(["_fast_budget_test"], "reason", False))), \
             patch("dast.ai.coordinator._run_canary_probe", new=AsyncMock(return_value=False)):
            client = MagicMock()
            result = await Coordinator.run(_target(), client, budget_seconds=5.0)

    assert result == []
    assert len(_activity_log) == 1


# ── early aborts ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_run_aborts_early_on_auth_endpoint_without_calling_planner():
    class _AnyAgent(VulnAgent):
        name = "Any"
        attack_type = "_auth_abort_test"
        description = ""
        async def run(self, target, client, collaborator=None):
            return []

    _activity_log.clear()
    plan_mock = AsyncMock(return_value=(["_auth_abort_test"], "should not be called", False))
    with _Registry():
        Coordinator.register(_AnyAgent)
        with patch.object(Coordinator, "_plan", new=plan_mock):
            client = MagicMock()
            result = await Coordinator.run(
                _target(url="https://example.com/oauth/callback"), client, budget_seconds=5.0,
            )

    assert result == []
    plan_mock.assert_not_called()
    assert len(_activity_log) == 1
    assert "auth" in _activity_log[0]["plan_reason"].lower()


@pytest.mark.asyncio
async def test_run_aborts_early_when_all_params_are_auth_tokens():
    class _AnyAgent(VulnAgent):
        name = "Any"
        attack_type = "_token_abort_test"
        description = ""
        async def run(self, target, client, collaborator=None):
            return []

    _activity_log.clear()
    plan_mock = AsyncMock(return_value=(["_token_abort_test"], "should not be called", False))
    target = _target(params=[{"name": "nonce", "location": "query", "value": "abc"}])
    with _Registry():
        Coordinator.register(_AnyAgent)
        with patch.object(Coordinator, "_plan", new=plan_mock):
            client = MagicMock()
            result = await Coordinator.run(target, client, budget_seconds=5.0)

    assert result == []
    plan_mock.assert_not_called()
    assert len(_activity_log) == 1
    assert "auth" in _activity_log[0]["plan_reason"].lower()


# ── baseline check abort ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_run_aborts_when_baseline_returns_404():
    class _AnyAgent(VulnAgent):
        name = "Any"
        attack_type = "_baseline_404_test"
        description = ""
        async def run(self, target, client, collaborator=None):
            return []

    async def fake_send(client, method, url, headers, body):
        return _resp(status=404, text="not found", content_type="text/plain")

    _activity_log.clear()
    plan_mock = AsyncMock(return_value=(["_baseline_404_test"], "should not be called", False))
    with _Registry():
        Coordinator.register(_AnyAgent)
        with patch.object(Coordinator, "_plan", new=plan_mock), \
             patch("dast.ai.coordinator._run_canary_probe", new=AsyncMock(return_value=False)), \
             patch("dast.scanners.active_checks._send", new=AsyncMock(side_effect=fake_send)):
            client = MagicMock()
            result = await Coordinator.run(_target(), client, budget_seconds=5.0)

    assert result == []
    plan_mock.assert_not_called()
    assert len(_activity_log) == 1
    assert "404" in _activity_log[0]["plan_reason"]


@pytest.mark.asyncio
async def test_run_skips_baseline_probe_when_no_params_and_no_body():
    class _AnyAgent(VulnAgent):
        name = "Any"
        attack_type = "_no_params_test"
        description = ""
        async def run(self, target, client, collaborator=None):
            return []

    _activity_log.clear()
    send_mock = AsyncMock(return_value=_resp())
    target = CheckTarget(
        method="GET", url="https://example.com/health",
        headers={}, body=None, params=[],
    )
    with _Registry():
        Coordinator.register(_AnyAgent)
        with patch.object(Coordinator, "_plan", new=AsyncMock(return_value=([], "nothing to do", False))), \
             patch("dast.ai.coordinator._run_canary_probe", new=AsyncMock(return_value=False)), \
             patch("dast.scanners.active_checks._send", new=send_mock):
            client = MagicMock()
            await Coordinator.run(target, client, budget_seconds=5.0)

    send_mock.assert_not_called()


# ── structural-error short-circuit via session intelligence ──────────────

@pytest.mark.asyncio
async def test_run_skips_when_session_intelligence_has_known_structural_error():
    class _AnyAgent(VulnAgent):
        name = "Any"
        attack_type = "_structural_skip_test"
        description = ""
        async def run(self, target, client, collaborator=None):
            return []

    host_intel = MagicMock()
    host_intel.to_planner_hint.return_value = ""
    host_intel.has_structural_error_for.return_value = "404 previously seen"
    session_intelligence = MagicMock()
    session_intelligence.get.return_value = host_intel

    _activity_log.clear()
    plan_mock = AsyncMock(return_value=(["_structural_skip_test"], "should not be called", False))
    send_mock = AsyncMock(return_value=_resp())
    with _Registry():
        Coordinator.register(_AnyAgent)
        with patch.object(Coordinator, "_plan", new=plan_mock), \
             patch("dast.ai.coordinator._run_canary_probe", new=AsyncMock(return_value=False)), \
             patch("dast.scanners.active_checks._send", new=send_mock):
            client = MagicMock()
            result = await Coordinator.run(
                _target(), client, session_intelligence=session_intelligence, budget_seconds=5.0,
            )

    assert result == []
    plan_mock.assert_not_called()
    send_mock.assert_not_called()


# ── full happy path: agents run, red-team validates ───────────────────────

@pytest.mark.asyncio
async def test_run_confirms_finding_via_red_team_validate():
    finding = _finding(bypass_validation=False, attack_type="_e2e_confirm_test")

    class _HitAgent(VulnAgent):
        name = "Hit"
        attack_type = "_e2e_confirm_test"
        description = ""
        async def run(self, target, client, collaborator=None):
            return [finding]

    _activity_log.clear()
    validate_mock = AsyncMock(return_value=(True, 0.9, "confirmed by LLM"))
    with _Registry():
        Coordinator.register(_HitAgent)
        with patch.object(Coordinator, "_plan", new=AsyncMock(return_value=(["_e2e_confirm_test"], "reason", False))), \
             patch("dast.ai.coordinator._run_canary_probe", new=AsyncMock(return_value=False)), \
             patch("dast.ai.red_team.validate", new=validate_mock):
            client = MagicMock()
            result = await Coordinator.run(_target(), client, budget_seconds=5.0)

    assert len(result) == 1
    assert result[0].title == "Reflected XSS"
    validate_mock.assert_awaited_once()


@pytest.mark.asyncio
async def test_run_discards_finding_when_red_team_rejects():
    finding = _finding(bypass_validation=False, attack_type="_e2e_reject_test")

    class _HitAgent(VulnAgent):
        name = "Hit"
        attack_type = "_e2e_reject_test"
        description = ""
        async def run(self, target, client, collaborator=None):
            return [finding]

    _activity_log.clear()
    validate_mock = AsyncMock(return_value=(False, 0.1, "rejected"))
    with _Registry():
        Coordinator.register(_HitAgent)
        with patch.object(Coordinator, "_plan", new=AsyncMock(return_value=(["_e2e_reject_test"], "reason", False))), \
             patch("dast.ai.coordinator._run_canary_probe", new=AsyncMock(return_value=False)), \
             patch("dast.ai.red_team.validate", new=validate_mock):
            client = MagicMock()
            result = await Coordinator.run(_target(), client, budget_seconds=5.0)

    assert result == []


@pytest.mark.asyncio
async def test_run_keeps_bypass_validation_finding_without_calling_red_team():
    finding = _finding(bypass_validation=True, attack_type="_e2e_bypass_test")

    class _HitAgent(VulnAgent):
        name = "Hit"
        attack_type = "_e2e_bypass_test"
        description = ""
        async def run(self, target, client, collaborator=None):
            return [finding]

    _activity_log.clear()
    validate_mock = AsyncMock(return_value=(True, 0.9, "should not be called"))
    with _Registry():
        Coordinator.register(_HitAgent)
        with patch.object(Coordinator, "_plan", new=AsyncMock(return_value=(["_e2e_bypass_test"], "reason", False))), \
             patch("dast.ai.coordinator._run_canary_probe", new=AsyncMock(return_value=False)), \
             patch("dast.ai.red_team.validate", new=validate_mock):
            client = MagicMock()
            result = await Coordinator.run(_target(), client, budget_seconds=5.0)

    assert len(result) == 1
    validate_mock.assert_not_awaited()


@pytest.mark.asyncio
async def test_run_validation_exception_does_not_confirm_finding():
    finding = _finding(bypass_validation=False, attack_type="_e2e_error_test")

    class _HitAgent(VulnAgent):
        name = "Hit"
        attack_type = "_e2e_error_test"
        description = ""
        async def run(self, target, client, collaborator=None):
            return [finding]

    _activity_log.clear()
    validate_mock = AsyncMock(side_effect=RuntimeError("bedrock down"))
    with _Registry():
        Coordinator.register(_HitAgent)
        with patch.object(Coordinator, "_plan", new=AsyncMock(return_value=(["_e2e_error_test"], "reason", False))), \
             patch("dast.ai.coordinator._run_canary_probe", new=AsyncMock(return_value=False)), \
             patch("dast.ai.red_team.validate", new=validate_mock):
            client = MagicMock()
            result = await Coordinator.run(_target(), client, budget_seconds=5.0)

    assert result == []


# ── adaptive budget ────────────────────────────────────────────────────────

class TestAdaptiveBudget:
    def test_rich_target_with_effective_types_gets_180s(self):
        host_intel = MagicMock()
        host_intel.effective_attack_types = {"sqli"}
        host_intel.ineffective_attack_types = set()
        host_intel.confirmed_vulns = {}
        assert Coordinator._adaptive_budget(_target(), host_intel) == 180.0

    def test_all_types_ineffective_gets_45s(self):
        host_intel = MagicMock()
        host_intel.effective_attack_types = set()
        host_intel.ineffective_attack_types = {"sqli"}
        host_intel.confirmed_vulns = {}
        assert Coordinator._adaptive_budget(_target(), host_intel) == 45.0

    def test_many_params_scales_and_caps_at_180s(self):
        params = [{"name": f"p{i}", "location": "query", "value": "1"} for i in range(30)]
        assert Coordinator._adaptive_budget(_target(params=params), None) == 180.0

    def test_simple_get_no_intel_gets_45s(self):
        target = _target(method="GET", params=[{"name": "q", "location": "query", "value": "x"}])
        assert Coordinator._adaptive_budget(target, None) == 45.0

    def test_normal_endpoint_gets_90s(self):
        params = [{"name": f"p{i}", "location": "query", "value": "1"} for i in range(5)]
        target = _target(method="POST", params=params)
        assert Coordinator._adaptive_budget(target, None) == 90.0
