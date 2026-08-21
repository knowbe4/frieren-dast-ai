"""
Unit tests for Coordinator activity log and agent registry.

AI/Bedrock calls are mocked — no AWS credentials required.
"""

from __future__ import annotations

import collections
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from dast.ai.coordinator import Coordinator, _activity_log
from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.scanners.active_checks import CheckTarget


def _target(url="https://example.com/api", method="GET", params=None):
    return CheckTarget(
        method=method,
        url=url,
        headers={"content-type": "application/json"},
        body=None,
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


# ── agent registration ─────────────────────────────────────────────────────

class TestAgentRegistry:
    def test_register_and_retrieve(self):
        class _TestAgent(VulnAgent):
            name = "Test Agent"
            attack_type = "_test_unique_xyz"
            description = "test"
            async def run(self, target, client, collaborator=None):
                return []

        original = dict(Coordinator._registry)
        try:
            Coordinator.register(_TestAgent)
            assert "_test_unique_xyz" in Coordinator.registered_types()
        finally:
            Coordinator._registry.clear()
            Coordinator._registry.update(original)

    def test_registered_types_returns_list(self):
        assert isinstance(Coordinator.registered_types(), list)


# ── activity log ──────────────────────────────────────────────────────────

class TestActivityLog:
    def test_log_is_bounded_deque(self):
        assert isinstance(_activity_log, collections.deque)
        assert _activity_log.maxlen == 200

    @pytest.mark.asyncio
    async def test_run_appends_to_log(self):
        class _NoopAgent(VulnAgent):
            name = "Noop"
            attack_type = "_noop_log_test"
            description = ""
            async def run(self, target, client, collaborator=None):
                return []

        _activity_log.clear()
        original = dict(Coordinator._registry)
        try:
            Coordinator._registry.clear()
            Coordinator.register(_NoopAgent)

            # Mock the planner so no Bedrock call is made.
            # Also mock the canary probe so no HTTP calls are made.
            with patch.object(Coordinator, "_plan", new=AsyncMock(return_value=(["_noop_log_test"], "test reason", False))), \
                 patch("dast.ai.coordinator._run_canary_probe", new=AsyncMock(return_value=False)):
                client = MagicMock()
                await Coordinator.run(_target(), client, collaborator=None)

            assert len(_activity_log) == 1
            event = _activity_log[0]
            assert event["method"] == "GET"
            assert "_noop_log_test" in event["agents_selected"]
            assert event["plan_reason"] == "test reason"
            assert isinstance(event["outcomes"], list)
        finally:
            Coordinator._registry.clear()
            Coordinator._registry.update(original)
            _activity_log.clear()

    @pytest.mark.asyncio
    async def test_confirmed_finding_in_log(self):
        f = _finding(bypass_validation=True)

        class _HitAgent(VulnAgent):
            name = "Hit"
            attack_type = "_hit_log_test"
            description = ""
            async def run(self, target, client, collaborator=None):
                return [f]

        _activity_log.clear()
        original = dict(Coordinator._registry)
        try:
            Coordinator._registry.clear()
            Coordinator.register(_HitAgent)

            with patch.object(Coordinator, "_plan", new=AsyncMock(return_value=(["_hit_log_test"], "", False))), \
                 patch("dast.ai.coordinator._run_canary_probe", new=AsyncMock(return_value=False)):
                client = MagicMock()
                await Coordinator.run(_target(), client)

            event = _activity_log[0]
            outcome = next(o for o in event["outcomes"] if o["attack_type"] == "_hit_log_test")
            assert outcome["finding_title"] == "Reflected XSS"
            assert outcome["confirmed"] is True
        finally:
            Coordinator._registry.clear()
            Coordinator._registry.update(original)
            _activity_log.clear()

    @pytest.mark.asyncio
    async def test_empty_registry_returns_empty_and_no_log(self):
        _activity_log.clear()
        original = dict(Coordinator._registry)
        try:
            Coordinator._registry.clear()
            client = MagicMock()
            result = await Coordinator.run(_target(), client)
            assert result == []
            assert len(_activity_log) == 0
        finally:
            Coordinator._registry.clear()
            Coordinator._registry.update(original)
            _activity_log.clear()

    @pytest.mark.asyncio
    async def test_no_agents_selected_logs_empty_event(self):
        _activity_log.clear()
        original = dict(Coordinator._registry)
        try:
            # registry has one agent but planner selects none
            class _DummyAgent(VulnAgent):
                name = "Dummy"
                attack_type = "_dummy_none_selected"
                description = ""
                async def run(self, target, client, collaborator=None):
                    return []

            Coordinator._registry.clear()
            Coordinator.register(_DummyAgent)

            with patch.object(Coordinator, "_plan", new=AsyncMock(return_value=([], "no relevant agents", False))):
                client = MagicMock()
                result = await Coordinator.run(_target(), client)

            assert result == []
            assert len(_activity_log) == 1
            assert _activity_log[0]["agents_selected"] == []
        finally:
            Coordinator._registry.clear()
            Coordinator._registry.update(original)
            _activity_log.clear()
