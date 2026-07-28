"""
Unit tests for Coordinator._plan — the LLM agent-selection step.

Mocks bedrock_client.invoke_json directly (schema-forced tool-use path),
following the fake-client pattern from test_bedrock_client.py / test_mutator.py.
"""

from __future__ import annotations

import io
import json
from typing import Any, Dict, List

import pytest

import dast.agents  # noqa: F401 — triggers agent registration into Coordinator._registry
from dast.ai import bedrock_client
from dast.ai.coordinator import Coordinator
from dast.scanners.active_checks import CheckTarget


class _FakeResponseBody:
    def __init__(self, payload: Dict[str, Any]) -> None:
        self._buf = io.BytesIO(json.dumps(payload).encode())

    def read(self) -> bytes:
        return self._buf.read()


class _FakeBedrockClient:
    def __init__(self, responses: List[Dict[str, Any]]) -> None:
        self._responses = list(responses)
        self.bodies: List[Dict[str, Any]] = []

    def invoke_model(self, modelId: str, body: str) -> Dict[str, Any]:
        self.bodies.append(json.loads(body))
        payload = self._responses.pop(0)
        return {"body": _FakeResponseBody(payload)}


def _tool_response(tool_input: Dict[str, Any]) -> Dict[str, Any]:
    return {"content": [{"type": "tool_use", "name": "emit_result", "input": tool_input}]}


@pytest.fixture
def install_fake_client(monkeypatch):
    def _install(responses: List[Dict[str, Any]]) -> _FakeBedrockClient:
        fake = _FakeBedrockClient(responses)
        monkeypatch.setattr(bedrock_client, "get_client", lambda: fake)
        monkeypatch.setattr(bedrock_client, "get_active_model", lambda: "test-model")
        return fake
    return _install


def _target(url="https://example.com/api", method="GET", params=None, body=None):
    return CheckTarget(
        method=method,
        url=url,
        headers={"content-type": "application/json"},
        body=body,
        params=params or [{"name": "id", "location": "query", "value": "1"}],
    )


def _last_user_message(fake: _FakeBedrockClient) -> str:
    content = fake.bodies[-1]["messages"][0]["content"]
    if isinstance(content, list):
        return content[0]["text"]
    return content


# ── happy path ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_happy_path_returns_llm_selected_agents(install_fake_client):
    install_fake_client([_tool_response({
        "agents": ["sqli", "xss"], "reason": "id param looks injectable and reflected in HTML",
    })])

    agents, reason, mine_params = await Coordinator._plan(_target())

    assert agents == ["sqli", "xss"]
    assert reason == "id param looks injectable and reflected in HTML"
    assert mine_params is False  # absent in the tool output → default False


# ── mine_params passthrough ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_mine_params_true_is_returned(install_fake_client):
    install_fake_client([_tool_response({
        "agents": ["sqli"], "reason": "debug toggle likely", "mine_params": True,
    })])

    agents, reason, mine_params = await Coordinator._plan(_target())

    assert agents == ["sqli"]
    assert mine_params is True


# ── non-list agents falls through to signal-based fallback ────────────────

@pytest.mark.asyncio
async def test_non_list_agents_falls_back_to_signal_based(install_fake_client):
    install_fake_client([_tool_response({"agents": "sqli", "reason": "malformed"})])

    agents, reason, mine_params = await Coordinator._plan(
        _target(),
        signal_attack_types=["sqli"],
        candidate_types=["sqli", "secrets"],
    )

    assert set(agents) == {"sqli", "secrets"}
    assert "signal-based fallback" in reason
    assert mine_params is False


# ── LLM raises ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_llm_raises_falls_back_to_union_of_signal_and_candidate(monkeypatch):
    def _raise(*a, **k):
        raise RuntimeError("bedrock down")

    monkeypatch.setattr(bedrock_client, "invoke_json", _raise)

    agents, reason, mine_params = await Coordinator._plan(
        _target(),
        signal_attack_types=["sqli"],
        candidate_types=["sqli", "secrets", "xss"],
    )

    # xss is a canary-covered (injectable) type and not in signal_attack_types,
    # so it's excluded — the fallback is signal types + non-injectable candidates.
    assert set(agents) == {"sqli", "secrets"}
    assert reason == "LLM failed — signal-based fallback"


@pytest.mark.asyncio
async def test_llm_raises_with_both_empty_falls_back_to_full_registry(monkeypatch):
    def _raise(*a, **k):
        raise RuntimeError("bedrock down")

    monkeypatch.setattr(bedrock_client, "invoke_json", _raise)

    agents, reason, mine_params = await Coordinator._plan(
        _target(),
        signal_attack_types=[],
        candidate_types=[],
    )

    assert agents  # never silently empty
    assert set(agents) == set(Coordinator._registry.keys())
    assert reason == "LLM failed — signal-based fallback"


# ── prompt construction ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_restrict_note_present_when_no_canary_signal_and_candidates_exist(install_fake_client):
    fake = install_fake_client([_tool_response({"agents": ["secrets"], "reason": "no signal"})])

    await Coordinator._plan(
        _target(),
        signal_attack_types=[],
        candidate_types=["secrets"],
    )

    user_message = _last_user_message(fake)
    assert "No canary signals detected" in user_message


@pytest.mark.asyncio
async def test_restrict_note_absent_when_signal_types_present(install_fake_client):
    fake = install_fake_client([_tool_response({"agents": ["sqli"], "reason": "signal found"})])

    await Coordinator._plan(
        _target(),
        signal_attack_types=["sqli"],
        candidate_types=["sqli"],
    )

    user_message = _last_user_message(fake)
    assert "No canary signals detected" not in user_message


@pytest.mark.asyncio
async def test_canary_summary_passed_through_into_prompt(install_fake_client):
    fake = install_fake_client([_tool_response({"agents": [], "reason": "n/a"})])

    await Coordinator._plan(
        _target(),
        canary_summary="sqli: no signal; xss: reflected in HTML",
    )

    user_message = _last_user_message(fake)
    assert "sqli: no signal; xss: reflected in HTML" in user_message


@pytest.mark.asyncio
async def test_canary_summary_omitted_when_empty(install_fake_client):
    fake = install_fake_client([_tool_response({"agents": [], "reason": "n/a"})])

    await Coordinator._plan(_target(), canary_summary="")

    user_message = _last_user_message(fake)
    assert "Canary probe results" not in user_message
