"""
Unit tests for dast.ai.mutator — the adaptive payload mutation loop.

Mocks the Bedrock client via the same fake-client pattern used in
test_bedrock_client.py, since mutator.next_payload calls
bedrock_client.invoke_json directly with a schema (forced tool-use path).
"""

from __future__ import annotations

import io
import json
from typing import Any, Dict, List

import pytest

from dast.ai import bedrock_client, mutator


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


# ── next_payload: action handling ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_mutate_action_returns_mutation_result(install_fake_client):
    fake = install_fake_client([_tool_response({
        "action": "mutate", "payload": "' OR 1=1--", "rationale": "quote was stripped",
    })])

    result = await mutator.next_payload(
        attack_type="sqli", original_payload="'", parameter="id",
        response_status=200, response_snippet="illegal character stripped",
        iteration=0,
    )

    assert result is not None
    assert result.action == "mutate"
    assert result.payload == "' OR 1=1--"
    assert result.rationale == "quote was stripped"
    assert len(fake.bodies) == 1


@pytest.mark.asyncio
async def test_stop_action_returns_none(install_fake_client):
    install_fake_client([_tool_response({
        "action": "stop", "payload": "", "rationale": "no defence quotable",
    })])

    result = await mutator.next_payload(
        attack_type="xss", original_payload="<script>", parameter="q",
        response_status=200, response_snippet="{}", iteration=1,
    )

    assert result is None


@pytest.mark.asyncio
async def test_mutate_action_with_empty_payload_treated_as_stop(install_fake_client):
    install_fake_client([_tool_response({
        "action": "mutate", "payload": "", "rationale": "nothing to try",
    })])

    result = await mutator.next_payload(
        attack_type="xss", original_payload="<script>", parameter="q",
        response_status=200, response_snippet="{}", iteration=1,
    )

    assert result is None


# ── safety ceiling ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_safety_ceiling_skips_llm_call(install_fake_client):
    fake = install_fake_client([])  # would raise IndexError if popped

    result = await mutator.next_payload(
        attack_type="sqli", original_payload="1", parameter="id",
        response_status=200, response_snippet="ok", iteration=15,
    )

    assert result is None
    assert fake.bodies == []


@pytest.mark.asyncio
async def test_safety_ceiling_boundary_just_under_still_calls_llm(install_fake_client):
    fake = install_fake_client([_tool_response({
        "action": "stop", "payload": "", "rationale": "done",
    })])

    result = await mutator.next_payload(
        attack_type="sqli", original_payload="1", parameter="id",
        response_status=200, response_snippet="ok", iteration=14,
    )

    assert result is None
    assert len(fake.bodies) == 1


# ── LLM failure degrades gracefully ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_llm_call_raises_returns_none_and_logs_warning(monkeypatch, caplog):
    def _raise(*args, **kwargs):
        raise RuntimeError("bedrock unavailable")

    monkeypatch.setattr(bedrock_client, "invoke_json", _raise)

    with caplog.at_level("WARNING"):
        result = await mutator.next_payload(
            attack_type="sqli", original_payload="1", parameter="id",
            response_status=200, response_snippet="ok", iteration=0,
        )

    assert result is None
    assert any("LLM call failed" in r.message for r in caplog.records)


# ── tried_payloads truncation ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_tried_payloads_truncated_to_last_20(install_fake_client):
    fake = install_fake_client([_tool_response({
        "action": "stop", "payload": "", "rationale": "exhausted",
    })])
    tried = [f"payload-{i}" for i in range(25)]

    await mutator.next_payload(
        attack_type="sqli", original_payload="1", parameter="id",
        response_status=200, response_snippet="ok", iteration=5,
        tried_payloads=tried,
    )

    user_message = fake.bodies[0]["messages"][0]["content"]
    if isinstance(user_message, list):
        user_message = user_message[0]["text"]
    assert "payload-24" in user_message
    assert "payload-5" in user_message  # last 20 = indices 5..24
    assert "payload-4" not in user_message
    assert "payload-0" not in user_message


@pytest.mark.asyncio
async def test_no_tried_payloads_omits_tried_section(install_fake_client):
    fake = install_fake_client([_tool_response({
        "action": "stop", "payload": "", "rationale": "n/a",
    })])

    await mutator.next_payload(
        attack_type="sqli", original_payload="1", parameter="id",
        response_status=200, response_snippet="ok", iteration=0,
    )

    user_message = fake.bodies[0]["messages"][0]["content"]
    if isinstance(user_message, list):
        user_message = user_message[0]["text"]
    assert "already tried" not in user_message


# ── build_mutator_context ───────────────────────────────────────────────────

class _StubDiscovery:
    def __init__(self, summary):
        self._summary = summary

    def to_agent_summary(self):
        return self._summary


class _StubHostIntel:
    def __init__(self, hint):
        self._hint = hint

    def to_mutator_hint(self, attack_type):
        return self._hint


class _Target:
    def __init__(self, discovery_context=None, host_intel=None):
        self.discovery_context = discovery_context
        self.host_intel = host_intel


class _RaisingDiscovery:
    def to_agent_summary(self):
        raise RuntimeError("boom")


class _RaisingHostIntel:
    def to_mutator_hint(self, attack_type):
        raise RuntimeError("boom")


def test_build_mutator_context_discovery_only():
    target = _Target(discovery_context=_StubDiscovery("tech: nginx"))
    assert mutator.build_mutator_context(target, "sqli") == "tech: nginx"


def test_build_mutator_context_host_intel_only():
    target = _Target(host_intel=_StubHostIntel("waf: cloudflare"))
    assert mutator.build_mutator_context(target, "sqli") == "waf: cloudflare"


def test_build_mutator_context_both_sections_joined():
    target = _Target(
        discovery_context=_StubDiscovery("tech: nginx"),
        host_intel=_StubHostIntel("waf: cloudflare"),
    )
    result = mutator.build_mutator_context(target, "sqli")
    assert result == "tech: nginx\nwaf: cloudflare"


def test_build_mutator_context_neither_returns_none():
    target = _Target()
    assert mutator.build_mutator_context(target, "sqli") is None


def test_build_mutator_context_empty_summaries_return_none():
    target = _Target(discovery_context=_StubDiscovery(""), host_intel=_StubHostIntel(""))
    assert mutator.build_mutator_context(target, "sqli") is None


def test_build_mutator_context_discovery_exception_is_swallowed():
    target = _Target(discovery_context=_RaisingDiscovery(), host_intel=_StubHostIntel("waf: x"))
    assert mutator.build_mutator_context(target, "sqli") == "waf: x"


def test_build_mutator_context_host_intel_exception_is_swallowed():
    target = _Target(discovery_context=_StubDiscovery("tech: y"), host_intel=_RaisingHostIntel())
    assert mutator.build_mutator_context(target, "sqli") == "tech: y"


def test_build_mutator_context_both_raise_returns_none():
    target = _Target(discovery_context=_RaisingDiscovery(), host_intel=_RaisingHostIntel())
    assert mutator.build_mutator_context(target, "sqli") is None
