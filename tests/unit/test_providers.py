"""
Unit tests for the multi-provider AI abstraction.

The gateway (dast.ai.bedrock_client) builds Anthropic-style request bodies and
reads Anthropic-style response envelopes. These tests verify that:
  - the Anthropic provider passes the body through (minus the Bedrock-only
    anthropic_version key) with the right headers;
  - the OpenAI provider translates the body to chat-completions on the way out
    and the response back to an Anthropic envelope on the way in (text + forced
    tool calls);
  - the gateway dispatches invoke_json() to the selected provider and still
    returns the schema-forced tool input as a dict.

All HTTP is mocked at the httpx.Client level — no network calls are made.
"""

from __future__ import annotations

import json
from typing import Any, Dict

import pytest

from dast.ai import bedrock_client, providers


class _FakeResponse:
    def __init__(self, status_code: int, payload: Dict[str, Any]) -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = json.dumps(payload)

    def json(self) -> Dict[str, Any]:
        return self._payload


class _FakeHttpClient:
    """Captures the posted (url, headers, json) and returns a queued response."""

    def __init__(self, response: _FakeResponse) -> None:
        self._response = response
        self.calls: list = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def post(self, url: str, headers: Dict[str, str], json: Dict[str, Any]) -> _FakeResponse:
        self.calls.append({"url": url, "headers": headers, "json": json})
        return self._response


@pytest.fixture
def patch_http(monkeypatch):
    """Install a fake httpx.Client on the providers module; return the fake."""
    def _install(response: _FakeResponse) -> _FakeHttpClient:
        fake = _FakeHttpClient(response)
        monkeypatch.setattr(providers.httpx, "Client", lambda *a, **k: fake)
        return fake
    return _install


# ── Anthropic provider ────────────────────────────────────────────────────────

def test_anthropic_passthrough_strips_version_and_sets_headers(patch_http):
    envelope = {"content": [{"type": "text", "text": "hi"}]}
    fake = patch_http(_FakeResponse(200, envelope))

    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 100,
        "system": "sys",
        "messages": [{"role": "user", "content": "hello"}],
    }
    result = providers.invoke_anthropic(body, model_id="claude-opus-4-8",
                                        api_key="sk-ant-x", base_url="https://api.anthropic.com")

    assert result == envelope
    call = fake.calls[0]
    assert call["url"] == "https://api.anthropic.com/v1/messages"
    assert call["headers"]["x-api-key"] == "sk-ant-x"
    assert call["headers"]["anthropic-version"] == "2023-06-01"
    # The Bedrock-only version key must not be in the JSON body; model must be.
    assert "anthropic_version" not in call["json"]
    assert call["json"]["model"] == "claude-opus-4-8"


def test_anthropic_missing_key_raises(patch_http):
    with pytest.raises(providers.ProviderError):
        providers.invoke_anthropic({}, model_id="m", api_key="", base_url="https://x")


def test_anthropic_http_error_raises(patch_http):
    patch_http(_FakeResponse(401, {"error": "bad key"}))
    with pytest.raises(providers.ProviderError):
        providers.invoke_anthropic({"messages": []}, model_id="m",
                                   api_key="k", base_url="https://x")


# ── OpenAI provider ─────────────────────────────────────────────────────────

def test_openai_text_response_becomes_anthropic_envelope(patch_http):
    oai_payload = {
        "choices": [{"message": {"role": "assistant", "content": "the answer"}}],
        "usage": {"prompt_tokens": 5},
    }
    fake = patch_http(_FakeResponse(200, oai_payload))

    body = {
        "max_tokens": 200,
        "temperature": 0,
        "system": "you are a scanner",
        "messages": [{"role": "user", "content": "go"}],
    }
    result = providers.invoke_openai(body, model_id="gpt-4o",
                                     api_key="sk-oai", base_url="https://api.openai.com/v1")

    assert result["content"] == [{"type": "text", "text": "the answer"}]
    call = fake.calls[0]
    assert call["url"] == "https://api.openai.com/v1/chat/completions"
    assert call["headers"]["Authorization"] == "Bearer sk-oai"
    # System prompt becomes a system-role message; temperature preserved.
    sent = call["json"]
    assert sent["messages"][0] == {"role": "system", "content": "you are a scanner"}
    assert sent["messages"][1] == {"role": "user", "content": "go"}
    assert sent["temperature"] == 0
    assert sent["model"] == "gpt-4o"


def test_openai_tool_call_becomes_tool_use_block(patch_http):
    oai_payload = {
        "choices": [{
            "message": {
                "role": "assistant",
                "content": None,
                "tool_calls": [{
                    "function": {"name": "emit_result", "arguments": '{"ok": true}'},
                }],
            },
        }],
    }
    fake = patch_http(_FakeResponse(200, oai_payload))

    schema = {"type": "object", "properties": {"ok": {"type": "boolean"}}}
    body = {
        "max_tokens": 100,
        "system": "s",
        "messages": [{"role": "user", "content": "u"}],
        "tools": [{"name": "emit_result", "description": "d", "input_schema": schema}],
        "tool_choice": {"type": "tool", "name": "emit_result"},
    }
    result = providers.invoke_openai(body, model_id="gpt-4o", api_key="k",
                                     base_url="https://api.openai.com/v1")

    block = result["content"][0]
    assert block["type"] == "tool_use"
    assert block["name"] == "emit_result"
    assert block["input"] == {"ok": True}
    # The request must translate the tool into an OpenAI function with forced choice.
    sent = fake.calls[0]["json"]
    assert sent["tools"][0]["type"] == "function"
    assert sent["tools"][0]["function"]["name"] == "emit_result"
    assert sent["tools"][0]["function"]["parameters"] == schema
    assert sent["tool_choice"] == {"type": "function", "function": {"name": "emit_result"}}


def test_openai_flattens_cached_system_blocks(patch_http):
    fake = patch_http(_FakeResponse(200, {"choices": [{"message": {"content": "x"}}]}))
    body = {
        "max_tokens": 100,
        "system": [{"type": "text", "text": "cached prompt", "cache_control": {"type": "ephemeral"}}],
        "messages": [{"role": "user", "content": "u"}],
    }
    providers.invoke_openai(body, model_id="gpt-4o", api_key="k", base_url="https://x/v1")
    assert fake.calls[0]["json"]["messages"][0] == {"role": "system", "content": "cached prompt"}


# ── gateway dispatch ──────────────────────────────────────────────────────────

def test_gateway_routes_invoke_json_to_openai(monkeypatch):
    """set_provider('openai') makes invoke_json go through the OpenAI provider."""
    captured: Dict[str, Any] = {}

    def _fake_openai(body, model_id, api_key, base_url):
        captured["body"] = body
        captured["model_id"] = model_id
        captured["api_key"] = api_key
        return {"content": [{"type": "tool_use", "name": "emit_result", "input": {"routed": True}}]}

    monkeypatch.setattr(providers, "invoke_openai", _fake_openai)
    monkeypatch.setattr(bedrock_client, "get_active_model", lambda: "gpt-4o")

    try:
        bedrock_client.set_provider(provider="openai", openai_api_key="sk-test")
        schema = {"type": "object", "properties": {"routed": {"type": "boolean"}}}
        result = bedrock_client.invoke_json("sys", "user", schema=schema)
    finally:
        bedrock_client.set_provider(provider="bedrock")

    assert result == {"routed": True}
    assert captured["model_id"] == "gpt-4o"
    assert captured["api_key"] == "sk-test"
    # The body handed to the provider still carries the forced-tool machinery.
    assert captured["body"]["tool_choice"] == {"type": "tool", "name": "emit_result"}


def test_get_active_provider_defaults_to_bedrock(monkeypatch):
    monkeypatch.setattr(bedrock_client, "_active_provider", "")
    assert bedrock_client.get_active_provider() == "bedrock"


# ── gateway provider ──────────────────────────────────────────────────────────

def test_gateway_strips_temperature_and_disables_thinking(monkeypatch):
    """invoke_gateway drops temperature/anthropic_version and disables thinking."""
    from dast.ai import gateway_auth

    sent: Dict[str, Any] = {}

    class _FakeTransport:
        def send(self, body, timeout=300):
            sent.update(body)
            return {"content": [{"type": "text", "text": "ok"}]}

    monkeypatch.setattr(gateway_auth, "get_shared_transport",
                        lambda base_url="": _FakeTransport())

    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "temperature": 0,
        "max_tokens": 100,
        "system": "sys",
        "messages": [{"role": "user", "content": "hi"}],
        "tools": [{"name": "emit_result", "description": "d", "input_schema": {}}],
        "tool_choice": {"type": "tool", "name": "emit_result"},
    }
    result = providers.invoke_gateway(body, model_id="claude-sonnet-5",
                                      api_key="", base_url="https://gw.example")

    assert result == {"content": [{"type": "text", "text": "ok"}]}
    # Server-side pinned / Bedrock-only keys removed; model injected; thinking off.
    assert "temperature" not in sent
    assert "anthropic_version" not in sent
    assert sent["model"] == "claude-sonnet-5"
    assert sent["thinking"] == {"type": "disabled"}
    # Schema-forced tool machinery survives so structured output still works.
    assert sent["tool_choice"] == {"type": "tool", "name": "emit_result"}


def test_gateway_error_becomes_provider_error(monkeypatch):
    from dast.ai import gateway_auth

    def _boom(base_url=""):
        raise gateway_auth.GatewayError("no session")

    monkeypatch.setattr(gateway_auth, "get_shared_transport", _boom)
    with pytest.raises(providers.ProviderError):
        providers.invoke_gateway({"messages": []}, model_id="m",
                                 api_key="", base_url="https://gw")


def test_gateway_routes_invoke_json(monkeypatch):
    """set_provider('gateway') routes invoke_json through the gateway provider."""
    captured: Dict[str, Any] = {}

    def _fake_gateway(body, model_id, api_key, base_url):
        captured["body"] = body
        captured["model_id"] = model_id
        captured["base_url"] = base_url
        return {"content": [{"type": "tool_use", "name": "emit_result", "input": {"routed": True}}]}

    monkeypatch.setattr(providers, "invoke_gateway", _fake_gateway)
    monkeypatch.setattr(bedrock_client, "get_active_model", lambda: "claude-sonnet-5")

    try:
        bedrock_client.set_provider(provider="gateway", gateway_base_url="https://gw.example")
        schema = {"type": "object", "properties": {"routed": {"type": "boolean"}}}
        result = bedrock_client.invoke_json("sys", "user", schema=schema)
    finally:
        bedrock_client.set_provider(provider="bedrock")

    assert result == {"routed": True}
    assert captured["model_id"] == "claude-sonnet-5"
    assert captured["base_url"] == "https://gw.example"
    assert captured["body"]["tool_choice"] == {"type": "tool", "name": "emit_result"}
