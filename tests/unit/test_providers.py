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


def test_provider_error_carries_status_code(patch_http):
    patch_http(_FakeResponse(503, {"error": "overloaded"}))
    with pytest.raises(providers.ProviderError) as exc_info:
        providers.invoke_anthropic({"messages": []}, model_id="m",
                                   api_key="k", base_url="https://x")
    assert exc_info.value.status_code == 503


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


def test_openai_local_base_url_allows_empty_key(patch_http):
    """A non-public base_url accepts an empty key and sends a placeholder bearer."""
    oai_payload = {"choices": [{"message": {"role": "assistant", "content": "hi"}}]}
    fake = patch_http(_FakeResponse(200, oai_payload))

    body = {"max_tokens": 50, "messages": [{"role": "user", "content": "go"}]}
    result = providers.invoke_openai(body, model_id="qwen2.5:14b",
                                     api_key="", base_url="http://localhost:11434/v1")

    assert result["content"] == [{"type": "text", "text": "hi"}]
    call = fake.calls[0]
    assert call["url"] == "http://localhost:11434/v1/chat/completions"
    assert call["headers"]["Authorization"] == "Bearer local"


def test_openai_public_base_url_still_requires_key(patch_http):
    """The public OpenAI API must reject an empty key rather than send a placeholder."""
    with pytest.raises(providers.ProviderError):
        providers.invoke_openai({"messages": []}, model_id="gpt-4o",
                                api_key="", base_url="https://api.openai.com/v1")


def test_is_public_openai_detects_host():
    assert providers.is_public_openai("https://api.openai.com/v1") is True
    assert providers.is_public_openai("https://eu.api.openai.com/v1") is True
    assert providers.is_public_openai("http://localhost:11434/v1") is False
    assert providers.is_public_openai("http://192.168.1.5:8000/v1") is False


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


class _QueuedHttpClient(_FakeHttpClient):
    """Like _FakeHttpClient but returns queued responses in order."""

    def __init__(self, responses: list) -> None:
        super().__init__(responses[0])
        self._queue = list(responses)

    def post(self, url: str, headers: Dict[str, str], json: Dict[str, Any]) -> _FakeResponse:
        self.calls.append({"url": url, "headers": headers, "json": json})
        return self._queue.pop(0)


def _structured_body(schema: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "max_tokens": 100,
        "system": "s",
        "messages": [{"role": "user", "content": "u"}],
        "tools": [{"name": "emit_result", "description": "d", "input_schema": schema}],
        "tool_choice": {"type": "tool", "name": "emit_result"},
    }


_VERDICT_SCHEMA = {
    "type": "object",
    "properties": {"vuln": {"type": "string", "enum": ["sqli", "none"]}},
    "required": ["vuln"],
}


def test_local_server_uses_json_schema_constrained_decoding(patch_http):
    # Ollama ignores a forced tool_choice for some models; constrained decoding
    # makes the server's grammar guarantee schema-valid JSON instead.
    fake = patch_http(_FakeResponse(200, {"choices": [{"message": {"content": '{"vuln": "sqli"}'}}]}))

    result = providers.invoke_openai(_structured_body(_VERDICT_SCHEMA), model_id="qwen2.5-coder:14b",
                                     api_key="", base_url="http://localhost:11434/v1")

    sent = fake.calls[0]["json"]
    assert sent["response_format"] == {
        "type": "json_schema",
        "json_schema": {"name": "emit_result", "schema": _VERDICT_SCHEMA},
    }
    assert "tools" not in sent and "tool_choice" not in sent
    # The JSON reply is re-shaped into the tool_use block the gateway expects.
    assert result["content"] == [{"type": "tool_use", "name": "emit_result", "input": {"vuln": "sqli"}}]


def test_public_openai_keeps_forced_tool_call(patch_http):
    fake = patch_http(_FakeResponse(200, {"choices": [{"message": {"content": "x"}}]}))
    providers.invoke_openai(_structured_body(_VERDICT_SCHEMA), model_id="gpt-4o",
                            api_key="k", base_url="https://api.openai.com/v1")
    sent = fake.calls[0]["json"]
    assert "response_format" not in sent
    assert sent["tool_choice"] == {"type": "function", "function": {"name": "emit_result"}}


def test_json_schema_rejected_falls_back_to_forced_tool(monkeypatch):
    rejected = _FakeResponse(400, {"error": {"message": "response_format json_schema not supported"}})
    accepted = _FakeResponse(200, {"choices": [{"message": {"content": None, "tool_calls": [
        {"function": {"name": "emit_result", "arguments": '{"vuln": "none"}'}}]}}]})
    fake = _QueuedHttpClient([rejected, accepted])
    monkeypatch.setattr(providers.httpx, "Client", lambda *a, **k: fake)

    result = providers.invoke_openai(_structured_body(_VERDICT_SCHEMA), model_id="m",
                                     api_key="", base_url="http://localhost:8000/v1")

    assert "response_format" in fake.calls[0]["json"]
    assert "tools" in fake.calls[1]["json"]
    assert result["content"][0]["input"] == {"vuln": "none"}


def test_structured_output_setting_forces_tools_on_local(patch_http, monkeypatch):
    from dast.config import settings
    monkeypatch.setattr(settings, "openai_structured_output", "tools")
    fake = patch_http(_FakeResponse(200, {"choices": [{"message": {"content": "x"}}]}))
    providers.invoke_openai(_structured_body(_VERDICT_SCHEMA), model_id="m",
                            api_key="", base_url="http://localhost:11434/v1")
    assert "tools" in fake.calls[0]["json"]
    assert "response_format" not in fake.calls[0]["json"]


def test_json_schema_non_json_reply_stays_text(patch_http):
    # Left as text so bedrock_client's repair + required-field checks still apply.
    patch_http(_FakeResponse(200, {"choices": [{"message": {"content": "not json"}}]}))
    result = providers.invoke_openai(_structured_body(_VERDICT_SCHEMA), model_id="m",
                                     api_key="", base_url="http://localhost:11434/v1")
    assert result["content"] == [{"type": "text", "text": "not json"}]


def test_local_server_gets_longer_read_timeout(monkeypatch):
    seen: Dict[str, Any] = {}
    fake = _FakeHttpClient(_FakeResponse(200, {"choices": [{"message": {"content": "x"}}]}))

    def _client(*args: Any, **kwargs: Any) -> _FakeHttpClient:
        seen["timeout"] = kwargs.get("timeout")
        return fake

    monkeypatch.setattr(providers.httpx, "Client", _client)
    providers.invoke_openai({"messages": []}, model_id="m", api_key="",
                            base_url="http://localhost:11434/v1")
    assert seen["timeout"].read == providers._LOCAL_HTTP_TIMEOUT.read
    providers.invoke_openai({"messages": []}, model_id="m", api_key="k",
                            base_url="https://api.openai.com/v1")
    assert seen["timeout"].read == providers._HTTP_TIMEOUT.read


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


def test_provider_key_present_true_for_local_openai_without_key(monkeypatch):
    """A local OpenAI base_url reports ready even with no API key set."""
    from dast.config import settings
    monkeypatch.setattr(settings, "openai_api_key", None)
    try:
        bedrock_client.set_provider(provider="openai", openai_api_key="",
                                    openai_base_url="http://localhost:11434/v1")
        assert bedrock_client.provider_api_key_present() is True
    finally:
        bedrock_client.set_provider(provider="bedrock")


def test_provider_key_present_false_for_public_openai_without_key(monkeypatch):
    """The public OpenAI API without a key is reported as not configured."""
    from dast.config import settings
    monkeypatch.setattr(settings, "openai_api_key", None)
    try:
        bedrock_client.set_provider(provider="openai", openai_api_key="",
                                    openai_base_url="https://api.openai.com/v1")
        assert bedrock_client.provider_api_key_present() is False
    finally:
        bedrock_client.set_provider(provider="bedrock")


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


# ── _invoke_external retry policy ────────────────────────────────────────────

def test_invoke_external_retries_on_5xx_then_succeeds(monkeypatch):
    calls = {"n": 0}
    envelope = {"content": [{"type": "text", "text": "ok"}]}

    def _flaky(**_):
        calls["n"] += 1
        if calls["n"] < 3:
            raise providers.ProviderError("Anthropic API 503: overloaded", status_code=503)
        return envelope

    monkeypatch.setattr(providers, "invoke_anthropic", _flaky)
    monkeypatch.setattr(bedrock_client.time, "sleep", lambda *_: None)  # no real backoff

    try:
        bedrock_client.set_provider("anthropic", anthropic_api_key="sk-ant-test")
        result = bedrock_client._invoke_external("anthropic", {"messages": []}, "m")
    finally:
        bedrock_client.set_provider(provider="bedrock")

    assert result == envelope
    assert calls["n"] == 3  # two 503s retried, third succeeds


def test_invoke_external_does_not_retry_on_4xx(monkeypatch):
    calls = {"n": 0}

    def _bad_request(**_):
        calls["n"] += 1
        raise providers.ProviderError("Anthropic API 400: bad body", status_code=400)

    monkeypatch.setattr(providers, "invoke_anthropic", _bad_request)
    monkeypatch.setattr(bedrock_client.time, "sleep", lambda *_: None)

    try:
        bedrock_client.set_provider("anthropic", anthropic_api_key="sk-ant-test")
        with pytest.raises(providers.ProviderError):
            bedrock_client._invoke_external("anthropic", {"messages": []}, "m")
    finally:
        bedrock_client.set_provider(provider="bedrock")

    assert calls["n"] == 1  # permanent error surfaced immediately, no retry
def test_openai_malformed_tool_arguments_are_not_turned_into_empty_object():
    from dast.ai.providers import _from_openai_response
    envelope = _from_openai_response({"choices": [{"message": {
        "tool_calls": [{"function": {"name": "emit_result", "arguments": "{not json"}}],
    }}]})
    assert not [b for b in envelope["content"] if b["type"] == "tool_use"]


# ── local provider detection + concurrency gate ──────────────────────────────

def test_is_local_provider_true_only_for_non_public_openai(monkeypatch):
    try:
        bedrock_client.set_provider("openai", openai_base_url="http://localhost:11434/v1")
        assert bedrock_client.is_local_provider() is True
        bedrock_client.set_provider("openai", openai_api_key="k",
                                    openai_base_url="https://api.openai.com/v1")
        assert bedrock_client.is_local_provider() is False
        bedrock_client.set_provider("anthropic", anthropic_api_key="sk-ant-test")
        assert bedrock_client.is_local_provider() is False
    finally:
        bedrock_client.set_provider(provider="bedrock")


def test_concurrency_limit_auto_is_one_for_local_and_unlimited_for_cloud(monkeypatch):
    from dast.config import settings
    monkeypatch.setattr(settings, "ai_max_concurrency", 0)
    monkeypatch.setattr(bedrock_client, "is_local_provider", lambda: True)
    assert bedrock_client._effective_concurrency_limit() == 1
    monkeypatch.setattr(bedrock_client, "is_local_provider", lambda: False)
    assert bedrock_client._effective_concurrency_limit() == 0
    monkeypatch.setattr(settings, "ai_max_concurrency", 3)
    assert bedrock_client._effective_concurrency_limit() == 3


def test_local_provider_calls_are_serialized(monkeypatch):
    # Parallel agents must not stack requests on a one-GPU local server: they
    # queue past the read timeout there. The gate lets one call through at a time.
    import threading
    import time as real_time

    from dast.config import settings
    monkeypatch.setattr(settings, "ai_max_concurrency", 0)
    monkeypatch.setattr(bedrock_client, "is_local_provider", lambda: True)

    state = {"active": 0, "peak": 0}
    guard = threading.Lock()

    def _slow_dispatch(provider, body, model):
        with guard:
            state["active"] += 1
            state["peak"] = max(state["peak"], state["active"])
        real_time.sleep(0.05)
        with guard:
            state["active"] -= 1
        return {"content": []}

    monkeypatch.setattr(bedrock_client, "_dispatch_external", _slow_dispatch)
    threads = [threading.Thread(target=bedrock_client._invoke_external,
                                args=("openai", {"messages": []}, "m")) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert state["peak"] == 1
