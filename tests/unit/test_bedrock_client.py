"""
Unit tests for the Bedrock client gateway — structured tool-use output,
repair-retry on malformed JSON, and temperature/cache request-body wiring.

All tests mock the boto3 client so no AWS calls are made. The mock captures
the request body sent to invoke_model so we can assert on its shape.
"""

from __future__ import annotations

import io
import json
from typing import Any, Dict, List

import pytest

from dast.ai import bedrock_client


class _FakeResponseBody:
    """Mimics the botocore StreamingBody returned under response['body']."""

    def __init__(self, payload: Dict[str, Any]) -> None:
        self._buf = io.BytesIO(json.dumps(payload).encode())

    def read(self) -> bytes:
        return self._buf.read()


class _FakeBedrockClient:
    """
    Fake bedrock-runtime client. Returns queued responses in order and records
    every request body it was called with.
    """

    def __init__(self, responses: List[Dict[str, Any]]) -> None:
        self._responses = list(responses)
        self.bodies: List[Dict[str, Any]] = []

    def invoke_model(self, modelId: str, body: str) -> Dict[str, Any]:
        self.bodies.append(json.loads(body))
        payload = self._responses.pop(0)
        return {"body": _FakeResponseBody(payload)}


def _text_response(text: str) -> Dict[str, Any]:
    return {"content": [{"type": "text", "text": text}]}


def _tool_response(tool_input: Dict[str, Any]) -> Dict[str, Any]:
    return {"content": [{"type": "tool_use", "name": "emit_result", "input": tool_input}]}


@pytest.fixture
def install_fake_client(monkeypatch):
    """Install a fake client and return a setter that queues its responses."""
    def _install(responses: List[Dict[str, Any]]) -> _FakeBedrockClient:
        fake = _FakeBedrockClient(responses)
        monkeypatch.setattr(bedrock_client, "get_client", lambda: fake)
        monkeypatch.setattr(bedrock_client, "get_active_model", lambda: "test-model")
        return fake
    return _install


# ── structured tool-use path ────────────────────────────────────────────────

def test_schema_forces_tool_use_and_returns_input(install_fake_client):
    schema = {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]}
    fake = install_fake_client([_tool_response({"ok": True})])

    result = bedrock_client.invoke_json("sys", "user", schema=schema)

    assert result == {"ok": True}
    body = fake.bodies[0]
    # tool + forced tool_choice must be present
    assert body["tools"][0]["name"] == "emit_result"
    assert body["tools"][0]["input_schema"] == schema
    assert body["tool_choice"] == {"type": "tool", "name": "emit_result"}


def test_structured_path_falls_back_to_text_when_no_tool_block(install_fake_client):
    schema = {"type": "object", "properties": {"ok": {"type": "boolean"}}}
    install_fake_client([_text_response('{"ok": false}')])

    result = bedrock_client.invoke_json("sys", "user", schema=schema)

    assert result == {"ok": False}


def test_structured_path_repairs_prose_from_local_model(install_fake_client, caplog):
    # A local OpenAI-compatible server (Ollama etc.) that ignores forced
    # tool_choice and answers with prose used to hard-fail with an uncaught
    # JSONDecodeError. It must now repair once and still return a dict.
    schema = {"type": "object", "properties": {"ok": {"type": "boolean"}}}
    fake = install_fake_client([
        _text_response("Sure! Here is the analysis you asked for: not json at all."),
        _text_response('{"ok": true}'),
    ])

    with caplog.at_level("WARNING"):
        result = bedrock_client.invoke_json("sys", "user", schema=schema)

    assert result == {"ok": True}
    assert len(fake.bodies) == 2  # original structured call + one text repair


def test_structured_path_repairs_when_response_has_no_text_block(install_fake_client):
    # A tool-only / empty envelope with no text block must not raise (KeyError)
    # on the fallback — it degrades to a repair round-trip instead.
    schema = {"type": "object", "properties": {"ok": {"type": "boolean"}}}
    fake = install_fake_client([
        {"content": []},
        _text_response('{"ok": false}'),
    ])

    result = bedrock_client.invoke_json("sys", "user", schema=schema)

    assert result == {"ok": False}
    assert len(fake.bodies) == 2


def test_structured_path_falls_back_when_tool_use_unsupported(monkeypatch):
    # A tool-less local model (e.g. codellama on Ollama) returns HTTP 400
    # "does not support tools" for a forced tool_choice. The schema call must
    # degrade to a plain-text JSON call rather than hard-failing.
    from dast.ai import providers

    calls = {"schema": 0, "text": 0}

    def fake_invoke_raw(*, schema=None, **kwargs):
        if schema is not None:
            calls["schema"] += 1
            raise providers.ProviderError(
                'OpenAI API 400: {"error":{"message":"model does not support tools"}}',
                status_code=400,
            )
        calls["text"] += 1
        return _text_response('{"verdict": "VULNERABLE"}')

    monkeypatch.setattr(bedrock_client, "_invoke_raw", fake_invoke_raw)

    result = bedrock_client.invoke_json("sys", "user", schema={"type": "object"})

    assert result == {"verdict": "VULNERABLE"}
    assert calls == {"schema": 1, "text": 1}  # forced tool-use rejected, then text


def test_structured_path_reraises_unrelated_400(monkeypatch):
    # A 400 that is NOT about tools/functions is a genuine bad request and must
    # surface, not be silently retried as text.
    from dast.ai import providers

    def fake_invoke_raw(*, schema=None, **kwargs):
        raise providers.ProviderError(
            'OpenAI API 400: {"error":{"message":"invalid request body"}}',
            status_code=400,
        )

    monkeypatch.setattr(bedrock_client, "_invoke_raw", fake_invoke_raw)

    with pytest.raises(providers.ProviderError):
        bedrock_client.invoke_json("sys", "user", schema={"type": "object"})


# ── function call written out as text (Ollama / llama.cpp) ───────────────────

_OK_SCHEMA = {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]}


def test_text_tool_call_wrapper_is_unwrapped(install_fake_client):
    # Ollama with Qwen ignores forced tool_choice and puts the call in the text
    # content. The caller must get the decision, not the {name, arguments} wrapper.
    install_fake_client([_text_response('{"name": "emit_result", "arguments": {"ok": true}}')])

    result = bedrock_client.invoke_json("sys", "user", schema=_OK_SCHEMA)

    assert result == {"ok": True}


def test_text_tool_call_with_string_arguments_is_unwrapped(install_fake_client):
    install_fake_client([_text_response('{"name": "emit_result", "arguments": "{\\"ok\\": false}"}')])

    result = bedrock_client.invoke_json("sys", "user", schema=_OK_SCHEMA)

    assert result == {"ok": False}


def test_text_tool_call_wrapper_unwrapped_when_schema_has_no_required(install_fake_client):
    schema = {"type": "object", "properties": {"ok": {"type": "boolean"}}}
    install_fake_client([_text_response('{"name": "emit_result", "parameters": {"ok": true}}')])

    result = bedrock_client.invoke_json("sys", "user", schema=schema)

    assert result == {"ok": True}


def test_text_output_missing_required_field_raises(install_fake_client):
    # Previously the text path returned whatever JSON it parsed, so a wrong shape
    # was read by the caller as an empty decision. It must now fail loudly.
    install_fake_client([_text_response('{"verdict": "VULNERABLE"}')])

    with pytest.raises(ValueError, match="missing required field"):
        bedrock_client.invoke_json("sys", "user", schema=_OK_SCHEMA)


def test_text_call_to_a_different_tool_is_not_unwrapped(install_fake_client):
    # The model called some other tool directly (seen with the copilot: it emitted
    # browser_snapshot instead of the step schema). Those are another tool's
    # arguments — they must not be passed off as this schema's object.
    install_fake_client([_text_response('{"name": "browser_snapshot", "arguments": {"ok": true}}')])

    with pytest.raises(ValueError, match="missing required field"):
        bedrock_client.invoke_json("sys", "user", schema=_OK_SCHEMA)


def test_schema_declaring_wrapper_keys_is_not_unwrapped(install_fake_client):
    schema = {
        "type": "object",
        "properties": {"name": {"type": "string"}, "arguments": {"type": "object"}},
        "required": ["name", "arguments"],
    }
    text = '{"name": "tool_x", "arguments": {"a": 1}}'
    install_fake_client([_text_response(text)])

    result = bedrock_client.invoke_json("sys", "user", schema=schema)

    assert result == {"name": "tool_x", "arguments": {"a": 1}}


def test_text_json_fallback_unwraps_tool_call_after_tool_use_rejected(monkeypatch):
    # The "does not support tools" 400 path re-asks for plain JSON; a model that
    # still answers in function-call shape must be unwrapped there too.
    from dast.ai import providers

    def fake_invoke_raw(*, schema=None, **kwargs):
        if schema is not None:
            raise providers.ProviderError(
                'OpenAI API 400: {"error":{"message":"model does not support tools"}}',
                status_code=400,
            )
        return _text_response('{"name": "emit_result", "arguments": {"ok": true}}')

    monkeypatch.setattr(bedrock_client, "_invoke_raw", fake_invoke_raw)

    result = bedrock_client.invoke_json("sys", "user", schema=_OK_SCHEMA)

    assert result == {"ok": True}


# ── repair-retry on malformed JSON (legacy path) ──────────────────────────────

def test_repair_retry_recovers_from_malformed_json(install_fake_client, caplog):
    fake = install_fake_client([
        _text_response("here you go: {oops not json"),
        _text_response('{"recovered": true}'),
    ])

    with caplog.at_level("WARNING"):
        result = bedrock_client.invoke_json("sys asking json", "user")

    assert result == {"recovered": True}
    assert len(fake.bodies) == 2  # original + one repair attempt


def test_legacy_path_parses_valid_json_without_retry(install_fake_client):
    fake = install_fake_client([_text_response('{"value": 7}')])

    result = bedrock_client.invoke_json("sys json", "user")

    assert result == {"value": 7}
    assert len(fake.bodies) == 1


# ── temperature + cache wiring ────────────────────────────────────────────────

def test_temperature_added_to_body_when_set(install_fake_client):
    fake = install_fake_client([_tool_response({"ok": True})])

    bedrock_client.invoke_json("sys", "user", schema={"type": "object"}, temperature=0)

    assert fake.bodies[0]["temperature"] == 0


def test_temperature_omitted_when_not_set(install_fake_client):
    fake = install_fake_client([_text_response('{"ok": true}')])

    bedrock_client.invoke_json("sys json", "user")

    assert "temperature" not in fake.bodies[0]


def test_cache_system_shapes_system_as_content_block(install_fake_client):
    fake = install_fake_client([_text_response('{"ok": true}')])

    bedrock_client.invoke_json("big static prompt json", "user", cache_system=True)

    system = fake.bodies[0]["system"]
    assert isinstance(system, list)
    assert system[0]["cache_control"] == {"type": "ephemeral"}
    assert system[0]["text"] == "big static prompt json"


def test_legacy_system_stays_plain_string(install_fake_client):
    fake = install_fake_client([_text_response('{"ok": true}')])

    bedrock_client.invoke_json("plain json", "user")

    assert isinstance(fake.bodies[0]["system"], str)
    assert "tools" not in fake.bodies[0]


def test_structured_output_missing_required_field_raises(install_fake_client):
    install_fake_client([_tool_response({"agents": []})])
    schema = {"type": "object", "properties": {"agents": {}, "reason": {}}, "required": ["agents", "reason"]}
    with pytest.raises(ValueError, match="reason"):
        bedrock_client.invoke_json(system="s", user="u", schema=schema)


_PAYLOADS_SCHEMA = {
    "type": "object",
    "properties": {"payloads": {"type": "array", "items": {"type": "object"}}},
    "required": ["payloads"],
}


def test_array_field_sent_as_json_string_is_decoded(install_fake_client):
    # Seen with the gateway provider: the tool-call argument typed `array` held the
    # JSON text of the array. Callers iterated it character by character.
    install_fake_client([_tool_response({"payloads": '[{"value": "a"}, {"value": "b"}]'})])

    result = bedrock_client.invoke_json("sys", "user", schema=_PAYLOADS_SCHEMA)

    assert result == {"payloads": [{"value": "a"}, {"value": "b"}]}


def test_string_that_is_not_the_declared_container_is_left_alone(install_fake_client):
    install_fake_client([_tool_response({"payloads": '{"value": "a"}'})])

    result = bedrock_client.invoke_json("sys", "user", schema=_PAYLOADS_SCHEMA)

    assert result == {"payloads": '{"value": "a"}'}


def test_string_typed_field_holding_json_is_not_decoded(install_fake_client):
    schema = {"type": "object", "properties": {"note": {"type": "string"}}, "required": ["note"]}
    install_fake_client([_tool_response({"note": "[1, 2]"})])

    result = bedrock_client.invoke_json("sys", "user", schema=schema)

    assert result == {"note": "[1, 2]"}


# ── multimodal / image input (vision navigator) ──────────────────────────────

def test_invoke_json_sends_image_block(install_fake_client):
    fake = install_fake_client([_tool_response({"elements": []})])
    schema = {"type": "object", "properties": {"elements": {"type": "array"}}, "required": ["elements"]}
    bedrock_client.invoke_json("sys", "find nav", schema=schema, image_b64="QUJD", temperature=0)
    content = fake.bodies[0]["messages"][0]["content"]
    assert isinstance(content, list)
    kinds = {block["type"] for block in content}
    assert kinds == {"text", "image"}
    img = next(b for b in content if b["type"] == "image")
    assert img["source"] == {"type": "base64", "media_type": "image/png", "data": "QUJD"}


def test_text_only_call_keeps_string_content(install_fake_client):
    fake = install_fake_client([_text_response("hi")])
    bedrock_client.invoke("sys", "hello")
    assert fake.bodies[0]["messages"][0]["content"] == "hello"  # unchanged shape


def test_image_rejected_for_openai_provider(monkeypatch):
    monkeypatch.setattr(bedrock_client, "get_active_provider", lambda: "openai")
    monkeypatch.setattr(bedrock_client, "get_active_model", lambda: "gpt-x")
    with pytest.raises(ValueError, match="image input is not supported"):
        bedrock_client.invoke("sys", "u", image_b64="QUJD")


# -- Tier model resolution under non-Bedrock providers --


@pytest.fixture
def _gateway_provider(monkeypatch):
    """Switch to gateway and set ARN-based tier defaults (the startup path)."""
    monkeypatch.setattr(bedrock_client, "_active_provider", "gateway")
    monkeypatch.setattr(bedrock_client, "_fast_model_id",
                        "arn:aws:bedrock:us-east-1:123:application-inference-profile/haiku")
    monkeypatch.setattr(bedrock_client, "_validation_model_id",
                        "arn:aws:bedrock:us-east-1:123:application-inference-profile/opus")
    monkeypatch.setattr(bedrock_client, "_default_model_cache", {})
    yield


def _fake_catalogue_with_tiers():
    return {"provider": "gateway", "source": "live", "error": "",
            "models": [
                {"id": "claude-sonnet-4-20250514", "label": "Claude Sonnet"},
                {"id": "claude-haiku-4-5-20250514", "label": "Claude Haiku"},
                {"id": "claude-opus-4-20250514", "label": "Claude Opus"},
            ]}


def test_fast_tier_resolves_haiku_under_gateway(_gateway_provider, monkeypatch):
    monkeypatch.setattr(bedrock_client, "list_models", _fake_catalogue_with_tiers)
    model = bedrock_client.get_fast_model()
    assert "haiku" in model.lower()


def test_validation_tier_resolves_opus_under_gateway(_gateway_provider, monkeypatch):
    monkeypatch.setattr(bedrock_client, "list_models", _fake_catalogue_with_tiers)
    model = bedrock_client.get_validation_model()
    assert "opus" in model.lower()


def test_tier_falls_back_to_active_when_catalogue_empty(_gateway_provider, monkeypatch):
    monkeypatch.setattr(bedrock_client, "list_models",
                        lambda: {"provider": "gateway", "models": [], "source": "preset", "error": ""})
    monkeypatch.setattr(bedrock_client, "get_active_model", lambda: "claude-sonnet-fallback")
    model = bedrock_client.get_fast_model()
    assert model == "claude-sonnet-fallback"


def test_tier_resolution_reuses_cached_catalogue(_gateway_provider, monkeypatch):
    call_count = [0]
    def _counting_list():
        call_count[0] += 1
        return _fake_catalogue_with_tiers()
    monkeypatch.setattr(bedrock_client, "list_models", _counting_list)
    bedrock_client.get_fast_model()
    bedrock_client.get_validation_model()
    assert call_count[0] == 1
