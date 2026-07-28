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
