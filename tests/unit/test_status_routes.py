"""
Unit tests for GET /api/status — AI reachability reporting.

The regression these lock in: the endpoint must probe the provider that actually
serves LLM calls. For a non-Bedrock provider (anthropic/openai) it must NOT run an
AWS STS probe (which would always fail and wrongly report "offline" while the AI is
fully working — the bug where an AI-validated finding coexisted with an "offline"
badge). It must also never report "connected" once the validator's sticky
availability flag has been tripped.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from fastapi import FastAPI
from fastapi.testclient import TestClient

from dast.ai import bedrock_client
from dast.proxy.api.status_routes import make_router


@dataclass
class _Ctx:
    status_cache: dict = field(default_factory=dict)
    status_cache_ts: list = field(default_factory=lambda: [0.0])
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 8080


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(make_router(_Ctx()))
    return TestClient(app)


def _reset_provider():
    bedrock_client.set_provider("bedrock")  # also clears the unavailable flag


def test_anthropic_provider_with_key_is_online_without_sts(monkeypatch):
    # A non-Bedrock provider must not depend on AWS STS at all.
    def _boom(*a, **k):
        raise AssertionError("STS must not be probed for a non-bedrock provider")

    import boto3
    monkeypatch.setattr(boto3, "Session", _boom)
    bedrock_client.set_provider("anthropic", anthropic_api_key="sk-ant-test")
    try:
        resp = _client().get("/api/status")
        body = resp.json()
        assert body["ai_enabled"] is True
    finally:
        _reset_provider()


def test_anthropic_provider_without_key_is_offline(monkeypatch):
    monkeypatch.setattr(bedrock_client, "provider_api_key_present", lambda: False)
    bedrock_client.set_provider("anthropic", anthropic_api_key="")
    try:
        body = _client().get("/api/status").json()
        assert body["ai_enabled"] is False
        assert "anthropic" in (body.get("ai_error") or "")
    finally:
        _reset_provider()


def test_gateway_provider_online_when_credentials_available(monkeypatch):
    # The gateway has no API key: reachability tracks a usable CLI OAuth session,
    # and it must never probe AWS STS.
    def _boom(*a, **k):
        raise AssertionError("STS must not be probed for the gateway provider")

    import boto3
    monkeypatch.setattr(boto3, "Session", _boom)
    from dast.ai import gateway_auth
    monkeypatch.setattr(gateway_auth, "credentials_available", lambda: True)
    bedrock_client.set_provider("gateway", gateway_base_url="https://gw.example")
    try:
        body = _client().get("/api/status").json()
        assert body["ai_enabled"] is True
    finally:
        _reset_provider()


def test_gateway_provider_offline_without_session(monkeypatch):
    from dast.ai import gateway_auth
    monkeypatch.setattr(gateway_auth, "credentials_available", lambda: False)
    bedrock_client.set_provider("gateway", gateway_base_url="https://gw.example")
    try:
        body = _client().get("/api/status").json()
        assert body["ai_enabled"] is False
    finally:
        _reset_provider()


def test_sticky_unavailable_flag_forces_offline_even_with_key(monkeypatch):
    bedrock_client.set_provider("anthropic", anthropic_api_key="sk-ant-test")
    bedrock_client.mark_ai_unavailable()
    try:
        body = _client().get("/api/status").json()
        assert body["ai_enabled"] is False
    finally:
        _reset_provider()


def test_boot_id_is_returned_and_stable_within_process():
    # The dashboard stamps every persisted session id with this value so a stale
    # session from another run/project is never silently resumed. It must be a
    # non-empty string and identical on every call within the same process.
    client = _client()
    first = client.get("/api/boot-id").json()
    assert isinstance(first.get("boot_id"), str)
    assert first["boot_id"]
    second = client.get("/api/boot-id").json()
    assert second["boot_id"] == first["boot_id"]
