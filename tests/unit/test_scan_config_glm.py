"""
Unit tests for the GLM provider round-trip through POST /api/scan-config.

Locks in: the glm fields are accepted (whitelisted in _provider_keys), routed
into set_provider so LLM calls dispatch to the GLM endpoint, and the API key is
never echoed back to the browser — only a *_set boolean.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from dast.ai import bedrock_client
from dast.proxy.api.settings_routes import make_router

_GLM_URL = "https://api.z.ai/api/paas/v4"


@dataclass
class _Ctx:
    settings: Optional[object] = None
    runner: Optional[object] = None
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 8080
    status_cache: dict = field(default_factory=dict)
    status_cache_ts: list = field(default_factory=lambda: [0.0])
    _scan_cfg: dict = field(default_factory=dict)


@pytest.fixture(autouse=True)
def _restore_provider():
    # set_provider mutates module-global state; keep tests isolated.
    yield
    bedrock_client.set_provider(provider="bedrock")


def _client(ctx: _Ctx) -> TestClient:
    app = FastAPI()
    app.include_router(make_router(ctx))
    return TestClient(app)


def _glm_ctx() -> _Ctx:
    # Seed the engine config the way ProxyRunner does at startup.
    ctx = _Ctx()
    ctx._scan_cfg.update({
        "ai_provider": "bedrock",
        "anthropic_api_key": "",
        "anthropic_base_url": "https://api.anthropic.com",
        "openai_api_key": "",
        "openai_base_url": "https://api.openai.com/v1",
        "glm_api_key": "",
        "glm_base_url": _GLM_URL,
        "gateway_base_url": "",
    })
    return ctx


def test_post_scan_config_switches_to_glm():
    ctx = _glm_ctx()
    response = _client(ctx).post("/api/scan-config", json={
        "ai_provider": "glm",
        "glm_api_key": "secret-glm-key",
        "glm_base_url": _GLM_URL,
    })
    assert response.status_code == 200
    assert bedrock_client.get_active_provider() == "glm"
    assert bedrock_client.provider_api_key_present() is True


def test_get_scan_config_masks_glm_key():
    ctx = _glm_ctx()
    _client(ctx).post("/api/scan-config", json={
        "ai_provider": "glm",
        "glm_api_key": "secret-glm-key",
        "glm_base_url": _GLM_URL,
    })
    body = _client(ctx).get("/api/scan-config").json()
    assert body["glm_api_key_set"] is True
    assert "glm_api_key" not in body or body.get("glm_api_key") in (None, "")
    assert body["glm_base_url"] == _GLM_URL


def test_post_scan_config_without_key_keeps_existing():
    # An absent key field must keep the stored one (the UI sends no key when the
    # password box is left blank); an explicit empty string clears it.
    ctx = _glm_ctx()
    client = _client(ctx)
    client.post("/api/scan-config", json={
        "ai_provider": "glm", "glm_api_key": "secret-glm-key", "glm_base_url": _GLM_URL})
    client.post("/api/scan-config", json={"ai_provider": "glm"})
    assert bedrock_client.get_active_provider() == "glm"
    assert bedrock_client.provider_api_key_present() is True
    client.post("/api/scan-config", json={"ai_provider": "glm", "glm_api_key": ""})
    assert bedrock_client.provider_api_key_present() is False


def test_unknown_provider_key_is_ignored():
    # A field outside _provider_keys must not break the request handling.
    ctx = _glm_ctx()
    response = _client(ctx).post("/api/scan-config", json={
        "ai_provider": "glm", "glm_base_url": _GLM_URL, "not_a_real_key": "x"})
    assert response.status_code == 200
