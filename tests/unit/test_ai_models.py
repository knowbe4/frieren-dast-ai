"""
Unit tests for provider-aware model listing (dast.ai.bedrock_client.list_models).

The Settings dropdowns must show the ACTIVE provider's models — not a static
Claude preset list for every provider. list_models() dispatches per provider and
degrades to presets (never raises) when a live catalogue is unavailable.
"""

from __future__ import annotations

import pytest

from dast.ai import bedrock_client, providers


@pytest.fixture(autouse=True)
def _reset_provider():
    # Each test sets its own provider; restore bedrock afterwards so global
    # module state does not leak between tests.
    yield
    bedrock_client.set_provider("bedrock")


class TestListModels:
    def test_bedrock_returns_static_presets(self):
        bedrock_client.set_provider("bedrock")
        result = bedrock_client.list_models()
        assert result["provider"] == "bedrock"
        assert result["source"] == "preset"
        assert result["error"] == ""
        assert len(result["models"]) == 3
        assert all("id" in m and "label" in m for m in result["models"])

    def test_openai_without_key_falls_back_to_presets_with_error(self):
        # No API key configured → provider call raises → graceful preset fallback.
        bedrock_client.set_provider("openai")
        result = bedrock_client.list_models()
        assert result["provider"] == "openai"
        assert result["source"] == "preset"
        assert result["error"]  # a non-empty explanation is surfaced

    def test_live_catalogue_is_used_when_available(self, monkeypatch):
        fake_models = [
            {"id": "gpt-4o", "label": "gpt-4o"},
            {"id": "gpt-4o-mini", "label": "gpt-4o-mini"},
        ]
        monkeypatch.setattr(providers, "list_openai_models", lambda **_: fake_models)
        bedrock_client.set_provider("openai", openai_api_key="sk-test")
        result = bedrock_client.list_models()
        assert result["source"] == "live"
        assert result["error"] == ""
        assert result["models"] == fake_models

    def test_empty_live_result_falls_back_to_presets(self, monkeypatch):
        # A provider that returns no models is treated as "no live catalogue".
        monkeypatch.setattr(providers, "list_anthropic_models", lambda **_: [])
        bedrock_client.set_provider("anthropic", anthropic_api_key="sk-ant-test")
        result = bedrock_client.list_models()
        assert result["source"] == "preset"

    def test_provider_exception_never_propagates(self, monkeypatch):
        def _boom(**_):
            raise providers.ProviderError("network down")

        monkeypatch.setattr(providers, "list_gateway_models", _boom)
        bedrock_client.set_provider("gateway")
        result = bedrock_client.list_models()  # must not raise
        assert result["source"] == "preset"
        assert "network down" in result["error"]
