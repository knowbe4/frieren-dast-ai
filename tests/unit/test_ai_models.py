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


_BEDROCK_ARN = "arn:aws:bedrock:us-east-1:123456789012:application-inference-profile/abc123"


class TestTierModelProviderGuard:
    """A Bedrock ARN configured for a tier must never be sent to a non-Bedrock
    provider — the gateway rejects ARNs with HTTP 400, silently degrading every
    tier-helper AI call (flaky detection). It must fall back to the active model."""

    def teardown_method(self):
        bedrock_client.set_tiered_models("", "")
        bedrock_client.set_active_model("")

    def test_bedrock_keeps_arn_tiers(self):
        bedrock_client.set_provider("bedrock")
        bedrock_client.set_tiered_models(fast=_BEDROCK_ARN, validation=_BEDROCK_ARN)
        assert bedrock_client.get_fast_model() == _BEDROCK_ARN
        assert bedrock_client.get_validation_model() == _BEDROCK_ARN

    def test_gateway_drops_arn_tier_falls_back_to_active_model(self):
        bedrock_client.set_provider("gateway")
        bedrock_client.set_active_model("claude-sonnet-5")
        bedrock_client.set_tiered_models(fast=_BEDROCK_ARN, validation=_BEDROCK_ARN)
        # Both tier helpers must resolve to the gateway model name, not the ARN.
        assert bedrock_client.get_fast_model() == "claude-sonnet-5"
        assert bedrock_client.get_validation_model() == "claude-sonnet-5"

    def test_gateway_keeps_provider_appropriate_tier_name(self):
        bedrock_client.set_provider("gateway")
        bedrock_client.set_active_model("claude-sonnet-5")
        bedrock_client.set_tiered_models(fast="claude-haiku-4-5", validation="claude-opus-5")
        # A real model NAME for the provider is honoured, not overridden.
        assert bedrock_client.get_fast_model() == "claude-haiku-4-5"
        assert bedrock_client.get_validation_model() == "claude-opus-5"


class TestResolveModelProviderGuard:
    """The invoke boundary (_resolve_model) is the single choke point every LLM
    call funnels through. It must never hand a Bedrock ARN to a non-Bedrock
    provider — regardless of whether the ARN arrived via the tier/active fallback
    or an explicit model_id (the coordinator planner passes one directly). When no
    provider-appropriate model resolves, it fails loud (pauses AI) instead of
    silently degrading detection."""

    def teardown_method(self):
        bedrock_client.set_provider("bedrock")
        bedrock_client.set_tiered_models("", "")
        bedrock_client.set_active_model("")
        bedrock_client.mark_ai_available()

    def test_bedrock_arn_passes_through_under_bedrock(self):
        bedrock_client.set_provider("bedrock")
        bedrock_client.set_active_model(_BEDROCK_ARN)
        assert bedrock_client._resolve_model(None) == _BEDROCK_ARN
        assert bedrock_client._resolve_model(_BEDROCK_ARN) == _BEDROCK_ARN
        assert bedrock_client.is_ai_available()

    def test_gateway_explicit_arn_model_id_fails_loud(self):
        # The coordinator planner path: an ARN passed as an explicit model_id.
        bedrock_client.set_provider("gateway")
        bedrock_client.set_active_model("claude-sonnet-5")
        with pytest.raises(bedrock_client.AiUnavailableError) as exc:
            bedrock_client._resolve_model(_BEDROCK_ARN)
        assert "gateway" in str(exc.value)
        assert not bedrock_client.is_ai_available()  # AI paused, not degraded

    def test_gateway_arn_active_model_fallback_fails_loud(self):
        # The fallback path: no explicit model, and the active model is an ARN.
        bedrock_client.set_provider("gateway")
        bedrock_client.set_active_model(_BEDROCK_ARN)
        with pytest.raises(bedrock_client.AiUnavailableError):
            bedrock_client._resolve_model(None)
        assert not bedrock_client.is_ai_available()

    def test_gateway_no_model_configured_fails_loud(self):
        bedrock_client.set_provider("gateway")
        bedrock_client.set_active_model("")
        with pytest.raises(bedrock_client.AiUnavailableError):
            bedrock_client._resolve_model(None)

    def test_gateway_provider_name_resolves(self):
        bedrock_client.set_provider("gateway")
        bedrock_client.set_active_model("claude-sonnet-5")
        assert bedrock_client._resolve_model(None) == "claude-sonnet-5"
        assert bedrock_client._resolve_model("claude-haiku-4-5") == "claude-haiku-4-5"
        assert bedrock_client.is_ai_available()
