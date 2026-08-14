"""
Startup smoke tests for ProxyRunner's AI-provider wiring.

These guard the exact gap that let an AttributeError reach `make desktop`: the
provider fields live on the pydantic config.settings, but ProxyRunner._settings
is a ProxySettings (scope/bypass only). Reading them off the wrong object raised
at construction time — a path no other test exercised because nothing else
instantiates ProxyRunner.

We construct the runner (as cli.py does) and drive set_provider() the way run()
does at startup, for every provider, asserting no attribute/name errors and that
the engine config carries the provider config the dashboard reads back.
"""

from __future__ import annotations

import pytest

from dast.ai import bedrock_client
from dast.config import settings
from dast.proxy.runner import ProxyRunner


def _make_runner() -> ProxyRunner:
    return ProxyRunner(
        proxy_port=8080,
        dashboard_port=8088,
        workers=2,
        iterations=3,
        confidence=0.5,
        attack_types=None,
        output_dir=None,
        auth_url=None,
        username=None,
        password=None,
        ai_model_id=settings.ai_model_id,
    )


@pytest.fixture(autouse=True)
def _restore_provider_state():
    """Keep provider state (a module global + settings.ai_provider) isolated."""
    original_provider = settings.ai_provider
    yield
    settings.ai_provider = original_provider
    bedrock_client.set_provider(provider="bedrock")


def test_engine_config_carries_provider_fields():
    runner = _make_runner()
    config = runner._engine_config
    for key in (
        "ai_provider",
        "anthropic_api_key",
        "anthropic_base_url",
        "openai_api_key",
        "openai_base_url",
        "gateway_base_url",
    ):
        assert key in config, f"engine_config missing {key}"
    # Base URLs default to the public endpoints (not empty).
    assert config["anthropic_base_url"]
    assert config["openai_base_url"]


@pytest.mark.parametrize("provider", ["bedrock", "anthropic", "openai", "gateway"])
def test_startup_set_provider_does_not_raise(provider):
    """Replicates run()'s startup call for each provider — must not raise."""
    settings.ai_provider = provider
    runner = _make_runner()
    assert runner._engine_config["ai_provider"] == provider

    # Exactly what ProxyRunner.run() does after construction.
    bedrock_client.set_provider(
        provider=runner._engine_config.get("ai_provider", ""),
        anthropic_api_key=runner._engine_config.get("anthropic_api_key", ""),
        anthropic_base_url=runner._engine_config.get("anthropic_base_url", ""),
        openai_api_key=runner._engine_config.get("openai_api_key", ""),
        openai_base_url=runner._engine_config.get("openai_base_url", ""),
        gateway_base_url=runner._engine_config.get("gateway_base_url", ""),
    )
    assert bedrock_client.get_active_provider() == provider
