"""Provider failover tests (dast/ai/bedrock_client.py + dast/ai/provider_health.py).

All tests stub ``bedrock_client._invoke_one`` — the single point where a request
reaches a NAMED provider — so no network is touched. They pin the contract of the
provider-level walk in ``_invoke_raw``: fail over on provider-level failures,
promote the survivor (sticky, preserving runtime credentials), never fail over on
content blocks or caller ValueErrors, and honor the health-registry cooldowns."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple
from unittest.mock import MagicMock

import pytest

from dast.ai import bedrock_client, provider_health
from dast.config import settings

_OK_ENVELOPE: Dict[str, Any] = {
    "content": [{"type": "text", "text": "hi"}], "usage": {},
}


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    """Fresh health registry + deterministic provider globals; the catalogue
    default resolver is stubbed so a failover never fetches a live catalogue."""
    provider_health.reset()
    monkeypatch.setattr(bedrock_client, "_ai_unavailable", False)
    monkeypatch.setattr(bedrock_client, "_active_provider", "")
    monkeypatch.setattr(bedrock_client, "_active_model_id", "test-model")
    monkeypatch.setattr(bedrock_client, "_anthropic_api_key", "")
    monkeypatch.setattr(bedrock_client, "_openai_api_key", "")
    monkeypatch.setattr(bedrock_client, "_glm_api_key", "")
    monkeypatch.setattr(bedrock_client, "_resolve_default_model",
                        lambda provider: f"{provider}-default")
    # A dev machine's real .env may carry provider keys — chain composition
    # tests must not depend on that, so pin the chain setting to the default.
    monkeypatch.setattr(settings, "ai_failover_chain", "")
    yield
    provider_health.reset()


def _install_invoke(monkeypatch, behavior):
    """Replace _invoke_one with a scripted dispatcher. ``behavior(provider, model)``
    returns a result or raises. Returns the list of (provider, model) calls made."""
    calls: List[Tuple[str, str]] = []

    def fake_invoke(provider: str, body: Dict[str, Any], model: str) -> Dict[str, Any]:
        calls.append((provider, model))
        return behavior(provider, model)

    monkeypatch.setattr(bedrock_client, "_invoke_one", fake_invoke)
    return calls


def _invoke_raw():
    return bedrock_client._invoke_raw(
        system="sys", user="user", model_id=None, max_tokens=100,
        temperature=0, cache_system=False, schema=None,
    )


def _expire_aws(monkeypatch):
    """Make the bedrock provider fail the way SSO exhaustion does (marking AI
    unavailable first, exactly like _invoke_one's retry-exhausted path)."""
    def behavior(provider: str, model: str) -> Dict[str, Any]:
        if provider == "bedrock":
            bedrock_client.mark_ai_unavailable()
            raise bedrock_client.AiUnavailableError("AWS credentials expired")
        return _OK_ENVELOPE
    return behavior


# ── failover + promotion ─────────────────────────────────────────────────────

def test_failover_promotes_healthy_provider(monkeypatch):
    monkeypatch.setattr(settings, "anthropic_api_key", "sk-test")
    calls = _install_invoke(monkeypatch, _expire_aws(monkeypatch))

    result = _invoke_raw()

    assert result == _OK_ENVELOPE
    assert [p for p, _m in calls] == ["bedrock", "anthropic"]
    # Sticky: the survivor is now the active provider and AI is re-enabled.
    assert bedrock_client.get_active_provider() == "anthropic"
    assert bedrock_client.is_ai_available()
    # The failed provider's streak is recorded, the survivor's cleared.
    assert provider_health.failure_streak("bedrock") == 1
    assert provider_health.failure_streak("anthropic") == 0


def test_promotion_preserves_runtime_credentials_and_heals_arn(monkeypatch):
    # set_provider() would wipe a runtime key not passed again; promotion must
    # keep it. A carried-over Bedrock ARN is healed to the provider's default.
    monkeypatch.setattr(bedrock_client, "_anthropic_api_key", "sk-runtime")
    monkeypatch.setattr(bedrock_client, "_active_model_id",
                        "arn:aws:bedrock:us-east-1:123:profile/x")
    monkeypatch.setattr(settings, "anthropic_api_key", "sk-test")
    _install_invoke(monkeypatch, _expire_aws(monkeypatch))

    _invoke_raw()

    assert bedrock_client.get_active_provider() == "anthropic"
    assert bedrock_client._anthropic_api_key == "sk-runtime"
    assert bedrock_client._active_model_id == "anthropic-default"


def test_failover_uses_provider_appropriate_model(monkeypatch):
    monkeypatch.setattr(settings, "anthropic_api_key", "sk-test")
    calls = _install_invoke(monkeypatch, _expire_aws(monkeypatch))

    _invoke_raw()

    # The anthropic attempts carry a NAME (its requested name, then its own
    # catalogue default) — never a Bedrock-only ARN.
    anthropic_models = [m for p, m in calls if p == "anthropic"]
    assert anthropic_models and all(not m.startswith("arn:") for m in anthropic_models)


# ── what must NOT fail over ──────────────────────────────────────────────────

def test_content_block_never_fails_over(monkeypatch):
    monkeypatch.setattr(settings, "anthropic_api_key", "sk-test")

    def blocked(provider: str, model: str) -> Dict[str, Any]:
        raise bedrock_client.AiContentBlockedError("blocked by safety classifier")

    calls = _install_invoke(monkeypatch, blocked)

    with pytest.raises(bedrock_client.AiContentBlockedError):
        _invoke_raw()

    assert len(calls) == 1  # no second provider tried
    assert bedrock_client.get_active_provider() == "bedrock"  # no promotion
    assert provider_health.failure_streak("bedrock") == 0  # not a health signal


def test_value_error_never_fails_over(monkeypatch):
    monkeypatch.setattr(settings, "anthropic_api_key", "sk-test")

    def bad_input(provider: str, model: str) -> Dict[str, Any]:
        raise ValueError("caller misuse")

    calls = _install_invoke(monkeypatch, bad_input)

    with pytest.raises(ValueError):
        _invoke_raw()
    assert len(calls) == 1


# ── chain construction: credentials + cooldowns ──────────────────────────────

def test_unconfigured_providers_are_skipped(monkeypatch):
    # No fallback member has usable credentials (regardless of what a local
    # .env carries): the auto chain collapses to bedrock, whose failure
    # propagates unchanged (the pre-failover behavior).
    monkeypatch.setattr(bedrock_client, "provider_ready",
                        lambda p: p == "bedrock")
    calls = _install_invoke(monkeypatch, _expire_aws(monkeypatch))

    with pytest.raises(bedrock_client.AiUnavailableError):
        _invoke_raw()

    assert [p for p, _m in calls] == ["bedrock"]
    assert bedrock_client.get_active_provider() == "bedrock"


def test_env_chain_override_is_honored(monkeypatch):
    monkeypatch.setattr(settings, "anthropic_api_key", "sk-test")
    monkeypatch.setattr(settings, "glm_api_key", "glm-key")
    monkeypatch.setattr(settings, "ai_failover_chain", "glm")

    calls = _install_invoke(monkeypatch, _expire_aws(monkeypatch))
    _invoke_raw()

    # Exactly the configured chain — anthropic is configured but NOT in it.
    assert [p for p, _m in calls] == ["bedrock", "glm"]


def test_cooldown_skips_failing_provider_and_still_fails_open(monkeypatch):
    monkeypatch.setattr(settings, "anthropic_api_key", "sk-test")
    # bedrock hit the failure threshold -> cooling; the chain must LEAD with the
    # healthy provider so this call doesn't re-pay bedrock's retry+backoff.
    for _ in range(3):
        provider_health.record_failure("bedrock", "expired")
    calls = _install_invoke(monkeypatch, _expire_aws(monkeypatch))

    result = _invoke_raw()

    assert result == _OK_ENVELOPE
    assert [p for p, _m in calls] == ["anthropic"]
    assert bedrock_client.get_active_provider() == "anthropic"


def test_everyone_cooling_collapses_to_active(monkeypatch):
    monkeypatch.setattr(settings, "anthropic_api_key", "sk-test")
    # Every chain member counts as configured (isolating the cooldown behavior
    # from whatever keys the local .env carries), and every one of them is
    # cooling down.
    monkeypatch.setattr(bedrock_client, "provider_ready", lambda p: True)
    for name in ("bedrock", "anthropic", "glm"):
        for _ in range(3):
            provider_health.record_failure(name, "down")

    calls = _install_invoke(monkeypatch, _expire_aws(monkeypatch))

    # Fail-open: with every member cooling, only the active provider is tried.
    with pytest.raises(bedrock_client.AiUnavailableError):
        _invoke_raw()
    assert [p for p, _m in calls] == ["bedrock"]


def test_success_resets_failure_streak(monkeypatch):
    provider_health.record_failure("bedrock", "blip")
    provider_health.record_failure("bedrock", "blip")
    provider_health.record_success("bedrock")
    assert provider_health.failure_streak("bedrock") == 0
    assert provider_health.is_healthy("bedrock")


# ── health registry surface (dashboard payload) ──────────────────────────────

def test_snapshot_shape_below_and_above_threshold():
    snap = provider_health.snapshot(["bedrock", "never-seen"])
    assert snap["bedrock"] == {"healthy": True, "cooldown_remaining_s": 0.0,
                               "consecutive_failures": 0, "last_error": ""}
    assert snap["never-seen"]["healthy"] is True

    for _ in range(3):
        provider_health.record_failure("bedrock", "sso expired")
    snap = provider_health.snapshot(["bedrock"])
    assert snap["bedrock"]["healthy"] is False
    assert snap["bedrock"]["consecutive_failures"] == 3
    assert snap["bedrock"]["cooldown_remaining_s"] > 0
    assert snap["bedrock"]["last_error"] == "sso expired"


def test_cooldown_widens_and_caps():
    for _ in range(3):
        provider_health.record_failure("bedrock", "x")
    provider_health.record_failure("bedrock", "x")
    assert provider_health.failure_streak("bedrock") == 4
    # 60s * 2^(4-3) = 120s window — widening, not resetting.
    assert provider_health.snapshot(["bedrock"])["bedrock"]["cooldown_remaining_s"] > 60


# ── candidate construction ───────────────────────────────────────────────────

def test_candidates_for_failover_provider_drop_arn():
    cands = bedrock_client._provider_candidates(
        "anthropic", "arn:aws:bedrock:us-east-1:123:profile/x")
    assert cands == ["anthropic-default"]  # ARN dropped, catalogue default kept


def test_candidates_for_active_provider_keep_model():
    assert bedrock_client._provider_candidates("bedrock", "test-model") == ["test-model"]


def test_promotion_resets_client_and_model_state(monkeypatch):
    # _promote_active_provider is the sticky switch: it must clear the cached
    # boto3 client (the old provider's) and re-enable AI.
    reset = MagicMock()
    monkeypatch.setattr(bedrock_client, "_reset_client", reset)
    bedrock_client.mark_ai_unavailable()
    bedrock_client._promote_active_provider("anthropic")
    reset.assert_called_once()
    assert bedrock_client.is_ai_available()
    assert bedrock_client.get_active_provider() == "anthropic"
