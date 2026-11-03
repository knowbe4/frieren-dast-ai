"""Model fallback chain in bedrock_client._invoke_raw.

When the resolved model sits in a configured tier chain (ai_validation_models /
ai_fast_models), an API failure/block on one model falls through to the next.
Credential exhaustion (AiUnavailableError) does NOT fall through (every model
fails the same way). A model outside any chain gets a single attempt.
"""

from __future__ import annotations

import pytest

from dast.ai import bedrock_client as bc
from dast.ai.bedrock_client import AiUnavailableError


@pytest.fixture
def chain(monkeypatch):
    # validation chain m1 -> m2 -> m3; keep the rest of _invoke_raw pure.
    monkeypatch.setattr(bc, "_tier_chain",
                        lambda tier: ["m1", "m2", "m3"] if tier == "validation" else [])
    monkeypatch.setattr(bc, "_resolve_model", lambda mid: mid or "m1")
    monkeypatch.setattr(bc, "get_active_provider", lambda: "gateway")
    monkeypatch.setattr(bc, "_build_body", lambda *a, **k: {"body": True})


def _patch_invoke_one(monkeypatch, behavior):
    calls = []

    def fake(provider, body, model):
        calls.append(model)
        result = behavior[model]
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(bc, "_invoke_one", fake)
    return calls


def _raw(model="m1"):
    return bc._invoke_raw(system="s", user="u", model_id=model, max_tokens=16,
                          temperature=0, cache_system=False, schema=None)


def test_falls_through_to_next_model_on_failure(chain, monkeypatch):
    calls = _patch_invoke_one(monkeypatch, {
        "m1": RuntimeError("blocked"),
        "m2": {"content": [{"type": "text", "text": "ok from m2"}]},
    })
    result = _raw("m1")
    assert result["content"][0]["text"] == "ok from m2"
    assert calls == ["m1", "m2"], "should try m1, then fall to m2 and stop"


def test_falls_through_twice(chain, monkeypatch):
    calls = _patch_invoke_one(monkeypatch, {
        "m1": RuntimeError("blocked"),
        "m2": RuntimeError("also blocked"),
        "m3": {"content": [{"type": "text", "text": "ok from m3"}]},
    })
    result = _raw("m1")
    assert result["content"][0]["text"] == "ok from m3"
    assert calls == ["m1", "m2", "m3"]


def test_raises_when_whole_chain_fails(chain, monkeypatch):
    _patch_invoke_one(monkeypatch, {
        "m1": RuntimeError("1"), "m2": RuntimeError("2"), "m3": RuntimeError("3"),
    })
    with pytest.raises(RuntimeError):
        _raw("m1")


def test_credential_exhaustion_does_not_fall_through(chain, monkeypatch):
    calls = _patch_invoke_one(monkeypatch, {
        "m1": AiUnavailableError("token expired"),
        "m2": {"content": [{"type": "text", "text": "should not reach"}]},
    })
    with pytest.raises(AiUnavailableError):
        _raw("m1")
    assert calls == ["m1"], "credential exhaustion must not burn the rest of the chain"


def test_model_outside_chain_single_attempt(chain, monkeypatch):
    # 'solo' is not in the validation chain -> one attempt, no fallback.
    calls = _patch_invoke_one(monkeypatch, {"solo": RuntimeError("boom")})
    with pytest.raises(RuntimeError):
        _raw("solo")
    assert calls == ["solo"]


# ── copilot tier selection (per-install config, default unchanged) ─────────────

def test_copilot_tier_defaults_to_fast(monkeypatch):
    monkeypatch.setattr(bc, "get_fast_model", lambda: "FAST")
    monkeypatch.setattr(bc, "get_validation_model", lambda: "VALID")
    monkeypatch.setattr(bc, "_settings_tier", lambda attr: "")  # unset -> default
    assert bc.get_copilot_model() == "FAST"


def test_copilot_tier_validation_when_configured(monkeypatch):
    monkeypatch.setattr(bc, "get_fast_model", lambda: "FAST")
    monkeypatch.setattr(bc, "get_validation_model", lambda: "VALID")
    monkeypatch.setattr(bc, "_settings_tier",
                        lambda attr: "validation" if attr == "copilot_model_tier" else "")
    assert bc.get_copilot_model() == "VALID"
