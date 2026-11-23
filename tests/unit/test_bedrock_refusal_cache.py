"""Gateway-refusal caching tests (dast/ai/bedrock_client.py).

A safety-classifier refusal (AiContentBlockedError) is content-policy-based and
model-stable: the same primary model refuses the same content every call. The
model-level walk in ``_invoke_provider`` therefore remembers a refused model and
deprioritises it on later calls so the first attempt goes straight to a model
that has not been refused — instead of re-paying the blocked round-trip each
time. Only safety refusals are cached; a transient error leaves the model in its
normal position.

All tests stub ``_invoke_one`` (the single point that reaches a named provider)
and ``_provider_candidates`` (the per-provider model list) so no network or
catalogue is touched and the candidate order is deterministic."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

import pytest

from dast.ai import bedrock_client

_OK: Dict[str, Any] = {"content": [{"type": "text", "text": "hi"}], "usage": {}}


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    """Fresh refusal cache + a fixed two-model candidate list per call."""
    monkeypatch.setattr(bedrock_client, "_refused_models", set())
    monkeypatch.setattr(
        bedrock_client, "_provider_candidates",
        lambda provider, model: ["model-a", "model-b"],
    )
    yield


def _install_invoke(monkeypatch, behavior):
    """Scripted _invoke_one; returns the list of (provider, model) calls made."""
    calls: List[Tuple[str, str]] = []

    def fake_invoke(provider: str, body: Dict[str, Any], model: str) -> Dict[str, Any]:
        calls.append((provider, model))
        return behavior(provider, model)

    monkeypatch.setattr(bedrock_client, "_invoke_one", fake_invoke)
    return calls


def _call():
    return bedrock_client._invoke_provider("bedrock", {}, "model-a")


def test_refused_model_is_deprioritised_on_next_call(monkeypatch):
    """model-a refuses, model-b answers. On the FIRST call the chain is walked in
    order (a → b). On the SECOND call the cached refusal pushes model-a last, so
    model-b is tried first and succeeds — model-a is never re-invoked."""
    def behavior(provider: str, model: str) -> Dict[str, Any]:
        if model == "model-a":
            raise bedrock_client.AiContentBlockedError("safety classifier refused")
        return _OK

    calls = _install_invoke(monkeypatch, behavior)

    # First call: a is tried (refused), then b succeeds.
    assert _call() == _OK
    assert calls == [("bedrock", "model-a"), ("bedrock", "model-b")]
    assert ("bedrock", "model-a") in bedrock_client._refused_models

    # Second call: model-a is deprioritised, so model-b is the first (and only)
    # attempt — the refused primary is not re-paid.
    calls.clear()
    assert _call() == _OK
    assert calls == [("bedrock", "model-b")]


def test_transient_error_is_not_cached(monkeypatch):
    """A non-refusal error (e.g. a timeout) must NOT populate the cache — the
    model keeps its normal position and is still retried on the next call."""
    def behavior(provider: str, model: str) -> Dict[str, Any]:
        if model == "model-a":
            raise RuntimeError("connection timed out")
        return _OK

    calls = _install_invoke(monkeypatch, behavior)

    assert _call() == _OK
    assert calls == [("bedrock", "model-a"), ("bedrock", "model-b")]
    # Transient errors are never cached.
    assert ("bedrock", "model-a") not in bedrock_client._refused_models

    # Next call still tries model-a first (unchanged order).
    calls.clear()
    assert _call() == _OK
    assert calls == [("bedrock", "model-a"), ("bedrock", "model-b")]


def test_all_candidates_refused_still_walks_whole_chain(monkeypatch):
    """Fail-open: when every candidate is cached-refused the walk still runs each
    model (surfacing the block) rather than skipping everything."""
    def behavior(provider: str, model: str) -> Dict[str, Any]:
        raise bedrock_client.AiContentBlockedError("refused")

    calls = _install_invoke(monkeypatch, behavior)

    with pytest.raises(bedrock_client.AiContentBlockedError):
        _call()
    assert calls == [("bedrock", "model-a"), ("bedrock", "model-b")]

    # Both are now cached; the next call must still attempt both and raise.
    calls.clear()
    with pytest.raises(bedrock_client.AiContentBlockedError):
        _call()
    assert len(calls) == 2
    assert set(calls) == {("bedrock", "model-a"), ("bedrock", "model-b")}
