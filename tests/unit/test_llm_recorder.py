"""LLM-call recorder tests (dast/ai/llm_recorder.py + bedrock_client wiring).

Two layers, mirroring the failover suite's approach:

- Direct recorder unit tests: outcome taxonomy, usage normalisation (Anthropic
  vs OpenAI shapes), excerpt caps, JSONL persistence, ring, snapshot/clear.
- Wiring tests that stub ``bedrock_client._invoke_one`` and exercise the REAL
  ``_invoke_raw`` walk, pinning that every attempt is recorded with the right
  outcome — including the repair-retry path carrying the caller's ``purpose``.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple

import pytest

from dast.ai import bedrock_client, llm_recorder, provider_health, response_cache
from dast.config import settings

_OK_ENVELOPE: Dict[str, Any] = {
    "content": [{"type": "text", "text": "hi"}], "usage": {},
}


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    """Deterministic provider globals + a clean response cache, mirroring the
    failover suite. (The recorder's JSONL sink and counters are isolated by the
    autouse conftest fixture _isolate_llm_recorder.)"""
    provider_health.reset()
    monkeypatch.setattr(bedrock_client, "_ai_unavailable", False)
    monkeypatch.setattr(bedrock_client, "_active_provider", "")
    monkeypatch.setattr(bedrock_client, "_active_model_id", "test-model")
    monkeypatch.setattr(bedrock_client, "_anthropic_api_key", "")
    monkeypatch.setattr(bedrock_client, "_openai_api_key", "")
    monkeypatch.setattr(bedrock_client, "_glm_api_key", "")
    monkeypatch.setattr(bedrock_client, "_resolve_default_model",
                        lambda provider: f"{provider}-default")
    monkeypatch.setattr(settings, "ai_failover_chain", "")
    response_cache.set_enabled(False)
    response_cache.clear()
    yield
    response_cache.set_enabled(False)
    response_cache.clear()
    provider_health.reset()


def _install_invoke(monkeypatch, behavior):
    """Replace _invoke_one with a scripted dispatcher (same contract as the
    failover suite). Returns the list of (provider, model) calls made."""
    calls: List[Tuple[str, str]] = []

    def fake_invoke(provider: str, body: Dict[str, Any], model: str) -> Dict[str, Any]:
        calls.append((provider, model))
        return behavior(provider, model)

    monkeypatch.setattr(bedrock_client, "_invoke_one", fake_invoke)
    return calls


def _snap() -> Dict[str, Any]:
    return llm_recorder.usage_snapshot()


def _jsonl_lines() -> List[Dict[str, Any]]:
    path = llm_recorder._CALLS_DIR / "llm_calls.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


# ── recorder core: record_call + snapshot ────────────────────────────────────

def test_usage_normalisation_both_shapes():
    llm_recorder.record_call(purpose="a", provider="bedrock", model="m",
                             usage={"input_tokens": 10, "output_tokens": 5})
    llm_recorder.record_call(purpose="a", provider="bedrock", model="m",
                             usage={"prompt_tokens": 7, "completion_tokens": 3})
    totals = _snap()["totals"]
    assert totals["calls"] == 2 and totals["ok"] == 2
    assert totals["input_tokens"] == 17 and totals["output_tokens"] == 8
    assert totals["latency_ms_avg"] >= 0


def test_excerpt_and_field_caps():
    entry = llm_recorder.record_call(
        purpose="p" * 100, provider="pr" * 50, model="m" * 120,
        usage=None, outcome="provider_error", error_excerpt="e" * 500)
    assert entry["purpose"] == "p" * 40
    assert entry["provider"] == "pr" * 20  # 100 chars -> 40-char cap
    assert entry["model"] == "m" * 80
    assert entry["error_excerpt"] == "e" * 200


def test_cache_hit_zeroes_usage():
    entry = llm_recorder.record_call(purpose="p", cache_hit=True,
                                     usage={"input_tokens": 99, "output_tokens": 99})
    assert entry["cache_hit"] is True
    assert entry["input_tokens"] == 0 and entry["output_tokens"] == 0


def test_record_call_never_raises_on_garbage_usage():
    entry = llm_recorder.record_call(purpose="p", usage="not-a-dict",  # type: ignore[arg-type]
                                     latency_ms="NaN")  # type: ignore[arg-type]
    assert entry["input_tokens"] == 0 and entry["latency_ms"] >= 0


def test_record_call_survives_unwritable_sink(tmp_path, monkeypatch):
    # _CALLS_DIR pointing at a regular FILE: mkdir fails, the entry is still
    # kept in memory (persistence failures only log — recording never breaks a scan).
    sink_file = tmp_path / "not-a-dir"
    sink_file.write_text("x", encoding="utf-8")
    monkeypatch.setattr(llm_recorder, "_CALLS_DIR", sink_file)
    entry = llm_recorder.record_call(purpose="p", outcome="ok")
    assert entry["outcome"] == "ok"
    assert _snap()["totals"]["calls"] == 1


def test_safety_block_excerpt_is_one_shot():
    llm_recorder.note_safety_block("r" * 500)
    taken = llm_recorder._take_safety_block()
    assert taken == "r" * 200  # capped
    assert llm_recorder._take_safety_block() == ""  # consumed


def test_jsonl_persistence_and_ring():
    for i in range(3):
        llm_recorder.record_call(purpose=f"p{i}", outcome="ok" if i < 2 else "throttled")
    lines = _jsonl_lines()
    assert [line["purpose"] for line in lines] == ["p0", "p1", "p2"]
    assert [line["outcome"] for line in lines] == ["ok", "ok", "throttled"]
    # The ring keeps the last _RING_SIZE entries; recent() slices the tail.
    assert len(llm_recorder.recent(limit=2)) == 2
    assert llm_recorder.recent(limit=2)[-1]["purpose"] == "p2"


def test_snapshot_aggregates_by_purpose_and_model():
    llm_recorder.record_call(purpose="planner", provider="bedrock", model="m1")
    llm_recorder.record_call(purpose="planner", provider="bedrock", model="m1")
    llm_recorder.record_call(purpose="validator", provider="glm", model="m2",
                             outcome="safety_block", error_excerpt="refused")
    snap = _snap()
    assert snap["by_purpose"] == {"planner": 2, "validator": 1}
    assert snap["by_model"] == {"m1": 2, "m2": 1}
    assert snap["totals"]["safety_block"] == 1
    assert snap["recent"][-1]["error_excerpt"] == "refused"


def test_snapshot_includes_response_cache_stats():
    response_cache.set_enabled(True)
    snap = _snap()
    assert snap["response_cache"]["enabled"] is True


def test_clear_resets_memory_but_keeps_jsonl():
    llm_recorder.record_call(purpose="p")
    llm_recorder.clear()
    snap = _snap()
    assert snap["totals"]["calls"] == 0
    assert snap["recent"] == []
    assert snap["by_purpose"] == {}
    assert len(_jsonl_lines()) == 1  # the durable record is kept


# ── dashboard routes (GET /api/ai/usage + POST /api/ai/usage/clear) ──────────

def test_usage_routes_round_trip(monkeypatch):
    from types import SimpleNamespace

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from dast.proxy.api.status_routes import make_router

    ctx = SimpleNamespace(scan_queue_state=None, mcp_last_heartbeat=[0.0])
    app = FastAPI()
    app.include_router(make_router(ctx))
    client = TestClient(app)

    llm_recorder.record_call(purpose="planner", outcome="ok",
                             usage={"input_tokens": 3, "output_tokens": 1})

    body = client.get("/api/ai/usage").json()
    assert body["totals"]["calls"] == 1
    assert body["totals"]["input_tokens"] == 3
    assert body["by_purpose"]["planner"] == 1

    assert client.post("/api/ai/usage/clear").json() == {"ok": True}
    assert client.get("/api/ai/usage").json()["totals"]["calls"] == 0


# ── wiring: the real _invoke_raw walk records every attempt ──────────────────

def _invoke_raw(purpose: str = ""):
    return bedrock_client._invoke_raw(
        system="sys", user="user", model_id=None, max_tokens=100,
        temperature=0, cache_system=False, schema=None, purpose=purpose,
    )


def test_ok_outcome_recorded_with_usage(monkeypatch):
    def behavior(provider: str, model: str) -> Dict[str, Any]:
        return {"content": [{"type": "text", "text": "hi"}],
                "usage": {"input_tokens": 11, "output_tokens": 4}}

    _install_invoke(monkeypatch, behavior)
    _invoke_raw(purpose="validator")

    totals = _snap()["totals"]
    assert totals["ok"] == 1 and totals["calls"] == 1
    assert totals["input_tokens"] == 11 and totals["output_tokens"] == 4
    entry = _snap()["recent"][-1]
    assert entry["purpose"] == "validator"
    assert entry["provider"] == "bedrock" and entry["model"] == "test-model"
    assert "user" in entry["req_excerpt"]  # prompt excerpt (system+user)
    assert entry["resp_excerpt"] == "hi"


def test_throttled_then_failover_recorded(monkeypatch):
    monkeypatch.setattr(settings, "anthropic_api_key", "sk-test")

    def behavior(provider: str, model: str) -> Dict[str, Any]:
        if provider == "bedrock":
            err = RuntimeError("rate exceeded")
            err.status_code = 429  # type: ignore[attr-defined]
            raise err
        return _OK_ENVELOPE

    _install_invoke(monkeypatch, behavior)
    _invoke_raw(purpose="planner")

    totals = _snap()["totals"]
    assert totals["throttled"] == 1 and totals["ok"] == 1
    throttled = [e for e in _snap()["recent"] if e["outcome"] == "throttled"]
    assert throttled[0]["provider"] == "bedrock"
    assert "rate exceeded" in throttled[0]["error_excerpt"]


def test_provider_error_recorded(monkeypatch):
    monkeypatch.setattr(settings, "anthropic_api_key", "sk-test")

    def behavior(provider: str, model: str) -> Dict[str, Any]:
        if provider == "bedrock":
            raise RuntimeError("connection reset")
        return _OK_ENVELOPE

    _install_invoke(monkeypatch, behavior)
    _invoke_raw()

    assert _snap()["totals"]["provider_error"] == 1


def test_content_block_records_safety_block(monkeypatch):
    # The raise site in _invoke_external captures the refusal excerpt before the
    # generic AiContentBlockedError replaces it — mirror that here.
    def behavior(provider: str, model: str) -> Dict[str, Any]:
        llm_recorder.note_safety_block("I cannot help with attacking that target")
        raise bedrock_client.AiContentBlockedError("blocked")

    _install_invoke(monkeypatch, behavior)
    with pytest.raises(bedrock_client.AiContentBlockedError):
        _invoke_raw(purpose="validator")

    totals = _snap()["totals"]
    assert totals["safety_block"] == 1
    entry = _snap()["recent"][-1]
    assert entry["purpose"] == "validator"
    assert "cannot help" in entry["error_excerpt"]


def test_value_error_records_caller_error(monkeypatch):
    _install_invoke(monkeypatch, lambda p, m: (_ for _ in ()).throw(ValueError("bad shape")))
    with pytest.raises(ValueError):
        _invoke_raw()
    assert _snap()["totals"]["caller_error"] == 1


def test_model_resolution_failure_records_unavailable(monkeypatch):
    monkeypatch.setattr(bedrock_client, "_resolve_model",
                        lambda model_id: (_ for _ in ()).throw(ValueError("no model")))
    with pytest.raises(ValueError):
        _invoke_raw(purpose="planner")
    totals = _snap()["totals"]
    assert totals["unavailable"] == 1
    assert "model resolution failed" in _snap()["recent"][-1]["error_excerpt"]


def test_invoke_json_cache_hit_recorded(monkeypatch):
    response_cache.set_enabled(True)
    _json_ok = {"content": [{"type": "text", "text": '{"answer": 1}'}], "usage": {}}
    calls = _install_invoke(monkeypatch, lambda p, m: _json_ok)
    kwargs = dict(system="sys", user="user", model_id=None, max_tokens=10,
                  temperature=0, schema=None, purpose="classifier")

    bedrock_client.invoke_json(**kwargs)
    bedrock_client.invoke_json(**kwargs)

    assert len(calls) == 1  # second answer came from the cache
    totals = _snap()["totals"]
    assert totals["ok"] == 1 and totals["cache_hit"] == 1
    hit = [e for e in _snap()["recent"] if e["outcome"] == "cache_hit"][0]
    assert hit["purpose"] == "classifier"
    assert hit["input_tokens"] == 0


def test_invoke_json_repair_carries_purpose(monkeypatch):
    # First attempt returns malformed text; the repair re-invocation must be
    # recorded under the CALLER's purpose, not the "other" fallback.
    payloads = ['oops not json {', '{"answer": 1}']

    def behavior(provider: str, model: str) -> Dict[str, Any]:
        text = payloads.pop(0)
        return {"content": [{"type": "text", "text": text}], "usage": {}}

    _install_invoke(monkeypatch, behavior)
    result = bedrock_client.invoke_json(
        system="sys", user="user", model_id=None, max_tokens=10,
        temperature=0, schema=None, purpose="verdict")

    assert result == {"answer": 1}
    entries = _snap()["recent"]
    assert len(entries) == 2
    assert all(e["purpose"] == "verdict" for e in entries)
    assert all(e["outcome"] == "ok" for e in entries)
