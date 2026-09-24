"""Tests for the opt-in deterministic AI response cache and its invoke_json hook."""

import pytest

from dast.ai import bedrock_client as bc
from dast.ai import response_cache as rc


@pytest.fixture(autouse=True)
def _reset_cache():
    """Every test starts and ends with a disabled, empty cache."""
    rc.set_enabled(False)
    rc.clear()
    yield
    rc.set_enabled(False)
    rc.clear()


@pytest.fixture
def _fake_backend(monkeypatch):
    """Replace the real LLM round-trip with a counter so we can see cache hits.
    Also pin provider/model so the cache key is stable across calls."""
    calls = {"n": 0}

    def _uncached(**kwargs):
        calls["n"] += 1
        return {"confirmed": True, "call": calls["n"]}

    monkeypatch.setattr(bc, "_invoke_json_uncached", _uncached)
    monkeypatch.setattr(bc, "get_active_provider", lambda: "bedrock")
    monkeypatch.setattr(bc, "_resolve_model", lambda m: "model-x")
    return calls


def test_disabled_by_default_no_caching(_fake_backend):
    bc.invoke_json(system="s", user="u", temperature=0, schema={"type": "object"})
    bc.invoke_json(system="s", user="u", temperature=0, schema={"type": "object"})
    assert _fake_backend["n"] == 2, "cache is off by default, both calls hit the backend"


def test_deterministic_call_is_memoised(_fake_backend):
    rc.set_enabled(True)
    a = bc.invoke_json(system="s", user="u", temperature=0, schema={"type": "object"})
    b = bc.invoke_json(system="s", user="u", temperature=0, schema={"type": "object"})
    assert _fake_backend["n"] == 1, "second identical deterministic call is served from cache"
    assert a == b
    # Returned dict must be a copy — mutating it must not poison the cache.
    a["confirmed"] = False
    c = bc.invoke_json(system="s", user="u", temperature=0, schema={"type": "object"})
    assert c["confirmed"] is True


def test_non_deterministic_call_never_cached(_fake_backend):
    rc.set_enabled(True)
    bc.invoke_json(system="s", user="u", temperature=0.7, schema={"type": "object"})
    bc.invoke_json(system="s", user="u", temperature=0.7, schema={"type": "object"})
    assert _fake_backend["n"] == 2, "temperature>0 always bypasses the cache"


def test_temperature_unset_never_cached(_fake_backend):
    rc.set_enabled(True)
    bc.invoke_json(system="s", user="u", schema={"type": "object"})
    bc.invoke_json(system="s", user="u", schema={"type": "object"})
    assert _fake_backend["n"] == 2, "no temperature (provider default) is not treated as deterministic"


def test_different_inputs_do_not_collide(_fake_backend):
    rc.set_enabled(True)
    bc.invoke_json(system="s", user="u1", temperature=0, schema={"type": "object"})
    bc.invoke_json(system="s", user="u2", temperature=0, schema={"type": "object"})
    assert _fake_backend["n"] == 2, "distinct user prompts are distinct cache keys"


def test_toggling_off_clears_cache(_fake_backend):
    rc.set_enabled(True)
    bc.invoke_json(system="s", user="u", temperature=0, schema={"type": "object"})
    rc.set_enabled(False)
    rc.set_enabled(True)
    bc.invoke_json(system="s", user="u", temperature=0, schema={"type": "object"})
    assert _fake_backend["n"] == 2, "disabling clears entries so re-enabling starts cold"


def test_make_key_is_stable_and_input_sensitive():
    base = dict(provider="bedrock", model="m", system="s", user="u",
                schema={"type": "object"}, max_tokens=2048)
    assert rc.make_key(**base) == rc.make_key(**base)
    assert rc.make_key(**{**base, "user": "other"}) != rc.make_key(**base)
    assert rc.make_key(**{**base, "schema": None}) != rc.make_key(**base)


def test_lru_eviction_bounds_size(monkeypatch):
    monkeypatch.setattr(rc, "_MAX_ENTRIES", 3)
    rc.set_enabled(True)
    rc.clear()
    for i in range(5):
        rc.put(f"k{i}", {"v": i})
    stats = rc.stats()
    assert stats["entries"] == 3, "cache never grows past _MAX_ENTRIES"
    assert rc.get("k0") is None and rc.get("k1") is None, "oldest entries evicted first"
    assert rc.get("k4") == {"v": 4}, "most recent entry retained"
