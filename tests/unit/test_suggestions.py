"""Recon suggestions: discovery hits and hidden params become deduplicated, neutral suggestions."""

from unittest.mock import patch

from dast.proxy.session_store import SessionStore
from dast.proxy.suggestions import record_discovery_hit, record_param_hit


def _store() -> SessionStore:
    store = SessionStore()
    store.active_suggestions = []
    return store


def test_discovery_hit_adds_entry_and_single_recon_suggestion():
    store = _store()
    hit = {"url": "https://app.test/backup/", "path": "/backup/", "status": 200, "kind": "dir"}
    with patch("dast.proxy.plugin_manager.log_event"):
        record_discovery_hit(store, hit, headers={})
        record_discovery_hit(store, hit, headers={})
    assert len(store.all_entries()) == 1
    assert [s["attack_type"] for s in store.active_suggestions] == ["recon"]
    assert store.active_suggestions[0]["source"] == "content-discovery"


def test_param_hits_dedup_per_parameter():
    store = _store()
    base = {"url": "https://app.test/search", "method": "GET", "location": "query", "reason": "reflected"}
    with patch("dast.proxy.plugin_manager.log_event"):
        record_param_hit(store, {**base, "parameter": "debug"})
        record_param_hit(store, {**base, "parameter": "debug"})
        record_param_hit(store, {**base, "parameter": "admin"})
    assert sorted(s["parameter"] for s in store.active_suggestions) == ["admin", "debug"]
    assert all(s["attack_type"] == "recon" for s in store.active_suggestions)
