"""
Unit tests for durable authenticated browser state
(dast/proxy/auth_state_store.py): a captured Playwright storage_state is persisted
to disk and reloaded, so a login survives a proxy restart.
"""

from __future__ import annotations

import stat

import pytest

from dast.proxy import auth_state_store

_STATE = {
    "cookies": [{"name": "session", "value": "abc", "domain": "example.com", "path": "/"}],
    "origins": [{"origin": "https://example.com", "localStorage": [{"name": "t", "value": "1"}]}],
}


@pytest.fixture(autouse=True)
def _tmp_state_path(tmp_path, monkeypatch):
    path = tmp_path / "auth_storage_state.json"
    monkeypatch.setattr(auth_state_store, "_AUTH_STATE_PATH", path)
    return path


def test_save_then_load_roundtrip(_tmp_state_path):
    auth_state_store.save_auth_state(_STATE)
    assert _tmp_state_path.exists()
    loaded = auth_state_store.load_auth_state()
    assert loaded == _STATE


def test_saved_file_is_owner_only():
    auth_state_store.save_auth_state(_STATE)
    mode = stat.S_IMODE(auth_state_store._AUTH_STATE_PATH.stat().st_mode)
    assert mode == stat.S_IRUSR | stat.S_IWUSR  # 0o600 — no group/other access


def test_empty_or_none_state_is_not_persisted(_tmp_state_path):
    auth_state_store.save_auth_state(None)
    auth_state_store.save_auth_state({})
    auth_state_store.save_auth_state({"cookies": [], "origins": []})
    assert not _tmp_state_path.exists()
    assert auth_state_store.load_auth_state() is None


def test_empty_state_does_not_overwrite_a_good_one(_tmp_state_path):
    auth_state_store.save_auth_state(_STATE)
    auth_state_store.save_auth_state({"cookies": [], "origins": []})  # must be ignored
    assert auth_state_store.load_auth_state() == _STATE


def test_load_tolerates_corrupt_file(_tmp_state_path):
    _tmp_state_path.write_text("{not valid json")
    assert auth_state_store.load_auth_state() is None


def test_clear_removes_the_file(_tmp_state_path):
    auth_state_store.save_auth_state(_STATE)
    auth_state_store.clear_auth_state()
    assert not _tmp_state_path.exists()
    auth_state_store.clear_auth_state()  # idempotent — no error when already gone
