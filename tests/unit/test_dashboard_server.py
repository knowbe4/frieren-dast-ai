"""
Unit tests for dast.proxy.dashboard_server — session/settings import validation,
settings apply logic, and the FastAPI app assembly (build_app + root route).
"""

from __future__ import annotations

import pytest

from dast.proxy.dashboard_server import (
    _apply_settings_data,
    _validate_session_import,
    _validate_settings_import,
)


# ── _validate_session_import ────────────────────────────────────────────────

class TestValidateSessionImport:
    def test_non_dict_rejected(self):
        assert _validate_session_import([1, 2, 3]) is not None

    def test_minimal_valid_session_accepted(self):
        assert _validate_session_import({"name": "my-session"}) is None

    def test_name_too_long_rejected(self):
        assert _validate_session_import({"name": "x" * 201}) is not None

    def test_name_wrong_type_rejected(self):
        assert _validate_session_import({"name": 123}) is not None

    def test_entries_not_a_list_rejected(self):
        assert _validate_session_import({"name": "s", "entries": "oops"}) is not None

    def test_too_many_entries_rejected(self):
        assert _validate_session_import({"name": "s", "entries": [{}] * 100_001}) is not None

    def test_valid_entries_accepted(self):
        data = {
            "name": "s",
            "entries": [{"method": "GET", "source": "proxy", "url": "https://example.com/"}],
        }
        assert _validate_session_import(data) is None

    def test_entry_invalid_method_rejected(self):
        data = {"name": "s", "entries": [{"method": "TELEPORT", "url": "https://example.com/"}]}
        assert _validate_session_import(data) is not None

    def test_entry_invalid_source_rejected(self):
        data = {"name": "s", "entries": [{"method": "GET", "source": "not-a-real-source", "url": "https://example.com/"}]}
        assert _validate_session_import(data) is not None

    def test_entry_url_too_long_rejected(self):
        data = {"name": "s", "entries": [{"method": "GET", "url": "https://example.com/" + "a" * 8200}]}
        assert _validate_session_import(data) is not None

    def test_entry_url_wrong_type_rejected(self):
        data = {"name": "s", "entries": [{"method": "GET", "url": 12345}]}
        assert _validate_session_import(data) is not None

    def test_cookies_not_a_dict_rejected(self):
        assert _validate_session_import({"name": "s", "cookies": ["a", "b"]}) is not None

    def test_cookies_dict_accepted(self):
        assert _validate_session_import({"name": "s", "cookies": {"session": "abc"}}) is None

    def test_only_first_20_entries_are_validated(self):
        # Entry 25 has an invalid method but is beyond the first-20 validation window.
        entries = [{"method": "GET", "url": "https://example.com/"} for _ in range(20)]
        entries.append({"method": "INVALID", "url": "https://example.com/"})
        assert _validate_session_import({"name": "s", "entries": entries}) is None


# ── _validate_settings_import ───────────────────────────────────────────────

class TestValidateSettingsImport:
    def test_non_dict_rejected(self):
        assert _validate_settings_import("nope") is not None

    def test_empty_dict_accepted(self):
        assert _validate_settings_import({}) is None

    def test_scope_rules_not_a_list_rejected(self):
        assert _validate_settings_import({"scope_rules": "oops"}) is not None

    def test_too_many_scope_rules_rejected(self):
        assert _validate_settings_import({"scope_rules": [{}] * 501}) is not None

    def test_valid_scope_rule_accepted(self):
        rule = {"protocol": "https", "kind": "include", "host": "example.com", "port": "", "file": ""}
        assert _validate_settings_import({"scope_rules": [rule]}) is None

    def test_scope_rule_invalid_protocol_rejected(self):
        rule = {"protocol": "ftp", "kind": "include"}
        assert _validate_settings_import({"scope_rules": [rule]}) is not None

    def test_scope_rule_invalid_kind_rejected(self):
        rule = {"protocol": "any", "kind": "sideways"}
        assert _validate_settings_import({"scope_rules": [rule]}) is not None

    def test_scope_rule_field_too_long_rejected(self):
        rule = {"protocol": "any", "kind": "include", "host": "x" * 501}
        assert _validate_settings_import({"scope_rules": [rule]}) is not None

    def test_bypass_domains_not_a_list_rejected(self):
        assert _validate_settings_import({"bypass_domains": "not-a-list"}) is not None

    def test_bypass_domains_too_many_rejected(self):
        assert _validate_settings_import({"bypass_domains": ["d.com"] * 1001}) is not None

    def test_bypass_domains_valid_accepted(self):
        assert _validate_settings_import({"bypass_domains": ["example.com", "other.com"]}) is None

    def test_bypass_domains_entry_too_long_rejected(self):
        assert _validate_settings_import({"bypass_domains": ["a" * 254]}) is not None

    def test_hidden_extensions_not_a_list_rejected(self):
        assert _validate_settings_import({"hidden_extensions": {}}) is not None

    def test_hidden_extensions_too_many_rejected(self):
        assert _validate_settings_import({"hidden_extensions": [".js"] * 201}) is not None

    def test_hidden_extensions_entry_too_long_rejected(self):
        assert _validate_settings_import({"hidden_extensions": ["." + "a" * 20]}) is not None

    def test_hidden_extensions_valid_accepted(self):
        assert _validate_settings_import({"hidden_extensions": [".js", ".css"]}) is None


# ── _apply_settings_data ─────────────────────────────────────────────────────

@pytest.fixture
def isolated_settings(tmp_path, monkeypatch):
    """A real ProxySettings instance with persistence redirected to a tmp file."""
    from dast.proxy import proxy_settings as ps_module

    monkeypatch.setattr(ps_module, "_SETTINGS_PATH", tmp_path / "proxy-settings.json")
    return ps_module.ProxySettings()


class TestApplySettingsData:
    def test_scope_rules_replaced_when_present(self, isolated_settings):
        _apply_settings_data(isolated_settings, {"scope_rules": [{"kind": "include", "host": "a.com"}]})
        assert isolated_settings.get_scope_rules() == [{"kind": "include", "host": "a.com"}]

    def test_scope_rules_untouched_when_absent(self, isolated_settings):
        isolated_settings._scope_rules = [{"kind": "include", "host": "existing.com"}]
        _apply_settings_data(isolated_settings, {})
        assert isolated_settings.get_scope_rules() == [{"kind": "include", "host": "existing.com"}]

    def test_bypass_domains_added_and_removed_to_match_import(self, isolated_settings):
        isolated_settings.add_bypass("stale.com")
        _apply_settings_data(isolated_settings, {"bypass_domains": ["fresh.com"]})
        snapshot = isolated_settings.to_dict()
        assert "fresh.com" in snapshot["bypass_domains"]
        assert "stale.com" not in snapshot["bypass_domains"]

    def test_hidden_extensions_added_and_removed_to_match_import(self, isolated_settings):
        isolated_settings.add_hidden_ext(".stale")
        _apply_settings_data(isolated_settings, {"hidden_extensions": [".fresh"]})
        snapshot = isolated_settings.to_dict()
        assert ".fresh" in snapshot["hidden_extensions"]
        assert ".stale" not in snapshot["hidden_extensions"]


# ── build_app ────────────────────────────────────────────────────────────────

def test_build_app_returns_fastapi_app_and_serves_ui(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from dast.proxy.dashboard_server import build_app
    from dast.proxy.session_store import SessionStore
    import asyncio

    monkeypatch.setattr("dast.proxy.api.status_routes.prefetch_ai_status", _noop_prefetch)

    store = SessionStore()
    app = build_app(store=store, scan_queue=asyncio.Queue())

    with TestClient(app) as client:
        resp = client.get("/")
        assert resp.status_code == 200
        assert "<!DOCTYPE html>" in resp.text or "<html" in resp.text.lower()


async def _noop_prefetch(ctx):
    return None
