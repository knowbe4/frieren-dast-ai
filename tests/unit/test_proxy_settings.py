"""
Unit tests for ProxySettings — scope rules, bypass domains,
hidden extensions, and pattern matching.

Tests run in-process and never touch the filesystem (settings are not saved).
"""

from __future__ import annotations

import pytest

from dast.proxy.proxy_settings import ProxySettings, _matches_field, _rule_matches_url


@pytest.fixture(autouse=True)
def _no_disk(monkeypatch):
    """Prevent any ProxySettings instance from reading or writing ~/.dast-ai/ during tests."""
    monkeypatch.setattr(ProxySettings, "_load", lambda self: None)
    monkeypatch.setattr(ProxySettings, "_save", lambda self: None)


# ── _matches_field ─────────────────────────────────────────────────────────

class TestMatchesField:
    def test_empty_pattern_matches_anything(self):
        assert _matches_field("anything", "") is True

    def test_exact_match(self):
        assert _matches_field("example.com", "example.com") is True

    def test_glob_wildcard(self):
        assert _matches_field("api.example.com", "*.example.com") is True
        assert _matches_field("example.com", "*.example.com") is False

    def test_regex_pattern(self):
        assert _matches_field("api.example.com", r"api\.(example|test)\.com") is True
        assert _matches_field("other.example.com", r"api\.(example|test)\.com") is False

    def test_case_insensitive(self):
        assert _matches_field("Example.COM", "example.com") is True


# ── _rule_matches_url ──────────────────────────────────────────────────────

class TestRuleMatchesUrl:
    def _rule(self, **kw):
        base = {"enabled": True, "protocol": "any", "host": "", "port": "", "file": "", "kind": "include"}
        base.update(kw)
        return base

    def test_disabled_rule_never_matches(self):
        rule = self._rule(enabled=False, host="example.com")
        assert _rule_matches_url(rule, "https://example.com/page") is False

    def test_host_match(self):
        rule = self._rule(host="example.com")
        assert _rule_matches_url(rule, "https://example.com/page") is True
        assert _rule_matches_url(rule, "https://other.com/page") is False

    def test_protocol_filter(self):
        rule = self._rule(protocol="https", host="example.com")
        assert _rule_matches_url(rule, "https://example.com/") is True
        assert _rule_matches_url(rule, "http://example.com/") is False

    def test_path_filter(self):
        rule = self._rule(host="example.com", file="/api/*")
        assert _rule_matches_url(rule, "https://example.com/api/users") is True
        assert _rule_matches_url(rule, "https://example.com/static/app.js") is False


# ── ProxySettings scope logic ──────────────────────────────────────────────

class TestProxySettings:
    def _settings_no_disk(self):
        s = ProxySettings()
        s._scope_rules = []
        return s

    def test_no_rules_everything_in_scope(self):
        s = self._settings_no_disk()
        assert s.is_in_scope("https://example.com/api/users") is True
        assert s.is_in_scope("https://totally-different.com/") is True

    def test_include_rule_restricts_scope(self):
        s = self._settings_no_disk()
        s._scope_rules = [{
            "enabled": True, "protocol": "any", "host": "example.com",
            "port": "", "file": "", "kind": "include",
        }]
        assert s.is_in_scope("https://example.com/api") is True
        assert s.is_in_scope("https://other.com/api") is False

    def test_exclude_rule_removes_from_scope(self):
        s = self._settings_no_disk()
        s._scope_rules = [
            {"enabled": True, "protocol": "any", "host": "example.com", "port": "", "file": "", "kind": "include"},
            {"enabled": True, "protocol": "any", "host": "example.com", "port": "", "file": "/admin*", "kind": "exclude"},
        ]
        assert s.is_in_scope("https://example.com/api") is True
        assert s.is_in_scope("https://example.com/admin/panel") is False

    def test_exclude_takes_priority_over_include(self):
        s = self._settings_no_disk()
        s._scope_rules = [
            {"enabled": True, "protocol": "any", "host": "*.example.com", "port": "", "file": "", "kind": "include"},
            {"enabled": True, "protocol": "any", "host": "admin.example.com", "port": "", "file": "", "kind": "exclude"},
        ]
        assert s.is_in_scope("https://api.example.com/") is True
        assert s.is_in_scope("https://admin.example.com/") is False

    def test_bypass_domain(self):
        s = self._settings_no_disk()
        s._bypass = {"accounts.google.com"}
        assert s.is_bypassed("accounts.google.com") is True
        assert s.is_bypassed("example.com") is False

    def test_hidden_extension(self):
        s = self._settings_no_disk()
        assert s.is_hidden("/app.js") is True
        assert s.is_hidden("/app.css") is True
        assert s.is_hidden("/api/users") is False
        assert s.is_hidden("/index.html") is False  # .html not hidden by default

    def test_add_and_remove_scope_rule(self):
        s = self._settings_no_disk()
        rule = {"enabled": True, "protocol": "https", "host": "example.com",
                "port": "", "file": "", "kind": "include"}
        s.add_scope_rule(rule)
        assert len(s.get_scope_rules()) == 1
        s.remove_scope_rule(0)
        assert len(s.get_scope_rules()) == 0

    def test_apex_domain_regex_preset_matches_subdomains_only(self):
        s = self._settings_no_disk()
        s._scope_rules = [
            # ^(.*\.)?domain$ matches the apex domain and all subdomains but not lookalike names
            {"enabled": True, "protocol": "https", "host": r"^(.*\.)?example\.com$", "port": "443", "file": "", "kind": "include"},
        ]
        # Should be in scope
        assert s.is_in_scope("https://app.example.com/login") is True
        assert s.is_in_scope("https://example.com/") is True
        # Should NOT be in scope (HTTP, wrong domain, lookalike domain)
        assert s.is_in_scope("http://app.example.com/") is False
        assert s.is_in_scope("https://evil.com/") is False
        assert s.is_in_scope("https://notexample.com/") is False

    def test_toggle_scope_rule(self):
        s = self._settings_no_disk()
        rule = {"enabled": True, "protocol": "any", "host": "example.com",
                "port": "", "file": "", "kind": "include"}
        s.add_scope_rule(rule)
        # Enabled: example.com in scope, other.com not
        assert s.is_in_scope("https://example.com/") is True
        assert s.is_in_scope("https://other.com/") is False
        s.toggle_scope_rule(0, False)
        assert s.get_scope_rules()[0]["enabled"] is False
        # Disabled include rule: no active include rules remain → other.com is back in scope
        assert s.is_in_scope("https://other.com/") is True
