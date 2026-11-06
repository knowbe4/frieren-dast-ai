"""
Unit tests for dast.proxy.auth_headers.extract_auth_headers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict

from dast.proxy.auth_headers import extract_auth_headers


@dataclass
class _FakeEntry:
    host: str
    request_headers: Dict[str, str] = field(default_factory=dict)
    source: str = "proxy"


def test_no_host_scans_globally():
    entries = [
        _FakeEntry(host="a.example.com", request_headers={"Authorization": "Bearer a"}),
        _FakeEntry(host="b.example.com", request_headers={}),
    ]
    # Reverse-chronological: caller controls order; most-recent-first here is entries[0].
    result = extract_auth_headers(entries, host=None)
    assert result == {"Authorization": "Bearer a"}


def test_exact_host_match():
    entries = [
        _FakeEntry(host="other.com", request_headers={"Cookie": "session=xyz"}),
        _FakeEntry(host="example.com", request_headers={"Authorization": "Bearer b"}),
    ]
    result = extract_auth_headers(entries, host="example.com")
    assert result == {"Authorization": "Bearer b"}


def test_subdomain_match_when_enabled():
    entries = [
        _FakeEntry(host="sub.example.com", request_headers={"Authorization": "Bearer sub"}),
    ]
    result = extract_auth_headers(entries, host="example.com", include_subdomains=True)
    assert result == {"Authorization": "Bearer sub"}


def test_subdomain_non_match_when_disabled():
    entries = [
        _FakeEntry(host="sub.example.com", request_headers={"Authorization": "Bearer sub"}),
    ]
    result = extract_auth_headers(entries, host="example.com", include_subdomains=False)
    assert result == {}


def test_unrelated_host_does_not_match():
    entries = [
        _FakeEntry(host="totally-different.net", request_headers={"Authorization": "Bearer x"}),
    ]
    result = extract_auth_headers(entries, host="example.com")
    assert result == {}


def test_source_exclusion_skips_synthetic_entries():
    entries = [
        _FakeEntry(host="example.com", request_headers={"Authorization": "Bearer synthetic"}, source="agent"),
        _FakeEntry(host="example.com", request_headers={"Authorization": "Bearer real"}, source="proxy"),
    ]
    result = extract_auth_headers(entries, host="example.com", exclude_sources=("agent", "imported"))
    assert result == {"Authorization": "Bearer real"}


def test_source_exclusion_disabled_allows_any_source():
    entries = [
        _FakeEntry(host="example.com", request_headers={"Authorization": "Bearer synthetic"}, source="agent"),
    ]
    result = extract_auth_headers(entries, host="example.com", exclude_sources=())
    assert result == {"Authorization": "Bearer synthetic"}


def test_limit_truncates_scanned_entries():
    entries = [
        _FakeEntry(host="example.com", request_headers={}),
        _FakeEntry(host="example.com", request_headers={"Authorization": "Bearer too-old"}),
    ]
    result = extract_auth_headers(entries, host="example.com", limit=1)
    assert result == {}


def test_no_matching_entries_returns_empty_dict():
    entries = [
        _FakeEntry(host="example.com", request_headers={"X-Custom": "not-auth-related"}),
    ]
    result = extract_auth_headers(entries, host="example.com")
    assert result == {}


def test_stops_at_first_matching_entry_with_headers():
    entries = [
        _FakeEntry(host="example.com", request_headers={"Authorization": "Bearer newest"}),
        _FakeEntry(host="example.com", request_headers={"Authorization": "Bearer older"}),
    ]
    result = extract_auth_headers(entries, host="example.com")
    assert result == {"Authorization": "Bearer newest"}


# ── inject_csrf (shared CSRF injector used by copilot + active scan) ───────────

from dast.proxy.auth_headers import inject_csrf  # noqa: E402


def test_inject_csrf_from_dict_map():
    h = {}
    inject_csrf(h, {"CSRF-TOKEN": "abc"})
    assert h["X-CSRF-Token"] == "abc"
    assert h["X-Requested-With"] == "XMLHttpRequest"


def test_inject_csrf_from_playwright_cookie_list():
    h = {}
    inject_csrf(h, [{"name": "XSRF-TOKEN", "value": "xyz", "domain": "x"}])
    assert h["X-CSRF-Token"] == "xyz"


def test_inject_csrf_from_named_session_cookie_map():
    # NamedSession.cookies shape: {name: {"value": ...}}
    h = {}
    inject_csrf(h, {"csrf_token": {"value": "pw", "domain": "x"}})
    assert h["X-CSRF-Token"] == "pw"


def test_inject_csrf_refresh_overwrites_stale():
    h = {"X-CSRF-Token": "STALE"}
    inject_csrf(h, {"CSRF-TOKEN": "fresh"}, refresh=True)
    assert h["X-CSRF-Token"] == "fresh"


def test_inject_csrf_without_refresh_keeps_existing():
    h = {"X-CSRF-Token": "KEEP"}
    inject_csrf(h, {"CSRF-TOKEN": "fresh"}, refresh=False)
    assert h["X-CSRF-Token"] == "KEEP"


def test_inject_csrf_no_csrf_cookie_sets_only_xhr():
    h = {}
    inject_csrf(h, {"session": "s"})
    assert "X-CSRF-Token" not in h
    assert h["X-Requested-With"] == "XMLHttpRequest"


def test_inject_csrf_empty_cookies_is_noop():
    h = {}
    inject_csrf(h, [])
    assert h == {}


def test_cross_session_headers_inject_fresh_csrf():
    """cross_session_idor replay drops the owner's CSRF and mirrors the target
    identity's own CSRF cookie so a cross-tenant write probe is not 403'd."""
    from dast.agents.cross_session_idor_agent import _build_session_headers

    class _Sess:
        auth_headers = {}
        cookies = {"_session": {"value": "s2"}, "CSRF-TOKEN": {"value": "tok2"}}

    original = {"cookie": "_session=s1", "x-csrf-token": "tok1", "accept": "application/json"}
    out = _build_session_headers(original, _Sess())
    assert out["X-CSRF-Token"] == "tok2"       # refreshed to identity 2's token
    assert "s2" in out["cookie"] and "s1" not in out["cookie"]
    assert out["accept"] == "application/json"  # non-auth headers preserved
