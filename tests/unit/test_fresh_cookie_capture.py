"""Freshest-cookie helpers in dast.proxy.auth_headers.

capture-from-proxy and authz_differential_probe must read the cookies that
ACTUALLY transited the proxy for a host (the newest request Cookie header),
not the in-memory jar — the jar is not reliably refreshed from SSO-callback
Set-Cookie responses, so it can hold pre-auth / stale cookies. These tests
cover the stale-vs-fresh case plus sibling-subdomain scoping and the jar
fallback."""

from __future__ import annotations

from dast.proxy.auth_headers import (
    freshest_cookie_header_for_host,
    freshest_cookies_for_host,
    host_matches_cookie_scope,
    newest_cookie_header_for_host,
    parse_cookie_header,
)


class _Entry:
    def __init__(self, host, cookie=None):
        self.host = host
        self.request_headers = {"Cookie": cookie} if cookie else {}


class _Store:
    def __init__(self, entries=None, jar=None):
        self._entries = entries or []
        self._jar = jar or []

    def entries_newest_first(self):
        return self._entries

    def get_cookies_for_host(self, host):
        return self._jar


# ── pure helpers ────────────────────────────────────────────────────────────

def test_parse_cookie_header_splits_pairs_and_ignores_junk():
    assert parse_cookie_header("sid=abc; t=1; = ; junk") == [("sid", "abc"), ("t", "1")]
    assert parse_cookie_header("") == []


def test_host_matches_exact_parent_child_and_sibling():
    assert host_matches_cookie_scope("app.example.com", "app.example.com")
    assert host_matches_cookie_scope("example.com", "app.example.com")  # parent
    assert host_matches_cookie_scope("app.example.com", "example.com")  # child
    # siblings sharing an immediate parent domain (domain-scoped session cookie)
    assert host_matches_cookie_scope("api.example.com", "settings-api.example.com")
    # unrelated host, and the two-label apex has no sibling scope
    assert not host_matches_cookie_scope("evil.test", "app.example.com")
    assert not host_matches_cookie_scope("other.test", "example.com")


# ── freshness: live history beats the stale jar ───────────────────────────────

def test_newest_cookie_header_prefers_history_over_jar():
    store = _Store(
        entries=[_Entry("app.example.com", "sid=FRESH")],
        jar=[{"name": "sid", "value": "STALE"}],
    )
    assert newest_cookie_header_for_host(store, "app.example.com") == "sid=FRESH"


def test_freshest_cookies_capture_live_values_with_jar_metadata():
    # The jar still holds the pre-auth cookie; the live request carries the
    # authenticated one. Capture must take the live value, keeping jar metadata.
    store = _Store(
        entries=[_Entry("app.example.com", "sid=FRESH; extra=1")],
        jar=[{"name": "sid", "value": "STALE", "domain": "app.example.com",
              "path": "/x", "secure": True, "httpOnly": True}],
    )
    cookies = {c["name"]: c for c in freshest_cookies_for_host(store, "app.example.com")}
    assert cookies["sid"]["value"] == "FRESH"
    assert cookies["sid"]["domain"] == "app.example.com"
    assert cookies["sid"]["path"] == "/x"          # metadata preserved from jar
    assert cookies["sid"]["httpOnly"] is True
    # a cookie only seen live gets the host as its domain
    assert cookies["extra"]["value"] == "1"
    assert cookies["extra"]["domain"] == "app.example.com"


def test_freshest_cookies_reuse_sibling_subdomain_session():
    # No history for the app host; the only authenticated request is on a sibling
    # subdomain (SSO/API host) — its domain-scoped session cookie must be reused.
    store = _Store(entries=[_Entry("api.example.com", "sid=FRESH")], jar=[])
    cookies = {c["name"]: c["value"]
               for c in freshest_cookies_for_host(store, "settings-api.example.com")}
    assert cookies == {"sid": "FRESH"}


def test_freshest_cookies_falls_back_to_jar_when_no_history():
    jar = [{"name": "sid", "value": "jarval", "domain": "app.example.com"}]
    store = _Store(entries=[], jar=jar)
    assert freshest_cookies_for_host(store, "app.example.com") == jar


def test_freshest_header_falls_back_to_jar_when_no_history():
    store = _Store(entries=[], jar=[{"name": "sid", "value": "v1"}])
    assert freshest_cookie_header_for_host(store, "app.example.com") == "sid=v1"
