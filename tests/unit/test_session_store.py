"""
Unit tests for SessionStore — entry lifecycle, cookie jar,
deduplication, body_preview, noise filtering.
"""

from __future__ import annotations


from dast.proxy.session_store import SessionStore, ProxyEntry


def _make_store() -> SessionStore:
    store = SessionStore()
    return store


# ── new_entry ──────────────────────────────────────────────────────────────

class TestNewEntry:
    def test_creates_entry_and_returns_id(self):
        store = _make_store()
        eid = store.new_entry("GET", "https://example.com/page", {}, None)
        assert eid is not None
        entry = store.get_entry(eid)
        assert entry is not None
        assert entry.method == "GET"
        assert entry.url == "https://example.com/page"

    def test_filters_noise_domain(self):
        store = _make_store()
        eid = store.new_entry("GET", "https://www.google-analytics.com/collect", {}, None)
        assert eid is None

    def test_filters_noise_extension(self):
        store = _make_store()
        eid = store.new_entry("GET", "https://example.com/app.css", {}, None)
        assert eid is None

    def test_source_scanner_not_overridden_by_browse_session(self):
        store = _make_store()
        store.active_browse_session_id = "sess-1"
        eid = store.new_entry("GET", "https://example.com/api", {}, None, source="agent")
        entry = store.get_entry(eid)
        assert entry.source == "agent"

    def test_source_browse_when_browse_session_active(self):
        store = _make_store()
        store.active_browse_session_id = "sess-1"
        eid = store.new_entry("GET", "https://example.com/page", {}, None, source="proxy")
        entry = store.get_entry(eid)
        assert entry.source == "browse"
        assert entry.browse_session_id == "sess-1"


# ── complete_entry ─────────────────────────────────────────────────────────

class TestCompleteEntry:
    def test_updates_status_and_headers(self):
        store = _make_store()
        eid = store.new_entry("GET", "https://example.com/", {}, None)
        store.complete_entry(eid, 200, {"content-type": "text/html"}, b"<html/>", 42.0)
        entry = store.get_entry(eid)
        assert entry.response_status == 200
        assert entry.duration_ms == 42.0
        assert entry.content_type == "text/html"

    def test_ignores_unknown_entry_id(self):
        store = _make_store()
        store.complete_entry("nonexistent", 200, {}, b"", 1.0)  # must not raise


# ── body_preview in to_dict ────────────────────────────────────────────────

class TestBodyPreview:
    def test_body_preview_truncated_to_120(self):
        store = _make_store()
        long_body = b"x" * 300
        eid = store.new_entry("POST", "https://example.com/api", {}, long_body)
        entry = store.get_entry(eid)
        d = entry.to_dict()
        assert d["body_preview"] is not None
        assert len(d["body_preview"]) == 120

    def test_body_preview_none_when_no_body(self):
        store = _make_store()
        eid = store.new_entry("GET", "https://example.com/", {}, None)
        d = store.get_entry(eid).to_dict()
        assert d["body_preview"] is None

    def test_body_preview_short_body_in_full(self):
        store = _make_store()
        eid = store.new_entry("POST", "https://example.com/", {}, b'{"key":"val"}')
        d = store.get_entry(eid).to_dict()
        assert d["body_preview"] == '{"key":"val"}'


# ── add_finding / deduplication ────────────────────────────────────────────

class TestAddFinding:
    def test_finding_stored(self):
        store = _make_store()
        eid = store.new_entry("GET", "https://example.com/api", {}, None)
        store.add_finding(eid, {"title": "XSS", "attack_type": "xss", "confirmed": True}, "vulnerable")
        entry = store.get_entry(eid)
        assert entry.scan_result == "vulnerable"
        assert len(entry.findings) == 1
        assert entry.findings[0]["title"] == "XSS"

    def test_duplicate_finding_ignored(self):
        store = _make_store()
        eid = store.new_entry("GET", "https://example.com/api", {}, None)
        f = {"title": "XSS", "attack_type": "xss"}
        store.add_finding(eid, f, "vulnerable")
        store.add_finding(eid, f, "vulnerable")
        assert len(store.get_entry(eid).findings) == 1

    def test_different_attack_types_not_deduplicated(self):
        store = _make_store()
        eid = store.new_entry("GET", "https://example.com/api", {}, None)
        store.add_finding(eid, {"title": "XSS", "attack_type": "xss"}, "vulnerable")
        store.add_finding(eid, {"title": "XSS", "attack_type": "sqli"}, "vulnerable")
        assert len(store.get_entry(eid).findings) == 2


# ── cookie jar ────────────────────────────────────────────────────────────

class TestCookieJar:
    def test_cookies_ingested_on_complete(self):
        store = _make_store()
        eid = store.new_entry("GET", "https://example.com/", {}, None)
        store.complete_entry(
            eid, 200,
            {"content-type": "text/html", "set-cookie": "session=abc123; HttpOnly; Secure"},
            b"", 10.0,
        )
        cookies = store.get_cookies_for_host("example.com")
        names = {c["name"] for c in cookies}
        assert "session" in names

    def test_get_crawl_cookies_includes_shared_jar(self):
        store = _make_store()
        eid = store.new_entry("GET", "https://example.com/", {}, None)
        store.complete_entry(
            eid, 200,
            {"content-type": "text/html", "set-cookie": "session=abc123"},
            b"", 10.0,
        )
        names = {c["name"] for c in store.get_crawl_cookies()}
        assert "session" in names

    def test_get_crawl_cookies_includes_named_sessions(self):
        """
        The regression this guards: a user who logged in via a NAMED session has
        cookies isolated in named_sessions (invisible to get_all_cookies), so the
        crawler used to run unauthenticated. get_crawl_cookies must surface them.
        """
        store = _make_store()
        store.save_named_session_from_playwright(
            "user_a", "member",
            [{"name": "auth", "value": "tok", "domain": "example.com", "path": "/"}],
        )
        crawl_names = {c["name"] for c in store.get_crawl_cookies()}
        all_names = {c["name"] for c in store.get_all_cookies()}
        assert "auth" in crawl_names
        assert "auth" not in all_names, "named-session cookies must stay out of the shared jar"

    def test_get_crawl_cookies_named_session_wins_on_collision(self):
        store = _make_store()
        eid = store.new_entry("GET", "https://example.com/", {}, None)
        store.complete_entry(
            eid, 200, {"set-cookie": "auth=stale"}, b"", 10.0,
        )
        store.save_named_session_from_playwright(
            "user_a", "member",
            [{"name": "auth", "value": "fresh", "domain": "example.com", "path": "/"}],
        )
        by_name = {c["name"]: c["value"] for c in store.get_crawl_cookies()}
        assert by_name["auth"] == "fresh", "an explicit named login must win over the passive jar"


# ── ProxyEntry.from_dict round-trip ───────────────────────────────────────

class TestFromDict:
    def test_round_trip(self):
        store = _make_store()
        eid = store.new_entry("POST", "https://example.com/api", {"content-type": "application/json"}, b'{"a":1}')
        store.complete_entry(eid, 201, {"content-type": "application/json"}, b'{"id":2}', 55.0)
        entry = store.get_entry(eid)
        d = entry.to_dict(include_bodies=True)
        restored = ProxyEntry.from_dict(d)
        assert restored.url == entry.url
        assert restored.method == entry.method
        assert restored.response_status == 201
        assert restored.request_body == b'{"a":1}'


# ── all_entries / clear ────────────────────────────────────────────────────

class TestAllEntriesClear:
    def test_all_entries_returns_all(self):
        store = _make_store()
        store.new_entry("GET", "https://example.com/a", {}, None)
        store.new_entry("GET", "https://example.com/b", {}, None)
        assert len(store.all_entries()) == 2

    def test_clear_removes_all(self):
        store = _make_store()
        store.new_entry("GET", "https://example.com/a", {}, None)
        store.clear()
        assert store.all_entries() == []
