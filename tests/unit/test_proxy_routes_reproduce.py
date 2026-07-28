"""
Unit tests for the "reproduce in browser" HTML generator and its
/api/reproduce/{entry_id} endpoint (dast.proxy.api.proxy_routes).
"""

from __future__ import annotations

import asyncio

import pytest

from dast.proxy.api.proxy_routes import (
    _build_reproduce_html,
    _form_fields_from_body,
    _unreproducible_headers,
)


# ── _unreproducible_headers ──────────────────────────────────────────────────

class TestUnreproducibleHeaders:
    def test_browser_managed_headers_are_not_flagged(self):
        headers = {"Cookie": "a=b", "Content-Type": "application/json", "Accept": "*/*"}
        assert _unreproducible_headers(headers) == []

    def test_custom_auth_header_is_flagged(self):
        headers = {"Authorization": "Bearer x"}
        assert _unreproducible_headers(headers) == ["Authorization"]

    def test_csrf_header_is_flagged(self):
        headers = {"X-CSRF-Token": "abc123"}
        assert _unreproducible_headers(headers) == ["X-CSRF-Token"]

    def test_sec_fetch_headers_are_not_flagged(self):
        headers = {"Sec-Fetch-Mode": "navigate"}
        assert _unreproducible_headers(headers) == []


# ── _form_fields_from_body ───────────────────────────────────────────────────

class TestFormFieldsFromBody:
    def test_empty_body(self):
        fields, warnings = _form_fields_from_body("")
        assert fields == []
        assert warnings == []

    def test_form_urlencoded_body_parsed_as_is(self):
        fields, warnings = _form_fields_from_body("a=1&b=2")
        assert dict(fields) == {"a": "1", "b": "2"}
        assert warnings == []

    def test_json_object_flattened_to_scalars(self):
        fields, warnings = _form_fields_from_body('{"a": "1", "b": 2, "c": true}')
        assert dict(fields) == {"a": "1", "b": "2", "c": "True"}
        assert warnings  # content-type mismatch warning

    def test_json_with_nested_value_drops_and_warns(self):
        fields, warnings = _form_fields_from_body('{"a": "1", "nested": {"x": 1}}')
        assert dict(fields) == {"a": "1"}
        assert any("nested" in w for w in warnings)

    def test_json_array_body_yields_no_fields(self):
        fields, warnings = _form_fields_from_body('[1, 2, 3]')
        assert fields == []
        assert warnings


# ── _build_reproduce_html ────────────────────────────────────────────────────

class TestBuildReproduceHtml:
    def test_get_request_renders_ok_link_no_auto_redirect(self):
        html = _build_reproduce_html({
            "method": "GET", "url": "https://example.com/x?a=1",
            "request_headers": {}, "request_body": None,
        })
        assert "<script>" not in html
        assert 'http-equiv="refresh"' not in html
        assert '<a class="go" href="https://example.com/x?a=1">' in html

    def test_get_request_url_in_link(self):
        html = _build_reproduce_html({
            "method": "GET", "url": "https://example.com/x?a=1",
            "request_headers": {}, "request_body": None,
        })
        assert "https://example.com/x?a=1" in html

    def test_post_json_body_renders_as_form(self):
        html = _build_reproduce_html({
            "method": "POST", "url": "https://example.com/api",
            "request_headers": {}, "request_body": '{"a": "1", "b": 2}',
        })
        assert '<form id="repro-form" method="POST"' in html
        assert 'name="a" value="1"' in html
        assert 'name="b" value="2"' in html

    def test_custom_auth_header_triggers_warning(self):
        html = _build_reproduce_html({
            "method": "POST", "url": "https://example.com/api",
            "request_headers": {"Authorization": "Bearer secret"}, "request_body": "",
        })
        assert "Authorization" in html
        assert "Copy as cURL" in html
        # The header value itself must never leak into this page.
        assert "secret" not in html

    def test_put_method_warns_about_form_limitation(self):
        html = _build_reproduce_html({
            "method": "PUT", "url": "https://example.com/api/1",
            "request_headers": {}, "request_body": "name=x",
        })
        assert "PUT request" in html
        assert 'method="POST"' in html  # forms can't send PUT

    def test_script_breakout_in_url_is_neutralized(self):
        # A captured proof URL could legitimately contain "</script>" (e.g. an
        # XSS payload). It must never terminate our own <script>/<meta> context.
        evil_url = "https://example.com/x?a=</script><script>alert(1)</script>"
        html = _build_reproduce_html({
            "method": "GET", "url": evil_url,
            "request_headers": {}, "request_body": None,
        })
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html

    def test_quote_breakout_in_href_attribute_is_escaped(self):
        evil_url = 'https://example.com/x?a="><script>alert(2)</script>'
        html = _build_reproduce_html({
            "method": "GET", "url": evil_url,
            "request_headers": {}, "request_body": None,
        })
        assert "<script>alert(2)</script>" not in html

    def test_form_field_value_is_html_escaped(self):
        html = _build_reproduce_html({
            "method": "POST", "url": "https://example.com/api",
            "request_headers": {}, "request_body": "name=<script>alert(3)</script>",
        })
        assert "<script>alert(3)</script>" not in html
        assert "&lt;script&gt;alert(3)&lt;/script&gt;" in html

    def test_post_request_requires_explicit_click_no_auto_submit(self):
        # The page must wait for the user to click OK — no setTimeout/auto-submit,
        # since this page can be reached via a shared/copied link.
        html = _build_reproduce_html({
            "method": "POST", "url": "https://example.com/api",
            "request_headers": {}, "request_body": "a=1",
        })
        assert "setTimeout" not in html
        assert 'onclick="document.getElementById(\'repro-form\').submit()"' in html


# ── /api/reproduce/{entry_id} endpoint ───────────────────────────────────────

class TestReproduceEndpoint:
    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient
        from dast.proxy.dashboard_server import build_app
        from dast.proxy.session_store import SessionStore

        store = SessionStore()
        app = build_app(store=store, scan_queue=asyncio.Queue())
        with TestClient(app) as c:
            c._store = store
            yield c

    def test_unknown_entry_returns_404(self, client):
        resp = client.get("/api/reproduce/does-not-exist")
        assert resp.status_code == 404

    def test_get_entry_returns_html_with_link(self, client):
        entry_id = client._store.new_entry("GET", "https://example.com/page", {}, None)
        resp = client.get(f"/api/reproduce/{entry_id}")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "https://example.com/page" in resp.text

    def test_post_entry_returns_html_with_form(self, client):
        entry_id = client._store.new_entry(
            "POST", "https://example.com/submit", {"content-type": "application/json"},
            b'{"a": "1"}',
        )
        resp = client.get(f"/api/reproduce/{entry_id}")
        assert resp.status_code == 200
        assert "<form" in resp.text
