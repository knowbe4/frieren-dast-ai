"""Shared probe markers and canary-signal logic."""


from dast.ai.canaries import (
    OPEN_REDIRECT_CANARY_HOST,
    SSTI_ARITHMETIC_PRODUCT,
    is_redirect_to_canary,
)
from dast.ai.coordinator import _CANARY_PAYLOADS, _has_canary_signal


class TestSstiMarker:
    def test_product_is_correct(self):
        assert str(8887 * 8893) == SSTI_ARITHMETIC_PRODUCT

    def test_payload_yaml_expectations_match_arithmetic(self):
        from dast.payloads.loader import _load
        data = _load("ssti.yaml")
        for group in (data.get("payloads") or {}).values():
            for item in group:
                if isinstance(item, dict) and "8887" in str(item.get("payload", "")):
                    assert item["expected"] == SSTI_ARITHMETIC_PRODUCT

    def test_ssti_agent_expectations_match_arithmetic(self):
        from dast.agents import ssti_agent
        for probe in ssti_agent._EVASIVE_CANARIES:
            if "8887" in probe["payload"]:
                assert probe["expected"] == SSTI_ARITHMETIC_PRODUCT


class TestRedirectCanary:
    def test_absolute_redirect(self):
        assert is_redirect_to_canary(f"https://{OPEN_REDIRECT_CANARY_HOST}/probe")

    def test_protocol_relative_and_backslash(self):
        assert is_redirect_to_canary(f"//{OPEN_REDIRECT_CANARY_HOST}")
        assert is_redirect_to_canary(f"/\\{OPEN_REDIRECT_CANARY_HOST}")

    def test_same_site_redirect_carrying_canary_in_query_is_not_open_redirect(self):
        assert not is_redirect_to_canary(f"/login?next=https://{OPEN_REDIRECT_CANARY_HOST}")
        assert not is_redirect_to_canary(f"https://app.example.com/?u=//{OPEN_REDIRECT_CANARY_HOST}")


class TestCanarySignal:
    def test_reflected_lfi_canary_is_not_a_signal(self):
        payload = _CANARY_PAYLOADS["lfi"]
        body = f"<p>File not found: {payload}</p>"
        assert not _has_canary_signal("lfi", payload, body, baseline_text="<p>ok</p>")

    def test_url_encoded_ssrf_echo_is_not_a_signal(self):
        payload = _CANARY_PAYLOADS["ssrf"]
        body = '<a href="/fetch?u=http%3A%2F%2F169.254.169.254%2F">retry</a>'
        assert not _has_canary_signal("ssrf", payload, body, baseline_text="")

    def test_real_file_content_is_a_signal(self):
        payload = _CANARY_PAYLOADS["lfi"]
        body = "root:x:0:0:root:/root:/bin/bash"
        assert _has_canary_signal("lfi", payload, body, baseline_text="<p>ok</p>")

    def test_error_present_in_baseline_is_not_a_signal(self):
        payload = _CANARY_PAYLOADS["sqli"]
        page = "<footer>Powered by MySQL</footer>"
        assert not _has_canary_signal("sqli", payload, page, baseline_text=page)

    def test_sql_error_caused_by_input_is_a_signal(self):
        payload = _CANARY_PAYLOADS["sqli"]
        body = "You have an error in your SQL syntax near '''"
        assert _has_canary_signal("sqli", payload, body, baseline_text="<p>results</p>")

    def test_bare_word_sql_is_not_a_signal(self):
        payload = _CANARY_PAYLOADS["sqli"]
        assert not _has_canary_signal("sqli", payload, "Learn SQL in 10 days", baseline_text="")

    def test_xss_reflection_is_a_signal(self):
        payload = _CANARY_PAYLOADS["xss"]
        assert _has_canary_signal("xss", payload, f"<div>{payload}</div>", baseline_text="")
