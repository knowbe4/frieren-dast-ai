"""
Regression tests for the time-based false-positive guard in the response analyzer.

A live scan of the internal DVWA confirmed two bogus "CRITICAL SQLI" findings on
the file-inclusion endpoint: the LLM analyzer marked VULNERABLE purely from a
~10s response time for a SLEEP(5)/WAITFOR DELAY payload (even rationalising the
mismatch as "triggered twice"), on an endpoint that is not SQL-backed. Blind /
time-based injection cannot be confirmed from a single response without a
differential timing baseline, so such verdicts are downgraded to NEEDS_RETRY.
"""

from __future__ import annotations

import dast.ai.response_analyzer as ra
from dast.ai.response_analyzer import _guard_timing_false_positive, analyze_attempt
from dast.models import (
    AttackAttempt,
    AttackPayload,
    AttackVerdict,
    Endpoint,
    HttpRequest,
    HttpResponse,
)


def _attempt(payload_value: str, body: str = "", duration_ms: float = 10_000.0) -> AttackAttempt:
    endpoint = Endpoint(url="http://target.test/vulnerabilities/fi/", method="GET")
    return AttackAttempt(
        endpoint=endpoint,
        payload=AttackPayload(
            value=payload_value,
            attack_type="sqli",
            injection_point="page",
            injection_location="query",
        ),
        request=HttpRequest(method="GET", url="http://target.test/vulnerabilities/fi/?page=x"),
        response=HttpResponse(status_code=200, body=body, duration_ms=duration_ms),
    )


class TestTimingGuard:
    def test_timing_only_sleep_verdict_downgraded(self):
        attempt = _attempt("1 AND SLEEP(5)")
        verdict, confidence, evidence = _guard_timing_false_positive(
            attempt, AttackVerdict.VULNERABLE, 0.85,
            evidence="Response duration of 10423ms (~10s) for a SLEEP(5) payload",
            reasoning="time-based delay was likely triggered twice",
        )
        assert verdict == AttackVerdict.NEEDS_RETRY
        assert confidence <= 0.5
        assert "differential" in evidence.lower()

    def test_waitfor_delay_verdict_downgraded(self):
        # WAITFOR DELAY is SQL Server syntax; a delay against MySQL cannot be real.
        attempt = _attempt("1; WAITFOR DELAY '0:0:5'")
        verdict, confidence, _ = _guard_timing_false_positive(
            attempt, AttackVerdict.VULNERABLE, 0.85,
            evidence="Duration: 10482ms for a WAITFOR DELAY payload",
            reasoning="delay executed roughly twice",
        )
        assert verdict == AttackVerdict.NEEDS_RETRY

    def test_content_sql_error_keeps_vulnerable(self):
        # A real SQL error in the body is independent, content-based evidence.
        attempt = _attempt(
            "1' AND SLEEP(5)-- -",
            body="You have an error in your SQL syntax near ''1'",
        )
        verdict, confidence, evidence = _guard_timing_false_positive(
            attempt, AttackVerdict.VULNERABLE, 0.9,
            evidence="SQL error reflected: You have an error in your SQL syntax",
            reasoning="error-based SQLi confirmed",
        )
        assert verdict == AttackVerdict.VULNERABLE
        assert confidence == 0.9

    def test_non_timing_payload_untouched(self):
        # A reflection-based verdict on a non-delay payload must not be downgraded.
        attempt = _attempt("<script>alert(1)</script>", body="<script>alert(1)</script>")
        verdict, confidence, _ = _guard_timing_false_positive(
            attempt, AttackVerdict.VULNERABLE, 0.95,
            evidence="Payload reflected unencoded in the response body",
            reasoning="reflected XSS",
        )
        assert verdict == AttackVerdict.VULNERABLE
        assert confidence == 0.95

    def test_protected_verdict_untouched(self):
        attempt = _attempt("1 AND SLEEP(5)")
        verdict, _, _ = _guard_timing_false_positive(
            attempt, AttackVerdict.PROTECTED, 0.8,
            evidence="payload stripped", reasoning="sanitized",
        )
        assert verdict == AttackVerdict.PROTECTED


class TestAnalyzeAttemptIntegration:
    def test_analyze_attempt_downgrades_timing_fp(self, monkeypatch):
        def fake_invoke_json(*args, **kwargs):
            return {
                "verdict": "VULNERABLE",
                "confidence": 0.85,
                "evidence": "Response duration of 10423ms for a SLEEP(5) payload",
                "reasoning": "time-based delay indicates SQL injection",
            }

        monkeypatch.setattr(ra.bedrock_client, "invoke_json", fake_invoke_json)
        attempt = _attempt("1 AND SLEEP(5)")
        verdict, evidence, confidence = analyze_attempt(attempt)
        assert verdict == AttackVerdict.NEEDS_RETRY
        assert confidence <= 0.5
