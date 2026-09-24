"""
Unit tests for the DNS-evidence helpers extracted from the validator.

extract_domain is pure and covers the source-priority order; collect_dns_evidence
is exercised through its dig fallback with a stubbed subprocess so no real DNS or
network is touched.
"""

from __future__ import annotations

from dast.hackerone import dns_checks
from dast.hackerone.dns_checks import extract_domain
from dast.hackerone.parser import H1Report


class TestExtractDomain:
    def test_from_proof_url(self):
        report = H1Report(proof_url="https://sub.example.com/path", vuln_type="dns_takeover")
        assert extract_domain(report) == "sub.example.com"

    def test_bare_domain_proof_url(self):
        report = H1Report(proof_url="dangling.example.com", vuln_type="dns_takeover")
        assert extract_domain(report) == "dangling.example.com"

    def test_from_all_urls_when_no_proof_url(self):
        report = H1Report(proof_url="", vuln_type="dns_takeover",
                          all_urls=["https://found.example.org/x"])
        assert extract_domain(report) == "found.example.org"

    def test_from_dig_command_in_raw_text(self):
        report = H1Report(proof_url="", vuln_type="dns_takeover",
                          raw_text="Run: dig target.example.net +short")
        assert extract_domain(report) == "target.example.net"

    def test_no_domain_returns_empty(self):
        report = H1Report(proof_url="", vuln_type="dns_takeover", raw_text="no urls here")
        assert extract_domain(report) == ""


class TestCollectDnsEvidenceDigFallback:
    def test_dig_no_output_flags_dangling(self, monkeypatch):
        monkeypatch.setattr(dns_checks, "_has_dnspython", lambda: False)

        class _Completed:
            stdout = ""
            stderr = ""

        monkeypatch.setattr(dns_checks.subprocess, "run", lambda *a, **kw: _Completed())
        checks: list[str] = []
        result = dns_checks.collect_dns_evidence("example.com", checks)
        assert result.dangling is True
        assert "dig_fallback" in checks

    def test_dig_with_ns_output_not_dangling(self, monkeypatch):
        monkeypatch.setattr(dns_checks, "_has_dnspython", lambda: False)

        class _Completed:
            stdout = "ns1.example.com.\nns2.example.com."
            stderr = ""

        monkeypatch.setattr(dns_checks.subprocess, "run", lambda *a, **kw: _Completed())
        result = dns_checks.collect_dns_evidence("example.com", [])
        assert result.dangling is False

    def test_invalid_domain_skips_dig(self, monkeypatch):
        monkeypatch.setattr(dns_checks, "_has_dnspython", lambda: False)

        def _fail(*a, **kw):
            raise AssertionError("dig must not run on an invalid domain")

        monkeypatch.setattr(dns_checks.subprocess, "run", _fail)
        result = dns_checks.collect_dns_evidence("not-a-domain", [])
        assert any("invalid domain" in line for line in result.lines)
