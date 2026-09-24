"""
DNS evidence collection for HackerOne DNS/subdomain-takeover reports.

Resolves NS and CNAME records for the reported domain and flags dangling
pointers (NXDOMAIN on a nameserver or CNAME target). Uses dnspython when it is
installed and falls back to ``dig`` otherwise. The validator combines this
evidence with an LLM verdict.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from typing import List
from urllib.parse import urlparse

from dast.hackerone.parser import H1Report
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_DIG_TIMEOUT_SECONDS = 10
_MAX_DOMAIN_LENGTH = 253
_DIG_COMMAND_RE = re.compile(
    r'(?:dig|nslookup|check|test)\s+([a-z0-9][a-z0-9\-\.]{3,60}\.[a-z]{2,})', re.IGNORECASE,
)


@dataclass
class DnsEvidence:
    """Human-readable DNS findings plus whether a dangling record was proven."""

    lines: List[str] = field(default_factory=list)
    dangling: bool = False


def _netloc(url: str) -> str:
    """Return the URL's netloc, or "" when it cannot be parsed."""
    try:
        return urlparse(url).netloc
    except Exception as exc:
        logger.debug("Could not parse URL while extracting DNS domain", error=str(exc))
        return ""


def extract_domain(report: H1Report) -> str:
    """Try to extract the target domain from the report."""
    # From proof_url first
    if report.proof_url:
        netloc = _netloc(report.proof_url)
        if netloc:
            return netloc
        # May be a bare domain (no scheme)
        if "." in report.proof_url and not report.proof_url.startswith("http"):
            return report.proof_url.split("/")[0]
    # From all_urls (may include bare domains added by the parser)
    for url in report.all_urls:
        if url.startswith("http"):
            netloc = _netloc(url)
            if netloc:
                return netloc
        elif "." in url and len(url) > 4:
            # Bare domain from dig-pattern extraction
            return url
    # From target_url
    if report.target_url:
        if not report.target_url.startswith("http"):
            return report.target_url
        try:
            return urlparse(report.target_url).netloc
        except Exception as exc:
            logger.debug("Could not parse target URL while extracting DNS domain", error=str(exc))
    # Raw text scan — "dig X" / "nslookup X"
    for match in _DIG_COMMAND_RE.finditer(report.raw_text):
        return match.group(1).strip(".")
    return ""


def _has_dnspython() -> bool:
    try:
        import dns.exception  # noqa: F401
        import dns.resolver  # noqa: F401
    except ImportError:
        return False
    return True


def _check_ns_records(domain: str, result: DnsEvidence, checks_run: List[str]) -> None:
    """Resolve NS records and flag any nameserver that no longer resolves."""
    import dns.exception
    import dns.resolver

    try:
        ns_answers = dns.resolver.resolve(domain, "NS")
        ns_names = [str(record.target).rstrip(".") for record in ns_answers]
        result.lines.append(f"NS records for {domain}: {', '.join(ns_names)}")
        checks_run.append("ns_lookup")

        # For each NS, check if it resolves (NXDOMAIN = dangling)
        for nameserver in ns_names:
            try:
                dns.resolver.resolve(nameserver, "A")
                result.lines.append(f"NS {nameserver}: resolves OK")
            except dns.exception.NXDOMAIN:
                result.lines.append(f"NS {nameserver}: NXDOMAIN — dangling nameserver pointer!")
                result.dangling = True
            except Exception as exc:
                result.lines.append(f"NS {nameserver}: lookup error ({exc})")

    except dns.exception.NXDOMAIN:
        result.lines.append(f"{domain}: NXDOMAIN on NS lookup")
        result.dangling = True
    except dns.exception.NoAnswer:
        result.lines.append(f"{domain}: no NS records found")
    except Exception as exc:
        result.lines.append(f"NS lookup error: {exc}")


def _check_cname_chain(domain: str, result: DnsEvidence) -> None:
    """Resolve the CNAME chain and flag a CNAME target that no longer resolves."""
    import dns.exception
    import dns.resolver

    try:
        cname_answers = dns.resolver.resolve(domain, "CNAME")
        for record in cname_answers:
            target = str(record.target).rstrip(".")
            result.lines.append(f"CNAME: {domain} → {target}")
            try:
                dns.resolver.resolve(target, "A")
                result.lines.append(f"CNAME target {target}: resolves OK")
            except dns.exception.NXDOMAIN:
                result.lines.append(f"CNAME target {target}: NXDOMAIN — dangling CNAME!")
                result.dangling = True
    except dns.exception.NoAnswer as exc:
        logger.debug("No CNAME record for domain", domain=domain, error=str(exc))
    except Exception as exc:
        logger.debug("CNAME lookup failed", domain=domain, error=str(exc))


def _check_with_dig(domain: str, result: DnsEvidence) -> None:
    """Fallback when dnspython is missing: ``dig NS +short`` on a sanitised domain."""
    try:
        # Sanitise domain: only allow label chars + dots; no @, spaces, or shell metacharacters
        safe_domain = re.sub(r'[^a-zA-Z0-9.\-]', '', domain)[:_MAX_DOMAIN_LENGTH]
        if not safe_domain or not re.match(r'^[a-zA-Z0-9].*\.[a-zA-Z]{2,}$', safe_domain):
            result.lines.append(f"Skipped dig: invalid domain {domain!r}")
            raise ValueError("unsafe domain")
        completed = subprocess.run(
            ["dig", safe_domain, "NS", "+short"],
            capture_output=True, text=True, timeout=_DIG_TIMEOUT_SECONDS,
        )
        ns_output = completed.stdout.strip()
        result.lines.append(f"dig NS {domain}:\n{ns_output or '(no output)'}")
        if not ns_output or "SERVFAIL" in completed.stderr:
            result.lines.append("SERVFAIL or no NS records — possible dangling pointer")
            result.dangling = True
    except Exception as exc:
        result.lines.append(f"dig error: {exc}")


def collect_dns_evidence(domain: str, checks_run: List[str]) -> DnsEvidence:
    """Run the NS + CNAME dangling-record checks for ``domain``."""
    result = DnsEvidence()
    use_dnspython = _has_dnspython()
    checks_run.append(f"dns_check:{domain}")
    if use_dnspython:
        _check_ns_records(domain, result, checks_run)
        _check_cname_chain(domain, result)
    else:
        checks_run.append("dig_fallback")
        _check_with_dig(domain, result)
    return result
