"""
Deterministic false-positive filter — runs BEFORE the LLM validator.

Rules are cheap, fast, and always correct. They handle well-known cases
where the scanner pattern fires but exploitation is structurally impossible.
If a rule matches, the finding is discarded immediately without any LLM call.

Adding a new rule: add a function _fp_<name>(finding, target) -> Optional[str]
that returns a reason string when the finding is a FP, None otherwise, then
register it in _RULES.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Optional

from dast.utils.logger import get_logger

logger = get_logger(__name__)

if TYPE_CHECKING:
    from dast.ai.agent_base import AgentFinding
    from dast.scanners.active_checks import CheckTarget


# ── individual rules ───────────────────────────────────────────────────────

def _fp_xss_json_response(finding: "AgentFinding", target: "CheckTarget") -> Optional[str]:
    """XSS payload reflected in a JSON response can never execute as JS."""
    if finding.attack_type != "xss":
        return None
    ct = (getattr(target, "headers", {}) or {}).get("content-type", "").lower()
    # Also check evidence — it may contain the response content-type
    evidence = getattr(finding, "evidence", "") or ""
    if "application/json" in ct or "application/json" in evidence.lower():
        return "XSS reflection in JSON response body — JS execution structurally impossible"
    return None


def _fp_xss_graphql_error(finding: "AgentFinding", target: "CheckTarget") -> Optional[str]:
    """GraphQL error responses echoing a payload are never exploitable XSS."""
    if finding.attack_type != "xss":
        return None
    snippet = (getattr(finding, "raw_response_snippet", "") or "").lower()
    evidence = (getattr(finding, "evidence", "") or "").lower()
    combined = snippet + evidence
    if ('"errors"' in combined or "'errors'" in combined) and (
        "no operation named" in combined
        or "expected" in combined
        or "to be one of" in combined
        or "variable $" in combined
        or "enum" in combined
        or "graphql" in combined
    ):
        return "GraphQL validation/enum error echoing payload — not executable XSS"
    return None


def _fp_sqli_graphql_variable(finding: "AgentFinding", target: "CheckTarget") -> Optional[str]:
    """SQLi probes in GraphQL variable fields that return schema validation errors."""
    if finding.attack_type != "sqli":
        return None
    snippet = (getattr(finding, "raw_response_snippet", "") or "").lower()
    if '"errors"' in snippet and ("expected type" in snippet or "variable" in snippet):
        return "GraphQL type validation error on SQLi payload — no SQL reached"
    return None


def _fp_idor_identical_response(finding: "AgentFinding", target: "CheckTarget") -> Optional[str]:
    """IDOR findings where evidence says responses are identical."""
    if finding.attack_type != "idor":
        return None
    evidence = (getattr(finding, "evidence", "") or "").lower()
    if "identical" in evidence or "same object" in evidence:
        return "IDOR probe returned identical data to baseline — same object accessed"
    return None


def _fp_ssrf_localhost_blocked(finding: "AgentFinding", target: "CheckTarget") -> Optional[str]:
    """SSRF findings where the evidence shows a 403/blocked response from internal host."""
    if finding.attack_type != "ssrf":
        return None
    evidence = (getattr(finding, "evidence", "") or "").lower()
    if "403" in evidence and ("blocked" in evidence or "forbidden" in evidence):
        return "SSRF probe returned 403 Forbidden — SSRF mitigation appears to be in place"
    return None


def _fp_graphql_enum_rejection(finding: "AgentFinding", target: "CheckTarget") -> Optional[str]:
    """
    Any payload injected into a GraphQL enum/type field is rejected at the schema layer.
    The server echoes the probe value in 'Expected X to be one of: ...' / 'provided invalid
    value' errors and never executes any logic — SSRF, XSS, SQLi, LLM injection, etc.
    are all structurally impossible when the input is rejected before reaching any handler.
    """
    raw_resp = (getattr(finding, "raw_response", "") or "").lower()
    snippet   = (getattr(finding, "raw_response_snippet", "") or "").lower()
    evidence  = (getattr(finding, "evidence", "") or "").lower()
    combined  = raw_resp + snippet + evidence
    if '"errors"' not in combined:
        return None
    enum_signals = (
        "to be one of" in combined
        or "expected type" in combined
        or "provided invalid value" in combined
        or "variable $" in combined
        or "coercion" in combined
        or "enum value" in combined
    )
    if not enum_signals:
        return None
    # Payload must also appear verbatim in the error (confirming it was echoed, not acted on)
    payload = (getattr(finding, "payload", "") or "").lower()
    if payload and payload not in combined:
        return None
    return "GraphQL type/enum validation rejected payload — server never executed any handler"


def _fp_ssti_payload_echoed(finding: "AgentFinding", target: "CheckTarget") -> Optional[str]:
    """
    SSTI finding where the raw payload appears verbatim in the response — the server
    stored and returned the input unchanged. Template evaluation would produce the
    computed result (e.g. '49'), not the original expression ('${7*7}').
    """
    if finding.attack_type != "ssti":
        return None
    payload = (getattr(finding, "payload", "") or "")
    raw_response = (getattr(finding, "raw_response", "") or "")
    if payload and raw_response and payload in raw_response:
        return "SSTI payload echoed verbatim in response — server stored it, did not evaluate it"
    return None


def _fp_lfi_no_content(finding: "AgentFinding", target: "CheckTarget") -> Optional[str]:
    """LFI/path traversal with no file content in evidence."""
    if finding.attack_type not in ("lfi", "path_traversal"):
        return None
    snippet = (getattr(finding, "raw_response_snippet", "") or "")
    if not snippet:
        return None
    # If neither Linux passwd nor Windows ini markers are present, it's not confirmed
    if not re.search(r"root:.*:0:0:|\\[fonts\\]|\[boot loader\]", snippet):
        return "LFI pattern matched but no file content markers found in response"
    return None


def _fp_open_redirect_same_domain(finding: "AgentFinding", target: "CheckTarget") -> Optional[str]:
    """Open redirect that stays on the same domain is not a vulnerability."""
    if finding.attack_type != "open_redirect":
        return None
    evidence = (getattr(finding, "evidence", "") or "").lower()
    # If the redirect location doesn't contain evil.example.com, it's not our probe
    if "evil.example.com" not in evidence:
        return "Redirect target is not the external probe domain — not an open redirect"
    return None


# ── rule registry ──────────────────────────────────────────────────────────

_RULES = [
    _fp_graphql_enum_rejection,     # covers all attack types — runs first
    _fp_ssti_payload_echoed,
    _fp_xss_json_response,
    _fp_xss_graphql_error,
    _fp_sqli_graphql_variable,
    _fp_idor_identical_response,
    _fp_ssrf_localhost_blocked,
    _fp_lfi_no_content,
    _fp_open_redirect_same_domain,
]


def check(finding: "AgentFinding", target: "CheckTarget") -> Optional[str]:
    """
    Run all deterministic FP rules against a finding.
    Returns a reason string if it's a false positive, None if it should proceed.
    """
    for rule in _RULES:
        try:
            reason = rule(finding, target)
            if reason:
                logger.debug("FP filter discarded finding", rule=rule.__name__,
                             title=getattr(finding, "title", ""), reason=reason,
                             url=getattr(target, "url", ""))
                return reason
        except Exception as exc:
            logger.warning("FP filter rule raised exception", rule=rule.__name__, error=str(exc))
    return None
