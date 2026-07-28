"""
Red-Team Exploit Validator — Stage 2 confirmation.

Inspired by the orchestrator-ai attacker simulation pattern.

After an agent produces a finding, the red-team validator:
  1. Runs deterministic FP rules (fp_filter.py) — immediate discard if matched
  2. Runs the LLM validator with a structured exploit-proof prompt that asks
     for a concrete exploitation scenario, not just "is this real?"
  3. Aggregates confidence from three independent sources:
       - Pattern strength: how strong was the agent's detection evidence
       - Browser confirmation: was JS execution confirmed in headless browser
       - LLM confidence: what the LLM reported as confidence (0.0–1.0)
     Final confidence = max(pattern_confidence, browser_confidence, llm_confidence)
  4. Returns (confirmed: bool, confidence: float, reasoning: str)

This replaces the simple Coordinator._validate() for all non-bypass findings.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Optional, Tuple

from dast.ai.prompt_safety import UNTRUSTED_CONTENT_DIRECTIVE, wrap_untrusted
from dast.ai.schemas import RED_TEAM_SCHEMA
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.ai.agent_base import AgentFinding
    from dast.scanners.active_checks import CheckTarget

logger = get_logger(__name__)

_SYSTEM = """\
You are an expert penetration tester performing exploit validation.
A detection agent has found a potential vulnerability. Your job is to act as
an attacker and determine whether this finding is genuinely exploitable.

You may be given source code for the relevant endpoint. Use it to:
- Identify sanitisation, encoding, or escaping that would neutralise the payload
- Find hidden parameters not visible in the request that affect behaviour
- Spot auth guards, rate limiters, or CSRF checks that block exploitation
- Confirm vulnerable patterns (e.g. unsanitised SQL interpolation, raw innerHTML)
Source code evidence should raise or lower your confidence accordingly.

Respond ONLY with JSON:
{
  "confirmed": true|false,
  "confidence": <0.0-1.0>,
  "exploit_scenario": "<one sentence: how an attacker would exploit this>",
  "reasoning": "<one sentence: why you confirmed or rejected, referencing code if relevant>"
}

Rules:
- confirmed=true only when there is unambiguous evidence of real exploitation impact
- confirmed=false for: GraphQL/JSON validation errors, CSP-blocked XSS, access-denied SSRF, schema errors
- confidence must reflect your actual certainty, not just follow the confirmed field
- A confirmed=true with confidence < 0.5 means you're guessing — set confirmed=false instead
- Do NOT confirm based on pattern match alone — require evidence of impact in the response
- GraphQL enum/type errors echoing payloads are NEVER vulnerabilities
- JSON application/json responses can NEVER execute injected JavaScript

Examples:

Finding: sqli, payload `' OR '1'='1`, response snippet contains `You have an error in your SQL syntax near ''1'='1'`.
Good: {"confirmed": true, "confidence": 0.9, "exploit_scenario": "Attacker injects a UNION query to dump the users table.", "reasoning": "The database echoed a raw SQL syntax error, proving the payload reached the query unescaped."}

Finding: xss, payload `<script>alert(1)</script>`, response is application/json and the body contains `{"name":"<script>alert(1)</script>"}`.
Good: {"confirmed": false, "confidence": 0.05, "exploit_scenario": "", "reasoning": "The payload is reflected inside a JSON response body, which a browser never parses as HTML, so the script cannot execute."}"""

# The user message embeds target-controlled content (response snippet, code,
# hints), so append the structural untrusted-content directive.
_SYSTEM += UNTRUSTED_CONTENT_DIRECTIVE


def _pattern_confidence(finding: "AgentFinding") -> float:
    """
    Estimate confidence from the agent's own evidence strength.
    Deterministic agents (bypass_validation=True) are not routed here.
    """
    attack = getattr(finding, "attack_type", "")
    evidence = (getattr(finding, "evidence", "") or "").lower()
    snippet = (getattr(finding, "raw_response_snippet", "") or "").lower()

    # Time-based SQLi: confirmed by delay — high confidence
    if attack == "sqli" and "ms" in evidence and "delay" in evidence:
        return 0.85

    # Error-based SQLi with SQL error message in snippet
    if attack == "sqli" and snippet and any(
        marker in snippet for marker in
        ("sql syntax", "ora-", "pg_query", "sqlite_error", "unclosed quotation")
    ):
        return 0.80

    # LFI with actual file content
    import re as _re
    if attack in ("lfi", "path_traversal") and snippet and _re.search(
        r"root:.*:0:0:|\\[fonts\\]|\[boot loader\]", snippet
    ):
        return 0.90

    # SSTI math expression evaluated
    if attack == "ssti" and ("49" in snippet or "evaluated" in evidence):
        return 0.85

    # Open redirect with confirmed redirect to our probe domain
    if attack == "open_redirect" and "evil.example.com" in evidence:
        return 0.80

    # CRLF with injected header confirmed
    if attack == "crlf" and "crlf=injected" in snippet:
        return 0.80

    # IDOR with non-identical non-error response
    if attack == "idor" and "different non-empty data" in evidence:
        return 0.70

    # XSS reflected (without browser confirmation): lower base confidence
    if attack == "xss":
        return 0.45

    # SSRF — OOB callback or internal probe with response
    if attack == "ssrf" and ("callback" in evidence or "internal" in evidence):
        return 0.75

    # MFA bypass — param removed or invalid OTP accepted
    if attack == "mfa_bypass":
        if "accepted" in evidence or "200" in evidence:
            return 0.80
        if "no rate" in evidence or "429" in evidence:
            return 0.65
        return 0.50

    return 0.40


def _browser_confidence(finding: "AgentFinding") -> Optional[float]:
    """Return confidence from browser confirmation if attempted."""
    bc = getattr(finding, "browser_confirmed", None)
    if bc is None:
        return None
    return 0.92 if bc else 0.30


async def validate(
    finding: "AgentFinding",
    target: "CheckTarget",
    model_id: Optional[str] = None,
    confidence_threshold: float = 0.5,
    app_profile_hint: str = "",
) -> Tuple[bool, float, str]:
    """
    Full red-team validation pipeline.
    Returns (confirmed, confidence, reasoning).
    """
    from dast.ai import fp_filter

    # Stage 1: deterministic FP filter — no LLM needed
    fp_reason = fp_filter.check(finding, target)
    if fp_reason:
        logger.debug("Red-team: deterministic FP", attack=finding.attack_type, reason=fp_reason)
        return False, 0.0, fp_reason

    # Stage 2: pattern-based confidence estimate
    pattern_conf = _pattern_confidence(finding)
    browser_conf = _browser_confidence(finding)

    # Build tech context for the LLM. These hints are derived from analysis of the
    # target application, so they are untrusted-adjacent — fence them in XML tags
    # so injected instructions cannot flip the validator's verdict.
    discovery_hint = ""
    if target.discovery_context:
        summary = target.discovery_context.to_agent_summary()
        if summary:
            discovery_hint = f"Tech context:\n{wrap_untrusted(summary, 'discovery_context')}"

    app_intelligence_hint = ""
    if app_profile_hint:
        app_intelligence_hint = f"App intelligence:\n{wrap_untrusted(app_profile_hint, 'app_intelligence')}"

    threat_model_hint = ""
    threat_model_text = getattr(target, "threat_model_hint", "") or ""
    if threat_model_text:
        threat_model_hint = f"Architectural constraints (security invariants for this host):\n{wrap_untrusted(threat_model_text, 'threat_model')}"

    browser_note = ""
    if finding.attack_type == "xss":
        bc = getattr(finding, "browser_confirmed", None)
        bcr = getattr(finding, "browser_confirm_reason", "")
        if bc is True:
            browser_note = "Browser confirmation: JavaScript executed in headless browser — strong signal.\n"
        elif bc is False:
            reason_map = {
                "csp_or_sink": "CSP blocked or payload reaches different sink",
                "timeout":     "page timed out",
            }
            label = reason_map.get(bcr, bcr)
            browser_note = f"Browser confirmation attempted — JS did NOT execute ({label}).\n"

    # Always consult source code repository — code context reveals auth guards,
    # sanitisation, hidden params, route constraints, and framework protections
    # that directly affect whether a finding is exploitable.
    code_hint = getattr(target, "code_hint", "") or ""
    if not code_hint:
        # No pre-fetched hint — do a targeted lookup now
        try:
            from urllib.parse import urlparse as _urlp2
            from dast.code_analysis import lookup_code_for_path
            _path2 = _urlp2(finding.url).path
            if _path2 and _path2 != "/":
                code_hint = lookup_code_for_path(_path2, max_snippets=3)
        except Exception:
            pass
    code_section = (
        f"Source code context (relevant to this endpoint):\n{wrap_untrusted(code_hint, 'source_code')}"
        if code_hint else ""
    )

    # Attack-type-scoped few-shot examples from our vulnerability knowledge base.
    # These are authored by our team (trusted, static) — they anchor what a REAL
    # vuln of this type looks like vs. the common false-positive look-alikes, so
    # they are interpolated directly (no untrusted-content fencing).
    examples_section = ""
    try:
        from dast.vuln_knowledge import format_examples_block
        examples_block = format_examples_block(finding.attack_type)
        if examples_block:
            examples_section = f"{examples_block}\n"
    except Exception as exc:
        logger.warning("Vuln-knowledge lookup failed", attack=finding.attack_type, error=str(exc))

    # Evidence and the raw response snippet are target-controlled — fence the
    # response snippet as untrusted data (wrap_untrusted also applies the denylist
    # sanitizer as a second layer). Finding metadata (title, severity) is
    # scanner-derived and safe to interpolate directly.
    from dast.ai.payload_generator import _sanitize_for_prompt
    response_snippet = getattr(finding, "raw_response_snippet", "") or ""
    user = (
        f"Finding: {finding.title}\n"
        f"Attack type: {finding.attack_type}\n"
        f"Severity: {finding.severity}\n"
        f"Endpoint: {finding.request_method} {finding.url}\n"
        f"Parameter: {finding.parameter}\n"
        f"Payload used: {_sanitize_for_prompt(finding.payload, 200)!r}\n"
        f"Evidence: {_sanitize_for_prompt(finding.evidence, 500)}\n"
        f"Response snippet:\n{wrap_untrusted(response_snippet, 'target_response', 400)}"
        f"{browser_note}"
        f"{examples_section}"
        f"{discovery_hint}"
        f"{app_intelligence_hint}"
        f"{threat_model_hint}"
        f"{code_section}"
    )

    from dast.ai import bedrock_client

    # AI known to be unavailable (expired/absent credentials, a prior Bedrock
    # failure that tripped the sticky flag). Do NOT attempt the LLM call — fall
    # back to pattern confidence and leave finding.ai_validated False so the
    # finding is never mislabeled "AI validated" when the AI never ran.
    if not bedrock_client.is_ai_available():
        finding.ai_validated = False
        fallback_confirmed = pattern_conf >= confidence_threshold
        logger.debug(
            "Red-team: AI unavailable — pattern confidence used",
            attack=finding.attack_type, url=finding.url,
            pattern_conf=round(pattern_conf, 2), confirmed=fallback_confirmed,
        )
        return fallback_confirmed, pattern_conf, "AI unavailable — pattern confidence used"

    try:
        # Validation uses the highest-tier model — it is the final exploit-proof
        # stage where false negatives are costly.
        validation_model = model_id or bedrock_client.get_validation_model()
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None,
            lambda: bedrock_client.invoke_json(
                system=_SYSTEM, user=user, model_id=validation_model,
                schema=RED_TEAM_SCHEMA, temperature=0, cache_system=True,
            ),
        )

        # The LLM call succeeded and returned a verdict — this finding was
        # genuinely reviewed by the AI, regardless of the confirm/reject outcome.
        finding.ai_validated = True

        llm_confirmed = bool(result.get("confirmed", False))
        llm_confidence = float(result.get("confidence", 1.0 if llm_confirmed else 0.0))
        reasoning = str(result.get("reasoning", ""))
        exploit_scenario = str(result.get("exploit_scenario", ""))

        # Multi-source confidence aggregation — take the strongest signal
        sources = [pattern_conf, llm_confidence]
        if browser_conf is not None:
            sources.append(browser_conf)
        final_confidence = max(sources)

        # Confirmed only if LLM says yes AND final confidence clears the threshold
        confirmed = llm_confirmed and final_confidence >= confidence_threshold

        if confirmed and exploit_scenario:
            finding.reasoning = f"{reasoning} | Exploit: {exploit_scenario}"
        elif confirmed:
            finding.reasoning = reasoning

        logger.debug(
            "Red-team validation",
            attack=finding.attack_type,
            url=finding.url,
            llm_confirmed=llm_confirmed,
            llm_conf=round(llm_confidence, 2),
            pattern_conf=round(pattern_conf, 2),
            browser_conf=round(browser_conf, 2) if browser_conf is not None else None,
            final_conf=round(final_confidence, 2),
            threshold=confidence_threshold,
            confirmed=confirmed,
        )
        return confirmed, final_confidence, reasoning

    except Exception as e:
        # The LLM call did not complete — the finding was NOT AI-validated.
        # Leave the flag False so it is labeled by pattern confidence, never "ai".
        finding.ai_validated = False
        # Conservative fallback: keep the finding but cap confidence at pattern level
        fallback_confirmed = pattern_conf >= confidence_threshold
        logger.warning(
            "Red-team LLM call failed — downgraded to pattern confidence (not AI validated)",
            attack=finding.attack_type, url=finding.url, error=str(e),
        )
        return fallback_confirmed, pattern_conf, "Validation error — pattern confidence used"
