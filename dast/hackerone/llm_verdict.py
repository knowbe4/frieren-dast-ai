"""
LLM helpers for the HackerOne validator: prompts, calls and verdict parsing.

Every call degrades gracefully (returns an empty/negative result on failure) so
an LLM outage never crashes a validation run. For XSS the LLM is advisory only
or repairs the INPUT URL — it never sets the verdict; the browser does.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

from dast.hackerone.parser import H1Report
from dast.utils.logger import get_logger

logger = get_logger(__name__)

SYSTEM_ANALYSE = """\
You are a security researcher validating a reported vulnerability.
Given the original report and the HTTP response received when accessing the proof URL,
determine whether the vulnerability is confirmed.

Be conservative — only say Confirmed if you are at least 95% certain based on
clear, unambiguous evidence (e.g. payload executing, error pattern matching,
redirect to attacker-controlled host with exact payload reflected).
"Looks suspicious" or "might be vulnerable" is NOT enough.

Respond in this exact format:
Verdict: <Confirmed|Not confirmed|Needs manual review>
Confidence: <0-100>%
Reasoning: <one sentence of specific evidence>
"""

SYSTEM_DNS = """\
You are a DNS security expert validating a DNS takeover report.
Given DNS resolution results, determine if there is a real dangling record.

Only say Confirmed if NS/CNAME resolution unambiguously shows NXDOMAIN on a
nameserver that can be registered — 95% confidence minimum required.

Respond in this exact format:
Verdict: <Confirmed|Not confirmed|Needs manual review>
Confidence: <0-100>%
Reasoning: <one sentence of specific evidence>
"""

SYSTEM_URL_REPAIR = """\
You repair a proof-of-concept URL so a browser will drive the payload the
reporter intended. You do NOT judge whether the vulnerability is real — a
browser will execute your URL and decide. Your only job is to output the exact,
correctly-encoded URL to load.

Common issues to fix:
- Percent-encoding lost in copy/paste (e.g. '+' in a javascript: payload must be
  %2b, otherwise the browser decodes it to a space and breaks the JS).
- HTML entities that leaked in (&amp; -> &, &#x27; -> ').
- A payload the report describes in prose that belongs in a specific parameter.

Rules:
- Keep the SAME scheme, host and path as the given proof URL. Never change the
  target host. Never invent a new destination.
- Output ONLY the repaired URL on a single line, nothing else.
- If the URL is already correct or you cannot improve it, output it unchanged.
"""

SYSTEM_SSRF_ASSESS = """\
You are a senior application security engineer reviewing a HackerOne SSRF report.

The automatic OOB callback test did not receive a hit (interactsh unavailable or
target did not call back). Assess the report on its own merits:

1. Is the root cause technically credible? (sanitisation missing, code path clear?)
2. Is the researcher's original OOB evidence convincing? (callback shown, token leaked?)
3. Is the impact realistic?

Respond in this exact format:
Verdict: <Confirmed|Not confirmed|Needs manual review>
Confidence: <0-100>%
Reasoning: <2-3 sentences of specific technical evidence>
"""

_VERDICT_RE = re.compile(r'Verdict:\s*(Confirmed|Not confirmed|Needs manual review)', re.IGNORECASE)
_CONFIDENCE_RE = re.compile(r'Confidence:\s*(\d+)')
_REASONING_RE = re.compile(r'Reasoning:\s*(.+)')


def parse_llm_verdict(text: str, confidence_threshold: int = 95) -> tuple[bool, str]:
    """
    Parse structured LLM verdict and apply confidence threshold.
    Returns (confirmed: bool, reasoning: str).
    Only returns confirmed=True if Verdict==Confirmed AND Confidence >= threshold.
    """
    verdict_match = _VERDICT_RE.search(text)
    confidence_match = _CONFIDENCE_RE.search(text)
    reasoning_match = _REASONING_RE.search(text)

    verdict = verdict_match.group(1).lower() if verdict_match else ""
    confidence = int(confidence_match.group(1)) if confidence_match else 0
    reasoning = reasoning_match.group(1).strip() if reasoning_match else text.strip()

    confirmed = verdict == "confirmed" and confidence >= confidence_threshold
    label = f"[{confidence}% confidence] {reasoning}"
    return confirmed, label


async def llm_verdict_http(
    report: H1Report, body: str, status_code: int, confidence_threshold: float = 0.95
) -> tuple[bool, str, str]:
    """Schema-forced reproduction verdict for the generic HTTP path.

    Returns (reproduced, label, severity). Unlike the free-text
    ``parse_llm_verdict`` regex path, the model is forced through
    H1_VERDICT_SCHEMA so the verdict is always a valid, typed object. Degrades to
    (False, "", "") on any LLM failure.
    """
    try:
        from dast.ai import bedrock_client
        from dast.ai.prompt_safety import _sanitize_for_prompt
        from dast.ai.prompt_safety import UNTRUSTED_CONTENT_DIRECTIVE, wrap_untrusted
        from dast.ai.schemas import H1_VERDICT_SCHEMA

        user = (
            f"Vuln type: {report.vuln_type}\n"
            f"Proof URL: {_sanitize_for_prompt(report.proof_url, 300)}\n"
            f"Method: {report.http_method}\n"
            f"Payload: {_sanitize_for_prompt(report.payload, 200)}\n"
            f"Report summary: {_sanitize_for_prompt(report.summary or report.raw_text[:400], 400)}\n\n"
            f"HTTP response status: {status_code}\n"
            "Response body:\n"
            + wrap_untrusted(body[:2000], "http_response")
        )
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None,
            lambda: bedrock_client.invoke_json(
                system=SYSTEM_ANALYSE + "\n\n" + UNTRUSTED_CONTENT_DIRECTIVE,
                user=user,
                model_id=bedrock_client.get_fast_model(),
                max_tokens=384, temperature=0,
                schema=H1_VERDICT_SCHEMA,
            ),
        )
        reproduced = bool(result.get("reproduced"))
        confidence = float(result.get("confidence", 0.0) or 0.0)
        severity = str(result.get("severity", "info"))
        reasoning = str(result.get("reasoning", "")).strip()
        confirmed = reproduced and confidence >= confidence_threshold
        label = f"[{int(confidence * 100)}% confidence, {severity}] {reasoning}"
        return confirmed, label, severity
    except Exception as exc:
        logger.debug("H1 schema verdict failed", error=str(exc))
        return False, "", ""


async def llm_analyse_response(report: H1Report, body: str, status_code: int) -> str:
    """Free-text advisory analysis of a response (never flips an XSS verdict)."""
    try:
        from dast.ai import bedrock_client
        from dast.ai.prompt_safety import _sanitize_for_prompt

        user = (
            f"Vuln type: {report.vuln_type}\n"
            f"Proof URL: {_sanitize_for_prompt(report.proof_url, 300)}\n"
            f"Payload: {_sanitize_for_prompt(report.payload, 200)}\n"
            f"Report summary: {_sanitize_for_prompt(report.summary or report.raw_text[:500], 500)}\n\n"
            f"HTTP response status: {status_code}\n"
            f"Response body (first 2000 chars):\n{_sanitize_for_prompt(body, 2000)}\n"
        )
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            lambda: bedrock_client.invoke(
                system=SYSTEM_ANALYSE, user=user,
                model_id=bedrock_client.get_fast_model(),
                max_tokens=256,
            ),
        )
    except Exception as exc:
        logger.debug("H1 LLM analysis failed", error=str(exc))
        return ""


async def llm_repair_proof_url(report: H1Report, proof_url: str, page_content: str) -> str:
    """
    Ask the LLM to reinterpret/re-encode the intended proof URL when the browser
    observed no execution. The LLM only proposes a corrected INPUT URL — the
    browser still has to execute it to confirm; the LLM never sets the verdict.

    Returns the repaired URL (same host enforced here; caller re-checks it with
    is_safe_url), or "" on failure / no useful change.
    """
    try:
        from dast.ai import bedrock_client
        from dast.ai.prompt_safety import _sanitize_for_prompt

        user = (
            f"Proof URL as received:\n{_sanitize_for_prompt(proof_url, 500)}\n\n"
            f"Reported payload / notes:\n{_sanitize_for_prompt(report.payload or '', 300)}\n\n"
            f"Report text (first 800 chars):\n{_sanitize_for_prompt(report.raw_text[:800], 800)}\n\n"
            "Loading the URL above triggered no JavaScript execution in the browser. "
            "Output the corrected URL to load (same scheme/host/path)."
        )
        loop = asyncio.get_running_loop()
        raw = await loop.run_in_executor(
            None,
            lambda: bedrock_client.invoke(
                system=SYSTEM_URL_REPAIR, user=user,
                model_id=bedrock_client.get_fast_model(),
                max_tokens=400, temperature=0,
            ),
        )
        candidate = (raw or "").strip().splitlines()[0].strip() if raw else ""
        if not candidate.lower().startswith(("http://", "https://")):
            return ""
        # Enforce same host as the original proof URL — the LLM must not redirect
        # us to a different target it hallucinated.
        if urlparse(candidate).netloc.lower() != urlparse(proof_url).netloc.lower():
            logger.warning("LLM URL repair changed the host; rejecting")
            return ""
        return candidate
    except Exception as exc:
        logger.debug("H1 LLM URL repair failed", error=str(exc))
        return ""


async def llm_dns_verdict(report: H1Report, domain: str, dns_evidence: str) -> str:
    """Free-text LLM verdict on collected DNS evidence."""
    try:
        from dast.ai import bedrock_client
        from dast.ai.prompt_safety import _sanitize_for_prompt

        user = (
            f"Target domain: {domain}\n\n"
            f"DNS evidence:\n{_sanitize_for_prompt(dns_evidence, 1500)}\n\n"
            f"Original report (first 800 chars):\n{_sanitize_for_prompt(report.raw_text, 800)}\n"
        )
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            lambda: bedrock_client.invoke(
                system=SYSTEM_DNS, user=user,
                model_id=bedrock_client.get_fast_model(),
                max_tokens=256,
            ),
        )
    except Exception as exc:
        logger.debug("H1 DNS LLM verdict failed", error=str(exc))
        return ""


async def llm_ssrf_assessment(report: H1Report) -> str:
    """
    Credibility assessment of an SSRF report when no OOB callback arrived.
    Returns the assessment text, or a short failure note on LLM error.
    """
    try:
        from dast.ai import bedrock_client
        from dast.ai.prompt_safety import _sanitize_for_prompt

        user = f"Full report (first 4000 chars):\n{_sanitize_for_prompt(report.raw_text, 4000)}\n"
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            lambda: bedrock_client.invoke(
                system=SYSTEM_SSRF_ASSESS, user=user,
                model_id=bedrock_client.get_validation_model(),
                max_tokens=400,
            ),
        )
    except Exception as exc:
        logger.debug("H1 SSRF LLM assessment failed", error=str(exc))
        return f"LLM assessment failed: {str(exc)[:150]}"
