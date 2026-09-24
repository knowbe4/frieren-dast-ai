"""
AI response analyzer — determines if an attack was successful.

Given the request/response pair, Claude classifies the result as:
  VULNERABLE   — clear evidence of exploitation
  PROTECTED    — request was sanitized/blocked (with evidence)
  NEEDS_RETRY  — response is ambiguous, different payload may work
  INCONCLUSIVE — not enough signal to decide

Also extracts evidence string and suggests whether to keep iterating.
"""

import re
from typing import Tuple

from dast.ai import bedrock_client
from dast.ai.prompt_safety import UNTRUSTED_CONTENT_DIRECTIVE, wrap_untrusted
from dast.ai.schemas import RESPONSE_ANALYZER_SCHEMA
from dast.models import AttackAttempt, AttackVerdict
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# A payload that relies on a server-side time delay to prove blind/time-based
# injection. Confirming these needs a differential timing baseline (a control
# request plus a payload whose delay scales) — impossible from the single
# response this analyzer sees, so a VULNERABLE verdict resting on timing alone
# is downgraded below.
_TIME_DELAY_PAYLOAD_RE = re.compile(
    r"\b(sleep\s*\(|waitfor\s+delay|pg_sleep|benchmark\s*\(|dbms_pipe\.receive_message|dbms_lock\.sleep)",
    re.IGNORECASE,
)
# Language that shows a verdict is leaning on response timing rather than on
# content in the body.
_TIMING_EVIDENCE_RE = re.compile(
    r"(duration|delay(ed)?|time[-\s]?based|blind|slept|responded in|took\s+\d|latency|\d+\s*ms\b|\d+(\.\d+)?\s*seconds?)",
    re.IGNORECASE,
)
# Independent, content-based SQL-injection evidence that legitimately justifies
# VULNERABLE even when the payload also contained a delay primitive.
_SQL_ERROR_RE = re.compile(
    r"(sql syntax|sqlstate|ora-\d{3,}|mysql_fetch|psql:|unclosed quotation|"
    r"native client|odbc|syntax error near|you have an error in your sql|"
    r"warning:\s*mysql|unterminated|pg::|sqlite3::)",
    re.IGNORECASE,
)

_SYSTEM_ANALYZER = """\
You are an expert web application security analyst.
Analyze the HTTP request/response pair for evidence of a successful attack.
Be precise: report VULNERABLE only if there is clear evidence in the response.
Respond ONLY with JSON.

Critical anti-false-positive rules (a false positive wastes a developer's time
and is a failure):
- The verdict concerns the CLAIMED attack type ONLY. If the response proves a
  DIFFERENT vulnerability than the claimed attack type (for example the body
  returns file contents such as /etc/passwd while the attack type is "sqli"),
  respond NEEDS_RETRY, not VULNERABLE — that other issue is tested separately by
  its own payloads. Report VULNERABLE only when the evidence matches the claimed
  attack type.
- Time-based / blind injection: NEVER report VULNERABLE from response duration
  alone. You are shown a single response with no timing baseline, and request
  timing is noisy. A delay that does not cleanly match the injected sleep (e.g.
  "seems to have run twice", partial, or a WAITFOR delay against a non-SQL-Server
  backend) is NOT confirmation — use NEEDS_RETRY.
""" + UNTRUSTED_CONTENT_DIRECTIVE


def analyze_attempt(attempt: AttackAttempt) -> Tuple[AttackVerdict, str, float]:
    """
    Analyze an attack attempt and return (verdict, evidence, confidence).

    evidence: raw evidence string extracted from the response
    confidence: 0.0–1.0
    """
    req = attempt.request
    resp = attempt.response

    if not req or not resp:
        return AttackVerdict.INCONCLUSIVE, "No request/response captured", 0.0

    user = f"""Attack type: {attempt.payload.attack_type}
Payload sent: {attempt.payload.value!r}
Injection point: {attempt.payload.injection_point} ({attempt.payload.injection_location})

Request:
  {req.method} {req.url}
  Headers: {dict(list(req.headers.items())[:5])}
  Body: {wrap_untrusted(req.body or "", "request_body", 500)}

Response:
  Status: {resp.status_code}
  Headers: {dict(list(resp.headers.items())[:5])}
  Body: {wrap_untrusted(resp.body, "target_response", 2000)}
  Duration: {resp.duration_ms:.0f}ms

Classify the result and respond with JSON:
{{
  "verdict": "VULNERABLE" | "PROTECTED" | "NEEDS_RETRY" | "INCONCLUSIVE",
  "confidence": <0.0 to 1.0>,
  "evidence": "<specific text from the response that supports your verdict>",
  "reasoning": "<one sentence explanation>"
}}

VULNERABLE criteria:
- Payload is reflected without encoding in the response
- SQL error message visible
- Access to resource belonging to another user (IDOR)
- Internal server path / stack trace exposed
- Redirect to attacker-controlled domain succeeded
- Server-side request was made to injected URL (SSRF)

PROTECTED criteria:
- Payload is encoded or stripped in the response
- CSP/security header blocks execution
- 400/403/422 with sanitization message

NEEDS_RETRY: response gives clues but is ambiguous (try a different payload variant)
INCONCLUSIVE: no signal either way"""

    try:
        result = bedrock_client.invoke_json(system=_SYSTEM_ANALYZER, user=user, schema=RESPONSE_ANALYZER_SCHEMA)
        verdict_str = result.get("verdict", "INCONCLUSIVE").upper()
        verdict = AttackVerdict(verdict_str) if verdict_str in AttackVerdict._value2member_map_ else AttackVerdict.INCONCLUSIVE
        evidence = str(result.get("evidence", ""))
        confidence = float(result.get("confidence", 0.0))
        reasoning = str(result.get("reasoning", ""))
        verdict, confidence, evidence = _guard_timing_false_positive(
            attempt, verdict, confidence, evidence, reasoning
        )
        return verdict, f"{evidence} | {reasoning}", confidence
    except Exception as e:
        return AttackVerdict.INCONCLUSIVE, f"Analysis error: {e}", 0.0


def _guard_timing_false_positive(
    attempt: AttackAttempt,
    verdict: AttackVerdict,
    confidence: float,
    evidence: str,
    reasoning: str,
) -> Tuple[AttackVerdict, float, str]:
    """Downgrade a VULNERABLE verdict that rests only on response timing.

    Blind/time-based injection cannot be confirmed from a single response: there
    is no timing baseline and request latency is noisy. When the payload used a
    delay primitive (SLEEP/WAITFOR/pg_sleep/...) and the confirmation leans on
    timing language with no independent content evidence (a SQL error string),
    the verdict is unreliable — downgrade to NEEDS_RETRY so a proper differential
    timing probe (or a different payload) is tried instead of emitting a finding.
    """
    if verdict != AttackVerdict.VULNERABLE:
        return verdict, confidence, evidence

    payload_value = attempt.payload.value or ""
    if not _TIME_DELAY_PAYLOAD_RE.search(payload_value):
        return verdict, confidence, evidence

    body = attempt.response.body if attempt.response else ""
    combined_rationale = f"{evidence} {reasoning}"
    # Independent, content-based evidence (a SQL error) legitimately confirms.
    if _SQL_ERROR_RE.search(body) or _SQL_ERROR_RE.search(combined_rationale):
        return verdict, confidence, evidence

    # No content evidence and the rationale is about timing -> not confirmable here.
    if _TIMING_EVIDENCE_RE.search(combined_rationale):
        logger.warning(
            "Downgraded time-based VULNERABLE verdict lacking a timing baseline",
            url=attempt.request.url if attempt.request else "",
            attack_type=attempt.payload.attack_type,
            payload=payload_value[:80],
            original_confidence=round(confidence, 2),
        )
        note = (
            "Downgraded from VULNERABLE: time-based/blind injection cannot be "
            "confirmed from a single response duration without a differential "
            "timing baseline."
        )
        return AttackVerdict.NEEDS_RETRY, min(confidence, 0.5), f"{evidence} | {note}"

    return verdict, confidence, evidence
