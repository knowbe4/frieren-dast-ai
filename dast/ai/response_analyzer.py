"""
AI response analyzer — determines if an attack was successful.

Given the request/response pair, Claude classifies the result as:
  VULNERABLE   — clear evidence of exploitation
  PROTECTED    — request was sanitized/blocked (with evidence)
  NEEDS_RETRY  — response is ambiguous, different payload may work
  INCONCLUSIVE — not enough signal to decide

Also extracts evidence string and suggests whether to keep iterating.
"""

from typing import Tuple

from dast.ai import bedrock_client
from dast.ai.payload_generator import _sanitize_for_prompt
from dast.models import AttackAttempt, AttackVerdict

_SYSTEM_ANALYZER = """\
You are an expert web application security analyst.
Analyze the HTTP request/response pair for evidence of a successful attack.
Be precise: report VULNERABLE only if there is clear evidence in the response.
Respond ONLY with JSON.
"""


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
  Body: {_sanitize_for_prompt(req.body or "", 500)}

Response:
  Status: {resp.status_code}
  Headers: {dict(list(resp.headers.items())[:5])}
  Body: {_sanitize_for_prompt(resp.body, 2000)}
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
        result = bedrock_client.invoke_json(system=_SYSTEM_ANALYZER, user=user)
        verdict_str = result.get("verdict", "INCONCLUSIVE").upper()
        verdict = AttackVerdict(verdict_str) if verdict_str in AttackVerdict._value2member_map_ else AttackVerdict.INCONCLUSIVE
        evidence = str(result.get("evidence", ""))
        confidence = float(result.get("confidence", 0.0))
        reasoning = str(result.get("reasoning", ""))
        return verdict, f"{evidence} | {reasoning}", confidence
    except Exception as e:
        return AttackVerdict.INCONCLUSIVE, f"Analysis error: {e}", 0.0
