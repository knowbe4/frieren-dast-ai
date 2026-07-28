"""
LLM classification of a probe-diff transformation signature.

``dast/agents/probe_diff.py`` produces a ``DiffSignature`` — a deterministic
record of how a parameter's break/repair probe pairs diverged. This module
interprets that signature: it asks the LLM which injection *class* and *context*
the divergence implies, so the coordinator can dispatch the right agents with a
high prior instead of spraying every payload set.

This is the "deep contextual reasoning" step from the product vision: the
transformation signature tells us *why* a parameter is injectable
(a single quote breaks it but an escaped quote does not → it lives in a quoted
string), which is far more actionable than a URL-pattern guess.

Degrades gracefully: any LLM failure returns a low-confidence "unknown"
verdict so the caller falls back to normal canary-driven planning — probe-diff
is an *enhancement* to targeting, never a gate on it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from dast.ai import bedrock_client
from dast.ai.prompt_safety import UNTRUSTED_CONTENT_DIRECTIVE, wrap_untrusted
from dast.ai.schemas import PROBE_CLASSIFIER_SCHEMA
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_SYSTEM = """\
You are a web application security expert interpreting a differential probe.

A single request parameter was probed with break/repair input PAIRS. For each
pair, a "break" input (designed to disturb an interpreter) and its
syntactically-neutralised "repair" twin were sent, and the two responses were
diffed. A pair that DIVERGED (break and repair produced different
status/structure/errors/arithmetic-evaluation) is strong evidence the parameter
flows into a parser or interpreter — the transformation signature reveals which
one and in what syntactic context.

Reason from the divergence signatures, NOT from the URL or parameter name:
- A quote breaks but its escaped twin does not -> the value sits in a quoted
  string context that honours escaping (classic SQL / string interpolation).
- 7*7 renders "49" but 7*'7 errors -> the value flows into a server-side
  template evaluator (SSTI).
- Break echoes unencoded while repair is encoded/stripped -> reflected-input /
  XSS context.
- A lone backslash changes behaviour -> an escape-honouring string context.

If no pair diverged, or the divergence is not injection-related (e.g. pure
caching/length noise), report injection_class "none" with low confidence.

Respond ONLY via the provided tool."""


@dataclass
class ProbeVerdict:
    injection_class: str          # e.g. "sqli", "ssti", "xss", "cmdi", "none"
    context: str                  # human-readable parsing context
    confidence: float             # 0.0–1.0
    recommended_agents: List[str] # attack-type ids to dispatch with a high prior
    reasoning: str

    @property
    def has_hypothesis(self) -> bool:
        return (
            self.injection_class not in ("", "none")
            and self.confidence > 0.0
        )


_UNKNOWN = ProbeVerdict(
    injection_class="none",
    context="",
    confidence=0.0,
    recommended_agents=[],
    reasoning="classification unavailable",
)


def classify(signature, model_id: Optional[str] = None) -> ProbeVerdict:
    """
    Classify a ``DiffSignature`` into an injection-class hypothesis.

    Only called when the signature actually has signal — a no-signal signature
    returns the inert verdict without an LLM round-trip. Any exception degrades
    to the low-confidence unknown verdict so planning proceeds normally.
    """
    if signature is None or not getattr(signature, "has_signal", False):
        return _UNKNOWN

    try:
        summary = signature.to_classifier_summary()
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Probe-diff summary failed", error=str(exc))
        return _UNKNOWN

    # The summary embeds target-controlled fragments (matched error strings), so
    # fence it as untrusted evidence.
    user = (
        "Interpret this differential-probe signature and identify the injection "
        "class, context, and which agents to run.\n\n"
        f"{wrap_untrusted(summary, 'probe_signature')}"
    )
    system = _SYSTEM + UNTRUSTED_CONTENT_DIRECTIVE

    try:
        from dast.ai.bedrock_client import get_fast_model
        result = bedrock_client.invoke_json(
            system=system,
            user=user,
            model_id=model_id or get_fast_model(),
            temperature=0,
            schema=PROBE_CLASSIFIER_SCHEMA,
        )
    except Exception as exc:
        logger.warning("Probe-diff classification failed", error=str(exc))
        return _UNKNOWN

    try:
        return ProbeVerdict(
            injection_class=str(result.get("injection_class", "none")).lower().strip(),
            context=str(result.get("context", "")),
            confidence=float(result.get("confidence", 0.0)),
            recommended_agents=[
                str(a).lower().strip()
                for a in (result.get("recommended_agents") or [])
                if str(a).strip()
            ],
            reasoning=str(result.get("reasoning", "")),
        )
    except (ValueError, TypeError) as exc:
        logger.warning("Probe-diff verdict parse failed", error=str(exc))
        return _UNKNOWN
