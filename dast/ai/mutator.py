"""
LLM payload mutator — adaptive attack loop.

After each probe attempt, the LLM analyses what the server did (reflected,
encoded, stripped, WAF blocked, etc.) and generates a new payload variant
targeting the specific defence observed.

This runs up to MAX_ITERATIONS times per parameter before giving up.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import List, Optional

from dast.ai import bedrock_client
from dast.ai.prompt_safety import UNTRUSTED_CONTENT_DIRECTIVE, wrap_untrusted
from dast.ai.schemas import MUTATOR_SCHEMA
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Hard ceiling to prevent infinite loops caused by bugs, not by the LLM.
# The LLM is the primary stop signal — it returns action="stop" when no further
# bypass is worth attempting. This limit only fires if the LLM never stops.
# 15 rounds is sufficient for realistic WAF bypass scenarios; 50 was excessive.
_SAFETY_CEILING = 15

_SYSTEM_MUTATOR = """\
You are an expert web application penetration tester running an adaptive attack loop.
You sent a payload and received a response. Analyse what happened and decide the next move.

You are in full control of when to stop — only use "stop" when you have genuinely exhausted
all reasonable bypass strategies for the observed defence. Do NOT stop just because a few
attempts failed; keep trying different techniques until you are confident nothing will work.

Response actions:
  mutate    — generate a new variant targeting the specific defence observed
  obfuscate — try encoding/casing/splitting to bypass WAF or filter
  stop      — only when you have tried all meaningful strategies and none are left

Bypass strategies by attack type (non-exhaustive):
  XSS:   tag stripped → event handler, javascript:URI, DOM sink; encoded → bypass encoding; WAF → polyglots, mutation XSS
  SQLi:  quote filtered → hex literals, char(), comments; WAF → whitespace variations, URL encoding, HTTP param pollution
  SSRF:  domain blocked → decimal IP, octal IP, IPv6, CNAME redirection, DNS rebinding payloads, redirect chains
  LFI:   ../ stripped → URL encode, double encode, null byte, Unicode normalization, zip wrapper
  SSTI:  {{ blocked → string concat, whitespace, alternate delimiters, engine-specific syntax

Rules:
- Before generating a new payload, you MUST quote the exact substring from the server response
  that identifies the active defence (e.g. the WAF error message, the encoded output, the
  stripped characters). Set this as your rationale. If you cannot quote a specific substring
  from the response that reveals the defence, use action="stop" — do not guess.
- Generate payloads that target the SPECIFIC defence you just quoted
- Do NOT generate payloads that delete/modify data, cause > 5s delay, or exhaust server resources
- Each new payload must be meaningfully different from previous attempts
- Respond ONLY with valid JSON

Examples:

Response snippet: `Error: input contains illegal character &#x27; (single quote stripped)`
Good: {"action": "mutate", "payload": "1 OR 1=1-- ", "rationale": "Response says the single quote was stripped; this boolean payload needs no quotes to break the WHERE clause."}

Response snippet: `{"status":"ok","id":42}` (payload reflected nowhere, no error, no defence visible)
Good: {"action": "stop", "payload": "", "rationale": "No defence substring is quotable from the response and the payload is not reflected; guessing further would be noise."}"""

# The user message embeds the target's response snippet, so append the
# structural untrusted-content directive.
_SYSTEM_MUTATOR += UNTRUSTED_CONTENT_DIRECTIVE


@dataclass
class MutationResult:
    action: str          # mutate | obfuscate | stop
    payload: str
    rationale: str


def build_mutator_context(target: object, attack_type: str) -> Optional[str]:
    """
    Assemble the ``tech_context`` string for the mutator from everything known
    about the target: the tech-stack discovery summary AND the per-host WAF
    memory (vendor, previously blocked payloads, and payloads that already
    bypassed a block — Gap 2). Agents call this instead of hand-building the
    context so the WAF memory actually reaches the mutator on every attack type.

    Returns None when there is nothing useful to add.
    """
    sections: List[str] = []

    discovery = getattr(target, "discovery_context", None)
    if discovery is not None:
        try:
            summary = discovery.to_agent_summary()
            if summary:
                sections.append(summary)
        except Exception:  # pragma: no cover - defensive; never break the scan
            pass

    host_intel = getattr(target, "host_intel", None)
    if host_intel is not None:
        try:
            waf_hint = host_intel.to_mutator_hint(attack_type)
            if waf_hint:
                sections.append(waf_hint)
        except Exception:  # pragma: no cover - defensive
            pass

    probe_hint = getattr(target, "probe_diff_hint", "")
    if probe_hint:
        sections.append(probe_hint)

    mining_hint = getattr(target, "param_mining_hint", "")
    if mining_hint:
        sections.append(mining_hint)

    return "\n".join(sections) if sections else None


async def next_payload(
    attack_type: str,
    original_payload: str,
    parameter: str,
    response_status: int,
    response_snippet: str,
    iteration: int,
    tried_payloads: Optional[List[str]] = None,
    tech_context: Optional[str] = None,
) -> Optional[MutationResult]:
    """
    Ask the LLM what to try next given what the server did.
    Returns None when the LLM decides to stop or the safety ceiling is reached.
    The LLM is the primary stop signal — it returns action="stop" when no further
    bypass strategy is worth attempting.
    """
    if iteration >= _SAFETY_CEILING:
        return None

    tried_section = ""
    if tried_payloads:
        listed = "\n".join(f"  - {p!r}" for p in tried_payloads[-20:])
        tried_section = f"\nPayloads already tried (do NOT repeat these):\n{listed}\n"

    tech_section = ""
    if tech_context:
        tech_section = f"\nTarget tech context (use to inform payload choice):\n{tech_context}\n"

    # Positive examples from the vulnerability knowledge base — show the mutator
    # what proven exploitation of this attack type looks like so it aims its
    # variants at reproducing that evidence rather than probing blindly.
    examples_section = ""
    try:
        from dast.vuln_knowledge import format_positive_examples
        examples_block = format_positive_examples(attack_type)
        if examples_block:
            examples_section = f"\n{examples_block}\n"
    except Exception as exc:
        logger.warning("Mutator: vuln-knowledge lookup failed", attack_type=attack_type, error=str(exc))

    user = f"""\
Attack type: {attack_type}
Parameter: {parameter}
Iteration: {iteration + 1}
{tried_section}{tech_section}{examples_section}
Last payload sent:
{original_payload!r}

Server response (status {response_status}):
{wrap_untrusted(response_snippet, 'target_response', 800)}
Decide the next action and respond with JSON:
{{
  "action": "mutate" | "obfuscate" | "stop",
  "payload": "<new payload string, empty if action=stop>",
  "rationale": "<one sentence: what defence did you observe, and how does this new payload bypass it>"
}}"""

    try:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None,
            lambda: bedrock_client.invoke_json(
                system=_SYSTEM_MUTATOR, user=user,
                schema=MUTATOR_SCHEMA, cache_system=True,
            ),
        )
        action = result.get("action", "stop")
        if action == "stop" or not result.get("payload"):
            logger.debug("Mutator: LLM decided to stop", attack_type=attack_type, tried=len(tried_payloads or []))
            return None
        mutation = MutationResult(
            action=action,
            payload=str(result["payload"]),
            rationale=str(result.get("rationale", "")),
        )
        logger.debug("Mutator: new payload generated", action=action, attack_type=attack_type,
                     payload=mutation.payload[:80], rationale=mutation.rationale[:100])
        return mutation
    except Exception as exc:
        logger.warning("Mutator: LLM call failed", attack_type=attack_type, error=str(exc))
        return None
