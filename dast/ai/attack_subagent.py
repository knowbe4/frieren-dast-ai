"""Attack subagent — the XBOW-style per-finding escalation loop (5-C-1).

The scan pipeline emits candidates it could NOT fully confirm (needs_review,
unconfirmed agent findings, imported hypotheses). Today those sit in the list
until a human or the copilot escalates them one by one. This module closes the
loop the XBOW way: for ONE candidate, a focused LLM subagent gets a hypothesis,
a RESTRICTED toolset (escalation primitives + the class's deterministic probe
+ record_finding/record_coverage), a hard budget, and an oracle contract:

    hypothesis -> probe -> verify -> record (confirmed with evidence)
                              -> rule out (coverage ruled_out)

Every tool call goes through the SAME registry the copilot and MCP use
(``run_tool`` — "one definition, two callers"), so scope gates, payload-safety
gates, read-only blocking and 5-A-2 intel write-back all apply unchanged.

Budgets are hard ceilings, not suggestions: max tool calls, wall-clock cap,
per-signature no-progress watchdog, consecutive-failure breaker — the same
watchdog philosophy as the copilot turn loop, scaled to a per-finding loop.

Only replay-verifiable classes are eligible: passive classes (sensitive_data)
and ones whose evidence is not replayable cannot be escalated by probes and
are skipped by ``is_escalatable``.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List, Optional, Set

from dast.ai import bedrock_client
from dast.ai.prompt_safety import UNTRUSTED_CONTENT_DIRECTIVE, wrap_untrusted
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Hard per-candidate budget (XBOW runs are tight; so is this).
MAX_TOOL_CALLS = 12
WALL_CLOCK_SECONDS = 240.0
_MAX_NOPROGRESS_REPEATS = 2
_MAX_CONSECUTIVE_FAILURES = 3
_OBSERVATION_MAX_CHARS = 1600

# Classes a probe loop CAN escalate — deterministic confirmation exists and the
# evidence is replayable. Passive/listing classes cannot: their "evidence" is a
# response body pattern that re-sending cannot reprove.
ESCALATABLE_ATTACK_TYPES: Set[str] = {
    "sqli", "xss", "cmdi", "ssti", "nosql", "lfi", "xxe", "ssrf", "idor",
    "auth_bypass", "authz_ladder", "bfla", "jwt", "oauth", "csrf", "hpp",
    "open_redirect", "cors", "host_header", "prototype_pollution", "graphql_idor",
    "graphql_abuse", "cache_poisoning", "cache_deception", "mfa_bypass",
    "password_reset", "business_logic", "race_condition", "llm_injection",
    "request_smuggling", "http2", "cswsh", "deserialization",
}

# The restricted menu: escalation primitives + recording + coverage. The
# class-specific deterministic probe is added per candidate.
_BASE_TOOL_ALLOWLIST = [
    "send_request", "test_unauth", "diff_responses", "extract_response",
    "verify_reflection", "oob_generate", "oob_poll",
    "record_finding", "record_coverage",
]

# attack_type -> deterministic probe tool (one per class, when one exists).
_PROBE_TOOL_BY_TYPE = {
    "sqli": "sqli_probe",
    "xss": "xss_probe",
    "idor": "idor_probe",
    "graphql_idor": "idor_probe",
    "auth_bypass": "authz_differential_probe",
    "authz_ladder": "authz_differential_probe",
    "bfla": "authz_differential_probe",
    "prototype_pollution": "prototype_pollution_probe",
    "cache_deception": "web_cache_deception_probe",
}

_ATTACK_STEP_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "thought": {
            "type": "string",
            "description": "One or two sentences: what the last observation showed and the next move.",
        },
        "action": {
            "type": "string",
            "enum": ["call_tool", "conclude"],
        },
        "tool_name": {
            "type": "string",
            "description": "Required when action=call_tool: one of the listed tools ONLY.",
        },
        "tool_args": {
            "type": "object",
            "description": "Required when action=call_tool, matching that tool's schema.",
            "additionalProperties": True,
        },
        "conclusion": {
            "type": "object",
            "description": "Required when action=conclude.",
            "properties": {
                "verdict": {
                    "type": "string",
                    "enum": ["confirmed", "ruled_out", "cannot_confirm"],
                    "description": (
                        "confirmed = the probes PROVED the issue (record_finding was called "
                        "with evidence entry ids); ruled_out = the probes DISPROVED it "
                        "(record_coverage ruled_out was called); cannot_confirm = blocked "
                        "(auth, WAF, scope) — say what is needed."
                    ),
                },
                "reasoning": {"type": "string"},
            },
            "required": ["verdict", "reasoning"],
        },
    },
    "required": ["thought", "action"],
}

_SYSTEM = (
    "You are a single-purpose attack subagent (XBOW pattern): escalate ONE candidate "
    "finding to a PROVEN result. Work in phases: (1) HYPOTHESIS — read the candidate; "
    "(2) PROBE — send the smallest set of requests that tests it, preferring the "
    "deterministic probe tool for the class; (3) VERIFY — compare against the control "
    "(diff_responses / test_unauth); (4) RECORD — a confirmed verdict REQUIRES "
    "record_finding with evidence entry ids from your probes; a disproved candidate "
    "REQUIRES record_coverage with outcome ruled_out; then conclude.\n\n"
    "Rules:\n"
    "1. Only tools from the menu; never invent arguments; URLs stay in scope.\n"
    "2. Detection only — no destructive payloads, no writes beyond what the candidate "
    "hypothesis needs to be proven.\n"
    "3. A tool result that repeats an earlier observation is no progress: change "
    "approach or conclude.\n"
    "4. Budget is tight (<= " + str(MAX_TOOL_CALLS) + " tool calls). Do not pad.\n"
    "5. If auth/WAF blocks every angle, conclude cannot_confirm and say exactly what "
    "an operator must provide."
)
_SYSTEM += UNTRUSTED_CONTENT_DIRECTIVE


def is_escalatable(finding: dict) -> bool:
    """True when the candidate's class can be proven by replaying probes."""
    if not isinstance(finding, dict):
        return False
    return (finding.get("attack_type") or "") in ESCALATABLE_ATTACK_TYPES


def _candidate_brief(finding: dict) -> str:
    parts = [
        f"title: {finding.get('title', '?')}",
        f"attack_type: {finding.get('attack_type', '?')}",
        f"severity: {finding.get('severity', '?')}",
        f"url: {finding.get('url', '?')}",
    ]
    if finding.get("method"):
        parts.append(f"method: {finding['method']}")
    if finding.get("parameter"):
        parts.append(f"parameter: {finding['parameter']}")
    if finding.get("payload"):
        parts.append(f"payload tried: {finding['payload']}")
    if finding.get("evidence"):
        parts.append(f"evidence so far:\n{finding['evidence'][:800]}")
    return "\n".join(parts)


def _render_menu(tool_defs: List[dict]) -> str:
    lines = []
    for definition in tool_defs:
        desc = (definition.get("description") or "").strip().splitlines()
        lines.append(f"- {definition['name']}: {desc[0] if desc else ''}")
    return "\n".join(lines)


def _signature(tool_name: str, args: dict) -> str:
    """Normalized call signature for the no-progress watchdog (volatile keys
    ignored — same philosophy as the copilot's _repeat_sigs)."""
    volatile = {"headers", "cookie", "cookies", "authorization"}
    flat = sorted(
        (k, str(v)[:120]) for k, v in (args or {}).items() if k.lower() not in volatile
    )
    return f"{tool_name}:{flat}"


class AttackSubagent:
    """One candidate, one loop, one verdict."""

    def __init__(self, ctx, finding: dict, model_id: Optional[str] = None):
        self._ctx = ctx
        self._finding = finding
        self._model_id = model_id or bedrock_client.get_validation_model()
        self.transcript: List[Dict[str, Any]] = []

    def _tool_defs(self) -> List[dict]:
        from dast.tools.base import all_tools

        allow = set(_BASE_TOOL_ALLOWLIST)
        probe = _PROBE_TOOL_BY_TYPE.get(self._finding.get("attack_type", ""))
        if probe:
            allow.add(probe)
        return [{"name": t.name, "description": t.description, "input_schema": t.input_schema}
                for t in all_tools() if t.name in allow]

    async def run(self) -> Dict[str, Any]:
        from dast.tools.base import run_tool

        defs = {d["name"] for d in self._tool_defs()}
        menu = _render_menu(self._tool_defs())
        candidate = wrap_untrusted(_candidate_brief(self._finding), "candidate_finding", 1200)

        user = (
            f"Escalate this candidate finding.\n\n{candidate}\n\n"
            f"Tools you may call (ONLY these):\n{menu}\n\n"
            "Begin. Conclude as soon as the verdict is proven either way."
        )

        transcript: List[Dict[str, Any]] = []
        sig_outcomes: Dict[str, List[str]] = {}
        consecutive_failures = 0
        deadline = time.monotonic() + WALL_CLOCK_SECONDS
        final: Dict[str, Any] = {
            "verdict": "cannot_confirm",
            "reasoning": "budget exhausted before a conclusion",
            "tool_calls": 0, "transcript": transcript,
        }

        for step_index in range(1, MAX_TOOL_CALLS + 2):
            if time.monotonic() > deadline:
                final["reasoning"] = "wall-clock budget reached before conclusion"
                break
            history = "\n".join(
                f"step {item['step']} ({item['tool_name']}): "
                + wrap_untrusted(str(item.get("observation", ""))[:400], "obs", 400)
                for item in transcript[-6:]
            ) or "(no tool calls yet)"
            step_user = f"{user}\n\nProgress so far:\n{history}"
            try:
                loop = asyncio.get_running_loop()
                step = await loop.run_in_executor(
                    None, lambda: bedrock_client.invoke_json(
                        system=_SYSTEM, user=step_user, model_id=self._model_id,
                        max_tokens=1500, temperature=0, cache_system=True,
                        schema=_ATTACK_STEP_SCHEMA, purpose="attack_subagent_step",
                    ))
            except Exception as exc:
                logger.warning("attack subagent step failed", error=str(exc))
                consecutive_failures += 1
                if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
                    final["reasoning"] = f"LLM unavailable after {consecutive_failures} failures"
                    break
                continue

            if step.get("action") == "conclude" or isinstance(step.get("conclusion"), dict):
                conclusion = step.get("conclusion") or {}
                final = {
                    "verdict": conclusion.get("verdict", "cannot_confirm"),
                    "reasoning": conclusion.get("reasoning", ""),
                    "tool_calls": len(transcript), "transcript": transcript,
                }
                break
            if step.get("action") != "call_tool" or step.get("tool_name") not in defs:
                consecutive_failures += 1
                if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
                    final["reasoning"] = "subagent kept proposing unavailable tools"
                    break
                continue
            consecutive_failures = 0

            tool_name = step["tool_name"]
            tool_args = step.get("tool_args") or {}
            sig = _signature(tool_name, tool_args)
            if len(sig_outcomes.get(sig, [])) >= _MAX_NOPROGRESS_REPEATS:
                final["reasoning"] = f"no-progress loop on {tool_name}"
                break
            sig_outcomes.setdefault(sig, []).append("ran")

            observation = await run_tool(self._ctx, tool_name, tool_args)
            # record_finding / record_coverage CLOSE the loop deterministically:
            # their success IS the verdict — no need to let the LLM conclude too.
            if tool_name == "record_finding" and observation.get("ok"):
                final = {
                    "verdict": "confirmed", "reasoning": "record_finding succeeded",
                    "tool_calls": len(transcript) + 1, "transcript": transcript,
                    "recorded": observation,
                }
                break
            if tool_name == "record_coverage" and observation.get("ok") \
                    and (tool_args or {}).get("outcome") == "ruled_out":
                final = {
                    "verdict": "ruled_out", "reasoning": "record_coverage ruled_out succeeded",
                    "tool_calls": len(transcript) + 1, "transcript": transcript,
                    "recorded": observation,
                }
                break

            transcript.append({
                "step": step_index, "tool_name": tool_name, "tool_args": tool_args,
                "thought": step.get("thought", ""),
                "observation": str(observation)[:_OBSERVATION_MAX_CHARS],
            })

        self.transcript = transcript
        final["title"] = self._finding.get("title", "")
        final["url"] = self._finding.get("url", "")
        final["attack_type"] = self._finding.get("attack_type", "")
        logger.info("attack subagent concluded", title=final.get("title", ""),
                    verdict=final.get("verdict"), tool_calls=final.get("tool_calls"))
        return final


async def escalate_candidate(ctx, finding: dict,
                             model_id: Optional[str] = None) -> Dict[str, Any]:
    """Convenience entry: build a subagent for ``finding`` and run it."""
    return await AttackSubagent(ctx, finding, model_id=model_id).run()
