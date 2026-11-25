"""attack_finding tool — spawn the XBOW-style attack subagent (5-C-1).

Given a candidate finding (by url+attack_type from the findings list, or an
explicit finding dict), runs the bounded escalation loop from
``dast.ai.attack_subagent``: hypothesis -> probe -> verify -> record, over a
restricted toolset with a hard budget. A confirmed candidate becomes a
recorded finding (via the record_finding tool inside the loop — grounded,
deduped, intel write-back included); a disproved one is closed as
``ruled_out`` in the coverage ledger. Same definition serves the copilot and
MCP clients ("one definition, two callers").
"""

from __future__ import annotations

from typing import Any, Dict

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_ATTACK_FINDING_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "url": {
            "type": "string",
            "description": "URL of the candidate finding to escalate (matched against /api/findings rows).",
        },
        "attack_type": {
            "type": "string",
            "description": "Class of the candidate (e.g. sqli, idor, ssrf). Required together with url unless `finding` is given.",
        },
        "finding": {
            "type": "object",
            "description": (
                "Explicit candidate dict (title/url/attack_type/payload/evidence). Use this when you "
                "already have the finding object in hand; url+attack_type is the lookup form."
            ),
            "properties": {
                "title": {"type": "string"},
                "url": {"type": "string"},
                "attack_type": {"type": "string"},
                "severity": {"type": "string"},
                "parameter": {"type": "string"},
                "payload": {"type": "string"},
                "evidence": {"type": "string"},
            },
        },
    },
}


async def _resolve_candidate(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    explicit = args.get("finding")
    if isinstance(explicit, dict) and explicit.get("url") and explicit.get("attack_type"):
        return explicit
    url = str(args.get("url", "")).strip()
    attack_type = str(args.get("attack_type", "")).strip().lower()
    if not url or not attack_type:
        return {}
    from dast.ai.chain_inventor import _gather_findings

    rows = await _gather_findings(ctx)
    url_host = url.split("/")[2] if "://" in url else ""
    for row in rows:
        if row.get("dismissed"):
            continue
        row_url = str(row.get("url", ""))
        if (row.get("attack_type") or "").lower() != attack_type:
            continue
        if url == row_url or (url_host and url_host in row_url):
            return row
    return {}


async def _attack_finding(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    from dast.ai.attack_subagent import AttackSubagent, is_escalatable

    candidate = await _resolve_candidate(ctx, args)
    if not candidate:
        return {"ok": False,
                "error": "candidate not found — pass an explicit `finding` dict, or url+attack_type matching a listed finding"}
    if not is_escalatable(candidate):
        return {"ok": False,
                "error": f"class '{candidate.get('attack_type')}' is not replay-verifiable; escalate it manually",
                "attack_type": candidate.get("attack_type")}
    result = await AttackSubagent(ctx, candidate).run()
    return {"ok": True, **result}


register(Tool(
    name="attack_finding",
    description=(
        "Spawn a single-purpose ATTACK SUBAGENT (XBOW pattern) to escalate ONE candidate "
        "finding to a proven verdict: the subagent gets a restricted toolset (repeater "
        "primitives + the class's deterministic probe + record_finding/record_coverage), a "
        "hard budget (~12 tool calls) and works hypothesis->probe->verify->record. Confirmed "
        "candidates become recorded findings with evidence; disproved ones are closed as "
        "ruled_out in the coverage ledger.\n"
        "Use this when a finding is unconfirmed/needs_review and you want it PROVEN or "
        "DISPROVEN without driving each request yourself. Only replay-verifiable classes "
        "(sqli, xss, idor, ssrf, authz, ...) are eligible. Do NOT use for single requests "
        "(send_request) or classes you cannot replay."
    ),
    input_schema=_ATTACK_FINDING_SCHEMA,
    handler=_attack_finding,
    tags=["triage", "http", "chain"],
))
