"""record_coverage tool — the copilot's entry into the 3-H coverage ledger.

Closes the 3-H follow-up: the ledger's v1 writer was machine-observed only
(the Coordinator). This tool lets the COPILOT record what IT examined, ruled
out, or left open on a surface while working autonomously — same closed
outcome vocabulary, same caps and normalization as
``dast/coverage/ledger.py``. An absent finding never reads as clean: use
``no_issue_found`` WITH evidence, or ``needs_follow_up`` with a reason.
"""

from __future__ import annotations

from typing import Any, Dict

from dast.coverage.ledger import OUTCOMES
from dast.tools.base import Tool, register
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "url": {"type": "string",
                "description": "The endpoint/URL the coverage refers to (same "
                               "surface the scan dedup uses). Required."},
        "risk_area": {"type": "string",
                      "description": "Attack class examined, e.g. sqli, xss, "
                                     "idor, graphql_abuse. Required."},
        "outcome": {"type": "string", "enum": list(OUTCOMES),
                    "description": "reported (a finding exists) | no_issue_found "
                                   "(probed, nothing found — include evidence) | "
                                   "ruled_out (cannot exist here — include reason) | "
                                   "not_applicable (auth/tech excludes it — include "
                                   "reason) | needs_follow_up (inconclusive — "
                                   "include reason). Required."},
        "evidence": {"type": "string",
                     "description": "REQUIRED for no_issue_found: what proves the "
                                    "test happened (probe counts, observation ids)."},
        "reason": {"type": "string",
                   "description": "REQUIRED for ruled_out / not_applicable / "
                                  "needs_follow_up: why the outcome holds."},
    },
    "required": ["url", "risk_area", "outcome"],
}


async def _record_coverage(ctx: Any, args: Dict[str, Any]) -> Dict[str, Any]:
    from urllib.parse import urlparse as _up

    from dast.coverage import ledger

    url = str(args.get("url", "")).strip()
    if not url:
        return {"ok": False, "error": "url is required"}
    parsed = _up(url)
    host = parsed.hostname or ""
    path = parsed.path or "/"
    risk_area = str(args.get("risk_area", "")).strip()
    outcome = str(args.get("outcome", "")).strip()
    evidence = str(args.get("evidence", "")).strip()
    reason = str(args.get("reason", "")).strip()

    if outcome not in OUTCOMES:
        return {"ok": False,
                "error": f"invalid outcome — use one of {', '.join(OUTCOMES)}"}
    if outcome == "no_issue_found" and not evidence:
        return {"ok": False, "error": "no_issue_found requires evidence (what "
                                      "proves the test happened)"}
    if outcome in ("ruled_out", "not_applicable", "needs_follow_up") and not reason:
        return {"ok": False, "error": f"{outcome} requires a reason"}

    try:
        entry = ledger.record(
            method=str(args.get("method", "GET") or "GET"),
            host=host, path=path,
            op=str(args.get("operation", "") or ""),
            risk_area=risk_area, outcome=outcome,
            evidence=evidence, reason=reason,
        )
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    gap_note = ""
    if outcome in ("no_issue_found", "ruled_out", "not_applicable") and not \
            (evidence or reason):
        gap_note = " — recorded, but counted as a gap (missing evidence/reason)"
    logger.info("copilot recorded coverage", surface=entry.surface,
                risk_area=entry.risk_area, outcome=entry.outcome)
    return {"ok": True, "recorded": entry.as_dict(), "note": gap_note}


register(Tool(
    name="record_coverage",
    description=(
        "Record what you examined on a surface for one risk class — including "
        "NEGATIVE results, so an absent finding is never read as a clean target. "
        "Use after probing an endpoint: outcome no_issue_found (with evidence) "
        "when the class was tested clean; ruled_out when it cannot exist there; "
        "needs_follow_up when inconclusive. These entries feed the planner's "
        "coverage view — an unrecorded class stays UNEXAMINED, never clean."
    ),
    input_schema=_SCHEMA,
    handler=_record_coverage,
    tags=["coverage", "triage"],
))
