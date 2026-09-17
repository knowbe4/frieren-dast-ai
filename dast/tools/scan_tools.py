"""
run_scan tool — launch Frieren's full active scan against ONE endpoint and return
the findings.

This wraps the existing scan pipeline (the same one AI mode drives: Coordinator ->
LLM planner -> parallel VulnAgents -> Red-Team Validator). It does NOT reimplement
scanning — it enqueues an already-observed endpoint onto the scan worker exactly the
way the manual "Send to AI" button does (``dast/proxy/api/proxy_routes.py`` ->
``/api/manual/send-to-ai``), waits for that one endpoint's scan to finish, and
returns its findings.

It is a discrete primitive, NOT orchestration: it scans the single endpoint asked
for. Choosing which endpoints to scan, in what order, is the driver's job.

Requires the in-process scan queue + queue state (``ctx.scan_queue`` /
``ctx.scan_queue_state``), so it only works for the in-process copilot driver. The
MCP process gets a clear "not available in this context".

The agents (LLM planner + VulnAgents) run only when AI mode is on OR the target is a
deliberately imported entry (``run_agents = is_imported or ai_mode`` in the scan
worker). With AI mode off on a proxied entry, only the deterministic layer runs; the
result reports ``agents_ran`` so the caller knows which layer produced the findings.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# A full agent scan (LLM planner + parallel VulnAgents + red-team) can run for a few
# minutes; bound the wait so a hung scan never blocks the caller indefinitely.
_SCAN_TIMEOUT_SECONDS = 300.0
_MAX_FINDINGS_RETURNED = 25

_SCAN_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "url": {
            "type": "string",
            "description": "The in-scope endpoint URL to scan. It must already exist in Frieren's "
                           "history (proxy it with send_request or discover it with crawl first) — "
                           "the scan reuses that captured request as the injection surface.",
        },
        "method": {
            "type": "string",
            "description": "Optional HTTP method to disambiguate when history has both GET and POST "
                           "for the same url (default: newest matching entry regardless of method).",
        },
        "entry_id": {
            "type": "string",
            "description": "Optional exact history entry id to scan, instead of matching by url. "
                           "Use the id from get_history when you want to scan one specific request.",
        },
    },
    "required": ["url"],
}


def _compact_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Trim a stored finding to the fields useful for reasoning — drop the large raw
    request/response blobs the pipeline attaches for the report."""
    compact: Dict[str, Any] = {}
    for key in ("title", "attack_type", "severity", "confidence", "parameter", "url"):
        value = finding.get(key)
        if value:
            compact[key] = value
    description = finding.get("description")
    if description:
        compact["description"] = str(description)[:400]
    return compact


def _resolve_entry(store: Any, url: str, method: str, entry_id: str) -> Optional[Any]:
    """Find the entry to scan: by explicit id, else the newest history entry whose
    url (and method, if given) matches. Returns None if nothing matches."""
    if entry_id:
        return store.get_entry(entry_id)
    wanted_method = method.strip().upper() if method else ""
    for entry in reversed(store.all_entries()):
        if entry.url != url:
            continue
        if wanted_method and entry.method.upper() != wanted_method:
            continue
        return entry
    return None


async def _run_scan(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    url = str(args.get("url", "")).strip()
    if not url:
        return {"ok": False, "error": "url is required"}
    if not ctx.is_in_scope(url):
        return {"ok": False, "error": "url is out of scope", "url": url}

    store = getattr(ctx, "store", None)
    scan_queue = getattr(ctx, "scan_queue", None)
    scan_queue_state = getattr(ctx, "scan_queue_state", None)
    if store is None or scan_queue is None or scan_queue_state is None:
        return {"ok": False, "error": "run_scan is not available in this context", "url": url}

    method = str(args.get("method", "")).strip()
    entry_id = str(args.get("entry_id", "")).strip()
    entry = _resolve_entry(store, url, method, entry_id)
    if entry is None:
        return {
            "ok": False,
            "error": "no matching request in history to scan — proxy this endpoint with "
                     "send_request or discover it with crawl first, then scan it",
            "url": url,
        }
    # entry_id may resolve to a different url than the arg — gate the real target too.
    if not ctx.is_in_scope(entry.url):
        return {"ok": False, "error": "resolved entry is out of scope", "url": entry.url}

    agents_ran = entry.source == "imported" or bool(getattr(store, "ai_mode", False))

    # Mark it the way "Send to AI" does: ai_queued bypasses the once-per-endpoint
    # dedup so a deliberate re-scan actually runs.
    entry.ai_queued = True
    entry.queued_for_scan = True

    # Register the completion event BEFORE enqueuing so a fast finish() can't fire
    # before we're waiting on it.
    scan_queue_state.completion_event(entry.id)
    scan_queue_state.enqueue(entry.id, entry.method, entry.url, entry.host)
    try:
        await scan_queue.put(entry.id)
    except Exception as exc:
        return {"ok": False, "error": f"could not enqueue scan: {str(exc)[:200]}", "url": entry.url}

    logger.info("run_scan tool: scanning endpoint", url=entry.url,
                method=entry.method, entry_id=entry.id, agents_ran=agents_ran)
    completed = await scan_queue_state.await_entry(entry.id, _SCAN_TIMEOUT_SECONDS)

    scanned = store.get_entry(entry.id)
    raw_findings: List[Dict[str, Any]] = []
    scan_result = None
    if scanned is not None:
        scan_result = scanned.scan_result
        raw_findings = [f for f in (scanned.findings or []) if f.get("title")]

    findings = [_compact_finding(f) for f in raw_findings[:_MAX_FINDINGS_RETURNED]]
    result: Dict[str, Any] = {
        "ok": True,
        "url": entry.url,
        "method": entry.method,
        "entry_id": entry.id,
        "status": scan_result or ("scanning" if not completed else "safe"),
        "findings_count": len(raw_findings),
        "findings": findings,
        "agents_ran": agents_ran,
        "timed_out": not completed,
    }
    if not agents_ran:
        result["note"] = ("AI mode is off and this is a proxied (not imported) entry, so only "
                          "the deterministic layer ran — enable AI mode for the full arsenal.")
    logger.info("run_scan tool: scan complete", url=entry.url,
                status=result["status"], findings=len(raw_findings), timed_out=not completed)
    return result


register(Tool(
    name="run_scan",
    description=(
        "Launch Frieren's full active vulnerability scan against ONE already-observed endpoint "
        "and return the findings. This is the real arsenal — the LLM planner picks attack types, "
        "parallel VulnAgents (xss/sqli/ssrf/lfi/ssti/cmdi/xxe/idor/...) inject payloads, and the "
        "Red-Team Validator confirms them — the same pipeline AI mode runs.\n"
        "Use this when: you have a specific in-scope endpoint (from crawl, get_history, or a "
        "send_request you made) and want it actively scanned now, then want the confirmed "
        "findings back to reason about.\n"
        "The endpoint must already be in history. Blocks until this one scan finishes (or a "
        "timeout). To scan many endpoints, call it once per endpoint."
    ),
    input_schema=_SCAN_SCHEMA,
    handler=_run_scan,
    tags=["active"],
))
