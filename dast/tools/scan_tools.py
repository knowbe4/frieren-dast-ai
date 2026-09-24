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


# ── scan_surface: breadth-first scan of every observed-but-unscanned endpoint ──

_DEFAULT_MAX_ENDPOINTS = 20
_HARD_MAX_ENDPOINTS = 100

_SURFACE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "max_endpoints": {
            "type": "integer",
            "description": "Max untested endpoints to scan in this call (default 20, cap 100). "
                           "Untested endpoints carry over — call again to cover the remainder.",
        },
        "methods": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Optional HTTP method filter (e.g. [\"POST\",\"PUT\"]). Default: all methods.",
        },
    },
    "required": [],
}


def _untested_surface_entries(store: Any, ctx: ToolContext, methods: List[str]) -> List[Any]:
    """One representative in-scope, not-yet-scanned entry per distinct endpoint
    (method + id-normalised path), newest first. Skips synthetic agent/scan traffic
    so only real observed endpoints are scanned."""
    from dast.proxy.session_store import normalise_endpoint_path

    wanted = {m.strip().upper() for m in methods if m and m.strip()}
    seen_endpoints: set = set()
    representatives: List[Any] = []
    try:
        entries = store.in_scope_entries()
    except Exception:
        entries = list(store.all_entries())
    for entry in sorted(entries, key=lambda e: getattr(e, "ts", 0.0), reverse=True):
        method = (entry.method or "").upper()
        if method in ("CONNECT", "OPTIONS", "HEAD"):
            continue
        if wanted and method not in wanted:
            continue
        if getattr(entry, "source", "") in ("agent", "scanner", "scan", "out-of-scope"):
            continue
        if getattr(entry, "scan_result", None):
            continue  # already scanned
        if not ctx.is_in_scope(entry.url):
            continue
        key = (method, normalise_endpoint_path(entry.path))
        if key in seen_endpoints:
            continue
        seen_endpoints.add(key)
        representatives.append(entry)
    return representatives


async def _scan_surface(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    store = getattr(ctx, "store", None)
    scan_queue = getattr(ctx, "scan_queue", None)
    scan_queue_state = getattr(ctx, "scan_queue_state", None)
    if store is None or scan_queue is None or scan_queue_state is None:
        return {"ok": False, "error": "scan_surface is not available in this context"}

    try:
        max_endpoints = int(args.get("max_endpoints", _DEFAULT_MAX_ENDPOINTS))
    except (TypeError, ValueError):
        max_endpoints = _DEFAULT_MAX_ENDPOINTS
    max_endpoints = max(1, min(max_endpoints, _HARD_MAX_ENDPOINTS))
    methods = args.get("methods") if isinstance(args.get("methods"), list) else []

    candidates = _untested_surface_entries(store, ctx, methods)
    batch = candidates[:max_endpoints]
    if not batch:
        return {"ok": True, "scanned_now": 0, "remaining": 0, "results": [],
                "note": "no untested in-scope endpoints observed — crawl to discover more surface first"}

    import asyncio

    entry_ids: List[str] = []
    for entry in batch:
        entry.ai_queued = True
        entry.queued_for_scan = True
        scan_queue_state.completion_event(entry.id)
        scan_queue_state.enqueue(entry.id, entry.method, entry.url, entry.host)
        try:
            await scan_queue.put(entry.id)
            entry_ids.append(entry.id)
        except Exception as exc:
            logger.warning("scan_surface: enqueue failed", url=entry.url, error=str(exc))
    logger.info("scan_surface: scanning endpoints", count=len(entry_ids),
                remaining=len(candidates) - len(batch))

    await asyncio.gather(*[
        scan_queue_state.await_entry(entry_id, _SCAN_TIMEOUT_SECONDS)
        for entry_id in entry_ids
    ], return_exceptions=True)

    results: List[Dict[str, Any]] = []
    vulnerable = 0
    for entry_id in entry_ids:
        scanned = store.get_entry(entry_id)
        if scanned is None:
            continue
        finding_count = len([f for f in (scanned.findings or []) if f.get("title")])
        if scanned.scan_result == "vulnerable":
            vulnerable += 1
        results.append({
            "url": scanned.url,
            "method": scanned.method,
            "status": scanned.scan_result or "scanning",
            "findings_count": finding_count,
        })

    remaining = len(candidates) - len(batch)
    summary: Dict[str, Any] = {
        "ok": True,
        "scanned_now": len(entry_ids),
        "vulnerable_endpoints": vulnerable,
        "remaining": remaining,
        "results": results,
    }
    if remaining > 0:
        summary["note"] = (f"{remaining} untested endpoints remain — call scan_surface again "
                           f"to cover them")
    logger.info("scan_surface: batch complete", scanned=len(entry_ids),
                vulnerable=vulnerable, remaining=remaining)
    return summary


register(Tool(
    name="scan_surface",
    description=(
        "Launch Frieren's full active scan across EVERY in-scope endpoint that has been observed "
        "but not yet scanned — one representative request per distinct endpoint (id-like path "
        "segments are collapsed, so /users/1 and /users/2 count once). Use this for breadth-first "
        "coverage of the REST attack surface so no controller is left untested; it is the "
        "multi-endpoint companion to run_scan (which scans exactly one endpoint).\n"
        "Scans run through the same pipeline (LLM planner + parallel VulnAgents + Red-Team "
        "Validator). Blocks until this batch finishes (or times out). Untested endpoints carry "
        "over between calls — call again until 'remaining' is 0. Crawl first to widen the surface "
        "this can reach."
    ),
    input_schema=_SURFACE_SCHEMA,
    handler=_scan_surface,
    tags=["active"],
))


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
