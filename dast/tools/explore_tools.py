"""
Explore tool — drive Frieren's exhaustive SpaExplorer as an agent-callable primitive.

Where ``crawl`` runs a bounded, shallow click-crawl, ``explore`` drives the
``SpaExplorer`` (``dast/proxy/spa_explorer.py``): it works a persisted UI-route
frontier, reveals menus, descends shadow DOM, follows client-side routes, and —
only when ``submit_forms`` is set and the run is active — fills/submits forms with
benign canaries. It is the breadth engine for a "complete" test: call it, then
call it again, until ``frontier_remaining`` is 0.

Requires the in-process crawl queue (``ctx.crawl_queue``) and store, so it only
works for the in-process copilot driver; elsewhere it returns a clear
"not available in this context".
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.tools.crawl_tools import _in_scope_url_set, _new_endpoints
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# An exhaustive explore can legitimately run for minutes; give it a long leash but
# still bound it so a wedged browser never blocks a copilot turn forever. The
# explorer resumes from the persisted frontier on the next call.
_EXPLORE_TIMEOUT_SECONDS = 900.0

_EXPLORE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "url": {
            "type": "string",
            "description": "In-scope seed URL to explore (e.g. https://host/app). Exploration "
                           "resumes from the persisted route frontier, so re-calling with the "
                           "same seed continues where it left off.",
        },
        "submit_forms": {
            "type": "boolean",
            "description": "When true (active runs only), fill forms with benign canary values and "
                           "submit them to reach wizard steps and capture update/mutation requests. "
                           "Default false (map and navigate only; no writes).",
        },
    },
    "required": ["url"],
}


async def _explore(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    url = str(args.get("url", "")).strip()
    if not url:
        return {"ok": False, "error": "url is required"}
    if not ctx.is_in_scope(url):
        return {"ok": False, "error": "url is out of scope", "url": url}

    crawl_queue = getattr(ctx, "crawl_queue", None)
    store = getattr(ctx, "store", None)
    if crawl_queue is None or store is None:
        return {"ok": False, "error": "explore is not available in this context", "url": url}

    read_only = bool(getattr(ctx, "read_only", False))
    # Form submission is active-only; read-only runs always map-only regardless of the flag.
    submit_forms = bool(args.get("submit_forms", False)) and not read_only

    before = _in_scope_url_set(store)
    done_event = asyncio.Event()
    logger.info("explore tool: starting", url=url, submit_forms=submit_forms, read_only=read_only)
    try:
        await crawl_queue.put({
            "mode": "exhaustive",
            "url": url,
            "headless": True,
            "read_only": read_only,
            "submit_forms": submit_forms,
            "session_safe": bool(getattr(ctx, "session_safe", False)),
            "done_event": done_event,
        })
    except Exception as exc:
        return {"ok": False, "error": f"could not enqueue explore: {str(exc)[:200]}", "url": url}

    timed_out = False
    try:
        await asyncio.wait_for(done_event.wait(), timeout=_EXPLORE_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        timed_out = True
        logger.warning("explore tool: timed out, returning partial surface", url=url)

    endpoints = _new_endpoints(store, before)
    stats = store.ui_route_graph.stats()
    logger.info("explore tool: complete", url=url, discovered=len(endpoints),
                frontier=stats["frontier"], visited=stats["visited"], timed_out=timed_out)
    return {
        "ok": True,
        "url": url,
        "routes_visited": stats["visited"],
        "frontier_remaining": stats["frontier"],
        "forms_submitted": stats["forms_submitted"],
        "discovered_count": len(endpoints),
        "endpoints": endpoints,
        "timed_out": timed_out,
    }


register(Tool(
    name="explore",
    description=(
        "Exhaustively explore an in-scope SPA like a human analyst: visit every discoverable "
        "route, reveal dropdown/hover menus, descend shadow DOM, follow client-side routes, and "
        "(with submit_forms=true, active runs only) fill and submit forms with benign canaries to "
        "reach wizard steps and capture update/mutation requests. Maintains a persisted route "
        "frontier.\n"
        "Use this for a COMPLETE test: call it, read frontier_remaining, and call again with the "
        "same url until frontier_remaining is 0. Crawled/clicked requests flow through the proxy, "
        "so with AI mode on they are also auto-scanned. For a quick shallow surface map use `crawl` "
        "instead."
    ),
    input_schema=_EXPLORE_SCHEMA,
    handler=_explore,
    tags=["recon"],
))
