"""
Crawl tool — drive Frieren's Playwright SPA crawler as an agent-callable primitive.

The crawler already exists (``dast/proxy/spa_crawler.py``) and is surfaced to humans
via ``POST /api/crawl`` (fire-and-forget onto the crawl worker's queue). This tool
exposes the SAME capability to the shared tool layer so the autonomous copilot can
discover an app's real surface — links, XHR/fetch endpoints, forms — instead of only
seeing the requests a human happened to proxy.

It is a discrete primitive, NOT orchestration: it runs ONE crawl of one seed URL and
returns the in-scope endpoints that appeared as a result. Deciding what to crawl and
what to do with the results is the driver's job.

Requires the in-process crawl queue (``ctx.crawl_queue``), so it only works for the
in-process copilot driver. The MCP process has no queue handle and gets a clear
"not available in this context" instead of a crash.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Set
from urllib.parse import urlparse

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Crawl completion is bounded so a stuck browser never blocks a copilot turn
# forever; on timeout we return whatever surface appeared so far.
_CRAWL_TIMEOUT_SECONDS = 240.0
_DEFAULT_MAX_CLICKS = 80
_MAX_CLICKS_CEILING = 300
_MAX_ENDPOINTS_RETURNED = 200

# Static assets are noise for vuln planning — omit them from the returned surface.
_STATIC_ASSET_SUFFIXES = (
    ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm",
)

_CRAWL_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "url": {
            "type": "string",
            "description": "In-scope seed URL to crawl (e.g. https://host/app). The crawler "
                           "navigates from here, clicking and following links within scope.",
        },
        "max_clicks": {
            "type": "integer",
            "description": f"Interaction budget for the crawl (default {_DEFAULT_MAX_CLICKS}, "
                           f"max {_MAX_CLICKS_CEILING}). Higher finds more but takes longer.",
        },
        "extra_seeds": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Optional extra in-scope URLs to seed the crawl beyond the main url.",
        },
    },
    "required": ["url"],
}


def _is_static_asset(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(suffix) for suffix in _STATIC_ASSET_SUFFIXES)


def _in_scope_url_set(store: Any) -> Set[str]:
    try:
        return {entry.url for entry in store.in_scope_entries()}
    except Exception as exc:
        logger.warning("crawl tool: history snapshot failed", error=str(exc))
        return set()


def _new_endpoints(store: Any, before: Set[str]) -> List[Dict[str, str]]:
    """In-scope endpoints that appeared after the crawl, minus static assets."""
    seen: Set[str] = set()
    endpoints: List[Dict[str, str]] = []
    try:
        entries = store.in_scope_entries()
    except Exception as exc:
        logger.warning("crawl tool: post-crawl history read failed", error=str(exc))
        return endpoints
    for entry in entries:
        url = entry.url
        if url in before or url in seen or _is_static_asset(url):
            continue
        seen.add(url)
        endpoints.append({"method": entry.method, "url": url})
        if len(endpoints) >= _MAX_ENDPOINTS_RETURNED:
            break
    return endpoints


async def _crawl(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    url = str(args.get("url", "")).strip()
    if not url:
        return {"ok": False, "error": "url is required"}
    if not ctx.is_in_scope(url):
        return {"ok": False, "error": "url is out of scope", "url": url}

    crawl_queue = getattr(ctx, "crawl_queue", None)
    store = getattr(ctx, "store", None)
    if crawl_queue is None or store is None:
        return {"ok": False, "error": "crawl is not available in this context", "url": url}

    try:
        max_clicks = int(args.get("max_clicks") or _DEFAULT_MAX_CLICKS)
    except (TypeError, ValueError):
        max_clicks = _DEFAULT_MAX_CLICKS
    max_clicks = max(1, min(max_clicks, _MAX_CLICKS_CEILING))

    extra_seeds = args.get("extra_seeds")
    if not isinstance(extra_seeds, list):
        extra_seeds = None

    before = _in_scope_url_set(store)
    done_event = asyncio.Event()
    logger.info("crawl tool: starting crawl", url=url, max_clicks=max_clicks)
    try:
        await crawl_queue.put({
            "url": url,
            "headless": True,
            "max_clicks": max_clicks,
            "extra_seeds": extra_seeds,
            "done_event": done_event,
        })
    except Exception as exc:
        return {"ok": False, "error": f"could not enqueue crawl: {str(exc)[:200]}", "url": url}

    timed_out = False
    try:
        await asyncio.wait_for(done_event.wait(), timeout=_CRAWL_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        timed_out = True
        logger.warning("crawl tool: crawl timed out, returning partial surface", url=url)

    endpoints = _new_endpoints(store, before)
    logger.info("crawl tool: crawl complete", url=url,
                discovered=len(endpoints), timed_out=timed_out)
    return {
        "ok": True,
        "url": url,
        "discovered_count": len(endpoints),
        "endpoints": endpoints,
        "timed_out": timed_out,
    }


register(Tool(
    name="crawl",
    description=(
        "Crawl an in-scope web app with Frieren's headless browser to discover its real "
        "attack surface: links, forms, and the XHR/fetch endpoints a SPA calls. Returns the "
        "in-scope endpoints (method + url) that were newly observed as a result.\n"
        "Use this when: you have a seed URL and need to map what's actually reachable before "
        "scanning — especially for a SPA where the interesting endpoints aren't in the page "
        "HTML. Crawled requests flow through the proxy, so with AI mode on they are also "
        "auto-scanned.\n"
        "This runs ONE crawl and blocks until it finishes (or a timeout). Do not use it to "
        "fetch a single page — use send_request for that."
    ),
    input_schema=_CRAWL_SCHEMA,
    handler=_crawl,
    tags=["recon"],
))
