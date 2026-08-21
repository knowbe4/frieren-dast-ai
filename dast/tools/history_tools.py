"""
get_history tool — read captured proxy traffic.

Dual data path (see ToolContext): an internal caller passes the live SessionStore
and reads it directly; the MCP process has no store, so it fetches ``/api/entries``
from the running dashboard over HTTP. One tool, both callers.
"""

from __future__ import annotations

from typing import Any, Dict, List

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_GET_HISTORY_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "host": {"type": "string", "description": "Optional host substring filter."},
        "limit": {"type": "integer", "description": "Max entries to return (default 50, max 500)."},
    },
    "required": [],
}


def _filter_and_limit(entries: List[dict], host: str, limit: int) -> List[dict]:
    if host:
        host_l = host.lower()
        entries = [e for e in entries if host_l in str(e.get("host", "")).lower()]
    return entries[-limit:] if limit > 0 else entries


async def _get_history(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    host = str(args.get("host", "")).strip()
    try:
        limit = int(args.get("limit", 50))
    except (TypeError, ValueError):
        limit = 50
    limit = max(1, min(limit, 500))

    # In-process path: read the live store directly.
    if ctx.store is not None:
        try:
            entries = [e.to_dict() for e in ctx.store.all_entries()]
            entries = _filter_and_limit(entries, host, limit)
            return {"ok": True, "count": len(entries), "entries": entries}
        except Exception as exc:
            return {"ok": False, "error": f"store read failed: {str(exc)[:200]}"}

    # External (MCP) path: query the running dashboard.
    try:
        import httpx

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{ctx.dashboard_base_url}/api/entries")
            resp.raise_for_status()
            entries = resp.json()
        if not isinstance(entries, list):
            return {"ok": False, "error": "unexpected /api/entries response shape"}
        entries = _filter_and_limit(entries, host, limit)
        return {"ok": True, "count": len(entries), "entries": entries}
    except Exception as exc:
        return {"ok": False, "error": f"dashboard fetch failed: {str(exc)[:200]}"}


register(Tool(
    name="get_history",
    description=(
        "Return HTTP entries already captured by the proxy (method, url, host, status, "
        "timing), optionally filtered by host and limited. Read-only — sends no traffic.\n"
        "Use this when: you need to see what has already been observed before acting — "
        "finding a target endpoint, inspecting a prior request/response, or understanding "
        "an app's surface before probing it.\n"
        "Do NOT use this to: send or replay a request (use send_request); list confirmed "
        "vulnerabilities (use get_findings); or discover endpoints that were never visited "
        "(use content_discovery)."
    ),
    input_schema=_GET_HISTORY_SCHEMA,
    handler=_get_history,
    tags=["read"],
))
