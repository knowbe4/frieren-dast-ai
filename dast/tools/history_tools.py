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
        "entry_id": {
            "type": "string",
            "description": "Look up ONE entry by its exact id and return it in full "
                           "(with request/response bodies). When set, all other filters "
                           "are ignored. Use this to inspect a specific captured request.",
        },
        "host": {"type": "string", "description": "Host substring filter (case-insensitive)."},
        "method": {
            "type": "string",
            "description": "Exact HTTP method filter (e.g. GET, POST), case-insensitive.",
        },
        "path": {
            "type": "string",
            "description": "Path substring filter (case-insensitive), e.g. '/compose/send'. "
                           "Combine with method to find a specific captured request amid noise.",
        },
        "source": {
            "type": "string",
            "description": "Filter by how the entry was captured: 'proxy' (manual browser), "
                           "'browse', 'crawler', 'agent', 'scan', 'copilot', 'imported', "
                           "'out-of-scope'. Use 'copilot' or 'proxy' to skip scanner/agent "
                           "probe noise.",
        },
        "limit": {"type": "integer", "description": "Max entries to return (default 50, max 500)."},
        "newest_first": {
            "type": "boolean",
            "description": "Return the most recent entries first (default true). The limit is "
                           "applied after sorting, so you get the newest N matching entries.",
        },
    },
    "required": [],
}


def _matches(entry: dict, host: str, method: str, path: str, source: str) -> bool:
    if host and host not in str(entry.get("host", "")).lower():
        return False
    if method and method != str(entry.get("method", "")).upper():
        return False
    if path and path not in str(entry.get("path", "")).lower():
        return False
    if source and source != str(entry.get("source", "")).lower():
        return False
    return True


def _filter_sort_limit(
    entries: List[dict], host: str, method: str, path: str, source: str,
    limit: int, newest_first: bool,
) -> List[dict]:
    filtered = [e for e in entries if _matches(entry=e, host=host, method=method, path=path, source=source)]
    # entries arrive oldest-first; most recent is the tail. Keep the newest `limit`.
    if newest_first:
        filtered = list(reversed(filtered))
    return filtered[:limit] if limit > 0 else filtered


def _read_args(args: Dict[str, Any]) -> Dict[str, Any]:
    try:
        limit = int(args.get("limit", 50))
    except (TypeError, ValueError):
        limit = 50
    return {
        "entry_id": str(args.get("entry_id", "")).strip(),
        "host": str(args.get("host", "")).strip().lower(),
        "method": str(args.get("method", "")).strip().upper(),
        "path": str(args.get("path", "")).strip().lower(),
        "source": str(args.get("source", "")).strip().lower(),
        "limit": max(1, min(limit, 500)),
        "newest_first": bool(args.get("newest_first", True)),
    }


async def _lookup_by_id_remote(ctx: ToolContext, entry_id: str) -> Dict[str, Any]:
    import httpx

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(f"{ctx.dashboard_base_url}/api/entry/{entry_id}")
    if resp.status_code == 404:
        return {"ok": False, "error": "entry not found", "entry_id": entry_id}
    resp.raise_for_status()
    return {"ok": True, "entry": resp.json()}


async def _get_history(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    p = _read_args(args)

    # In-process path: read the live store directly.
    if ctx.store is not None:
        try:
            if p["entry_id"]:
                entry = ctx.store.get_entry(p["entry_id"])
                if not entry:
                    return {"ok": False, "error": "entry not found", "entry_id": p["entry_id"]}
                return {"ok": True, "entry": entry.to_dict(include_bodies=True)}
            entries = [e.to_dict() for e in ctx.store.all_entries()]
            entries = _filter_sort_limit(
                entries, p["host"], p["method"], p["path"], p["source"],
                p["limit"], p["newest_first"],
            )
            return {"ok": True, "count": len(entries), "entries": entries}
        except Exception as exc:
            return {"ok": False, "error": f"store read failed: {str(exc)[:200]}"}

    # External (MCP) path: query the running dashboard.
    try:
        if p["entry_id"]:
            return await _lookup_by_id_remote(ctx, p["entry_id"])
        import httpx

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{ctx.dashboard_base_url}/api/entries")
            resp.raise_for_status()
            entries = resp.json()
        if not isinstance(entries, list):
            return {"ok": False, "error": "unexpected /api/entries response shape"}
        entries = _filter_sort_limit(
            entries, p["host"], p["method"], p["path"], p["source"],
            p["limit"], p["newest_first"],
        )
        return {"ok": True, "count": len(entries), "entries": entries}
    except Exception as exc:
        return {"ok": False, "error": f"dashboard fetch failed: {str(exc)[:200]}"}


register(Tool(
    name="get_history",
    description=(
        "Return HTTP entries already captured by the proxy (method, url, host, status, "
        "timing, source), optionally filtered and sorted. Read-only — sends no traffic.\n"
        "Filters: host, method, path (substring), source (proxy/browse/crawler/agent/scan/"
        "copilot/imported/out-of-scope), limit, newest_first. Pass entry_id to fetch ONE "
        "entry in full with bodies.\n"
        "Use this when: you need to see what has already been observed before acting — "
        "finding a specific endpoint amid scanner noise (filter by method+path+source), "
        "inspecting a prior request/response (entry_id), or understanding an app's surface.\n"
        "Do NOT use this to: send or replay a request (use send_request); list confirmed "
        "vulnerabilities (use get_findings); or discover endpoints that were never visited "
        "(use content_discovery)."
    ),
    input_schema=_GET_HISTORY_SCHEMA,
    handler=_get_history,
    tags=["read"],
))
