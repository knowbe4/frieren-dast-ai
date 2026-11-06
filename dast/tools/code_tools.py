"""code_* tools — let an agent/the copilot consult the source code Frieren has
ALREADY loaded via its code-analysis subsystem (``dast/code_analysis/``), so it can
clarify how an endpoint works, confirm a hypothesis, or locate the handler for a URL
path instead of guessing from black-box behaviour alone.

These are thin adapters over the EXISTING capability — they do NOT reimplement any
analysis. The source is loaded by ``POST /api/code/analyze`` (dashboard / code-analysis
UI); these tools only read what is loaded:
  - ``lookup_code_for_path`` (``dast/code_analysis/analyzer.py``) — find the code
    handling a URL path; called in-process.
  - ``GET /api/code/search`` / ``/api/code/file`` / ``/api/code/list`` — the dashboard
    HTTP API, used both in-process and (for the store-less MCP process) as the data path.

Dual data path (see dast/tools/context.py): the loaded analyses live in-process in the
proxy, so ``code_lookup_path`` calls the in-process function directly and, when that
yields nothing (e.g. the external MCP process has no loaded analyses), falls back to the
dashboard search API. Nothing here is stateful/secret-handling beyond returning source
the operator deliberately loaded for analysis.
"""

from __future__ import annotations

from typing import Any, Dict

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)


# ─────────────────────────────── code_search ───────────────────────────────

_SEARCH_SCHEMA = {
    "type": "object",
    "properties": {
        "query": {"type": "string", "description": "Term to search across loaded source file paths "
                                                   "and content (case-insensitive)."},
        "limit": {"type": "integer", "description": "Max matches to return (default 20)."},
    },
    "required": ["query"],
}


async def _code_search(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    query = str(args.get("query", "")).strip()
    if not query:
        return {"ok": False, "error": "query is required"}
    limit = int(args.get("limit") or 20)
    import httpx
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(f"{ctx.dashboard_base_url}/api/code/search",
                                    params={"q": query, "limit": limit})
            resp.raise_for_status()
            matches = resp.json() or []
    except Exception as exc:
        return {"ok": False, "error": f"code search failed: {str(exc)[:160]}"}
    if not matches:
        return {"ok": True, "count": 0, "matches": [],
                "note": "no matches (is any source loaded? load a repo via the code-analysis UI "
                        "or POST /api/code/analyze first)"}
    return {"ok": True, "count": len(matches), "matches": matches}


# ──────────────────────────────── code_file ────────────────────────────────

_FILE_SCHEMA = {
    "type": "object",
    "properties": {
        "analysis_id": {"type": "string", "description": "Analysis id the file belongs to (from code_list / code_search)."},
        "path": {"type": "string", "description": "Exact file path to read (as returned by code_search)."},
    },
    "required": ["analysis_id", "path"],
}


async def _code_file(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    analysis_id = str(args.get("analysis_id", "")).strip()
    path = str(args.get("path", "")).strip()
    if not analysis_id or not path:
        return {"ok": False, "error": "analysis_id and path are required"}
    import httpx
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(f"{ctx.dashboard_base_url}/api/code/file",
                                    params={"analysis_id": analysis_id, "path": path})
            if resp.status_code == 404:
                return {"ok": False, "error": "file or analysis not found", "path": path}
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        return {"ok": False, "error": f"read failed: {str(exc)[:160]}", "path": path}
    return {"ok": True, "path": data.get("path", path), "language": data.get("language", ""),
            "content": data.get("content", "")}


# ──────────────────────────────── code_list ────────────────────────────────

_EMPTY_SCHEMA = {"type": "object", "properties": {}}


async def _code_list(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    import httpx
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(f"{ctx.dashboard_base_url}/api/code/list")
            resp.raise_for_status()
            analyses = resp.json() or []
    except Exception as exc:
        return {"ok": False, "error": f"list failed: {str(exc)[:160]}"}
    return {"ok": True, "count": len(analyses), "analyses": analyses}


# ───────────────────────────── code_lookup_path ────────────────────────────

_LOOKUP_SCHEMA = {
    "type": "object",
    "properties": {
        "url_path": {"type": "string", "description": "URL path to find the handling source code for "
                                                      "(e.g. /app/backend/integrations). Returns the most "
                                                      "relevant controller/service/model snippets."},
        "max_snippets": {"type": "integer", "description": "Max code snippets to return (default 3)."},
    },
    "required": ["url_path"],
}


async def _code_lookup_path(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    url_path = str(args.get("url_path", "")).strip()
    if not url_path:
        return {"ok": False, "error": "url_path is required"}
    max_snippets = int(args.get("max_snippets") or 3)
    # In-process: the loaded analyses live here; call the shared analyzer function directly.
    try:
        from dast.code_analysis.analyzer import lookup_code_for_path
        snippets = lookup_code_for_path(url_path, max_snippets=max_snippets)
    except Exception as exc:
        logger.warning("code_lookup_path: in-process lookup failed", error=str(exc)[:120])
        snippets = ""
    if snippets:
        return {"ok": True, "url_path": url_path, "code": snippets}
    # External MCP process (no in-proc analyses) or no path match: fall back to a search on
    # the last meaningful path segment via the dashboard API.
    parts = [s for s in url_path.strip("/").split("/") if s]
    # Prefer the last segment that is a real resource noun (not a placeholder or pure id/uuid).
    segment = ""
    for s in reversed(parts):
        if s.startswith("{"):
            continue
        if s.replace("-", "").isdigit() or (len(s) >= 8 and all(c in "0123456789abcdef-" for c in s.lower())):
            continue
        segment = s
        break
    segment = segment or (parts[-1] if parts else "")
    if segment:
        fallback = await _code_search(ctx, {"query": segment, "limit": max_snippets})
        if fallback.get("ok") and fallback.get("count"):
            fallback["note"] = (f"no direct path match; showing search results for '{segment}' "
                                f"(derived from {url_path})")
            return fallback
    return {"ok": True, "url_path": url_path, "code": "",
            "note": "no relevant source found (is the target's repo loaded via code-analysis?)"}


register(Tool(
    name="code_search", input_schema=_SEARCH_SCHEMA, handler=_code_search, tags=["code", "read"],
    description="Search the SOURCE CODE Frieren has loaded (via its code-analysis subsystem) by term, "
                "across file paths and content. Use to understand how the target works or confirm a "
                "hypothesis from code instead of guessing. Returns file paths + a matching-line preview. "
                "Requires a repo to have been loaded first (code-analysis UI / POST /api/code/analyze)."))
register(Tool(
    name="code_file", input_schema=_FILE_SCHEMA, handler=_code_file, tags=["code", "read"],
    description="Read one loaded source file's full content by analysis_id + path (paths come from "
                "code_search / code_list). Use to inspect a handler end to end after code_search locates it."))
register(Tool(
    name="code_list", input_schema=_EMPTY_SCHEMA, handler=_code_list, tags=["code", "read"],
    description="List the code analyses currently loaded in Frieren (id, sources, files scanned, endpoints, "
                "hypotheses). Use first to see whether any source is available to consult."))
register(Tool(
    name="code_lookup_path", input_schema=_LOOKUP_SCHEMA, handler=_code_lookup_path, tags=["code", "read"],
    description="Find the source code that handles a given URL path (e.g. the controller/service for "
                "/app/backend/integrations). The fastest way to answer 'what does this endpoint actually do, "
                "and what are its parameters/authz checks' from code. Returns the most relevant snippets, "
                "controllers first for /api paths."))
