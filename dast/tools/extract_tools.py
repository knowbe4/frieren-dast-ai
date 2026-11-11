"""extract_response tool — pull small, structured slices out of a FULL captured response body.

The copilot's turn transcript trims a tool result's body to a short preview (see
``dast/ai/copilot/session.py`` ``_OBSERVATION_BODY_CHARS``) so a large response cannot blow the
LLM context. That preview is too small to enumerate a big JSON list (e.g. hundreds of
``store_items[].uuid``) or to read one field out of a large ``/spa/session`` body. The full body
is already captured in the proxy store (``ProxyEntry.response_body``); this tool evaluates a
dependency-free JSON path (or a regex) over that FULL body server-side and returns only the matched
values, paginated and capped — so the result always fits the observation.

One primitive, two unblocks: enumerate a large array field, or read a single nested field.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from dast.proxy.signalr import decode_body
from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Caps so the result always survives the turn-transcript observation trim.
_MAX_VALUES = 200
_MAX_VALUE_CHARS = 200

# Path tokens: a bare key, ``[]`` (map over an array), or ``[n]`` (index into an array).
_TOKEN_RE = re.compile(r"([^.\[\]]+)|\[(\d*)\]")

_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "url": {
            "type": "string",
            "description": "URL of a request you already sent; the MOST RECENT captured response "
                           "for it is used. Provide this or entry_id.",
        },
        "entry_id": {
            "type": "string",
            "description": "Proxy-history entry id to read instead of resolving by url.",
        },
        "path": {
            "type": "string",
            "description": "Dependency-free JSON selector over the full response body. Examples: "
                           "'store_items[].uuid' (every uuid in the array), "
                           "'user.attributes.appJwt' (one nested field), 'items[0].id'. "
                           "'[]' maps over an array; '[n]' indexes it.",
        },
        "regex": {
            "type": "string",
            "description": "Fallback for non-JSON bodies: returns each match (first capture group "
                           "if the pattern has one, else the whole match).",
        },
        "limit": {"type": "integer", "description": "Max values to return (default 100, max 200)."},
        "offset": {"type": "integer", "description": "Skip this many matches first (default 0) — page through large results."},
    },
}


def _tokens(path: str) -> List[Tuple[str, Any]]:
    toks: List[Tuple[str, Any]] = []
    for match in _TOKEN_RE.finditer(path):
        if match.group(1) is not None:
            toks.append(("key", match.group(1)))
        elif match.group(2) == "":
            toks.append(("map", None))
        else:
            toks.append(("index", int(match.group(2))))
    return toks


def _select(root: Any, path: str) -> List[Any]:
    """Evaluate a dot/bracket path, returning the list of matched values (a ``[]`` fans out)."""
    frontier: List[Any] = [root]
    for kind, value in _tokens(path):
        nxt: List[Any] = []
        for current in frontier:
            if kind == "key":
                if isinstance(current, dict) and value in current:
                    nxt.append(current[value])
            elif kind == "map":
                if isinstance(current, list):
                    nxt.extend(current)
            elif kind == "index":
                if isinstance(current, list) and -len(current) <= value < len(current):
                    nxt.append(current[value])
        frontier = nxt
    return frontier


def _stringify(value: Any) -> str:
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    return text[:_MAX_VALUE_CHARS]


def _slice_result(matches: List[Any], offset: int, limit: int, url: str, selector: str) -> Dict[str, Any]:
    total = len(matches)
    window = matches[offset:offset + limit]
    return {
        "ok": True,
        "url": url,
        "selector": selector,
        "total": total,
        "count": len(window),
        "offset": offset,
        "truncated": offset + len(window) < total,
        "values": [_stringify(v) for v in window],
    }


def _summary(body: str, url: str) -> Dict[str, Any]:
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return {"ok": True, "url": url, "kind": "text", "length": len(body),
                "preview": body[:_MAX_VALUE_CHARS],
                "note": "body is not JSON — pass a regex to extract matches."}
    if isinstance(data, dict):
        return {"ok": True, "url": url, "kind": "object", "keys": sorted(data.keys())[:50],
                "note": "pass path=<key>[.<key>...] to read a field."}
    if isinstance(data, list):
        first = data[0] if data else None
        return {"ok": True, "url": url, "kind": "array", "length": len(data),
                "element_keys": sorted(first.keys())[:50] if isinstance(first, dict) else None,
                "note": "pass path=[].<key> to map a field over every element."}
    return {"ok": True, "url": url, "kind": type(data).__name__, "value": _stringify(data)}


def _entry_body(entry: Any) -> str:
    """Decode a captured entry's full response body. Accepts a ProxyEntry (in-proc store) or a
    dict (dashboard /api/entry, already decoded)."""
    if isinstance(entry, dict):
        return str(entry.get("response_body") or "")
    raw = getattr(entry, "response_body", None)
    path = getattr(entry, "path", "") or ""
    try:
        return decode_body(raw, path) or "" if raw else ""
    except Exception as exc:
        logger.debug("extract_response: body decode failed", error=str(exc)[:160])
        return ""


def _norm(url: str) -> str:
    return (url or "").split("?", 1)[0].rstrip("/").lower()


async def _resolve_entry(ctx: ToolContext, url: str, entry_id: str) -> Tuple[Optional[Any], str]:
    """Return (entry, resolved_url) or (None, ""). In-proc store first; dashboard API as fallback."""
    store = getattr(ctx, "store", None)
    if store is not None:
        if entry_id:
            entry = store.get_entry(entry_id)
            return (entry, getattr(entry, "url", "") if entry else "")
        target = _norm(url)
        for entry in store.entries_newest_first():
            eurl = getattr(entry, "url", "")
            if _norm(eurl) == target or target in _norm(eurl):
                return (entry, eurl)
        return (None, "")
    # MCP / no in-proc store: query the dashboard (mirrors history_tools).
    try:
        import httpx
        async with httpx.AsyncClient(timeout=10) as client:
            if entry_id:
                resp = await client.get(f"{ctx.dashboard_base_url}/api/entry/{entry_id}")
                if resp.status_code == 404:
                    return (None, "")
                resp.raise_for_status()
                entry = resp.json()
                return (entry, str(entry.get("url", "")))
            resp = await client.get(f"{ctx.dashboard_base_url}/api/entries")
            resp.raise_for_status()
            entries = resp.json()
        target = _norm(url)
        for entry in reversed(entries if isinstance(entries, list) else []):
            if _norm(str(entry.get("url", ""))) == target or target in _norm(str(entry.get("url", ""))):
                eid = str(entry.get("id", ""))
                if eid:  # re-fetch with bodies
                    async with httpx.AsyncClient(timeout=10) as client:
                        full = await client.get(f"{ctx.dashboard_base_url}/api/entry/{eid}")
                    if full.status_code == 200:
                        fe = full.json()
                        return (fe, str(fe.get("url", "")))
                return (entry, str(entry.get("url", "")))
        return (None, "")
    except Exception as exc:
        logger.debug("extract_response: dashboard resolve failed", error=str(exc)[:160])
        return (None, "")


async def _extract_response(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    url = str(args.get("url", "")).strip()
    entry_id = str(args.get("entry_id", "")).strip()
    path = str(args.get("path", "")).strip()
    regex = str(args.get("regex", "")).strip()
    try:
        limit = int(args.get("limit", 100))
    except (TypeError, ValueError):
        limit = 100
    try:
        offset = int(args.get("offset", 0))
    except (TypeError, ValueError):
        offset = 0
    limit = max(1, min(limit, _MAX_VALUES))
    offset = max(0, offset)

    if not url and not entry_id:
        return {"ok": False, "error": "provide url or entry_id"}

    try:
        entry, resolved_url = await _resolve_entry(ctx, url, entry_id)
        if entry is None:
            return {"ok": False, "error": "no captured response found for the given url/entry_id"}
        if resolved_url and not ctx.is_in_scope(resolved_url):
            return {"ok": False, "error": "entry url is out of scope", "url": resolved_url}

        body = _entry_body(entry)
        if not body:
            return {"ok": True, "url": resolved_url, "total": 0, "count": 0, "values": [],
                    "note": "empty response body"}

        if path:
            try:
                data = json.loads(body)
            except (ValueError, TypeError):
                return {"ok": False, "url": resolved_url,
                        "error": "response body is not JSON — use regex instead"}
            return _slice_result(_select(data, path), offset, limit, resolved_url, f"path={path}")
        if regex:
            try:
                compiled = re.compile(regex)
            except re.error as exc:
                return {"ok": False, "error": f"invalid regex: {str(exc)[:120]}"}
            matches = [m.group(1) if m.groups() else m.group(0) for m in compiled.finditer(body)]
            return _slice_result(matches, offset, limit, resolved_url, "regex")
        return _summary(body, resolved_url)
    except Exception as exc:  # never raise out of a handler
        return {"ok": False, "error": f"extract failed: {str(exc)[:200]}"}


register(Tool(
    name="extract_response",
    description=(
        "Read fields out of the FULL body of a response you already captured, when the tool "
        "observation only showed a truncated preview. Give the request url (or an entry_id) plus "
        "a JSON path like 'store_items[].uuid' (every uuid in the array) or 'user.attributes.appJwt' "
        "(one nested field); results are paginated (limit/offset) and capped. Use regex for non-JSON "
        "bodies, or omit both to get a shape summary first. This reads already-captured data — it "
        "sends no new request."
    ),
    input_schema=_SCHEMA,
    handler=_extract_response,
    tags=["history"],
))
