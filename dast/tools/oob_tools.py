"""
Out-of-band (OOB) interaction tools — Burp-Collaborator-style blind-vuln detection.

Two primitives that let an agent or MCP client detect blind SSRF / XXE / RCE and
similar out-of-band bugs:

  1. ``oob_generate`` mints a unique OAST URL (public interactsh) to embed in a
     payload (via ``send_request``).
  2. ``oob_poll`` reports whether the target ever called that URL back.

Both wrap the dashboard's existing ``/api/interactions/*`` surface. Interactsh
session state (and its background poll loop) lives in the dashboard process, so
every caller — internal or MCP — talks to it over HTTP; there is no in-process
shortcut. Requires the dashboard to be running.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_OOB_GENERATE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {},
    "required": [],
}

_OOB_POLL_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "id": {"type": "string", "description": "The session id returned by oob_generate."},
        "wait_seconds": {
            "type": "integer",
            "description": "Optional: poll for up to this many seconds until a callback arrives (default 0, max 120).",
        },
    },
    "required": ["id"],
}

_POLL_INTERVAL_SECONDS = 3.0


async def _oob_generate(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    try:
        import httpx

        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(f"{ctx.dashboard_base_url}/api/interactions/new")
            if resp.status_code == 503:
                return {"ok": False, "error": "OOB unavailable — all interactsh servers unreachable"}
            resp.raise_for_status()
            data = resp.json()
        oob_url = data.get("oob_url")
        session_id = data.get("session_id")
        if not oob_url or not session_id:
            return {"ok": False, "error": "unexpected /api/interactions/new response shape"}
        return {
            "ok": True,
            "id": session_id,
            "oob_url": oob_url,
            "hint": "Embed oob_url in a payload via send_request, then call oob_poll with this id.",
        }
    except Exception as exc:
        return {"ok": False, "error": f"oob_generate failed: {str(exc)[:200]}"}


async def _fetch_session(client: Any, ctx: ToolContext, session_id: str) -> Dict[str, Any] | None:
    resp = await client.get(f"{ctx.dashboard_base_url}/api/interactions/{session_id}")
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json()


async def _oob_poll(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    session_id = str(args.get("id", "")).strip()
    if not session_id:
        return {"ok": False, "error": "id is required"}
    try:
        wait_seconds = int(args.get("wait_seconds", 0))
    except (TypeError, ValueError):
        wait_seconds = 0
    wait_seconds = max(0, min(wait_seconds, 120))

    try:
        import httpx

        async with httpx.AsyncClient(timeout=15) as client:
            deadline_polls = max(1, int(wait_seconds / _POLL_INTERVAL_SECONDS)) if wait_seconds else 1
            for attempt in range(deadline_polls):
                session = await _fetch_session(client, ctx, session_id)
                if session is None:
                    return {"ok": False, "error": f"unknown OOB session id: {session_id}"}
                callbacks = session.get("callbacks") or []
                if callbacks or attempt == deadline_polls - 1:
                    return {
                        "ok": True,
                        "hit": bool(callbacks),
                        "count": len(callbacks),
                        "oob_url": session.get("oob_url"),
                        "interactions": callbacks,
                    }
                await asyncio.sleep(_POLL_INTERVAL_SECONDS)
        # Unreachable, but keep the type-checker and control flow happy.
        return {"ok": True, "hit": False, "count": 0, "interactions": []}
    except Exception as exc:
        return {"ok": False, "error": f"oob_poll failed: {str(exc)[:200]}"}


register(Tool(
    name="oob_generate",
    description=(
        "Mint a unique out-of-band (OOB) callback URL (public interactsh) for blind "
        "vulnerability testing. Returns an oob_url and a session id.\n"
        "Use this when: you suspect a BLIND bug with no in-band signal — blind SSRF, "
        "blind XXE, blind/OOB command injection, or exfil via DNS/HTTP callback. Step 1 of "
        "the flow: generate here, embed oob_url in a payload via send_request, then oob_poll.\n"
        "Do NOT use this when: the vuln reflects in the response body or timing (test that "
        "directly with send_request); or just to make an HTTP request (use send_request)."
    ),
    input_schema=_OOB_GENERATE_SCHEMA,
    handler=_oob_generate,
    tags=["oob"],
))

register(Tool(
    name="oob_poll",
    description=(
        "Check whether an OOB callback URL (from oob_generate) received any interaction — "
        "an interaction proves the target reached out, confirming the blind vulnerability. "
        "Returns the received HTTP/DNS interactions; pass wait_seconds to block until one "
        "arrives or the timeout elapses.\n"
        "Use this when: you have already called oob_generate AND sent a payload containing "
        "its oob_url via send_request, and now need to confirm the callback.\n"
        "Do NOT use this before generating a URL and sending the payload — there is nothing "
        "to poll yet. Requires the id returned by oob_generate."
    ),
    input_schema=_OOB_POLL_SCHEMA,
    handler=_oob_poll,
    tags=["oob"],
))
