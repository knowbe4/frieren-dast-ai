"""transport_capability tools — read and record the learned per-host transport preference
(reach a host/sub-app over the API path vs the browser session).

Thin wrappers over ``dast/session/transport_capability.py``. The copilot's auto-fallback seeds
this in-process; these tools expose the same store to external MCP callers (per the API+MCP
rule) so an agent can consult or set a host's preferred transport. No secrets are involved.
"""

from __future__ import annotations

from typing import Any, Dict
from urllib.parse import urlparse

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)


def _host_of(value: str) -> str:
    v = (value or "").strip()
    if "://" in v:
        return (urlparse(v).hostname or "").lower()
    return v.split("/", 1)[0].split(":", 1)[0].lower()


async def _get_transport_capability(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    host = _host_of(str(args.get("host", "")))
    if not host:
        return {"ok": False, "error": "host is required"}
    if not ctx.is_in_scope(f"https://{host}/"):
        return {"ok": False, "error": "host is out of scope", "host": host}
    path = str(args.get("path", ""))
    task = str(args.get("task", "")) or None
    try:
        from dast.session.transport_capability import capability_for
        rec = capability_for(host, path, task=task)
    except Exception as exc:
        return {"ok": False, "error": f"could not read transport capability: {str(exc)[:160]}"}
    if not rec:
        return {"ok": True, "host": host, "known": False}
    return {"ok": True, "host": host, "known": True, "sub_app": rec.get("sub_app", ""),
            "task": rec.get("task", ""), "prefer": rec.get("prefer", ""),
            "auth": rec.get("auth", ""), "reason": rec.get("reason", "")}


async def _record_transport_capability(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    host = _host_of(str(args.get("host", "")))
    prefer = str(args.get("prefer", "")).strip().lower()
    auth = str(args.get("auth", "")).strip().lower()
    if not host:
        return {"ok": False, "error": "host is required"}
    if prefer not in ("api", "browser"):
        return {"ok": False, "error": "prefer must be 'api' or 'browser'"}
    if auth not in ("api", "browser", "both"):
        return {"ok": False, "error": "auth must be 'api', 'browser' or 'both'"}
    if not ctx.is_in_scope(f"https://{host}/"):
        return {"ok": False, "error": "host is out of scope", "host": host}
    path = str(args.get("path", ""))
    task = str(args.get("task", "")) or None
    reason = str(args.get("reason", ""))
    try:
        from dast.session.auth_provider import subapp_for_path
        from dast.session.transport_capability import record_capability
        written = record_capability(host, path, auth=auth, prefer=prefer,
                                    reason=reason, task=task)
    except Exception as exc:
        return {"ok": False, "error": f"could not save transport capability: {str(exc)[:160]}"}
    if not written:
        return {"ok": False, "error": "could not save transport capability"}
    return {"ok": True, "host": written, "sub_app": subapp_for_path(path or "") or "",
            "prefer": prefer, "auth": auth}


register(Tool(
    name="get_transport_capability",
    input_schema={
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Target host (e.g. api.phisher.example)."},
            "path": {"type": "string", "description": "Optional request path, so the learned "
                     "preference for a specific sub-app (e.g. /serviceA) is resolved."},
            "task": {"type": "string", "description": "Optional task label (e.g. graphql)."},
        },
        "required": ["host"],
    },
    handler=_get_transport_capability,
    tags=["util"],
    description="Read the learned transport preference for a host/sub-app: whether authenticated "
                "requests work over the API (send_request) or need the browser session "
                "(browser_fetch), and which to prefer. Returns known=false when nothing is learned "
                "yet. Consult before choosing a transport for an authenticated call.",
))

register(Tool(
    name="record_transport_capability",
    input_schema={
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Host the fact is about."},
            "prefer": {"type": "string", "description": "Preferred transport: 'api' or 'browser'."},
            "auth": {"type": "string", "description": "What works: 'api', 'browser' or 'both'."},
            "path": {"type": "string", "description": "Optional request path (keys the sub-app)."},
            "task": {"type": "string", "description": "Optional task label (e.g. graphql)."},
            "reason": {"type": "string", "description": "Short why (no secrets)."},
        },
        "required": ["host", "prefer", "auth"],
    },
    handler=_record_transport_capability,
    tags=["util"],
    description="Record the learned transport preference for a host/sub-app into the local "
                "per-host store (~/.dast-ai/transport_capability/<host>.jsonl, never committed), so "
                "future runs pick the right transport up front. No secret values.",
))
