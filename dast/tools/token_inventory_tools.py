"""token_inventory tool — the redacted credential landscape observed for a host.

Lets the copilot see, in one call, every credential seen in traffic (session cookies, per-sub-app
JWT bearers with non-secret claims, custom auth headers, query tokens) so it can reason about
which credential a given endpoint needs. Returns metadata only — never a token/cookie value.
"""

from __future__ import annotations

from typing import Any, Dict
from urllib.parse import urlparse

from dast.session.token_inventory import build_token_inventory
from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "host": {"type": "string",
                 "description": "Host to inventory (e.g. app.example.com). A full URL is accepted; "
                                "its host is used. Defaults to the first in-scope focus host."},
    },
}


async def _token_inventory(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    store = getattr(ctx, "store", None)
    if store is None:
        return {"ok": False, "error": "no store in this context"}
    host = str(args.get("host", "")).strip()
    if host and "://" in host:
        host = urlparse(host).hostname or host
    if not host:
        focus = [h for h in (getattr(ctx, "approved_hosts", None) or []) if h]
        host = focus[0] if focus else ""
    if not host:
        return {"ok": False, "error": "host is required (none in focus)"}
    inv = build_token_inventory(store, host.lower())
    return {"ok": True, **inv}


register(Tool(
    name="token_inventory",
    input_schema=_SCHEMA,
    handler=_token_inventory,
    tags=["session"],
    description=(
        "List the credentials OBSERVED in traffic for a host — session cookies, per-sub-app JWT "
        "bearers (with non-secret claims + freshness), custom auth headers, and query tokens — so "
        "you can tell which credential an endpoint needs. Metadata only: token/cookie VALUES are "
        "never returned (a short fingerprint distinguishes them). Use it to understand a "
        "multi-token / integrated app before testing sub-app endpoints."
    ),
))
