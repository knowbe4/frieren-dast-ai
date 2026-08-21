"""
Recon tools — content discovery (forced browsing) and hidden-parameter mining.

Both wrap the existing scope-gated, proxy-routed scanners in
``dast/scanners/``. They surface fresh attack surface (unlinked paths / hidden
parameter names) without inferring a vulnerability — detection-only recon.
"""

from __future__ import annotations

from typing import Any, Dict

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_CONTENT_DISCOVERY_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "Base URL whose host is probed for unlinked paths."},
        "include_dirs": {"type": "boolean", "description": "Probe directory wordlist (default true)."},
        "include_files": {"type": "boolean", "description": "Probe file wordlist (default true)."},
        "include_graphql": {"type": "boolean", "description": "Probe GraphQL endpoint paths (default true)."},
    },
    "required": ["url"],
}

_PARAM_MINING_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "Request URL to mine for hidden parameter names."},
        "method": {"type": "string", "description": "HTTP method (default GET)."},
        "body": {"type": "string", "description": "Optional request body (form/JSON) for non-GET."},
        "content_type": {"type": "string", "description": "Body content-type hint (e.g. application/json)."},
    },
    "required": ["url"],
}


async def _content_discovery(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    url = str(args.get("url", "")).strip()
    if not url:
        return {"ok": False, "error": "url is required"}
    if not ctx.is_in_scope(url):
        return {"ok": False, "error": "url is out of scope", "url": url}
    try:
        from dast.scanners.content_discovery import run_content_discovery
        hits = await run_content_discovery(
            base_url=url,
            headers={},
            settings=ctx.get_settings(),
            proxy_url=ctx.proxy_url,
            include_dirs=bool(args.get("include_dirs", True)),
            include_files=bool(args.get("include_files", True)),
            include_graphql=bool(args.get("include_graphql", True)),
        )
        return {"ok": True, "count": len(hits), "hits": hits}
    except Exception as exc:
        return {"ok": False, "error": f"content discovery failed: {str(exc)[:200]}"}


async def _param_mining(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    url = str(args.get("url", "")).strip()
    if not url:
        return {"ok": False, "error": "url is required"}
    if not ctx.is_in_scope(url):
        return {"ok": False, "error": "url is out of scope", "url": url}
    try:
        from dast.scanners.param_miner import run_param_mining
        hits = await run_param_mining(
            base_url=url,
            headers={},
            settings=ctx.get_settings(),
            method=str(args.get("method", "GET")).upper(),
            body=args.get("body"),
            content_type=str(args.get("content_type", "")),
            proxy_url=ctx.proxy_url,
        )
        return {"ok": True, "count": len(hits), "hits": hits}
    except Exception as exc:
        return {"ok": False, "error": f"param mining failed: {str(exc)[:200]}"}


register(Tool(
    name="content_discovery",
    description=(
        "Forced-browsing recon: probe a wordlist of common paths against an in-scope host "
        "to discover unlinked/hidden endpoints (admin panels, backups, API routes). Sends "
        "many requests through the proxy.\n"
        "Use this when: you have a host but need to find endpoints that were never linked "
        "or visited, before deciding what to test.\n"
        "Do NOT use this to: find hidden query/body parameters on a known endpoint (use "
        "param_mining); list endpoints already observed (use get_history); or hit a single "
        "known URL (use send_request)."
    ),
    input_schema=_CONTENT_DISCOVERY_SCHEMA,
    handler=_content_discovery,
    tags=["recon"],
))

register(Tool(
    name="param_mining",
    description=(
        "Brute-force hidden parameter names against a known in-scope request, detecting "
        "which ones the server honors via reflection or behavior-change. Sends many "
        "requests through the proxy.\n"
        "Use this when: you have a specific endpoint and suspect it accepts undocumented "
        "query/body parameters worth attacking.\n"
        "Do NOT use this to: discover endpoints/paths (use content_discovery); read params "
        "already seen in traffic (use get_history); or test a single known parameter with a "
        "payload (use send_request)."
    ),
    input_schema=_PARAM_MINING_SCHEMA,
    handler=_param_mining,
    tags=["recon"],
))
