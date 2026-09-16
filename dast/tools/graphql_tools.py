"""
GraphQL tools — schema introspection as an agent-callable primitive.

Introspection already lives in ``dast/plugins/graphql_introspection.py`` (the real
``query IntrospectionQuery { __schema { ... } }``) and is surfaced to humans via the
GraphQL tab's Schema Explorer (``POST /api/graphql/introspect``). This tool exposes
the SAME capability to the shared tool layer so the Exploration Copilot and MCP
clients can introspect a schema through Frieren's dedicated path instead of
hand-rolling an introspection query over ``send_request``.

Thin adapter: in-process it calls ``_introspect`` against the live store; the MCP
process (no in-proc store) falls back to the dashboard route.
"""

from __future__ import annotations

from typing import Any, Dict

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_INTROSPECT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "url": {
            "type": "string",
            "description": "GraphQL endpoint URL to introspect (e.g. https://host/graphql).",
        },
        "headers": {
            "type": "object",
            "description": (
                "Optional auth headers (cookies/bearer) for the introspection request. "
                "The copilot injects the current session Cookie automatically; only set "
                "this to point introspection at a different user's session."
            ),
        },
    },
    "required": ["url"],
}


def _summarise_schema(url: str, schema: Dict[str, Any]) -> Dict[str, Any]:
    """Compact, LLM-friendly summary of a stored introspection schema."""
    queries = schema.get("queries") or {}
    mutations = schema.get("mutations") or {}
    return {
        "ok": True,
        "url": url,
        "query_count": len(queries),
        "mutation_count": len(mutations),
        "queries": sorted(queries.keys()),
        "mutations": sorted(mutations.keys()),
        "schema": schema,
    }


async def _graphql_introspect(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    url = str(args.get("url", "")).strip()
    if not url:
        return {"ok": False, "error": "url is required"}
    if not ctx.is_in_scope(url):
        return {"ok": False, "error": "url is out of scope", "url": url}

    headers = args.get("headers") or {}
    if not isinstance(headers, dict):
        headers = {}

    # In-process path: run introspection against the live store directly. The
    # store keeps the compact schema on ``graphql_schemas[url]`` on success.
    if ctx.store is not None:
        try:
            from dast.plugins.graphql_introspection import _introspect

            error = await _introspect(url, dict(headers), ctx.store, "Copilot Introspection")
            if error:
                return {"ok": False, "error": error, "url": url}
            schema = ctx.store.graphql_schemas.get(url)
            if not schema or not schema.get("introspected"):
                return {"ok": False, "error": "introspection did not return a usable schema", "url": url}
            return _summarise_schema(url, schema)
        except Exception as exc:
            return {"ok": False, "error": f"introspection failed: {str(exc)[:200]}", "url": url}

    # External (MCP) path: drive the running dashboard's introspection route.
    try:
        import httpx

        payload: Dict[str, Any] = {"endpoint": url}
        if headers:
            payload["headers"] = headers
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(
                f"{ctx.dashboard_base_url}/api/graphql/introspect", json=payload
            )
            resp.raise_for_status()
            data = resp.json()
        if not isinstance(data, dict) or not data.get("ok"):
            error = (data or {}).get("error") if isinstance(data, dict) else None
            return {"ok": False, "error": error or "introspection failed", "url": url}
        return _summarise_schema(url, data.get("schema") or {})
    except Exception as exc:
        return {"ok": False, "error": f"dashboard introspection failed: {str(exc)[:200]}", "url": url}


register(Tool(
    name="graphql_introspect",
    description=(
        "Run GraphQL schema introspection against an in-scope endpoint and return its "
        "queries, mutations, and types. This is Frieren's dedicated introspection path — "
        "it sends the canonical IntrospectionQuery and caches the compact schema.\n"
        "Use this when: you have a GraphQL endpoint (e.g. /graphql) and need to understand "
        "its schema (available queries/mutations/fields) before crafting requests or looking "
        "for sensitive fields.\n"
        "Do NOT hand-roll an introspection query with send_request — use this tool so the "
        "schema is parsed and cached. Falls back gracefully if introspection is disabled on "
        "the server."
    ),
    input_schema=_INTROSPECT_SCHEMA,
    handler=_graphql_introspect,
    tags=["recon", "graphql"],
))
