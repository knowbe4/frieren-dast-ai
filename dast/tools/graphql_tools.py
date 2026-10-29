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

            # Route through the Frieren proxy so the introspection request is
            # captured in history and treated like every other test request.
            error = await _introspect(
                url, dict(headers), ctx.store, "Copilot Introspection",
                proxy_url=ctx.proxy_url,
            )
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


# ---------------------------------------------------------------------------
# graphql_type_info — inspect a single type from the cached schema
# ---------------------------------------------------------------------------

_TYPE_INFO_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "url": {
            "type": "string",
            "description": "GraphQL endpoint URL (must have been introspected first).",
        },
        "type_name": {
            "type": "string",
            "description": (
                "Name of the GraphQL type to inspect "
                "(e.g. 'User', 'PhishingCampaignAttributes', 'ApiScopes')."
            ),
        },
    },
    "required": ["url", "type_name"],
}

_SENSITIVE_PATTERNS = (
    "secret", "token", "password", "otp", "credential", "apikey",
    "privatekey", "encryptedpassword", "resetpassword", "confirmationtoken",
    "sharedsecret", "mfa", "totp", "auth_token", "jwt",
)


def _get_cached_schema(ctx: ToolContext, url: str) -> Dict[str, Any]:
    """Return the cached compact schema for *url*, or an empty dict."""
    if ctx.store is not None:
        schema = ctx.store.graphql_schemas.get(url)
        if schema and schema.get("introspected"):
            return schema
    return {}


def _lookup_type(schema: Dict[str, Any], type_name: str) -> Dict[str, Any]:
    """Find *type_name* across all type categories in the compact schema."""
    for category in ("input_types", "object_types", "enum_types", "union_types"):
        types_map = schema.get(category) or {}
        if type_name in types_map:
            kind_map = {
                "input_types": "INPUT_OBJECT",
                "object_types": types_map.get(type_name, {}).get("kind", "OBJECT"),
                "enum_types": "ENUM",
                "union_types": "UNION",
            }
            return {"found": True, "category": category, "kind": kind_map[category],
                    "data": types_map[type_name]}
    # Check if it's a query or mutation root field name
    for root in ("queries", "mutations"):
        root_map = schema.get(root) or {}
        if type_name in root_map:
            return {"found": True, "category": root, "kind": root.upper().rstrip("S"),
                    "data": root_map[type_name]}
    return {"found": False}


async def _graphql_type_info(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    url = str(args.get("url", "")).strip()
    type_name = str(args.get("type_name", "")).strip()
    if not url:
        return {"ok": False, "error": "url is required"}
    if not type_name:
        return {"ok": False, "error": "type_name is required"}
    if not ctx.is_in_scope(url):
        return {"ok": False, "error": "url is out of scope", "url": url}

    schema = _get_cached_schema(ctx, url)
    if not schema:
        return {"ok": False, "error": "no cached schema for this URL — run graphql_introspect first",
                "url": url}

    result = _lookup_type(schema, type_name)
    if not result["found"]:
        available = []
        for cat in ("input_types", "object_types", "enum_types", "union_types"):
            available.extend(sorted((schema.get(cat) or {}).keys()))
        suggestions = [n for n in available if type_name.lower() in n.lower()][:10]
        return {"ok": False, "error": f"type '{type_name}' not found in schema",
                "suggestions": suggestions}

    data = result["data"]
    kind = result["kind"]
    out: Dict[str, Any] = {"ok": True, "name": type_name, "kind": kind}

    if kind == "ENUM":
        out["enum_values"] = data.get("values", [])
    elif kind == "UNION":
        out["possible_types"] = data.get("possible_types", [])
    elif kind in ("QUERY", "MUTATION"):
        out["args"] = data.get("args", [])
        out["return_type"] = data.get("return_type")
    else:
        fields = data.get("fields", [])
        out["fields"] = [
            {
                "name": f["name"],
                "type": f.get("type", ""),
                "required": f.get("wrapper", "") == "NON_NULL",
                "is_list": "LIST" in (f.get("wrapper") or ""),
            }
            for f in fields
        ]

    return out


register(Tool(
    name="graphql_type_info",
    description=(
        "Inspect a single GraphQL type from the cached schema: its fields (with types, "
        "required/optional, list), enum values, or union members. The schema must have "
        "been introspected first with graphql_introspect.\n"
        "Use this to look up field names and argument types BEFORE crafting a query or "
        "mutation — eliminates guessing and avoids GraphQL validation errors.\n"
        "Works for: object types (User, Account), input types (PhishingCampaignAttributes), "
        "enums (ApiScopes, TimeZones), unions, and root query/mutation fields."
    ),
    input_schema=_TYPE_INFO_SCHEMA,
    handler=_graphql_type_info,
    tags=["recon", "graphql"],
))


# ---------------------------------------------------------------------------
# graphql_find_sensitive — scan schema for fields that may leak secrets
# ---------------------------------------------------------------------------

_FIND_SENSITIVE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "url": {
            "type": "string",
            "description": "GraphQL endpoint URL (must have been introspected first).",
        },
    },
    "required": ["url"],
}


async def _graphql_find_sensitive(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    url = str(args.get("url", "")).strip()
    if not url:
        return {"ok": False, "error": "url is required"}
    if not ctx.is_in_scope(url):
        return {"ok": False, "error": "url is out of scope", "url": url}

    schema = _get_cached_schema(ctx, url)
    if not schema:
        return {"ok": False, "error": "no cached schema for this URL — run graphql_introspect first",
                "url": url}

    hits: list = []
    for category in ("object_types", "input_types"):
        types_map = schema.get(category) or {}
        for type_name, type_data in types_map.items():
            if type_name.startswith("__"):
                continue
            for field in (type_data.get("fields") or []):
                field_name = field.get("name", "")
                normalised = field_name.lower().replace("_", "")
                if any(p in normalised for p in _SENSITIVE_PATTERNS):
                    hits.append({
                        "type": type_name,
                        "field": field_name,
                        "field_type": field.get("type", ""),
                        "category": "input" if category == "input_types" else "object",
                    })

    hits.sort(key=lambda h: (h["type"], h["field"]))
    return {"ok": True, "url": url, "sensitive_fields": hits, "count": len(hits)}


register(Tool(
    name="graphql_find_sensitive",
    description=(
        "Scan the cached GraphQL schema for fields whose names suggest they may expose "
        "credentials or secrets: *secret*, *token*, *password*, *otp*, *credential*, "
        "*apiKey*, *privateKey*, *sharedSecret*, etc.\n"
        "Run graphql_introspect first to populate the cache. Returns a list of "
        "{type, field, field_type} hits ranked by type name.\n"
        "Use this to quickly identify field-level authorization gaps — e.g. a "
        "'PartnerAdmin.apiTokens.sharedSecret' field that returns raw credentials."
    ),
    input_schema=_FIND_SENSITIVE_SCHEMA,
    handler=_graphql_find_sensitive,
    tags=["recon", "graphql"],
))
