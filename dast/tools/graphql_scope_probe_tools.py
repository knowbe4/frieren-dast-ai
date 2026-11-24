"""
graphql_scope_probe — deterministic access-control probe for GraphQL enum arguments.

Detects fail-open filter bypasses where a client-supplied enum argument (e.g.
permissionScope) selects a server-side permission filter, and switching to a scope
the user has no grants for causes the filter to skip — returning all records.

The probe varies each enum argument value on a GraphQL operation and compares
response record counts. A variant that returns MORE records than the baseline is
flagged as a potential scope bypass.

Auth is self-contained (same cookie-jar + Bearer + CSRF pattern as sqli_probe).
Every request is routed through the proxy so it lands in history, in-scope.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from dast.graphql.query_builder import (
    build_argument_value,
    build_selection_set,
    _gql_type_string,
    _lookup_field,
)
from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Count extraction heuristic
# ---------------------------------------------------------------------------

def _extract_count(response_json: dict, operation: str) -> Optional[int]:
    """Extract the record count from a GraphQL response using common patterns."""
    data = response_json.get("data")
    if not isinstance(data, dict):
        return None
    op_data = data.get(operation)
    if op_data is None:
        return None
    if isinstance(op_data, dict):
        # Pagination pattern (KMSAT style): data.op.pagination.totalCount
        pagination = op_data.get("pagination")
        if isinstance(pagination, dict) and "totalCount" in pagination:
            return int(pagination["totalCount"])
        # Relay-style totalCount at operation level
        if "totalCount" in op_data:
            return int(op_data["totalCount"])
        # Nodes array
        nodes = op_data.get("nodes")
        if isinstance(nodes, list):
            return len(nodes)
        # Edges array
        edges = op_data.get("edges")
        if isinstance(edges, list):
            return len(edges)
    if isinstance(op_data, list):
        return len(op_data)
    return None


def _extract_errors(response_json: dict) -> List[str]:
    """Extract GraphQL error messages from a response."""
    errors = response_json.get("errors")
    if not isinstance(errors, list):
        return []
    return [e.get("message", "") for e in errors if isinstance(e, dict) and e.get("message")]


# ---------------------------------------------------------------------------
# Schema helpers
# ---------------------------------------------------------------------------

def _get_cached_schema(ctx: ToolContext, url: str) -> Dict[str, Any]:
    if ctx.store is not None:
        schema = ctx.store.graphql_schemas.get(url)
        if schema and schema.get("introspected"):
            return schema
    return {}


def _find_enum_arguments(schema: dict, operation_kind: str, field_name: str) -> List[Dict[str, Any]]:
    """Find all enum-typed arguments on a given operation field."""
    try:
        field = _lookup_field(schema, operation_kind, field_name)
    except ValueError:
        return []
    args = field.get("args") or []
    enum_types = schema.get("enum_types", {})
    result = []
    for arg in args:
        arg_type = arg.get("type", "")
        if arg_type in enum_types:
            values = enum_types[arg_type].get("values") or []
            result.append({
                "name": arg["name"],
                "type": arg_type,
                "wrapper": arg.get("wrapper"),
                "values": values,
            })
    return result


# ---------------------------------------------------------------------------
# Auth resolution (same pattern as sqli_probe)
# ---------------------------------------------------------------------------

async def _resolve_auth(ctx: ToolContext, url: str, method: str) -> Dict[str, Any]:
    store = getattr(ctx, "store", None)
    parsed = urlparse(url)
    host, path = parsed.hostname or "", parsed.path or "/"
    jar_cookie_map: Dict[str, str] = {}
    session_name = getattr(getattr(ctx, "_session", None), "session_name", None)
    if store is not None:
        try:
            if session_name and hasattr(store, "get_named_session_cookies_for_host"):
                jar = store.get_named_session_cookies_for_host(session_name, host) or []
            else:
                jar = store.get_cookies_for_host(host) or []
            jar_cookie_map = {c.get("name"): c.get("value", "") for c in jar if c.get("name")}
        except Exception as exc:
            logger.debug("graphql_scope_probe: cookie jar lookup failed", host=host, error=str(exc))
    rec = None
    session = getattr(ctx, "_session", None)
    try:
        from dast.session.auth_provider import scan_history_bearer
        if session is not None and store is not None and hasattr(session, "_ensure_fresh_bearer"):
            rec = await session._ensure_fresh_bearer(
                store, host, path, browser=getattr(ctx, "browser", None))
        elif session is not None and hasattr(session, "_select_bearer"):
            if store is not None and hasattr(session, "_capture_bearer_tokens"):
                session._capture_bearer_tokens(store, host)
            rec = session._select_bearer(host, path)
        elif store is not None:
            rec = scan_history_bearer(store, host, path)
    except Exception as exc:
        logger.debug("graphql_scope_probe: bearer resolution failed", host=host, error=str(exc))
    csrf_token = None
    if store is not None and method in ("POST", "PUT", "PATCH", "DELETE"):
        try:
            from dast.session.auth_provider import scan_history_csrf
            csrf_token = scan_history_csrf(store, host, exclude_source="copilot")
        except Exception as exc:
            logger.debug("graphql_scope_probe: csrf resolution failed", host=host, error=str(exc))
    return {"cookies": jar_cookie_map or None, "bearer_rec": rec, "csrf_token": csrf_token}


# ---------------------------------------------------------------------------
# Query builder for a specific enum value override
# ---------------------------------------------------------------------------

def _build_query_with_enum(
    schema: dict,
    operation_kind: str,
    field_name: str,
    enum_arg_name: str,
    enum_value: Optional[str],
    count_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a GraphQL operation, overriding one enum argument with a specific value.

    If enum_value is None, the argument is omitted (baseline).
    Returns {"query": str, "variables": dict, "operation_name": str}.
    """
    field = _lookup_field(schema, operation_kind, field_name)
    args = field.get("args") or []

    var_decls: List[str] = []
    call_args: List[str] = []
    variables: Dict[str, Any] = {}
    var_idx = 0

    for arg in args:
        is_target = arg["name"] == enum_arg_name
        is_required = (arg.get("wrapper") or "").startswith("NON_NULL")

        # Skip the target enum arg when building baseline (enum_value is None)
        if is_target and enum_value is None:
            continue

        # Skip optional non-target args — heuristic defaults for optional args
        # (per, page, search, all, etc.) cause server 500s on many real APIs.
        if not is_target and not is_required:
            continue

        var_name = f"var{var_idx}"
        gql_type = _gql_type_string(arg["type"], arg.get("wrapper"))
        var_decls.append(f"${var_name}: {gql_type}")
        call_args.append(f"{arg['name']}: ${var_name}")

        if is_target:
            variables[var_name] = enum_value
        else:
            variables[var_name] = build_argument_value(
                schema, arg["type"], arg.get("wrapper"),
                arg_name=arg["name"],
            )
        var_idx += 1

    return_type = field.get("return_type", "")
    selection = build_selection_set(schema, return_type) if return_type else "{ __typename }"

    op_name = field_name[0].upper() + field_name[1:] if field_name else "Op"
    decls = "(" + ", ".join(var_decls) + ")" if var_decls else ""
    call = "(" + ", ".join(call_args) + ")" if call_args else ""

    query = f"{operation_kind} {op_name}{decls} {{ {field_name}{call} {selection} }}"
    return {"query": query, "variables": variables, "operation_name": op_name}


# ---------------------------------------------------------------------------
# Input schema
# ---------------------------------------------------------------------------

_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "url": {
            "type": "string",
            "description": "GraphQL endpoint URL (must be in scope and have been introspected).",
        },
        "operation": {
            "type": "string",
            "description": "The query or mutation field name to test (e.g. 'users', 'groups').",
        },
        "operation_kind": {
            "type": "string",
            "description": "Whether the operation is a 'query' or 'mutation'. Default 'query'.",
        },
        "enum_argument": {
            "type": "string",
            "description": (
                "Specific enum argument to vary (e.g. 'permissionScope'). "
                "If omitted, all enum arguments on the operation are tested."
            ),
        },
        "baseline_variables": {
            "type": "object",
            "description": (
                "Optional variable overrides for the baseline query "
                "(e.g. {\"var0\": 10} to set per/limit)."
            ),
        },
        "count_path": {
            "type": "string",
            "description": (
                "JSONPath-like dot path to the count field in the response "
                "(e.g. 'data.users.pagination.totalCount'). If omitted, the tool "
                "auto-detects common pagination/nodes/edges patterns."
            ),
        },
        "record": {
            "type": "boolean",
            "description": "Record a finding when a bypass is flagged (default true).",
        },
        "title": {
            "type": "string",
            "description": "Optional finding title override.",
        },
        "severity": {
            "type": "string",
            "description": "Optional finding severity override (critical|high|medium|low|info).",
        },
    },
    "required": ["url", "operation"],
}


def _resolve_count_path(response_json: dict, count_path: str) -> Optional[int]:
    """Navigate a dot-separated path into a JSON response to extract a count."""
    node: Any = response_json
    for key in count_path.split("."):
        if isinstance(node, dict):
            node = node.get(key)
        else:
            return None
    if isinstance(node, int):
        return node
    if isinstance(node, list):
        return len(node)
    return None


# ---------------------------------------------------------------------------
# Main handler
# ---------------------------------------------------------------------------

async def _graphql_scope_probe(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    url = str(args.get("url", "")).strip()
    operation = str(args.get("operation", "")).strip()
    operation_kind = str(args.get("operation_kind", "query")).strip().lower() or "query"
    enum_argument = str(args.get("enum_argument", "")).strip() or None
    baseline_vars = args.get("baseline_variables") or {}
    count_path = str(args.get("count_path", "")).strip() or None
    should_record = bool(args.get("record", True))

    if not url:
        return {"ok": False, "error": "url is required"}
    if not operation:
        return {"ok": False, "error": "operation is required"}
    if operation_kind not in ("query", "mutation"):
        return {"ok": False, "error": "operation_kind must be 'query' or 'mutation'"}
    if not ctx.is_in_scope(url):
        return {"ok": False, "error": "url is out of scope", "url": url}

    schema = _get_cached_schema(ctx, url)
    if not schema:
        return {"ok": False, "error": "no cached schema for this URL — run graphql_introspect first",
                "url": url}

    # Validate operation exists
    try:
        _lookup_field(schema, operation_kind, operation)
    except ValueError:
        available = list((schema.get("queries" if operation_kind == "query" else "mutations") or {}).keys())
        suggestions = [n for n in available if operation.lower() in n.lower()][:10]
        return {"ok": False, "error": f"{operation_kind} '{operation}' not found in schema",
                "suggestions": suggestions}

    # Find enum arguments to test
    all_enum_args = _find_enum_arguments(schema, operation_kind, operation)
    if not all_enum_args:
        return {"ok": True, "result": "no_enum_args",
                "message": f"'{operation}' has no enum arguments — nothing to probe"}

    if enum_argument:
        targets = [ea for ea in all_enum_args if ea["name"] == enum_argument]
        if not targets:
            available_names = [ea["name"] for ea in all_enum_args]
            return {"ok": False,
                    "error": f"enum argument '{enum_argument}' not found on '{operation}'",
                    "available_enum_arguments": available_names}
    else:
        targets = all_enum_args

    # Auth setup
    method = "POST"
    auth = await _resolve_auth(ctx, url, method)

    from dast.session.auth_provider import attach as _attach
    source_label = getattr(ctx, "source_label", None)

    def _headers() -> Dict[str, str]:
        h: Dict[str, str] = {
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
        }
        if source_label:
            h["x-dast-source"] = str(source_label)
        _attach(h, transport="api", cookies=auth["cookies"], bearer_rec=auth["bearer_rec"],
                csrf_token=auth["csrf_token"], drop_all_authorization=True)
        return h

    import httpx

    async def _send_graphql(
        client: httpx.AsyncClient,
        query_data: Dict[str, Any],
        variable_overrides: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Send a GraphQL operation through the proxy. Returns parsed response + raw status."""
        from dast.scanners import noise_governor
        pace_token = await noise_governor.acquire(urlparse(url).hostname or url)
        try:
            body = dict(query_data)
            if variable_overrides:
                variables = dict(body.get("variables") or {})
                variables.update(variable_overrides)
                body["variables"] = variables
            resp = await client.request(
                method, url, headers=_headers(),
                content=json.dumps(body).encode("utf-8"),
            )
            text = resp.text
            try:
                parsed = json.loads(text)
            except Exception:
                parsed = {}
            return {"status": resp.status_code, "parsed": parsed, "text": text[:5000]}
        except Exception as exc:
            return {"status": 0, "parsed": {}, "error": str(exc)[:200]}
        finally:
            if pace_token is not None:
                pace_token.release()

    # Run the probe
    results: List[Dict[str, Any]] = []
    flagged_bypasses: List[Dict[str, Any]] = []

    proxy_url = ctx.proxy_url

    async with httpx.AsyncClient(
        proxy=proxy_url, verify=False, timeout=30.0,
    ) as client:
        for enum_arg in targets:
            arg_name = enum_arg["name"]
            arg_values = enum_arg["values"]
            arg_result: Dict[str, Any] = {
                "argument": arg_name,
                "type": enum_arg["type"],
                "values_tested": len(arg_values),
                "variants": [],
            }

            # 1. Baseline: query WITHOUT the enum argument
            baseline_query = _build_query_with_enum(
                schema, operation_kind, operation, arg_name, None)
            baseline_resp = await _send_graphql(client, baseline_query, baseline_vars)

            if baseline_resp.get("error"):
                arg_result["baseline_error"] = baseline_resp["error"]
                results.append(arg_result)
                continue

            baseline_errors = _extract_errors(baseline_resp["parsed"])
            if count_path:
                baseline_count = _resolve_count_path(baseline_resp["parsed"], count_path)
            else:
                baseline_count = _extract_count(baseline_resp["parsed"], operation)

            arg_result["baseline"] = {
                "count": baseline_count,
                "status": baseline_resp["status"],
                "has_errors": bool(baseline_errors),
            }

            # 2. For each enum value: query WITH that value
            for enum_val in arg_values:
                variant_query = _build_query_with_enum(
                    schema, operation_kind, operation, arg_name, enum_val)
                variant_resp = await _send_graphql(client, variant_query, baseline_vars)

                if variant_resp.get("error"):
                    arg_result["variants"].append({
                        "value": enum_val, "error": variant_resp["error"],
                    })
                    continue

                variant_errors = _extract_errors(variant_resp["parsed"])
                if count_path:
                    variant_count = _resolve_count_path(variant_resp["parsed"], count_path)
                else:
                    variant_count = _extract_count(variant_resp["parsed"], operation)

                delta = None
                is_flagged = False
                if baseline_count is not None and variant_count is not None:
                    delta = variant_count - baseline_count
                    # Flag if the variant returns MORE records than baseline
                    is_flagged = variant_count > baseline_count and delta > 0

                variant_info: Dict[str, Any] = {
                    "value": enum_val,
                    "count": variant_count,
                    "status": variant_resp["status"],
                    "delta": delta,
                    "flagged": is_flagged,
                    "has_errors": bool(variant_errors),
                }

                if is_flagged:
                    variant_info["bypass_signal"] = (
                        f"variant '{enum_val}' returned {variant_count} records "
                        f"vs baseline {baseline_count} (+{delta})"
                    )
                    flagged_bypasses.append({
                        "argument": arg_name,
                        "value": enum_val,
                        "baseline_count": baseline_count,
                        "variant_count": variant_count,
                        "delta": delta,
                    })

                if variant_errors and not baseline_errors:
                    variant_info["new_errors"] = variant_errors[:3]

                arg_result["variants"].append(variant_info)

            results.append(arg_result)

    # Build result
    out: Dict[str, Any] = {
        "ok": True,
        "url": url,
        "operation": operation,
        "arguments_tested": len(targets),
        "results": results,
        "bypasses_found": len(flagged_bypasses),
    }

    if flagged_bypasses:
        out["flagged"] = flagged_bypasses
        out["verdict"] = "SCOPE_BYPASS_DETECTED"
        out["message"] = (
            f"Potential scope bypass: {len(flagged_bypasses)} enum value(s) return "
            f"more records than the baseline on '{operation}'. This suggests the server "
            f"fails open when the user has no permission for the requested scope."
        )

        # Record a finding for each unique argument that had a bypass
        if should_record and getattr(ctx, "store", None) is not None:
            bypassed_args = {b["argument"] for b in flagged_bypasses}
            for arg_name in bypassed_args:
                arg_bypasses = [b for b in flagged_bypasses if b["argument"] == arg_name]
                worst = max(arg_bypasses, key=lambda b: b["delta"])

                severity = str(args.get("severity", "")).strip().lower()
                if severity not in ("critical", "high", "medium", "low", "info"):
                    severity = "high" if worst["delta"] > 10 else "medium"

                finding_title = (
                    str(args.get("title", "")).strip()
                    or f"GraphQL scope bypass via '{arg_name}' on {operation}()"
                )
                evidence = (
                    f"Baseline (no {arg_name}): {worst['baseline_count']} records. "
                    f"With {arg_name}={worst['value']}: {worst['variant_count']} records "
                    f"(+{worst['delta']}). The server returns unfiltered data when the "
                    f"user has no permission for the '{worst['value']}' scope."
                )
                finding = {
                    "title": finding_title,
                    "severity": severity,
                    "attack_type": "bfla",
                    "cwe": "CWE-863",
                    "parameter": arg_name,
                    "evidence": evidence,
                    "confirmed": True,
                    "confidence": 0.9,
                    "validated_by": ["graphql_scope_probe"],
                    "source": "copilot",
                }
                try:
                    entry_id = ctx.store.record_manual_finding(finding, url, method)
                    out.setdefault("recorded_entry_ids", []).append(entry_id)
                    logger.info("graphql_scope_probe recorded finding",
                                entry_id=entry_id, argument=arg_name, operation=operation)
                except Exception as exc:
                    out.setdefault("record_errors", []).append(str(exc)[:200])
    else:
        out["verdict"] = "NO_BYPASS"
        out["message"] = (
            f"No scope bypass detected: all enum variants on '{operation}' returned "
            f"<= baseline record counts."
        )

    return out


register(Tool(
    name="graphql_scope_probe",
    description=(
        "Test a GraphQL operation for access control bypass via enum argument variation. "
        "Varies each enum argument value (e.g. permissionScope) and compares response "
        "record counts. Flags when a variant returns MORE records than the baseline — "
        "this indicates the server's permission filter fails open when the user has no "
        "grants for the requested scope.\n\n"
        "The schema must have been introspected first with graphql_introspect.\n\n"
        "Use this when testing GraphQL APIs for access control: authenticate as a "
        "partially-privileged user (not admin, not bare learner), then probe operations "
        "that accept enum arguments selecting permission scopes, roles, or filter modes. "
        "A sub-admin seeing 129 users with permissionScope:TRAINING vs 0 without it is "
        "a scope bypass finding.\n\n"
        "Works best with a 'medium-privilege' test persona — a user with some permissions "
        "but not all. Full admins see everything regardless (no differential), and zero-"
        "permission users may not pass the resolver policy at all."
    ),
    input_schema=_SCHEMA,
    handler=_graphql_scope_probe,
    tags=["active", "graphql", "authz"],
))
