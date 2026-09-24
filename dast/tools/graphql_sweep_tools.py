"""
graphql_sweep tool — breadth-first coverage of an introspected GraphQL schema.

``graphql_introspect`` only *fetches* the schema; nothing tests the operations it
exposes. On a large API (hundreds of queries + mutations) an agent cannot call a
per-operation tool once each — the tool-call budget would run out long before the
surface is covered. This tool closes that gap: given an already-introspected
endpoint, it exercises EVERY query/mutation field in one call (bounded, resumable
across calls), so the whole schema gets touched instead of a hand-picked few.

It is coverage + exposure mapping, not exploitation. As the current (proxy-injected)
session it:
  - QUERIES: executes them with heuristic placeholder args (queries are side-effect-
    free by GraphQL convention) and reports which return data.
  - MUTATIONS: sends the operation with EMPTY variables so a required-argument
    validation error rejects it BEFORE the resolver runs — a non-destructive authz
    probe. Mutations with no required args are catalogued for manual review and never
    auto-fired (auto-firing them could be destructive).

Requests route through the Frieren proxy (``ctx.proxy_url``) so they are captured in
history and carry the run's authenticated session, exactly like ``send_request``.

Every probed operation is recorded on ``store.graphql_tested_ops[endpoint]`` so the
autonomous copilot's coverage gate knows what remains untested. Flagged operations
(those that returned data as the current user) are surfaced for the caller to reason
about — deep authz/BOLA testing across users is the caller's next step, not this
tool's job.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Tuple

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_OPERATION_BUCKET = {"query": "queries", "mutation": "mutations"}

# One call covers up to _DEFAULT_MAX_OPS untested operations; the caller re-invokes
# until the coverage gate reports the schema fully swept.
_DEFAULT_MAX_OPS = 250
_HARD_MAX_OPS = 1000
_CONCURRENCY = 6
_REQUEST_TIMEOUT = 10.0
_MAX_FLAGGED_RETURNED = 40

_AUTH_ERROR_MARKERS = (
    "unauthor", "forbidden", "not authenticated", "authentication required",
    "permission", "access denied", "not allowed", "login required", "must be logged in",
)

_SWEEP_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "url": {
            "type": "string",
            "description": "The in-scope GraphQL endpoint URL to sweep. It must already have an "
                           "introspected schema (call graphql_introspect on it first).",
        },
        "kinds": {
            "type": "array",
            "items": {"type": "string", "enum": ["query", "mutation"]},
            "description": "Which operation kinds to sweep (default: both query and mutation).",
        },
        "max_operations": {
            "type": "integer",
            "description": "Max untested operations to probe in this call (default 250, cap 1000). "
                           "Untested ops carry over — call again to cover the remainder.",
        },
    },
    "required": ["url"],
}


def _normalise_kinds(raw: Any) -> List[str]:
    if not isinstance(raw, list) or not raw:
        return ["query", "mutation"]
    kinds = [k for k in ("query", "mutation") if k in raw]
    return kinds or ["query", "mutation"]


def _mutation_has_required_args(schema: Dict[str, Any], field_name: str) -> bool:
    """True if the mutation declares at least one non-null (required) argument.
    An empty-variables authz probe against such a mutation fails validation before
    the resolver executes, so it never performs a write."""
    field = (schema.get("mutations") or {}).get(field_name) or {}
    for arg in field.get("args") or []:
        wrapper = str(arg.get("wrapper") or "")
        if wrapper.startswith("NON_NULL"):  # NON_NULL, NON_NULL_LIST, NON_NULL_LIST_OF_NON_NULL
            return True
    return False


def _has_nonnull_data(payload: Any) -> bool:
    """True if a GraphQL ``data`` object carries at least one non-null field value."""
    if not isinstance(payload, dict):
        return payload not in (None, "", [], {})
    return any(value not in (None, "", [], {}) for value in payload.values())


def _classify(status: int, data: Any) -> Tuple[str, bool]:
    """Map a GraphQL response to (classification, flagged). Flag only when the current
    session got data back — a reachable, data-returning operation is the lead worth a
    deeper cross-user/authz look. Validation/execution errors are the expected, safe
    outcome for the mutation authz probe and are NOT flagged (keeps false positives low)."""
    if status in (401, 403):
        return "auth_blocked", False
    if isinstance(data, dict):
        errors = data.get("errors")
        payload = data.get("data")
        if errors:
            error_text = json.dumps(errors).lower()
            if any(marker in error_text for marker in _AUTH_ERROR_MARKERS):
                return "auth_blocked", False
            if _has_nonnull_data(payload):
                return "data_returned", True  # partial data despite errors — still a lead
            return "error", False
        if _has_nonnull_data(payload):
            return "data_returned", True
        return "empty", False
    return "non_json", False


async def _probe_operation(
    ctx: ToolContext, url: str, schema: Dict[str, Any], kind: str, field_name: str,
    semaphore: asyncio.Semaphore,
) -> Dict[str, Any]:
    from dast.graphql.query_builder import build_operation

    async with semaphore:
        try:
            operation = build_operation(schema, kind, field_name)
        except Exception as exc:  # malformed schema entry — count as covered, note why
            return {"kind": kind, "field": field_name,
                    "classification": "build_error", "flagged": False,
                    "detail": str(exc)[:120]}

        variables = operation["variables"]
        if kind == "mutation":
            if not _mutation_has_required_args(schema, field_name):
                # No required args: an empty-variables probe would actually execute the
                # resolver, which could be destructive. Catalogue for manual review.
                return {"kind": kind, "field": field_name,
                        "classification": "skipped_zero_arg_mutation", "flagged": True,
                        "detail": "no required args — not auto-fired; test manually"}
            variables = {}  # force pre-resolver validation rejection (non-destructive probe)

        body = json.dumps({
            "query": operation["query"],
            "variables": variables,
            "operationName": operation["operation_name"],
        })
        try:
            import httpx

            async with httpx.AsyncClient(
                proxy=ctx.proxy_url, verify=False, follow_redirects=False,
                timeout=_REQUEST_TIMEOUT,
            ) as client:
                resp = await client.post(
                    url, content=body.encode("utf-8"),
                    headers={"content-type": "application/json", "accept": "application/json"},
                )
        except Exception as exc:
            return {"kind": kind, "field": field_name,
                    "classification": "request_error", "flagged": False,
                    "detail": str(exc)[:120]}

        try:
            data = resp.json()
        except Exception:
            data = None
        classification, flagged = _classify(resp.status_code, data)
        return {"kind": kind, "field": field_name, "status": resp.status_code,
                "classification": classification, "flagged": flagged}


async def _graphql_sweep(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    url = str(args.get("url", "")).strip()
    if not url:
        return {"ok": False, "error": "url is required"}
    if not ctx.is_in_scope(url):
        return {"ok": False, "error": "url is out of scope", "url": url}

    store = getattr(ctx, "store", None)
    if store is None:
        return {"ok": False,
                "error": "graphql_sweep is not available in this context (no in-process store)",
                "url": url}

    schema = store.graphql_schemas.get(url)
    if not schema or not schema.get("introspected"):
        return {"ok": False,
                "error": "no introspected schema for this endpoint — run graphql_introspect first",
                "url": url}

    kinds = _normalise_kinds(args.get("kinds"))
    try:
        max_operations = int(args.get("max_operations", _DEFAULT_MAX_OPS))
    except (TypeError, ValueError):
        max_operations = _DEFAULT_MAX_OPS
    max_operations = max(1, min(max_operations, _HARD_MAX_OPS))

    tested: set = store.graphql_tested_ops.setdefault(url, set())

    total_ops = 0
    pending: List[Tuple[str, str]] = []
    for kind in kinds:
        bucket = schema.get(_OPERATION_BUCKET[kind]) or {}
        total_ops += len(bucket)
        for field_name in sorted(bucket.keys()):
            if f"{kind}:{field_name}" not in tested:
                pending.append((kind, field_name))

    batch = pending[:max_operations]
    if not batch:
        return {"ok": True, "url": url, "kinds": kinds,
                "operations_total": total_ops,
                "operations_tested_now": 0,
                "operations_tested_cumulative": len(tested),
                "operations_remaining": 0,
                "by_classification": {}, "flagged": [],
                "note": "all operations for the requested kinds already swept"}

    logger.info("graphql_sweep: probing operations", url=url, kinds=kinds,
                batch=len(batch), remaining=len(pending) - len(batch))

    semaphore = asyncio.Semaphore(_CONCURRENCY)
    results = await asyncio.gather(*[
        _probe_operation(ctx, url, schema, kind, field_name, semaphore)
        for kind, field_name in batch
    ])

    by_classification: Dict[str, int] = {}
    flagged: List[Dict[str, Any]] = []
    for (kind, field_name), result in zip(batch, results):
        tested.add(f"{kind}:{field_name}")
        classification = result.get("classification", "unknown")
        by_classification[classification] = by_classification.get(classification, 0) + 1
        if result.get("flagged"):
            flagged.append({k: v for k, v in result.items() if k != "flagged"})

    remaining = len(pending) - len(batch)
    summary: Dict[str, Any] = {
        "ok": True,
        "url": url,
        "kinds": kinds,
        "operations_total": total_ops,
        "operations_tested_now": len(batch),
        "operations_tested_cumulative": len(tested),
        "operations_remaining": remaining,
        "by_classification": by_classification,
        "flagged": flagged[:_MAX_FLAGGED_RETURNED],
        "flagged_count": len(flagged),
    }
    if remaining > 0:
        summary["note"] = (f"{remaining} operations still untested — call graphql_sweep again "
                           f"on this endpoint to cover them")
    logger.info("graphql_sweep: batch complete", url=url, tested_now=len(batch),
                cumulative=len(tested), remaining=remaining, flagged=len(flagged))
    return summary


register(Tool(
    name="graphql_sweep",
    description=(
        "Systematically exercise EVERY query and mutation of an already-introspected GraphQL "
        "endpoint, in one call, for breadth-first coverage of the whole schema. Use this after "
        "graphql_introspect instead of hand-picking a few operations with send_request — on a "
        "large schema you cannot cover hundreds of operations one tool call at a time.\n"
        "As the current authenticated session it EXECUTES queries (read-only) and probes mutations "
        "non-destructively (empty variables so required-arg validation rejects them before the "
        "resolver runs; zero-required-arg mutations are catalogued for manual review, never fired). "
        "It returns a coverage tally plus the operations that returned data as the current user — "
        "your leads for deeper cross-user / authorization (BOLA/IDOR) testing.\n"
        "Untested operations carry over between calls; call again until operations_remaining is 0."
    ),
    input_schema=_SWEEP_SCHEMA,
    handler=_graphql_sweep,
    tags=["active", "graphql"],
))
