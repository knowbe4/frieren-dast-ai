"""
graphql_fuzz — schema-free GraphQL testing over operations captured in traffic.

``graphql_sweep`` needs an introspected schema, which production endpoints disable.
This tool instead takes the GraphQL operations the app actually sent (captured in
history), fuzzes their ``variables`` with the GraphQL payload set, and flags
responses that diverge (5xx, new ``errors``, large length delta). It is the only
autonomous path to exercise GraphQL on a hardened endpoint.

Each probed operation is recorded on ``store.graphql_tested_ops[endpoint]`` as
``fuzz:<op_key>`` so the autonomous coverage gate counts it as tested. Active-only
(in ``read_only.BLOCKED_TOOLS``).
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List, Tuple

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_DEFAULT_MAX_OPS = 25
_HARD_MAX_OPS = 100
_AUTH_HEADER_NAMES = {"cookie", "authorization", "x-csrf-token", "x-xsrf-token"}

_GRAPHQL_FUZZ_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "url": {
            "type": "string",
            "description": "The GraphQL endpoint URL (e.g. https://host/graphql) whose captured "
                           "operations should be fuzzed. Operations are taken from proxy history.",
        },
        "max_operations": {
            "type": "integer",
            "description": f"Max distinct captured operations to fuzz this call (default "
                           f"{_DEFAULT_MAX_OPS}, max {_HARD_MAX_OPS}). Resumable: already-fuzzed "
                           f"operations are skipped, so re-call until operations_remaining is 0.",
        },
    },
    "required": ["url"],
}


def _op_key(body: dict) -> str:
    """Stable key for a captured operation: its operationName, else a short hash of
    the whitespace-normalised query."""
    name = body.get("operationName")
    if isinstance(name, str) and name.strip():
        return name.strip()
    query = body.get("query") or ""
    normalised = re.sub(r"\s+", " ", str(query)).strip()
    return "anon:" + hashlib.sha256(normalised.encode("utf-8")).hexdigest()[:12]


def _captured_operations(store: Any, url: str) -> List[Tuple[str, dict, Dict[str, str]]]:
    """Distinct GraphQL operations captured for ``url`` as (op_key, body, auth_headers)."""
    from dast.plugins.graphql_analyzer import _is_graphql

    seen: Dict[str, Tuple[str, dict, Dict[str, str]]] = {}
    try:
        entries = store.in_scope_entries()
    except Exception as exc:
        logger.warning("graphql_fuzz: history read failed", error=str(exc))
        return []
    for entry in entries:
        try:
            if getattr(entry, "url", "") != url or not _is_graphql(entry):
                continue
            raw = entry.request_body
            if not raw:
                continue
            body = json.loads(raw[:200000].decode("utf-8", errors="replace"))
            # Some clients batch operations as a list — fuzz each.
            items = body if isinstance(body, list) else [body]
            for item in items:
                if not isinstance(item, dict) or not isinstance(item.get("query"), str):
                    continue
                if not (item.get("variables") or {}):
                    continue  # nothing to fuzz
                key = _op_key(item)
                if key not in seen:
                    headers = {k: v for k, v in (entry.request_headers or {}).items()
                               if k.lower() in _AUTH_HEADER_NAMES or k.lower() == "content-type"}
                    seen[key] = (key, item, headers)
        except Exception as exc:
            logger.debug("graphql_fuzz: skipping entry", error=str(exc))
    return list(seen.values())


async def _graphql_fuzz(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    import httpx

    from dast.graphql.variable_fuzzer import build_fuzz_matrix, extract_variables, run_fuzz_job
    from dast.payloads.loader import get_all_payloads

    url = str(args.get("url", "")).strip()
    if not url:
        return {"ok": False, "error": "url is required"}
    if not ctx.is_in_scope(url):
        return {"ok": False, "error": "url is out of scope", "url": url}
    store = getattr(ctx, "store", None)
    if store is None:
        return {"ok": False, "error": "graphql_fuzz is not available in this context", "url": url}

    try:
        max_operations = int(args.get("max_operations", _DEFAULT_MAX_OPS))
    except (TypeError, ValueError):
        max_operations = _DEFAULT_MAX_OPS
    max_operations = max(1, min(max_operations, _HARD_MAX_OPS))

    operations = _captured_operations(store, url)
    if not operations:
        return {"ok": True, "url": url, "operations_fuzzed": 0, "attempts": 0, "hits": [],
                "operations_remaining": 0,
                "note": "no captured GraphQL operations with variables for this endpoint — "
                        "browse/explore the app first so its queries are recorded"}

    payloads = get_all_payloads("graphql")
    tested: set = store.graphql_tested_ops.setdefault(url, set())
    pending = [op for op in operations if f"fuzz:{op[0]}" not in tested]
    batch = pending[:max_operations]

    total_attempts = 0
    hits: List[dict] = []
    async with httpx.AsyncClient(follow_redirects=False, timeout=httpx.Timeout(20.0), verify=False) as client:
        for op_key, body, headers in batch:
            headers.setdefault("content-type", "application/json")
            body_template = json.dumps(body)
            try:
                variables = extract_variables(body_template)
            except ValueError:
                tested.add(f"fuzz:{op_key}")  # no fuzzable variables — count as covered
                continue
            attempts = build_fuzz_matrix(variables, payloads)
            # Baseline to compare against (length + whether errors are normal here).
            baseline_length, baseline_had_errors = 0, False
            try:
                resp = await client.request("POST", url, headers=headers, content=body_template.encode("utf-8"))
                baseline_length = len(resp.content)
                try:
                    baseline_had_errors = bool(resp.json().get("errors"))
                except Exception:
                    baseline_had_errors = False
            except Exception as exc:
                logger.warning("graphql_fuzz: baseline failed", url=url, op=op_key, error=str(exc))

            job: Dict[str, Any] = {"results": [], "cancel": False}
            await run_fuzz_job(job, "POST", url, headers, body_template,
                               attempts, baseline_length, baseline_had_errors)
            total_attempts += len(attempts)
            for result in job.get("results", []):
                if result.get("hit"):
                    hits.append({"operation": op_key, "variable": result["variable"],
                                 "payload": result["payload"], "status_code": result["status_code"],
                                 "length_bytes": result["length_bytes"],
                                 "errors_present": result["errors_present"]})
            tested.add(f"fuzz:{op_key}")

    remaining = len([op for op in operations if f"fuzz:{op[0]}" not in tested])
    logger.info("graphql_fuzz: complete", url=url, fuzzed=len(batch), attempts=total_attempts,
                hits=len(hits), remaining=remaining)
    return {
        "ok": True,
        "url": url,
        "operations_fuzzed": len(batch),
        "attempts": total_attempts,
        "hits": hits[:50],
        "hit_count": len(hits),
        "operations_remaining": remaining,
    }


register(Tool(
    name="graphql_fuzz",
    description=(
        "Fuzz the variables of GraphQL operations captured in traffic — the schema-free way to "
        "test a GraphQL endpoint whose introspection is disabled (production). Flags responses that "
        "diverge from baseline (5xx, new errors, large length delta) as leads to verify. Each "
        "operation is recorded as tested for coverage.\n"
        "Use when graphql_introspect fails/returns no schema, or graphql_sweep reports "
        "fallback='graphql_fuzz'. Browse or `explore` the app first so its GraphQL operations are "
        "captured. Resumable: call until operations_remaining is 0."
    ),
    input_schema=_GRAPHQL_FUZZ_SCHEMA,
    handler=_graphql_fuzz,
    tags=["active", "graphql"],
))
