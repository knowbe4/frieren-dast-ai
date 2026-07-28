"""
GraphQL API routes — schema lookup, manual introspection, query building, and
the variable-fuzzing job (run/poll/stop), backing the dashboard's GraphQL tab
(Schema Explorer / Query Builder / Fuzzer).
"""

from __future__ import annotations

import asyncio
import uuid
from typing import TYPE_CHECKING

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.proxy.api.context import DashboardContext

logger = get_logger(__name__)

_AUTH_HEADERS = frozenset({
    "cookie", "authorization", "x-csrf-token", "x-xsrf-token",
    "x-requested-with", "x-auth-token", "x-api-key",
})


def make_router(ctx: "DashboardContext") -> APIRouter:
    router = APIRouter()
    store = ctx.store
    fuzz_jobs = ctx.graphql_fuzz_jobs

    @router.get("/api/graphql/schema")
    async def get_graphql_schema(endpoint: str = ""):
        """Return the compact schema for a GraphQL endpoint (from introspection plugin)."""
        if not endpoint:
            return JSONResponse({"error": "endpoint parameter required"}, status_code=400)
        schema = store.graphql_schemas.get(endpoint)
        if schema is None:
            # Try exact-path-boundary prefix match (schema stored without query
            # string) — never a bare startswith, which could return a sibling
            # endpoint's schema when one path is a literal prefix of another
            # (e.g. /graphql vs /graphql/v2).
            target_path = endpoint.split("?")[0]
            for key, val in store.graphql_schemas.items():
                if target_path == key or target_path.startswith(key.rstrip("/") + "/"):
                    schema = val
                    break
        if schema is None:
            return JSONResponse({"schema": None, "available": list(store.graphql_schemas.keys())})
        if not schema.get("introspected"):
            return JSONResponse({"schema": None, "introspected": False})
        return JSONResponse({"schema": schema})

    @router.get("/api/graphql/endpoints")
    async def list_graphql_endpoints():
        """
        List all known GraphQL endpoints — discovered from traffic or added
        manually — each flagged with whether its schema has been introspected
        yet. Introspection is never automatic; the caller decides when to
        trigger it via POST /api/graphql/introspect.
        """
        return JSONResponse({
            "endpoints": [
                {"endpoint": url, "introspected": bool((schema or {}).get("introspected"))}
                for url, schema in store.graphql_schemas.items()
            ]
        })

    @router.post("/api/graphql/endpoints")
    async def add_graphql_endpoint(request: Request):
        """Manually register a GraphQL endpoint that wasn't auto-detected."""
        from dast.plugins.graphql_introspection import catalogue_endpoint

        body = await request.json()
        endpoint = str(body.get("endpoint", "")).strip()
        if not endpoint:
            return JSONResponse({"error": "endpoint is required"}, status_code=400)
        added = catalogue_endpoint(endpoint, store)
        return JSONResponse({"ok": True, "added": added})

    @router.post("/api/graphql/rescan-history")
    async def rescan_history():
        """
        Walk the entire captured HTTP history (not just new live traffic) and
        catalogue any GraphQL endpoints that were missed — e.g. because they
        were captured before this plugin/session was active to observe them
        live. Never introspects automatically, same as live detection.
        """
        from dast.plugins.graphql_introspection import (
            _endpoint_url,
            _is_graphql_endpoint,
            catalogue_endpoint,
        )

        found = 0
        for entry in store.all_entries():
            if entry.source == "agent":
                continue
            if not _is_graphql_endpoint(entry):
                continue
            if catalogue_endpoint(_endpoint_url(entry), store):
                found += 1
        return JSONResponse({"ok": True, "new_endpoints": found})

    def _best_auth_headers_for_endpoint(endpoint: str) -> dict:
        """Borrow auth headers from the most recent real (non-imported/agent) captured
        request to the same host as `endpoint`, falling back to the session cookie jar."""
        from urllib.parse import urlparse

        host = urlparse(endpoint).netloc
        best: dict = {}
        with store._lock:
            for eid in reversed(store._order):
                e = store._entries.get(eid)
                if not e or e.host != host or e.source in ("imported", "agent"):
                    continue
                for k, v in e.request_headers.items():
                    if k.lower() in _AUTH_HEADERS:
                        best[k.lower()] = v
                if best:
                    return best

        session_cookies = store.get_cookies_for_host(host)
        if session_cookies:
            cookie_header = "; ".join(
                f"{c['name']}={c['value']}" for c in session_cookies if c.get("name")
            )
            if cookie_header:
                best["cookie"] = cookie_header
        return best

    def _all_headers_from_most_recent_request(endpoint: str) -> dict:
        """Return the FULL header set (not just the auth subset) of the most
        recent real captured request to this exact endpoint — used to prefill
        the GraphQL tab's editable header/cookie field so the user sees
        everything and can hand-edit it (e.g. swap in a different session)."""
        from dast.plugins.graphql_introspection import _endpoint_url as _ep_url

        with store._lock:
            for eid in reversed(store._order):
                e = store._entries.get(eid)
                if not e or e.source in ("imported", "agent"):
                    continue
                if _ep_url(e) != endpoint:
                    continue
                return {
                    k: v for k, v in e.request_headers.items()
                    if k.lower() not in ("host", "content-length", "transfer-encoding", "connection")
                }
        return _best_auth_headers_for_endpoint(endpoint)

    def _headers_from_named_session(name: str, endpoint: str) -> dict:
        """Build a header dict (cookie + any auth_headers) from a saved NamedSession."""
        session = store.named_sessions.get(name)
        if not session:
            return {}
        headers = dict(session.auth_headers or {})
        if session.cookies:
            cookie_header = "; ".join(
                f"{c['name']}={c['value']}" for c in session.cookies.values() if c.get("name")
            )
            if cookie_header:
                headers["cookie"] = cookie_header
        return headers

    @router.get("/api/graphql/headers-for-endpoint")
    async def headers_for_endpoint(endpoint: str = "", named_session: str = ""):
        """
        Return a header dict to prefill the GraphQL tab's editable header field:
        from a named session if requested, else from the most recent real
        captured request to this endpoint.
        """
        if not endpoint:
            return JSONResponse({"error": "endpoint is required"}, status_code=400)
        if named_session:
            headers = _headers_from_named_session(named_session, endpoint)
        else:
            headers = _all_headers_from_most_recent_request(endpoint)
        return JSONResponse({"headers": headers})

    @router.post("/api/graphql/introspect")
    async def trigger_introspection(request: Request):
        """Manually (re-)run introspection for a given endpoint. Accepts an
        optional headers override — explicit headers win over the most-recent-
        traffic guess, so the caller can point introspection at a different
        user's session on a multi-user proxy."""
        from dast.plugins.graphql_introspection import _introspect

        body = await request.json()
        endpoint = str(body.get("endpoint", "")).strip()
        if not endpoint:
            return JSONResponse({"error": "endpoint is required"}, status_code=400)

        override_headers = body.get("headers")
        if isinstance(override_headers, dict) and override_headers:
            headers = override_headers
        else:
            headers = _best_auth_headers_for_endpoint(endpoint)
        error = await _introspect(endpoint, headers, store, "GraphQL Introspection")

        if error:
            return JSONResponse({"ok": False, "error": error}, status_code=200)
        schema = store.graphql_schemas.get(endpoint)
        if schema is None or not schema.get("introspected"):
            return JSONResponse(
                {"ok": False, "error": "Introspection did not return a usable schema"},
                status_code=200,
            )
        return JSONResponse({"ok": True, "schema": schema})

    @router.post("/api/graphql/build")
    async def build_query(request: Request):
        """Build a complete query/mutation from a stored schema. Sync — no job needed."""
        from dast.graphql.query_builder import build_operation

        body = await request.json()
        endpoint = str(body.get("endpoint", "")).strip()
        operation = str(body.get("operation", "")).strip()
        field_name = str(body.get("field_name", "")).strip()

        schema = store.graphql_schemas.get(endpoint)
        if schema is None or not schema.get("introspected"):
            return JSONResponse(
                {"error": f"no introspected schema for endpoint {endpoint!r} — run introspection first"},
                status_code=404,
            )

        try:
            result = build_operation(schema, operation, field_name)
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

        return JSONResponse(result)

    @router.post("/api/graphql/fuzz/extract-vars")
    async def fuzz_extract_vars(request: Request):
        """Preview which variables would be fuzzed, without starting a job."""
        from dast.graphql.variable_fuzzer import extract_variables

        body = await request.json()
        request_body = str(body.get("body", ""))
        try:
            variables = extract_variables(request_body)
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

        return JSONResponse({
            "variables": [
                {"name": v.name, "original_value": v.original_value, "inferred_type": v.inferred_type}
                for v in variables
            ]
        })

    @router.post("/api/graphql/fuzz/run")
    async def fuzz_run(request: Request):
        """Start a variable-fuzzing job. Returns {job_id} immediately."""
        from dast.graphql.variable_fuzzer import (
            build_fuzz_matrix,
            extract_variables,
        )
        from dast.payloads.loader import get_all_payloads, get_payloads

        body = await request.json()
        method = str(body.get("method", "POST")).upper()
        url = str(body.get("url", "")).strip()
        headers = dict(body.get("headers") or {})
        request_body = str(body.get("body", ""))
        payload_source = str(body.get("payload_source", "yaml"))
        custom_payloads_raw = str(body.get("custom_payloads") or "")
        payload_groups = body.get("payload_groups") or []

        if not url:
            return JSONResponse({"error": "url is required"}, status_code=400)

        try:
            variables = extract_variables(request_body)
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

        if payload_source == "custom":
            payloads = [line.strip() for line in custom_payloads_raw.splitlines() if line.strip()]
        elif payload_groups:
            seen: set = set()
            payloads = []
            for group in payload_groups:
                for p in get_payloads("graphql", group):
                    if p not in seen:
                        seen.add(p)
                        payloads.append(p)
        else:
            payloads = get_all_payloads("graphql")

        if not payloads:
            return JSONResponse({"error": "No payloads available for the selected configuration."}, status_code=400)

        attempts = build_fuzz_matrix(variables, payloads)

        for hop in ("host", "content-length", "transfer-encoding", "connection", "accept-encoding"):
            headers.pop(hop, None)
            headers.pop(hop.title(), None)
        headers.setdefault("content-type", "application/json")

        # Baseline request to compare fuzzed responses against.
        baseline_length = 0
        baseline_had_errors = False
        try:
            async with httpx.AsyncClient(follow_redirects=False, timeout=httpx.Timeout(15.0), verify=False) as client:
                resp = await client.request(method, url, headers=headers, content=request_body.encode("utf-8"))
                baseline_length = len(resp.content)
                try:
                    baseline_had_errors = bool(resp.json().get("errors"))
                except Exception:
                    baseline_had_errors = False
        except Exception as exc:
            logger.warning("GraphQL fuzz baseline request failed", url=url, error=str(exc))

        job_id = str(uuid.uuid4())
        fuzz_jobs[job_id] = {
            "status": "queued", "progress": {"done": 0, "total": len(attempts)},
            "results": [], "cancel": False,
        }

        from dast.graphql.variable_fuzzer import run_fuzz_job
        asyncio.ensure_future(run_fuzz_job(
            fuzz_jobs[job_id], method, url, headers, request_body,
            attempts, baseline_length, baseline_had_errors,
        ))

        return {"job_id": job_id, "total": len(attempts)}

    @router.get("/api/graphql/fuzz/results/{job_id}")
    async def fuzz_results(job_id: str):
        job = fuzz_jobs.get(job_id)
        if not job:
            return JSONResponse({"error": "unknown job_id"}, status_code=404)
        return {
            "status": job["status"],
            "progress": job.get("progress"),
            "results": job["results"],
        }

    @router.post("/api/graphql/fuzz/stop/{job_id}")
    async def fuzz_stop(job_id: str):
        job = fuzz_jobs.get(job_id)
        if not job:
            return JSONResponse({"error": "unknown job_id"}, status_code=404)
        job["cancel"] = True
        return {"ok": True}

    return router
