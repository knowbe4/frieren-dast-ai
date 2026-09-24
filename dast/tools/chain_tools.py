"""
validate_chain tool — reproduce and validate a multi-step attack chain.

A single request cannot prove an exploit whose later steps depend on data leaked
by earlier ones (a guest token + signed cookies, an unguessable path disclosed
by a GraphQL field, then content fetched with those cookies). This tool runs
such a chain end to end through the proxy: every step is scope-gated and
payload-safety gated, Set-Cookie is threaded forward, variables bind response
data into later requests, and a final control step proves the credential is what
defeats the check.

Accepts either a ready ``chain`` spec (see dast/chains/models.py) or free-text
``report_text`` that the LLM planner turns into one. Wraps ``dast.chains`` — the
handler stays thin per the tool-layer conventions.
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from urllib.parse import urlparse

from dast.chains.engine import ChainEngine
from dast.chains.models import Chain
from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_CHAIN_STEP_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "name": {"type": "string", "description": "Short label for this step."},
        "method": {"type": "string", "description": "HTTP method (GET/POST/...). Defaults to GET."},
        "url": {
            "type": "string",
            "description": (
                "Absolute URL. May contain {{var}} placeholders bound by an earlier step's "
                "extractor."
            ),
        },
        "headers": {
            "type": "object",
            "description": (
                "Request headers. Use {{var}} to inject an extracted value, e.g. "
                '{"authorization": "Bearer {{zenkaJwt}}"}.'
            ),
        },
        "body": {"type": "string", "description": "Request body (e.g. a JSON GraphQL query) for POST/PUT/PATCH."},
        "send_cookies": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "Cookie names to send. Omit to send the whole accumulated jar; use [] to send "
                "NO cookies (a control step that proves a token, not the cookie, grants access)."
            ),
        },
        "extract": {
            "type": "array",
            "description": "Bind values out of this step's response into variables for later steps.",
            "items": {
                "type": "object",
                "properties": {
                    "kind": {"type": "string", "description": "json | regex | set_cookie | b64json | jwt_claim"},
                    "var": {"type": "string", "description": "Variable name to bind; reference it later as {{var}}."},
                    "expr": {"type": "string", "description": "Dotted JSON path / regex / cookie name, per kind (e.g. user.attributes.zenkaJwt)."},
                    "from": {"type": "string", "description": "body (default) | header:<Name> | var:<name>"},
                },
                "required": ["kind", "var"],
            },
        },
        "assertions": {
            "type": "array",
            "description": "Conditions that must hold for this step to pass.",
            "items": {
                "type": "object",
                "properties": {
                    "kind": {
                        "type": "string",
                        "description": (
                            "status_eq | status_in | header_contains | body_contains | "
                            "body_not_contains | var_present | var_contains | var_equals"
                        ),
                    },
                    "value": {"description": "Operand for status_eq / var_equals / var_contains."},
                    "values": {"type": "array", "description": "Operand for status_in."},
                    "name": {"type": "string", "description": "Header name for header_contains."},
                    "needle": {"type": "string", "description": "Substring for *_contains."},
                    "var": {"type": "string", "description": "Variable name for var_* assertions."},
                },
                "required": ["kind"],
            },
        },
    },
    "required": ["name", "url"],
}

_VALIDATE_CHAIN_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "report_text": {
            "type": "string",
            "description": (
                "PREFERRED. A free-text description of the multi-step attack (a HackerOne report, "
                "or your own prose listing the ordered requests). The planner turns it into an "
                "executable chain, including the control step. Use this whenever you can describe "
                "the steps in words — it is far more reliable than hand-building `chain`."
            ),
        },
        "chain": {
            "type": "object",
            "description": (
                "A ready, explicit chain spec. Only use this if you already have exact steps; "
                "otherwise pass report_text and let the planner build it."
            ),
            "properties": {
                "name": {"type": "string", "description": "Short name for the chain."},
                "vuln_type": {"type": "string", "description": "Vulnerability class, e.g. broken_access_control."},
                "description": {"type": "string", "description": "One-line summary of what the chain proves."},
                "steps": {
                    "type": "array",
                    "items": _CHAIN_STEP_SCHEMA,
                    "description": (
                        "Ordered steps. A later step may reference {{var}} bound by an earlier "
                        "step's extractor (e.g. extract zenkaJwt from /spa/session, then send it "
                        "as a Bearer header to /reports/graphql)."
                    ),
                },
            },
            "required": ["steps"],
        },
    },
    "anyOf": [{"required": ["report_text"]}, {"required": ["chain"]}],
}


def _host(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


async def _make_sender(ctx: ToolContext):
    import httpx

    async def _sender(method: str, url: str, headers: Dict[str, str], body: str):
        request_body = body if method in ("POST", "PUT", "PATCH", "DELETE") else ""
        # A fresh client per request: no implicit httpx cookie jar carries state
        # between steps — the engine's explicit jar is the only cookie source, so
        # a control step that sends none really sends none.
        async with httpx.AsyncClient(
            proxy=ctx.proxy_url, verify=False, follow_redirects=False, timeout=15,
        ) as client:
            resp = await client.request(
                method, url, headers=headers or None,
                content=request_body.encode("utf-8") if request_body else None,
            )
        resp_headers: Dict[str, str] = {}
        for key, value in resp.headers.multi_items():
            if key.lower() == "set-cookie":
                existing = resp_headers.get("set-cookie", "")
                resp_headers["set-cookie"] = f"{existing}, {value}" if existing else value
            else:
                resp_headers[key] = value
        return resp.status_code, resp_headers, resp.text

    return _sender


async def _validate_chain(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    chain_spec: Optional[Dict[str, Any]] = args.get("chain")
    report_text = str(args.get("report_text", "")).strip()

    if not chain_spec and not report_text:
        return {"ok": False, "error": "provide either 'chain' or 'report_text'"}

    # Build the chain: explicit spec wins; otherwise plan from the report.
    if chain_spec:
        try:
            chain = Chain.from_dict(chain_spec)
        except Exception as exc:
            return {"ok": False, "error": f"invalid chain spec: {str(exc)[:200]}"}
    else:
        import asyncio

        from dast.chains.planner import plan_chain
        loop = asyncio.get_running_loop()
        chain = await loop.run_in_executor(None, lambda: plan_chain(report_text))
        if chain is None:
            return {"ok": False, "error": "could not plan a chain from the report (AI unavailable or no steps)"}

    if not chain.steps:
        return {"ok": False, "error": "chain has no steps"}

    # Scope gate up front over every literal host in the chain. An MCP caller
    # (no in-process store) can request an interactive per-target approval, like
    # send_request, so an out-of-scope reported target can still be validated.
    approved_hosts: set = set()
    for step in chain.steps:
        host = _host(step.url)
        if not host:
            continue  # templated host — the engine gates the rendered URL at runtime
        if ctx.is_in_scope(step.url) or host in approved_hosts:
            continue
        if ctx.store is None:
            from dast.tools import approval
            if await approval.request_approval(ctx, step.url, step.method):
                approved_hosts.add(host)
                continue
        return {"ok": False, "error": "chain target is out of scope", "url": step.url, "host": host}

    def _in_scope(url: str) -> bool:
        return ctx.is_in_scope(url) or _host(url) in approved_hosts

    sender = await _make_sender(ctx)
    engine = ChainEngine(sender=sender, is_in_scope=_in_scope)
    result = await engine.run(chain)

    return {
        "ok": True,
        "status": result.status,
        "confirmed": result.confirmed,
        "vuln_type": result.vuln_type,
        "name": result.name,
        "steps": [s.to_dict() for s in result.steps],
        "evidence": result.evidence[:4000],
    }


register(Tool(
    name="validate_chain",
    description=(
        "Validate a MULTI-STEP attack chain against the target: run an ordered sequence of "
        "requests where later steps consume data (tokens, cookies, leaked paths) bound from "
        "earlier responses, then a control step proves the credential is what defeats the "
        "check. Routes every step through the proxy, scope-gated and payload-safety gated, and "
        "returns a per-step verdict (confirmed/refuted/needs_auth/blocked).\n"
        "Use this when: a report describes a chain of requests (unauth bootstrap -> token -> "
        "privileged read -> content fetch), or single-request triage_report cannot express the "
        "dependency between steps. Pass 'report_text' to have the chain planned for you, or a "
        "ready 'chain' spec to run it verbatim.\n"
        "Do NOT use this for: a single request (use send_request); a report that reproduces in "
        "one request (use triage_report); or listing existing findings (use get_findings)."
    ),
    input_schema=_VALIDATE_CHAIN_SCHEMA,
    handler=_validate_chain,
    tags=["triage", "http"],
))
