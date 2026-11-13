"""
sqli_probe tool — deterministic, LLM-free SQL-injection probe (a mini sqlmap).

Confirming a SQL injection is a fixed differential: send a syntax-breaking payload and look for a
DBMS error (or a boolean/time differential), then read back a read-only ``version()`` to prove
impact. None of that needs a language model — so this tool runs the whole thing itself from the
static ``sqli.yaml`` seeds and the existing ``sqli_exploit.extract_db_facts`` engine. That makes
SQLi validation immune to the gateway's content-safety refusals that block the LLM payload
generator: the copilot (or the SQL VulnAgent) can call this directly when the model path won't
produce payloads.

Auth is self-contained (cookies from the proxy jar, same source send_request uses) and every
request is routed through the proxy so each step lands in history, in-scope. Payloads are
detection-only (error/boolean/time ≤ the YAML sleep ceiling) — no stacked writes, no data change.
Supports a plain query/body parameter OR a GraphQL variable (e.g. a string field in a mutation).
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from dast.agents.sqli_exploit import extract_db_facts
from dast.graphql.variable_fuzzer import _has_graphql_errors, _inject
from dast.payloads.loader import get_payloads, get_signatures, get_value
from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")
_LOCATIONS = ("graphql_var", "query", "body")


def _error_re() -> "re.Pattern":
    """Compile the canonical SQL-error signature set from sqli.yaml. The signatures are regex
    fragments (e.g. ``sql syntax.*near``), joined UNescaped — same as sqli_agent._build_error_re."""
    sigs = get_signatures("sqli", "error_signatures") or []
    if not sigs:
        return re.compile(r"(?!x)x")  # matches nothing
    return re.compile("|".join(sigs), re.IGNORECASE)


_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "Target URL (must be in scope). For GraphQL, the "
                "graphql endpoint, e.g. https://host/reports/graphql/."},
        "method": {"type": "string", "description": "HTTP method (default POST)."},
        "injection_point": {"type": "string", "description": "Name of the parameter / GraphQL "
                            "variable to inject into, e.g. 'title' or 'id'."},
        "injection_location": {"type": "string", "description": "Where the parameter lives: "
                               "'graphql_var' (a GraphQL variable), 'query' (URL query string), or "
                               "'body' (JSON/form body). Default 'graphql_var'."},
        "body": {"type": "string", "description": "Request body template. For graphql_var a JSON "
                 "{query, variables, operationName}. If omitted for graphql_var, the most recent "
                 "captured operation for this URL is used."},
        "content_type": {"type": "string", "description": "Content-Type for the request (default "
                         "application/json)."},
        "record": {"type": "boolean", "description": "Record a finding when CONFIRMED (default true)."},
        "title": {"type": "string", "description": "Finding title (optional; a sensible default is used)."},
        "severity": {"type": "string", "description": "critical|high|medium|low|info (default high)."},
        "cwe": {"type": "string", "description": "CWE id (default CWE-89)."},
    },
    "required": ["url", "injection_point"],
}


async def _resolve_auth(ctx: ToolContext, url: str, method: str) -> Dict[str, Any]:
    """Resolve the SAME auth send_request uses, so the probe can reach a Bearer-authed sub-app
    (e.g. a reports GraphQL endpoint) instead of 403ing with jar cookies alone: jar cookies + the
    sub-app Bearer (from the engine's /spa/session) + a CSRF token from history. Resolved ONCE
    (host/path are constant across payloads); applied per request via auth_provider.attach.
    Never raises."""
    store = getattr(ctx, "store", None)
    parsed = urlparse(url)
    host, path = parsed.hostname or "", parsed.path or "/"
    jar_cookie_map: Dict[str, str] = {}
    if store is not None:
        try:
            jar = store.get_cookies_for_host(host) or []
            jar_cookie_map = {c.get("name"): c.get("value", "") for c in jar if c.get("name")}
        except Exception as exc:
            logger.debug("sqli_probe: cookie jar lookup failed", host=host, error=str(exc))
    rec = None
    session = getattr(ctx, "_session", None)
    try:
        from dast.session.auth_provider import scan_history_bearer
        if session is not None and store is not None and hasattr(session, "_ensure_fresh_bearer"):
            rec = await session._ensure_fresh_bearer(
                store, host, path, browser=getattr(ctx, "browser", None))
        elif store is not None:
            rec = scan_history_bearer(store, host, path)
    except Exception as exc:
        logger.debug("sqli_probe: bearer resolution failed", host=host, error=str(exc))
    csrf_token = None
    if store is not None and method in ("POST", "PUT", "PATCH", "DELETE"):
        try:
            from dast.session.auth_provider import scan_history_csrf
            csrf_token = scan_history_csrf(store, host, exclude_source="copilot")
        except Exception as exc:
            logger.debug("sqli_probe: csrf resolution failed", host=host, error=str(exc))
    return {"cookies": jar_cookie_map or None, "bearer_rec": rec, "csrf_token": csrf_token}


def _resolve_graphql_body(ctx: ToolContext, url: str, given_body: str) -> Optional[dict]:
    """Return the GraphQL request body dict: the caller-supplied one, else the most recent
    captured operation for this URL from history."""
    if given_body.strip():
        try:
            data = json.loads(given_body)
            if isinstance(data, dict) and data.get("query"):
                return data
        except Exception:
            return None
    store = getattr(ctx, "store", None)
    if store is None:
        return None
    try:
        from dast.tools.graphql_fuzz_tools import _captured_operations
        ops = _captured_operations(store, url)
    except Exception as exc:
        logger.warning("sqli_probe: captured-op lookup failed", error=str(exc))
        return None
    if not ops:
        return None
    # ops entries are (op_key, body_dict, auth_headers); take the first.
    return ops[0][1] if isinstance(ops[0][1], dict) else None


def _set_query_param(url: str, param: str, value: str) -> str:
    parts = urlparse(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q[param] = value
    return urlunparse(parts._replace(query=urlencode(q)))


async def _sqli_probe(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    url = str(args.get("url", "")).strip()
    point = str(args.get("injection_point", "")).strip()
    location = str(args.get("injection_location", "graphql_var")).strip().lower() or "graphql_var"
    method = str(args.get("method", "POST")).strip().upper() or "POST"
    content_type = str(args.get("content_type", "application/json")).strip() or "application/json"
    if not url or not point:
        return {"ok": False, "error": "url and injection_point are required"}
    if location not in _LOCATIONS:
        return {"ok": False, "error": f"injection_location must be one of {_LOCATIONS}"}
    if not ctx.is_in_scope(url):
        return {"ok": False, "error": "url is out of scope", "url": url}

    gql_body: Optional[dict] = None
    if location == "graphql_var":
        gql_body = _resolve_graphql_body(ctx, url, str(args.get("body", "")))
        if gql_body is None:
            return {"ok": False, "error": "no GraphQL body given and none captured for this URL — "
                    "pass 'body' as {query, variables, operationName} JSON"}

    source_label = getattr(ctx, "source_label", None)
    # Resolve cookies + sub-app Bearer + CSRF once (same machinery as send_request), applied to
    # each request via attach so a Bearer-authed sub-app (e.g. /reports/graphql) is reachable.
    from dast.session.auth_provider import attach as _attach
    auth = await _resolve_auth(ctx, url, method)

    def _headers() -> Dict[str, str]:
        # X-Requested-With explicitly: some SPA sub-apps require it even when auth is a Bearer with
        # no CSRF (attach only sets it alongside a CSRF token).
        h: Dict[str, str] = {"content-type": content_type, "X-Requested-With": "XMLHttpRequest"}
        if source_label:
            h["x-dast-source"] = str(source_label)
        _attach(h, transport="api", cookies=auth["cookies"], bearer_rec=auth["bearer_rec"],
                csrf_token=auth["csrf_token"], drop_all_authorization=True)
        return h

    import httpx

    time_threshold_ms = float(get_value("sqli", "time_threshold_ms", 4500) or 4500)

    async def _send_value(client: "httpx.AsyncClient", value: str) -> Optional["httpx.Response"]:
        """Inject ``value`` at the chosen point and send through the proxy. Returns the response."""
        try:
            if location == "graphql_var":
                injected = _inject(gql_body, point, value)
                return await client.request(method, url, headers=_headers(),
                                            content=json.dumps(injected).encode("utf-8"))
            if location == "query":
                return await client.request(method, _set_query_param(url, point, value),
                                            headers=_headers())
            # body: JSON object field
            body_obj = {point: value}
            return await client.request(method, url, headers=_headers(),
                                        content=json.dumps(body_obj).encode("utf-8"))
        except Exception as exc:
            logger.debug("sqli_probe: send failed", error=str(exc)[:160])
            return None

    err_re = _error_re()
    steps: List[Dict[str, Any]] = []
    confirmed = False
    technique = ""
    confirming_payload = ""
    evidence_snippet = ""

    try:
        async with httpx.AsyncClient(proxy=ctx.proxy_url, verify=False,
                                     follow_redirects=False, timeout=30) as client:
            # Baseline (benign value) — to tell a NEW sql error / graphql error from a pre-existing one.
            base = await _send_value(client, "sqli_probe_baseline")
            base_text = base.text if base is not None else ""
            base_sql_err = bool(err_re.search(base_text))
            base_gql_err = _has_graphql_errors(base_text)
            steps.append({"label": "baseline", "status": getattr(base, "status_code", None),
                          "sql_error": base_sql_err, "graphql_error": base_gql_err})

            # Error-based: a syntax-breaking payload that yields a NEW SQL error is the strong signal.
            for payload in get_payloads("sqli", "error_based"):
                resp = await _send_value(client, payload)
                if resp is None:
                    continue
                text = resp.text
                new_sql_err = bool(err_re.search(text)) and not base_sql_err
                new_gql_err = _has_graphql_errors(text) and not base_gql_err
                if new_sql_err or new_gql_err:
                    confirmed = True
                    technique = "error-based"
                    confirming_payload = payload
                    m = err_re.search(text)
                    evidence_snippet = (m.group(0) if m else text)[:300]
                    steps.append({"label": "error-based hit", "payload": payload,
                                  "status": resp.status_code,
                                  "sql_error": new_sql_err, "graphql_error": new_gql_err,
                                  "snippet": evidence_snippet})
                    break
                steps.append({"label": "error-based miss", "payload": payload,
                              "status": resp.status_code})

            # Time-based fallback only if error-based did not confirm.
            if not confirmed:
                for payload in get_payloads("sqli", "time_based"):
                    t0 = time.monotonic()
                    resp = await _send_value(client, payload)
                    elapsed_ms = (time.monotonic() - t0) * 1000.0
                    if resp is None:
                        continue
                    if elapsed_ms >= time_threshold_ms:
                        confirmed = True
                        technique = "time-based"
                        confirming_payload = payload
                        evidence_snippet = f"response delayed {elapsed_ms:.0f}ms (>= {time_threshold_ms:.0f}ms)"
                        steps.append({"label": "time-based hit", "payload": payload,
                                      "elapsed_ms": round(elapsed_ms), "status": resp.status_code})
                        break
                    steps.append({"label": "time-based miss", "payload": payload,
                                  "elapsed_ms": round(elapsed_ms)})

            # Impact proof: best-effort read-only version()/db/user extraction (error-based only).
            facts: Dict[str, str] = {}
            proof_summary = ""
            if confirmed and technique == "error-based":
                async def _send(value: str) -> Optional["httpx.Response"]:
                    return await _send_value(client, value)
                try:
                    proof = await extract_db_facts(_send, confirming_payload, dbms_hints=None)
                except Exception as exc:
                    proof = None
                    logger.debug("sqli_probe: extraction failed", error=str(exc)[:160])
                if proof is not None:
                    facts = dict(proof.facts)
                    proof_summary = proof.summary()
                    steps.append({"label": "impact proof", "technique": proof.technique,
                                  "dbms": proof.dbms, "facts": facts})
    except Exception as exc:
        return {"ok": False, "error": f"probe failed: {str(exc)[:200]}", "steps": steps}

    if confirmed:
        verdict = (f"CONFIRMED — {technique} SQL injection in '{point}' ({location}). "
                   f"Payload {confirming_payload!r} produced: {evidence_snippet}."
                   + (f" Read-only proof: {proof_summary}." if proof_summary else ""))
    else:
        verdict = (f"NOT CONFIRMED — no SQL error differential or timing delay for '{point}' "
                   f"({location}).")

    result: Dict[str, Any] = {"ok": True, "confirmed": confirmed, "verdict": verdict,
                              "technique": technique, "facts": facts if confirmed else {},
                              "steps": steps}

    if confirmed and bool(args.get("record", True)) and getattr(ctx, "store", None) is not None:
        severity = str(args.get("severity", "high")).strip().lower()
        if severity not in _VALID_SEVERITIES:
            severity = "high"
        finding = {
            "title": str(args.get("title", "")).strip()
            or f"SQL injection in '{point}' ({technique})",
            "severity": severity,
            "attack_type": "sqli",
            "cwe": str(args.get("cwe", "CWE-89")).strip() or "CWE-89",
            "parameter": point,
            "evidence": verdict,
            "steps": steps,
            "extracted_data": facts,
            "confirmed": True,
            "confidence": 1.0,
            "validated_by": ["sqli_probe"],
            "source": "copilot",
        }
        try:
            entry_id = ctx.store.record_manual_finding(finding, url, method)
            result["recorded_entry_id"] = entry_id
            logger.info("sqli_probe recorded finding", entry_id=entry_id, severity=severity,
                        technique=technique)
        except Exception as exc:
            result["record_error"] = str(exc)[:200]

    return result


register(Tool(
    name="sqli_probe",
    description=(
        "Deterministically probe ONE parameter or GraphQL variable for SQL injection — no LLM, so "
        "the gateway's content-safety filter cannot block it. Sends static error-based then "
        "time-based payloads, detects a NEW SQL-error / GraphQL-error differential or a timing "
        "delay vs a baseline, and on a hit extracts a read-only version()/database()/user() proof. "
        "Records a CONFIRMED finding with the full step chain + extracted facts as evidence. "
        "injection_location: 'graphql_var' (inject into a GraphQL variable; the "
        "captured operation body is reused if you don't pass one), 'query', or 'body'. Cookies come "
        "from the proxy jar automatically; everything routes through the proxy. "
        "Use this to validate a suspected SQLi reliably, or when the LLM payload path refuses."
    ),
    input_schema=_SCHEMA,
    handler=_sqli_probe,
    tags=["active", "write"],
))
