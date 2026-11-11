"""
send_request tool — a scope-gated, payload-safety-gated HTTP sender.

Routes the request through the running proxy (so it is captured, rate-limited and
circuit-broken like every other Frieren request), enforces ``is_in_scope`` BEFORE
sending, and refuses destructive payloads (SQL writes/DDL, ``rm -rf``, shutdown,
...) in the URL or body — offering the detection-equivalent safe variant instead.
This is the repeater primitive exposed to agents and MCP clients.
"""

from __future__ import annotations

import html
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlparse

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils import read_only
from dast.utils.logger import get_logger
from dast.utils.placeholders import looks_like_placeholder

logger = get_logger(__name__)

# Reflection detection: an injected value shorter than this is too noisy to be a
# reliable reflection signal (e.g. "1", "ok"), so it is skipped.
_MIN_REFLECTION_VALUE_LEN = 4
# Caps so the reflection summary stays a compact signal, never a second body dump.
_MAX_REFLECTIONS = 6
_REFLECTION_CONTEXT_CHARS = 80


def _all_set_cookies(resp: Any) -> List[str]:
    """Every Set-Cookie value from the response and any redirect hop.

    ``dict(resp.headers)`` collapses repeated headers to a single value, hiding
    multi-cookie issuance (e.g. three CloudFront signed cookies); ``follow_redirects``
    also hides cookies set on an intermediate 3xx hop. This gathers them all.
    Tolerant of non-httpx response shapes (a plain-dict ``headers``, no ``history``)
    so the handler never raises.
    """
    cookies: List[str] = []
    hops = list(getattr(resp, "history", None) or [])
    hops.append(resp)
    for hop in hops:
        headers = getattr(hop, "headers", None)
        if headers is None:
            continue
        if hasattr(headers, "get_list"):
            cookies.extend(headers.get_list("set-cookie"))
        else:
            value = headers.get("set-cookie") if hasattr(headers, "get") else None
            if value:
                cookies.append(value)
    return cookies


def _reflection_context(text: str, needle: str) -> str:
    """A short snippet of ``text`` around the first occurrence of ``needle``."""
    idx = text.find(needle)
    if idx < 0:
        return ""
    start = max(0, idx - _REFLECTION_CONTEXT_CHARS)
    end = min(len(text), idx + len(needle) + _REFLECTION_CONTEXT_CHARS)
    return text[start:end]


def _detect_reflections(url: str, body: str, response_text: str) -> List[Dict[str, Any]]:
    """Report which request-supplied values echo back in the response body.

    The observation fed to an agent is truncated well below the full body, so a
    reflection deep in a large page is invisible to the caller. This surfaces a
    decisive, compact signal instead: for each injected value that echoes back,
    whether it reflected RAW (unencoded — the XSS-relevant case) and whether an
    HTML-escaped copy is also present, with a short context snippet.
    """
    candidates: List[tuple[str, str, str]] = []  # (location, name, value)
    for name, value in parse_qsl(urlparse(url).query, keep_blank_values=False):
        candidates.append(("query", name, value))
    for name, value in parse_qsl(body or "", keep_blank_values=False):
        candidates.append(("body", name, value))

    reflections: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for location, name, value in candidates:
        if len(value) < _MIN_REFLECTION_VALUE_LEN or value in seen:
            continue
        seen.add(value)
        raw_reflected = value in response_text
        escaped = html.escape(value, quote=True)
        escaped_reflected = escaped != value and escaped in response_text
        if not raw_reflected and not escaped_reflected:
            continue
        reflections.append({
            "parameter": name,
            "location": location,
            "reflected_raw": raw_reflected,
            "html_escaped_also_present": escaped_reflected,
            "context": _reflection_context(response_text, value if raw_reflected else escaped),
        })
        if len(reflections) >= _MAX_REFLECTIONS:
            break
    return reflections

_SEND_REQUEST_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "method": {
            "type": "string",
            "description": "HTTP method (GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS). Default GET.",
        },
        "url": {"type": "string", "description": "Absolute target URL. Must be in scope."},
        "headers": {
            "type": "object",
            "additionalProperties": {"type": "string"},
            "description": "Optional request headers.",
        },
        "body": {"type": "string", "description": "Optional request body for methods that take one."},
        "follow_redirects": {
            "type": "boolean",
            "description": (
                "Whether to follow HTTP redirects (default true). Set to false to capture "
                "the raw 302/301 response and its Location header without following it. "
                "Useful for inspecting redirect targets (e.g. OAuth authorize URLs)."
            ),
            "default": True,
        },
    },
    "required": ["url"],
}


def _destructive_reason(text: str) -> Dict[str, str] | None:
    """Return {reason, safe_variant} if the text is destructive, else None."""
    if not text:
        return None
    from dast.triage import payload_safety
    verdict = payload_safety.classify(text)
    if verdict.is_destructive:
        return {"reason": verdict.reason, "safe_variant": verdict.safe_variant or ""}
    return None


def _first_placeholder_field(url: str, headers: Dict[str, str], body: str) -> str | None:
    """Name of the first field carrying a model placeholder (e.g. ``<UNKNOWN>``), else None."""
    if looks_like_placeholder(url):
        return "url"
    for name, value in headers.items():
        if looks_like_placeholder(value):
            return f"header '{name}'"
    if looks_like_placeholder(body):
        return "body"
    return None


async def _send_request(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    url = str(args.get("url", "")).strip()
    if not url:
        return {"ok": False, "error": "url is required"}
    method = str(args.get("method", "GET")).upper()
    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
        return {"ok": False, "error": f"unsupported method: {method}"}
    if getattr(ctx, "read_only", False) and not read_only.is_safe_method(method):
        # Carve-out: GraphQL (incl. introspection) must POST, but a read-only
        # query/introspection changes nothing — allow it; still block mutations.
        if not (method == "POST" and read_only.is_read_only_graphql(url, args.get("body") or "")):
            return {"ok": False, "read_only": True,
                    "error": f"read-only mode: {method} is blocked; only GET/HEAD/OPTIONS "
                             "(and read-only GraphQL POST) are sent"}

    # Scope gate BEFORE anything is sent. Out-of-scope is denied by default, but an
    # MCP caller (no in-process store) can ask the dashboard operator for an
    # interactive per-target approval (Burp-style) — useful for validating an
    # externally-reported vuln whose target is not in the configured scan scope.
    if not ctx.is_in_scope(url):
        approved = False
        if ctx.store is None:
            from dast.tools import approval
            approved = await approval.request_approval(ctx, url, method)
        if not approved:
            return {"ok": False, "error": "url is out of scope", "url": url}

    headers = {str(k): str(v) for k, v in (args.get("headers") or {}).items()}

    # Placeholder gate: refuse model stand-in values (e.g. "<UNKNOWN>", "<jwt>") in the url,
    # a header, or the body — they are noise and can lock accounts. Run this BEFORE the auth
    # strip below so a placeholder Authorization is refused with explicit guidance, not
    # silently dropped by the always-strip step. The real value must come from
    # history/an earlier response.
    placeholder_field = _first_placeholder_field(url, headers, args.get("body") or "")
    if placeholder_field:
        logger.warning("send_request refused placeholder value", field=placeholder_field)
        return {"ok": False, "error": (
            f"refused: placeholder value in {placeholder_field} (e.g. '<UNKNOWN>'). You do not "
            "have the real value — read it from get_history or an earlier response, or ask the "
            "operator; do not invent one.")}

    # Schema contract: Authorization is ALWAYS stripped from caller-supplied headers —
    # auth is auto-injected below via the shared attach(). A non-secret garbage Authorization
    # (e.g. a model's forged alg-confusion token or a raw hash) would otherwise survive the
    # raw-secret strip, block the auto-inject, and hit the upstream as a bogus header — e.g.
    # an AWS SigV4 parse error that reads like a finding. Dropping it is attach's
    # drop_all_authorization contract (see auth_provider.attach).
    #
    # Cookies: the copilot engine marks its injected cookies trusted via
    # x-dast-cookies-injected; honor that and leave them. Otherwise strip LLM-supplied
    # cookies (often stale) and re-seed from the proxy jar. (In a separate `dast-ai mcp`
    # process ctx.store is None -> no cookie/Bearer source; use browser_fetch there.)
    trusted_cookies = headers.pop("x-dast-cookies-injected", None)
    jar_cookie_map: Dict[str, str] = {}
    if not trusted_cookies:
        headers = {k: v for k, v in headers.items() if k.lower() != "cookie"}
        if ctx.store is not None:
            _host = urlparse(url).hostname or ""
            try:
                jar_cookies = ctx.store.get_cookies_for_host(_host) or []
                jar_cookie_map = {c.get("name"): c.get("value", "")
                                  for c in jar_cookies if c.get("name")}
            except Exception as exc:
                logger.debug("send_request: cookie jar lookup failed",
                             host=_host, error=str(exc))

    # Resolve a sub-app Bearer when one is known for this (host, path), so a direct / MCP
    # caller can reach a Bearer-authed sub-app instead of a 403. Prefer the
    # session's _ensure_fresh_bearer (waits for the live SPA to mint one); the attach() below
    # sets the header and never returns the token to the caller.
    rec: Optional[Dict[str, Any]] = None
    from dast.session.auth_provider import attach as _attach
    from dast.session.auth_provider import scan_history_bearer
    parsed = urlparse(url)
    bearer_host = parsed.hostname or ""
    bearer_path = parsed.path or "/"
    session = getattr(ctx, "_session", None)
    try:
        if (session is not None and ctx.store is not None
                and hasattr(session, "_ensure_fresh_bearer")):
            rec = await session._ensure_fresh_bearer(
                ctx.store, bearer_host, bearer_path,
                browser=getattr(ctx, "browser", None))
        elif session is not None and hasattr(session, "_select_bearer"):
            if ctx.store is not None and hasattr(session, "_capture_bearer_tokens"):
                session._capture_bearer_tokens(ctx.store, bearer_host)
            rec = session._select_bearer(bearer_host, bearer_path)
        elif ctx.store is not None:
            rec = scan_history_bearer(ctx.store, bearer_host, bearer_path)
    except Exception as exc:
        logger.debug("send_request: bearer resolution failed",
                     host=bearer_host, error=str(exc))
        rec = None

    # One shared attach: drop any caller Authorization, set the jar Cookie (when not trusted)
    # + CSRF/XHR, and attach the resolved Bearer. Then drop the internal trusted marker so it
    # never leaks upstream (the proxy does not strip it).
    _res = _attach(headers, transport="api", cookies=(jar_cookie_map or None),
                   bearer_rec=rec, trusted_marker=bool(trusted_cookies),
                   drop_all_authorization=True)
    if _res.stripped:
        logger.warning("send_request stripped hand-pasted/caller auth header(s)",
                       headers=",".join(_res.stripped))
    headers.pop("x-dast-cookies-injected", None)

    body = args.get("body") or ""

    # Tag the proxy-history entry with the caller's source (e.g. "copilot") so the
    # operator can tell this traffic apart from manual browsing. The proxy reads
    # x-dast-source to label the entry and strips it before forwarding upstream.
    source_label = getattr(ctx, "source_label", None)
    if source_label and "x-dast-source" not in {k.lower() for k in headers}:
        headers["x-dast-source"] = str(source_label)

    # Payload-safety gate: refuse destructive URL/body, surfacing the safe variant.
    for where, text in (("url", url), ("body", body)):
        destructive = _destructive_reason(text)
        if destructive:
            logger.warning("send_request refused destructive payload", where=where,
                           reason=destructive["reason"])
            return {
                "ok": False,
                "error": f"refused: destructive payload in {where} ({destructive['reason']})",
                "safe_variant": destructive["safe_variant"],
                "hint": "Re-send with the safe_variant substituted; detection-only policy.",
            }

    try:
        import httpx

        follow = bool(args.get("follow_redirects", True))
        request_body = body if method in ("POST", "PUT", "PATCH", "DELETE") else ""
        async with httpx.AsyncClient(
            proxy=ctx.proxy_url, verify=False, follow_redirects=follow, timeout=15,
        ) as client:
            resp = await client.request(
                method, url, headers=headers or None,
                content=request_body.encode("utf-8") if request_body else None,
            )
        full_text = resp.text
        # dict(resp.headers) collapses repeated headers to a single value, which
        # hides multi-cookie issuance (e.g. CloudFront signed cookies set as three
        # separate Set-Cookie headers). Surface EVERY Set-Cookie value explicitly,
        # including cookies set on any redirect hop (follow_redirects is on, so those
        # would otherwise be invisible on the final response), so a caller can observe
        # and reuse them.
        set_cookies = _all_set_cookies(resp)
        history = list(getattr(resp, "history", None) or [])
        result: Dict[str, Any] = {
            "ok": True,
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body": full_text[:500_000],
            "length": len(full_text),
            "final_url": str(resp.url),
        }
        _flagged = list(dict.fromkeys(_res.stripped))
        if _flagged:
            result["note"] = (
                f"stripped caller-supplied auth header(s) ({', '.join(_flagged)}) — do not set "
                "Authorization/Cookie; auth is injected automatically "
                "(use get_bearer_token to confirm a token is cached)."
            )
        if set_cookies:
            result["set_cookies"] = set_cookies
        if history:
            result["redirects"] = [
                {"status": hop.status_code, "url": str(hop.url)} for hop in history
            ]
        # Reflection signal computed on the FULL body (before truncation) so a
        # reflected value deep in a large page is still reported to the caller.
        reflections = _detect_reflections(url, request_body, full_text)
        if reflections:
            result["reflections"] = reflections
        return result
    except Exception as exc:
        return {"ok": False, "error": f"request failed: {str(exc)[:200]}"}


_TEST_UNAUTH_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "Absolute target URL to test without authentication. Must be in scope."},
        "method": {
            "type": "string",
            "description": "HTTP method (default GET).",
            "default": "GET",
        },
        "headers": {
            "type": "object",
            "additionalProperties": {"type": "string"},
            "description": "Optional request headers. Cookie and Authorization headers are always stripped.",
        },
        "body": {"type": "string", "description": "Optional request body."},
    },
    "required": ["url"],
}

_AUTH_HEADER_NAMES = frozenset({
    "cookie", "authorization", "x-csrf-token", "x-api-key", "x-auth-token",
    "x-session-token", "x-requested-with",
})


async def _test_unauth(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    """Send a request deliberately stripped of all auth to test for missing authentication."""
    url = str(args.get("url", "")).strip()
    if not url:
        return {"ok": False, "error": "url is required"}
    if not ctx.is_in_scope(url):
        return {"ok": False, "error": "url is out of scope", "url": url}

    method = str(args.get("method", "GET")).upper()
    raw_headers = {str(k): str(v) for k, v in (args.get("headers") or {}).items()}
    headers = {k: v for k, v in raw_headers.items() if k.lower() not in _AUTH_HEADER_NAMES}
    body = args.get("body") or ""

    try:
        import httpx
        request_body = body if method in ("POST", "PUT", "PATCH", "DELETE") else ""
        # Route through the MITM proxy (like send_request / get_app_token) so the
        # unauthenticated test is RECORDED in history and inspectable — never out-of-band.
        # proxy=None (MCP/no-proxy context) degrades to a direct send, as before.
        async with httpx.AsyncClient(proxy=getattr(ctx, "proxy_url", None),
                                     verify=False, follow_redirects=False, timeout=15) as client:
            resp = await client.request(
                method, url, headers=headers or None,
                content=request_body.encode("utf-8") if request_body else None,
            )
        full_text = resp.text
        content_type = resp.headers.get("content-type", "")
        is_accessible = resp.status_code not in (301, 302, 401, 403)
        result: Dict[str, Any] = {
            "ok": True,
            "status": resp.status_code,
            "content_type": content_type,
            "body": full_text[:500000],
            "length": len(full_text),
            "is_accessible": is_accessible,
        }
        if is_accessible and resp.status_code in (200, 204):
            result["note"] = "endpoint accessible without authentication"
            logger.info("test_unauth: endpoint accessible without auth",
                        url=url, status=resp.status_code, content_type=content_type)
        return result
    except ImportError:
        try:
            import urllib.request
            import ssl
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, method=method, headers=headers)
            if body and method in ("POST", "PUT", "PATCH", "DELETE"):
                req.data = body.encode("utf-8")
            with urllib.request.urlopen(req, context=ssl_ctx, timeout=15) as resp:
                resp_body = resp.read().decode("utf-8", errors="replace")
                status = resp.status
            return {
                "ok": True, "status": status,
                "content_type": resp.headers.get("content-type", ""),
                "body": resp_body[:500000], "length": len(resp_body),
                "is_accessible": status not in (301, 302, 401, 403),
            }
        except urllib.error.HTTPError as exc:
            return {
                "ok": True, "status": exc.code,
                "content_type": exc.headers.get("content-type", ""),
                "body": "", "length": 0,
                "is_accessible": exc.code not in (301, 302, 401, 403),
            }
        except Exception as exc:
            return {"ok": False, "error": f"request failed (urllib fallback): {str(exc)[:200]}"}
    except Exception as exc:
        return {"ok": False, "error": f"request failed: {str(exc)[:200]}"}


register(Tool(
    name="test_unauth",
    description=(
        "Send a request WITHOUT any cookies or auth headers to test if an endpoint "
        "requires authentication. All Cookie, Authorization, X-CSRF-Token, and similar "
        "auth headers are deliberately stripped. The request goes DIRECTLY to the target "
        "(not through the proxy) to avoid automatic cookie injection from the jar. "
        "Use this to detect unauthenticated access vulnerabilities: if status is 200 or "
        "204, the endpoint may be missing authentication. Returns is_accessible=true when "
        "the status is not 301/302/401/403."
    ),
    input_schema=_TEST_UNAUTH_SCHEMA,
    handler=_test_unauth,
    tags=["http", "active"],
))

register(Tool(
    name="send_request",
    description=(
        "Send a single HTTP request through the Frieren proxy and return the response "
        "(status, headers, body). This is the repeater primitive: it routes through the "
        "proxy so the request is captured, rate-limited and circuit-broken, enforces scope, "
        "and refuses destructive payloads (offering a safe detection-only variant). Every "
        "Set-Cookie the server issued is returned as the 'set_cookies' list (including cookies "
        "set on any redirect hop) -- read that, not 'headers', to observe issued cookies, since "
        "'headers' collapses repeated Set-Cookie to one value.\n"
        "Set follow_redirects=false to capture a raw 302/301 response and its Location header "
        "without following the redirect chain. This is useful when you need to inspect redirect "
        "targets (e.g. OAuth /authorize URLs with acr_values or prompt parameters).\n"
        "Auth is injected automatically when you do not supply it: session cookies + CSRF/XHR "
        "headers from the jar, and a cached sub-app Bearer selected by request "
        "path when one is known. If a request still 401/403s after that (e.g. an SPA whose token "
        "lives only in in-memory JS state), it is automatically re-issued via the browser session, "
        "which carries that token — you do not need to switch tools by hand.\n"
        "Use this when: reproducing or probing a specific endpoint, testing whether a "
        "payload reflects/changes behavior, replaying a captured request with a tweak, or "
        "delivering an SSRF/XXE payload that embeds an OOB URL from oob_generate.\n"
        "Do NOT use this to: read requests you already captured (use get_history); "
        "enumerate unknown paths (use content_discovery) or hidden params (use param_mining); "
        "encode a value before sending (use the url_/base64_/html_ encode tools); or run a "
        "destructive write — it will be refused."
    ),
    input_schema=_SEND_REQUEST_SCHEMA,
    handler=_send_request,
    tags=["http"],
))


_GET_BEARER_TOKEN_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "host": {
            "type": "string",
            "description": "Target API host (e.g. 'api.internal.example.com'). "
                           "If omitted, returns tokens for all hosts.",
        },
    },
    "required": [],
}


async def _get_bearer_token(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    host = str(args.get("host", "")).strip().lower()
    bearer_tokens: Dict[str, Any] = getattr(ctx, "bearer_tokens", {})
    import time as _time
    now = _time.time()

    if host:
        cached = bearer_tokens.get(host)
        if cached is None and ctx.store:
            try:
                from dast.ai.copilot.session import CopilotSession
                session = getattr(ctx, "_session", None) or getattr(ctx, "session", None)
                if session and hasattr(session, "_capture_bearer_tokens"):
                    session._capture_bearer_tokens(ctx.store, host)
                    bearer_tokens = getattr(ctx, "bearer_tokens", {})
                    cached = bearer_tokens.get(host)
            except Exception:
                pass
        if cached:
            exp = cached.get("exp")
            expired = exp is not None and exp < now
            return {
                "ok": True,
                "host": host,
                "token_preview": cached["token"][:20] + "...",
                "status": "expired" if expired else "valid",
                "expires_in": int(exp - now) if exp else None,
                "age_seconds": int(now - cached.get("captured_at", now)),
                "auth_endpoint": cached.get("auth_endpoint"),
            }
        if ctx.store:
            try:
                entries = ctx.store.all_entries()
                for entry in reversed(entries):
                    entry_host = (entry.get("host") or "").lower()
                    if entry_host != host:
                        continue
                    req_h = entry.get("request_headers") or {}
                    for k, v in req_h.items():
                        if k.lower() == "authorization" and str(v).startswith("Bearer "):
                            token_val = str(v)[7:].strip()
                            from dast.ai.copilot.session import CopilotSession
                            exp = CopilotSession._decode_jwt_exp(token_val)
                            expired = exp is not None and exp < now
                            return {
                                "ok": True,
                                "host": host,
                                "source": "proxy_history",
                                "token_preview": token_val[:20] + "...",
                                "status": "expired" if expired else "valid",
                                "expires_in": int(exp - now) if exp else None,
                                "entry_id": entry.get("id", ""),
                            }
            except Exception:
                pass
        return {"ok": False, "error": f"No Bearer token found for {host}. "
                "Use browser_login first, then navigate to a page that triggers API calls."}

    if bearer_tokens:
        result = {"ok": True, "tokens": {}}
        for h, cached in bearer_tokens.items():
            exp = cached.get("exp")
            expired = exp is not None and exp < now
            result["tokens"][h] = {
                "status": "expired" if expired else "valid",
                "expires_in": int(exp - now) if exp else None,
                "auth_endpoint": cached.get("auth_endpoint"),
            }
        return result
    return {"ok": False, "error": "No Bearer tokens cached. Use browser_login first."}


register(Tool(
    name="get_bearer_token",
    description=(
        "Look up the current Bearer/JWT token for an API host. Returns the token "
        "status (valid/expired/missing), expiry, and the endpoint that issued it. "
        "Use after browser_login when you need to verify token availability or when "
        "send_request returns 401 on a Bearer-authenticated API."
    ),
    input_schema=_GET_BEARER_TOKEN_SCHEMA,
    handler=_get_bearer_token,
    tags=["auth"],
))
