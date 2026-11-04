"""app_knowledge tools — resolve a sub-app Bearer from /spa/session and record learned
app facts into the local per-host knowledge store.

``get_app_token`` fixes a concrete blocker: the real per-app tokens live in the (large)
``GET /spa/session`` JSON under ``user.attributes.<app>Jwt``, but the copilot's observation
body is truncated (~900 chars) so it could not read past the first token. This tool extracts
the named field server-side (untruncated), decodes its entitlement claims, primes it against
the sub-app (so the engine can borrow the Authorization header on later calls), and returns the
entitlement flags — never the raw token.

``record_app_knowledge`` appends a learned fact to ~/.dast-ai/app_knowledge/<host>.md.
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import httpx

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# app → (field in user.attributes, a probe endpoint path to prime + prove the token)
_APP_MAP: Dict[str, Dict[str, str]] = {
    "modstore": {"field": "modstoreJwt", "probe": "/modstore/graphql"},
    "ccm": {"field": "ccmJwt", "probe": "/customercontent/graphql"},
    "search": {"field": "searchJwt", "probe": ""},
    "zenka": {"field": "zenkaJwt", "probe": ""},
}


def _host_of(value: str) -> str:
    v = (value or "").strip()
    if "://" in v:
        return (urlparse(v).hostname or "").lower()
    return v.split("/", 1)[0].split(":", 1)[0].lower()


def _cookie_header(ctx: ToolContext, host: str) -> str:
    """Build a Cookie header for host from the jar + the engine session's cookies."""
    pairs: Dict[str, str] = {}
    store = getattr(ctx, "store", None)
    if store is not None:
        try:
            for c in store.get_cookies_for_host(host) or []:
                if c.get("name"):
                    pairs[c["name"]] = c.get("value", "")
        except Exception:
            pass
    sess = getattr(ctx, "_session", None) or getattr(ctx, "session", None)
    sc = getattr(sess, "_session_cookies", None)
    if isinstance(sc, dict):
        pairs.update(sc)
    return "; ".join(f"{k}={v}" for k, v in pairs.items() if k)


def _decode_jwt_account(token: str) -> Dict[str, Any]:
    """Decode a JWT payload (no verify) and return the account/entitlement claims."""
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    except (IndexError, ValueError, binascii.Error, json.JSONDecodeError):
        return {}
    acct = payload.get("account") if isinstance(payload.get("account"), dict) else {}
    return {
        "account_id": acct.get("id", payload.get("account_id")),
        "entitlements": {
            "ai_translations_active": acct.get("ai_translations_active"),
            "can_download_modules": acct.get("can_download_modules"),
            "can_preview_content": acct.get("can_preview_content"),
            "subscription_level": acct.get("subscription_level"),
        },
        "exp": payload.get("exp"),
    }


async def _get_app_token(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    host = _host_of(str(args.get("host", "")))
    app = str(args.get("app", "")).strip().lower()
    if not host:
        return {"ok": False, "error": "host is required"}
    if app not in _APP_MAP:
        return {"ok": False, "error": f"app must be one of {sorted(_APP_MAP)}"}
    session_url = f"https://{host}/spa/session"
    if not ctx.is_in_scope(session_url):
        return {"ok": False, "error": "host is out of scope", "host": host}

    field = _APP_MAP[app]["field"]
    probe_path = _APP_MAP[app]["probe"]
    cookie = _cookie_header(ctx, host)
    try:
        async with httpx.AsyncClient(proxy=ctx.proxy_url, verify=False,
                                     follow_redirects=True, timeout=15) as client:
            resp = await client.get(session_url, headers={
                "Cookie": cookie, "X-Requested-With": "XMLHttpRequest",
                "Accept": "application/json",
            })
            data = resp.json()
    except Exception as exc:
        return {"ok": False, "error": f"could not fetch /spa/session: {str(exc)[:160]}"}

    attrs = ((data.get("user") or {}).get("attributes") or {}) if isinstance(data, dict) else {}
    token = attrs.get(field) or ((data.get("guest") or {}).get(field) if isinstance(data, dict) else None)
    if not token:
        available = sorted(k for k in attrs if k.endswith("Jwt"))
        return {"ok": False, "error": f"no user.attributes.{field} in /spa/session",
                "available_tokens": available, "host": host}

    claims = _decode_jwt_account(token)

    # Cache onto the engine so the inline bearer-refresh path can use it.
    sess = getattr(ctx, "_session", None) or getattr(ctx, "session", None)
    cache = getattr(sess, "_bearer_tokens", None)
    if isinstance(cache, dict):
        cache[host] = {"token": token, "source_entry_id": "app_token_resolver",
                       "auth_endpoint": probe_path or None, "exp": claims.get("exp")}

    # Prime: one authed probe so the token lands in proxy history → the engine's
    # _apply_session_auth borrows the Authorization header on later copilot calls.
    probe_status: Optional[int] = None
    if probe_path:
        try:
            async with httpx.AsyncClient(proxy=ctx.proxy_url, verify=False,
                                         follow_redirects=False, timeout=15) as client:
                pr = await client.post(f"https://{host}{probe_path}", headers={
                    "Authorization": f"Bearer {token}", "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/json", "x-dast-source": "copilot",
                }, content=json.dumps({"query": "{ __typename }"}))
                probe_status = pr.status_code
        except Exception as exc:
            logger.debug("app token prime probe failed", host=host, error=str(exc)[:160])

    return {
        "ok": True, "app": app, "host": host,
        "account_id": claims.get("account_id"),
        "entitlements": claims.get("entitlements", {}),
        "token_preview": token[:12] + "...",
        "probe_endpoint": probe_path or None,
        "probe_status": probe_status,
        "note": ("token cached + primed; subsequent same-host requests carry it. "
                 "Check entitlements before testing flag-gated findings."),
    }


async def _record_app_knowledge(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    host = _host_of(str(args.get("host", "")))
    note = str(args.get("note", "")).strip()
    if not host:
        return {"ok": False, "error": "host is required"}
    if not note:
        return {"ok": False, "error": "note is required"}
    if not ctx.is_in_scope(f"https://{host}/"):
        return {"ok": False, "error": "host is out of scope", "host": host}
    try:
        from dast.app_knowledge.store import append_note
        written = append_note(host, note)
    except Exception as exc:
        return {"ok": False, "error": f"could not save app knowledge: {str(exc)[:160]}"}
    if not written:
        return {"ok": False, "error": "could not save app knowledge"}
    return {"ok": True, "host": written, "note_len": len(note)}


register(Tool(
    name="get_app_token",
    input_schema={
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Target host (e.g. training.knowbe4.com)."},
            "app": {"type": "string",
                    "description": "Which sub-app token to resolve: modstore | ccm | search | zenka."},
        },
        "required": ["host", "app"],
    },
    handler=_get_app_token,
    tags=["auth"],
    description="Resolve a sub-app Bearer token from GET /spa/session (user.attributes.<app>Jwt), "
                "untruncated, when a sub-app (modstore/ccm) returns not_authorized/403 because the "
                "session cookie alone is not enough. Decodes and returns the account id + entitlement "
                "flags (ai_translations_active, can_download_modules, ...), caches the token and primes "
                "it so later same-host requests carry it. Never returns the raw token. Use this BEFORE "
                "testing a flag-gated finding to confirm the account actually has the entitlement.",
))

register(Tool(
    name="record_app_knowledge",
    input_schema={
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Host the fact is about (e.g. training.knowbe4.com)."},
            "note": {"type": "string", "description": "A concise learned fact about the app (auth model, "
                     "token location, endpoint, entitlement). Do NOT include secret values."},
        },
        "required": ["host", "note"],
    },
    handler=_record_app_knowledge,
    tags=["util"],
    description="Append a learned fact about the target app to the local per-host knowledge store "
                "(~/.dast-ai/app_knowledge/<host>.md, never committed), so future runs start informed. "
                "Record auth model, where tokens live, endpoint behavior, entitlement requirements — "
                "never secret values.",
))
