"""session_* tools — save / list / activate authenticated sessions so the copilot
can set up multi-user (cross-tenant) testing itself.

Until now a copilot/browser login lived only in the shared ephemeral AgentBrowser and
the passive proxy jar: it was invisible to Named Sessions (multi-user IDOR) and Login
Profiles, so an AI driver could not set up the cross-session IDOR scan. These tools
close that gap with thin adapters over the existing session store and profile store.

Guardrails (see dast/tools/CLAUDE.md): scope-gate the host before acting, and NEVER
return secrets — results carry only names/roles/hosts/counts, never cookie values.

Dual data path (see dast/tools/context.py): the in-process copilot driver passes a
live ``ctx.store`` and these tools use it directly; the external MCP process has no
store, so each tool falls back to the dashboard HTTP API (``GET /api/named-sessions``,
``POST /api/profiles/quick-capture`` + ``POST /api/profiles/{slug}/activate``) so an
external AI driver can drive session setup too. (Launching the cross-session IDOR scan
itself stays in-process only, like ``run_scan`` — see ``idor_scan_tools``.)
"""

from __future__ import annotations

from typing import Any, Dict

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)


# ─────────────────────────── save_login_session ────────────────────────────

_SAVE_SCHEMA = {
    "type": "object",
    "properties": {
        "name": {"type": "string", "description": "Unique name for the session (e.g. 'tenant_a', 'admin')."},
        "host": {"type": "string", "description": "Host whose authenticated cookies to snapshot from the proxy "
                                                  "jar (e.g. app.example.com). Log in / browse it first so the jar has the session."},
        "role": {"type": "string", "description": "Privilege level / role label for cross-session comparison "
                                                  "(e.g. 'admin', 'member', 'user'). Default 'user'."},
        "username": {"type": "string", "description": "Optional login username/email. Store it (with password + "
                                                      "auth_url) so an autonomous run can AUTO-RELOGIN this identity "
                                                      "when the session expires, instead of pausing. Never echoed back."},
        "password": {"type": "string", "description": "Optional login password, stored encrypted alongside username. "
                                                      "Only used for auto-relogin; never returned in any result."},
        "auth_url": {"type": "string", "description": "Optional login page URL for auto-relogin (required together "
                                                      "with username/password for relogin to work)."},
    },
    "required": ["name", "host"],
}


def _store_profile_credentials(name: str, host: str, role: str, cookies: list,
                               auth_headers: Dict[str, str], username: str,
                               password: str, auth_url: str) -> bool:
    """Persist a credentialed login profile (encrypted) so the autonomous run can
    auto-relogin this identity on session expiry. Returns True if stored."""
    try:
        from dast.profiles.models import LoginProfile, Credential, slugify
        from dast.profiles.store import load_profile, save_profile
    except Exception as exc:
        logger.warning("save_login_session: profile store unavailable", error=str(exc)[:120])
        return False
    slug = slugify(name)
    profile = load_profile(slug) or LoginProfile(slug=slug, name=name)
    profile.name = name
    if not profile.host_pattern:
        profile.host_pattern = host
    profile.auth_url = auth_url
    profile.privilege_level = role
    profile.credentials = [Credential(label="default", username=username, secret=password)]
    state: Dict[str, Any] = {"cookies": cookies, "origins": []}
    if auth_headers:
        state["_auth_headers"] = auth_headers
    profile.saved_session = state
    import time as _time
    profile.updated_at = _time.time()
    save_profile(profile)
    logger.info("save_login_session: stored credentialed profile for auto-relogin",
                slug=slug, host=host, has_auth_url=bool(auth_url))
    return True


async def _save_via_http(ctx: ToolContext, name: str, host: str, role: str) -> Dict[str, Any]:
    """External-MCP fallback: capture the jar for the host into a login profile
    (quick-capture) and immediately activate it into a NAMED session, all over the
    dashboard HTTP API. Returns secret-free counts, mirroring the in-process path."""
    import httpx
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            cap = await client.post(
                f"{ctx.dashboard_base_url}/api/profiles/quick-capture",
                json={"name": name, "host": host, "privilege_level": role})
            if cap.status_code == 404:
                return {"ok": False, "error": f"no cookies in the proxy jar for {host} — log in / "
                                              "browse it through the proxy first, then save", "host": host}
            cap.raise_for_status()
            cap_data = cap.json()
            slug = cap_data.get("slug") or name
            captured = cap_data.get("captured", {}) or {}
            act = await client.post(f"{ctx.dashboard_base_url}/api/profiles/{slug}/activate")
            act.raise_for_status()
            act_data = act.json()
    except Exception as exc:
        return {"ok": False, "error": f"save failed: {str(exc)[:160]}", "host": host}
    logger.info("save_login_session: saved via dashboard HTTP", name=name, host=host, role=role,
                slug=slug, cookies=captured.get("cookies"))
    return {
        "ok": True, "name": act_data.get("named_session", slug), "host": host, "role": role,
        "cookies": captured.get("cookies", act_data.get("cookies_imported", 0)),
        "auth_headers": captured.get("auth_headers", 0),
        "note": "saved as a named session via the dashboard; with >=2 named sessions, "
                "run_multiuser_idor replays requests across them (run it from the in-process copilot)",
    }


async def _save_login_session(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    name = str(args.get("name", "")).strip()
    host = str(args.get("host", "")).strip().lower()
    role = str(args.get("role") or args.get("privilege_level") or "user").strip()
    if not name or not host:
        return {"ok": False, "error": "name and host are required"}
    if not ctx.is_in_scope(f"https://{host}/"):
        return {"ok": False, "error": "host is out of scope", "host": host}
    store = getattr(ctx, "store", None)
    if store is None:
        return await _save_via_http(ctx, name, host, role)
    try:
        cookies = store.get_cookies_for_host(host) or []
    except Exception as exc:
        return {"ok": False, "error": f"cookie-jar lookup failed: {str(exc)[:160]}", "host": host}
    if not cookies:
        return {"ok": False, "error": f"no cookies in the proxy jar for {host} — log in / browse it "
                                      "through the proxy first, then save", "host": host}
    auth_headers: Dict[str, str] = {}
    try:
        from dast.proxy.auth_headers import extract_auth_headers
        recent = store.entries_newest_first()[:100]
        auth_headers = extract_auth_headers(recent, host=host, exclude_sources=())
    except Exception as exc:
        logger.warning("save_login_session: auth-header extract failed", host=host, error=str(exc)[:120])
    try:
        session = store.save_named_session_from_playwright(
            name=name, role=role, playwright_cookies=cookies, auth_headers=auth_headers)
    except Exception as exc:
        return {"ok": False, "error": f"save failed: {str(exc)[:160]}"}
    logger.info("save_login_session: saved named session", name=name, host=host, role=role,
                cookies=len(session.cookies), auth_headers=len(session.auth_headers))
    # Optionally persist credentials (encrypted) so an autonomous run can auto-relogin
    # this identity on expiry instead of pausing. All three fields are required together.
    username = str(args.get("username") or "").strip()
    password = str(args.get("password") or "")
    auth_url = str(args.get("auth_url") or "").strip()
    credentials_stored = False
    if username and password and auth_url:
        credentials_stored = _store_profile_credentials(
            name, host, role, cookies, auth_headers, username, password, auth_url)
    return {
        "ok": True, "name": name, "host": host, "role": role,
        "cookies": len(session.cookies), "auth_headers": len(session.auth_headers),
        "named_sessions_total": len(store.get_named_sessions()),
        "credentials_stored": credentials_stored,
        "note": "saved as a named session; with >=2 named sessions, run_multiuser_idor will replay "
                "requests across them to find cross-account / privilege-escalation leaks"
                + ("; credentials stored for auto-relogin on expiry" if credentials_stored else ""),
    }


# ─────────────────────────── list_login_sessions ───────────────────────────

_EMPTY_SCHEMA = {"type": "object", "properties": {}}


async def _list_via_http(ctx: ToolContext) -> Dict[str, Any]:
    """External-MCP fallback: read named sessions from the dashboard. The HTTP view
    carries name/role/cookie_count (no per-host breakdown or header count)."""
    import httpx
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{ctx.dashboard_base_url}/api/named-sessions")
            resp.raise_for_status()
            data = resp.json() or []
    except Exception as exc:
        return {"ok": False, "error": f"dashboard lookup failed: {str(exc)[:160]}"}
    out = [{"name": s.get("name"), "role": s.get("role"),
            "cookies": s.get("cookie_count", 0), "hosts": []} for s in data]
    return {"ok": True, "count": len(out), "sessions": out}


async def _list_login_sessions(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    store = getattr(ctx, "store", None)
    if store is None:
        return await _list_via_http(ctx)
    try:
        sessions = store.get_named_sessions()
    except Exception as exc:
        return {"ok": False, "error": f"lookup failed: {str(exc)[:160]}"}
    out = []
    for s in sessions:
        hosts = sorted({(c.get("domain") or "").lstrip(".") for c in s.cookies.values() if c.get("domain")})
        out.append({"name": s.name, "role": s.role, "cookies": len(s.cookies),
                    "auth_headers": len(s.auth_headers), "hosts": hosts})
    return {"ok": True, "count": len(out), "sessions": out}


# ────────────────────────── activate_login_profile ─────────────────────────

_ACTIVATE_SCHEMA = {
    "type": "object",
    "properties": {
        "slug": {"type": "string", "description": "Slug of a saved login profile (from list_login_profiles) "
                                                  "to load into a named session + the live jar so scans authenticate."},
    },
    "required": ["slug"],
}


async def _activate_via_http(ctx: ToolContext, slug: str) -> Dict[str, Any]:
    """External-MCP fallback: activate a saved login profile into a named session +
    the live jar over the dashboard HTTP API."""
    import httpx
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(f"{ctx.dashboard_base_url}/api/profiles/{slug}/activate")
            if resp.status_code == 404:
                return {"ok": False, "error": f"no login profile with slug '{slug}'"}
            if resp.status_code == 400:
                return {"ok": False, "error": f"profile '{slug}' has no captured session; capture it first"}
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        return {"ok": False, "error": f"activate failed: {str(exc)[:160]}"}
    return {"ok": True, "slug": slug, "named_session": data.get("named_session", slug),
            "cookies_imported": data.get("cookies_imported", 0)}


async def _login_profile_with_credentials(ctx: ToolContext, store: Any, profile: Any) -> Dict[str, Any]:
    """Log a credential-only profile in LIVE (no captured session) via the shared adaptive_login
    cascade, then persist the session so later requests run authenticated. Mirrors the autonomous
    run's `_ensure_profile_login`. The model never receives the password. Never raises."""
    creds = getattr(profile, "credentials", None) or []
    cred = creds[0] if creds else None
    auth_url = (getattr(profile, "auth_url", "") or "").strip()
    browser = getattr(ctx, "browser", None)
    engine = getattr(ctx, "_session", None) or getattr(ctx, "session", None)
    if browser is None or cred is None or not getattr(cred, "username", "") \
            or not getattr(cred, "secret", "") or not auth_url:
        return {"ok": False, "error": (
            f"profile '{profile.slug}' has no captured session and cannot be logged in automatically "
            "(needs a browser + a username/secret + auth_url on the profile). Capture a session first.")}
    # TOTP (2FA) auto-fill — only for test accounts (the guard refuses otherwise).
    from dast.profiles.totp import may_use_totp
    totp_secret = (cred.totp_secret
                   if getattr(cred, "totp_secret", "")
                   and may_use_totp(getattr(profile, "test_account", False), cred.username)
                   else "")
    try:
        from dast.browser.login_cascade import adaptive_login
        result = await adaptive_login(
            browser, auth_url, cred.username, cred.secret,
            totp_secret=totp_secret or None,
            in_scope=getattr(ctx, "is_in_scope", None), store=store, session=engine)
    except Exception as exc:
        return {"ok": False, "error": f"login error for profile '{profile.slug}': {str(exc)[:160]}"}
    if not getattr(result, "ok", False):
        return {"ok": False, "error": (
            f"login failed for profile '{profile.slug}': {getattr(result, 'error', '') or 'unknown'}")}
    # Persist the freshly-logged-in session: named-session jar + global jar, and seed the engine so
    # the inline 401/expiry auto-relogin keeps working. Best-effort; a persist failure is logged, not fatal.
    imported = 0
    try:
        full = await browser.export_cookies_full()
    except Exception:
        full = []
    try:
        if full:
            store.save_named_session_from_playwright(
                name=profile.slug, role=profile.name, playwright_cookies=full, auth_headers={})
            imported = store.import_playwright_cookies(full)
    except Exception as exc:
        logger.warning("activate_login_profile: session persist failed", slug=profile.slug,
                       error=str(exc)[:160])
    try:
        if engine is not None:
            simple = {c["name"]: c.get("value", "") for c in full if c.get("name")}
            sc = getattr(engine, "_session_cookies", None)
            if simple and isinstance(sc, dict):
                sc.update(simple)
            engine._last_login = {"url": auth_url, "email": cred.username, "password": cred.secret}
            if totp_secret:
                engine._last_login["totp_secret"] = totp_secret
            if hasattr(engine, "session_name"):
                engine.session_name = profile.slug
    except Exception as exc:
        logger.warning("activate_login_profile: engine seed failed", slug=profile.slug, error=str(exc)[:160])
    if engine is not None and hasattr(engine, "reset_dedup"):
        engine.reset_dedup("activate_login_profile")
    logger.info("activate_login_profile: logged in from credentials", slug=profile.slug,
                cookies_imported=imported)
    return {"ok": True, "slug": profile.slug, "named_session": profile.slug, "logged_in": True,
            "privilege_level": getattr(profile, "privilege_level", "") or "",
            "cookies_imported": imported}


async def _activate_login_profile(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    slug = str(args.get("slug") or args.get("profile", "")).strip()
    if not slug:
        return {"ok": False, "error": "slug is required"}
    store = getattr(ctx, "store", None)
    if store is None:
        return await _activate_via_http(ctx, slug)
    try:
        from dast.profiles.store import load_profile
    except Exception as exc:
        return {"ok": False, "error": f"profile store unavailable: {str(exc)[:120]}"}
    profile = load_profile(slug)
    if profile is None:
        return {"ok": False, "error": f"no login profile with slug '{slug}'"}
    state = getattr(profile, "saved_session", None) or {}
    cookies = state.get("cookies") or []
    if not cookies:
        # No captured session: log the profile in LIVE from its stored credentials (the same cascade
        # the autonomous run uses), instead of erroring — so the copilot can authenticate a
        # credential-only profile by slug alone, with no password and no pre-capture.
        return await _login_profile_with_credentials(ctx, store, profile)
    try:
        store.save_named_session_from_playwright(
            name=profile.slug, role=profile.name,
            playwright_cookies=cookies, auth_headers=state.get("_auth_headers") or {})
        imported = store.import_playwright_cookies(cookies)
    except Exception as exc:
        return {"ok": False, "error": f"activate failed: {str(exc)[:160]}"}
    logger.info("activate_login_profile: activated", slug=slug, cookies_imported=imported)
    engine = getattr(ctx, "_session", None) or getattr(ctx, "session", None)
    if engine is not None:
        # Arm the expiry auto-relogin: a saved session goes stale, and without these the
        # copilot has nothing to re-authenticate with (mirrors the autonomous activation).
        creds = getattr(profile, "credentials", None) or []
        auth_url = (getattr(profile, "auth_url", "") or "").strip()
        if auth_url and creds and getattr(creds[0], "username", "") and getattr(creds[0], "secret", ""):
            engine._last_login = {"url": auth_url, "email": creds[0].username,
                                  "password": creds[0].secret}
            from dast.profiles.totp import may_use_totp
            if getattr(creds[0], "totp_secret", "") and may_use_totp(
                    getattr(profile, "test_account", False), creds[0].username):
                engine._last_login["totp_secret"] = creds[0].totp_secret
        if hasattr(engine, "reset_dedup"):
            engine.reset_dedup("activate_login_profile")
    return {"ok": True, "slug": slug, "named_session": profile.slug,
            "privilege_level": getattr(profile, "privilege_level", "") or "",
            "cookies_imported": imported}


register(Tool(
    name="save_login_session", input_schema=_SAVE_SCHEMA, handler=_save_login_session,
    tags=["session", "active"],
    description="Save the current authenticated session for a host (snapshotted from the proxy jar) "
                "as a NAMED session with a role/privilege label. Use after logging a user in through the "
                "proxy. Saving two or more different users (e.g. tenant_a and tenant_b) is the setup step "
                "for cross-account / multi-user IDOR testing via run_multiuser_idor. Returns counts only, "
                "never cookie values."))
register(Tool(
    name="list_login_sessions", input_schema=_EMPTY_SCHEMA, handler=_list_login_sessions,
    tags=["session", "read"],
    description="List the saved NAMED sessions (name, role, hosts, cookie/header counts) available for "
                "multi-user testing. Secret-free. Use to confirm you have >=2 sessions before run_multiuser_idor."))
register(Tool(
    name="activate_login_profile", input_schema=_ACTIVATE_SCHEMA, handler=_activate_login_profile,
    tags=["session", "active"],
    description="Authenticate as a login profile (by slug, from list_login_profiles): activates its "
                "captured session if it has one, otherwise LOGS IN LIVE from the profile's stored "
                "credentials (you never see the password) and saves the session. After it returns ok, "
                "subsequent scans/requests run authenticated as that profile."))
