"""
Login-profile routes — manage encrypted per-site login profiles (Discovery > Logins).

  GET    /api/profiles                          list profiles (redacted — no secrets)
  GET    /api/profiles/{slug}                   one profile (redacted)
  POST   /api/profiles                          create/update a profile
  DELETE /api/profiles/{slug}                   delete a profile
  POST   /api/profiles/{slug}/session-import    import an active session (no login)
  POST   /api/profiles/{slug}/activate          load the saved session into the live store
  POST   /api/profiles/{slug}/capture-from-proxy  snapshot live proxy jar into the profile
  POST   /api/profiles/quick-capture            create profile + capture session in one step

Secrets are never returned by any route — only ``*_set`` booleans (mirrors the
key-masking convention of GET /api/scan-config). All persistence goes through
dast.profiles.store; encryption is handled there.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from dast.profiles import crypto, session_import
from dast.profiles.models import Credential, LoginProfile, slugify
from dast.profiles.store import (
    delete_profile,
    list_profiles,
    load_profile,
    save_profile,
)
from dast.proxy.api.context import DashboardContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)


class CredentialIn(BaseModel):
    label: str = "default"
    username: str = ""
    secret: Optional[str] = None  # None = leave existing secret unchanged on update


class ProfileIn(BaseModel):
    slug: Optional[str] = None
    name: str
    host_pattern: str = ""
    auth_url: str = ""
    credentials: List[CredentialIn] = []
    selector_overrides: Dict[str, str] = {}
    privilege_level: str = ""


class SessionImportIn(BaseModel):
    target_url: str = ""
    storage_state_json: str = ""
    cookie_header: str = ""
    auth_token: str = ""


class QuickCaptureIn(BaseModel):
    name: str
    host: str
    privilege_level: str = ""


class CaptureFromProxyIn(BaseModel):
    host: str = ""  # optional override; derived from host_pattern if omitted


def _merge_credentials(
    incoming: List[CredentialIn], existing: List[Credential]
) -> List[Credential]:
    """Build the credential list, preserving a secret when the client omits it.

    A credential's secret is only overwritten when the request supplies a non-None
    ``secret``; sending null/omitting keeps the previously stored secret (so the UI
    can round-trip a redacted profile without wiping passwords).
    """
    by_label = {c.label: c for c in existing}
    merged: List[Credential] = []
    for c in incoming:
        prior = by_label.get(c.label)
        secret = c.secret if c.secret is not None else (prior.secret if prior else "")
        merged.append(Credential(label=c.label, username=c.username, secret=secret or ""))
    return merged


def make_router(ctx: DashboardContext) -> APIRouter:
    router = APIRouter()

    @router.get("/api/profiles")
    async def list_all() -> dict:
        return {
            "crypto_available": crypto.is_available(),
            "profiles": [p.to_public_dict() for p in list_profiles()],
        }

    @router.get("/api/profiles/detected-hosts")
    async def detected_hosts() -> dict:
        """Return hosts that currently have cookies in the proxy jar.
        Used by Quick Capture to surface sessions the operator has already browsed."""
        if ctx.store is None:
            return {"hosts": []}
        try:
            hosts = ctx.store.get_cookie_hosts()
        except Exception as exc:
            logger.warning("detected-hosts: store lookup failed", error=str(exc))
            return {"hosts": []}
        return {"hosts": sorted(hosts)}

    @router.get("/api/profiles/{slug}")
    async def get_one(slug: str) -> dict:
        profile = load_profile(slug)
        if profile is None:
            return JSONResponse({"error": "profile not found"}, status_code=404)
        return profile.to_public_dict()

    @router.post("/api/profiles")
    async def create_or_update(req: ProfileIn) -> dict:
        if not req.name.strip():
            return JSONResponse({"error": "name is required"}, status_code=400)
        slug = req.slug or slugify(req.name)
        existing = load_profile(slug)
        profile = existing or LoginProfile(slug=slug, name=req.name)
        profile.name = req.name
        profile.host_pattern = req.host_pattern
        profile.auth_url = req.auth_url
        profile.selector_overrides = dict(req.selector_overrides)
        profile.credentials = _merge_credentials(
            req.credentials, existing.credentials if existing else []
        )
        profile.privilege_level = req.privilege_level
        try:
            save_profile(profile)
        except Exception as exc:
            logger.error("profile save failed", slug=slug, error=str(exc))
            return JSONResponse({"error": f"save failed: {exc}"}, status_code=500)
        return profile.to_public_dict()

    @router.delete("/api/profiles/{slug}")
    async def remove(slug: str) -> dict:
        return {"deleted": delete_profile(slug)}

    @router.post("/api/profiles/{slug}/session-import")
    async def import_session(slug: str, req: SessionImportIn) -> dict:
        profile = load_profile(slug)
        if profile is None:
            return JSONResponse({"error": "profile not found"}, status_code=404)
        imported = session_import.build_session(
            target_url=req.target_url or profile.auth_url,
            storage_state_json=req.storage_state_json,
            cookie_header=req.cookie_header,
            auth_token=req.auth_token,
        )
        if imported.is_empty:
            return JSONResponse(
                {"error": "no cookies or auth token found in the supplied session"},
                status_code=400,
            )
        # Fold auth headers into the stored storage_state origins so activate can
        # reapply them; keep the session on the profile (encrypted at rest).
        state: Dict[str, Any] = dict(imported.storage_state)
        if imported.auth_headers:
            state["_auth_headers"] = imported.auth_headers
        profile.saved_session = state
        save_profile(profile)
        logger.info("session imported to profile", slug=slug, cookies=len(imported.cookies))
        return profile.to_public_dict()

    @router.post("/api/profiles/{slug}/activate")
    async def activate(slug: str) -> dict:
        profile = load_profile(slug)
        if profile is None:
            return JSONResponse({"error": "profile not found"}, status_code=404)
        if not profile.saved_session:
            return JSONResponse(
                {"error": "profile has no saved session; import or record one first"},
                status_code=400,
            )
        cookies = list(profile.saved_session.get("cookies", []))
        auth_headers = dict(profile.saved_session.get("_auth_headers", {}))
        ctx.store.save_named_session_from_playwright(
            name=profile.slug, role=profile.name, playwright_cookies=cookies,
            auth_headers=auth_headers,
        )
        imported = ctx.store.import_playwright_cookies(cookies)
        logger.info("login profile activated", slug=slug, cookies=imported)
        return {"activated": True, "cookies_imported": imported, "named_session": profile.slug}

    @router.post("/api/profiles/{slug}/capture-from-proxy")
    async def capture_from_proxy(slug: str, req: CaptureFromProxyIn) -> dict:
        """Snapshot the current proxy jar into the profile's saved_session.

        Reads live cookies (and auth headers) for the profile's host from the proxy
        store and saves them as the profile's session — no browser or login needed,
        just browse through Frieren's proxy first."""
        profile = load_profile(slug)
        if profile is None:
            return JSONResponse({"error": "profile not found"}, status_code=404)
        host = (req.host or "").strip().lower()
        if not host:
            # Derive from host_pattern: strip leading "*."
            pat = (profile.host_pattern or "").strip().lower()
            host = pat.lstrip("*.") if pat else ""
        if not host:
            return JSONResponse(
                {"error": "provide a host or set host_pattern on the profile"},
                status_code=400,
            )
        jar_cookies = []
        try:
            jar_cookies = ctx.store.get_cookies_for_host(host) or []
        except Exception as exc:
            logger.warning("capture-from-proxy: jar lookup failed", slug=slug, host=host, error=str(exc))
        if not jar_cookies:
            return JSONResponse(
                {"error": f"no cookies found in proxy jar for {host}; browse the site first"},
                status_code=404,
            )
        # Build auth headers from recent proxy entries for the host
        auth_headers: Dict[str, str] = {}
        try:
            from dast.proxy.auth_headers import extract_auth_headers
            recent = [
                ctx.store._entries[eid]
                for eid in reversed(ctx.store._order[-100:])
                if eid in ctx.store._entries
            ]
            auth_headers = extract_auth_headers(recent, host=host, exclude_sources=())
        except Exception as exc:
            logger.warning("capture-from-proxy: auth-header extract failed", slug=slug, error=str(exc))
        state: Dict[str, Any] = {"cookies": jar_cookies, "origins": []}
        if auth_headers:
            state["_auth_headers"] = auth_headers
        profile.saved_session = state
        import time as _time
        profile.updated_at = _time.time()
        save_profile(profile)
        logger.info("profile session captured from proxy jar", slug=slug, host=host,
                    cookies=len(jar_cookies), auth_headers=len(auth_headers))
        result = profile.to_public_dict()
        result["captured"] = {"host": host, "cookies": len(jar_cookies),
                              "auth_headers": len(auth_headers)}
        return result

    @router.post("/api/profiles/quick-capture")
    async def quick_capture(req: QuickCaptureIn) -> dict:
        """Create (or update) a named session profile and immediately capture the
        current proxy jar cookies for the given host — all in one step.

        Typical flow: log in through the browser (with Frieren's proxy active),
        then call this with a name, host, and privilege level to save the session."""
        name = req.name.strip()
        host = req.host.strip().lower()
        if not name or not host:
            return JSONResponse({"error": "name and host are required"}, status_code=400)
        jar_cookies = []
        try:
            jar_cookies = ctx.store.get_cookies_for_host(host) or []
        except Exception as exc:
            logger.warning("quick-capture: jar lookup failed", host=host, error=str(exc))
        if not jar_cookies:
            return JSONResponse(
                {"error": f"no cookies found in proxy jar for {host}; browse the site first"},
                status_code=404,
            )
        auth_headers: Dict[str, str] = {}
        try:
            from dast.proxy.auth_headers import extract_auth_headers
            recent = [
                ctx.store._entries[eid]
                for eid in reversed(ctx.store._order[-100:])
                if eid in ctx.store._entries
            ]
            auth_headers = extract_auth_headers(recent, host=host, exclude_sources=())
        except Exception as exc:
            logger.warning("quick-capture: auth-header extract failed", host=host, error=str(exc))
        slug = slugify(name)
        profile = load_profile(slug) or LoginProfile(slug=slug, name=name)
        profile.name = name
        if not profile.host_pattern:
            profile.host_pattern = host
        profile.privilege_level = req.privilege_level
        state: Dict[str, Any] = {"cookies": jar_cookies, "origins": []}
        if auth_headers:
            state["_auth_headers"] = auth_headers
        profile.saved_session = state
        import time as _time
        profile.updated_at = _time.time()
        save_profile(profile)
        logger.info("quick-capture: profile created/updated", slug=slug, host=host,
                    privilege=req.privilege_level, cookies=len(jar_cookies))
        result = profile.to_public_dict()
        result["captured"] = {"host": host, "cookies": len(jar_cookies),
                              "auth_headers": len(auth_headers)}
        return result

    return router
