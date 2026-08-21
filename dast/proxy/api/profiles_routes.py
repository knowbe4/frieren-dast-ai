"""
Login-profile routes — manage encrypted per-site login profiles (Discovery > Logins).

  GET    /api/profiles                     list profiles (redacted — no secrets)
  GET    /api/profiles/{slug}              one profile (redacted)
  POST   /api/profiles                     create/update a profile
  DELETE /api/profiles/{slug}              delete a profile
  POST   /api/profiles/{slug}/session-import  import an active session (no login)
  POST   /api/profiles/{slug}/activate     load the saved session into the live store

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


class SessionImportIn(BaseModel):
    target_url: str = ""
    storage_state_json: str = ""
    cookie_header: str = ""
    auth_token: str = ""


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
        # Register a named session (consumed by cross-session agents) and merge the
        # cookies into the live jar so proxied/scanned requests carry the session.
        ctx.store.save_named_session_from_playwright(
            name=profile.slug, role=profile.name, playwright_cookies=cookies,
            auth_headers=auth_headers,
        )
        imported = ctx.store.import_playwright_cookies(cookies)
        logger.info("login profile activated", slug=slug, cookies=imported)
        return {"activated": True, "cookies_imported": imported, "named_session": profile.slug}

    return router
