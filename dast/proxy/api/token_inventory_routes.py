"""Read-only token-inventory route: GET /api/token-inventory.

Exposes the redacted, traffic-learned credential landscape (session cookies, per-sub-app JWT
bearers, custom auth headers, query tokens) for the operator/dashboard. Values are never
returned — only type, location, non-secret JWT claims, and a short fingerprint.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter

from dast.proxy.api.context import DashboardContext
from dast.session.token_inventory import build_token_inventory
from dast.utils.logger import get_logger

logger = get_logger(__name__)


def make_router(ctx: DashboardContext) -> APIRouter:
    router = APIRouter()

    @router.get("/api/token-inventory")
    async def token_inventory(host: Optional[str] = None):
        """Redacted credential inventory. ?host=<h> for one host; omitted = every host that has
        cookies captured. Never includes token/cookie values."""
        store = ctx.store
        if store is None:
            return {"inventories": []}
        if host:
            hosts = [host.strip().lower()]
        else:
            try:
                hosts = sorted(store.get_cookie_hosts() or [])
            except Exception as exc:  # noqa: BLE001
                logger.debug("token-inventory: host list failed", error=str(exc)[:120])
                hosts = []
        inventories = [build_token_inventory(store, h) for h in hosts if h]
        return {"inventories": inventories}

    return router
