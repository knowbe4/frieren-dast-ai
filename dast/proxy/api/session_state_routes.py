"""
Session state routes — re-auth breaker observability + recovery.

  GET  /api/session/state          breaker state (gave_up, failures, cooldown, ...)
  POST /api/session/reauth/reset   re-arm automatic re-auth after a manual login

The SessionRefreshWorker used to be a run() local with an unrecoverable breaker:
after 3 failed re-auths the worker went permanently silent while its log message
promised a recovery that nothing implemented. The worker is now retained on the
ProxyRunner (ctx.runner.refresh_worker), its state is readable here, and the
breaker resets via this route or automatically when a verified session lands
(profile activation, successful replay).
"""

from __future__ import annotations


from fastapi import APIRouter
from fastapi.responses import JSONResponse

from dast.proxy.api.context import DashboardContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)


def _refresh_worker(ctx: DashboardContext):
    runner = getattr(ctx, "runner", None)
    return getattr(runner, "refresh_worker", None) if runner is not None else None


def reset_refresh_breaker(ctx: DashboardContext, reason: str) -> bool:
    """Re-arm automatic re-auth because a fresh session just landed (profile
    activation, successful replay, dashboard reset). Best-effort: returns False
    when there is no refresh worker (the proxy started without auth credentials)."""
    worker = _refresh_worker(ctx)
    if worker is None:
        return False
    worker.reset(reason)
    return True


def make_router(ctx: DashboardContext) -> APIRouter:
    router = APIRouter()

    @router.get("/api/session/state")
    async def session_state():
        """Re-auth breaker state for the dashboard (modelled on /api/ai/availability)."""
        worker = _refresh_worker(ctx)
        if worker is None:
            return {
                "active": False,
                "reason": "no session refresh worker — start the proxy with "
                          "--auth-url and credentials to enable automatic re-auth",
            }
        return worker.state_snapshot()

    @router.post("/api/session/reauth/reset")
    async def reauth_reset():
        """Recover the breaker: after a manual re-auth (Browse tab) the automatic
        re-auth resumes instead of staying silently dead until restart."""
        worker = _refresh_worker(ctx)
        if worker is None:
            return JSONResponse(
                {"error": "no session refresh worker — automatic re-auth is not active"},
                status_code=404,
            )
        reset_refresh_breaker(ctx, "dashboard manual reset")
        return {"reset": True, "state": worker.state_snapshot()}

    return router
