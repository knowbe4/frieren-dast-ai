"""
Status and WebSocket routes: /api/status, /ws, /ws/crawl, startup event.
"""

from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

from dast.proxy.api.context import DashboardContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)


def make_router(ctx: DashboardContext) -> APIRouter:
    router = APIRouter()

    @router.get("/api/status")
    async def get_status():
        import time as _time
        if ctx.status_cache and (_time.monotonic() - ctx.status_cache_ts[0]) < 300:
            return ctx.status_cache.copy()

        try:
            import os
            import boto3
            from dast.config import settings as cfg
            from dast.ai import bedrock_client
            from dast.proxy.dashboard_server import _detect_aws_sso_profile

            ai_ok = False
            ai_model = cfg.ai_model_id
            ai_error = None
            aws_identity = None

            # Probe the provider that actually serves LLM calls. Only the bedrock
            # provider authenticates via AWS — for anthropic/openai an STS probe
            # would always fail and wrongly report "offline" while the AI is fully
            # working (the exact bug where an AI-validated finding coexisted with
            # an "offline" badge on a non-Bedrock provider).
            provider = bedrock_client.get_active_provider()

            if provider == "bedrock":
                try:
                    profile  = os.environ.get("AWS_PROFILE") or cfg.aws_profile
                    region   = os.environ.get("AWS_REGION") or cfg.aws_region or "us-east-1"
                    key_id   = os.environ.get("AWS_ACCESS_KEY_ID") or cfg.aws_access_key_id
                    secret   = os.environ.get("AWS_SECRET_ACCESS_KEY") or cfg.aws_secret_access_key
                    token    = os.environ.get("AWS_SESSION_TOKEN") or cfg.aws_session_token

                    if not profile and not key_id:
                        profile = _detect_aws_sso_profile()

                    logger.debug("AI status check", provider=provider, profile=profile, region=region, has_key=bool(key_id))

                    if profile:
                        session = boto3.Session(profile_name=profile, region_name=region)
                    elif key_id and secret:
                        kw = {"aws_access_key_id": key_id, "aws_secret_access_key": secret, "region_name": region}
                        if token:
                            kw["aws_session_token"] = token
                        session = boto3.Session(**kw)
                    else:
                        session = boto3.Session(region_name=region)

                    loop = asyncio.get_running_loop()
                    identity = await loop.run_in_executor(
                        None,
                        lambda: session.client("sts", region_name=region).get_caller_identity()
                    )
                    aws_identity = identity.get("Arn", "").split("/")[-1]
                    ai_ok = True
                except Exception as e:
                    ai_error = str(e).split("\n")[0]
            else:
                # anthropic / openai — reachability is "is an API key configured".
                logger.debug("AI status check", provider=provider)
                ai_ok = bedrock_client.provider_api_key_present()
                if not ai_ok:
                    ai_error = f"No API key configured for provider '{provider}'"

            # Reconcile with the validator's own sticky availability flag. A real
            # provider failure (expired AWS token, provider error) trips
            # mark_ai_unavailable(); the probe above can still pass and is cached
            # for 5 min, so without this the status could read "connected" while
            # every AI validation is actually being refused. The status indicator
            # must never contradict what the validator will do.
            if not bedrock_client.is_ai_available():
                ai_ok = False
                if not ai_error:
                    ai_error = "AI marked unavailable (credentials expired mid-scan) — click Resume"

            result = {
                "ai_enabled": ai_ok,
                "ai_model": ai_model,
                "ai_model_label": cfg.ai_model_label,
                "aws_identity": aws_identity,
                "ai_error": ai_error,
                "attack_types": [
                    "xss", "sqli", "idor", "ssrf",
                    "open_redirect", "auth_bypass", "mass_assignment", "graphql_injection",
                ],
            }
            ctx.status_cache.clear()
            ctx.status_cache.update(result)
            ctx.status_cache_ts[0] = _time.monotonic()
            return result
        except Exception as e:
            logger.error("AI status endpoint error", error=str(e))
            return JSONResponse({"ai_enabled": False, "ai_error": str(e), "ai_model": None,
                                 "aws_identity": None, "attack_types": []}, status_code=200)

    @router.post("/api/ai/resume")
    async def resume_ai():
        """Re-test AWS credentials; on success, clear the unavailable flag and resume the scan queue."""
        import os
        import boto3
        from dast.proxy.dashboard_server import _detect_aws_sso_profile
        from dast.config import settings as cfg

        try:
            profile = os.environ.get("AWS_PROFILE") or cfg.aws_profile
            region  = os.environ.get("AWS_REGION") or cfg.aws_region or "us-east-1"
            key_id  = os.environ.get("AWS_ACCESS_KEY_ID") or cfg.aws_access_key_id
            secret  = os.environ.get("AWS_SECRET_ACCESS_KEY") or cfg.aws_secret_access_key
            token   = os.environ.get("AWS_SESSION_TOKEN") or cfg.aws_session_token

            if not profile and not key_id:
                profile = _detect_aws_sso_profile()

            if profile:
                session = boto3.Session(profile_name=profile, region_name=region)
            elif key_id and secret:
                kw = {"aws_access_key_id": key_id, "aws_secret_access_key": secret, "region_name": region}
                if token:
                    kw["aws_session_token"] = token
                session = boto3.Session(**kw)
            else:
                session = boto3.Session(region_name=region)

            loop = asyncio.get_running_loop()
            identity = await loop.run_in_executor(
                None,
                lambda: session.client("sts", region_name=region).get_caller_identity()
            )

            from dast.ai import bedrock_client as _bc
            _bc._reset_client()
            _bc.mark_ai_available()

            if ctx.scan_queue_state is not None:
                ctx.scan_queue_state.resume()

            ctx.status_cache.clear()
            ctx.status_cache_ts[0] = 0.0

            from dast.proxy.plugin_manager import log_event
            ident = identity.get("Arn", "").split("/")[-1]
            log_event("scan-worker", "info",
                      f"AI resumed — credentials valid ({ident})", source="agent")

            return {"ok": True, "identity": ident}

        except Exception as exc:
            return JSONResponse({"ok": False, "error": str(exc).split("\n")[0]}, status_code=200)

    @router.get("/api/ai/availability")
    async def ai_availability():
        from dast.ai import bedrock_client as _bc
        paused = ctx.scan_queue_state.paused if ctx.scan_queue_state else False
        return {"available": _bc.is_ai_available(), "scan_queue_paused": paused}

    @router.websocket("/ws")
    async def websocket_endpoint(ws: WebSocket):
        await ws.accept()
        ctx.ws_clients.add(ws)
        try:
            for e in ctx.store.all_entries():
                await ws.send_text(json.dumps(e.to_dict()))
            # Keep the connection alive: receive client messages (including "ping"
            # heartbeats from the UI) with a timeout. When idle too long, send a
            # server-side ping frame so proxies/firewalls don't kill the connection.
            while True:
                try:
                    msg = await asyncio.wait_for(ws.receive_text(), timeout=30.0)
                    # Client sent "ping" — reply with "pong" to confirm aliveness
                    if msg == "ping":
                        await ws.send_text("pong")
                except asyncio.TimeoutError:
                    # No message in 30s — send a keepalive ping from server side
                    try:
                        await ws.send_text(json.dumps({"type": "keepalive"}))
                    except Exception:
                        break  # connection is dead
        except (WebSocketDisconnect, Exception):
            pass
        finally:
            ctx.ws_clients.discard(ws)

    @router.websocket("/ws/crawl")
    async def crawl_ws_endpoint(ws: WebSocket):
        await ws.accept()
        ctx.crawl_log_clients.add(ws)
        try:
            while True:
                await ws.receive_text()
        except (WebSocketDisconnect, Exception):
            pass
        finally:
            ctx.crawl_log_clients.discard(ws)

    return router


async def prefetch_ai_status(ctx: DashboardContext) -> None:
    """Pre-warm the AI status cache on startup so the first page load is fast."""
    import os
    import time as _time
    try:
        import boto3
        from dast.config import settings as cfg
        from dast.ai import bedrock_client
        from dast.proxy.dashboard_server import _detect_aws_sso_profile

        ai_model = cfg.ai_model_id
        aws_identity = None
        provider = bedrock_client.get_active_provider()

        if provider == "bedrock":
            profile  = os.environ.get("AWS_PROFILE") or cfg.aws_profile
            region   = os.environ.get("AWS_REGION") or cfg.aws_region or "us-east-1"
            key_id   = os.environ.get("AWS_ACCESS_KEY_ID") or cfg.aws_access_key_id
            secret   = os.environ.get("AWS_SECRET_ACCESS_KEY") or cfg.aws_secret_access_key
            token    = os.environ.get("AWS_SESSION_TOKEN") or cfg.aws_session_token

            if not profile and not key_id:
                profile = _detect_aws_sso_profile()

            if profile:
                session = boto3.Session(profile_name=profile, region_name=region)
            elif key_id and secret:
                kw = {"aws_access_key_id": key_id, "aws_secret_access_key": secret, "region_name": region}
                if token:
                    kw["aws_session_token"] = token
                session = boto3.Session(**kw)
            else:
                session = boto3.Session(region_name=region)

            loop = asyncio.get_running_loop()
            identity = await loop.run_in_executor(
                None,
                lambda: session.client("sts", region_name=region).get_caller_identity()
            )
            aws_identity = identity.get("Arn", "").split("/")[-1]
            probe_ok = True
        else:
            # anthropic / openai — reachability is "is an API key configured".
            probe_ok = bedrock_client.provider_api_key_present()

        # Reconcile with the validator's sticky availability flag (see get_status).
        ai_ok = probe_ok and bedrock_client.is_ai_available()
        result = {
            "ai_enabled": ai_ok,
            "ai_model": ai_model,
            "ai_model_label": cfg.ai_model_label,
            "aws_identity": aws_identity,
            "ai_error": None if ai_ok else f"AI not reachable for provider '{provider}'",
            "attack_types": [
                "xss", "sqli", "idor", "ssrf",
                "open_redirect", "auth_bypass", "mass_assignment", "graphql_injection",
            ],
        }
        ctx.status_cache.clear()
        ctx.status_cache.update(result)
        ctx.status_cache_ts[0] = _time.monotonic()
        logger.info("AI status pre-warmed", provider=provider, identity=aws_identity, model=ai_model, ai_enabled=ai_ok)
    except Exception as exc:
        ctx.status_cache.clear()
        ctx.status_cache.update({
            "ai_enabled": False,
            "ai_model": None,
            "aws_identity": None,
            "ai_error": str(exc).split("\n")[0],
            "attack_types": [],
        })
        ctx.status_cache_ts[0] = _time.monotonic()
        logger.warning("AI status pre-warm failed", error=str(exc).split("\n")[0])
