"""
Login worker — records and replays login flows for saved profiles.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Optional

from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.proxy.runner import ProxyRunner

logger = get_logger(__name__)


async def run_login_worker(runner: "ProxyRunner", login_queue: asyncio.Queue) -> None:
    """Drive login-flow recording (visible browser) and replay jobs.

    Recording opens a visible, proxy-routed BrowseSession with the DOM recorder
    installed; the analyst logs in by hand and the session's steps are captured.
    Replay re-executes a saved LoginFlow, pausing for a human on captcha/MFA.
    """
    from dast.proxy.browse_session import BrowseSession
    from dast.proxy.plugin_manager import log_event
    from dast.session.flow_replayer import replay_login_flow

    _record_session: Optional[BrowseSession] = None

    while True:
        job = await login_queue.get()
        action = job.get("action")

        # ── start recording a login flow ────────────────────────────────
        if action == "start_record":
            try:
                if _record_session and _record_session.running:
                    await _record_session.stop()
                session = BrowseSession(
                    proxy_port=runner._proxy_port,
                    on_stop=lambda: None,
                )
                await session.start(start_url=job.get("url"), headless=False, record=True)
                _record_session = session
                log_event("browser", "info", "Login-flow recording started",
                          url=job.get("url", ""), source="browser")
                job.get("result_cb", lambda *_: None)(True, "", session.session_id)
            except Exception as exc:
                log_event("browser", "error",
                          f"Login-flow recording failed to start: {exc}", source="browser")
                job.get("result_cb", lambda *_: None)(False, str(exc), "")
            continue

        # ── stop recording, return flow + captured session ──────────────
        if action == "stop_record":
            if not _record_session:
                job.get("result_cb", lambda *_: None)(False, "no recording in progress", {})
                continue
            try:
                flow = _record_session.stop_recording()
                cookies = await _record_session.get_playwright_cookies()
                storage_state = await _record_session.get_storage_state()
                await _record_session.stop()
                log_event("browser", "info",
                          f"Login-flow recording stopped — {len(flow.get('steps', []))} step(s)",
                          source="browser")
                job.get("result_cb", lambda *_: None)(True, "", {
                    "flow": flow, "cookies": cookies, "storage_state": storage_state,
                })
            except Exception as exc:
                log_event("browser", "error",
                          f"Login-flow recording stop failed: {exc}", source="browser")
                job.get("result_cb", lambda *_: None)(False, str(exc), {})
            finally:
                _record_session = None
            continue

        # ── cancel recording without saving ─────────────────────────────
        if action == "cancel_record":
            if _record_session:
                try:
                    await _record_session.stop()
                except Exception:
                    pass
                _record_session = None
                log_event("browser", "info", "Login-flow recording cancelled", source="browser")
            job.get("result_cb", lambda *_: None)(True, "")
            continue

        # ── replay a saved flow (headed, human-in-loop on captcha) ──────
        if action == "replay":
            from dast.profiles.flow import LoginFlow
            try:
                flow = LoginFlow.from_dict(job.get("flow", {}))
                result = await replay_login_flow(
                    proxy_port=runner._proxy_port,
                    flow=flow,
                    username=job.get("username", ""),
                    password=job.get("password", ""),
                    headless=job.get("headless", False),
                    on_pause=job.get("on_pause"),
                    resume_event=job.get("resume_event"),
                )
                log_event(
                    "browser",
                    "info" if result.get("success") else "warn",
                    f"Login-flow replay {'succeeded' if result.get('success') else 'failed'}"
                    + (f": {result.get('error')}" if result.get("error") else ""),
                    source="browser",
                )
                job.get("result_cb", lambda *_: None)(result)
            except Exception as exc:
                log_event("browser", "error",
                          f"Login-flow replay error: {exc}", source="browser")
                job.get("result_cb", lambda *_: None)(
                    {"success": False, "error": str(exc)}
                )
            continue
