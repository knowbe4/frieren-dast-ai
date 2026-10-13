"""
Browse worker — headless/named Browse-tab sessions routed through the proxy.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Optional

from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.proxy.runner import ProxyRunner

logger = get_logger(__name__)


async def run_browse_worker(runner: "ProxyRunner", browse_queue: asyncio.Queue) -> None:
    from dast.proxy.browse_session import BrowseSession, login_with_credentials
    from dast.proxy.plugin_manager import log_event

    # Unnamed session (legacy start/stop flow)
    _active: Optional[BrowseSession] = None
    # Named sessions: name → BrowseSession (each isolated context)
    _named: dict[str, BrowseSession] = {}

    while True:
        job = await browse_queue.get()
        action = job.get("action")

        # ── legacy stop (unnamed session) ───────────────────────────────
        if action == "stop":
            if _active:
                await _active.stop()
                runner._store.active_browse_session_id = None
                _active = None
                log_event("browser", "info", "Browse session stopped", source="browser")
            continue

        # ── legacy start (unnamed session) ──────────────────────────────
        if action == "start":
            if _active and _active.running:
                await _active.stop()

            def on_stop():
                nonlocal _active
                runner._store.active_browse_session_id = None
                _active = None

            session = BrowseSession(
                proxy_port=runner._proxy_port,
                on_stop=on_stop,
            )
            await session.start(start_url=job.get("url"), headless=False)
            runner._store.active_browse_session_id = session.session_id
            _active = session
            log_event("browser", "info", "Browse session started",
                      url=job.get("url", ""), source="browser")
            job.get("result_cb", lambda s: None)(session.session_id)
            continue

        # ── named browser session ────────────────────────────────────────
        if action == "start_named":
            name = job.get("name", "")
            role = job.get("role", "user")
            if name in _named and _named[name].running:
                job.get("result_cb", lambda *_: None)(
                    False, "session already open", _named[name].session_id
                )
                continue

            def _make_stop_cb(n: str):
                def _on_stop():
                    _named.pop(n, None)
                return _on_stop

            ns = BrowseSession(
                proxy_port=runner._proxy_port,
                on_stop=_make_stop_cb(name),
                name=name,
            )
            try:
                await ns.start(start_url=job.get("url"), headless=False)
                _named[name] = ns
                log_event("browser", "info", f'Named browse session "{name}" started',
                          url=job.get("url", ""), source="browser")
                job.get("result_cb", lambda *_: None)(True, "", ns.session_id)
            except Exception as exc:
                log_event("browser", "error", f'Failed to open named session "{name}": {exc}',
                          source="browser")
                job.get("result_cb", lambda *_: None)(False, str(exc), "")
            continue

        if action == "save_named":
            # Capture cookies from the named browser context and persist as NamedSession
            name = job.get("name", "")
            role = job.get("role", "user")
            ns = _named.get(name)
            if not ns:
                job.get("result_cb", lambda *_: None)(False, "session not open", 0)
                continue
            pw_cookies = await ns.get_playwright_cookies()
            saved = runner._store.save_named_session_from_playwright(name, role, pw_cookies)
            log_event("browser", "info",
                      f'Named session "{name}" saved — {len(saved.cookies)} cookie(s)',
                      source="browser")
            job.get("result_cb", lambda *_: None)(True, "", len(saved.cookies))
            continue

        if action == "stop_named":
            name = job.get("name", "")
            ns = _named.pop(name, None)
            if ns:
                await ns.stop()
                log_event("browser", "info", f'Named browse session "{name}" stopped',
                          source="browser")
            job.get("result_cb", lambda *_: None)(True, "")
            continue

        if action == "list_named":
            result = [
                {"name": n, "session_id": s.session_id, "running": s.running}
                for n, s in _named.items()
            ]
            job.get("result_cb", lambda r: None)(result)
            continue

        # ── headless credential login ────────────────────────────────────
        if action == "credentials":
            name = job.get("name", "")
            role = job.get("role", "user")
            try:
                result = await login_with_credentials(
                    proxy_port=runner._proxy_port,
                    login_url=job["login_url"],
                    username=job["username"],
                    password=job["password"],
                    username_selector=job.get("username_selector",
                        "input[type=email],input[type=text],input[name*=user],input[name*=email],input[id*=user],input[id*=email]"),
                    password_selector=job.get("password_selector", "input[type=password]"),
                    submit_selector=job.get("submit_selector",
                        "button[type=submit],input[type=submit]"),
                )
                if result["success"]:
                    saved = runner._store.save_named_session_from_playwright(
                        name, role, result["cookies"], result["auth_headers"]
                    )
                    log_event("browser", "info",
                              f'Credentials login for "{name}" succeeded — '
                              f'{len(saved.cookies)} cookie(s)', source="browser")
                    job.get("result_cb", lambda *_: None)(True, "", len(saved.cookies))
                else:
                    log_event("browser", "warn",
                              f'Credentials login for "{name}" failed: {result["error"]}',
                              source="browser")
                    job.get("result_cb", lambda *_: None)(False, result["error"], 0)
            except Exception as exc:
                log_event("browser", "error",
                          f'Credentials login for "{name}" error: {exc}', source="browser")
                job.get("result_cb", lambda *_: None)(False, str(exc), 0)
