"""
Proxy runner — starts proxy + dashboard + scan worker together.

Three concurrent tasks:
  1. ProxyServer   — asyncio TCP server on :8080
  2. Dashboard     — uvicorn/FastAPI on :8088, WebSocket push
  3. Scan worker   — drains scan_queue, runs AttackEngine per entry
"""

import asyncio
import re
import socket
import webbrowser
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

import uvicorn

import dast.agents  # noqa: F401 — registers all VulnAgent subclasses with Coordinator
from dast.models import ScanConfig
from dast.proxy.cert_authority import CertAuthority
from dast.proxy.dashboard_server import build_app
from dast.proxy.proxy_server import ProxyServer
from dast.proxy.session_store import ProxyEntry, SessionStore
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.ai.agent_base import AgentFinding

logger = get_logger(__name__)


def _find_free_port(preferred_port: int, host: str = "127.0.0.1", max_attempts: int = 10) -> int:
    """Return preferred_port if free, else the next free port up to max_attempts higher."""
    for offset in range(max_attempts):
        port = preferred_port + offset
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind((host, port))
                return port
            except OSError:
                continue
    raise OSError(
        f"Could not find a free port in range {preferred_port}-{preferred_port + max_attempts - 1}"
    )

def _detection_method(f: "AgentFinding") -> list:
    """
    Derive all detection-method labels from an AgentFinding.
    Returns a list because a finding can be confirmed by multiple methods
    (e.g. error_pattern + ai, or pattern + browser).
    """
    attack = getattr(f, "attack_type", "")
    bypass = getattr(f, "bypass_validation", False)
    browser_ok = getattr(f, "browser_confirmed", None)
    title = (getattr(f, "title", "") or "").lower()

    methods = []

    # Deterministic evidence is always the primary signal
    if bypass:
        if attack == "sqli":
            methods.append("time_based" if ("time" in title or "blind" in title) else "error_pattern")
        elif attack == "ssrf":
            methods.append("oob_callback" if ("oob" in title or "callback" in title) else "response_diff")
        elif attack in ("lfi", "file_read"):
            methods.append("file_match")
        elif attack == "sensitive_data":
            methods.append("secret_pattern")
        elif attack == "auth_bypass":
            methods.append("response_diff")
        else:
            methods.append("pattern")

    # Browser confirmation is additive
    if browser_ok is True:
        methods.append("browser")

    # LLM red-team validation — only when not bypass (bypass skips the validator)
    # AND the AI validator actually ran and returned a verdict. When the LLM call
    # was skipped (AI offline) or failed, red_team.validate() confirms via pattern
    # confidence instead — so the finding is labeled "pattern", never "ai". This
    # prevents an "AI validated" badge on a finding the AI never reviewed.
    ai_validated = getattr(f, "ai_validated", False)
    if not bypass:
        methods.append("ai" if ai_validated else "pattern")

    # Every finding needs at least one label. If nothing above applied, fall back
    # to "pattern" rather than implying an AI verdict that never happened.
    return methods if methods else ["pattern"]


# Path segments that would destroy session state or application data.
# Checked against the last URL path segment (lowercased) before scanning.
_DANGEROUS_SEGMENTS = frozenset({
    # Session termination
    "logout", "logoff", "log-out", "log_out", "signout", "sign-out", "sign_out",
    "end-session", "endsession", "invalidate-session", "revoke-session",
    # Account / data destruction
    "delete-account", "deleteaccount", "deactivate", "deactivate-account",
    "close-account", "closeaccount", "cancel-account", "cancelaccount",
    "unsubscribe",
    # Password / credential reset (sending a payload here corrupts the reset flow)
    "reset-password", "resetpassword", "change-password", "changepassword",
})


class ProxyRunner:
    def __init__(
        self,
        proxy_port: int = 8080,
        proxy_host: str = "127.0.0.1",
        dashboard_port: int = 8088,
        workers: int = 4,
        iterations: int = 3,
        confidence: float = 0.7,
        attack_types: Optional[list] = None,
        output_dir: str = "./scan-results",
        auth_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        ai_model_id: str = "",
    ):
        self._proxy_port = proxy_port
        self._proxy_host = proxy_host
        # Live handle to the running proxy listener, so the bind host can be
        # rebound at runtime (see restart_proxy_listener).
        self._proxy_server: Optional["ProxyServer"] = None
        self._dashboard_port = dashboard_port
        self._workers = workers
        self._scan_sem: Optional[asyncio.Semaphore] = None
        self._iterations = iterations
        self._confidence = confidence
        self._attack_types = attack_types or [
            "xss", "sqli", "idor", "ssrf",
            "open_redirect", "auth_bypass", "mass_assignment", "graphql_injection",
        ]
        self._output_dir = output_dir
        self._auth_url = auth_url
        self._username = username
        self._password = password
        self._ai_model_id = ai_model_id

        self._store = SessionStore()
        self._ca = CertAuthority()
        from dast.proxy.proxy_settings import ProxySettings
        from dast.proxy.plugin_manager import PluginManager
        from dast.proxy.intercept_store import InterceptStore
        self._settings = ProxySettings()
        self._plugin_manager = PluginManager()
        self._intercept_store = InterceptStore()
        # Expose settings on the store so workers (AppContext, ThreatModel)
        # can filter out-of-scope entries without a direct runner reference.
        self._store._settings = self._settings
        # Bounded to apply backpressure: on a long session against a large app the
        # queue could otherwise grow without limit and inflate memory. The producer
        # (_ai_mode_listener) already dedups by normalised endpoint, so this ceiling
        # is only hit under pathological fan-out; when full we log and skip rather
        # than block the proxy ingestion path.
        self._scan_queue: asyncio.Queue = asyncio.Queue(maxsize=5000)
        from dast.proxy.scan_queue_state import ScanQueueState
        self._scan_queue_state = ScanQueueState()
        self._pool = None
        # Shared mutable config — dashboard reads/writes this same dict at runtime
        self._engine_config: dict = {
            "workers": workers,
            "probe_concurrency": 3,
            "passive_enabled": True,
            "passive_ai": True,
            "active_enabled": True,
            "llm_planner": True,
            "llm_validator": True,
            "probe_diff": False,
            "model_id": ai_model_id or "",
            "confidence_threshold": 0.5,
        }
        # AI provider config — seeded from the pydantic app settings (config.py),
        # not ProxySettings (proxy_settings.py, which only holds scope/bypass).
        # The dashboard reflects the startup provider; the user can switch it at
        # runtime via /api/scan-config.
        from dast.config import settings as _app_settings
        self._engine_config.update({
            "ai_provider": _app_settings.ai_provider,
            "anthropic_api_key": _app_settings.anthropic_api_key or "",
            "anthropic_base_url": _app_settings.anthropic_base_url,
            "openai_api_key": _app_settings.openai_api_key or "",
            "openai_base_url": _app_settings.openai_base_url,
            # Gateway base URL is internal — seeded from .env only, never a code default.
            "gateway_base_url": _app_settings.gateway_base_url or "",
        })

    async def run(self) -> None:
        import os
        from dast.ai import bedrock_client as _bc
        # Set the active model so all LLM calls (planner, validator, mutator) use it
        if self._ai_model_id:
            _bc.set_active_model(self._ai_model_id)
        # Select the AI provider (Bedrock / Anthropic / OpenAI) from the engine
        # config (seeded from app settings in __init__) so all LLM calls route to
        # the configured backend from the first scan.
        _bc.set_provider(
            provider=self._engine_config.get("ai_provider", ""),
            anthropic_api_key=self._engine_config.get("anthropic_api_key", ""),
            anthropic_base_url=self._engine_config.get("anthropic_base_url", ""),
            openai_api_key=self._engine_config.get("openai_api_key", ""),
            openai_base_url=self._engine_config.get("openai_base_url", ""),
            gateway_base_url=self._engine_config.get("gateway_base_url", ""),
        )
        logger.info(
            "Proxy process environment",
            aws_profile=os.environ.get("AWS_PROFILE"),
            aws_region=os.environ.get("AWS_REGION"),
            has_access_key=bool(os.environ.get("AWS_ACCESS_KEY_ID")),
        )
        loop = asyncio.get_running_loop()
        self._store.set_event_loop(loop)
        self._store.set_scan_queue(self._scan_queue)
        self._plugin_manager.load_all()
        self._store.set_plugin_manager(self._plugin_manager)
        await self._plugin_manager.setup_all()

        # Wire AppContextWorker and ThreatModelWorker into DiscoveryEngine
        from dast.discovery.app_context import AppContextWorker
        from dast.discovery.threat_model import ThreatModelWorker
        self._app_context_worker = AppContextWorker(
            store=self._store,
            engine=self._store.discovery_engine,
            scan_queue=self._scan_queue,
            scan_queue_state=self._scan_queue_state,
        )
        self._threat_model_worker = ThreatModelWorker(
            store=self._store,
            engine=self._store.discovery_engine,
        )
        self._store.discovery_engine.set_app_context_worker(self._app_context_worker)
        self._store.discovery_engine.set_threat_model_worker(self._threat_model_worker)

        # Build browser context pool for the scan worker
        from dast.browser.context_pool import ContextPool
        from dast.session.manager import SessionManager
        from dast.session.auth_agent import AuthAgent

        self._pool = ContextPool(size=self._workers, headless=True)
        session_mgr = SessionManager()
        await self._pool.start()

        refresh_worker = None
        if self._auth_url and self._username:
            async with self._pool.acquire() as ctx:
                agent = AuthAgent(
                    context=ctx,
                    session_manager=session_mgr,
                    auth_url=self._auth_url,
                    username=self._username,
                    password=self._password,
                )
                ok = await agent.login()
                if ok:
                    state = await ctx.storage_state()
                    await self._pool.apply_auth_state(state)
                    logger.info("Auth state applied to proxy scan pool")
                else:
                    logger.warning("Proxy auth failed — scanning unauthenticated")

            # Wire session refresh: watch for 401/redirect-to-login in the entry stream
            from dast.session.refresh_worker import SessionRefreshWorker
            refresh_worker = SessionRefreshWorker(
                auth_url=self._auth_url,
                username=self._username,
                password=self._password,
                pool=self._pool,
                session_manager=session_mgr,
                proxy_port=self._proxy_port,
            )

            async def _refresh_listener(entry) -> None:
                refresh_worker.on_entry(entry)

            self._store.add_listener(_refresh_listener)

        config = ScanConfig(
            target_url="",
            auth_url=self._auth_url,
            username=self._username,
            password=self._password,
            parallel_workers=self._workers,
            browser_headless=True,
            max_attack_iterations=self._iterations,
            confidence_threshold=self._confidence,
            enabled_attack_types=self._attack_types,
            ai_model_id=self._ai_model_id,
            output_dir=self._output_dir,
        )

        # Start proxy — falls back to the next free port if _proxy_port is busy
        # (e.g. a previous instance still shutting down). The browser's manual
        # proxy setting is NOT auto-updated when this happens, so a fallback
        # here would silently break interception — surface it loudly.
        # The persisted settings bind host (set via the Setup tab) is
        # authoritative once configured; the constructor default (CLI/env) only
        # applies on the very first run before anything is saved.
        persisted_host = self._settings.get_bind_host() if self._settings else ""
        if persisted_host:
            self._proxy_host = persisted_host
        persisted_port = self._settings.get_bind_port() if self._settings else 0
        if persisted_port:
            self._proxy_port = persisted_port
        requested_proxy_port = self._proxy_port
        proxy = ProxyServer(self._store, self._ca, self._settings, host=self._proxy_host, port=self._proxy_port, intercept_store=self._intercept_store)
        await proxy.start()
        self._proxy_server = proxy
        self._proxy_host = proxy._host
        self._proxy_port = proxy._port
        if self._proxy_port != requested_proxy_port:
            logger.warning(
                "PROXY PORT CHANGED — update your browser's proxy settings",
                requested_port=requested_proxy_port, actual_port=self._proxy_port,
            )

        # Dashboard port: same fallback, checked before uvicorn binds since
        # uvicorn.Server.serve() has no built-in retry-on-busy-port.
        self._dashboard_port = _find_free_port(self._dashboard_port)

        logger.info(
            "Proxy ready",
            proxy=f"http://{self._proxy_host}:{self._proxy_port}",
            dashboard=f"http://127.0.0.1:{self._dashboard_port}",
            ca_cert=str(self._ca.ca_cert_path),
        )

        # Build dashboard app
        crawl_queue: asyncio.Queue = asyncio.Queue()
        browse_queue: asyncio.Queue = asyncio.Queue()
        discovery_queue: asyncio.Queue = asyncio.Queue()
        login_queue: asyncio.Queue = asyncio.Queue()
        app = build_app(self._store, self._scan_queue, self._ca, self._settings, crawl_queue, self._plugin_manager, browse_queue, self._proxy_port, scan_config=self._engine_config, scan_queue_state=self._scan_queue_state, runner=self, intercept_store=self._intercept_store, discovery_queue=discovery_queue, login_queue=login_queue, proxy_host=self._proxy_host)
        uv_config = uvicorn.Config(
            app,
            host="127.0.0.1",
            port=self._dashboard_port,
            log_level="warning",
        )
        uv_server = uvicorn.Server(uv_config)

        # Open dashboard only after uvicorn is confirmed ready (started flag set by uvicorn)
        async def _open_browser():
            # The desktop (Electron) launcher renders the dashboard in its own
            # native window and sets DAST_DESKTOP=1 to suppress the system-browser
            # tab that would otherwise open on top of it.
            import os as _os
            if _os.environ.get("DAST_DESKTOP") == "1":
                logger.info("DAST_DESKTOP=1 — skipping system browser open")
                return
            # Poll until uvicorn marks itself as started (port is bound and accepting)
            for _ in range(40):
                if uv_server.started:
                    break
                await asyncio.sleep(0.1)
            webbrowser.open(f"http://127.0.0.1:{self._dashboard_port}")

        # Opening the browser is a one-shot side effect that returns immediately
        # (and does nothing under DAST_DESKTOP=1). It must NOT gate shutdown, or
        # its normal completion would tear the whole app down right after startup.
        browser_task = asyncio.create_task(_open_browser())

        # Long-lived tasks only: these loop forever, so the ONLY one that returns
        # under normal operation is uvicorn's serve() — and only when it receives
        # SIGINT (uvicorn installs its own handler, so Ctrl+C never reaches us as
        # KeyboardInterrupt). A plain gather() would then keep waiting on the
        # infinite workers, hanging the process and stranding the proxy port.
        # Waiting on FIRST_COMPLETED lets uvicorn's graceful exit (or a worker
        # crash) deterministically tear the rest down.
        long_lived = [
            uv_server.serve(),
            self._scan_worker(config, session_mgr),
            self._crawl_worker(crawl_queue),
            self._discovery_worker(discovery_queue),
            self._browse_worker(browse_queue),
            self._login_worker(login_queue),
            self._app_context_worker.run(),
            self._threat_model_worker.run(),
        ]
        if refresh_worker is not None:
            long_lived.append(refresh_worker.run())

        tasks = [asyncio.create_task(coro) for coro in long_lived]
        try:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                exc = task.exception()
                if exc and not isinstance(exc, asyncio.CancelledError):
                    logger.error("Proxy task exited with error", error=str(exc))
            # Tell uvicorn to exit gracefully if a worker (not uvicorn) finished
            # first, then cancel everything still pending.
            uv_server.should_exit = True
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
        finally:
            browser_task.cancel()
            await asyncio.gather(browser_task, return_exceptions=True)
            self._app_context_worker.stop()
            self._threat_model_worker.stop()
            if self._proxy_server is not None:
                await self._proxy_server.stop()
            await self._pool.stop()
            await self._plugin_manager.teardown_all()

    async def restart_proxy_listener(self, host: str, port: Optional[int] = None) -> dict:
        """
        Rebind the proxy listener to a new host/port without dropping the
        dashboard, the scan session, or intercepted traffic (Burp-style listener
        restart).

        On failure to bind the requested address, the previous listener is
        restored so the proxy is never left down. Returns a dict with ``ok`` and
        the effective ``host``/``port`` (or ``error`` on failure).
        """
        if self._proxy_server is None:
            return {"ok": False, "error": "proxy listener is not running"}

        old_host, old_port = self._proxy_host, self._proxy_port
        new_port = old_port if port is None else int(port)
        if host == old_host and new_port == old_port:
            return {"ok": True, "host": old_host, "port": old_port}

        await self._proxy_server.stop()
        new_server = ProxyServer(
            self._store, self._ca, self._settings,
            host=host, port=new_port, intercept_store=self._intercept_store,
        )
        try:
            # Bind the exact requested port only (no free-port fallback here): a
            # silent bump would leave the browser pointed at the wrong port.
            await new_server.start(max_port_attempts=1)
        except OSError as exc:
            logger.warning("Proxy rebind failed, restoring previous listener",
                           requested_host=host, error=str(exc))
            restored = ProxyServer(
                self._store, self._ca, self._settings,
                host=old_host, port=old_port, intercept_store=self._intercept_store,
            )
            await restored.start()
            self._proxy_server = restored
            self._proxy_host, self._proxy_port = restored._host, restored._port
            return {"ok": False, "error": str(exc),
                    "host": self._proxy_host, "port": self._proxy_port}

        self._proxy_server = new_server
        self._proxy_host, self._proxy_port = new_server._host, new_server._port
        logger.info("Proxy listener rebound", host=self._proxy_host, port=self._proxy_port)
        return {"ok": True, "host": self._proxy_host, "port": self._proxy_port}

    async def _browse_worker(self, browse_queue: asyncio.Queue) -> None:
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
                    self._store.active_browse_session_id = None
                    _active = None
                    log_event("browser", "info", "Browse session stopped", source="browser")
                continue

            # ── legacy start (unnamed session) ──────────────────────────────
            if action == "start":
                if _active and _active.running:
                    await _active.stop()

                def on_stop():
                    self._store.active_browse_session_id = None

                session = BrowseSession(
                    proxy_port=self._proxy_port,
                    on_stop=on_stop,
                )
                await session.start(start_url=job.get("url"), headless=False)
                self._store.active_browse_session_id = session.session_id
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
                    proxy_port=self._proxy_port,
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
                saved = self._store.save_named_session_from_playwright(name, role, pw_cookies)
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
                        proxy_port=self._proxy_port,
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
                        saved = self._store.save_named_session_from_playwright(
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

    async def _login_worker(self, login_queue: asyncio.Queue) -> None:
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
                        proxy_port=self._proxy_port,
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
                        proxy_port=self._proxy_port,
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

    async def _crawl_worker(self, crawl_queue: asyncio.Queue) -> None:
        from dast.proxy.spa_crawler import SpaCrawler
        from dast.proxy.plugin_manager import log_event

        _active_stop: Optional[asyncio.Event] = None

        while True:
            job = await crawl_queue.get()

            if job.get("action") == "stop":
                if _active_stop:
                    _active_stop.set()
                    log_event("crawler", "info", "Crawler stopped", source="crawler")
                continue

            stop_event = asyncio.Event()
            _active_stop = stop_event
            log_cb = job.get("log_cb") or (lambda m: None)
            target_url = job.get("url", "")
            log_event("crawler", "info", "Crawl started", url=target_url, source="crawler")

            crawler = SpaCrawler(self._store, log_cb, stop_event, proxy_port=self._proxy_port)
            try:
                await crawler.run(
                    target_url=target_url,
                    auth_cookies=job.get("cookies"),
                    max_clicks=job.get("max_clicks", 200),
                    headless=job.get("headless", True),
                    extra_seeds=job.get("extra_seeds"),
                )
                log_event("crawler", "info", "Crawl finished", url=target_url, source="crawler")
            except Exception as e:
                log_cb(f"Crawler error: {e}")
                logger.error("Crawl failed", url=target_url, error=str(e))
                log_event("crawler", "error", f"Crawl error: {e}", url=target_url, source="crawler")

    async def _discovery_worker(self, discovery_queue: asyncio.Queue) -> None:
        """
        Consume content-discovery jobs: forced-browse a host's common paths and
        turn each hit into a synthetic sitemap entry + an AI scan suggestion.

        Mirrors _crawl_worker: one job at a time, a stop job sets a cancel flag.
        All HTTP + scope safety lives in content_discovery.run_content_discovery.
        """

        from dast.proxy.plugin_manager import log_event
        from dast.scanners.content_discovery import run_content_discovery

        cancel = {"stop": False}

        while True:
            job = await discovery_queue.get()

            if job.get("action") == "stop":
                cancel["stop"] = True
                log_event("content-discovery", "info", "Content discovery stopped", source="crawler")
                continue

            cancel["stop"] = False
            log_cb = job.get("log_cb")
            base_url = job.get("url", "")
            headers = job.get("headers") or {}
            proxy_url = f"http://127.0.0.1:{self._proxy_port}"
            log_event("content-discovery", "info", "Content discovery started",
                      url=base_url, source="crawler")

            try:
                hits = await run_content_discovery(
                    base_url=base_url,
                    headers=headers,
                    settings=self._settings,
                    proxy_url=proxy_url,
                    log_cb=log_cb,
                    include_dirs=job.get("dirs", True),
                    include_files=job.get("files", True),
                    include_graphql=job.get("graphql", True),
                    should_cancel=lambda: cancel["stop"],
                )
            except Exception as e:
                logger.error("Content discovery failed", url=base_url, error=str(e))
                log_event("content-discovery", "error", f"Content discovery error: {e}",
                          url=base_url, source="crawler")
                continue

            recorded = 0
            for hit in hits:
                try:
                    self._record_discovery_hit(hit, headers)
                    recorded += 1
                except Exception as e:
                    logger.warning("Failed to record discovery hit",
                                   url=hit.get("url", ""), error=str(e))

            log_event("content-discovery", "info",
                      f"Content discovery finished: {len(hits)} hit(s), {recorded} recorded",
                      url=base_url, source="crawler")

    def _record_discovery_hit(self, hit: dict, headers: dict) -> None:
        """
        Turn a single content-discovery hit into a synthetic sitemap entry and
        an AI scan suggestion. Reuses the synthetic-entry pattern from
        ai_routes.py and the suggestion shape from app_context.py.

        Classification (per plan): dir/file hits are neutral "recon" suggestions
        (no vulnerability inferred from a path); GraphQL hits get
        "graphql_injection". Optional LLM refinement is applied when the
        discovery_llm_classify scan-config flag is on AND AI is available.
        """
        import time
        import uuid
        from urllib.parse import urlparse

        from dast.proxy.plugin_manager import log_event

        store = self._store
        url = hit["url"]
        parsed = urlparse(url)
        host = parsed.hostname or ""
        path = hit["path"] or "/"
        method = hit.get("method", "GET")

        # ── synthetic sitemap entry (only if not already present) ──────────
        already = any(
            e.host == host and e.path == path and e.method == method
            for e in list(store._entries.values())
        )
        if not already:
            synthetic_id = f"disc-{int(time.time() * 1000)}-{uuid.uuid4().hex[:6]}"
            entry = ProxyEntry(
                id=synthetic_id,
                method=method,
                url=url,
                host=host,
                path=path,
                request_headers=dict(headers),
                request_body=None,
                response_status=hit.get("status"),
                content_type=hit.get("content_type", ""),
                source="discovery",
            )
            with store._lock:
                store._entries[synthetic_id] = entry
                store._order.append(synthetic_id)
            store._notify(entry)

        # ── classification ────────────────────────────────────────────────
        kind = hit.get("kind", "file")
        if kind == "graphql":
            attack_type = "graphql_injection"
            rationale = f"GraphQL endpoint discovered via forced browsing (HTTP {hit.get('status')})"
        else:
            attack_type = "recon"
            rationale = (
                f"{kind.capitalize()} discovered via forced browsing "
                f"(HTTP {hit.get('status')}, {hit.get('length', 0)} bytes) — review to decide what to test"
            )

        # Optional LLM refinement of the attack_type (opt-in, degrades to recon).
        if attack_type == "recon" and self._discovery_llm_classify_enabled():
            refined = self._llm_classify_discovery_hit(hit)
            if refined:
                attack_type = refined
                rationale = f"{rationale} | LLM-inferred candidate: {refined}"

        # ── AI scan suggestion (dedup on host/endpoint/attack_type) ────────
        suggestions = getattr(store, "active_suggestions", None)
        if suggestions is not None:
            endpoint = f"{method} {path}"
            key = (host, endpoint, attack_type)
            if key not in {(s["host"], s["endpoint"], s["attack_type"]) for s in suggestions}:
                auto_scan = getattr(store, "auto_scan_suggestions", False)
                suggestions.append({
                    "host": host,
                    "endpoint": endpoint,
                    "method": method,
                    "path": path,
                    "attack_type": attack_type,
                    "parameter": "",
                    "hypothesis": rationale,
                    "severity": "info",
                    "source": "content-discovery",
                    "rationale": rationale,
                    "priority": "info",
                    "status": "queued" if auto_scan else "pending",
                    "body_preview": "",
                    "ts": time.time(),
                })
                log_event("content-discovery", "finding",
                          f"Discovered {kind}: {path} (HTTP {hit.get('status')})",
                          url=url, source="agent")

    def _discovery_llm_classify_enabled(self) -> bool:
        """True if the opt-in LLM classification flag is set in scan-config."""
        return bool(self._engine_config.get("discovery_llm_classify", False))

    def _llm_classify_discovery_hit(self, hit: dict) -> Optional[str]:
        """
        Ask the fast-tier LLM to infer a likely attack_type for a discovered
        path. Returns a lowercase attack_type string or None. Never raises —
        any failure degrades to None (caller keeps the generic "recon" type).
        """
        try:
            from dast.ai import bedrock_client
            from dast.ai.prompt_safety import wrap_untrusted, UNTRUSTED_CONTENT_DIRECTIVE

            system = (
                "You are a web security triage assistant. Given a discovered URL path, "
                "return the single most likely vulnerability class to test for it, chosen "
                "from: idor, lfi, sqli, xss, ssrf, open_redirect, auth_bypass, "
                "info_disclosure, recon. Answer with just the label.\n"
                + UNTRUSTED_CONTENT_DIRECTIVE
            )
            user = wrap_untrusted(
                f"path={hit.get('path')} status={hit.get('status')} "
                f"content_type={hit.get('content_type')}",
                "discovered_path",
            )
            result = bedrock_client.invoke_json(
                system=system,
                user=user,
                schema={
                    "type": "object",
                    "properties": {"attack_type": {"type": "string"}},
                    "required": ["attack_type"],
                },
                model_id=bedrock_client.get_fast_model(),
                temperature=0,
            )
            candidate = str(result.get("attack_type", "")).strip().lower()
            _allowed = {
                "idor", "lfi", "sqli", "xss", "ssrf", "open_redirect",
                "auth_bypass", "info_disclosure",
            }
            return candidate if candidate in _allowed else None
        except Exception as exc:
            logger.warning("LLM discovery classification failed", error=str(exc))
            return None

    async def _mine_params_for_entry(self, entry, proxy_url: str) -> int:
        """
        Run deterministic hidden-parameter mining against a single captured
        request and record each discovered parameter as a recon suggestion.

        This is the AI-off deterministic scan path (invoked from _attack_one when
        AI mode is off but the user explicitly requested a scan) — no LLM, inert
        canary probes only. All HTTP + scope safety lives in
        param_miner.run_param_mining. Returns the number of hidden params found.
        """
        from dast.proxy.plugin_manager import log_event
        from dast.scanners.param_miner import run_param_mining

        base_url = entry.url
        headers = dict(entry.request_headers or {})
        content_type = headers.get("content-type", headers.get("Content-Type", ""))
        body = None
        if entry.request_body:
            try:
                body = entry.request_body.decode("utf-8", errors="replace")
            except Exception:
                body = None

        async def _log_cb(msg: str) -> None:
            log_event("param-mining", "debug", msg, url=base_url, source="agent")

        hits = await run_param_mining(
            base_url=base_url,
            headers=headers,
            settings=self._settings,
            method=entry.method,
            body=body,
            content_type=content_type,
            proxy_url=proxy_url,
            log_cb=_log_cb,
        )

        recorded = 0
        for hit in hits:
            try:
                self._record_param_hit(hit)
                recorded += 1
            except Exception as e:
                logger.warning("Failed to record param hit",
                               parameter=hit.get("parameter", ""), error=str(e))
        return len(hits)

    def _record_param_hit(self, hit: dict) -> None:
        """
        Turn a discovered hidden parameter into an AI scan suggestion. Reuses the
        suggestion shape from _record_discovery_hit — a hidden parameter is fresh
        attack surface, so it is queued as a neutral "recon" suggestion carrying
        the parameter name; no vulnerability is inferred from the name alone (per
        CLAUDE.md: understand before testing).
        """
        import time
        from urllib.parse import urlparse

        from dast.proxy.plugin_manager import log_event

        store = self._store
        url = hit.get("url", "")
        parsed = urlparse(url)
        host = parsed.hostname or ""
        path = parsed.path or "/"
        method = hit.get("method", "GET")
        parameter = hit.get("parameter", "")
        location = hit.get("location", "query")
        reason = hit.get("reason", "")
        if not parameter:
            return

        rationale = (
            f"Hidden parameter '{parameter}' ({location}) discovered via param mining "
            f"[{reason}] — unlinked attack surface, test for injection/access-control"
        )

        suggestions = getattr(store, "active_suggestions", None)
        if suggestions is None:
            return
        endpoint = f"{method} {path}"
        attack_type = "recon"
        key = (host, endpoint, attack_type, parameter)
        existing_keys = {
            (s["host"], s["endpoint"], s["attack_type"], s.get("parameter", ""))
            for s in suggestions
        }
        if key in existing_keys:
            return
        auto_scan = getattr(store, "auto_scan_suggestions", False)
        suggestions.append({
            "host": host,
            "endpoint": endpoint,
            "method": method,
            "path": path,
            "attack_type": attack_type,
            "parameter": parameter,
            "hypothesis": rationale,
            "severity": "info",
            "source": "param-discovery",
            "rationale": rationale,
            "priority": "info",
            "status": "queued" if auto_scan else "pending",
            "body_preview": "",
            "ts": time.time(),
        })
        log_event("param-mining", "finding",
                  f"Hidden parameter: {parameter} ({location}, {reason})",
                  url=url, source="agent")

    async def _scan_worker(self, config: ScanConfig, session_mgr) -> None:
        from dast.scanners import active_checks as _ac
        from dast.scanners.active_checks import run_active_checks
        qs = self._scan_queue_state

        self._scan_sem = asyncio.Semaphore(self._workers)
        # Align the global probe-concurrency semaphore with the configured value at
        # startup (it otherwise keeps the module default until the user touches the
        # UI). More workers with a tiny probe budget yields little real throughput,
        # so scale the probe ceiling with worker count as a sensible floor.
        probe_concurrency = int(self._engine_config.get("probe_concurrency", 3) or 3)
        probe_concurrency = max(probe_concurrency, self._workers)
        _ac._PROBE_SEM = asyncio.Semaphore(probe_concurrency)
        logger.info("Scan worker started", workers=self._workers, probe_concurrency=probe_concurrency)
        proxy_url = f"http://127.0.0.1:{self._proxy_port}"
        # Dedup: track (method, host, normalised-path, operation) tuples completed this session
        _scanned_keys: set = set()

        async def _attack_one(entry_id: str) -> None:
            from dast.proxy.plugin_manager import log_event

            # Wait here if paused — release sem only once we're ready to run
            await qs.wait_if_paused()

            # Check cancellation before acquiring the semaphore
            if qs.is_cancelled(entry_id):
                qs.finish(entry_id, 0, "cancelled")
                return

            # Always read self._scan_sem at acquire time so runtime changes take effect
            # even for tasks that were already waiting in the queue.
            async with self._scan_sem:  # type: ignore[attr-defined]
                # Re-check after acquiring (may have been cancelled while waiting)
                if qs.is_cancelled(entry_id):
                    qs.finish(entry_id, 0, "cancelled")
                    return

                entry = self._store.get_entry(entry_id)
                if not entry:
                    qs.finish(entry_id, 0, "skipped", "Entry not found in store")
                    return

                # ai_queued=True means the user explicitly clicked Scan/Send to AI.
                # Its ONLY effect is to bypass dedup so a deliberate re-scan runs;
                # it does NOT bypass the ai_mode or scope gates below (an earlier
                # version let it, which fired agents at an out-of-scope SSO host
                # with AI mode off).
                # skip_dedup=True means AppContextWorker wants to re-scan without dedup.
                manually_queued = getattr(entry, "ai_queued", False)
                skip_dedup      = getattr(entry, "skip_dedup", False)
                # Only a genuinely imported target list is a deliberate, specific
                # scan request that may run with AI off / fall out of scope.
                is_imported     = entry.source == "imported"

                # Three-layer scan model (see CLAUDE.md "AI Disabled By Default"):
                #   1. Passive plugins — always run on the wire (not here).
                #   2. Deterministic scanners (param mining) — run on an EXPLICIT
                #      scan request even with AI off. No LLM, inert canary probes,
                #      scope-gated. This is the normal scan without agents.
                #   3. AI agents (coordinator + LLM planner) — only with AI on.
                # `ai_mode` off is NOT a reason to skip the whole scan anymore: it
                # only downgrades this entry to the deterministic layer.
                run_agents = bool(is_imported or self._store.ai_mode)

                # Scope is a hard safety boundary — never bypassed by a queue click.
                # Only an explicit import (a deliberate, specific target list) may
                # fall out of scope.
                if not is_imported and not self._settings.is_in_scope(entry.url):
                    logger.debug("Scan skipped — out of scope", url=entry.url)
                    qs.finish(entry_id, 0, "skipped", "URL is out of scope — configure scope in Proxy → Settings")
                    return

                target = _entry_to_check_target(entry, store=self._store)
                if not target:
                    from urllib.parse import urlparse as _up2
                    _seg = _up2(entry.url).path.rstrip("/").rsplit("/", 1)[-1].lower()
                    if _seg in _DANGEROUS_SEGMENTS:
                        log_event("scan-worker", "warn",
                                  f"Scan skipped — session-destructive path: {entry.url}",
                                  url=entry.url, source="agent")
                        qs.finish(entry_id, 0, "skipped", f"Destructive path blocked: /{_seg}")
                    else:
                        qs.finish(entry_id, 0, "skipped", "No injectable parameters found (no query params or JSON body)")
                    self._store.add_finding(entry_id, {}, "safe")
                    return

                # Dedup by method + normalised path + host + operation — manually queued
                # or skip_dedup entries re-scan. Path is normalised (UUIDs/IDs → {id}) so
                # /users/<uuid-a> and /users/<uuid-b> count as the same logical endpoint
                # and we don't re-scan it once per distinct ID. Matches the enqueue-time
                # dedup key (_ai_mode_seen) so both layers group endpoints identically.
                from dast.ai.coordinator import _extract_operation
                operation = _extract_operation(target)
                scan_key = (entry.method, entry.host, _normalise_dedup_path(entry.path), operation)
                if not manually_queued and not skip_dedup and scan_key in _scanned_keys:
                    logger.debug("Scan skipped — duplicate operation already scanned",
                                 url=entry.url, operation=operation)
                    # Set a terminal scan_result so status polling (e.g. code-hypothesis
                    # validation) stops reporting "scanning" forever — a skip is terminal.
                    self._store.add_finding(entry_id, {}, "safe")
                    qs.finish(entry_id, 0, "skipped", "Duplicate — same endpoint+operation already scanned this session")
                    return
                _scanned_keys.add(scan_key)

                # Host circuit breaker: if this host was already confirmed
                # unreachable this session, skip immediately instead of spending a
                # scan slot on requests that will all fail (DNS/connection error).
                from dast.scanners.active_checks import is_host_dead
                if is_host_dead(entry.host):
                    logger.info("Scan skipped — host unreachable", url=entry.url, host=entry.host)
                    log_event("scan-worker", "warn",
                              f"Scan skipped — host unreachable: {entry.host}",
                              url=entry.url, source="agent")
                    # Terminal result so status polling stops reporting "scanning".
                    self._store.add_finding(entry_id, {}, "error")
                    qs.finish(entry_id, 0, "skipped", f"Host unreachable: {entry.host}")
                    return

                current_task = asyncio.current_task()
                op_label = f" [{operation}]" if operation else ""
                qs.start(entry_id, entry.method, entry.url, entry.host,
                         task=current_task, operation=operation)

                # ── Deterministic layer (AI off) ──────────────────────────────
                # AI mode is off but the user explicitly requested this scan.
                # Run only the deterministic scanners (hidden-parameter mining) —
                # no LLM, no agents. Hits become recon suggestions the operator
                # can act on (or that the AI planner picks up once AI is enabled).
                if not run_agents:
                    log_event("scan-worker", "info",
                              f"Deterministic scan (AI off) — {entry.method} {entry.url}{op_label}",
                              url=entry.url, source="agent")
                    logger.info("Deterministic scan started (AI off)",
                                method=entry.method, url=entry.url)
                    try:
                        hidden = await self._mine_params_for_entry(entry, proxy_url)
                    except asyncio.CancelledError:
                        logger.info("Deterministic scan cancelled by user", url=entry.url)
                        qs.finish(entry_id, 0, "cancelled")
                        return
                    except Exception as e:
                        logger.error("Deterministic scan error", url=entry.url, error=str(e))
                        log_event("scan-worker", "error",
                                  f"Param mining error: {e}", url=entry.url, source="agent")
                        self._store.add_finding(entry_id, {}, "error")
                        qs.finish(entry_id, 0, "error")
                        return
                    # Terminal "safe" result — deterministic mining found no vuln,
                    # only (optionally) fresh attack surface as recon suggestions.
                    self._store.add_finding(entry_id, {}, "safe")
                    log_event("scan-worker", "info",
                              f"Deterministic scan complete — {hidden} hidden param(s); "
                              f"enable AI mode for full agent testing",
                              url=entry.url, source="agent")
                    qs.finish(entry_id, 0, "safe",
                              f"Deterministic scan (AI off): {hidden} hidden param(s) found")
                    return

                log_event("scan-worker", "info",
                          f"Active scan started — {entry.method} {entry.url}{op_label}",
                          url=entry.url, source="agent")
                logger.info("Active scan started", method=entry.method, url=entry.url)
                try:
                    model_id = self._engine_config.get("model_id") or self._ai_model_id or None
                    confidence_threshold = float(self._engine_config.get("confidence_threshold", 0.5))
                    # Imported entries and code-hypothesis entries get the full ceiling budget —
                    # the user explicitly requested them so adaptive cost-cutting is wrong.
                    budget_override = None
                    if entry.source == "imported" or getattr(entry, "import_hints", None):
                        budget_override = float(
                            self._engine_config.get("scan_budget_seconds", 300) or 300
                        )
                    findings = await run_active_checks(
                        target, proxy_url=proxy_url, model_id=model_id,
                        confidence_threshold=confidence_threshold,
                        session_intelligence=self._store.session_intelligence,
                        budget_seconds=budget_override,
                        probe_diff=bool(self._engine_config.get("probe_diff", False)),
                    )
                except asyncio.CancelledError:
                    logger.info("Active scan cancelled by user", url=entry.url)
                    log_event("scan-worker", "info", "Scan cancelled by user", url=entry.url, source="agent")
                    qs.finish(entry_id, 0, "cancelled")
                    return
                except Exception as e:
                    from dast.ai.bedrock_client import AiUnavailableError
                    if isinstance(e, AiUnavailableError):
                        logger.warning("AI unavailable — pausing scan queue", error=str(e))
                        log_event("scan-worker", "warn",
                                  "AI offline: AWS credentials expired — scan queue paused. "
                                  "Run 'aws sso login' then click Resume in the dashboard.",
                                  url=entry.url, source="agent")
                        qs.pause()
                        qs.finish(entry_id, 0, "error")
                        return
                    logger.error("Active scan error", url=entry.url, error=str(e))
                    log_event("scan-worker", "error", f"Scan error: {e}", url=entry.url, source="agent")
                    _update_import_stubs(entry, False, error=True)
                    self._store.add_finding(entry_id, {"error": str(e)}, "error")
                    qs.finish(entry_id, 0, "error")
                    return

                # Update any stub imported findings on this entry to reflect scan outcome
                _update_import_stubs(entry, bool(findings))

                if findings:
                    for f in findings:
                        validated_by = _detection_method(f)
                        finding_dict = {
                            "title":        getattr(f, "title", ""),
                            "severity":     getattr(f, "severity", "info"),
                            "cwe":          getattr(f, "cwe", ""),
                            "attack_type":  getattr(f, "attack_type", ""),
                            "evidence":     (getattr(f, "evidence", "") or "")[:400],
                            "payload":      (getattr(f, "payload", "") or "")[:200],
                            "parameter":    getattr(f, "parameter", ""),
                            "confirmed":    True,
                            "validated_by": validated_by,
                            "reasoning":    getattr(f, "reasoning", ""),
                        }
                        # Record WHEN the AI confirmed this finding so the UI can
                        # distinguish a historical AI verdict from current AI
                        # availability (the live "AI offline" status is decoupled).
                        if "ai" in validated_by:
                            finding_dict["validated_at"] = datetime.now(timezone.utc).isoformat()
                        snippet = getattr(f, "raw_response_snippet", "")
                        if snippet:
                            finding_dict["snippet"] = snippet[:400]
                        browser_confirmed = getattr(f, "browser_confirmed", None)
                        if browser_confirmed is not None:
                            finding_dict["browser_confirmed"] = browser_confirmed
                        browser_reason = getattr(f, "browser_confirm_reason", "")
                        if browser_reason:
                            finding_dict["browser_confirm_reason"] = browser_reason
                        raw_request = getattr(f, "raw_request", "")
                        if raw_request:
                            finding_dict["raw_request"] = raw_request[:6000]
                        raw_response = getattr(f, "raw_response", "")
                        if raw_response:
                            finding_dict["raw_response"] = raw_response[:6000]
                        probe_request = getattr(f, "probe_request", "")
                        if probe_request:
                            finding_dict["probe_request"] = probe_request[:6000]
                        probe_response = getattr(f, "probe_response", "")
                        if probe_response:
                            finding_dict["probe_response"] = probe_response[:6000]
                        self._store.add_finding(entry_id, finding_dict, "vulnerable")
                        log_event(
                            getattr(f, "attack_type", "agent"),
                            "finding",
                            f"{getattr(f, 'title', '')} — param: {getattr(f, 'parameter', '')}",
                            url=entry.url,
                            finding=getattr(f, "title", ""),
                            source="agent",
                        )
                    logger.warning("Active scan: VULNERABLE", url=entry.url, findings=len(findings))
                    qs.finish(entry_id, len(findings), "vulnerable")
                else:
                    self._store.add_finding(entry_id, {}, "safe")
                    log_event("scan-worker", "info", "Scan complete — no findings",
                              url=entry.url, source="agent")
                    logger.info("Active scan: safe", url=entry.url)
                    qs.finish(entry_id, 0, "safe")

        # Tracks normalised path patterns already queued in AI mode this session
        # e.g. ("GET", "api.x.com", "/users/{id}") — avoids scanning 100 user IDs
        _ai_mode_seen: set = set()

        async def _ai_mode_listener(entry) -> None:
            """Queue completed in-scope entries for scan when AI mode is active.

            Uses LLM planner (via Coordinator) to decide which agents to run —
            so header-only attacks on GET /health are still caught.
            Deduplicates on normalised path pattern so /users/123 and /users/456
            don't both get scanned.
            """
            if not self._store.ai_mode:
                return
            if entry.source in ("agent", "out-of-scope", "imported"):
                return
            if entry.response_status is None:
                return
            if entry.queued_for_scan or entry.scan_result:
                return
            if not self._settings.is_in_scope(entry.url):
                return

            # Normalise path: replace UUIDs, numeric IDs, and hex strings with {id}
            norm_path = _normalise_dedup_path(entry.path)
            pattern_key = (entry.method, entry.host, norm_path)
            if pattern_key in _ai_mode_seen:
                return
            _ai_mode_seen.add(pattern_key)

            entry.queued_for_scan = True
            qs.enqueue(entry.id, entry.method, entry.url, entry.host)
            try:
                # Non-blocking so a backed-up scan queue never stalls proxy ingestion.
                self._scan_queue.put_nowait(entry.id)
            except asyncio.QueueFull:
                # Revert so the entry can be re-queued later (manually or on next pass)
                entry.queued_for_scan = False
                qs.dequeue(entry.id)
                logger.warning("Scan queue full — dropping auto-queued entry",
                               url=entry.url, qsize=self._scan_queue.qsize())
                from dast.proxy.plugin_manager import log_event
                log_event("scan-worker", "warn",
                          f"Scan queue full ({self._scan_queue.qsize()}) — skipped auto-queue for {entry.url}",
                          url=entry.url, source="agent")

        self._store.add_listener(_ai_mode_listener)

        while True:
            entry_id = await self._scan_queue.get()
            qs.dequeue(entry_id)
            asyncio.create_task(_attack_one(entry_id))


_ID_RE = re.compile(
    r"(?<=/)"                                     # preceded by /
    r"(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"  # UUID
    r"|[0-9]{2,}"                                 # numeric ID (2+ digits)
    r"|[0-9a-f]{24,})"                            # hex ID (MongoDB ObjectId etc)
    r"(?=/|$)",                                   # followed by / or end
    re.IGNORECASE,
)


def _normalise_dedup_path(path: str) -> str:
    """Replace variable path segments (IDs, UUIDs) with {id} for dedup."""
    return _ID_RE.sub("{id}", path.split("?")[0])


def _update_import_stubs(entry: "ProxyEntry", found_vulnerabilities: bool, error: bool = False) -> None:
    """
    After an active scan completes on an imported/code-hypothesis entry, update any
    stub findings (import_status='queued') to reflect whether the scan confirmed
    the hypothesis or ruled it safe.

    When the scan finds no vulnerability:
      - import_status → "unconfirmed"
      - confirmed → False  (removes it from the Issues panel and dashboard counts)

    When the scan confirms a vulnerability:
      - import_status → "confirmed"
      - confirmed stays True (new AgentFinding already added by the scan)

    On error: import_status → "error", confirmed stays True (benefit of the doubt).
    """
    for f in entry.findings:
        if f.get("import_status") == "queued":
            base = f.get("reasoning", "").split(" — active")[0]
            if error:
                f["import_status"] = "error"
                f["reasoning"] = base + " — Active DAST scan errored before completing."
                # Leave confirmed=True on error — benefit of the doubt
            elif found_vulnerabilities:
                f["import_status"] = "confirmed"
                f["reasoning"] = base + " — Active DAST scan confirmed a finding on this endpoint."
            else:
                f["import_status"] = "unconfirmed"
                f["confirmed"] = False   # demote — no longer treated as a real finding
                f["reasoning"] = base + " — Active DAST scan found no exploitable vulnerability on this endpoint."


def _entry_to_check_target(entry: ProxyEntry, store=None):
    """Convert a ProxyEntry into a CheckTarget for the active scanner."""
    from urllib.parse import parse_qs, urlparse
    import json as _json
    from dast.scanners.active_checks import CheckTarget, ServiceContext

    if entry.method == "CONNECT":
        return None

    parsed = urlparse(entry.url)

    # Skip paths that would destroy session state or application data.
    # Match the last path segment to catch /auth/logout, /api/v1/logout, etc.
    _last_seg = parsed.path.lower().rstrip("/").rsplit("/", 1)[-1]
    if _last_seg in _DANGEROUS_SEGMENTS:
        logger.debug("Scan skipped — session-destructive path", url=entry.url, segment=_last_seg)
        return None
    params = []

    for name, values in parse_qs(parsed.query).items():
        params.append({"name": name, "location": "query", "value": values[0] if values else ""})

    content_type = entry.request_headers.get("content-type", "").lower()

    # Only text-based content types can carry injectable parameters.
    # Binary bodies (images, audio, video, archives, protobuf, etc.) must never be
    # modified — doing so corrupts uploads and produces no useful security signal.
    _FUZZABLE_CT = (
        "application/json",
        "application/x-www-form-urlencoded",
        "application/graphql",
        "text/",
        "application/xml",
        "application/soap+xml",
    )
    _is_fuzzable_ct = any(content_type.startswith(ct) or ct in content_type for ct in _FUZZABLE_CT)
    _is_multipart = "multipart/form-data" in content_type

    raw_body: Optional[bytes] = None
    body_str = ""

    # For imported entries whose LLM-inferred body is prose (not real structured data),
    # try to borrow the real body from a browse/proxy entry on the same host + path.
    # This gives agents real parameter values and IDs instead of fictional placeholder text.
    if entry.source == "imported" and store is not None and entry.method in ("POST", "PUT", "PATCH"):
        _current_body_str = (entry.request_body or b"").decode("utf-8", errors="replace").strip()
        _body_looks_fake = (
            not _current_body_str
            or (not _current_body_str.startswith("{")
                and not _current_body_str.startswith("[")
                and "=" not in _current_body_str[:100])
        )
        if _body_looks_fake:
            try:
                from urllib.parse import urlparse as _up_borrow
                _borrow_path = _up_borrow(entry.url).path
                _borrow_segs = [s for s in _borrow_path.split("/") if s]
                _borrow_prefix = "/" + "/".join(_borrow_segs[:-1]) if len(_borrow_segs) > 1 else _borrow_path
                for _be in reversed(store.all_entries()):
                    if _be.source in ("agent", "imported"):
                        continue
                    if _be.host != entry.host:
                        continue
                    if _be.method != entry.method:
                        continue
                    if not _be.request_body:
                        continue
                    _be_path = _up_borrow(_be.url).path
                    if _be_path == _borrow_path or _be_path.startswith(_borrow_prefix):
                        _bs = _be.request_body[:200].decode("utf-8", errors="replace").strip()
                        if _bs.startswith("{") or _bs.startswith("[") or "=" in _bs[:80]:
                            entry.request_body = _be.request_body
                            _borrowed_ct = _be.request_headers.get("content-type", "")
                            if _borrowed_ct and not entry.request_headers.get("content-type"):
                                entry.request_headers = dict(entry.request_headers)
                                entry.request_headers["content-type"] = _borrowed_ct
                            content_type = _borrowed_ct.lower()
                            logger.debug(
                                "imported entry: borrowed real body from browse",
                                url=entry.url,
                                donor=_be_path,
                                body_len=len(_be.request_body),
                            )
                            break
            except Exception as _borrow_exc:
                logger.debug("imported entry: body borrow failed", error=str(_borrow_exc))

    if entry.request_body and (_is_fuzzable_ct or _is_multipart or not content_type):
        body_raw = entry.request_body
        body_str = body_raw.decode("utf-8", errors="replace")

        if _is_multipart or "webkitformboundary" in body_str[:200].lower():
            raw_body = body_raw  # kept for agents to inject into

            # Extract each file part's filename and Content-Type as fuzzable params.
            # Param name encodes both the field kind and the form-field name so the
            # injector knows which MIME header to rewrite, e.g.:
            #   multipart_filename:artwork   → rewrites  filename="..."
            #   multipart_ct:artwork         → rewrites  Content-Type: ...
            # The binary payload between CRLFCRLF and the next boundary is never touched.
            for m in re.finditer(
                r'Content-Disposition:[^\r\n]*?name="([^"]+)"'
                r'(?:[^\r\n]*?;\s*filename="([^"]*)")?'
                r'[^\r\n]*\r?\n(?:Content-Type:\s*([^\r\n]+))?',
                body_str,
            ):
                part_name = m.group(1)
                filename = m.group(2)
                part_ct = m.group(3)
                if filename is not None:
                    params.append({
                        "name": f"multipart_filename:{part_name}",
                        "location": "multipart_filename",
                        "value": filename,
                    })
                    # File parts: allow agents to replace the entire content
                    # (e.g. replace image bytes with an XSS probe or SSRF URL)
                    params.append({
                        "name": f"multipart_body:{part_name}",
                        "location": "multipart_body",
                        "value": "",
                    })
                if part_ct:
                    params.append({
                        "name": f"multipart_ct:{part_name}",
                        "location": "multipart_ct",
                        "value": part_ct.strip(),
                    })

            # Also parse the `operations` field for GraphQL variables (GraphQL-over-multipart)
            ops_match = re.search(
                r'name=["\']operations["\']\r?\n\r?\n(\{.*?\})\r?\n--',
                body_str, re.DOTALL,
            )
            body_str = ops_match.group(1) if ops_match else ""

    if body_str:
        try:
            data = _json.loads(body_str)
            if isinstance(data, dict):
                # GraphQL: extract variables as the actual parameters to fuzz.
                # Top-level keys (query, operationName, variables) are structural —
                # injecting payloads into the raw `query` string breaks GraphQL syntax.
                if "query" in data and isinstance(data.get("variables"), dict):
                    def _flatten_vars(obj: dict, prefix: str) -> None:
                        for k, v in obj.items():
                            full_key = f"{prefix}.{k}" if prefix else k
                            if isinstance(v, dict):
                                _flatten_vars(v, full_key)
                            elif isinstance(v, (str, int, float, bool)):
                                params.append({"name": full_key, "location": "body_graphql", "value": str(v)[:200]})
                    _flatten_vars(data["variables"], "")
                else:
                    # Flatten nested objects so nested fields are individually testable
                    # e.g. {"address":{"city":"x"}} → param "address.city" with value "x"
                    def _flatten_json(obj: dict, prefix: str) -> None:
                        for k, v in obj.items():
                            full_key = f"{prefix}.{k}" if prefix else k
                            if isinstance(v, dict):
                                _flatten_json(v, full_key)
                            elif isinstance(v, list):
                                params.append({"name": full_key, "location": "body", "value": str(v)[:200]})
                            else:
                                params.append({"name": full_key, "location": "body", "value": str(v) if v is not None else ""})
                    _flatten_json(data, "")
        except Exception:
            for part in body_str.split("&"):
                if "=" in part:
                    k, _, v = part.partition("=")
                    params.append({"name": k, "location": "body", "value": v})

    # For GET entries with no detected params, try to extract params from import_hints
    # (e.g. code hypotheses where suggested_payload = "username=victim@example.com")
    if not params and entry.method == "GET":
        for hint in (entry.import_hints or []):
            raw_payload = hint.get("payload", "") or ""
            # Extract "key=value" pairs from the payload string
            for part in raw_payload.split("&"):
                if "=" in part:
                    k, _, v = part.partition("=")
                    k = k.strip().lstrip("?")
                    if k:
                        params.append({"name": k, "location": "query", "value": v.strip()})
            param_name = hint.get("parameter", "")
            if param_name and not any(p["name"] == param_name for p in params):
                params.append({"name": param_name, "location": "query", "value": ""})
        # Still no params — skip (nothing for agents to fuzz)
        if not params:
            return None

    # Build service context (Layer 2) from the service graph if available
    service_context = None
    if store is not None:
        group = store.service_graph.group_for_host(entry.host)
        if group and len(group.hosts) > 1:
            service_context = ServiceContext(
                group_id=group.id,
                sibling_hosts=[h for h in group.hosts if h != entry.host],
                shared_tokens=list(group.shared_tokens),
                shared_cookies=dict(group.shared_cookies),
            )

    # Build discovery context (Layer 3) — tech stack, JS endpoints, call chains
    discovery_context = None
    if store is not None:
        discovery_context = store.discovery_engine.enrich_target(entry.host, entry.url, params)

    # Build app profile hint (Layer 4) — LLM-synthesised app intelligence
    app_profile_hint = ""
    if store is not None:
        profile = store.discovery_engine.get_app_profile(entry.host)
        if profile:
            hint = profile.to_coordinator_hint()
            if hint:
                app_profile_hint = hint

    # Append Blazor circuit intelligence so the Blazor agent can fuzz with
    # real handler IDs observed in intercepted traffic (via BlazorDetectorPlugin).
    if store is not None and store.session_intelligence is not None:
        try:
            host_intel = store.session_intelligence.get(entry.host)
            handler_ids = host_intel.get_blazor_handler_ids()
            input_fields = host_intel.get_blazor_input_fields()
            if handler_ids:
                ids_str = ",".join(str(h) for h in handler_ids[:30])
                app_profile_hint += f"\nblazor_handler_ids: {ids_str}"
            if input_fields:
                app_profile_hint += f"\nblazor_input_fields: {','.join(input_fields[:10])}"
        except Exception:
            pass

    # Build threat model hint — architectural constraints for red-team validator
    threat_model_hint = ""
    if store is not None:
        threat_model = store.discovery_engine.get_threat_model(entry.host)
        if threat_model:
            hint = threat_model.to_validator_hint()
            if hint:
                threat_model_hint = hint

    # Build code hint — source code snippets relevant to this URL path
    code_hint = ""
    try:
        from urllib.parse import urlparse as _urlparse
        from dast.code_analysis import lookup_code_for_path
        _url_path = _urlparse(entry.url).path
        if _url_path and _url_path != "/":
            code_hint = lookup_code_for_path(_url_path)
    except Exception:
        pass

    named_sessions = store.get_named_sessions() if store is not None else []

    return CheckTarget(
        method=entry.method,
        url=entry.url,
        headers=dict(entry.request_headers),
        body=body_str or None,
        params=params,
        raw_body=raw_body,
        service_context=service_context,
        discovery_context=discovery_context,
        app_profile_hint=app_profile_hint,
        threat_model_hint=threat_model_hint,
        code_hint=code_hint,
        import_hints=list(entry.import_hints) if entry.import_hints else None,
        named_sessions=named_sessions if named_sessions else None,
    )
