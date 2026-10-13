"""
Proxy runner — starts proxy + dashboard + scan worker together.

Three concurrent tasks:
  1. ProxyServer   — asyncio TCP server on :8080
  2. Dashboard     — uvicorn/FastAPI on :8088, WebSocket push
  3. Scan worker   — drains scan_queue, runs AttackEngine per entry
"""

import asyncio
import socket
import webbrowser
from typing import Optional

import uvicorn

import dast.agents  # noqa: F401 — registers all VulnAgent subclasses with Coordinator
from dast.models import ScanConfig
from dast.proxy.cert_authority import CertAuthority
from dast.proxy.dashboard_server import build_app
from dast.proxy.proxy_server import ProxyServer
from dast.proxy.session_store import SessionStore
from dast.proxy.workers.browse_worker import run_browse_worker
from dast.proxy.workers.login_worker import run_login_worker
from dast.proxy.workers.recon_workers import run_crawl_worker, run_discovery_worker
from dast.proxy.workers.scan_worker import run_scan_worker
from dast.utils.logger import get_logger

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
            # Concurrent probes PER endpoint scan (the global pool is this x workers,
            # see _scan_worker). 4 gives time-based blind probes enough throughput to
            # confirm within budget even when several endpoints scan at once.
            "probe_concurrency": 4,
            # How many endpoint scans may run concurrently against ONE host. Default
            # 1 (serialize per host) so a single-worker target's slower agents are not
            # starved of their per-endpoint budget by sibling scans time-slicing the
            # same backend (see active_checks._HostScanGate). Different hosts still
            # scan in parallel up to `workers`. Raise for genuinely scalable targets.
            "host_scan_concurrency": 1,
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

        # Pointing --auth-url at a host declares it the target, so make sure that
        # host is in the proxy scope. Otherwise its traffic records as
        # "out-of-scope" and its findings are silently dropped from the Findings
        # tab / report (in_scope_entries filters them out) even though we probed it.
        if self._auth_url and self._settings is not None:
            try:
                from urllib.parse import urlparse as _urlparse_scope
                auth_host = (_urlparse_scope(self._auth_url).hostname or "").strip()
                if auth_host and not self._settings.is_in_scope(self._auth_url):
                    self._settings.add_scope_rule({
                        "protocol": "any", "host": auth_host,
                        "port": "", "file": "", "kind": "include",
                    })
                    logger.info("Added auth-url host to proxy scope", host=auth_host)
            except Exception as exc:
                logger.warning("Could not add auth-url host to scope", error=str(exc))

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
                    # Seed the shared cookie jar too, so the copilot's send_request
                    # and the crawler (which read the store jar, not the scan pool)
                    # are authenticated — not just the scanner's browser contexts.
                    try:
                        seeded = self._store.import_playwright_cookies(state.get("cookies", []))
                        logger.info("Auth state applied to proxy scan pool and cookie jar",
                                    jar_cookies=seeded)
                    except Exception as exc:
                        logger.warning("Could not seed cookie jar from login", error=str(exc))
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
            run_scan_worker(self, config, session_mgr),
            run_crawl_worker(self, crawl_queue),
            run_discovery_worker(self, discovery_queue),
            run_browse_worker(self, browse_queue),
            run_login_worker(self, login_queue),
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
