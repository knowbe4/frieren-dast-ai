"""
DiscoveryEngine — orchestrates all discovery modules and maintains per-host
DiscoveryContext objects that are injected into CheckTarget.

Called from two places:
  1. session_store.complete_entry() → observe_entry() (runs on every proxied response)
  2. runner._entry_to_check_target() → context_for_host() (read when building CheckTarget)

Thread-safe — individual modules handle their own locking.
"""

from __future__ import annotations

import asyncio
import re
import threading
from typing import Dict, Optional, TYPE_CHECKING

from dast.discovery.fingerprinter import fingerprint, merge_tech_stacks
from dast.discovery.js_analyzer import extract_endpoints
from dast.discovery.models import DiscoveryContext
from dast.discovery.openapi_probe import OpenApiProbe, endpoints_from_schema
from dast.discovery.traffic_graph import TrafficGraph
from dast.utils.logger import get_logger

# Imported lazily to avoid circular imports at module load time
_AppContextWorker = None

if TYPE_CHECKING:
    from dast.proxy.session_store import ProxyEntry

logger = get_logger(__name__)

_IS_JS = re.compile(r"javascript|ecmascript", re.I)
_IS_JSON = re.compile(r"application/json", re.I)
_MAX_JS_SIZE = 2 * 1024 * 1024  # 2 MB — skip minified megabundles beyond this


class DiscoveryEngine:
    """
    Singleton-style engine shared across the proxy session.
    Maintains DiscoveryContext per host, updated incrementally as traffic flows.
    """

    def __init__(self) -> None:
        self._contexts: Dict[str, DiscoveryContext] = {}
        self._lock = threading.Lock()
        self._traffic_graph = TrafficGraph()
        self._openapi_probe = OpenApiProbe()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._app_context_worker = None   # set by runner after store is ready
        self._threat_model_worker = None  # set by runner after store is ready

    def set_event_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def set_app_context_worker(self, worker) -> None:
        self._app_context_worker = worker

    def set_threat_model_worker(self, worker) -> None:
        self._threat_model_worker = worker

    def get_app_profile(self, host: str):
        if self._app_context_worker:
            return self._app_context_worker.get_profile(host)
        return None

    def all_app_profiles(self) -> dict:
        if self._app_context_worker:
            return self._app_context_worker.all_profiles()
        return {}

    def get_threat_model(self, host: str):
        if self._threat_model_worker:
            return self._threat_model_worker.get_model(host)
        return None

    def all_threat_models(self) -> dict:
        if self._threat_model_worker:
            return self._threat_model_worker.all_models()
        return {}

    # ── main entry point (called per proxied entry) ────────────────────

    def observe_entry(self, entry: "ProxyEntry") -> None:
        """
        Update discovery context from a completed proxy entry.
        Synchronous — does not block the proxy. OpenAPI probe is scheduled async.
        """
        host = entry.host
        if not host:
            return

        ctx = self._get_or_create(host)

        # 1. Tech stack fingerprinting (zero cost, always run)
        new_stack = fingerprint(entry)
        if new_stack is not None:
            with self._lock:
                ctx.tech_stack = merge_tech_stacks(ctx.tech_stack, new_stack)

        # 2. JS analysis — extract endpoints from captured bundles
        ct = entry.content_type or ""
        if _IS_JS.search(ct) and entry.response_body:
            size = len(entry.response_body)
            if size <= _MAX_JS_SIZE:
                try:
                    js_text = entry.response_body.decode("utf-8", errors="replace")
                    new_eps = extract_endpoints(js_text)
                    if new_eps:
                        with self._lock:
                            existing_keys = {(ep.method, ep.path) for ep in ctx.api_endpoints}
                            for ep in new_eps:
                                if (ep.method, ep.path) not in existing_keys:
                                    ctx.api_endpoints.append(ep)
                                    existing_keys.add((ep.method, ep.path))
                        logger.debug(
                            "JS analysis: endpoints extracted",
                            host=host,
                            count=len(new_eps),
                            url=entry.url,
                        )
                except Exception as e:
                    logger.debug("JS analysis error", host=host, error=str(e))

        # 3. Traffic graph — index JSON responses + detect call chains
        if _IS_JSON.search(ct):
            self._traffic_graph.observe_response(host, entry.url, entry.response_body)

        # 4. OpenAPI probe — fire once per new host (async, non-blocking)
        if not self._openapi_probe.already_checked(host) and self._loop:
            scheme = "https" if entry.url.startswith("https") else "http"
            asyncio.run_coroutine_threadsafe(
                self._run_openapi_probe(host, scheme, ctx),
                self._loop,
            )

    async def _run_openapi_probe(
        self, host: str, scheme: str, ctx: DiscoveryContext
    ) -> None:
        try:
            schema = await self._openapi_probe.probe_host(host, scheme)
            if schema:
                endpoints = endpoints_from_schema(schema)
                with self._lock:
                    ctx.openapi_schema = schema
                    existing_keys = {(ep.method, ep.path) for ep in ctx.api_endpoints}
                    added = 0
                    for ep in endpoints:
                        if (ep.method, ep.path) not in existing_keys:
                            ctx.api_endpoints.append(ep)
                            existing_keys.add((ep.method, ep.path))
                            added += 1
                logger.info(
                    "OpenAPI schema loaded",
                    host=host,
                    total_endpoints=len(endpoints),
                    new_endpoints=added,
                )
        except Exception as e:
            logger.debug("OpenAPI probe error", host=host, error=str(e))

    # ── called when building CheckTarget ──────────────────────────────

    def enrich_target(self, host: str, url: str, params: list) -> Optional[DiscoveryContext]:
        """
        Observe the outgoing request params against the traffic graph, then
        return the current DiscoveryContext for the host (may be None if nothing found yet).
        """
        if params:
            self._traffic_graph.observe_request(host, url, params)

        ctx = self._contexts.get(host)
        if ctx is None:
            return None

        # Attach current call edges for this URL
        edges = self._traffic_graph.edges_for_url(url)
        if edges:
            with self._lock:
                existing_keys = {
                    (e.source_url, e.source_field, e.target_url, e.target_param)
                    for e in ctx.call_edges
                }
                for edge in edges:
                    key = (edge.source_url, edge.source_field, edge.target_url, edge.target_param)
                    if key not in existing_keys:
                        ctx.call_edges.append(edge)
                        existing_keys.add(key)

        # Return context only if it has useful content
        if ctx.tech_stack or ctx.api_endpoints or ctx.call_edges or ctx.openapi_schema:
            return ctx
        return None

    def context_for_host(self, host: str) -> Optional[DiscoveryContext]:
        return self._contexts.get(host)

    # ── internals ──────────────────────────────────────────────────────

    def _get_or_create(self, host: str) -> DiscoveryContext:
        with self._lock:
            if host not in self._contexts:
                self._contexts[host] = DiscoveryContext(host=host)
            return self._contexts[host]
