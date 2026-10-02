"""
ToolContext — the runtime dependencies a shared tool needs.

The same tool layer powers two callers:
  - the internal agentic triage loop, which runs IN-PROCESS with the live proxy
    and passes its SessionStore + ProxySettings directly, and
  - the MCP server (``dast-ai mcp``), a SEPARATE process that drives an
    already-running Frieren over the proxy port (for sending) and the dashboard
    HTTP API (for reading live state). It has no in-process store, so tools fall
    back to the dashboard base URL.

A tool reads ``ctx.store`` when present (fast, in-process) and otherwise talks to
``ctx.dashboard_base_url``. Scope is always enforced through ``ctx.get_settings()``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from dast.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ToolContext:
    """Dependencies shared by every tool. All fields have safe defaults so an
    external (MCP) caller can construct one from just the ports."""

    proxy_port: int = 8080
    dashboard_port: int = 8088
    # In-process SessionStore for internal callers; None for the MCP process.
    store: Optional[Any] = None
    # ProxySettings (scope enforcement). Lazily constructed from disk if None so
    # the MCP process inherits the same scope rules the running proxy uses.
    settings: Optional[Any] = None
    # Async plumbing for orchestration tools (``crawl``, ``run_scan``). Present
    # ONLY for the in-process copilot driver; left None for the MCP process and
    # the internal triage loop, so those callers get a graceful "not available in
    # this context" from those tools instead of a crash. These are the same queue
    # objects ProxyRunner hands to the scan worker and crawl worker.
    scan_queue: Optional[Any] = None
    scan_queue_state: Optional[Any] = None
    crawl_queue: Optional[Any] = None
    # Proxy-history source tag for request-sending tools (e.g. "copilot"). When
    # set, send-style tools stamp the x-dast-source header so the operator can
    # tell copilot-generated traffic apart from manual browsing in the history.
    source_label: Optional[str] = None
    # Session-safe mode: the target enforces strict/single-concurrent sessions,
    # so heavy automated traffic (ambient auto-scan, large crawls) would trip
    # concurrent-session detection and log the shared cookie out. Tools consult
    # this to throttle their own volume (e.g. crawl caps its click budget).
    session_safe: bool = False
    # Live browser the agent can drive (navigate/fill/click/snapshot) for form
    # workflows that need fresh CSRF tokens. Present only for the in-process
    # copilot; None elsewhere, so the browser_* tools degrade gracefully.
    browser: Optional[Any] = None

    def get_settings(self) -> Any:
        """Return the scope settings, building a disk-backed default on first use."""
        if self.settings is None:
            try:
                from dast.proxy.proxy_settings import ProxySettings
                self.settings = ProxySettings()
            except Exception as exc:
                logger.warning("ToolContext could not load ProxySettings", error=str(exc))
                self.settings = None
        return self.settings

    def is_in_scope(self, url: str) -> bool:
        """Scope gate. With no settings available, default to in-scope=False for
        safety (an external caller must have loadable scope rules to send)."""
        settings = self.get_settings()
        if settings is None:
            return False
        try:
            return bool(settings.is_in_scope(url))
        except Exception as exc:
            logger.warning("scope check failed", url=url[:120], error=str(exc))
            return False

    @property
    def proxy_url(self) -> str:
        return f"http://127.0.0.1:{self.proxy_port}"

    @property
    def dashboard_base_url(self) -> str:
        return f"http://127.0.0.1:{self.dashboard_port}"


class AgentToolContext(ToolContext):
    """ToolContext whose scope gate also honors a per-job approved-host set.

    Scope relaxation is confined to this agent run: a host the operator approves
    at an approve-pause becomes in-scope for the tools without touching the
    process-wide scan scope or any other job.
    """

    def __init__(self, *, approved_hosts: Optional[set] = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.approved_hosts: set = approved_hosts if approved_hosts is not None else set()

    def is_in_scope(self, url: str) -> bool:
        if super().is_in_scope(url):
            return True
        try:
            from urllib.parse import urlparse
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            return False
        return bool(host) and host in self.approved_hosts
