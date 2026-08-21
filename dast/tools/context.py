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
