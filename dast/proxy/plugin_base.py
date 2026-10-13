"""
Plugin base class for Frieren DAST-AI proxy plugins.

Each plugin is a Python file in:
  - dast/plugins/        (built-in)
  - ~/.dast-ai/plugins/  (user-installed)

A plugin must define a class that inherits ProxyPlugin and set class-level
metadata attributes. The plugin manager discovers and instantiates it automatically.

Lifecycle:
  setup()              — called once when the proxy starts
  on_entry()           — called after every proxied request/response is recorded (passive)
  on_active_probe()    — called when a scanned entry qualifies for active probing;
                         receives an httpx.AsyncClient so the plugin can send HTTP
                         requests. Results recorded via store.record_plugin_request().
  teardown()           — called once when the proxy stops
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import httpx
    from dast.proxy.session_store import ProxyEntry, SessionStore


# Entry sources whose requests the scanner synthesized itself (agent attack
# payloads, param-discovery probes, probe-diff baselines) rather than genuine
# application or user traffic. Observers that judge "what the app does" must skip
# them: flagging our own injected requests is a self-inflicted false positive, and
# re-enqueueing them feeds the scan queue with its own probes.
SYNTHETIC_SOURCES = frozenset({"param-mining", "probe-diff", "agent", "vuln-agent"})


class ProxyPlugin:
    # --- metadata (override in subclass) ---
    name: str        = "unnamed"
    description: str = ""
    version: str     = "0.1.0"
    author: str      = ""

    # Set to False to disable by default; user can toggle in dashboard
    enabled: bool = True

    # Set to True if this plugin sends active HTTP probes (shown in dashboard)
    active: bool = False

    async def setup(self) -> None:
        """Called once when the plugin is loaded."""

    async def on_entry(self, entry: "ProxyEntry", store: "SessionStore") -> None:
        """
        Called after every proxied request/response pair is recorded (passive).
        No HTTP client — observe only, no outbound requests.
        Use store.add_finding(entry.id, {...}, status) to attach findings.
        """

    async def on_active_probe(
        self,
        entry: "ProxyEntry",
        store: "SessionStore",
        client: "httpx.AsyncClient",
    ) -> None:
        """
        Called for each in-scope entry that has been queued for active scanning.
        The plugin may send HTTP requests via `client`.
        Use store.record_plugin_request(plugin_name, method, url, ...) to register
        outbound requests so they appear in the proxy history.
        Override only in active plugins (set active = True).
        """

    async def teardown(self) -> None:
        """Called once when the proxy stops."""
