"""
Plugin manager — discovers, loads, and runs ProxyPlugin subclasses.

Search order:
  1. dast/plugins/        (built-in plugins shipped with the package)
  2. ~/.dast-ai/plugins/  (user-installed plugins)
"""

from __future__ import annotations

import collections
import importlib.util
import inspect
import sys
import time
from pathlib import Path
from typing import List, TYPE_CHECKING

from dast.proxy.plugin_base import ProxyPlugin
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.proxy.session_store import ProxyEntry, SessionStore

logger = get_logger(__name__)

_BUILTIN_DIR = Path(__file__).parent.parent / "plugins"
_USER_DIR    = Path.home() / ".dast-ai" / "plugins"

# Rolling event log — last 500 plugin events, exposed via /api/logs
_event_log: collections.deque = collections.deque(maxlen=500)


def log_event(
    plugin: str,
    level: str,
    message: str,
    url: str = "",
    finding: str = "",
    source: str = "plugin",
) -> None:
    """Append an event to the global system log."""
    _event_log.appendleft({
        "ts":      time.time(),
        "source":  source,   # "plugin" | "agent" | "browser" | "crawler" | "system"
        "plugin":  plugin,
        "level":   level,    # "info" | "finding" | "warn" | "error" | "system"
        "message": message,
        "url":     url,
        "finding": finding,
    })


class PluginManager:
    def __init__(self) -> None:
        self._plugins: List[ProxyPlugin] = []

    # ── discovery ──────────────────────────────────────────────────────

    def load_all(self) -> None:
        for directory in [_BUILTIN_DIR, _USER_DIR]:
            if not directory.exists():
                continue
            for path in sorted(directory.glob("*.py")):
                if path.name.startswith("_"):
                    continue
                self._load_file(path)
        logger.info("Plugins loaded", count=len(self._plugins),
                    names=[p.name for p in self._plugins])

    def _load_file(self, path: Path) -> None:
        module_name = f"dast_plugin_{path.stem}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
        except Exception as e:
            logger.warning("Failed to load plugin", path=str(path), error=str(e))
            return

        for _, cls in inspect.getmembers(module, inspect.isclass):
            if cls is ProxyPlugin:
                continue
            if issubclass(cls, ProxyPlugin):
                try:
                    instance = cls()
                    self._plugins.append(instance)
                    logger.info("Plugin registered", name=instance.name, path=str(path))
                except Exception as e:
                    logger.warning("Failed to instantiate plugin", cls=cls.__name__, error=str(e))

    # ── lifecycle ──────────────────────────────────────────────────────

    async def setup_all(self) -> None:
        for p in self._plugins:
            if p.enabled:
                try:
                    await p.setup()
                except Exception as e:
                    logger.warning("Plugin setup error", name=p.name, error=str(e))

    async def teardown_all(self) -> None:
        for p in self._plugins:
            try:
                await p.teardown()
            except Exception as e:
                logger.warning("Plugin teardown error", name=p.name, error=str(e))

    async def dispatch(self, entry: "ProxyEntry", store: "SessionStore") -> None:
        for p in self._plugins:
            if not p.enabled:
                continue
            before = len(entry.findings)
            try:
                await p.on_entry(entry, store)
            except Exception as e:
                logger.warning("Plugin on_entry error", name=p.name, error=str(e))
                log_event(p.name, "error", str(e), url=entry.url)
                continue
            after = len(entry.findings)
            for f in entry.findings[before:after]:
                log_event(
                    plugin=p.name,
                    level="finding",
                    message=f.get("title", "Finding"),
                    url=entry.url,
                    finding=f.get("title", ""),
                )

    async def dispatch_active(
        self,
        entry: "ProxyEntry",
        store: "SessionStore",
        proxy_url: str = "",
    ) -> None:
        """Call on_active_probe() on all enabled active plugins."""
        active_plugins = [p for p in self._plugins if p.enabled and p.active]
        if not active_plugins:
            return
        import httpx
        timeout = httpx.Timeout(15.0)
        proxies = {"http://": proxy_url, "https://": proxy_url} if proxy_url else None
        async with httpx.AsyncClient(
            verify=False,
            timeout=timeout,
            follow_redirects=True,
            **({"proxies": proxies} if proxies else {}),
        ) as client:
            for p in active_plugins:
                try:
                    await p.on_active_probe(entry, store, client)
                except Exception as e:
                    logger.warning("Plugin on_active_probe error", name=p.name, error=str(e))

    # ── dashboard API ──────────────────────────────────────────────────

    def list_plugins(self) -> List[dict]:
        return [
            {
                "name": p.name,
                "description": p.description,
                "version": p.version,
                "author": p.author,
                "enabled": p.enabled,
            }
            for p in self._plugins
        ]

    def set_enabled(self, name: str, enabled: bool) -> bool:
        for p in self._plugins:
            if p.name == name:
                p.enabled = enabled
                return True
        return False
