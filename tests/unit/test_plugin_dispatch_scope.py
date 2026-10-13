"""PluginManager.dispatch() never hands out-of-scope traffic to a plugin."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from dast.proxy.plugin_base import ProxyPlugin
from dast.proxy.plugin_manager import PluginManager


class _RecordingPlugin(ProxyPlugin):
    name = "recording"

    def __init__(self) -> None:
        self.seen = []

    async def on_entry(self, entry, store) -> None:
        self.seen.append(entry.url)


class _Store:
    def snapshot_findings(self, entry):
        return []


def _dispatch(source: str) -> list:
    manager = PluginManager()
    plugin = _RecordingPlugin()
    manager._plugins = [plugin]
    entry = SimpleNamespace(url=f"https://{source}.test/", source=source)
    asyncio.run(manager.dispatch(entry, _Store()))
    return plugin.seen


def test_out_of_scope_entries_never_reach_plugins():
    # Several plugins send requests from on_entry (JWT tester attacks, CORS proof
    # probe, scan enqueues); a third-party host crossing the proxy must get none.
    assert _dispatch("out-of-scope") == []


def test_in_scope_entries_still_reach_plugins():
    assert _dispatch("proxy") == ["https://proxy.test/"]
