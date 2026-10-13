"""dispatch_active() — the on_active_probe hook the scan worker calls."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from dast.proxy.plugin_base import ProxyPlugin
from dast.proxy.plugin_manager import PluginManager


class _RecordingPlugin(ProxyPlugin):
    name = "recording"
    active = True

    def __init__(self) -> None:
        self.calls = []

    async def on_active_probe(self, entry, store, client) -> None:
        self.calls.append((entry, store, client))


class _BrokenPlugin(ProxyPlugin):
    name = "broken"
    active = True

    async def on_active_probe(self, entry, store, client) -> None:
        raise RuntimeError("boom")


@pytest.mark.asyncio
async def test_dispatch_active_builds_a_proxied_client_and_calls_active_plugins():
    # Regression: the client was built with httpx's removed `proxies=` argument,
    # so every dispatch through Frieren's proxy failed before reaching a plugin.
    manager = PluginManager()
    recording, passive = _RecordingPlugin(), ProxyPlugin()
    manager._plugins = [_BrokenPlugin(), recording, passive]
    entry, store = SimpleNamespace(url="http://t.test/"), object()

    await manager.dispatch_active(entry, store, proxy_url="http://127.0.0.1:8080")

    assert len(recording.calls) == 1       # a failing plugin does not stop the others
    assert recording.calls[0][0] is entry
