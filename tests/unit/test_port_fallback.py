"""
Unit tests for port-fallback behavior in the proxy (ProxyServer.start) and
dashboard (dast.proxy.runner._find_free_port).

Regression: a second `dast-ai proxy` run (or a leftover process from a prior
run still releasing its socket) crashed with a raw OSError/traceback on
asyncio.start_server instead of falling back to another port.
"""

from __future__ import annotations

import asyncio
import socket

import pytest

from dast.proxy.runner import _find_free_port


def _occupy_port(host: str = "127.0.0.1") -> "socket.socket":
    """Bind and listen on an OS-assigned free port; return the bound socket
    (caller must close it) so its port number is deterministically occupied."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, 0))
    s.listen(1)
    return s


class TestFindFreePort:
    def test_returns_preferred_port_when_free(self):
        # Bind to something to grab a genuinely free port number, then release it.
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        free_port = probe.getsockname()[1]
        probe.close()

        assert _find_free_port(free_port) == free_port

    def test_falls_back_when_preferred_port_busy(self):
        occupied = _occupy_port()
        busy_port = occupied.getsockname()[1]
        try:
            result = _find_free_port(busy_port)
            assert result != busy_port
            assert result > busy_port
        finally:
            occupied.close()

    def test_raises_when_no_free_port_in_range(self):
        sockets = []
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe.bind(("127.0.0.1", 0))
            base_port = probe.getsockname()[1]
            probe.close()

            for offset in range(3):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", base_port + offset))
                s.listen(1)
                sockets.append(s)

            with pytest.raises(OSError):
                _find_free_port(base_port, max_attempts=3)
        finally:
            for s in sockets:
                s.close()


class TestProxyServerPortFallback:
    @pytest.fixture
    def store_and_ca(self, tmp_path, monkeypatch):
        from dast.proxy import cert_authority as ca_mod
        from dast.proxy.session_store import SessionStore

        monkeypatch.setattr(ca_mod, "_CA_DIR", tmp_path)
        monkeypatch.setattr(ca_mod, "_CA_KEY_PATH", tmp_path / "ca.key")
        monkeypatch.setattr(ca_mod, "_CA_CERT_PATH", tmp_path / "ca.crt")
        return SessionStore(), ca_mod.CertAuthority()

    @pytest.mark.asyncio
    async def test_start_binds_requested_port_when_free(self, store_and_ca):
        from dast.proxy.proxy_server import ProxyServer

        store, ca = store_and_ca
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        free_port = probe.getsockname()[1]
        probe.close()

        server = ProxyServer(store, ca, port=free_port)
        await server.start()
        try:
            assert server._port == free_port
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_start_falls_back_when_requested_port_busy(self, store_and_ca):
        from dast.proxy.proxy_server import ProxyServer

        store, ca = store_and_ca
        occupied = _occupy_port()
        busy_port = occupied.getsockname()[1]
        try:
            server = ProxyServer(store, ca, port=busy_port)
            await server.start()
            try:
                assert server._port != busy_port
                assert server._port > busy_port
            finally:
                await server.stop()
        finally:
            occupied.close()

    @pytest.mark.asyncio
    async def test_start_raises_after_exhausting_attempts(self, store_and_ca, monkeypatch):
        from dast.proxy.proxy_server import ProxyServer

        store, ca = store_and_ca

        async def _always_busy(*a, **k):
            raise OSError("address already in use")

        monkeypatch.setattr(asyncio, "start_server", _always_busy)
        server = ProxyServer(store, ca, port=1)
        with pytest.raises(OSError):
            await server.start(max_port_attempts=3)
