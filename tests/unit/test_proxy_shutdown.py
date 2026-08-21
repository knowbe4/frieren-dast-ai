"""
Regression test for the Ctrl+C / port-stays-open bug.

On Python 3.12+ asyncio.Server.wait_closed() blocks until every connection is
gone, so a single idle/long-lived client would hang shutdown forever and leave
the listening port bound. ProxyServer.stop() must cancel in-flight connection
handlers and never block past its ceiling.
"""

from __future__ import annotations

import asyncio

import pytest

from dast.proxy.proxy_server import ProxyServer
from dast.proxy.session_store import SessionStore


@pytest.mark.asyncio
async def test_stop_cancels_inflight_connections_and_returns_fast():
    server = ProxyServer(SessionStore(), ca=None, settings=None, host="127.0.0.1", port=0)
    await server.start()
    # port=0 asks the OS for an ephemeral port; read the real one off the socket
    # (start() records the requested port, not the OS-assigned one).
    port = server._server.sockets[0].getsockname()[1]

    # Open a client that connects and then goes silent — its handler blocks on
    # readline(), keeping a connection task alive (the exact thing that used to
    # wedge wait_closed()).
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    await asyncio.sleep(0.05)
    assert server._conn_tasks, "handler task should be registered while connected"

    # stop() must return well within its 3s ceiling despite the open connection.
    await asyncio.wait_for(server.stop(), timeout=2.0)
    assert server._server is None

    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
