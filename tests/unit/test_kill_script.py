"""
`make kill` must only kill processes LISTENING on the proxy/dashboard ports.

A browser with the dashboard open holds client sockets to those ports; killing
it (Chrome's network service) drops in-memory session cookies and logs the
user out of SSO.
"""

from __future__ import annotations

import importlib.util
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType

import pytest

_KILL_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "kill.py"


def _load_kill_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("frieren_kill_script", _KILL_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _spawn(code: str) -> subprocess.Popen:
    return subprocess.Popen([sys.executable, "-c", code])


@pytest.mark.skipif(sys.platform == "win32" or not shutil.which("lsof"), reason="needs lsof")
def test_listening_pids_excludes_connected_clients() -> None:
    kill_module = _load_kill_module()
    port = _free_port()
    server = _spawn(
        "import socket, time\n"
        "s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        f"s.bind(('127.0.0.1', {port})); s.listen(); conn, _ = s.accept(); time.sleep(30)\n"
    )
    client = None
    try:
        deadline = time.time() + 5
        while str(server.pid) not in kill_module.listening_pids(port) and time.time() < deadline:
            time.sleep(0.05)
        # Long-lived client, like a browser holding the dashboard WebSocket.
        client = _spawn(
            "import socket, time\n"
            f"c = socket.create_connection(('127.0.0.1', {port})); time.sleep(30)\n"
        )
        time.sleep(0.5)

        pids = kill_module.listening_pids(port)

        assert pids == [str(server.pid)]
        assert str(client.pid) not in pids
    finally:
        for process in (server, client):
            if process is not None:
                process.kill()
                process.wait()
