"""Unit-test safety net: no outbound network.

Unit tests must never reach a real LLM provider or target (cost, flakiness, and
real credentials on a developer machine). Outbound socket connects to anything
other than loopback raise, so a code path that would silently call Bedrock /
Anthropic / OpenAI fails loudly instead. Mocked transports (respx, ASGI test
clients, monkeypatched clients) never open a socket and are unaffected.
"""

import ipaddress
import socket

import pytest

_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex


def _is_loopback(address) -> bool:
    if not isinstance(address, tuple) or not address:
        return True  # AF_UNIX paths and other non-IP sockets
    host = address[0]
    if host in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _guarded_connect(self, address):
    if not _is_loopback(address):
        raise ConnectionRefusedError(f"Outbound network disabled in unit tests: {address!r}")
    return _real_connect(self, address)


def _guarded_connect_ex(self, address):
    if not _is_loopback(address):
        raise ConnectionRefusedError(f"Outbound network disabled in unit tests: {address!r}")
    return _real_connect_ex(self, address)


@pytest.fixture(autouse=True)
def _block_outbound_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", _guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", _guarded_connect_ex)
