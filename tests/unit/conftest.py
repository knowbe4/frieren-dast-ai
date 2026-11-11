"""Unit-test safety net: no outbound network + no developer .env.

Unit tests must never reach a real LLM provider or target (cost, flakiness, and
real credentials on a developer machine). Outbound socket connects to anything
other than loopback raise, so a code path that would silently call Bedrock /
Anthropic / OpenAI fails loudly instead. Mocked transports (respx, ASGI test
clients, monkeypatched clients) never open a socket and are unaffected.

They must also be deterministic regardless of the developer's local `.env`: a
machine configured for the gateway provider (AI_PROVIDER=gateway,
ai_validation_models=...) would otherwise leak into `dast.config.settings` and
break provider/tier tests (and route LLM calls into the no-network guard). Set
the opt-out BEFORE importing anything from `dast`, so the settings singleton is
built without the `.env` file.
"""

import os

os.environ.setdefault("DAST_DISABLE_DOTENV", "1")

import ipaddress  # noqa: E402
import socket  # noqa: E402

import pytest  # noqa: E402

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


@pytest.fixture(autouse=True)
def _isolate_login_journal(tmp_path, monkeypatch):
    """Redirect the login journal to a per-test tmp dir so the SPA login strategy
    never reads/writes the developer's real ~/.dast-ai/login_journal (which made the
    'first candidate wins' assertion non-deterministic and leaked test host files)."""
    from dast.session import login_journal  # noqa: PLC0415
    monkeypatch.setattr(login_journal, "_JOURNAL_DIR", tmp_path / "login_journal")


@pytest.fixture(autouse=True)
def _isolate_transport_capability(tmp_path, monkeypatch):
    """Redirect the learned transport-capability store to a per-test tmp dir so tests never
    read/write the developer's real ~/.dast-ai/transport_capability."""
    from dast.session import transport_capability  # noqa: PLC0415
    monkeypatch.setattr(transport_capability, "_DIR", tmp_path / "transport_capability")


# Generic PLACEHOLDER sub-app map for the whole unit suite — never real target topology.
# Two prefixed apps (alpha/beta) + one prefix-less app (gamma) exercise prefix resolution and
# the app->jwt-field map. Redirects subapp_map._CONFIG_PATH so sub-app selection resolves in
# tests (it is empty by default without the operator's local ~/.dast-ai/subapp_map.json) and
# never reads the developer's real config.
_PLACEHOLDER_SUBAPP_MAP = {
    "sub_apps": [
        {"prefix": "/alpha", "app": "alpha", "jwt_field": "alphaJwt", "probe": "/alpha/graphql"},
        {"prefix": "/beta", "app": "beta", "jwt_field": "betaJwt", "probe": "/beta/graphql"},
        {"app": "gamma", "jwt_field": "gammaJwt"},
    ]
}


@pytest.fixture(autouse=True)
def _seed_subapp_map(tmp_path, monkeypatch):
    import json  # noqa: PLC0415

    from dast.session import subapp_map  # noqa: PLC0415
    cfg = tmp_path / "subapp_map.json"
    cfg.write_text(json.dumps(_PLACEHOLDER_SUBAPP_MAP), encoding="utf-8")
    monkeypatch.setattr(subapp_map, "_CONFIG_PATH", cfg)
    subapp_map._reset_cache()
    yield
    subapp_map._reset_cache()
