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


@pytest.fixture(autouse=True)
def _isolate_activation_recipe(tmp_path, monkeypatch):
    """Redirect the learned activation-recipe store to a per-test tmp dir so tests never
    read/write the developer's real ~/.dast-ai/activation_recipe."""
    from dast.session import activation_recipe  # noqa: PLC0415
    monkeypatch.setattr(activation_recipe, "_DIR", tmp_path / "activation_recipe")


@pytest.fixture(autouse=True)
def _isolate_copilot_snapshots(tmp_path, monkeypatch):
    """Redirect copilot session snapshots to a per-test tmp dir (6-A-1) so tests
    never read/write the developer's real ~/.dast-ai/copilot_sessions — the
    CopilotService now restores snapshots in its constructor."""
    from dast.proxy.api import copilot_persist  # noqa: PLC0415
    monkeypatch.setattr(copilot_persist, "_DIR", tmp_path / "copilot_sessions")


# Generic PLACEHOLDER sub-app map for the whole unit suite — never real target topology.
# Two prefixed apps (alpha/beta) + one prefix-less app (gamma) exercise prefix resolution and
# the app->jwt-field map. 'beta' also declares a 'prime' descriptor so session-prime tests have a
# primeable app (alpha has none -> exercises the no-prime path). Redirects subapp_map._CONFIG_PATH
# so sub-app selection resolves in tests (it is empty by default without the operator's local
# ~/.dast-ai/subapp_map.json) and never reads the developer's real config.
_PLACEHOLDER_SUBAPP_MAP = {
    "sub_apps": [
        {"prefix": "/alpha", "app": "alpha", "jwt_field": "alphaJwt", "probe": "/alpha/graphql"},
        {"prefix": "/beta", "app": "beta", "jwt_field": "betaJwt", "probe": "/beta/graphql",
         "prime": {"endpoint": "/beta/session", "method": "GET", "cookie": "_beta_session",
                   "nav": "/beta/home"}},
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


# Generic PLACEHOLDER site (product-group) map — never real target topology. 'alpha' groups an exact
# host + a wildcard subdomain so site grouping, wildcard match, and fallback-to-host are all exercised.
_PLACEHOLDER_SITES = {
    "sites": [
        {"id": "alpha", "domains": ["admin.alpha.example.com", "*.esi.alpha.example.com"]},
    ]
}


@pytest.fixture(autouse=True)
def _seed_site_map(tmp_path, monkeypatch):
    import json  # noqa: PLC0415

    from dast.session import site_map  # noqa: PLC0415
    cfg = tmp_path / "sites.json"
    cfg.write_text(json.dumps(_PLACEHOLDER_SITES), encoding="utf-8")
    monkeypatch.setattr(site_map, "_CONFIG_PATH", cfg)
    site_map._reset_cache()
    yield
    site_map._reset_cache()


@pytest.fixture(autouse=True)
def _isolate_provider_health():
    """Reset the LLM provider-health registry around every test. Tests that
    exercise the real ``_invoke_raw`` walk (model fallback, failover) record
    real failures into it; without the reset a cooldown leaked into later
    tests and silently reordered their failover chain."""
    from dast.ai import provider_health  # noqa: PLC0415
    provider_health.reset()
    yield
    provider_health.reset()


@pytest.fixture(autouse=True)
def _isolate_llm_recorder(tmp_path, monkeypatch):
    """Redirect the LLM-call recorder's JSONL sink to a per-test tmp dir and
    reset the in-memory ring/counters around every test. Tests that exercise
    the real ``_invoke_raw`` walk (failover, model fallback — and the recorder
    suite itself) now record one entry per attempt; without the redirect each
    of those would append to the developer's real ~/.dast-ai/llm_calls file
    and leak counters across tests."""
    from dast.ai import llm_recorder  # noqa: PLC0415
    monkeypatch.setattr(llm_recorder, "_CALLS_DIR", tmp_path / "llm_calls")
    llm_recorder.clear()
    yield
    llm_recorder.clear()


@pytest.fixture(autouse=True)
def _reset_noise_governor():
    """Back to the off profile around every test. Tests that pace probes set
    a real noise profile; without the reset one of those profiles leaked into
    later tests and silently changed their pacing/timing."""
    from dast.scanners import noise_governor  # noqa: PLC0415
    noise_governor.reset()
    yield
    noise_governor.reset()


@pytest.fixture(autouse=True)
def _reset_coverage_ledger():
    """Empty the coverage ledger around every test — the store is process-wide
    and the coordinator writes into it during scans; without the reset one
    test's entries leaked into another test's planner prompts and snapshots."""
    from dast.coverage import ledger  # noqa: PLC0415
    ledger.reset()
    yield
    ledger.reset()
