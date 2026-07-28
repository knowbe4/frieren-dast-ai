"""
Unit tests for hidden-parameter discovery (param mining).

The single most important guarantee is the SCOPE SAFETY test: param mining must
NEVER inject a candidate into an out-of-scope URL. The other tests cover
reflection detection, behavior-change isolation + lone-confirmation (the
anti-false-positive guard), and the dead-host circuit breaker.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dast.scanners import param_miner as pm


def _resp(status: int, body: bytes = b"body", content_type: str = "text/html"):
    r = MagicMock()
    r.status_code = status
    r.content = body
    r.text = body.decode("utf-8", errors="replace")
    r.headers = {"content-type": content_type}
    return r


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _no_real_network(monkeypatch):
    monkeypatch.setattr(pm, "reset_host_reachability", lambda: None)
    monkeypatch.setattr(pm, "is_host_dead", lambda h: False)
    # Small deterministic wordlist.
    monkeypatch.setattr(
        pm, "load_wordlist", lambda name: ["debug", "admin", "id", "page"]
    )


def test_out_of_scope_target_issues_no_probe():
    """The hard safety guarantee: an out-of-scope base URL probes nothing."""
    settings = MagicMock()
    settings.is_in_scope.return_value = False
    send = AsyncMock()
    with patch.object(pm, "_send", new=send), patch.object(pm, "_client"):
        hits = _run(pm.run_param_mining("https://evil.example/", {}, settings))
    assert hits == []
    assert send.call_count == 0, "must not send any request to an out-of-scope host"


def test_out_of_scope_query_url_never_sent():
    """
    Even for an in-scope base, if the augmented URL falls out of scope the probe
    is skipped WITHOUT being sent. (The scope check runs on the built URL.)
    """
    settings = MagicMock()
    # base in scope, but any URL carrying an injected param is out of scope
    settings.is_in_scope.side_effect = lambda url: "dastpm" not in url

    probed: list[str] = []

    async def fake_send(client, method, url, headers, body, payload=None, source="agent"):
        probed.append(url)
        return _resp(200)

    with patch.object(pm, "_send", new=AsyncMock(side_effect=fake_send)), \
         patch.object(pm, "_client"):
        _run(pm.run_param_mining("https://in.scope/", {}, settings))

    # Baseline (no injected param) is fine; nothing carrying a canary is sent.
    assert all("dastpm" not in u for u in probed)


def test_reflection_detects_exact_param():
    """A canary echoed in the body pinpoints the reflected parameter name."""
    settings = MagicMock()
    settings.is_in_scope.return_value = True

    debug_canary = pm._canary(0)  # index 0 in batch: debug, admin, id, page

    async def fake_send(client, method, url, headers, body, payload=None, source="agent"):
        # Reflect only the 'debug' canary verbatim.
        if debug_canary in url:
            return _resp(200, f"echo {debug_canary} back".encode())
        return _resp(200, b"nothing reflected")

    with patch.object(pm, "_send", new=AsyncMock(side_effect=fake_send)), \
         patch.object(pm, "_client"):
        hits = _run(pm.run_param_mining("https://in.scope/x", {}, settings))

    reflected = {h["parameter"] for h in hits if h["reason"] == "reflected"}
    assert "debug" in reflected
    assert reflected == {"debug"}, "only the echoed canary must be flagged"


def test_behavior_change_isolated_and_confirmed():
    """
    A param that shifts the status code is isolated by binary search and must
    reproduce the change ON ITS OWN before being reported.
    """
    settings = MagicMock()
    settings.is_in_scope.return_value = True

    async def fake_send(client, method, url, headers, body, payload=None, source="agent"):
        # Baseline + all others are 200; presence of the admin param (any
        # canary value) flips to 403. Detection keys on the name, not the value.
        if "admin=dastpm" in url:
            return _resp(403, b"forbidden")
        return _resp(200, b"ok")

    with patch.object(pm, "_send", new=AsyncMock(side_effect=fake_send)), \
         patch.object(pm, "_client"):
        hits = _run(pm.run_param_mining("https://in.scope/x", {}, settings))

    changed = {h["parameter"] for h in hits if h["reason"] == "behavior-change"}
    assert "admin" in changed
    assert changed == {"admin"}, "only the confirmed param must be reported"


def test_noisy_page_yields_no_false_positive():
    """
    A page whose length drifts every request (no single param responsible) must
    not produce a behavior-change hit — the lone-confirmation step filters it.
    """
    settings = MagicMock()
    settings.is_in_scope.return_value = True
    counter = {"n": 0}

    async def fake_send(client, method, url, headers, body, payload=None, source="agent"):
        # Body grows on every call regardless of params → pure noise.
        counter["n"] += 1
        return _resp(200, b"x" * (100 + counter["n"] * 100))

    with patch.object(pm, "_send", new=AsyncMock(side_effect=fake_send)), \
         patch.object(pm, "_client"):
        hits = _run(pm.run_param_mining("https://in.scope/x", {}, settings))

    assert all(h["reason"] != "behavior-change" for h in hits), \
        "drifting length must not be reported as a hidden parameter"


def test_existing_params_are_not_reguessed():
    """Parameters already present on the request are excluded from candidates."""
    settings = MagicMock()
    settings.is_in_scope.return_value = True
    seen_params: list[str] = []

    async def fake_send(client, method, url, headers, body, payload=None, source="agent"):
        # Record which candidate canaries appear (base URL already has id=5).
        for cand in ("debug", "admin", "id", "page"):
            if f"{cand}=dastpm" in url:
                seen_params.append(cand)
        return _resp(200)

    with patch.object(pm, "_send", new=AsyncMock(side_effect=fake_send)), \
         patch.object(pm, "_client"):
        _run(pm.run_param_mining("https://in.scope/x?id=5", {}, settings))

    assert "id" not in seen_params, "an existing param must not be re-guessed"


def test_dead_host_short_circuits(monkeypatch):
    settings = MagicMock()
    settings.is_in_scope.return_value = True
    monkeypatch.setattr(pm, "is_host_dead", lambda h: True)
    # Baseline still attempted, but the batch loop must break immediately.
    send = AsyncMock(return_value=_resp(200))
    with patch.object(pm, "_send", new=send), patch.object(pm, "_client"):
        hits = _run(pm.run_param_mining("https://in.scope/x", {}, settings))
    assert hits == []


def test_reflected_param_not_masked_by_disruptive_batchmate():
    """
    A reflected param sharing a batch with a disruptive param (one that flips the
    status, replacing the body with its own error page) must still be found. The
    disruptive response no longer echoes co-injected canaries, so the batch is
    re-probed without the offender to surface the masked reflection.
    """
    settings = MagicMock()
    settings.is_in_scope.return_value = True
    debug_canary = pm._canary(0)  # index 0: debug

    async def fake_send(client, method, url, headers, body, payload=None, source="agent"):
        # 'admin' flips to 403 with a forbidden page (masks everything else).
        if "admin=dastpm" in url:
            return _resp(403, b"forbidden")
        # Otherwise reflect 'debug' verbatim when its canary is present.
        if debug_canary in url:
            return _resp(200, f"item ok debug={debug_canary}".encode())
        return _resp(200, b"ok")

    with patch.object(pm, "_send", new=AsyncMock(side_effect=fake_send)), \
         patch.object(pm, "_client"):
        hits = _run(pm.run_param_mining("https://in.scope/item", {}, settings))

    reflected = {h["parameter"] for h in hits if h["reason"] == "reflected"}
    changed = {h["parameter"] for h in hits if h["reason"] == "behavior-change"}
    assert "debug" in reflected, "reflected param masked by a 403 batchmate must still be found"
    assert changed == {"admin"}


def test_canary_indices_are_not_substrings_of_each_other():
    """
    Canary values must not be substrings of one another. Without a delimiter,
    index 1's canary ('...e1') matches inside index 16's ('...e16'), so a
    non-reflected low-index param would be a phantom reflection hit whenever a
    high-index param is genuinely reflected. Guard against that regression.
    """
    settings = MagicMock()
    settings.is_in_scope.return_value = True
    # 18 candidates so a two-digit index (>=10) exists; reflect only that one.
    names = [f"p{i}" for i in range(18)]
    monkeypatch_names = names
    high_canary = pm._canary(16)

    async def fake_send(client, method, url, headers, body, payload=None, source="agent"):
        if high_canary in url:
            return _resp(200, f"reflected {high_canary}".encode())
        return _resp(200, b"ok")

    with patch.object(pm, "load_wordlist", lambda name: monkeypatch_names), \
         patch.object(pm, "_send", new=AsyncMock(side_effect=fake_send)), \
         patch.object(pm, "_client"):
        hits = _run(pm.run_param_mining("https://in.scope/x", {}, settings))

    reflected = {h["parameter"] for h in hits if h["reason"] == "reflected"}
    assert reflected == {"p16"}, f"only the truly-reflected param must be flagged, got {reflected}"


def test_json_body_location_detected():
    """A JSON POST mines parameters into the JSON body, not the query string."""
    settings = MagicMock()
    settings.is_in_scope.return_value = True
    bodies: list = []

    async def fake_send(client, method, url, headers, body, payload=None, source="agent"):
        bodies.append(body)
        return _resp(200)

    with patch.object(pm, "_send", new=AsyncMock(side_effect=fake_send)), \
         patch.object(pm, "_client"):
        _run(pm.run_param_mining(
            "https://in.scope/api", {}, settings,
            method="POST", body='{"a":1}', content_type="application/json",
        ))

    # At least one probe body must be JSON containing an injected canary.
    assert any(b and b.startswith("{") and "dastpm" in b for b in bodies)


def test_passed_in_client_is_reused_and_not_closed():
    """
    When a caller passes its own client (the coordinator's proxy-routed one),
    run_param_mining must reuse it verbatim and never open or close a client of
    its own — mirroring the probe_diff primitive.
    """
    settings = MagicMock()
    settings.is_in_scope.return_value = True
    shared_client = MagicMock()

    async def fake_send(client, method, url, headers, body, payload=None, source="agent"):
        assert client is shared_client, "must use the passed-in client, not a fresh one"
        return _resp(200)

    factory = MagicMock()
    with patch.object(pm, "_send", new=AsyncMock(side_effect=fake_send)), \
         patch.object(pm, "_client", new=factory):
        _run(pm.run_param_mining(
            "https://in.scope/x", {}, settings, client=shared_client,
        ))

    factory.assert_not_called()
    shared_client.aclose.assert_not_called()
