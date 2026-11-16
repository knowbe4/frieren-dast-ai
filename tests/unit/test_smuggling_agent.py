"""Unit tests for the request-smuggling agent (dast/agents/smuggling_agent.py).

The raw transport is faked at `_send_raw_probe` (the agent's direct-socket
sender — httpx/_send cannot carry the duplicate framing headers). Tests pin the
detection contract: a probe connection answering MORE responses than the
consistently-framed control confirms the desync; matching counts do not.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from dast.agents import smuggling_agent as sm
from dast.scanners.active_checks import CheckTarget
from dast.session.refresh_worker import SessionRefreshWorker  # noqa: F401  (breaker parity check)


def _target(headers=None):
    return CheckTarget(
        method="POST", url="https://app.test/api/submit",
        headers=headers or {"content-type": "application/json",
                            "content-length": "7", "transfer-encoding": "chunked"},
        body='{"a":1}',
        params=[],
    )


def _raw(statuses):
    """Fake _send_raw_probe returning the given response status list."""
    async def fake(host, port, use_tls, payload, smug_token):
        if statuses is None:
            return None
        if smug_token:  # probe: embed the token so the noise guard accepts it
            from dast.agents.smuggling_agent import _parse_responses
            return _parse_responses(
                b"".join(b"HTTP/1.1 200 OK\r\n\r\n" if s == 200 else
                         f"HTTP/1.1 {s} Not Found\r\n\r\n".encode()
                         for s in statuses) + smug_token.encode())
        # The CONTROL connection always yields exactly ONE (consistent framing).
        return sm._parse_responses(b"HTTP/1.1 200 OK\r\n\r\n")
    return fake


@pytest.mark.asyncio
async def test_count_only_differential_does_not_confirm_a_finding():
    """Fail-safe: a probe connection yielding MORE raw responses than the
    Connection: close control is NOT a reliable desync signal (benign keep-alive
    pipelining explains it on a single origin), so the count-only verdict must
    NOT emit any finding — and never a confirmed critical."""
    target = _target()
    with patch.object(sm, "_send_raw_probe", new=_raw([200, 404])), \
         patch.object(sm, "is_host_dead", return_value=False):
        findings = await sm.SmugglingAgent().run(target, __import__("unittest").mock.MagicMock())
    assert findings == []


@pytest.mark.asyncio
async def test_no_desync_when_probe_and_control_match():
    target = _target()
    with patch.object(sm, "_send_raw_probe", new=_raw([200])), \
         patch.object(sm, "is_host_dead", return_value=False):
        findings = await sm.SmugglingAgent().run(target, __import__("unittest").mock.MagicMock())
    assert findings == []


@pytest.mark.asyncio
async def test_transport_failure_yields_no_finding():
    target = _target()
    with patch.object(sm, "_send_raw_probe", new=_raw(None)), \
         patch.object(sm, "is_host_dead", return_value=False):
        findings = await sm.SmugglingAgent().run(target, __import__("unittest").mock.MagicMock())
    assert findings == []


@pytest.mark.asyncio
async def test_dead_host_short_circuits():
    target = _target()
    with patch.object(sm, "is_host_dead", return_value=True):
        findings = await sm.SmugglingAgent().run(target, __import__("unittest").mock.MagicMock())
    assert findings == []


def test_probe_bytes_carry_both_framing_headers_and_benign_smuggled_get():
    target = _target()
    payload = sm._build_probe(target, "/dast-smuggled-123", cl_te=False)
    low = payload.lower()
    assert b"content-length:" in low
    assert b"transfer-encoding: chunked" in low
    assert b"get /dast-smuggled-123 http/1.1" in low
    # The smuggled request is a benign GET — no destructive payload ever.
    assert b"drop " not in low and b"delete " not in low
    control = sm._build_control(target)
    assert control.lower().count(b"content-length") == 1
    assert b"transfer-encoding" not in control.lower()


# ── hints → dispatch channel ─────────────────────────────────────────────────

def test_hint_entry_sets_focus_attack_type():
    entry = SimpleNamespace(focus_attack_types=None)
    sm._focus_from_hint(entry)
    assert entry.focus_attack_types == ["request_smuggling"]


def test_hints_plugin_arms_the_focus_channel():
    import asyncio
    from dast.plugins import request_smuggling_hints as hints

    captured = []

    class _Store:
        def add_finding(self, *a, **k):
            captured.append(k if k else a)

    entry = SimpleNamespace(
        id="e1",
        request_headers={"Content-Length": "5", "Transfer-Encoding": "chunked"},
        response_status=200,
        request_body=b"a=1",
        focus_attack_types=None,
    )
    asyncio.run(hints.RequestSmugglingHintsPlugin().on_entry(entry, _Store()))
    assert captured, "hint finding expected for dual-framing request"
    assert entry.focus_attack_types == ["request_smuggling"]


def test_hint_attack_type_uses_agent_vocabulary():
    """The finding's attack_type must match the registry vocabulary (underscored)
    so coverage mapping and dispatch agree."""
    import inspect
    from dast.plugins import request_smuggling_hints
    source = inspect.getsource(request_smuggling_hints)
    assert '"request-smuggling"' not in source
    assert '"request_smuggling"' in source
