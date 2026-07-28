"""
Unit tests for AI-native probe-diffing (Backslash-Powered, done our way).

The most important guarantee is the SCOPE SAFETY test: probe-diff must NEVER
issue a probe to an out-of-scope URL. The rest cover the diff engine
(attribute extraction, break-vs-repair divergence detection), the DiffSignature
summary, and graceful degradation of the LLM classifier.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dast.agents import probe_diff as pd


def _resp(status: int, body: bytes = b"<html><body>ok</body></html>"):
    r = MagicMock()
    r.status_code = status
    r.content = body
    r.text = body.decode("utf-8", errors="replace")
    r.headers = {"content-type": "text/html"}
    return r


def _run(coro):
    return asyncio.run(coro)


def _target(url="https://in.scope/item?id=1", method="GET", headers=None, body=None):
    t = MagicMock()
    t.url = url
    t.method = method
    t.headers = headers or {}
    t.body = body
    return t


@pytest.fixture(autouse=True)
def _no_real_network(monkeypatch):
    monkeypatch.setattr(pd, "is_host_dead", lambda h: False)


# ── attribute extraction / diffing engine ────────────────────────────────────

def test_structure_hash_stable_across_text_but_changes_on_structure():
    same_a = pd._structure_hash("<html><body><p>hello</p></body></html>")
    same_b = pd._structure_hash("<html><body><p>different text</p></body></html>")
    changed = pd._structure_hash("<html><body><p>x</p><script>y</script></body></html>")
    assert same_a == same_b, "tag skeleton is identical → same hash"
    assert same_a != changed, "an extra tag must change the structural hash"


def test_error_signature_detected():
    attrs = pd._extract_attrs(_resp(500, b"You have an error in your SQL syntax near"), "marker")
    assert "sql syntax" in attrs.error_signature.lower()


def test_eval_marker_and_reflection_flags():
    attrs = pd._extract_attrs(_resp(200, b"result is 49 and marker echoed"), "marker")
    assert attrs.eval_marker is True
    assert attrs.reflected is True
    attrs2 = pd._extract_attrs(_resp(200, b"nothing here"), "marker")
    assert attrs2.eval_marker is False
    assert attrs2.reflected is False


def test_differs_from_detects_status_and_error():
    a = pd.ResponseAttrs(200, 100, 10, "h1", False, "", False)
    b = pd.ResponseAttrs(500, 100, 10, "h1", False, "sql syntax", False)
    diffs = a.differs_from(b)
    assert "status" in diffs and "error_signature" in diffs


def test_length_noise_below_threshold_not_flagged():
    a = pd.ResponseAttrs(200, 100, 10, "h1", False, "", False)
    b = pd.ResponseAttrs(200, 120, 10, "h1", False, "", False)  # 20 < 32 noise floor
    assert a.differs_from(b) == []


# ── scope safety ──────────────────────────────────────────────────────────────

def test_out_of_scope_target_issues_no_probe():
    """The hard safety guarantee: an out-of-scope target probes nothing."""
    settings = MagicMock()
    settings.is_in_scope.return_value = False
    send = AsyncMock()
    with patch.object(pd, "_send", new=send), patch.object(pd, "_client"):
        sig = _run(pd.run_probe_pairs(
            _target("https://evil.example/x?a=1"),
            {"name": "a", "location": "query"},
            settings,
        ))
    assert sig is None
    assert send.call_count == 0, "must not send any request to an out-of-scope target"


def test_out_of_scope_built_url_never_sent():
    """If an injected URL falls out of scope, that pair is skipped, not sent."""
    settings = MagicMock()
    # base in scope; anything carrying a probe input is out of scope
    settings.is_in_scope.side_effect = lambda url: "dast" not in url or "dastbaseline" in url

    probed: list[str] = []

    async def fake_send(client, method, url, headers, body, payload=None, source="agent"):
        probed.append(url)
        return _resp(200)

    with patch.object(pd, "_send", new=AsyncMock(side_effect=fake_send)), \
         patch.object(pd, "_client"):
        _run(pd.run_probe_pairs(
            _target(), {"name": "id", "location": "query"}, settings,
        ))

    # No probe carrying a break/repair input ('dast<quote>' etc.) was sent.
    assert all("dast%27" not in u and "dast'" not in u for u in probed)


# ── divergence signal ─────────────────────────────────────────────────────────

def test_string_quote_divergence_produces_signal():
    """A quote that 500s while its escaped twin 200s is a clear divergence."""
    settings = MagicMock()
    settings.is_in_scope.return_value = True

    async def fake_send(client, method, url, headers, body, payload=None, source="agent"):
        # The raw single quote breaks (500 + SQL error); the escaped quote is fine.
        # urlencoded, dast' -> dast%27 and dast\' -> dast%5C%27
        if "dast%27" in url and "dast%5C%27" not in url:
            return _resp(500, b"<html>You have an error in your SQL syntax</html>")
        return _resp(200, b"<html><body>ok</body></html>")

    with patch.object(pd, "_send", new=AsyncMock(side_effect=fake_send)), \
         patch.object(pd, "_client"):
        sig = _run(pd.run_probe_pairs(
            _target(), {"name": "id", "location": "query"}, settings,
        ))

    assert sig is not None
    assert sig.has_signal is True
    assert "string_quote" in sig.divergent_labels
    summary = sig.to_classifier_summary()
    assert "string_quote" in summary


def test_inert_param_yields_no_signal():
    """A param whose break and repair responses are identical yields no signal."""
    settings = MagicMock()
    settings.is_in_scope.return_value = True

    async def fake_send(client, method, url, headers, body, payload=None, source="agent"):
        return _resp(200, b"<html><body>always the same</body></html>")

    with patch.object(pd, "_send", new=AsyncMock(side_effect=fake_send)), \
         patch.object(pd, "_client"):
        sig = _run(pd.run_probe_pairs(
            _target(), {"name": "id", "location": "query"}, settings,
        ))

    assert sig is not None
    assert sig.has_signal is False
    assert sig.divergent_labels == []


def test_baseline_failure_returns_none():
    settings = MagicMock()
    settings.is_in_scope.return_value = True
    with patch.object(pd, "_send", new=AsyncMock(return_value=None)), \
         patch.object(pd, "_client"):
        sig = _run(pd.run_probe_pairs(
            _target(), {"name": "id", "location": "query"}, settings,
        ))
    assert sig is None


def test_reused_client_is_not_closed():
    """When a client is passed in, run_probe_pairs must not close it."""
    settings = MagicMock()
    settings.is_in_scope.return_value = True
    client = MagicMock()
    client.aclose = AsyncMock()

    async def fake_send(c, method, url, headers, body, payload=None, source="agent"):
        return _resp(200)

    with patch.object(pd, "_send", new=AsyncMock(side_effect=fake_send)):
        _run(pd.run_probe_pairs(
            _target(), {"name": "id", "location": "query"}, settings, client=client,
        ))
    client.aclose.assert_not_called()
