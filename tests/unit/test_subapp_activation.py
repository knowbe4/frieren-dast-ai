"""Central-less sub-app token acquisition: path-derived keying + proactive activation nav.

- subapp_for_path derives a key for an UNMAPPED sub-app path (no hand-written config).
- _activate_subapp navigates to the feature, captures the token, records the recipe, is idempotent.
- refresh_bearer proactively activates when no fresh token exists, and skips it when one does.
"""

from __future__ import annotations

import pytest

from dast.ai.copilot.session import CopilotSession, RefreshTier
from dast.session.auth_provider import _derived_subapp, subapp_for_path


def test_subapp_for_path_contract_unchanged():
    # subapp_for_path keeps its "None for unmapped" contract (derivation is NOT wired into it).
    assert subapp_for_path("/v1/dashboard") is None
    assert subapp_for_path("/billing/graphql") is None


def test_derived_subapp_is_graphql_scoped():
    # Derives the segment before 'graphql' for an unmapped GraphQL sub-app.
    assert _derived_subapp("/billing/graphql") == "billing"
    assert _derived_subapp("/orders/graphql") == "orders"
    assert _derived_subapp("/reports/graphql/") == "reports"
    # Does not mis-fire on page/version/shell/static or non-graphql paths.
    assert _derived_subapp("/v1/dashboard") is None
    assert _derived_subapp("/api/graphql") is None   # 'api' is a generic segment
    assert _derived_subapp("/v2/graphql") is None     # version marker
    assert _derived_subapp("/graphql") is None        # nothing before it
    assert _derived_subapp("/app/reporting") is None  # no graphql segment


@pytest.mark.asyncio
async def test_activate_subapp_navigates_captures_records(monkeypatch):
    recorded = []
    monkeypatch.setattr("dast.session.activation_recipe.activation_nav",
                        lambda host, app: "/reports")
    monkeypatch.setattr("dast.session.activation_recipe.learn_from_history",
                        lambda store, host, app: None)
    monkeypatch.setattr("dast.session.activation_recipe.record_activation",
                        lambda host, app, nav, source="": recorded.append((host, app, nav, source)))

    s = CopilotSession("s-act", focus_hosts=["app.example.com"])

    async def _await_ok(store, host, app, *, probe_hint="", **k):
        return True
    s._await_subapp_bearer = _await_ok

    class _B:
        def __init__(self):
            self.nav = None
        async def navigate(self, url):
            self.nav = url
            return {"ok": True}

    br = _B()
    ok = await s._activate_subapp(object(), "app.example.com", "reports", br, probe_hint="/reports/graphql")
    assert ok is True
    assert br.nav == "https://app.example.com/reports"
    assert recorded == [("app.example.com", "reports", "/reports", "activate")]

    # Idempotent: bounded to one nav per (host, app) per run.
    br2 = _B()
    assert await s._activate_subapp(object(), "app.example.com", "reports", br2, probe_hint="/x") is False
    assert br2.nav is None


@pytest.mark.asyncio
async def test_refresh_bearer_proactively_activates(monkeypatch):
    s = CopilotSession("s-rb", focus_hosts=["app.example.com"])
    s._capture_bearer_tokens = lambda store, host: None

    async def _wait(store, host, path, browser, timeout_s):
        return None
    s._tier_wait_spa = _wait

    state = {"activated": False}
    s._select_bearer = lambda host, path: ({"token": "tkn", "exp": None}
                                           if state["activated"] else None)

    async def _act(store, host, app, browser, probe_hint=""):
        state["activated"] = True
        return True
    s._activate_subapp = _act

    out = await s.refresh_bearer(object(), "app.example.com", "/reports/graphql",
                                 browser=object(), max_tier=RefreshTier.WAIT_SPA)
    assert out.record and out.record["token"] == "tkn"
    assert state["activated"] is True


@pytest.mark.asyncio
async def test_refresh_bearer_skips_activation_when_token_fresh(monkeypatch):
    s = CopilotSession("s-rb2", focus_hosts=["app.example.com"])
    s._capture_bearer_tokens = lambda store, host: None
    s._select_bearer = lambda host, path: {"token": "already", "exp": None}

    called = {"act": False}
    async def _act(*a, **k):
        called["act"] = True
        return True
    s._activate_subapp = _act

    out = await s.refresh_bearer(object(), "app.example.com", "/reports/graphql",
                                 browser=object(), max_tier=RefreshTier.WAIT_SPA)
    assert out.record["token"] == "already"
    assert called["act"] is False  # fast path: no navigation when a fresh token exists
