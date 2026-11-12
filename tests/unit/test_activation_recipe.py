"""Unit tests for the learned activation-recipe store (dast/session/activation_recipe.py):
record/resolve, product-site keying (cross-subdomain share), the Referer-of-authenticated-call
learn-from-history heuristic, and the never-raises contract. Uses only generic PLACEHOLDER topology.
The conftest seeds site 'alpha' = {admin.alpha.example.com, *.esi.alpha.example.com} and a sub-app
map whose '/beta' prefix -> sub-app 'beta' (site-less, matches any site)."""

from __future__ import annotations

import pytest

from dast.session import activation_recipe as ar


@pytest.fixture(autouse=True)
def _tmp_recipe_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(ar, "_DIR", tmp_path / "activation_recipe")


def test_record_and_resolve_roundtrip():
    assert ar.record_activation("admin.alpha.example.com", "beta", "/beta/home") == "alpha"
    assert ar.activation_nav("admin.alpha.example.com", "beta") == "/beta/home"


def test_site_keying_shares_across_subdomains():
    # recorded on the admin host -> resolvable from a sibling subdomain of the same product site
    ar.record_activation("admin.alpha.example.com", "beta", "/beta/activation")
    assert ar.activation_nav("us1.esi.alpha.example.com", "beta") == "/beta/activation"


def test_freshest_wins():
    ar.record_activation("admin.alpha.example.com", "beta", "/old")
    ar.record_activation("admin.alpha.example.com", "beta", "/new")
    assert ar.activation_nav("admin.alpha.example.com", "beta") == "/new"


def test_unknown_or_bad_input_returns_none():
    assert ar.activation_nav("admin.alpha.example.com", "neverseen") is None
    assert ar.record_activation("admin.alpha.example.com", "", "/x") is None
    assert ar.record_activation("admin.alpha.example.com", "beta", "") is None


class _Store:
    def __init__(self, entries):
        self._entries = entries

    def all_entries(self):
        return self._entries


def test_learn_from_history_uses_referer_of_authenticated_call():
    # The SPA's own (source != copilot) 2xx call to /beta/* carrying a Bearer + a Referer: that
    # Referer is the activation page. learn_from_history records it and returns it.
    entries = [
        # noise: a copilot replay (must be ignored)
        {"url": "https://admin.alpha.example.com/beta/graphql", "status": 200, "source": "copilot",
         "request_headers": {"Referer": "https://admin.alpha.example.com/WRONG", "Authorization": "Bearer z"}},
        # the real SPA authed call
        {"url": "https://admin.alpha.example.com/beta/graphql", "status": 200, "source": "proxy",
         "request_headers": {"Referer": "https://admin.alpha.example.com/beta/studio", "Authorization": "Bearer abc"}},
    ]
    nav = ar.learn_from_history(_Store(entries), "admin.alpha.example.com", "beta")
    assert nav == "https://admin.alpha.example.com/beta/studio"
    # learned recipe is now persisted + resolvable from a sibling subdomain
    assert ar.activation_nav("x.esi.alpha.example.com", "beta") == "https://admin.alpha.example.com/beta/studio"


def test_learn_from_history_ignores_unauthenticated_or_bearerless():
    entries = [
        # 401 (not authenticated) -> ignored
        {"url": "https://admin.alpha.example.com/beta/graphql", "status": 401, "source": "proxy",
         "request_headers": {"Referer": "https://admin.alpha.example.com/beta/x", "Authorization": "Bearer a"}},
        # 200 but no Bearer -> ignored
        {"url": "https://admin.alpha.example.com/beta/graphql", "status": 200, "source": "proxy",
         "request_headers": {"Referer": "https://admin.alpha.example.com/beta/y"}},
        # 200 with Bearer but no Referer -> ignored
        {"url": "https://admin.alpha.example.com/beta/graphql", "status": 200, "source": "proxy",
         "request_headers": {"Authorization": "Bearer a"}},
    ]
    assert ar.learn_from_history(_Store(entries), "admin.alpha.example.com", "beta") is None


def test_learn_from_history_never_raises_on_bad_store():
    assert ar.learn_from_history(None, "admin.alpha.example.com", "beta") is None

    class _Boom:
        def all_entries(self):
            raise RuntimeError("boom")

    assert ar.learn_from_history(_Boom(), "admin.alpha.example.com", "beta") is None
