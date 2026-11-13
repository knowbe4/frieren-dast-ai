"""Unit tests for dast.session.auth_provider — the single source of truth for sub-app
Bearer selection from proxy history (collapsed from two duplicate scans)."""

from __future__ import annotations

import base64
import json
import time

from dast.session.auth_provider import (
    attach,
    collect_host_bearer,
    decode_jwt_exp,
    rec_is_fresh,
    scan_history_bearer,
    select_bearer,
    subapp_for_path,
)


def _jwt(exp=None) -> str:
    def seg(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
    payload = {"sub": "1"}
    if exp is not None:
        payload["exp"] = exp
    return f"{seg({'alg': 'HS512'})}.{seg(payload)}.{seg('sig1234567890')}"


class _Store:
    def __init__(self, entries):
        self._entries = entries

    def all_entries(self):
        return self._entries


def _entry(host, path, token, source="proxy", eid="e"):
    return {"host": host, "path": path, "source": source, "id": eid,
            "request_headers": {"Authorization": f"Bearer {token}"}}


def test_subapp_for_path():
    assert subapp_for_path("/alpha/graphql") == "alpha"
    assert subapp_for_path("/beta/graphql") == "beta"
    assert subapp_for_path("/v1/dashboard") is None
    assert subapp_for_path("") is None


def test_decode_jwt_exp():
    assert decode_jwt_exp(_jwt(exp=9999999999)) == 9999999999.0
    assert decode_jwt_exp(_jwt()) is None       # no exp claim
    assert decode_jwt_exp("not-a-jwt") is None


def test_rec_is_fresh():
    assert rec_is_fresh({"token": "t"}) is True                      # no exp -> fresh
    assert rec_is_fresh({"token": "t", "exp": time.time() + 100}) is True
    assert rec_is_fresh({"token": "t", "exp": time.time() - 100}) is False
    assert rec_is_fresh({"exp": None}) is False                      # no token
    assert rec_is_fresh(None) is False


def test_collect_and_select_per_subapp():
    host = "api.phisher.example"
    store = _Store([
        _entry(host, "/v1/dashboard", _jwt(), eid="a"),           # host-level
        _entry(host, "/alpha/graphql", _jwt(), eid="b"),          # alpha sub-app
        _entry(host, "/beta/graphql", _jwt(), eid="c"),           # beta sub-app
    ])
    rec = collect_host_bearer(store, host)
    assert rec and rec.get("token")
    assert set(rec.get("by_app", {})) == {"alpha", "beta"}
    # host-level default for a non-sub-app path
    assert select_bearer(rec, "/v1/dashboard")["token"] == rec["token"]
    # per-sub-app selection
    assert select_bearer(rec, "/alpha/x")["auth_endpoint"] == "/alpha/graphql"
    assert select_bearer(rec, "/beta/x")["auth_endpoint"] == "/beta/graphql"


def test_expired_token_skipped():
    host = "api.phisher.example"
    store = _Store([_entry(host, "/v1/dashboard", _jwt(exp=time.time() - 10))])
    assert collect_host_bearer(store, host) is None
    assert scan_history_bearer(store, host, "/v1/dashboard") is None


def test_exclude_source():
    host = "api.phisher.example"
    store = _Store([_entry(host, "/v1/dashboard", _jwt(), source="copilot")])
    assert collect_host_bearer(store, host, exclude_source="copilot") is None
    assert collect_host_bearer(store, host) is not None   # included when not excluded


def test_domain_suffix_match_and_scan_wrapper():
    store = _Store([_entry("sub.target.example", "/alpha/g", _jwt(), eid="x")])
    rec = scan_history_bearer(store, "api.target.example", "/alpha/y")
    assert rec and rec["auth_endpoint"] == "/alpha/g"   # matched on registrable domain
    assert scan_history_bearer(None, "h", "/p") is None    # null store -> None, no raise


# --------------------------------------------------------------- scan_history_csrf + CSRF fallback


def test_scan_history_csrf_recovers_token_from_history():
    from dast.session.auth_provider import scan_history_csrf
    host = "app.example.com"
    store = _Store([
        {"host": host, "path": "/graphql", "source": "proxy",
         "request_headers": {"X-CSRF-Token": "spa-tok-1"}},
        {"host": host, "path": "/graphql", "source": "proxy",
         "request_headers": {"X-CSRF-Token": "spa-tok-2"}},  # freshest (last)
    ])
    assert scan_history_csrf(store, host) == "spa-tok-2"
    # a copilot-sourced entry is skipped when excluded
    store2 = _Store([{"host": host, "path": "/graphql", "source": "copilot",
                      "request_headers": {"X-CSRF-Token": "mine"}}])
    assert scan_history_csrf(store2, host, exclude_source="copilot") is None
    assert scan_history_csrf(None, host) is None          # null store -> None, no raise


def test_attach_injects_csrf_token_fallback_when_no_cookie_csrf():
    # Cookie-authed SPA with NO CSRF cookie (Rails meta-tag CSRF): the captured token is injected.
    headers: dict = {}
    attach(headers, transport="api", cookies={"session": "abc"}, csrf_token="captured-xyz")
    assert headers["X-CSRF-Token"] == "captured-xyz"
    assert headers["X-Requested-With"] == "XMLHttpRequest"


def test_attach_csrf_cookie_wins_over_fallback():
    # When a CSRF cookie yields a token, the fallback must NOT override it.
    headers: dict = {}
    attach(headers, transport="api",
           cookies={"session": "abc", "CSRF-TOKEN": "from-cookie"}, csrf_token="fallback")
    assert headers["X-CSRF-Token"] == "from-cookie"


# --------------------------------------------------------------- attach()


def test_attach_api_sets_cookie_csrf_and_bearer():
    headers: dict = {}
    res = attach(headers, transport="api",
                 cookies={"session": "abc", "CSRF-TOKEN": "tok123"},
                 bearer_rec={"token": "BEAR", "exp": None})
    assert headers["Cookie"] == "session=abc; CSRF-TOKEN=tok123"
    assert headers["X-CSRF-Token"] == "tok123"
    assert headers["X-Requested-With"] == "XMLHttpRequest"
    assert headers["Authorization"] == "Bearer BEAR"
    assert headers["x-dast-cookies-injected"] == "1"
    assert res.attached_bearer is True


def test_attach_api_strips_model_cookie_unless_trusted():
    # Not trusted: a model-pasted Cookie/CSRF is replaced with the active session's.
    headers = {"Cookie": "evil=1", "X-CSRF-Token": "stale"}
    res = attach(headers, transport="api", cookies={"session": "real", "CSRF-TOKEN": "fresh"})
    assert headers["Cookie"] == "session=real; CSRF-TOKEN=fresh"   # re-seeded from the jar
    assert "evil=1" not in headers["Cookie"]
    assert headers["X-CSRF-Token"] == "fresh"                      # stale model CSRF refreshed
    assert res.overrode_session_header is True

    # Trusted marker: leave the model's cookie in place (we set it on a prior pass).
    headers2 = {"Cookie": "ours=1", "x-dast-cookies-injected": "1"}
    res2 = attach(headers2, transport="api", cookies={"session": "real"}, trusted_marker=True)
    assert headers2["Cookie"] == "ours=1"            # not overwritten
    assert res2.overrode_session_header is False


def test_attach_api_drop_all_authorization():
    # A non-secret caller Authorization survives the raw-secret strip but drop_all removes it,
    # so the resolved Bearer is attached instead.
    headers = {"Authorization": "Token notasecret"}
    attach(headers, transport="api", cookies={"session": "x"},
           bearer_rec={"token": "BEAR", "exp": None}, drop_all_authorization=True)
    assert headers["Authorization"] == "Bearer BEAR"

    # Without drop_all, a non-secret caller Authorization is kept and blocks the Bearer.
    headers2 = {"Authorization": "Token notasecret"}
    attach(headers2, transport="api", bearer_rec={"token": "BEAR", "exp": None})
    assert headers2["Authorization"] == "Token notasecret"


def test_attach_skips_expired_bearer():
    headers: dict = {}
    res = attach(headers, transport="api",
                 bearer_rec={"token": "OLD", "exp": time.time() - 10})
    assert "Authorization" not in headers
    assert res.attached_bearer is False


def test_attach_browser_strips_cookie_auth_keeps_csrf_and_bearer():
    headers = {"Cookie": "a=1", "Authorization": "Bearer caller", "Content-Type": "application/json"}
    attach(headers, transport="browser",
           cookies={"XSRF-TOKEN": "xt"},
           bearer_rec={"token": "RIDE", "exp": None})
    assert "Cookie" not in headers                   # browser context owns the jar
    assert headers["X-CSRF-Token"] == "xt"
    assert headers["X-Requested-With"] == "XMLHttpRequest"
    assert headers["Content-Type"] == "application/json"
    assert headers["Authorization"] == "Bearer RIDE"  # caller auth dropped, captured Bearer rides


def test_attach_no_cookies_is_a_clean_noop():
    # The MCP-process case: no store -> cookies None -> no Cookie set, no crash.
    headers: dict = {}
    res = attach(headers, transport="api", cookies=None, bearer_rec=None)
    assert headers == {}
    assert res.attached_bearer is False
    assert res.overrode_session_header is False


# ── cross-host / integration token graph (Pass B fallback) ──────────────────

def _jwt_aud(aud=None, exp=None) -> str:
    def seg(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
    p = {"sub": "1"}
    if aud is not None:
        p["aud"] = aud
    if exp is not None:
        p["exp"] = exp
    return f"{seg({'alg': 'HS512'})}.{seg(p)}.{seg('sig1234567890')}"


class _SG:
    def __init__(self, mapping):
        self._m = mapping
    def known_hosts_for(self, host):
        return list(self._m.get(host, []))


class _SGStore(_Store):
    def __init__(self, entries, sg):
        super().__init__(entries)
        self.service_graph = sg


_APP = "app.target.example"
_SSO = "sso.other.example"  # different apex -> only reachable via the service graph


def test_cross_host_fallback_with_matching_aud():
    tok = _jwt_aud(aud=["https://app.target.example/"])
    store = _SGStore([_entry(_SSO, "/oauth/token", tok)], _SG({_APP: [_SSO]}))
    rec = collect_host_bearer(store, _APP)
    assert rec and rec["token"] == tok and rec.get("cross_host") is True
    assert rec["matched_host"] == _SSO


def test_cross_host_rejected_by_unrelated_aud():
    tok = _jwt_aud(aud="service-c")
    store = _SGStore([_entry(_SSO, "/oauth/token", tok)], _SG({_APP: [_SSO]}))
    assert collect_host_bearer(store, _APP) is None


def test_cross_host_not_used_when_same_apex_exists():
    same = _jwt_aud()  # no aud; same-apex token on a subdomain of app.target.example
    sibling = _jwt_aud(aud="https://app.target.example/")
    store = _SGStore(
        [_entry("api.target.example", "/x", same), _entry(_SSO, "/oauth/token", sibling)],
        _SG({_APP: [_SSO]}))
    rec = collect_host_bearer(store, _APP)
    assert rec and rec["token"] == same and "cross_host" not in rec  # same-apex wins, Pass B skipped


def test_cross_host_none_without_service_graph():
    store = _Store([_entry(_SSO, "/oauth/token", _jwt_aud(aud=_APP))])  # no service_graph attr
    assert collect_host_bearer(store, _APP) is None


def test_cross_host_skips_expired_and_excluded():
    expired = _jwt_aud(aud=_APP, exp=int(time.time()) - 10)
    store = _SGStore([_entry(_SSO, "/oauth/token", expired)], _SG({_APP: [_SSO]}))
    assert collect_host_bearer(store, _APP) is None
    fresh = _jwt_aud(aud=_APP, exp=int(time.time()) + 3600)
    store2 = _SGStore([_entry(_SSO, "/oauth/token", fresh, source="copilot")], _SG({_APP: [_SSO]}))
    assert collect_host_bearer(store2, _APP, exclude_source="copilot") is None
