"""Unit tests for dast.session.auth_provider — the single source of truth for sub-app
Bearer selection from proxy history (collapsed from two duplicate scans)."""

from __future__ import annotations

import base64
import json
import time

from dast.session.auth_provider import (
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
    assert subapp_for_path("/modstore/graphql") == "modstore"
    assert subapp_for_path("/customercontent/graphql") == "ccm"
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
        _entry(host, "/modstore/graphql", _jwt(), eid="b"),       # modstore sub-app
        _entry(host, "/customercontent/graphql", _jwt(), eid="c"),  # ccm sub-app
    ])
    rec = collect_host_bearer(store, host)
    assert rec and rec.get("token")
    assert set(rec.get("by_app", {})) == {"modstore", "ccm"}
    # host-level default for a non-sub-app path
    assert select_bearer(rec, "/v1/dashboard")["token"] == rec["token"]
    # per-sub-app selection
    assert select_bearer(rec, "/modstore/x")["auth_endpoint"] == "/modstore/graphql"
    assert select_bearer(rec, "/customercontent/x")["auth_endpoint"] == "/customercontent/graphql"


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
    store = _Store([_entry("sub.phisher.example", "/modstore/g", _jwt(), eid="x")])
    rec = scan_history_bearer(store, "api.phisher.example", "/modstore/y")
    assert rec and rec["auth_endpoint"] == "/modstore/g"   # matched on registrable domain
    assert scan_history_bearer(None, "h", "/p") is None    # null store -> None, no raise
