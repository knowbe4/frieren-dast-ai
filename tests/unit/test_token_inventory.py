"""Traffic-learned token inventory: builds a redacted credential landscape and NEVER leaks values."""

from __future__ import annotations

import base64
import json
import time

from dast.session.token_inventory import build_token_inventory


def _jwt(claims: dict) -> str:
    def seg(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{seg({'alg':'none'})}.{seg(claims)}.sig"


_BEARER = _jwt({"sub": "u1", "scope": "reports:read", "iss": "idp", "secretclaim": "leak-me",
                "exp": int(time.time()) + 3600})
_COOKIE_JWT = _jwt({"sub": "u1", "site": "app.example.com", "exp": int(time.time()) + 3600})
_APIKEY = "ak_SUPERSECRETVALUE123"
_QTOK = "qt_SECRETQUERYTOKEN456"


class _Entry:
    def __init__(self, host, path, headers=None, url=None, source="proxy"):
        self.host = host
        self.path = path
        self.url = url or f"https://{host}{path}"
        self.request_headers = headers or {}
        self.source = source


class _Store:
    def __init__(self, entries, cookies):
        self._entries = entries
        self._cookies = cookies

    def in_scope_entries(self):
        return list(self._entries)

    def all_entries(self):
        return list(self._entries)

    def get_cookies_for_host(self, host):
        return list(self._cookies)

    def get_cookie_hosts(self):
        return ["app.example.com"]


def _store():
    entries = [
        _Entry("app.example.com", "/reports/graphql",
               headers={"Authorization": f"Bearer {_BEARER}"}),
        _Entry("app.example.com", "/svc/data",
               headers={"X-Api-Key": _APIKEY}),
        _Entry("app.example.com", "/dl",
               url=f"https://app.example.com/dl?access_token={_QTOK}&page=1"),
        _Entry("app.example.com", "/copilot-replay",
               headers={"X-Api-Key": "should-be-ignored"}, source="copilot"),
    ]
    cookies = [
        {"name": "_session", "value": _COOKIE_JWT, "domain": "app.example.com",
         "path": "/", "secure": True, "httpOnly": True},
        {"name": "CSRF-TOKEN", "value": "csrf-raw-value", "domain": "app.example.com",
         "path": "/", "secure": True, "httpOnly": False},
    ]
    return _Store(entries, cookies)


def test_inventory_lists_each_credential_type():
    inv = build_token_inventory(_store(), "app.example.com")
    assert inv["host"] == "app.example.com"
    # Bearer discovered with its safe claims; endpoint recorded.
    assert any(b["type"] == "jwt" and b["claims"].get("scope") == "reports:read"
               and b["fresh"] for b in inv["bearers"])
    # Cookie-with-JWT and plain cookie, with flags.
    names = {c["name"]: c for c in inv["cookies"]}
    assert names["_session"]["type"] == "cookie+jwt" and names["_session"]["httpOnly"] is True
    assert names["CSRF-TOKEN"]["type"] == "cookie"
    # Custom header + query token (copilot-sourced entry ignored).
    assert [h["name"] for h in inv["headers"]] == ["X-Api-Key"]
    assert inv["headers"][0]["endpoint"] == "/svc/data"
    assert [q["param"] for q in inv["query_tokens"]] == ["access_token"]


def test_inventory_never_leaks_values_or_unsafe_claims():
    inv = build_token_inventory(_store(), "app.example.com")
    blob = json.dumps(inv)
    for secret in (_BEARER, _COOKIE_JWT, _APIKEY, _QTOK, "csrf-raw-value", "leak-me"):
        assert secret not in blob, f"leaked secret-ish value: {secret[:12]}"
    # Fingerprints present (to distinguish credentials) but short + non-reversible.
    assert all(len(b["fingerprint"]) == 8 for b in inv["bearers"])
    # Unsafe JWT claim dropped from the allowlist.
    for b in inv["bearers"]:
        assert "secretclaim" not in b["claims"]


def test_expired_bearer_marked_stale():
    expired = _jwt({"sub": "u", "exp": int(time.time()) - 10})
    st = _Store([_Entry("h.example", "/x/graphql",
                        headers={"Authorization": f"Bearer {expired}"})], [])
    inv = build_token_inventory(st, "h.example")
    # An already-expired token is dropped by collect_host_bearer (freshness filter) -> no bearers.
    assert inv["bearers"] == []


def test_empty_store_and_brief_block():
    assert build_token_inventory(None, "h")["bearers"] == []
    from dast.ai.copilot.context_brief import _token_inventory_block
    assert _token_inventory_block(None, "h") == ""
    block = _token_inventory_block(_store(), "app.example.com")
    assert block.startswith("## Token inventory — app.example.com")
    assert "JWT bearers" in block and "cookies:" in block
