"""Unit tests for the copilot per-session isolation + sub-app auth + scope-guard fixes.

Covers:
- a scoped run sources cookies ONLY from its own named-session jar, never the shared
  global jar (cross-session cookie leak);
- a scoped run never borrows a Bearer from the shared proxy history (cross-session
  token leak — one run's session must never pick up another account's token);
- the Bearer cache selects the right sub-app token by request path (modstore vs ccm,
  which share one host) instead of letting one overwrite the other;
- the scope gate returns an escalating denial that names the real focus host, remembers
  a denied host so a repeat does not re-pause the operator, and is counted as a failure;
- the named-session cookie accessors on the store apply browser host-matching semantics.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import pytest

from dast.ai.copilot.session import CopilotSession
from dast.session.auth_provider import subapp_for_path as _subapp_for_path
from dast.proxy.session_store import SessionStore


@dataclass
class _Entry:
    host: str
    request_headers: Dict[str, str] = field(default_factory=dict)
    source: str = "proxy"
    id: str = "e1"
    path: str = "/"


class _Store:
    """Minimal store exposing the global + named-session accessors _apply_session_auth
    and the browser seed read."""

    def __init__(self, global_cookies: Optional[List[dict]] = None,
                 named: Optional[Dict[str, List[dict]]] = None,
                 entries: Optional[List[_Entry]] = None) -> None:
        self._global = global_cookies or []
        self._named = named or {}
        self._entries = entries or []

    def get_cookies_for_host(self, host: str) -> List[dict]:
        return list(self._global)

    def get_named_session_cookies_for_host(self, name: str, host: str) -> List[dict]:
        return list(self._named.get(name, []))

    def get_named_session_cookies(self, name: str) -> List[dict]:
        return list(self._named.get(name, []))

    def all_entries(self) -> List[_Entry]:
        return list(self._entries)


class _Ctx:
    def __init__(self, store: Any, in_scope: bool = True) -> None:
        self.store = store
        self._in_scope = in_scope

    def is_in_scope(self, url: str) -> bool:
        return self._in_scope


# --- item 1: cookie isolation -------------------------------------------------

def test_scoped_run_cookies_from_named_jar_not_global() -> None:
    store = _Store(
        global_cookies=[{"name": "session", "value": "GLOBAL_A"}],
        named={"profB": [{"name": "session", "value": "OWN_B", "domain": "in.scope"}]},
    )
    session = CopilotSession("s-iso1", focus_hosts=["in.scope"])
    session.session_name = "profB"
    args: Dict[str, Any] = {"url": "https://in.scope/x"}
    session._apply_session_auth(_Ctx(store), args)
    # The scoped run must use its OWN session cookie, never the global jar's.
    assert args["headers"]["Cookie"] == "session=OWN_B"


def test_unscoped_run_still_uses_global_jar() -> None:
    store = _Store(global_cookies=[{"name": "session", "value": "GLOBAL_A"}])
    session = CopilotSession("s-iso2")  # no focus, no session_name -> unscoped
    args: Dict[str, Any] = {"url": "https://in.scope/x"}
    session._apply_session_auth(_Ctx(store), args)
    assert args["headers"]["Cookie"] == "session=GLOBAL_A"


# --- item 1: Bearer leak ------------------------------------------------------

def test_scoped_run_never_borrows_bearer_from_global_history() -> None:
    store = _Store(
        named={"profB": [{"name": "session", "value": "OWN_B", "domain": "in.scope"}]},
        entries=[_Entry("in.scope", {"Authorization": "Bearer LEAK"})],
    )
    session = CopilotSession("s-iso3", focus_hosts=["in.scope"])
    session.session_name = "profB"
    args: Dict[str, Any] = {"url": "https://in.scope/api"}
    session._apply_session_auth(_Ctx(store), args)
    # The other run's token sitting in shared history must NOT be injected.
    assert "Authorization" not in args.get("headers", {})


# --- item 3: sub-app Bearer selection by path ---------------------------------

def test_select_bearer_by_subapp_path() -> None:
    session = CopilotSession("s-sub1")
    session._bearer_tokens["h"] = {
        "token": "DEFAULT",
        "by_app": {"modstore": {"token": "MOD"}, "ccm": {"token": "CCM"}},
    }
    assert session._select_bearer("h", "/modstore/graphql")["token"] == "MOD"
    assert session._select_bearer("h", "/customercontent/graphql")["token"] == "CCM"
    assert session._select_bearer("h", "/other")["token"] == "DEFAULT"


def test_subapp_for_path() -> None:
    assert _subapp_for_path("/modstore/graphql") == "modstore"
    assert _subapp_for_path("/customercontent/session") == "ccm"
    assert _subapp_for_path("/spa/session") is None


def test_scoped_run_injects_correct_subapp_bearer() -> None:
    store = _Store(named={"p": [{"name": "s", "value": "c", "domain": "in.scope"}]})
    session = CopilotSession("s-sub2", focus_hosts=["in.scope"])
    session.session_name = "p"
    session._bearer_tokens["in.scope"] = {
        "token": "DEF",
        "by_app": {"modstore": {"token": "MOD", "exp": None},
                   "ccm": {"token": "CCM", "exp": None}},
    }
    a1: Dict[str, Any] = {"url": "https://in.scope/modstore/graphql"}
    session._apply_session_auth(_Ctx(store), a1)
    assert a1["headers"]["Authorization"] == "Bearer MOD"
    a2: Dict[str, Any] = {"url": "https://in.scope/customercontent/graphql"}
    session._apply_session_auth(_Ctx(store), a2)
    assert a2["headers"]["Authorization"] == "Bearer CCM"


# --- item 4: scope guard ------------------------------------------------------

@pytest.mark.asyncio
async def test_scope_gate_denies_names_focus_and_remembers() -> None:
    session = CopilotSession("s-gate", focus_hosts=["in.scope"])
    ctx = _Ctx(_Store(), in_scope=False)

    async def deny(_kind: str, _payload: dict) -> dict:
        return {"decision": "deny"}

    async def observe(_entry: dict, _msg: str) -> None:
        return None

    args = {"url": "https://evil.invented/x", "method": "GET"}
    msg1 = await session._scope_gate("send_request", args, ctx, set(), {}, deny, observe)
    assert msg1 is not None
    assert "in.scope" in msg1  # names the real focus host
    assert session._denied_hosts["evil.invented"] == 1

    # A repeat must NOT re-pause the operator, and must escalate.
    async def must_not_pause(_kind: str, _payload: dict) -> dict:
        raise AssertionError("should not pause again for an already-denied host")

    msg2 = await session._scope_gate(
        "send_request", args, ctx, set(), {}, must_not_pause, observe)
    assert session._denied_hosts["evil.invented"] == 2
    assert "STOP inventing" in msg2


@pytest.mark.asyncio
async def test_scope_gate_allows_in_focus() -> None:
    session = CopilotSession("s-gate2", focus_hosts=["in.scope"])
    ctx = _Ctx(_Store(), in_scope=True)

    async def deny(_kind: str, _payload: dict) -> dict:
        return {"decision": "deny"}

    async def observe(_entry: dict, _msg: str) -> None:
        return None

    args = {"url": "https://in.scope/x", "method": "GET"}
    assert await session._scope_gate(
        "send_request", args, ctx, set(), {}, deny, observe) is None


# --- store accessors ----------------------------------------------------------

def test_named_session_cookie_accessors_host_matching() -> None:
    store = SessionStore()
    store.save_named_session_from_playwright(
        name="n", role="role", playwright_cookies=[
            {"name": "a", "value": "1", "domain": "in.scope"},
            {"name": "b", "value": "2", "domain": "other.com"},
            {"name": "c", "value": "3", "domain": ".in.scope"},
        ])
    for_host = store.get_named_session_cookies_for_host("n", "in.scope")
    assert {c["name"] for c in for_host} == {"a", "c"}  # host match, leading dot ok
    all_cookies = store.get_named_session_cookies("n")
    assert {c["name"] for c in all_cookies} == {"a", "b", "c"}
    assert store.get_named_session_cookies("missing") == []
