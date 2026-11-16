"""Unit tests for the deterministic dispatch rules
(`Coordinator._select_attack_types_for_params` + `_PARAM_ATTACK_MAP`).

Round 2-C: eight registered agents (open_redirect, xxe, prototype_pollution,
graphql_idor, cross_session_idor, password_reset, discovery, blazor) were NEVER
dispatched deterministically — reachable only via targeted `only_attack_types` or
a lucky LLM planner pick. These tests pin the structural rules that light them up
(and, with them, the coverage dimensions that were permanently empty).
"""

from __future__ import annotations

from dast.ai.coordinator import _select_attack_types_for_params
from dast.scanners.active_checks import CheckTarget


def _target(method="GET", url="https://app.test/items", headers=None, body=None, params=None,
            named_sessions=None):
    return CheckTarget(
        method=method, url=url, headers=headers or {"content-type": "application/json"},
        body=body, params=params or [], named_sessions=named_sessions or [],
    )


# ── xxe: XML surfaces ─────────────────────────────────────────────────────────

def test_xml_content_type_dispatches_xxe():
    target = _target(method="POST", headers={"content-type": "application/xml"},
                     body="<?xml version=\"1.0\"?><root/>")
    assert "xxe" in _select_attack_types_for_params(target, None)


def test_xml_shaped_body_dispatches_xxe_without_ct():
    target = _target(method="POST", headers={"content-type": "text/plain"},
                     body="<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY x \"y\">]>")
    assert "xxe" in _select_attack_types_for_params(target, None)


def test_json_body_does_not_dispatch_xxe():
    target = _target(method="POST", body='{"a": 1}')
    assert "xxe" not in _select_attack_types_for_params(target, None)


# ── graphql_idor ──────────────────────────────────────────────────────────────

def test_graphql_url_dispatches_graphql_idor():
    target = _target(method="POST", url="https://app.test/graphql",
                     body='{"query": "{ user(id: 1) { name } }"}')
    types = _select_attack_types_for_params(target, None)
    assert "graphql_idor" in types
    assert {"sqli", "nosql"} <= set(types)  # pre-existing graphql rule intact


def test_body_graphql_param_dispatches_graphql_idor():
    target = _target(method="POST",
                     params=[{"name": "id", "location": "body_graphql", "value": "5"}])
    assert "graphql_idor" in _select_attack_types_for_params(target, None)


# ── cross_session_idor: needs two named sessions ──────────────────────────────

def test_two_named_sessions_dispatch_cross_session_idor():
    target = _target(method="GET",
                     params=[{"name": "order_id", "location": "query", "value": "101"}],
                     named_sessions=["alice", "bob"])
    assert "cross_session_idor" in _select_attack_types_for_params(target, None)


def test_single_named_session_stays_out():
    target = _target(named_sessions=["alice"])
    assert "cross_session_idor" not in _select_attack_types_for_params(target, None)


# ── password_reset rides the link-shaped endpoint rule ────────────────────────

def test_reset_endpoint_dispatches_password_reset_and_host_header():
    target = _target(method="POST", url="https://app.test/users/password/reset",
                     body='{"email": "a@b.c"}')
    types = _select_attack_types_for_params(target, None)
    assert "password_reset" in types
    assert "host_header" in types


# ── GET-side orphans: discovery + blazor (+ pre-existing cache_poisoning) ─────

def test_get_dispatches_discovery_and_blazor():
    types = _select_attack_types_for_params(_target(), None)
    assert {"discovery", "blazor", "cache_poisoning"} <= set(types)


def test_post_does_not_dispatch_blazor_or_discovery():
    target = _target(method="POST", body='{"a": 1}')
    types = _select_attack_types_for_params(target, None)
    assert "blazor" not in types
    assert "discovery" not in types


# ── map entries: open_redirect / prototype_pollution / boolean flips ─────────

def test_string_param_gains_open_redirect():
    target = _target(params=[{"name": "q", "location": "query", "value": "x"}])
    assert "open_redirect" in _select_attack_types_for_params(target, None)


def test_json_param_gains_prototype_pollution():
    target = _target(method="POST", body='{"a": 1}',
                     params=[{"name": "filter", "location": "body", "value": '{"a":1}'}])
    assert "prototype_pollution" in _select_attack_types_for_params(target, None)


def test_boolean_param_gains_prototype_pollution_only():
    """Boolean values used to map to NOTHING (documented as 'no injection surface'),
    which also excluded the pollution-by-flip pattern; injection classes stay out."""
    target = _target(params=[{"name": "is_admin", "location": "query", "value": "true"}])
    types = _select_attack_types_for_params(target, None)
    assert "prototype_pollution" in types
    assert "sqli" not in types  # injection classes genuinely don't apply


def test_token_class_params_stay_uninjected():
    """`token` stays empty on purpose: JWT testing arrives with the 3-E agent."""
    target = _target(params=[{"name": "auth", "location": "query",
                              "value": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"}])
    types = _select_attack_types_for_params(target, None)
    assert "sqli" not in types and "xss" not in types
