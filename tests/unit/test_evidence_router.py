"""
Unit tests for the pure evidence -> action router (dast/ai/evidence_router.py).

route() is pure over a RouterEvidence bundle, so these build fixtures directly —
no store, no network.
"""

from __future__ import annotations

from types import SimpleNamespace

from dast.ai.evidence_router import RouterEvidence, route


def _edge(url, param, value, confidence=0.9):
    return SimpleNamespace(target_url=url, target_param=param, sample_value=value, confidence=confidence)


def _kinds(plan):
    return {(r.kind, r.attack_type) for r in plan.recommend}


def test_numeric_id_flow_recommends_sqli_and_idor():
    ev = RouterEvidence(call_edges=[_edge("https://h/api/u", "id", "123")])
    plan = route(ev)
    assert ("run_scan", "sqli") in _kinds(plan)
    assert ("idor_probe", "idor") in _kinds(plan)
    # high-confidence (0.9) edge -> auto_safe
    assert all(r.auto_safe for r in plan.recommend)


def test_non_id_param_is_not_routed():
    ev = RouterEvidence(call_edges=[_edge("https://h/api/s", "q", "hello")])
    assert route(ev).recommend == []


def test_llm_endpoint_recommends_llm_injection_auto_safe():
    ev = RouterEvidence(llm_endpoints=[("https://h/v1/chat", "/v1/chat")])
    plan = route(ev)
    recs = [r for r in plan.recommend if r.attack_type == "llm_injection"]
    assert recs and recs[0].kind == "run_scan" and recs[0].auto_safe


def test_mysql_excludes_mssql_and_recommends_no_mssql():
    ev = RouterEvidence(tech_stack=SimpleNamespace(database_hints=["MySQL"]))
    plan = route(ev)
    assert any("MySQL" in a.reason for a in plan.avoid)
    assert any("MSSQL" in a.reason for a in plan.avoid)


def test_vuln_hypothesis_routes_to_agent():
    hyp = SimpleNamespace(attack_type="xss", endpoint="https://h/search", parameter="q",
                          rationale="reflected param", priority="high")
    ev = RouterEvidence(app_profile=SimpleNamespace(vuln_hypotheses=[hyp]))
    plan = route(ev)
    recs = [r for r in plan.recommend if r.attack_type == "xss"]
    assert recs and recs[0].auto_safe and recs[0].confidence >= 0.8


def test_graphql_endpoint_recommends_sweep_unless_tested():
    ev = RouterEvidence(graphql_endpoints={"https://h/graphql"})
    assert ("graphql_sweep", "") in _kinds(route(ev))
    # already swept -> dropped
    ev2 = RouterEvidence(graphql_endpoints={"https://h/graphql"}, tested_gql_ops={"https://h/graphql"})
    assert route(ev2).recommend == []


def test_already_tested_endpoint_is_dropped():
    ev = RouterEvidence(
        call_edges=[_edge("https://h/api/u", "id", "123")],
        tested_ledger={("/api/u", "*")},
    )
    assert route(ev).recommend == []  # endpoint already scanned


def test_confirmed_and_ineffective_are_excluded():
    intel = SimpleNamespace(consistently_ineffective_types=lambda: {"sqli"})
    ev = RouterEvidence(
        call_edges=[_edge("https://h/api/u", "id", "123")],
        host_intel=intel,
    )
    plan = route(ev)
    # sqli ruled out host-wide, but idor still recommended
    assert ("run_scan", "sqli") not in _kinds(plan)
    assert ("idor_probe", "idor") in _kinds(plan)
    assert any(a.attack_type == "sqli" for a in plan.avoid)


def test_empty_evidence_is_empty_plan():
    plan = route(RouterEvidence())
    assert plan.recommend == [] and plan.avoid == []
    assert plan.to_prompt_block() == ""


def test_auto_actions_drops_active_in_read_only():
    ev = RouterEvidence(llm_endpoints=[("https://h/v1/chat", "/v1/chat")])
    plan = route(ev)
    assert plan.auto_actions(read_only=False)          # run_scan present when active
    assert plan.auto_actions(read_only=True) == []     # dropped in read-only
