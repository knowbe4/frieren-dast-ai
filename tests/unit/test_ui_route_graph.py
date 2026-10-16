"""
Unit tests for the UI-route graph / frontier that backs complete-mode coverage.
"""

from __future__ import annotations

from dast.proxy.ui_route_graph import UiRouteGraph, normalise_route_key


def test_normalise_route_key_collapses_ids_and_drops_query():
    a = normalise_route_key("https://app.example.com/orders/1?x=1")
    b = normalise_route_key("https://app.example.com/orders/2?x=9")
    assert a == b == "app.example.com/orders/:id"


def test_normalise_route_key_normalises_hash_route():
    a = normalise_route_key("https://app.example.com/#/users/42/edit")
    b = normalise_route_key("https://app.example.com/#/users/99/edit")
    assert a == b
    assert a.endswith("#/users/:id/edit")


def test_add_discovered_is_deduped_and_reports_new():
    g = UiRouteGraph()
    assert g.add_discovered("https://app.example.com/orders/1") is True
    # Same endpoint template (different id) is not new.
    assert g.add_discovered("https://app.example.com/orders/2") is False
    assert g.stats()["total"] == 1
    assert g.stats()["frontier"] == 1


def test_mark_visited_moves_out_of_frontier():
    g = UiRouteGraph()
    g.add_discovered("https://app.example.com/dashboard")
    key = normalise_route_key("https://app.example.com/dashboard")
    g.mark_visited(key, api_entries=3, interactive_elements=5, forms_submitted=1)
    assert g.stats() == {"total": 1, "visited": 1, "frontier": 0, "failed": 0, "forms_submitted": 1}
    assert g.frontier() == []
    assert g.visited()[0].api_entries == 3


def test_visited_route_is_not_reopened():
    g = UiRouteGraph()
    g.add_discovered("https://app.example.com/x")
    key = normalise_route_key("https://app.example.com/x")
    g.mark_visited(key)
    assert g.add_discovered("https://app.example.com/x") is False
    assert g.stats()["visited"] == 1


def test_mark_failed_only_if_not_visited():
    g = UiRouteGraph()
    g.add_discovered("https://app.example.com/a")
    g.add_discovered("https://app.example.com/b")
    ka = normalise_route_key("https://app.example.com/a")
    kb = normalise_route_key("https://app.example.com/b")
    g.mark_visited(kb)
    g.mark_failed(ka)
    g.mark_failed(kb)  # already visited — must stay visited
    stats = g.stats()
    assert stats["failed"] == 1 and stats["visited"] == 1


def test_round_trip_serialization():
    g = UiRouteGraph()
    g.add_discovered("https://app.example.com/one", via="seed")
    g.add_discovered("https://app.example.com/two", via="nav", parent="app.example.com/one", depth=1)
    g.mark_visited(normalise_route_key("https://app.example.com/one"), api_entries=2)
    restored = UiRouteGraph.from_list(g.to_list())
    assert restored.stats() == g.stats()


def test_from_list_tolerates_bad_rows():
    restored = UiRouteGraph.from_list([
        {"route_key": "h/x", "url": "https://h/x", "state": "frontier"},
        {"not_a_route": True},            # missing route_key — skipped
        "garbage",                         # not a dict — skipped
        {"route_key": "h/y", "url": "https://h/y", "bogus_field": 1},  # extra field ignored
    ])
    assert restored.stats()["total"] == 2


def test_from_list_handles_empty():
    assert UiRouteGraph.from_list(None).stats()["total"] == 0
    assert UiRouteGraph.from_list([]).stats()["total"] == 0
