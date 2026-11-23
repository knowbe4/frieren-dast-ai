"""Coverage ledger tests (dast/coverage/ledger.py).

Gap-derivation cases mirror ARTEX's coverage_ledger_test.go table; the
translation cases pin the machine-observed mapping the Coordinator feeds in
(findings → reported, blockers → needs_follow_up, ran-clean → no_issue_found
with probe-count evidence).
"""

from __future__ import annotations

import pytest

from dast.coverage import ledger as cov


@pytest.fixture(autouse=True)
def _isolate():
    cov.reset()
    yield
    cov.reset()


def _rec(area="sqli", outcome="no_issue_found", **kw):
    kw.setdefault("method", "GET")
    kw.setdefault("host", "app.example.com")
    kw.setdefault("path", "/items")
    return cov.record(risk_area=area, outcome=outcome, **kw)


# ── machine-observed translation ─────────────────────────────────────────────

def test_findings_become_reported_with_evidence():
    cov.record_scan_outcome("GET", "app.example.com", "/items", "list", "sqli",
                            findings=["SQLi in q (confirmed)", "second"])
    (e,) = cov.entries_for("GET", "/items", "list")
    assert e.outcome == "reported"
    assert "SQLi in q (confirmed)" in e.evidence


def test_ran_clean_is_no_issue_found_with_probe_evidence():
    cov.record_scan_outcome("GET", "app.example.com", "/items", "list", "xss",
                            probe_count=7)
    (e,) = cov.entries_for("GET", "/items", "list")
    assert e.outcome == "no_issue_found"
    assert "7 probes" in e.evidence  # an absent finding is NOT a silent pass


def test_blockers_become_needs_follow_up():
    cov.record_scan_outcome("GET", "app.example.com", "/items", "list", "sqli",
                            blockers=["budget_timeout"])
    (e,) = cov.entries_for("GET", "/items", "list")
    assert e.outcome == "needs_follow_up"
    assert "budget_timeout" in e.reason


def test_auth_blockers_become_not_applicable():
    cov.record_scan_outcome("GET", "app.example.com", "/admin", "list", "idor",
                            blockers=["401 unauthorized"])
    (e,) = cov.entries_for("GET", "/admin", "list")
    assert e.outcome == "not_applicable"


def test_bad_outcome_is_an_error_never_a_truncate():
    with pytest.raises(ValueError):
        cov.record("GET", "app.example.com", "/x", "", "sqli", outcome="sorta-fine")


# ── upsert + history ─────────────────────────────────────────────────────────

def test_upsert_last_write_wins_and_history_keeps_both():
    cov.record_scan_outcome("GET", "app.example.com", "/items", "list", "sqli",
                            blockers=["budget_timeout"])
    cov.record_scan_outcome("GET", "app.example.com", "/items", "list", "sqli",
                            findings=["SQLi confirmed"])
    (current,) = cov.entries_for("GET", "/items", "list")
    assert current.outcome == "reported"
    hist = cov.history_for("GET", "/items", "list", "list" and "sqli")
    assert [h.outcome for h in hist] == ["needs_follow_up"]


def test_fields_are_normalised_to_one_line():
    e = cov.record("GET", "app.example.com", "/x", "", "sqli", outcome="needs_follow_up",
                   reason="waf blocked\n\twith  details\r\nand more")
    assert "\n" not in e.reason and "\t" not in e.reason
    assert e.reason == "waf blocked with details and more"


def test_global_cap_rejects_new_keys_but_allows_updates(monkeypatch):
    cov.reset()  # defensive: this test pins the store size, not whatever ran before
    monkeypatch.setattr(cov, "_MAX_ENTRIES", 2)
    cov.record("GET", "h1", "/a", "", "sqli", outcome="no_issue_found", evidence="1 probes")
    cov.record("GET", "h1", "/b", "", "sqli", outcome="no_issue_found", evidence="1 probes")
    with pytest.raises(ValueError):
        cov.record("GET", "h1", "/c", "", "sqli", outcome="no_issue_found", evidence="1")
    # updating an EXISTING key is always allowed (same surface + risk_area)
    cov.record("GET", "h1", "/a", "", "sqli", outcome="reported", evidence="found")


# ── gap derivation (ARTEX coverage_ledger_test.go table) ────────────────────

def _build(entries, candidates=None):
    return cov.build_ledger(entries, candidate_classes=candidates)


def test_no_entry_means_unexamined_never_clean():
    ledger = _build([], candidates=["sqli", "xss"])
    assert ledger["unexamined"] == ["sqli", "xss"]
    assert [g.as_line() for g in ledger["gaps"]] == [
        "unrecorded_risk_class sqli", "unrecorded_risk_class xss"]


def test_no_issue_found_without_evidence_is_a_gap():
    entries = [_rec("sqli", "no_issue_found", evidence="")]
    ledger = _build(entries, candidates=["sqli"])
    assert "sqli" in ledger["unexamined"]  # without evidence the class is NOT covered
    # the central invariant leads; the per-entry gap follows
    assert [g.kind for g in ledger["gaps"]] == ["unrecorded_risk_class", "missing_evidence"]


def test_no_issue_found_with_evidence_closes_the_class():
    entries = [_rec("sqli", "no_issue_found", evidence="5 probes, no signal")]
    ledger = _build(entries, candidates=["sqli"])
    assert ledger["unexamined"] == []
    assert ledger["gaps"] == []


def test_ruled_out_needs_reason():
    entries = [_rec("sqli", "ruled_out", reason="")]
    ledger = _build(entries, candidates=["sqli"])
    assert [g.kind for g in ledger["gaps"]] == ["unrecorded_risk_class", "missing_reason"]


def test_needs_follow_up_covers_but_keeps_gap_open():
    entries = [_rec("sqli", "needs_follow_up", reason="budget_timeout")]
    ledger = _build(entries, candidates=["sqli"])
    assert ledger["unexamined"] == []  # covered…
    assert ledger["gaps"][0].as_line() == "needs_follow_up GET /items sqli"  # …but open


def test_unrecorded_classes_come_first_in_gap_order():
    entries = [_rec("xss", "needs_follow_up", reason="waf")]
    ledger = _build(entries, candidates=["sqli", "xss"])
    kinds = [g.kind for g in ledger["gaps"]]
    assert kinds[0] == "unrecorded_risk_class"  # the central invariant first
    assert "needs_follow_up" in kinds


def test_risk_area_matching_is_case_insensitive():
    entries = [_rec("SQLI", "reported", evidence="found")]
    ledger = _build(entries, candidates=["sqli"])
    assert ledger["unexamined"] == []
    assert ledger["findings_by_class"] == {"sqli": 1}


# ── completeness caveats ─────────────────────────────────────────────────────

def test_complete_run_has_no_caveat():
    c = cov.completeness_for("")
    assert c.complete is True and c.caveat == ""


@pytest.mark.parametrize("reason,state", [
    ("budget", "budget"), ("timeout", "timeout"), ("cancelled", "aborted"),
    ("paused", "paused"), ("weird", "weird"),
])
def test_incomplete_runs_always_carry_a_caveat(reason, state):
    c = cov.completeness_for(reason)
    assert c.complete is False
    assert c.state == state
    assert c.caveat  # never silent
    assert "does not mean the target is clean" in c.caveat or "partial" in c.caveat


# ── planner lines + snapshot ─────────────────────────────────────────────────

def test_planner_gap_lines_top_n_and_empty_when_clean():
    assert cov.planner_gap_lines("GET", "/items") == []  # no entries → nothing to say
    cov.record_scan_outcome("GET", "app.example.com", "/items", "list", "sqli",
                            blockers=["budget_timeout"])
    lines = cov.planner_gap_lines("GET", "/items", "list", candidate_classes=["xss"])
    assert lines[0] == "unrecorded_risk_class xss"
    assert "needs_follow_up GET /items (list) sqli" in lines
    assert len(lines) <= 3


def test_snapshot_aggregates_per_host():
    cov.record_scan_outcome("GET", "a.example.com", "/x", "", "sqli",
                            findings=["found"])
    cov.record_scan_outcome("GET", "a.example.com", "/y", "", "xss", probe_count=3)
    cov.record_scan_outcome("GET", "b.example.com", "/z", "", "sqli",
                            blockers=["budget_timeout"])
    snap = cov.snapshot()
    assert snap["total_entries"] == 3
    assert snap["hosts"]["a.example.com"]["findings"] == 1
    assert snap["hosts"]["b.example.com"]["needs_follow_up"] == ["GET /z sqli"]
    only_a = cov.snapshot(host="a.example.com")
    assert list(only_a["hosts"].keys()) == ["a.example.com"]
