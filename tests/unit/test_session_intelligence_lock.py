"""Per-host intel hints are read under the owning SessionIntelligence lock."""

from dast.ai.session_intelligence import SessionIntelligence


def test_hosts_from_session_intelligence_share_its_lock():
    intelligence = SessionIntelligence()
    intel = intelligence.get("app.example.com")
    assert intel._shared_lock is intelligence._lock
    intel.record_scan_result("xss", found=True, path="/a")
    assert isinstance(intel.to_planner_hint("/a", []), str)
    assert isinstance(intel.to_mutator_hint("xss"), str)
