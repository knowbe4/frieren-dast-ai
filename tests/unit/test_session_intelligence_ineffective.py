"""Host-wide "consistently ineffective" gating for attack-type candidate selection.

Regression guard for a false-negative class: a single speculative probe failing on
one endpoint (e.g. sqli on a search field that isn't SQL-backed) used to blacklist
the attack type host-wide, suppressing it on a later endpoint where it was the real
vulnerability (error-based sqli on DVWA /sqli/, csrf on /exec/).
"""

from dast.ai.session_intelligence import (
    _CONSISTENT_INEFFECTIVE_MIN_PATHS,
    HostIntel,
)


class TestConsistentlyIneffectiveTypes:
    def test_single_failed_path_does_not_suppress(self) -> None:
        intel = HostIntel(host="127.0.0.1")
        intel.record_scan_result("sqli", found=False, path="/vulnerabilities/xss_r/")
        # One failed endpoint is not enough to blacklist the type host-wide.
        assert "sqli" not in intel.consistently_ineffective_types()

    def test_multiple_distinct_failed_paths_suppress(self) -> None:
        intel = HostIntel(host="127.0.0.1")
        intel.record_scan_result("sqli", found=False, path="/a")
        intel.record_scan_result("sqli", found=False, path="/b")
        assert "sqli" in intel.consistently_ineffective_types()

    def test_same_path_twice_counts_once(self) -> None:
        intel = HostIntel(host="127.0.0.1")
        intel.record_scan_result("sqli", found=False, path="/a")
        intel.record_scan_result("sqli", found=False, path="/a")
        # Distinct paths, not attempts — one endpoint must not self-blacklist.
        assert len(intel.ineffective_paths["sqli"]) == 1
        assert "sqli" not in intel.consistently_ineffective_types()

    def test_confirmed_vuln_clears_ineffective_paths(self) -> None:
        intel = HostIntel(host="127.0.0.1")
        intel.record_scan_result("sqli", found=False, path="/a")
        intel.record_scan_result("sqli", found=False, path="/b")
        assert "sqli" in intel.consistently_ineffective_types()
        intel.record_confirmed_vuln("/c", "id", "sqli")
        # A confirmed finding proves the type works — never call it ineffective.
        assert "sqli" not in intel.consistently_ineffective_types()
        assert "sqli" not in intel.ineffective_paths

    def test_effective_type_never_ineffective(self) -> None:
        intel = HostIntel(host="127.0.0.1")
        intel.record_confirmed_vuln("/a", "id", "sqli")
        intel.record_scan_result("sqli", found=False, path="/b")
        intel.record_scan_result("sqli", found=False, path="/c")
        assert "sqli" not in intel.consistently_ineffective_types()

    def test_threshold_constant_is_more_than_one(self) -> None:
        # The whole point is that one failure is insufficient.
        assert _CONSISTENT_INEFFECTIVE_MIN_PATHS >= 2
