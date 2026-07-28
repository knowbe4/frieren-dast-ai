"""
Unit tests for central WAF/block detection (dast/agents/block_detector.py) and
the per-host bypass memory that feeds the mutator (Gap 2).

Two guarantees under test:
  1. A block is detected from a content signature even on HTTP 200 — the case
     the old status-only checks missed, which made the mutator give up instead
     of attempting a bypass.
  2. A payload that bypassed a block on one endpoint is remembered per host and
     surfaced to the mutator (via to_mutator_hint) ahead of blocked payloads.
"""

from __future__ import annotations

from dast.agents.block_detector import detect_block
from dast.ai.session_intelligence import SessionIntelligence, _detect_waf


class TestDetectBlock:
    def test_block_page_on_http_200_is_detected(self):
        # The core gap: a WAF that answers 200 with a block page.
        v = detect_block(200, "Access Denied. Your request has been blocked.")
        assert v.is_block
        assert v.reason == "content"

    def test_cloudflare_interstitial_on_200(self):
        v = detect_block(200, "<title>Attention Required! | Cloudflare</title>")
        assert v.is_block and v.reason == "content"

    def test_clean_200_is_not_a_block(self):
        v = detect_block(200, '{"results": [1, 2, 3], "total": 3}')
        assert not v.is_block

    def test_classic_403_status(self):
        v = detect_block(403, "forbidden")
        assert v.is_block and v.reason == "status"

    def test_429_sets_rate_limit_flag(self):
        v = detect_block(429, "slow down")
        assert v.is_block and v.is_rate_limit

    def test_non_429_block_is_not_rate_limit(self):
        assert not detect_block(403, "nope").is_rate_limit

    def test_content_signature_wins_over_status(self):
        # A 200 block page reports reason=content, not status.
        v = detect_block(200, "The requested URL was rejected. Your support ID is 123.")
        assert v.reason == "content"

    def test_size_collapse_needs_large_baseline(self):
        # Big healthy baseline, tiny response now → weak block signal fires.
        v = detect_block(200, "x" * 10, baseline_len=5000)
        assert v.is_block and v.reason == "size_collapse"

    def test_size_collapse_ignored_without_baseline(self):
        # No baseline → a naturally short clean response is not a block.
        assert not detect_block(200, "ok").is_block

    def test_small_baseline_does_not_trigger_collapse(self):
        # Baseline not much larger than the stub → no false collapse signal.
        assert not detect_block(200, "short", baseline_len=600).is_block

    def test_signal_is_populated_for_observe(self):
        v = detect_block(403, "blocked by firewall")
        assert v.signal  # ready to pass into VulnAgent.observe(signal=...)


class TestDetectWafContentAware:
    def test_vendor_detected_on_200_block_page(self):
        # _detect_waf now fingerprints vendor even when the status is 200, as
        # long as a block page is recognised.
        vendor = _detect_waf(200, {}, "cloudflare: attention required, cf-ray: abc")
        assert vendor == "cloudflare"

    def test_no_waf_on_clean_200(self):
        assert _detect_waf(200, {}, '{"ok": true}') is None


class TestBypassMemory:
    def test_bypass_recorded_and_surfaced_to_mutator(self):
        si = SessionIntelligence()
        si.record_scan_complete(
            host="a.com", path="/p1", attack_type="sqli", found=False,
            waf_signal=("1 OR 1=1", "HTTP 403: blocked"),
        )
        si.record_scan_complete(
            host="a.com", path="/p1", attack_type="sqli", found=True,
            bypass_payload="1/**/OR/**/1=1",
        )
        hint = si.get("a.com").to_mutator_hint("sqli")
        assert "bypassed the block" in hint
        assert "1/**/OR/**/1=1" in hint
        # Blocked payload is still listed as context.
        assert "1 OR 1=1" in hint

    def test_bypass_is_per_attack_type(self):
        si = SessionIntelligence()
        si.record_scan_complete(
            host="a.com", path="/p", attack_type="sqli", found=True,
            bypass_payload="sqli-bypass",
        )
        # A different attack type on the same host does not see it.
        assert "sqli-bypass" not in si.get("a.com").to_mutator_hint("xss")

    def test_duplicate_bypass_not_stored_twice(self):
        intel = SessionIntelligence().get("a.com")
        intel.record_bypass("sqli", "same-payload")
        intel.record_bypass("sqli", "same-payload")
        assert intel.waf_bypasses.count(("same-payload", "sqli")) == 1

    def test_empty_bypass_ignored(self):
        intel = SessionIntelligence().get("a.com")
        intel.record_bypass("sqli", "")
        assert not intel.waf_bypasses

    def test_no_waf_history_yields_empty_hint(self):
        assert SessionIntelligence().get("clean.com").to_mutator_hint("sqli") == ""


class TestBuildMutatorContext:
    def test_combines_host_intel_waf_hint(self):
        from dast.ai.mutator import build_mutator_context

        si = SessionIntelligence()
        si.record_scan_complete(
            host="a.com", path="/p", attack_type="sqli", found=True,
            bypass_payload="proven-bypass",
        )

        class _Target:
            discovery_context = None
            host_intel = si.get("a.com")

        ctx = build_mutator_context(_Target(), "sqli")
        assert ctx and "proven-bypass" in ctx

    def test_returns_none_when_nothing_known(self):
        from dast.ai.mutator import build_mutator_context

        class _Target:
            discovery_context = None
            host_intel = None

        assert build_mutator_context(_Target(), "sqli") is None
