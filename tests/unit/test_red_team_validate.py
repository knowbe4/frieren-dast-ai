"""
Unit tests for dast.ai.red_team — both the deterministic _pattern_confidence
heuristic (migrated here from test_agent_logic.py for locality) and the async
validate() pipeline, which is exercised end-to-end via a fake Bedrock client.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

import pytest

from dast.ai import bedrock_client, red_team


# ── shared fakes ──────────────────────────────────────────────────────────

@dataclass
class _FakeFinding:
    title: str = "Test Finding"
    severity: str = "high"
    cwe: str = "CWE-89"
    attack_type: str = "sqli"
    evidence: str = ""
    payload: str = "'"
    parameter: str = "id"
    url: str = "https://example.com/api"
    request_method: str = "GET"
    confirmed: bool = True
    bypass_validation: bool = False
    ai_validated: bool = False
    reasoning: str = ""
    raw_response_snippet: str = ""
    browser_confirmed: Optional[bool] = None
    browser_confirm_reason: str = ""
    raw_request: str = ""
    raw_response: str = ""
    probe_request: str = ""
    probe_response: str = ""


@dataclass
class _FakeTarget:
    url: str = "https://example.com/api"
    method: str = "GET"
    headers: Dict = field(default_factory=dict)
    body: Optional[str] = None
    params: List = field(default_factory=list)
    discovery_context: Optional[object] = None
    threat_model_hint: str = ""
    code_hint: str = ""


# ── _pattern_confidence (migrated from test_agent_logic.py) ────────────────

class TestPatternConfidence:
    def test_sqli_timebased_high(self):
        f = _FakeFinding(attack_type="sqli", evidence="Response delayed 5200ms with 5s delay in param 'id'")
        assert red_team._pattern_confidence(f) >= 0.80

    def test_sqli_error_based_high(self):
        f = _FakeFinding(attack_type="sqli", raw_response_snippet="SQL syntax error near 'OR 1=1'")
        assert red_team._pattern_confidence(f) >= 0.75

    def test_ssti_evaluated_high(self):
        f = _FakeFinding(attack_type="ssti", raw_response_snippet="Result: 49")
        assert red_team._pattern_confidence(f) >= 0.80

    def test_open_redirect_high(self):
        f = _FakeFinding(attack_type="open_redirect", evidence="Redirected to evil.example.com")
        assert red_team._pattern_confidence(f) >= 0.75

    def test_crlf_injected_high(self):
        f = _FakeFinding(attack_type="crlf", raw_response_snippet="Set-Cookie: crlf=injected; Path=/")
        assert red_team._pattern_confidence(f) >= 0.75

    def test_mfa_bypass_accepted_high(self):
        f = _FakeFinding(attack_type="mfa_bypass", evidence="OTP accepted with invalid code, status 200")
        assert red_team._pattern_confidence(f) >= 0.75

    def test_mfa_bypass_no_rate_limit_medium(self):
        f = _FakeFinding(attack_type="mfa_bypass", evidence="Sent 4 invalid OTPs — no 429 rate limit response")
        assert red_team._pattern_confidence(f) >= 0.60

    def test_unknown_attack_type_fallback(self):
        f = _FakeFinding(attack_type="unknown_future_type", evidence="some evidence")
        assert red_team._pattern_confidence(f) == 0.40

    def test_xss_no_browser_is_low(self):
        f = _FakeFinding(attack_type="xss")
        assert red_team._pattern_confidence(f) < 0.50


class TestBrowserConfidence:
    def test_no_browser_attempt_returns_none(self):
        f = _FakeFinding(browser_confirmed=None)
        assert red_team._browser_confidence(f) is None

    def test_browser_confirmed_true_is_high(self):
        f = _FakeFinding(browser_confirmed=True)
        assert red_team._browser_confidence(f) == 0.92

    def test_browser_confirmed_false_is_low(self):
        f = _FakeFinding(browser_confirmed=False)
        assert red_team._browser_confidence(f) == 0.30


# ── validate() — fp_filter short-circuit ────────────────────────────────────

@pytest.mark.asyncio
async def test_fp_filter_rejects_short_circuits_before_llm(monkeypatch):
    called = False

    def _invoke_json(*args, **kwargs):
        nonlocal called
        called = True
        return {"confirmed": True, "confidence": 0.9}

    monkeypatch.setattr(bedrock_client, "invoke_json", _invoke_json)

    finding = _FakeFinding(attack_type="xss")
    target = _FakeTarget(headers={"content-type": "application/json"})

    confirmed, confidence, reason = await red_team.validate(finding, target)

    assert confirmed is False
    assert confidence == 0.0
    assert "JSON" in reason
    assert called is False


# ── validate() — LLM confirms / rejects ─────────────────────────────────────

@pytest.mark.asyncio
async def test_llm_confirms_with_high_confidence(monkeypatch):
    monkeypatch.setattr(bedrock_client, "invoke_json", lambda *a, **k: {
        "confirmed": True, "confidence": 0.9,
        "exploit_scenario": "attacker dumps the users table",
        "reasoning": "raw SQL error observed",
    })

    finding = _FakeFinding(
        attack_type="sqli",
        raw_response_snippet="SQL syntax error near 'OR 1=1'",
    )
    target = _FakeTarget()

    confirmed, confidence, reasoning = await red_team.validate(finding, target, confidence_threshold=0.5)

    assert confirmed is True
    assert confidence == 0.9
    assert "raw SQL error observed" in finding.reasoning
    assert "attacker dumps the users table" in finding.reasoning


@pytest.mark.asyncio
async def test_llm_rejects_even_when_final_confidence_would_clear_threshold(monkeypatch):
    # pattern_conf for sqli-error-based is 0.80, well above the 0.5 threshold —
    # but the LLM explicitly rejects, and the "and" gate must still win.
    monkeypatch.setattr(bedrock_client, "invoke_json", lambda *a, **k: {
        "confirmed": False, "confidence": 0.1,
        "exploit_scenario": "", "reasoning": "error message is generic, not exploitable",
    })

    finding = _FakeFinding(
        attack_type="sqli",
        raw_response_snippet="SQL syntax error near 'OR 1=1'",
    )
    target = _FakeTarget()

    confirmed, confidence, reasoning = await red_team.validate(finding, target, confidence_threshold=0.5)

    assert confirmed is False
    # final_confidence is still max(pattern_conf, llm_confidence) = 0.80
    assert confidence == pytest.approx(0.80)


# ── validate() — threshold boundary ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_confidence_exactly_at_threshold_confirms(monkeypatch):
    monkeypatch.setattr(bedrock_client, "invoke_json", lambda *a, **k: {
        "confirmed": True, "confidence": 0.5, "exploit_scenario": "", "reasoning": "borderline",
    })
    finding = _FakeFinding(attack_type="unknown_future_type")  # pattern_conf = 0.40
    target = _FakeTarget()

    confirmed, confidence, _ = await red_team.validate(finding, target, confidence_threshold=0.5)

    assert confirmed is True
    assert confidence == 0.5


@pytest.mark.asyncio
async def test_confidence_just_under_threshold_does_not_confirm(monkeypatch):
    monkeypatch.setattr(bedrock_client, "invoke_json", lambda *a, **k: {
        "confirmed": True, "confidence": 0.49, "exploit_scenario": "", "reasoning": "borderline",
    })
    finding = _FakeFinding(attack_type="unknown_future_type")  # pattern_conf = 0.40
    target = _FakeTarget()

    confirmed, confidence, _ = await red_team.validate(finding, target, confidence_threshold=0.5)

    assert confirmed is False
    assert confidence == pytest.approx(0.49)


# ── validate() — multi-source aggregation ───────────────────────────────────

@pytest.mark.asyncio
async def test_browser_confidence_can_carry_over_threshold_via_max(monkeypatch):
    monkeypatch.setattr(bedrock_client, "invoke_json", lambda *a, **k: {
        "confirmed": True, "confidence": 0.2, "exploit_scenario": "", "reasoning": "weak llm signal",
    })
    # xss pattern_conf = 0.45; browser_confirmed=True -> browser_conf = 0.92
    finding = _FakeFinding(attack_type="xss", browser_confirmed=True)
    target = _FakeTarget()

    confirmed, confidence, _ = await red_team.validate(finding, target, confidence_threshold=0.5)

    assert confirmed is True
    assert confidence == 0.92


# ── validate() — LLM failure fallback ───────────────────────────────────────

@pytest.mark.asyncio
async def test_llm_raises_falls_back_to_pattern_confidence_above_threshold(monkeypatch):
    def _raise(*args, **kwargs):
        raise RuntimeError("bedrock unavailable")

    monkeypatch.setattr(bedrock_client, "invoke_json", _raise)

    finding = _FakeFinding(attack_type="sqli", raw_response_snippet="SQL syntax error near 'x'")
    target = _FakeTarget()

    confirmed, confidence, reasoning = await red_team.validate(finding, target, confidence_threshold=0.5)

    assert confirmed is True
    assert confidence == pytest.approx(0.80)
    assert "pattern confidence" in reasoning.lower()


@pytest.mark.asyncio
async def test_llm_raises_falls_back_to_pattern_confidence_below_threshold(monkeypatch):
    def _raise(*args, **kwargs):
        raise RuntimeError("bedrock unavailable")

    monkeypatch.setattr(bedrock_client, "invoke_json", _raise)

    finding = _FakeFinding(attack_type="unknown_future_type")  # pattern_conf = 0.40
    target = _FakeTarget()

    confirmed, confidence, reasoning = await red_team.validate(finding, target, confidence_threshold=0.5)

    assert confirmed is False
    assert confidence == pytest.approx(0.40)
    assert "pattern confidence" in reasoning.lower()


# ── validate() — ai_validated flag (drives the "AI validated" badge) ─────────

@pytest.mark.asyncio
async def test_ai_validated_true_when_llm_confirms(monkeypatch):
    monkeypatch.setattr(bedrock_client, "invoke_json", lambda *a, **k: {
        "confirmed": True, "confidence": 0.9, "exploit_scenario": "", "reasoning": "ok",
    })
    finding = _FakeFinding(attack_type="sqli", raw_response_snippet="SQL syntax error near 'x'")
    await red_team.validate(finding, _FakeTarget(), confidence_threshold=0.5)
    assert finding.ai_validated is True


@pytest.mark.asyncio
async def test_ai_validated_true_even_when_llm_rejects(monkeypatch):
    # A reject is still a genuine AI verdict — the finding was reviewed.
    monkeypatch.setattr(bedrock_client, "invoke_json", lambda *a, **k: {
        "confirmed": False, "confidence": 0.1, "exploit_scenario": "", "reasoning": "no",
    })
    finding = _FakeFinding(attack_type="sqli", raw_response_snippet="SQL syntax error near 'x'")
    await red_team.validate(finding, _FakeTarget(), confidence_threshold=0.5)
    assert finding.ai_validated is True


@pytest.mark.asyncio
async def test_ai_validated_false_when_llm_raises(monkeypatch):
    def _raise(*args, **kwargs):
        raise RuntimeError("bedrock unavailable")

    monkeypatch.setattr(bedrock_client, "invoke_json", _raise)
    finding = _FakeFinding(attack_type="sqli", raw_response_snippet="SQL syntax error near 'x'")
    await red_team.validate(finding, _FakeTarget(), confidence_threshold=0.5)
    assert finding.ai_validated is False


@pytest.mark.asyncio
async def test_ai_unavailable_skips_llm_and_uses_pattern_confidence(monkeypatch):
    called = False

    def _invoke_json(*args, **kwargs):
        nonlocal called
        called = True
        return {"confirmed": True, "confidence": 0.9}

    monkeypatch.setattr(bedrock_client, "invoke_json", _invoke_json)
    monkeypatch.setattr(bedrock_client, "is_ai_available", lambda: False)

    finding = _FakeFinding(attack_type="sqli", raw_response_snippet="SQL syntax error near 'x'")
    confirmed, confidence, reasoning = await red_team.validate(
        finding, _FakeTarget(), confidence_threshold=0.5)

    # LLM never called; pattern confidence (0.80) confirms; flag stays False.
    assert called is False
    assert confirmed is True
    assert confidence == pytest.approx(0.80)
    assert finding.ai_validated is False
    assert "ai unavailable" in reasoning.lower()


# ── _detection_method — label honesty ────────────────────────────────────────

def test_detection_method_ai_only_when_ai_validated():
    from dast.proxy.runner import _detection_method

    validated = _FakeFinding(bypass_validation=False, ai_validated=True, browser_confirmed=None)
    assert _detection_method(validated) == ["ai"]

    # Non-bypass finding confirmed via pattern fallback (AI never ran) must NOT
    # claim "ai" — it is labeled "pattern" instead.
    not_validated = _FakeFinding(bypass_validation=False, ai_validated=False, browser_confirmed=None)
    assert _detection_method(not_validated) == ["pattern"]


def test_detection_method_browser_additive_with_ai():
    from dast.proxy.runner import _detection_method

    f = _FakeFinding(attack_type="xss", bypass_validation=False,
                     ai_validated=True, browser_confirmed=True)
    methods = _detection_method(f)
    assert "browser" in methods
    assert "ai" in methods


# ── prompt-injection defense sanity check ───────────────────────────────────

def test_system_prompt_embeds_untrusted_content_directive():
    from dast.ai.prompt_safety import UNTRUSTED_CONTENT_DIRECTIVE
    assert UNTRUSTED_CONTENT_DIRECTIVE in red_team._SYSTEM
