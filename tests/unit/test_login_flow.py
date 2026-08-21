"""Unit tests for the pure login-flow logic (dast.profiles.flow)."""

from __future__ import annotations

from dast.profiles.flow import (
    CAPTCHA_SIGNATURES,
    LoginFlow,
    LoginStep,
    coalesce_recorded_steps,
    has_captcha,
    resolve_value,
)


def test_login_step_round_trip() -> None:
    step = LoginStep(action="fill", selector="#user", value_ref="username", timeout_ms=5000)
    restored = LoginStep.from_dict(step.to_dict())
    assert restored == step


def test_login_flow_round_trip() -> None:
    flow = LoginFlow(
        steps=[
            LoginStep(action="navigate", value="https://example.com/login"),
            LoginStep(action="fill", selector="#user", value_ref="username"),
            LoginStep(action="fill", selector="#pass", value_ref="password"),
            LoginStep(action="click", selector="#submit"),
        ],
        start_url="https://example.com/login",
        success_url_regex=r"/dashboard",
    )
    restored = LoginFlow.from_dict(flow.to_dict())
    assert restored.steps == flow.steps
    assert restored.start_url == flow.start_url
    assert restored.success_url_regex == flow.success_url_regex
    assert not restored.is_empty


def test_empty_flow() -> None:
    assert LoginFlow().is_empty
    assert LoginFlow.from_dict({}).is_empty


def test_resolve_value_substitutes_credential_refs() -> None:
    user_step = LoginStep(action="fill", selector="#u", value_ref="username")
    pass_step = LoginStep(action="fill", selector="#p", value_ref="password")
    literal_step = LoginStep(action="fill", selector="#org", value="acme")
    assert resolve_value(user_step, "alice", "s3cret") == "alice"
    assert resolve_value(pass_step, "alice", "s3cret") == "s3cret"
    assert resolve_value(literal_step, "alice", "s3cret") == "acme"


def test_has_captcha_detects_signatures() -> None:
    assert has_captcha('<div class="g-recaptcha" data-sitekey="x"></div>')
    assert has_captcha("<script src='https://hcaptcha.com/1/api.js'></script>")
    assert has_captcha("<div class='cf-turnstile'></div>")
    assert not has_captcha("<form><input name='user'></form>")
    assert not has_captcha("")


def test_captcha_signatures_are_lowercase() -> None:
    # has_captcha lowercases the page; signatures must be lowercase to ever match.
    assert all(sig == sig.lower() for sig in CAPTCHA_SIGNATURES)


def test_coalesce_collapses_consecutive_fills_same_selector() -> None:
    raw = [
        {"action": "navigate", "value": "https://example.com"},
        {"action": "fill", "selector": "#user", "value": "al"},
        {"action": "fill", "selector": "#user", "value": "alice"},  # correction
        {"action": "fill", "selector": "#pass", "value_ref": "password"},
        {"action": "click", "selector": "#submit"},
    ]
    steps = coalesce_recorded_steps(raw)
    assert [s.action for s in steps] == ["navigate", "fill", "fill", "click"]
    # The kept #user fill is the final (corrected) value.
    user_fill = next(s for s in steps if s.selector == "#user")
    assert user_fill.value == "alice"


def test_coalesce_keeps_fills_on_different_selectors() -> None:
    raw = [
        {"action": "fill", "selector": "#user", "value_ref": "username"},
        {"action": "fill", "selector": "#pass", "value_ref": "password"},
    ]
    steps = coalesce_recorded_steps(raw)
    assert len(steps) == 2


def test_coalesce_drops_unknown_actions() -> None:
    raw = [
        {"action": "scroll", "selector": "body"},
        {"action": "click", "selector": "#submit"},
    ]
    steps = coalesce_recorded_steps(raw)
    assert [s.action for s in steps] == ["click"]
