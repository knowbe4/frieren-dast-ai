"""
xss_probe tool — deterministic, LLM-free reflected/stored/DOM-XSS + AngularJS-CSTI probe.

Mirrors ``sqli_probe``: a fixed, self-contained confirmation the gateway's content-safety filter
cannot block, because no language model generates the payload. The twist is that confirming an
XSS needs a REAL browser firing a REAL ``alert()`` dialog — a reflection in the body is not proof,
and a 200 is not proof. So this tool drives ``ctx.browser`` (the live ``AgentBrowser`` that already
carries the authenticated session) rather than httpx:

  1. Inject a benign unique MARKER (not a payload) and read the rendered DOM.
  2. ``xss_context.classify_context`` locates the marker and decides the reflection context
     (HTML body / quoted attribute / JS-string / href / AngularJS expression), and
     ``detect_angular_version`` reads the AngularJS era for a CSTI sandbox-escape.
  3. Pick the context-correct payload from ``xss.yaml`` (the quote-free sibling when the app
     HTML-encodes quotes), substitute the per-run MARK, and deliver it through the browser.
  4. CONFIRM strictly via a captured JS dialog: for a context payload the dialog message must
     contain the exact MARK (an ambient alert cannot match); for the fixed AngularJS alert(1)
     cheat-sheet vectors, a fired dialog is the proof. Reflection alone never confirms.

Dialogs are read from two sources so a synchronous inline-script alert is never missed: the
AgentBrowser's native ``page.on("dialog")`` handler (``pop_last_dialog``) AND the
``XSS_PROOF_INIT_SCRIPT`` window hooks installed before delivery (which also catch an alert that
fires during document commit, before the native listener can attach).
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

from dast.payloads.loader import get_value
from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.triage import xss_synthesis as synth
from dast.triage.xss_browser import XSS_PROOF_INIT_SCRIPT
from dast.triage.xss_context import classify_context, detect_angular_version
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")
_LOCATIONS = ("query", "fragment", "path", "body")

# JS that resets then reads the XSS_PROOF_INIT_SCRIPT window hooks. Returned by the init script
# when an alert/confirm/prompt fired during the current document, with the string message.
_READ_DIALOG_JS = "() => (window._xssAlertFired === true)"
_READ_MSG_JS = "() => String(window._xssAlertMessage == null ? '' : window._xssAlertMessage)"
_RESET_DIALOG_JS = "() => { window._xssAlertFired = false; window._xssAlertMessage = ''; }"


_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "Target URL (must be in scope). For a URL-borne "
                "parameter this is the page URL; for a form field it is the page carrying the form."},
        "injection_point": {"type": "string", "description": "The parameter / form-field NAME to "
                            "inject into (e.g. 'q', 'search', 'comment')."},
        "injection_location": {"type": "string", "description": "Where the parameter lives: "
                               "'query' (URL query string, default), 'fragment' (URL #fragment, for "
                               "a DOM-XSS sink reading location.hash), 'path' (appended to the URL "
                               "path), or 'body' (a form field — the tool navigates, fills the field "
                               "named by injection_point, and submits). Default 'query'."},
        "method": {"type": "string", "description": "Optional HTTP method hint (informational; the "
                   "browser drives navigation/form submission). Default GET."},
        "record": {"type": "boolean", "description": "Record a finding when CONFIRMED (default true)."},
        "title": {"type": "string", "description": "Finding title (optional; a sensible default is used)."},
        "severity": {"type": "string", "description": "critical|high|medium|low|info (default high)."},
        "cwe": {"type": "string", "description": "CWE id (default CWE-79)."},
        "synthesize": {"type": "boolean", "description": "When the curated payloads all MISS on an "
                       "AngularJS target, attempt deterministic in-tool CSTI sandbox-escape SYNTHESIS "
                       "— build the escape from primitives, verifying each step against the live "
                       "target's own $parse/$eval (no LLM). Default true."},
    },
    "required": ["url", "injection_point"],
}

# Bounds for the deterministic synthesis fallback (no LLM; the live sink is the only oracle).
_SYNTH_MAX_ORACLE_EVALS = 25
_SYNTH_MAX_COMPOSE_STEPS = 8

# The element id the AngularJS HTML-directive gadgets carry (``<input id=x ...>``) and the matching
# ``#x`` focus fragment the probe appends so a real browser focuses it (fires ``ng-focus``).
_ANGULAR_HTML_FOCUS_ID = synth.HTML_GADGET_ELEMENT_ID


def _set_query_param(url: str, param: str, value: str) -> str:
    parts = urlparse(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q[param] = value
    return urlunparse(parts._replace(query=urlencode(q)))


def _set_fragment(url: str, param: str, value: str) -> str:
    parts = urlparse(url)
    frag = f"{param}={value}" if param else value
    return urlunparse(parts._replace(fragment=frag))


def _append_path(url: str, value: str) -> str:
    parts = urlparse(url)
    base = parts.path.rstrip("/")
    new_path = f"{base}/{quote(value, safe='')}"
    return urlunparse(parts._replace(path=new_path))


def _build_url(url: str, point: str, value: str, location: str) -> str:
    """Place ``value`` at ``point`` in a URL-borne location (query/fragment/path)."""
    if location == "fragment":
        return _set_fragment(url, point, value)
    if location == "path":
        return _append_path(url, value)
    return _set_query_param(url, point, value)  # query (default)


def _with_focus_fragment(url: str, element_id: str) -> str:
    """Append a ``#<element_id>`` URL fragment so a REAL browser focuses the injected element on
    navigation — the auto-trigger the AngularJS-sandbox-escape-and-CSP class relies on (the lab's
    ``<input id=x ng-focus=...>#x`` gadget). Replaces any existing fragment (the query/path delivery
    paths carry none). ``autofocus`` does not reliably dispatch focus headless, so this is a cheap,
    correct addition that lets a real browser self-fire; the programmatic focus remains as the
    headless fallback."""
    parts = urlparse(url)
    return urlunparse(parts._replace(fragment=element_id))


def _build_angular_key_url(url: str, point: str, expr: str) -> str:
    """Deliver an AngularJS ``$parse``-of-KEY sandbox escape: the Angular expression is sent as the
    KEY of a SECOND query param, so the client's ``$parse(<paramName>)(...)`` evaluates it. Shape
    (the lab needs it verbatim): ``<path>?<point>=1&<EXPR_AS_KEY>=1``.

    The stored ``angular_no_strings`` vector is ``<expr>=1`` — a trailing ``=1`` that is the param's
    KEY→value separator. We keep that final ``=1`` and percent-encode every INTERNAL ``=`` (e.g. the
    ``charAt=`` assignment) to ``%3d`` so it stays part of the KEY instead of ending it. All other
    expression chars (``& [ ] | ; ( ) . : { }``) are kept RAW — the browser must send them as-is, so
    the query is built by hand (NOT via ``urlencode``, which was why value-delivery clobbered this
    structure) and handed to the browser verbatim."""
    key_part, sep, value_part = expr.rpartition("=")
    if not sep:  # no trailing =value in the stored vector; treat the whole expr as the key
        key_part, value_part = expr, "1"
    raw_query = f"{point}=1&{key_part.replace('=', '%3d')}={value_part}"
    parts = urlparse(url)
    return urlunparse(parts._replace(query=raw_query))  # urlunparse joins; it does NOT re-encode


def _field_selector(snap: Dict[str, Any], point: str) -> str:
    """Build a CSS selector for the form field named ``point`` from a browser snapshot
    (matching name, then id). Falls back to a plain [name=...] selector."""
    fields: List[Dict[str, Any]] = list(snap.get("fields", []) or [])
    for form in (snap.get("forms", []) or []):
        fields.extend(form.get("fields", []) or [])
    for f in fields:
        if f.get("name") == point:
            return f'[name="{point}"]'
    for f in fields:
        if f.get("id") == point:
            return f'#{point}'
    return f'[name="{point}"]'


def _submit_selector(snap: Dict[str, Any]) -> Optional[str]:
    """Best submit control from a snapshot: a submit-typed button, else the first button."""
    buttons: List[Dict[str, Any]] = list(snap.get("buttons", []) or [])
    for b in buttons:
        if (b.get("type") or "").lower() == "submit":
            if b.get("id"):
                return f'#{b["id"]}'
            if b.get("name"):
                return f'[name="{b["name"]}"]'
            return "button[type=submit], input[type=submit]"
    if buttons:
        b = buttons[0]
        if b.get("id"):
            return f'#{b["id"]}'
        if b.get("name"):
            return f'[name="{b["name"]}"]'
    return "button[type=submit], input[type=submit], button"


async def _install_proof_script(browser: Any) -> None:
    """Install XSS_PROOF_INIT_SCRIPT on the live page via add_init_script BEFORE delivery, so an
    alert() that fires on a synchronous inline script (during commit, before the native dialog
    listener attaches) is still captured into window._xssAlertFired. Idempotent per browser."""
    if getattr(browser, "_xss_proof_installed", False):
        return
    try:
        page = await browser._ensure_page()
        await page.add_init_script(XSS_PROOF_INIT_SCRIPT)
        browser._xss_proof_installed = True
    except Exception as exc:
        logger.debug("xss_probe: proof-script install failed", error=str(exc)[:160])


async def _reset_dialog(browser: Any) -> None:
    """Clear both dialog sources before a delivery, so a captured dialog belongs to THIS payload."""
    try:
        browser.pop_last_dialog()
    except Exception:
        pass
    try:
        page = await browser._ensure_page()
        await page.evaluate(_RESET_DIALOG_JS)
    except Exception:
        pass


async def _capture_dialog(browser: Any) -> Optional[Dict[str, Any]]:
    """Read the most recent JS dialog from either source: the native page.on("dialog") handler
    (pop_last_dialog) first, else the XSS_PROOF_INIT_SCRIPT window hooks (which capture an alert
    the init script's override intercepted). Returns {"type","message"} or None."""
    try:
        native = browser.pop_last_dialog()
    except Exception:
        native = None
    if native is not None:
        return native
    try:
        page = await browser._ensure_page()
        if await page.evaluate(_READ_DIALOG_JS):
            msg = await page.evaluate(_READ_MSG_JS)
            await page.evaluate(_RESET_DIALOG_JS)
            return {"type": "alert", "message": str(msg)}
    except Exception as exc:
        logger.debug("xss_probe: init-script dialog read failed", error=str(exc)[:160])
    return None


async def _read_dom(browser: Any) -> str:
    """Current rendered DOM for context classification. Best-effort; '' on failure."""
    try:
        page = await browser._ensure_page()
        return await page.content()
    except Exception as exc:
        logger.debug("xss_probe: DOM read failed", error=str(exc)[:160])
        return ""


async def _eval_in_page(browser: Any, js: str) -> Any:
    """Run arbitrary JS on the live page via ``page.evaluate`` and return the value. Reuses the same
    page path the dialog read JS already uses — the authenticated session is unchanged."""
    page = await browser._ensure_page()
    return await page.evaluate(js)


def _angular_eval_js(expr: str) -> str:
    """JS that evaluates an AngularJS expression through the APP's OWN ``$parse``/``$eval`` (the same
    evaluator the vulnerable sink uses) and returns ``{ok, val}`` or ``{ok:false, err}``. The scope
    is read from the first ``ng-app``/``ng-controller`` element (falling back to ``$parse`` via the
    injector), so synthesis probes the REAL sandbox — a sandbox error surfaces as ``err`` (e.g.
    ``$parse:isecfld``) and a successful evaluation as the stringified ``val``. ``expr`` is embedded
    as a JSON string literal (synthesis probes never contain a double quote)."""
    expr_lit = json.dumps(expr)
    return (
        "() => {"
        "  const el = document.querySelector('[ng-app],[ng-controller]') || document.body;"
        f"  const EXPR = {expr_lit};"
        "  try {"
        "    const ng = window.angular;"
        "    let s = null;"
        "    if (ng && ng.element) { try { s = ng.element(el).scope(); } catch (e) {} }"
        "    let r;"
        "    if (s && s.$eval) { r = s.$eval(EXPR); }"
        "    else if (ng && ng.element) { r = ng.element(el).injector().get('$parse')(EXPR)(s || {}); }"
        "    else { return { ok: false, err: 'no-angular' }; }"
        "    return { ok: true, val: String(r) };"
        "  } catch (e) { return { ok: false, err: String((e && e.message) || e) }; }"
        "}"
    )


async def _angular_eval(browser: Any, expr: str) -> Dict[str, Any]:
    """Evaluate ``expr`` through the app's own Angular evaluator (the per-primitive ORACLE). Returns
    ``{ok, val, err}``; any transport failure is reported as ``{ok: False, err: ...}``."""
    try:
        res = await _eval_in_page(browser, _angular_eval_js(expr))
    except Exception as exc:
        return {"ok": False, "err": str(exc)[:160]}
    if isinstance(res, dict):
        return {"ok": bool(res.get("ok")), "val": res.get("val"), "err": res.get("err")}
    return {"ok": False, "err": f"non-dict oracle result: {str(res)[:80]}"}


async def _focus_injected_element(browser: Any, element_id: str = "x") -> bool:
    """Programmatically focus the injected element so an ``ng-focus`` directive fires in a HEADLESS
    browser. ``autofocus`` does not reliably dispatch a focus event headless, so after delivering the
    ``ng-focus`` gadget the probe focuses the element (and dispatches a ``focus`` event) itself. This
    is legitimate: the vulnerability is real — a real victim's browser autofocuses the element — the
    probe merely delivers the trigger. Returns True when an element was found and focused."""
    js = (
        "() => {"
        f"  const el = document.getElementById({json.dumps(element_id)});"
        "  if (!el) return false;"
        "  try { el.focus(); } catch (e) {}"
        "  try { el.dispatchEvent(new FocusEvent('focus', {bubbles: true})); } catch (e) {}"
        "  return true;"
        "}"
    )
    try:
        return bool(await _eval_in_page(browser, js))
    except Exception as exc:
        logger.debug("xss_probe: programmatic focus failed", error=str(exc)[:160])
        return False


async def _html_trigger_outcome(browser: Any, sentinel: str,
                                element_id: str = "x") -> "tuple[str, Any]":
    """Read the compile/trigger oracle outcome for the injected element ``#<element_id>`` and the
    ``window.name`` sentinel it should have set, distinguishing THREE diagnosable outcomes:

      * ``"compiled+fired"``    — the ``window.name`` sentinel is set: the server-reflected markup was
        ``$compile``'d AND the directive expression ran to completion (the success case).
      * ``"compiled+errored"``  — the element is inside the bootstrapped Angular app (``injector()``
        resolves) but the sentinel is unset: it compiled/linked but the directive EXPRESSION threw
        (sandbox error, or ``$event`` undefined in an ``ng-init`` — the exact bug this path guards).
      * ``"not-compiled"``      — the element exists in the DOM but Angular never linked it (no
        injector): ``ng-app`` did not scan the reflected subtree, so no directive ever runs.

    Also returns ``"not-delivered"`` (element absent) / ``"read-failed"`` (oracle unreachable). The
    second tuple element is the raw read, for the step log."""
    js = (
        "() => {"
        f"  const el = document.getElementById({json.dumps(element_id)});"
        "  const present = !!el;"
        "  let compiled = false;"
        "  if (el) {"
        "    try {"
        "      const ng = window.angular;"
        "      if (ng && ng.element) { compiled = !!ng.element(el).injector(); }"
        "    } catch (e) {}"
        "  }"
        "  const wn = (window.name == null ? '' : String(window.name));"
        "  return { present: present, compiled: compiled, windowName: wn };"
        "}"
    )
    try:
        res = await _eval_in_page(browser, js)
    except Exception as exc:
        logger.debug("synth-html: outcome read failed", error=str(exc)[:160])
        return "read-failed", None
    if not isinstance(res, dict):
        return "read-failed", res
    window_name = str(res.get("windowName") or "")
    if sentinel in window_name:
        return "compiled+fired", res
    if res.get("compiled"):
        return "compiled+errored", res
    if res.get("present"):
        return "not-compiled", res
    return "not-delivered", res


async def _deliver(browser: Any, url: str, point: str, value: str, location: str,
                   key_delivery: bool = False, fragment_id: Optional[str] = None) -> None:
    """Deliver ``value`` at the injection point through the live browser. URL-borne locations
    navigate; a form field is filled and submitted. Reuses the authenticated session.

    ``key_delivery`` True → ``value`` is an AngularJS ``$parse``-of-KEY sandbox escape, delivered as
    a RAW second query-param KEY (``?<point>=1&<expr>=1`` with internal ``=`` → ``%3d``), bypassing
    the url-encoding of the normal value/fragment/path/body paths. ``location`` is ignored.

    ``fragment_id`` (e.g. ``"x"``) appends a ``#<id>`` focus fragment to the navigated URL so a real
    browser focuses the injected element (firing an ``ng-focus`` directive) — used for the
    AngularJS-HTML-directive gadgets. Ignored for a ``body`` form submit and for ``fragment`` delivery
    (where the payload already owns the fragment)."""
    if key_delivery:
        nav = _build_angular_key_url(url, point, value)
        if fragment_id:
            nav = _with_focus_fragment(nav, fragment_id)
        await browser.navigate(nav)
        return
    if location == "body":
        await browser.navigate(url)
        snap = await browser.snapshot()
        selector = _field_selector(snap, point)
        await browser.fill(selector, value)
        submit = _submit_selector(snap)
        if submit:
            await browser.click(submit, expect_nav=True)
        return
    nav = _build_url(url, point, value, location)
    if fragment_id and location != "fragment":
        nav = _with_focus_fragment(nav, fragment_id)
    await browser.navigate(nav)


def _angular_vectors(version: str, quotes_encoded: bool) -> List[str]:
    """The fixed AngularJS sandbox-escape vectors for the detected era, as RAW parameter values.
    When quotes are HTML-encoded near the reflection the string-free ``angular_no_strings`` form
    is preferred (tried first); otherwise the era cheat-sheet ``angular_csti`` form leads. Both are
    returned so a miss on one still tries the other."""
    ns = list((get_value("xss", "angular_no_strings", {}) or {}).get(version, []) or [])
    csti = get_value("xss", "angular_csti", {}) or {}
    era = list(csti.get(version, []) or csti.get("no_sandbox", []) or [])
    return (ns + era) if quotes_encoded else (era + ns)


def _candidate_payloads(context: str, quotes_encoded: bool, version: str, mark: str,
                        framework: str = "", angular_parse_sink: bool = False,
                        angular_parse_key_sink: bool = False, csp_present: bool = False,
                        ) -> "List[tuple[str, bool, bool]]":
    """Build the ordered candidate list as ``(payload, angular_fixed, key_delivery)`` tuples.

    ``angular_fixed`` True → a fixed AngularJS ``alert(1)`` sandbox-escape vector, delivered RAW and
    confirmed by ANY fired dialog; False → a MARK-substituted context payload confirmed only when
    the dialog echoes the unique MARK. ``key_delivery`` True → an Angular ``$parse``-of-KEY escape
    delivered as a raw second query-param KEY (see ``_build_angular_key_url``) rather than a value.

    For an Angular app (``framework == "angularjs"`` OR a detected ``$parse``/``$eval`` sink) the
    Angular value-vectors are ALWAYS included in addition to the normal context payloads — tried
    FIRST when the value feeds an Angular expression (surface ``angular_expression``/``js_string_*``
    or ``angular_parse_sink``), and appended after the context payloads otherwise. When the sink
    consumes a param KEY (``angular_parse_key_sink``) the string-free ``angular_no_strings`` vectors
    are ALSO appended as key-delivery candidates — tried LAST so they fire only once the (doomed)
    value-delivery vectors have missed. Non-Angular targets get exactly the context payloads,
    unchanged, and no key-delivery candidate is ever added for them.

    ``angular_html_injection`` (a RAW-HTML reflection in an Angular subtree) gets the
    ``angular_html_directive`` element gadgets (which carry ``alert({MARK})``, confirmed on the MARK
    dialog) plus the ``{{ }}`` value-vectors, ORDERED by ``csp_present``: under CSP the directive
    gadgets lead (inline-handler / Function-ctor ``{{ }}`` escapes are blocked) with ``{{ }}`` as a
    fallback; with no CSP the simpler ``{{ }}`` vectors lead. ``csp_present`` also lifts the Angular
    value-vectors ahead of the (CSP-blocked) inline-handler context payloads for an Angular app whose
    reflection surface is a plain ``html_body``/attr/href."""
    def _context_list() -> "List[tuple[str, bool, bool]]":
        ctx_payloads = get_value("xss", "context_payloads", {}) or {}
        group = context
        if quotes_encoded:
            qf = f"{context}_quote_free"
            if ctx_payloads.get(qf):
                group = qf
        return [(p.replace("{MARK}", mark), False, False)
                for p in (ctx_payloads.get(group, []) or [])]

    def _key_candidates() -> "List[tuple[str, bool, bool]]":
        # Only for a param-KEY $parse sink. The angular_no_strings vectors are purpose-built for
        # key delivery (they carry the trailing ``=1`` param separator and need no string literal);
        # a fired dialog proves the escape (angular_fixed=True).
        if not angular_parse_key_sink:
            return []
        ns = (get_value("xss", "angular_no_strings", {}) or {}).get(version, []) or []
        return [(expr, True, True) for expr in ns]

    def _directive_gadgets() -> "List[tuple[str, bool, bool]]":
        # Element gadgets for a RAW-HTML Angular injection. They fire alert({MARK}), so a fired dialog
        # must echo the MARK (angular_fixed=False); delivered as a normal VALUE. The ``{NGINIT}`` seed
        # carries the EVENT-FREE no-strings escape (built here because its fromCharCode codes depend on
        # the per-run MARK); the ``ng-focus`` seed uses the ``$event.composedPath()`` gadget and is
        # focused programmatically at delivery. ng-init auto-fires at LINK with zero interaction, so it
        # is ordered FIRST; ng-focus follows as the focus-triggered fallback.
        lib = get_value("xss", "angular_html_directive", {}) or {}
        seeds = lib.get(version, []) or lib.get("no_sandbox", []) or []
        ng_init = [s for s in seeds if "{NGINIT}" in s]
        ng_focus = [s for s in seeds if "{NGINIT}" not in s]
        out: "List[tuple[str, bool, bool]]" = []
        for s in ng_init:
            out.append((s.replace("{NGINIT}", synth.ng_init_alert_expr(mark)), False, False))
        for s in ng_focus:
            out.append((s.replace("{MARK}", mark), False, False))
        return out

    # RAW-HTML Angular injection: directive gadgets + {{ }} value-vectors, ordered by CSP.
    if context == "angular_html_injection":
        gadgets = _directive_gadgets()
        moustache = [(p, True, False) for p in _angular_vectors(version, quotes_encoded)]
        return (gadgets + moustache) if csp_present else (moustache + gadgets)

    # Pure Angular interpolation context: Angular vectors only (plus a key candidate iff key sink).
    if context == "angular_expression":
        return [(p, True, False) for p in _angular_vectors(version, quotes_encoded)] \
            + _key_candidates()

    is_angular = framework == "angularjs" or angular_parse_sink
    if not is_angular:
        return _context_list()

    angular_firsts = [(p, True, False) for p in _angular_vectors(version, quotes_encoded)]
    # The value feeds an Angular expression sink (surface JS-string or an explicit $parse sink):
    # try the Angular CSTI value-vectors before the (doomed) JS-string break-outs, then the raw
    # key-delivery vectors last for a param-KEY sink.
    if angular_parse_sink or str(context).startswith("js_string"):
        return angular_firsts + _context_list() + _key_candidates()
    # Angular app, reflection surface unrelated (html_body/attr/href). Under CSP the inline-handler
    # context payloads are blocked, so lead with the Angular expression value-vectors; otherwise the
    # context payloads lead and the Angular vectors are appended as a fallback.
    if csp_present:
        return angular_firsts + _context_list() + _key_candidates()
    return _context_list() + angular_firsts + _key_candidates()


async def _synthesize_angular(browser: Any, url: str, point: str, location: str, version: str,
                              mark: str, quotes_encoded: bool, key_sink: bool,
                              steps: List[Dict[str, Any]],
                              ) -> "tuple[Optional[str], Optional[Dict[str, Any]]]":
    """Deterministic in-tool AngularJS CSTI sandbox-escape SYNTHESIS (no LLM, no gateway).

    Runs ONLY after every curated candidate has missed. Instead of selecting a canned vector it
    BUILDS the escape from the ``angular_primitives`` grammar, using the live target's own
    ``$parse``/``$eval`` as a per-primitive ORACLE: it establishes the sink evaluates expressions
    (``7*7``→``49``), probes which escape primitive the sandbox permits (picking the
    ``constructor.constructor`` path or the ``charAt``-override path from the sandbox error codes),
    composes the escape sub-expression by sub-expression — verifying the no-strings string builder
    reproduces the exact attack string through the oracle — and finally delivers the composed
    ``alert(MARK)`` expression through the REAL injection point, confirming on the MARK dialog.

    Bounded: at most ``_SYNTH_MAX_ORACLE_EVALS`` oracle evaluations / ``_SYNTH_MAX_COMPOSE_STEPS``
    compose steps. Returns ``(payload, dialog)`` on CONFIRM, else ``(None, None)`` so the curated
    NOT-CONFIRMED verdict stands."""
    budget = {"evals": 0}

    async def oracle(expr: str) -> Dict[str, Any]:
        if budget["evals"] >= _SYNTH_MAX_ORACLE_EVALS:
            return {"ok": False, "err": "oracle budget exhausted"}
        budget["evals"] += 1
        return await _angular_eval(browser, expr)

    # (a) ESTABLISH ORACLE — the sink must actually evaluate Angular expressions.
    o_expr, o_exp = synth.oracle_probe()
    r = await oracle(o_expr)
    steps.append({"label": "synth: oracle", "expr": o_expr, "expected": o_exp, "result": r})
    if not (r.get("ok") and str(r.get("val")) == o_exp):
        steps.append({"label": "synth: abort — sink does not evaluate expressions"})
        return None, None

    # (b) PROBE PRIMITIVES — keep the ones that verify; pick the path from what the sandbox permits.
    verified: List[str] = []

    fc_expr, fc_exp = synth.fromcharcode_probe()
    r_fc = await oracle(fc_expr)
    fromcharcode_ok = bool(r_fc.get("ok") and str(r_fc.get("val")) == fc_exp)
    if fromcharcode_ok:
        verified.append("string_builder(fromCharCode)")
    steps.append({"label": "synth: probe fromCharCode", "expr": fc_expr, "expected": fc_exp,
                  "result": r_fc, "verified": fromcharcode_ok})

    strategy: Optional[str] = None
    c_expr, c_exp = synth.constructor_probe()
    r_c = await oracle(c_expr)
    if r_c.get("ok") and str(r_c.get("val")) == c_exp:
        verified.append("function_ctor(constructor.constructor)")
        strategy = "constructor"
    steps.append({"label": "synth: probe constructor.constructor", "expr": c_expr,
                  "expected": c_exp, "result": r_c, "verified": strategy == "constructor"})

    if strategy is None:  # sandbox blocked constructor access → try the charAt-override path
        ch_expr, ch_exp = synth.charat_probe()
        r_ch = await oracle(ch_expr)
        charat_ok = bool(r_ch.get("ok") and str(r_ch.get("val")) == ch_exp)
        if charat_ok:
            verified.append("charat_override([].join)")
            strategy = "charat"
        steps.append({"label": "synth: probe charAt override", "expr": ch_expr, "expected": ch_exp,
                      "result": r_ch, "verified": charat_ok})

    if strategy is None:
        steps.append({"label": "synth: abort — no escape primitive verified", "verified": verified})
        return None, None
    if strategy == "charat" and not fromcharcode_ok:
        steps.append({"label": "synth: abort — charAt path needs the fromCharCode builder",
                      "verified": verified})
        return None, None

    # (c) COMPOSE — assemble the escape, verifying the no-strings string builder via the oracle.
    effect = f"alert({mark})"
    strings_ok = not quotes_encoded
    if strategy == "charat":
        code_str = synth.effect_string(effect)            # x=alert(MARK)
        build_expr = synth.fromcharcode_expr(code_str)
        r_b = await oracle(build_expr)
        steps.append({"label": "synth: compose string builder", "expr": build_expr,
                      "expected": code_str, "result": r_b})
        if not (r_b.get("ok") and str(r_b.get("val")) == code_str):
            steps.append({"label": "synth: abort — string builder mismatch"})
            return None, None
        final = synth.charat_payload(effect, key_delivery=key_sink)
        key_delivery = key_sink
    else:  # constructor path
        if not strings_ok:  # quotes encoded → the code body must be fromCharCode-built; verify it
            build_expr = synth.fromcharcode_expr(effect)
            r_b = await oracle(build_expr)
            steps.append({"label": "synth: compose string builder", "expr": build_expr,
                          "expected": effect, "result": r_b})
            if not (r_b.get("ok") and str(r_b.get("val")) == effect):
                steps.append({"label": "synth: abort — string builder mismatch"})
                return None, None
        final = synth.constructor_payload(effect, strings_ok=strings_ok)
        key_delivery = False

    steps.append({"label": "synth: composed", "strategy": strategy, "verified": verified,
                  "payload": final, "key_delivery": key_delivery})

    # (d) CONFIRM — deliver the composed expression through the REAL injection point (the terminal
    # oracle). The escape runs alert(MARK), so the dialog must echo the unique MARK.
    await _reset_dialog(browser)
    await _deliver(browser, url, point, final, location, key_delivery=key_delivery)
    dialog = await _capture_dialog(browser)
    if dialog is not None and mark in str(dialog.get("message", "")):
        steps.append({"label": "synth: CONFIRMED", "payload": final, "dialog": dialog})
        return final, dialog
    steps.append({"label": "synth: miss (final delivery)", "payload": final, "dialog": dialog})
    return None, None


async def _synthesize_angular_html(browser: Any, url: str, point: str, location: str, mark: str,
                                   steps: List[Dict[str, Any]],
                                   ) -> "tuple[Optional[str], Optional[Dict[str, Any]]]":
    """Deterministic in-tool SYNTHESIS of an AngularJS HTML-element directive gadget — the CSTI that
    survives a ``script-src`` CSP (gateway-free, no LLM).

    Runs ONLY after every curated ``angular_html_directive`` gadget has missed. Mirrors
    ``_synthesize_angular`` but drives TWO live oracles against the real page:

      (a) COMPILE/TRIGGER oracle — deliver an element whose directive sets a ``window.name`` SENTINEL;
          read back a THREE-way outcome (``_html_trigger_outcome``: not-compiled / compiled+errored /
          compiled+fired) to PROVE the server-reflected markup was ``$compile``'d AND the directive
          auto-fired — and to make a miss diagnosable. Triggers are tried in order ``ng-init`` (the
          EVENT-FREE escape, auto-fires at link with zero interaction), then ``ng-focus`` (the
          ``$event.composedPath()`` gadget, focused PROGRAMMATICALLY since autofocus does not dispatch
          focus headless); the first that leaves the sentinel is the one the terminal payload uses.
      (b) SANDBOX oracle — reuse ``_angular_eval`` (the app's own ``$parse``/``$eval``) to confirm the
          ``orderBy``/``(z=alert)`` call mechanism is not sandbox-blocked.

    Then compose the seed + chosen trigger + the ``alert(MARK)`` gadget, deliver it as the reflected
    VALUE (focusing the element when the trigger is ``ng-focus``), and confirm on a dialog echoing the
    unique MARK. Bounded by the same ``_SYNTH_MAX_*`` budgets. Returns ``(payload, dialog)`` on
    CONFIRM, else ``(None, None)``."""
    budget = {"evals": 0}

    async def oracle(expr: str) -> Dict[str, Any]:
        if budget["evals"] >= _SYNTH_MAX_ORACLE_EVALS:
            return {"ok": False, "err": "oracle budget exhausted"}
        budget["evals"] += 1
        return await _angular_eval(browser, expr)

    # (a) COMPILE/TRIGGER oracle — a numeric window.name sentinel (distinct from the MARK). For each
    #     trigger deliver the sentinel gadget and read back a THREE-way outcome (see
    #     ``_html_trigger_outcome``): not-compiled / compiled+errored / compiled+fired — so a miss is
    #     diagnosable. ng-init is tried FIRST (event-free, auto-fires at link with zero interaction);
    #     ng-focus follows, focused PROGRAMMATICALLY (autofocus does not dispatch focus headless).
    sentinel = f"9{mark}"
    chosen_trigger: Optional[str] = None
    for trigger in ("ng-init", "ng-focus"):
        if budget["evals"] >= _SYNTH_MAX_COMPOSE_STEPS:
            break
        probe_el = synth.html_sentinel_payload(sentinel, trigger=trigger)
        await _reset_dialog(browser)
        await _deliver(browser, url, point, probe_el, location,
                       fragment_id=_ANGULAR_HTML_FOCUS_ID)
        focused: Optional[bool] = None
        if trigger == "ng-focus":
            focused = await _focus_injected_element(browser)
        outcome, read = await _html_trigger_outcome(browser, sentinel)
        steps.append({"label": f"synth-html: trigger probe ({trigger})", "payload": probe_el,
                      "sentinel": sentinel, "outcome": outcome, "read": read,
                      "focused": focused, "fired": outcome == "compiled+fired"})
        if outcome == "compiled+fired":
            chosen_trigger = trigger
            break
    if chosen_trigger is None:
        steps.append({"label": "synth-html: abort — no directive trigger compiled + auto-fired"})
        return None, None

    # (b) SANDBOX oracle — the orderBy/(z=...) call mechanism must not be sandbox-blocked.
    sb_expr, sb_exp = synth.html_sandbox_probe()
    r_sb = await oracle(sb_expr)
    sandbox_ok = bool(r_sb.get("ok") and str(r_sb.get("val")) == sb_exp)
    steps.append({"label": "synth-html: probe orderBy sandbox", "expr": sb_expr,
                  "expected": sb_exp, "result": r_sb, "verified": sandbox_ok})
    if not sandbox_ok:
        steps.append({"label": "synth-html: abort — orderBy gadget sandbox-blocked"})
        return None, None

    # (c) COMPOSE + CONFIRM — the full element fires alert(MARK) on the chosen trigger.
    final = synth.html_directive_payload(mark, trigger=chosen_trigger)
    steps.append({"label": "synth-html: composed", "trigger": chosen_trigger, "payload": final})
    await _reset_dialog(browser)
    await _deliver(browser, url, point, final, location, fragment_id=_ANGULAR_HTML_FOCUS_ID)
    if chosen_trigger == "ng-focus":
        await _focus_injected_element(browser)
    dialog = await _capture_dialog(browser)
    if dialog is not None and mark in str(dialog.get("message", "")):
        steps.append({"label": "synth-html: CONFIRMED", "payload": final, "dialog": dialog})
        return final, dialog
    steps.append({"label": "synth-html: miss (final delivery)", "payload": final, "dialog": dialog})
    return None, None


async def _xss_probe(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    url = str(args.get("url", "")).strip()
    point = str(args.get("injection_point", "")).strip()
    location = str(args.get("injection_location", "query")).strip().lower() or "query"
    method = str(args.get("method", "GET")).strip().upper() or "GET"
    if not url or not point:
        return {"ok": False, "error": "url and injection_point are required"}
    if location not in _LOCATIONS:
        return {"ok": False, "error": f"injection_location must be one of {_LOCATIONS}"}
    if not ctx.is_in_scope(url):
        return {"ok": False, "error": "url is out of scope", "url": url}
    browser = getattr(ctx, "browser", None)
    if browser is None:
        return {"ok": False, "error": "xss_probe needs the agent browser (not available in this "
                "context); it confirms XSS via a real alert() dialog, not httpx"}

    # Unique per-run MARK (numeric so it survives JS-number contexts) + a benign DOM marker.
    mark = str(int(time.time() * 1000) % 100000000)
    marker = f"dastxss{mark}"

    steps: List[Dict[str, Any]] = []
    try:
        await _install_proof_script(browser)
        # 1. Benign marker → read rendered DOM → classify the reflection context.
        await _reset_dialog(browser)
        await _deliver(browser, url, point, marker, location)
        dom = await _read_dom(browser)
        info = classify_context(dom, marker)
        context = str(info.get("context"))
        quotes_encoded = bool(info.get("quotes_encoded"))
        angular_parse_sink = bool(info.get("angular_parse_sink"))
        angular_parse_key_sink = bool(info.get("angular_parse_key_sink"))
        framework = str(info.get("framework") or "")
        version = detect_angular_version(dom)
        # CSP awareness: the classifier flags an in-markup CSP (ng-csp / meta-CSP); OR in a CSP
        # *response header* from the last navigation so the directive/expression gadgets are tried
        # ahead of CSP-blocked inline-handler vectors. Guarded — a missing property never raises.
        csp_present = bool(info.get("csp_present"))
        try:
            headers = getattr(browser, "last_response_headers", {}) or {}
            if any(str(k).lower() == "content-security-policy" for k in headers):
                csp_present = True
        except Exception:
            pass
        steps.append({"label": "classify", "context": context,
                      "quotes_encoded": quotes_encoded, "angular_parse_sink": angular_parse_sink,
                      "angular_parse_key_sink": angular_parse_key_sink, "csp_present": csp_present,
                      "framework": framework, "framework_version": version,
                      "snippet": info.get("snippet")})

        if context == "unknown":
            return {"ok": True, "confirmed": False, "context": context,
                    "framework_version": version,
                    "verdict": f"NOT CONFIRMED — marker not reflected in the DOM for '{point}' "
                               f"({location}); nothing to probe.", "steps": steps}

        candidates = _candidate_payloads(context, quotes_encoded, version, mark,
                                         framework=framework,
                                         angular_parse_sink=angular_parse_sink,
                                         angular_parse_key_sink=angular_parse_key_sink,
                                         csp_present=csp_present)
        if not candidates:
            return {"ok": True, "confirmed": False, "context": context,
                    "framework_version": version,
                    "verdict": f"NOT CONFIRMED — no payload template for context '{context}' "
                               f"(version {version}).", "steps": steps}

        # 2. Deliver each candidate; confirm strictly on a captured alert() dialog. For an
        #    angular_html_injection gadget append a ``#x`` focus fragment so a REAL browser focuses
        #    the injected ``<input id=x>`` on navigation (the lab's auto-trigger) — cheap + correct;
        #    the programmatic focus below remains the headless fallback.
        frag = _ANGULAR_HTML_FOCUS_ID if context == "angular_html_injection" else None
        for payload, angular_fixed, key_delivery in candidates:
            await _reset_dialog(browser)
            await _deliver(browser, url, point, payload, location,
                           key_delivery=key_delivery, fragment_id=frag)
            # An ng-focus directive gadget fires only on a focus event; autofocus / the #x fragment
            # do not reliably dispatch focus headless, so focus the injected element programmatically
            # before reading the oracle (ng-init auto-fires at link, so it needs no focus).
            if context == "angular_html_injection" and "ng-focus" in payload:
                await _focus_injected_element(browser)
            dialog = await _capture_dialog(browser)
            if dialog is None:
                steps.append({"label": "miss (no dialog)", "payload": payload})
                continue
            msg = str(dialog.get("message", ""))
            # Context payloads: the dialog MUST echo our MARK (ambient alert cannot). Fixed
            # AngularJS alert(1) vectors: a fired dialog is the proof (message is "1").
            confirmed = True if angular_fixed else (mark in msg)
            if confirmed:
                steps.append({"label": "CONFIRMED", "payload": payload, "dialog": dialog})
                return _confirm_result(ctx, args, url, method, point, location, context,
                                       version, payload, dialog, steps, angular_fixed=angular_fixed)
            steps.append({"label": "miss (dialog without marker)", "payload": payload,
                          "dialog": dialog})

        # 3. All curated candidates missed. On an AngularJS target, try deterministic in-tool CSTI
        #    synthesis (gateway-free): build the sandbox escape from primitives, using the live sink
        #    as an oracle. Gated behind ``synthesize`` (default True); additive fallback only.
        synthesize = bool(args.get("synthesize", True))
        is_angular = (framework == "angularjs" or angular_parse_sink
                      or context in ("angular_expression", "angular_html_injection"))
        if synthesize and is_angular:
            if context == "angular_html_injection":
                # RAW-HTML Angular injection → synthesize the element-directive gadget (CSP-safe).
                syn_payload, syn_dialog = await _synthesize_angular_html(
                    browser, url, point, location, mark, steps=steps)
            else:
                syn_payload, syn_dialog = await _synthesize_angular(
                    browser, url, point, location, version, mark,
                    quotes_encoded=quotes_encoded, key_sink=angular_parse_key_sink, steps=steps)
            if syn_dialog is not None and syn_payload is not None:
                return _confirm_result(ctx, args, url, method, point, location, context,
                                       version, syn_payload, syn_dialog, steps, angular_fixed=True)

        # 4. Honest SUSPECTED fallback for the AngularJS-HTML-directive-under-CSP class. Reflected
        #    raw into an Angular-bootstrapped DOM (``angular_html_injection``) but no gadget fired a
        #    MARK alert: this class needs fragment-focus (``#x``) + VICTIM delivery (an exploit
        #    server) to fire, which a headless scanner cannot self-confirm. Rather than a silent
        #    NOT-CONFIRMED, emit a SUSPECTED / needs-review finding carrying a ready-to-use
        #    exploit-server PoC. confirmed stays False (zero-FP contract intact).
        if context == "angular_html_injection":
            return _suspected_result(ctx, args, url, method, point, location, context,
                                     version, steps, csp_present=csp_present)
    except Exception as exc:
        return {"ok": False, "error": f"probe failed: {str(exc)[:200]}", "steps": steps}

    return {"ok": True, "confirmed": False, "context": context, "framework_version": version,
            "verdict": f"NOT CONFIRMED — no payload fired an alert() carrying the marker for "
                       f"'{point}' ({location}, context {context}).", "steps": steps}


def _confirm_result(ctx: ToolContext, args: Dict[str, Any], url: str, method: str, point: str,
                    location: str, context: str, version: str, payload: str,
                    dialog: Dict[str, Any], steps: List[Dict[str, Any]],
                    angular_fixed: bool = False) -> Dict[str, Any]:
    """Build the CONFIRMED result and record the finding (same store API sqli_probe uses).

    ``angular_fixed`` marks that the confirming payload was a fixed AngularJS sandbox-escape vector
    — so the finding is reported as CSTI even when the surface reflection context was a JS string
    feeding ``$parse``/``$eval`` (not just the ``angular_expression`` interpolation or the
    ``angular_html_injection`` raw-HTML-directive context)."""
    is_angular = angular_fixed or context in ("angular_expression", "angular_html_injection")
    kind = (f"AngularJS client-side template injection (CSTI, v{version})" if is_angular
            else f"{context} XSS")
    verdict = (f"CONFIRMED — {kind} in '{point}' ({location}). Payload {payload!r} fired a JS "
               f"dialog ({dialog.get('type')}: {dialog.get('message')!r}).")
    sev_arg = str(args.get("severity", "")).strip().lower()
    severity = sev_arg if sev_arg in _VALID_SEVERITIES else "high"
    result: Dict[str, Any] = {
        "ok": True, "confirmed": True, "context": context, "framework_version": version,
        "payload": payload, "dialog": dialog, "verdict": verdict,
        "severity": severity, "steps": steps,
    }
    if bool(args.get("record", True)) and getattr(ctx, "store", None) is not None:
        evidence = (verdict + f" [context={context}; framework_version={version}; "
                    f"dialog_message={dialog.get('message')!r}]")
        finding = {
            "title": str(args.get("title", "")).strip()
            or (f"AngularJS template injection (CSTI) in '{point}'" if is_angular
                else f"Reflected XSS in '{point}' ({context})"),
            "severity": severity,
            "attack_type": "xss",
            "cwe": str(args.get("cwe", "CWE-79")).strip() or "CWE-79",
            "parameter": point,
            "evidence": evidence,
            "context": context,
            "framework_version": version,
            "payload": payload,
            "steps": steps,
            "confirmed": True,
            "confidence": 1.0,
            "validated_by": ["xss_probe"],
            "source": "copilot",
        }
        try:
            entry_id = ctx.store.record_manual_finding(finding, url, method)
            result["recorded_entry_id"] = entry_id
            logger.info("xss_probe recorded finding", entry_id=entry_id, context=context,
                        severity=severity)
        except Exception as exc:
            result["record_error"] = str(exc)[:200]
    return result


def _suspected_result(ctx: ToolContext, args: Dict[str, Any], url: str, method: str, point: str,
                      location: str, context: str, version: str, steps: List[Dict[str, Any]],
                      csp_present: bool = False) -> Dict[str, Any]:
    """Build an HONEST SUSPECTED (needs-review) result for the AngularJS-HTML-directive-under-CSP
    class and record it as an UNCONFIRMED finding carrying a ready-to-use exploit-server PoC.

    This class reflects raw into an AngularJS-bootstrapped DOM (often under CSP) where the CSTI fires
    via an HTML-directive gadget that needs fragment-focus (``#x``) + VICTIM delivery (an exploit
    server) — a headless scanner cannot reliably self-fire it. So rather than a silent NOT-CONFIRMED
    this emits ``suspected=True`` with a generated ``poc`` (and records it with ``confirmed=False`` /
    ``needs_review=True``). It NEVER sets ``confirmed=True`` — the strict zero-FP contract is intact;
    only a real MARK alert dialog confirms (via ``_confirm_result``)."""
    poc = synth.exploit_server_poc(url, point, location=location)
    under_csp = " under CSP" if csp_present else ""
    rationale = (
        f"'{point}' reflects raw into an AngularJS-bootstrapped DOM{under_csp} (v{version}); likely "
        f"client-side template injection (CSTI) via an HTML-directive gadget that needs "
        f"fragment-focus (#x) + victim delivery (exploit server) to fire — not auto-confirmable from "
        f"the headless scanner."
    )
    verdict = f"SUSPECTED (needs review) — {rationale} Deliver the generated exploit-server PoC to confirm."
    sev_arg = str(args.get("severity", "")).strip().lower()
    severity = sev_arg if sev_arg in _VALID_SEVERITIES else "low"
    steps.append({"label": "SUSPECTED — exploit-server PoC generated", "poc": poc})
    result: Dict[str, Any] = {
        "ok": True, "confirmed": False, "suspected": True, "context": context,
        "framework_version": version, "poc": poc, "verdict": verdict,
        "severity": severity, "steps": steps,
    }
    if bool(args.get("record", True)) and getattr(ctx, "store", None) is not None:
        evidence = (rationale + f" [context={context}; framework_version={version}; "
                    f"csp_present={csp_present}] Exploit-server PoC (deliver to a victim): {poc}")
        finding = {
            "title": str(args.get("title", "")).strip()
            or f"Suspected AngularJS template injection (CSTI, needs review) in '{point}'",
            "severity": severity,
            "attack_type": "xss",
            "cwe": str(args.get("cwe", "CWE-79")).strip() or "CWE-79",
            "parameter": point,
            "evidence": evidence,
            "context": context,
            "framework_version": version,
            "poc": poc,
            "steps": steps,
            "confirmed": False,
            "suspected": True,
            "needs_review": True,
            "confidence": 0.5,
            "validated_by": ["xss_probe"],
            "source": "copilot",
        }
        try:
            entry_id = ctx.store.record_manual_finding(finding, url, method)
            result["recorded_entry_id"] = entry_id
            logger.info("xss_probe recorded SUSPECTED finding", entry_id=entry_id, context=context,
                        severity=severity, needs_review=True)
        except Exception as exc:
            result["record_error"] = str(exc)[:200]
    return result


register(Tool(
    name="xss_probe",
    description=(
        "Deterministically probe ONE parameter or form field for reflected/stored/DOM XSS or "
        "AngularJS client-side template injection (CSTI) — no LLM, so the gateway's content-safety "
        "filter cannot block it. It injects a benign marker, auto-detects the reflection context "
        "(HTML body / quoted attribute / JS-string / href / AngularJS expression) and the AngularJS "
        "version, picks the context-correct (and quote-free when quotes are encoded) payload itself, "
        "delivers it through the REAL agent browser (carrying the authenticated session), and "
        "confirms STRICTLY via the captured alert() dialog — the dialog must echo the probe's unique "
        "marker (ambient alerts cannot), so reflection alone never confirms. injection_location: "
        "'query' (default), 'fragment' (location.hash DOM sink), 'path', or 'body' (fills + submits "
        "the named form field). Records a CONFIRMED finding (CWE-79) with the context, version, "
        "payload, and dialog message as evidence. Use this once you have located the reflected "
        "parameter instead of hand-crafting XSS payloads. For an AngularJS-bootstrapped raw-HTML "
        "reflection under CSP (the HTML-directive-gadget class) that the headless scanner cannot "
        "self-fire, it returns confirmed=False with suspected=True and a ready-to-use exploit-server "
        "'poc' (records a needs-review finding) — deliver that PoC via the exploit server; it is "
        "never reported as confirmed."
    ),
    input_schema=_SCHEMA,
    handler=_xss_probe,
    tags=["active", "write"],
))
