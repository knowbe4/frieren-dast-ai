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

import time
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

from dast.payloads.loader import get_value
from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
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
    },
    "required": ["url", "injection_point"],
}


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


async def _deliver(browser: Any, url: str, point: str, value: str, location: str,
                   key_delivery: bool = False) -> None:
    """Deliver ``value`` at the injection point through the live browser. URL-borne locations
    navigate; a form field is filled and submitted. Reuses the authenticated session.

    ``key_delivery`` True → ``value`` is an AngularJS ``$parse``-of-KEY sandbox escape, delivered as
    a RAW second query-param KEY (``?<point>=1&<expr>=1`` with internal ``=`` → ``%3d``), bypassing
    the url-encoding of the normal value/fragment/path/body paths. ``location`` is ignored."""
    if key_delivery:
        await browser.navigate(_build_angular_key_url(url, point, value))
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
    await browser.navigate(_build_url(url, point, value, location))


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
                        angular_parse_key_sink: bool = False,
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
    unchanged, and no key-delivery candidate is ever added for them."""
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
    # Angular app, but the reflection surface is unrelated (html_body/attr/href): context payloads
    # first, Angular value-vectors appended as a fallback, key-delivery vectors last.
    return _context_list() + angular_firsts + _key_candidates()


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
        steps.append({"label": "classify", "context": context,
                      "quotes_encoded": quotes_encoded, "angular_parse_sink": angular_parse_sink,
                      "angular_parse_key_sink": angular_parse_key_sink,
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
                                         angular_parse_key_sink=angular_parse_key_sink)
        if not candidates:
            return {"ok": True, "confirmed": False, "context": context,
                    "framework_version": version,
                    "verdict": f"NOT CONFIRMED — no payload template for context '{context}' "
                               f"(version {version}).", "steps": steps}

        # 2. Deliver each candidate; confirm strictly on a captured alert() dialog.
        for payload, angular_fixed, key_delivery in candidates:
            await _reset_dialog(browser)
            await _deliver(browser, url, point, payload, location, key_delivery=key_delivery)
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
    feeding ``$parse``/``$eval`` (not just the ``angular_expression`` interpolation context)."""
    is_angular = angular_fixed or context == "angular_expression"
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
        "parameter instead of hand-crafting XSS payloads."
    ),
    input_schema=_SCHEMA,
    handler=_xss_probe,
    tags=["active", "write"],
))
