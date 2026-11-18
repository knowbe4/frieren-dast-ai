"""
prototype_pollution_probe — deterministic, LLM-free client-side prototype-pollution DOM-XSS probe.

Mirrors ``sqli_probe`` / ``xss_probe``: a FIXED confirmation procedure the gateway's content-safety
filter cannot block, because no language model generates the payload. Confirming a client-side
prototype pollution needs a REAL browser: a reflected sentinel is not proof, a 200 is not proof —
the prototype must actually be polluted AND a gadget must turn that pollution into script
execution. So this tool drives ``ctx.browser`` (the live ``AgentBrowser`` carrying the
authenticated session) rather than httpx:

  1. Pollute a unique sentinel property through each source vector
     (``dast.triage.protopollute.source_vectors``) and read ``Object.prototype[<sentinel>]`` on the
     live page (``READ_PROTO_JS``). A source that makes the empty-object read return the sentinel
     value is a confirmed Object.prototype pollution source.
  2. For each gadget in the library, rebuild the vector with the gadget's property and a JS-exec
     value (``gadget_url``), re-trigger the page (navigate / reload per the gadget ``trigger``),
     and CONFIRM strictly via a captured ``alert(<marker>)`` dialog — the dialog message MUST carry
     the run marker (``marker_in_dialog``); an ambient alert can never match.

CRITICAL: confirmation uses ONLY the EXISTING native dialog capture (the AgentBrowser's
``page.on("dialog")`` handler, surfaced on the ``navigate``/``reload`` result and via
``pop_last_dialog``). It never installs ``XSS_PROOF_INIT_SCRIPT`` / overrides ``window.alert`` on
the shared copilot page — doing so would break the native dialog handler that ``xss_probe`` and
reflected-XSS rely on (cross-tool regression). One browser/session is reused for every gadget.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.triage.protopollute import (
    READ_PROTO_JS,
    gadget_url,
    load_gadgets,
    make_sentinel,
    marker_in_dialog,
    source_vectors,
)
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")


_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "Target page URL (must be in scope). The probe "
                "appends prototype-pollution source vectors to this URL's query/fragment."},
        "gadget": {"type": "string", "description": "Optional: pin ONE gadget by name (e.g. "
                   "'transport_url'); default iterates the whole gadget library."},
        "source_vector": {"type": "string", "description": "Optional: pin ONE source-vector label "
                          "(e.g. 'proto_query', 'proto_hash'); default tries every vector."},
        "record": {"type": "boolean", "description": "Record a finding when CONFIRMED (default true)."},
        "title": {"type": "string", "description": "Finding title (optional; a sensible default is used)."},
        "severity": {"type": "string", "description": "critical|high|medium|low|info (default high)."},
        "cwe": {"type": "string", "description": "CWE id (default CWE-1321)."},
    },
    "required": ["url"],
}


def _dialog_from_result(result: Any) -> Optional[Dict[str, Any]]:
    """Extract a JS dialog surfaced on a navigate/reload result (``{"dialog": {...}}``), or None."""
    if isinstance(result, dict):
        dlg = result.get("dialog")
        if dlg:
            return dlg
    return None


async def _trigger(browser: Any, url: str, trigger: str) -> Optional[Dict[str, Any]]:
    """Navigate to ``url`` (and reload for reload/interact gadgets) and return the captured native
    dialog, if any. Reads the dialog from BOTH the navigate/reload result AND a late
    ``pop_last_dialog()`` (a data:-URL gadget may fire its alert just after commit). Uses ONLY the
    native handler — never overrides window.alert on the shared page."""
    try:
        browser.pop_last_dialog()  # clear any stale dialog before this delivery
    except Exception:
        pass
    nav = await browser.navigate(url)
    dialog = _dialog_from_result(nav)
    if trigger in ("reload", "interact"):
        rl = await browser.reload()
        dialog = dialog or _dialog_from_result(rl)
    if dialog is None:
        try:
            dialog = browser.pop_last_dialog()
        except Exception:
            dialog = None
    return dialog


async def _protopollute(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    url = str(args.get("url", "")).strip()
    gadget_pin = str(args.get("gadget", "")).strip()
    vector_pin = str(args.get("source_vector", "")).strip()
    if not url:
        return {"ok": False, "error": "url is required"}
    if not ctx.is_in_scope(url):
        return {"ok": False, "error": "url is out of scope", "url": url}
    browser = getattr(ctx, "browser", None)
    if browser is None:
        return {"ok": False, "error": "prototype_pollution_probe needs the agent browser (not "
                "available in this context); it confirms pollution by reading Object.prototype on "
                "the live page and a gadget alert() dialog, not httpx"}

    sentinel_key, sentinel_val = make_sentinel()
    # Numeric marker so it survives inside a bare alert(<marker>) with no quotes; the confirming
    # dialog message must echo this exact value (an ambient alert cannot).
    marker = str(int(time.time() * 1000) % 100000000)
    steps: List[Dict[str, Any]] = []

    try:
        page = await browser._ensure_page()

        # 1. Find source vectors that actually pollute Object.prototype on the live page.
        vectors = source_vectors(url, sentinel_key, sentinel_val)
        if vector_pin:
            vectors = [(lbl, vurl) for lbl, vurl in vectors if lbl == vector_pin]
            if not vectors:
                return {"ok": False, "error": f"unknown source_vector '{vector_pin}'"}
        polluting: List[tuple] = []
        for label, vurl in vectors:
            await browser.navigate(vurl)
            try:
                value = await page.evaluate(READ_PROTO_JS, sentinel_key)
            except Exception as exc:
                logger.debug("protopollute: proto read failed", error=str(exc)[:160])
                value = None
            hit = value == sentinel_val
            steps.append({"label": "source", "source_vector": label, "url": vurl,
                          "polluted": hit})
            if hit:
                polluting.append((label, vurl))

        if not polluting:
            return {"ok": True, "confirmed": False,
                    "verdict": "NOT CONFIRMED — no source vector polluted Object.prototype on "
                               "the live page; the app is not client-side prototype-pollutable "
                               "via these vectors.", "steps": steps}

        # 2. For each polluting source, drive the gadget library until an alert() carries the marker.
        gadgets = load_gadgets()
        if gadget_pin:
            gadgets = [g for g in gadgets if g.get("name") == gadget_pin]
            if not gadgets:
                return {"ok": False, "error": f"unknown gadget '{gadget_pin}'"}

        for label, source_url in polluting:
            for gadget in gadgets:
                gurl = gadget_url(url, label, gadget, marker)
                trigger = str(gadget.get("trigger", "load")).strip().lower() or "load"
                dialog = await _trigger(browser, gurl, trigger)
                if marker_in_dialog(dialog, marker):
                    steps.append({"label": "CONFIRMED", "source_vector": label,
                                  "gadget": gadget.get("name"), "url": gurl, "dialog": dialog})
                    return _confirm_result(ctx, args, url, label, source_url, gadget, gurl,
                                           dialog, steps)
                steps.append({"label": "gadget miss", "source_vector": label,
                              "gadget": gadget.get("name"), "url": gurl,
                              "dialog": dialog})
    except Exception as exc:
        return {"ok": False, "error": f"probe failed: {str(exc)[:200]}", "steps": steps}

    return {"ok": True, "confirmed": False,
            "source_vector": polluting[0][0] if polluting else None,
            "verdict": "NOT CONFIRMED — a source polluted Object.prototype, but no gadget turned "
                       "the pollution into a confirmed alert(). Prototype pollution is present but "
                       "no DOM-XSS gadget fired.", "steps": steps}


def _confirm_result(ctx: ToolContext, args: Dict[str, Any], url: str, source_label: str,
                    source_url: str, gadget: Dict[str, Any], gadget_url_str: str,
                    dialog: Dict[str, Any], steps: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build the CONFIRMED result and record a CWE-1321 finding (same store API xss/sqli use)."""
    gadget_name = str(gadget.get("name", ""))
    prop = str(gadget.get("property", ""))
    dialog_msg = dialog.get("message") if isinstance(dialog, dict) else dialog
    verdict = (f"CONFIRMED — client-side prototype pollution to DOM XSS. Source vector "
               f"'{source_label}' polluted Object.prototype; gadget '{gadget_name}' "
               f"(property {prop!r}) fired a JS dialog ({dialog.get('type') if isinstance(dialog, dict) else 'alert'}: "
               f"{dialog_msg!r}).")
    sev_arg = str(args.get("severity", "")).strip().lower()
    severity = sev_arg if sev_arg in _VALID_SEVERITIES else "high"
    result: Dict[str, Any] = {
        "ok": True, "confirmed": True, "source_vector": source_label, "gadget": gadget_name,
        "dialog": dialog, "verdict": verdict, "severity": severity, "steps": steps,
    }
    if bool(args.get("record", True)) and getattr(ctx, "store", None) is not None:
        evidence = (verdict + f" [source_vector_url={source_url}; polluted_property={prop!r}; "
                    f"confirming_url={gadget_url_str}; dialog_message={dialog_msg!r}]")
        finding = {
            "title": str(args.get("title", "")).strip()
            or f"Client-side prototype pollution to DOM XSS via {gadget_name}",
            "severity": severity,
            "attack_type": "prototype_pollution",
            "cwe": str(args.get("cwe", "CWE-1321")).strip() or "CWE-1321",
            "parameter": prop,
            "evidence": evidence,
            "source_vector": source_label,
            "polluted_property": prop,
            "gadget": gadget_name,
            "payload": gadget_url_str,
            "steps": steps,
            "confirmed": True,
            "confidence": 1.0,
            "validated_by": ["prototype_pollution_probe"],
            "source": "copilot",
        }
        try:
            entry_id = ctx.store.record_manual_finding(finding, url, "GET")
            result["recorded_entry_id"] = entry_id
            logger.info("prototype_pollution_probe recorded finding", entry_id=entry_id,
                        source_vector=source_label, gadget=gadget_name, severity=severity)
        except Exception as exc:
            result["record_error"] = str(exc)[:200]
    return result


register(Tool(
    name="prototype_pollution_probe",
    description=(
        "Deterministically probe ONE page URL for CLIENT-SIDE prototype pollution that leads to "
        "DOM XSS — no LLM, so the gateway's content-safety filter cannot block it. It pollutes a "
        "unique sentinel property through a library of source vectors (__proto__[...] and "
        "constructor[prototype] in the query string, the location.hash variants, nested-merge "
        "shapes, and WAF-bypass encodings), reads Object.prototype on the REAL agent browser "
        "(carrying the authenticated session) to find which source actually pollutes the "
        "prototype, then drives a gadget library (transport_url/src/srcdoc/...) and confirms "
        "STRICTLY via a captured alert() dialog carrying the probe's unique marker — reflection or "
        "a mere polluted prototype never confirms on their own. Optional 'gadget' / "
        "'source_vector' pin a single one. Records a CONFIRMED finding (CWE-1321) with the source "
        "vector, polluted property, confirming URL and dialog message as evidence. Use this once "
        "you suspect a client-side proto-pollution sink instead of hand-crafting gadget payloads."
    ),
    input_schema=_SCHEMA,
    handler=_protopollute,
    tags=["active", "write"],
))
