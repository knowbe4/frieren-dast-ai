"""
authz_differential_probe tool — deterministic same-owner authorization differential.

A cross-tenant / BOLA verdict is only meaningful against a baseline: the SAME
operation fired against a resource the caller OWNS. A bare cross-tenant status is
ambiguous — 404/500/403 can be enforcement OR a missing route OR a feature gate,
and a 2xx can be a real leak OR the backend ignoring the injected id and returning
the caller's OWN data. This tool fires the operation twice under the caller's
session — once against an owned resource (control) and once against another
tenant's resource (target) — and classifies on the pair, deterministically, in ONE
call with no LLM (so it fits short session windows where an AI loop cannot run).

For a mutation, a 2xx does not prove impact and a 500/404 does not rule out a
side-effect; an optional victim read-back (as the victim, cookie supplied by the
operator) confirms whether the change actually landed.

Auth is self-contained: the freshest live Cookie header for the target host is read
from proxy history (falling back to the cookie jar) and attached to every
sub-request, routed through the proxy so each step is recorded in history in-scope.

Complements idor_tools.idor_probe (single-session write-then-read of a stored
object) and idor_scan_tools.run_multiuser_idor (LLM, same-resource two-session
replay). Use THIS when you have the caller's session and want a deterministic
own-vs-other differential on an existing resource (read or mutation).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from dast.proxy.auth_headers import build_cookie_header
from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")
_SAFE_METHODS = ("GET", "HEAD", "OPTIONS")

_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "target_url": {
            "type": "string",
            "description": "URL of the operation against a resource the caller does NOT own "
                           "(another tenant/org/user). This is the potential BOLA.",
        },
        "control_url": {
            "type": "string",
            "description": "SAME operation shape against a resource the caller DOES own — the "
                           "baseline. Required: without it a cross-tenant status cannot be "
                           "interpreted (enforcement vs missing-route vs param-ignored).",
        },
        "method": {"type": "string", "description": "HTTP method for both requests (default GET)."},
        "body": {"type": "string", "description": "Request body for target_url (for non-GET)."},
        "control_body": {
            "type": "string",
            "description": "Request body for control_url (usually identical shape with the caller's "
                           "own id). Defaults to 'body' when omitted.",
        },
        "content_type": {"type": "string", "description": "Content-Type for bodies (default application/json)."},
        "own_marker": {
            "type": "string",
            "description": "A string unique to the CALLER's own data (own email/org id). If it "
                           "appears in the target response, the backend ignored the injected id and "
                           "returned the caller's own data — NOT a vulnerability.",
        },
        "victim_marker": {
            "type": "string",
            "description": "A string unique to the VICTIM's data (their email/org name/id). If it "
                           "appears in the target response, a cross-tenant READ is CONFIRMED.",
        },
        "victim_readback_url": {
            "type": "string",
            "description": "Optional: for a mutation, a URL that reads the victim resource back to "
                           "confirm the change landed. Best supplied with victim_cookie so it reads "
                           "AS the victim.",
        },
        "victim_cookie": {
            "type": "string",
            "description": "Optional Cookie header for victim_readback_url (the victim's session). "
                           "When omitted the read-back uses the caller's session.",
        },
        "victim_readback_marker": {
            "type": "string",
            "description": "Optional: a string expected in victim_readback_url ONLY if the mutation "
                           "landed (e.g. the new value written). Its presence CONFIRMS a "
                           "cross-tenant mutation.",
        },
        "record": {"type": "boolean", "description": "Record a finding when CONFIRMED (default true)."},
        "title": {"type": "string", "description": "Finding title (optional; a sensible default is used)."},
        "severity": {"type": "string", "description": "critical|high|medium|low|info (default high)."},
        "cwe": {"type": "string", "description": "CWE id (default CWE-639)."},
        "parameter": {"type": "string", "description": "Injection point (default 'resource id')."},
    },
    "required": ["target_url", "control_url"],
}


def _is_2xx(status: Optional[int]) -> bool:
    return isinstance(status, int) and 200 <= status < 300


def _parent_domain(host: str) -> str:
    """Everything after the first label, when that leaves a >=2-label domain.
    api.foo.example.com -> foo.example.com; example.com -> '' (too short)."""
    labels = host.split(".")
    parent = ".".join(labels[1:]) if len(labels) >= 3 else ""
    return parent if parent.count(".") >= 1 else ""


def _host_matches(entry_host: str, host: str) -> bool:
    """Match an entry's host to the target host for cookie reuse. Session cookies
    are domain-scoped, so besides an exact / parent-child match we also treat
    SIBLING subdomains that share an immediate parent domain as a match
    (api.foo.example.com <-> settings-api.foo.example.com)."""
    eh = (entry_host or "").lower()
    h = (host or "").lower()
    if not h or not eh:
        return False
    if eh == h or eh.endswith("." + h) or h.endswith("." + eh):
        return True
    parent = _parent_domain(h)
    return bool(parent) and (eh == parent or eh.endswith("." + parent))


def _live_cookie_header(ctx: ToolContext, host: str) -> Optional[str]:
    """Freshest live Cookie header for *host* from proxy history, falling back to
    the cookie jar. Reading from the newest entry sidesteps the stale-jar problem
    (the jar is not always refreshed from SSO-callback Set-Cookie responses)."""
    store = getattr(ctx, "store", None)
    if store is None:
        return None
    try:
        for entry in store.entries_newest_first():
            if not _host_matches(getattr(entry, "host", ""), host):
                continue
            headers = getattr(entry, "request_headers", None) or {}
            for k, v in headers.items():
                if k.lower() == "cookie" and v:
                    return str(v)
    except Exception as exc:
        logger.warning("authz_diff: history cookie lookup failed", host=host, error=str(exc))
    try:
        cookies = store.get_cookies_for_host(host) or []
    except Exception as exc:
        logger.warning("authz_diff: jar cookie lookup failed", host=host, error=str(exc))
        return None
    header = build_cookie_header(cookies)
    return header or None


async def _authz_differential_probe(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    target_url = str(args.get("target_url", "")).strip()
    control_url = str(args.get("control_url", "")).strip()
    if not target_url or not control_url:
        return {"ok": False, "error": "target_url and control_url are required"}

    method = str(args.get("method", "GET")).strip().upper() or "GET"
    body = args.get("body")
    control_body = args.get("control_body", body)
    content_type = str(args.get("content_type", "application/json")).strip() or "application/json"
    own_marker = str(args.get("own_marker", "") or "")
    victim_marker = str(args.get("victim_marker", "") or "")
    readback_url = str(args.get("victim_readback_url", "")).strip()
    victim_cookie = str(args.get("victim_cookie", "") or "")
    readback_marker = str(args.get("victim_readback_marker", "") or "")

    # Read-only mode: refuse a mutating operation outright.
    if getattr(ctx, "read_only", False) and method not in _SAFE_METHODS:
        return {"ok": False, "error": f"read-only mode: refusing a {method} request"}

    # Scope-gate every URL before sending anything.
    for url in (target_url, control_url, readback_url):
        if url and not ctx.is_in_scope(url):
            return {"ok": False, "error": "url is out of scope", "url": url}

    host = urlparse(target_url).hostname or ""
    cookie = _live_cookie_header(ctx, host)
    source_label = getattr(ctx, "source_label", None)

    def _headers(cookie_override: Optional[str] = None,
                 with_body: bool = False) -> Dict[str, str]:
        h: Dict[str, str] = {}
        ck = cookie_override if cookie_override is not None else cookie
        if ck:
            h["cookie"] = ck
        if source_label:
            h["x-dast-source"] = str(source_label)
        if with_body:
            h["content-type"] = content_type
        return h

    steps: List[Dict[str, Any]] = []
    try:
        import httpx

        async with httpx.AsyncClient(
            proxy=ctx.proxy_url, verify=False, follow_redirects=False, timeout=15,
        ) as client:
            # (a) control — same operation on a resource the caller OWNS (baseline)
            is_write = method not in _SAFE_METHODS
            c = await client.request(
                method, control_url, headers=_headers(with_body=is_write),
                content=(str(control_body).encode("utf-8") if (is_write and control_body is not None) else None))
            control_2xx = _is_2xx(c.status_code)
            steps.append({"label": "control (own resource)", "method": method, "url": control_url,
                          "status": c.status_code,
                          "note": ("baseline OK — caller can perform this on their own resource"
                                   if control_2xx else
                                   "baseline FAILED — own resource did not succeed")})

            # (b) target — same operation on ANOTHER tenant's resource
            t = await client.request(
                method, target_url, headers=_headers(with_body=is_write),
                content=(str(body).encode("utf-8") if (is_write and body is not None) else None))
            target_text = t.text
            target_2xx = _is_2xx(t.status_code)
            own_hit = bool(own_marker) and own_marker in target_text
            victim_hit = bool(victim_marker) and victim_marker in target_text
            steps.append({"label": "target (other tenant's resource)", "method": method,
                          "url": target_url, "status": t.status_code,
                          "note": _target_note(target_2xx, own_hit, victim_hit)})

            # (c) optional victim read-back to confirm a mutation landed
            readback_hit = False
            if readback_url and target_2xx and not victim_hit and not own_hit:
                rb_cookie = victim_cookie or cookie
                rb = await client.request("GET", readback_url, headers=_headers(cookie_override=rb_cookie))
                readback_hit = bool(readback_marker) and readback_marker in rb.text
                steps.append({"label": "victim read-back", "method": "GET", "url": readback_url,
                              "status": rb.status_code,
                              "note": ("victim resource reflects the change — mutation landed"
                                       if readback_hit else
                                       "victim resource does not reflect the change")})
    except Exception as exc:
        return {"ok": False, "error": f"probe failed: {str(exc)[:200]}", "steps": steps}

    verdict, confirmed = _classify(
        control_2xx=control_2xx, target_2xx=target_2xx,
        own_hit=own_hit, victim_hit=victim_hit,
        had_markers=bool(own_marker or victim_marker),
        readback_url=bool(readback_url), readback_hit=readback_hit)

    result: Dict[str, Any] = {"ok": True, "confirmed": confirmed, "verdict": verdict, "steps": steps}

    if confirmed and bool(args.get("record", True)) and getattr(ctx, "store", None) is not None:
        severity = str(args.get("severity", "high")).strip().lower()
        if severity not in _VALID_SEVERITIES:
            severity = "high"
        finding = {
            "title": str(args.get("title", "")).strip()
            or "Broken object-level authorization (BOLA) — cross-tenant access, no ownership check",
            "severity": severity,
            "attack_type": "broken-access-control",
            "cwe": str(args.get("cwe", "CWE-639")).strip() or "CWE-639",
            "parameter": str(args.get("parameter", "resource id")).strip() or "resource id",
            "evidence": verdict,
            "steps": steps,
            "confirmed": True,
            "confidence": 1.0,
            "validated_by": ["authz_differential_probe"],
            "source": "copilot",
        }
        try:
            entry_id = ctx.store.record_manual_finding(finding, target_url, method)
            result["recorded_entry_id"] = entry_id
            logger.info("authz_diff recorded finding", entry_id=entry_id, severity=severity)
        except Exception as exc:
            result["record_error"] = str(exc)[:200]

    return result


def _target_note(target_2xx: bool, own_hit: bool, victim_hit: bool) -> str:
    if not target_2xx:
        return "rejected on another tenant's resource"
    if own_hit:
        return "2xx but returned the CALLER's own data — injected id ignored"
    if victim_hit:
        return "2xx and returned the VICTIM's data — cross-tenant read"
    return "2xx on another tenant's resource"


def _classify(*, control_2xx: bool, target_2xx: bool, own_hit: bool, victim_hit: bool,
              had_markers: bool, readback_url: bool, readback_hit: bool) -> tuple[str, bool]:
    """Deterministic verdict from the own-vs-other differential."""
    if not control_2xx:
        return ("INCONCLUSIVE — the same operation failed on the caller's OWN resource, so there is "
                "no baseline. The target status may reflect a missing route or a feature gate, not "
                "enforcement. Fix the control request and re-run.", False)
    if not target_2xx:
        return ("NOT CONFIRMED (enforced) — the operation succeeds on the caller's own resource but "
                "is rejected on another tenant's. The backend enforces the ownership boundary.", False)
    # target is 2xx
    if own_hit:
        return ("NOT CONFIRMED (param ignored) — the target returned the CALLER's own data; the "
                "backend ignored the injected id. Not a cross-tenant access.", False)
    if victim_hit:
        return ("CONFIRMED (cross-tenant read) — the caller read another tenant's data (victim "
                "marker present in the response).", True)
    if readback_hit:
        return ("CONFIRMED (cross-tenant mutation) — the victim resource reflects the caller's "
                "change (confirmed by read-back).", True)
    if readback_url:
        return ("NEEDS REVIEW — the target accepted the request (2xx) but the victim read-back did "
                "not reflect the change. Possible no-op; verify the read-back/marker.", False)
    return ("NEEDS REVIEW — the target returned 2xx but no own_marker/victim_marker/read-back was "
            "supplied to disambiguate a real leak from the backend ignoring the id. Supply a marker "
            "or a victim read-back and re-run.", False)


register(Tool(
    name="authz_differential_probe",
    description=(
        "Deterministically decide a cross-tenant / BOLA verdict by firing the SAME operation twice "
        "under the caller's session: against a resource the caller OWNS (control_url, the baseline) "
        "and against another tenant's resource (target_url). Classifies on the pair in ONE call, no "
        "LLM: INCONCLUSIVE (own also failed — no baseline), NOT CONFIRMED (enforced, or the id was "
        "ignored and own data came back), CONFIRMED (victim data read, or a mutation confirmed via "
        "victim read-back), or NEEDS REVIEW. Records a finding with the full request chain only when "
        "CONFIRMED. Cookies are taken from proxy history (freshest) automatically.\n"
        "Use this for a read OR mutation on an EXISTING resource when you have the caller's session "
        "and want a decisive own-vs-other differential — it works inside short session windows where "
        "the LLM-driven run_multiuser_idor cannot. For a write-then-read stored-object IDOR use "
        "idor_probe instead.\n"
        "Supply own_marker / victim_marker for a decisive 2xx verdict. SAFETY: control_url must be a "
        "resource YOU own; target_url is another tenant's resource you are AUTHORIZED to test."
    ),
    input_schema=_SCHEMA,
    handler=_authz_differential_probe,
    tags=["active"],
))
