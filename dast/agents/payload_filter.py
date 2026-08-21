"""
Tech-stack-aware payload group filter.

Every agent calls `get_filtered_payloads(attack_type, target)` instead of
calling `get_payloads()` directly. This module decides which payload groups
to include or exclude based on evidence from:

  1. discovery_context.tech_stack   (fingerprinter — most reliable)
  2. app_profile_hint               (LLM background synthesis)
  3. Response headers in the request (X-Powered-By, Server, Set-Cookie)
  4. URL patterns                   (.php, .jsp, .aspx, …)

Only groups with confirmed-relevant tech are included. Generic groups
(unix traversal, boolean SQLi, basic XSS, …) are always included.
Tech-specific groups are opt-in: they only appear when there is evidence
that the target uses that technology.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, List

from dast.payloads.loader import get_payloads

if TYPE_CHECKING:
    from dast.scanners.active_checks import CheckTarget


# ── Tech detection helpers ──────────────────────────────────────────────────

_PHP_RE = re.compile(
    r"x-powered-by:\s*php|\.php\b|php/[0-9]|<?php|phpsessid", re.I
)
_JAVA_RE = re.compile(
    r"x-powered-by:\s*(servlet|jsp|tomcat|jboss|weblogic|websphere)|"
    r"\.jsp\b|\.do\b|jsessionid|spring|struts|jersey|grails",
    re.I,
)
_DOTNET_RE = re.compile(
    r"x-powered-by:\s*asp\.net|\.aspx?\b|asp\.net|__viewstate|aspsessionid|"
    r"x-aspnet-version",
    re.I,
)
_NODE_RE = re.compile(r"x-powered-by:\s*express|node\.?js", re.I)
_RUBY_RE = re.compile(r"x-powered-by:\s*phusion|rack|rails|sinatra|ruby", re.I)
_PYTHON_RE = re.compile(r"x-powered-by:\s*(django|flask|fastapi|gunicorn|uwsgi)|"
                        r"wsgi|django|flask|fastapi", re.I)
_GRAPHQL_RE = re.compile(r"graphql|\.graphql\b|/graphql\b", re.I)
_XML_RE = re.compile(r"application/xml|text/xml|application/soap", re.I)
_NOSQL_RE = re.compile(r"mongodb|mongoose|elastic|couchdb|redis|dynamodb|firestore", re.I)
_WINDOWS_RE = re.compile(
    r"iis|windows|\.aspx?\b|aspsessionid|x-aspnet", re.I
)
_TEMPLATE_RE = re.compile(
    r"jinja|twig|nunjucks|handlebars|mustache|smarty|freemarker|velocity|thymeleaf|"
    r"erb\b|haml\b|liquid\b|pug\b|jade\b",
    re.I,
)


def _scan_target(target: "CheckTarget") -> str:
    """Return a combined string from all observable target signals."""
    parts: list = [target.url]

    for k, v in (target.headers or {}).items():
        parts.append(f"{k}: {v}")

    dc = getattr(target, "discovery_context", None)
    if dc is not None:
        ts = getattr(dc, "tech_stack", None)
        if ts is not None:
            parts.append(getattr(ts, "language", "") or "")
            parts.append(getattr(ts, "framework", "") or "")
            parts.append(getattr(ts, "server", "") or "")
            parts.append(getattr(ts, "template_engine", "") or "")
            parts.append(getattr(ts, "cms", "") or "")
            parts.extend(getattr(ts, "database_hints", []))

    parts.append(getattr(target, "app_profile_hint", "") or "")

    return " ".join(parts)


def _has(pattern: re.Pattern, signal: str) -> bool:
    return bool(pattern.search(signal))


def _content_type(target: "CheckTarget") -> str:
    return (target.headers or {}).get("content-type", "").lower()


# ── Per-attack-type group selectors ────────────────────────────────────────

def _lfi_groups(target: "CheckTarget", signal: str) -> List[str]:
    groups = ["unix", "null_byte"]
    if _has(_WINDOWS_RE, signal) or _has(_DOTNET_RE, signal):
        groups.append("windows")
    if _has(_PHP_RE, signal):
        groups.append("wrappers")
    return groups


def _sqli_groups(target: "CheckTarget", signal: str) -> List[str]:
    groups = ["error_based", "boolean_based"]
    # Time-based is expensive (5 s delay each) — only run when response
    # shows DB errors or when we already have evidence of SQLi on this host.
    # Always include for now (agent itself caps SLEEP at 5 s) but order last.
    groups.append("time_based")
    # Stacked queries only work on MS-SQL / PostgreSQL
    if any(kw in signal for kw in ("mssql", "sql server", "sqlserver", "postgres", "pg::", "npgsql")):
        groups.append("stacked")
    return groups


def _xss_groups(target: "CheckTarget", signal: str) -> List[str]:
    groups = ["basic"]
    ct = _content_type(target)
    # DOM payloads are only relevant in HTML responses / SPAs
    if "json" not in ct and "xml" not in ct:
        groups.append("dom")
    # Obfuscation and bypass only matter when there is a WAF or content filter.
    # Include them — they're short — but put them after basic.
    groups += ["obfuscation", "bypass"]
    # Blind XSS (oob callback) only useful with a collaborator endpoint.
    # Include only when the app profile suggests user-controlled output (CMS, ticketing, etc.)
    hint = signal.lower()
    if any(kw in hint for kw in ("cms", "admin", "ticket", "support", "message", "comment", "forum", "blog")):
        groups.append("blind")
    return groups


def _ssrf_groups(target: "CheckTarget", signal: str) -> List[str]:
    groups = ["oob_http", "internal_probe"]
    # Obfuscated SSRF probes are useful against URL parsers — include when
    # param value looks like a URL or the endpoint name suggests it handles URLs.
    hint = signal.lower()
    if any(kw in hint for kw in ("url", "redirect", "callback", "webhook", "fetch", "proxy", "forward", "endpoint")):
        groups.append("oob_obfuscated")
    return groups


def _cmdi_groups(target: "CheckTarget", signal: str) -> List[str]:
    groups = ["unix_basic"]
    if _has(_WINDOWS_RE, signal) or _has(_DOTNET_RE, signal):
        groups += ["windows_basic", "windows_blind_time"]
    else:
        groups.append("unix_blind_time")
    # Bypass payloads only when there is evidence of a WAF / filter
    hint = signal.lower()
    if any(kw in hint for kw in ("waf", "filter", "blocked", "modsec", "cloudflare", "akamai")):
        groups.append("bypass")
    return groups


def _xxe_groups(target: "CheckTarget", signal: str) -> List[str]:
    ct = _content_type(target)
    body = (target.body or "").lower()
    # XXE only applies to XML/SOAP bodies or multipart with XML parts
    if not (_has(_XML_RE, signal) or "xml" in ct or "soap" in ct or body.startswith("<")):
        return []
    groups = ["basic_file_read"]
    # OOB/SSRF XXE requires an outbound network channel — include by default
    groups += ["oob_dtd", "ssrf_internal"]
    # CDATA bypass only useful when entities are blocked — include as late variant
    groups.append("cdata_bypass")
    return groups


def _ssti_groups(target: "CheckTarget", signal: str) -> List[str]:
    # SSTI only makes sense when the app renders templates on the server.
    ct = _content_type(target)
    body = (target.body or "").lower()
    response_looks_html = "html" in ct or "<" in body

    # Check if fingerprinter detected a server-side template engine
    dc = getattr(target, "discovery_context", None)
    ts = getattr(dc, "tech_stack", None) if dc else None
    has_template_engine = bool(getattr(ts, "template_engine", None))
    has_cms = bool(getattr(ts, "cms", None))  # CMS always has templates

    has_template_hint = _has(_TEMPLATE_RE, signal)
    hint = signal.lower()
    looks_like_template_endpoint = any(
        kw in hint for kw in ("template", "render", "view", "page", "report", "email", "pdf", "notify")
    )

    if not (response_looks_html or has_template_hint or has_template_engine or has_cms or looks_like_template_endpoint):
        return []

    groups = ["detection"]
    if has_template_hint or has_template_engine or looks_like_template_endpoint:
        groups += ["obfuscation", "rce_probe"]
    return groups


def _nosql_groups(target: "CheckTarget", signal: str) -> List[str]:
    if not _has(_NOSQL_RE, signal):
        hint = signal.lower()
        if not any(kw in hint for kw in ("nosql", "mongo", "elastic", "redis", "dynamo", "document")):
            return []
    groups = ["mongodb_operator"]
    if any(kw in signal.lower() for kw in ("mongodb", "mongoose", "mongo")):
        groups.append("mongodb_js_injection")
    if any(kw in signal.lower() for kw in ("elastic", "elasticsearch")):
        groups.append("elasticsearch")
    if any(kw in signal.lower() for kw in ("redis",)):
        groups.append("redis_crlf")
    return groups


def _prototype_pollution_groups(target: "CheckTarget", signal: str) -> List[str]:
    # Prototype pollution is JavaScript-only.
    if not (_has(_NODE_RE, signal) or "javascript" in signal.lower() or "node" in signal.lower()
            or "express" in signal.lower() or "json" in _content_type(target)):
        return []
    groups = ["detection"]
    ct = _content_type(target)
    if "json" in ct:
        groups.append("json_body")
    else:
        groups.append("query_string")
    return groups


def _jwt_groups(target: "CheckTarget", signal: str) -> List[str]:
    # JWT attacks only when there is an Authorization: Bearer header or
    # a recognisable JWT in a cookie/param.
    has_bearer = any(
        k.lower() == "authorization" and "bearer" in v.lower()
        for k, v in (target.headers or {}).items()
    )
    has_jwt_cookie = any(
        "eyj" in v.lower()
        for k, v in (target.headers or {}).items()
        if k.lower() == "cookie"
    )
    if not (has_bearer or has_jwt_cookie):
        return []
    return ["alg_none", "weak_secrets", "kid_injection"]


# ── Public API ──────────────────────────────────────────────────────────────

# Map: attack_type → group selector function
_SELECTORS = {
    "lfi":                  _lfi_groups,
    "sqli":                 _sqli_groups,
    "xss":                  _xss_groups,
    "ssrf":                 _ssrf_groups,
    "cmdi":                 _cmdi_groups,
    "xxe":                  _xxe_groups,
    "ssti":                 _ssti_groups,
    "nosql":                _nosql_groups,
    "prototype_pollution":  _prototype_pollution_groups,
    "jwt":                  _jwt_groups,
}


def get_filtered_payloads(attack_type: str, target: "CheckTarget") -> List[str]:
    """
    Return payloads for `attack_type` filtered to groups relevant for `target`.

    Falls back to `get_payloads(attack_type, group)` for each selected group.
    If no selector exists for this attack_type, returns an empty list
    (caller should use get_payloads/get_all_payloads directly).

    Returns an empty list when no groups apply (e.g. XXE on a JSON-only API).
    """
    selector = _SELECTORS.get(attack_type)
    if selector is None:
        return []

    signal = _scan_target(target)
    groups = selector(target, signal)
    if not groups:
        return []

    payloads: List[str] = []
    seen: set = set()
    for group in groups:
        for p in get_payloads(attack_type, group):
            if p not in seen:
                seen.add(p)
                payloads.append(p)
    return payloads
