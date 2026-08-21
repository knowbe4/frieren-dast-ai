"""
Passive scanner plugin — runs on every proxied request/response without
sending extra traffic. Fires findings into the dashboard automatically.

Rules are defined in YAML files under dast/passive_rules/ and loaded at
startup. Adding a new check requires only a new YAML file — no code changes.

Special match types handled by the engine:
  header_absent         — fires if a named response header is missing
  header_present        — fires if a named response header exists
  header_value_regex    — fires if header value matches regex
  header_name_any       — multi-header variant of header_value_regex
  cookie_flag_absent    — fires for each Set-Cookie missing the flag
  cookie_name_regex     — additional filter on cookie name (used with cookie checks)
  body_regex            — fires if response body matches regex
  path_regex            — fires if request path matches regex
  cors_check            — stateful: compares request Origin vs response ACAO
  also_header_name/val  — secondary header assertion (AND condition)
  request_header_present + header_value_not_regex — used for cache/auth checks
  csp_frame_ancestors_absent — additionally verify CSP has no frame-ancestors
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

import yaml

from dast.proxy.plugin_base import ProxyPlugin
from dast.utils.logger import get_logger

logger = get_logger(__name__)

if TYPE_CHECKING:
    from dast.proxy.session_store import ProxyEntry, SessionStore

# ── aggressive-rule runtime toggle ───────────────────────────────────────────
# Rules tagged `aggressive: true` in YAML are more false-positive prone
# (e.g. CSP-completeness "missing directive" checks using negative-lookahead).
# They are skipped by default to honour the lowest-false-positive-rate goal, and
# only evaluated when the operator opts in via POST /api/scan-config. This is a
# per-loop gate (not applied in the @lru_cache'd loader, which stays config-agnostic).
_AGGRESSIVE_RULES_ENABLED = False


def set_aggressive_rules(enabled: bool) -> None:
    """Enable or disable evaluation of `aggressive: true` passive rules at runtime."""
    global _AGGRESSIVE_RULES_ENABLED
    _AGGRESSIVE_RULES_ENABLED = bool(enabled)
    logger.info("Aggressive passive rules toggled", enabled=_AGGRESSIVE_RULES_ENABLED)


def aggressive_rules_enabled() -> bool:
    """Return whether aggressive passive rules are currently enabled."""
    return _AGGRESSIVE_RULES_ENABLED


# ── rule loading ───────────────────────────────────────────────────────────

_RULES_DIR = Path(__file__).parent.parent / "passive_rules"

Finding = Tuple[str, str, str, str, Optional[int], Optional[str], bool, Optional[str], bool]
# (title, severity, cwe, evidence, line_no, snippet, needs_ai_validation, redacted_snippet, confirmed)


@lru_cache(maxsize=None)
def _load_all_rules() -> List[Dict[str, Any]]:
    rules: List[Dict[str, Any]] = []
    for yaml_path in sorted(_RULES_DIR.rglob("*.yaml")):
        try:
            data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
            for rule in data.get("rules", []):
                rule["_source_file"] = str(yaml_path.relative_to(_RULES_DIR))
                rules.append(rule)
        except Exception as exc:
            logger.warning("Failed to load passive rule file", path=str(yaml_path), error=str(exc))
    logger.info("Passive rules loaded", count=len(rules))
    return rules


# ── entry helpers ──────────────────────────────────────────────────────────

def _hdrs(entry: "ProxyEntry") -> Dict[str, str]:
    return {k.lower(): v for k, v in entry.response_headers.items()}


def _req_hdrs(entry: "ProxyEntry") -> Dict[str, str]:
    return {k.lower(): v for k, v in entry.request_headers.items()}


def _body(entry: "ProxyEntry", max_bytes: int = 8192) -> str:
    if not entry.response_body:
        return ""
    raw = entry.response_body[:max_bytes]
    return raw.decode("utf-8", errors="replace")


def _is_html(entry: "ProxyEntry") -> bool:
    ct = entry.content_type.lower()
    return "text/html" in ct or "application/xhtml" in ct


def _is_json(entry: "ProxyEntry") -> bool:
    return "application/json" in entry.content_type.lower()


def _content_type_matches(entry: "ProxyEntry", required: str) -> bool:
    if required in ("any", "", None):
        return True
    if required == "html":
        return _is_html(entry)
    if required == "json":
        return _is_json(entry)
    return True


# ── condition checks ───────────────────────────────────────────────────────

def _conditions_match(
    rule: Dict[str, Any],
    entry: "ProxyEntry",
    fired_hosts: Dict[str, set],
) -> bool:
    cond = rule.get("conditions", {})

    if not _content_type_matches(entry, cond.get("content_type", "any")):
        return False

    status_codes = cond.get("status_codes", [])
    if status_codes and entry.response_status not in status_codes:
        return False

    scheme_req = cond.get("scheme", "any")
    if scheme_req == "https" and not entry.url.startswith("https"):
        return False
    if scheme_req == "http" and not entry.url.startswith("http://"):
        return False

    if cond.get("one_per_host"):
        rule_id = rule.get("id", "")
        if entry.host in fired_hosts.get(rule_id, set()):
            return False

    return True


def _record_host_fire(rule: Dict[str, Any], entry: "ProxyEntry", fired_hosts: Dict[str, set]) -> None:
    cond = rule.get("conditions", {})
    if cond.get("one_per_host"):
        rule_id = rule.get("id", "")
        fired_hosts.setdefault(rule_id, set()).add(entry.host)


# ── evidence formatting ────────────────────────────────────────────────────

def _format_evidence(template: str, **ctx: Any) -> str:
    try:
        return template.format(**ctx)
    except (KeyError, IndexError):
        return template


# ── match evaluators ───────────────────────────────────────────────────────

def _eval_header_absent(rule: Dict[str, Any], entry: "ProxyEntry") -> Optional[Finding]:
    match = rule.get("match", {})
    hdr = match.get("header_absent", "").lower()
    if not hdr:
        return None
    hdrs = _hdrs(entry)
    if hdr in hdrs:
        return None
    evidence = _format_evidence(
        rule.get("evidence_template", f"Header '{hdr}' not present in response"),
        header=hdr,
        path=entry.path,
    )
    return (rule["title"], rule["severity"], rule["cwe"], evidence, None, None, rule.get("needs_ai_validation", False), None, rule.get("confirmed", True))


def _eval_header_present(rule: Dict[str, Any], entry: "ProxyEntry") -> Optional[Finding]:
    match = rule.get("match", {})
    hdr = match.get("header_present", "").lower()
    if not hdr:
        return None
    hdrs = _hdrs(entry)
    val = hdrs.get(hdr, "")
    if not val:
        return None
    evidence = _format_evidence(
        rule.get("evidence_template", f"Header '{hdr}' present in response"),
        header=hdr,
        value=val,
        path=entry.path,
    )
    return (rule["title"], rule["severity"], rule["cwe"], evidence, None, None, rule.get("needs_ai_validation", False), None, rule.get("confirmed", True))


def _eval_header_value_regex(rule: Dict[str, Any], entry: "ProxyEntry") -> Optional[Finding]:
    match = rule.get("match", {})
    pattern_str = match.get("header_value_regex", "")
    if not pattern_str:
        return None
    hdrs = _hdrs(entry)
    pattern = re.compile(pattern_str, re.IGNORECASE)

    # also_header check (AND condition)
    also_name = match.get("also_header_name", "").lower()
    also_val = match.get("also_header_value", "")

    # multi-header variant
    header_names: List[str] = match.get("header_name_any", [])
    if not header_names:
        single = match.get("header_name", "").lower()
        if single:
            header_names = [single]
        else:
            header_names = list(hdrs.keys())

    for hdr in header_names:
        val = hdrs.get(hdr, "")
        if not val or not pattern.search(val):
            continue
        if also_name and also_val:
            actual_also = hdrs.get(also_name, "").lower()
            if also_val.lower() not in actual_also:
                continue
        evidence = _format_evidence(
            rule.get("evidence_template", f"Header '{hdr}' value matches pattern"),
            header=hdr,
            value=val,
            path=entry.path,
        )
        return (rule["title"], rule["severity"], rule["cwe"], evidence, None, None, rule.get("needs_ai_validation", False), None, rule.get("confirmed", True))
    return None


def _eval_body_regex(rule: Dict[str, Any], entry: "ProxyEntry") -> Optional[Finding]:
    match = rule.get("match", {})
    pattern_str = match.get("body_regex", "")
    if not pattern_str:
        return None
    max_bytes = match.get("body_max_scan_bytes", 8192)
    body = _body(entry, max_bytes)
    if not body:
        return None
    try:
        m = re.search(pattern_str, body, re.IGNORECASE | re.DOTALL)
    except re.error:
        return None
    if not m:
        return None

    line_no = body[:m.start()].count("\n") + 1
    before = body[max(0, m.start() - 200):m.start()]
    matched = body[m.start():m.end()]
    after = body[m.end():m.end() + 200]
    snippet = (before + matched + after).strip()
    # Redacted version used only when sending to LLM to avoid leaking secrets in prompts
    redacted_snippet = (before + re.sub(r"[A-Za-z0-9]", "*", matched) + after).strip()

    evidence = _format_evidence(
        rule.get("evidence_template", "Response body matches pattern"),
        path=entry.path,
        snippet=snippet,
    )
    return (rule["title"], rule["severity"], rule["cwe"], evidence, line_no, snippet, rule.get("needs_ai_validation", False), redacted_snippet, rule.get("confirmed", True))


def _eval_path_regex(rule: Dict[str, Any], entry: "ProxyEntry") -> Optional[Finding]:
    match = rule.get("match", {})
    pattern_str = match.get("path_regex", "")
    if not pattern_str:
        return None
    try:
        if not re.search(pattern_str, entry.path or "", re.IGNORECASE):
            return None
    except re.error:
        return None

    # Also check body patterns for LLM response detection
    body_pattern = match.get("also_body_regex", "")
    if body_pattern:
        body = _body(entry, 2000)
        if not re.search(body_pattern, body, re.IGNORECASE):
            return None

    evidence = _format_evidence(
        rule.get("evidence_template", "Path matches pattern"),
        path=entry.path,
    )
    return (rule["title"], rule["severity"], rule["cwe"], evidence, None, None, rule.get("needs_ai_validation", False), None, rule.get("confirmed", True))


def _cors_etld_plus1(host: str) -> str:
    """Return eTLD+1 (e.g. 'example.com') for same-site comparison."""
    # Strip port if present
    host = host.split(":")[0].lower()
    parts = host.split(".")
    # Simple heuristic: last two labels (covers .com, .io, .net; misses .co.uk etc.)
    # Good enough for false-positive suppression — better to under-suppress than to miss real vulns.
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _cors_is_same_site(origin: str, server_host: str) -> bool:
    """Return True if the origin and server share the same eTLD+1."""
    try:
        from urllib.parse import urlparse as _up
        origin_host = _up(origin).hostname or ""
    except Exception:
        return False
    return _cors_etld_plus1(origin_host) == _cors_etld_plus1(server_host)


def _eval_cors(rule: Dict[str, Any], entry: "ProxyEntry") -> Optional[Finding]:
    match = rule.get("match", {})
    if not match.get("cors_check"):
        return None
    mode = match.get("cors_mode", "")
    if mode != "reflected_with_credentials":
        return None

    hdrs = _hdrs(entry)
    req_hdrs = _req_hdrs(entry)
    acao = hdrs.get("access-control-allow-origin", "").strip()
    acac = hdrs.get("access-control-allow-credentials", "").lower()
    origin = req_hdrs.get("origin", "").strip()

    if not acao or not origin:
        return None
    if acao != origin:
        return None
    if acac != "true":
        return None

    # Same-site reflection is not exploitable — the origin and the server share the
    # same eTLD+1 (e.g. console.example.com → api.console.example.com). A browser
    # will already allow that via the same-origin policy. Only flag cross-site reflections.
    from urllib.parse import urlparse as _up
    server_host = _up(entry.url).hostname or "" if entry.url else (entry.host or "")
    if _cors_is_same_site(origin, server_host):
        return None

    evidence = _format_evidence(
        rule.get("evidence_template", "Server reflects Origin with Allow-Credentials: true"),
        origin=origin,
        path=entry.path,
    )
    return (rule["title"], rule["severity"], rule["cwe"], evidence, None, None, rule.get("needs_ai_validation", False), None, rule.get("confirmed", True))


def _eval_cookies(rule: Dict[str, Any], entry: "ProxyEntry") -> List[Finding]:
    match = rule.get("match", {})
    flag = match.get("cookie_flag_absent", "").lower()
    if not flag:
        return []

    raw = entry.response_headers.get("set-cookie", "")
    if not raw:
        return []
    raw_list: List[str] = raw if isinstance(raw, list) else [raw]

    cookie_name_pattern = match.get("cookie_name_regex", "")
    name_re = re.compile(cookie_name_pattern, re.IGNORECASE) if cookie_name_pattern else None

    findings: List[Finding] = []
    for cookie_str in raw_list:
        name = cookie_str.split("=")[0].strip()
        lower = cookie_str.lower()

        if name_re and not name_re.search(name):
            continue

        # scheme condition for secure flag
        cond = rule.get("conditions", {})
        if flag == "secure" and cond.get("scheme") == "https":
            if not entry.url.startswith("https"):
                continue

        if flag in lower:
            continue  # flag IS present — skip

        evidence = _format_evidence(
            rule.get("evidence_template", f"Cookie missing {flag}"),
            cookie_name=name,
            path=entry.path,
        )
        findings.append((
            rule["title"], rule["severity"], rule["cwe"],
            evidence, None, None, rule.get("needs_ai_validation", False), None, rule.get("confirmed", True),
        ))
    return findings


def _eval_cache_auth(rule: Dict[str, Any], entry: "ProxyEntry") -> Optional[Finding]:
    match = rule.get("match", {})
    req_hdr = match.get("request_header_present", "").lower()
    if not req_hdr:
        return None
    if req_hdr not in _req_hdrs(entry):
        return None

    cc_pattern = match.get("header_value_not_regex", "")
    hdrs = _hdrs(entry)
    cc_val = hdrs.get("cache-control", "")
    if cc_pattern and re.search(cc_pattern, cc_val, re.IGNORECASE):
        return None  # safe value present — no finding

    evidence = _format_evidence(
        rule.get("evidence_template", "Authenticated response may be cached"),
        path=entry.path,
        value=cc_val,
    )
    return (rule["title"], rule["severity"], rule["cwe"], evidence, None, None, rule.get("needs_ai_validation", False), None, rule.get("confirmed", True))


def _eval_clickjacking(rule: Dict[str, Any], entry: "ProxyEntry") -> Optional[Finding]:
    match = rule.get("match", {})
    if not match.get("csp_frame_ancestors_absent"):
        return None
    hdr = match.get("header_absent", "").lower()
    if not hdr:
        return None

    hdrs = _hdrs(entry)
    if hdr in hdrs:
        return None

    # Also check CSP for frame-ancestors
    csp = hdrs.get("content-security-policy", "")
    if "frame-ancestors" in csp.lower():
        return None

    # If the rule also requires a body_regex match (e.g. Blazor detection),
    # the body must contain the pattern — otherwise it fires on every page
    # that lacks framing protection regardless of tech stack.
    body_pattern = match.get("body_regex", "")
    if body_pattern:
        max_bytes = match.get("body_max_scan_bytes", 8192)
        body = _body(entry, max_bytes)
        try:
            if not re.search(body_pattern, body, re.IGNORECASE | re.DOTALL):
                return None
        except re.error:
            return None

    evidence = _format_evidence(
        rule.get("evidence_template", "No frame embedding protection"),
        path=entry.path,
    )
    return (rule["title"], rule["severity"], rule["cwe"], evidence, None, None, rule.get("needs_ai_validation", False), None, rule.get("confirmed", True))


# ── rule dispatcher ────────────────────────────────────────────────────────

def _eval_rule(rule: Dict[str, Any], entry: "ProxyEntry") -> List[Finding]:
    match = rule.get("match", {})
    results: List[Finding] = []

    if match.get("cookie_flag_absent"):
        return _eval_cookies(rule, entry)

    if match.get("cors_check"):
        r = _eval_cors(rule, entry)
        if r:
            results.append(r)
        return results

    if match.get("csp_frame_ancestors_absent"):
        r = _eval_clickjacking(rule, entry)
        if r:
            results.append(r)
        return results

    if match.get("request_header_present"):
        r = _eval_cache_auth(rule, entry)
        if r:
            results.append(r)
        return results

    if match.get("header_absent"):
        r = _eval_header_absent(rule, entry)
        if r:
            results.append(r)

    if match.get("header_present"):
        r = _eval_header_present(rule, entry)
        if r:
            results.append(r)

    if match.get("header_value_regex") or match.get("header_name_any"):
        r = _eval_header_value_regex(rule, entry)
        if r:
            results.append(r)

    if match.get("body_regex"):
        r = _eval_body_regex(rule, entry)
        if r:
            results.append(r)

    if match.get("path_regex"):
        r = _eval_path_regex(rule, entry)
        if r:
            results.append(r)

    return results


# ── AI validation (same as before) ────────────────────────────────────────

_AI_VALIDATE_SYSTEM = """\
You are a security analyst reviewing a potential finding reported by a passive web scanner.
Determine if this is a REAL security issue or a false positive.
Respond ONLY with JSON: {"confirmed": true|false, "reasoning": "<one sentence>"}

Apply common sense to the type of finding:

Credentials / secrets (AWS keys, GitHub tokens, Stripe keys, API keys):
  confirmed=false: presigned S3 URL, placeholder values (EXAMPLE, YOUR_KEY, redacted), test/demo tokens in docs
  confirmed=true: bare real-looking credential outside of a signed URL or documentation context

Stack traces / error pages:
  confirmed=false: error is inside a JS bundle comment, minified code, or test fixture; not a real runtime exception
  confirmed=true: actual runtime exception with file paths, line numbers, or class names in an HTML/JSON response

Directory listing:
  confirmed=false: HTML content that just mentions "index" or "parent directory" in a different context
  confirmed=true: actual Apache/Nginx/IIS directory index page showing file listings

Open redirect:
  confirmed=false: hardcoded absolute URL in JS that never changes (e.g. a CDN URL, a known partner domain)
  confirmed=true: redirect URL that could be attacker-controlled or uses user-supplied input

Debug mode / debug toolbar:
  confirmed=false: pattern found inside a minified JS bundle or documentation comment
  confirmed=true: actual debug toolbar or debug output visible in the response body

JWT token exposure:
  confirmed=false: JWT is the user's own session token being legitimately returned to them (auth endpoint response, /me, /session)
  confirmed=true: JWT appearing in an unexpected endpoint response where it should not be present

System prompt leak (LLM):
  confirmed=false: common phrases that happen to match the pattern but are clearly not system instructions
  confirmed=true: response contains actual LLM system prompt instructions or configuration
"""

_AI_VALIDATE_LLM_INJECTION = """\
You are a security analyst reviewing a suspected LLM prompt injection finding.
The passive scanner found the marker DAST_LLM_PWNED_7x9z in the HTTP response body.

Your task: determine if the LLM actually EXECUTED the injected instruction (true positive)
or if the application merely ECHOED / STORED the user input and returned it verbatim (false positive).

Respond ONLY with JSON: {"confirmed": true|false, "reasoning": "<one sentence>"}

confirmed=false (false positive — echo / storage):
- The marker appears ONLY inside the same field that was sent as input (e.g. input.prompt, variables.prompt)
- The response just stores and returns the user-supplied string without any LLM processing visible
- The field containing the marker is clearly the input being reflected back, not generated output
- Example: {"data": {"generateCoverArt": {"node": {"url": "...", "prompt": "...DAST_LLM_PWNED_7x9z..."}}}}
  where "prompt" is the field the user sent — this is an echo, not injection

confirmed=true (real injection — LLM followed the injected instruction):
- The marker appears in a field that is clearly LLM-generated OUTPUT (e.g. text, response, message, completion, content, result, body, answer, translation)
- The marker appears OUTSIDE the input field, in a different part of the response
- The LLM visibly acted on the injected instruction rather than just passing the string through
"""

_PRESIGNED_URL_CTX = re.compile(
    r"(?:"
    # Standard presigned URL parameter names (literal hyphens)
    r"X-Amz-Credential"
    r"|X-Amz-Security-Token"
    r"|X-Amz-Algorithm=AWS4"
    r"|AWSAccessKeyId"
    r"|response-content-disposition"
    r"|\.s3\.amazonaws\.com"
    # URL-encoded hyphen variants (e.g. some double-encoded responses)
    r"|X%2DAmz%2DCredential"
    r"|X%2DAmz%2DSecurity%2DToken"
    # Presigned credential value format: KEYID immediately followed by %2F (date separator)
    # e.g. ASIAZNBXTZ5JFYWWQKW4%2F20260515%2Fus-east-1
    r"|(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}%2F"
    r")",
    re.IGNORECASE,
)


def _is_presigned_url_context(snippet: str) -> bool:
    """Return True if the snippet context suggests a presigned S3/AWS URL."""
    return bool(_PRESIGNED_URL_CTX.search(snippet))


_CORS_PROBE_ORIGIN = "https://evil.attacker.com"

# Rule IDs that benefit from an active confirmatory probe (crafted Origin header).
# Only rules where sending a specific Origin produces a meaningfully different response
# are included — static wildcard rules need no probe since the header is always present.
_RULES_WITH_PROBE = {
    "cors-reflected-origin-with-credentials",
    "cors-null-origin",
}


async def _active_cors_probe(entry: "ProxyEntry", rule_id: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Send a repeat of the intercepted request with a crafted Origin header to
    produce a definitive before/after proof.  Returns (probe_request_text, probe_response_text)
    or (None, None) on any error.
    """
    try:
        import httpx
    except ImportError:
        return None, None

    from urllib.parse import urlparse
    try:
        headers = dict(entry.request_headers or {})
        # Override origin with a clearly-attacker-controlled domain
        if rule_id == "cors-null-origin":
            headers["origin"] = "null"
        else:
            headers["origin"] = _CORS_PROBE_ORIGIN
        # Never forward proxy-internal headers
        for h in ("x-dast-crawler", "x-dast-payload", "proxy-connection"):
            headers.pop(h, None)

        body = entry.request_body or b""

        async with httpx.AsyncClient(verify=False, timeout=10.0, follow_redirects=True) as client:
            resp = await client.request(
                method=entry.method,
                url=entry.url,
                headers=headers,
                content=body,
            )

        # Format probe request text
        parsed = urlparse(entry.url)
        path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
        req_lines = [f"{entry.method} {path} HTTP/1.1", f"Host: {entry.host}"]
        for k, v in headers.items():
            if k.lower() != "host":
                req_lines.append(f"{k}: {v}")
        req_lines.append("")
        if body:
            req_lines.append(body.decode("utf-8", errors="replace"))
        probe_req_text = "\r\n".join(req_lines)

        # Format probe response text
        resp_lines = [f"HTTP/1.1 {resp.status_code}"]
        for k, v in resp.headers.items():
            resp_lines.append(f"{k}: {v}")
        resp_lines.append("")
        resp_lines.append(resp.text[:4000])
        probe_resp_text = "\r\n".join(resp_lines)

        return probe_req_text[:6000], probe_resp_text[:6000]
    except Exception:
        return None, None


def _format_raw_request(entry: "ProxyEntry") -> str:
    from dast.proxy.http_format import _format_raw_request as _fmt_req
    return _fmt_req(entry)


def _format_raw_response(entry: "ProxyEntry") -> str:
    from dast.proxy.http_format import _format_raw_response as _fmt_resp
    return _fmt_resp(entry)


async def _ai_validate_finding(title: str, snippet: str, raw_response_body: str = "") -> Tuple[Optional[bool], str]:
    """
    Returns (confirmed, reasoning). `confirmed` is:
      - True  — the LLM call succeeded and confirmed the finding
      - False — the LLM call succeeded and rejected the finding (or the fast-path
                presigned-URL suppression fired)
      - None  — the LLM call did not run/complete (AI unavailable, timeout, etc.)
                — callers MUST treat this as "AI validation did not happen" and
                fall back to passive-only, never as an implicit confirmation.
    """
    # Fast-path: suppress presigned URL false positives without an LLM call.
    if "AWS" in title and _is_presigned_url_context(snippet):
        return False, "Key appears inside a presigned S3 URL — not a leaked credential"

    # Do not attempt an LLM call when AI is known to be unavailable (expired/absent
    # credentials). Return None so the caller keeps the finding passive-only and
    # never stamps an "AI validated" badge on an unreviewed finding.
    from dast.ai import bedrock_client
    if not bedrock_client.is_ai_available():
        return None, ""

    # LLM injection findings use a dedicated prompt that understands echo vs execution
    is_llm_injection = "LLM Prompt Injection" in title or "llm_injection" in title.lower()
    if is_llm_injection:
        system_prompt = _AI_VALIDATE_LLM_INJECTION
        # Use the raw response body so the LLM can inspect the full JSON structure
        context = raw_response_body[:2000] if raw_response_body else snippet
        user = f"Finding: {title}\nFull response body (first 2000 chars):\n{context}"
    else:
        system_prompt = _AI_VALIDATE_SYSTEM
        user = f"Finding: {title}\nMatched context (secret redacted): {snippet}"

    try:
        import asyncio
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None,
            lambda: bedrock_client.invoke_json(system=system_prompt, user=user),
        )
        # Only claim AI validation when the model EXPLICITLY confirmed. A response
        # missing the key (degraded/empty output from a misconfigured provider)
        # must NOT default to confirmed — that stamps a false "AI validated" badge
        # on a finding the AI never actually reviewed.
        if "confirmed" not in result:
            return None, result.get("reasoning", "")
        return bool(result.get("confirmed")), result.get("reasoning", "")
    except Exception as exc:
        logger.warning("AI validation unavailable — keeping finding as passive-only", title=title, error=str(exc))
        return None, ""


# ── plugin ─────────────────────────────────────────────────────────────────

class PassiveScannerPlugin(ProxyPlugin):
    name        = "Passive Scanner"
    description = (
        "Automatically checks every response for misconfigurations and information "
        "disclosure using YAML-defined rules. No extra requests sent."
    )
    version     = "2.0.0"
    author      = "Frieren DAST-AI"

    def __init__(self) -> None:
        pass

    async def on_entry(self, entry: "ProxyEntry", store: "SessionStore") -> None:
        if entry.response_status is None or entry.method == "CONNECT":
            return

        # Use session-level fired_hosts so re-instantiation doesn't reset deduplication
        fired_hosts = store.passive_fired_hosts

        rules = _load_all_rules()
        # (rule_id, finding_tuple)
        all_findings: List[Tuple[str, Finding]] = []

        for rule in rules:
            try:
                if rule.get("aggressive", False) and not _AGGRESSIVE_RULES_ENABLED:
                    continue
                if not _conditions_match(rule, entry, fired_hosts):
                    continue
                found = _eval_rule(rule, entry)
                if found:
                    _record_host_fire(rule, entry, fired_hosts)
                    for f in found:
                        all_findings.append((rule.get("id", ""), f))
            except Exception:
                pass

        for rule_id, finding_tuple in all_findings:
            title, severity, cwe, evidence, line_no, snippet, needs_ai = finding_tuple[:7]
            redacted_snippet = finding_tuple[7] if len(finding_tuple) > 7 else snippet
            rule_confirmed = finding_tuple[8] if len(finding_tuple) > 8 else True

            # Presigned URL suppression: runs for ALL AWS findings regardless of needs_ai.
            # Must use the real snippet (not redacted) because X-Amz-Credential markers
            # are alphanumeric and get destroyed by redaction.
            if "AWS" in title and snippet and _is_presigned_url_context(snippet):
                continue

            validated_by = ["passive"]

            # AI validation is an AI feature — it must stay OFF unless the user has
            # explicitly enabled AI mode. In manual mode (the default) no AI config
            # runs at all: the finding is surfaced as plain "Passive", never routed
            # through an LLM and never stamped "AI validated".
            if needs_ai and not store.ai_mode:
                logger.debug(
                    "Passive AI validation skipped — manual mode (AI disabled)",
                    title=title, rule_id=rule_id,
                )

            if needs_ai and store.ai_mode:
                validate_snippet = redacted_snippet or snippet or evidence or ""
                if validate_snippet:
                    try:
                        raw_body = ""
                        if entry.response_body:
                            raw_body = entry.response_body.decode("utf-8", errors="replace")[:2000]
                        confirmed, _ = await _ai_validate_finding(title, validate_snippet, raw_response_body=raw_body)
                        if confirmed is False:
                            continue
                        if confirmed is True:
                            validated_by = ["passive", "ai"]
                        # confirmed is None — AI unavailable; keep validated_by=["passive"]
                        # and still surface the finding (fail-open on visibility,
                        # never fail-open on the "AI validated" claim).
                    except Exception:
                        pass

            finding_dict: Dict[str, Any] = {
                "title": title,
                "severity": severity,
                "cwe": cwe,
                "attack_type": "passive",
                "rule_id": rule_id,
                "evidence": evidence,
                "confirmed": rule_confirmed,
                "validated_by": validated_by,
            }
            # Record WHEN the AI confirmed this finding so the UI can distinguish a
            # historical AI verdict from current AI availability (the live "AI
            # offline" status is a separate, temporally decoupled signal).
            if "ai" in validated_by:
                finding_dict["validated_at"] = datetime.now(timezone.utc).isoformat()
            if line_no is not None:
                finding_dict["line_no"] = line_no
            if snippet:
                finding_dict["snippet"] = snippet

            # Attach the intercepted request/response so the UI can show the
            # full HTTP context in the evidence panel.
            raw_req = _format_raw_request(entry)
            raw_resp = _format_raw_response(entry)
            if raw_req:
                finding_dict["raw_request"] = raw_req[:6000]
            if raw_resp:
                finding_dict["raw_response"] = raw_resp[:6000]

            # For CORS and similar vuln types: fire an active confirmatory probe
            # so the issue card shows both the original intercepted pair and the
            # exploit proof pair (before/after with a crafted origin).
            if rule_id in _RULES_WITH_PROBE:
                try:
                    probe_req, probe_resp = await _active_cors_probe(entry, rule_id)
                    if probe_req:
                        finding_dict["probe_request"] = probe_req
                    if probe_resp:
                        finding_dict["probe_response"] = probe_resp
                except Exception as exc:
                    logger.warning("Active CORS probe failed", rule_id=rule_id, url=entry.url, error=str(exc))

            logger.debug("Passive finding recorded", rule_id=rule_id, title=finding_dict.get("title"),
                         severity=finding_dict.get("severity"), url=entry.url)
            store.add_finding(entry.id, finding_dict, "vulnerable")
