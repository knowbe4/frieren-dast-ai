"""
LLM Coordinator — scan orchestrator.

Flow:
  1. _plan(): LLM examines the endpoint and selects which agents to run
  2. Run selected agents in parallel (all implement VulnAgent.run())
  3. _validate(): LLM re-examines each finding; keeps only confirmed ones
     (agents with bypass_validation=True skip this step)

Agent registration is deferred: each agent module calls
Coordinator.register(AgentClass) at import time. The dast.agents package
triggers all imports via its __init__.py.
"""

from __future__ import annotations

import asyncio
import collections
import time
from typing import TYPE_CHECKING, Dict, List, Optional, Type

from dast.ai import bedrock_client
from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.ai.prompt_safety import UNTRUSTED_CONTENT_DIRECTIVE, wrap_untrusted
from dast.ai.schemas import BASELINE_SCHEMA, PLANNER_SCHEMA
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

logger = get_logger(__name__)

# ── Activity log ───────────────────────────────────────────────────────────
# Rolling buffer of the last 200 scan events — exposed via /api/ai/log.
# Each entry: {ts, method, url, agents_selected, plan_reason, outcomes}
# outcomes: [{agent, attack_type, finding_title, confirmed, reasoning}]
_activity_log: collections.deque = collections.deque(maxlen=200)

_SYSTEM_PLAN = """\
You are a senior web application penetration tester with 15 years of experience across bug bounties,
red team engagements, and deep OWASP research. You are the coordinator of an automated DAST scanner.

Your job is NOT to map URL patterns to vulnerability categories.
Your job is to READ AND UNDERSTAND what this specific endpoint does — what it accepts, what it
returns, what state it changes — and from that understanding, derive which tests are worth running.

STEP 1 — UNDERSTAND THE ENDPOINT
Before selecting any agents, reason about:
- What does this endpoint actually do? (create a resource? query a database? process a file?
  handle financial data? verify identity? call an external service?)
- What fields does the request send? What does the response return that the request did NOT send?
  (extra response fields = potential mass assignment targets)
- Does the response reveal anything surprising? (internal paths, stack traces, DB field names,
  user IDs from other users, prices, permissions, role names?)
- Is there auth context? (cookies, Authorization header → access control tests are relevant)
- What does the baseline response tell you about the backend? (errors, framework clues, field types)

STEP 2 — DERIVE SPECIFIC TESTS
Only AFTER understanding the endpoint, select agents whose tests make sense given what you found.
Never select an agent because the URL "looks like" a certain type. Select it because the observed
request/response gives concrete evidence it might be vulnerable to that specific attack.

Selection rules:
- INJECTION (sqli, xss, lfi, ssrf, cmdi, ssti, xxe, nosql):
  Select only when canary probes showed signal OR the response reveals evidence of the relevant
  backend (DB errors → sqli, file paths → lfi, template rendering → ssti, XML/SOAP → xxe).
  Never select injection types just because the param name sounds injectable.

- BUSINESS LOGIC (business_logic):
  Select when: the response returns fields the request did NOT send (mass assignment candidates),
  the endpoint handles prices/quantities/discounts/quotas/roles/permissions/status transitions,
  or the response shows the server is computing and storing a derived value the client shouldn't
  control. SKIP for pure GET reads and search/filter endpoints.

- ACCESS CONTROL (idor, auth_bypass):
  idor: select when URL or body contains numeric IDs or UUIDs that could reference other users.
  auth_bypass: select when auth headers are present and the endpoint looks like it checks them.
  Both: skip if the endpoint clearly doesn't gate access on identity.

- mfa_bypass: ONLY for MFA/OTP verification endpoints. Never for generic auth or other endpoints.

- CSRF: select for state-changing endpoints where the response shows NO CSRF token rotation.

- SECRETS: always run — passive, reads response only, zero noise.

Respond ONLY with JSON: {"agents": ["<agent_attack_type>", ...], "reason": "<one concrete sentence explaining what the endpoint does and why these agents follow from that understanding>"}

The reason must describe the endpoint's behaviour, not a URL pattern. Bad: "POST endpoint with id param". Good: "Checkout endpoint that accepts a price field and returns order total — price manipulation and quantity overflow are the primary risks."
"""

_SYSTEM_BASELINE = """\
You are an expert web application penetration tester.
You sent a baseline request to an endpoint and received a response.
Analyse the response and decide what should happen next.

Respond ONLY with JSON:
{
  "status": "<ok|abort|adapt>",
  "reason": "<one sentence>",
  "structural_error": "<exact error message if the request body/schema is wrong, else empty>",
  "auth_issue": <true if the response indicates auth failure (401/403/session expired), else false>,
  "endpoint_hint": "<if the error reveals the correct endpoint path or operation name, put it here, else empty>"
}

status meanings:
- "ok":     Baseline succeeded (2xx or expected app response). Proceed with agents.
- "abort":  The request is fundamentally broken (wrong schema, unknown field/type, endpoint
            doesn't exist). No amount of payload mutation will fix this. Stop immediately.
- "adapt":  The request has a fixable problem (auth failure, minor field mismatch). Agents
            may still find something, or the coordinator should try to repair the request.

Be conservative with "abort" — only use it when the error is clearly structural and not
something an agent payload could trigger (e.g. SQL error on a benign value is "ok").

Examples:

Response: 200 with a normal JSON object matching the endpoint's purpose.
{"status": "ok", "reason": "Endpoint returned the expected resource.", "structural_error": "", "auth_issue": false, "endpoint_hint": ""}

Response: 400 `{"errors":[{"message":"Unknown field 'foo' on type 'Query'. Did you mean 'food'?"}]}`.
{"status": "abort", "reason": "Request targets a field that does not exist in the schema.", "structural_error": "Unknown field 'foo' on type 'Query'", "auth_issue": false, "endpoint_hint": "food"}

Response: 401 `{"message":"session expired"}`.
{"status": "adapt", "reason": "Auth failure — session must be refreshed before agents run.", "structural_error": "", "auth_issue": true, "endpoint_hint": ""}
"""

# Both system prompts embed target-controlled content in their user message, so
# append the structural untrusted-content directive to each.
_SYSTEM_PLAN += UNTRUSTED_CONTENT_DIRECTIVE
_SYSTEM_BASELINE += UNTRUSTED_CONTENT_DIRECTIVE


def _extract_operation(target: "CheckTarget") -> str:
    """Extract a human-readable operation label from a CheckTarget.

    For GraphQL: returns operationName or the first word of the query string.
    For REST: returns the path tail (last non-empty segment).
    """
    if target.body:
        try:
            import json as _json
            data = _json.loads(target.body)
            if isinstance(data, dict) and "query" in data:
                op = data.get("operationName")
                if op:
                    return str(op)
                # Extract first identifier from the query string
                import re as _re
                m = _re.search(r'\b(query|mutation|subscription)\s+(\w+)', data["query"])
                if m:
                    return f"{m.group(1)} {m.group(2)}"
                m2 = _re.search(r'(?:query|mutation)\s*\{?\s*(\w+)', data["query"])
                if m2:
                    return m2.group(1)
        except Exception:
            pass

    from urllib.parse import urlparse as _urlparse
    parts = [p for p in _urlparse(target.url).path.split("/") if p]
    return parts[-1] if parts else ""


import re as _re


# Parameter names that are auth/OIDC tokens — injecting into these is pointless
# because the server validates them cryptographically, not via SQL/LFI/etc.
_AUTH_TOKEN_PARAMS = frozenset({
    "nonce", "state", "code", "id_token", "access_token", "refresh_token",
    "token", "assertion", "client_assertion", "jwt", "saml_response",
    "relay_state", "relaystate", "resume", "session_token", "session_id",
    "auth_token", "api_token", "api_key", "apikey",
})

# Path segments that identify auth/SSO/OIDC endpoints — scanning these produces
# only noise: 302 redirects, 400 bad requests, and no exploitable surface.
# Pure SSO/OIDC/relay paths — no exploitable application logic; scanning produces
# only 302/400 noise.  MFA verification endpoints are intentionally excluded from
# this list so the mfa_agent can test them for rate-limit, reuse and bypass flaws.
_AUTH_PATH_RE = _re.compile(
    r"/(signin|sign-in|sign_in|login|logon|logout|sign-out|sign_out"
    r"|oauth|oauth2|oidc|authorize|authorise|callback|token"
    r"|saml|sso|idp|identity"
    r"|u/login|u/authorize|u/authorise"
    r"|api/signin|api/login|api/idp|api/sso|api/session|api/token"
    r"|auth/relay|auth/callback|auth/token|auth/signin"
    r"|session/new|users/sign_in|users/sign_out"
    r"|account/login|account/signin"
    r"|connect/token|connect/authorize"
    r")(/|$)",
    _re.I,
)

# MFA/2FA verification endpoints — exploitable for rate-limit bypass, OTP reuse,
# backup code enumeration, etc.  Routed to the mfa_agent, not skipped entirely.
_MFA_PATH_RE = _re.compile(
    r"/(mfa|mfa-challenge|mfa_challenge|mfa-verify|mfa_verify"
    r"|two-factor|two_factor|2fa|totp|otp"
    r"|verify-code|verify_code|confirm-code|confirm_code"
    r"|u/mfa|u/otp"
    r")(/|$)",
    _re.I,
)


_REDIRECT_PARAM_NAMES = frozenset({
    "returnurl", "return_url", "redirecturl", "redirect_url", "next", "goto",
    "dest", "destination", "continue", "redirect", "redir", "forward", "target",
    "url", "to", "ref", "callback", "back", "from", "out",
})


def _is_auth_host(hostname: str) -> bool:
    """Return True when the hostname itself denotes an SSO/login/identity service.

    A dedicated auth host serves login relays on paths as bare as ``/`` — path-only
    detection (``_AUTH_PATH_RE``) misses those, so an agent would fire redirect/
    header payloads at a login host. This matches the common naming subdomains and
    labels used for identity providers.
    """
    host = (hostname or "").lower()
    if not host:
        return False
    labels = host.split(".")
    _AUTH_LABELS = {
        "login", "logon", "signin", "auth", "sso", "idp", "oauth", "oauth2",
        "oidc", "identity", "accounts", "account", "hrd", "adfs", "openid",
    }
    # Any DNS label that is exactly an auth marker (e.g. login.example.com,
    # hrd.test.example.com → the 'hrd' label).
    if any(label in _AUTH_LABELS for label in labels):
        return True
    # Or a label that starts with an auth marker followed by a separator
    # (login-web, auth-gateway, sso2, ...).
    for label in labels:
        for marker in ("login", "signin", "auth", "sso", "identity", "accounts"):
            if label.startswith(marker) and label != marker and not label[len(marker)].isalpha():
                return True
    return False


def _is_auth_endpoint(url: str) -> bool:
    """Return True when the URL is a pure SSO/OIDC relay with no exploitable logic.

    Detected either by the hostname being a dedicated auth/identity service
    (catches bare ``/`` on a login host) or by the path matching a known auth
    route. Exception: if the URL carries a redirect/return param that points to an
    absolute URL or protocol-relative URL, allow through for open_redirect testing.
    """
    from urllib.parse import urlparse as _up, parse_qs as _qs
    parsed = _up(url)
    is_auth = _is_auth_host(parsed.hostname or "") or bool(_AUTH_PATH_RE.search(parsed.path))
    if not is_auth:
        return False
    # Check if any query param looks like an open-redirect target
    for name, values in _qs(parsed.query).items():
        if name.lower() in _REDIRECT_PARAM_NAMES:
            for v in values:
                # Absolute URL or protocol-relative — worth testing for redirect
                if v.startswith(("http://", "https://", "//", "/\\")):
                    return False
    return True


def _is_mfa_endpoint(url: str) -> bool:
    """Return True when the URL path is an MFA/OTP verification endpoint."""
    from urllib.parse import urlparse as _up
    path = _up(url).path
    return bool(_MFA_PATH_RE.search(path))


def _params_are_all_auth_tokens(target: "CheckTarget") -> bool:
    """Return True if every injectable param looks like an auth/OIDC token."""
    params = target.params or []
    if not params:
        return False
    return all(p.get("name", "").lower() in _AUTH_TOKEN_PARAMS for p in params)


# ── Parameter value classification ─────────────────────────────────────────

_NUMERIC_RE = _re.compile(r'^\d+$')
_UUID_RE = _re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', _re.I)
_PATH_VALUE_RE = _re.compile(r'[./\\]')
_LONG_TOKEN_RE = _re.compile(r'^[A-Za-z0-9\-_]{32,}$')
# JWT: three base64url segments separated by dots
_JWT_RE = _re.compile(r'^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*$')


def _classify_param(name: str, value: str) -> str:
    """
    Classify a parameter by its name and value into a semantic type.

    Returns one of: "numeric_id", "uuid", "path", "search", "token", "boolean",
                    "json", "empty", "string"
    """
    name_l = name.lower()
    val = (value or "").strip()

    if not val:
        return "empty"
    if val in ("true", "false", "1", "0"):
        return "boolean"
    if _NUMERIC_RE.match(val):
        return "numeric_id"
    if _UUID_RE.match(val):
        return "uuid"
    # JWT / long opaque tokens before path — they contain dots/dashes but aren't file paths
    if _JWT_RE.match(val) or _LONG_TOKEN_RE.match(val):
        return "token"
    if _PATH_VALUE_RE.search(val) and len(val) > 3:
        return "path"
    if val.startswith("{") or val.startswith("["):
        return "json"
    # Name-based hints
    if name_l in _AUTH_TOKEN_PARAMS or any(kw in name_l for kw in ("token", "secret", "nonce", "hmac", "signature", "sig", "hash")):
        return "token"
    if any(kw in name_l for kw in ("search", "query", "q", "filter", "keyword", "term", "text", "name")):
        return "search"
    if any(kw in name_l for kw in ("file", "path", "dir", "folder", "include", "load", "template")):
        return "path"
    if any(kw in name_l for kw in ("id", "uid", "user_id", "item_id", "record", "pk", "fk")):
        return "numeric_id"
    return "string"


# Attack types that produce deterministic signals — no LLM needed to confirm
_CONTEXTUAL_TYPES = frozenset({
    "xss", "auth_bypass", "llm_injection", "discovery", "nosql",
    "business_logic", "csrf", "idor", "cross_session_idor", "graphql_idor",
    "blazor", "sensitive_data",
})

# Which attack types are relevant for each param classification.
# Only listed types will be attempted on a param of that class.
_PARAM_ATTACK_MAP: Dict[str, List[str]] = {
    "numeric_id": ["sqli", "idor", "business_logic"],
    "uuid":       ["idor", "business_logic"],
    "path":       ["lfi", "ssrf", "cmdi"],
    "search":     ["sqli", "xss", "ssrf", "lfi"],
    "string":     ["sqli", "xss", "ssrf", "lfi", "ssti", "cmdi"],
    "json":       ["sqli", "nosql", "business_logic"],
    "token":      [],   # cryptographic token — skip injection
    "boolean":    [],   # boolean fields have no injection surface
    "empty":      ["sqli", "xss"],  # try basic canaries on empty params
}

# Canary payloads for the pre-probe pass — 1 fast payload per attack type.
# These are purely to detect signal (error, reflection, delay) — not full exploitation.
_CANARY_PAYLOADS: Dict[str, str] = {
    "sqli":   "'",
    "xss":    "<dast>",
    "lfi":    "../etc/passwd",
    "ssrf":   "http://169.254.169.254/",
    "nosql":  '{"$gt":""}',
    "ssti":   "{{8887*8893}}",
    "cmdi":   ";id",
    "xxe":    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe "dast">]><x>&xxe;</x>',
}

# Patterns that indicate signal for each attack type in the canary response
_SIGNAL_PATTERNS: Dict[str, _re.Pattern] = {
    "sqli": _re.compile(
        r"sql|syntax error|mysql|ora-|sqlite|pg::|unclosed quotation|"
        r"you have an error in your sql|warning: mysql|"
        r"microsoft ole db provider for sql|odbc sql",
        _re.I,
    ),
    "xss":  _re.compile(r"<dast>", _re.I),
    "lfi":  _re.compile(r"root:.*:0:0:|bin/bash|etc/passwd|\[boot loader\]|windows/system32", _re.I),
    "ssrf": _re.compile(r"169\.254\.169\.254|ec2\.internal|metadata\.google\.internal", _re.I),
    "cmdi": _re.compile(r"uid=\d+|gid=\d+|root:|command not found", _re.I),
    "xxe":  _re.compile(r"xml.*parsing|entity.*not.*allowed|dtd.*not.*allowed|unexpected.*<!DOCTYPE", _re.I),
    "nosql":_re.compile(r"\$where|operator.*not.*allowed|cast.*failed|bson.*error", _re.I),
    "ssti": _re.compile(r"\b79014691\b|\b84232313\b", _re.I),
}


async def _run_canary_probe(
    client: "httpx.AsyncClient",
    target: "CheckTarget",
    param: dict,
    attack_type: str,
) -> bool:
    """
    Send a single canary payload for attack_type into param.
    Returns True if the response contains a signal indicating potential vulnerability.
    Time-based types (sqli blind) return False here — the full agent handles timing.
    """
    from dast.scanners.active_checks import _inject_body, _inject_query, _send
    payload = _CANARY_PAYLOADS.get(attack_type)
    if not payload:
        return False

    try:
        loc = param.get("location", "query")
        if loc == "query":
            url = _inject_query(target.url, param["name"], payload)
            resp = await _send(client, target.method, url, target.headers, target.body)
        elif loc in ("body", "body_graphql"):
            body = _inject_body(
                target.body or "", param["name"], payload,
                target.headers.get("content-type", ""),
                location=loc,
            )
            resp = await _send(client, target.method, target.url, target.headers, body)
        else:
            return False

        if resp is None:
            return False

        pattern = _signal_PATTERNS_for(attack_type)
        if pattern and pattern.search(resp.text):
            return True

        # For XSS: reflection of payload is signal
        if attack_type == "xss" and payload in resp.text:
            return True

        return False
    except Exception:
        return False


def _signal_PATTERNS_for(attack_type: str) -> Optional[_re.Pattern]:
    return _SIGNAL_PATTERNS.get(attack_type)


def _select_attack_types_for_params(
    target: "CheckTarget",
    host_intel: Optional[object],
) -> List[str]:
    """
    Deterministically select which attack types to attempt based on parameter
    classifications. Never calls the LLM. Returns a deduplicated ordered list.

    Rules:
    1. Skip params that are auth tokens or have class "token"/"boolean"
    2. Map each param to a set of candidate attack types from _PARAM_ATTACK_MAP
    3. Apply host intelligence: skip types consistently ineffective, boost effective
    4. For GraphQL: always include sqli + nosql; add business_logic for mutations
    5. For state-changing methods (POST/PUT/PATCH/DELETE): add csrf + business_logic
    """
    effective = getattr(host_intel, "effective_attack_types", set()) if host_intel else set()
    ineffective = getattr(host_intel, "ineffective_attack_types", set()) if host_intel else set()
    waf_obs = getattr(host_intel, "waf_observations", []) if host_intel else []

    waf_blocks: Dict[str, int] = {}
    for _, _, at in waf_obs:
        waf_blocks[at] = waf_blocks.get(at, 0) + 1

    candidate_types: set = set()

    is_graphql = "graphql" in target.url.lower()
    if is_graphql:
        candidate_types.update(["sqli", "nosql"])

    for param in (target.params or []):
        pname = param.get("name", "")
        pval = param.get("value", "")
        if pname.lower() in _AUTH_TOKEN_PARAMS:
            continue
        ptype = _classify_param(pname, pval)
        for at in _PARAM_ATTACK_MAP.get(ptype, []):
            candidate_types.add(at)

    # State-changing methods are candidates for csrf and business_logic, but
    # the LLM planner decides whether they're worth running based on the actual
    # response — e.g. business_logic only makes sense if the response shows
    # the server computes/returns extra fields the client didn't send.
    # We add them as candidates here; the planner filters from the baseline response.
    if target.method in ("POST", "PUT", "PATCH", "DELETE"):
        candidate_types.update(["business_logic", "csrf"])

    # GET endpoints are candidates for cache poisoning — an unkeyed request
    # header reflected into a cacheable response. Header-based, no param canary;
    # the agent itself bails fast if the response is not cacheable.
    if target.method == "GET":
        candidate_types.add("cache_poisoning")

    # MFA/OTP verification endpoints — dedicated agent for rate-limit and bypass tests
    if _is_mfa_endpoint(target.url):
        candidate_types.add("mfa_bypass")

    # Always include secrets scanning — passive, low noise
    candidate_types.add("sensitive_data")

    # Auth bypass for any authenticated endpoint
    auth_headers = {k.lower() for k in (target.headers or {})}
    if "authorization" in auth_headers or "cookie" in auth_headers:
        candidate_types.add("auth_bypass")

    # Filter by host intelligence
    result = []
    for at in candidate_types:
        if at in ineffective and at not in effective:
            continue  # consistently failed, no new signal — skip
        if waf_blocks.get(at, 0) >= 5 and at not in effective:
            continue  # WAF blocks everything for this type
        result.append(at)

    # Sort: deterministic types first (faster, no LLM needed), contextual last
    result.sort(key=lambda t: (t in _CONTEXTUAL_TYPES, t))
    return result


class Coordinator:
    _registry: Dict[str, Type[VulnAgent]] = {}

    @classmethod
    def register(cls, agent_class: Type[VulnAgent]) -> None:
        cls._registry[agent_class.attack_type] = agent_class
        logger.debug("Agent registered", attack_type=agent_class.attack_type, name=agent_class.name)

    @classmethod
    def registered_types(cls) -> List[str]:
        return list(cls._registry.keys())

    # Ceiling used only when budget_seconds is not passed in.
    # The actual per-scan budget is computed adaptively by _adaptive_budget().
    SCAN_BUDGET_SECONDS: float = 300.0

    @classmethod
    def _adaptive_budget(
        cls,
        target: "CheckTarget",
        host_intel: Optional[object],
    ) -> float:
        """
        Compute a context-aware scan budget in seconds.

        Rules (applied in order, most restrictive wins):
        - Host has many confirmed vulns already → 60s (we know it's vulnerable, find fast)
        - Attack types all previously ineffective on this host → 45s (low confidence)
        - Many params (>10) with no prior findings → 60s per 5-param block, cap 180s
        - Normal endpoint (≤10 params) → 90s base
        - Simple GET with ≤3 params and no prior findings → 45s
        - Endpoint has confirmed prior finding → 180s (rich target, explore fully)
        """
        num_params = len(target.params or [])
        effective = getattr(host_intel, "effective_attack_types", set()) if host_intel else set()
        ineffective = getattr(host_intel, "ineffective_attack_types", set()) if host_intel else set()
        confirmed_vulns = getattr(host_intel, "confirmed_vulns", {}) if host_intel else {}

        # Rich target — AI has already confirmed something here
        if effective:
            return 180.0

        # Host has confirmed vulns on this path — scan deeply
        if confirmed_vulns:
            return 180.0

        # All known attack types are ineffective — don't spend much time
        all_types_ineffective = ineffective and not effective
        if all_types_ineffective:
            return 45.0

        # Scale with param count, capped
        if num_params > 10:
            return min(60.0 * ((num_params // 5) + 1), 180.0)

        # Simple GET with few params and no prior intel → quick pass
        if target.method == "GET" and num_params <= 3 and not effective:
            return 45.0

        return 90.0

    @classmethod
    async def run(
        cls,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
        use_llm_planner: bool = True,
        model_id: Optional[str] = None,
        confidence_threshold: float = 0.5,
        session_intelligence: Optional[object] = None,
        budget_seconds: Optional[float] = None,
        probe_diff: bool = False,
    ) -> List[AgentFinding]:
        if not cls._registry:
            return []

        # Compute adaptive budget unless caller explicitly set one
        if budget_seconds is None:
            from urllib.parse import urlparse as _up0
            _h0 = _up0(target.url).netloc
            _host_intel0 = None
            if session_intelligence is not None:
                try:
                    _host_intel0 = session_intelligence.get(_h0)
                except Exception:
                    pass
            effective_budget = min(
                cls._adaptive_budget(target, _host_intel0),
                cls.SCAN_BUDGET_SECONDS,
            )
        else:
            effective_budget = budget_seconds

        try:
            return await asyncio.wait_for(
                cls._run_inner(
                    target, client, collaborator, use_llm_planner,
                    model_id, confidence_threshold, session_intelligence,
                    probe_diff,
                ),
                timeout=effective_budget,
            )
        except asyncio.TimeoutError:
            from dast.proxy.plugin_manager import log_event as _le
            _le(
                "coordinator", "warn",
                f"Scan budget exceeded ({effective_budget:.0f}s) — partial results discarded",
                url=target.url, source="agent",
            )
            logger.warning("Coordinator scan timed out", url=target.url, budget_s=effective_budget)
            return []

    @classmethod
    async def _run_inner(
        cls,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
        use_llm_planner: bool = True,
        model_id: Optional[str] = None,
        confidence_threshold: float = 0.5,
        session_intelligence: Optional[object] = None,
        probe_diff: bool = False,
    ) -> List[AgentFinding]:
        from urllib.parse import urlparse as _urlparse
        _parsed_url = _urlparse(target.url)
        _host = _parsed_url.netloc
        _path = _parsed_url.path

        # Extract operation label for per-operation intelligence scoping
        _operation = _extract_operation(target)

        # Read session intelligence for this host — gives the planner context
        # about what has already been found/blocked/failed in this session.
        host_intel = None
        intel_hint = ""
        if session_intelligence is not None:
            try:
                host_intel = session_intelligence.get(_host)
                intel_hint = host_intel.to_planner_hint(_path, target.params)
            except Exception:
                pass

        # Early abort: auth/SSO/OIDC endpoint — path-based detection.
        # These endpoints process cryptographic tokens (SAML assertions, OIDC codes,
        # session cookies) that are validated before any business logic runs.
        # Injecting SQL/LFI/XSS payloads into them produces only 302/400 noise.
        if _is_auth_endpoint(target.url):
            _log_reason = "Skipping scan — auth/SSO endpoint detected by path"
            from dast.proxy.plugin_manager import log_event as _le_auth
            _le_auth("coordinator", "info", _log_reason, url=target.url, source="agent")
            logger.debug("Coordinator early abort: auth endpoint by path", url=target.url)
            _activity_log.appendleft({
                "ts": time.time(),
                "method": target.method,
                "url": target.url,
                "params": [p["name"] for p in target.params[:10]],
                "operation": _operation,
                "agents_selected": [],
                "plan_reason": _log_reason,
                "outcomes": [],
            })
            return []

        # Early abort: if every injectable parameter is an auth/OIDC token
        # (nonce, code, state, id_token, etc.) there is nothing useful to probe.
        # These values are validated cryptographically — SQL/LFI/XSS injection
        # into them will always be rejected before any business logic runs.
        if _params_are_all_auth_tokens(target):
            _log_reason = f"Skipping scan — all parameters are auth/OIDC tokens ({', '.join(p['name'] for p in target.params[:5])})"
            from dast.proxy.plugin_manager import log_event as _le0
            _le0("coordinator", "info", _log_reason, url=target.url, source="agent")
            logger.debug("Coordinator early abort: auth-token params only", url=target.url)
            _activity_log.appendleft({
                "ts": time.time(),
                "method": target.method,
                "url": target.url,
                "params": [p["name"] for p in target.params[:10]],
                "operation": _operation,
                "agents_selected": [],
                "plan_reason": _log_reason,
                "outcomes": [],
            })
            return []

        # ── Pre-probe canary pass ─────────────────────────────────────────────
        # Deterministically select candidate attack types from param values.
        # Then send one cheap canary payload per (attack_type, param) pair.
        # The LLM planner sees which types got a signal and selects full agents
        # ONLY for those — so no agent runs on an endpoint unless there is
        # evidence it may be injectable.
        plan_reason = ""

        # Deterministic candidate selection — never calls LLM
        candidate_types = _select_attack_types_for_params(target, host_intel)

        # Run canary probes in parallel for all (attack_type, param) combos
        # that have a canary payload defined.  Collect signal map.
        signal_map: Dict[str, List[str]] = {}   # attack_type → param names with signal
        if candidate_types and (target.params or []):
            canary_combos = [
                (param, at)
                for at in candidate_types
                if at in _CANARY_PAYLOADS
                for param in (target.params or [])
                if param.get("name", "").lower() not in _AUTH_TOKEN_PARAMS
            ]
            if canary_combos:
                canary_tasks = [
                    _run_canary_probe(client, target, param, at)
                    for param, at in canary_combos
                ]
                canary_results = await asyncio.gather(*canary_tasks, return_exceptions=True)
                for (param, at), hit in zip(canary_combos, canary_results):
                    if hit is True:
                        signal_map.setdefault(at, []).append(param.get("name", ""))

        # Always include non-injectable types (no canary) — they're always worth running
        # if the param classification says they're relevant.
        no_canary_types = [t for t in candidate_types if t not in _CANARY_PAYLOADS]

        # Build signal summary for the LLM planner prompt
        signal_lines: List[str] = []
        for at in sorted(signal_map):
            params_hit = ", ".join(signal_map[at])
            signal_lines.append(f"  {at}: SIGNAL on param(s) [{params_hit}]")
        for at in candidate_types:
            if at not in signal_map and at in _CANARY_PAYLOADS:
                signal_lines.append(f"  {at}: no signal")
        for at in no_canary_types:
            signal_lines.append(f"  {at}: (no canary — always run if relevant)")
        canary_summary = "\n".join(signal_lines) if signal_lines else "(no canary probes sent)"

        # ── Probe-diff pass (opt-in) ──────────────────────────────────────────
        # Deeper than the single-payload canary: send break/repair PAIRS per
        # param and diff the responses, then let the LLM read the transformation
        # signature to name the injection class + context. Feeds the planner a
        # high-prior targeting hint. Degrades to a no-op on any failure.
        if probe_diff and (target.params or []):
            probe_summary = await cls._run_probe_diff_pass(
                target, client, model_id, signal_map
            )
            if probe_summary:
                canary_summary += "\n\nProbe-diff transformation analysis:\n" + probe_summary

        if signal_map:
            _log_signal = ", ".join(f"{at}:{','.join(params)}" for at, params in signal_map.items())
            from dast.proxy.plugin_manager import log_event as _le_canary
            _le_canary(
                "coordinator", "info",
                f"Canary signals: {_log_signal} — escalating to full agents",
                url=target.url, source="agent",
            )

        from dast.proxy.plugin_manager import log_event as _log_event

        # Baseline check: send the original request BEFORE planning.
        # This serves two purposes:
        # 1. Abort early if the endpoint is structurally broken (wrong schema, 404, etc.)
        # 2. Feed the real response to the LLM planner so it reasons about
        #    what the endpoint actually does, not just what its URL suggests.
        # Short-circuit: if session intel already recorded a structural error for
        # this exact path, skip the network round-trip entirely.
        if host_intel is not None:
            prev_error = host_intel.has_structural_error_for(_path, _operation)
            if prev_error:
                _log_event(
                    "coordinator", "warn",
                    f"Skipping scan — structural error already known for [{_operation or _path}]: {prev_error}",
                    url=target.url, source="agent",
                )
                return []

        baseline_response_summary = ""
        _run_baseline = (
            target.method in ("GET", "POST", "PUT", "PATCH", "DELETE")
            and (bool(target.body) or bool(target.params))
        )
        if _run_baseline:
            from dast.ai.bedrock_client import get_fast_model as _get_fast
            baseline_abort, baseline_response_summary = await cls._baseline_check(
                target, client, model_id=model_id or _get_fast()
            )
            if baseline_abort:
                # Record structural error in session intelligence so future scans
                # on the same path don't repeat the same mistake
                if host_intel is not None and session_intelligence is not None:
                    try:
                        session_intelligence.record_scan_complete(
                            host=_host, path=_path,
                            attack_type="all", found=False,
                            operation=_operation,
                            structural_error=baseline_abort,
                        )
                    except Exception:
                        pass
                _log_event(
                    "coordinator", "warn",
                    f"Baseline check failed — aborting scan: {baseline_abort}",
                    url=target.url, source="agent",
                )
                logger.warning(
                    "Coordinator aborting: baseline structural error",
                    url=target.url, reason=baseline_abort,
                )
                _activity_log.appendleft({
                    "ts": time.time(),
                    "method": target.method,
                    "url": target.url,
                    "params": [p["name"] for p in target.params[:10]],
                    "operation": _operation,
                    "agents_selected": [],
                    "plan_reason": f"Aborted: {baseline_abort}",
                    "outcomes": [],
                })
                return []

        # ── LLM planner: select which agents to run ───────────────────────
        # The planner now receives the baseline response so it can reason about
        # what the endpoint actually does, not just its URL structure.
        mine_params = False
        if use_llm_planner:
            from dast.ai.bedrock_client import get_fast_model
            plan_model = model_id or get_fast_model()
            selected_types, plan_reason, mine_params = await cls._plan(
                target, model_id=plan_model, session_intel_hint=intel_hint,
                canary_summary=canary_summary, signal_attack_types=list(signal_map.keys()),
                candidate_types=candidate_types,
                baseline_response=baseline_response_summary,
            )
        else:
            selected_types = list({*signal_map.keys(), *no_canary_types})
            plan_reason = "No-LLM mode: canary signals + non-injectable types"

        # ── Automatic hidden-parameter mining (planner-decided) ───────────────
        # When the planner judges this endpoint likely to accept undocumented
        # parameters, mine them now. Discovered names become recon suggestions
        # (fresh attack surface) — no vuln is inferred from a name alone.
        # Deterministic, scope-gated, inert canary probes; degrades to a no-op.
        if mine_params:
            try:
                await cls._run_param_mining_pass(target, client)
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("Param-mining pass failed", url=target.url, error=str(exc))

        agents = [
            cls._registry[t]()
            for t in selected_types
            if t in cls._registry
        ]

        if not agents:
            _activity_log.appendleft({
                "ts": time.time(),
                "method": target.method,
                "url": target.url,
                "params": [p["name"] for p in target.params[:10]],
                "operation": _extract_operation(target),
                "agents_selected": [],
                "plan_reason": plan_reason or "No matching agents for this endpoint",
                "outcomes": [],
            })
            _log_event(
                "coordinator", "info",
                f"No agents selected — {plan_reason or 'no matching agents'}",
                url=target.url, source="agent",
            )
            return []

        agent_names = ", ".join(a.name for a in agents)
        canary_hit_count = sum(len(v) for v in signal_map.values()) if signal_map else 0
        mode_label = f"canary+AI ({canary_hit_count} signal(s))" if signal_map else "AI"
        _log_event(
            "coordinator", "info",
            f"[{mode_label}] Running {len(agents)} agent(s): {agent_names}",
            url=target.url, source="agent",
        )
        if plan_reason:
            _log_event(
                "coordinator", "info",
                f"Planner: {plan_reason}",
                url=target.url, source="agent",
            )
        logger.debug(
            "Coordinator running agents",
            url=target.url,
            agents=[a.name for a in agents],
        )

        # Attach host_intel so agents can read it without coordinator coupling
        if host_intel is not None:
            target.host_intel = host_intel

        # Run all selected agents in parallel
        tasks = [agent.run_safe(target, client, collaborator) for agent in agents]
        results = await asyncio.gather(*tasks)

        raw_findings: List[AgentFinding] = []
        agent_raw: Dict[str, List[AgentFinding]] = {}  # attack_type → findings
        for agent, result in zip(agents, results):
            findings = result if isinstance(result, list) else []
            agent_raw[agent.attack_type] = findings
            raw_findings.extend(findings)

        # Validate findings
        confirmed: List[AgentFinding] = []
        deterministic: List[AgentFinding] = []
        non_deterministic: List[AgentFinding] = []

        for finding in raw_findings:
            if finding.bypass_validation:
                deterministic.append(finding)
            else:
                non_deterministic.append(finding)

        # Validate all findings via Red Team.
        # Deterministic findings (time-based SQLi, LFI match, secrets) bypass LLM validation.
        # All others go through the 3-stage Red-Team Validator.
        validate_tasks = [
            cls._validate(f, target, model_id=model_id, confidence_threshold=confidence_threshold)
            for f in non_deterministic
        ]
        validation_results = await asyncio.gather(*validate_tasks, return_exceptions=True)
        for finding, result in zip(non_deterministic, validation_results):
            if isinstance(result, BaseException):
                logger.warning("Validation error — finding NOT confirmed",
                               title=finding.title, error=str(result))
                continue
            if result:
                confirmed.append(finding)
        confirmed.extend(deterministic)

        # Write back scan results to session intelligence
        if host_intel is not None and session_intelligence is not None:
            try:
                confirmed_set = {c.title for c in confirmed}
                for agent in agents:
                    agent_findings = agent_raw.get(agent.attack_type, [])
                    confirmed_by_agent = [f for f in agent_findings if f.title in confirmed_set]
                    found = bool(confirmed_by_agent)
                    for cf in confirmed_by_agent:
                        session_intelligence.record_scan_complete(
                            host=_host, path=_path,
                            attack_type=agent.attack_type,
                            found=True,
                            operation=_operation,
                            confirmed_param=cf.parameter,
                            auth_headers=target.headers,
                        )
                    if not found:
                        session_intelligence.record_scan_complete(
                            host=_host, path=_path,
                            attack_type=agent.attack_type,
                            found=False,
                            operation=_operation,
                            auth_headers=target.headers,
                        )

                    # Collect observations the agent recorded during its run
                    for obs in getattr(agent, "observations", []):
                        if obs.kind == "waf_block" and obs.payload:
                            session_intelligence.record_scan_complete(
                                host=_host, path=_path,
                                attack_type=obs.attack_type,
                                found=False,
                                operation=_operation,
                                waf_signal=(obs.payload, obs.signal),
                            )
                        elif obs.kind == "waf_bypass" and obs.payload:
                            # A payload that got through a block on this host — reused
                            # by the mutator on later endpoints of the same host.
                            session_intelligence.record_scan_complete(
                                host=_host, path=_path,
                                attack_type=obs.attack_type,
                                found=True,
                                operation=_operation,
                                bypass_payload=obs.payload,
                            )
                        elif obs.kind == "rate_limit":
                            session_intelligence.record_scan_complete(
                                host=_host, path=_path,
                                attack_type=obs.attack_type,
                                found=False,
                                operation=_operation,
                                rate_limited=True,
                            )
                        elif obs.kind == "structural_error" and obs.signal:
                            session_intelligence.record_scan_complete(
                                host=_host, path=_path,
                                attack_type=obs.attack_type,
                                found=False,
                                operation=_operation,
                                structural_error=obs.signal,
                            )
            except Exception as exc:
                logger.warning("Session intelligence write-back failed", url=target.url, error=str(exc))

        # Build per-agent outcome log entries
        confirmed_titles = {f.title for f in confirmed}
        outcomes = []
        for agent in agents:
            agent_findings = agent_raw.get(agent.attack_type, [])
            if agent_findings:
                for f in agent_findings:
                    outcomes.append({
                        "agent": agent.name,
                        "attack_type": agent.attack_type,
                        "finding_title": f.title,
                        "confirmed": f.title in confirmed_titles,
                        "reasoning": getattr(f, "reasoning", ""),
                    })
            else:
                outcomes.append({
                    "agent": agent.name,
                    "attack_type": agent.attack_type,
                    "finding_title": None,
                    "confirmed": False,
                    "reasoning": "",
                })

        _activity_log.appendleft({
            "ts": time.time(),
            "method": target.method,
            "url": target.url,
            "params": [p["name"] for p in target.params[:10]],
            "operation": _extract_operation(target),
            "agents_selected": [a.attack_type for a in agents],
            "plan_reason": plan_reason,
            "outcomes": outcomes,
        })

        logger.info(
            "Coordinator scan complete",
            url=target.url,
            raw=len(raw_findings),
            confirmed=len(confirmed),
        )

        # Log per-agent outcome to the Logs tab
        for agent in agents:
            agent_findings = agent_raw.get(agent.attack_type, [])
            confirmed_by_agent = [f for f in agent_findings if f.title in confirmed_titles]
            if confirmed_by_agent:
                titles = ", ".join(f.title for f in confirmed_by_agent)
                _log_event(
                    agent.name, "finding",
                    f"Confirmed: {titles}",
                    url=target.url, source="agent",
                )
            else:
                _log_event(
                    agent.name, "info",
                    "No findings",
                    url=target.url, source="agent",
                )

        return confirmed

    @classmethod
    async def _baseline_check(
        cls,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        model_id: Optional[str] = None,
    ) -> tuple[Optional[str], str]:
        """
        Send the original request and use the LLM to analyse the response.

        Returns (abort_reason_or_None, response_summary).
        - abort_reason: non-None means stop scanning this endpoint.
        - response_summary: human-readable summary of the baseline response for the planner.

        The LLM classifies the response as ok / abort / adapt.
        Fast deterministic checks run first to avoid an LLM call on clear-cut cases.
        """
        import json as _json
        from dast.scanners.active_checks import _send as _do_send

        try:
            resp = await _do_send(
                client, target.method, target.url,
                target.headers, target.body,
            )
        except Exception:
            return None, ""

        if resp is None:
            return None, ""

        # Build a compact, sanitized summary of the response for downstream use.
        # Truncated to avoid poisoning the planner prompt with huge bodies.
        try:
            _resp_body_preview = resp.text[:1200]
        except Exception:
            _resp_body_preview = ""
        response_summary = (
            f"Baseline response: HTTP {resp.status_code}\n"
            f"Content-Type: {resp.headers.get('content-type', 'unknown')}\n"
            f"Body ({len(_resp_body_preview)} chars shown):\n{_resp_body_preview}"
        )

        # ── Fast deterministic abort ──────────────────────────────────────
        if resp.status_code in (404, 405, 501):
            return f"HTTP {resp.status_code} — endpoint not found at this URL", response_summary

        # 401/403 on a POST/JSON endpoint where all params are auth tokens means
        # the server rejects the request before any business logic runs.
        if resp.status_code in (401, 403) and _params_are_all_auth_tokens(target):
            return f"HTTP {resp.status_code} — all parameters are auth/OIDC tokens, injection not applicable", response_summary

        # GraphQL structural errors — detectable without LLM
        if "json" in resp.headers.get("content-type", ""):
            try:
                data = _json.loads(resp.text)
                errors = data.get("errors") if isinstance(data, dict) else None
                if errors and isinstance(errors, list):
                    _STRUCTURAL_CODES = {
                        "undefinedField", "variableRequiresValidType", "unknownType",
                        "variableNotUsed", "undefinedDirective", "fragmentDoesNotExist",
                    }
                    _STRUCTURAL_PHRASES = (
                        "isn't a defined input type",
                        "doesn't exist on type",
                        "is not defined",
                        "Unknown type",
                        "Unknown argument",
                        "Field does not exist",
                    )
                    for err in errors:
                        code = (err.get("extensions") or {}).get("code", "")
                        msg = err.get("message", "")
                        if code in _STRUCTURAL_CODES or any(p in msg for p in _STRUCTURAL_PHRASES):
                            return f"GraphQL schema error: {msg[:120]}", response_summary
            except Exception:
                pass

        # 401/403 on a baseline request — auth wall, abort to avoid 401 flooding.
        if resp.status_code in (401, 403):
            return f"HTTP {resp.status_code} — server rejected baseline request (auth required or forbidden)", response_summary

        # ── LLM analysis for ambiguous cases ─────────────────────────────
        should_ask_llm = (
            resp.status_code >= 400
        ) or (
            resp.status_code == 200
            and len(resp.text) < 500
            and any(w in resp.text.lower() for w in ("error", "invalid", "not found", "undefined"))
        )

        if not should_ask_llm:
            return None, response_summary

        try:
            # target.body and resp.text are controlled by the scanned application
            # (untrusted) — fence them in XML tags so injected instructions in the
            # response cannot hijack the classification. URL/method/status are
            # scanner-derived and safe to interpolate directly.
            req_summary = (
                f"Request: {target.method} {target.url}\n"
                f"Content-Type: {target.headers.get('content-type', '')}\n"
                f"Request body:\n{wrap_untrusted(target.body or '', 'request_body', 600)}"
            )
            resp_llm_summary = (
                f"Response status: {resp.status_code}\n"
                f"Response body:\n{wrap_untrusted(resp.text, 'target_response', 800)}"
            )
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                None,
                lambda: bedrock_client.invoke_json(
                    system=_SYSTEM_BASELINE,
                    user=req_summary + resp_llm_summary,
                    model_id=model_id or None,
                    max_tokens=256,
                    schema=BASELINE_SCHEMA,
                    temperature=0,
                    cache_system=True,
                ),
            )
            status = result.get("status", "ok")
            reason = result.get("reason", "")
            structural = result.get("structural_error", "")

            if status == "abort":
                return structural or reason or "LLM determined request is structurally broken", response_summary
        except Exception as e:
            logger.debug("Baseline LLM analysis failed", error=str(e))

        return None, response_summary

    @classmethod
    async def _run_probe_diff_pass(
        cls,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        model_id: Optional[str],
        signal_map: Dict[str, List[str]],
    ) -> str:
        """
        Run break/repair probe pairs on each injectable param, classify any
        divergence via the LLM, and fold the resulting injection-class
        hypotheses into ``signal_map`` (so agents get dispatched) while
        returning an LLM-readable summary for the planner prompt.

        Reuses the coordinator's proxy-routed client. Fully defensive — any
        failure yields an empty summary and leaves signal_map untouched.
        """
        from dast.agents.probe_diff import run_probe_pairs
        from dast.ai.probe_classifier import classify

        probe_params = [
            p for p in (target.params or [])
            if p.get("name", "").lower() not in _AUTH_TOKEN_PARAMS
            and p.get("location", "query") in ("query", "body", "body_graphql")
        ]
        if not probe_params:
            return ""

        summary_lines: List[str] = []
        for param in probe_params:
            try:
                signature = await run_probe_pairs(
                    target, param, settings=None, client=client
                )
            except Exception as exc:
                logger.warning("Probe-diff pass failed", parameter=param.get("name"), error=str(exc))
                continue
            if signature is None or not signature.has_signal:
                continue

            verdict = classify(signature, model_id=model_id)
            pname = param.get("name", "")
            if verdict.has_hypothesis:
                summary_lines.append(
                    f"  {pname}: {verdict.injection_class} "
                    f"(context: {verdict.context}, conf {verdict.confidence:.2f}) "
                    f"— {verdict.reasoning}"
                )
                # Fold recommended agents into signal_map so the planner treats
                # them as signalled. Fall back to the classified class itself.
                agents = verdict.recommended_agents or [verdict.injection_class]
                for at in agents:
                    if at and at != "none":
                        if pname not in signal_map.setdefault(at, []):
                            signal_map[at].append(pname)
            else:
                summary_lines.append(
                    f"  {pname}: diverged on {', '.join(signature.divergent_labels)} "
                    f"but no injection-class hypothesis"
                )

        summary = "\n".join(summary_lines)
        if summary_lines:
            # Expose to the mutator (via build_mutator_context) so payload
            # discovery aims at the proven syntactic context, not just the class.
            try:
                target.probe_diff_hint = "Probe-diff injection-context analysis:\n" + summary
            except Exception:  # pragma: no cover - defensive; target is a dataclass
                pass
            from dast.proxy.plugin_manager import log_event as _le_probe
            _le_probe(
                "coordinator", "info",
                f"Probe-diff analysis: {len(summary_lines)} param(s) with transformation signal",
                url=target.url, source="agent",
            )
        return summary

    @classmethod
    async def _run_param_mining_pass(
        cls,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
    ) -> None:
        """
        Brute-force hidden/undocumented parameter NAMES on this endpoint (the
        planner judged it likely to accept some) and fold every discovered name
        onto ``target.params`` as fresh attack surface the just-selected agents
        will then test — plus a ``param_mining_hint`` the mutator can read.

        Reuses the coordinator's proxy-routed client (never opened/closed here).
        Detection-only: injects an inert canary, never a payload. Scope-gating
        happens inside run_param_mining (settings=None here because the shared
        client is already scope-constrained by the proxy). Fully defensive — any
        failure leaves target.params untouched.
        """
        from urllib.parse import urlparse
        from dast.scanners.param_miner import run_param_mining

        headers = dict(target.headers or {})
        content_type = headers.get("content-type", headers.get("Content-Type", ""))

        try:
            hits = await run_param_mining(
                base_url=target.url,
                headers=headers,
                settings=None,
                method=target.method,
                body=target.body,
                content_type=content_type,
                client=client,
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Param-mining pass failed", url=target.url, error=str(exc))
            return

        if not hits:
            return

        # Map the miner's location vocabulary (query/form/json) onto the agent
        # vocabulary (query/body) and append names not already on the target.
        existing_names = {p.get("name", "") for p in (target.params or [])}
        discovered: List[str] = []
        for hit in hits:
            name = hit.get("parameter", "")
            if not name or name in existing_names:
                continue
            miner_loc = hit.get("location", "query")
            agent_loc = "query" if miner_loc == "query" else "body"
            target.params.append({"name": name, "location": agent_loc, "value": ""})
            existing_names.add(name)
            discovered.append(name)

        if not discovered:
            return

        hint = (
            "Hidden parameters discovered by param mining (undocumented, now "
            "under test as fresh attack surface): " + ", ".join(discovered)
        )
        try:
            target.param_mining_hint = hint
        except Exception:  # pragma: no cover - defensive; target is a dataclass
            pass

        from dast.proxy.plugin_manager import log_event as _le_mine
        _le_mine(
            "coordinator", "info",
            f"Param mining: {len(discovered)} hidden param(s) discovered — "
            f"{', '.join(discovered[:8])}",
            url=target.url, source="agent",
        )
        logger.info(
            "Param-mining pass complete",
            url=target.url,
            host=urlparse(target.url).hostname,
            discovered=len(discovered),
        )

    @classmethod
    async def _plan(
        cls,
        target: "CheckTarget",
        model_id: Optional[str] = None,
        session_intel_hint: str = "",
        canary_summary: str = "",
        signal_attack_types: Optional[List[str]] = None,
        candidate_types: Optional[List[str]] = None,
        baseline_response: str = "",
    ) -> tuple[List[str], str, bool]:
        available = ", ".join(cls._registry.keys())

        # Show param names AND values (truncated) so the LLM has richer signal
        param_parts = []
        for p in (target.params or [])[:10]:
            val = str(p.get("value", ""))[:60]
            param_parts.append(f"{p['name']}={val!r}" if val else p["name"])
        param_names = ", ".join(param_parts) or "(none)"

        # Hints below are derived from analysis of the target application, so they
        # are untrusted-adjacent — fence them so injected instructions in a crawled
        # response or analysed source file cannot hijack agent selection.
        discovery_summary = ""
        if target.discovery_context:
            summary = target.discovery_context.to_agent_summary()
            if summary:
                discovery_summary = f"\nDiscovery context:\n{wrap_untrusted(summary, 'discovery_context')}"

        app_profile_hint = ""
        if getattr(target, "app_profile_hint", ""):
            app_profile_hint = f"\nApp intelligence (from background analysis):\n{wrap_untrusted(target.app_profile_hint, 'app_intelligence')}"

        session_section = ""
        if session_intel_hint:
            session_section = f"\nSession intelligence (accumulated from this scan session):\n{wrap_untrusted(session_intel_hint, 'session_intelligence')}"

        code_section = ""
        if getattr(target, "code_hint", ""):
            code_section = f"\n{wrap_untrusted(target.code_hint, 'source_code')}"

        canary_section = ""
        if canary_summary:
            canary_section = (
                f"\nCanary probe results (cheap single-payload tests sent before this decision):\n"
                f"{canary_summary}\n"
                f"\nIMPORTANT: Strongly prefer attack types that showed SIGNAL in the canary pass."
                f" You MAY still include types with no canary if the endpoint structure strongly"
                f" suggests them (e.g. business_logic on a state-changing endpoint, secrets always)."
                f" Skip types with no canary and no structural reason.\n"
            )

        # If no signal at all and we have candidate types, restrict to non-injectable
        # types only so we don't waste time running full agents on clean params.
        restrict_note = ""
        if signal_attack_types is not None and not signal_attack_types and candidate_types:
            no_canary = [t for t in (candidate_types or []) if t not in _CANARY_PAYLOADS]
            if no_canary:
                restrict_note = (
                    f"\nNo canary signals detected. Restrict agents to: {', '.join(no_canary)}."
                    f" Do NOT select injection-type agents (sqli, xss, lfi, ssrf, cmdi, ssti, nosql)"
                    f" unless the endpoint structure strongly justifies it.\n"
                )
            else:
                restrict_note = (
                    "\nNo canary signals detected. Canary probes found no injection signal on any"
                    " parameter. Only select secrets and non-injection agents.\n"
                )

        baseline_section = ""
        if baseline_response:
            baseline_section = f"\n{baseline_response}\n"

        # Sanitize body before embedding — MongoDB/NoSQL operators trigger Bedrock content filter
        _body_snippet = (target.body or "")[:600]
        _body_snippet = _re.sub(r'\$(?:where|ne|eq|gt|lt|gte|lte|in|nin|regex|exists|or|and|not|nor|all|elemMatch)\b', r'[op]', _body_snippet)
        # Request body is target-controlled — fence it as untrusted data.
        _body_section = wrap_untrusted(_body_snippet, 'request_body') or "(none)\n"

        user = (
            f"Endpoint: {target.method} {target.url}\n"
            f"Parameters: {param_names}\n"
            f"Content-Type: {target.headers.get('content-type', 'unknown')}\n"
            f"Request body:\n{_body_section}"
            f"Available agent types: {available}\n"
            f"{baseline_section}"
            f"{discovery_summary}"
            f"{app_profile_hint}"
            f"{session_section}"
            f"{code_section}"
            f"{canary_section}"
            f"{restrict_note}"
            f"\nSelect only the agents worth running for this endpoint."
            f" Use the baseline response above to understand what this endpoint does before deciding."
            f" Prioritise attack types that showed canary signal or have worked on this host before."
            f" Skip attack types marked as ineffective unless this endpoint looks different."
            f" Use the source code context above (if present) to identify hidden parameters,"
            f" protections (CSRF tokens, rate limiters, auth checks), and likely vuln types."
        )

        try:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                None,
                lambda: bedrock_client.invoke_json(
                    system=_SYSTEM_PLAN, user=user, model_id=model_id or None,
                    schema=PLANNER_SCHEMA, temperature=0, cache_system=True,
                ),
            )
            selected = result.get("agents", [])
            reason = str(result.get("reason", ""))
            mine_params = bool(result.get("mine_params", False))
            if isinstance(selected, list):
                return [str(t) for t in selected], reason, mine_params
        except Exception as e:
            logger.warning("Planner LLM failed, falling back to signal-based selection", error=str(e))
            # Fall back: run agents for signal types + non-injectable types.
            # Mining is an LLM decision — default it OFF on any planner failure.
            fallback = list({*(signal_attack_types or []), *[t for t in (candidate_types or []) if t not in _CANARY_PAYLOADS]})
            return fallback or list(cls._registry.keys()), "LLM failed — signal-based fallback", False

        # Reached only if invoke_json succeeded but returned no "agents" key.
        # Fall back to signal-based selection rather than running every agent.
        fallback = list({*(signal_attack_types or []), *[t for t in (candidate_types or []) if t not in _CANARY_PAYLOADS]})
        return fallback, "LLM returned no agent list — signal-based fallback", False

    @classmethod
    async def _validate(
        cls,
        finding: AgentFinding,
        target: "CheckTarget",
        model_id: Optional[str] = None,
        confidence_threshold: float = 0.5,
    ) -> bool:
        from dast.ai import red_team
        confirmed, _confidence, _reasoning = await red_team.validate(
            finding,
            target,
            model_id=model_id,
            confidence_threshold=confidence_threshold,
            app_profile_hint=getattr(target, "app_profile_hint", "") or "",
        )
        return confirmed
