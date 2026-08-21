"""
Business Logic Agent — LLM-driven detection of application business logic flaws.

Tests for vulnerabilities that arise from incorrect implementation of application
logic rather than injection-class attacks:
  - Numeric boundary abuse: negative prices, zero quantities, integer overflow on financials
  - Privilege escalation via parameter injection: role/admin/plan fields in request body
  - Workflow bypass: setting status/state/step params to skip required transitions
  - Mass assignment: injecting response-visible sensitive fields back into modifying requests

Strategy:
  1. Baseline request captures the normal response
  2. LLM analyses the endpoint (method, URL, params, baseline response) and produces probes
  3. Each probe is sent and the LLM evaluates (baseline vs probe) to confirm a logic flaw
  4. All findings go through the Red Team Validator (bypass_validation=False)

Probe count capped at 8 per endpoint to stay within scan budget.
"""

from __future__ import annotations

import asyncio
import json as _json
import re
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

from dast.ai import bedrock_client
from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.ai.payload_generator import _sanitize_for_prompt
from dast.scanners.active_checks import _fmt_http_pair, _inject_query, _send
from dast.utils.jwt import b64url_encode_json, decode_jwt_claims, decode_jwt_header
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

logger = get_logger(__name__)

_MAX_PROBES = 8

# Field name patterns for open redirect detection in request bodies
_REDIRECT_FIELD_RE = re.compile(
    r"^(redirect|return|next|goto|dest(?:ination)?|url|callback|continue|"
    r"forward|target|location|back|refer(?:rer)?|per_redirect|redirect_uri|"
    r"redirect_url|return_url|next_url|success_url|cancel_url)$",
    re.IGNORECASE,
)

# Field name patterns that strongly suggest privilege/role control
_PRIVILEGE_FIELD_RE = re.compile(
    r"(admin|superuser|super_user|is_admin|role|roles|permission|privilege|"
    r"plan|tier|level|access|scope|grant|elevated|staff|moderator|owner|"
    r"is_staff|is_superuser|is_elevated|is_owner|is_moderator|is_verified|"
    r"verified|trusted|is_trusted|internal|is_internal)",
    re.IGNORECASE,
)


_SYSTEM_BL_PLAN = """\
You are a senior penetration tester with deep expertise in business logic vulnerabilities,
having found critical flaws in payment systems, SaaS multi-tenant platforms, and REST APIs.

Given an HTTP endpoint, its request body, and baseline response, generate targeted probes that
a real expert would try — not generic fuzzing, but specific parameter manipulations grounded in
what this endpoint actually does.

Think: "What is this endpoint's business purpose? What would break if I manipulate X? What fields
does the server trust from the client that it shouldn't?"

Vulnerability categories to reason about:

mass_assignment:
  The server returns fields in the response that the client didn't send. This often means the
  server's ORM or deserialiser accepts those fields too. Compare response vs request — every
  extra response field is a candidate. Focus on: booleans (false→true), roles/plans/tiers
  (user→admin), status fields, limit/quota fields.
  Example: POST {"email":"x"} → 200 {"email":"x","is_admin":false,"plan":"free"}
  Probes: is_admin=true, plan="enterprise"

privilege_escalation:
  Fields in the request that control access level — try escalating them.
  role="user" → role="admin", plan="basic" → plan="enterprise", scope="read" → scope="write"

workflow_bypass:
  State machine fields that should only advance via server logic.
  status="pending" → status="approved", step=1 → step=5, verified=false → verified=true

numeric_boundary:
  Financial/quantity fields. Try: negative (-1), zero (0), extreme large (99999999),
  decimal precision abuse (0.001), integer overflow.

Respond ONLY with valid JSON:
{
  "operation_summary": "<one sentence: what this endpoint does and why it's a business logic target>",
  "probes": [
    {
      "description": "<specific exploit scenario: what flaw, what impact>",
      "param_name": "<exact field name>",
      "param_location": "<query|body|body_graphql>",
      "probe_value": "<value as string>",
      "test_type": "<numeric_boundary|privilege_escalation|workflow_bypass|mass_assignment>"
    }
  ]
}

Hard rules:
- Maximum 8 probes. Ruthlessly prioritise — only high-confidence candidates.
- mass_assignment: only fields visible in the response but absent from the request.
- numeric_boundary: only if the endpoint clearly handles financial or quantity data.
- Return empty probes list for pure-read GET endpoints, search/filter params, or auth flows.
- Never probe injection-class params (search terms, free-text fields) — that's for other agents.
"""

_SYSTEM_BL_EVAL = """\
You are a senior penetration tester evaluating whether a business logic probe produced a real
vulnerability. You have seen thousands of false positives and you are ruthlessly skeptical.

A baseline request was sent to establish normal behaviour. Then a modified probe was sent with
one parameter changed. Your job: decide if the response difference proves an exploitable flaw.

Respond ONLY with valid JSON:
{
  "confirmed": true|false,
  "finding_title": "<concise, specific vulnerability title — empty if not confirmed>",
  "severity": "<critical|high|medium|low>",
  "reasoning": "<2-3 sentences: what the response proves (or why it doesn't prove anything)>"
}

Confirm TRUE only when the evidence is unambiguous:
- Mass assignment accepted: the injected field appears in the response WITH its new value, AND
  the server responded 2xx (not a 422/400 validation error that accepted the field in the body
  but ignored it).
- Privilege escalation: the response now contains data or capabilities that were absent/restricted
  at baseline — e.g. response body shows role="admin", or returns admin-only fields.
- Workflow bypass: the resource's state in the response jumped to the injected state, bypassing
  expected validation (e.g. status changed from "pending" to "approved" without going through
  "reviewed").
- Numeric boundary: a negative/zero monetary value was accepted (2xx) and the response shows
  the transaction proceeded (e.g. balance decreased by a negative amount = credit gained).

Confirm FALSE for:
- Server returned 4xx for the probe (rejected). 422 Unprocessable Entity = field validated.
- Response body is identical to baseline — probe had no observable effect.
- The injected field appears in the response but with the original/server-assigned value (server
  ignored the client's value and set its own — this is CORRECT server behaviour, not a flaw).
- Generic error page, 500, or 404 response.
- The only difference is a timestamp, request ID, or other non-security field.

Severity guide:
- critical: account takeover, payment manipulation, admin access gained
- high:     privilege escalation to elevated role, bypass of security control
- medium:   workflow bypass, minor limit bypass, data exposure
- low:      informational anomaly with limited exploitability
"""


_JWT_RE = re.compile(
    r"^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$"
)

def _is_jwt(value: str) -> bool:
    return bool(_JWT_RE.match(str(value).strip()))

# JWT decode helpers now live in dast.utils.jwt; aliased for in-module callers.
_decode_jwt_claims = decode_jwt_claims
_decode_jwt_header = decode_jwt_header


def _build_jwt_alg_none(original_token: str, extra_claims: Optional[dict] = None) -> str:
    """
    Build an alg:none JWT preserving the original claims payload,
    optionally injecting extra claims (e.g. role: admin).
    """
    claims = _decode_jwt_claims(original_token) or {}
    if extra_claims:
        claims.update(extra_claims)

    for variant_alg in ("none", "None", "NONE"):
        header = {"alg": variant_alg, "typ": "JWT"}
        yield f"{b64url_encode_json(header)}.{b64url_encode_json(claims)}."


def _jwt_probes(key: str, location: str, original_token: str = "") -> List[Dict[str, Any]]:
    """
    JWT-specific probes for a field containing a JWT token.

    Strategy:
    1. Decode the claims — extract URLs from iss/aud/jku/x5u for SSRF probes
    2. alg:none — preserve original claims (+ admin escalation variant)
    3. kid injection — path traversal + SQL
    4. jku/x5u SSRF — if claims contain URL-type headers
    5. Malformed tokens — truncated, empty sig, wrong encoding
    """
    from dast.payloads.loader import get_payloads

    probes: List[Dict[str, Any]] = []

    claims = _decode_jwt_claims(original_token) if original_token else {}
    header = _decode_jwt_header(original_token) if original_token else {}
    alg = (header or {}).get("alg", "RS256")

    # ── 1. alg:none — preserve original claims ───────────────────────────
    for i, none_token in enumerate(_build_jwt_alg_none(original_token)):
        probes.append({
            "param_name": key,
            "param_location": location,
            "probe_value": none_token,
            "test_type": "privilege_escalation",
            "description": f"JWT alg:none bypass (variant {i+1}) — original claims preserved, signature removed",
            "_deterministic": True,
        })

    # alg:none with elevated claims
    for none_token in _build_jwt_alg_none(original_token, {"role": "admin", "is_admin": True}):
        probes.append({
            "param_name": key,
            "param_location": location,
            "probe_value": none_token,
            "test_type": "privilege_escalation",
            "description": "JWT alg:none + privilege escalation — role=admin injected into claims",
            "_deterministic": True,
        })
        break  # one variant enough

    # ── 2. URL scan — all parts of the JWT ───────────────────────────────
    # Decode header, claims, AND scan the raw base64 parts for embedded URLs.
    # URLs can appear in ANY claim (iss, aud, jku, x5u, resource, api_url, etc.)
    # or even embedded inside string values as sub-strings.
    # Strategy:
    #   a) Flatten ALL fields from header + claims into a single key→value map
    #   b) Extract every http/https URL found anywhere in any value (deep scan)
    #   c) For each URL-bearing field: build a token replacing that URL with OOB
    #   d) For header URL fields (jku, x5u): inject into header instead of claims

    _SSRF_URL = "https://collaborator.dast-ai.internal/jwt-ssrf"
    _URL_RE = re.compile(r'https?://[^\s"\'<>}\]){,]+', re.IGNORECASE)

    def _find_urls_in_value(val) -> List[str]:
        """Recursively find all http(s) URLs in a value (string, list, dict)."""
        found = []
        if isinstance(val, str):
            found.extend(_URL_RE.findall(val))
        elif isinstance(val, list):
            for item in val:
                found.extend(_find_urls_in_value(item))
        elif isinstance(val, dict):
            for v in val.values():
                found.extend(_find_urls_in_value(v))
        return found

    def _replace_url_in_value(val, old_url: str, new_url: str):
        """Replace a URL anywhere inside a value (string, list, dict)."""
        if isinstance(val, str):
            return val.replace(old_url, new_url)
        elif isinstance(val, list):
            return [_replace_url_in_value(item, old_url, new_url) for item in val]
        elif isinstance(val, dict):
            return {k: _replace_url_in_value(v, old_url, new_url) for k, v in val.items()}
        return val

    # Collect all URL-bearing locations: (section, claim_key, url)
    # section = "header" | "claims"
    url_locations: List[tuple] = []  # (section, claim_key, original_url)

    for section, data_dict in [("header", header or {}), ("claims", claims or {})]:
        for claim_key, claim_val in data_dict.items():
            for url in _find_urls_in_value(claim_val):
                url_locations.append((section, claim_key, url))

    # Deduplicate by URL — one probe per unique URL found
    seen_urls: set = set()
    for section, claim_key, original_url in url_locations:
        if original_url in seen_urls:
            continue
        seen_urls.add(original_url)

        # Build modified token with this URL replaced by OOB URL
        mod_header = dict(header or {"alg": "none", "typ": "JWT"})
        mod_claims = dict(claims or {})
        # Always use alg:none so the server actually processes the token
        mod_header["alg"] = "none"

        if section == "header":
            mod_header[claim_key] = _replace_url_in_value(
                mod_header.get(claim_key, original_url), original_url, _SSRF_URL
            )
        else:
            mod_claims[claim_key] = _replace_url_in_value(
                mod_claims.get(claim_key, original_url), original_url, _SSRF_URL
            )

        ssrf_token = f"{b64url_encode_json(mod_header)}.{b64url_encode_json(mod_claims)}."
        probes.append({
            "param_name": key,
            "param_location": location,
            "probe_value": ssrf_token,
            "test_type": "mass_assignment",
            "description": (
                f"JWT SSRF: {section}.{claim_key} URL replaced "
                f"({original_url[:60]}{'...' if len(original_url)>60 else ''} → OOB)"
            ),
            "_deterministic": True,
            "_attack_hint": "ssrf",
        })

    # ── 3. kid injection (only if header has kid or alg suggests key lookup) ──
    if (header or {}).get("kid") is not None or alg in ("RS256", "RS384", "RS512", "ES256"):
        kid_payloads = get_payloads("jwt", "kid_injection")

        for kid_val in kid_payloads[:3]:
            kid_header = {"alg": "none", "typ": "JWT", "kid": kid_val}
            kid_token = f"{b64url_encode_json(kid_header)}.{b64url_encode_json(claims or {'sub': 'test'})}."
            probes.append({
                "param_name": key,
                "param_location": location,
                "probe_value": kid_token,
                "test_type": "privilege_escalation",
                "description": f"JWT kid injection: kid={kid_val!r} — path traversal/SQL in key lookup",
                "_deterministic": True,
            })

    # ── 4. Malformed / truncated tokens ──────────────────────────────────
    for bad_token, desc in [
        ("invalid.token.here", "malformed JWT — not base64url encoded"),
        ("eyJhbGciOiJIUzI1NiJ9.e30.", "JWT with empty claims and no signature"),
        (original_token.rsplit(".", 1)[0] + "." if original_token and "." in original_token else "", "JWT with signature stripped"),
    ]:
        if bad_token:
            probes.append({
                "param_name": key,
                "param_location": location,
                "probe_value": bad_token,
                "test_type": "workflow_bypass",
                "description": f"JWT malformed: {desc}",
                "_deterministic": True,
            })

    return probes


def _deterministic_probes(target: "CheckTarget", baseline_text: str) -> List[Dict[str, Any]]:
    """
    Generate business logic probes deterministically from the request body — no LLM needed.

    Covers the cases the LLM often misses on auth/login endpoints:
      1. Boolean flip  — every true→false and false→true in the body
      2. Open redirect — any redirect/return/url field set to an attacker domain
      3. Mass assignment — common privilege-escalation fields injected into any JSON body
      4. Numeric boundary — any int/float field set to negative, zero, overflow values
    """
    import json as _json

    probes: List[Dict[str, Any]] = []
    body = target.body or ""
    ct = target.headers.get("content-type", "").lower()
    location = "body"

    # Only handle JSON bodies for now
    if "application/json" not in ct and not body.strip().startswith("{"):
        return probes

    try:
        data = _json.loads(body)
    except Exception:
        return probes

    if not isinstance(data, dict):
        return probes

    # ── 0. JWT fields — detect and test JWT-specific attacks ─────────────
    # When a string field contains a JWT, skip generic probes for it and
    # use JWT-specific attacks (alg:none, weak secret, etc.) instead.
    jwt_keys: set = set()
    for key, val in data.items():
        if isinstance(val, str) and _is_jwt(val):
            jwt_keys.add(key)
            probes.extend(_jwt_probes(key, location, original_token=val))

    # ── 1. Boolean flip ──────────────────────────────────────────────────
    for key, val in data.items():
        if isinstance(val, bool):
            flipped = not val
            probes.append({
                "param_name": key,
                "param_location": location,
                "probe_value": str(flipped).lower(),
                "test_type": "privilege_escalation",
                "description": f"Boolean flip: {key}={val} → {flipped} (may bypass auth/feature flag)",
                "_deterministic": True,
            })

    # ── 2. Open redirect via body field ──────────────────────────────────
    for key, val in data.items():
        if key in jwt_keys:
            continue  # JWT fields handled separately above
        if isinstance(val, str) and _REDIRECT_FIELD_RE.match(key):
            probes.append({
                "param_name": key,
                "param_location": location,
                "probe_value": "https://evil.attacker.com/steal",
                "test_type": "workflow_bypass",
                "description": f"Open redirect: {key}={val!r} → attacker URL",
                "_deterministic": True,
            })

    # ── 3. Numeric boundary ───────────────────────────────────────────────
    for key, val in data.items():
        if isinstance(val, (int, float)) and not isinstance(val, bool):
            if val > 0:
                probes.append({
                    "param_name": key,
                    "param_location": location,
                    "probe_value": "-1",
                    "test_type": "numeric_boundary",
                    "description": f"Numeric boundary: {key}={val} → -1 (negative value abuse)",
                    "_deterministic": True,
                })
            probes.append({
                "param_name": key,
                "param_location": location,
                "probe_value": "99999999",
                "test_type": "numeric_boundary",
                "description": f"Numeric boundary: {key}={val} → 99999999 (overflow probe)",
                "_deterministic": True,
            })

    return probes[:_MAX_PROBES]


def _coerce_probe_value(value_str: str) -> Any:
    """Convert a string probe value to a Python type suitable for JSON serialization."""
    import json as _j
    low = value_str.strip().lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low in ("null", "none"):
        return None
    # JSON array or object (e.g. '["admin"]')
    if (value_str.startswith("[") or value_str.startswith("{")):
        try:
            return _j.loads(value_str)
        except Exception:
            pass
    try:
        if "." in value_str:
            return float(value_str)
        return int(value_str)
    except (ValueError, TypeError):
        return value_str


def _inject_into_body(
    body: str,
    param_name: str,
    probe_value_str: str,
    content_type: str,
) -> Optional[str]:
    """
    Return a new request body with param_name set to probe_value.
    Handles JSON bodies and URL-encoded form bodies.
    Returns None if the body type is not injectable.
    """
    coerced = _coerce_probe_value(probe_value_str)
    ct = content_type.lower()

    if "application/json" in ct or (body and body.strip().startswith("{")):
        try:
            data = _json.loads(body) if body else {}
            if not isinstance(data, dict):
                return None
            data[param_name] = coerced
            return _json.dumps(data)
        except Exception:
            return None

    if "application/x-www-form-urlencoded" in ct or ("=" in body and not body.strip().startswith("{")):
        try:
            pairs: Dict[str, list] = {}
            for part in body.split("&"):
                if "=" in part:
                    k, _, v = part.partition("=")
                    pairs.setdefault(k, []).append(v)
            pairs[param_name] = [str(probe_value_str)]
            return "&".join(f"{k}={v}" for k, vals in pairs.items() for v in vals)
        except Exception:
            return None

    return None


def _inject_into_graphql_variables(
    body: str,
    param_name: str,
    probe_value_str: str,
) -> Optional[str]:
    """Inject probe_value into a GraphQL variables dict."""
    coerced = _coerce_probe_value(probe_value_str)
    try:
        data = _json.loads(body)
        if not isinstance(data, dict) or "query" not in data:
            return None
        variables = data.get("variables") or {}
        if not isinstance(variables, dict):
            return None
        # Support dotted paths like "input.price"
        parts = param_name.split(".", 1)
        if len(parts) == 2 and isinstance(variables.get(parts[0]), dict):
            variables[parts[0]][parts[1]] = coerced
        else:
            variables[param_name] = coerced
        data["variables"] = variables
        return _json.dumps(data)
    except Exception:
        return None


def _response_informed_probes(
    request_body: str,
    response_text: str,
    existing_probes: List[Dict],
) -> List[Dict[str, Any]]:
    """
    Mine the baseline response for fields absent from the request.
    These are mass assignment candidates — the server returns them so it may accept them.

    Example: POST {"host":"aaaa.com"} → 201 {"host":"aaaa.com","valid":false,"owner_id":7}
    Probes: valid=true (boolean flip), owner_id=-1 (numeric boundary)
    """
    import json as _j

    # Skip server-generated or read-only fields that can never be injected
    _SKIP_KEYS = frozenset({
        "id", "uuid", "created_at", "updated_at", "inserted_at", "deleted_at",
        "created_by", "updated_by", "timestamp", "ts", "etag", "version",
        "href", "url", "_links", "_meta", "self",
    })

    try:
        req_data = _j.loads(request_body) if request_body else {}
    except Exception:
        req_data = {}

    try:
        resp_data = _j.loads(response_text) if response_text else {}
    except Exception:
        resp_data = {}

    if not isinstance(req_data, dict):
        req_data = {}
    if not isinstance(resp_data, dict):
        resp_data = {}

    # Flatten one level of nesting (e.g. {"user": {"role": "member"}} → user.role)
    def _flatten(d: dict, prefix: str = "") -> dict:
        out = {}
        for k, v in d.items():
            key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                out.update(_flatten(v, key))
            else:
                out[key] = v
        return out

    resp_flat = _flatten(resp_data)
    req_keys = set(_flatten(req_data).keys())
    existing_keys = {p["param_name"] for p in existing_probes}

    probes: List[Dict[str, Any]] = []
    for key, val in resp_flat.items():
        base_key = key.split(".")[-1]
        if key in req_keys or key in existing_keys:
            continue
        if base_key.lower() in _SKIP_KEYS:
            continue

        # Boolean false → probe true (bypass feature flag / privilege check)
        if val is False:
            probes.append({
                "param_name": key,
                "param_location": "body",
                "probe_value": "true",
                "test_type": "mass_assignment",
                "description": f"Response-informed: {key}=false in response, probe true (feature/privilege bypass)",
                "_deterministic": True,
            })
        # Privilege-sounding string field → probe elevated value
        elif isinstance(val, str) and _PRIVILEGE_FIELD_RE.search(key):
            elevated = "admin" if val.lower() not in ("admin", "superadmin", "root") else "superadmin"
            probes.append({
                "param_name": key,
                "param_location": "body",
                "probe_value": elevated,
                "test_type": "mass_assignment",
                "description": f"Response-informed: {key}={val!r} in response, probe {elevated!r}",
                "_deterministic": True,
            })
        # Numeric field not in request — probe negative (boundary abuse)
        elif isinstance(val, (int, float)) and not isinstance(val, bool) and val > 0:
            probes.append({
                "param_name": key,
                "param_location": "body",
                "probe_value": "-1",
                "test_type": "numeric_boundary",
                "description": f"Response-informed: {key}={val} in response, probe -1 (negative boundary)",
                "_deterministic": True,
            })
        # Status/state string field — probe a value that skips transitions
        elif isinstance(val, str) and any(kw in key.lower() for kw in ("status", "state", "step", "phase", "stage")):
            probes.append({
                "param_name": key,
                "param_location": "body",
                "probe_value": "approved",
                "test_type": "workflow_bypass",
                "description": f"Response-informed: {key}={val!r} in response, probe 'approved' (workflow skip)",
                "_deterministic": True,
            })

        if len(probes) >= 6:
            break

    # If no response-informed probes found (204 or no body), add blind mass assignment
    # candidates — common privilege fields that applications often accept silently.
    if not probes:
        _BLIND_MASS_FIELDS = [
            ("role", "admin", "Blind mass assignment: inject role=admin"),
            ("isAdmin", "true", "Blind mass assignment: inject isAdmin=true"),
            ("is_admin", "true", "Blind mass assignment: inject is_admin=true"),
            ("admin", "true", "Blind mass assignment: inject admin=true"),
            ("permissions", "all", "Blind mass assignment: inject permissions=all"),
            ("plan", "enterprise", "Blind mass assignment: inject plan=enterprise"),
            ("tier", "premium", "Blind mass assignment: inject tier=premium"),
            ("verified", "true", "Blind mass assignment: inject verified=true"),
            ("active", "true", "Blind mass assignment: inject active=true"),
            ("scope", "admin:write", "Blind mass assignment: inject scope=admin:write"),
        ]
        existing_keys = set(p["param_name"].lower() for p in existing_probes)
        for field, value, desc in _BLIND_MASS_FIELDS:
            if field.lower() not in existing_keys and field.lower() not in req_keys:
                probes.append({
                    "param_name": field,
                    "param_location": "body",
                    "probe_value": value,
                    "test_type": "mass_assignment",
                    "description": desc,
                    "_deterministic": True,
                })

    return probes


_SYSTEM_BL_HINT = """\
You are a senior penetration tester who just intercepted an HTTP request. You've seen the
endpoint, the request body, and the server's baseline response. Your automated scanner already
covers the obvious cases. Now think like an expert: what application-specific business logic
fields would YOU probe that a generic scanner wouldn't know about?

Look at the response fields, the URL path, and the endpoint's apparent purpose. Think about:
- Fields the server sets automatically (ownership, quotas, billing, feature flags, access level)
  that a client might be able to override by including them in the request.
- Application-specific state transitions: what would happen if you skipped a required step?
- Limits that might not be enforced: max quantity, rate, or resource count.

Rules:
- Only suggest fields NOT already in the current probe list (listed in the prompt).
- Each probe must be specific to THIS endpoint's business logic — no generic injections.
- Probe values must make logical sense for the test (e.g. plan="enterprise" not plan="<script>").
- Maximum {max_probes} suggestions. Return empty if nothing compelling stands out.

Respond ONLY with valid JSON:
{{
  "probes": [
    {{
      "param_name": "<field name>",
      "param_location": "<body|query>",
      "probe_value": "<test value as string>",
      "test_type": "<mass_assignment|privilege_escalation|numeric_boundary|workflow_bypass>",
      "description": "<specific exploit scenario: what flaw, what impact>"
    }}
  ]
}}
"""


async def _llm_hint_probes(
    target: "CheckTarget",
    baseline_status: int,
    baseline_text: str,
    existing_probes: List[Dict],
    max_probes: int,
) -> List[Dict[str, Any]]:
    """
    Ask the LLM to suggest app-context-specific probe fields.
    The LLM returns field names + values — code sends all of them.
    The LLM never decides which probes fire or interprets individual responses.
    """
    existing_params = ", ".join(
        f"{p['param_name']}={p['probe_value']!r}"
        for p in existing_probes[:10]
    )
    user = (
        f"Method: {target.method}\n"
        f"URL: {_sanitize_for_prompt(target.url, 300)}\n"
        f"Request body: {_sanitize_for_prompt(target.body or '', 400)}\n"
        f"Baseline status: {baseline_status}\n"
        f"Baseline response (first 600 chars):\n{_sanitize_for_prompt(baseline_text, 600)}\n"
        f"Already testing these fields (skip them): {existing_params}\n"
    )
    try:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None,
            lambda: bedrock_client.invoke_json(
                system=_SYSTEM_BL_HINT.format(max_probes=max_probes),
                user=user,
                model_id=bedrock_client.get_fast_model(),
                max_tokens=512,
            ),
        )
        probes = result.get("probes") or []
        if isinstance(probes, list):
            return [
                {**p, "_llm_hint": True}
                for p in probes[:max_probes]
                if p.get("param_name") and p.get("probe_value")
            ]
    except Exception as exc:
        logger.debug("BusinessLogic LLM hint failed", error=str(exc))
    return []


async def _llm_evaluate(
    probe: Dict[str, Any],
    target: "CheckTarget",
    baseline_status: int,
    baseline_text: str,
    probe_status: int,
    probe_text: str,
) -> Tuple[bool, str, str, str]:
    """
    Evaluate baseline vs probe response.
    Returns (confirmed, finding_title, severity, reasoning).
    """
    user = (
        f"Endpoint: {target.method} {_sanitize_for_prompt(target.url, 200)}\n"
        f"Probe type: {probe.get('test_type', 'unknown')}\n"
        f"Probe description: {_sanitize_for_prompt(probe.get('description', ''), 200)}\n"
        f"Parameter modified: {probe.get('param_name', '')} → {_sanitize_for_prompt(str(probe.get('probe_value', '')), 100)}\n\n"
        f"--- Baseline response (status {baseline_status}) ---\n"
        f"{_sanitize_for_prompt(baseline_text, 600)}\n\n"
        f"--- Probe response (status {probe_status}) ---\n"
        f"{_sanitize_for_prompt(probe_text, 600)}\n"
    )
    try:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None,
            lambda: bedrock_client.invoke_json(
                system=_SYSTEM_BL_EVAL,
                user=user,
                model_id=bedrock_client.get_validation_model(),
                max_tokens=512,
            ),
        )
        confirmed = bool(result.get("confirmed", False))
        title = str(result.get("finding_title", ""))
        severity = str(result.get("severity", "medium"))
        reasoning = str(result.get("reasoning", ""))
        return confirmed, title, severity, reasoning
    except Exception as exc:
        logger.debug("BusinessLogic evaluator failed", error=str(exc))
        return False, "", "medium", ""


class BusinessLogicAgent(VulnAgent):
    name = "Business Logic Agent"
    attack_type = "business_logic"
    description = (
        "Detects business logic vulnerabilities by LLM-driven probe generation: "
        "numeric boundary abuse (negative prices/quantities), privilege escalation via "
        "parameter injection (role/admin/plan fields), workflow bypass (status/step "
        "manipulation), and mass assignment of response-visible sensitive fields."
    )

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        if not target.params and not target.body:
            return []

        # ── Step 1: Baseline ──────────────────────────────────────────────
        baseline_resp = await _send(
            client, target.method, target.url, target.headers, target.body
        )
        if baseline_resp is None:
            return []

        baseline_status = baseline_resp.status_code
        baseline_text = baseline_resp.text

        # ── Step 2: Generate ALL probes ───────────────────────────────────
        #
        # Probe generation has two tiers — the LLM never does the fuzzing itself:
        #
        # Tier A — deterministic (always runs, zero LLM cost):
        #   Boolean fields in body: flip true↔false
        #   Redirect/url fields: inject attacker URL
        #   Common privilege fields absent from request: admin, is_admin, role…
        #   Response-informed: fields in response absent from request
        #   Numeric fields: -1, 0, overflow
        #
        # Tier B — LLM hint (optional, context-aware additions only):
        #   LLM reads the endpoint + baseline response and suggests fields the
        #   code wouldn't know about (app-specific: coupon_code, promo_tier…).
        #   It returns field names + test values — NOT a decision to send them.
        #   Code sends all probes. LLM never sees individual probe responses here.

        det_probes = _deterministic_probes(target, baseline_text)
        resp_probes = _response_informed_probes(
            target.body or "", baseline_text, det_probes
        )

        # Deduplicate response-informed vs deterministic
        det_keys = {(p["param_name"], p["test_type"]) for p in det_probes}
        resp_probes = [
            p for p in resp_probes
            if (p["param_name"], p["test_type"]) not in det_keys
        ]

        # LLM hint tier: ask LLM for app-context-specific field suggestions.
        # Only runs if there are remaining probe slots. LLM returns field names,
        # not instructions to fuzz — code decides how to send.
        llm_hint_probes: List[Dict] = []
        combined_so_far = det_probes + resp_probes
        remaining = _MAX_PROBES - len(combined_so_far)
        if remaining > 0:
            llm_hint_probes = await _llm_hint_probes(
                target, baseline_status, baseline_text, combined_so_far, remaining
            )

        probes = combined_so_far + llm_hint_probes

        if not probes:
            logger.debug("BusinessLogic: no probes generated", url=target.url)
            return []

        logger.info(
            "BusinessLogic probes generated",
            url=target.url,
            deterministic=len(det_probes),
            response_informed=len(resp_probes),
            llm_hint=len(llm_hint_probes),
            total=len(probes),
            types=list({p["test_type"] for p in probes}),
        )

        # ── Step 3: Send all probes ────────────────────────────────────────
        # Fully parallel — probes are independent
        async def _run_probe(probe: Dict) -> Optional[tuple]:
            param_name = probe.get("param_name", "")
            param_location = probe.get("param_location", "body")
            probe_value_str = str(probe.get("probe_value", ""))
            if not param_name or not probe_value_str:
                return None
            is_det = probe.get("_deterministic", False)
            resp = await self._send_probe(
                target, client, param_name, param_location, probe_value_str,
                is_deterministic=is_det,
            )
            return (probe, resp) if resp is not None else None

        probe_results = await asyncio.gather(*[_run_probe(p) for p in probes])

        # ── Step 4: LLM evaluates each (baseline, probe) pair ─────────────
        # The LLM's ONLY job here: decide if a response difference confirms a vuln.
        # It does NOT choose what to test — that already happened above.
        findings: List[AgentFinding] = []

        for result in probe_results:
            if result is None:
                continue
            probe, probe_resp = result
            test_type = probe.get("test_type", "")
            param_name = probe.get("param_name", "")
            probe_value_str = str(probe.get("probe_value", ""))

            confirmed, title, severity, reasoning = await _llm_evaluate(
                probe, target, baseline_status, baseline_text,
                probe_resp.status_code, probe_resp.text,
            )
            if not confirmed:
                logger.debug(
                    "BusinessLogic probe not confirmed",
                    param=param_name, value=probe_value_str,
                    probe_status=probe_resp.status_code,
                )
                continue

            baseline_req, baseline_resp_text = _fmt_http_pair(baseline_resp)
            probe_req, probe_resp_text = _fmt_http_pair(probe_resp)
            findings.append(AgentFinding(
                title=title or f"Business Logic Flaw — {probe.get('description', test_type)}",
                severity=severity,
                cwe=_cwe_for_type(test_type),
                attack_type="business_logic",
                evidence=(
                    f"[{test_type}] '{param_name}' = {probe_value_str!r} — {reasoning}"
                ),
                payload=f"{param_name}={probe_value_str}",
                parameter=param_name,
                url=target.url,
                request_method=target.method,
                bypass_validation=False,
                reasoning=reasoning,
                raw_request=baseline_req,
                raw_response=baseline_resp_text,
                probe_request=probe_req,
                probe_response=probe_resp_text,
            ))

        return findings

    async def _send_probe(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        param_name: str,
        param_location: str,
        probe_value_str: str,
        is_deterministic: bool = True,
    ):
        """Build and send one probe request. Returns httpx.Response or None."""
        ct = target.headers.get("content-type", "")
        # Deterministic probes = code-driven = "scan" source tag
        # LLM-hinted probes    = context-aware but still code-sent = "agent" source tag
        src = "scan" if is_deterministic else "agent"

        if param_location == "query":
            probe_url = _inject_query(target.url, param_name, probe_value_str)
            return await _send(client, target.method, probe_url, target.headers, target.body, source=src)

        if param_location == "body_graphql":
            new_body = _inject_into_graphql_variables(
                target.body or "", param_name, probe_value_str
            )
        else:
            new_body = _inject_into_body(target.body or "", param_name, probe_value_str, ct)

        if new_body is None:
            return None

        return await _send(client, target.method, target.url, target.headers, new_body, source=src)


def _cwe_for_type(test_type: str) -> str:
    _CWE_MAP = {
        "numeric_boundary":    "CWE-840",
        "privilege_escalation": "CWE-269",
        "workflow_bypass":     "CWE-841",
        "mass_assignment":     "CWE-915",
    }
    return _CWE_MAP.get(test_type, "CWE-840")


from dast.ai.coordinator import Coordinator
Coordinator.register(BusinessLogicAgent)
