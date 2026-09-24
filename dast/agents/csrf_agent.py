"""
CSRF Agent — detects missing or bypassable CSRF protection on state-changing endpoints.

Checks:
1. Token removal — omit CSRF token param/header and see if request still succeeds
2. Token swap — replace CSRF token with a random value and see if accepted
3. Token header removal — strip a CSRF token header and see if accepted
4. Tokenless cookie-authenticated request — flag only when ALL affirmative CSRF
   preconditions hold (ambient cookie auth + no token + no SameSite=Strict/Lax +
   server ignores Origin/Referer). The cross-origin probe rules OUT Origin/Referer
   defense; it is never treated as positive evidence on its own.

Targets: POST/PUT/PATCH/DELETE requests with form bodies or JSON bodies.
CSRF on JSON endpoints is real when the server accepts text/plain content-type
or lacks CORS restrictions.

bypass_validation=False — all findings go through the Red Team validator.
"""

from __future__ import annotations

import re
import secrets
from typing import TYPE_CHECKING, List, Optional

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.scanners.active_checks import _fmt_http_pair, _send
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

logger = get_logger(__name__)

# CSRF token parameter/header names to detect
_CSRF_PARAM_RE = re.compile(
    r'csrf|xsrf|_token|authenticity_token|anti.?forgery|request.?verification',
    re.IGNORECASE,
)
_CSRF_HEADER_RE = re.compile(
    r'x-csrf-token|x-xsrf-token|x-requested-with|x-request-token',
    re.IGNORECASE,
)

_STATE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Response status codes that indicate a successful request (not rejected)
_SUCCESS_CODES = frozenset({200, 201, 202, 204})

# How similar must the stripped response be to the baseline to call it accepted?
# We measure the ratio of response lengths. If it's within 30% and both are 2xx,
# we consider the CSRF protection absent.
_SIMILARITY_RATIO = 0.70


def _responses_similar(baseline_status: int, baseline_len: int,
                        probe_status: int, probe_len: int) -> bool:
    """Return True if the probe response looks like it was accepted, not rejected."""
    if probe_status not in _SUCCESS_CODES:
        return False
    if baseline_status not in _SUCCESS_CODES:
        return False
    if baseline_len == 0:
        return probe_len == 0
    ratio = probe_len / baseline_len if baseline_len > 0 else 0.0
    return ratio >= _SIMILARITY_RATIO


def _find_csrf_params(target: "CheckTarget") -> List[str]:
    """Return parameter names that look like CSRF tokens."""
    return [
        p["name"] for p in target.params
        if _CSRF_PARAM_RE.search(p["name"])
    ]


def _find_csrf_headers(target: "CheckTarget") -> List[str]:
    """Return header names that look like CSRF tokens."""
    return [
        k for k in target.headers
        if _CSRF_HEADER_RE.search(k)
    ]


def _request_carries_cookie_auth(target: "CheckTarget") -> bool:
    """True when the request carries an ambient cookie credential. CSRF is only
    exploitable against cookie-borne authority: a forged cross-site request cannot
    read or attach a header/bearer token, so a tokenless header-authenticated API
    is NOT CSRF-susceptible. Gating on this eliminates the false positive of
    flagging every tokenless state-changing endpoint."""
    for name, value in (target.headers or {}).items():
        if name.lower() == "cookie" and str(value).strip():
            return True
    shared = getattr(target, "shared_cookies", None)
    return bool(shared)


def _samesite_protects(resp: "httpx.Response") -> bool:
    """True when a Set-Cookie in this response marks a cookie SameSite=Strict or
    Lax — the browser then withholds it on cross-site requests, mitigating CSRF.
    Best-effort: the session cookie is usually not re-set on a state-changing
    request, so an unknown SameSite is treated as unprotected (proceed)."""
    try:
        headers = resp.headers
        get_list = getattr(headers, "get_list", None)
        if callable(get_list):
            set_cookies = get_list("set-cookie")
        else:
            raw = headers.get("set-cookie", "") if hasattr(headers, "get") else ""
            set_cookies = [raw] if raw else []
    except Exception as exc:
        logger.debug("CSRF SameSite parse skipped", error=str(exc))
        return False
    for cookie in set_cookies:
        if re.search(r"samesite\s*=\s*(strict|lax)", str(cookie), re.IGNORECASE):
            return True
    return False


def _remove_param_from_body(body: str, param: str) -> str:
    """Remove a JSON or form field from a request body."""
    if not body:
        return body
    # JSON body
    try:
        import json as _json
        data = _json.loads(body)
        if isinstance(data, dict) and param in data:
            data_copy = dict(data)
            del data_copy[param]
            return _json.dumps(data_copy)
    except Exception as exc:
        logger.debug("failed to remove param from JSON body; falling back to form parsing", param=param, error=str(exc))
    # Form body
    pairs = [(k, v) for part in body.split("&") if "=" in part
             for k, v in [part.split("=", 1)] if k != param]
    return "&".join(f"{k}={v}" for k, v in pairs)


def _replace_param_in_body(body: str, param: str, value: str) -> str:
    """Replace a JSON or form field value in a request body."""
    if not body:
        return body
    try:
        import json as _json
        data = _json.loads(body)
        if isinstance(data, dict):
            data_copy = dict(data)
            data_copy[param] = value
            return _json.dumps(data_copy)
    except Exception as exc:
        logger.debug("failed to replace param in JSON body; falling back to form parsing", param=param, error=str(exc))
    pairs = []
    for part in body.split("&"):
        if "=" in part:
            k, _, v = part.partition("=")
            pairs.append(f"{k}={value if k == param else v}")
    return "&".join(pairs)


class CsrfAgent(VulnAgent):
    name = "CSRF Agent"
    attack_type = "csrf"
    description = (
        "Detects missing or bypassable CSRF protection on state-changing endpoints "
        "by removing or swapping CSRF tokens and testing cross-origin Origin headers."
    )

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        if target.method not in _STATE_METHODS:
            return []

        findings: List[AgentFinding] = []

        # Baseline request
        baseline_resp = await _send(
            client, target.method, target.url, target.headers, target.body
        )
        if baseline_resp is None:
            return []

        baseline_status = baseline_resp.status_code
        baseline_len = len(baseline_resp.content)

        # ── Check 1: CSRF token removal from params ────────────────────────
        csrf_params = _find_csrf_params(target)
        for param_name in csrf_params:
            stripped_body = _remove_param_from_body(target.body or "", param_name)
            probe_resp = await _send(
                client, target.method, target.url, target.headers, stripped_body
            )
            if probe_resp is None:
                continue
            if _responses_similar(baseline_status, baseline_len,
                                   probe_resp.status_code, len(probe_resp.content)):
                baseline_req, baseline_resp_text = _fmt_http_pair(baseline_resp)
                probe_req, probe_resp_text = _fmt_http_pair(probe_resp)
                findings.append(AgentFinding(
                    title="CSRF — Token Removal Accepted",
                    severity="high",
                    cwe="CWE-352",
                    attack_type="csrf",
                    evidence=(
                        f"Removing CSRF parameter '{param_name}' from the request body "
                        f"still returned {probe_resp.status_code} (baseline: {baseline_status}). "
                        f"The server does not enforce CSRF token presence."
                    ),
                    payload=f"(omit {param_name})",
                    parameter=param_name,
                    url=target.url,
                    request_method=target.method,
                    bypass_validation=False,
                    raw_request=baseline_req,
                    raw_response=baseline_resp_text,
                    probe_request=probe_req,
                    probe_response=probe_resp_text,
                ))
                break  # one finding per endpoint is enough

        # ── Check 2: CSRF token replacement with random value ──────────────
        if not findings:
            for param_name in csrf_params:
                fake_token = secrets.token_hex(16)
                swapped_body = _replace_param_in_body(target.body or "", param_name, fake_token)
                probe_resp = await _send(
                    client, target.method, target.url, target.headers, swapped_body
                )
                if probe_resp is None:
                    continue
                if _responses_similar(baseline_status, baseline_len,
                                       probe_resp.status_code, len(probe_resp.content)):
                    baseline_req, baseline_resp_text = _fmt_http_pair(baseline_resp)
                    probe_req, probe_resp_text = _fmt_http_pair(probe_resp)
                    findings.append(AgentFinding(
                        title="CSRF — Random Token Accepted",
                        severity="high",
                        cwe="CWE-352",
                        attack_type="csrf",
                        evidence=(
                            f"Replacing CSRF parameter '{param_name}' with a random value "
                            f"'{fake_token[:16]}...' still returned {probe_resp.status_code}. "
                            f"The server does not validate the CSRF token value."
                        ),
                        payload=f"{param_name}={fake_token[:16]}...",
                        parameter=param_name,
                        url=target.url,
                        request_method=target.method,
                        bypass_validation=False,
                        raw_request=baseline_req,
                        raw_response=baseline_resp_text,
                        probe_request=probe_req,
                        probe_response=probe_resp_text,
                    ))
                    break

        # ── Check 3: CSRF token removal from headers ───────────────────────
        csrf_headers = _find_csrf_headers(target)
        for header_name in csrf_headers:
            stripped_headers = {k: v for k, v in target.headers.items()
                                 if k.lower() != header_name.lower()}
            probe_resp = await _send(
                client, target.method, target.url, stripped_headers, target.body
            )
            if probe_resp is None:
                continue
            if _responses_similar(baseline_status, baseline_len,
                                   probe_resp.status_code, len(probe_resp.content)):
                baseline_req, baseline_resp_text = _fmt_http_pair(baseline_resp)
                probe_req, probe_resp_text = _fmt_http_pair(probe_resp)
                findings.append(AgentFinding(
                    title="CSRF — Token Header Removal Accepted",
                    severity="high",
                    cwe="CWE-352",
                    attack_type="csrf",
                    evidence=(
                        f"Removing CSRF header '{header_name}' still returned "
                        f"{probe_resp.status_code} (baseline: {baseline_status}). "
                        f"The server does not enforce CSRF token header."
                    ),
                    payload=f"(omit {header_name} header)",
                    parameter=header_name,
                    url=target.url,
                    request_method=target.method,
                    bypass_validation=False,
                    raw_request=baseline_req,
                    raw_response=baseline_resp_text,
                    probe_request=probe_req,
                    probe_response=probe_resp_text,
                ))
                break

        # ── Check 4: Tokenless cookie-authenticated state-changing request ──
        # CSRF is exploitable only when a forged cross-site request rides an
        # ambient cookie credential the browser attaches automatically. So this
        # fires only when EVERY affirmative precondition holds — never on the mere
        # fact that a forged Origin header returned 200 (servers do not defend CSRF
        # by inspecting Origin, so that alone false-positives on protected apps):
        #   - no anti-CSRF token in params or headers (checks 1-3 found none), AND
        #   - the request is authenticated by an ambient cookie (no cookie -> a
        #     forged request carries no authority -> not exploitable), AND
        #   - the session cookie is not SameSite=Strict/Lax (else withheld
        #     cross-site), AND
        #   - the state-changing request is actually accepted (2xx), AND
        #   - the server does not validate Origin/Referer. The cross-origin probe
        #     is used here to RULE OUT Origin/Referer defense (a rejected forged
        #     Origin proves protection), never as positive evidence.
        if (not csrf_params and not csrf_headers and not findings
                and _request_carries_cookie_auth(target)
                and baseline_status in _SUCCESS_CODES
                and not _samesite_protects(baseline_resp)):
            cross_origin_headers = {
                **target.headers,
                "Origin": "https://evil.example.com",
                "Referer": "https://evil.example.com/attack.html",
            }
            probe_resp = await _send(
                client, target.method, target.url, cross_origin_headers, target.body
            )
            # A forged Origin that is REJECTED (dissimilar/blocked) means the server
            # enforces Origin/Referer checking -> CSRF-protected -> no finding.
            if probe_resp is not None and _responses_similar(
                baseline_status, baseline_len,
                probe_resp.status_code, len(probe_resp.content),
            ):
                baseline_req, baseline_resp_text = _fmt_http_pair(baseline_resp)
                probe_req, probe_resp_text = _fmt_http_pair(probe_resp)
                findings.append(AgentFinding(
                    title="CSRF — Cookie-Authenticated State Change Without Token or SameSite",
                    severity="medium",
                    cwe="CWE-352",
                    attack_type="csrf",
                    evidence=(
                        f"State-changing {target.method} is authenticated by an ambient "
                        f"cookie, carries no anti-CSRF token, its session cookie is not "
                        f"SameSite=Strict/Lax, and the server does not validate "
                        f"Origin/Referer (a forged cross-origin request still returned "
                        f"{probe_resp.status_code}). A cross-site page can forge this "
                        f"request with the victim's cookie."
                    ),
                    payload="(no CSRF token; cross-site forgeable)",
                    parameter="(request)",
                    url=target.url,
                    request_method=target.method,
                    bypass_validation=False,
                    raw_request=baseline_req,
                    raw_response=baseline_resp_text,
                    probe_request=probe_req,
                    probe_response=probe_resp_text,
                ))

        return findings


from dast.ai.coordinator import Coordinator
Coordinator.register(CsrfAgent)
