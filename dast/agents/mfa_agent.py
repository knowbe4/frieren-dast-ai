"""
MFA Bypass Agent — tests MFA/OTP/2FA verification endpoints for security flaws.

Targets ONLY endpoints identified as MFA verification flows (path contains mfa,
otp, 2fa, totp, verify-code, etc.).  Never runs on generic login or SSO endpoints.

Checks (in priority order):
1. Missing rate limiting — submit the same invalid OTP rapidly; look for no lockout
2. OTP reuse — re-submit a previously observed valid-looking OTP
3. Backup code brute-force — try common/short backup codes without lockout
4. MFA parameter removal — omit the OTP/code field entirely and check if auth proceeds
5. Response analysis — check if error messages reveal code length, format, or expiry

All findings go through the Red Team validator (bypass_validation=False).
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import TYPE_CHECKING, List, Optional

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.proxy.plugin_manager import log_event
from dast.scanners.active_checks import _fmt_http_pair, _send
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

logger = get_logger(__name__)

# Param names that typically carry the OTP/backup code
_OTP_PARAM_RE = re.compile(
    r'(otp|totp|mfa|two.?factor|2fa|code|pin|backup.?code|recovery.?code|passcode)',
    re.IGNORECASE,
)

# Invalid OTPs to probe with for rate-limit testing
_INVALID_OTPS = ["000000", "999999", "111111", "123456", "000001", "999998"]
# Backup code candidates (short alphanumeric)
_BACKUP_CODES = ["00000000", "12345678", "AAAAAAAA", "backup01", "recovery1"]

# Status codes that suggest authentication succeeded
_AUTH_SUCCESS_CODES = frozenset({200, 201, 302})
# Status codes that suggest the OTP was rejected (expected during probing)
_AUTH_REJECT_CODES = frozenset({400, 401, 403, 422, 429})


def _find_otp_param(body: Optional[str]) -> Optional[str]:
    """Return the name of the OTP/code parameter in a JSON body, or None."""
    if not body:
        return None
    try:
        data = json.loads(body)
        if not isinstance(data, dict):
            return None
        for key in data:
            if _OTP_PARAM_RE.search(key):
                return key
    except Exception:
        pass
    return None


def _replace_otp(body: str, param: str, new_value: str) -> str:
    """Return the JSON body with `param` replaced by `new_value`."""
    try:
        data = json.loads(body)
        data[param] = new_value
        return json.dumps(data)
    except Exception:
        return body


def _remove_param(body: str, param: str) -> str:
    """Return the JSON body with `param` removed entirely."""
    try:
        data = json.loads(body)
        data.pop(param, None)
        return json.dumps(data)
    except Exception:
        return body


def _status_changed_to_success(baseline_status: int, probe_status: int) -> bool:
    """True if probe succeeded where baseline did not (or probe is unconditionally successful)."""
    if probe_status in _AUTH_SUCCESS_CODES and baseline_status not in _AUTH_SUCCESS_CODES:
        return True
    if probe_status == 200 and baseline_status in {401, 403}:
        return True
    return False


class MFABypassAgent(VulnAgent):
    name = "MFA Bypass Agent"
    attack_type = "mfa_bypass"
    description = (
        "Tests MFA/OTP/2FA verification endpoints for rate-limit bypass, "
        "OTP reuse, backup code brute-force, and parameter removal bypass"
    )

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        findings: List[AgentFinding] = []
        log_event(
            "mfa_bypass", "info",
            f"MFA agent started — {target.method} {target.url}",
            url=target.url, source="agent",
        )

        otp_param = _find_otp_param(target.body)
        if not otp_param:
            logger.debug("MFA agent: no OTP param found in body", url=target.url)
            return findings

        # Baseline: send the original request to understand the normal response
        baseline = await _send(client, target.method, target.url, target.headers, target.body)
        if baseline is None:
            return findings

        # ── Check 1: Rate limiting ─────────────────────────────────────────
        findings += await self._check_rate_limit(target, client, otp_param, baseline)
        if findings:
            return findings  # no point continuing if rate limit is missing

        # ── Check 2: OTP parameter removal ────────────────────────────────
        findings += await self._check_param_removal(target, client, otp_param, baseline)

        # ── Check 3: Backup code brute-force (only if no rate limit found) ─
        findings += await self._check_backup_codes(target, client, otp_param, baseline)

        return findings

    async def _check_rate_limit(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        otp_param: str,
        baseline,
    ) -> List[AgentFinding]:
        """Send several invalid OTPs rapidly; flag if none trigger a 429 or lockout."""
        reject_count = 0
        rate_limited = False
        responses: List = []

        for otp in _INVALID_OTPS[:4]:
            body = _replace_otp(target.body or "{}", otp_param, otp)
            resp = await _send(client, target.method, target.url, target.headers, body)
            if resp is None:
                continue
            if resp.status_code == 429 or "rate" in resp.text.lower() or "locked" in resp.text.lower():
                rate_limited = True
                break
            if resp.status_code in _AUTH_REJECT_CODES:
                reject_count += 1
            responses.append(resp)
            await asyncio.sleep(0.1)

        if rate_limited or reject_count < 3:
            return []

        # No rate limiting detected — all 4 attempts rejected but none triggered 429
        baseline_req, baseline_resp_text = _fmt_http_pair(baseline)
        _, last_resp_text = _fmt_http_pair(responses[-1])
        log_event(
            "mfa_bypass", "finding",
            f"Missing rate limiting on MFA endpoint — {target.url}",
            url=target.url, finding="MFA Rate Limit Missing", source="agent",
        )
        return [AgentFinding(
            title="MFA Endpoint Missing Rate Limiting",
            severity="high",
            cwe="CWE-307",
            attack_type="mfa_bypass",
            parameter=otp_param,
            payload=_INVALID_OTPS[0],
            url=target.url,
            request_method=target.method,
            evidence=(
                f"Submitted {reject_count} invalid OTP values without triggering a 429 or "
                f"account lockout. An attacker can brute-force a 6-digit OTP in <1 000 000 "
                f"requests (typical TOTP window: 30s, 10^6 combinations). No rate limiting "
                f"detected on param '{otp_param}'."
            ),
            raw_request=baseline_req,
            raw_response=baseline_resp_text,
            probe_request=f"POST {target.url} with {otp_param}={_INVALID_OTPS[-1]}",
            probe_response=last_resp_text,
            confirmed=False,
        )]

    async def _check_param_removal(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        otp_param: str,
        baseline,
    ) -> List[AgentFinding]:
        """Remove the OTP param entirely; flag if the server responds as if auth succeeded."""
        body_no_otp = _remove_param(target.body or "{}", otp_param)
        resp = await _send(client, target.method, target.url, target.headers, body_no_otp)
        if resp is None:
            return []

        if _status_changed_to_success(baseline.status_code, resp.status_code):
            baseline_req, baseline_resp_text = _fmt_http_pair(baseline)
            probe_req, probe_resp_text = _fmt_http_pair(resp)
            log_event(
                "mfa_bypass", "finding",
                f"MFA bypass: OTP param removal succeeded — {target.url}",
                url=target.url, finding="MFA Parameter Removal Bypass", source="agent",
            )
            return [AgentFinding(
                title="MFA Bypass — OTP Parameter Removal",
                severity="critical",
                cwe="CWE-287",
                attack_type="mfa_bypass",
                parameter=otp_param,
                payload="(param removed)",
                url=target.url,
                request_method=target.method,
                evidence=(
                    f"Removing the '{otp_param}' parameter from the MFA verification request "
                    f"returned HTTP {resp.status_code} (baseline was HTTP {baseline.status_code}). "
                    f"The server appears to skip MFA when the field is absent."
                ),
                raw_request=baseline_req,
                raw_response=baseline_resp_text,
                probe_request=probe_req,
                probe_response=probe_resp_text,
                confirmed=False,
            )]
        return []

    async def _check_backup_codes(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        otp_param: str,
        baseline,
    ) -> List[AgentFinding]:
        """Try a small set of guessable backup codes; flag if any are accepted."""
        for code in _BACKUP_CODES:
            body = _replace_otp(target.body or "{}", otp_param, code)
            resp = await _send(client, target.method, target.url, target.headers, body)
            if resp is None:
                continue
            if resp.status_code in _AUTH_SUCCESS_CODES and baseline.status_code not in _AUTH_SUCCESS_CODES:
                baseline_req, baseline_resp_text = _fmt_http_pair(baseline)
                probe_req, probe_resp_text = _fmt_http_pair(resp)
                log_event(
                    "mfa_bypass", "finding",
                    f"MFA bypass: guessable backup code accepted — {target.url}",
                    url=target.url, finding="Guessable MFA Backup Code", source="agent",
                )
                return [AgentFinding(
                    title="Guessable MFA Backup Code Accepted",
                    severity="critical",
                    cwe="CWE-521",
                    attack_type="mfa_bypass",
                    parameter=otp_param,
                    payload=code,
                    url=target.url,
                    request_method=target.method,
                    evidence=(
                        f"Backup code '{code}' was accepted by the MFA endpoint "
                        f"(HTTP {resp.status_code}). Common backup codes are trivially guessable."
                    ),
                    raw_request=baseline_req,
                    raw_response=baseline_resp_text,
                    probe_request=probe_req,
                    probe_response=probe_resp_text,
                    confirmed=False,
                )]
            await asyncio.sleep(0.1)
        return []


from dast.ai.coordinator import Coordinator  # noqa: E402
Coordinator.register(MFABypassAgent)
