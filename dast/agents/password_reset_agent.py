"""
Password Reset Bypass Agent — deterministic tests for auth flow logic flaws.

Targets endpoints identified as password reset/change flows (path contains
reset_password, change_password, forgot_password, etc.).  Never runs on
generic login or SSO endpoints.

Checks (all deterministic, no LLM calls):
1. Invalid token + valid email — does the server still reset the password?
2. Empty token + valid email — is the token field required?
3. Token param removed entirely — does the flow proceed without it?
4. Different email with same token — is the token bound to the email?

All findings go through the Red Team validator (bypass_validation=False)
unless the differential is unambiguous.
"""

from __future__ import annotations

import json
import re
import uuid
from typing import TYPE_CHECKING, Dict, List, Optional

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.proxy.plugin_manager import log_event
from dast.scanners.active_checks import _fmt_http_pair, _send
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

logger = get_logger(__name__)

_RESET_PATH_RE = re.compile(
    r'(reset.?password|change.?password|forgot.?password|password.?reset|'
    r'password.?change|auth.?password|auth.?reset|password.?update)',
    re.IGNORECASE,
)

_TOKEN_PARAM_RE = re.compile(
    r'(reset_password_token|reset_token|password_token|token|'
    r'confirmation_token|otp|code|verification_code)',
    re.IGNORECASE,
)

_EMAIL_PARAM_RE = re.compile(
    r'(email|e.?mail|user_email|username|login)',
    re.IGNORECASE,
)

_PASSWORD_PARAM_RE = re.compile(
    r'(password|new_password|passwd|confirmation|password_confirmation)',
    re.IGNORECASE,
)

_SUCCESS_CODES = frozenset({200, 201, 302, 303})
_REJECT_CODES = frozenset({400, 401, 403, 422, 429})

_SUCCESS_BODY_RE = re.compile(
    r'(redirect[Tt]o|"success"|"ok"|password.*changed|password.*updated|'
    r'password.*reset|signed.*in|logged.*in|"token"|"access_token")',
    re.IGNORECASE,
)

_REJECT_BODY_RE = re.compile(
    r'(invalid.*token|expired.*token|token.*invalid|token.*expired|'
    r'not.*found|unauthorized|forbidden|"error"|reset.*failed)',
    re.IGNORECASE,
)


def _is_reset_endpoint(target: "CheckTarget") -> bool:
    if _RESET_PATH_RE.search(target.url):
        return True
    if target.body and _TOKEN_PARAM_RE.search(target.body) and _PASSWORD_PARAM_RE.search(target.body):
        return True
    return False


def _parse_body(body: Optional[str]) -> Optional[Dict]:
    if not body:
        return None
    try:
        data = json.loads(body)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _find_param(data: Dict, pattern: re.Pattern) -> Optional[str]:
    for key in data:
        if pattern.search(key):
            return key
    return None


def _replace_param(body: str, param: str, new_value: str) -> str:
    try:
        data = json.loads(body)
        data[param] = new_value
        return json.dumps(data)
    except Exception:
        return body


def _remove_param(body: str, param: str) -> str:
    try:
        data = json.loads(body)
        data.pop(param, None)
        return json.dumps(data)
    except Exception:
        return body


def _response_looks_successful(status: int, body: str) -> bool:
    if status in _SUCCESS_CODES and _SUCCESS_BODY_RE.search(body):
        return True
    if status in _SUCCESS_CODES and not _REJECT_BODY_RE.search(body):
        return status in {200, 201}
    return False


def _response_looks_rejected(status: int, body: str) -> bool:
    if status in _REJECT_CODES:
        return True
    if _REJECT_BODY_RE.search(body):
        return True
    return False


class PasswordResetAgent(VulnAgent):
    name = "Password Reset Bypass Agent"
    attack_type = "password_reset"
    description = (
        "Tests password reset/change endpoints for token validation bypass, "
        "email-token binding, and parameter removal bypass. Deterministic checks."
    )

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        findings: List[AgentFinding] = []
        log_event(
            "password_reset", "info",
            f"Password Reset agent started — {target.method} {target.url}",
            url=target.url, source="agent",
        )

        if not _is_reset_endpoint(target):
            logger.debug("Password Reset agent: not a reset endpoint", url=target.url)
            return findings

        data = _parse_body(target.body)
        if data is None:
            logger.debug("Password Reset agent: no JSON body", url=target.url)
            return findings

        token_param = _find_param(data, _TOKEN_PARAM_RE)
        email_param = _find_param(data, _EMAIL_PARAM_RE)
        password_param = _find_param(data, _PASSWORD_PARAM_RE)

        if not token_param:
            logger.debug("Password Reset agent: no token param found", url=target.url)
            return findings

        logger.info("Password Reset agent: testing",
                     url=target.url, token_param=token_param,
                     email_param=email_param, password_param=password_param)

        baseline = await _send(client, target.method, target.url, target.headers, target.body)
        if baseline is None:
            return findings

        baseline_success = _response_looks_successful(baseline.status_code, baseline.text)
        baseline_rejected = _response_looks_rejected(baseline.status_code, baseline.text)
        baseline_req, baseline_resp = _fmt_http_pair(baseline)

        canary_password = f"DastCanary-{uuid.uuid4().hex[:8]}!1A"

        test_cases = self._build_test_cases(
            target, data, token_param, email_param, password_param, canary_password,
        )

        for test in test_cases:
            resp = await _send(
                client, target.method, target.url, target.headers, test["body"],
            )
            if resp is None:
                continue

            probe_success = _response_looks_successful(resp.status_code, resp.text)
            probe_req, probe_resp = _fmt_http_pair(resp)

            bypass_detected = False
            if baseline_success and probe_success:
                if resp.status_code == baseline.status_code:
                    bypass_detected = True
            elif baseline_rejected and probe_success:
                bypass_detected = True

            if bypass_detected:
                findings.append(AgentFinding(
                    title=f"Password Reset Bypass: {test['title']}",
                    severity="critical",
                    cwe="CWE-640",
                    attack_type="password_reset",
                    evidence=(
                        f"{test['description']}. "
                        f"Baseline: HTTP {baseline.status_code}. "
                        f"Probe: HTTP {resp.status_code} with body length {len(resp.text)}. "
                        f"Both responses indicate success, meaning the token was not validated."
                    ),
                    payload=test["body"],
                    parameter=test["param"],
                    url=target.url,
                    request_method=target.method,
                    confirmed=False,
                    bypass_validation=False,
                    raw_request=baseline_req,
                    raw_response=baseline_resp,
                    probe_request=probe_req,
                    probe_response=probe_resp,
                ))
                log_event(
                    "password_reset", "finding",
                    f"Password Reset bypass candidate: {test['title']} on {target.url}",
                    url=target.url, source="agent",
                )

        return findings

    def _build_test_cases(
        self,
        target: "CheckTarget",
        data: Dict,
        token_param: str,
        email_param: Optional[str],
        password_param: Optional[str],
        canary_password: str,
    ) -> List[Dict]:
        tests: List[Dict] = []
        body = target.body or "{}"

        mutated = _replace_param(body, token_param, "invalidtoken_" + uuid.uuid4().hex[:8])
        if password_param:
            mutated = _replace_param(mutated, password_param, canary_password)
        tests.append({
            "title": "Invalid token accepted",
            "description": f"Sent request with {token_param}=invalidtoken_* (fabricated value)",
            "body": mutated,
            "param": token_param,
        })

        mutated = _replace_param(body, token_param, "")
        if password_param:
            mutated = _replace_param(mutated, password_param, canary_password)
        tests.append({
            "title": "Empty token accepted",
            "description": f"Sent request with {token_param}='' (empty string)",
            "body": mutated,
            "param": token_param,
        })

        mutated = _remove_param(body, token_param)
        if password_param:
            mutated = _replace_param(mutated, password_param, canary_password)
        tests.append({
            "title": "Token parameter removed",
            "description": f"Sent request without {token_param} parameter entirely",
            "body": mutated,
            "param": token_param,
        })

        if email_param and data.get(email_param):
            original_email = data[email_param]
            fake_email = f"dast-canary-{uuid.uuid4().hex[:6]}@test.invalid"
            mutated = _replace_param(body, email_param, fake_email)
            if password_param:
                mutated = _replace_param(mutated, password_param, canary_password)
            tests.append({
                "title": "Different email with same token",
                "description": (
                    f"Sent request with {email_param}={fake_email} "
                    f"(original: {original_email}) to test email-token binding"
                ),
                "body": mutated,
                "param": email_param,
            })

        return tests


from dast.ai.coordinator import Coordinator  # noqa: E402
Coordinator.register(PasswordResetAgent)
