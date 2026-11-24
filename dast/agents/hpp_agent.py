"""HPP agent — HTTP Parameter Pollution via duplicated parameters.

Round 4-A, technique from ARTEX api-security (``?role=user&role=admin``): send
a security-relevant parameter TWICE with an escalated second value and detect
the differential. Many stacks take the LAST occurrence (PHP/Rails) while
validation layers validate the FIRST — pollution is the gap between those two
readings. Detection is honest-by-default: a finding requires the escalated
canary value to be REFLECTED or the response to materially change versus the
single-value baseline; nothing is inferred from status-code noise alone.

Only parameters whose NAME looks authorization-relevant are probed
(``role|admin|priv|is_|level|debug``), and the escalated value is a benign
canary string — never a real privilege grant (``role=admin``-style escalation
against a live target WOULD be a real privilege change, so the canary is an
observability probe, not a takeover).
"""

from __future__ import annotations

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

_PARAM_NAME_RE = re.compile(r"role|admin|priv|is_|level|debug|user_type|access", re.IGNORECASE)
_CANARY = "dast-hpp-check"

# Escalated values that are OBSERVABLE but harmless: a canary marker and an
# obviously-inert flag. No "admin"/"true" grants are ever sent.
_ESCALATIONS = (
    _CANARY,
    "1",
)


class HppAgent(VulnAgent):
    name = "HPP Agent"
    attack_type = "hpp"
    description = (
        "HTTP Parameter Pollution: duplicated security-relevant parameters with "
        "an escalated canary value, detected by reflection or response differential"
    )

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        findings: List[AgentFinding] = []

        probe_params = [
            p for p in (target.params or [])
            if p.get("name") and _PARAM_NAME_RE.search(p["name"])
            and p.get("location") in ("query", "body", None, "")
        ]
        if not probe_params:
            return findings

        for param in probe_params[:4]:
            name = param["name"]
            original = str(param.get("value", ""))
            finding = await self._probe_param(target, client, name, original)
            if finding:
                findings.append(finding)
                return findings
        return findings

    async def _probe_param(self, target: "CheckTarget", client: "httpx.AsyncClient",
                           name: str, original: str) -> Optional[AgentFinding]:
        # Baseline: the request as captured (single occurrence).
        baseline = await _send(client, target.method, target.url,
                               target.headers, target.body)
        if baseline is None:
            return None
        baseline_body = baseline.text[:4000]

        for escalation in _ESCALATIONS:
            # BOTH occurrences reach the server: the legit pair first, the
            # escalated duplicate second (last-occurrence stacks are the common
            # consumer side of the pollution gap).
            sep = "&" if "?" in target.url else "?"
            polluted_url = f"{target.url}{sep}{name}={original or ''}&{name}={escalation}"
            duplicated = f"{original}&{name}={escalation}" if original else f"{name}={escalation}"
            resp = await _send(client, target.method, polluted_url,
                               target.headers, target.body,
                               payload=duplicated[:100])
            if resp is None:
                continue

            body = resp.text[:4000]
            reflected = _CANARY in body and _CANARY not in baseline_body
            materially_different = (
                resp.status_code != baseline.status_code
                or abs(len(body) - len(baseline_body)) > 200
            )
            if not (reflected or materially_different):
                continue

            raw_req, raw_resp = _fmt_http_pair(resp)
            how = "reflected in the response" if reflected else \
                f"response changed vs single-value baseline (status {baseline.status_code}→{resp.status_code}, body size delta)"
            log_event("agent", "finding",
                      f"HPP differential on {target.url} ({name})",
                      url=target.url, finding="HTTP Parameter Pollution", source="agent")
            return AgentFinding(
                title="HTTP Parameter Pollution — Duplicate Parameter Handled Inconsistently",
                severity="medium",
                cwe="CWE-436",
                attack_type="hpp",
                evidence=(
                    f"Sending parameter '{name}' twice ({original!r} + {escalation!r}) "
                    f"produced a different result than the single-value request: the "
                    f"escalated value was {how}. Validation and consumption layers "
                    f"read different occurrences — the classic pollution gap.\n\n"
                    f"Request:\n{raw_req}\n\nResponse:\n{raw_resp[:2000]}"
                ),
                confirmed=bool(reflected),
                payload=f"{name}={duplicated}",
                parameter=name,
                url=target.url,
                request_method=target.method,
                bypass_validation=False,
                raw_request=raw_req,
                raw_response=raw_resp[:2000],
            )
        return None


from dast.ai.coordinator import Coordinator  # noqa: E402

Coordinator.register(HppAgent)
