"""Rate-limit trust agent — XFF spoofing + path-normalization inconsistency.

Round 4-A, technique from ARTEX api-security (P8 "rate-limit trust confusion"):
many rate limiters key on ``X-Forwarded-For`` / ``X-Real-IP`` or on the raw
request path. If the edge TRUSTS those client-controlled inputs, the limiter
can be sidestepped; if path normalization is inconsistent (``/api`` vs ``/Api``
vs ``/api/``), per-path limiters see different keys for the same resource.

Honest-by-default detection (ARTEX discipline: the FINDING is the trust-boundary
mechanism — it is never demonstrated under load against the target):

- **XFF reflection**: the endpoint echoes the spoofed client IP back (directly
  or in an error/debug body) — proof the input reaches trust-sensitive code.
- **Path-normalization differential**: path variants return materially
  different statuses for the same resource (200 vs 404) — proof that
  path-keyed controls see different keys.

Low noise: 2 XFF probes + up to 3 path variants, always-on-low like
``sensitive_data``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional
from urllib.parse import urlparse, urlunparse

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.proxy.plugin_manager import log_event
from dast.scanners.active_checks import _fmt_http_pair, _send
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

logger = get_logger(__name__)

_SPOOF_IP = "203.0.113.7"  # TEST-NET-3 — never a real third party
_XFF_HEADERS = (
    ("x-forwarded-for", _SPOOF_IP),
    ("x-real-ip", _SPOOF_IP),
)


class RateLimitTrustAgent(VulnAgent):
    name = "Rate-Limit Trust Agent"
    attack_type = "rate_limit_trust"
    description = (
        "Rate-limit trust confusion: client-controlled XFF/X-Real-IP reaching "
        "responses, and path-normalization variants that defeat path-keyed controls"
    )

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        findings: List[AgentFinding] = []

        finding = await self._probe_xff_trust(target, client)
        if finding:
            findings.append(finding)

        finding = await self._probe_path_normalization(target, client)
        if finding:
            findings.append(finding)
            return findings
        return findings

    async def _probe_xff_trust(
        self, target: "CheckTarget", client: "httpx.AsyncClient"
    ) -> Optional[AgentFinding]:
        # One probe with BOTH headers (spoofing stacks commonly set them
        # together); reflection of the spoofed TEST-NET IP is the evidence.
        headers = {**target.headers,
                   _XFF_HEADERS[0][0]: _XFF_HEADERS[0][1],
                   _XFF_HEADERS[1][0]: _XFF_HEADERS[1][1]}
        resp = await _send(client, target.method, target.url, headers, target.body)
        if not resp:
            return None
        body = resp.text[:4000]
        # Confirmed only when the SPOOFED TEST-NET IP literal we injected is
        # reflected back — a generic phrase like "your ip"/"client address" is
        # not proof the client-controlled header reached trust-sensitive code.
        if _SPOOF_IP not in body:
            return None

        raw_req, raw_resp = _fmt_http_pair(resp)
        log_event("agent", "finding",
                  f"Rate-limit trust boundary on {target.url} (XFF reflected)",
                  url=target.url, finding="Rate-limit trust confusion", source="agent")
        return AgentFinding(
            title="Rate-Limit Trust Confusion — Client-Controlled XFF Reaches Application",
            severity="low",
            cwe="CWE-345",
            attack_type="rate_limit_trust",
            evidence=(
                "The endpoint reflects the client-supplied X-Forwarded-For / "
                "X-Real-IP values (" + _SPOOF_IP + "), meaning edge/proxy trust in "
                "these headers extends to the application. A rate limiter keyed on "
                "them can be sidestepped by rotating the header; on its own this is "
                "a trust-boundary finding, not demonstrated bypass.\n\n"
                f"Request:\n{raw_req}\n\nResponse:\n{raw_resp[:2000]}"
            ),
            confirmed=True,
            payload=f"{_XFF_HEADERS[0][0]}: {_SPOOF_IP}; {_XFF_HEADERS[1][0]}: {_SPOOF_IP}",
            parameter="x-forwarded-for",
            url=target.url,
            request_method=target.method,
            bypass_validation=False,
            raw_request=raw_req,
            raw_response=raw_resp[:2000],
        )

    async def _probe_path_normalization(
        self, target: "CheckTarget", client: "httpx.AsyncClient"
    ) -> Optional[AgentFinding]:
        # Baseline status first; a variant is only interesting when it answers
        # MATERIALLY differently (200 vs 404) for the same resource.
        baseline = await _send(client, target.method, target.url,
                               target.headers, target.body)
        if baseline is None:
            return None

        parsed = target.url.split("?", 1)
        base_path = parsed[0].rstrip("/")
        query = f"?{parsed[1]}" if len(parsed) > 1 else ""
        # Uppercase ONLY the path component — scheme+host must stay intact, or we
        # test host casing (HTTPS://EXAMPLE.COM) instead of path normalization.
        pu = urlparse(base_path)
        upper_variant = urlunparse(pu._replace(path=pu.path.upper()))
        variants = (f"{base_path}", f"{base_path}/", upper_variant)
        seen = {baseline.status_code}
        captured_path = parsed[0]
        for variant in variants:
            if variant == captured_path:
                continue  # identical to the captured request
            resp = await _send(client, target.method, variant + query,
                               target.headers, target.body)
            if resp is None:
                continue
            if resp.status_code in seen:
                continue
            # A path variant answering with a DIFFERENT status for the same
            # resource = normalization gap (one of them dodges path-keyed controls).
            raw_req, raw_resp = _fmt_http_pair(resp)
            log_event("agent", "finding",
                      f"Path normalization gap on {target.url} ({variant} → {resp.status_code})",
                      url=target.url, finding="Path normalization inconsistency",
                      source="agent")
            return AgentFinding(
                title="Rate-Limit Path Gap — Path Normalization Inconsistency",
                severity="low",
                cwe="CWE-436",
                attack_type="rate_limit_trust",
                evidence=(
                    f"Path variants of the same resource answer differently "
                    f"(baseline {baseline.status_code} vs '{variant}' → "
                    f"{resp.status_code}). Path-keyed rate limits or WAF rules see "
                    f"different keys for the same handler — the mechanism, not a "
                    f"demonstrated bypass.\n\n"
                    f"Request:\n{raw_req}\n\nResponse:\n{raw_resp[:2000]}"
                ),
                confirmed=False,
                payload=variant,
                parameter="path",
                url=target.url,
                request_method=target.method,
                bypass_validation=False,
                raw_request=raw_req,
                raw_response=raw_resp[:2000],
            )
        return None


from dast.ai.coordinator import Coordinator  # noqa: E402

Coordinator.register(RateLimitTrustAgent)
