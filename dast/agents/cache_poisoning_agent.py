"""
Web cache-poisoning agent — detects unkeyed request inputs (headers) that are
reflected into a cacheable response, so an attacker can poison the shared cache.

Technique (deterministic, low-FP):
  1. Only runs on cacheable GET-style responses. If the baseline response is
     explicitly non-cacheable (Cache-Control: no-store/private and no cache
     indicator header), the agent bails immediately — no noise.
  2. For each candidate unkeyed header, send request #1 carrying the header with
     a UNIQUE marker against a UNIQUE cache-buster URL. If the marker reflects
     into the response (body or a redirect/link header), the header is a
     reflected input.
  3. Confirm the input is UNKEYED (the real cache-poisoning proof): send request
     #2 to the SAME cache-buster URL WITHOUT the header. If the marker still
     appears, the malicious response was served from cache -> the cache key does
     not include the header -> confirmed cache poisoning.

Safety:
  * Every probe uses a UNIQUE random cache-buster query parameter, so we only
    ever poison a cache key that WE alone request — never the real page other
    users would be served. This keeps the blast radius to our own synthetic URL.
  * EVERY built URL is gated through ``ProxySettings.is_in_scope()`` before any
    request (via the shared ``active_checks`` path) and the agent only mutates
    request headers + adds its own cache-buster param — it never sends a
    destructive request.
  * Reuses ``active_checks._client()/_send()`` so probes are proxy-routed,
    rate-limited, and circuit-broken.
"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING, List, Optional
from urllib.parse import urlparse

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.ai.coordinator import Coordinator
from dast.payloads.loader import get_value
from dast.proxy.plugin_manager import log_event
from dast.scanners.active_checks import _fmt_http_pair, _inject_query, _send
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

logger = get_logger(__name__)

# Header names whose reflected value would be a redirect/link target — checked
# in addition to the body because cache poisoning frequently lands in these.
_REFLECTION_HEADERS = ("location", "content-location", "link", "refresh")

# Cache-Control tokens that positively indicate the response is cacheable by a
# SHARED cache — the only place cache poisoning is exploitable. `max-age` alone
# on a private response is not enough; we require a public/shared directive.
_CACHEABLE_SIGNALS = ("public", "s-maxage")


def _unique_marker() -> str:
    """A per-probe token that cannot collide with another probe's marker."""
    return f"dastcp{random.randint(10000000, 99999999)}q"


def _cache_buster_url(url: str) -> str:
    """Append a unique cache-buster query param so this probe owns its own key."""
    return _inject_query(url, f"dastcb{random.randint(10000000, 99999999)}", "1")


def _is_cacheable(resp: "httpx.Response", indicator_headers: List[str],
                  non_cacheable_signals: List[str]) -> bool:
    """
    Require POSITIVE evidence that a SHARED cache is in play before probing —
    otherwise the agent sprays unkeyed-header payloads at every endpoint (e.g. a
    301/302 with no caching whatsoever), which is pure noise, not signal.

    Cacheable only when one of:
      * a cache-indicator header is present (x-cache, cf-cache-status, age, ...)
        — proof a cache actually served/handled this response, OR
      * Cache-Control carries a shared-cache directive (public / s-maxage).

    A redirect (3xx) or an explicit no-store/private response is never treated
    as cacheable. Defaulting to "cacheable unless opted out" was the bug.
    """
    if resp.status_code in (301, 302, 303, 307, 308):
        return False
    lowered = {k.lower(): v for k, v in resp.headers.items()}
    if any(h in lowered for h in indicator_headers):
        return True
    cache_control = lowered.get("cache-control", "").lower()
    if any(sig in cache_control for sig in non_cacheable_signals):
        return False
    return any(sig in cache_control for sig in _CACHEABLE_SIGNALS)


def _marker_reflected(resp: "httpx.Response", marker: str) -> bool:
    """True if the marker appears in the response body or a link/redirect header."""
    for header_name in _REFLECTION_HEADERS:
        if marker in resp.headers.get(header_name, ""):
            return True
    try:
        return marker in resp.text
    except Exception:
        return False


class CachePoisoningAgent(VulnAgent):
    name = "Cache Poisoning Agent"
    attack_type = "cache_poisoning"
    description = "Detects unkeyed request headers reflected into a cacheable response"

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        # Cache poisoning is a GET-side concern — POST/PUT responses are not cached.
        if target.method.upper() != "GET":
            return []

        headers_spec = get_value("cache_poisoning", "payloads", {}) or {}
        unkeyed_headers = headers_spec.get("unkeyed_headers", []) or []
        if not unkeyed_headers:
            return []

        indicator_headers = [
            h.lower() for h in (get_value("cache_poisoning", "cache_indicator_headers", []) or [])
        ]
        non_cacheable_signals = [
            s.lower() for s in (get_value("cache_poisoning", "non_cacheable_signals", []) or [])
        ]

        # Baseline against a unique key: is this endpoint cacheable at all?
        baseline_url = _cache_buster_url(target.url)
        baseline_resp = await _send(
            client, "GET", baseline_url, target.headers, None, source="agent"
        )
        if baseline_resp is None:
            return []
        if not _is_cacheable(baseline_resp, indicator_headers, non_cacheable_signals):
            logger.debug(
                "cache_poisoning: endpoint not cacheable, skipping",
                url=target.url,
            )
            return []

        findings: List[AgentFinding] = []
        for header in unkeyed_headers:
            header_name = header.get("name", "")
            header_template = header.get("value", "")
            if not header_name:
                continue
            finding = await self._probe_header(
                target, client, header_name, header_template, indicator_headers
            )
            if finding:
                findings.append(finding)

        return findings

    async def _probe_header(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        header_name: str,
        header_template: str,
        indicator_headers: List[str],
    ) -> Optional[AgentFinding]:
        marker = _unique_marker()
        header_value = header_template.replace("{{MARKER}}", marker)
        # One shared cache-buster URL for BOTH requests so they map to the same
        # cache key — the poison and the retrieval target the identical entry.
        probe_url = _cache_buster_url(target.url)

        # Request #1: carry the malicious unkeyed header.
        poison_headers = dict(target.headers)
        poison_headers[header_name] = header_value
        resp1 = await _send(
            client, "GET", probe_url, poison_headers, None,
            payload=f"{header_name}: {header_value}", source="agent",
        )
        if resp1 is None or not _marker_reflected(resp1, marker):
            return None

        # Request #2: SAME url, WITHOUT the header. If the marker still shows,
        # the response was served from cache -> the input is unkeyed -> confirmed.
        resp2 = await _send(
            client, "GET", probe_url, dict(target.headers), None, source="agent"
        )
        cached = resp2 is not None and _marker_reflected(resp2, marker)

        req_text, resp_text = _fmt_http_pair(resp1)
        host = urlparse(target.url).hostname or target.url

        if cached:
            log_event(
                "agent", "warning",
                f"Cache poisoning confirmed: unkeyed header '{header_name}' reflected "
                f"and served from cache on {target.url}",
                url=target.url,
                finding=f"Unkeyed header {header_name} poisons cache",
                source="agent",
            )
            probe2_req, probe2_resp = _fmt_http_pair(resp2)
            return AgentFinding(
                title="Web Cache Poisoning",
                severity="high",
                cwe="CWE-444",
                attack_type="cache_poisoning",
                evidence=(
                    f"Header '{header_name}: {header_value}' was reflected into the "
                    f"response, and a follow-up request to the same URL WITHOUT the "
                    f"header still returned the injected marker {marker!r} — proving "
                    f"'{header_name}' is an unkeyed input cached against host {host!r}. "
                    f"An attacker can poison the shared cache for other users."
                ),
                payload=f"{header_name}: {header_value}",
                parameter=header_name,
                url=target.url,
                request_method="GET",
                confirmed=True,
                bypass_validation=True,
                raw_request=req_text,
                raw_response=resp_text,
                probe_request=probe2_req,
                probe_response=probe2_resp,
            )

        # Reflected but not confirmed cached — the header influences output but we
        # could not prove it is unkeyed. Report for LLM validation, not as fact.
        return AgentFinding(
            title="Reflected Unkeyed Header (Potential Cache Poisoning)",
            severity="medium",
            cwe="CWE-444",
            attack_type="cache_poisoning",
            evidence=(
                f"Header '{header_name}: {header_value}' was reflected into the "
                f"response for {target.url}, but caching of the poisoned response "
                f"could not be confirmed. If '{header_name}' is unkeyed at a shared "
                f"cache, this is exploitable cache poisoning."
            ),
            payload=f"{header_name}: {header_value}",
            parameter=header_name,
            url=target.url,
            request_method="GET",
            confirmed=False,
            bypass_validation=False,
            raw_request=req_text,
            raw_response=resp_text,
        )


Coordinator.register(CachePoisoningAgent)
