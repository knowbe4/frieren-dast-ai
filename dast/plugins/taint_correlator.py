"""
Taint Correlator plugin — passively watches every proxied response for taint
markers that agents (and the taint seeder) inject at entry points, and records
where each marker surfaces.

The signal that matters is *cross-endpoint* surfacing: a unique benign marker
injected at endpoint A appearing in the response of endpoint B proves that user
input persisted and flowed across a request boundary. That is the exact surface
of stored XSS, second-order SQL injection, and cross-endpoint reflection — vulns
that reflection-only detection on the injecting request cannot see.

This plugin does not send traffic; it only observes. Immediate same-endpoint
reflection is intentionally ignored here (the reflected-XSS agents own that case)
to keep noise low. Correlations are recorded once per (marker, sink endpoint) so
each data flow is reported exactly once.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from dast.proxy.plugin_base import ProxyPlugin
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.proxy.session_store import ProxyEntry, SessionStore

logger = get_logger(__name__)


class TaintCorrelatorPlugin(ProxyPlugin):
    name        = "taint-correlator"
    description = "Correlates injected taint markers with the responses they surface in (stored/second-order flows)"
    version     = "1.0.0"
    author      = "Frieren DAST-AI"
    enabled     = True

    async def on_entry(self, entry: "ProxyEntry", store: "SessionStore") -> None:
        taint_store = getattr(store, "taint_store", None)
        if taint_store is None or not entry.response_body:
            return

        try:
            body = entry.response_body.decode("utf-8", errors="replace")
        except Exception as exc:
            logger.warning("Taint correlator: response decode failed", url=entry.url, error=str(exc))
            return

        hits = taint_store.find_hits(entry.url, body, observed_entry_id=entry.id)
        for hit in hits:
            # Same-endpoint reflection is normal request echo — the reflected-XSS
            # agents cover it. Only cross-endpoint surfacing is a stored/second-order
            # signal worth a finding.
            if not hit.is_cross_location:
                continue
            if not taint_store.record_correlation(hit):
                continue  # already reported this data flow

            marker = hit.marker
            store.add_finding(
                entry.id,
                {
                    "title": "Cross-Endpoint Input Reflection (Stored / Second-Order Injection Surface)",
                    "severity": "medium",
                    "cwe": "CWE-79",
                    "attack_type": "taint",
                    "evidence": (
                        f"A unique marker injected into parameter {marker.source_param!r} "
                        f"({marker.source_location}) of {marker.source_method} {marker.source_url} "
                        f"surfaced in the response of {entry.method} {entry.url}. "
                        f"Input persisted and crossed a request boundary — confirm the sink "
                        f"context for stored XSS / second-order injection."
                    ),
                    "parameter": marker.source_param,
                    "confirmed": True,
                    "validated_by": ["taint-correlation"],
                    "needs_ai_validation": True,
                },
                "vulnerable",
            )
            logger.info(
                "Taint correlator: cross-endpoint data flow flagged",
                source_url=marker.source_url,
                source_param=marker.source_param,
                sink_url=entry.url,
            )
