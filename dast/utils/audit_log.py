"""
Audit log — append-only JSONL record of every scan event.

Separate from the application log. The audit log is the complete
forensic record of everything the scanner did:
  - Every URL crawled (with status, depth, param count)
  - Every endpoint discovered (with all parameters and sample values)
  - Every attack attempt (method, url, payload, injection point, response)
  - Every AI verdict (verdict, confidence, evidence, reasoning)
  - Every finding confirmed

Written as one JSON object per line (JSONL) so it can be streamed,
grepped, and imported into jq / pandas for analysis.

Usage:
    audit = AuditLog(Path("scan-results/audit.jsonl"))
    audit.crawled(url, status=200, depth=2, links_found=5)
    audit.endpoint_discovered(endpoint)
    audit.attack_attempt(attempt, verdict, evidence, confidence)
    audit.finding_confirmed(finding)
"""

import json
import threading
import time
from pathlib import Path
from typing import Any, Dict

from dast.models import AttackAttempt, AttackVerdict, Endpoint, Finding


class AuditLog:
    """
    Thread-safe append-only JSONL audit log.

    Each line is a self-contained JSON object with:
      ts       — ISO timestamp
      event    — event type (crawled, endpoint, attack, finding, error, ...)
      + event-specific fields
    """

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = path
        self._lock = threading.Lock()
        self._fh = open(str(path), "a", encoding="utf-8", buffering=1)  # line-buffered

    # ------------------------------------------------------------------
    # Crawl events
    # ------------------------------------------------------------------

    def crawled(
        self,
        url: str,
        *,
        status: int,
        depth: int,
        links_found: int = 0,
        interactions_captured: int = 0,
        duration_ms: float = 0.0,
        via: str = "crawler",
    ) -> None:
        self._write(
            event="crawled",
            url=url,
            status=status,
            depth=depth,
            links_found=links_found,
            interactions_captured=interactions_captured,
            duration_ms=round(duration_ms, 1),
            via=via,
        )

    def page_error(self, url: str, *, error: str, depth: int = 0) -> None:
        self._write(event="page_error", url=url, error=error, depth=depth)

    # ------------------------------------------------------------------
    # Endpoint discovery
    # ------------------------------------------------------------------

    def endpoint_discovered(self, endpoint: Endpoint) -> None:
        self._write(
            event="endpoint_discovered",
            method=endpoint.method,
            url=endpoint.url,
            content_type=endpoint.content_type,
            auth_required=endpoint.auth_required,
            discovered_via=endpoint.discovered_via,
            parameters=[
                {
                    "name": p.name,
                    "location": p.location,
                    "type": p.inferred_type,
                    "sample_value": p.value[:200] if p.value else "",
                }
                for p in endpoint.parameters
            ],
            param_count=len(endpoint.parameters),
            sample_status=(
                endpoint.sample_response.status_code
                if endpoint.sample_response else None
            ),
        )

    # ------------------------------------------------------------------
    # Attack events
    # ------------------------------------------------------------------

    def attack_start(
        self,
        endpoint: Endpoint,
        *,
        attack_type: str,
        payload_count: int,
    ) -> None:
        self._write(
            event="attack_start",
            method=endpoint.method,
            url=endpoint.url,
            attack_type=attack_type,
            payload_count=payload_count,
        )

    def attack_attempt(
        self,
        attempt: AttackAttempt,
        *,
        verdict: AttackVerdict,
        evidence: str,
        confidence: float,
    ) -> None:
        req = attempt.request
        resp = attempt.response

        self._write(
            event="attack_attempt",
            iteration=attempt.iteration,
            # Endpoint
            method=attempt.endpoint.method,
            url=attempt.endpoint.url,
            # Payload
            attack_type=attempt.payload.attack_type,
            payload_value=attempt.payload.value,
            injection_point=attempt.payload.injection_point,
            injection_location=attempt.payload.injection_location,
            payload_rationale=attempt.payload.rationale,
            # Actual request sent
            request={
                "method": req.method if req else None,
                "url": req.url if req else None,
                "headers": _sanitize_headers(req.headers if req else {}),
                "body": (req.body[:1000] if req and req.body else None),
            },
            # Response received
            response={
                "status": resp.status_code if resp else None,
                "duration_ms": round(resp.duration_ms, 1) if resp else None,
                "headers": _sanitize_headers(resp.headers if resp else {}),
                "body_preview": (resp.body[:500] if resp and resp.body else None),
                "body_length": len(resp.body) if resp and resp.body else 0,
            },
            # AI verdict
            verdict=verdict.value,
            confidence=round(confidence, 3),
            evidence=evidence[:500] if evidence else "",
        )

    def attack_skip(self, endpoint: Endpoint, *, reason: str) -> None:
        self._write(
            event="attack_skip",
            method=endpoint.method,
            url=endpoint.url,
            reason=reason,
        )

    def mutation(
        self,
        endpoint: Endpoint,
        *,
        iteration: int,
        attack_type: str,
        original_payload: str,
        mutated_payload: str,
        reason: str,
    ) -> None:
        self._write(
            event="mutation",
            method=endpoint.method,
            url=endpoint.url,
            iteration=iteration,
            attack_type=attack_type,
            original_payload=original_payload,
            mutated_payload=mutated_payload,
            reason=reason,
        )

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def finding_confirmed(self, finding: Finding) -> None:
        self._write(
            event="finding_confirmed",
            title=finding.title,
            severity=finding.severity.value,
            attack_type=finding.attack_type,
            cwe=finding.cwe,
            confidence=round(finding.confidence, 3),
            method=finding.endpoint.method,
            url=finding.endpoint.url,
            evidence=finding.evidence[:500],
            ai_reasoning=finding.ai_reasoning[:500],
            iterations=len(finding.confirmed_attempts),
        )

    # ------------------------------------------------------------------
    # Auth events
    # ------------------------------------------------------------------

    def auth_attempt(self, url: str, *, username: str, success: bool) -> None:
        self._write(
            event="auth_attempt",
            url=url,
            username=username,
            success=success,
        )

    def session_rollback(self, *, reason: str, success: bool) -> None:
        self._write(event="session_rollback", reason=reason, success=success)

    # ------------------------------------------------------------------
    # Generic error
    # ------------------------------------------------------------------

    def error(self, message: str, **kwargs: Any) -> None:
        self._write(event="error", message=message, **kwargs)

    # ------------------------------------------------------------------
    # Scan lifecycle
    # ------------------------------------------------------------------

    def scan_start(self, target: str, config: Dict[str, Any]) -> None:
        self._write(event="scan_start", target=target, config=config)

    def scan_end(
        self,
        *,
        status: str,
        duration_s: float,
        endpoints: int,
        attempts: int,
        findings: int,
    ) -> None:
        self._write(
            event="scan_end",
            status=status,
            duration_s=round(duration_s, 1),
            endpoints=endpoints,
            attempts=attempts,
            findings=findings,
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _write(self, **fields: Any) -> None:
        fields["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        line = json.dumps(fields, ensure_ascii=False, default=str)
        with self._lock:
            self._fh.write(line + "\n")

    def close(self) -> None:
        with self._lock:
            self._fh.flush()
            self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def _sanitize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Redact auth tokens and cookies from logged headers."""
    sensitive = {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"}
    return {
        k: ("[REDACTED]" if k.lower() in sensitive else v)
        for k, v in headers.items()
    }
