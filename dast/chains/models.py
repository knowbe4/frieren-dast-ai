"""
Data model for an attack chain.

A chain is a JSON-serializable spec so it can be authored by hand, produced by
the LLM planner (``planner.py``) from a free-text report, or round-tripped over
MCP. Nothing here performs I/O — execution lives in ``engine.py``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Extractor:
    """Bind a value out of a step's response (or an earlier variable) into ``var``.

    kind:
      json       — source text is JSON; ``expr`` is a dotted path (supports
                   ``key``, ``key[0]``, ``key[*]`` to collect a list).
      regex      — ``expr`` is a regex; binds group 1 if present else group 0.
      set_cookie — ``expr`` is a cookie name; binds its value from Set-Cookie.
      b64json    — source is base64url; decoded, parsed as JSON, then ``expr``.
      jwt_claim  — source is a JWT; its payload is decoded, then ``expr`` (json).

    source (``from``):
      body (default) | header:<Name> | var:<name>
    """

    kind: str
    var: str
    expr: str = ""
    source: str = "body"

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "Extractor":
        return Extractor(
            kind=str(data.get("kind", "")).strip(),
            var=str(data.get("var", "")).strip(),
            expr=str(data.get("expr", "")),
            source=str(data.get("from", data.get("source", "body"))).strip() or "body",
        )


@dataclass
class Assertion:
    """A condition that must hold for the step to be considered a pass.

    kind:
      status_eq / status_in — response status equals / is in ``values``.
      header_contains        — response header ``name`` contains ``needle``.
      body_contains / body_not_contains — response body substring test.
      var_present            — variable ``var`` was bound and is non-empty.
      var_contains / var_equals — variable ``var`` contains / equals ``value``.
    """

    kind: str
    # Generic operands; only the ones relevant to ``kind`` are read.
    value: Any = None
    values: List[Any] = field(default_factory=list)
    name: str = ""
    needle: str = ""
    var: str = ""

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "Assertion":
        return Assertion(
            kind=str(data.get("kind", "")).strip(),
            value=data.get("value"),
            values=list(data.get("values", []) or []),
            name=str(data.get("name", "")),
            needle=str(data.get("needle", "")),
            var=str(data.get("var", "")),
        )


@dataclass
class ChainStep:
    """One request in the chain.

    ``url``, ``headers`` and ``body`` may contain ``{{var}}`` placeholders that
    are substituted from variables bound by earlier steps' extractors.

    send_cookies:
      None  — send the whole accumulated cookie jar (default).
      []    — send no cookies (a control step, to prove cookies are what matter).
      [...] — send only the named cookies.

    max_range_bytes: when set, a ``Range: bytes=0-(n-1)`` header caps the
    response so a media/content check never pulls the full asset (safety).
    """

    name: str
    method: str = "GET"
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    extract: List[Extractor] = field(default_factory=list)
    assertions: List[Assertion] = field(default_factory=list)
    send_cookies: Optional[List[str]] = None
    max_range_bytes: Optional[int] = None

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "ChainStep":
        send_cookies = data.get("send_cookies")
        if send_cookies is not None:
            send_cookies = [str(c) for c in send_cookies]
        max_range = data.get("max_range_bytes")
        return ChainStep(
            name=str(data.get("name", "")).strip() or "step",
            method=str(data.get("method", "GET")).upper().strip() or "GET",
            url=str(data.get("url", "")).strip(),
            headers={str(k): str(v) for k, v in (data.get("headers") or {}).items()},
            body=str(data.get("body", "") or ""),
            extract=[Extractor.from_dict(e) for e in (data.get("extract") or [])],
            assertions=[Assertion.from_dict(a) for a in (data.get("assertions") or [])],
            send_cookies=send_cookies,
            max_range_bytes=int(max_range) if max_range is not None else None,
        )


@dataclass
class Chain:
    """A named, ordered sequence of steps that together prove one vulnerability."""

    name: str
    steps: List[ChainStep] = field(default_factory=list)
    vuln_type: str = "attack_chain"
    description: str = ""

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "Chain":
        return Chain(
            name=str(data.get("name", "")).strip() or "attack_chain",
            steps=[ChainStep.from_dict(s) for s in (data.get("steps") or [])],
            vuln_type=str(data.get("vuln_type", "attack_chain")).strip() or "attack_chain",
            description=str(data.get("description", "")),
        )


@dataclass
class StepResult:
    """Outcome of executing a single step (secrets redacted for reporting)."""

    name: str
    method: str
    url: str
    status: Optional[int] = None
    passed: bool = False
    assertion_results: List[str] = field(default_factory=list)
    extracted: List[str] = field(default_factory=list)   # "var=redacted_preview"
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "passed": self.passed,
            "assertions": self.assertion_results,
            "extracted": self.extracted,
            "note": self.note,
        }


@dataclass
class ChainResult:
    """Overall verdict for a chain.

    status: confirmed | refuted | needs_auth | blocked | error
      confirmed — every step's assertions passed end to end.
      refuted   — a step ran but its assertions failed (the vuln did not reproduce).
      blocked   — a step was refused by the scope or payload-safety gate.
      needs_auth— a step hit an auth wall; supply a session and re-run.
      error     — a step could not be sent (network/parse).
    """

    name: str
    status: str
    vuln_type: str = "attack_chain"
    steps: List[StepResult] = field(default_factory=list)
    evidence: str = ""

    @property
    def confirmed(self) -> bool:
        return self.status == "confirmed"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "vuln_type": self.vuln_type,
            "confirmed": self.confirmed,
            "steps": [s.to_dict() for s in self.steps],
            "evidence": self.evidence,
        }
