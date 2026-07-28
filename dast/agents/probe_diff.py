"""
AI-native probe-diffing ("Backslash Powered", done our way).

Instead of spraying fixed payloads and pattern-matching the response, this
module sends probe *pairs* — a "break" input and its "repaired" twin — into a
single parameter and diffs the two responses. The transformation signature
(what changed between break and repair) reveals the injection *class* and
*context* far more reliably than any single payload, because it isolates the
parameter's effect from the page's normal variance.

Classic Backslash-Powered pairs:
  * ``'``      vs ``\\'``        — a broken string quote vs an escaped one.
    If ``'`` errors/changes but ``\\'`` does not, the value sits in a
    string context that honours backslash escaping → likely SQL / quoted
    string interpolation.
  * ``${{7*7}}`` vs ``${{7*'7}}`` — a template expression vs a broken one.
    If the first renders ``49`` and the second errors, the value flows into
    a template evaluator → SSTI.
  * ``\\`` vs (two backslashes) — a lone backslash vs an escaped backslash,
    the language-agnostic escaping probe.

This module is a PURE PRIMITIVE, not a per-vuln agent: it probes and diffs,
producing a ``DiffSignature``. Interpretation (which injection class, whether
to dispatch an agent) is the caller's job — the LLM classifier in
``dast/ai/probe_classifier.py`` and the coordinator's planner. Keeping probe
and classification separate mirrors the repo's split between
``content_discovery`` (find) and the coordinator (decide).

Safety:
  * Every probe input is non-destructive by construction — a quote, a
    backslash, or an arithmetic template expression, never a payload with a
    side effect. There is nothing here that reads a file, sleeps, or reaches
    out of band.
  * EVERY built URL is filtered through ``ProxySettings.is_in_scope()`` BEFORE
    any request is issued — the same hard safety guarantee as
    ``content_discovery`` and ``param_miner``.
  * Reuses ``dast.scanners.active_checks._client()/_send()`` so every probe is
    proxy-routed, rate-limited, and circuit-broken (dead-host short-circuit).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse

from dast.scanners.active_checks import (
    _client,
    _inject_body,
    _inject_query,
    _send,
    is_host_dead,
)
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Marker used to detect arithmetic evaluation (SSTI). 7*7 collapsing to "49"
# in the response body means the parameter flowed into a template evaluator.
_SSTI_EVAL_MARKER = "49"

# Error-signature fragments that indicate the input reached an interpreter and
# broke it — the strongest single diff signal. Kept small and high-signal.
_ERROR_SIGNATURES: List[re.Pattern] = [
    re.compile(r"sql syntax|syntax error|unclosed quotation|unterminated string", re.I),
    re.compile(r"you have an error in your sql|warning:\s*\w*_?(mysqli?|pg|oci)", re.I),
    re.compile(r"ora-\d{5}|sqlite3?\.|psycopg2?\.|pdoexception", re.I),
    re.compile(r"template.*(syntax|error)|jinja2|twig|freemarker|velocity", re.I),
    re.compile(r"unexpected token|parse error|nameerror|typeerror", re.I),
    re.compile(r"stack trace|traceback \(most recent call last\)", re.I),
]


@dataclass(frozen=True)
class ProbePair:
    """
    One break/repair input pair injected into a single parameter.

    ``break_input`` is expected to disturb an interpreter; ``repair_input`` is
    the syntactically-neutralised twin. A difference between the two responses
    (while both differ from a static baseline in the same way would be noise)
    is the signal.
    """
    label: str
    break_input: str
    repair_input: str
    hint: str  # what a break!=repair divergence suggests (for the classifier)


# The standard non-destructive probe set. Order matters only for logging.
DEFAULT_PROBE_PAIRS: List[ProbePair] = [
    ProbePair(
        label="string_quote",
        break_input="dast'",
        repair_input="dast\\'",
        hint="single quote breaks but escaped quote does not -> quoted string / SQL context",
    ),
    ProbePair(
        label="double_quote",
        break_input='dast"',
        repair_input='dast\\"',
        hint="double quote breaks but escaped does not -> double-quoted string context",
    ),
    ProbePair(
        label="backslash",
        break_input="dast\\",
        repair_input="dast\\\\",
        hint="lone backslash breaks but doubled does not -> escape-honouring string context",
    ),
    ProbePair(
        label="template_expr",
        break_input="dast${{7*7}}",
        repair_input="dast${{7*'7}}",
        hint="7*7 renders 49 while 7*'7 errors -> server-side template evaluation (SSTI)",
    ),
    ProbePair(
        label="brace_expr",
        break_input="dast{{7*7}}",
        repair_input="dast{{7*'7}}",
        hint="{{7*7}} renders 49 -> template context (Jinja2/Twig-style)",
    ),
]


@dataclass
class ResponseAttrs:
    """Extracted, comparable attributes of a single response."""
    status: int
    length: int
    word_count: int
    structure_hash: str          # hash of the HTML tag skeleton (structural fingerprint)
    reflected: bool              # did the injected marker echo in the body?
    error_signature: str         # first matched interpreter-error fragment, or ""
    eval_marker: bool            # did an arithmetic-eval marker (49) appear?

    def differs_from(self, other: "ResponseAttrs") -> List[str]:
        """Return the list of attribute names that differ meaningfully."""
        diffs: List[str] = []
        if self.status != other.status:
            diffs.append("status")
        # Length noise threshold mirrors param_miner's _LENGTH_NOISE_BYTES.
        if abs(self.length - other.length) >= 32:
            diffs.append("length")
        if self.structure_hash != other.structure_hash:
            diffs.append("structure")
        if self.error_signature != other.error_signature:
            diffs.append("error_signature")
        if self.eval_marker != other.eval_marker:
            diffs.append("eval_marker")
        if self.reflected != other.reflected:
            diffs.append("reflection")
        return diffs


@dataclass
class PairResult:
    """The diff outcome for one probe pair on one parameter."""
    label: str
    hint: str
    break_attrs: Optional[ResponseAttrs]
    repair_attrs: Optional[ResponseAttrs]
    diverged: bool               # break and repair responses differ (the signal)
    divergent_attrs: List[str] = field(default_factory=list)


@dataclass
class DiffSignature:
    """
    The full probe-diff outcome for one parameter — the primitive's return
    value. ``has_signal`` is a cheap deterministic pre-filter; the LLM
    classifier turns divergent pairs into an injection-class hypothesis.
    """
    parameter: str
    location: str
    url: str
    method: str
    baseline_attrs: Optional[ResponseAttrs]
    pairs: List[PairResult] = field(default_factory=list)

    @property
    def has_signal(self) -> bool:
        return any(p.diverged for p in self.pairs)

    @property
    def divergent_labels(self) -> List[str]:
        return [p.label for p in self.pairs if p.diverged]

    def to_classifier_summary(self) -> str:
        """Compact, LLM-readable summary of the divergent probe pairs."""
        lines = [
            f"Parameter: {self.parameter} ({self.location}) on {self.method} "
            f"{urlparse(self.url).path or '/'}",
        ]
        if self.baseline_attrs is not None:
            b = self.baseline_attrs
            lines.append(f"Baseline: status {b.status}, len {b.length}, "
                         f"words {b.word_count}")
        for p in self.pairs:
            if not p.diverged:
                continue
            lines.append(
                f"- pair '{p.label}': break vs repair diverged on "
                f"{', '.join(p.divergent_attrs)} | hint: {p.hint}"
            )
            if p.break_attrs and p.break_attrs.error_signature:
                lines.append(f"    break error: {p.break_attrs.error_signature!r}")
            if p.break_attrs and p.break_attrs.eval_marker and not (
                p.repair_attrs and p.repair_attrs.eval_marker
            ):
                lines.append("    break evaluated arithmetic (49) but repair did not")
        if not self.has_signal:
            lines.append("- no probe pair diverged (parameter appears inert)")
        return "\n".join(lines)


# ── attribute extraction ────────────────────────────────────────────────────

_TAG_RE = re.compile(r"<\s*(/?)\s*([a-zA-Z][a-zA-Z0-9]*)")


def _structure_hash(text: str) -> str:
    """
    Hash the HTML tag skeleton (ordered open/close tag names, attributes
    stripped) so a structural change is detected even when text content or
    reflected values differ. Non-HTML bodies hash their own length bucket so
    JSON/text responses still get a stable-ish fingerprint.
    """
    tags = _TAG_RE.findall(text)
    if not tags:
        # Non-markup body: bucket by rounded length so small content changes
        # don't churn the hash but structural size shifts do.
        bucket = len(text) // 128
        return f"nomarkup:{bucket}"
    skeleton = "".join(f"{slash}{name.lower()}" for slash, name in tags)
    return hashlib.sha1(skeleton.encode("utf-8", "replace")).hexdigest()[:16]


def _match_error_signature(text: str) -> str:
    for pattern in _ERROR_SIGNATURES:
        m = pattern.search(text)
        if m:
            return m.group(0)[:80]
    return ""


def _extract_attrs(resp, marker: str) -> ResponseAttrs:
    try:
        text = resp.text
    except Exception:
        text = ""
    return ResponseAttrs(
        status=resp.status_code,
        length=len(resp.content or b""),
        word_count=len(text.split()),
        structure_hash=_structure_hash(text),
        reflected=marker in text,
        error_signature=_match_error_signature(text),
        eval_marker=_SSTI_EVAL_MARKER in text,
    )


# ── probing ──────────────────────────────────────────────────────────────────

def _build_probe(
    target_url: str,
    method: str,
    body: Optional[str],
    content_type: str,
    param: dict,
    value: str,
) -> tuple[str, Optional[str]]:
    """Return (url, body) with `value` injected into `param` at its location."""
    loc = param.get("location", "query")
    if loc == "query":
        return _inject_query(target_url, param["name"], value), body
    if loc in ("body", "body_graphql"):
        new_body = _inject_body(body or "", param["name"], value, content_type, location=loc)
        return target_url, new_body
    # Unknown location — fall back to query, always safe.
    return _inject_query(target_url, param["name"], value), body


async def run_probe_pairs(
    target,
    param: dict,
    settings,
    proxy_url: Optional[str] = None,
    pairs: Optional[List[ProbePair]] = None,
    client=None,
) -> Optional[DiffSignature]:
    """
    Send break/repair probe pairs into ONE parameter and diff the responses.

    `target` must expose ``url``, ``method``, ``headers``, ``body`` (the
    CheckTarget shape). `settings`, if given, must expose
    ``is_in_scope(url) -> bool`` — every built URL is gated through it before
    any request. Pass None only when the target is already known in-scope AND
    the probe cannot change the host/path (probe-diff only mutates param
    *values*, so the scope decision is identical to the target's), matching the
    coordinator's own canary-probe pattern.

    `client`, if given, is reused (so the caller's proxy-routed client is
    honoured); otherwise a fresh proxy-routed client is opened from `proxy_url`.

    Returns a ``DiffSignature``, or None if the baseline could not be
    established or the host is dead. Pure probe + diff — no classification.
    """
    pairs = pairs or DEFAULT_PROBE_PAIRS
    url = getattr(target, "url", "")
    method = (getattr(target, "method", "GET") or "GET").upper()
    headers = getattr(target, "headers", {}) or {}
    body = getattr(target, "body", None)
    content_type = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            content_type = v
            break

    hostname = urlparse(url).hostname or url
    location = param.get("location", "query")

    if settings is not None and not settings.is_in_scope(url):
        logger.warning("Probe-diff target out of scope", url=url)
        return None
    if is_host_dead(hostname):
        return None

    args = (target, param, pairs, settings, url, method, headers,
            body, content_type, hostname, location)
    if client is not None:
        return await _probe_all_pairs(client, *args)
    async with _client(proxy_url) as owned_client:
        return await _probe_all_pairs(owned_client, *args)


async def _probe_all_pairs(
    client, target, param, pairs, settings, url, method, headers,
    body, content_type, hostname, location,
) -> Optional[DiffSignature]:
    # Baseline: a benign marker value — anchors "normal" for this parameter.
    baseline_marker = "dastbaseline"
    b_url, b_body = _build_probe(url, method, body, content_type, param, baseline_marker)
    if settings is not None and not settings.is_in_scope(b_url):
        return None
    baseline_resp = await _send(
        client, method, b_url, headers, b_body, source="probe-diff"
    )
    if baseline_resp is None:
        logger.warning("Probe-diff baseline failed", url=url, parameter=param.get("name"))
        return None
    baseline_attrs = _extract_attrs(baseline_resp, baseline_marker)

    sig = DiffSignature(
        parameter=param.get("name", ""),
        location=location,
        url=url,
        method=method,
        baseline_attrs=baseline_attrs,
    )

    for pair in pairs:
        if is_host_dead(hostname):
            break
        break_url, break_body = _build_probe(
            url, method, body, content_type, param, pair.break_input
        )
        repair_url, repair_body = _build_probe(
            url, method, body, content_type, param, pair.repair_input
        )
        # HARD SAFETY GATE on both built URLs before sending either.
        if settings is not None and (
            not settings.is_in_scope(break_url)
            or not settings.is_in_scope(repair_url)
        ):
            continue

        break_resp = await _send(
            client, method, break_url, headers, break_body, source="probe-diff"
        )
        repair_resp = await _send(
            client, method, repair_url, headers, repair_body, source="probe-diff"
        )
        break_attrs = _extract_attrs(break_resp, pair.break_input) if break_resp else None
        repair_attrs = _extract_attrs(repair_resp, pair.repair_input) if repair_resp else None

        diverged = False
        divergent_attrs: List[str] = []
        if break_attrs is not None and repair_attrs is not None:
            divergent_attrs = break_attrs.differs_from(repair_attrs)
            diverged = bool(divergent_attrs)

        sig.pairs.append(PairResult(
            label=pair.label,
            hint=pair.hint,
            break_attrs=break_attrs,
            repair_attrs=repair_attrs,
            diverged=diverged,
            divergent_attrs=divergent_attrs,
        ))

    logger.info(
        "Probe-diff complete",
        host=hostname,
        parameter=sig.parameter,
        signal=sig.has_signal,
        divergent=sig.divergent_labels,
    )
    return sig
