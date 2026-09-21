"""
Engagement authorization state.

Frieren DAST-AI performs *active* security testing (it sends attack payloads to
whatever the operator routes through it). Before the tool does anything, the
operator must declare that they hold explicit authorization for the targets under
test and accept responsibility for the testing performed. That declaration is made
once at startup — either with the ``--authorized`` CLI flag or by confirming the
terminal prompt (see ``dast/cli.py``) — and recorded here as process-global state.

This module is intentionally tiny and dependency-free so any part of the app can
read the flag without importing the CLI or the proxy runner. It follows the same
module-level-mutable-global pattern as ``dast.ai.bedrock_client`` (set once at
startup via a setter, read anywhere via a getter).

The flag governs the copilot's *willingness* to proceed, not the host-scope
barrier: when authorization is declared, the copilot stops handing turns back with
``blocked_reason='need_authorization'`` / ``'out_of_scope'`` asking the operator to
re-confirm that they are allowed to test. Per-host scope approval (``approved_hosts``
and the scope gate) still applies as an independent safety control.
"""

from __future__ import annotations

from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Set once at startup; read per copilot turn. False until the operator declares
# authorization, so the tool never assumes consent it was not given.
_full_authorization: bool = False


def set_full_authorization(value: bool) -> None:
    """Record whether the operator has declared full authorization for the run.

    Called once at startup from the CLI (flag or terminal confirmation). Idempotent.
    """
    global _full_authorization
    _full_authorization = bool(value)
    logger.info("Engagement authorization set", full_authorization=_full_authorization)


def is_full_authorization() -> bool:
    """True when the operator has declared full authorization for this run."""
    return _full_authorization


# Appended to the copilot system prompt when authorization is declared. It changes
# the LLM's willingness to proceed on scope/authorization grounds only — it does not
# lower the technical bar (still block on real obstacles, still confirm on evidence).
AUTHORIZED_ENGAGEMENT_DIRECTIVE = """

AUTHORIZATION STATUS: The operator has declared, at startup, that this is a fully
authorized engagement — they hold explicit written authorization for the targets
under test and accept full responsibility for the testing performed. Treat scope
and authorization as already confirmed for the hosts the operator directs you to.
Do NOT block, refuse, or hand the turn back with blocked_reason 'need_authorization'
or 'out_of_scope' just to ask the operator to re-confirm that they are allowed to
test — proceed with the requested tests. This does not lower the technical bar: keep
blocking honestly for real obstacles (a WAF you cannot bypass, an auth/login wall, a
concrete value only the operator has), and keep confirming findings on real evidence
you observed through the tools — never fabricate. Per-host scope approval remains
governed by the operator's scope settings."""
