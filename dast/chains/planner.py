"""
Attack-chain planner.

Turns a free-text multi-step vulnerability report into an executable
:class:`Chain`. This is what lets a "chain of attack" described in prose (a
HackerOne submission, an internal write-up) become something ChainEngine can
run and confirm. The report text is untrusted evidence, so it is fenced with
``wrap_untrusted`` and the system prompt carries the injection-defense directive.

The LLM output is schema-forced (``ATTACK_CHAIN_SCHEMA``) so malformed specs
cannot occur; on any AI failure the planner degrades to ``None`` and the caller
falls back to manual review.
"""

from __future__ import annotations

from typing import Optional

from dast.ai import bedrock_client
from dast.ai.prompt_safety import UNTRUSTED_CONTENT_DIRECTIVE, wrap_untrusted
from dast.ai.schemas import ATTACK_CHAIN_SCHEMA
from dast.chains.models import Chain
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_SYSTEM = (
    "You are a security engineer turning a written multi-step vulnerability report into an "
    "executable request chain that PROVES the issue. A chain is an ordered list of HTTP "
    "requests where each step can bind values out of its response (a token, a Set-Cookie, an "
    "unguessable path leaked by a field) that later steps consume via {{variable}} templates.\n\n"
    "Rules:\n"
    "1. Reproduce faithfully: use the exact hosts, paths, methods, headers and bodies from the "
    "report. Do not invent endpoints.\n"
    "2. Thread state: if step 1 returns a token or cookie that step 2 needs, add an extractor in "
    "step 1 and reference the variable in step 2. Set-Cookie is harvested automatically.\n"
    "3. Assertions encode the expected evidence (status codes, header/body substrings, that a "
    "leaked value is present).\n"
    "4. ALWAYS end with a CONTROL step: repeat the sensitive request but WITHOUT the credential "
    "that supposedly grants access (send_cookies: []), asserting it now FAILS (e.g. status_in "
    "[401,403]). This is what separates a real access-control break from normal behavior.\n"
    "5. SAFETY: this runs against a LIVE target. Never write/delete/mutate data. When a step "
    "fetches content/media, set max_range_bytes to a small value (e.g. 64) so only a proof-sized "
    "slice is requested, never the full asset. Detection only.\n"
    "6. Keep the chain minimal — the fewest steps that prove the claim."
)
_SYSTEM += UNTRUSTED_CONTENT_DIRECTIVE


def plan_chain(report_text: str, model_id: Optional[str] = None) -> Optional[Chain]:
    """Plan an executable chain from a free-text report. Returns None on failure."""
    report_text = (report_text or "").strip()
    if not report_text:
        return None
    user = (
        "Turn the following multi-step vulnerability report into an executable chain spec. "
        "Include a control step as instructed.\n\n"
        + wrap_untrusted(report_text, "vuln_report", 8000)
    )
    try:
        data = bedrock_client.invoke_json(
            system=_SYSTEM,
            user=user,
            model_id=model_id,
            max_tokens=3000,
            temperature=0,
            cache_system=True,
            schema=ATTACK_CHAIN_SCHEMA,
        )
    except Exception as exc:
        logger.warning("chain planning failed", error=str(exc))
        return None

    chain = Chain.from_dict(data)
    if not chain.steps:
        logger.warning("chain planner returned no steps")
        return None
    logger.info("chain planned", name=chain.name, steps=len(chain.steps), vuln_type=chain.vuln_type)
    return chain
