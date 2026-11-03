"""Opt-in LLM eval: does the adaptive-login fallback solve the hard tiers with a
REAL model driving the browser?

Unlike the CI suites (which stub the decider), this runs ``make_llm_decider()`` —
it calls the configured provider and spends tokens. It drives the deterministic
engine first and, on failure, lets the model find the fields/buttons from the page
snapshot and log in.

Usage:
    uv run python -m tests.evals.login_adaptive_eval
    uv run python -m tests.evals.login_adaptive_eval --tiers t2,t11

Needs Chromium (``uv run playwright install chromium``) and a configured AI
provider (see .env / AI_PROVIDER). Not part of the default pytest run.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import Dict, List, Tuple

from dast.browser.login_cascade import adaptive_login, make_llm_decider
from dast.utils.logger import get_logger
from tests.fixtures.login_pages.browser_harness import (
    chromium_available,
    proxyless_agent_browser,
)
from tests.fixtures.login_pages.server import PASSWORD, USERNAME, login_fixture

logger = get_logger(__name__)

# tier -> (path, expected_engine_on_success). The LLM should clear T2/T11; T4 is
# a known limitation (iframe fields not in the main-frame snapshot) and is
# expected to stay unsolved even with the model.
_TIERS: Dict[str, Tuple[str, str]] = {
    "t2": ("/t2/login", "llm"),
    "t11": ("/t11/login", "llm"),
    "t4": ("/t4/login", "none"),
}
_EXPECT_SOLVED = {"t2": True, "t11": True, "t4": False}


async def _run_tier(tier: str, path: str, with_idp: bool = False) -> Dict[str, object]:
    with login_fixture(with_idp=with_idp) as server:
        async with proxyless_agent_browser() as browser:
            result = await adaptive_login(
                browser, f"{server.base_url}{path}", USERNAME, PASSWORD,
                decide=make_llm_decider(), success_url_suffix="/dashboard",
            )
    return {"tier": tier, "ok": result.ok, "engine": result.engine,
            "llm_steps": result.llm_steps, "url": result.url}


async def _main(tiers: List[str]) -> int:
    rows: List[Dict[str, object]] = []
    passed = 0
    for tier in tiers:
        path, _ = _TIERS[tier]
        try:
            row = await _run_tier(tier, path)
        except Exception as exc:  # degrade: a provider/browser error is a fail, not a crash
            row = {"tier": tier, "ok": False, "engine": "error",
                   "llm_steps": 0, "url": f"error: {str(exc)[:120]}"}
        expected = _EXPECT_SOLVED[tier]
        ok = bool(row["ok"]) == expected
        passed += int(ok)
        row["verdict"] = "PASS" if ok else "FAIL"
        rows.append(row)
        print(f"[{row['verdict']}] {tier:4} solved={row['ok']!s:5} "
              f"engine={row['engine']:13} steps={row['llm_steps']} -> {row['url']}")

    print(f"\n{passed}/{len(tiers)} tiers matched expectation")
    return 0 if passed == len(tiers) else 1


def main() -> None:
    parser = argparse.ArgumentParser(description="Adaptive-login LLM eval")
    parser.add_argument("--tiers", default="t2,t11,t4",
                        help="comma-separated tiers to run (default: t2,t11,t4)")
    args = parser.parse_args()
    tiers = [t.strip().lower() for t in args.tiers.split(",") if t.strip()]
    unknown = [t for t in tiers if t not in _TIERS]
    if unknown:
        print(f"unknown tiers: {unknown}; known: {list(_TIERS)}")
        sys.exit(2)
    # Check Chromium synchronously, before the event loop starts (the sync
    # Playwright API cannot run inside a running asyncio loop).
    if not chromium_available():
        print("SKIP: Chromium not available (uv run playwright install chromium)")
        sys.exit(0)
    sys.exit(asyncio.run(_main(tiers)))


if __name__ == "__main__":
    main()
