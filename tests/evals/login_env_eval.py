"""Opt-in LLM eval: run the adaptive-login cascade with a REAL model against the
high-fidelity product-clone environments, N times each, and report success rates.

This is the closest thing to "multiple real environments": the fixtures imitate
the DOM/flow of Okta, Auth0, Keycloak, Azure AD, WordPress and Django admin, with
realistic page noise. Because the model is non-deterministic, each environment is
run several times and the success RATE is reported (not a single pass/fail).

Spends tokens. Needs Chromium and a configured AI provider. Not in the CI run.

Usage:
    uv run python -m tests.evals.login_env_eval
    uv run python -m tests.evals.login_env_eval --repeats 5 --envs okta,azure_ad
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections import Counter
from typing import Dict, List

from dast.browser.login_cascade import adaptive_login, make_llm_decider
from dast.utils.logger import get_logger
from tests.fixtures.login_pages.browser_harness import (
    chromium_available,
    proxyless_agent_browser,
)
from tests.fixtures.login_pages.environments import (
    ENVIRONMENTS,
    PASSWORD,
    USERNAME,
    env_fixture,
    env_login_url,
)

logger = get_logger(__name__)

# Per-environment expected outcome. Default is "login" (should authenticate).
# sso_mfa is a combo that must bail cleanly at the MFA wall, not log in.
_EXPECT: Dict[str, str] = {"sso_mfa": "mfa"}


def _is_success(expect: str, result) -> bool:
    if expect == "mfa":
        return (not result.ok) and result.error == "mfa_required"
    return bool(result.ok)


async def _run_env(base_url: str, env: str, repeats: int) -> Dict[str, object]:
    url = env_login_url(base_url, env)
    expect = _EXPECT.get(env, "login")
    successes = 0
    engines: Counter = Counter()
    steps: List[int] = []
    for _ in range(repeats):
        async with proxyless_agent_browser() as browser:
            try:
                result = await adaptive_login(
                    browser, url, USERNAME, PASSWORD,
                    decide=make_llm_decider(), success_url_suffix="/dashboard",
                )
                successes += int(_is_success(expect, result))
                engines[result.engine] += 1
                if result.engine == "llm":
                    steps.append(result.llm_steps)
            except Exception as exc:
                engines["error"] += 1
                logger.warning("env eval run errored", env=env, error=str(exc)[:160])
    avg_steps = round(sum(steps) / len(steps), 1) if steps else 0
    return {"env": env, "expect": expect, "repeats": repeats, "successes": successes,
            "rate": round(successes / repeats, 2) if repeats else 0.0,
            "engines": dict(engines), "avg_llm_steps": avg_steps}


async def _main(envs: List[str], repeats: int) -> int:
    rows: List[Dict[str, object]] = []
    with env_fixture() as server:
        for env in envs:
            row = await _run_env(server.base_url, env, repeats)
            rows.append(row)
            print(f"{row['env']:12} [{row['expect']:5}] {row['successes']}/{row['repeats']} "
                  f"(rate {row['rate']:.0%})  engines={row['engines']}  "
                  f"avg_llm_steps={row['avg_llm_steps']}")

    total = sum(int(r["successes"]) for r in rows)
    total_runs = sum(int(r["repeats"]) for r in rows)
    print(f"\nOVERALL: {total}/{total_runs} logins succeeded "
          f"({(total / total_runs if total_runs else 0):.0%}) across {len(rows)} environments")
    # Non-zero exit if any environment never logged in at all (a hard regression).
    dead = [r["env"] for r in rows if int(r["successes"]) == 0]
    if dead:
        print(f"environments that NEVER logged in: {dead}")
        return 1
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Adaptive-login eval over product-clone environments")
    parser.add_argument("--repeats", type=int, default=5,
                        help="runs per environment (default 5)")
    parser.add_argument("--envs", default=",".join(ENVIRONMENTS),
                        help=f"comma-separated environments (default: all {len(ENVIRONMENTS)})")
    args = parser.parse_args()
    envs = [e.strip().lower() for e in args.envs.split(",") if e.strip()]
    unknown = [e for e in envs if e not in ENVIRONMENTS]
    if unknown:
        print(f"unknown environments: {unknown}; known: {list(ENVIRONMENTS)}")
        sys.exit(2)
    if not chromium_available():
        print("SKIP: Chromium not available (uv run playwright install chromium)")
        sys.exit(0)
    sys.exit(asyncio.run(_main(envs, args.repeats)))


if __name__ == "__main__":
    main()
