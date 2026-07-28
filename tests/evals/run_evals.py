"""
LLM eval harness (PoC) — measures decision quality of the planner and red-team
validator against a hand-labelled golden set.

Opt-in: calls the real Bedrock model, so it needs AWS credentials and costs
tokens. Not collected by the default pytest run. See tests/evals/README.md.

Usage:
    uv run python -m tests.evals.run_evals
    uv run python -m tests.evals.run_evals --suite planner --min-accuracy 0.9
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from dast.utils.logger import get_logger

logger = get_logger(__name__)

_CASES_DIR = Path(__file__).parent


@dataclass
class CaseResult:
    name: str
    passed: bool
    detail: str
    injection_probe: bool = False


@dataclass
class SuiteResult:
    suite: str
    results: List[CaseResult] = field(default_factory=list)

    @property
    def accuracy(self) -> float:
        if not self.results:
            return 1.0
        return sum(1 for r in self.results if r.passed) / len(self.results)

    @property
    def injection_accuracy(self) -> Optional[float]:
        probes = [r for r in self.results if r.injection_probe]
        if not probes:
            return None
        return sum(1 for r in probes if r.passed) / len(probes)


def _load_cases(filename: str) -> List[Dict]:
    with open(_CASES_DIR / filename) as fh:
        data = yaml.safe_load(fh)
    return data.get("cases", [])


def _make_target(case: Dict):
    """Build a minimal CheckTarget from a planner case."""
    from dast.scanners.active_checks import CheckTarget

    body = case.get("body") or ""
    params = []
    # Derive params from query string so the planner sees named inputs.
    from urllib.parse import urlparse, parse_qsl
    for name, value in parse_qsl(urlparse(case["url"]).query):
        params.append({"name": name, "location": "query", "value": value})

    return CheckTarget(
        method=case["method"],
        url=case["url"],
        headers={"content-type": case.get("content_type", "application/json")},
        body=body or None,
        params=params,
    )


async def _run_planner_case(case: Dict) -> CaseResult:
    import dast.agents  # noqa: F401 — registers agents into the registry
    from dast.ai.coordinator import Coordinator

    target = _make_target(case)
    baseline = (
        f"Baseline response (status {case['response_status']}):\n"
        f"{case.get('response_body', '')}"
    )
    try:
        selected, reason, _mine_params = await Coordinator._plan(
            target,
            baseline_response=baseline,
        )
    except Exception as exc:
        return CaseResult(case["name"], False, f"plan raised: {exc}",
                          case.get("injection_probe", False))

    selected_set = set(selected)
    missing = [a for a in case.get("expect_include", []) if a not in selected_set]
    leaked = [a for a in case.get("expect_exclude", []) if a in selected_set]
    passed = not missing and not leaked
    detail = f"selected={sorted(selected_set)}"
    if missing:
        detail += f" MISSING={missing}"
    if leaked:
        detail += f" LEAKED={leaked}"
    return CaseResult(case["name"], passed, detail, case.get("injection_probe", False))


async def _run_red_team_case(case: Dict) -> CaseResult:
    from dast.ai.agent_base import AgentFinding
    from dast.ai import red_team
    from dast.scanners.active_checks import CheckTarget

    finding = AgentFinding(
        title=f"{case['attack_type']} in {case['parameter']}",
        severity=case.get("severity", "medium"),
        cwe="",
        attack_type=case["attack_type"],
        evidence=case.get("evidence", ""),
        payload=case.get("payload", ""),
        parameter=case.get("parameter", ""),
        url=case["url"],
        request_method="GET",
        raw_response_snippet=case.get("response_snippet", ""),
    )
    target = CheckTarget(
        method="GET", url=case["url"],
        headers={"content-type": "application/json"},
        body=None, params=[],
    )
    try:
        confirmed, confidence, reasoning = await red_team.validate(finding, target)
    except Exception as exc:
        return CaseResult(case["name"], False, f"validate raised: {exc}",
                          case.get("injection_probe", False))

    passed = confirmed == case["expect_confirmed"]
    detail = (f"confirmed={confirmed} conf={confidence:.2f} "
              f"expected={case['expect_confirmed']}")
    return CaseResult(case["name"], passed, detail, case.get("injection_probe", False))


async def run_suite(suite: str) -> SuiteResult:
    if suite == "planner":
        cases = _load_cases("planner_cases.yaml")
        runner = _run_planner_case
    elif suite == "red_team":
        cases = _load_cases("red_team_cases.yaml")
        runner = _run_red_team_case
    else:
        raise ValueError(f"unknown suite: {suite}")

    result = SuiteResult(suite=suite)
    # Sequential on purpose — keeps token usage predictable and output readable.
    for case in cases:
        cr = await runner(case)
        result.results.append(cr)
        mark = "PASS" if cr.passed else "FAIL"
        probe = " [injection]" if cr.injection_probe else ""
        print(f"  [{mark}]{probe} {cr.name}: {cr.detail}")
    return result


async def main_async(args: argparse.Namespace) -> int:
    suites = ["planner", "red_team"] if args.suite == "all" else [args.suite]
    exit_code = 0
    for suite in suites:
        print(f"\n=== eval suite: {suite} ===")
        result = await run_suite(suite)
        print(f"  accuracy: {result.accuracy:.0%} "
              f"({sum(1 for r in result.results if r.passed)}/{len(result.results)})")
        inj = result.injection_accuracy
        if inj is not None:
            print(f"  injection-resistance: {inj:.0%}")
        if args.min_accuracy and result.accuracy < args.min_accuracy:
            print(f"  BELOW THRESHOLD ({args.min_accuracy:.0%}) — suite '{suite}' failed")
            exit_code = 1
    return exit_code


def main() -> None:
    parser = argparse.ArgumentParser(description="Run LLM decision-quality evals.")
    parser.add_argument("--suite", choices=["all", "planner", "red_team"], default="all")
    parser.add_argument("--min-accuracy", type=float, default=0.0,
                        help="Exit non-zero if any suite scores below this (0-1).")
    args = parser.parse_args()
    sys.exit(asyncio.run(main_async(args)))


if __name__ == "__main__":
    main()
