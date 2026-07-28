"""
Structural tests for the LLM eval golden sets (tests/evals/*.yaml).

These run in the DEFAULT pytest run (no Bedrock, no tokens). They do NOT measure
decision quality — that is what `tests/evals/run_evals.py` does against the live
model. Their job is to stop the golden set from silently rotting: every case must
be well-formed and self-consistent, and the red-team set must stay balanced
between real vulns (false-negative guard) and look-alikes (false-positive guard).
A skewed or malformed golden set produces a meaningless accuracy number.
"""

from __future__ import annotations

from pathlib import Path

import yaml

_EVALS_DIR = Path(__file__).parent.parent / "evals"


def _load(filename: str) -> list[dict]:
    data = yaml.safe_load((_EVALS_DIR / filename).read_text(encoding="utf-8"))
    return data.get("cases", [])


class TestRedTeamGoldenSet:
    def setup_method(self):
        self.cases = _load("red_team_cases.yaml")

    def test_cases_present(self):
        assert len(self.cases) >= 20, "golden set too small to measure FP/FN meaningfully"

    def test_required_fields_and_types(self):
        for case in self.cases:
            for field in ("name", "attack_type", "url", "expect_confirmed"):
                assert field in case, f"case {case.get('name', '?')} missing {field}"
            assert isinstance(case["expect_confirmed"], bool), (
                f"case {case['name']}: expect_confirmed must be a bool"
            )

    def test_names_are_unique(self):
        names = [c["name"] for c in self.cases]
        assert len(names) == len(set(names)), "duplicate case names"

    def test_balanced_polarity(self):
        # A lopsided set inflates accuracy: a model that always says "reject"
        # scores high on an all-negative set while catching zero real vulns.
        positives = sum(1 for c in self.cases if c["expect_confirmed"])
        negatives = len(self.cases) - positives
        assert positives >= 8, "need enough real-vuln cases to measure false negatives"
        assert negatives >= 8, "need enough look-alike cases to measure false positives"

    def test_injection_probes_present(self):
        # Prompt-injection resistance must be measured in BOTH directions:
        # a snippet trying to force confirm, and one trying to force reject.
        probes = [c for c in self.cases if c.get("injection_probe")]
        assert len(probes) >= 2, "need injection probes to validate prompt_safety"
        verdicts = {c["expect_confirmed"] for c in probes}
        assert verdicts == {True, False}, "injection probes must cover both verdict directions"

    def test_attack_type_breadth(self):
        # The knowledge base spans the top-20 web vulns; the golden set should
        # sample broadly, not concentrate on one or two types.
        types = {c["attack_type"] for c in self.cases}
        assert len(types) >= 8, f"golden set covers only {len(types)} attack types"


class TestPlannerGoldenSet:
    def setup_method(self):
        self.cases = _load("planner_cases.yaml")

    def test_required_fields(self):
        for case in self.cases:
            for field in ("name", "method", "url"):
                assert field in case, f"planner case {case.get('name', '?')} missing {field}"
            # A case that neither includes nor excludes anything asserts nothing.
            assert case.get("expect_include") or case.get("expect_exclude"), (
                f"planner case {case['name']} has no expectation"
            )
