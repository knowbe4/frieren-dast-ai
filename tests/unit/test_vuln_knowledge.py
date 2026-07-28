"""
Unit tests for the vulnerability knowledge base (dast/vuln_knowledge/).

The KB is data-driven few-shot examples keyed by attack_type. These tests lock
in the two guarantees callers rely on:
  1. Every shipped YAML is well-formed and indexed by its attack_type (+ aliases).
  2. The prompt-formatting helpers degrade gracefully (empty string, never raise)
     for attack types with no coverage.
"""

from __future__ import annotations

from dast.vuln_knowledge import (
    format_examples_block,
    format_positive_examples,
    get_examples,
    known_attack_types,
)
from dast.vuln_knowledge import loader


class TestLoad:
    def test_top_vulns_are_covered(self):
        types = set(known_attack_types())
        # A representative slice of the top-20 web vulns, keyed to live attack_types.
        for expected in (
            "sqli", "xss", "ssrf", "lfi", "cmdi", "ssti", "xxe", "nosql",
            "idor", "auth_bypass", "csrf", "open_redirect",
            "prototype_pollution", "llm_injection", "sensitive_data",
            "jwt", "business_logic", "mfa_bypass", "crlf", "method_tamper",
        ):
            assert expected in types, f"missing knowledge base for {expected}"

    def test_aliases_resolve_to_same_entry(self):
        # path_traversal is an alias of lfi; llm_prompt_leak of llm_injection.
        assert get_examples("path_traversal") == get_examples("lfi")
        assert get_examples("llm_prompt_leak") == get_examples("llm_injection")

    def test_every_type_has_at_least_one_example(self):
        for attack_type in known_attack_types():
            positive, negative = get_examples(attack_type)
            assert positive or negative, f"{attack_type} has no examples"

    def test_example_counts_are_capped(self):
        # Loader caps positives at 3 and negatives at 2 to keep prompts focused.
        for attack_type in known_attack_types():
            positive, negative = get_examples(attack_type)
            assert len(positive) <= loader._MAX_POSITIVE
            assert len(negative) <= loader._MAX_NEGATIVE

    def test_examples_carry_reasoning(self):
        # Reasoning is the whole point — examples without it are dropped by the loader.
        for attack_type in known_attack_types():
            positive, negative = get_examples(attack_type)
            for ex in positive + negative:
                assert ex["reasoning"], f"{attack_type} example missing reasoning"


class TestFormatExamplesBlock:
    def test_block_contains_both_polarities(self):
        block = format_examples_block("sqli")
        assert "REAL vulnerabilities" in block
        assert "NOT vulnerabilities" in block
        assert "confirmed=true" in block
        assert "confirmed=false" in block

    def test_unknown_attack_type_returns_empty(self):
        assert format_examples_block("does_not_exist") == ""

    def test_empty_attack_type_returns_empty(self):
        assert format_examples_block("") == ""


class TestFormatPositiveExamples:
    def test_positive_only_omits_negatives(self):
        block = format_positive_examples("ssrf")
        assert "aim your payloads" in block
        assert "NOT vulnerabilities" not in block

    def test_unknown_attack_type_returns_empty(self):
        assert format_positive_examples("does_not_exist") == ""
