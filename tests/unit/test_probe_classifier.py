"""
Unit tests for the probe-diff LLM classifier.

Covers: no-signal short-circuit (no LLM call), successful classification into a
ProbeVerdict, and graceful degradation to the inert verdict on LLM failure.
"""

from __future__ import annotations

from unittest.mock import patch

from dast.ai import probe_classifier as pc
from dast.agents.probe_diff import DiffSignature, PairResult, ResponseAttrs


def _sig_with_signal():
    sig = DiffSignature(
        parameter="id", location="query",
        url="https://in.scope/item?id=1", method="GET",
        baseline_attrs=ResponseAttrs(200, 100, 10, "h1", False, "", False),
    )
    sig.pairs.append(PairResult(
        label="string_quote",
        hint="single quote breaks but escaped quote does not -> SQL string context",
        break_attrs=ResponseAttrs(500, 200, 12, "h2", False, "sql syntax", False),
        repair_attrs=ResponseAttrs(200, 100, 10, "h1", False, "", False),
        diverged=True,
        divergent_attrs=["status", "error_signature"],
    ))
    return sig


def _sig_no_signal():
    sig = DiffSignature(
        parameter="id", location="query",
        url="https://in.scope/item?id=1", method="GET",
        baseline_attrs=ResponseAttrs(200, 100, 10, "h1", False, "", False),
    )
    sig.pairs.append(PairResult(
        label="string_quote", hint="...",
        break_attrs=ResponseAttrs(200, 100, 10, "h1", False, "", False),
        repair_attrs=ResponseAttrs(200, 100, 10, "h1", False, "", False),
        diverged=False, divergent_attrs=[],
    ))
    return sig


def test_no_signal_short_circuits_without_llm():
    with patch.object(pc.bedrock_client, "invoke_json") as inv:
        verdict = pc.classify(_sig_no_signal())
    inv.assert_not_called()
    assert verdict.injection_class == "none"
    assert verdict.has_hypothesis is False


def test_none_signature_returns_unknown():
    assert pc.classify(None).has_hypothesis is False


def test_successful_classification():
    fake = {
        "injection_class": "SQLI",
        "context": "single-quoted SQL string",
        "confidence": 0.8,
        "recommended_agents": ["SQLI", "nosql"],
        "reasoning": "quote breaks, escaped quote does not",
    }
    with patch.object(pc.bedrock_client, "invoke_json", return_value=fake), \
         patch.object(pc.bedrock_client, "get_fast_model", return_value="m"):
        verdict = pc.classify(_sig_with_signal())
    assert verdict.injection_class == "sqli"  # normalised lower-case
    assert verdict.recommended_agents == ["sqli", "nosql"]
    assert verdict.confidence == 0.8
    assert verdict.has_hypothesis is True


def test_llm_failure_degrades_to_unknown():
    with patch.object(pc.bedrock_client, "invoke_json", side_effect=RuntimeError("boom")):
        verdict = pc.classify(_sig_with_signal())
    assert verdict.injection_class == "none"
    assert verdict.has_hypothesis is False


def test_bad_confidence_type_degrades():
    fake = {"injection_class": "sqli", "context": "x", "confidence": "not-a-number",
            "recommended_agents": [], "reasoning": "y"}
    with patch.object(pc.bedrock_client, "invoke_json", return_value=fake):
        verdict = pc.classify(_sig_with_signal())
    assert verdict.has_hypothesis is False
