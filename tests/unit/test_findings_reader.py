"""Tests for dast.importers.findings_reader attack-type inference.

orchestrator-ai findings carry explicit nulls (e.g. ``"cwe": null``). ``.get(k, "")``
returns None for a present-but-null key, which used to crash the ``" ".join`` in
_infer_attack_type. Inference must tolerate null title/description/cwe.
"""

from __future__ import annotations

from dast.importers.findings_reader import _infer_attack_type


def test_null_cwe_does_not_crash_and_infers_from_text() -> None:
    finding = {"title": "SSRF via unvalidated image URL", "description": "x", "cwe": None}
    assert _infer_attack_type(finding) == "ssrf"


def test_all_null_fields_yield_a_default() -> None:
    # Must not raise even when every text field is null/absent.
    result = _infer_attack_type({"title": None, "description": None, "cwe": None})
    assert isinstance(result, str)


def test_sqli_inferred_with_null_cwe() -> None:
    finding = {"title": "SQL Injection via unescaped id", "description": None, "cwe": None}
    assert _infer_attack_type(finding) == "sqli"
