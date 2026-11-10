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


def test_function_level_authz_infers_bfla_not_idor() -> None:
    # A role bypass on one's own tenant is function-level (BFLA), not object-level (IDOR).
    finding = {"title": "Broken function level authorization: learner can archive admin module",
               "description": "no role check", "cwe": "CWE-862"}
    assert _infer_attack_type(finding) == "bfla"


def test_object_reference_still_infers_idor() -> None:
    finding = {"title": "Insecure Direct Object Reference", "description": "cross-tenant",
               "cwe": "CWE-639"}
    assert _infer_attack_type(finding) == "idor"
