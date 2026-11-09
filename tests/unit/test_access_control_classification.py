"""Object-level (IDOR/BOLA) vs function-level (BFLA) access-control classification.

Frieren must not collapse the two: IDOR/BOLA is object-level and cross-tenant
(CWE-639); BFLA is function-level, same-tenant vertical privilege escalation
(CWE-862). These tests lock the taxonomy split across the deterministic maps and
the hypothesis/source classifier.
"""

from __future__ import annotations

from dast.attack.engine import _CWE_MAP, _SEVERITY_MAP
from dast.models import Severity
from dast.proxy.api.code_routes import _vuln_type_to_attack


def test_bfla_is_a_distinct_high_cwe862_class() -> None:
    assert _CWE_MAP["bfla"] == "CWE-862"
    assert _SEVERITY_MAP["bfla"] == Severity.HIGH
    # idor remains object-level CWE-639, not merged into bfla.
    assert _CWE_MAP["idor"] == "CWE-639"


def test_classifier_routes_function_level_to_bfla() -> None:
    for text in ("missing function-level authorization",
                 "broken function level access control",
                 "vertical privilege escalation",
                 "privilege escalation to admin",
                 "CWE-862"):
        assert _vuln_type_to_attack(text) == "bfla", text


def test_classifier_routes_object_level_to_idor() -> None:
    for text in ("insecure direct object reference",
                 "IDOR via incremented id",
                 "BOLA cross-tenant object access",
                 "CWE-639"):
        assert _vuln_type_to_attack(text) == "idor", text
