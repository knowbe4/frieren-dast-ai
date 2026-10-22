"""
Unit tests for tech-aware SQL dialect exclusion (dast/agents/db_dialect.py +
its use in payload_filter.get_filtered_payloads).
"""

from __future__ import annotations

import re
from types import SimpleNamespace

from dast.agents import db_dialect
from dast.agents.payload_filter import get_filtered_payloads
from dast.payloads.loader import get_payloads

_FOREIGN_TO_MYSQL = re.compile(r"WAITFOR\s+DELAY|pg_sleep|sqlite_master", re.IGNORECASE)


def test_definite_db_single():
    assert db_dialect.definite_db(["MySQL"]) == "MySQL"
    assert db_dialect.definite_db(["PostgreSQL"]) == "PostgreSQL"


def test_definite_db_ambiguous_or_unknown_returns_none():
    assert db_dialect.definite_db(["MySQL", "PostgreSQL"]) is None  # ambiguous
    assert db_dialect.definite_db([]) is None                        # nothing
    assert db_dialect.definite_db(["MongoDB"]) is None               # not a known SQL dialect
    assert db_dialect.definite_db(["Redis", "Elasticsearch"]) is None


def test_strip_foreign_dialect_keeps_matching_and_generic():
    payloads = get_payloads("sqli", "time_based")
    kept = db_dialect.strip_foreign_dialect(payloads, "MySQL")
    assert any("SLEEP(" in p.upper() for p in kept)         # MySQL kept
    assert not any(_FOREIGN_TO_MYSQL.search(p) for p in kept)  # MSSQL/PG/SQLite dropped
    assert len(kept) < len(payloads)                         # something was actually removed


def test_strip_foreign_dialect_unknown_db_is_noop():
    payloads = get_payloads("sqli", "time_based")
    assert db_dialect.strip_foreign_dialect(payloads, "MongoDB") == payloads


def _target_with_db(db_hints):
    tech = SimpleNamespace(database_hints=db_hints, language=None, framework=None, server=None,
                           template_engine=None, cms=None)
    dc = SimpleNamespace(tech_stack=tech)
    return SimpleNamespace(
        url="https://app.example.com/item?id=1", body=None,
        headers={}, app_profile_hint="", discovery_context=dc,
    )


def test_get_filtered_payloads_excludes_mssql_on_mysql_target():
    target = _target_with_db(["MySQL"])
    payloads = get_filtered_payloads("sqli", target)
    assert payloads, "should still return MySQL + generic payloads"
    assert not any(_FOREIGN_TO_MYSQL.search(p) for p in payloads)


def test_get_filtered_payloads_keeps_all_when_db_ambiguous():
    ambiguous = get_filtered_payloads("sqli", _target_with_db(["MySQL", "MSSQL"]))
    # Ambiguous DB -> no exclusion -> the WAITFOR/pg_sleep payloads survive.
    assert any(_FOREIGN_TO_MYSQL.search(p) for p in ambiguous)
