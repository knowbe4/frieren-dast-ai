"""
Database-dialect knowledge for tech-aware payload exclusion.

SQLi time-based payloads are dialect-specific individual strings inside one group
(``SLEEP(`` = MySQL, ``WAITFOR DELAY`` = MSSQL, ``pg_sleep`` = PostgreSQL,
``sqlite_master`` = SQLite, ``dbms_``/``utl_`` = Oracle). When the fingerprinter
has pinned the backend to a single known database, firing the other dialects'
payloads is pure noise. This module says which DB a set of hints points to, and
strips payloads that carry a *different* dialect's marker.

Conservative by design: if the hints are ambiguous (zero or more than one known
DB), ``definite_db`` returns None and nothing is stripped — coverage is never
reduced on uncertainty.
"""

from __future__ import annotations

import re
from typing import List, Optional

# Canonical DB name -> regex matching that dialect's signature in a payload string
# OR in a free-text tech signal. Case-insensitive.
_DB_MARKERS = {
    "MySQL": re.compile(r"\bSLEEP\s*\(|\bmysql\b|\bmariadb\b", re.IGNORECASE),
    "MSSQL": re.compile(r"WAITFOR\s+DELAY|\bmssql\b|sql\s*server|sqlserver|\bxp_cmdshell\b", re.IGNORECASE),
    "PostgreSQL": re.compile(r"\bpg_sleep\b|\bpostgres(?:ql)?\b|\bpg::|\bnpgsql\b", re.IGNORECASE),
    "SQLite": re.compile(r"\bsqlite_master\b|\bsqlite3?\b|\brandomblob\b", re.IGNORECASE),
    "Oracle": re.compile(r"\bdbms_(?:pipe|lock)\b|\butl_\b|\bora-\d|\boracle\b", re.IGNORECASE),
}

# Databases whose dialect this module can distinguish in payload strings. A hint
# naming any other engine (Mongo, Redis, …) is not an SQL dialect and is ignored
# for SQLi dialect selection.
_KNOWN_SQL_DBS = frozenset(_DB_MARKERS)


def definite_db(database_hints: List[str]) -> Optional[str]:
    """Return the single SQL database the hints unambiguously point to, else None.

    ``None`` when zero or more than one known SQL DB appears — the safe default
    that strips nothing.
    """
    matched = set()
    for hint in database_hints or []:
        for db, pattern in _DB_MARKERS.items():
            if pattern.search(hint or ""):
                matched.add(db)
    return next(iter(matched)) if len(matched) == 1 else None


def strip_foreign_dialect(payloads: List[str], db: str) -> List[str]:
    """Drop payloads carrying ANOTHER known SQL dialect's marker; keep generic
    payloads (no dialect marker) and the matching DB's. No-op if ``db`` is not a
    known SQL database."""
    if db not in _KNOWN_SQL_DBS:
        return list(payloads)
    foreign = [(name, pattern) for name, pattern in _DB_MARKERS.items() if name != db]
    kept: List[str] = []
    for payload in payloads:
        if any(pattern.search(payload) for _name, pattern in foreign):
            continue
        kept.append(payload)
    return kept
