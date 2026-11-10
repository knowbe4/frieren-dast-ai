"""Per-host login journal under ~/.dast-ai/login_journal: append-only success/error
records (no secrets), and last_success() returns the freshest known-good record so the
SPA strategy can reuse the known endpoint. Writes go to a tmp dir, not the real HOME.
"""

from __future__ import annotations

import json

import pytest

from dast.session import login_journal


@pytest.fixture(autouse=True)
def _tmp_journal_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(login_journal, "_JOURNAL_DIR", tmp_path / "login_journal")


def test_record_and_last_success_roundtrip():
    login_journal.record("https://app.example.com/login", "error",
                         strategy="deterministic", reason="form raised")
    login_journal.record("https://app.example.com/login", "success", strategy="spa_api",
                         endpoint="https://app.example.com/spa/auth/login",
                         body_shape="email,password", success_url="https://app.example.com/login")
    rec = login_journal.last_success("app.example.com")
    assert rec is not None
    assert rec["strategy"] == "spa_api"
    assert rec["endpoint"] == "https://app.example.com/spa/auth/login"
    assert rec["body_shape"] == "email,password"


def test_last_success_skips_newer_errors():
    base = "https://app.example.com/login"
    login_journal.record(base, "success", strategy="spa_api",
                         endpoint="https://app.example.com/spa/auth/login")
    login_journal.record(base, "error", strategy="spa_api", reason="creds rotated")
    # The freshest SUCCESS wins, even though a newer error exists.
    rec = login_journal.last_success("app.example.com")
    assert rec is not None and rec["outcome"] == "success"


def test_no_secrets_are_written(tmp_path):
    login_journal.record("https://app.example.com/login", "success", strategy="spa_api",
                         endpoint="https://app.example.com/spa/auth/login",
                         body_shape="email,password")
    path = login_journal._path_for("app.example.com")
    raw = path.read_text(encoding="utf-8")
    entry = json.loads(raw.splitlines()[-1])
    assert set(entry).issubset({
        "ts", "host", "outcome", "strategy", "endpoint", "body_shape", "success_url", "reason"})
    # No secret-bearing KEYS in the record (body_shape may contain the field *name*
    # "password", which is not a secret).
    for banned in ("password", "secret", "token", "authorization", "cookie"):
        assert banned not in entry
    # The literal credential VALUE never appears anywhere in the file.
    assert "pw" not in raw


def test_bad_input_is_ignored():
    assert login_journal.record("", "success") is None
    assert login_journal.record("https://app.example.com", "bogus") is None
    assert login_journal.last_success("never-seen.example.com") is None


def test_recent_records_most_recent_first_all_strategies():
    # A deterministic success has no endpoint, so last_success skips it — recent_records sees it.
    login_journal.record("https://app.example.com/login", "error", strategy="deterministic",
                         reason="bad creds")
    login_journal.record("https://app.example.com/login", "success", strategy="deterministic",
                         success_url="https://app.example.com/dashboard")
    recs = login_journal.recent_records("app.example.com")
    assert [r["strategy"] for r in recs] == ["deterministic", "deterministic"]
    assert recs[0]["outcome"] == "success"   # most recent first
    assert login_journal.recent_records("never-seen.example.com") == []


def test_last_winning_strategy_returns_recent_success_any_strategy():
    login_journal.record("https://app.example.com/login", "success", strategy="deterministic",
                         success_url="https://app.example.com/dashboard")
    assert login_journal.last_winning_strategy("app.example.com") == "deterministic"
    # A later spa_api success wins.
    login_journal.record("https://app.example.com/login", "success", strategy="spa_api",
                         endpoint="https://app.example.com/spa/auth/login")
    assert login_journal.last_winning_strategy("app.example.com") == "spa_api"
    # A later failure does not overwrite the last SUCCESS.
    login_journal.record("https://app.example.com/login", "error", strategy="llm",
                         reason="gave up")
    assert login_journal.last_winning_strategy("app.example.com") == "spa_api"
    assert login_journal.last_winning_strategy("never-seen.example.com") is None
