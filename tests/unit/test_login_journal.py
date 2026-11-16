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
        "ts", "ts_epoch", "host", "outcome", "strategy", "endpoint", "body_shape",
        "success_url", "reason", "verified"})
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
    # A later failure INVALIDATES the promotion: the winner is reordered to the FRONT
    # of the cascade, so promoting it after it just failed would poison every future
    # run (the poisoned-winner audit finding). Fall back to default order instead.
    login_journal.record("https://app.example.com/login", "error", strategy="llm",
                         reason="gave up")
    assert login_journal.last_winning_strategy("app.example.com") is None
    assert login_journal.last_winning_strategy("never-seen.example.com") is None


def test_site_grouping_shares_across_subdomains():
    # conftest seeds site 'alpha' = {admin.alpha.example.com, *.esi.alpha.example.com}; a success
    # recorded on one host is found from a sibling subdomain (same product group).
    assert login_journal.record("https://admin.alpha.example.com/login", "success",
                                 strategy="deterministic",
                                 endpoint="https://admin.alpha.example.com/auth",
                                 success_url="https://admin.alpha.example.com/home") == "alpha"
    rec = login_journal.last_success("us1.esi.alpha.example.com")
    assert rec is not None and rec["strategy"] == "deterministic"
    assert login_journal.last_winning_strategy("x.esi.alpha.example.com") == "deterministic"


def test_legacy_per_host_journal_still_read_after_grouping():
    # A pre-existing per-host journal (written before grouping) is still read via legacy fallback.
    login_journal.journal_dir()
    legacy = login_journal._path_for("admin.alpha.example.com")
    import time as _time
    legacy.write_text(json.dumps({"ts_epoch": _time.time(), "outcome": "success",
                                  "strategy": "llm",
                                  "endpoint": "https://admin.alpha.example.com/auth",
                                  "host": "admin.alpha.example.com"}) + "\n", encoding="utf-8")
    rec = login_journal.last_success("admin.alpha.example.com")   # site-key file absent -> legacy
    assert rec is not None and rec["strategy"] == "llm"


# ── TTL + failure invalidation (round 2-B) ───────────────────────────────────

def _write_raw(key, entry):
    login_journal._path_for(key).parent.mkdir(parents=True, exist_ok=True)
    with login_journal._path_for(key).open("a", encoding="utf-8") as h:
        h.write(json.dumps(entry) + "\n")


def test_success_older_than_ttl_is_ignored():
    import time as _time
    key = "app.ttl.example.com"
    old = _time.time() - 8 * 24 * 3600
    _write_raw(key, {"ts_epoch": old, "outcome": "success", "strategy": "spa_api",
                     "endpoint": f"https://{key}/spa/auth/login", "host": key})
    fresh = _time.time() - 60
    _write_raw(key, {"ts_epoch": fresh, "outcome": "success", "strategy": "spa_api",
                     "endpoint": f"https://{key}/api/auth/login", "host": key})
    rec = login_journal.last_success(key)
    assert rec["endpoint"] == f"https://{key}/api/auth/login"  # only the fresh one
    # All-stale journal → None.
    _write_raw(key, {"ts_epoch": old, "outcome": "error", "strategy": "spa_api",
                     "endpoint": f"https://{key}/api/auth/login", "host": key})
    rec2 = login_journal.last_success(key)
    # The STALE error (8 days old) does NOT invalidate the fresh success.
    assert rec2 is not None and rec2["endpoint"] == f"https://{key}/api/auth/login"
    # A FRESH error on the learned endpoint does.
    _write_raw(key, {"ts_epoch": _time.time() - 30, "outcome": "error",
                     "strategy": "spa_api",
                     "endpoint": f"https://{key}/api/auth/login", "host": key})
    assert login_journal.last_success(key) is None


def test_error_on_learned_endpoint_invalidates_it():
    """The last attempt against the learned endpoint FAILED — the learned shape no
    longer works, so last_success must not hand it back."""
    base = "https://app.inv.example.com/login"
    learned = "https://app.inv.example.com/spa/auth/login"
    login_journal.record(base, "success", strategy="spa_api", endpoint=learned)
    login_journal.record(base, "error", strategy="spa_api", endpoint=learned,
                         reason="credentials rejected")
    rec = login_journal.last_success(base)
    assert rec is None


def test_error_elsewhere_does_not_invalidate_other_endpoint_success():
    base = "https://app.inv2.example.com/login"
    login_journal.record(base, "success", strategy="spa_api",
                         endpoint="https://app.inv2.example.com/spa/auth/login")
    login_journal.record(base, "error", strategy="spa_api",
                         endpoint="https://app.inv2.example.com/api/login",
                         reason="no such endpoint")
    rec = login_journal.last_success(base)
    assert rec is not None and rec["endpoint"].endswith("/spa/auth/login")


def test_pre_epoch_entries_are_stale():
    """The TTL exists to stop forever-living winners; entries predating the epoch
    field cannot be TTL-checked, so they are not promoted."""
    key = "app.preepoch.example.com"
    _write_raw(key, {"ts": "2020-01-01T00:00:00", "outcome": "success",
                     "strategy": "spa_api", "endpoint": f"https://{key}/x", "host": key})
    assert login_journal.last_success(key) is None
    assert login_journal.last_winning_strategy(key) is None
