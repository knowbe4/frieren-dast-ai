"""Integration-test isolation for the login journal.

The login-page fixtures all bind to loopback, so every environment shares the host key
``127.0.0.1``. Once ``adaptive_login`` learns per-host strategy ordering from the journal, a
win recorded by one test would reorder the strategies for the next (e.g. a prior spa_api/llm
success on 127.0.0.1 would make a later "solved deterministically" test try that first). Redirect
the journal to a per-test tmp dir so each integration test starts from the default order and
never reads/writes the developer's real ~/.dast-ai/login_journal. Mirrors the unit fixture.
"""

import pytest


@pytest.fixture(autouse=True)
def _isolate_login_journal(tmp_path, monkeypatch):
    from dast.session import login_journal  # noqa: PLC0415
    monkeypatch.setattr(login_journal, "_JOURNAL_DIR", tmp_path / "login_journal")
