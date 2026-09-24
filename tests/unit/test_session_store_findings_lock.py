"""
Every mutation of ProxyEntry.findings goes through one locked, deduplicating
path on SessionStore (``_append_finding_locked``): agent/plugin findings via
``add_finding`` and import stubs via ``_drain_pending_findings``. Plugin
dispatch only reads findings through the store's locked snapshot.
"""

from __future__ import annotations

import asyncio
from typing import List

import pytest

from dast.proxy import plugin_manager as plugin_manager_module
from dast.proxy.plugin_base import ProxyPlugin
from dast.proxy.plugin_manager import PluginManager
from dast.proxy.session_store import ProxyEntry, SessionStore


def _store_with_entry(path: str = "/api/users") -> tuple[SessionStore, ProxyEntry]:
    store = SessionStore()
    entry_id = store.new_entry("GET", f"https://example.com{path}", {}, None)
    assert entry_id is not None
    entry = store.get_entry(entry_id)
    assert entry is not None
    return store, entry


def _spy_on_locked_append(store: SessionStore, monkeypatch: pytest.MonkeyPatch) -> List[bool]:
    """Wrap _append_finding_locked; record whether the store lock was held on each call."""
    lock_held_per_call: List[bool] = []
    original = store._append_finding_locked

    def spy(entry: ProxyEntry, finding: dict, attach_evidence: bool) -> bool:
        lock_held_per_call.append(store._lock.locked())
        return original(entry, finding, attach_evidence)

    monkeypatch.setattr(store, "_append_finding_locked", spy)
    return lock_held_per_call


def _finding(title: str = "Reflected XSS", parameter: str = "q") -> dict:
    return {"title": title, "attack_type": "xss", "parameter": parameter}


class TestAddFindingPath:
    def test_add_finding_appends_under_lock_and_dedups(self, monkeypatch: pytest.MonkeyPatch) -> None:
        store, entry = _store_with_entry()
        lock_held = _spy_on_locked_append(store, monkeypatch)

        store.add_finding(entry.id, _finding(), "vulnerable")
        store.add_finding(entry.id, _finding(), "vulnerable")

        assert lock_held == [True, True]
        assert len(entry.findings) == 1
        assert entry.scan_result == "vulnerable"

    def test_add_finding_attaches_raw_request_evidence(self) -> None:
        store, entry = _store_with_entry()
        store.add_finding(entry.id, _finding(), "vulnerable")
        assert entry.findings[0].get("raw_request")

    def test_duplicate_does_not_change_scan_result(self) -> None:
        store, entry = _store_with_entry()
        store.add_finding(entry.id, _finding(), "vulnerable")
        store.add_finding(entry.id, _finding(), "safe")
        # Duplicate returns early — scan_result is untouched.
        assert entry.scan_result == "vulnerable"

    def test_confirmed_finding_upgrades_held_duplicate(self) -> None:
        # A finding held for review while the AI was offline must be promoted
        # (not deduped away) when a later confirmed finding with the same key
        # arrives on re-scan.
        store, entry = _store_with_entry()
        held = {**_finding(), "confirmed": False, "needs_review": True,
                "validated_by": ["unvalidated"]}
        store.add_finding(entry.id, held, "vulnerable")
        assert len(entry.findings) == 1
        assert entry.findings[0]["confirmed"] is False

        confirmed = {**_finding(), "confirmed": True, "validated_by": ["ai"],
                     "reasoning": "exploit proven"}
        store.add_finding(entry.id, confirmed, "vulnerable")

        # Upgraded in place — still a single finding, now confirmed.
        assert len(entry.findings) == 1
        assert entry.findings[0]["confirmed"] is True
        assert entry.findings[0]["validated_by"] == ["ai"]

    def test_held_finding_does_not_downgrade_confirmed_duplicate(self) -> None:
        # The reverse must NOT happen: a held finding arriving after a confirmed
        # one is skipped, leaving the confirmed finding intact.
        store, entry = _store_with_entry()
        confirmed = {**_finding(), "confirmed": True, "validated_by": ["ai"]}
        store.add_finding(entry.id, confirmed, "vulnerable")

        held = {**_finding(), "confirmed": False, "needs_review": True,
                "validated_by": ["unvalidated"]}
        store.add_finding(entry.id, held, "vulnerable")

        assert len(entry.findings) == 1
        assert entry.findings[0]["confirmed"] is True

    def test_empty_finding_only_updates_scan_result(self, monkeypatch: pytest.MonkeyPatch) -> None:
        store, entry = _store_with_entry()
        lock_held = _spy_on_locked_append(store, monkeypatch)
        store.add_finding(entry.id, {}, "safe")
        assert lock_held == []
        assert entry.findings == []
        assert entry.scan_result == "safe"


class TestPendingImportStubPath:
    def test_stub_goes_through_locked_path_and_dedups_against_existing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store, entry = _store_with_entry()
        store.add_finding(entry.id, _finding(), "vulnerable")
        lock_held = _spy_on_locked_append(store, monkeypatch)

        duplicate_stub = _finding()
        fresh_stub = _finding(title="SQL Injection", parameter="id")
        store.pending_import_findings = [
            {"path": "/api/users", "method": "GET", "hints": [], "stub": duplicate_stub},
            {"path": "/api/users", "method": "GET", "hints": [{"parameter": "id"}], "stub": fresh_stub},
        ]
        store._drain_pending_findings(entry)

        assert lock_held == [True, True]
        titles = [f["title"] for f in entry.findings]
        assert titles == ["Reflected XSS", "SQL Injection"]
        assert store.pending_import_findings == []
        assert entry.import_hints == [{"parameter": "id"}]

    def test_stub_does_not_receive_raw_evidence(self) -> None:
        store, entry = _store_with_entry()
        stub = _finding(title="Imported IDOR", parameter="user_id")
        store.pending_import_findings = [{"path": "/api/users", "method": "GET", "stub": stub}]
        store._drain_pending_findings(entry)
        assert entry.findings == [stub]
        assert "raw_request" not in entry.findings[0]
        assert entry.queued_for_scan is True

    def test_unmatched_pending_findings_are_kept(self) -> None:
        store, entry = _store_with_entry()
        pending = {"path": "/other", "method": "POST", "stub": _finding()}
        store.pending_import_findings = [pending]
        store._drain_pending_findings(entry)
        assert store.pending_import_findings == [pending]
        assert entry.findings == []


class _DuplicateReportingPlugin(ProxyPlugin):
    name = "duplicate_reporter"

    async def on_entry(self, entry: ProxyEntry, store: SessionStore) -> None:
        store.add_finding(entry.id, _finding(title="Plugin finding"), "vulnerable")
        store.add_finding(entry.id, _finding(title="Plugin finding"), "vulnerable")


class _RemovingPlugin(ProxyPlugin):
    name = "remove_then_add"

    async def on_entry(self, entry: ProxyEntry, store: SessionStore) -> None:
        store.remove_finding(entry.id, 0)
        store.add_finding(entry.id, _finding(title="Replacement finding"), "vulnerable")


class TestPluginDispatchPath:
    def _run_dispatch(
        self, plugin: ProxyPlugin, store: SessionStore, entry: ProxyEntry,
        monkeypatch: pytest.MonkeyPatch,
    ) -> List[dict]:
        logged_events: List[dict] = []

        def capture_log_event(**kwargs: str) -> None:
            logged_events.append(kwargs)

        monkeypatch.setattr(plugin_manager_module, "log_event", capture_log_event)
        manager = PluginManager()
        manager._plugins = [plugin]
        asyncio.run(manager.dispatch(entry, store))
        return logged_events

    def test_plugin_findings_hit_lock_and_dedup(self, monkeypatch: pytest.MonkeyPatch) -> None:
        store, entry = _store_with_entry()
        lock_held = _spy_on_locked_append(store, monkeypatch)

        snapshot_calls: List[bool] = []
        original_snapshot = store.snapshot_findings

        def snapshot_spy(target_entry: ProxyEntry) -> List[dict]:
            snapshot_calls.append(True)
            return original_snapshot(target_entry)

        monkeypatch.setattr(store, "snapshot_findings", snapshot_spy)

        events = self._run_dispatch(_DuplicateReportingPlugin(), store, entry, monkeypatch)

        assert lock_held == [True, True]
        assert len(entry.findings) == 1
        assert len(snapshot_calls) == 2
        assert [event["finding"] for event in events] == ["Plugin finding"]
        assert events[0]["plugin"] == "duplicate_reporter"

    def test_dispatch_logs_new_finding_even_when_plugin_removes_one(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store, entry = _store_with_entry()
        store.add_finding(entry.id, _finding(title="Existing finding"), "vulnerable")

        events = self._run_dispatch(_RemovingPlugin(), store, entry, monkeypatch)

        assert [f["title"] for f in entry.findings] == ["Replacement finding"]
        assert [event["finding"] for event in events] == ["Replacement finding"]

    def test_snapshot_is_a_copy(self) -> None:
        store, entry = _store_with_entry()
        store.add_finding(entry.id, _finding(), "vulnerable")
        snapshot = store.snapshot_findings(entry)
        snapshot.clear()
        assert len(entry.findings) == 1
