"""Unit tests for dast.scanners.oob_correlator — marker attribution, no network."""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

from dast.scanners.oob_correlator import OobCorrelator, OobHit, interaction_labels


class FakeSession:
    """Stand-in for InteractshSession: fixed domain, queued interaction batches."""

    def __init__(self, registers: bool = True) -> None:
        self._registers = registers
        self.url = "http://abcdefghijklmnopqrst0123456789abc.oast.test"
        self.batches: List[List[Dict[str, Any]]] = []
        self.deregistered = False

    async def register(self) -> bool:
        return self._registers

    def marker_host(self, marker: str) -> str:
        return f"{marker}.abcdefghijklmnopqrst0123456789abc.oast.test"

    async def fetch_interactions(self) -> List[Dict[str, Any]]:
        return self.batches.pop(0) if self.batches else []

    async def deregister(self) -> None:
        self.deregistered = True



def _correlator(session: FakeSession, hits: List[OobHit]) -> OobCorrelator:
    async def _on_hit(hit: OobHit) -> None:
        hits.append(hit)

    correlator = OobCorrelator(label="test", on_hit=_on_hit, session_factory=lambda: session)
    correlator._register_display = lambda url: None  # no Interactions tab in unit tests
    return correlator


def _dns(full_id: str) -> Dict[str, Any]:
    return {"protocol": "dns", "full-id": full_id, "remote-address": "203.0.113.7"}


@pytest.mark.asyncio
async def test_injection_value_carries_unique_marker_host():
    correlator = _correlator(FakeSession(), [])
    assert await correlator.start()
    first = correlator.new_injection("e1", "https://t/a", "get", "header", "Referer", "http://{{OOB_HOST}}/")
    second = correlator.new_injection("e1", "https://t/a", "GET", "header", "From", "root@{{OOB_HOST}}")
    assert first.marker != second.marker
    assert first.value == f"http://{first.marker}.abcdefghijklmnopqrst0123456789abc.oast.test/"
    assert first.method == "GET"


@pytest.mark.asyncio
async def test_hit_is_attributed_to_the_exact_injection():
    session, hits = FakeSession(), []
    correlator = _correlator(session, hits)
    await correlator.start()
    referer = correlator.new_injection("e1", "https://t/a", "GET", "header", "Referer", "{{OOB_HOST}}")
    correlator.new_injection("e1", "https://t/a", "GET", "header", "From", "{{OOB_HOST}}")
    session.batches.append([_dns(f"{referer.marker}.abcdefghijklmnopqrst0123456789abc")])

    assert await correlator.poll_once() == 1
    assert len(hits) == 1
    assert hits[0].injection is referer
    assert hits[0].protocol == "dns"


@pytest.mark.asyncio
async def test_repeated_lookups_report_once_per_protocol_and_http_separately():
    # Resolvers retry and a fetch produces DNS then HTTP: one hit per protocol.
    session, hits = FakeSession(), []
    correlator = _correlator(session, hits)
    await correlator.start()
    injection = correlator.new_injection("e1", "https://t/a", "GET", "header", "Referer", "{{OOB_HOST}}")
    full_id = f"{injection.marker}.abcdefghijklmnopqrst0123456789abc"
    session.batches.append([_dns(full_id), _dns(full_id), {"protocol": "http", "full-id": full_id}])

    assert await correlator.poll_once() == 2
    assert sorted(hit.protocol for hit in hits) == ["dns", "http"]


@pytest.mark.asyncio
async def test_unknown_marker_is_ignored():
    session, hits = FakeSession(), []
    correlator = _correlator(session, hits)
    await correlator.start()
    correlator.new_injection("e1", "https://t/a", "GET", "header", "Referer", "{{OOB_HOST}}")
    session.batches.append([_dns("frzzzzzzzzzzzz.abcdefghijklmnopqrst0123456789abc")])

    assert await correlator.poll_once() == 0
    assert hits == []


@pytest.mark.asyncio
async def test_unreachable_oob_server_disables_injections():
    correlator = _correlator(FakeSession(registers=False), [])
    assert await correlator.start() is False
    assert correlator.available is False
    assert correlator.new_injection("e1", "u", "GET", "header", "Referer", "{{OOB_HOST}}") is None


@pytest.mark.asyncio
async def test_stop_polls_once_more_and_deregisters():
    session, hits = FakeSession(), []
    correlator = _correlator(session, hits)
    await correlator.start()
    injection = correlator.new_injection("e1", "u", "GET", "header", "From", "{{OOB_HOST}}")
    session.batches.append([_dns(f"{injection.marker}.abcdefghijklmnopqrst0123456789abc")])

    await correlator.stop()

    assert len(hits) == 1
    assert session.deregistered is True


def test_interaction_labels_are_lowercased_and_split():
    labels = interaction_labels({"full-id": "FRABC.Corr", "unique-id": "corr"})
    assert labels == ["frabc", "corr", "corr"]
