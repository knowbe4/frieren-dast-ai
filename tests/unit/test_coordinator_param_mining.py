"""
Unit tests for Coordinator._run_param_mining_pass — the automatic
hidden-parameter mining the LLM planner can trigger (mine_params=True).

Guarantees:
  * discovered names are folded onto target.params as fresh attack surface
    (mapped from the miner's location vocabulary to the agent vocabulary),
  * a param_mining_hint is set for the mutator,
  * names already on the target are not duplicated,
  * the pass is fully defensive — a miner failure leaves target.params intact,
  * the coordinator's own client is reused (passed through to run_param_mining).
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dast.ai.coordinator import Coordinator
from dast.scanners.active_checks import CheckTarget


def _target(params=None):
    return CheckTarget(
        method="GET",
        url="https://example.com/api/item",
        headers={"content-type": "application/json"},
        body=None,
        params=params if params is not None else [
            {"name": "id", "location": "query", "value": "1"},
        ],
    )


def _run(coro):
    return asyncio.run(coro)


@pytest.mark.asyncio
async def test_discovered_params_folded_onto_target():
    target = _target()
    client = MagicMock()
    hits = [
        {"parameter": "debug", "location": "query", "reason": "reflected", "status": 200},
        {"parameter": "callback", "location": "json", "reason": "behavior-change", "status": 200},
    ]

    with patch(
        "dast.scanners.param_miner.run_param_mining",
        new=AsyncMock(return_value=hits),
    ) as fake_mine:
        await Coordinator._run_param_mining_pass(target, client)

    # The shared client is reused, not a fresh one.
    assert fake_mine.call_args.kwargs["client"] is client

    names = {p["name"]: p["location"] for p in target.params}
    assert names["debug"] == "query"        # query stays query
    assert names["callback"] == "body"      # json → body (agent vocabulary)
    assert "id" in names                    # original param retained
    assert "debug" in target.param_mining_hint
    assert "callback" in target.param_mining_hint


@pytest.mark.asyncio
async def test_no_hits_leaves_target_untouched():
    target = _target()
    with patch(
        "dast.scanners.param_miner.run_param_mining",
        new=AsyncMock(return_value=[]),
    ):
        await Coordinator._run_param_mining_pass(target, MagicMock())

    assert [p["name"] for p in target.params] == ["id"]
    assert target.param_mining_hint == ""


@pytest.mark.asyncio
async def test_existing_param_not_duplicated():
    target = _target()
    hits = [{"parameter": "id", "location": "query", "reason": "reflected", "status": 200}]
    with patch(
        "dast.scanners.param_miner.run_param_mining",
        new=AsyncMock(return_value=hits),
    ):
        await Coordinator._run_param_mining_pass(target, MagicMock())

    # 'id' already existed — no duplicate row, no hint (nothing new discovered).
    assert [p["name"] for p in target.params] == ["id"]
    assert target.param_mining_hint == ""


@pytest.mark.asyncio
async def test_miner_failure_is_defensive():
    target = _target()
    with patch(
        "dast.scanners.param_miner.run_param_mining",
        new=AsyncMock(side_effect=RuntimeError("boom")),
    ):
        # Must not raise.
        await Coordinator._run_param_mining_pass(target, MagicMock())

    assert [p["name"] for p in target.params] == ["id"]
    assert target.param_mining_hint == ""
