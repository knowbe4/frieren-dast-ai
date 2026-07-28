"""
DashboardContext — shared mutable state passed to every API router.

All router factories receive a single ctx: DashboardContext so they can
access the store, queues, and mutable dicts without needing the full
build_app closure.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional, Set

from fastapi import WebSocket

if TYPE_CHECKING:
    from dast.proxy.session_store import SessionStore
    from dast.proxy.proxy_settings import ProxySettings
    from dast.proxy.cert_authority import CertAuthority
    from dast.proxy.plugin_manager import PluginManager
    from dast.proxy.scan_queue_state import ScanQueueState
    from dast.proxy.runner import ProxyRunner
    from dast.proxy.intercept_store import InterceptStore


@dataclass
class DashboardContext:
    store: "SessionStore"
    scan_queue: asyncio.Queue
    ca: Optional["CertAuthority"] = None
    settings: Optional["ProxySettings"] = None
    crawl_queue: Optional[asyncio.Queue] = None
    plugin_manager: Optional["PluginManager"] = None
    browse_queue: Optional[asyncio.Queue] = None
    discovery_queue: Optional[asyncio.Queue] = None
    proxy_port: int = 8080
    scan_config: Optional[dict] = None
    scan_queue_state: Optional["ScanQueueState"] = None
    runner: Optional["ProxyRunner"] = None
    intercept_store: Optional["InterceptStore"] = None

    # Mutable runtime state — shared across all routers
    ws_clients: Set[WebSocket] = field(default_factory=set)
    crawl_log_clients: Set[WebSocket] = field(default_factory=set)
    status_cache: dict = field(default_factory=dict)
    status_cache_ts: list = field(default_factory=lambda: [0.0])
    auto_scan_enabled: list = field(default_factory=lambda: [False])  # list for mutability
    intruder_jobs: dict = field(default_factory=dict)
    import_findings_jobs: dict = field(default_factory=dict)
    graphql_fuzz_jobs: dict = field(default_factory=dict)

    # Effective scan config dict (aliased from scan_config or a new dict)
    _scan_cfg: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Default model IDs come from dast.config.settings (the single source of
        # truth for model ARNs/names) — override at runtime via POST /api/scan-config
        # or the AI tab.
        from dast.config import settings as _settings
        default_fast_model = _settings.anthropic_default_haiku_model
        default_validation_model = _settings.anthropic_default_opus_model

        if self.scan_config is not None:
            self._scan_cfg = self.scan_config
        else:
            self._scan_cfg = {
                "workers": 2,
                "probe_concurrency": 3,
                "passive_enabled": True,
                "passive_ai": True,
                "active_enabled": True,
                "llm_planner": True,
                "llm_validator": True,
                "model_id": "",
                "fast_model_id": default_fast_model,
                "validation_model_id": default_validation_model,
                "confidence_threshold": 0.5,
                "scan_budget_seconds": 300,
                "passive_aggressive_rules": False,
            }

        # Apply tiered model defaults to bedrock_client immediately
        from dast.ai import bedrock_client as _bc
        _bc.set_tiered_models(
            fast=self._scan_cfg.get("fast_model_id", default_fast_model),
            validation=self._scan_cfg.get("validation_model_id", default_validation_model),
        )

    async def broadcast(self, entry) -> None:
        import json
        dead = set()
        msg = json.dumps(entry.to_dict())
        for ws in list(self.ws_clients):
            try:
                await ws.send_text(msg)
            except Exception:
                dead.add(ws)
        self.ws_clients.difference_update(dead)

    async def broadcast_crawl_log(self, msg: str) -> None:
        dead = set()
        for ws in list(self.crawl_log_clients):
            try:
                await ws.send_text(msg)
            except Exception:
                dead.add(ws)
        self.crawl_log_clients.difference_update(dead)
