"""
Scan worker — drains the scan queue and runs the deterministic layer (param
mining) and, with AI on, the coordinator + agents for each entry.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING
from datetime import datetime, timezone

from dast.proxy.check_target_adapter import _DANGEROUS_SEGMENTS, _entry_to_check_target
from dast.proxy.scan_support import detection_method, normalise_dedup_path, update_import_stubs
from dast.proxy.suggestions import record_param_hit
from dast.utils.tasks import spawn_tracked

from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.models import ScanConfig
    from dast.proxy.runner import ProxyRunner

logger = get_logger(__name__)


async def mine_params_for_entry(runner: "ProxyRunner", entry, proxy_url: str) -> int:
    """
    Run deterministic hidden-parameter mining against a single captured
    request and record each discovered parameter as a recon suggestion.

    This is the AI-off deterministic scan path (invoked from _attack_one when
    AI mode is off but the user explicitly requested a scan) — no LLM, inert
    canary probes only. All HTTP + scope safety lives in
    param_miner.run_param_mining. Returns the number of hidden params found.
    """
    from dast.proxy.plugin_manager import log_event
    from dast.scanners.param_miner import run_param_mining

    base_url = entry.url
    headers = dict(entry.request_headers or {})
    content_type = headers.get("content-type", headers.get("Content-Type", ""))
    body = None
    if entry.request_body:
        try:
            body = entry.request_body.decode("utf-8", errors="replace")
        except Exception:
            body = None

    async def _log_cb(msg: str) -> None:
        log_event("param-mining", "debug", msg, url=base_url, source="agent")

    hits = await run_param_mining(
        base_url=base_url,
        headers=headers,
        settings=runner._settings,
        method=entry.method,
        body=body,
        content_type=content_type,
        proxy_url=proxy_url,
        log_cb=_log_cb,
    )

    recorded = 0
    for hit in hits:
        try:
            record_param_hit(runner._store, hit)
            recorded += 1
        except Exception as e:
            logger.warning("Failed to record param hit",
                           parameter=hit.get("parameter", ""), error=str(e))
    return len(hits)


async def run_scan_worker(runner: "ProxyRunner", config: "ScanConfig", session_mgr) -> None:
    from dast.scanners import active_checks as _ac
    from dast.scanners.active_checks import run_active_checks
    qs = runner._scan_queue_state

    runner._scan_sem = asyncio.Semaphore(runner._workers)
    # `probe_concurrency` is the concurrent-probe budget PER endpoint scan, but
    # the probe semaphore is GLOBAL across all endpoints scanning at once. Sizing
    # it as a flat global cap (previously max(pc, workers)) collapses to roughly
    # one probe slot per worker: a single slow probe — a 5s time-based SLEEP for
    # blind SQLi or command injection — then monopolises a worker's only slot and
    # starves every other probe on that endpoint. Under N concurrent workers the
    # endpoint never finishes its time-based probes within the per-endpoint budget
    # and an injectable endpoint is forfeited to timeout (the root cause of flaky
    # blind-SQLi / cmdi detection). Scale the global pool by worker count so each
    # concurrent scan gets its full probe budget instead of fighting for one slot.
    per_scan_probe_concurrency = max(1, int(runner._engine_config.get("probe_concurrency", 4) or 4))
    global_probe_slots = per_scan_probe_concurrency * runner._workers
    _ac.set_probe_concurrency(global_probe_slots)
    # Endpoint scans against ONE host are serialized by default so a single-worker
    # target's slower agents keep their per-endpoint budget (see _admit below and
    # active_checks._HostScanGate). Cross-host parallelism is unaffected.
    host_scan_concurrency = max(1, int(runner._engine_config.get("host_scan_concurrency", 1) or 1))
    _ac.configure_host_scan_concurrency(host_scan_concurrency)
    logger.info(
        "Scan worker started", workers=runner._workers,
        probe_concurrency=per_scan_probe_concurrency, global_probe_slots=global_probe_slots,
        host_scan_concurrency=host_scan_concurrency,
    )
    proxy_url = f"http://127.0.0.1:{runner._proxy_port}"
    # Dedup: track (method, host, normalised-path, operation) tuples completed this session
    _scanned_keys: set = set()

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _admit(entry_id: str):
        # Admission control for one endpoint scan. Acquire the per-host endpoint
        # gate FIRST, then the global scan semaphore — so a host waiting its turn
        # never pins a global worker slot that a different host could use. The
        # semaphore is read at acquire time so runtime worker-count changes take
        # effect even for tasks already waiting in the queue.
        peek = runner._store.get_entry(entry_id)
        host = peek.host if peek else None
        if host:
            await _ac.acquire_host_scan_slot(host)
        try:
            async with runner._scan_sem:  # type: ignore[attr-defined]
                yield
        finally:
            if host:
                await _ac.release_host_scan_slot(host)

    async def _attack_one(entry_id: str) -> None:
        from dast.proxy.plugin_manager import log_event

        # Wait here if paused — enter admission only once we're ready to run
        await qs.wait_if_paused()

        # Check cancellation before acquiring any slot
        if qs.is_cancelled(entry_id):
            qs.finish(entry_id, 0, "cancelled")
            return

        async with _admit(entry_id):
            # Re-check after acquiring (may have been cancelled while waiting)
            if qs.is_cancelled(entry_id):
                qs.finish(entry_id, 0, "cancelled")
                return

            entry = runner._store.get_entry(entry_id)
            if not entry:
                qs.finish(entry_id, 0, "skipped", "Entry not found in store")
                return

            # ai_queued=True means the user explicitly clicked Scan/Send to AI.
            # Its ONLY effect is to bypass dedup so a deliberate re-scan runs;
            # it does NOT bypass the ai_mode or scope gates below (an earlier
            # version let it, which fired agents at an out-of-scope SSO host
            # with AI mode off).
            # skip_dedup=True means AppContextWorker wants to re-scan without dedup.
            manually_queued = getattr(entry, "ai_queued", False)
            skip_dedup      = getattr(entry, "skip_dedup", False)
            # Only a genuinely imported target list is a deliberate, specific
            # scan request that may run with AI off / fall out of scope.
            is_imported     = entry.source == "imported"

            # Three-layer scan model (see CLAUDE.md "AI Disabled By Default"):
            #   1. Passive plugins — always run on the wire (not here).
            #   2. Deterministic scanners (param mining) — run on an EXPLICIT
            #      scan request even with AI off. No LLM, inert canary probes,
            #      scope-gated. This is the normal scan without agents.
            #   3. AI agents (coordinator + LLM planner) — only with AI on.
            # `ai_mode` off is NOT a reason to skip the whole scan anymore: it
            # only downgrades this entry to the deterministic layer.
            run_agents = bool(is_imported or runner._store.ai_mode)

            # Scope is a hard safety boundary — never bypassed by a queue click.
            # Only an explicit import (a deliberate, specific target list) may
            # fall out of scope.
            if not is_imported and not runner._settings.is_in_scope(entry.url):
                logger.debug("Scan skipped — out of scope", url=entry.url)
                qs.finish(entry_id, 0, "skipped", "URL is out of scope — configure scope in Proxy → Settings")
                return

            target = _entry_to_check_target(entry, store=runner._store)
            if not target:
                from urllib.parse import urlparse as _up2
                _seg = _up2(entry.url).path.rstrip("/").rsplit("/", 1)[-1].lower()
                if _seg in _DANGEROUS_SEGMENTS:
                    log_event("scan-worker", "warn",
                              f"Scan skipped — session-destructive path: {entry.url}",
                              url=entry.url, source="agent")
                    qs.finish(entry_id, 0, "skipped", f"Destructive path blocked: /{_seg}")
                else:
                    qs.finish(entry_id, 0, "skipped", "No injectable parameters found (no query params or JSON body)")
                runner._store.add_finding(entry_id, {}, "safe")
                return

            # Dedup by method + normalised path + host + operation — manually queued
            # or skip_dedup entries re-scan. Path is normalised (UUIDs/IDs → {id}) so
            # /users/<uuid-a> and /users/<uuid-b> count as the same logical endpoint
            # and we don't re-scan it once per distinct ID. Matches the enqueue-time
            # dedup key (_ai_mode_seen) so both layers group endpoints identically.
            from dast.ai.coordinator import _extract_operation
            operation = _extract_operation(target)
            scan_key = (entry.method, entry.host, normalise_dedup_path(entry.path), operation)
            if not manually_queued and not skip_dedup and scan_key in _scanned_keys:
                logger.debug("Scan skipped — duplicate operation already scanned",
                             url=entry.url, operation=operation)
                # Set a terminal scan_result so status polling (e.g. code-hypothesis
                # validation) stops reporting "scanning" forever — a skip is terminal.
                runner._store.add_finding(entry_id, {}, "safe")
                qs.finish(entry_id, 0, "skipped", "Duplicate — same endpoint+operation already scanned this session")
                return
            _scanned_keys.add(scan_key)

            # Host circuit breaker: if this host was already confirmed
            # unreachable this session, skip immediately instead of spending a
            # scan slot on requests that will all fail (DNS/connection error).
            from dast.scanners.active_checks import is_host_dead
            if is_host_dead(entry.host):
                logger.info("Scan skipped — host unreachable", url=entry.url, host=entry.host)
                log_event("scan-worker", "warn",
                          f"Scan skipped — host unreachable: {entry.host}",
                          url=entry.url, source="agent")
                # Terminal result so status polling stops reporting "scanning".
                runner._store.add_finding(entry_id, {}, "error")
                qs.finish(entry_id, 0, "skipped", f"Host unreachable: {entry.host}")
                return

            current_task = asyncio.current_task()
            op_label = f" [{operation}]" if operation else ""
            qs.start(entry_id, entry.method, entry.url, entry.host,
                     task=current_task, operation=operation)

            # ── Deterministic layer (AI off) ──────────────────────────────
            # AI mode is off but the user explicitly requested this scan.
            # Run only the deterministic scanners (hidden-parameter mining) —
            # no LLM, no agents. Hits become recon suggestions the operator
            # can act on (or that the AI planner picks up once AI is enabled).
            if not run_agents:
                log_event("scan-worker", "info",
                          f"Deterministic scan (AI off) — {entry.method} {entry.url}{op_label}",
                          url=entry.url, source="agent")
                logger.info("Deterministic scan started (AI off)",
                            method=entry.method, url=entry.url)
                try:
                    hidden = await mine_params_for_entry(runner, entry, proxy_url)
                except asyncio.CancelledError:
                    logger.info("Deterministic scan cancelled by user", url=entry.url)
                    qs.finish(entry_id, 0, "cancelled")
                    return
                except Exception as e:
                    logger.error("Deterministic scan error", url=entry.url, error=str(e))
                    log_event("scan-worker", "error",
                              f"Param mining error: {e}", url=entry.url, source="agent")
                    runner._store.add_finding(entry_id, {}, "error")
                    qs.finish(entry_id, 0, "error")
                    return
                # Terminal "safe" result — deterministic mining found no vuln,
                # only (optionally) fresh attack surface as recon suggestions.
                runner._store.add_finding(entry_id, {}, "safe")
                log_event("scan-worker", "info",
                          f"Deterministic scan complete — {hidden} hidden param(s); "
                          f"enable AI mode for full agent testing",
                          url=entry.url, source="agent")
                qs.finish(entry_id, 0, "safe",
                          f"Deterministic scan (AI off): {hidden} hidden param(s) found")
                return

            log_event("scan-worker", "info",
                      f"Active scan started — {entry.method} {entry.url}{op_label}",
                      url=entry.url, source="agent")
            logger.info("Active scan started", method=entry.method, url=entry.url)
            try:
                model_id = runner._engine_config.get("model_id") or runner._ai_model_id or None
                confidence_threshold = float(runner._engine_config.get("confidence_threshold", 0.5))
                # Imported entries and code-hypothesis entries get the full ceiling budget —
                # the user explicitly requested them so adaptive cost-cutting is wrong.
                budget_override = None
                if entry.source == "imported" or getattr(entry, "import_hints", None):
                    budget_override = float(
                        runner._engine_config.get("scan_budget_seconds", 300) or 300
                    )
                # The operator's "Scan Budget per Endpoint" is the hard ceiling
                # for every scan, not only imported entries (the UI promises it).
                budget_ceiling = float(
                    runner._engine_config.get("scan_budget_seconds", 300) or 300
                )
                findings = await run_active_checks(
                    target, proxy_url=proxy_url, model_id=model_id,
                    confidence_threshold=confidence_threshold,
                    session_intelligence=runner._store.session_intelligence,
                    budget_seconds=budget_override,
                    probe_diff=bool(runner._engine_config.get("probe_diff", False)),
                    taint_store=runner._store.taint_store,
                    budget_ceiling=budget_ceiling,
                )
            except asyncio.CancelledError:
                logger.info("Active scan cancelled by user", url=entry.url)
                log_event("scan-worker", "info", "Scan cancelled by user", url=entry.url, source="agent")
                qs.finish(entry_id, 0, "cancelled")
                return
            except Exception as e:
                from dast.ai.bedrock_client import AiUnavailableError
                if isinstance(e, AiUnavailableError):
                    logger.warning("AI unavailable — pausing scan queue", error=str(e))
                    log_event("scan-worker", "warn",
                              "AI offline: AWS credentials expired — scan queue paused. "
                              "Run 'aws sso login' then click Resume in the dashboard.",
                              url=entry.url, source="agent")
                    qs.pause()
                    qs.finish(entry_id, 0, "error")
                    return
                logger.error("Active scan error", url=entry.url, error=str(e))
                log_event("scan-worker", "error", f"Scan error: {e}", url=entry.url, source="agent")
                update_import_stubs(entry, False, error=True)
                runner._store.add_finding(entry_id, {"error": str(e)}, "error")
                qs.finish(entry_id, 0, "error")
                return

            # Update any stub imported findings on this entry to reflect scan outcome
            update_import_stubs(entry, bool(findings))

            if findings:
                for f in findings:
                    # A finding held for review (AI validator offline/errored,
                    # pattern confidence plausible) is NOT confirmed — it is
                    # surfaced separately with an "unvalidated" label so a human
                    # can review it. It is never counted as an AI/pattern vuln.
                    held = getattr(f, "needs_review", False)
                    validated_by = ["unvalidated"] if held else detection_method(f)
                    finding_dict = {
                        "title":        getattr(f, "title", ""),
                        "severity":     getattr(f, "severity", "info"),
                        "cwe":          getattr(f, "cwe", ""),
                        "attack_type":  getattr(f, "attack_type", ""),
                        "evidence":     (getattr(f, "evidence", "") or "")[:400],
                        "payload":      (getattr(f, "payload", "") or "")[:200],
                        "parameter":    getattr(f, "parameter", ""),
                        "confirmed":    not held,
                        "needs_review": held,
                        "validated_by": validated_by,
                        "reasoning":    getattr(f, "reasoning", ""),
                    }
                    # Record WHEN the AI confirmed this finding so the UI can
                    # distinguish a historical AI verdict from current AI
                    # availability (the live "AI offline" status is decoupled).
                    if "ai" in validated_by:
                        finding_dict["validated_at"] = datetime.now(timezone.utc).isoformat()
                    confidence = getattr(f, "confidence", None)
                    if confidence is not None:
                        finding_dict["confidence"] = round(float(confidence), 2)
                    snippet = getattr(f, "raw_response_snippet", "")
                    if snippet:
                        finding_dict["snippet"] = snippet[:400]
                    browser_confirmed = getattr(f, "browser_confirmed", None)
                    if browser_confirmed is not None:
                        finding_dict["browser_confirmed"] = browser_confirmed
                    browser_reason = getattr(f, "browser_confirm_reason", "")
                    if browser_reason:
                        finding_dict["browser_confirm_reason"] = browser_reason
                    raw_request = getattr(f, "raw_request", "")
                    if raw_request:
                        finding_dict["raw_request"] = raw_request[:6000]
                    raw_response = getattr(f, "raw_response", "")
                    if raw_response:
                        finding_dict["raw_response"] = raw_response[:6000]
                    probe_request = getattr(f, "probe_request", "")
                    if probe_request:
                        finding_dict["probe_request"] = probe_request[:6000]
                    probe_response = getattr(f, "probe_response", "")
                    if probe_response:
                        finding_dict["probe_response"] = probe_response[:6000]
                    extracted_data = getattr(f, "extracted_data", None)
                    if extracted_data:
                        finding_dict["extracted_data"] = {
                            str(k): str(v)[:200] for k, v in extracted_data.items()
                        }
                    runner._store.add_finding(entry_id, finding_dict, "vulnerable")
                    log_event(
                        getattr(f, "attack_type", "agent"),
                        "finding",
                        f"{getattr(f, 'title', '')} — param: {getattr(f, 'parameter', '')}",
                        url=entry.url,
                        finding=getattr(f, "title", ""),
                        source="agent",
                    )
                n_held = sum(1 for f in findings if getattr(f, "needs_review", False))
                n_confirmed = len(findings) - n_held
                if n_held:
                    log_event("scan-worker", "warn",
                              f"{n_held} finding(s) held for review — AI validator offline; "
                              "confirm manually or re-run when AI is available.",
                              url=entry.url, source="agent")
                logger.warning("Active scan: VULNERABLE", url=entry.url,
                               confirmed=n_confirmed, needs_review=n_held)
                qs.finish(entry_id, len(findings), "vulnerable")
            else:
                runner._store.add_finding(entry_id, {}, "safe")
                log_event("scan-worker", "info", "Scan complete — no findings",
                          url=entry.url, source="agent")
                logger.info("Active scan: safe", url=entry.url)
                qs.finish(entry_id, 0, "safe")

    # Tracks normalised path patterns already queued in AI mode this session
    # e.g. ("GET", "api.x.com", "/users/{id}") — avoids scanning 100 user IDs
    _ai_mode_seen: set = set()

    async def _ai_mode_listener(entry) -> None:
        """Queue completed in-scope entries for scan when AI mode is active.

        Uses LLM planner (via Coordinator) to decide which agents to run —
        so header-only attacks on GET /health are still caught.
        Deduplicates on normalised path pattern so /users/123 and /users/456
        don't both get scanned.
        """
        if not runner._store.ai_mode:
            return
        if entry.source in ("agent", "out-of-scope", "imported"):
            return
        if entry.response_status is None:
            return
        if entry.queued_for_scan or entry.scan_result:
            return
        if not runner._settings.is_in_scope(entry.url):
            return

        # Normalise path: replace UUIDs, numeric IDs, and hex strings with {id}
        norm_path = normalise_dedup_path(entry.path)
        pattern_key = (entry.method, entry.host, norm_path)
        if pattern_key in _ai_mode_seen:
            return
        _ai_mode_seen.add(pattern_key)

        entry.queued_for_scan = True
        qs.enqueue(entry.id, entry.method, entry.url, entry.host)
        try:
            # Non-blocking so a backed-up scan queue never stalls proxy ingestion.
            runner._scan_queue.put_nowait(entry.id)
        except asyncio.QueueFull:
            # Revert so the entry can be re-queued later (manually or on next pass)
            entry.queued_for_scan = False
            qs.dequeue(entry.id)
            logger.warning("Scan queue full — dropping auto-queued entry",
                           url=entry.url, qsize=runner._scan_queue.qsize())
            from dast.proxy.plugin_manager import log_event
            log_event("scan-worker", "warn",
                      f"Scan queue full ({runner._scan_queue.qsize()}) — skipped auto-queue for {entry.url}",
                      url=entry.url, source="agent")

    runner._store.add_listener(_ai_mode_listener)

    # Bounded dispatch: at most a few waiting tasks per worker leave the queue at a
    # time. Pulling everything into tasks immediately made the queue's maxsize
    # meaningless and let in-flight task count grow without bound; tasks are also
    # strongly referenced here so none is garbage-collected mid-scan.
    in_flight: set = set()
    while True:
        max_in_flight = max(1, runner._workers) * 4
        while len(in_flight) >= max_in_flight:
            await asyncio.wait(in_flight, return_when=asyncio.FIRST_COMPLETED)
        entry_id = await runner._scan_queue.get()
        qs.dequeue(entry_id)
        spawn_tracked(_attack_one(entry_id), name=f"scan-{entry_id}", registry=in_flight)
