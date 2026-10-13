"""
Recon workers — SPA crawl jobs and content-discovery (forced browsing) jobs.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Optional

from dast.proxy.suggestions import classify_discovery_hit_with_llm, record_discovery_hit

from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.proxy.runner import ProxyRunner

logger = get_logger(__name__)


async def run_crawl_worker(runner: "ProxyRunner", crawl_queue: asyncio.Queue) -> None:
    from dast.proxy.spa_crawler import SpaCrawler
    from dast.proxy.plugin_manager import log_event

    _active_stop: Optional[asyncio.Event] = None

    while True:
        job = await crawl_queue.get()

        if job.get("action") == "stop":
            if _active_stop:
                _active_stop.set()
                log_event("crawler", "info", "Crawler stopped", source="crawler")
            continue

        stop_event = asyncio.Event()
        _active_stop = stop_event
        log_cb = job.get("log_cb") or (lambda m: None)
        target_url = job.get("url", "")
        log_event("crawler", "info", "Crawl started", url=target_url, source="crawler")

        crawler = SpaCrawler(runner._store, log_cb, stop_event, proxy_port=runner._proxy_port)
        try:
            await crawler.run(
                target_url=target_url,
                auth_cookies=job.get("cookies"),
                max_clicks=job.get("max_clicks", 200),
                headless=job.get("headless", True),
                extra_seeds=job.get("extra_seeds"),
            )
            log_event("crawler", "info", "Crawl finished", url=target_url, source="crawler")
        except Exception as e:
            log_cb(f"Crawler error: {e}")
            logger.error("Crawl failed", url=target_url, error=str(e))
            log_event("crawler", "error", f"Crawl error: {e}", url=target_url, source="crawler")
        finally:
            # A programmatic caller (the crawl tool) can pass a done_event to
            # block until this job finishes; UI callers omit it. Always set it
            # so an awaiting caller is released on success, error, or cancel.
            done_event = job.get("done_event")
            if done_event is not None:
                done_event.set()


async def run_discovery_worker(runner: "ProxyRunner", discovery_queue: asyncio.Queue) -> None:
    """
    Consume content-discovery jobs: forced-browse a host's common paths and
    turn each hit into a synthetic sitemap entry + an AI scan suggestion.

    Mirrors _crawl_worker: one job at a time, a stop job sets a cancel flag.
    All HTTP + scope safety lives in content_discovery.run_content_discovery.
    """

    from dast.proxy.plugin_manager import log_event
    from dast.scanners.content_discovery import run_content_discovery

    cancel = {"stop": False}

    while True:
        job = await discovery_queue.get()

        if job.get("action") == "stop":
            cancel["stop"] = True
            log_event("content-discovery", "info", "Content discovery stopped", source="crawler")
            continue

        cancel["stop"] = False
        log_cb = job.get("log_cb")
        base_url = job.get("url", "")
        headers = job.get("headers") or {}
        proxy_url = f"http://127.0.0.1:{runner._proxy_port}"
        log_event("content-discovery", "info", "Content discovery started",
                  url=base_url, source="crawler")

        try:
            hits = await run_content_discovery(
                base_url=base_url,
                headers=headers,
                settings=runner._settings,
                proxy_url=proxy_url,
                log_cb=log_cb,
                include_dirs=job.get("dirs", True),
                include_files=job.get("files", True),
                include_graphql=job.get("graphql", True),
                should_cancel=lambda: cancel["stop"],
            )
        except Exception as e:
            logger.error("Content discovery failed", url=base_url, error=str(e))
            log_event("content-discovery", "error", f"Content discovery error: {e}",
                      url=base_url, source="crawler")
            continue

        recorded = 0
        classify_with_llm = bool(runner._engine_config.get("discovery_llm_classify", False))
        for hit in hits:
            try:
                # The LLM call is blocking — run it off the event loop so the
                # proxy and dashboard stay responsive while hits are classified.
                llm_attack_type = None
                if classify_with_llm and hit.get("kind", "file") != "graphql":
                    llm_attack_type = await asyncio.to_thread(classify_discovery_hit_with_llm, hit)
                record_discovery_hit(runner._store, hit, headers, llm_attack_type=llm_attack_type)
                recorded += 1
            except Exception as e:
                logger.warning("Failed to record discovery hit",
                               url=hit.get("url", ""), error=str(e))

        log_event("content-discovery", "info",
                  f"Content discovery finished: {len(hits)} hit(s), {recorded} recorded",
                  url=base_url, source="crawler")
