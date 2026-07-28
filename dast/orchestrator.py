"""
Scan orchestrator — wires all stages together.

Pipeline:
  1. Auth         → browser login, checkpoint saved
  2. Crawl        → parallel BrowserContext workers discover endpoints
  3. Attack       → feedback-loop attack engine per endpoint
  4. Report       → JSON + Markdown + audit log
"""

import time
from pathlib import Path

from dast.attack.engine import AttackEngine
from dast.browser.context_pool import ContextPool
from dast.models import ScanConfig, ScanResult, ScanStatus
from dast.report.exporter import export_all
from dast.scanners.crawler import CrawlerWorker
from dast.session.auth_agent import AuthAgent
from dast.session.manager import SessionManager
from dast.utils.audit_log import AuditLog
from dast.utils.logger import get_logger, set_log_file

logger = get_logger(__name__)


class ScanOrchestrator:
    def __init__(self, config: ScanConfig):
        self._config = config
        self._session = SessionManager()
        self._pool = ContextPool(
            size=config.parallel_workers,
            headless=config.browser_headless,
        )

    async def run(self) -> ScanResult:
        start = time.time()

        # Setup output dir and file-based logging
        output_dir = Path(self._config.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%d-%H%M%S")
        set_log_file(output_dir / f"dast-debug_{ts}.log.json")

        audit = AuditLog(output_dir / f"dast-audit_{ts}.jsonl")
        audit.scan_start(
            target=self._config.target_url,
            config={
                "max_depth": self._config.max_depth,
                "max_pages": self._config.max_pages,
                "parallel_workers": self._config.parallel_workers,
                "max_attack_iterations": self._config.max_attack_iterations,
                "confidence_threshold": self._config.confidence_threshold,
                "enabled_attack_types": self._config.enabled_attack_types,
                "browser_headless": self._config.browser_headless,
            },
        )

        result = ScanResult(config=self._config, status=ScanStatus.PENDING)

        try:
            await self._pool.start()

            # Stage 1: Authentication
            if self._config.auth_url and self._config.username:
                result.status = ScanStatus.CRAWLING
                logger.info("Starting authentication", url=self._config.auth_url, username=self._config.username)
                ok = await self._authenticate(audit)
                if not ok:
                    raise RuntimeError("Authentication failed. Check credentials and --auth-url.")
                if self._session.has_checkpoint:
                    async with self._pool.acquire() as ctx:
                        state = await ctx.storage_state()
                    await self._pool.apply_auth_state(state)

            # Stage 2: Crawl
            result.status = ScanStatus.CRAWLING
            logger.info("Starting crawl", target=self._config.target_url)
            endpoints = await self._crawl(audit)
            result.endpoints_discovered = endpoints
            result.pages_crawled = len({ep.url for ep in endpoints})
            logger.info(
                "Crawl complete",
                endpoints=len(endpoints),
                pages=result.pages_crawled,
            )

            # Stage 3: Attack
            if endpoints:
                result.status = ScanStatus.ATTACKING
                logger.info("Starting attack phase", endpoints=len(endpoints))
                engine = AttackEngine(
                    config=self._config,
                    session_manager=self._session,
                    audit=audit,
                )
                findings = await engine.attack_all(endpoints, self._pool)
                result.findings = findings
                logger.info(
                    "Attack phase complete",
                    findings=len(findings),
                    confirmed=[f.title for f in findings],
                )
            else:
                logger.warning("No endpoints discovered — skipping attack phase")

            result.status = ScanStatus.COMPLETED

        except Exception as e:
            logger.error("Scan failed", error=str(e), exc_info=True)
            audit.error(str(e))
            result.status = ScanStatus.FAILED
            result.errors.append(str(e))

        finally:
            await self._pool.stop()
            result.scan_duration_s = time.time() - start
            audit.scan_end(
                status=result.status.value,
                duration_s=result.scan_duration_s,
                endpoints=len(result.endpoints_discovered),
                attempts=len(result.attack_attempts),
                findings=len(result.findings),
            )
            audit.close()

        export_all(result, Path(self._config.output_dir))
        return result

    async def _authenticate(self, audit: AuditLog) -> bool:
        async with self._pool.acquire() as ctx:
            agent = AuthAgent(
                context=ctx,
                session_manager=self._session,
                auth_url=self._config.auth_url,
                username=self._config.username,
                password=self._config.password,
            )
            ok = await agent.login()
            audit.auth_attempt(
                self._config.auth_url,
                username=self._config.username,
                success=ok,
            )
            return ok

    async def _crawl(self, audit: AuditLog) -> list:
        async with self._pool.acquire() as ctx:
            worker = CrawlerWorker(
                context=ctx,
                base_url=self._config.target_url,
                max_depth=self._config.max_depth,
                max_pages=self._config.max_pages,
                delay_ms=self._config.request_delay_ms,
                audit=audit,
            )
            return await worker.crawl([self._config.target_url])
