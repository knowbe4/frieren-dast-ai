"""
CLI entry point for Frieren DAST-AI.

Commands:
  scan          Fully automated: crawl + attack
  browse        Open browser for manual navigation, record all traffic
  attack        Attack endpoints captured in a previous browse session
  verify        Dynamically verify findings from an orchestrator-ai report
"""

import asyncio
import sys
import time
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from dast.config import settings
from dast.models import ScanConfig
from dast.orchestrator import ScanOrchestrator
from dast.utils.logger import configure_logging

console = Console()

_DEFAULT_ATTACKS = [
    "xss", "sqli", "idor", "ssrf",
    "open_redirect", "auth_bypass", "mass_assignment", "graphql_injection",
]


def _parse_attack_types(attack_types: Optional[str]) -> list:
    if attack_types:
        return [a.strip() for a in attack_types.split(",")]
    return list(_DEFAULT_ATTACKS)


def _print_findings(findings, output_dir: str) -> None:
    confirmed = len(findings)
    if confirmed:
        console.print(f"\n[bold red]Findings: {confirmed}[/bold red]")
        for f in findings:
            color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(
                f.severity.value, "dim"
            )
            console.print(
                f"  [{color}][{f.severity.value}][/{color}] {f.title}"
                f" [dim]({f.confidence:.0%} confidence)[/dim]"
            )
    else:
        console.print("\n[green]No confirmed vulnerabilities found[/green]")
    console.print(f"\n[dim]Reports saved to: {output_dir}[/dim]")


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group()
@click.option("--debug", is_flag=True, default=False, help="Enable debug logging")
def main(debug: bool):
    configure_logging("DEBUG" if debug else "INFO")


# ---------------------------------------------------------------------------
# scan — fully automated
# ---------------------------------------------------------------------------

@main.command()
@click.option("--target", required=True, help="Target URL to scan")
@click.option("--auth-url", default=None, help="Login page URL")
@click.option("--username", default=None, help="Login username/email")
@click.option("--password", default=None, help="Login password")
@click.option("--max-depth", default=5, show_default=True, help="Max crawl depth")
@click.option("--max-pages", default=200, show_default=True, help="Max pages to crawl")
@click.option("--workers", default=4, show_default=True, help="Parallel browser workers")
@click.option("--delay-ms", default=100, show_default=True, help="Delay between requests (ms)")
@click.option("--iterations", default=3, show_default=True, help="Max attack iterations per endpoint")
@click.option("--confidence", default=0.7, show_default=True, help="Min confidence to report finding")
@click.option("--output-dir", default="./scan-results", show_default=True, help="Output directory")
@click.option("--no-headless", is_flag=True, default=False, help="Show browser window during scan")
@click.option("--attack-types", default=None, help="Comma-separated attack types (default: all)")
def scan(
    target, auth_url, username, password,
    max_depth, max_pages, workers, delay_ms,
    iterations, confidence, output_dir, no_headless, attack_types,
):
    """Fully automated scan: crawl then attack."""
    enabled = _parse_attack_types(attack_types)

    config = ScanConfig(
        target_url=target,
        auth_url=auth_url,
        username=username,
        password=password,
        max_depth=max_depth,
        max_pages=max_pages,
        parallel_workers=workers,
        request_delay_ms=delay_ms,
        browser_headless=not no_headless,
        max_attack_iterations=iterations,
        confidence_threshold=confidence,
        enabled_attack_types=enabled,
        ai_model_id=settings.ai_model_id,
        output_dir=output_dir,
    )

    console.print(f"\n[bold cyan]Frieren DAST-AI scan[/bold cyan] — {target}")
    console.print(f"[dim]Workers: {workers} | Depth: {max_depth} | Attacks: {', '.join(enabled)}[/dim]\n")

    try:
        result = asyncio.run(ScanOrchestrator(config).run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted[/yellow]")
        sys.exit(1)

    console.print(f"\n[bold]Done[/bold] — {result.scan_duration_s:.1f}s")
    console.print(f"  Endpoints: {len(result.endpoints_discovered)} | Pages: {result.pages_crawled}")
    _print_findings(result.findings, output_dir)
    sys.exit(1 if result.findings else 0)


# ---------------------------------------------------------------------------
# browse — manual navigation session
# ---------------------------------------------------------------------------

@main.command()
@click.option(
    "--target",
    default=None,
    help="URL to open on start. Omit to open a blank browser and navigate freely.",
)
@click.option(
    "--session-file",
    default=None,
    help="Where to save the session (default: scan-results/session-<timestamp>.json)",
)
@click.option(
    "--then-attack",
    is_flag=True,
    default=False,
    help="Attack captured endpoints after you close the browser",
)
@click.option(
    "--live",
    is_flag=True,
    default=False,
    help="Attack endpoints in the background while you browse (real-time)",
)
@click.option("--workers", default=4, show_default=True, help="Parallel workers for attack phase")
@click.option("--iterations", default=3, show_default=True, help="Max attack iterations per endpoint")
@click.option("--confidence", default=0.7, show_default=True, help="Min confidence to report finding")
@click.option("--output-dir", default="./scan-results", show_default=True, help="Output directory")
@click.option("--attack-types", default=None, help="Comma-separated attack types (default: all)")
@click.option("--auth-url", default=None, help="Login page URL")
@click.option("--username", default=None, help="Login username")
@click.option("--password", default=None, help="Login password")
def browse(
    target, session_file, then_attack, live,
    workers, iterations, confidence, output_dir, attack_types,
    auth_url, username, password,
):
    """
    Open a real browser for manual navigation.

    Browse the application normally — log in, click around, trigger API calls.
    Every request and response within scope is silently recorded.
    When you close the browser, the session is saved to a JSON file.

    Without --target the browser opens blank. Navigate to any URL you want —
    every domain you visit is automatically added to the capture scope.
    Noise domains (analytics, CDNs, OAuth providers) are silently ignored.

    --then-attack: attack everything after the browser closes.
    --live:        attack each endpoint in the background the moment it is
                   discovered, while you continue browsing (active-scan style).
    """
    from dast.browser.manual_session import ManualBrowseSession

    ts = time.strftime("%Y%m%d-%H%M%S")
    session_path = Path(session_file) if session_file else (
        Path(output_dir) / f"session-{ts}.json"
    )

    console.print("\n[bold cyan]Frieren DAST-AI browse[/bold cyan]" + (f" — {target}" if target else ""))
    if not target:
        console.print("[dim]Free roam: navigate to any app. All domains you visit are captured.[/dim]")
    elif live:
        console.print("[dim]Live mode: endpoints are attacked as they are discovered.[/dim]")
    else:
        console.print("[dim]Browse normally. Close the browser window when done.[/dim]")
    console.print(f"[dim]Session will be saved to: {session_path}[/dim]\n")

    if live:
        findings = _browse_live(
            target=target,
            session_path=session_path,
            workers=workers,
            iterations=iterations,
            confidence=confidence,
            output_dir=output_dir,
            attack_types=attack_types,
            auth_url=auth_url,
            username=username,
            password=password,
        )
        if findings is not None:
            _print_findings(findings, output_dir)
        sys.exit(1 if findings else 0)

    # --- non-live browse ---
    def on_endpoint(ep):
        console.print(
            f"  [dim][+][/dim] [cyan]{ep.method}[/cyan] {ep.url}"
            + (f" ({len(ep.parameters)} params)" if ep.parameters else "")
        )

    session = ManualBrowseSession(base_url=target, on_endpoint_discovered=on_endpoint)

    try:
        endpoints = asyncio.run(session.run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Session ended by Ctrl+C[/yellow]")
        endpoints = session._endpoints

    # Report which domains were captured when running in free-roam mode
    if not target and session.scoped_domains:
        console.print(f"[dim]Captured domains: {', '.join(session.scoped_domains)}[/dim]")

    session.save(session_path)
    console.print(
        f"\n[green]Session saved[/green] — "
        f"{len(endpoints)} endpoints | "
        f"{session.interaction_count} interactions"
    )

    if not endpoints:
        console.print("[yellow]No endpoints captured. Nothing to attack.[/yellow]")
        sys.exit(0)

    # Derive target from captured endpoints when --target was not given
    effective_target = target or _target_from_endpoints(endpoints)

    if then_attack:
        console.print("\n[bold cyan]Starting attack phase...[/bold cyan]")
        _run_attack_on_endpoints(
            endpoints=endpoints,
            target=effective_target,
            workers=workers,
            iterations=iterations,
            confidence=confidence,
            output_dir=output_dir,
            attack_types=attack_types,
            auth_url=auth_url,
            username=username,
            password=password,
        )
    else:
        console.print(
            f"\n[dim]To attack this session later:[/dim]\n"
            f"  uv run dast-ai attack --session-file {session_path}"
        )


# ---------------------------------------------------------------------------
# attack — attack a previously saved session
# ---------------------------------------------------------------------------

@main.command()
@click.option("--session-file", required=True, help="Session JSON file from 'browse' command")
@click.option("--target", default=None, help="Target base URL (read from session file if omitted)")
@click.option("--workers", default=4, show_default=True, help="Parallel browser workers")
@click.option("--iterations", default=3, show_default=True, help="Max attack iterations per endpoint")
@click.option("--confidence", default=0.7, show_default=True, help="Min confidence to report finding")
@click.option("--output-dir", default="./scan-results", show_default=True, help="Output directory")
@click.option("--attack-types", default=None, help="Comma-separated attack types (default: all)")
@click.option("--auth-url", default=None, help="Login page URL (for fresh auth before attacking)")
@click.option("--username", default=None, help="Login username")
@click.option("--password", default=None, help="Login password")
def attack(
    session_file, target, workers, iterations,
    confidence, output_dir, attack_types, auth_url, username, password,
):
    """
    Attack endpoints from a previously saved browse session.

    Loads the session JSON file saved by 'browse', then runs the AI
    attack engine (payload generation + feedback loop) against every
    captured endpoint.
    """
    from dast.browser.manual_session import ManualBrowseSession
    import json

    path = Path(session_file)
    if not path.exists():
        console.print(f"[red]Session file not found: {path}[/red]")
        sys.exit(1)

    # Read base_url from session file if not overridden
    session_data = json.loads(path.read_text(encoding="utf-8"))
    base_url = target or session_data.get("base_url", "")
    endpoint_count = session_data.get("endpoint_count", 0)

    console.print(f"\n[bold cyan]Frieren DAST-AI attack[/bold cyan] — {base_url}")
    console.print(f"[dim]Session: {path.name} | {endpoint_count} endpoints[/dim]\n")

    endpoints = ManualBrowseSession.load(path)
    if not endpoints:
        console.print("[yellow]No endpoints found in session file.[/yellow]")
        sys.exit(0)

    _run_attack_on_endpoints(
        endpoints=endpoints,
        target=base_url,
        workers=workers,
        iterations=iterations,
        confidence=confidence,
        output_dir=output_dir,
        attack_types=attack_types,
        auth_url=auth_url,
        username=username,
        password=password,
    )


def _target_from_endpoints(endpoints: list) -> str:
    """Derive a base URL from the first captured endpoint when --target was not given."""
    if not endpoints:
        return ""
    from urllib.parse import urlparse
    first = endpoints[0].url
    parsed = urlparse(first)
    return f"{parsed.scheme}://{parsed.netloc}"


# ---------------------------------------------------------------------------
# live browse + attack helper
# ---------------------------------------------------------------------------

def _browse_live(
    target, session_path, workers, iterations, confidence,
    output_dir, attack_types, auth_url, username, password,
):
    """
    Run browser and attack engine concurrently in the same event loop.

    Endpoints discovered by the interceptor are pushed onto an asyncio.Queue.
    The attack engine drains that queue as it fills, so attacks run while
    the user is still browsing.
    """
    from dast.browser.manual_session import ManualBrowseSession
    from dast.attack.engine import AttackEngine
    from dast.browser.context_pool import ContextPool
    from dast.session.manager import SessionManager
    from dast.session.auth_agent import AuthAgent
    from dast.models import ScanResult, ScanStatus
    from dast.report.exporter import export_all

    enabled = _parse_attack_types(attack_types)
    # target may be None (free-roam); ScanConfig.target_url will be updated
    # after we know what domains were captured
    findings_live: list = []
    start = time.time()

    async def _run():
        endpoint_queue: asyncio.Queue = asyncio.Queue()

        session_mgr = SessionManager()
        pool = ContextPool(size=workers, headless=True)
        await pool.start()

        try:
            # Authenticate if credentials provided (requires a known auth URL)
            if auth_url and username:
                async with pool.acquire() as ctx:
                    agent = AuthAgent(
                        context=ctx,
                        session_manager=session_mgr,
                        auth_url=auth_url,
                        username=username,
                        password=password,
                    )
                    ok = await agent.login()
                    if not ok:
                        console.print(
                            "[yellow]Warning: authentication failed, attacking unauthenticated[/yellow]"
                        )
                    else:
                        state = await ctx.storage_state()
                        await pool.apply_auth_state(state)

            # Config target_url is only used for report metadata — use a placeholder
            # when target is unknown; it gets resolved from captured endpoints below.
            config = ScanConfig(
                target_url=target or "",
                auth_url=auth_url,
                username=username,
                password=password,
                parallel_workers=workers,
                browser_headless=False,
                max_attack_iterations=iterations,
                confidence_threshold=confidence,
                enabled_attack_types=enabled,
                ai_model_id=settings.ai_model_id,
                output_dir=output_dir,
            )
            engine = AttackEngine(config=config, session_manager=session_mgr)

            def on_endpoint(ep):
                console.print(
                    f"  [dim][+][/dim] [cyan]{ep.method}[/cyan] {ep.url}"
                    + (f" ({len(ep.parameters)} params)" if ep.parameters else "")
                )
                endpoint_queue.put_nowait(ep)

            def on_finding(f):
                color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(
                    f.severity.value, "dim"
                )
                console.print(
                    f"\n  [bold {color}][LIVE FINDING][/bold {color}]"
                    f" [{color}][{f.severity.value}][/{color}] {f.title}"
                    f" [dim]({f.confidence:.0%})[/dim]"
                )
                findings_live.append(f)

            browse_session = ManualBrowseSession(
                base_url=target, on_endpoint_discovered=on_endpoint
            )

            browse_task = asyncio.create_task(browse_session.run())
            attack_task = asyncio.create_task(
                engine.attack_live(endpoint_queue, pool, on_finding=on_finding)
            )

            await browse_task
            await endpoint_queue.put(None)
            all_findings = await attack_task

            if not target and browse_session.scoped_domains:
                console.print(f"[dim]Captured domains: {', '.join(browse_session.scoped_domains)}[/dim]")

            browse_session.save(session_path)
            console.print(
                f"\n[green]Session saved[/green] — "
                f"{browse_session.endpoint_count} endpoints | "
                f"{browse_session.interaction_count} interactions"
            )
            return all_findings, config

        finally:
            await pool.stop()

    try:
        findings, config = asyncio.run(_run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Live session interrupted[/yellow]")
        findings = findings_live
        config = ScanConfig(target_url=target or "", output_dir=output_dir)

    duration = time.time() - start

    result = ScanResult(
        config=config,
        status=ScanStatus.COMPLETED,
        findings=findings,
        scan_duration_s=duration,
    )
    export_all(result, Path(output_dir))
    console.print(f"\n[bold]Live session complete[/bold] — {duration:.1f}s")
    return findings


# ---------------------------------------------------------------------------
# shared attack runner
# ---------------------------------------------------------------------------

def _run_attack_on_endpoints(
    endpoints, target, workers, iterations, confidence,
    output_dir, attack_types,
    auth_url=None, username=None, password=None,
    seed_map=None,
):
    """
    Run the attack engine against a pre-built endpoint list.

    seed_map: optional dict mapping id(endpoint) → AttackPayload. When present,
    the seed payload is tried as the very first attempt for that endpoint before
    AI-generated payloads. Used by the verify command to front-load the
    payload inferred from the Stage 2 reasoning.
    """
    from dast.attack.engine import AttackEngine
    from dast.browser.context_pool import ContextPool
    from dast.session.manager import SessionManager
    from dast.session.auth_agent import AuthAgent

    enabled = _parse_attack_types(attack_types)
    config = ScanConfig(
        target_url=target,
        auth_url=auth_url,
        username=username,
        password=password,
        parallel_workers=workers,
        browser_headless=True,
        max_attack_iterations=iterations,
        confidence_threshold=confidence,
        enabled_attack_types=enabled,
        ai_model_id=settings.ai_model_id,
        output_dir=output_dir,
    )

    async def _run():
        session = SessionManager()
        pool = ContextPool(size=workers, headless=True)
        await pool.start()

        try:
            # Authenticate if credentials provided
            if config.auth_url and config.username:
                async with pool.acquire() as ctx:
                    agent = AuthAgent(
                        context=ctx,
                        session_manager=session,
                        auth_url=config.auth_url,
                        username=config.username,
                        password=config.password,
                    )
                    ok = await agent.login()
                    if not ok:
                        console.print("[yellow]Warning: authentication failed, attacking unauthenticated[/yellow]")
                    else:
                        state = await ctx.storage_state()
                        await pool.apply_auth_state(state)

            engine = AttackEngine(config=config, session_manager=session)
            findings = await engine.attack_all(endpoints, pool, seed_map=seed_map)
        finally:
            await pool.stop()

        return findings

    start = time.time()
    console.print(f"[dim]Attacking {len(endpoints)} endpoints with {len(enabled)} attack types...[/dim]\n")

    try:
        findings = asyncio.run(_run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Attack interrupted[/yellow]")
        sys.exit(1)

    duration = time.time() - start

    # Export report
    from dast.models import ScanResult, ScanStatus
    from dast.report.exporter import export_all

    result = ScanResult(
        config=config,
        status=ScanStatus.COMPLETED,
        endpoints_discovered=endpoints,
        findings=findings,
        scan_duration_s=duration,
    )
    export_all(result, Path(output_dir))

    console.print(f"\n[bold]Attack complete[/bold] — {duration:.1f}s")
    _print_findings(findings, output_dir)
    sys.exit(1 if findings else 0)


# ---------------------------------------------------------------------------
# verify — dynamically confirm findings from an orchestrator-ai report
# ---------------------------------------------------------------------------

@main.command()
@click.argument("findings_file")
@click.option("--target", required=True, help="Target base URL (e.g. https://app.example.com)")
@click.option("--auth-url", default=None, help="Login page URL")
@click.option("--username", default=None, help="Login username")
@click.option("--password", default=None, help="Login password")
@click.option(
    "--status",
    default="confirmed",
    show_default=True,
    type=click.Choice(["confirmed", "all", "high+"]),
    help="Which findings to attempt: confirmed, all, or high+",
)
@click.option("--workers", default=2, show_default=True, help="Parallel browser workers")
@click.option("--iterations", default=4, show_default=True, help="Max attack iterations per finding")
@click.option("--confidence", default=0.6, show_default=True, help="Min confidence to report as confirmed")
@click.option("--output-dir", default="./scan-results", show_default=True, help="Output directory")
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Infer endpoints but do not attack — just print what would be tested",
)
def verify(
    findings_file, target, auth_url, username, password,
    status, workers, iterations, confidence, output_dir, dry_run,
):
    """
    Dynamically verify findings from an orchestrator-ai report.

    FINDINGS_FILE is a scanner-findings_*.json or security-report_*.md produced
    by the orchestrator-ai pipeline.

    For each finding, an AI inferrer reads the vulnerable file path, description,
    and Stage 2 reasoning to infer the live HTTP endpoint and build a concrete
    attack request. The attack engine then attempts to reproduce the vulnerability
    dynamically.

    Example:
      uv run dast-ai verify security-scan-results/20260512/ccm/scanner-findings_ccm.json \\
        --target https://ccm.example.com \\
        --auth-url https://ccm.example.com/login \\
        --username admin@test.com --password secret
    """
    from dast.importers.findings_reader import read_findings
    from dast.importers.endpoint_inferrer import infer_endpoint

    console.print(f"\n[bold cyan]Frieren DAST-AI verify[/bold cyan] — {findings_file}")
    console.print(f"[dim]Target: {target} | Filter: {status}[/dim]\n")

    # Step 1 — load findings
    try:
        raw_findings = read_findings(findings_file, status_filter=status)
    except (FileNotFoundError, ValueError) as e:
        console.print(f"[red]Error reading findings: {e}[/red]")
        sys.exit(1)

    if not raw_findings:
        console.print(f"[yellow]No findings matched filter '{status}'.[/yellow]")
        sys.exit(0)

    console.print(f"[dim]Loaded {len(raw_findings)} findings — inferring endpoints...[/dim]\n")

    # Step 2 — infer endpoints (AI call per finding, done sequentially to avoid rate-limit)
    inferred: list = []
    skipped_not_inferable = 0
    skipped_error = 0

    for f in raw_findings:
        sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(
            f["severity"], "dim"
        )
        console.print(
            f"  [{sev_color}][{f['severity']}][/{sev_color}] "
            f"[bold]{f['title'][:70]}[/bold]"
        )
        console.print(f"    [dim]{f['file']}:{f.get('line', '?')}[/dim]")

        endpoint, seed_payload = infer_endpoint(f, base_url=target)

        if endpoint is None:
            console.print("    [dim]-> not inferable as HTTP endpoint, skipping[/dim]")
            skipped_not_inferable += 1
            continue

        console.print(
            f"    [green]->[/green] [cyan]{endpoint.method}[/cyan] {endpoint.url}"
            + (f" | seed: {seed_payload.value[:60]!r}" if seed_payload else "")
        )
        inferred.append((f, endpoint, seed_payload))

    console.print(
        f"\n[dim]{len(inferred)} inferable | "
        f"{skipped_not_inferable} not inferable | "
        f"{skipped_error} errors[/dim]"
    )

    if not inferred:
        console.print("[yellow]No endpoints could be inferred. Nothing to attack.[/yellow]")
        sys.exit(0)

    if dry_run:
        console.print("\n[dim]--dry-run: stopping before attack phase.[/dim]")
        sys.exit(0)

    # Step 3 — attack inferred endpoints
    # Inject seed payloads as the first payload tried for each endpoint
    endpoints_to_attack = [ep for (_, ep, _) in inferred]
    seed_map = {id(ep): seed for (_, ep, seed) in inferred if seed}

    console.print(f"\n[bold cyan]Starting attack phase — {len(endpoints_to_attack)} endpoints[/bold cyan]\n")

    _run_attack_on_endpoints(
        endpoints=endpoints_to_attack,
        target=target,
        workers=workers,
        iterations=iterations,
        confidence=confidence,
        output_dir=output_dir,
        attack_types=None,  # let the engine use all types; seed payload guides first attempt
        auth_url=auth_url,
        username=username,
        password=password,
        seed_map=seed_map,
    )


# ---------------------------------------------------------------------------
# proxy — HTTP/HTTPS proxy + web dashboard
# ---------------------------------------------------------------------------

@main.command()
@click.option("--proxy-port", default=8080, show_default=True, help="Proxy port (configure in your browser)")
@click.option("--proxy-host", default="127.0.0.1", show_default=True,
              help="Proxy bind host. Use a LAN IP or 0.0.0.0 to accept connections "
                   "from other devices (open proxy — only on trusted networks). "
                   "Overridden by a bind host saved in the Setup tab.")
@click.option("--dashboard-port", default=8088, show_default=True, help="Dashboard port")
@click.option("--auth-url", default=None, help="Login page URL (pre-authenticates the scan pool)")
@click.option("--username", default=None, help="Login username")
@click.option("--password", default=None, help="Login password")
@click.option("--workers", default=4, show_default=True, help="Parallel scan workers")
@click.option("--iterations", default=3, show_default=True, help="Max attack iterations per request")
@click.option("--confidence", default=0.7, show_default=True, help="Min confidence to report finding")
@click.option("--output-dir", default="./scan-results", show_default=True, help="Output directory")
@click.option("--attack-types", default=None, help="Comma-separated attack types (default: all)")
def proxy(
    proxy_port, proxy_host, dashboard_port,
    auth_url, username, password,
    workers, iterations, confidence, output_dir, attack_types,
):
    """
    Start HTTP/HTTPS proxy + web dashboard.

    Configure your browser to use HTTP proxy localhost:<proxy-port>.
    Browse any application normally — every request appears in the dashboard.
    Select individual requests or click "Scan all" to run the AI attack engine.
    Findings appear in real time on the dashboard.

    Browser proxy setup:
      Chrome/Firefox: Settings → Network → Manual proxy → HTTP: 127.0.0.1 :<proxy-port>

    The dashboard opens automatically at http://localhost:<dashboard-port>
    """
    from dast.proxy.runner import ProxyRunner
    from dast.utils.logger import set_log_file
    import datetime

    enabled = _parse_attack_types(attack_types)

    from dast.proxy.cert_authority import CertAuthority
    _ca = CertAuthority()

    # Save every proxy session to a timestamped log file for post-mortem debugging
    _log_dir = Path.home() / ".dast-ai" / "logs"
    _log_dir.mkdir(parents=True, exist_ok=True)
    _session_ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    _log_file = _log_dir / f"proxy_{_session_ts}.log"
    set_log_file(_log_file)

    console.print("\n[bold cyan]Frieren DAST-AI proxy[/bold cyan]")
    console.print(f"  Proxy:     [bold]{proxy_host}:{proxy_port}[/bold]  ← set in browser proxy settings")
    console.print(f"  Dashboard: [bold]http://127.0.0.1:{dashboard_port}[/bold]  ← opens automatically")
    console.print(f"  CA cert:   [dim]{_ca.ca_cert_path}[/dim]")
    console.print(f"  Log file:  [dim]{_log_file}[/dim]")
    console.print("  [dim]Install the CA cert once to intercept HTTPS — see Setup tab in dashboard.[/dim]")
    console.print("  [dim]If either port above is already in use, the proxy falls back to the next"
                  " free one and prints a WARNING below — watch for it.[/dim]")
    console.print("  [dim]Press Ctrl+C to stop.[/dim]\n")

    runner = ProxyRunner(
        proxy_port=proxy_port,
        proxy_host=proxy_host,
        dashboard_port=dashboard_port,
        workers=workers,
        iterations=iterations,
        confidence=confidence,
        attack_types=enabled,
        output_dir=output_dir,
        auth_url=auth_url,
        username=username,
        password=password,
        ai_model_id=settings.ai_model_id,
    )

    try:
        asyncio.run(runner.run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Proxy stopped[/yellow]")


# ---------------------------------------------------------------------------
# mcp — expose the shared tool layer over the Model Context Protocol (stdio)
# ---------------------------------------------------------------------------

@main.command()
@click.option("--proxy-port", default=8080, show_default=True, help="Proxy port of the running Frieren instance")
@click.option("--dashboard-port", default=8088, show_default=True, help="Dashboard port of the running Frieren instance")
def mcp(proxy_port, dashboard_port):
    """
    Start the MCP server (stdio) exposing Frieren's tool layer to AI clients.

    Drives an ALREADY-RUNNING Frieren instance: sends traffic through its proxy
    port and reads live state via its dashboard API. Start `dast-ai proxy` first,
    then register this command as an MCP server in your client (e.g. Claude
    Desktop/Code). Tools: send_request (out-of-scope targets prompt the dashboard
    operator for approval), get_history, get_findings, content_discovery,
    param_mining, triage_report, list_login_profiles, oob_generate/oob_poll (blind
    OOB detection), and url/base64/html encode+decode — all scope- and
    payload-safety-gated.
    """
    from dast.mcp import run_stdio

    # No console banner: stdout is the MCP transport and must carry only protocol
    # frames. Logs go to structlog (stderr / log file).
    asyncio.run(run_stdio(proxy_port=proxy_port, dashboard_port=dashboard_port))


if __name__ == "__main__":
    main()
