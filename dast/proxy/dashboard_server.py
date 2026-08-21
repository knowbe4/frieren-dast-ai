"""
Dashboard web server — FastAPI + WebSocket.

The HTML UI lives in dast/proxy/ui/. index.html holds the markup and references
its assets — styles.css and the ordered js/*.js feature files — which are served
as static files mounted at /ui. The js/*.js files are classic (non-module)
scripts and MUST load in filename order (the numeric prefixes encode that order);
concatenating them reproduces the original single inline script block.
API routes are split across dast/proxy/api/ modules.
"""

import asyncio
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from dast.proxy.session_store import SessionStore
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_UI_PATH = Path(__file__).parent / "ui" / "index.html"


def _detect_aws_sso_profile() -> str | None:
    """
    Auto-detect a usable SSO profile by finding one whose sso-session has a
    valid (non-expired) token in ~/.aws/sso/cache.
    Falls back to the first SSO profile if no valid token is found.
    """
    import configparser
    import json
    from datetime import datetime, timezone
    from pathlib import Path

    config_path = Path.home() / ".aws" / "config"
    sso_cache_dir = Path.home() / ".aws" / "sso" / "cache"
    if not config_path.exists():
        return None

    cp = configparser.ConfigParser()
    try:
        cp.read(config_path)
    except Exception:
        return None

    session_to_url: dict = {}
    for section in cp.sections():
        if section.startswith("sso-session"):
            sname = section.removeprefix("sso-session").strip()
            url = cp.get(section, "sso_start_url", fallback=None)
            if url:
                session_to_url[sname] = url

    url_valid: dict = {}
    if sso_cache_dir.exists():
        now = datetime.now(timezone.utc)
        for cache_file in sso_cache_dir.glob("*.json"):
            try:
                data = json.loads(cache_file.read_text())
                start_url = data.get("startUrl", "")
                expires_str = data.get("expiresAt", "")
                has_token = bool(data.get("accessToken"))
                if start_url and has_token and expires_str:
                    expires = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
                    if expires > now:
                        url_valid[start_url] = True
            except Exception:
                continue

    first_sso: str | None = None
    for section in cp.sections():
        if section.startswith("sso-session"):
            continue
        sso_session = cp.get(section, "sso_session", fallback=None)
        sso_account = cp.get(section, "sso_account_id", fallback=None)
        if not (sso_session or sso_account):
            continue
        name = section.removeprefix("profile ").strip()
        if first_sso is None:
            first_sso = name
        if sso_session:
            start_url = session_to_url.get(sso_session, "")
            if url_valid.get(start_url):
                logger.debug("Auto-detected SSO profile (valid token)", profile=name)
                return name

    if first_sso:
        logger.debug("Auto-detected SSO profile (fallback, no valid token found)", profile=first_sso)
    return first_sso


_ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "CONNECT"}
_ALLOWED_SOURCES = {"proxy", "crawler", "browse", "agent", "imported", "out-of-scope", "passive", "scanner"}
_ALLOWED_PROTOCOLS = {"any", "http", "https", ""}
_ALLOWED_KINDS = {"include", "exclude"}


def _validate_session_import(data: dict) -> str | None:
    """Return an error string if the session JSON is structurally invalid."""
    if not isinstance(data, dict):
        return "Expected a JSON object"
    name = data.get("name", "")
    if not isinstance(name, str) or len(name) > 200:
        return "Invalid session name"
    entries = data.get("entries")
    if entries is not None and not isinstance(entries, list):
        return "entries must be a list"
    if entries:
        if len(entries) > 100_000:
            return "Too many entries (max 100 000)"
        for i, e in enumerate(entries[:20]):
            if not isinstance(e, dict):
                return f"Entry {i} is not an object"
            method = e.get("method", "")
            if method and method not in _ALLOWED_METHODS:
                return f"Entry {i} has invalid method"
            source = e.get("source", "proxy")
            if source not in _ALLOWED_SOURCES:
                return f"Entry {i} has invalid source"
            url = e.get("url", "")
            if not isinstance(url, str) or len(url) > 8192:
                return f"Entry {i} has invalid URL"
    cookies = data.get("cookies")
    if cookies is not None and not isinstance(cookies, dict):
        return "cookies must be an object"
    return None


def _validate_settings_import(data: dict) -> str | None:
    """Return an error string if the settings JSON is structurally invalid."""
    if not isinstance(data, dict):
        return "Expected a JSON object"
    rules = data.get("scope_rules")
    if rules is not None:
        if not isinstance(rules, list):
            return "scope_rules must be a list"
        if len(rules) > 500:
            return "Too many scope rules (max 500)"
        for i, r in enumerate(rules):
            if not isinstance(r, dict):
                return f"Rule {i} is not an object"
            if r.get("protocol", "any") not in _ALLOWED_PROTOCOLS:
                return f"Rule {i} has invalid protocol"
            if r.get("kind", "include") not in _ALLOWED_KINDS:
                return f"Rule {i} has invalid kind"
            for field in ("host", "port", "file"):
                v = r.get(field, "")
                if not isinstance(v, str) or len(v) > 500:
                    return f"Rule {i} field '{field}' is invalid"
    bypass = data.get("bypass_domains")
    if bypass is not None:
        if not isinstance(bypass, list) or len(bypass) > 1000:
            return "bypass_domains must be a list with at most 1000 entries"
        if any(not isinstance(d, str) or len(d) > 253 for d in bypass):
            return "bypass_domains contains invalid entries"
    hidden = data.get("hidden_extensions")
    if hidden is not None:
        if not isinstance(hidden, list) or len(hidden) > 200:
            return "hidden_extensions must be a list with at most 200 entries"
        if any(not isinstance(x, str) or len(x) > 20 for x in hidden):
            return "hidden_extensions contains invalid entries"
    return None


def _apply_settings_data(settings, data: dict) -> None:
    """Apply validated settings data (scope_rules, bypass, hidden_ext) to a ProxySettings object."""
    saved_rules = data.get("scope_rules")
    if saved_rules is not None:
        with settings._lock:
            settings._scope_rules = list(saved_rules)
        settings._save()
    saved_bypass = data.get("bypass_domains")
    if saved_bypass is not None:
        saved_bypass_set = set(saved_bypass)
        current_bypass = set(settings._bypass)
        for dom in current_bypass - saved_bypass_set:
            settings.remove_bypass(dom)
        for dom in saved_bypass_set - current_bypass:
            settings.add_bypass(dom)
    saved_ext = data.get("hidden_extensions")
    if saved_ext is not None:
        saved_ext_set = set(saved_ext)
        current_ext = set(settings._hidden_ext)
        for ext in current_ext - saved_ext_set:
            settings.remove_hidden_ext(ext)
        for ext in saved_ext_set - current_ext:
            settings.add_hidden_ext(ext)


def build_app(
    store: SessionStore,
    scan_queue: asyncio.Queue,
    ca=None,
    settings=None,
    crawl_queue: asyncio.Queue = None,
    plugin_manager=None,
    browse_queue: asyncio.Queue = None,
    proxy_port: int = 8080,
    scan_config: dict = None,
    scan_queue_state=None,
    runner=None,
    intercept_store=None,
    discovery_queue: asyncio.Queue = None,
    login_queue: asyncio.Queue = None,
    proxy_host: str = "127.0.0.1",
) -> FastAPI:
    from dast.proxy.api.context import DashboardContext
    from dast.proxy.api.proxy_routes import make_router as proxy_router
    from dast.proxy.api.settings_routes import make_router as settings_router
    from dast.proxy.api.ai_routes import make_router as ai_router
    from dast.proxy.api.session_routes import make_router as session_router
    from dast.proxy.api.browser_routes import make_router as browser_router
    from dast.proxy.api.findings_routes import make_router as findings_router
    from dast.proxy.api.repeater_routes import make_router as repeater_router
    from dast.proxy.api.intruder_routes import make_router as intruder_router
    from dast.proxy.api.status_routes import make_router as status_router, prefetch_ai_status
    from dast.proxy.api.hackerone_routes import make_router as hackerone_router
    from dast.proxy.api.code_routes import make_router as code_router
    from dast.proxy.api.intercept_routes import make_router as intercept_router
    from dast.proxy.api.graphql_routes import make_router as graphql_router
    from dast.proxy.api.interactions_routes import make_router as interactions_router
    from dast.proxy.api.fedramp_routes import make_router as fedramp_router
    from dast.proxy.api.jwt_routes import make_router as jwt_router
    from dast.proxy.api.profiles_routes import make_router as profiles_router
    from dast.proxy.api.login_flow_routes import make_router as login_flow_router
    from dast.proxy.api.mcp_approval_routes import make_router as mcp_approval_router
    from dast.proxy.api.agent_triage_routes import make_router as agent_triage_router

    ctx = DashboardContext(
        store=store,
        scan_queue=scan_queue,
        ca=ca,
        settings=settings,
        crawl_queue=crawl_queue,
        plugin_manager=plugin_manager,
        browse_queue=browse_queue,
        discovery_queue=discovery_queue,
        login_queue=login_queue,
        proxy_port=proxy_port,
        proxy_host=proxy_host,
        scan_config=scan_config,
        scan_queue_state=scan_queue_state,
        runner=runner,
        intercept_store=intercept_store,
    )

    app = FastAPI(title="Frieren DAST-AI Proxy Dashboard")

    @app.on_event("startup")
    async def _startup() -> None:
        await prefetch_ai_status(ctx)

    @app.get("/", response_class=HTMLResponse)
    async def ui():
        return HTMLResponse(_UI_PATH.read_text(encoding="utf-8"))

    # Serve the UI's static assets (styles.css, js/*.js) referenced by index.html.
    # Mounted at /ui so it never collides with "/" or the /api/* routers.
    app.mount("/ui", StaticFiles(directory=str(_UI_PATH.parent)), name="ui")

    store.add_listener(ctx.broadcast)

    # Wire intercept broadcast so the store can push queue updates to WebSocket clients
    # without knowing about the HTTP layer (avoids circular import).
    if intercept_store is not None:
        from dast.proxy.api.intercept_routes import _broadcast_queue as _ic_broadcast
        async def _ic_on_change():
            await _ic_broadcast(ctx)
        intercept_store.set_broadcast_callback(_ic_on_change)

    app.include_router(proxy_router(ctx))
    app.include_router(settings_router(ctx))
    app.include_router(ai_router(ctx))
    app.include_router(session_router(ctx))
    app.include_router(browser_router(ctx))
    app.include_router(findings_router(ctx))
    app.include_router(repeater_router(ctx))
    app.include_router(intruder_router(ctx))
    app.include_router(status_router(ctx))
    app.include_router(hackerone_router(ctx))
    app.include_router(code_router(ctx))
    app.include_router(intercept_router(ctx))
    app.include_router(graphql_router(ctx))
    app.include_router(interactions_router(ctx))
    app.include_router(fedramp_router(ctx))
    app.include_router(jwt_router(ctx))
    app.include_router(profiles_router(ctx))
    app.include_router(login_flow_router(ctx))
    app.include_router(mcp_approval_router(ctx))
    app.include_router(agent_triage_router(ctx))

    return app
