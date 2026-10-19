"""
SpaExplorer — exhaustive, analyst-like SPA traversal.

Unlike ``SpaCrawler`` (one click per page, global fingerprint dedup, stops after
~a dozen clicks on a shared-nav app), the explorer works a persisted route
frontier: it visits each discovered route, reveals hover/dropdown menus, descends
open shadow DOM, follows Angular ``routerLink`` / hash routes, clicks onClick-only
nav, and — only when the operator opts in and the run is active — fills and
submits forms with benign canaries to reach wizard steps and capture mutation
requests. It does NOT self-limit by a shallow click budget; it runs until the
frontier drains (or a safety ceiling / the stop event).

Everything is routed through the proxy via ``proxied_browser_context`` so entries
are captured and scope/read-only rules apply. Destructive controls (logout,
delete, …) are never clicked or submitted.
"""

from __future__ import annotations

import asyncio
import inspect
import uuid
from typing import Callable, List, Optional
from urllib.parse import urlparse

from dast.ai import canaries
from dast.proxy import dom_probe
from dast.proxy.browser_session import proxied_browser_context
from dast.proxy.session_store import SessionStore
from dast.proxy.ui_route_graph import normalise_route_key
from dast.utils.logger import get_logger
from dast.utils.tasks import spawn_tracked

logger = get_logger(__name__)

# Elements worth interacting with. CSS selectors pierce OPEN shadow DOM in
# Playwright, so shadow-hosted nav is reached. Leaf menu/tab/tree roles plus
# routerLink hosts and generic buttons.
_EXPLORE_CLICKABLE = (
    "a[href]",
    "button:not([disabled])",
    "[role='button']:not([disabled])",
    "[role='tab']",
    "[role='menuitem']",
    "[role='treeitem']",
    "[role='option']",
    "[routerLink]",
    "[ng-reflect-router-link]",
    "[data-href]",
    "input[type='submit']:not([disabled])",
)

_SKIP_EXTENSIONS = {".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                    ".ico", ".woff", ".woff2", ".ttf", ".map", ".webp", ".avif"}

# Never click or submit these — they destroy session or data. Reused from the
# crawler's intent; kept local so the two modules stay independent.
_DANGEROUS_KEYWORDS = {
    "logout", "log out", "log-out", "sign out", "sign-out", "signout",
    "delete", "remove", "deactivate", "close account", "cancel account",
    "revoke", "end session", "terminate", "unsubscribe", "reset password",
    "change password", "disable",
}

_DEFAULT_MAX_ROUTES = 400
_SESSION_SAFE_MAX_ROUTES = 60
_MAX_INTERACTIONS_PER_ROUTE = 40
_SESSION_SAFE_INTERACTIONS = 12
_MAX_FORMS_PER_ROUTE = 5
_MAX_WIZARD_STEPS = 6
# Cap on vision-model navigation calls per run (each is a multimodal LLM call).
_MAX_VISION_CALLS = 25
_VIEWPORT = {"width": 1280, "height": 900}


class SpaExplorer:
    def __init__(
        self,
        store: SessionStore,
        log_cb: Callable,
        stop_event: asyncio.Event,
        proxy_port: int = 8080,
    ) -> None:
        self._store = store
        self._log_cb = log_cb
        self._stop = stop_event
        self._proxy_port = proxy_port
        self.session_id = str(uuid.uuid4())[:8]
        self._read_only = False
        self._submit_forms = False
        self._session_safe = False
        self._vision = False
        self._vision_calls = 0

    def _log(self, msg: str) -> None:
        logger.debug(msg, session_id=self.session_id)
        if inspect.iscoroutinefunction(self._log_cb):
            spawn_tracked(self._log_cb(msg), name="explore-log")
        else:
            try:
                self._log_cb(msg)
            except Exception as exc:  # noqa: BLE001
                logger.debug("explorer: log_cb failed", error=str(exc))

    async def run(
        self,
        target_url: str,
        *,
        read_only: bool = False,
        submit_forms: bool = False,
        session_safe: bool = False,
        headless: bool = True,
        max_routes: Optional[int] = None,
        vision: bool = False,
    ) -> None:
        self._read_only = read_only
        self._submit_forms = submit_forms and not read_only
        self._session_safe = session_safe
        self._vision = vision
        max_routes = max_routes or (_SESSION_SAFE_MAX_ROUTES if session_safe else _DEFAULT_MAX_ROUTES)

        graph = self._store.ui_route_graph
        graph.add_discovered(target_url, via="seed")
        # Vision runs inside _visit_route; if a prior (DOM/AX) pass already visited
        # the seed and left an empty frontier, re-open it so the vision pass has a
        # route to work on. Without this a vision re-run exits immediately.
        if self._vision and not graph.frontier():
            graph.reopen(normalise_route_key(target_url))

        parsed = urlparse(target_url)
        base_host = parsed.netloc
        settings = getattr(self._store, "_settings", None)

        def _is_allowed_host(host: str) -> bool:
            if host == base_host:
                return True
            return bool(settings and settings.is_in_scope(f"https://{host}/"))

        self._log(f"Explorer {self.session_id} starting → {target_url} "
                  f"(read_only={read_only}, submit_forms={self._submit_forms}, max_routes={max_routes})")
        self._store.active_crawler_session_id = self.session_id

        visited_count = 0
        try:
            async with proxied_browser_context(
                self._store, self._proxy_port, self.session_id,
                read_only=read_only, headless=headless, log_cb=self._log,
            ) as (context, page, request_count):
                from dast.scanners.active_checks import is_host_dead
                if is_host_dead(parsed.hostname or base_host):
                    self._log(f"Host unreachable ({base_host}) — skipping explore")
                    return

                while not self._stop.is_set() and visited_count < max_routes:
                    frontier = graph.frontier()
                    if not frontier:
                        self._log("Frontier drained — exploration complete")
                        break
                    # Shallowest-first so top-level sections are mapped before deep leaves.
                    route = min(frontier, key=lambda r: r.depth)
                    await self._visit_route(page, route, graph, _is_allowed_host)
                    visited_count += 1

                if visited_count >= max_routes:
                    self._log(f"Reached max-routes safety ceiling ({max_routes}); "
                              f"{len(graph.frontier())} route(s) still queued — restart to continue")
        except Exception as exc:  # noqa: BLE001 — never crash the worker on one run
            logger.error("explorer run failed", session_id=self.session_id, error=str(exc))
            self._log(f"Explorer error: {exc}")
        finally:
            self._store.active_crawler_session_id = None

        stats = graph.stats()
        self._log(f"Explore complete — visited {stats['visited']}, frontier {stats['frontier']}, "
                  f"failed {stats['failed']}, forms submitted {stats['forms_submitted']}")
        logger.info("Explore finished", session_id=self.session_id, **stats)

    async def _visit_route(self, page, route, graph, is_allowed_host) -> None:
        if is_host_dead_url(route.url):
            graph.mark_failed(route.route_key)
            return
        entries_before = len(self._store.in_scope_entries())
        try:
            await page.goto(route.url, wait_until="domcontentloaded", timeout=30000)
        except Exception as exc:
            logger.debug("explorer: nav timeout", url=route.url, error=str(exc))
            try:
                await page.wait_for_load_state("domcontentloaded", timeout=5000)
            except Exception:
                graph.mark_failed(route.route_key)
                return
        # A micro-frontend SPA renders its nav well after `load`: wait for the
        # network to go idle, then for actual interactive elements to appear,
        # before snapshotting. Without this the collector runs on an empty shell.
        await self._wait_for_spa_render(page)

        landed = page.url
        # A redirect to login means the session wasn't accepted — record and move on.
        if landed != route.url and any(
            kw in landed.lower() for kw in ("login", "signin", "/sso", "/authorize")
        ):
            self._log(f"Route redirected to auth ({landed}) — not authenticated for {route.url}")
            graph.mark_failed(route.route_key)
            graph.add_discovered(landed, via="nav", parent=route.route_key, depth=route.depth)
            return

        await self._scroll(page)
        await self._reveal_menus(page)

        routes_before = graph.stats()["total"]
        new_routes = await self._collect_routes(page, is_allowed_host)
        for url in new_routes:
            graph.add_discovered(url, via="link", parent=route.route_key, depth=route.depth + 1)

        interactions = await self._click_nav_elements(page, route, graph, is_allowed_host)
        # Also drive nav via the accessibility tree (role+name), which reaches
        # web-component nav inside shadow DOM that CSS selectors miss.
        cap = _SESSION_SAFE_INTERACTIONS if self._session_safe else _MAX_INTERACTIONS_PER_ROUTE
        interactions += await self._click_ax_nav(page, route, graph, is_allowed_host, set(), cap)

        # Vision fallback: the link collector + DOM + accessibility paths discovered
        # NO new route on a page that clearly rendered (web-component/canvas UI whose
        # nav is pixels, not structure). Gate on routes discovered, not click count —
        # a component SPA often exposes clickable controls that lead nowhere
        # enumerable, so "interactions > 0 but zero routes" is exactly when vision is
        # needed. Coordinator-enabled only, and bounded per run.
        routes_discovered = graph.stats()["total"] - routes_before
        vision_fires = (self._vision and routes_discovered == 0
                        and self._vision_calls < _MAX_VISION_CALLS and not self._stop.is_set())
        if vision_fires:
            logger.info("explorer: vision fallback engaged", url=page.url[:80],
                        dom_ax_interactions=interactions, vision_calls=self._vision_calls,
                        session_id=self.session_id)
            interactions += await self._vision_nav(page, route, graph, is_allowed_host)
        else:
            logger.debug("explorer: vision not engaged", vision=self._vision,
                         routes_discovered=routes_discovered, interactions=interactions,
                         url=page.url[:80], session_id=self.session_id)

        forms_submitted = 0
        if self._submit_forms:
            forms_submitted = await self._submit_forms_on_page(page, route, graph, is_allowed_host)

        api_entries = max(0, len(self._store.in_scope_entries()) - entries_before)
        graph.mark_visited(
            route.route_key,
            api_entries=api_entries,
            interactive_elements=interactions,
            forms_submitted=forms_submitted,
        )
        self._log(f"Visited {landed} — +{api_entries} API calls, {interactions} interactions, "
                  f"{forms_submitted} forms; frontier now {len(graph.frontier())}")

    async def _wait_for_spa_render(self, page) -> None:
        """Give a client-rendered SPA time to actually paint its nav before we
        enumerate: network-idle, then poll until interactive elements exist (links,
        buttons, role=button/menuitem/tab, routerLink), piercing open shadow DOM."""
        try:
            await page.wait_for_load_state("networkidle", timeout=8000)
        except Exception:
            pass
        census_js = """() => {
          const sels = ["a[href]","button","[role=button]","[role=menuitem]","[role=tab]",
                        "[routerLink]","[ng-reflect-router-link]","[onclick]"];
          let n = 0;
          const scan = (root) => {
            for (const s of sels) { try { n += root.querySelectorAll(s).length; } catch(e){} }
            try { root.querySelectorAll('*').forEach(el => { if (el.shadowRoot) scan(el.shadowRoot); }); } catch(e){}
          };
          scan(document);
          return n;
        }"""
        deadline = asyncio.get_event_loop().time() + 10
        count = 0
        while asyncio.get_event_loop().time() < deadline:
            try:
                count = await page.evaluate(census_js)
            except Exception:
                count = 0
            if count >= 5:
                break
            await asyncio.sleep(0.5)
        # Per-frame census: a micro-frontend SPA renders nav/content inside iframes
        # that top-document queries never see. Log counts per frame at info so we
        # can tell "empty shell" from "content is in a frame we're not crawling".
        frame_counts = []
        try:
            for fr in page.frames:
                try:
                    fc = await fr.evaluate(census_js)
                except Exception:
                    fc = -1
                frame_counts.append((fr.url[:60], fc))
        except Exception as exc:
            logger.debug("explorer: frame census failed", error=str(exc))
        # Accessibility-tree census: the AX tree surfaces roles even inside shadow
        # DOM (incl. closed) that querySelectorAll cannot reach. If the DOM census
        # is low but the AX tree is rich, the nav lives in web components and we
        # must drive it via roles, not CSS selectors.
        ax_roles: dict = {}
        ax_links: list = []
        try:
            snap = await page.accessibility.snapshot(interesting_only=False)

            def _walk(node):
                if not isinstance(node, dict):
                    return
                role = node.get("role", "")
                ax_roles[role] = ax_roles.get(role, 0) + 1
                if role in ("link", "button", "menuitem", "tab") and node.get("name"):
                    if len(ax_links) < 25:
                        ax_links.append(node.get("name")[:30])
                for child in node.get("children") or []:
                    _walk(child)
            _walk(snap)
        except Exception as exc:
            logger.debug("explorer: ax snapshot failed", error=str(exc))
        top_roles = dict(sorted(ax_roles.items(), key=lambda kv: -kv[1])[:12])
        logger.info("explorer census", url=page.url[:80], top_interactive=count,
                    frames=len(frame_counts), frame_counts=frame_counts[:8],
                    ax_total=sum(ax_roles.values()), ax_roles=top_roles, ax_nav_sample=ax_links,
                    session_id=self.session_id)
        self._log(f"SPA render settled: {count} DOM interactive, "
                  f"{sum(ax_roles.values())} AX nodes, {len(frame_counts)} frame(s)")

    async def _settle_after_click(self, page) -> None:
        """Settle the page after a click that MAY navigate. A navigating click
        dispatches its navigation on a later task, so calling
        ``wait_for_load_state('networkidle')`` immediately can resolve against the
        pre-navigation document — the URL would be read before the navigation commits
        and the new route would be missed on a fast server. A brief pause lets the
        navigation get in-flight; networkidle then waits for it to finish. A no-op
        click just settles quickly."""
        await asyncio.sleep(0.15)
        try:
            await page.wait_for_load_state("networkidle", timeout=3000)
        except Exception:
            await asyncio.sleep(0.3)

    async def _scroll(self, page) -> None:
        try:
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await asyncio.sleep(0.6)
            await page.evaluate("window.scrollTo(0, 0)")
            await asyncio.sleep(0.3)
        except Exception as exc:
            logger.debug("explorer: scroll failed", error=str(exc))

    async def _reveal_menus(self, page) -> None:
        """Hover menu triggers so display:none dropdown/flyout items render and
        become discoverable by the route collector."""
        for selector in dom_probe.MENU_TRIGGER_SELECTORS:
            if self._stop.is_set():
                return
            try:
                triggers = await page.query_selector_all(selector)
            except Exception:
                continue
            for trigger in triggers[:15]:
                try:
                    if await trigger.is_visible():
                        await trigger.hover(timeout=1000)
                        await asyncio.sleep(0.15)
                except Exception:
                    continue

    async def _collect_routes(self, page, is_allowed_host) -> List[str]:
        try:
            raw = await page.evaluate(dom_probe.COLLECT_ROUTES_JS)
        except Exception as exc:
            logger.debug("explorer: route collect failed", error=str(exc))
            return []
        out: List[str] = []
        for url in raw or []:
            try:
                parsed = urlparse(url)
                if not parsed.netloc or not is_allowed_host(parsed.netloc):
                    continue
                if any(parsed.path.lower().endswith(ext) for ext in _SKIP_EXTENSIONS):
                    continue
                low = url.lower()
                if any(kw in low for kw in ("logout", "signout", "sign-out", "/delete", "deactivate", "revoke")):
                    continue
                out.append(url)
            except Exception:
                continue
        return out

    async def _click_nav_elements(self, page, route, graph, is_allowed_host) -> int:
        """Click interactive elements that have no href (onClick-only nav) to
        discover routes the DOM collector can't see. After a navigating click we
        return to the route to keep enumerating it. Per-route fingerprinting so a
        shared nav is followed (each destination once) rather than skipped."""
        cap = _SESSION_SAFE_INTERACTIONS if self._session_safe else _MAX_INTERACTIONS_PER_ROUTE
        clicked_fps: set = set()
        interactions = 0
        # Tag every interactive-looking element (div/span nav with click handlers,
        # role, tabindex, cursor:pointer) across open shadow DOM, then collect those
        # handles — SPAs rarely use plain <a>/<button> for nav.
        try:
            tagged = await page.evaluate(dom_probe.TAG_CLICKABLES_JS)
            self._log(f"Tagged {tagged} clickable element(s) on {page.url[:70]}")
        except Exception as exc:
            logger.debug("explorer: clickable tagging failed", error=str(exc))
        try:
            handles = await page.query_selector_all("[data-dast-clickable]")
        except Exception as exc:
            logger.debug("explorer: element query failed", error=str(exc))
            return 0

        for el in handles:
            if self._stop.is_set() or interactions >= cap:
                break
            try:
                if not await el.is_visible():
                    continue
                tag = await el.evaluate("e => e.tagName.toLowerCase()")
                text = (await el.text_content() or "").strip()[:60]
                href = await el.get_attribute("href") or ""
                aria = await el.get_attribute("aria-label") or ""
                combined = f"{text} {aria} {href}".lower()
                if any(kw in combined for kw in _DANGEROUS_KEYWORDS):
                    continue
                # Form submission is exclusively the opt-in _submit_forms path's job:
                # never trigger a submit control or any control inside a <form> here,
                # so a plain nav walk (submit_forms off / read-only) performs no writes.
                el_type = (await el.get_attribute("type") or "").lower()
                if el_type == "submit":
                    continue
                try:
                    if await el.evaluate("e => !!e.closest('form')"):
                        continue
                except Exception:
                    pass
                # Links/routerLinks are already captured by the route collector.
                # Here we only trigger onClick-only elements (no usable href).
                if href and (href.startswith("http") or href.startswith("/") or href.startswith("#")):
                    continue
                fp = f"{tag}:{text}:{aria}"
                if fp in clicked_fps:
                    continue
                clicked_fps.add(fp)

                url_before = page.url
                await el.scroll_into_view_if_needed(timeout=2000)
                await el.click(timeout=2500)
                interactions += 1
                await self._settle_after_click(page)

                landed = page.url
                if landed != url_before:
                    parsed = urlparse(landed)
                    if parsed.netloc and is_allowed_host(parsed.netloc):
                        if graph.add_discovered(landed, via="click", parent=route.route_key, depth=route.depth + 1):
                            self._log(f"  → onClick route: {landed}")
                    # Return to the route so remaining elements are still enumerated.
                    try:
                        await page.goto(route.url, wait_until="domcontentloaded", timeout=15000)
                        await asyncio.sleep(0.6)
                    except Exception:
                        break
            except Exception as exc:
                logger.debug("explorer: element interaction failed", error=str(exc))
        return interactions

    async def _click_ax_nav(self, page, route, graph, is_allowed_host, clicked_fps, cap) -> int:
        """Click nav items via the ACCESSIBILITY TREE (role + name). The AX tree
        surfaces interactive elements the browser computes even inside web-component
        shadow DOM that CSS querySelectorAll cannot reach — this is how a modern
        component-based SPA (e.g. a micro-frontend console) exposes its nav.
        Playwright role locators resolve across shadow DOM."""
        interactions = 0
        try:
            snap = await page.accessibility.snapshot(interesting_only=True)
        except Exception as exc:
            logger.debug("explorer: ax snapshot failed", error=str(exc))
            return 0

        candidates: List[tuple] = []  # (role, name)

        def _walk(node):
            if not isinstance(node, dict) or len(candidates) >= 200:
                return
            role = node.get("role", "")
            name = (node.get("name") or "").strip()
            if role in ("link", "button", "menuitem", "tab", "treeitem") and name:
                candidates.append((role, name))
            for child in node.get("children") or []:
                _walk(child)
        _walk(snap)

        for role, name in candidates:
            if self._stop.is_set() or interactions >= cap:
                break
            fp = f"ax:{role}:{name}"
            if fp in clicked_fps:
                continue
            clicked_fps.add(fp)
            if any(kw in name.lower() for kw in _DANGEROUS_KEYWORDS):
                continue
            try:
                loc = page.get_by_role(role, name=name, exact=True).first
                if not await loc.is_visible():
                    continue
                url_before = page.url
                await loc.scroll_into_view_if_needed(timeout=1500)
                await loc.click(timeout=2500)
                interactions += 1
                await self._settle_after_click(page)
                landed = page.url
                if landed != url_before:
                    parsed = urlparse(landed)
                    if parsed.netloc and is_allowed_host(parsed.netloc):
                        if graph.add_discovered(landed, via="click", parent=route.route_key, depth=route.depth + 1):
                            self._log(f"  -> AX nav route: {name!r} -> {landed}")
                    try:
                        await page.goto(route.url, wait_until="domcontentloaded", timeout=15000)
                        await self._wait_for_spa_render(page)
                    except Exception:
                        break
            except Exception as exc:
                logger.debug("explorer: ax nav click failed", role=role, name=name[:40], error=str(exc))
        return interactions

    async def _vision_nav(self, page, route, graph, is_allowed_host) -> int:
        """Last-resort navigation when the DOM and accessibility tree expose no
        clickable nav (web-component/canvas UI): screenshot the page, ask the cheap
        multimodal model for the on-screen nav controls, and click them by
        coordinate. Discovered routes feed the frontier like any other click."""
        from dast.ai import bedrock_client
        from dast.proxy.vision_nav import vision_clickables

        self._vision_calls += 1
        try:
            targets = await vision_clickables(page, bedrock_client.invoke_json, _VIEWPORT)
        except Exception as exc:  # noqa: BLE001 — vision is best-effort
            logger.warning("explorer: vision nav failed", error=str(exc))
            return 0

        interactions = 0
        for t in targets:
            if self._stop.is_set():
                break
            label = (t.get("label") or "").lower()
            if any(kw in label for kw in _DANGEROUS_KEYWORDS):
                continue
            x, y = t.get("x"), t.get("y")
            if x is None or y is None:
                continue
            try:
                url_before = page.url
                await page.mouse.click(int(x), int(y))
                interactions += 1
                await self._settle_after_click(page)
                landed = page.url
                if landed != url_before:
                    parsed = urlparse(landed)
                    if parsed.netloc and is_allowed_host(parsed.netloc):
                        if graph.add_discovered(landed, via="vision", parent=route.route_key, depth=route.depth + 1):
                            self._log(f"  -> vision nav route: {t.get('label')!r} -> {landed}")
                    try:
                        await page.goto(route.url, wait_until="domcontentloaded", timeout=15000)
                        await self._wait_for_spa_render(page)
                    except Exception:
                        break
            except Exception as exc:
                logger.debug("explorer: vision click failed", x=x, y=y, error=str(exc))
        return interactions

    async def _submit_forms_on_page(self, page, route, graph, is_allowed_host) -> int:
        """Fill forms with benign canaries and submit to capture the update/mutation
        request and advance wizard steps. Active + opt-in only; never submits a form
        whose submit control reads as a destructive action."""
        submitted = 0
        for _step in range(_MAX_WIZARD_STEPS):
            if self._stop.is_set() or submitted >= _MAX_FORMS_PER_ROUTE:
                break
            try:
                forms = await page.evaluate(dom_probe.COLLECT_FORMS_JS)
            except Exception as exc:
                logger.debug("explorer: form collect failed", error=str(exc))
                return submitted
            if not forms:
                return submitted

            progressed = False
            for form in forms:
                if submitted >= _MAX_FORMS_PER_ROUTE:
                    break
                if await self._fill_one_form(page, form):
                    submit_ok = await self._click_submit(page)
                    if submit_ok:
                        submitted += 1
                        progressed = True
                        try:
                            await page.wait_for_load_state("networkidle", timeout=3000)
                        except Exception:
                            await asyncio.sleep(0.6)
                        break  # re-collect forms (wizard may have advanced)
            if not progressed:
                break
        return submitted

    async def _fill_one_form(self, page, form: dict) -> bool:
        filled_any = False
        for field in form.get("fields", []):
            if field.get("hidden") or field.get("type") in ("submit", "button", "file", "hidden"):
                continue
            name = field.get("name") or field.get("id")
            if not name:
                continue
            selector = f'[name="{name}"]' if field.get("name") else f'#{field.get("id")}'
            try:
                if field.get("tag") == "select":
                    options = await page.query_selector_all(f"{selector} option")
                    for opt in options:
                        value = await opt.get_attribute("value")
                        if value:
                            await page.select_option(selector, value=value)
                            filled_any = True
                            break
                elif field.get("type") in ("checkbox", "radio"):
                    await page.check(selector, timeout=1500)
                    filled_any = True
                else:
                    await page.fill(selector, canaries.form_field_value(field.get("type", ""), name), timeout=1500)
                    filled_any = True
            except Exception as exc:
                logger.debug("explorer: fill field failed", field=name, error=str(exc))
        return filled_any

    async def _click_submit(self, page) -> bool:
        for selector in ('button[type="submit"]', 'input[type="submit"]',
                         'button:has-text("Save")', 'button:has-text("Next")',
                         'button:has-text("Continue")', 'button:has-text("Submit")'):
            try:
                btn = await page.query_selector(selector)
                if btn is None or not await btn.is_visible():
                    continue
                label = ((await btn.text_content() or "") + " " + (await btn.get_attribute("aria-label") or "")).lower()
                if any(kw in label for kw in _DANGEROUS_KEYWORDS):
                    continue
                await btn.click(timeout=2500)
                self._log(f"  submitted form via '{label.strip()[:30]}'")
                return True
            except Exception as exc:
                logger.debug("explorer: submit click failed", selector=selector, error=str(exc))
        return False


def is_host_dead_url(url: str) -> bool:
    from dast.scanners.active_checks import is_host_dead
    try:
        return is_host_dead(urlparse(url).hostname or "")
    except Exception:
        return False
