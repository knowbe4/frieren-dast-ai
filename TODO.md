# Frieren DAST-AI — TODO

Improvements identified during H1 #3823255 retest session (2026-10-01).

---

## Bugs (code fixes ready, need commit)

- [x] **Match/replace content-length desync** — when match/replace modifies the request body, the `content-length` header was not updated, causing the upstream server to hang waiting for bytes that never arrive. Fixed in `dast/proxy/proxy_server.py`.
- [x] **Browser close not detected on macOS** — closing the Chromium window does not always kill the browser process on macOS, so the `disconnected` event never fires and the dashboard still reports `active: true`. The operator has to go to Manual Browse > Close Browser manually. Fixed in `dast/proxy/browse_session.py` (page/context close listener) and `dast/proxy/runner.py` (`_active` cleanup via `nonlocal`).

## XSS payloads

- [x] **H1 #3823255 payloads added to xss.yaml** — three report-specific bypass payloads (null-byte prefix, DOM nesting/mXSS, encoded ontoggle) added to the `bypass` category.

## Copilot improvements

- [x] **Copilot source label in history** — copilot `send_request` entries are now tagged `source: "copilot"` (threaded through `ToolContext.source_label`) with a dedicated history badge and filter checkbox. Crawl traffic already shows as `crawler`.
- [x] **Copilot pause banner** — persistent top-level banner below the main tab bar, visible on every tab, driven by the copilot WS `pause`/`resumed` events (WS now connected at startup and seeded from any already-paused run). Clicking it jumps to the paused run.
- [ ] **Copilot session-safe mode** — the copilot's `crawl` tool with `auto_ai_mode=true` fires 200+ rapid httpx requests (param mining probes) sharing the browser's session cookie. ASP.NET apps with concurrent session detection invalidate the session, logging out both the copilot and the manual browser. Need a mode that throttles or skips param mining for targets with strict session management.
- [ ] **Copilot browser-driving capability** — the copilot cannot fill forms, click buttons, or interact with the real browser. For targets with CSRF tokens (ComposeToken, Viewstate, draftId), raw `send_request` replay fails. The copilot should be able to drive the manual browser (navigate, fill fields, submit) for form-based workflows that require fresh tokens.
- [ ] **Encrypted credential storage + auto re-login** — save credentials securely per machine (encrypted, hardware-bound key) so the copilot can automatically re-login when sessions expire. Extends the existing `dast/profiles/` system.

## UI/UX improvements

- [x] **Intercept diff view** — `PendingRequest` now snapshots the request/response as first intercepted (`orig_*` fields) and the intercept editor has a Diff toggle showing an inline original-vs-modified line diff.
- [ ] **Proxy findings view** — improve how findings are surfaced/reviewed in the proxy UI (not just the history table). Needs scoping: dedicated findings panel, per-entry finding badges, severity grouping, evidence drill-down. (Raised 2026-10-01.)
- [ ] **Match/replace UI visibility** — the Match & Replace section is inside Proxy > Settings (scroll down), which is not obvious. Consider making it a dedicated sub-tab (like Intercept) or adding a visual indicator when rules are active.
- [ ] **Settings page restructure** — the Proxy > Settings page crams too many sections together (scope, match/replace, bypass domains, etc.) with no clear visual separation. Each section (Scope, Match & Replace, Bypass Domains, etc.) should have distinct, visible headers/cards/accordions, or be split into dedicated sub-tabs. The current layout makes it easy to miss features — the user should see all available tools at a glance without scrolling and guessing.

## Copilot autonomous retest capability (H1 #3823255 learnings)

The copilot should be able to fully retest a HackerOne report autonomously without operator intervention. During the H1 #3823255 retest (2026-10-01), the copilot failed at every step and the operator had to manually test via match/replace + manual browser. Key gaps:

- [ ] **Copilot should handle CSRF-protected forms end-to-end** — the copilot couldn't test `/compose/send` because ComposeToken/Viewstate are single-use CSRF tokens. It needs to: open the browser, navigate to `/compose`, extract fresh tokens from the form, build a valid request with the XSS payload in BodyHtml, submit, then check the rendered output. This is the core gap — `send_request` alone cannot replay CSRF-protected endpoints.
- [ ] **Copilot should use match/replace for payload injection** — instead of trying to replay stale requests, the copilot should set up a match/replace rule (e.g. swap BodyHtml), then drive the browser to submit the form normally. The proxy injects the payload transparently, preserving all CSRF tokens. This is what we did manually and it worked.
- [ ] **Copilot should verify rendered output automatically** — after sending an XSS payload, the copilot should fetch the rendered page (e.g. `/p/<id>`) and check if dangerous HTML/JS survived sanitization. It should compare a clean baseline (normal email) vs the payload email and report whether the payload was stripped, encoded, or rendered unmodified.
- [x] **get_history pagination/filtering** — `get_history` now filters by method, path (substring), and source, sorts newest-first by default, and supports `entry_id` lookup returning a single entry with bodies.
- [ ] **Copilot should not flood strict session targets** — the first copilot run called `crawl` with `auto_ai_mode=true` which fired 200+ param-mining probes and killed the ASP.NET session. The copilot needs to detect strict session management (e.g. single concurrent session) and avoid heavy automated traffic. When `auto_ai_mode=true`, param mining should be throttled or skipped for targets that show session sensitivity.
- [ ] **Autonomous retest workflow** — for H1 retests specifically, the copilot should follow this workflow: (1) read the report to understand the vuln, (2) open a browser and authenticate, (3) set up match/replace to inject payloads, (4) drive the browser through the vulnerable flow, (5) check rendered output, (6) record finding or confirm fix. This should be a single objective like "retest H1 #XXXX" and the copilot handles it.
