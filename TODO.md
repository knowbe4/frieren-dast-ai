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
- [x] **Copilot session-safe mode** — added a `session_safe` flag (autonomous run config + API + UI checkbox, threaded via `ToolContext.session_safe`). When on, it skips the ambient `auto_ai_mode` auto-scan (the param-mining/agent flood that shared the login cookie) and caps `crawl` to 20 clicks with no extra seeds, so strict/single-session targets (ASP.NET) stay logged in.
- [ ] **Copilot browser-driving capability** — the copilot cannot fill forms, click buttons, or interact with the real browser. For targets with CSRF tokens (ComposeToken, Viewstate, draftId), raw `send_request` replay fails. The copilot should be able to drive the manual browser (navigate, fill fields, submit) for form-based workflows that require fresh tokens.
- [ ] **Encrypted credential storage + auto re-login** — save credentials securely per machine (encrypted, hardware-bound key) so the copilot can automatically re-login when sessions expire. Extends the existing `dast/profiles/` system.

## UI/UX improvements

- [x] **Intercept diff view** — `PendingRequest` now snapshots the request/response as first intercepted (`orig_*` fields) and the intercept editor has a Diff toggle showing an inline original-vs-modified line diff.
- [ ] **Proxy findings view** — improve how findings are surfaced/reviewed in the proxy UI (not just the history table). Needs scoping: dedicated findings panel, per-entry finding badges, severity grouping, evidence drill-down. (Raised 2026-10-01.)
- [x] **Match/replace UI visibility** — the Proxy Settings page now has a sticky section jump-nav; the Match & Replace link carries a badge showing the active-rule count, so the operator sees at a glance when rewriting is live.
- [x] **Settings page restructure** — added a sticky section jump-nav (Scope, Bypass & Extensions, Match & Replace, Setup) with anchors on each section so every tool is one click away and visible at a glance. (Did not split into separate sub-tabs — the jump-nav keeps the existing single-page handlers intact; revisit sub-tabs if the page keeps growing.)

## Copilot autonomous retest capability (H1 #3823255 learnings)

The copilot should be able to fully retest a HackerOne report autonomously without operator intervention. During the H1 #3823255 retest (2026-10-01), the copilot failed at every step and the operator had to manually test via match/replace + manual browser. Key gaps:

- [ ] **Copilot should handle CSRF-protected forms end-to-end** — the copilot couldn't test `/compose/send` because ComposeToken/Viewstate are single-use CSRF tokens. It needs to: open the browser, navigate to `/compose`, extract fresh tokens from the form, build a valid request with the XSS payload in BodyHtml, submit, then check the rendered output. This is the core gap — `send_request` alone cannot replay CSRF-protected endpoints.
- [ ] **Copilot should use match/replace for payload injection** — instead of trying to replay stale requests, the copilot should set up a match/replace rule (e.g. swap BodyHtml), then drive the browser to submit the form normally. The proxy injects the payload transparently, preserving all CSRF tokens. This is what we did manually and it worked.
- [x] **Copilot should verify rendered output automatically** — added the `verify_reflection` tool: fetches a rendered page and classifies the payload as rendered_raw / encoded / stripped with evidence. Baseline-vs-payload comparison is done by calling it twice (benign value, then payload).
- [x] **get_history pagination/filtering** — `get_history` now filters by method, path (substring), and source, sorts newest-first by default, and supports `entry_id` lookup returning a single entry with bodies.
- [x] **Copilot should not flood strict session targets** — addressed by the session-safe mode above (skips ambient auto-scan + caps crawl). Still manual opt-in via the checkbox; automatic detection of strict session management (back off on login-redirect/401 after probes) remains a future enhancement.
- [ ] **Autonomous retest workflow** — for H1 retests specifically, the copilot should follow this workflow: (1) read the report to understand the vuln, (2) open a browser and authenticate, (3) set up match/replace to inject payloads, (4) drive the browser through the vulnerable flow, (5) check rendered output, (6) record finding or confirm fix. This should be a single objective like "retest H1 #XXXX" and the copilot handles it.
