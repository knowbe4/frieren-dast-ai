# Frieren DAST-AI — TODO

Improvements identified during HackerOne retest sessions (2026-10-01).

---

## Bugs (fixed)

- [x] **Match/replace content-length desync** — when match/replace modifies the request body, the `content-length` header was not updated. Fixed in `dast/proxy/proxy_server.py`.
- [x] **Browser close not detected on macOS** — closing the Chromium window does not always kill the browser process on macOS. Fixed in `dast/proxy/browse_session.py` and `dast/proxy/runner.py`.

## XSS payloads

- [x] **Sanitizer bypass payloads** — three bypass payloads (null-byte prefix, DOM nesting/mXSS, encoded ontoggle) added to the `bypass` category.

## Copilot improvements

- [x] **Copilot source label in history** — copilot `send_request` entries are now tagged `source: "copilot"` with a dedicated history badge and filter checkbox.
- [x] **Copilot pause banner** — persistent top-level banner below the main tab bar, visible on every tab, driven by the copilot WS `pause`/`resumed` events.
- [x] **Copilot session-safe mode** — `session_safe` flag skips ambient auto-scan and caps crawl for strict/single-session targets (ASP.NET).
- [x] **Copilot browser-driving capability** — `AgentBrowser` + six `browser_*` tools (navigate/snapshot/fill/click/wait_for/extract). Headless, proxy-routed, cookie-seeded, one persistent page per session. Validated live.
- [x] **Encrypted credential storage + auto re-login** — already present in `dast/profiles/`; added `DAST_PROFILES_KEY` env override for optional hardware-bound key.

## UI/UX improvements

- [x] **Intercept diff view** — `PendingRequest` snapshots the original; Diff toggle shows inline original-vs-modified line diff.
- [x] **Findings tab** — promoted from buried Proxy > Issues sub-tab to a top-level **Findings** tab with a severity-colored live count badge.
- [x] **Multi-request evidence (steps)** — `record_finding` takes an optional `steps` array rendered as a clean numbered evidence table in the Findings tab and detail panel.
- [x] **Deterministic BOLA/IDOR runner (`idor_probe`)** — one tool call runs the full write/read/control/delete differential, classifies deterministically, and records a finding with steps. Covered by unit tests.
- [x] **Model-layer tool-arg forcing** — when a `call_tool` is missing a required arg, the loop re-asks with the tool's own JSON Schema; falls back to a precise nudge on failure.
- [x] **Match/replace UI visibility** — sticky section jump-nav in Proxy Settings; Match & Replace link carries a badge showing the active-rule count.
- [x] **Settings page restructure** — sticky section jump-nav (Scope, Bypass & Extensions, Match & Replace, Setup) with anchors on each section.

## Copilot autonomous retest capability

- [x] **CSRF-protected forms end-to-end** — validated live: navigate, snapshot, extract hidden token, fill, submit via browser tools + `match_replace` for transparent payload injection.
- [x] **Match/replace as copilot tool** — `match_replace` tool (add/list/remove/clear), copilot-scoped rules auto-cleaned on session end.
- [x] **Verify rendered output (`verify_reflection`)** — classifies payload survival (rendered_raw / encoded / stripped) with evidence.
- [x] **get_history pagination/filtering** — filters by method, path, source; newest-first; entry_id lookup with bodies.
- [x] **Session flooding prevention** — session-safe mode skips ambient auto-scan + caps crawl.
- [x] **Autonomous retest workflow** — composable via system-prompt playbook: auto SSO login, browser-driving, `idor_probe`, `verify_reflection`, `record_finding` with steps.

## Copilot autonomy fixes

- [x] **AuthAgent staged SSO login** — follows SSO sign-in button + handles staged email/Continue/password; seeds the proxy cookie jar from login. Headless auto-relogin via SessionRefreshWorker uses the same path.
- [x] **Tool-arg validation + repair** — required args validated from schema before dedup/execution; schema-forced repair pass before nudge fallback.
- [x] **Anti-repeat reset after mutation** — successful state-changing requests clear the dedup set so confirming re-reads run.
- [x] **Stale get_history guidance** — system prompt instructs confirming mutations with fresh requests, not history.
- [x] **Auth-host auto-scoped** — `--auth-url` host auto-added to proxy scope so findings are not silently dropped.
- [x] **BOLA/IDOR differential runner** — `idor_probe` tool; proven live.

## Dashboard UI backlog (2026-10-28)

- [ ] **GraphQL mode hides response** — switching a request to GraphQL view in the Proxy tab makes the response panel below disappear.
- [ ] **Findings "Go to request" shows original, not vuln request** — clicking "Go to request" on a finding navigates to the clean intercepted request, not the probe that triggered the vulnerability. Should show original request/response + vuln request/response side by side (like Burp Suite).
- [ ] **No pretty view in Repeater** — request/response bodies are shown raw; need formatted JSON/HTML/XML view with syntax highlighting.
- [ ] **No pretty view in GraphQL tab** — same as Repeater; GraphQL queries and responses need formatted display.

## Copilot engine backlog (2026-10-28)

- [x] **browser_snapshot anti-repeat false positive** — fixed: dedup key now includes the browser's current page URL for browser read tools (snapshot, extract, wait_for).
- [ ] **Tool tabs need server-side storage + API** — Repeater, Intruder, GraphQL, Decoder, JWT tabs store state client-side only with no read API. The copilot cannot list, read, or replay saved requests. Each tab needs: (a) server-side storage for named request/response pairs; (b) CRUD API (`GET/POST/PUT/DELETE /api/repeater/tabs`, etc.); (c) copilot tool wrappers so the copilot can read operator-prepared requests, replay with modifications, and use as baselines for differential testing.
## GraphQL IDOR / Access Control backlog (2026-10-28)

- [ ] **GraphQL mutation IDOR agent** — for every mutation that takes an `id` argument:
  (a) run the sibling list/query to enumerate visible resources;
  (b) attempt to mutate IDs outside the user's expected scope (system IDs, other-tenant IDs,
  sequential probing);
  (c) confirm the mutation succeeded by re-querying. Deterministic, no LLM needed. Should
  detect vulns like notificationTemplateCategoryUpdate allowing account admins to rename
  shared system categories.
- [ ] **Multi-session IDOR testing** — use named profiles (`dast/profiles/`) to run the same
  mutation as two different users (user A, user B in different accounts/tenants). If A can
  mutate B's resource, confirmed cross-tenant IDOR. The profiles infra exists but the copilot
  and agents never use it for automated cross-session differential testing.
- [ ] **Resource scope heuristic** — compare the set of resources a list query returns vs what
  the user "owns" (created_by, account_id match). Resources visible but not owned are
  candidates for IDOR write testing. Heuristic signals: very low sequential IDs (system
  seeds), names containing "system"/"default"/"global", missing account_id field in response.

- [x] **Repeater API should route through proxy** — fixed: requests now route through
  the local proxy when proxy_port is set, so traffic appears in History and plugins
  process it.
- [ ] **Repeater proxy routing strips/modifies operator-set headers** — the Repeater now
  routes through the MITM proxy, but the proxy overwrites headers like X-Forwarded-Host,
  X-Forwarded-For, X-Real-IP that the operator set explicitly. This breaks header injection
  tests (e.g. SSRF via X-Forwarded-Host). The Repeater should preserve operator-defined
  headers through the proxy, or offer a "direct (no proxy)" mode for header injection tests.

## Copilot auth/cookie backlog (2026-10-28)

- [ ] **Copilot should check proxy cookie jar before requesting auth** — when send_request
  hits a 401/403, the copilot pauses for operator auth even when valid session cookies for
  that host already exist in the proxy cookie jar (from the operator's browser traffic).
  The copilot should auto-inject jar cookies before escalating to an auth pause.
- [ ] **Copilot auth resume with jar cookies still gets 403** — `from_jar: true` resume
  collects cookies from the proxy jar and retries, but the retry may still fail (403) if
  the cookies are incomplete (e.g., missing CSRF token header, or the endpoint needs
  a specific auth mechanism beyond session cookies).
