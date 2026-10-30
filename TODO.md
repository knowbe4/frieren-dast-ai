# Frieren DAST-AI — TODO

Improvements identified during HackerOne retest sessions (2026-10-01).

---

## Bugs (fixed)

- [x] **Match/replace content-length desync** — when match/replace modifies the request body, the `content-length` header was not updated. Fixed in `dast/proxy/proxy_server.py`.
- [x] **Browser close not detected on macOS** — closing the Chromium window does not always kill the browser process on macOS. Fixed in `dast/proxy/browse_session.py` and `dast/proxy/runner.py`.

## XSS payloads

- [x] **Sanitizer bypass payloads** — three bypass payloads (null-byte prefix, DOM nesting/mXSS, encoded ontoggle) added to the `bypass` category.

## Copilot pentest tools (2026-10-29) — implemented

- [x] **browser_login tool** — autonomous multi-step login (email→submit→detect password→fill→
  submit). Handles 2-step flows (KMSAT, Okta). Exports cookies + CSRF to `_session_cookies`.
  Validated live via copilot: logged in to KMSAT and made authenticated GraphQL calls.
- [x] **browser_fetch CSRF auto-inject** — resolves relative URLs, auto-injects X-CSRF-Token
  from `document.cookie` and X-Requested-With header. Note: still has proxy interference bug
  (returns HTML instead of JSON when browser is proxy-routed — workaround: use send_request).
- [x] **test_unauth tool** — sends requests with NO cookies/auth to detect unauthenticated
  endpoints. Validated live: detected CDRMS CSV export (HIGH), Hermes webhooks (Medium).
- [x] **unauthenticated_endpoint passive rule** — flags 200/204 responses without session
  cookies. `one_per_host: true`, `needs_ai_validation: true`.
- [x] **CSRF auto-injection in send_request** — reliably extracts CSRF-TOKEN from
  `_session_cookies` and injects as `X-CSRF-Token` + `X-Requested-With` headers.
- [x] **Response body limits increased** — send_request 500KB, browser_fetch 50KB, repeater
  500KB (was 8KB/8KB/50KB). Validated: CDRMS CSV returns 1053 rows instead of 99.
- [x] **graphql_type_info tool** — inspect any GraphQL type: fields, enums, unions, args.
  Reads from cached schema (`ctx.store.graphql_schemas`).
- [x] **graphql_find_sensitive tool** — scans schema for credential-leaking field names
  (secret, token, password, otp, key, credential, apiKey, sharedSecret).

## Copilot reliability backlog (2026-10-30)

- [ ] **Copilot GraphQL requests should feed the GraphQL tab** — when the copilot sends
  GraphQL queries/mutations via send_request, the proxy should auto-detect the GraphQL
  body (JSON with `query` field), parse the operation name/type, and save it to the
  GraphQL tab's operation list. Currently copilot GraphQL traffic passes through the proxy
  but is not parsed or saved — dozens of test queries are lost after the session ends.
  This also means the schema introspection the copilot runs doesn't populate the tab.
- [ ] **Copilot `save_to_repeater` / `save_to_graphql` tools** — the copilot should be
  able to explicitly save a request to the Repeater or GraphQL tab for operator reuse.
  Requires the "Tool tabs server-side storage + API" item below. The copilot would call
  `save_to_repeater(name, request, response)` after a finding, so the operator can replay
  the exact request from the UI.
- [x] **browser_login auto-retry with snapshot feedback** — after 3 password-field retries
  fail, takes a browser_snapshot and returns it in the error. Also retries the submit click
  on attempt 2, and adds networkidle wait after password submit.
- [x] **Auto-relogin on 302/401** — `_last_login` stores credentials from browser_login.
  When send_request gets 302-to-login or 401, auto re-authenticates and retries once.
  `_relogin_in_progress` flag prevents infinite loops.
- [x] **Scope + target injection in copilot prompt** — `_scope_hosts_block()` in
  context_brief.py injects current scope hosts. `POST /api/scan-config` with `target_hosts`
  creates persisted scope rules.
- [x] **graphql_type_info filter/limit** — `filter` (case-insensitive field name match) and
  `limit` (default 50) parameters added. Response includes `total_fields` and `truncated`.
- [ ] **browser_fetch direct mode** — for API calls, bypass the proxy by extracting browser
  cookies and using httpx directly. The proxy intercepts fetch() and desynchronizes CSRF
  tokens. Same root cause as the Repeater cookie isolation issue.
- [ ] **Scope persistence across restarts** — save scope config to `~/.dast-ai/scope.json`
  on change, auto-load on startup. Currently must reconfigure via /api/scan-config after
  every restart.

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

- [x] **GraphQL mode hides response** — fixed: GraphQL content now renders in the Request pane while the Response pane stays visible.
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

- [ ] **browser_fetch returns HTML instead of JSON on proxy-routed browser** — `browser_fetch`
  runs `page.evaluate(fetch())` which goes through the Frieren proxy (the AgentBrowser is
  launched with `proxy: http://127.0.0.1:8080`). The proxy intercepts the request and may
  dessynchronize the CSRF token or session cookie, causing the server to return the SPA HTML
  shell instead of the API JSON response. Workaround: use `send_request` after `browser_login`
  (the CSRF auto-injection from `_session_cookies` works). Fix: either (a) launch a secondary
  browser context without proxy for `browser_fetch` API calls, or (b) implement per-source
  cookie jar isolation in the proxy (same root cause as the Repeater cookie issue below).
  Confirmed: `page.evaluate(fetch())` works perfectly when the browser is NOT proxy-routed
  (tested with vanilla Playwright — returns `{"data":{"currentUser":{...}}}` correctly).
- [ ] **Repeater API should route through proxy with cookie isolation** — the Repeater
  needs to route through the proxy so traffic appears in History and plugins process it,
  BUT it must use an isolated cookie jar (copy-on-use from the main jar) so that session
  rotation from Repeater requests does not invalidate the browser's session. The naive
  proxy routing (cfdf231, reverted in 7a42ffd) caused the KMSAT backend to rotate
  _knowbe4_session_new on the Repeater response, which then logged the browser out.
  Solution: per-source cookie jar isolation in the proxy, or a dedicated proxy session
  for Repeater traffic that doesn't share cookies with the browser.
- [ ] **Repeater proxy routing strips/modifies operator-set headers** — the Repeater now
  routes through the MITM proxy, but the proxy overwrites headers like X-Forwarded-Host,
  X-Forwarded-For, X-Real-IP that the operator set explicitly. This breaks header injection
  tests (e.g. SSRF via X-Forwarded-Host). The Repeater should preserve operator-defined
  headers through the proxy, or offer a "direct (no proxy)" mode for header injection tests.

## New detection rules from KMSAT pentest (2026-10-28)

- [ ] **MFA bypass param fuzzer agent** — for every login endpoint detected (path contains
  login, sign_in, authenticate), test with extra params that might bypass MFA: mfa_forced,
  skip_mfa, bypass_2fa, otp_bypass, mfa_skip, no_mfa, force_login. Compare responses:
  if the response changes from MFA challenge (routeTo MFA route) to direct session
  (redirectTo + Set-Cookie) when the param is added, confirmed MFA bypass. Deterministic.
- [ ] **OAuth state validation checker** — enhance the existing `oauth_flow_analyzer` plugin
  to detect OAuth callbacks that don't validate the state parameter. Pattern: callback URL
  with ?code= parameter that returns a success response regardless of state value. Test by
  replaying the callback with a different/missing state and comparing responses.
- [ ] **GraphQL sensitive field exposure scanner** — for each GraphQL type with fields like
  otpSecretKey, otpCode, encryptedPassword, resetPasswordToken, etc., test if field-level
  authorization is properly enforced by querying other users' records. Needs multi-session
  (see GraphQL IDOR backlog).
- [ ] **GraphQL cursor injection scanner** — test pagination cursors (after/before) with
  arbitrary sort_field values (e.g. encrypted_password, otp_secret_key) and check if the
  cursor text field leaks column values. Deterministic: if cursor.text contains a value
  that looks like a hash/token/email when sorting by a sensitive column, confirmed leak.

## Copilot auth/cookie backlog (2026-10-28)

- [x] **Copilot should check proxy cookie jar before requesting auth** — fixed: auth gate
  now checks jar via _jar_has_cookies_for() and auto-injects cookies before pausing.
- [x] **send_request Set-Cookie persistence** — fixed: Set-Cookie values from responses are
  now written synchronously to the proxy jar via _ingest_cookies.
- [x] **Copilot full login flow** — solved via `browser_login` tool + CSRF auto-injection.
  `browser_login` handles multi-step SPA login (email→Continue→password→submit), exports
  cookies (including CSRF-TOKEN) to `_session_cookies`. `send_request` auto-injects
  `X-CSRF-Token` and `X-Requested-With: XMLHttpRequest` headers from session cookies.
  Validated live: copilot logged in to KMSAT and queried GraphQL autonomously.
- [x] **Copilot auth resume with jar cookies still gets 403** — resolved by the CSRF
  auto-injection fix. The 403 was caused by missing X-CSRF-Token header, not stale cookies.
  KMSAT does NOT rotate session cookies (confirmed via code review: Redis session store with
  stable session ID). The real issue was CSRF token mismatch.
