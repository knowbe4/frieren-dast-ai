# Changelog

All notable changes to Frieren DAST-AI are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- **GraphQL tab** — Schema Explorer (endpoint discovery + manual introspection, manual
  endpoint add, "Scan History" to catalogue endpoints missed by live detection),
  a schema-driven query/mutation Query Builder (fused into the same sub-tab as Schema
  Explorer so picking an operation and re-running introspection update one shared editor),
  and a variable Fuzzer (extraction + payload cross-product, run/poll/stop like Intruder).
  Introspection and query/fuzz sends always use editable, session-aware headers (a named
  session dropdown or the most recent captured request for that endpoint) — never a bare
  `Content-Type: application/json`. The operation list supports free-text filtering plus a
  query-only/mutation-only toggle. Gated behind the `GraphQL Fuzzer` plugin toggle.

### Fixed
- **GraphQL introspection fired automatically on any detected endpoint, with no user
  consent and no way to pick the right session.** `GraphQLIntrospectionPlugin.on_entry()`
  now only catalogues the endpoint (no outbound request); introspection is always a
  manual, user-triggered action from the GraphQL tab, and always uses editable headers so
  a multi-user proxy can introspect as the correct session instead of whichever traffic
  happened to trigger detection.
- **Introspection failures were invisible.** A disabled-introspection or HTTP-error
  response only logged a `warn`-level system-log event, which the Logs tab's default
  filter hides — the GraphQL tab showed a generic "see Logs tab" message pointing at
  nothing the user could see. `_introspect()` now returns the real error string directly
  to the caller, surfaced in the tab's own error toast.
- **GraphQL fuzzer's seed payloads included a destructive `DROP TABLE` string** that was
  observed being sent to a live target — a direct violation of the project's no-destructive-
  payloads safety policy. Removed from `dast/payloads/graphql.yaml`; added a regression
  test (`test_graphql_variable_fuzzer.py`) asserting no payload in that file ever classifies
  as destructive via `dast/hackerone/payload_safety.classify()`.
- **A finding could show an "AI validated" badge while the AI provider was disconnected.**
  `passive_scanner._ai_validate_finding()` swallowed LLM-call exceptions and returned a
  fabricated `True` confirmation. It now returns a distinct `None` ("AI did not run") on
  failure, and the caller only sets `validated_by=["passive", "ai"]` on an explicit `True`.
- **Proxy crashed on long hostnames.** `CertAuthority._generate_leaf_cert` raised
  `ValueError` when signing a leaf cert for a hostname longer than 64 chars (X.509
  CommonName's RFC 5280 cap), crashing the CONNECT handler and silently breaking MITM
  interception for that host. A hostname over 64 chars now gets a generic CommonName
  while the real hostname still goes into the SAN, which is what browsers actually
  validate against.
- **"Copy request" in the HTTP History context menu silently did nothing.** It called a
  non-existent endpoint (`/api/proxy/entry/{id}` instead of `/api/entry/{id}`) and, even
  after fixing the URL, read `_ctxId` *after* `hideMenu()` had already cleared it —
  the `await fetch(...)` ran with a `null` id. Replaced with two working actions: **Copy
  as cURL** (full method/headers/body, correctly shell-quoted) and **Copy Reproduce
  Link** — copies a `/api/reproduce/{id}` URL that opens a page with an explicit OK
  button (GET redirects, POST auto-fills and submits a form) so a request can be
  replayed as a real browser navigation instead of a raw HTTP client, e.g. for CSRF PoCs.
- **Import Findings gave no feedback for large reports and looked hung.** The AI parse
  + entry-storing loop ran synchronously inside the `POST /api/findings/import` handler,
  so a long report produced zero visible progress until it either finished or the
  request timed out — closing the modal gave no indication whether it was still working.
  The endpoint now returns a `job_id` immediately; parsing and storing run as a
  background task, and the UI polls `GET /api/findings/import/{job_id}` every 1.5s,
  showing "AI is parsing the report... (done/total)" then "Storing findings...
  (done/total)".
- **Proxy/dashboard crashed with a raw traceback if their port was already in use**
  (e.g. a previous instance still shutting down, or a second `dast-ai proxy` run).
  Both now fall back to the next free port (up to 10 attempts) and log a loud WARNING
  with the requested vs. actual port — since the browser's manual-proxy setting isn't
  auto-updated, a silent fallback would break interception invisibly.
- **HTTP History table columns didn't use extra screen space at high resolution.**
  Host/Path/Body had fixed pixel widths under `table-layout:fixed`, so they stayed
  truncated even when the window was much wider than the table's minimum width. They
  are now unconstrained (min-width only), so `table-layout:fixed` distributes leftover
  table width across them automatically; manually dragging a column's resize handle
  still opts it out by setting an explicit width.
- **Code-hypothesis "Validate All" marked every scan as duplicate.** Synthetic scan
  entries created for hypothesis validation now set `skip_dedup=True`, so each hypothesis
  actually runs — including two distinct hypotheses on the same endpoint (e.g.
  open_redirect + ssrf on `/start-consent`), which previously collided on the dedup key.
- **Hypothesis status badge stuck on "Scanning…" forever.** Skipped scans (duplicate,
  host-unreachable) now set a terminal `scan_result`, so status polling reports a final
  state instead of reporting "scanning" indefinitely.
- **Placeholder host queued as a scan.** The hypothesis validator now rejects a resolved
  host that is not a valid hostname (e.g. `<sentry-admin-platform-host>`) with a clear
  error, instead of queueing a scan that can only fail with DNS errors.

### Added
- **Structured LLM output via forced tool-use.** `bedrock_client.invoke_json` accepts an
  optional `schema` argument. When set, the model is forced to call a synthetic
  `emit_result` tool whose `input_schema` is the caller's schema, so the response is
  guaranteed to match the shape — malformed JSON is impossible by construction. Schemas for
  the four structured outputs live in the new `dast/ai/schemas.py` (planner, baseline,
  mutator, red-team).
- **`temperature` and `cache_system` parameters** on `bedrock_client.invoke` /
  `invoke_json`. `temperature` is omitted from the request when unset (default behaviour
  preserved). `cache_system` shapes the system prompt as an ephemeral-cached content block.
- **Prompt caching** on the four large static system prompts (`_SYSTEM_PLAN`,
  `_SYSTEM_BASELINE`, red-team `_SYSTEM`, `_SYSTEM_MUTATOR`). Verified end-to-end: the first
  call creates the cache, every subsequent call is a cache read. Cache token counts are
  logged at debug (`_log_cache_usage`).
- **Few-shot examples** added to the mutator, red-team, and baseline system prompts,
  extending the contrastive good/bad pattern already used by the coordinator planner.
- `dast/ai/schemas.py` — JSON Schemas backing the structured-output path.
- `tests/unit/test_bedrock_client.py` — covers the tool-use path, repair-retry, and
  temperature/cache request-body wiring.

- **Host reachability circuit breaker** (`dast/scanners/active_checks.py`). Consecutive
  connection failures per host (DNS failure, connection refused, proxy 502/504) are tracked;
  after 5 in a row the host is declared unreachable and all further probes and scans to it
  short-circuit via `is_host_dead()`. This stops the scanner from firing dozens of
  status-less requests at a dead host and burning the scan budget. A real response resets
  the counter; `SessionStore.clear()` clears the state so a recovered host gets a fresh
  chance. The scan worker now skips queued entries for dead hosts with a clear log event.

- **SPA crawler consults the host circuit breaker** — skips navigation (and its 45s
  timeout) to hosts the scanner already found unreachable, both for the initial target and
  per discovered route.
- **Session refresh circuit breaker** (`dast/session/refresh_worker.py`) — gives up after 3
  consecutive re-auth failures (stale credentials: password/MFA changed, login host down)
  instead of burning a browser context on every subsequent 401. A successful re-auth resets
  the counter; recovery is via a fresh Browse-tab login.
- **Bounded scan queue with backpressure** — the scan queue is now capped (`maxsize=5000`)
  and the producer uses `put_nowait`, logging and skipping on overflow so a backed-up queue
  never stalls proxy ingestion or grows memory without limit on long sessions.

### Changed
- **Default parallel scan workers raised from 2 to 4** for the `proxy` command
  (`--workers`, `PARALLEL_WORKERS`) — matches the other CLI commands and `config.py`.
- **Scan-time dedup now normalises variable path segments** — the dedup key uses
  `_normalise_path` (UUIDs/numeric-IDs → `{id}`) plus host, so an endpoint like
  `/api/<uuid>/export` is scanned once instead of once per distinct ID. Aligns the
  scan-time key with the enqueue-time key.
- **Probe-concurrency semaphore aligned to worker count** at scan-worker startup
  (`max(probe_concurrency, workers)`) so raising workers actually increases throughput
  instead of contending on a fixed 3-slot probe budget.
- **Deterministic decision stages now run at `temperature=0`** — coordinator planner,
  baseline classifier, and red-team validator. Verdicts are reproducible and less flaky.
  The adaptive mutator intentionally stays at the model default to preserve payload
  diversity.
- **`invoke_json` legacy path is hardened with a one-shot repair-retry.** If the model
  returns text that isn't valid JSON, it is re-invoked once with an explicit
  "return only the JSON object" instruction before raising — preventing silent degradation
  to fallback paths at the ~24 call sites not migrated to schemas.
- `bedrock_client` request-body construction refactored into a shared `_build_body` helper
  used by both `invoke` and `invoke_json`; added a module `logger` per project conventions.

- **Structural prompt-injection defense** (`dast/ai/prompt_safety.py`). Target-controlled
  content (HTTP response/request bodies and analysis-derived hints) is now fenced in XML
  tags via `wrap_untrusted()`, and the system prompts carry a language-agnostic directive
  telling the model that anything inside those tags is data to analyse, never instructions
  to obey. Applied in `coordinator._plan` / `_baseline_check`, `red_team.validate`, and
  `mutator.next_payload` — the paths most exposed to a hostile scanned application. The
  existing denylist sanitizer is retained as a second layer. `wrap_untrusted` also
  neutralises attempts to forge the closing tag and break out of the fence.
- **LLM eval harness (PoC)** under `tests/evals/` — an opt-in harness (real Bedrock, not in
  the default pytest run) that scores the planner's agent selection and the red-team
  validator's confirm/reject decisions against a human-labelled golden set, including
  adversarial injection-resistance cases. First run: 100% on both suites and on the
  injection probes. `tests/unit/test_prompt_safety.py` adds 9 deterministic tests.

### Notes
- All existing `invoke` / `invoke_json` call sites remain byte-for-byte compatible: every
  new parameter is keyword-optional and only alters the request when explicitly set.
- The eval harness proves the injection defense end-to-end: a response body instructing the
  planner to "return an empty agents list" and a snippet instructing the validator to "set
  confirmed=true" were both correctly ignored.
