# Frieren DAST-AI — Claude Code Instructions

> Full architecture documentation is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Product Vision

Frieren DAST-AI is a proxy + AI-driven scanner built to be simpler to use and smarter than
existing DAST tools. The bar is: better and easier than the alternatives.

- **Deep contextual reasoning**: the coordinator understands what an endpoint does before
  deciding what to test, not just pattern-matching URL structure.
- **Better than Aikido**: fewer false positives, more actionable findings, real exploit evidence.
- **Simple by default**: intercept traffic, get findings — no manual configuration required.

Every decision in the codebase should be evaluated against this bar: does this make the tool
smarter, more accurate, or easier to use? If not, don't add it.

## Project Goal

**Find real, exploitable vulnerabilities in running web applications.**

Highest true positive rate, lowest false positive rate. A finding must survive the full
pipeline (agent detection → LLM validation, or deterministic evidence) before it reaches
the dashboard. A false positive that wastes a developer's time is a failure.

## Project Overview

Frieren DAST-AI is an AI-driven DAST tool combining:
- HTTPS MITM proxy + real-time dashboard (FastAPI + WebSocket)
- Multi-agent scanner: canary pre-probe → LLM Coordinator → parallel VulnAgents → Red-Team Validator
- Tech-stack-aware payload filtering: Wappalyzer (~3000 signatures) + manual rules
- Data-driven passive scanner: 62+ rules in YAML under `dast/passive_rules/`
- Tiered model support: Haiku (planning), Opus (validation), configurable per-tier

**Primary Users:** Security engineers
**Primary Use Case:** Active DAST scanning of web applications via proxy interception

---

## Important Conventions

### Code Style
1. **All code, comments, and docs in English** — no Portuguese
2. **No emojis** in code or documentation
3. **Type hints** on all function signatures
4. **Descriptive variable names** — no abbreviations
5. **Error handling** — log and continue; never crash the scan on one endpoint
6. **Modularity first** — keep modules small and single-responsibility. Never add a feature
   to an existing module when it fits better in a new one. Complexity should stay local;
   cross-module coupling should be explicit and minimal.
7. **Understand before acting** — agents, plugins, and LLM prompts must read and interpret
   the actual request/response context before testing anything. Never assume a vulnerability
   category from the URL path alone; use params, body, headers, and response content as
   evidence. A tool that spams payloads without understanding the endpoint is noise, not signal.
8. **Logging required everywhere** — every module must have `logger = get_logger(__name__)`.
   Log at the appropriate level:
   - `logger.debug` — probe attempts, payload choices, iteration steps (high volume, off by default)
   - `logger.info` — agent start/done, scan start/result, session load/save, findings recorded
   - `logger.warning` — recoverable errors, LLM call failures, unexpected responses, FP filter hits
   - `logger.error` — unrecoverable errors, exceptions that abort an operation
   Never swallow exceptions silently (`except Exception: pass`) — always log them with `error=str(exc)`.

### Package Manager
**ALWAYS use uv:**
```bash
uv run dast-ai proxy          # start proxy + dashboard
uv run pytest
```
Never use `python3` directly. Never activate venv manually.

### Agent Development
- Add a new file in `dast/agents/` inheriting from `VulnAgent`
- Call `get_filtered_payloads(attack_type, target)` from `dast/agents/payload_filter.py` instead of `get_payloads()` directly
- Load extra payloads from YAML in `dast/payloads/` via `loader.py`
- Call `Coordinator.register(YourAgent)` at the bottom of the module
- Import the module in `dast/agents/__init__.py`
- Safety policy: no destructive payloads; SLEEP/WAITFOR max 5s; detection only
- Auth agent: use `urlparse(target.url).path` for path-based bypass headers, not hardcoded paths

### Payload Development
- Add or edit `dast/payloads/*.yaml` — no code changes needed
- Use `get_payloads(category, group)`, `get_all_payloads(category)`,
  `get_detection_payloads(category)` from `dast/payloads/loader.py`
- Document intent with comments in the YAML

### Passive Scanner Rule Development
- Add a `.yaml` file anywhere under `dast/passive_rules/` — it is auto-discovered at startup
- Follow the rule schema in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- `one_per_host: true` in conditions prevents noisy per-request repetition
- `needs_ai_validation: true` routes the finding through the LLM before storing it
- Run `uv run python -c "from dast.plugins.passive_scanner import _load_all_rules; print(len(_load_all_rules()), 'rules')"` to verify

### Content Discovery (forced browsing)
- `dast/wordlists/*.txt` — plain-text wordlists (one entry per line, `#`-comments
  ignored), SecLists-derived (MIT, see each file header). `directories.txt` (~100),
  `files.txt` (~100), `graphql.txt` (endpoint paths). Add a list by dropping a
  `<name>.txt` — load it with `load_wordlist("<name>")` from `dast/wordlists/loader.py`.
  This is a NET-NEW asset type, intentionally separate from `dast/payloads/loader.py`
  (that one is YAML-only, grouped payload categories).
- `dast/scanners/content_discovery.py` — `run_content_discovery()` actively GET-probes the
  wordlist paths against a host to surface unlinked endpoints. Detection-only recon, no
  payloads. Reuses `active_checks._client()/_send()` (proxy-routed, rate-limited,
  circuit-broken) and gates EVERY candidate URL through `ProxySettings.is_in_scope()`
  BEFORE probing — the hard safety guarantee (the standalone crawlers lack it). Soft-404
  filtered via an up-front baseline probe.
- Driven by `ProxyRunner._discovery_worker` (runner.py, alongside `_crawl_worker`) off a
  `discovery_queue`; the `POST /api/discovery` route (browser_routes.py) re-checks scope
  and rejects out-of-scope URLs with 400. Hits become synthetic `source="discovery"`
  sitemap entries + `source="content-discovery"` AI suggestions (patterns reused from
  `ai_routes.py` / `app_context.py`).
- Classification: dir/file hits are neutral `recon` suggestions (never infer a vuln from a
  path alone); GraphQL hits get `graphql_injection`. Opt-in LLM refinement via the
  `discovery_llm_classify` scan-config flag (default OFF; one `invoke_json` per hit through
  the fast tier, degrades to `recon` on any failure).
- UI: the "Discovery" top-level tab (formerly "Browse") → "Content Discovery" sub-tab
  (alongside "Manual Browse" and "Crawl"). Reuses the `/ws/crawl` log stream.
- Verify: `uv run python -c "from dast.wordlists.loader import load_wordlist, known_wordlists; print(known_wordlists(), [len(load_wordlist(n)) for n in known_wordlists()])"`

### Param Mining (hidden-parameter discovery)
- `dast/scanners/param_miner.py` — `run_param_mining()` brute-forces unlinked parameter
  NAMES against ONE in-scope request (query/form/JSON body auto-detected from method +
  content-type). This is the parameter-side companion to `content_discovery.py` (which
  brute-forces unlinked PATHS); a discovered hidden param is fresh attack surface every
  vuln agent then gets to test. Wordlist: `dast/wordlists/params.txt` (SecLists
  `burp-parameter-names`, MIT). Detection-only — injects an inert canary, never a payload.
- Two detection signals, lowest-FP first: (1) reflection — each candidate in a batch gets
  its OWN unique canary (`dastpm7c1e<i>`), so one request reveals exactly which names echo;
  (2) behavior-change — a batch that shifts status/length is binary-searched to the single
  name, then RE-CONFIRMED in isolation. The anti-FP guard: TWO baselines are sent up front;
  if body length is unstable, length-based detection is disabled (status-only) so dynamic
  pages never yield hits. `_BATCH_SIZE=25`, `_LENGTH_NOISE_BYTES=32`.
- Reuses `active_checks._client()/_send()` (proxy-routed, rate-limited, circuit-broken) and
  gates EVERY built URL through `ProxySettings.is_in_scope()` BEFORE probing — the hard
  safety guarantee (matches content_discovery). Existing params on the request are excluded
  from the candidate list. `run_param_mining(..., client=)` reuses a passed-in proxy-routed
  client (never closes it), mirroring `probe_diff.run_probe_pairs` — this is how the
  coordinator shares its client.
- Param mining is AUTOMATIC, not a manual action (there is NO Param Mining UI tab). It runs
  as part of a scan on two paths, per the "AI Disabled By Default" three-layer model:
  - **Deterministic layer (AI off):** when the user explicitly sends an endpoint to Scan
    with AI mode OFF, `ProxyRunner._attack_one` runs `_mine_params_for_entry` — no LLM, no
    agents, inert canary probes only. This is the normal scan without agents. Hits become
    `source="param-discovery"` neutral `recon` AI suggestions carrying the param name (no
    vuln inferred from a name alone) via `_record_param_hit` (reuses the suggestion shape
    from `_record_discovery_hit`).
  - **AI layer (AI on):** the LLM planner decides per-endpoint via the `mine_params` field
    in `PLANNER_SCHEMA`. When true, `Coordinator._run_param_mining_pass` mines (reusing the
    coordinator's client) and folds discovered names directly onto `target.params` (location
    mapped query/form/json → query/body) so the just-selected agents test them immediately,
    plus sets `target.param_mining_hint` (surfaced to the mutator via
    `build_mutator_context`). Fully defensive — a miner failure leaves `target.params` intact.
- Verify: `uv run pytest tests/unit/test_param_miner.py tests/unit/test_coordinator_param_mining.py`;
  `uv run python -c "from dast.wordlists.loader import load_wordlist; print(len(load_wordlist('params')))"`

### Probe-Diffing (AI-native "Backslash Powered")
- `dast/agents/probe_diff.py` — a PURE PRIMITIVE, not a per-vuln agent. `run_probe_pairs()`
  injects break/repair input PAIRS into ONE parameter and diffs the two responses:
  `dast'` vs `dast\'` (string_quote), `dast"` vs `dast\"` (double_quote), `dast\` vs
  `dast\\` (backslash), `dast${{7*7}}` vs `dast${{7*'7}}` (template_expr), `dast{{7*7}}`
  vs `dast{{7*'7}}` (brace_expr). A break-vs-repair divergence isolates the parameter's
  syntactic context far more reliably than a single payload. All probes are
  non-destructive by construction (a quote/backslash/arith expr — nothing reads a file,
  sleeps, or goes out of band). Returns a `DiffSignature` (`has_signal`,
  `divergent_labels`, `to_classifier_summary()`); the diff engine compares status,
  length (`>=32` noise floor, mirrors param_miner), HTML structure hash, interpreter
  error signature, arithmetic-eval marker (`49`), and reflection. Gates EVERY built URL
  through `ProxySettings.is_in_scope()` BEFORE sending — same hard guarantee as
  content_discovery/param_miner. Reuses `active_checks._client()/_send()/_inject_query()/
  _inject_body()`; accepts a `client=` so the coordinator's proxy-routed client is reused
  (never closes a passed-in client).
- `dast/ai/probe_classifier.py` — `classify(signature)` turns a DiffSignature into a
  `ProbeVerdict` (injection_class, context, confidence, recommended_agents, reasoning).
  Short-circuits with NO LLM call when there is no signal; fences the summary via
  `wrap_untrusted(summary, 'probe_signature')`; degrades to an inert `_UNKNOWN` verdict on
  any exception or bad output. Schema: `PROBE_CLASSIFIER_SCHEMA` in `dast/ai/schemas.py`.
  Probe (find) and classification (decide) are kept separate, mirroring content_discovery
  vs coordinator.
- Wiring: `Coordinator.run(..., probe_diff=False)` → `_run_probe_diff_pass()` probes each
  injectable param (query/body/body_graphql, excludes auth-token params), folds
  `recommended_agents` into the signal_map and sets `target.probe_diff_hint`, which
  `mutator.build_mutator_context()` appends to the mutator context. Opt-in, default OFF:
  `run_active_checks(probe_diff=...)` ← `runner._engine_config["probe_diff"]` ←
  `POST /api/scan-config` (`probe_diff` flag in settings_routes) ← the `sc-probe-diff` UI
  checkbox (85-overview-scanconfig-provider.js). Degrades gracefully everywhere — a
  no-signal or LLM failure just leaves agent dispatch unchanged.
- Verify: `uv run pytest tests/unit/test_probe_diff.py tests/unit/test_probe_classifier.py`

### Cache Poisoning (unkeyed-input detection)
- `dast/agents/cache_poisoning_agent.py` — `CachePoisoningAgent` (attack_type
  `cache_poisoning`). Detects web cache poisoning via UNKEYED request headers
  (`X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Host`, `Forwarded`, ...) reflected into a
  cacheable response. GET-only; bails fast if the baseline response is non-cacheable
  (`Cache-Control: no-store/private` and no cache-indicator header). Two-request proof,
  lowest-FP: (1) send the header with a UNIQUE marker; if it reflects (body OR a
  redirect/link header) the input is reflected; (2) re-request the SAME url WITHOUT the
  header — if the marker survives, it was served from cache → the input is unkeyed →
  CONFIRMED (`bypass_validation=True`, high). Reflected-but-not-cached degrades to an
  unconfirmed medium that the LLM validator adjudicates.
- SAFETY: every probe appends a UNIQUE random cache-buster query param
  (`_cache_buster_url`), so both requests map to a key only WE request — we never poison
  the real shared page other users are served. Blast radius is our own synthetic URL.
  Reuses `active_checks._send()/_inject_query()` (proxy-routed, scope-gated,
  circuit-broken). Payloads/config in `dast/payloads/cache_poisoning.yaml` (`unkeyed_headers`,
  `blind_headers`, `cache_indicator_headers`, `non_cacheable_signals`).
- Wiring: `Coordinator._select_attack_types_for_params()` adds `cache_poisoning` as a
  candidate for every GET (no-canary type — the LLM planner decides, the agent
  self-gates on cacheability). Registered via `Coordinator.register()`, imported in
  `dast/agents/__init__.py`.
- Verify: `uv run pytest tests/unit/test_cache_poisoning_agent.py`

### Manual Toolbelt (Decoder/Encoder + JWT editor)
- Two sub-tabs under the "Extras" tab (alongside H1 Validator / Code / FedRAMP /
  Interactions), wired via `switchExtrasSub('decoder'|'jwt')` in
  `dast/proxy/ui/js/75-subtabs-ai-panel.js`. Both live in
  `dast/proxy/ui/js/76-extras-decoder-jwt.js` (script tag after the 75 module).
- **Decoder/Encoder** — CLIENT-SIDE ONLY, no backend, no request ever leaves the page.
  base64 / base64url / URL (incl. encode-all) / HTML / hex encode-decode + JWT decode
  (header+payload pretty-print). Ops are a pure `_DECODER_OPS` list (`{id,label,fn}`);
  add a transform by appending one entry. Live-transforms on input; errors render inline
  in red, never throw.
- **JWT editor** — decode a pasted token, edit header/payload JSON, re-sign, send to
  Repeater as `Authorization: Bearer`. Signing modes HS256/384/512 (HMAC secret) and
  `alg:none` (unsigned — signature-strip attack). The ONE backend touchpoint is
  `POST /api/jwt/build` (`dast/proxy/api/jwt_routes.py`, registered in
  `dashboard_server.py`), which reuses `jwt_tester._build_token()` so encoding stays
  identical to the automated JWT agent. The route FORCES `header["alg"]` from the chosen
  mode (operator's stray header alg never wins) and rejects unsupported modes with 400.
- Verify: `uv run pytest tests/unit/test_jwt_routes.py`

### Scope Presets (per organization)
- Drop a `<slug>.json` under `dast/scope_presets/` (gitignored, see `example.json.example`
  for the schema) — auto-discovered at startup and written to `~/.dast-ai/projects/<slug>.json`
  on first run if absent. No code changes and nothing organization-specific committed.
- Users can also create/edit scope rules directly from the Proxy > Settings sub-tab without a preset file.

### GraphQL Query Builder / Fuzzer
- `dast/plugins/graphql_introspection.py` stores an *extended* compact schema per
  endpoint in `store.graphql_schemas[endpoint]`: `mutations`/`queries` (args with
  `type` + `wrapper` — NON_NULL/LIST collapsed into one label — and `return_type`),
  `input_types`, `object_types` (OBJECT/INTERFACE, for selection-set recursion),
  `union_types`, `enum_types`. This is a superset of what the findings importer reads
  (`args`/`input_types[x]["fields"]`) — safe to extend further, never remove keys.
  `_introspect(endpoint, headers, store, plugin_name)` is a module-level function (not
  a method) — it is called ONLY from the manual `POST /api/graphql/introspect` route,
  never automatically. `GraphQLIntrospectionPlugin.on_entry()` only catalogues endpoints
  it sees on the wire (`store.graphql_schemas[endpoint] = {"introspected": False}`ish
  via `catalogue_endpoint()`); it never sends an outbound introspection request itself,
  regardless of AI-mode state. `POST /api/graphql/rescan-history` catalogues endpoints
  from already-captured history the same way, for traffic seen before the plugin was
  loaded to observe it live. Both `_introspect()` and `POST /api/graphql/introspect`
  return the failure reason directly (not just a generic "see Logs tab" pointer) since
  the Logs tab's default filter hides the `warn`-level events these failures log.
- `dast/graphql/query_builder.py` — pure functions (`build_argument_value`,
  `build_selection_set`, `build_operation`) operating only on the schema dict above, no
  I/O. Recursion caps: `MAX_INPUT_DEPTH=3` (with self-reference cycle detection),
  `MAX_SELECTION_DEPTH=2`, `MAX_FIELDS_PER_LEVEL=15`. Always emits variable-based
  queries (`$var0: Type!`), never inline literals.
- `dast/graphql/variable_fuzzer.py` — extracts variables from a captured request's
  JSON `variables` object (inline query-literal argument extraction is explicitly
  NOT implemented — documented follow-up, not a gap to silently fill), cross-products
  against a payload list one variable at a time (others held at original value, same
  single-injection-point model as Repeater/Intruder), records status/length/GraphQL
  `errors`-present per attempt. No vulnerability classification here — that's
  `dast/plugins/graphql_analyzer.py`'s job on every proxied response, independent of
  this user-triggered fuzzer.
- The GraphQL tab is enabled/disabled via the `GraphQL Fuzzer` plugin (no-op
  lifecycle, pure UI toggle) — see "Plugin-gated tab pattern" above.

### Mutation Loop
- The LLM mutator decides when to stop (`action: "stop"`) — do not add fixed iteration limits
- Safety ceiling: 15 rounds per parameter (protects against bugs, not normal use)
- Always pass `tried_payloads` to `next_payload()` so the LLM avoids repeats
- Build the mutator's `tech_context` via `mutator.build_mutator_context(target, attack_type)`
  — it merges the discovery summary with the per-host WAF memory (see WAF Bypass below)

### WAF Bypass
- `dast/agents/block_detector.py` — central `detect_block(status, body, baseline_len)`
  returns a `BlockVerdict`. Recognises a block from status codes AND from block-page
  content signatures EVEN on HTTP 200 (a WAF hiding behind 200 used to be missed, so the
  mutator gave up instead of attempting a bypass). Agents call it before the mutator and
  feed `verdict.signal` into `self.observe("waf_block", ...)`.
- Per-host bypass memory (Gap 2): when a payload succeeds after an earlier block, the agent
  emits `self.observe("waf_bypass", payload=...)`; the coordinator records it via
  `session_intelligence.record_scan_complete(bypass_payload=...)`. `HostIntel.to_mutator_hint()`
  then offers that proven payload to the mutator FIRST on later endpoints of the same host.
- All six mutator-using agents are wired to the central detector + per-host memory:
  `sqli_agent`, `xss_agent`, `file_read_agent`, `ssrf_agent`, `discovery_agent` (SSTI),
  `llm_injection_agent`. Each builds `tech_context` via `build_mutator_context()`, records
  blocks with `detect_block()` → `observe("waf_block")`, and emits `observe("waf_bypass")`
  when a payload succeeds after a prior block.

### Host Reachability Circuit Breaker
- `dast/scanners/active_checks.py` tracks consecutive connection failures per host
  (DNS failure, connection refused, proxy 502/504) via `_HOST_FAILURE_STATE`
- After `_HOST_DEAD_THRESHOLD` (5) consecutive failures the host is marked dead; all
  further probes and scans to it short-circuit (`is_host_dead()`), so a dead host never
  floods the history with status-less requests
- A single real response resets the counter; `reset_host_reachability()` clears all state
  and is called on `SessionStore.clear()` (network may have changed)
- The scan worker skips queued entries for dead hosts with a "Host unreachable" log event
- The SPA crawler also consults `is_host_dead()` before navigating (skips the 45s timeout)

### Scan Reliability Guards
- Scan-time dedup key is `(method, host, _normalise_path(path), operation)` — path
  normalisation collapses UUIDs/numeric-IDs (`/users/{id}`), matching the enqueue-time
  dedup so an endpoint isn't re-scanned once per distinct ID
- Scan queue is bounded (`maxsize=5000`); the producer uses `put_nowait` and logs+skips on
  `QueueFull` so a backed-up queue never stalls proxy ingestion
- Probe-concurrency semaphore (`_PROBE_SEM`) is aligned to `max(probe_concurrency, workers)`
  at scan-worker startup — more workers with a tiny probe budget yields little throughput
- Session refresh worker gives up after `_MAX_REAUTH_FAILURES` (3) consecutive failures
  (stale credentials); a success resets the counter — recover via a fresh Browse-tab login

### Service Graph
- `ServiceGraph` lives on `SessionStore` — access via `store.service_graph`
- `SessionStore.complete_entry()` calls `service_graph.observe()` automatically
- Layer 2: `CheckTarget` has optional `service_context` field — agents read it, never mutate it
- Manual merge/split via `/api/service-graph/merge` and `/api/service-graph/split`

### App Context + Threat Model
- Both workers start with the proxy and run as background coroutines in `asyncio.gather`
- AppContextWorker: synthesises `AppProfile` per host — app type, auth model, resource types, vuln hypotheses
  - First analysis: 15 entries; re-analysis: every 30 new entries
  - Output injected into Coordinator planner prompt via `CheckTarget.app_profile_hint`
- ThreatModelWorker: synthesises `ThreatModel` per host — architectural constraints, security invariants
  - First analysis: 15 entries; re-analysis: every 50 new entries (invariants change slowly)
  - Output injected into red_team.validate() via `CheckTarget.threat_model_hint`
- Both exposed via `store.discovery_engine.get_app_profile(host)` / `get_threat_model(host)`
- API endpoints: `GET /api/ai/app-context` and `GET /api/ai/threat-models`

### Red-Team Validator
- `dast/ai/red_team.py` — runs after agents, before findings reach the dashboard
- Stage 1: `fp_filter.check()` — deterministic rules, no LLM (9 rules in `dast/ai/fp_filter.py`)
- Stage 2: `_pattern_confidence()` — estimates confidence from evidence strength per attack type
- Stage 3: LLM asks for exploit scenario + reasoning; returns `confirmed`, `confidence`, `reasoning`
- Multi-source aggregation: `final_confidence = max(pattern_conf, browser_conf, llm_confidence)`
- Confirmed only if `llm_confirmed AND final_confidence >= confidence_threshold`
- On LLM failure: falls back to pattern confidence alone
- `confidence_threshold` configurable at runtime via AI tab slider; default 0.5
- Stage 3 prompt is enriched with attack-type-scoped few-shot examples from the
  Vulnerability Knowledge Base (see below) — positive + negative exemplars

### Vulnerability Knowledge Base
- `dast/vuln_knowledge/` — one YAML per attack_type with `positive_examples`
  (1-3 real vulns) and `negative_examples` (1-2 look-alikes that are NOT vulns),
  each with a one-line `reasoning`. Covers the top-20 web vulns.
- Auto-discovered recursively (like passive rules); `loader.py` indexes by
  `attack_type` and `aliases` (e.g. `path_traversal`→`lfi`, `llm_prompt_leak`→`llm_injection`)
- Two consumers, both degrade gracefully to no-op when a type has no coverage:
  - `red_team.validate()` — injects positive+negative via `format_examples_block()`
    to sharpen the real-vs-look-alike verdict (fewer false positives)
  - `mutator.next_payload()` — injects positive-only via `format_positive_examples()`
    so payload discovery aims at the response signal that proves exploitation
- Examples are our own trusted content — interpolated directly, NOT `wrap_untrusted()`
- Add a vuln class: drop a new `<attack_type>.yaml` — no code changes
- Verify: `uv run python -c "from dast.vuln_knowledge import known_attack_types; print(known_attack_types())"`

### System Logs
- Rolling 500-event buffer in `dast/proxy/plugin_manager._event_log`
- Written by: `log_event(plugin, level, message, url, finding, source)` — call from anywhere
- `source` values: `"plugin"`, `"agent"`, `"browser"`, `"crawler"`
- Visible in Logs tab — 6-column table matching HTTP History layout
- API: `GET /api/logs`, `POST /api/logs/clear`

### AI Calls
- All AI calls go through `dast.ai.bedrock_client` — never call boto3 directly
- `invoke_json()` for structured output, `invoke()` for free text
- Multi-provider: the gateway dispatches to AWS Bedrock (default), the Anthropic
  Messages API, or an OpenAI-compatible endpoint based on the active provider.
  Every request is built Anthropic-shaped and every response is read
  Anthropic-shaped; `dast/ai/providers.py` translates to/from OpenAI so callers
  and the schema-forced tool-use path are provider-agnostic. Select at runtime
  via `bedrock_client.set_provider(provider, keys...)` or `POST /api/scan-config`
  (`ai_provider`, `anthropic_api_key`, `openai_api_key`, `*_base_url`). Configure
  defaults via `.env`: `AI_PROVIDER`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,
  `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`. For non-Bedrock providers `model_id`
  is a plain model name (e.g. `claude-opus-4-8`, `gpt-4o`), not an ARN. API keys
  are never echoed back by `GET /api/scan-config` (only `*_set` booleans).
- Prefer schema-forced output: pass `schema=` (a JSON Schema from `dast/ai/schemas.py`) to
  `invoke_json()` — the model is forced through a tool call, so malformed JSON is impossible.
  Without a schema, `invoke_json()` still parses text and self-repairs once on bad JSON.
- `temperature=0` for deterministic decisions (planner, baseline, red-team); omit for the
  mutator (payload diversity). Pass `cache_system=True` for large static system prompts.
- Always fence untrusted target content with `prompt_safety.wrap_untrusted(content, tag)` and
  append `UNTRUSTED_CONTENT_DIRECTIVE` to the system prompt — structural defense against
  prompt injection. `_sanitize_for_prompt()` (denylist) runs underneath as a second layer.
- Always catch AI exceptions and degrade gracefully

### Dashboard / UI
- Main tabs: Dashboard → Proxy → Discovery → AI → Scan → Plugins → GraphQL → Repeater → Intruder → Logs → Extras
  - Proxy sub-tabs: HTTP history, Intercept, Site map, Issues, Settings (scope rules + Setup/CA cert)
  - Discovery sub-tabs: Manual Browse, Crawl, Content Discovery
  - AI sub-tabs: Suggestions, Settings (provider, model tiers, scan engine, activity log, service graph)
  - Extras sub-tabs: H1 Validator, Code, FedRAMP, Interactions, Decoder, JWT
- HTTP history table supports column resize by dragging the border handle on each `<th>`
- Save notifications (sessions, project settings) show the full file path
- Scan engine settings (model, workers, concurrency, confidence threshold) live in AI tab
- Applied at runtime via `POST /api/scan-config`; `GET /api/scan-config` returns current config
- Overview dashboard auto-refreshes every 10 s; also refreshes on tab switch
- Logs tab: filter by source, level, or text; red row tint for findings
- GraphQL tab: Schema Explorer (endpoint picker + operation list on the left — filterable
  by text and by query/mutation-only — with the schema-driven query/variables editor and
  Send to Repeater/Send to Fuzzer on the right; manual re-introspect and manual endpoint
  add live in the same sidebar), Fuzzer (variable extraction + payload cross-product,
  run/poll/stop like Intruder). Schema Explorer and Query Builder were originally two
  separate sub-tabs; they were fused into one because picking an operation and re-running
  introspection both need to update the same editor pane, and splitting that across a tab
  boundary meant re-navigating and re-clicking the operation after every introspection.
- **Plugin-gated tab pattern**: a top-level tab's visibility can be tied to a plugin's
  enabled state — frontend-only, no backend wiring. `loadPlugins()` calls a
  `_gql`-prefixed visibility helper after fetching `/api/plugins`; called eagerly from
  `ws.onopen` (not just when the Plugins tab is opened) so the tab hides/shows correctly
  from the very first page load. See `_gqlTabVisibility()` for the concrete example if
  adding another plugin-gated tab.

---

## Common Tasks

```bash
# Install dependencies
uv sync

# Install Playwright browsers
uv run playwright install chromium

# Start proxy + dashboard
uv run dast-ai proxy

# Start with auth
uv run dast-ai proxy \
  --auth-url https://app.example.com/login \
  --username admin@example.com \
  --password secret

# Run tests
uv run pytest

# Check passive rule count
uv run python -c "from dast.plugins.passive_scanner import _load_all_rules; print(len(_load_all_rules()), 'rules')"

# Check payload counts
uv run python -c "
from dast.payloads.loader import _load
for f in ['xss','sqli','ssrf','lfi','ssti','llm_injection','cmdi','xxe','jwt','nosql','prototype_pollution','graphql']:
    d = _load(f+'.yaml')
    n = sum(len(v) for v in d.get('payloads',{}).values())
    print(f'{f}: {n} payloads')
"

# Bump the project version everywhere it's hardcoded (pyproject.toml,
# desktop/package.json, CLAUDE.md, docs/ARCHITECTURE.md) in one atomic step —
# never edit these by hand, they drift out of sync silently otherwise.
make bump-version VERSION=0.9.0

# Run the desktop launcher's e2e test (real Electron + real backend)
make desktop-test
```

---

## Key Files

- `dast/proxy/runner.py` — starts proxy + dashboard + scan worker
- `dast/proxy/session_store.py` — all intercepted entries, cookie jar, service graph
- `dast/proxy/dashboard_server.py` — FastAPI app + all API routes + HTML/JS
- `dast/ai/coordinator.py` — LLM coordinator (canary pass + planner + validator dispatch)
- `dast/ai/red_team.py` — Red-Team Validator (FP filter + pattern conf + LLM)
- `dast/ai/fp_filter.py` — deterministic false-positive rules
- `dast/ai/mutator.py` — adaptive payload mutator
- `dast/ai/bedrock_client.py` — single LLM gateway (schema-forced output, temperature, prompt caching, tiered models)
- `dast/ai/schemas.py` — JSON Schemas for structured LLM output (planner, baseline, mutator, red-team)
- `dast/ai/prompt_safety.py` — structural prompt-injection defense (XML fencing of untrusted content)
- `dast/vuln_knowledge/*.yaml` — per-attack-type vuln/not-vuln few-shot examples (consumed by red_team + mutator)
- `tests/evals/` — opt-in LLM decision-quality harness (golden sets + `run_evals.py`); not in default pytest
- `dast/agents/payload_filter.py` — tech-stack-aware payload group selector (central)
- `dast/discovery/fingerprinter.py` — Wappalyzer + manual tech-stack fingerprinting
- `dast/discovery/app_context.py` — AppContextWorker (background AppProfile synthesis)
- `dast/discovery/threat_model.py` — ThreatModelWorker (background per-host constraints)
- `dast/payloads/*.yaml` — seed payloads (edit to add new payloads)
- `dast/wordlists/*.txt` — content-discovery wordlists (SecLists-derived); `loader.py` reads them
- `dast/scanners/content_discovery.py` — forced-browsing scanner (scope-gated, proxy-routed GET recon)
- `dast/scanners/param_miner.py` — hidden-parameter discovery (scope-gated reflection + behavior-change mining)
- `dast/agents/probe_diff.py` — AI-native probe-diffing primitive (break/repair pairs, scope-gated, pure probe+diff)
- `dast/ai/probe_classifier.py` — LLM classifier turning a DiffSignature into an injection-class hypothesis
- `dast/agents/cache_poisoning_agent.py` — web cache-poisoning agent (unkeyed-header reflection, cache-buster-isolated proof)
- `dast/proxy/api/jwt_routes.py` — JWT editor build route (`POST /api/jwt/build`, reuses jwt_tester encoding)
- `dast/proxy/ui/js/76-extras-decoder-jwt.js` — client-side Decoder/Encoder + JWT editor UI (Extras tab)
- `dast/passive_rules/**/*.yaml` — passive scanner rules (add files to add checks)
- `dast/agents/*.py` — vulnerability agents
- `dast/agents/mfa_agent.py` — MFA/OTP bypass agent (rate limit, param removal, backup codes)
- `dast/plugins/passive_scanner.py` — YAML rule engine for passive checks
- `dast/plugins/graphql_analyzer.py` — passive GraphQL security analysis (6 finding types + AI validation)
- `dast/plugins/graphql_introspection.py` — auto-introspection, compact schema storage (wrapper/enum/object/union types)
- `dast/plugins/graphql_fuzzer.py` — no-op plugin, UI toggle for the GraphQL tab
- `dast/graphql/query_builder.py` — schema-driven GraphQL query/mutation generator (type-aware arg heuristics, recursive selection sets)
- `dast/graphql/variable_fuzzer.py` — GraphQL variable extraction + payload cross-product fuzzer
- `dast/payloads/graphql.yaml` — GraphQL variable-fuzzing seed payloads
- `dast/proxy/api/graphql_routes.py` — GraphQL schema lookup, manual introspection, query build, fuzz run/poll/stop
- `dast/session/refresh_worker.py` — automatic session re-auth on 401/redirect-to-login
- `dast/report/sarif.py` — SARIF 2.1.0 export builder

### Session Output
```
~/.dast-ai/sessions/          Session JSON files (path shown in save notification)
~/.dast-ai/projects/          Named proxy settings snapshots
~/.dast-ai/logs/              proxy_YYYYMMDD_HHMMSS.log files for post-mortem debugging
~/.dast-ai/ca.crt             CA certificate (install once in browser/OS trust store)
~/.dast-ai/ca.key             CA private key
```

---

## Environment Variables

```bash
# AI provider — one of: bedrock (default), anthropic, openai
AI_PROVIDER=bedrock

# Required for AI analysis when AI_PROVIDER=bedrock
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_REGION=us-east-1

# Required when AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=
ANTHROPIC_BASE_URL=           # default https://api.anthropic.com

# Required when AI_PROVIDER=openai (base_url also targets any OpenAI-compatible gateway)
OPENAI_API_KEY=
OPENAI_BASE_URL=              # default https://api.openai.com/v1

# Optional
AWS_PROFILE=                  # auto-refreshes on ExpiredTokenException
AI_MODEL_ID=                  # Bedrock: an ARN; anthropic/openai: a model name

# Proxy
PROXY_PORT=8080               # default
DASHBOARD_PORT=8088           # default
PARALLEL_WORKERS=4            # default parallel scan workers (--workers)
```

---

## AWS Bedrock Model ARNs

Application-inference-profile ARNs are account-specific — replace the account ID and profile
ID below with your own. Never use cross-region inference IDs like `us.anthropic.claude-*`.

| Model  | ARN |
|--------|-----|
| Haiku  | `arn:aws:bedrock:us-east-1:YOUR_ACCOUNT_ID:application-inference-profile/YOUR_HAIKU_PROFILE_ID` |
| Opus   | `arn:aws:bedrock:us-east-1:YOUR_ACCOUNT_ID:application-inference-profile/YOUR_OPUS_PROFILE_ID` |
| Sonnet | `arn:aws:bedrock:us-east-1:YOUR_ACCOUNT_ID:application-inference-profile/YOUR_SONNET_PROFILE_ID` |

### Tiered Model Conventions
- `bedrock_client.get_fast_model()` — returns `_fast_model_id` or active model
- `bedrock_client.get_validation_model()` — returns `_validation_model_id` or active model
- `bedrock_client.set_tiered_models(fast, validation)` — set both at once (called by `/api/scan-config`)
- Never call `bedrock_client.invoke()` with a hardcoded model — always use the tier helpers or `model_id` param

---

## Known Issues

### Playwright not installed
```bash
uv run playwright install chromium
```

### CA cert not trusted
Download from `http://127.0.0.1:8088/ca.crt` and install in browser/OS trust store.

### AWS token expiry
Set `AWS_PROFILE` — credentials auto-refresh on `ExpiredTokenException`.

---

**Last Updated:** 2026-08-04
**Version:** 0.8.1
