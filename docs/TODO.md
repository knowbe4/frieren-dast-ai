# Frieren DAST-AI — TODO

## Done (proxy mode, current architecture)

### Infrastructure
- [x] HTTPS MITM proxy (asyncio TCP, per-host CA-signed certs)
- [x] FastAPI dashboard (WebSocket push, all API routes, embedded HTML/JS)
- [x] Session store (in-memory, passive scan on every entry, cookie jar)
- [x] Plugin system (ProxyPlugin ABC, auto-discover, enable/disable at runtime)
- [x] Session persistence (save/load/export JSON, path shown in notification)
- [x] Proxy settings (scope rules, bypass, extension filters, project snapshots)

### LLM reliability & safety (2026-07-15)
- [x] Structured output via forced tool-use (schemas.py) — malformed JSON impossible
- [x] One-shot repair-retry on bad JSON in the legacy invoke_json path
- [x] temperature=0 for deterministic decisions (planner, baseline, red-team)
- [x] Prompt caching on large static system prompts (verified cache reads)
- [x] Few-shot examples in mutator, red-team, and baseline prompts
- [x] Structural prompt-injection defense (prompt_safety.py — XML fencing of untrusted content)
- [x] LLM eval harness PoC (tests/evals/) — planner + red-team, incl. injection-resistance
- See ai-improvements-TODO.md and CHANGELOG.md for detail

### Scanner pipeline
- [x] LLM Coordinator: LLM planner → parallel VulnAgents → Red-Team Validator
- [x] Red-Team Validator: deterministic FP filter → pattern confidence → LLM exploit-proof prompt
- [x] Multi-source confidence aggregation: max(pattern, browser, LLM)
- [x] Configurable confidence threshold (default 0.5), runtime slider in AI tab
- [x] Deterministic FP filter (9 rules, no LLM calls) — fp_filter.py
- [x] Adaptive mutation loop (LLM-controlled stop, 15-round safety ceiling)
- [x] YAML payload library (11 files: xss, sqli, ssrf, lfi, ssti, llm_injection, cmdi, xxe, jwt, nosql, prototype_pollution)

### Vulnerability agents (8)
- [x] xss_agent — reflected/stored + DOM + obfuscation/bypass + Playwright browser confirm
- [x] sqli_agent — error-based + boolean + time-based blind
- [x] ssrf_agent — OOB callback + internal_probe (cloud metadata, file://, sibling hosts)
- [x] file_read_agent — path traversal / LFI / PHP wrappers
- [x] auth_agent — header stripping + 9 bypass combos
- [x] secrets_agent — deterministic credential/token patterns (bypass_validation=True)
- [x] discovery_agent — SSTI, open redirect, CRLF, HTTP method tampering
- [x] llm_injection_agent — prompt injection, jailbreak, system prompt leak
- [x] graphql_agent — GraphQL introspection + injection
- [x] idor_agent — integer ID enumeration + object reference testing

### Discovery layers
- [x] Layer 1: Service Graph — multi-host grouping (JWT, domain, correlation headers, cookies)
- [x] Layer 2: ServiceContext — sibling hosts + shared tokens injected into CheckTarget
- [x] Layer 3: DiscoveryContext — tech stack fingerprint, JS-extracted endpoints, call chains, OpenAPI
- [x] Layer 4: AppContextWorker — background LLM AppProfile synthesis per host
- [x] Layer 5: ThreatModelWorker — background per-host architectural constraints

### Passive scanner
- [x] YAML rule engine (47 rules, 11 files, auto-discovered under passive_rules/)
- [x] AI validation for sensitive_data.yaml findings
- [x] AWS presigned URL suppression (deterministic, before AI branch)

### Dashboard
- [x] Dashboard tab: overview metrics, findings by severity, agent status
- [x] Proxy tab: HTTP history (resizable columns) + Settings (scope, bypass)
- [x] Target tab: site map + issues (dedup by title|path|parameter)
- [x] Browse tab: headless browser session
- [x] Crawl tab: SPA crawler
- [x] AI tab: app context, threat model, agent activity log, service graph, payload inventory, scan engine config
- [x] Logs tab: rolling system log, 6-column table, filters (source/level/text)
- [x] Plugins tab: enable/disable plugins
- [x] Setup tab: CA cert download, AI status
- [x] Repeater tab: manual request editing and replay

### Other
- [x] Global system log (plugin_manager._event_log, 500 events)
- [x] Scan engine config at runtime (model, workers, concurrency, confidence threshold)
- [x] Bedrock application-inference-profile support (Sonnet, Haiku, Opus)
- [x] Multi-provider AI (Bedrock / Anthropic API / OpenAI-compatible), model config
      centralized in dast.config.settings (2026-07-21)
- [x] Per-organization scope presets via dast/scope_presets/*.json (auto-discovered,
      gitignored) instead of one org hardcoded in proxy_settings.py (2026-07-21)
- [x] Copy as cURL + Copy Reproduce Link in HTTP History context menu, replacing the
      broken "Copy request" item (2026-07-21)
- [x] Import Findings runs as a background job with progress polling instead of
      blocking the request with no feedback (2026-07-21)
- [x] Proxy + dashboard fall back to the next free port (loud warning) instead of
      crashing when the requested port is already in use (2026-07-21)
- [x] HTTP History Host/Path/Body columns auto-grow to fill extra window width
      (2026-07-21)

---

## Up next

### False positive reduction
- [ ] Browser confirm for SSRF (OOB DNS callback via headless browser)
- [ ] IDOR confirmation: fetch 2 resources with different tokens, diff the response
- [ ] Auth bypass: check that stripped-header response differs meaningfully from baseline

### Agent coverage
- [ ] WebSocket attack support (ws:// interception + payload injection)
- [ ] File upload vulnerabilities (polyglot upload, path in filename parameter)
- [ ] Business logic: multi-step flows (add to cart, quantity tampering, price bypass)
- [ ] JWT attack agent (alg:none, weak secret brute, kid injection) — payloads exist, agent missing
- [ ] NoSQL injection agent — payloads exist, agent missing
- [ ] Prototype pollution agent — payloads exist, agent missing

### Dashboard / UX
- [ ] OpenAPI docs for the dashboard REST API (FastAPI /docs currently disabled)
- [ ] Scan history: persist scan results across proxy restarts

### Infrastructure
- [ ] Rate limiting: per-domain token bucket to avoid triggering WAFs
- [ ] Scope enforcement: support regex patterns in addition to host/path prefix
- [ ] Docker image for CI environments

### Known limitations
- Auth supports browser-based form login only — no OAuth2, SSO, or magic links
- No WebSocket interception yet
- No deduplication of findings across scan restarts (in-memory only)
