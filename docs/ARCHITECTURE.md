# Frieren DAST-AI Architecture

> For Claude Code conventions, commands, and key files see [CLAUDE.md](../CLAUDE.md).

**Version:** 0.8.2
**Last Updated:** 2026-08-14

---

## Proxy + Scanner Pipeline

```
Browser (or automated crawler)
    |   configured to route through proxy (:8080)
    v
[HTTPS MITM Proxy]            dast/proxy/proxy_server.py
  - Intercepts all HTTP/HTTPS
  - TLS termination via per-host CA-signed certificate
  - Strips internal headers before forwarding
    |
    v
[SessionStore]                dast/proxy/session_store.py
  - All entries stored in memory
  - Passive scanner plugin fires on every completed entry (YAML rule engine)
  - Service graph observes every entry (auto-grouping)
    |
    v
[Dashboard]                   dast/proxy/dashboard_server.py
  FastAPI + uvicorn + WebSocket
  - Dashboard tab: overview metrics, findings by severity, agent status
  - Proxy tab: HTTP history (resizable columns), Intercept, Site map, Issues,
               Settings (scope rules, bypass domains, save/load, CA cert / Setup)
  - Discovery tab: Manual Browse (headless browser), Crawl (SPA crawler),
                    Content Discovery (forced browsing), Param Mining
  - AI tab: Suggestions sub-tab (AI-surfaced findings/recon), Settings sub-tab
            (provider, model tiers, scan engine config, app context, threat
            model, activity log, service graph, payload inventory)
  - Scan tab: live scan queue (pending/running/completed, pause/cancel, replay)
  - Plugins tab: enable/disable plugins
  - GraphQL tab: Schema Explorer + Query Builder, Fuzzer
  - Repeater tab: manual request edit/resend, one tab per request
  - Intruder tab: payload-position fuzzing
  - Logs tab: rolling system log (plugins, agents, browser, crawler)
  - Extras tab: H1 Validator, Code, FedRAMP, Interactions, Decoder/Encoder, JWT editor
    |
    v
[Scan queue]                  dast/proxy/runner.py
  - In-scope entries queued automatically
  - Active scan worker: runs Coordinator per entry
    |
    v
[Coordinator]                 dast/ai/coordinator.py  ← LLM planner/validator pattern
  0. Canary pre-probe pass (no LLM):
       _select_attack_types_for_params() classifies params (numeric_id, uuid,
       path, search, token, string, json, boolean, empty) and maps to candidate
       attack types via _PARAM_ATTACK_MAP.
       Auth-token params (nonce, state, code, id_token, …) skipped entirely.
       _run_canary_probe() sends one cheap payload per (attack_type, param)
       and checks the response against _SIGNAL_PATTERNS.
       signal_map: {attack_type → [param_names_with_signal]} passed to planner.
  1. LLM Planner: sees canary results + param classifications — selects agents
     for types with signal; can extend to non-signal types when warranted
  2. Selected agents run in parallel (asyncio.gather)
  3. Red-Team Validator (dast/ai/red_team.py): confirms non-deterministic findings
       Stage 1: deterministic FP filter (dast/ai/fp_filter.py) — immediate discard
       Stage 2: pattern confidence estimate from evidence strength
       Stage 3: LLM exploit-proof prompt — asks for exploitation scenario
       Aggregated confidence: max(pattern_conf, browser_conf, llm_confidence)
       Confirmed only if LLM agrees AND confidence >= threshold
  Deterministic findings (time-based SQLi, LFI match, secrets) skip validator
    |
    v
[VulnAgents]                  dast/agents/
  Each agent targets one vulnerability class.
  All agents call get_filtered_payloads(attack_type, target) from
  dast/agents/payload_filter.py — only tech-relevant payload groups are sent.
  - xss_agent            — reflected/stored XSS + DOM + obfuscation/bypass; blind XSS
                           only for CMS/admin/messaging apps
  - sqli_agent           — error-based + boolean + time-based blind (5s max);
                           stacked queries only for MSSQL/PostgreSQL
  - ssrf_agent           — OOB callback + internal_probe; obfuscated probes for
                           URL-handling endpoints
  - file_read_agent      — path traversal / LFI; PHP wrappers only when PHP evidence
  - auth_agent           — auth header stripping + 9 header-based bypass combos
                           (real endpoint path, not /admin)
  - secrets_agent        — deterministic credential/token patterns
  - discovery_agent      — SSTI (skipped on pure JSON APIs), open redirect,
                           CRLF, HTTP method tampering
  - llm_injection_agent  — prompt injection, jailbreak, system prompt leak
  - business_logic_agent — numeric boundary abuse, privilege escalation via param
                           injection, workflow bypass, mass assignment
  - csrf_agent           — token removal, swap, header bypass, cross-origin
    |
    v
[Findings]                    SessionStore.add_finding()
  Displayed in real-time on dashboard
  AI-rejected findings → False Positives sub-tab (restorable)
```

---

## Coordinator Intelligence

### Param Classification

`_classify_param(name, value)` returns one of:

| Class | Detection rule |
|-------|---------------|
| `token` | Long random string ≥ 24 chars |
| `jwt` | Three Base64url segments separated by dots |
| `numeric_id` | Pure digits ≤ 15 chars |
| `uuid` | Standard UUID pattern |
| `path` | Contains `/` or `..` |
| `search` | Name matches: q, query, search, filter, keyword, term, text |
| `boolean` | Value in {true, false, 1, 0, yes, no} |
| `json` | Value starts with `{` or `[` |
| `empty` | Empty string |
| `string` | Everything else |

### Param → Attack Type Mapping (`_PARAM_ATTACK_MAP`)

| Param class | Candidate attack types |
|-------------|----------------------|
| `numeric_id` | sqli, idor, business_logic |
| `uuid` | idor, business_logic |
| `path` | lfi, ssrf, xxe |
| `search` | sqli, xss, ssrf, lfi |
| `string` | sqli, xss, ssrf, lfi, cmdi, ssti |
| `json` | sqli, nosql, xxe, business_logic |
| `token`, `jwt`, `boolean` | *(skipped)* |
| `empty` | sqli, xss |

Auth-token params (`_AUTH_TOKEN_PARAMS`: nonce, state, code, id_token, access_token, refresh_token, …) are excluded from all probing entirely.

### Canary Payloads and Signal Patterns

| Attack type | Canary payload | Signal pattern (response) |
|-------------|---------------|--------------------------|
| sqli | `'` | SQL error keywords, syntax error |
| xss | `<dast>` | `<dast>` reflected literally |
| lfi | `../etc/passwd` | `root:`, `/bin/bash` |
| ssrf | `http://169.254.169.254/` | AWS metadata, cloud provider response |
| cmdi | `;id` | `uid=`, `gid=` |
| xxe | `<!DOCTYPE>` | XML parse error |
| nosql | `{"$gt":""}` | MongoDB operator error |
| ssti | `{{7*7}}` | `49` isolated in response |

---

## Tech-Stack-Aware Payload Filtering

### Overview

`dast/agents/payload_filter.py` — central module used by all agents.

```
get_filtered_payloads(attack_type, target) -> List[str]
    |
    v
_scan_target(target) — combine URL + request headers + discovery_context.tech_stack
                       (framework, language, server, template_engine, cms, db_hints)
                       + app_profile_hint
    |
    v
Selector function for attack_type:
  _lfi_groups      — unix + null_byte always; windows if Windows/ASP.NET; wrappers if PHP
  _sqli_groups     — error_based + boolean_based always; stacked if MSSQL/PostgreSQL
  _xss_groups      — basic always; dom if HTML; blind only for CMS/admin/messaging apps
  _ssrf_groups     — oob_http + internal_probe always; obfuscated if URL-handling endpoint
  _cmdi_groups     — unix_basic always; windows if Windows; bypass if WAF signals
  _xxe_groups      — EMPTY if not XML/SOAP body; basic + oob + cdata otherwise
  _ssti_groups     — EMPTY if no HTML/template/CMS evidence; detection + rce_probe if present
  _nosql_groups    — EMPTY without MongoDB/Elastic/Redis signal; db-specific groups otherwise
  _jwt_groups      — EMPTY without Bearer token or JWT cookie; alg_none + kid_injection otherwise
  _prototype_pollution_groups — EMPTY for non-JS apps; detection + json_body/query_string
    |
    v
Load YAML groups via get_payloads(attack_type, group) for each selected group
Return de-duplicated payload list
```

Returning an empty list (`[]`) means the agent skips that attack type entirely.
Generic groups (unix traversal, boolean SQLi, basic XSS, …) are always included when the attack type is applicable. Tech-specific groups are opt-in.

### Tech Evidence Sources (in priority order)

1. `discovery_context.tech_stack` from Wappalyzer + manual fingerprinter (most reliable)
2. `app_profile_hint` — LLM background synthesis (text string, checked with regex)
3. Request headers (`X-Powered-By`, `Server`, `Set-Cookie`, `Content-Type`)
4. URL patterns (`.php`, `.jsp`, `.aspx`, path segments)

---

## Tech-Stack Fingerprinter

`dast/discovery/fingerprinter.py` — zero extra requests, runs on proxy-captured data.

### Strategy

```
Per-entry fingerprint(entry):
  1. Wappalyzer (primary) — analyze_from_response(entry, "fast")
       ~3000 technology signatures
       Maps Wappalyzer categories to TechStack fields:
         Web frameworks / JS frameworks  → framework
         Programming languages           → language
         Web servers / Reverse proxies   → server
         Databases / NoSQL / Search      → database_hints
         CMS / Blogs / Ecommerce         → cms
         Templating engines / UI         → template_engine
         Security / CDN                  → waf_hints
       Confidence threshold: 50 (ignore low-confidence detections)
       Skips noisy JS libraries: jQuery, Bootstrap, Google Analytics, etc.

  2. Manual regex rules (complement — fills gaps Wappalyzer misses):
       _FRAMEWORK_RULES  — Django, Flask, FastAPI, Rails, Spring, Laravel, NestJS,
                           ASP.NET, Gin, Fiber, Actix, Phoenix, Symfony, Nuxt,
                           Remix, Quarkus, Micronaut (44 rules)
       _TEMPLATE_RULES   — Jinja2/Nunjucks, Twig, Handlebars/Mustache, Thymeleaf,
                           FreeMarker, Velocity, Smarty, ERB, Razor, Pug, JSP
       _CMS_RULES        — WordPress, Drupal, Joomla, Shopify, TYPO3, Ghost,
                           Magento, Contentful, Strapi, Sitecore, Kentico, Confluence
       _DB_HINTS         — error message / stack trace detection for PostgreSQL,
                           MySQL, SQLite, MSSQL, Oracle, MongoDB, Redis, Elasticsearch
       _ORM_HINTS        — SQLAlchemy, ActiveRecord, Hibernate, TypeORM, Sequelize,
                           Prisma, GORM, Doctrine
       _WAF_HINTS        — Cloudflare, Sucuri, AWS WAF, ModSecurity, Incapsula,
                           Akamai, FortiWeb
       _CDN_HINTS        — Cloudflare, Fastly, Akamai, CloudFront

  3. Merge: Wappalyzer fields take precedence; manual rules fill None fields
     and extend list fields (db_hints, waf_hints, orm_hints)

Results merged into host-level TechStack by DiscoveryEngine.
TechStack.to_agent_summary() injects context into agent prompts.
```

### TechStack Fields

```python
@dataclass
class TechStack:
    framework: Optional[str]          # e.g. "Django", "Rails", "Spring"
    language: Optional[str]           # e.g. "Python", "Java", "JavaScript"
    server: Optional[str]             # e.g. "nginx/1.18", "Apache/2.4"
    database_hints: List[str]         # e.g. ["PostgreSQL", "Redis"]
    orm_hints: List[str]              # e.g. ["ActiveRecord", "SQLAlchemy"]
    cdn: Optional[str]                # e.g. "Cloudflare"
    waf_hints: List[str]              # e.g. ["Cloudflare", "ModSecurity"]
    template_engine: Optional[str]    # e.g. "Jinja2", "Twig", "Thymeleaf"
    cms: Optional[str]                # e.g. "WordPress", "Drupal", "Shopify"
    extra: Dict[str, str]
```

---

## Passive Scanner Rule Engine

```
dast/passive_rules/           YAML rule files — add a file to add a check, no code needed
  headers/
    security_headers.yaml     HSTS, CSP, Referrer-Policy, Permissions-Policy,
                              Cache-Control, CSP unsafe-inline/eval, HSTS short max-age
    info_disclosure.yaml      Server version via header, debug mode, X-Powered-By, X-Generator
    cache_control.yaml        Cacheable authenticated responses
  cookies/
    cookie_flags.yaml         HttpOnly, Secure, SameSite; session cookie gets higher severity
  cors/
    cors.yaml                 Wildcard+credentials (high), wildcard, reflected origin+credentials,
                              null origin
  secrets/
    sensitive_data.yaml       AWS/GitHub/Slack/Stripe/Google API keys, JWTs, private keys,
                              credit cards, generic api_key fields — AI-validated where needed
  injection/
    error_pages.yaml          Stack traces, SQL errors, PHP/ASP.NET/.NET XML error pages
  ai/
    llm_endpoints.yaml        LLM endpoint detection, prompt injection confirmation marker,
                              system prompt leakage
  discovery/
    directory_listing.yaml    Apache/nginx/IIS directory index
    open_redirect.yaml        Meta-refresh redirect, JS location.href redirect
    clickjacking.yaml         Missing X-Frame-Options AND missing CSP frame-ancestors
```

### Rule Schema (key fields)

```yaml
id: headers-hsts-missing
title: "Missing HSTS Header"
severity: medium          # critical | high | medium | low | info
cwe: "CWE-319"
description: "..."
match:
  header_absent: strict-transport-security
  # Also available:
  # header_present / header_value_regex / header_name_any
  # body_regex / body_max_scan_bytes
  # cookie_flag_absent / cookie_name_regex
  # path_regex
  # cors_check + cors_mode
  # request_header_present + header_value_not_regex
  # csp_frame_ancestors_absent
  # also_header_name / also_header_value
conditions:
  content_type: html         # html | json | any
  status_codes: [200]
  scheme: https              # https | http | any
  one_per_host: true         # suppress after first match per host
evidence_template: "Header {header} absent on {path}"
needs_ai_validation: false   # true → routes through LLM before storing
```

---

## Adaptive Mutation Loop

```
Seed payloads (from YAML, filtered by payload_filter.py)
    |
    v
Send probe → observe response
    |
    ├── Hit? → confirm (browser for XSS, pattern for LFI, delay for SQLi)
    │              → AgentFinding(bypass_validation=True if deterministic)
    │
    └── Blocked? → LLM Mutator (dast/ai/mutator.py)
                     Analyses what the server did (WAF block, encoding, stripping)
                     Generates bypass variant targeting that specific defence
                     Returns action: "mutate" | "obfuscate" | "stop"
                     LLM decides when to stop — safety ceiling: 15 rounds
                     Always passes tried_payloads to avoid repeats
                     |
                     └── new payload → loop back
```

---

## Service Graph (Layers 1 + 2)

```
Layer 1 — Service map (passive, zero scan impact)
  ServiceGraph auto-detects host groupings via:
  - Shared JWT (same `iss` claim or token prefix)
  - Common parent domain (api.x.com + app.x.com → same group)
  - Shared correlation headers (X-Trace-ID, traceparent)
  - Shared session cookie name+value
  Manual overrides (merge/split) available in AI tab
  API: POST /api/service-graph/merge, POST /api/service-graph/split

Layer 2 — Context sharing (read-only, optional per agent)
  CheckTarget receives service_context: known sibling hosts + shared tokens
  SSRF agent uses sibling hosts as internal probe targets
  Auth agent shares tokens seen on any host in the same group
```

---

## App Context + Threat Model

```
AppContextWorker              dast/discovery/app_context.py
  Background coroutine, starts with proxy
  Synthesises AppProfile per host: app type, auth model, resource types,
  vuln hypotheses
  First analysis: 15 entries; re-analysis: every 30 new entries
  Output injected into Coordinator planner prompt via CheckTarget.app_profile_hint
  API: GET /api/ai/app-context

ThreatModelWorker             dast/discovery/threat_model.py
  Background coroutine, starts with proxy
  Synthesises ThreatModel per host: architectural constraints, security invariants,
  things that are NOT vulnerabilities
  First analysis: 15 entries; re-analysis: every 50 new entries
  Output injected into red_team.validate() via CheckTarget.threat_model_hint
  API: GET /api/ai/threat-models

Both exposed via:
  store.discovery_engine.get_app_profile(host)
  store.discovery_engine.get_threat_model(host)
```

---

## MFA Bypass Agent

```
dast/agents/mfa_agent.py — activated only for MFA/OTP verification endpoints

Routing:
  coordinator._is_mfa_endpoint(url) → True for paths matching mfa, otp, 2fa, totp,
  verify-code, confirm-code, etc.
  Added as candidate type "mfa_bypass" in _select_attack_types_for_params()

Checks (in order):
  1. Rate limiting — submit 4 invalid OTPs rapidly; no 429 or lockout → HIGH finding
  2. OTP parameter removal — omit the code field; 200 response → CRITICAL finding
  3. Backup code brute-force — try 5 common backup codes; any accepted → CRITICAL finding

Design:
  - Reads the OTP param name from the actual request body (regex on field names)
  - Stops after rate-limit check if a finding is found (no point in further checks)
  - All findings go through the Red-Team Validator (bypass_validation=False)
  - Pure SSO/OIDC relay endpoints are still skipped by _is_auth_endpoint()
```

---

## Session Refresh Worker

```
dast/session/refresh_worker.py — transparent re-auth on session expiry

Activation:
  Only created when --auth-url and credentials are provided to the proxy runner.
  Runs as a background coroutine in asyncio.gather alongside the proxy.

Detection signals:
  - HTTP 401 or 403 on any in-scope endpoint
  - HTTP 3xx redirect to a URL matching /login, /signin, /sign-in, etc.
  - HTTP 200 with body phrases like "session expired", "please log in again"

Throttling:
  - 30s cooldown between re-auth attempts (avoids thundering herd on concurrent 401s)
  - Signal queue: extra signals during cooldown are silently discarded

Re-auth flow:
  1. Borrows a browser context from ContextPool
  2. Runs AuthAgent.login() against the saved auth_url + credentials
  3. On success: applies refreshed storage_state to all pool contexts
  4. Logs outcome to the proxy event log (visible in Logs tab)

Modular: SessionRefreshWorker has no dependency on the scan pipeline.
```

---

## Red-Team Validator

```
dast/ai/red_team.py — runs after agents, before findings reach the dashboard

Stage 1: fp_filter.check()
  Deterministic, no LLM (9 rules in dast/ai/fp_filter.py)
  Immediate discard for known false-positive patterns

Stage 2: _pattern_confidence()
  Estimates confidence from evidence strength per attack type
  e.g. time-based SQLi with confirmed delay → high confidence

Stage 3: LLM exploit-proof prompt
  Asks: "Given this evidence, describe a concrete exploitation scenario"
  Returns: confirmed (bool), confidence (float 0-1), reasoning (str)
  Model: validation_model (Opus by default — highest stakes)
  Structured output: forced via schema (RED_TEAM_SCHEMA) at temperature 0
  Untrusted target content (response snippet, code, hints) is XML-fenced via
  prompt_safety.wrap_untrusted so injected instructions cannot flip the verdict

Aggregation:
  final_confidence = max(pattern_conf, browser_conf, llm_confidence)
  Confirmed only if llm_confirmed AND final_confidence >= confidence_threshold

On LLM failure: falls back to pattern confidence alone
confidence_threshold: configurable at runtime via AI tab slider; default 0.5
AI-rejected findings: moved to False Positives sub-tab in Issues panel (restorable)
```

---

## Tiered Model Architecture

| Stage | Default model | Override field | Rationale |
|-------|--------------|----------------|-----------|
| Planning (agent selection) | active model | `fast_model_id` | Simple classification, many calls |
| Baseline check | fast model | `fast_model_id` | Structural analysis, not exploit-level |
| Adaptive mutation | active model | `model_id` | Creative, not high-stakes |
| Red-team validation | validation model | `validation_model_id` | Highest stakes — exploit-proof |

Defaults: Haiku (fast), Opus (validation).
Configured in `DashboardContext._DEFAULT_FAST_MODEL` / `_DEFAULT_VALIDATION_MODEL`.
Override at runtime in the AI tab or via `POST /api/scan-config`.

---

## Module Map

```
dast/
├── agents/                   Vulnerability agents (one class per module)
│   ├── __init__.py           Imports all agents → triggers Coordinator.register()
│   ├── payload_filter.py     Tech-stack-aware payload group selector
│   │                         get_filtered_payloads(attack_type, target) → List[str]
│   ├── xss_agent.py
│   ├── sqli_agent.py
│   ├── ssrf_agent.py
│   ├── file_read_agent.py
│   ├── auth_agent.py         9 bypass combos; real endpoint path
│   ├── mfa_agent.py          MFA/OTP bypass: rate limit, param removal, backup codes
│   ├── secrets_agent.py
│   ├── discovery_agent.py
│   ├── llm_injection_agent.py
│   ├── business_logic_agent.py
│   └── csrf_agent.py
│
├── ai/
│   ├── agent_base.py         VulnAgent ABC + AgentFinding dataclass
│   ├── coordinator.py        LLM Coordinator: canary pass + planner + validator dispatch
│   ├── red_team.py           Red-Team Validator
│   ├── fp_filter.py          Deterministic FP rules (9 rules, no LLM)
│   ├── mutator.py            Adaptive payload mutator (LLM-controlled stop)
│   ├── bedrock_client.py     Bedrock Claude wrapper (schema-forced output, temperature, prompt caching, tiered models)
│   ├── schemas.py            JSON Schemas for structured LLM output
│   ├── prompt_safety.py      Structural prompt-injection defense (XML fencing of untrusted content)
│   ├── payload_generator.py  Standalone scan mode
│   └── response_analyzer.py  Standalone scan mode (legacy)
│
├── payloads/                 Seed payloads in YAML — edit without touching code
│   ├── loader.py             Cached YAML loader
│   ├── xss.yaml
│   ├── sqli.yaml
│   ├── ssrf.yaml
│   ├── lfi.yaml
│   ├── ssti.yaml
│   ├── llm_injection.yaml
│   ├── cmdi.yaml             OS command injection (unix/windows/bypass)
│   ├── xxe.yaml              XML external entity (file read, OOB, SSRF, CDATA)
│   ├── jwt.yaml              JWT attacks (alg:none, weak secrets, kid injection, jku)
│   ├── nosql.yaml            NoSQL injection (MongoDB, Elasticsearch, Redis)
│   └── prototype_pollution.yaml
│
├── passive_rules/            YAML-driven passive scanner rules (62 rules, 11+ files)
│   ├── headers/              security_headers.yaml, info_disclosure.yaml, cache_control.yaml
│   ├── cookies/              cookie_flags.yaml
│   ├── cors/                 cors.yaml
│   ├── secrets/              sensitive_data.yaml
│   ├── injection/            error_pages.yaml
│   ├── ai/                   llm_endpoints.yaml
│   └── discovery/            directory_listing.yaml, open_redirect.yaml, clickjacking.yaml
│
├── proxy/
│   ├── proxy_server.py       HTTPS MITM TCP server
│   ├── cert_authority.py     Per-host certificate generation
│   ├── session_store.py      In-memory entry store + cookie jar
│   ├── service_graph.py      Multi-host service grouping (Layer 1+2)
│   ├── runner.py             Orchestrates proxy + dashboard + scan worker
│   ├── dashboard_server.py   FastAPI app + WebSocket + all API routes + HTML/JS
│   │                         Includes /api/scan-config (GET/POST) for runtime config
│   ├── proxy_settings.py     Scope rules, bypass, extension filters
│   ├── plugin_base.py        ProxyPlugin ABC
│   ├── plugin_manager.py     Plugin discovery and dispatch (rolling 500-event log)
│   ├── spa_crawler.py        Playwright SPA crawler routing through proxy
│   ├── browse_session.py     Headless browse session
│   └── session_manager.py    Session save/load/export
│
├── plugins/
│   ├── passive_scanner.py    YAML rule engine — loads dast/passive_rules/**/*.yaml
│   ├── graphql_analyzer.py   Passive GraphQL analysis: introspection, batching, CSRF,
│   │                         field suggestions, debug disclosure. LLM validates ambiguous findings.
│   ├── js_host_extractor.py  Extracts hosts from JS bundles
│   └── hello_world.py        Example plugin
│
├── scanners/
│   ├── active_checks.py      run_active_checks() — Coordinator entry point
│   │                         _PROBE_SEM concurrency updated at runtime via /api/scan-config
│   └── collaborator.py       OOB TCP listener for blind SSRF/XXE
│
├── discovery/
│   ├── engine.py             DiscoveryEngine: orchestrates all discovery modules per host
│   ├── app_context.py        AppContextWorker: background LLM AppProfile synthesis
│   ├── threat_model.py       ThreatModelWorker: background per-host architectural constraints
│   ├── fingerprinter.py      Tech stack fingerprinting (Wappalyzer + manual regex)
│   ├── js_analyzer.py        API endpoint extraction from JS bundles
│   ├── traffic_graph.py      JSON response field → request param call chain detection
│   ├── openapi_probe.py      Auto-discovery of /openapi.json, /swagger.json
│   └── models.py             TechStack + DiscoveryContext dataclasses
│
├── browser/                  Standalone scan mode (browser-based)
├── session/
│   ├── auth_agent.py         Playwright-based login automation
│   ├── manager.py            Session checkpoint + rollback
│   └── refresh_worker.py     Background re-auth on 401/redirect-to-login detection
├── attack/                   Standalone scan mode (legacy attack engine)
├── report/                   JSON + Markdown + SARIF 2.1.0 export
└── utils/
    └── logger.py             structlog structured logging
```

---

## Recon & Discovery Subsystems

### Content Discovery (forced browsing)
- `dast/wordlists/*.txt` — plain-text wordlists (SecLists-derived, MIT). Add a `<name>.txt`,
  load via `load_wordlist("<name>")` (`dast/wordlists/loader.py`). Separate from
  `dast/payloads/loader.py` (YAML-only).
- `dast/scanners/content_discovery.py::run_content_discovery()` — GET-probes wordlist paths to
  surface unlinked endpoints. Detection-only, no payloads. Reuses `active_checks._client()/
  _send()` and gates EVERY URL through `ProxySettings.is_in_scope()` BEFORE probing (hard
  safety guarantee). Soft-404 filtered via baseline probe. Driven by
  `ProxyRunner._discovery_worker` off `discovery_queue`; `POST /api/discovery` re-checks scope.
  Hits → `source="discovery"` sitemap + `source="content-discovery"` suggestions. Dir/file hits
  are neutral `recon` (never infer vuln from path); GraphQL hits → `graphql_injection`. Opt-in
  LLM refinement via `discovery_llm_classify` flag (default OFF). UI: Discovery tab → Content
  Discovery sub-tab.

### Param Mining (hidden-parameter discovery)
- `dast/scanners/param_miner.py::run_param_mining()` — brute-forces unlinked param NAMES
  against ONE in-scope request (query/form/JSON auto-detected). Parameter-side companion to
  content_discovery. Wordlist `dast/wordlists/params.txt`. Detection-only (inert canary).
  Signals, lowest-FP first: (1) reflection — each candidate gets a unique canary
  (`dastpm7c1e<i>`); (2) behavior-change — status/length shift binary-searched to one name,
  re-confirmed in isolation. Anti-FP: two baselines up front; unstable body length disables
  length detection (status-only). `_BATCH_SIZE=25`, `_LENGTH_NOISE_BYTES=32`. Scope-gates every
  URL; excludes existing params; `client=` reuses coordinator's client (never closes it).
- AUTOMATIC, no UI tab. Two paths: (a) AI off — `ProxyRunner._attack_one` →
  `_mine_params_for_entry` (inert probes only); hits → `source="param-discovery"` `recon`
  suggestions. (b) AI on — planner's `mine_params` field (`PLANNER_SCHEMA`) →
  `Coordinator._run_param_mining_pass` folds names onto `target.params` + sets
  `target.param_mining_hint`. Miner failure leaves `target.params` intact.

### Probe-Diffing (AI-native "Backslash Powered")
- `dast/agents/probe_diff.py::run_probe_pairs()` — PURE PRIMITIVE, not a per-vuln agent.
  Injects break/repair PAIRS into one param and diffs responses: `dast'`/`dast\'`,
  `dast"`/`dast\"`, `dast\`/`dast\\`, `dast${{7*7}}`/`dast${{7*'7}}`, `dast{{7*7}}`/
  `dast{{7*'7}}`. Non-destructive by construction. Returns `DiffSignature` (`has_signal`,
  `divergent_labels`, `to_classifier_summary()`); diffs status, length (`>=32` floor),
  HTML-structure hash, interpreter error, arith-eval marker (`49`), reflection. Scope-gates
  every URL; `client=` reuses coordinator's client.
- `dast/ai/probe_classifier.py::classify(signature)` → `ProbeVerdict` (injection_class,
  context, confidence, recommended_agents). No LLM call when no signal; fences summary via
  `wrap_untrusted(.., 'probe_signature')`; degrades to `_UNKNOWN` on error.
  `PROBE_CLASSIFIER_SCHEMA` in schemas.py.
- Wiring: `Coordinator.run(.., probe_diff=False)` → `_run_probe_diff_pass()` folds
  `recommended_agents` into signal_map + sets `target.probe_diff_hint`. Opt-in default OFF:
  `sc-probe-diff` checkbox → `POST /api/scan-config` → `runner._engine_config["probe_diff"]`.

### Cache Poisoning (unkeyed-input detection)
- `dast/agents/cache_poisoning_agent.py::CachePoisoningAgent` (`cache_poisoning`). Detects
  poisoning via UNKEYED headers (`X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Host`,
  `Forwarded`, ...) reflected into a cacheable response. GET-only; bails on non-cacheable
  baseline. Two-request proof: (1) send header with unique marker → reflected?; (2) re-request
  WITHOUT header → marker survives → unkeyed → CONFIRMED (`bypass_validation=True`, high).
  Reflected-but-not-cached → unconfirmed medium for LLM validator.
- SAFETY: every probe appends a unique cache-buster query param (`_cache_buster_url`), so both
  requests map to a key only WE request — never poisons the real shared page. Config in
  `dast/payloads/cache_poisoning.yaml`. Wiring:
  `Coordinator._select_attack_types_for_params()` adds `cache_poisoning` for every GET
  (no-canary; planner decides, agent self-gates on cacheability).

### Scope Presets (per organization)
- Drop a `<slug>.json` under `dast/scope_presets/` (gitignored, see `example.json.example`
  for the schema) — auto-discovered at startup and written to `~/.dast-ai/projects/<slug>.json`
  on first run if absent. No code changes and nothing organization-specific committed.
- Users can also create/edit scope rules directly from the Proxy > Settings sub-tab without a preset file.

## GraphQL Subsystem

### Query Builder / Fuzzer
- `dast/plugins/graphql_introspection.py` stores an extended compact schema per endpoint in
  `store.graphql_schemas[endpoint]` (`mutations`/`queries` with arg `type`+`wrapper` and
  `return_type`, `input_types`, `object_types`, `union_types`, `enum_types`). Superset of what
  the findings importer reads — safe to extend, never remove keys. `_introspect(...)` is a
  module-level function called ONLY from `POST /api/graphql/introspect` (never automatically).
  `on_entry()` only catalogues endpoints seen on the wire; never sends an outbound
  introspection request. `POST /api/graphql/rescan-history` catalogues from captured history.
  Both introspect paths return the failure reason directly (Logs tab hides `warn` events).
- `dast/graphql/query_builder.py` — pure functions (`build_argument_value`,
  `build_selection_set`, `build_operation`), no I/O. Caps: `MAX_INPUT_DEPTH=3` (cycle
  detection), `MAX_SELECTION_DEPTH=2`, `MAX_FIELDS_PER_LEVEL=15`. Always variable-based queries.
- `dast/graphql/variable_fuzzer.py` — extracts variables from a captured request's JSON
  `variables` (inline query-literal extraction NOT implemented — documented follow-up),
  cross-products against payloads one variable at a time. No vuln classification here — that's
  `graphql_analyzer.py`'s job on every proxied response.
- GraphQL tab enabled/disabled via the `GraphQL Fuzzer` plugin (see Plugin-gated tab pattern).

## Mutation & WAF

### WAF Bypass
- `dast/agents/block_detector.py` — central `detect_block(status, body, baseline_len)`
  returns a `BlockVerdict`. Recognises a block from status codes AND from block-page
  content signatures EVEN on HTTP 200 (a WAF hiding behind 200 used to be missed, so the
  mutator gave up instead of attempting a bypass). Agents call it before the mutator and
  feed `verdict.signal` into `self.observe("waf_block", ...)`.
- Per-host bypass memory: when a payload succeeds after an earlier block, the agent
  emits `self.observe("waf_bypass", payload=...)`; the coordinator records it via
  `session_intelligence.record_scan_complete(bypass_payload=...)`. `HostIntel.to_mutator_hint()`
  then offers that proven payload to the mutator FIRST on later endpoints of the same host.
- All six mutator-using agents are wired to the central detector + per-host memory:
  `sqli_agent`, `xss_agent`, `file_read_agent`, `ssrf_agent`, `discovery_agent` (SSTI),
  `llm_injection_agent`. Each builds `tech_context` via `build_mutator_context()`, records
  blocks with `detect_block()` → `observe("waf_block")`, and emits `observe("waf_bypass")`
  when a payload succeeds after a prior block.

## Reliability Guards

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

## Validation Knowledge

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

### AI Triage Engine (HackerOne / pasted reports)
- `dast/hackerone/parser.py::parse_report(text)` — regex first, LLM enrichment second
  (SCHEMA-FORCED via `H1_PARSE_SCHEMA`, fast tier, text fenced with `wrap_untrusted(..,
  "h1_report")`). Runs on a worker thread, so `_llm_enrich` calls `invoke_json`
  SYNCHRONOUSLY — never `asyncio.get_running_loop()` (raised on the loopless thread;
  regression-tested). Extracts `http_method`, `request_headers` (Authorization/Cookie DROPPED
  — session supplies auth), `request_body`. LLM failure degrades to regex.
- `dast/hackerone/validator.py::_validate_http` reproduces the report's ACTUAL request
  (branches on method, sends body, merges headers with auth stripped). `payload_safety.make_safe`
  gates BOTH URL and body — destructive payload substituted with safe variant, else nothing
  sent (`needs_manual`). Verdict SCHEMA-FORCED via `H1_VERDICT_SCHEMA`; confirmed iff
  `reproduced AND confidence >= 0.95`. `ValidationResult` carries `severity`.
- `dast/proxy/api/hackerone_routes.py` — on `needs_auth`, `_try_profile_auth` matches a Phase-1
  login profile and authenticates via `session/profile_reauth.reauth_from_profile` (flow replay
  → saved-session fallback) before manual browser login. On `confirmed`, `_persist_finding`
  creates a synthetic `source="agent"` entry + finding → dashboard → SARIF. Both best-effort.
- Login profiles (encrypted, per-site) + flow recording/replay: `dast/profiles/` and
  `dast/session/flow_replayer.py`.

## Integration Layer

### Manual Toolbelt (Decoder/Encoder + JWT editor)
- Two Extras sub-tabs via `switchExtrasSub('decoder'|'jwt')` (75-subtabs-ai-panel.js); both in
  `dast/proxy/ui/js/76-extras-decoder-jwt.js`.
- **Decoder/Encoder** — CLIENT-SIDE ONLY, no backend. base64/base64url/URL/HTML/hex + JWT
  decode. Ops are a pure `_DECODER_OPS` list; add a transform by appending one entry. Errors
  render inline, never throw.
- **JWT editor** — decode/edit/re-sign a token, send to Repeater. Modes HS256/384/512 +
  `alg:none`. One backend touchpoint: `POST /api/jwt/build` (`dast/proxy/api/jwt_routes.py`)
  reuses `jwt_tester._build_token()`; FORCES `header["alg"]` from the chosen mode, rejects
  unsupported modes with 400.

### Shared Tool Layer + MCP Server
- `dast/tools/` — SINGLE source of truth for agent-callable capabilities. One definition, two
  callers (internal agentic loop + external MCP server) dispatch through the same registry, so
  capabilities never drift.
  - `base.py` — `Tool` dataclass (`name`, `description`, `input_schema`, `handler`, `tags`) +
    `_REGISTRY`; `register`/`get_tool`/`all_tools`. `run_tool(ctx, name, arguments)` NEVER
    raises — unknown tool or handler exception → `{"ok": False, "error": ...}`. Every handler
    returns `{"ok": bool, ...}`.
  - `context.py` — `ToolContext` (`proxy_port`, `dashboard_port`, `store`, `settings`).
    `is_in_scope(url)` returns False with no settings (safe default). Internal callers pass the
    in-proc `store`; the MCP process reads over the dashboard HTTP API.
  - Six built-in tools, each scope-gated via `ctx.is_in_scope()` BEFORE any request:
    `send_request` (refuses destructive URL/body, offers safe variant), `get_history`,
    `content_discovery`, `param_mining`, `triage_report`, `list_login_profiles` (read-only,
    secret-free; activation NOT exposed).
- `dast/mcp/` — exposes the tool layer over MCP (external Claude Desktop/Code drive a running
  instance). `mcp` imported LAZILY in `run_stdio`; `tool_definitions()` is PURE (unit-testable
  without runtime). Low-level `mcp.server.lowlevel.Server` with `on_list_tools`/`on_call_tool`
  (`isError` from `ok`). Start: `uv run dast-ai mcp` (stdout IS the transport, no banner). Add a
  tool: `register(Tool(...))` in a `dast/tools/*_tools.py`, import it in `__init__.py`.
- MCP liveness badge: the MCP server posts `POST /api/mcp/heartbeat` every 10s (`_heartbeat_loop`
  in `dast/mcp/server.py`); the dashboard tracks `ctx.mcp_last_heartbeat` and serves
  `GET /api/mcp/status` (connected if a heartbeat arrived within 30s). The top-bar `mcp-dot`/
  `mcp-lbl` badge polls it every 10s (`loadMcpStatus` in 80-setup-status-sessions.js). The two
  processes are otherwise decoupled — a down dashboard just makes the heartbeat retry.

### System Logs
- Rolling 500-event buffer in `dast/proxy/plugin_manager._event_log`
- Written by: `log_event(plugin, level, message, url, finding, source)` — call from anywhere
- `source` values: `"plugin"`, `"agent"`, `"browser"`, `"crawler"`
- Visible in Logs tab — 6-column table matching HTTP History layout
- API: `GET /api/logs`, `POST /api/logs/clear`

## Multi-Provider AI Gateway

- All AI calls go through `dast.ai.bedrock_client`. The gateway dispatches to AWS Bedrock
  (default), the Anthropic Messages API, an OpenAI-compatible endpoint, or the internal Claude
  apps gateway based on the active provider. Every request is built Anthropic-shaped and read
  Anthropic-shaped; `dast/ai/providers.py` translates to/from OpenAI so callers and the
  schema-forced tool-use path are provider-agnostic. Select at runtime via
  `bedrock_client.set_provider(provider, keys...)` or `POST /api/scan-config` (`ai_provider`,
  `anthropic_api_key`, `openai_api_key`, `*_base_url`, `gateway_base_url`). Defaults via `.env`
  (see Environment Variables in CLAUDE.md). For non-Bedrock providers `model_id` is a plain
  model name (e.g. `claude-opus-4-8`, `gpt-4o`), not an ARN. API keys are never echoed back by
  `GET /api/scan-config` (only `*_set` booleans).
- Gateway provider (`dast/ai/gateway_auth.py`): the internal Claude apps gateway speaks the
  Anthropic Messages API over an OAuth JWT reused from the Claude Code CLI session (macOS
  Keychain, service `Claude Code-credentials`; or an explicit `GATEWAY_JWT` on Linux/CI). It
  takes NO API key. The gateway pins temperature server-side and forces extended thinking on, so
  `invoke_gateway` strips `temperature` and sends `thinking:{"type":"disabled"}`. The gateway
  hostname is INTERNAL and lives ONLY in `.env` (`GATEWAY_BASE_URL`) — never a code default
  (`config.py` ships an empty string); `scripts/check_no_internal_data.py` blocks any
  `*.internal|corp|private.knowbe4.com` host from tracked files.
- The `/api/ai/status` badge probes the ACTIVE provider (STS for bedrock; API-key presence for
  anthropic/openai; `gateway_auth.credentials_available()` for gateway). The status is cached
  5 min; `POST /api/scan-config` clears that cache on a provider switch so the badge re-probes.

## Dashboard / UI Layout

- Main tabs: Dashboard → Proxy → Discovery → AI → Scan → Plugins → GraphQL → Repeater → Intruder → Logs → Extras
  - Proxy sub-tabs: HTTP history, Intercept, Site map, Issues, Settings (scope rules + Setup/CA cert)
  - Discovery sub-tabs: Manual Browse, Crawl, Content Discovery
  - AI sub-tabs: Suggestions, Settings (provider, model tiers, scan engine, activity log, service graph)
  - Extras sub-tabs: H1 Validator, Code, FedRAMP, Interactions, Decoder, JWT
- Top-bar badges: proxy connection (`ws-dot`), AI status (`ai-dot`), MCP status (`mcp-dot`).
- HTTP history table supports column resize by dragging the border handle on each `<th>`
- Save notifications (sessions, project settings) show the full file path
- Scan engine settings (model, workers, concurrency, confidence threshold) live in AI tab;
  applied at runtime via `POST /api/scan-config`; `GET /api/scan-config` returns current config
- Overview dashboard auto-refreshes every 10 s; also refreshes on tab switch
- Logs tab: filter by source, level, or text; red row tint for findings
- GraphQL tab: fused Schema Explorer + Query Builder (endpoint picker + filterable operation
  list on the left; schema-driven query/variables editor + Send to Repeater/Fuzzer on the
  right; manual re-introspect + manual endpoint add in the same sidebar), plus a Fuzzer
  (variable extraction + payload cross-product, run/poll/stop like Intruder). Explorer and
  Builder were fused because picking an operation and re-running introspection both update the
  same editor pane.
- **Plugin-gated tab pattern**: a top-level tab's visibility can be tied to a plugin's enabled
  state — frontend-only, no backend wiring. `loadPlugins()` calls a `_gql`-prefixed visibility
  helper after fetching `/api/plugins`; called eagerly from `ws.onopen` (not just when the
  Plugins tab is opened) so the tab hides/shows correctly from the first page load. See
  `_gqlTabVisibility()` for the concrete example.

---

## CI Mode (Planned)

```
# Planned CLI usage
uv run dast-ai scan \
  --openapi https://api.example.com/openapi.json \
  --exit-code medium \
  --format sarif \
  --output findings.sarif \
  --mode pr          # pr=fast/fuzzing only | nightly=full AI

# Exit codes
0 = no findings above threshold
1 = findings found at or above threshold
2 = scan error
```

Design:
- `dast ci scan`: no proxy, accepts OpenAPI spec or HAR file as input
- `--mode pr`: deterministic agents only (no LLM planner/validator) — fast, cheap, PR CI
- `--mode nightly`: full AI scan — all agents, full red-team validation
- `--exit-code <severity>`: exit 1 if any finding at or above this level (critical|high|medium|low)
- `--format sarif`: SARIF 2.1.0 output (already implemented in `dast/report/sarif.py`)

GitHub Actions example:
```yaml
- name: DAST Scan
  run: uv run dast-ai scan --openapi ${{ env.API_URL }}/openapi.json --exit-code high --format sarif --output dast.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: dast.sarif
```
