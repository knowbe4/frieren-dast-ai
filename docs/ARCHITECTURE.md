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
