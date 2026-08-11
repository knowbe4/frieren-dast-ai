<div align="center">

<img src="assets/logo.png" alt="Frieren DAST-AI" width="320">

# Frieren DAST-AI

AI-driven Dynamic Application Security Testing tool for security engineers.

</div>

Combines an HTTPS MITM proxy with a multi-agent scanner and a real-time web
dashboard. Route any browser or tool through the proxy — findings appear automatically.

## Maintenance

Maintained and kept up to date by the KnowBe4 InfoSec team. Contributions are welcome —
fork, modify, or extend it however you like. If you fork or redistribute this project,
please credit the official repository: https://github.com/knowbe4/frieren-dast-ai

### Secret-scan guardrails

This is a public repository. To keep internal data out of it, `make setup` installs
git hooks that scan every commit and push:

- **gitleaks** and a repo-specific internal-data guard run on each commit.
- **trufflehog** (verified secrets) runs on push.
- The same checks run server-side in CI (`.github/workflows/secret-scan.yml`).

The hooks require `gitleaks` and `trufflehog` on your PATH — install once with
`brew install gitleaks trufflehog` (gitleaks is also fetched automatically by the
pre-commit framework). Run a full-repo scan any time with `make secrets-scan`.
Never bypass the guards with `git commit --no-verify` — the push guard will still
block the leak, and CI will fail the build.

## How it works

```
Browser / tool (configured to use proxy :8080)
    |
    v
[HTTPS MITM Proxy]         Intercepts all HTTP/HTTPS, TLS termination per host
    |
    v
[Session Store]            Every request/response stored in memory
    |
    +---> [Passive Scanner]    Zero-request checks fire on every response
    |     (YAML rule engine)   47 rules: headers, cookies, CORS, secrets,
    |                          error pages, LLM endpoints, OWASP Top 10
    |
    +---> [Scan Queue]         In-scope entries queued for active scanning
              |
              v
         [Coordinator]         LLM planner → agents → LLM validator
              |
              v
         [VulnAgents]          10 agents run in parallel per endpoint:
              |                xss, sqli, ssrf, file_read, auth_bypass,
              |                secrets, discovery, llm_injection,
              |                business_logic, blazor
              v
         [Findings]            Real-time push to dashboard via WebSocket
```

## Quick start

```bash
# 1. Install deps, Playwright, and create .env from template
make setup

# 2. First time only: create the AWS SSO profile (see "AWS setup" section below)
make sso-configure

# 3. Authenticate (required once per session / when token expires)
make sso

# 4. Start proxy + dashboard
make proxy

# 5. Configure your browser: HTTP proxy → 127.0.0.1:8080
# 6. Install CA cert: http://127.0.0.1:8088/ca.crt  (one-time)
# 7. Dashboard: http://127.0.0.1:8088
```

## Desktop app (Electron)

Prefer a standalone window over a terminal + separate browser? A native Electron
launcher lives in `desktop/`. It is **only a launcher** — it spawns
`uv run dast-ai proxy` as a child process, waits for the dashboard port, and renders
the existing dashboard in a native window with a tray icon. All proxy / MITM /
scan / AI behaviour is identical to running the backend from the terminal.

```bash
# First run only — install Electron deps (~200MB)
make desktop-install

# Launch the native app (spawns the backend automatically)
make desktop

# Port overrides pass through to the backend
make desktop PROXY_PORT=9090 DASHBOARD_PORT=9099
```

Requires Node.js + npm. AWS credentials (`AWS_PROFILE` / `AWS_ACCESS_KEY_ID`) are
inherited from your shell, same as `make proxy`.

### Building a distributable

`electron-builder` produces double-click bundles (portable `.exe` / `.AppImage` need
no install). **Phase 1 caveat:** the packaged app still assumes `uv` + the checked-out
repo are present at runtime — it bundles the launcher, not the Python backend.

```bash
make desktop-dist-mac      # macOS .dmg + .zip
make desktop-dist-win      # Windows portable .exe + NSIS installer
make desktop-dist-linux    # Linux AppImage
```

See [`desktop/README.md`](desktop/README.md) for the Electron-install troubleshooting
and the Phase 2 (self-contained binary) notes.

## Dashboard tabs

| Tab | Description |
|-----|-------------|
| **Dashboard** | Overview: request count, finding counts by severity, agent status, scan engine metrics |
| **Proxy** | HTTP history, request Intercept, Site map, Issues (all findings), and Settings (scope rules, CA cert / Setup) |
| **Discovery** | Manual Browse (headless browser routed through the proxy), Crawl (SPA crawler), Content Discovery (forced browsing), Param Mining (hidden-parameter discovery) |
| **AI** | Suggestions (AI-surfaced findings/recon to review) and Settings (provider, model tiers, scan engine, app context, threat model, activity log, service graph, payload inventory) |
| **Scan** | Live scan queue — pending / running / completed, pause/cancel, replay |
| **Plugins** | Enable/disable passive scanner and other plugins |
| **GraphQL** | Schema Explorer + Query Builder (introspection, operation picker, query/variables editor) and Fuzzer (variable extraction + payload cross-product) |
| **Repeater** | Manually edit and resend captured requests, one tab per request, follow-redirects toggle |
| **Intruder** | Payload-position fuzzing across a request |
| **Logs** | Rolling 500-event system log — agent, plugin, browser, and crawler events |
| **Extras** | H1 Validator, Code (source-aware review), FedRAMP, Interactions (OOB/interactsh), Decoder/Encoder, JWT editor |

## Proxy > Settings

- **Scope rules** — include/exclude by protocol, host, port, path (glob or regex)
- **Bypass domains** — forwarded as-is, not intercepted or recorded
- **Hidden extensions** — filtered from HTTP history (`.js`, `.css`, etc.)
- **Save / Load** — save named setting snapshots; saved path shown in notification
- **Setup** — CA cert download and install instructions, AI engine status

Scan engine settings (workers, probe concurrency, passive/active toggles, LLM
planner/validator toggles) live in the **AI > Settings** sub-tab, applied at
runtime without a restart.

## Agents

Each agent targets one vulnerability class. All run in parallel per endpoint, selected
by the LLM planner based on endpoint characteristics.

| Agent | Checks | Payload file |
|-------|--------|-------------|
| `xss_agent` | Reflected/stored XSS, DOM XSS, bypass variants; Playwright browser confirmation | `xss.yaml` |
| `sqli_agent` | Error-based, boolean-blind, time-based blind SQLi (5 s max) | `sqli.yaml` |
| `ssrf_agent` | OOB HTTP callbacks, internal probes, cloud metadata, sibling-host probing | `ssrf.yaml` |
| `file_read_agent` | Path traversal, LFI, PHP wrappers, null byte injection | `lfi.yaml` |
| `auth_agent` | Auth header stripping, 9 header-based bypass combinations per endpoint | — |
| `secrets_agent` | AWS keys, GitHub/Slack tokens, private keys, JWTs, credit cards | — |
| `discovery_agent` | SSTI, open redirect, CRLF injection, HTTP method tampering | `ssti.yaml` |
| `llm_injection_agent` | Prompt injection, jailbreak, system prompt leakage | `llm_injection.yaml` |
| `business_logic_agent` | Numeric boundary abuse, privilege escalation, workflow bypass, mass assignment | — |
| `blazor_agent` | Blazor WASM assembly enumeration, SignalR hub enumeration, unauthenticated negotiate, circuit exhaustion, exposed debug artefacts | `blazor.yaml` |

## Passive scanner rules

Rules live in `dast/passive_rules/` as YAML files. Adding a new check requires only a
new YAML file — no code changes needed. 62 rules loaded at startup.

```
dast/passive_rules/
├── headers/
│   ├── security_headers.yaml   HSTS, CSP, X-Frame-Options, Referrer-Policy, ...
│   ├── info_disclosure.yaml    Server version, debug mode, X-Powered-By
│   └── cache_control.yaml      Cacheable authenticated responses
├── cookies/
│   └── cookie_flags.yaml       HttpOnly, Secure, SameSite, session cookie severity
├── cors/
│   └── cors.yaml               Wildcard, reflected origin, null origin
├── secrets/
│   └── sensitive_data.yaml     AWS/GitHub/Slack/Stripe keys, JWTs, credit cards
├── injection/
│   └── error_pages.yaml        Stack traces, SQL errors, PHP/ASP.NET error pages
├── ai/
│   └── llm_endpoints.yaml      LLM endpoint detection, injection marker, prompt leak
├── frameworks/
│   └── blazor.yaml             Blazor-specific checks (WASM boot, SignalR, circuit management)
├── http2/
│   └── continuation_flood.yaml HTTP/2 CONTINUATION flood probe
└── discovery/
    ├── directory_listing.yaml
    ├── open_redirect.yaml
    └── clickjacking.yaml
```

## Payload files

Seed payloads are in `dast/payloads/*.yaml`. Edit without touching code. The LLM mutator
generates WAF bypass variants adaptively when probes are blocked.

| File | Coverage |
|------|----------|
| `xss.yaml` | Basic, DOM, obfuscation, bypass, blind |
| `sqli.yaml` | Error-based, boolean-blind, time-based, obfuscation, stacked |
| `ssrf.yaml` | OOB HTTP, IP obfuscation, internal probes (cloud metadata, file://) |
| `lfi.yaml` | Unix/Windows traversal, null byte, PHP wrappers |
| `ssti.yaml` | Detection + obfuscation for Jinja2, Twig, Mako, FreeMarker, Pebble |
| `llm_injection.yaml` | Direct/indirect injection, jailbreak, system prompt leak |
| `cmdi.yaml` | Unix/Windows basic, blind time-based, bypass/obfuscation |
| `xxe.yaml` | File read, OOB DTD, SSRF-via-XXE, parameter entity, CDATA |
| `jwt.yaml` | alg:none, weak secrets, kid injection, jku/jwks header injection |
| `nosql.yaml` | MongoDB operators, JS injection, Elasticsearch, Redis CRLF |
| `prototype_pollution.yaml` | Query string, JSON body, header, detection payloads |
| `blazor.yaml` | Blazor WASM boot endpoints, SignalR negotiate, debug artefacts |

## Service graph

Auto-detects that multiple hosts belong to the same microservice application via shared
JWTs, common parent domain, correlation headers (`X-Trace-ID`, `traceparent`), and
shared session cookie name+value. Agents receive sibling-host context automatically:
SSRF probes target known internal services; auth agent shares tokens across hosts.

Manual merge/split available in the AI tab and via API.

## Sessions

Save the current HTTP history + proxy settings to disk at any time. The save notification
shows the exact file path. Sessions can be loaded, exported as JSON, or deleted from the
Sessions panel.

```
~/.dast-ai/sessions/    Session JSON files
~/.dast-ai/ca.crt       CA certificate (install once in browser/OS trust store)
~/.dast-ai/ca.key       CA private key
```

## AI provider setup

Frieren DAST-AI needs an LLM backend for the coordinator, agents, and red-team validator.
Pick one of three providers via `AI_PROVIDER` in `.env`:

### Option 1 — AWS Bedrock (default)

```bash
# 1. Create an SSO profile — one-time per machine
make sso-configure
#   When prompted, enter your organization's SSO start URL, region, account ID, and role.

# 2. Copy .env.example to .env (make setup does this automatically), then set
#    AWS_PROFILE and the three ANTHROPIC_DEFAULT_*_MODEL ARNs to your own
#    Bedrock application-inference-profile IDs.

# 3. Authenticate — repeat each time the token expires (usually once per day)
make sso
```

### Option 2 — Anthropic API directly

```bash
AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...
AI_MODEL_ID=claude-opus-4-8       # or claude-sonnet-5, claude-haiku-4-5, etc.
```

### Option 3 — OpenAI / OpenAI-compatible (ChatGPT, Codex, local gateways, etc.)

```bash
AI_PROVIDER=openai
OPENAI_API_KEY=sk-...
OPENAI_BASE_URL=https://api.openai.com/v1   # point at any OpenAI-compatible endpoint
AI_MODEL_ID=gpt-4o
```

All three can also be switched at runtime from the AI tab in the dashboard (`POST /api/scan-config`).

### Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `config profile (X) could not be found` | Bedrock profile not created yet | Run `make sso-configure` |
| `AWS_PROFILE is not set` | `.env` missing or `AWS_PROFILE=` empty | Run `make setup`, then edit `.env` |
| `ExpiredTokenException` | Bedrock token expired | Run `make sso` again |
| `Could not connect to Bedrock` | Wrong model ARN | Use your own ARNs, not `us.anthropic.*` cross-region IDs |

## Environment variables

```bash
# AI provider — one of: bedrock (default), anthropic, openai
AI_PROVIDER=bedrock

# Required when AI_PROVIDER=bedrock
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_REGION=us-east-1
AWS_PROFILE=          # SSO profile — credentials auto-refresh on expiry

# Required when AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=

# Required when AI_PROVIDER=openai
OPENAI_API_KEY=
OPENAI_BASE_URL=      # default https://api.openai.com/v1

# Optional — active model (defaults to the Sonnet tier below)
AI_MODEL_ID=

# Ports (can also be set via CLI flags)
PROXY_PORT=8080
DASHBOARD_PORT=8088
PARALLEL_WORKERS=4
```

## Common tasks

```bash
# Install everything (deps + Playwright + .env)
make setup

# AWS SSO login
make sso

# Start proxy + dashboard
make proxy

# Start the native desktop app (Electron launcher)
make desktop-install   # first run only
make desktop

# Start with pre-authenticated session
uv run dast-ai proxy \
  --auth-url https://app.example.com/login \
  --username admin@example.com \
  --password secret

# Run unit tests
make test

# Run integration tests (proxy must be running)
make test-integration

# Run LLM decision-quality evals (opt-in — uses Bedrock, costs tokens)
make evals                        # planner + red-team suites
make evals SUITE=planner          # one suite
make evals MIN_ACCURACY=0.9       # non-zero exit if below threshold

# Verify passive rule count and payload counts
make check

# JS + Python lint
make lint
```

## Known issues

**Playwright not installed**
```bash
uv run playwright install chromium
```

**CA cert not trusted** — download from `http://127.0.0.1:8088/ca.crt` and add to your
browser or OS trust store.

**AWS token expiry** — set `AWS_PROFILE`; credentials auto-refresh on `ExpiredTokenException`.
