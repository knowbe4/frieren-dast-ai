# Frieren DAST-AI — Claude Code Instructions

> Deep architecture and per-feature wiring live in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
> This file is only the conventions and gotchas you can't infer from the code. Keep it lean —
> if a rule is already followed without it, delete the rule.

## What This Is

Frieren DAST-AI is a proxy + AI-driven scanner: HTTPS MITM proxy + real-time dashboard
(FastAPI + WebSocket), a multi-agent scanner (canary pre-probe → LLM Coordinator → parallel
VulnAgents → Red-Team Validator), tech-stack-aware payload filtering, and a data-driven passive
scanner. Primary users: security engineers running active DAST via proxy interception.

**The bar:** find real, exploitable vulnerabilities — highest true-positive rate, lowest
false-positive rate. A finding must survive the full pipeline (agent detection → LLM validation,
or deterministic evidence) before reaching the dashboard. A false positive that wastes a
developer's time is a failure. Evaluate every change against: does this make the tool smarter,
more accurate, or easier to use? If not, don't add it.

---

## Code Style (enforceable rules)

1. **All code, comments, and docs in English** — no Portuguese.
2. **No emojis** in code or documentation.
3. **Type hints** on all function signatures.
4. **Descriptive variable names** — no abbreviations.
5. **Error handling** — log and continue; never crash the scan on one endpoint. Never swallow
   exceptions silently (`except Exception: pass`) — always log them with `error=str(exc)`.
6. **Modularity first** — keep modules small and single-responsibility. Never bolt a feature onto
   an existing module when it belongs in a new one. Complexity stays local; cross-module coupling
   is explicit and minimal.
7. **Understand before acting** — agents, plugins, and LLM prompts must read the actual
   request/response context before testing. Never infer a vuln category from the URL path alone;
   use params, body, headers, and response content as evidence. Spamming payloads without
   understanding the endpoint is noise, not signal.
8. **Logging everywhere** — every module has `logger = get_logger(__name__)`. `debug` = probe
   attempts/payload choices (high volume); `info` = agent/scan lifecycle, session load/save,
   findings; `warning` = recoverable errors, LLM failures, FP-filter hits; `error` =
   unrecoverable/aborting exceptions.

## Package Manager — ALWAYS use uv

```bash
uv run dast-ai proxy          # start proxy + dashboard
uv run pytest
```
Never use `python3` directly. Never activate a venv manually.

---

## Extension Recipes (how to add X — no code changes beyond the drop-in)

**Agent vs Plugin — which do I write?** The `dast/agents/` and `dast/plugins/` folders stay
flat and are two different extension points, not a category split:
- **Agent** (`dast/agents/*_agent.py`) — an AI-coordinated *active* vuln probe. Subclasses
  `VulnAgent`, is `Coordinator.register()`-ed and imported in `agents/__init__.py` (explicit
  discovery), runs inside the scan pipeline, injects payloads, and needs the full
  request/response context. Files here that are *not* agents (`block_detector.py`,
  `payload_filter.py`, `probe_diff.py`) are shared agent infrastructure — they intentionally
  omit the `_agent` suffix; do not add new non-agent modules here without that reason.
- **Plugin** (`dast/plugins/*.py`) — a proxy-lifecycle hook. Subclasses `ProxyPlugin`
  (`dast/proxy/plugin_base.py`), auto-discovered by `glob("*.py")` over `dast/plugins/` and
  `~/.dast-ai/plugins/` (drop-a-file, no registration), and driven by `on_entry()` (passive) or
  `on_active_probe()` (active). Filename is free-form (descriptive noun); discovery is by class,
  not name — but note several plugins are imported by module name elsewhere, so renaming an
  existing one means updating those call sites.

Rule of thumb: needs the coordinator/LLM plan and payload filtering → agent; reacts to raw
proxy traffic on every entry → plugin.

- **Vuln agent** — new file in `dast/agents/` subclassing `VulnAgent`; call
  `get_filtered_payloads(attack_type, target)` (not `get_payloads()` directly); load extra
  payloads from `dast/payloads/*.yaml` via `loader.py`; `Coordinator.register(YourAgent)` at the
  bottom; import in `dast/agents/__init__.py`. Safety: no destructive payloads; SLEEP/WAITFOR
  ≤ 5s; detection only. Auth agent: use `urlparse(target.url).path`, never hardcoded paths.
- **Mutator-using agent** — build `tech_context` via `mutator.build_mutator_context(target,
  attack_type)`, record blocks with `block_detector.detect_block()` → `observe("waf_block")`,
  and emit `observe("waf_bypass")` when a payload lands after a prior block (see WAF Bypass in
  ARCHITECTURE.md).
- **Payloads** — add/edit `dast/payloads/*.yaml`; read via `get_payloads`/`get_all_payloads`/
  `get_detection_payloads` from `dast/payloads/loader.py`; document intent in the YAML.
- **Passive rule** — add a `.yaml` anywhere under `dast/passive_rules/` (auto-discovered). Schema
  in ARCHITECTURE.md. `one_per_host: true` avoids per-request noise; `needs_ai_validation: true`
  routes through the LLM before storing.
- **Content-discovery wordlist** — drop `dast/wordlists/<name>.txt`; load via
  `load_wordlist("<name>")`.
- **Vuln-knowledge class** — drop `dast/vuln_knowledge/<attack_type>.yaml` (positive + negative
  few-shot examples). Auto-discovered; consumed by red_team + mutator.
- **Agent-callable tool / MCP tool** — see [`dast/tools/CLAUDE.md`](dast/tools/CLAUDE.md).
- **Scope preset** — drop `dast/scope_presets/<slug>.json` (gitignored). Auto-discovered.

## Mutation Loop

- The LLM mutator decides when to stop (`action: "stop"`) — do not add fixed iteration limits.
- Safety ceiling: 15 rounds per parameter (guards against bugs, not normal use).
- Always pass `tried_payloads` to `next_payload()` so the LLM avoids repeats.

## AI Calls (hard rules)

- All AI calls go through `dast.ai.bedrock_client` — never call boto3/providers directly.
  `invoke_json()` for structured output, `invoke()` for free text. Multi-provider details
  (bedrock/anthropic/openai/gateway) are in ARCHITECTURE.md → Multi-Provider AI Gateway.
- Prefer schema-forced output: pass `schema=` (a JSON Schema from `dast/ai/schemas.py`) to
  `invoke_json()` — the model is forced through a tool call, so malformed JSON is impossible.
- `temperature=0` for deterministic decisions (planner, baseline, red-team); omit for the mutator
  (payload diversity). Pass `cache_system=True` for large static system prompts.
- Never hardcode a model — use `get_fast_model()`/`get_validation_model()` or the `model_id` param.
- Always fence untrusted target content with `prompt_safety.wrap_untrusted(content, tag)` and
  append `UNTRUSTED_CONTENT_DIRECTIVE` to the system prompt (structural prompt-injection defense).
- Always catch AI exceptions and degrade gracefully.

---

## Feature Reference (detail → ARCHITECTURE.md; verify commands here)

| Subsystem | Verify command |
|-----------|----------------|
| Passive rules | `uv run python -c "from dast.plugins.passive_scanner import _load_all_rules; print(len(_load_all_rules()), 'rules')"` |
| Payload counts | `uv run python -c "from dast.payloads.loader import _load; [print(f, sum(len(v) for v in _load(f+'.yaml').get('payloads',{}).values())) for f in ['xss','sqli','ssrf','lfi','ssti','llm_injection','cmdi','xxe','jwt','nosql','prototype_pollution','graphql']]"` |
| Content-discovery wordlists | `uv run python -c "from dast.wordlists.loader import load_wordlist, known_wordlists; print(known_wordlists(), [len(load_wordlist(n)) for n in known_wordlists()])"` |
| Param mining | `uv run pytest tests/unit/test_param_miner.py tests/unit/test_coordinator_param_mining.py` |
| Probe-diffing | `uv run pytest tests/unit/test_probe_diff.py tests/unit/test_probe_classifier.py` |
| Cache poisoning | `uv run pytest tests/unit/test_cache_poisoning_agent.py` |
| JWT editor route | `uv run pytest tests/unit/test_jwt_routes.py` |
| Vuln knowledge | `uv run python -c "from dast.vuln_knowledge import known_attack_types; print(known_attack_types())"` |
| H1 triage engine | `uv run pytest tests/unit/test_h1_parser.py tests/unit/test_h1_validator_http.py tests/unit/test_h1_validator_xss.py` |
| Tool layer / MCP | `uv run pytest tests/unit/test_tools_registry.py`; `uv run dast-ai mcp --help` |

---

## Common Tasks

```bash
uv sync                                   # install deps
uv run playwright install chromium        # install browsers
uv run dast-ai proxy                      # start proxy + dashboard
uv run dast-ai proxy --auth-url https://app.example.com/login --username admin@example.com --password secret
uv run pytest
make bump-version VERSION=0.9.0           # bump version everywhere it's hardcoded (never hand-edit — it drifts)
make desktop-test                         # desktop launcher e2e (real Electron + backend)
```

## Key Files

- `dast/proxy/runner.py` — starts proxy + dashboard + scan worker
- `dast/proxy/session_store.py` — intercepted entries, cookie jar, service graph
- `dast/proxy/dashboard_server.py` — FastAPI app assembly + router wiring (routes live in
  `dast/proxy/api/*_routes.py`); UI is external static files in `dast/proxy/ui/`
- `dast/ai/coordinator.py` — LLM coordinator (canary + planner + validator dispatch)
- `dast/ai/red_team.py` / `fp_filter.py` — Red-Team Validator + deterministic FP rules
- `dast/ai/mutator.py` — adaptive payload mutator
- `dast/ai/bedrock_client.py` — single LLM gateway (schema-forced, tiered models, prompt caching)
- `dast/ai/providers.py` / `gateway_auth.py` — non-Bedrock adapters + Claude apps gateway auth
- `dast/ai/schemas.py` — JSON Schemas for structured LLM output
- `dast/ai/prompt_safety.py` — structural prompt-injection defense
- `dast/agents/*.py` — vulnerability agents; `payload_filter.py` = tech-aware group selector
- `dast/tools/` — shared tool registry (one definition drives internal agents AND MCP)
- `dast/mcp/server.py` — MCP stdio server bridging the tool registry
- `dast/payloads/*.yaml`, `dast/wordlists/*.txt`, `dast/passive_rules/**/*.yaml`,
  `dast/vuln_knowledge/*.yaml` — data-driven assets (edit to extend behavior)
- `dast/report/sarif.py` — SARIF 2.1.0 export
- `tests/evals/` — opt-in LLM decision-quality harness (not in default pytest)

### Session Output
```
~/.dast-ai/sessions/   Session JSON (path shown in save notification)
~/.dast-ai/projects/   Named proxy settings snapshots
~/.dast-ai/logs/       proxy_YYYYMMDD_HHMMSS.log for post-mortem debugging
~/.dast-ai/ca.crt      CA certificate (install once in browser/OS trust store)
~/.dast-ai/ca.key      CA private key
```

---

## Environment Variables

```bash
AI_PROVIDER=bedrock            # one of: bedrock (default), anthropic, openai, gateway

# bedrock
AWS_ACCESS_KEY_ID=  AWS_SECRET_ACCESS_KEY=  AWS_REGION=us-east-1
AWS_PROFILE=                   # optional; auto-refreshes on ExpiredTokenException

# anthropic
ANTHROPIC_API_KEY=  ANTHROPIC_BASE_URL=   # default https://api.anthropic.com

# openai (base_url also targets any OpenAI-compatible gateway)
OPENAI_API_KEY=  OPENAI_BASE_URL=         # default https://api.openai.com/v1

# gateway (internal Claude apps gateway; no API key — reuses Claude Code CLI OAuth session).
# GATEWAY_BASE_URL is an INTERNAL hostname: set it in .env only, NEVER in code.
GATEWAY_BASE_URL=              # internal gateway URL (no default)
GATEWAY_JWT=                   # Linux/CI only: explicit bearer JWT (no Keychain)
GATEWAY_KEYCHAIN_SERVICE=      # override CLI Keychain service (default "Claude Code-credentials")

AI_MODEL_ID=                   # bedrock: an ARN; anthropic/openai/gateway: a model name
PROXY_PORT=8080  DASHBOARD_PORT=8088  PARALLEL_WORKERS=4
```

## AWS Bedrock Model ARNs

Application-inference-profile ARNs are account-specific — replace the account/profile IDs with
your own. Never use cross-region inference IDs like `us.anthropic.claude-*`.

| Model  | ARN |
|--------|-----|
| Haiku  | `arn:aws:bedrock:us-east-1:YOUR_ACCOUNT_ID:application-inference-profile/YOUR_HAIKU_PROFILE_ID` |
| Opus   | `arn:aws:bedrock:us-east-1:YOUR_ACCOUNT_ID:application-inference-profile/YOUR_OPUS_PROFILE_ID` |
| Sonnet | `arn:aws:bedrock:us-east-1:YOUR_ACCOUNT_ID:application-inference-profile/YOUR_SONNET_PROFILE_ID` |

Tiered helpers: `get_fast_model()` (planning/baseline, default Haiku), `get_validation_model()`
(red-team, default Opus), `set_tiered_models(fast, validation)` (called by `/api/scan-config`).

---

## Known Issues

- **Playwright not installed** → `uv run playwright install chromium`
- **CA cert not trusted** → download `http://127.0.0.1:8088/ca.crt`, install in browser/OS trust store
- **AWS token expiry** → set `AWS_PROFILE`; credentials auto-refresh on `ExpiredTokenException`

---

**Last Updated:** 2026-08-14 · **Version:** 0.8.2
