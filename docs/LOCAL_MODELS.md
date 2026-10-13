# Running Frieren against a local LLM (Qwen example)

Frieren's AI layer is pluggable: every LLM call goes through `dast.ai.bedrock_client`, which
dispatches to AWS Bedrock, the Anthropic API, the internal gateway, or **any OpenAI-compatible
endpoint** (`dast/ai/providers.py`). A local model server — Ollama, vLLM, LM Studio, or
`llama.cpp` — exposes exactly that OpenAI-compatible surface, so you point Frieren at it with the
`openai` provider. No code changes are needed.

This guide uses **Qwen2.5-Instruct** as the worked example, but the same steps apply to any local
model your server can serve.

---

## Reality check — local is for development, not real scans

Running locally is **slow and far less accurate** than a frontier model (Bedrock / the internal
gateway / Opus). Set expectations before you invest time:

- **Slow.** A single scan is dozens of LLM calls (planner, canary, per-agent payload decisions,
  mutator rounds, red-team validation). On consumer hardware each call is seconds, so one endpoint
  takes **minutes**, and the coordinator will frequently hit its per-endpoint time budget and give
  up before finishing. A full target sweep that is minutes on Opus can be hours locally.
- **Low recall.** Frieren's whole value is a high true-positive, low false-positive rate, and that
  is driven by model reasoning. Small local models miss real vulns and misjudge exploitability.
  Measured example: **`qwen2.5:7b-instruct` on an M3/16GB scored 0% recall** on the Juice Shop
  live bench (`tests/live/ground_truth/juiceshop.yaml`) — it found none of the planted SQLi / XSS /
  NoSQL / open-redirect. A ≥ 14B model does better but still trails a frontier model.
- **Flaky structured output (mitigated).** Local servers often ignore a forced `tool_choice` and
  write the call out as text. Frieren now requests `json_schema` constrained decoding from local
  servers and unwraps calls written as text — see **Built-in local tuning** below.

**Use local for:** running the pipeline end-to-end without cloud credentials, developing/debugging
agents and plugins, and CI-style smoke tests. **Use a frontier model for:** any run where the
findings matter. The `.env` keeps both configs side by side so you can switch providers in seconds.

---

## Before you start — two hard requirements

Frieren is not a chatbot; it drives an agentic scanner. These are the difference between
"it works" and "every scan silently degrades", so read them first.

1. **The model must support tool calling with forced `tool_choice`.**
   Frieren gets structured decisions from the model by forcing a single function call
   (`invoke_json` → OpenAI `tools` + `tool_choice: {type: "function"}`; see
   `providers.py:_to_openai_request`). If the server or model can't honor a *forced named* tool
   call, the coordinator, canary, and red-team validator all fail. Use an instruct model with
   native tool support (Qwen2.5-Instruct qualifies) and a server configured to force tool calls
   (see the vLLM notes below — it is the most reliable for this).

2. **Model capability drives the false-positive rate.**
   The Red-Team Validator is Frieren's main false-positive guard, and it is only as good as the
   model behind it. A small model produces weak plans and unreliable verdicts — more noise, the
   opposite of the project's goal. Prefer **≥ 14B instruct** (32B is noticeably better); treat 7B
   as smoke-test only.

---

## `.env` — the four settings that matter

```bash
AI_PROVIDER=openai
OPENAI_BASE_URL=http://localhost:11434/v1   # your server's OpenAI base (see per-server values)
OPENAI_API_KEY=                             # optional for a local base_url; required only for api.openai.com
AI_MODEL_ID=qwen2.5:14b                      # the model NAME your server exposes (never an ARN)
```

- `OPENAI_BASE_URL` is the base to which Frieren appends `/chat/completions` and `/models`, so it
  must end at the `/v1`-style root, **not** include `/chat/completions`.
- `OPENAI_API_KEY` can be left blank when `OPENAI_BASE_URL` is not the public OpenAI API: Frieren
  detects the non-`api.openai.com` host and sends a placeholder bearer token, which local servers
  ignore. A real key is required only when targeting `api.openai.com`. (If your local server *does*
  enforce a token, set it here and it is used verbatim.)
- `AI_MODEL_ID` is a plain model name for the `openai` provider. It must **not** be a Bedrock ARN —
  if it is (or is left unset, which defaults to the Bedrock Sonnet placeholder), Frieren fails loud
  with `No model configured for AI provider 'openai'` rather than silently misbehaving.

You can also set all of this at runtime from the dashboard **AI → Settings** tab, which calls
`POST /api/scan-config` (`ai_provider`, `openai_api_key`, `openai_base_url`, `model_id`). API keys
are never echoed back — `GET /api/scan-config` returns only `*_set` booleans.

---

## Option A — Ollama (easiest)

```bash
# 1. Install Ollama (https://ollama.com), then pull a tool-capable instruct model.
ollama pull qwen2.5:14b        # or qwen2.5:7b for a smoke test, qwen2.5:32b for better quality

# 2. Ollama serves an OpenAI-compatible API on port 11434 by default.
#    Confirm the model is listed:
curl -s http://localhost:11434/v1/models | grep -o '"id":"[^"]*"'
```

`.env`:

```bash
AI_PROVIDER=openai
OPENAI_BASE_URL=http://localhost:11434/v1
OPENAI_API_KEY=ollama
AI_MODEL_ID=qwen2.5:14b
```

Use a recent Ollama build — support for forcing a specific tool call (`tool_choice`) was added
relatively late. If forced structured calls fail on your version (see Troubleshooting), switch to
vLLM, which handles this reliably.

---

## Option B — vLLM (most reliable tool calling)

vLLM exposes forced `tool_choice` cleanly, which is the exact mechanism Frieren depends on, so it
is the recommended backend for real scans.

```bash
# GPU host. Serve Qwen with tool calling enabled (Qwen uses the hermes tool parser).
vllm serve Qwen/Qwen2.5-14B-Instruct \
  --enable-auto-tool-choice \
  --tool-call-parser hermes
# Defaults to port 8000, OpenAI-compatible at /v1.
```

`.env`:

```bash
AI_PROVIDER=openai
OPENAI_BASE_URL=http://localhost:8000/v1
OPENAI_API_KEY=local
AI_MODEL_ID=Qwen/Qwen2.5-14B-Instruct
```

---

## Option C — LM Studio / llama.cpp

Both expose an OpenAI-compatible server:

- **LM Studio** — load a Qwen2.5-Instruct GGUF, start the local server (default
  `http://localhost:1234/v1`), and set `AI_MODEL_ID` to the model identifier LM Studio shows.
- **`llama.cpp`** — `llama-server -m qwen2.5-14b-instruct.gguf --port 8080` →
  `OPENAI_BASE_URL=http://localhost:8080/v1`.

Tool-calling support varies by build and model quant; verify it before trusting scan results.

---

## Tiered models (fast vs. validation)

Frieren uses two tiers: a **fast** model (planning, canary, baseline) and a **validation** model
(red-team exploit proof). Their defaults are Bedrock ARNs, which are ignored under a non-Bedrock
provider — so with only `AI_MODEL_ID` set, **both tiers use that one local model** (a safe
fallback; see `bedrock_client._usable_tier_model`).

To split the work across two local models — a small fast one and a larger validator — pull both on
your server and set the tiers at runtime:

```bash
curl -s http://127.0.0.1:8088/api/scan-config -H 'Content-Type: application/json' -d '{
  "ai_provider": "openai",
  "openai_base_url": "http://localhost:11434/v1",
  "openai_api_key": "ollama",
  "model_id": "qwen2.5:32b",
  "fast_model_id": "qwen2.5:7b",
  "validation_model_id": "qwen2.5:32b"
}'
```

The tiers can also be set at boot through the tier defaults in `.env` (plain model names):

```bash
ANTHROPIC_DEFAULT_HAIKU_MODEL=qwen2.5:3b          # fast tier: planner, baseline, classifiers
ANTHROPIC_DEFAULT_OPUS_MODEL=qwen2.5-coder:14b    # validation tier: red-team verdicts
AI_MODEL_ID=qwen2.5-coder:14b                     # active model: payload generation / mutation
```

On a 16 GB Mac a 3B + 14B pair (~11 GB) stays resident in Ollama at once; two mid-size models do
not and Ollama swaps them on every call.

---

## Built-in local tuning

When `AI_PROVIDER=openai` points at a non-public host, Frieren treats it as a local server and
adapts automatically:

| Behaviour | Why | Override |
|-----------|-----|----------|
| Structured output uses `response_format: json_schema` (constrained decoding) instead of a forced tool call; falls back to the tool call if the server rejects it | Ollama + Qwen ignore a forced `tool_choice` and write the call out as text; the grammar guarantees schema-valid JSON and enum values | `OPENAI_STRUCTURED_OUTPUT=auto\|tools\|json_schema` |
| At most **1** concurrent LLM call | One GPU serves one request at a time; parallel agent calls only queue server-side and time out | `AI_MAX_CONCURRENCY=<n>` |
| 180 s read timeout (60 s for cloud) | A 14B model can take over a minute to prefill a large prompt | — |
| Adaptive per-endpoint budget × 4 | Budgets tuned for cloud latency expire before agents send real payloads | capped by **Scan Budget per Endpoint** |

The **Scan Budget per Endpoint** setting (AI tab, `scan_budget_seconds`) is the hard ceiling for
every scan. For local runs raise it and keep scanning serial:

```bash
curl -s http://127.0.0.1:8088/api/scan-config -H 'Content-Type: application/json' \
  -H 'Origin: http://127.0.0.1:8088' \
  -d '{"workers": 1, "probe_concurrency": 2, "scan_budget_seconds": 900, "ai_response_cache": true}'
```

---

## Verify it works

```bash
# 1. The server is up and lists your model.
curl -s -o /dev/null -w "models: %{http_code}\n" http://localhost:11434/v1/models

# 2. Start Frieren and confirm AI is enabled for the active provider.
uv run dast-ai proxy
#    Then, in another shell (safe fields only — no secrets in this response):
curl -s http://127.0.0.1:8088/api/status | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print('ai_enabled:', d.get('ai_enabled'), '| error:', bool(d.get('ai_error')))"
```

`ai_enabled: True` with no error means the provider, key, and model resolved. Then run a small scan
through the proxy and check that findings come back with validation badges — the end-to-end signal
that the local model is driving the pipeline correctly.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Dashboard shows AI disabled; logs mention no API key | `OPENAI_API_KEY` is empty **and** `OPENAI_BASE_URL` still points at `api.openai.com` | Point `OPENAI_BASE_URL` at your local server (any non-`api.openai.com` host makes the key optional), or set a real key for the public API |
| `No model configured for AI provider 'openai' ... Bedrock ARN cannot be used` | `AI_MODEL_ID` unset or an ARN | Set `AI_MODEL_ID` to the local model name |
| `OpenAI API 400 ... tool_choice` / model "does not support tools" | Server/model can't force a tool call | Use a tool-capable instruct model (Qwen2.5-Instruct) and enable tool calling (vLLM: `--enable-auto-tool-choice --tool-call-parser hermes`; update Ollama) |
| Structured decisions come back empty or malformed | Model too small/weak for forced JSON | Use ≥ 14B instruct; prefer vLLM's forced `tool_choice` |
| `Connection refused` / timeouts | Server not running or wrong port | Start the server; match `OPENAI_BASE_URL` host:port exactly |
| Scans are slow | Local model + hardware throughput | Use a smaller `fast_model_id` for planning; keep the larger model for validation |

---

See also: **AI provider setup** in [../README.md](../README.md) and **Multi-Provider AI Gateway**
in [ARCHITECTURE.md](ARCHITECTURE.md).
