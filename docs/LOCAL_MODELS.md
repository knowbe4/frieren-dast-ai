# Running Frieren against a local LLM (Qwen example)

Frieren's AI layer is pluggable: every LLM call goes through `dast.ai.bedrock_client`, which
dispatches to AWS Bedrock, the Anthropic API, the internal gateway, or **any OpenAI-compatible
endpoint** (`dast/ai/providers.py`). A local model server — Ollama, vLLM, LM Studio, or
`llama.cpp` — exposes exactly that OpenAI-compatible surface, so you point Frieren at it with the
`openai` provider. No code changes are needed.

This guide uses **Qwen2.5-Instruct** as the worked example, but the same steps apply to any local
model your server can serve.

---

## Before you start — three hard requirements

Frieren is not a chatbot; it drives an agentic scanner. Two of these are the difference between
"it works" and "every scan silently degrades", so read them first.

1. **The model must support tool calling with forced `tool_choice`.**
   Frieren gets structured decisions from the model by forcing a single function call
   (`invoke_json` → OpenAI `tools` + `tool_choice: {type: "function"}`; see
   `providers.py:_to_openai_request`). If the server or model can't honor a *forced named* tool
   call, the coordinator, canary, and red-team validator all fail. Use an instruct model with
   native tool support (Qwen2.5-Instruct qualifies) and a server configured to force tool calls
   (see the vLLM notes below — it is the most reliable for this).

2. **`OPENAI_API_KEY` must be non-empty — even though local servers ignore it.**
   `invoke_openai` and the dashboard's AI-reachability check both treat an empty key as "provider
   not configured" (`bedrock_client.provider_api_key_present`). Local servers don't validate the
   key, so set any placeholder (e.g. `local`, `ollama`). Leaving it blank shows AI as disabled.

3. **Model capability drives the false-positive rate.**
   The Red-Team Validator is Frieren's main false-positive guard, and it is only as good as the
   model behind it. A small model produces weak plans and unreliable verdicts — more noise, the
   opposite of the project's goal. Prefer **≥ 14B instruct** (32B is noticeably better); treat 7B
   as smoke-test only.

---

## `.env` — the four settings that matter

```bash
AI_PROVIDER=openai
OPENAI_BASE_URL=http://localhost:11434/v1   # your server's OpenAI base (see per-server values)
OPENAI_API_KEY=local                        # any non-empty value; local servers ignore it
AI_MODEL_ID=qwen2.5:14b                      # the model NAME your server exposes (never an ARN)
```

- `OPENAI_BASE_URL` is the base to which Frieren appends `/chat/completions` and `/models`, so it
  must end at the `/v1`-style root, **not** include `/chat/completions`.
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
| Dashboard shows AI disabled; logs mention no API key | `OPENAI_API_KEY` is empty | Set any non-empty placeholder (`local`, `ollama`) |
| `No model configured for AI provider 'openai' ... Bedrock ARN cannot be used` | `AI_MODEL_ID` unset or an ARN | Set `AI_MODEL_ID` to the local model name |
| `OpenAI API 400 ... tool_choice` / model "does not support tools" | Server/model can't force a tool call | Use a tool-capable instruct model (Qwen2.5-Instruct) and enable tool calling (vLLM: `--enable-auto-tool-choice --tool-call-parser hermes`; update Ollama) |
| Structured decisions come back empty or malformed | Model too small/weak for forced JSON | Use ≥ 14B instruct; prefer vLLM's forced `tool_choice` |
| `Connection refused` / timeouts | Server not running or wrong port | Start the server; match `OPENAI_BASE_URL` host:port exactly |
| Scans are slow | Local model + hardware throughput | Use a smaller `fast_model_id` for planning; keep the larger model for validation |

---

See also: **AI provider setup** in [../README.md](../README.md) and **Multi-Provider AI Gateway**
in [ARCHITECTURE.md](ARCHITECTURE.md).
