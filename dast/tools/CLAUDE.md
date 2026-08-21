# `dast/tools/` — Shared Tool Layer + MCP conventions

This is the SINGLE source of truth for agent-callable capabilities. One `Tool` definition drives
two callers — the internal agentic triage loop (in-process) and the external MCP server
(`dast-ai mcp`, separate process) — so a capability can never drift between them. Read this
before adding or changing a tool. Architecture context: see the "Shared Tool Layer + MCP Server"
section in [../../docs/ARCHITECTURE.md](../../docs/ARCHITECTURE.md).

## Layout

- `base.py` — `Tool` dataclass + `_REGISTRY`; `register`/`get_tool`/`all_tools`/`run_tool`.
- `context.py` — `ToolContext` (`proxy_port`, `dashboard_port`, `store`, `settings`).
- `<capability>_tools.py` — one file per capability group (`http_`, `history_`, `recon_`,
  `triage_`, `profile_`). Each ends with `register(Tool(...))` calls.
- `__init__.py` — imports every `*_tools` module for its registration side effect.

## How to add a tool

1. Create `dast/tools/<name>_tools.py`.
2. Define a JSON Schema for the arguments (`type: object`, `properties`, `required`).
3. Write an `async def _handler(ctx: ToolContext, args: dict) -> dict`.
4. `register(Tool(name=..., description=..., input_schema=..., handler=_handler, tags=[...]))`.
5. Import the new module in `__init__.py`. It is now advertised over MCP automatically.
6. Add/extend a test in `tests/unit/test_tools_registry.py`.

```python
async def _handler(ctx: ToolContext, args: dict) -> dict:
    url = str(args.get("url", "")).strip()
    if not url:
        return {"ok": False, "error": "url is required"}
    if not ctx.is_in_scope(url):                      # scope gate BEFORE any request
        return {"ok": False, "error": "url is out of scope", "url": url}
    try:
        ...                                           # do the work
        return {"ok": True, "count": len(hits), "hits": hits}
    except Exception as exc:                          # never raise out of a handler
        return {"ok": False, "error": f"failed: {str(exc)[:200]}"}

register(Tool(name="my_tool", description="...", input_schema=_SCHEMA,
              handler=_handler, tags=["recon"]))
```

## Non-negotiable conventions

- **Every handler returns `{"ok": bool, ...}`.** `run_tool` NEVER raises — an unknown tool or a
  handler exception both degrade to `{"ok": False, "error": ...}`. Catch inside the handler and
  return the error; do not let it propagate.
- **Scope-gate before any outbound request:** call `ctx.is_in_scope(url)` FIRST and refuse
  out-of-scope URLs. With no loadable settings, `is_in_scope` returns False (safe default) — an
  external MCP caller must have loadable scope rules to send anything.
- **Payload safety for anything that mutates:** a send-style tool must refuse destructive URL/body
  via `payload_safety.classify` and offer the safe variant (see `http_tools.send_request`).
- **Dual data path:** read `ctx.store` when present (fast, in-process); otherwise fall back to the
  dashboard HTTP API via `ctx.dashboard_base_url`. The MCP process has no in-proc store.
- **Keep handlers thin.** Wrap an existing scanner/engine in `dast/scanners/`, `dast/hackerone/`,
  etc. — never reimplement scanning logic here. The tool layer is an adapter, not a home for
  new detection code.
- **Descriptions are prompts.** The `description` and each schema field `description` are what an
  LLM sees to decide when/how to call the tool. Write them for that reader: state what it does,
  what it needs, and what it returns.

## When to add a tool (vs. not)

Add a tool when the capability is a **discrete, reusable primitive** an agent (internal or
external) would choose to invoke: send a request, read history, run recon, triage a report. Good
tools are idempotent-ish, well-scoped, and safe to expose.

Do NOT add a tool for:
- **Multi-step orchestration** — that's the coordinator's / agent's job. Tools are primitives the
  planner composes, not workflows.
- **State-changing admin actions** — e.g. activating a login profile is intentionally NOT exposed
  (`list_login_profiles` is read-only and secret-free via `to_public_dict()`). Anything that
  changes server state or handles secrets stays off the tool layer unless there's a clear reason.
- **One-off internal helpers** — if only one call site needs it and it's not a capability an agent
  would pick, keep it a plain function in its own module.

## When to expose over MCP (vs. keep internal-only)

Everything in this registry is advertised over MCP by construction — that's the point (one
definition, two callers). So the decision is really "should this be a registered tool at all",
governed by the rules above. If a capability must be internal-only, it should NOT live here as a
`Tool`; keep it as a normal function the coordinator calls directly. Do not add an "internal-only"
flag to the registry — the value of this layer is that internal and MCP callers stay identical.

## MCP server

`dast/mcp/server.py` bridges the registry to the Model Context Protocol. `mcp` is imported LAZILY
inside `run_stdio` so core never depends on it; `tool_definitions()` is PURE (no `mcp` import) and
unit-testable. Start with `uv run dast-ai mcp` — stdout IS the transport, so there is no console
banner. The server posts a liveness heartbeat to the dashboard so its UI can show an MCP-connected
badge (`/api/mcp/heartbeat` → `/api/mcp/status` → top-bar `mcp-dot`).

## Verify

```bash
uv run pytest tests/unit/test_tools_registry.py
uv run dast-ai mcp --help
```
