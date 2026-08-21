# frieren-dast (Claude Code plugin)

Exposes [Frieren DAST-AI](https://github.com/knowbe4/frieren-dast-ai)'s shared tool
layer to Claude over MCP, so you can drive proxy-based security testing and validate
vulnerabilities from inside Claude Code. Installing this plugin auto-registers the MCP
server — no manual MCP config editing.

The tools bridge to an **already-running Frieren instance**: they send traffic through
its proxy port and read live state via its dashboard API. All tools are scope- and
payload-safety-gated.

## Tools exposed

`send_request`, `get_history`, `content_discovery`, `param_mining`, `triage_report`,
`list_login_profiles` — the exact same registry the internal agentic triage loop uses.

## Prerequisites

- [`uv`](https://docs.astral.sh/uv/) on your PATH (`uvx` ships with it). The plugin runs
  `uvx --from git+https://github.com/knowbe4/frieren-dast-ai dast-ai mcp`, which installs
  and runs the MCP server on demand — you do **not** need the repo cloned.
- A running Frieren instance. In a checkout of the repo:

  ```bash
  uv run dast-ai proxy
  ```

  The MCP server defaults to proxy port `8080` and dashboard port `8088`.

## Install

```bash
/plugin marketplace add knowbe4/frieren-dast-ai
/plugin install frieren-dast@knowbe4-frieren
```

Then start (or confirm) a Frieren proxy is running, and the tools become available to
Claude. Verify the standalone server independently with:

```bash
uvx --from git+https://github.com/knowbe4/frieren-dast-ai dast-ai mcp --help
```

## Using a local checkout instead of uvx

If you already have the repo cloned and want the MCP server to run from it (faster start,
no per-run install), point the plugin's MCP `command` at your checkout by editing
`.claude-plugin/plugin.json`:

```json
"mcpServers": {
  "frieren-dast": {
    "command": "uv",
    "args": ["run", "--directory", "/absolute/path/to/frieren-dast-ai", "dast-ai", "mcp"]
  }
}
```
