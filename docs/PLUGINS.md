# Frieren DAST-AI Plugin Guide

Plugins run after every request/response is recorded by the proxy. They can
inspect traffic, extract data, and attach findings that appear in the dashboard.

## Quick start

1. Copy `dast/plugins/hello_world.py` to `~/.dast-ai/plugins/my_plugin.py`
2. Rename the class and fill in the metadata
3. Restart the proxy — your plugin appears in the **Plugins** tab

## Minimal example

```python
from dast.proxy.plugin_base import ProxyPlugin

class MyPlugin(ProxyPlugin):
    name        = "my-plugin"
    description = "What this plugin does"
    version     = "1.0.0"
    author      = "Your name"
    enabled     = True

    async def on_entry(self, entry, store) -> None:
        # entry.method, entry.url, entry.path, entry.host
        # entry.request_headers, entry.request_body
        # entry.response_status, entry.response_headers, entry.response_body
        # entry.content_type, entry.duration_ms, entry.source ("proxy" | "crawler")

        if "interesting" in (entry.response_body or b"").decode("utf-8", errors="replace"):
            store.add_finding(
                entry.id,
                {
                    "title": "Interesting keyword found",
                    "severity": "low",           # critical | high | medium | low | informational
                    "attack_type": "my-plugin",
                    "confidence": 0.8,           # 0.0 – 1.0
                    "evidence": "Found 'interesting' in response body",
                    "confirmed": False,
                },
                "safe",                          # "vulnerable" | "safe" | "error"
            )
```

## Lifecycle hooks

| Method | When called |
|--------|-------------|
| `setup()` | Once at proxy start |
| `on_entry(entry, store)` | After every request/response pair |
| `teardown()` | Once at proxy stop |

## File locations

| Location | Purpose |
|----------|---------|
| `dast/plugins/` | Built-in plugins (shipped with Frieren DAST-AI) |
| `~/.dast-ai/plugins/` | Your custom plugins (not overwritten on update) |

## Tips

- Files starting with `_` are ignored
- Multiple plugin classes per file are supported
- `enabled = False` loads the plugin but leaves it off by default (user can toggle in dashboard)
- Plugins run asynchronously — use `await` freely, but catch your own exceptions
- Do not store large amounts of data on `self` — the plugin instance lives for the whole session
