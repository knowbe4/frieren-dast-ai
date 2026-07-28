"""
Hello World plugin — starter template for Frieren DAST-AI proxy plugins.

Copy this file to ~/.dast-ai/plugins/ and rename it to get started.
"""

from dast.proxy.plugin_base import ProxyPlugin
from dast.proxy.plugin_manager import log_event


class HelloWorldPlugin(ProxyPlugin):
    name        = "hello-world"
    description = "Starter template — demonstrates the plugin lifecycle and findings API"
    version     = "1.0.0"
    author      = "Frieren DAST-AI"

    enabled = False

    async def setup(self) -> None:
        log_event(self.name, "info", "Plugin loaded", source="plugin")

    async def on_entry(self, entry, store) -> None:
        log_event(self.name, "info", f"{entry.method} {entry.url}", url=entry.url, source="plugin")

        if entry.method == "POST":
            store.add_finding(
                entry.id,
                {
                    "title": "Hello World (demo finding)",
                    "severity": "informational",
                    "attack_type": "hello-world",
                    "evidence": f"POST to {entry.url} was recorded by the hello-world plugin.",
                    "confirmed": False,
                },
                "safe",
            )

    async def teardown(self) -> None:
        log_event(self.name, "info", "Plugin unloaded", source="plugin")
