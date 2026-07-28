"""
GraphQL Fuzzer plugin — no-op lifecycle, registered purely so the "GraphQL"
dashboard tab (Schema Explorer, Query Builder, Fuzzer) has a discoverable
enable/disable toggle in the Plugins tab.

All fuzzing/query-building is user-triggered from the GraphQL tab UI (see
dast/proxy/api/graphql_routes.py and dast/graphql/) — this plugin never
observes traffic or sends probes, and is never part of the passive/active
scan pipeline.
"""

from __future__ import annotations

from dast.proxy.plugin_base import ProxyPlugin


class GraphQLFuzzerPlugin(ProxyPlugin):
    name = "GraphQL Fuzzer"
    description = (
        "Enables the GraphQL tab (Schema Explorer, Query Builder, Fuzzer) in the "
        "dashboard. Purely a UI feature toggle — this plugin does not run on the "
        "passive or active scan pipeline."
    )
    version = "0.1.0"
    author = "dast-ai"
    enabled = True
    active = False
