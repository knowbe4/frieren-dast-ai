"""import_scan_output tool — turn nmap/nuclei output into frieren candidates (6-A-2).

External scanner output is not a report to read — it is SURFACE to attack.
This tool parses nmap XML (open HTTP services → imported entries queued for
active scanning) and nuclei JSONL (findings → imported stubs with
import_status='queued' that the scan pipeline and the 5-C attack sub-agents
VERIFY against the live target). Mechanical, deterministic, idempotent per
record — re-importing the same output adds nothing.

The handler posts to the dashboard's import routes (which own the scan queue
and the idempotency check) instead of touching the store directly — the same
"talk to the dashboard process" pattern as copilot_ask. For files larger than
the 1 MiB tool cap, POST them to /api/history/import/nmap | /nuclei directly
(64 MiB) — same parsers, same keys.
"""

from __future__ import annotations

from typing import Any, Dict

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_MAX_CONTENT_CHARS = 1_000_000  # 1 MiB of text per tool call

_IMPORT_SCAN_OUTPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "format": {
            "type": "string",
            "enum": ["nmap", "nuclei"],
            "description": "nmap = nmap -oX XML output; nuclei = nuclei -json JSONL output.",
        },
        "content": {
            "type": "string",
            "description": "The scanner output text (up to 1 MiB). Larger files: POST them "
                           "directly to /api/history/import/nmap or /nuclei on the dashboard.",
        },
    },
    "required": ["format", "content"],
}


async def _import_scan_output(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    kind = str(args.get("format", "")).strip().lower()
    content = str(args.get("content", ""))
    if kind not in ("nmap", "nuclei"):
        return {"ok": False, "error": "format must be 'nmap' or 'nuclei'"}
    if not content.strip():
        return {"ok": False, "error": "content is required"}
    if len(content) > _MAX_CONTENT_CHARS:
        return {"ok": False,
                "error": "content over the 1 MiB tool cap — POST the file to "
                         f"/api/history/import/{kind} on the dashboard instead"}

    try:
        import httpx

        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                f"{ctx.dashboard_base_url}/api/history/import/{kind}",
                content=content.encode("utf-8"),
                headers={"content-type": "text/plain; charset=utf-8"},
            )
        if resp.status_code == 400:
            return {"ok": False, "error": resp.json().get("error", "invalid input")}
        if resp.status_code == 413:
            return {"ok": False, "error": "file over the 64 MiB route cap"}
        resp.raise_for_status()
        out = resp.json()
        out["ok"] = True
        return out
    except Exception as exc:  # noqa: BLE001 — tool convention: never raise
        return {"ok": False, "error": f"import failed: {str(exc)[:200]}"}


register(Tool(
    name="import_scan_output",
    description=(
        "Import external scanner output as frieren CANDIDATES: 'nmap' (-oX XML) — every open "
        "HTTP(S) service becomes an imported GET entry queued for active scanning; 'nuclei' "
        "(-json JSONL) — each finding becomes an imported stub that the scan pipeline and the "
        "attack sub-agents VERIFY against the live target before it is believed. Idempotent: "
        "re-importing the same output adds nothing (deterministic keys).\n"
        "Use this to seed coverage from other tooling (recon hand-off, CI scans) instead of "
        "re-deriving the same surface. Content cap 1 MiB per call — bigger files go straight "
        "to POST /api/history/import/nmap | /nuclei (64 MiB)."
    ),
    input_schema=_IMPORT_SCAN_OUTPUT_SCHEMA,
    handler=_import_scan_output,
    tags=["recon", "triage"],
))
