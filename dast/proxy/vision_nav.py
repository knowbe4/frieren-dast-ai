"""
Vision-based navigation fallback for SPAs whose nav is not enumerable via the DOM
or the accessibility tree (web components with closed shadow DOM, canvas UIs).

A viewport screenshot is sent to the CHEAPEST multimodal model (fast/Haiku tier)
which returns the on-screen navigation controls as center pixel coordinates; the
caller clicks them with ``page.mouse.click(x, y)``. This is a deliberate last
resort — the coordinator only turns it on when normal DOM/accessibility navigation
finds nothing on an app that clearly rendered.

Kept dependency-light and off the proxy hot path: one function the explorer calls.
"""

from __future__ import annotations

import base64
from typing import Any, List

from dast.utils.logger import get_logger

logger = get_logger(__name__)

_SYSTEM = (
    "You are a navigation assistant for an authorized web app crawler. You are shown a "
    "screenshot of a rendered single-page app. Identify the primary NAVIGATION controls — "
    "sidebar/menu items, tabs, and links that would take the user to a DIFFERENT section of "
    "the app. Return each control's visible label and the pixel coordinates of its CENTER in "
    "the screenshot. Mark anything that logs out, deletes, removes, or destroys data as "
    "destructive=true (it will be skipped). Do NOT invent controls that are not visibly present."
)


async def vision_clickables(page: Any, invoke_json_fn, viewport: dict) -> List[dict]:
    """Return nav controls the model sees in a viewport screenshot, as
    [{label, x, y, kind, destructive}]. Empty list on any failure (caller falls
    back to doing nothing — vision is best-effort)."""
    try:
        png = await page.screenshot(full_page=False)
    except Exception as exc:  # noqa: BLE001 — never break the crawl on a screenshot
        logger.warning("vision_nav: screenshot failed", error=str(exc))
        return []
    image_b64 = base64.b64encode(png).decode()
    width = int(viewport.get("width", 1280))
    height = int(viewport.get("height", 900))
    user = (
        f"Screenshot of {page.url[:200]} at viewport {width}x{height} pixels (origin top-left). "
        "List the navigation controls to click to reach other sections, with the center x,y of each."
    )
    try:
        from dast.ai import bedrock_client
        result = await _ainvoke(
            invoke_json_fn, system=_SYSTEM, user=user,
            schema=_schema(), image_b64=image_b64,
            model_id=bedrock_client.get_fast_model(), max_tokens=1500, temperature=0,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("vision_nav: model call failed", error=str(exc))
        return []

    elements = result.get("elements") if isinstance(result, dict) else None
    if not isinstance(elements, list):
        return []
    out: List[dict] = []
    for el in elements:
        if not isinstance(el, dict) or el.get("destructive"):
            continue
        try:
            x, y = int(el["x"]), int(el["y"])
        except (KeyError, TypeError, ValueError):
            continue
        # Discard coordinates outside the viewport (model hallucination / off-screen).
        if not (0 <= x <= width and 0 <= y <= height):
            continue
        out.append({"label": str(el.get("label", ""))[:80], "x": x, "y": y,
                    "kind": str(el.get("kind", "nav"))})
    logger.info("vision_nav: model returned nav controls", url=page.url[:80], count=len(out))
    return out


def _schema():
    from dast.ai.schemas import VISION_CLICKABLES_SCHEMA
    return VISION_CLICKABLES_SCHEMA


async def _ainvoke(invoke_json_fn, **kwargs):
    """Run the (sync) invoke_json off the event loop so the crawl stays responsive.
    ``invoke_json_fn`` defaults to bedrock_client.invoke_json; injectable for tests."""
    import asyncio
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, lambda: invoke_json_fn(**kwargs))
