"""
Unit tests for the vision navigator (dast/proxy/vision_nav.py): it screenshots
the page, asks the (mocked) multimodal model for nav controls, and returns
in-viewport, non-destructive click targets.
"""

from __future__ import annotations

import asyncio

from dast.proxy import vision_nav

_VIEWPORT = {"width": 1280, "height": 900}


class _FakePage:
    url = "https://app.example.com/dashboard"

    async def screenshot(self, full_page=False):
        return b"\x89PNG fake bytes"


def _invoke_returning(elements):
    def _fn(**kwargs):
        # The schema + image must be passed through.
        assert kwargs.get("image_b64"), "screenshot must be attached as image_b64"
        assert kwargs.get("schema") is not None
        return {"elements": elements}
    return _fn


def _run(coro):
    return asyncio.run(coro)


def test_returns_in_viewport_non_destructive_targets():
    elements = [
        {"label": "Settings", "x": 100, "y": 200, "kind": "nav", "destructive": False},
        {"label": "Log out", "x": 50, "y": 50, "kind": "button", "destructive": True},   # dropped
        {"label": "Off screen", "x": 5000, "y": 50, "kind": "nav"},                       # dropped (OOB)
        {"label": "Reports", "x": 120, "y": 260, "kind": "link"},
    ]
    out = _run(vision_nav.vision_clickables(_FakePage(), _invoke_returning(elements), _VIEWPORT))
    labels = {t["label"] for t in out}
    assert labels == {"Settings", "Reports"}
    assert all(0 <= t["x"] <= 1280 and 0 <= t["y"] <= 900 for t in out)


def test_empty_on_model_failure():
    def _boom(**kwargs):
        raise RuntimeError("model down")
    out = _run(vision_nav.vision_clickables(_FakePage(), _boom, _VIEWPORT))
    assert out == []


def test_empty_on_screenshot_failure():
    class _BadPage(_FakePage):
        async def screenshot(self, full_page=False):
            raise RuntimeError("no screenshot")
    out = _run(vision_nav.vision_clickables(_BadPage(), _invoke_returning([]), _VIEWPORT))
    assert out == []


def test_malformed_elements_are_skipped():
    elements = [{"label": "No coords"}, {"x": "nan", "y": 1}, {"label": "Good", "x": 10, "y": 10}]
    out = _run(vision_nav.vision_clickables(_FakePage(), _invoke_returning(elements), _VIEWPORT))
    assert [t["label"] for t in out] == ["Good"]
