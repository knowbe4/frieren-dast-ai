"""Login strategies — one module per login SHAPE, tried in order by the login cascade
(``dast/browser/login_cascade.py``). Splitting them keeps each shape independently
testable (one harness environment + test per strategy) so fixing one cannot silently
break another.

Strategies:
  - form      : deterministic DOM form-fill (static / open-shadow / 2-step / SSO). Lives in
                ``AgentBrowser.login`` today; the cascade calls it first.
  - spa_api   : POST credentials to the app's JSON auth endpoint — DOM-independent, so it
                works through shadow DOM / iframes / closed shadow where form-fill cannot.
  - llm       : LLM-driven adaptive fallback for unusual multi-step flows.
"""

from __future__ import annotations

from dast.browser.login_strategies import spa_api as spa_api  # noqa: F401

__all__ = ["spa_api"]
