"""
Login-flow model + recorder/replayer primitives.

A LoginFlow is an ordered list of LoginStep actions that reproduce a login:
navigate, fill (referencing a credential field, never an inlined secret), click,
wait_for, press. Secrets are referenced by name ("username"/"password"); literal
values are only stored for non-credential fields (e.g. an org slug).

This module holds the *pure* pieces (data model, credential substitution, captcha
signatures, the JS recorder script). The browser-driving recorder lives on
BrowseSession and the replayer in dast.session.flow_replayer — both consume these.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Credential field references understood by the replayer.
REF_USERNAME = "username"
REF_PASSWORD = "password"

# Captcha / bot-wall signatures. If any appears on the page during replay, the
# flow cannot proceed unattended and the analyst is called in (Phase 2 pause).
CAPTCHA_SIGNATURES = [
    "recaptcha",
    "g-recaptcha",
    "h-captcha",
    "hcaptcha",
    "cf-turnstile",
    "turnstile",
    "px-captcha",
    "funcaptcha",
    "arkoselabs",
    "data-sitekey",
]

# Injected into every recorded page. Captures fills/clicks/submits and reports
# them to Python via the exposed binding window.__dastRecordStep. A filled field
# is classified in-page so credential secrets are NEVER sent back: password-type
# fields report ref="password" with no value; user/email/login fields report
# ref="username" with no value; anything else reports its literal value.
RECORDER_INIT_SCRIPT = r"""
(() => {
  if (window.__dastRecorderInstalled) return;
  window.__dastRecorderInstalled = true;

  function cssPath(el) {
    if (!el || el.nodeType !== 1) return '';
    if (el.id) return '#' + CSS.escape(el.id);
    if (el.name) return el.tagName.toLowerCase() + '[name="' + el.name + '"]';
    const parts = [];
    let node = el;
    while (node && node.nodeType === 1 && parts.length < 5) {
      let sel = node.tagName.toLowerCase();
      const parent = node.parentNode;
      if (parent) {
        const sibs = Array.from(parent.children).filter(c => c.tagName === node.tagName);
        if (sibs.length > 1) sel += ':nth-of-type(' + (sibs.indexOf(node) + 1) + ')';
      }
      parts.unshift(sel);
      if (node.id) { parts[0] = '#' + CSS.escape(node.id); break; }
      node = parent;
    }
    return parts.join(' > ');
  }

  function classify(el) {
    const t = (el.type || '').toLowerCase();
    const hint = ((el.name || '') + ' ' + (el.id || '') + ' ' + (el.autocomplete || '')).toLowerCase();
    if (t === 'password') return 'password';
    if (/user|email|login|account/.test(hint) || t === 'email') return 'username';
    return null;  // literal
  }

  document.addEventListener('change', (e) => {
    const el = e.target;
    if (!el || !('value' in el)) return;
    if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT') {
      const ref = classify(el);
      window.__dastRecordStep({
        action: 'fill', selector: cssPath(el), valueRef: ref,
        value: ref ? '' : (el.value || ''),
      });
    }
  }, true);

  document.addEventListener('click', (e) => {
    const el = e.target.closest('button, input[type=submit], a[role=button], [type=button]');
    if (!el) return;
    window.__dastRecordStep({ action: 'click', selector: cssPath(el), valueRef: null, value: '' });
  }, true);
})();
"""


@dataclass
class LoginStep:
    action: str                         # navigate | fill | click | wait_for | press
    selector: str = ""
    value_ref: Optional[str] = None     # "username" | "password" | None (use literal)
    value: str = ""                     # literal value (non-credential) OR url for navigate
    timeout_ms: int = 10000

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "selector": self.selector,
            "value_ref": self.value_ref,
            "value": self.value,
            "timeout_ms": self.timeout_ms,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "LoginStep":
        return cls(
            action=str(d.get("action", "")),
            selector=str(d.get("selector", "")),
            value_ref=d.get("value_ref"),
            value=str(d.get("value", "")),
            timeout_ms=int(d.get("timeout_ms", 10000)),
        )


@dataclass
class LoginFlow:
    steps: List[LoginStep] = field(default_factory=list)
    start_url: str = ""
    success_url_regex: str = ""         # optional: URL that confirms success
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "steps": [s.to_dict() for s in self.steps],
            "start_url": self.start_url,
            "success_url_regex": self.success_url_regex,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "LoginFlow":
        return cls(
            steps=[LoginStep.from_dict(s) for s in d.get("steps", [])],
            start_url=str(d.get("start_url", "")),
            success_url_regex=str(d.get("success_url_regex", "")),
            created_at=float(d.get("created_at", time.time())),
        )

    @property
    def is_empty(self) -> bool:
        return not self.steps


def resolve_value(step: LoginStep, username: str, password: str) -> str:
    """Return the concrete value for a fill step from the chosen credential."""
    if step.value_ref == REF_USERNAME:
        return username
    if step.value_ref == REF_PASSWORD:
        return password
    return step.value


def has_captcha(html: str) -> bool:
    """Heuristic: True if the page markup contains a known captcha/bot-wall signature."""
    if not html:
        return False
    low = html.lower()
    return any(sig in low for sig in CAPTCHA_SIGNATURES)


def coalesce_recorded_steps(raw_steps: List[Dict[str, Any]]) -> List[LoginStep]:
    """Turn raw recorder events into clean LoginSteps.

    Collapses consecutive fills on the same selector (keep the last value the user
    left in the field) so re-typing/corrections don't produce duplicate steps.
    """
    steps: List[LoginStep] = []
    for raw in raw_steps:
        step = LoginStep.from_dict(raw)
        if step.action not in ("navigate", "fill", "click", "wait_for", "press"):
            continue
        if (
            step.action == "fill"
            and steps
            and steps[-1].action == "fill"
            and steps[-1].selector == step.selector
        ):
            steps[-1] = step  # replace — keep the final value in that field
            continue
        steps.append(step)
    return steps
