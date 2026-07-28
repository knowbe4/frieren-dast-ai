"""
Evidence formatting for H1 validation results.

The evidence string is what a triager reads (and what gets pasted into a
HackerOne report), so it must state plainly WHAT happened, WHERE (from which
origin to which host), the RISK in one line, and how to REPRODUCE. When a result
is inconclusive or errored, the evidence must instead explain WHY, how to test
MANUALLY, and suggest payload variations to try.

Everything here is plain text with labeled sections. The dashboard renders it in
a ``white-space: pre-wrap`` panel, so line breaks and indentation display as
written and it is safe to copy verbatim into a report.

This module has no side effects and does no I/O — it only formats strings.
"""

from __future__ import annotations

from typing import List, Optional
from urllib.parse import urlparse

# One-line risk summaries per attack type, written for a triager. Redirect XSS
# has its own line because its impact (credential/cookie exfiltration via forced
# navigation) differs from stored/reflected script execution.
_RISK_BY_TYPE = {
    "xss": (
        "An attacker who gets a victim to open the crafted link executes "
        "JavaScript in the victim's session on this origin — enabling cookie/"
        "session theft, actions on behalf of the victim, and UI manipulation."
    ),
    "xss_redirect": (
        "An attacker who gets a victim to open the crafted link forces the "
        "victim's browser to an attacker-controlled host, carrying session data "
        "(cookies/domain) in the URL — enabling credential/session exfiltration "
        "and phishing under the trust of the original site."
    ),
    "sqli": (
        "The parameter is injectable into a backend SQL query, allowing an "
        "attacker to read or modify database contents."
    ),
    "open_redirect": (
        "The endpoint redirects to an attacker-controlled destination, usable "
        "for phishing and OAuth token theft."
    ),
    "ssrf": (
        "The server can be coerced into making requests to attacker-chosen "
        "destinations, exposing internal services and cloud metadata."
    ),
    "ssti": (
        "User input reaches a template engine and is evaluated server-side, "
        "which can escalate to remote code execution."
    ),
    "lfi": (
        "The application includes/serves files from a user-controlled path, "
        "exposing local files (and sometimes enabling code execution)."
    ),
    "rce": (
        "User input reaches a command/eval sink, allowing arbitrary code "
        "execution on the server."
    ),
    "xxe": (
        "The XML parser resolves external entities, enabling local file read "
        "and server-side request forgery."
    ),
    "idor": (
        "An object identifier can be changed to access another user's data "
        "without authorization (broken object-level authorization)."
    ),
    "csrf": (
        "A state-changing action can be triggered cross-site without a valid "
        "anti-CSRF token, letting an attacker act as the victim."
    ),
    "auth_bypass": (
        "Access control can be bypassed, reaching protected functionality "
        "without proper authentication/authorization."
    ),
    "privilege_escalation": (
        "A lower-privileged user can perform actions reserved for higher "
        "privileges (broken function-level authorization)."
    ),
    "info_disclosure": (
        "The endpoint leaks sensitive information (secrets, internal data, "
        "stack traces) to an unauthorized party."
    ),
    "business_logic": (
        "A flaw in the application's workflow lets an attacker abuse intended "
        "functionality for unintended gain."
    ),
    "dns_takeover": (
        "A dangling DNS record can be claimed by an attacker, enabling "
        "subdomain takeover (phishing, cookie theft, trust bypass)."
    ),
}

_MANUAL_STEPS_BY_TYPE = {
    "xss": [
        "Open the proof URL in a logged-in browser session on the target.",
        "If nothing fires on load, interact with the injected element "
        "(click the link / hover, as the report describes).",
        "Confirm execution: a dialog fires, the page redirects off-origin, or "
        "the injected script runs (check the console / network tab).",
    ],
    "sqli": [
        "Send the proof URL and compare the response to a benign baseline.",
        "Try a boolean pair (e.g. ' AND 1=1-- - vs ' AND 1=2-- -) and look "
        "for a content difference.",
        "Try a time-based probe (e.g. ' OR SLEEP(5)-- -) and measure the "
        "response delay. Do NOT use write/DDL statements against production.",
    ],
    "open_redirect": [
        "Open the proof URL and observe the Location header / final landing host.",
        "Confirm the browser lands on the attacker-specified host.",
    ],
    "ssti": [
        "Inject a math expression for the suspected engine (e.g. {{7*7}}, "
        "${7*7}, #{7*7}) and check whether the response returns 49.",
        "If it evaluates, escalate carefully to a benign object/introspection "
        "payload — do NOT run destructive or code-exec payloads on production.",
    ],
    "lfi": [
        "Request a known-readable local file via the parameter (e.g. a traversal "
        "to a benign file) and check the response for its contents.",
        "Compare against a baseline request to rule out generic errors.",
    ],
    "rce": [
        "Use a time-based, non-destructive probe (e.g. a bounded sleep) and "
        "measure the response delay — never run destructive commands.",
        "If a delay is observed, capture request/response as proof and stop.",
    ],
    "xxe": [
        "Submit an XML body defining a benign external entity pointing at an "
        "OOB collaborator you control; watch for the callback.",
        "Do not target internal/metadata endpoints on production.",
    ],
    "idor": [
        "Authenticate as user A, capture a request referencing A's object id.",
        "Replay it with B's id (or an adjacent id) and check whether A can read/"
        "modify B's data.",
    ],
    "csrf": [
        "Build a minimal cross-site form/request that performs the state change.",
        "Trigger it from an unrelated origin while logged in and confirm the "
        "action succeeds without a valid anti-CSRF token.",
    ],
    "auth_bypass": [
        "Send the request to the protected endpoint without credentials / with "
        "the auth header stripped and check for a 200 with protected content.",
    ],
    "privilege_escalation": [
        "As a low-privileged user, replay a high-privilege action and verify it "
        "succeeds.",
    ],
    "info_disclosure": [
        "Request the endpoint unauthenticated and inspect the response for "
        "secrets, internal data, or stack traces.",
    ],
    "business_logic": [
        "Follow the reported workflow step by step and attempt the described "
        "abuse (e.g. negative quantity, replay, out-of-order step).",
    ],
    "dns_takeover": [
        "Run dig NS <domain> +short and dig CNAME <domain> +short.",
        "Look for SERVFAIL / NXDOMAIN pointing at a claimable provider target.",
    ],
    "ssrf": [
        "Set the vulnerable parameter to an OOB URL you control (collaborator / "
        "interactsh) and watch for an inbound HTTP/DNS callback.",
        "If a callback arrives, the server made the request — capture it as proof. "
        "Do not target internal/cloud-metadata hosts on production.",
    ],
}

# Payload variations to suggest when a type could not be auto-confirmed.
_PAYLOAD_SUGGESTIONS_BY_TYPE = {
    "xss": [
        "<script>alert(document.domain)</script>",
        "\"><img src=x onerror=alert(document.domain)>",
        "javascript:alert(document.domain)  (for href/redirect sinks)",
        "'-alert(document.domain)-'  (for JS-string contexts)",
    ],
    "sqli": [
        "' AND 1=1-- -   vs   ' AND 1=2-- -   (boolean-based, non-writing)",
        "' OR SLEEP(5)-- -   (time-based, non-writing)",
        "1) UNION SELECT NULL-- -   (column-count probing)",
    ],
    "open_redirect": [
        "?next=https://attacker.example",
        "?next=//attacker.example",
        "?next=https:attacker.example",
    ],
    "ssti": [
        "{{7*7}}   (Jinja2/Twig — expect 49)",
        "${7*7}    (FreeMarker/JSP EL)",
        "#{7*7}    (Ruby/Thymeleaf)",
        "<%= 7*7 %>  (ERB)",
    ],
    "lfi": [
        "../../../../etc/hostname   (traversal to a benign file)",
        "....//....//etc/hostname   (bypass naive filters)",
        "php://filter/convert.base64-encode/resource=index  (PHP wrappers)",
    ],
    "rce": [
        "; sleep 5   (time-based, non-destructive)",
        "| sleep 5",
        "$(sleep 5)",
        "`sleep 5`",
    ],
    "xxe": [
        "<!DOCTYPE x [<!ENTITY e SYSTEM \"http://OOB-COLLAB\">]><x>&e;</x>  (OOB)",
        "Use a collaborator/OOB host you control; avoid internal/metadata targets.",
    ],
    "idor": [
        "Increment/decrement the object id (e.g. /api/orders/1001 -> 1002).",
        "Swap a UUID for another known object's UUID.",
        "Change an owner/user id in the body or a query param.",
    ],
}


# Map common vuln-type aliases onto the canonical keys used in the tables above,
# so a report labeled path_traversal / cmdi / template_injection still gets
# type-specific guidance.
_TYPE_ALIASES = {
    "path_traversal": "lfi",
    "file_inclusion": "lfi",
    "directory_traversal": "lfi",
    "cmdi": "rce",
    "command_injection": "rce",
    "os_command_injection": "rce",
    "code_injection": "rce",
    "template_injection": "ssti",
    "server_side_template_injection": "ssti",
    "server_side_request_forgery": "ssrf",
    "xml_external_entity": "xxe",
    "broken_access_control": "idor",
    "bola": "idor",
    "authorization": "idor",
    "authz": "idor",
    "authentication_bypass": "auth_bypass",
    "privesc": "privilege_escalation",
    "information_disclosure": "info_disclosure",
    "data_exposure": "info_disclosure",
    "subdomain_takeover": "dns_takeover",
    "reflected_xss": "xss",
    "stored_xss": "xss",
    "dom_xss": "xss",
}


def _canon(vuln_type: str) -> str:
    """Normalize a vuln_type to the canonical key used by the evidence tables."""
    key = (vuln_type or "").strip().lower()
    return _TYPE_ALIASES.get(key, key)


def _host(url: str) -> str:
    try:
        return urlparse(url).netloc or url
    except Exception:
        return url


def _section(title: str, body: str) -> str:
    return f"{title}:\n{body}".rstrip()


def build_confirmed_xss(
    proof_url: str,
    payload: str,
    mechanism: str,
    exfil_host: str = "",
    dialog_message: Optional[str] = None,
) -> str:
    """
    Structured evidence for a confirmed XSS.

    mechanism — one of "redirect", "dialog", "reflected_alert"; selects the
    "what happened" wording and the risk line.
    exfil_host — for redirect XSS, the off-origin host the browser was sent to.
    """
    origin = _host(proof_url)
    lines: List[str] = ["CONFIRMED — XSS execution observed by the browser.", ""]

    if mechanism == "redirect":
        what = (
            f"Loading the proof URL on {origin} executed the injected "
            f"javascript: payload, which navigated the browser OFF-ORIGIN to "
            f"'{exfil_host}'. Flow: {origin} -> {exfil_host}."
        )
        risk = _RISK_BY_TYPE["xss_redirect"]
    elif mechanism == "dialog":
        msg = f" (message: {dialog_message!r})" if dialog_message else ""
        what = (
            f"The injected payload executed on {origin} and triggered a "
            f"JavaScript dialog{msg} — proof of arbitrary script execution."
        )
        risk = _RISK_BY_TYPE["xss"]
    else:  # reflected_alert
        what = (
            f"The payload is reflected unescaped in the {origin} response and "
            f"the injected alert() executes in the browser."
        )
        risk = _RISK_BY_TYPE["xss"]

    lines.append(_section("What happened", what))
    lines.append("")
    lines.append(_section("Risk", risk))
    lines.append("")
    lines.append(_section("Reproduction", "\n".join([
        f"1. Open the proof URL in a browser:\n   {proof_url}",
        "2. Observe the injected payload execute (redirect / dialog / script).",
    ])))
    if payload:
        lines.append("")
        lines.append(_section("Payload", payload))
    return "\n".join(lines)


def build_inconclusive(
    vuln_type: str,
    proof_url: str,
    payload: str,
    reason: str,
    observed: str = "",
    llm_advisory: str = "",
    extra_suggestions: Optional[List[str]] = None,
) -> str:
    """
    Structured evidence for a needs_manual / not_confirmed result.

    reason — a short human explanation of WHY it was inconclusive (e.g. "no
    execution observed", "auth wall", "destructive payload blocked").
    observed — optional note of what the browser did see (e.g. navigations).
    """
    origin = _host(proof_url)
    canon = _canon(vuln_type)
    lines: List[str] = ["NOT AUTO-CONFIRMED — manual review needed.", ""]
    lines.append(_section("Why", reason))
    if observed:
        lines.append("")
        lines.append(_section("What the validator observed", observed))

    steps = _MANUAL_STEPS_BY_TYPE.get(canon)
    if steps:
        numbered = "\n".join(f"{i}. {s}" for i, s in enumerate(steps, 1))
        lines.append("")
        lines.append(_section(f"How to test manually (target: {origin})", numbered))

    suggestions = list(_PAYLOAD_SUGGESTIONS_BY_TYPE.get(canon, []))
    if extra_suggestions:
        suggestions = list(extra_suggestions) + suggestions
    if suggestions:
        body = "\n".join(f"- {s}" for s in suggestions)
        lines.append("")
        lines.append(_section("Suggested payloads to try", body))

    if payload:
        lines.append("")
        lines.append(_section("Reported payload", payload))
    if llm_advisory:
        lines.append("")
        lines.append(_section("LLM advisory (not a confirmation)", llm_advisory))
    return "\n".join(lines)


def build_error(
    vuln_type: str,
    proof_url: str,
    error: str,
    likely_cause: str = "",
) -> str:
    """
    Structured evidence for an error result: what failed, the likely cause, and
    how to proceed manually.
    """
    origin = _host(proof_url)
    lines: List[str] = ["ERROR — validation could not complete.", ""]
    lines.append(_section("Error", error))
    if likely_cause:
        lines.append("")
        lines.append(_section("Likely cause", likely_cause))
    steps = _MANUAL_STEPS_BY_TYPE.get(_canon(vuln_type))
    if steps:
        numbered = "\n".join(f"{i}. {s}" for i, s in enumerate(steps, 1))
        lines.append("")
        lines.append(_section(f"How to test manually (target: {origin})", numbered))
    return "\n".join(lines)
