"""
SARIF 2.1.0 export — converts Frieren DAST-AI findings to Static Analysis Results
Interchange Format for GitHub/GitLab Security tab integration.

SARIF spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import time
from typing import Any, Dict, List


_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_SEVERITY_TO_SECURITY_SEVERITY = {
    "critical": "9.0",
    "high": "7.5",
    "medium": "5.0",
    "low": "2.5",
    "info": "1.0",
}


def _make_rule_id(finding: dict) -> str:
    """
    Derive a specific, human-readable SARIF rule ID for a finding.

    Priority order:
    1. rule_id from passive scanner YAML (e.g. "missing-hsts", "cors-reflected-origin")
    2. attack_type + title slug for active findings (e.g. "DAST-XSS-ReflectedXss")
    3. Plain "DAST-{ATTACK_TYPE}" as a last resort
    """
    # Passive scanner stores the YAML rule id directly
    yaml_rule_id = finding.get("rule_id", "").strip()
    if yaml_rule_id:
        return yaml_rule_id

    attack_type = finding.get("attack_type", "unknown").lower()
    title = finding.get("title", "")
    if title:
        title_slug = _to_camel(title.replace(" ", "_").replace("-", "_"))
        return f"DAST-{attack_type.upper()}-{title_slug}"

    return f"DAST-{attack_type.upper()}"


def _cwe_uri(cwe: str) -> str:
    """Return a CWE detail URI for the helpUri field, or OWASP as fallback."""
    if cwe and cwe.upper().startswith("CWE-"):
        cwe_num = cwe.upper().replace("CWE-", "").strip()
        if cwe_num.isdigit():
            return f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
    return "https://owasp.org/www-project-top-ten/"


def build_sarif(entries: list) -> Dict[str, Any]:
    """
    Build a SARIF 2.1.0 document from a list of ProxyEntry objects (with findings).

    entries: list of ProxyEntry (from store.all_entries())
    Returns a dict ready for json.dumps().
    """
    rules: Dict[str, dict] = {}
    results: List[dict] = []

    for entry in entries:
        for finding in getattr(entry, "findings", []):
            if not finding or not finding.get("title"):
                continue

            rule_id  = _make_rule_id(finding)
            severity = finding.get("severity", "info").lower()
            attack_type = finding.get("attack_type", "unknown")
            cwe = finding.get("cwe", "")
            title = finding.get("title", rule_id)

            if rule_id not in rules:
                tags = ["security", "DAST", attack_type]
                if cwe:
                    tags.append(cwe)

                full_desc_parts = [title]
                evidence = finding.get("evidence", "")
                if evidence:
                    full_desc_parts.append(evidence)
                reasoning = finding.get("reasoning", "")
                if reasoning:
                    full_desc_parts.append(reasoning)

                rules[rule_id] = {
                    "id": rule_id,
                    "name": _to_camel(
                        finding.get("rule_id", attack_type)
                        .replace("-", "_").replace(" ", "_")
                    ),
                    "shortDescription": {"text": title},
                    "fullDescription": {"text": " — ".join(full_desc_parts)},
                    "defaultConfiguration": {
                        "level": _SEVERITY_TO_LEVEL.get(severity, "warning")
                    },
                    "properties": {
                        "security-severity": _SEVERITY_TO_SECURITY_SEVERITY.get(severity, "5.0"),
                        "tags": tags,
                        "cwe": cwe,
                        "attack_type": attack_type,
                    },
                    "helpUri": _cwe_uri(cwe),
                    "help": {
                        "text": evidence or title,
                        "markdown": "\n\n".join(filter(None, [
                            f"**{title}**",
                            f"**Evidence:** {evidence}" if evidence else "",
                            f"**CWE:** [{cwe}]({_cwe_uri(cwe)})" if cwe else "",
                            f"**Reasoning:** {reasoning}" if reasoning else "",
                        ])),
                    },
                }

            # Build the result message — passive findings use evidence,
            # active findings include parameter + payload context.
            parameter = finding.get("parameter", "")
            payload   = (finding.get("payload", "") or "")[:120]
            evidence  = finding.get("evidence", "")

            if attack_type == "passive":
                msg_text = evidence or title
            else:
                parts = [title]
                if parameter:
                    parts.append(f"parameter: {parameter}")
                if payload:
                    parts.append(f"payload: {payload}")
                msg_text = " — ".join(parts)

            result = {
                "ruleId": rule_id,
                "level": _SEVERITY_TO_LEVEL.get(severity, "warning"),
                "message": {"text": msg_text},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": entry.url,
                                "uriBaseId": "%SRCROOT%",
                            }
                        },
                        "logicalLocations": [
                            {
                                "name": entry.url,
                                "kind": "url",
                                "fullyQualifiedName": f"{entry.method} {entry.url}",
                            }
                        ],
                    }
                ],
                "properties": {
                    "severity": severity,
                    "attack_type": attack_type,
                    "parameter": parameter,
                    "payload": payload,
                    "validated_by": finding.get("validated_by", ""),
                    "confidence": finding.get("confidence", 0),
                    "reasoning": finding.get("reasoning", ""),
                    "cwe": cwe,
                },
            }

            raw_request   = finding.get("raw_request", "")
            raw_response  = finding.get("raw_response", "")
            probe_request = finding.get("probe_request", "")
            probe_response= finding.get("probe_response", "")

            # Build a rich markdown message with inline HTTP evidence.
            # GitHub/GitLab Security tab renders this in the finding detail panel.
            md_parts = [f"**{title}**", ""]
            if evidence:
                md_parts += [f"**Evidence:** {evidence}", ""]
            if cwe:
                md_parts += [f"**CWE:** [{cwe}]({_cwe_uri(cwe)})", ""]
            reasoning = finding.get("reasoning", "")
            if reasoning:
                md_parts += [f"**Reasoning:** {reasoning}", ""]
            if raw_request:
                md_parts += ["**Request:**", f"```http\n{raw_request[:3000]}\n```", ""]
            if raw_response:
                md_parts += ["**Response:**", f"```http\n{raw_response[:3000]}\n```", ""]
            if probe_request:
                md_parts += ["**Exploit Proof — Request:**", f"```http\n{probe_request[:2000]}\n```", ""]
            if probe_response:
                md_parts += ["**Exploit Proof — Response:**", f"```http\n{probe_response[:2000]}\n```", ""]

            result["message"] = {
                "text": msg_text,
                "markdown": "\n".join(md_parts).strip(),
            }

            # relatedLocations — one entry per HTTP pair so tooling that parses
            # SARIF structurally (not just markdown) also gets the raw HTTP.
            related: List[dict] = []
            loc_id = 1
            if raw_request:
                related.append({
                    "id": loc_id,
                    "message": {"text": "HTTP Request (baseline)"},
                    "physicalLocation": {
                        "artifactLocation": {"uri": entry.url, "uriBaseId": "%SRCROOT%"},
                    },
                    "properties": {"snippet": raw_request[:3000]},
                })
                loc_id += 1
            if raw_response:
                related.append({
                    "id": loc_id,
                    "message": {"text": "HTTP Response (baseline)"},
                    "physicalLocation": {
                        "artifactLocation": {"uri": entry.url, "uriBaseId": "%SRCROOT%"},
                    },
                    "properties": {"snippet": raw_response[:3000]},
                })
                loc_id += 1
            if probe_request:
                related.append({
                    "id": loc_id,
                    "message": {"text": "HTTP Request (exploit proof)"},
                    "physicalLocation": {
                        "artifactLocation": {"uri": entry.url, "uriBaseId": "%SRCROOT%"},
                    },
                    "properties": {"snippet": probe_request[:2000]},
                })
                loc_id += 1
            if probe_response:
                related.append({
                    "id": loc_id,
                    "message": {"text": "HTTP Response (exploit proof)"},
                    "physicalLocation": {
                        "artifactLocation": {"uri": entry.url, "uriBaseId": "%SRCROOT%"},
                    },
                    "properties": {"snippet": probe_response[:2000]},
                })
            if related:
                result["relatedLocations"] = related

            results.append(result)

    sarif: Dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Frieren DAST-AI",
                        "version": "0.5.0",
                        "informationUri": "https://github.com/your-org/dast-ai",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    }
                ],
            }
        ],
    }
    return sarif


def _to_camel(s: str) -> str:
    return "".join(w.capitalize() for w in s.replace("-", "_").split("_"))
