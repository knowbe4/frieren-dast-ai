"""nmap / nuclei scan-output import — mechanical, deterministic (6-A-2).

External scanner output becomes FIRST-CLASS frieren candidates: nmap's open
HTTP services become imported GET entries queued for the active-scan pipeline
(the planner + deterministic agents take it from there); nuclei findings
become imported findings with ``import_status="queued"`` that the scan
pipeline — and through it the 5-C attack sub-agents — VERIFY against the live
target instead of being trusted on faith.

Contract copied from the HAR import (``dast/proxy/har_import.py``): document
level errors raise ValueError (routes map to 4xx), per-entry errors are
counted and never fatal (≤50 detail strings), hard caps, and a deterministic
``import_key`` per record so re-importing the same output is idempotent.
Both parsers are stdlib-only (``xml.etree`` + line-JSON) — no LLM, no new
dependencies.
"""

from __future__ import annotations

import hashlib
import json
import xml.etree.ElementTree as ET
from typing import Any, Dict, List
from urllib.parse import urlparse

from dast.utils.logger import get_logger

logger = get_logger(__name__)

_MAX_ENTRIES = 2000
_MAX_ERRORS = 50

# Service names/ports that indicate an HTTP surface worth queueing for scan.
_HTTP_SERVICE_HINTS = {"http", "https", "http-alt", "http-proxy", "httpmgmt", "www", "ssl"}
_HTTP_PORT_HINTS = {80, 443, 591, 3000, 4443, 4567, 5000, 7000, 8000, 8008, 8080,
                    8081, 8443, 8834, 8888, 9090, 9443}


def _key(prefix: str, *parts: Any) -> str:
    raw = "|".join(str(p) for p in parts)
    return f"{prefix}-{hashlib.sha256(raw.encode('utf-8', errors='replace')).hexdigest()[:32]}"


def _import_stats(errors: List[str], skipped: int) -> Dict[str, Any]:
    return {"errors": errors[:_MAX_ERRORS], "error_count": len(errors),
            "skipped_over_cap": skipped}


# ── nmap XML ─────────────────────────────────────────────────────────────────

def import_nmap_xml(xml_text: str) -> Dict[str, Any]:
    """Parse ``nmap -oX`` output.

    Returns ``{"entries": [...], "other_services": [...], "stats": {...}}``
    where each entry payload is a discovered HTTP(S) surface:
    ``{"key", "method", "url", "host", "port", "service", "product", "version"}``.
    Non-HTTP open ports are reported in ``other_services`` (context, not
    entries — frieren speaks HTTP/WS, not arbitrary TCP).
    """
    errors: List[str] = []
    entries: List[Dict[str, Any]] = []
    other_services: List[Dict[str, Any]] = []
    skipped = 0
    seen_keys: set = set()

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError(f"invalid nmap XML: {str(exc)[:160]}") from exc

    host_els = root.findall("host")
    for host_el in host_els:
        if len(entries) + len(other_services) >= _MAX_ENTRIES:
            skipped += 1
            continue
        try:
            addr_el = host_el.find("address[@addrtype='ipv4']")
            if addr_el is None:
                addr_el = host_el.find("address")
            ip = (addr_el.get("addr", "") if addr_el is not None else "").strip()
            hostname = ""
            names_el = host_el.find("hostnames")
            if names_el is not None:
                name_el = names_el.find("hostname[@type='ptr']")
                if name_el is None:
                    name_el = names_el.find("hostname")
                hostname = (name_el.get("name", "") if name_el is not None else "").strip()
            # Prefer the hostname when present (frieren scopes by host names).
            host_label = hostname or ip
            if not host_label:
                continue
            ports_el = host_el.find("ports")
            if ports_el is None:
                continue
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state", "") != "open":
                    continue
                try:
                    port = int(port_el.get("portid", "0"))
                except ValueError:
                    continue
                svc_el = port_el.find("service")
                service = (svc_el.get("name", "") if svc_el is not None else "").lower()
                product = (svc_el.get("product", "") if svc_el is not None else "").strip()
                version = (svc_el.get("version", "") if svc_el is not None else "").strip()
                tunnel = (svc_el.get("tunnel", "") if svc_el is not None else "").lower()

                is_http = service in _HTTP_SERVICE_HINTS or service.startswith("http") \
                    or port in _HTTP_PORT_HINTS or tunnel == "ssl"
                if not is_http:
                    other_services.append({
                        "host": host_label, "port": port,
                        "protocol": port_el.get("protocol", "tcp"),
                        "service": service or "unknown", "product": product,
                    })
                    continue
                scheme = "https" if service in ("https", "ssl") or tunnel == "ssl" \
                    or port in (443, 8443, 9443) else "http"
                host_header = host_label
                url = f"{scheme}://{host_header}"
                if port not in (80, 443):
                    url += f":{port}"
                url += "/"
                key = _key("scanout", scheme, host_label.lower(), port)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                entries.append({
                    "key": key, "method": "GET", "url": url,
                    "host": host_label.lower(), "port": port,
                    "service": service or "http", "product": product,
                    "version": version,
                })
        except Exception as exc:  # noqa: BLE001 — per-entry tolerance (HAR contract)
            errors.append(f"host parse failed: {str(exc)[:120]}")

    return {"entries": entries, "other_services": other_services,
            "stats": _import_stats(errors, skipped)}


# ── nuclei JSONL ─────────────────────────────────────────────────────────────

_SEVERITY_MAP = {
    "critical": "critical", "high": "high", "medium": "medium",
    "low": "low", "info": "info", "informational": "info", "unknown": "info",
}


def import_nuclei_jsonl(text: str) -> Dict[str, Any]:
    """Parse nuclei's JSONL output (one JSON result per line, ``-json``/``-j``).

    Returns ``{"entries": [...], "stats": {...}}`` where each entry payload
    carries a ready stub finding (``import_status="queued"``) for the synthetic
    entry — the scan pipeline verifies it against the live target.
    """
    errors: List[str] = []
    entries: List[Dict[str, Any]] = []
    skipped = 0
    seen_keys: set = set()

    for line_no, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        if len(entries) >= _MAX_ENTRIES:
            skipped += 1
            continue
        try:
            data = json.loads(line)
            if not isinstance(data, dict):
                raise ValueError("line is not a JSON object")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"line {line_no}: {str(exc)[:120]}")
            continue

        info = data.get("info") or {}
        template_id = str(data.get("template-id", "") or info.get("template-id", "")).strip()
        name = str(info.get("name", "") or template_id or "nuclei finding").strip()
        severity = _SEVERITY_MAP.get(str(info.get("severity", "")).strip().lower(), "info")
        classification = info.get("classification") or {}
        cwe = str(classification.get("cwe-id", "") or "").strip()
        cve = str(classification.get("cve-id", "") or "").strip()
        host = str(data.get("host", "") or "").strip()
        matched = str(data.get("matched-at", "") or host).strip()
        if not matched:
            errors.append(f"line {line_no}: no host/matched-at")
            continue
        extracted = data.get("extracted-results")
        evidence_parts = [f"nuclei template: {template_id or name}"]
        if cve:
            evidence_parts.append(f"CVE: {cve}")
        if extracted:
            evidence_parts.append(f"extracted: {extracted}")
        response = data.get("response")
        if isinstance(response, str) and response.strip():
            evidence_parts.append(f"response:\n{response[:1200]}")

        url = matched
        parsed = urlparse(matched)
        path = parsed.path or "/"
        key = _key("nuclei", template_id or name, parsed.netloc.lower(), path)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        stub = {
            "title": f"[nuclei] {name}",
            "severity": severity,
            "cwe": cwe or ("CVE" if cve else ""),
            "attack_type": "nuclei",
            "evidence": "\n".join(evidence_parts)[:2000],
            "parameter": "",
            "payload": "",
            "reasoning": "Imported from a nuclei scan — queued for live verification.",
            "import_status": "queued",
            "confirmed": False,
            "validated_by": ["imported"],
        }
        entries.append({
            "key": key, "method": "GET", "url": url, "host": parsed.netloc.lower(),
            "path": path, "finding": stub,
        })

    return {"entries": entries, "stats": _import_stats(errors, skipped)}
