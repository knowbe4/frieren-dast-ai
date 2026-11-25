"""Unit tests for nmap/nuclei scan-output ingestion (6-A-2).

The parsers are pure (fixture text in, payloads out): caps, per-entry error
tolerance, deterministic dedup keys, and the nmap http/not-http split. The
import routes are exercised end-to-end with TestClient (synthetic entries in
a real SessionStore, queued ids captured) — no network.
"""

from __future__ import annotations

import pytest

from dast.importers.scan_output_import import (
    import_nmap_xml,
    import_nuclei_jsonl,
)

NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames><hostname name="shop.test" type="ptr"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.24"/></port>
      <port protocol="tcp" portid="8081"><state state="open"/><service name="http-alt" product="Tomcat"/></port>
      <port protocol="tcp" portid="5432"><state state="open"/><service name="postgresql"/></port>
    </ports>
  </host>
  <host>
    <address addr="10.0.0.9" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
      <port protocol="tcp" portid="22"><state state="closed"/><service name="ssh"/></port>
    </ports>
  </host>
</nmaprun>
"""

NUCLEI_JSONL = "\n".join([
    '{"template-id":"CVE-2021-44228","info":{"name":"Apache Log4j RCE","severity":"critical",'
    '"classification":{"cve-id":"CVE-2021-44228","cwe-id":"CWE-502"}},"host":"https://shop.test",'
    '"matched-at":"https://shop.test/api/search","extracted-results":["${jndi:ldap://x}"],'
    '"response":"HTTP/1.1 500"}',
    '{"template-id":"tech-detect","info":{"name":"Nginx detection","severity":"info"},'
    '"host":"https://shop.test","matched-at":"https://shop.test/"}',
    "not json at all",
])


# ── nmap parser ──────────────────────────────────────────────────────────────

def test_nmap_http_services_become_entries():
    out = import_nmap_xml(NMAP_XML)
    urls = [e["url"] for e in out["entries"]]
    assert "https://shop.test/" in urls                    # hostname preferred, 443 bare
    assert "http://shop.test:8081/" in urls                # http-alt with port
    assert "http://10.0.0.9/" in urls                      # no hostname → ip
    assert all(e["method"] == "GET" for e in out["entries"])
    nginx = next(e for e in out["entries"] if e["port"] == 443)
    assert nginx["product"] == "nginx" and nginx["version"] == "1.24"
    assert nginx["key"].startswith("scanout-")


def test_nmap_non_http_reported_not_ingested():
    out = import_nmap_xml(NMAP_XML)
    others = {(o["host"], o["port"]) for o in out["other_services"]}
    assert ("shop.test", 5432) in others                   # postgres → context only
    assert all("5432" not in e["url"] for e in out["entries"])
    # closed ports never appear anywhere
    assert not any(o["port"] == 22 for o in out["other_services"])


def test_nmap_keys_are_stable_and_deterministic():
    a = import_nmap_xml(NMAP_XML)
    b = import_nmap_xml(NMAP_XML)
    assert [e["key"] for e in a["entries"]] == [e["key"] for e in b["entries"]]
    assert len({e["key"] for e in a["entries"]}) == len(a["entries"])


def test_nmap_invalid_xml_raises_valueerror():
    with pytest.raises(ValueError):
        import_nmap_xml("<not-xml")


# ── nuclei parser ────────────────────────────────────────────────────────────

def test_nuclei_findings_become_stub_entries():
    out = import_nuclei_jsonl(NUCLEI_JSONL)
    assert out["stats"]["error_count"] == 1                # the garbage line, not fatal
    assert len(out["entries"]) == 2
    log4j = out["entries"][0]
    stub = log4j["finding"]
    assert stub["title"] == "[nuclei] Apache Log4j RCE"
    assert stub["severity"] == "critical"
    assert stub["cwe"] == "CWE-502"
    assert stub["import_status"] == "queued" and stub["confirmed"] is False
    assert "CVE-2021-44228" in stub["evidence"]
    assert log4j["url"] == "https://shop.test/api/search"
    assert log4j["key"].startswith("nuclei-")


def test_nuclei_keys_dedup_identical_lines():
    line = NUCLEI_JSONL.splitlines()[0]
    out = import_nuclei_jsonl(f"{line}\n{line}")
    assert len(out["entries"]) == 1


def test_nuclei_unknown_severity_maps_to_info():
    line = ('{"template-id":"x","info":{"name":"Weird","severity":"weird"},'
            '"host":"https://t.test","matched-at":"https://t.test/a"}')
    out = import_nuclei_jsonl(line)
    assert out["entries"][0]["finding"]["severity"] == "info"


# ── the import routes (end-to-end, no network) ───────────────────────────────

@pytest.fixture
def _import_client():
    from types import SimpleNamespace

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from dast.proxy.api.proxy_routes import make_router
    from dast.proxy.session_store import SessionStore

    store = SessionStore()
    queued = []

    class _FakeQueue:
        async def put(self, item):
            queued.append(item)

    ctx = SimpleNamespace(store=store, scan_queue=_FakeQueue(),
                          scan_queue_state=None, ca=None, settings=None,
                          runner=None)
    app = FastAPI()
    app.include_router(make_router(ctx))
    return SimpleNamespace(client=TestClient(app), store=store, queued=queued)


def test_nmap_route_stores_and_queues_entries(_import_client):
    r = _import_client.client.post("/api/history/import/nmap",
                                   content=NMAP_XML.encode())
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True and data["added"] == 3
    assert len(_import_client.queued) == 3                 # all queued for scan
    assert any("postgresql" == o["service"]
               for o in data["other_services"])
    # entries really in the store with import keys
    keys = {e.import_key for e in _import_client.store.all_entries() if e.import_key}
    assert len(keys) == 3
    assert all(k.startswith("scanout-") for k in keys)


def test_nmap_route_reimport_is_idempotent(_import_client):
    _import_client.client.post("/api/history/import/nmap", content=NMAP_XML.encode())
    r2 = _import_client.client.post("/api/history/import/nmap",
                                    content=NMAP_XML.encode())
    assert r2.json()["added"] == 0
    assert len(_import_client.queued) == 3                 # no double-queue


def test_nuclei_route_stubs_are_queued_for_verification(_import_client):
    r = _import_client.client.post("/api/history/import/nuclei",
                                   content=NUCLEI_JSONL.encode())
    assert r.status_code == 200
    data = r.json()
    assert data["added"] == 2 and data["errors"]
    entries = _import_client.store.all_entries()
    stubs = [f for e in entries for f in e.findings]
    assert len(stubs) == 2
    assert all(f["import_status"] == "queued" and f["confirmed"] is False
               for f in stubs)
    assert _import_client.queued                           # queued for live verification


def test_nuclei_route_tolerates_garbage_lines(_import_client):
    """JSONL contract: per-line errors are counted, never fatal — garbage
    lines become stats, not a 400 (only nmap document-level breaks raise)."""
    r = _import_client.client.post("/api/history/import/nuclei", content=b"\x00\xff")
    assert r.status_code == 200
    data = r.json()
    assert data["added"] == 0
    assert len(data["errors"]) >= 1
    assert data["errors"][0].startswith("line ")
