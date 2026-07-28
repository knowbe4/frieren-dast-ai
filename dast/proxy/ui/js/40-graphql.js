// ── GraphQL tab ──────────────────────────────────────────────────────────────

function switchGraphqlSub(sub) {
  ['explorer', 'fuzzer'].forEach(s => {
    document.getElementById('graphql-sub-' + s).style.display = s === sub ? 'flex' : 'none';
    document.getElementById('st-graphql-' + s).classList.toggle('on', s === sub);
  });
  if (sub === 'explorer') gqlLoadEndpoints();
}

let _gqlSchemaCache = {};   // endpoint -> schema
let _gqlSelectedEndpoint = '';
let _gqlSelectedOp = null;   // { operation: 'query'|'mutation', field_name }

async function gqlLoadEndpoints() {
  try {
    const r = await fetch('/api/graphql/endpoints');
    const data = await r.json();
    const endpoints = data.endpoints || [];  // [{endpoint, introspected}]
    const urls = endpoints.map(e => e.endpoint);
    const sel = document.getElementById('gql-endpoint-select');
    if (sel) {
      const current = sel.value;
      sel.innerHTML = endpoints.length
        ? endpoints.map(e => `<option value="${esc(e.endpoint)}">${e.introspected ? '✓ ' : '(not introspected) '}${esc(e.endpoint)}</option>`).join('')
        : '<option value="">No endpoints discovered yet</option>';
      if (urls.includes(current)) sel.value = current;
    }
    // Note: we deliberately do NOT auto-select the first endpoint here — doing
    // so would auto-fetch/auto-introspect on the user's behalf. The user picks
    // an endpoint explicitly, and introspection is always a manual action.
    if (_gqlSelectedEndpoint && !urls.includes(_gqlSelectedEndpoint)) {
      await gqlSelectEndpoint('');
    }
  } catch (e) {
    console.error('gqlLoadEndpoints:', e);
  }
}

async function gqlAddEndpointManually() {
  const input = document.getElementById('gql-manual-endpoint');
  const url = input.value.trim();
  if (!url) return;
  try {
    const r = await fetch('/api/graphql/endpoints', {
      method: 'POST',
      headers: {'content-type': 'application/json'},
      body: JSON.stringify({ endpoint: url }),
    });
    const data = await r.json();
    if (!data.ok) { showToast(data.error || 'Failed to add endpoint', true); return; }
    input.value = '';
    showToast(data.added ? 'Endpoint added' : 'Endpoint already known');
    await gqlLoadEndpoints();
  } catch (e) {
    showToast('Failed to add endpoint', true);
  }
}

async function gqlRescanHistory() {
  showToast('Scanning HTTP history for GraphQL endpoints...');
  try {
    const r = await fetch('/api/graphql/rescan-history', { method: 'POST' });
    const data = await r.json();
    showToast(`Scan complete — ${data.new_endpoints} new endpoint${data.new_endpoints === 1 ? '' : 's'} found`);
    await gqlLoadEndpoints();
  } catch (e) {
    showToast('Rescan failed', true);
  }
}

async function _gqlFetchSchema(endpoint) {
  if (_gqlSchemaCache[endpoint]) return _gqlSchemaCache[endpoint];
  const r = await fetch('/api/graphql/schema?endpoint=' + encodeURIComponent(endpoint));
  const data = await r.json();
  if (data.schema) _gqlSchemaCache[endpoint] = data.schema;
  return data.schema;
}

function _gqlOpRowHtml(kind, field, info, onClick) {
  const args = (info.args || []).map(a => `${a.name}: ${a.type}`).join(', ');
  const color = kind === 'query' ? 'var(--green)' : 'var(--blue)';
  return `<div class="gql-op-item" style="padding:6px 8px;cursor:pointer;border-radius:3px;font-size:11px;line-height:1.5"
    onmouseover="this.style.background='var(--hov)'" onmouseout="this.style.background=''"
    onclick="${onClick}('${kind}', '${esc(field)}')">
    <span style="color:${color};font-weight:600">${esc(field)}</span>
    <span style="color:var(--txt2)">(${esc(args)})</span>
  </div>`;
}

function _gqlOpListHtml(schema, onClick, filterText, kindFilter) {
  const needle = (filterText || '').trim().toLowerCase();
  const matches = ([field]) => !needle || field.toLowerCase().includes(needle);
  const showQueries = kindFilter !== 'mutation';
  const showMutations = kindFilter !== 'query';
  const queries = showQueries ? Object.entries(schema.queries || {}).filter(matches) : [];
  const mutations = showMutations ? Object.entries(schema.mutations || {}).filter(matches) : [];
  if (!queries.length && !mutations.length) {
    return `<div class="empty" style="padding:10px 0;font-size:11px">${
      needle ? 'No operations match your filter.' : 'No queries/mutations in this schema.'
    }</div>`;
  }
  const section = (label, color, entries, kind) => {
    if (!entries.length) return '';
    return `
      <div style="font-size:10px;font-weight:700;color:${color};text-transform:uppercase;letter-spacing:.5px;
                  padding:8px 8px 4px;position:sticky;top:0;background:var(--bg2)">${label} (${entries.length})</div>
      ${entries.map(([field, info]) => _gqlOpRowHtml(kind, field, info, onClick)).join('')}`;
  };
  return section('Queries', 'var(--green)', queries, 'query')
    + (queries.length && mutations.length
        ? '<div style="height:1px;background:var(--bdr);margin:6px 0"></div>' : '')
    + section('Mutations', 'var(--blue)', mutations, 'mutation');
}

// ── header dict <-> textarea text helpers, shared by Schema Explorer + Query Builder ──

function _gqlHeadersToText(headers) {
  return Object.entries(headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n');
}

function _gqlHeadersFromText(text) {
  const headers = {};
  for (const line of (text || '').split('\n')) {
    const idx = line.indexOf(':');
    if (idx > 0) headers[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
  }
  return headers;
}

async function _gqlLoadNamedSessionsInto(selectId) {
  const sel = document.getElementById(selectId);
  if (!sel) return;
  try {
    const r = await fetch('/api/named-sessions');
    const sessions = await r.json();
    sel.innerHTML = '<option value="">Most recent captured request</option>' +
      sessions.map(s => `<option value="${esc(s.name)}">${esc(s.name)} (${esc(s.role)})</option>`).join('');
  } catch (e) { /* leave the default option in place */ }
}

async function _gqlFetchHeadersForEndpoint(endpoint, namedSession) {
  const qs = new URLSearchParams({ endpoint, ...(namedSession ? { named_session: namedSession } : {}) });
  const r = await fetch('/api/graphql/headers-for-endpoint?' + qs.toString());
  const data = await r.json();
  return data.headers || {};
}

async function gqlLoadSessionHeaders(namedSession) {
  if (!_gqlSelectedEndpoint) return;
  const headers = await _gqlFetchHeadersForEndpoint(_gqlSelectedEndpoint, namedSession);
  document.getElementById('gql-headers').value = _gqlHeadersToText(headers);
}

// Refilters the already-fetched schema client-side — no network call — so
// typing in the filter box stays instant even against a 1000+ operation schema.
function gqlFilterOpList() {
  const schema = _gqlSchemaCache[_gqlSelectedEndpoint];
  if (!schema) return;
  const filterText = document.getElementById('gql-op-filter').value;
  const kindFilter = document.getElementById('gql-op-kind-filter').value;
  const opList = document.getElementById('gql-op-list');
  opList.innerHTML = _gqlOpListHtml(schema, 'gqlPickOp', filterText, kindFilter);
}

async function gqlSelectEndpoint(endpoint) {
  _gqlSelectedEndpoint = endpoint;
  _gqlSelectedOp = null;
  const opList = document.getElementById('gql-op-list');
  document.getElementById('gql-op-filter').value = '';
  document.getElementById('gql-op-kind-filter').value = 'all';
  document.getElementById('gql-editor').value = '';
  document.getElementById('gql-preview').textContent = '';
  if (!endpoint) {
    opList.innerHTML = '';
    document.getElementById('gql-headers').value = '';
    return;
  }
  await _gqlLoadNamedSessionsInto('gql-session-select');
  document.getElementById('gql-session-select').value = '';
  document.getElementById('gql-headers').value =
    _gqlHeadersToText(await _gqlFetchHeadersForEndpoint(endpoint, ''));
  const schema = await _gqlFetchSchema(endpoint);
  opList.innerHTML = schema
    ? _gqlOpListHtml(schema, 'gqlPickOp')
    : '<div class="empty" style="padding:10px 0;font-size:11px">No schema stored yet — try Re-run introspection.</div>';
}

async function gqlPickOp(operation, fieldName) {
  _gqlSelectedOp = { operation, field_name: fieldName };
  try {
    const r = await fetch('/api/graphql/build', {
      method: 'POST',
      headers: {'content-type': 'application/json'},
      body: JSON.stringify({ endpoint: _gqlSelectedEndpoint, operation, field_name: fieldName }),
    });
    const data = await r.json();
    if (data.error) { showToast(data.error, true); return; }
    document.getElementById('gql-editor').value = JSON.stringify(
      { query: data.query, variables: data.variables }, null, 2
    );
    gqlUpdatePreview();
  } catch (e) {
    showToast('Failed to build query', true);
  }
}

async function gqlReintrospect() {
  if (!_gqlSelectedEndpoint) { showToast('Select an endpoint first', true); return; }
  const headers = _gqlHeadersFromText(document.getElementById('gql-headers').value);
  showToast('Re-running introspection...');
  try {
    const r = await fetch('/api/graphql/introspect', {
      method: 'POST',
      headers: {'content-type': 'application/json'},
      body: JSON.stringify({ endpoint: _gqlSelectedEndpoint, headers }),
    });
    const data = await r.json();
    if (!data.ok) { showToast(data.error || 'Introspection failed', true); return; }
    delete _gqlSchemaCache[_gqlSelectedEndpoint];
    const opToRestore = _gqlSelectedOp;
    await gqlSelectEndpoint(_gqlSelectedEndpoint);
    // Re-populate the editor for whichever operation was open before the
    // re-introspect, instead of leaving it blank — the user shouldn't have
    // to re-find and re-click the same operation after every refresh.
    if (opToRestore) {
      const schema = _gqlSchemaCache[_gqlSelectedEndpoint];
      const stillExists = schema && (
        opToRestore.operation === 'query' ? schema.queries : schema.mutations
      )[opToRestore.field_name];
      if (stillExists) await gqlPickOp(opToRestore.operation, opToRestore.field_name);
    }
    showToast('Schema refreshed');
  } catch (e) {
    showToast('Introspection request failed', true);
  }
}

function gqlUpdatePreview() {
  const raw = document.getElementById('gql-editor').value;
  const preview = document.getElementById('gql-preview');
  try {
    const parsed = JSON.parse(raw);
    preview.innerHTML = _gqlKeyword(parsed.query || '') +
      (parsed.variables ? '\n\n' + _fmtJsonTree(JSON.stringify(parsed.variables)) : '');
  } catch (e) {
    preview.textContent = raw;
  }
}

// Headers used for both Send actions: whatever is in the editable header
// field (prefilled from real traffic/a named session, per gqlSelectEndpoint),
// with Content-Type forced to application/json since the body is always a GraphQL JSON payload.
function _gqlHeadersTextForSend() {
  const headers = _gqlHeadersFromText(document.getElementById('gql-headers').value);
  headers['Content-Type'] = 'application/json';
  return _gqlHeadersToText(headers);
}

function gqlSendToRepeater() {
  if (!_gqlSelectedEndpoint) { showToast('Build a query first', true); return; }
  let parsed;
  try {
    parsed = JSON.parse(document.getElementById('gql-editor').value);
  } catch (e) {
    showToast('Editor content is not valid JSON', true);
    return;
  }
  const label = _gqlSelectedOp ? `${_gqlSelectedOp.operation} ${_gqlSelectedOp.field_name}` : 'GraphQL';
  repNewTab({
    method: 'POST',
    url: _gqlSelectedEndpoint,
    headers: _gqlHeadersTextForSend(),
    body: JSON.stringify(parsed),
    label,
  });
  switchMain('repeater');
}

function gqlSendToFuzzer() {
  if (!_gqlSelectedEndpoint) { showToast('Build a query first', true); return; }
  let parsed;
  try {
    parsed = JSON.parse(document.getElementById('gql-editor').value);
  } catch (e) {
    showToast('Editor content is not valid JSON', true);
    return;
  }
  document.getElementById('gql-fuzz-method').value = 'POST';
  document.getElementById('gql-fuzz-url').value = _gqlSelectedEndpoint;
  document.getElementById('gql-fuzz-headers').value = _gqlHeadersTextForSend();
  document.getElementById('gql-fuzz-body').value = JSON.stringify(parsed);
  switchMain('graphql');
  switchGraphqlSub('fuzzer');
  gqlFuzzPreviewVars();
}

// ── GraphQL Fuzzer sub-tab ───────────────────────────────────────────────────

let _gqlFuzzJobId = null;
let _gqlFuzzPollTimer = null;

function gqlFuzzLoadFromRepeater() {
  const id = _repActiveId;
  if (!id) { showToast('No active Repeater tab', true); return; }
  document.getElementById('gql-fuzz-method').value  = document.getElementById(`rep-method-${id}`)?.value || 'POST';
  document.getElementById('gql-fuzz-url').value     = document.getElementById(`rep-url-${id}`)?.value || '';
  document.getElementById('gql-fuzz-headers').value = document.getElementById(`rep-headers-${id}`)?.value || '';
  document.getElementById('gql-fuzz-body').value    = document.getElementById(`rep-body-${id}`)?.value || '';
  gqlFuzzPreviewVars();
}

async function gqlFuzzPreviewVars() {
  const body = document.getElementById('gql-fuzz-body').value;
  const el = document.getElementById('gql-fuzz-vars');
  if (!body.trim()) { el.textContent = 'No variables detected yet.'; return; }
  try {
    const r = await fetch('/api/graphql/fuzz/extract-vars', {
      method: 'POST',
      headers: {'content-type': 'application/json'},
      body: JSON.stringify({ body }),
    });
    const data = await r.json();
    if (data.error) { el.textContent = data.error; return; }
    el.innerHTML = 'Variables: ' + data.variables.map(v =>
      `<code>${esc(v.name)}</code> (${esc(v.inferred_type)})`
    ).join(', ');
  } catch (e) {
    el.textContent = 'Could not parse variables.';
  }
}

function _gqlFuzzResetResults() {
  document.getElementById('gql-fuzz-results-tbody').innerHTML =
    '<tr><td colspan="8" style="padding:12px 10px;color:var(--txt2);font-family:inherit">No results yet — load a request and click Start.</td></tr>';
}

async function gqlFuzzStart() {
  const method = document.getElementById('gql-fuzz-method').value.trim() || 'POST';
  const url    = document.getElementById('gql-fuzz-url').value.trim();
  if (!url) { showToast('Enter a target URL first', true); return; }

  const headersRaw = document.getElementById('gql-fuzz-headers').value;
  const headers = {};
  for (const line of headersRaw.split('\n')) {
    const idx = line.indexOf(':');
    if (idx > 0) headers[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
  }
  const body = document.getElementById('gql-fuzz-body').value;
  const payloadSrc = document.querySelector('input[name="gql-fuzz-payload-src"]:checked')?.value || 'yaml';
  const customPayloads = document.getElementById('gql-fuzz-custom-payloads').value;

  _gqlFuzzResetResults();
  document.getElementById('gql-fuzz-status').textContent = 'status: starting...';
  document.getElementById('gql-fuzz-start-btn').disabled = true;
  document.getElementById('gql-fuzz-stop-btn').disabled = false;
  const bar = document.getElementById('gql-fuzz-progress-bar');
  const fill = document.getElementById('gql-fuzz-progress-fill');
  bar.style.display = 'block';
  fill.style.width = '0%';

  try {
    const resp = await fetch('/api/graphql/fuzz/run', {
      method: 'POST',
      headers: {'content-type': 'application/json'},
      body: JSON.stringify({
        method, url, headers, body,
        payload_source: payloadSrc, custom_payloads: customPayloads,
      }),
    });
    const data = await resp.json();
    if (data.error) { _gqlFuzzDone('error: ' + data.error); return; }
    _gqlFuzzJobId = data.job_id;
    _gqlFuzzPoll();
  } catch (e) {
    _gqlFuzzDone('request failed: ' + e.message);
  }
}

function _gqlFuzzPoll() {
  if (!_gqlFuzzJobId) return;
  clearTimeout(_gqlFuzzPollTimer);
  _gqlFuzzPollTimer = setTimeout(async () => {
    try {
      const r = await fetch('/api/graphql/fuzz/results/' + _gqlFuzzJobId);
      const data = await r.json();
      _gqlFuzzRenderResults(data.results || []);
      const prog = data.progress || {};
      const done = prog.done || 0;
      const total = prog.total || 0;
      const pct = total > 0 ? Math.round((done / total) * 100) : 0;
      document.getElementById('gql-fuzz-progress-fill').style.width = pct + '%';
      if (data.status === 'running' || data.status === 'queued') {
        document.getElementById('gql-fuzz-status').textContent = `status: running — ${done} / ${total} requests...`;
        _gqlFuzzPoll();
      } else {
        _gqlFuzzDone(`status: ${data.status} — ${done} requests sent`);
      }
    } catch (e) {
      _gqlFuzzDone('poll error: ' + e.message);
    }
  }, 600);
}

function _gqlFuzzDone(msg) {
  document.getElementById('gql-fuzz-status').textContent = msg;
  document.getElementById('gql-fuzz-start-btn').disabled = false;
  document.getElementById('gql-fuzz-stop-btn').disabled = true;
  clearTimeout(_gqlFuzzPollTimer);
}

async function gqlFuzzStop() {
  if (!_gqlFuzzJobId) return;
  try {
    await fetch('/api/graphql/fuzz/stop/' + _gqlFuzzJobId, { method: 'POST' });
    document.getElementById('gql-fuzz-status').textContent = 'status: stopping...';
    document.getElementById('gql-fuzz-stop-btn').disabled = true;
  } catch (e) { /* ignore */ }
}

function _gqlFuzzRenderResults(results) {
  if (!results || results.length === 0) return;
  const tbody = document.getElementById('gql-fuzz-results-tbody');
  tbody.innerHTML = '';
  for (const r of results) {
    const tr = document.createElement('tr');
    if (r.hit) tr.style.cssText = 'background:rgba(255,140,0,.12)';
    const payload = String(r.payload || '').slice(0, 80).replace(/</g,'&lt;').replace(/>/g,'&gt;');
    const hitBadge = r.hit ? '<span style="color:var(--orange);font-weight:600">YES</span>' : '';
    const errBadge = r.errors_present ? '<span style="color:var(--yellow)">yes</span>' : '';
    tr.innerHTML = `
      <td style="padding:3px 8px;border-bottom:1px solid var(--bdr)">${r.n}</td>
      <td style="padding:3px 8px;border-bottom:1px solid var(--bdr)">${esc(r.variable)}</td>
      <td style="padding:3px 8px;border-bottom:1px solid var(--bdr);max-width:220px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis" title="${payload}">${payload}</td>
      <td style="padding:3px 8px;border-bottom:1px solid var(--bdr)">${r.status_code ?? ''}</td>
      <td style="padding:3px 8px;border-bottom:1px solid var(--bdr)">${r.duration_ms ?? ''}</td>
      <td style="padding:3px 8px;border-bottom:1px solid var(--bdr)">${r.length_bytes ?? ''}</td>
      <td style="padding:3px 8px;border-bottom:1px solid var(--bdr)">${errBadge}</td>
      <td style="padding:3px 8px;border-bottom:1px solid var(--bdr)">${hitBadge}</td>
    `;
    tbody.appendChild(tr);
  }
}

// ── GraphQL tab visibility (plugin-gated) ────────────────────────────────────

function _gqlTabVisibility(plugins) {
  const p = plugins.find(x => x.name === 'GraphQL Fuzzer');
  const hidden = !!(p && !p.enabled);
  const tab = document.getElementById('mt-graphql');
  if (!tab) return;
  tab.style.display = hidden ? 'none' : '';
  if (hidden && document.getElementById('panel-graphql').classList.contains('on')) {
    switchMain('overview');
  }
}

function switchProxySub(sub) {
  const isHistory   = sub === 'history';
  const isIntercept = sub === 'intercept';
  const isSitemap   = sub === 'sitemap';
  const isIssues    = sub === 'issues';
  const isSettings  = sub === 'psettings';
  document.getElementById('proxy-history').style.display   = isHistory   ? 'flex' : 'none';
  document.getElementById('proxy-intercept').style.display = isIntercept ? 'flex' : 'none';
  document.getElementById('proxy-sitemap').style.display   = isSitemap   ? 'flex' : 'none';
  document.getElementById('proxy-issues').style.display    = isIssues    ? 'flex' : 'none';
  document.getElementById('proxy-settings').style.display  = isSettings  ? 'flex' : 'none';
  document.getElementById('st-history').classList.toggle('on',   isHistory);
  document.getElementById('st-intercept').classList.toggle('on', isIntercept);
  document.getElementById('st-sitemap').classList.toggle('on',   isSitemap);
  document.getElementById('st-issues').classList.toggle('on',    isIssues);
  document.getElementById('st-psettings').classList.toggle('on', isSettings);
  if (isSettings) { loadSettings(); loadScanConfig(); loadMatchReplace(); updateSetupPort(); updateSetupAiStatus(); }
  if (isIntercept) { interceptLoadStatus(); }
  if (isSitemap) renderSmHostList();
  if (isIssues) renderAllIssues();
}

