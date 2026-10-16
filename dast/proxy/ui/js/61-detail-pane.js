// ── HTTP detail pane (proxy history + site map) ────────────────────────
// A compact summary header, then Request and Response panes, each with its own
// Pretty | Raw toggle (sticky across selections, Pretty by default):
//   Pretty — collapsible Headers / Cookies / Query params / Body sections,
//            JSON bodies as a collapsible tree.
//   Raw    — the original HTTP message text, untouched, for copy/paste.
// Everything rendered here is attacker-controlled target data, so every value
// goes through esc() and inline handlers use jsArg().

// Section open/closed state, keyed by data-sec. Persists across selections.
const _dpSectionOpen = {
  'req-headers': true, 'req-cookies': false, 'req-query': true, 'req-body': true,
  'resp-headers': true, 'resp-cookies': false, 'resp-body': true,
};

function _dpSecToggled(el) {
  const key = el.dataset.sec;
  if (key) _dpSectionOpen[key] = el.open;
}

// Flatten a header dict into [name, value] pairs. Repeated headers (e.g.
// Set-Cookie) may arrive as a list — each occurrence becomes its own row.
function _dpHeaderPairs(headers) {
  const pairs = [];
  for (const [name, value] of Object.entries(headers || {})) {
    if (Array.isArray(value)) value.forEach(v => pairs.push([name, String(v ?? '')]));
    else pairs.push([name, String(value ?? '')]);
  }
  return pairs;
}

function _dpParseCookieHeader(value) {
  return String(value || '').split(';').map(part => part.trim()).filter(Boolean).map(part => {
    const eq = part.indexOf('=');
    return eq >= 0 ? [part.slice(0, eq), part.slice(eq + 1)] : [part, ''];
  });
}

// "name=value; Path=/; HttpOnly" -> ["name", "value", "Path=/; HttpOnly"]
function _dpParseSetCookie(value) {
  const text = String(value || '');
  const semi = text.indexOf(';');
  const pair = semi >= 0 ? text.slice(0, semi) : text;
  const attributes = semi >= 0 ? text.slice(semi + 1).trim() : '';
  const eq = pair.indexOf('=');
  return eq >= 0
    ? [pair.slice(0, eq).trim(), pair.slice(eq + 1), attributes]
    : [pair.trim(), '', attributes];
}

function _dpQueryPairs(url) {
  try {
    return Array.from(new URL(url).searchParams.entries());
  } catch (_) {
    return [];
  }
}

function _dpFormatSize(chars) {
  if (chars == null || isNaN(chars)) return '';
  if (chars < 1024) return `${chars} B`;
  if (chars < 1024 * 1024) return `${(chars / 1024).toFixed(1)} KB`;
  return `${(chars / (1024 * 1024)).toFixed(1)} MB`;
}

function _dpHeaderValue(headers, wanted) {
  for (const [name, value] of _dpHeaderPairs(headers)) {
    if (name.toLowerCase() === wanted) return value;
  }
  return '';
}

function _dpStatusClass(status) {
  const n = parseInt(status, 10);
  if (!n) return 'dp-st-none';
  if (n >= 500) return 'dp-st-5';
  if (n >= 400) return 'dp-st-4';
  if (n >= 300) return 'dp-st-3';
  return 'dp-st-2';
}

function _dpKvRows(pairs) {
  return pairs.map(([name, value]) =>
    `<div class="dp-k">${esc(name)}</div><div class="dp-v">${value === '' ? '<span class="dp-empty-val">empty</span>' : esc(value)}</div>`
  ).join('');
}

function _dpSection(key, title, count, innerHtml) {
  const open = _dpSectionOpen[key] !== false;
  return `<details class="dp-sec" data-sec="${esc(key)}" ${open ? 'open' : ''} ontoggle="_dpSecToggled(this)">
    <summary><span class="dp-chev"></span><span class="dp-sec-title">${esc(title)}</span>${count !== null ? `<span class="dp-count">${esc(String(count))}</span>` : ''}</summary>
    ${innerHtml}
  </details>`;
}

// Body text only (no headers), honouring the per-pane raw/pretty mode.
function _dpFmtBody(body, mode) {
  if (!body) return '';
  return mode === 'pretty' && _isJsonBody(body) ? _fmtJsonTree(body) : esc(body);
}

// Active (non-dismissed) findings for the entry, mirroring what the Findings
// view lists, plus the dismissed count so the badge can point at the FP tab.
function _dpFindingCounts(d) {
  let active = 0, dismissed = 0, topRank = 9;
  const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  for (const f of (d.findings || [])) {
    if (!f.title) continue;
    if (f.import_status && f.import_status !== 'confirmed' && !f.confirmed) continue;
    if (f.dismissed) { dismissed++; continue; }
    active++;
    topRank = Math.min(topRank, rank[(f.severity || 'info').toLowerCase()] ?? 4);
  }
  return { active, dismissed, topRank };
}

function _dpFindingsBadge(d) {
  const { active, dismissed, topRank } = _dpFindingCounts(d);
  if (!active && !dismissed) return '';
  const sevName = ['critical', 'high', 'medium', 'low', 'info'][topRank] || 'info';
  const label = active
    ? `${active} finding${active !== 1 ? 's' : ''}`
    : `${dismissed} dismissed`;
  const title = active
    ? 'Open this request\'s findings in the Findings view'
    : 'Open this request\'s dismissed findings (False Positives)';
  return `<button class="dp-findings ${active ? 'dp-sev-' + sevName : 'dp-findings-muted'}"
    title="${esc(title)}" onclick="showEntryFindings(${jsArg(d.id)})"><span class="dp-dot"></span>${esc(label)}</button>`;
}

function _dpSummary(d) {
  let host = d.host || '';
  let pathAndQuery = d.path || '';
  try {
    const parsed = new URL(d.url);
    host = `${parsed.protocol}//${parsed.host}`;
    pathAndQuery = parsed.pathname + parsed.search;
  } catch (_) { /* keep store values */ }
  const contentLength = _dpHeaderValue(d.response_headers, 'content-length');
  const size = contentLength ? _dpFormatSize(parseInt(contentLength, 10))
    : (d.response_body ? _dpFormatSize(d.response_body.length) : '');
  const contentType = (d.content_type || _dpHeaderValue(d.response_headers, 'content-type')).split(';')[0].trim();
  const meta = [
    d.duration_ms != null && d.status ? `${Math.round(d.duration_ms)} ms` : '',
    size,
    contentType,
  ].filter(Boolean).map(esc).join('<span class="dp-meta-sep">·</span>');
  return `<div class="dp-summary">
    <div class="dp-sum-row">
      <span class="dp-method">${esc(d.method || '')}</span>
      <span class="dp-status ${_dpStatusClass(d.status)}">${esc(String(d.status || 'pending'))}</span>
      <span class="dp-meta">${meta}</span>
      <span class="dp-fill"></span>
      ${_dpFindingsBadge(d)}
    </div>
    <div class="dp-url" title="${esc(d.url || '')}"><span class="dp-host">${esc(host)}</span><span class="dp-path">${esc(pathAndQuery)}</span></div>
  </div>`;
}

function _dpPaneToggle(pane, isGraphQL, mode) {
  return `<div class="pane-view-toggle">
    <button class="${mode === 'pretty' ? 'on' : ''}" onclick="_setPaneView(${jsArg(pane)},'pretty')" title="Headers, cookies and params grouped; JSON as a tree">Pretty</button>
    <button class="${mode === 'raw' ? 'on' : ''}" onclick="_setPaneView(${jsArg(pane)},'raw')" title="Original HTTP message text">Raw</button>
    ${isGraphQL ? `<button class="gql-btn" onclick="_setPaneView('gql',true)">GraphQL</button>` : ''}
  </div>`;
}

function _dpRequestSections(d) {
  const pairs = _dpHeaderPairs(d.request_headers);
  const headerRows = pairs.filter(([name]) => name.toLowerCase() !== 'cookie');
  const cookies = pairs.filter(([name]) => name.toLowerCase() === 'cookie')
    .flatMap(([, value]) => _dpParseCookieHeader(value));
  const query = _dpQueryPairs(d.url);
  let html = _dpSection('req-headers', 'Headers', headerRows.length,
    `<div class="dp-kv">${_dpKvRows(headerRows)}</div>`);
  if (cookies.length) {
    html += _dpSection('req-cookies', 'Cookies', cookies.length, `<div class="dp-kv">${_dpKvRows(cookies)}</div>`);
  }
  if (query.length) {
    html += _dpSection('req-query', 'Query params', query.length, `<div class="dp-kv">${_dpKvRows(query)}</div>`);
  }
  if (d.request_body) {
    html += _dpSection('req-body', 'Body', _dpFormatSize(d.request_body.length),
      `<pre class="dp-body">${_dpFmtBody(d.request_body, 'pretty')}</pre>`);
  }
  return html;
}

function _dpResponseSections(d) {
  if (!d.status) return '<div class="dp-none">No response yet</div>';
  const pairs = _dpHeaderPairs(d.response_headers);
  const headerRows = pairs.filter(([name]) => name.toLowerCase() !== 'set-cookie');
  const setCookies = pairs.filter(([name]) => name.toLowerCase() === 'set-cookie')
    .map(([, value]) => _dpParseSetCookie(value));
  let html = _dpSection('resp-headers', 'Headers', headerRows.length,
    `<div class="dp-kv">${_dpKvRows(headerRows)}</div>`);
  if (setCookies.length) {
    const rows = setCookies.map(([name, value, attributes]) =>
      `<div class="dp-k">${esc(name)}</div><div class="dp-v">${value === '' ? '<span class="dp-empty-val">empty</span>' : esc(value)}${attributes ? `<div class="dp-attr">${esc(attributes)}</div>` : ''}</div>`
    ).join('');
    html += _dpSection('resp-cookies', 'Set-Cookie', setCookies.length, `<div class="dp-kv">${rows}</div>`);
  }
  html += _dpSection('resp-body', 'Body', d.response_body ? _dpFormatSize(d.response_body.length) : null,
    d.response_body
      ? `<pre class="dp-body">${_dpFmtBody(d.response_body, 'pretty')}</pre>`
      : '<div class="dp-none">Empty body</div>');
  return html;
}

function buildRRHtml(d) {
  const noteBanner = d.manual_note
    ? `<div class="dp-note"><span class="dp-note-lbl">AI note</span><span>${esc(d.manual_note)}</span></div>`
    : '';
  const isGQL    = _isGraphQLBody(d.request_body);
  const reqMode  = _paneViewMode.req;
  const respMode = _paneViewMode.resp;
  const head = _dpSummary(d) + noteBanner;

  if (isGQL && _paneViewMode.gql === true) {
    return `<div class="dp">${head}
      <div class="pane-hdr">GraphQL
        <div class="pane-view-toggle">
          <button onclick="_setPaneView('gql',false)">Raw</button>
          <button class="on">GraphQL</button>
        </div>
      </div>
      <div id="pane-gql-area" class="dp-gql">${_buildGQLView(d.request_body, d.response_body)}</div>
    </div>`;
  }

  const reqContent = reqMode === 'raw'
    ? `<pre class="dp-raw">${fmtReq(d, 'raw')}</pre>`
    : _dpRequestSections(d);
  const respContent = respMode === 'raw'
    ? `<pre class="dp-raw">${fmtResp(d, 'raw')}</pre>`
    : _dpResponseSections(d);
  return `<div class="dp">${head}
    <div class="split-wrap">
      <div class="pane">
        <div class="pane-hdr">Request${_dpPaneToggle('req', isGQL, reqMode)}</div>
        <div class="code-area" id="pane-req-area">${reqContent}</div>
      </div>
      <div class="pane">
        <div class="pane-hdr">Response${_dpPaneToggle('resp', false, respMode)}</div>
        <div class="code-area" id="pane-resp-area">${respContent}</div>
      </div>
    </div>
  </div>`;
}
