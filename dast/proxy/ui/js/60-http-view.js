// ── shared render helpers ──────────────────────────────────────────────
// buildRRHtml (the request/response detail pane) lives in 61-detail-pane.js.

// Render a finding's multi-request evidence chain (f.steps) as a clean numbered
// table instead of a wall of text. Each step is one request in the proof
// (e.g. a BOLA differential: foreign-write, foreign-read, control, delete). This
// is what makes a multi-request finding legible — the evidence is no longer
// pinned to a single request. Used by the Findings view.
function _buildFindingSteps(f) {
  const steps = Array.isArray(f.steps) ? f.steps : null;
  if (!steps || !steps.length) return '';
  const mColor = m => ({ GET: '#4ec9b0', POST: '#569cd6', PUT: '#d7ba7d',
    PATCH: '#d7ba7d', DELETE: '#ff6b6b' }[(m || '').toUpperCase()] || 'var(--txt)');
  const sColor = s => {
    const n = parseInt(s, 10);
    return n >= 500 ? '#ff6b6b' : n >= 400 ? '#e5a23b'
      : (n >= 200 && n < 300) ? '#7ec87e' : 'var(--txt2)';
  };
  const rows = steps.map((s, i) => {
    const note = s.note ? `<div style="color:var(--txt2);font-size:9px;margin-top:1px">${esc(s.note)}</div>` : '';
    return `<tr style="border-bottom:1px solid var(--bdr)">
      <td style="padding:3px 6px;color:var(--txt2);text-align:right;vertical-align:top">${i + 1}</td>
      <td style="padding:3px 6px;font-weight:600;color:${mColor(s.method)};vertical-align:top">${esc((s.method || '').toUpperCase())}</td>
      <td style="padding:3px 6px;font-family:monospace;word-break:break-all;vertical-align:top">${esc(s.url || '')}${note}</td>
      <td style="padding:3px 6px;color:${sColor(s.status)};font-weight:600;text-align:right;vertical-align:top">${esc(String(s.status ?? ''))}</td>
      <td style="padding:3px 6px;color:var(--txt2);vertical-align:top">${esc(s.label || '')}</td>
    </tr>`;
  }).join('');
  return `<div style="margin-top:8px">
    <div style="font-size:9px;color:var(--txt2);text-transform:uppercase;letter-spacing:.4px;margin-bottom:3px">Evidence — ${steps.length}-request chain</div>
    <table style="width:100%;border-collapse:collapse;font-size:10px;background:#111;border:1px solid var(--bdr);border-radius:3px">
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

// ── JSON collapsible tree ───────────────────────────────────────────────
// req/resp: 'pretty' | 'raw', sticky across selections. gql: GraphQL split view.
const _paneViewMode = { req: 'pretty', resp: 'pretty', gql: false };

function _isJsonBody(body) {
  if (!body) return false;
  const s = body.trim();
  return s.startsWith('{') || s.startsWith('[');
}

function _isGraphQLBody(body) {
  if (!body) return false;
  try {
    const d = JSON.parse(body);
    const items = Array.isArray(d) ? d : [d];
    return items.some(item => typeof item === 'object' && typeof item.query === 'string' &&
      /^\s*(query|mutation|subscription|{)/.test(item.query));
  } catch(_) { return false; }
}

// ── GraphQL viewer ──────────────────────────────────────────────────────────

function _gqlKeyword(q) {
  // Syntax-colour a raw GraphQL query string.
  // Order matters: field/argument names are coloured first on plain text,
  // then keywords and introspection fields override specific tokens,
  // then comments and strings are applied last.
  // This prevents later regexes from matching inside already-injected <span> tags.
  const _KW = new Set(['query','mutation','subscription','fragment','on']);
  const _INTRO = new Set(['__schema','__type','__typename']);
  const escaped = q
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

  // Split into lines; process each line so comment spans don't bleed
  return escaped.split('\n').map(line => {
    // Comments — colour entire rest-of-line, no further processing
    const commentIdx = line.indexOf('#');
    let prefix = commentIdx >= 0 ? line.slice(0, commentIdx) : line;
    const commentPart = commentIdx >= 0
      ? `<span style="color:#546e7a;font-style:italic">${line.slice(commentIdx)}</span>`
      : '';

    // String literals — pull out first so identifiers inside strings aren't coloured
    prefix = prefix.replace(/"([^"]*)"/g, '<span style="color:#c3e88d">"$1"</span>');

    // Field names and argument names: word followed by ( or :
    // Only applied to non-string, non-comment segments
    prefix = prefix.replace(/\b([A-Za-z_]\w*)(\s*)([:(])/g, (m, name, sp, after) => {
      if (_KW.has(name)) return m;      // keywords handled below
      if (_INTRO.has(name)) return m;   // introspection handled below
      return `<span style="color:#82aaff">${name}</span>${sp}${after}`;
    });

    // Keywords
    prefix = prefix.replace(
      /\b(query|mutation|subscription|fragment|on)\b(?![^<]*>)/g,
      '<span style="color:#c792ea">$1</span>'
    );

    // Introspection built-ins
    prefix = prefix.replace(
      /\b(__schema|__type|__typename)\b(?![^<]*>)/g,
      '<span style="color:#f07178">$1</span>'
    );

    return prefix + commentPart;
  }).join('\n');
}

function _buildGQLView(reqBody, respBody) {
  let ops = [];
  try {
    const d = JSON.parse(reqBody || '');
    ops = Array.isArray(d) ? d : [d];
  } catch(_) { return '<div style="color:var(--txt2);padding:8px">Could not parse GraphQL body</div>'; }

  let respData = null;
  try { respData = respBody ? JSON.parse(respBody) : null; } catch(_) {}

  const isBatch = ops.length > 1;
  let html = '';

  if (isBatch) {
    html += `<div style="padding:4px 8px;background:#2a1a00;border-bottom:1px solid var(--bdr);
      font-size:10px;color:#ff9800">Batch request — ${ops.length} operations</div>`;
  }

  ops.forEach((op, idx) => {
    const query = op.query || '';
    const vars = op.variables || null;
    const opName = op.operationName || _inferOpName(query) || (isBatch ? `Operation ${idx+1}` : '');

    // Determine operation type
    const opTypeM = query.match(/^\s*(query|mutation|subscription)/);
    const opType = opTypeM ? opTypeM[1] : 'query';
    const opTypeColor = opType === 'mutation' ? '#f07178' : opType === 'subscription' ? '#c792ea' : '#82aaff';

    // Response data for this operation
    let opResp = null;
    if (respData) {
      if (Array.isArray(respData)) opResp = respData[idx];
      else if (idx === 0) opResp = respData;
    }
    const respErrors = opResp?.errors || (idx === 0 && respData?.errors) || null;
    const respDataVal = opResp?.data || (idx === 0 && respData?.data) || null;

    html += `<div style="border-bottom:1px solid var(--bdr3,#252525)">`;

    // Operation header
    html += `<div style="display:flex;align-items:center;gap:8px;padding:6px 10px;
      background:var(--bg2);border-bottom:1px solid var(--bdr);font-size:11px">
      <span style="padding:1px 7px;border-radius:3px;background:${opTypeColor}22;
        color:${opTypeColor};border:1px solid ${opTypeColor}55;font-size:10px;
        font-weight:600;text-transform:uppercase">${esc(opType)}</span>
      ${opName ? `<span style="color:var(--txt);font-weight:600">${esc(opName)}</span>` : ''}
      ${isBatch ? `<span style="color:var(--txt2);font-size:10px">#${idx+1}</span>` : ''}
    </div>`;

    // Two-column: query left, response right
    html += `<div style="display:grid;grid-template-columns:1fr 1fr;min-height:120px">`;

    // Query panel
    html += `<div style="border-right:1px solid var(--bdr);display:flex;flex-direction:column">
      <div style="padding:3px 8px;font-size:9px;color:var(--txt2);text-transform:uppercase;
        letter-spacing:.4px;border-bottom:1px solid var(--bdr3,#252525);background:var(--bg)">
        Query</div>
      <pre style="margin:0;padding:8px;font-size:10.5px;overflow:auto;white-space:pre;
        color:var(--txt);flex:1;line-height:1.5">${_gqlKeyword(query)}</pre>`;

    if (vars) {
      html += `<div style="border-top:1px solid var(--bdr3,#252525);padding:3px 8px;
        font-size:9px;color:var(--txt2);text-transform:uppercase;letter-spacing:.4px;
        background:var(--bg)">Variables</div>
        <pre style="margin:0;padding:8px;font-size:10.5px;overflow:auto;
          color:var(--txt);max-height:120px">${_fmtJsonTree(JSON.stringify(vars))}</pre>`;
    }
    html += `</div>`;

    // Response panel
    html += `<div style="display:flex;flex-direction:column">
      <div style="padding:3px 8px;font-size:9px;color:var(--txt2);text-transform:uppercase;
        letter-spacing:.4px;border-bottom:1px solid var(--bdr3,#252525);background:var(--bg)">
        Response data</div>`;

    if (respErrors && respErrors.length) {
      html += `<div style="padding:6px 8px;background:#2a1a1a;border-bottom:1px solid var(--bdr)">`;
      respErrors.forEach(err => {
        const msg = (err.message || err) + '';
        const locs = err.locations ? ` (line ${err.locations[0]?.line}, col ${err.locations[0]?.column})` : '';
        html += `<div style="color:#ef5350;font-size:10px;margin-bottom:3px">
          &#9888; ${esc(msg)}${esc(locs)}</div>`;
      });
      html += `</div>`;
    }

    if (respDataVal !== null && respDataVal !== undefined) {
      html += `<pre style="margin:0;padding:8px;font-size:10.5px;overflow:auto;
        color:var(--txt);flex:1;line-height:1.5">${_fmtJsonTree(JSON.stringify(respDataVal))}</pre>`;
    } else if (!respErrors) {
      html += `<div style="padding:16px 8px;color:var(--txt2);font-size:11px">No response yet</div>`;
    }
    html += `</div></div></div>`;
  });

  return html;
}

function _inferOpName(query) {
  const m = query.match(/^\s*(?:query|mutation|subscription)\s+(\w+)/);
  return m ? m[1] : null;
}

// Build a collapsible DOM tree from a parsed JSON value.
// Returns an HTML string — inline so it can slot into a <pre>.
function _buildJsonTree(val, indent) {
  indent = indent || 0;
  const pad = '  '.repeat(indent);
  const padI = '  '.repeat(indent + 1);

  if (val === null) return `<span class="jp-null">null</span>`;
  if (typeof val === 'boolean') return `<span class="jp-bool">${val}</span>`;
  if (typeof val === 'number') return `<span class="jp-num">${val}</span>`;
  if (typeof val === 'string') {
    return `<span class="jp-str">"${esc(val)}"</span>`;
  }

  if (Array.isArray(val)) {
    if (val.length === 0) return `<span class="jp-bracket">[]</span>`;
    const uid = 'jp' + Math.random().toString(36).slice(2);
    const summary = `<span class="jp-sum">[…${val.length}]</span>`;
    const items = val.map((v, i) => {
      const comma = i < val.length - 1 ? ',' : '';
      return `<span class="jp-row">${_buildJsonTree(v, indent + 1)}${comma}</span>`;
    }).join('');
    return (
      `<span class="jp-cl">` +
        `<span class="jp-toggle" onclick="_jpToggle(this)" title="collapse">▾</span>` +
        `<span class="jp-bracket">[</span>${summary}` +
        `<span class="jp-body" id="${uid}">\n${items}${pad}</span>` +
        `<span class="jp-bracket">]</span>` +
      `</span>`
    );
  }

  if (typeof val === 'object') {
    const keys = Object.keys(val);
    if (keys.length === 0) return `<span class="jp-bracket">{}</span>`;
    const uid = 'jp' + Math.random().toString(36).slice(2);
    const summary = `<span class="jp-sum">{${keys.length} key${keys.length !== 1 ? 's' : ''}}</span>`;
    const items = keys.map((k, i) => {
      const comma = i < keys.length - 1 ? ',' : '';
      return `<span class="jp-row"><span class="jp-key">"${esc(k)}"</span>: ${_buildJsonTree(val[k], indent + 1)}${comma}</span>`;
    }).join('');
    return (
      `<span class="jp-cl">` +
        `<span class="jp-toggle" onclick="_jpToggle(this)" title="collapse">▾</span>` +
        `<span class="jp-bracket">{</span>${summary}` +
        `<span class="jp-body" id="${uid}">\n${items}${pad}</span>` +
        `<span class="jp-bracket">}</span>` +
      `</span>`
    );
  }

  return esc(String(val));
}

function _jpToggle(btn) {
  const cl = btn.closest('.jp-cl');
  if (!cl) return;
  const body = cl.querySelector(':scope > .jp-body');
  const sum  = cl.querySelector(':scope > .jp-sum');
  if (!body || !sum) return;
  const collapsed = body.style.display === 'none';
  body.style.display = collapsed ? '' : 'none';
  sum.style.display  = collapsed ? 'none' : 'inline';
  btn.textContent    = collapsed ? '▾' : '▸';
  btn.title          = collapsed ? 'collapse' : 'expand';
}

function _fmtJsonTree(body) {
  try {
    return `<span class="json-pretty">${_buildJsonTree(JSON.parse(body))}</span>`;
  } catch (_) {
    return esc(body);
  }
}

function _setPaneView(pane, mode) {
  if (pane === 'gql') {
    _paneViewMode.gql = mode; // true = GraphQL view, false = back to split
    renderDetail();
    return;
  }
  _paneViewMode[pane] = mode;
  _paneViewMode.gql = false;
  // Re-render from each view's own entry (proxy history and site map share
  // the mode but not the selected request).
  renderDetail();
  renderSmDetail();
}

// _setRepView — same toggle for Repeater response panel
function _setRepView(tabId, mode) {
  const respEl = document.getElementById(`rep-response-${tabId}`);
  const tab = _repTabs.find(t => t.id === tabId);
  if (!respEl || !tab) return;
  tab._viewMode = mode;
  // raw text is stored in tab._rawText, set when response arrives
  const rawText = tab._rawText || '';
  if (mode === 'pretty') {
    // extract body after the blank line
    const sep = rawText.indexOf('\n\n');
    const bodyStr = sep >= 0 ? rawText.slice(sep + 2) : rawText;
    if (_isJsonBody(bodyStr)) {
      const headers = sep >= 0 ? esc(rawText.slice(0, sep)) : '';
      respEl.innerHTML = `${headers}\n\n${_fmtJsonTree(bodyStr)}`;
    } else {
      respEl.textContent = rawText;
    }
  } else {
    respEl.textContent = rawText;
  }
  ['raw','pretty'].forEach(m => {
    const btn = document.getElementById(`rep-resp-btn-${m}-${tabId}`);
    if (btn) btn.classList.toggle('on', m === mode);
  });
}

// One line per header occurrence: repeated headers (Set-Cookie) arrive as lists.
function _rawHeaderLines(headers) {
  const lines = [];
  for (const [k, v] of Object.entries(headers || {})) {
    for (const item of (Array.isArray(v) ? v : [v])) {
      lines.push(`<span class="hk">${esc(k)}</span>: <span class="hv">${esc(item)}</span>`);
    }
  }
  return lines.join('\n');
}

function fmtReq(d, mode) {
  const h = _rawHeaderLines(d.request_headers);
  const body = d.request_body
    ? '\n\n' + (mode === 'pretty' && _isJsonBody(d.request_body)
        ? _fmtJsonTree(d.request_body)
        : esc(d.request_body))
    : '';
  return `<span class="hm">${esc(d.method)}</span> ${esc(d.url)}\n${h}${body}`;
}
function fmtResp(d, mode) {
  if (!d.status) return '<span style="color:var(--txt2)">No response</span>';
  const h = _rawHeaderLines(d.response_headers);
  const body = d.response_body
    ? '\n\n' + (mode === 'pretty' && _isJsonBody(d.response_body)
        ? _fmtJsonTree(d.response_body)
        : esc(d.response_body))
    : '';
  return `<span class="hm">HTTP/1.1 ${d.status}</span>\n${h}${body}`;
}

function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// jsArg — a value as a JS literal that is safe inside a double-quoted inline
// handler attribute: onclick="fn(${jsArg(v)})". JSON.stringify makes a valid JS
// string literal; esc() then hides its quotes from the HTML parser, which decodes
// them back before the handler runs. Never use '${esc(v)}' in a handler — the
// browser turns &#39; back into ' and the value breaks out of the JS string.
function jsArg(v) {
  return esc(JSON.stringify(v == null ? '' : String(v)));
}

