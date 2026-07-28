// ── shared render helpers ──────────────────────────────────────────────
function buildRRHtml(d) {
  const noteBanner = d.manual_note
    ? `<div style="padding:5px 10px;background:#1a1a2e;border-bottom:1px solid var(--yellow);
                  font-size:10px;color:var(--yellow);display:flex;align-items:center;gap:8px">
         <span style="font-weight:600">AI note:</span>
         <span style="color:var(--txt)">${esc(d.manual_note)}</span>
       </div>`
    : '';
  const reqJson  = _isJsonBody(d.request_body);
  const respJson = _isJsonBody(d.response_body);
  const isGQL    = _isGraphQLBody(d.request_body);
  const reqMode  = _paneViewMode.req;
  const respMode = _paneViewMode.resp;
  const gqlMode  = _paneViewMode.gql === true;

  if (isGQL && gqlMode) {
    return `${noteBanner}<div class="pane-hdr" style="border-bottom:1px solid var(--bdr)">
      <span style="color:var(--txt2);font-size:11px">GraphQL</span>
      <span class="pane-title">${esc(d.method)} ${esc(d.url)}</span>
      <div class="pane-view-toggle">
        <button onclick="_setPaneView('gql',false)">Raw</button>
        <button class="on">GraphQL</button>
      </div>
    </div>
    <div id="pane-gql-area" style="overflow:auto;flex:1">${_buildGQLView(d.request_body, d.response_body)}</div>`;
  }

  return `${noteBanner}<div class="split-wrap">
    <div class="pane">
      <div class="pane-hdr">
        Request
        ${isGQL ? `<div class="pane-view-toggle">
          <button id="req-btn-raw"    class="${!gqlMode&&reqMode==='raw'?'on':''}"    onclick="_setPaneView('req','raw')">Raw</button>
          <button id="req-btn-pretty" class="${!gqlMode&&reqMode==='pretty'?'on':''}" onclick="_setPaneView('req','pretty')">Pretty</button>
          <button id="req-btn-gql"    class="gql-btn"                                onclick="_setPaneView('gql',true)">GraphQL</button>
        </div>` : reqJson ? `<div class="pane-view-toggle">
          <button id="req-btn-raw"    class="${reqMode==='raw'?'on':''}"    onclick="_setPaneView('req','raw')">Raw</button>
          <button id="req-btn-pretty" class="${reqMode==='pretty'?'on':''}" onclick="_setPaneView('req','pretty')">Pretty</button>
        </div>` : ''}
      </div>
      <div class="code-area" id="pane-req-area"><pre>${fmtReq(d, reqMode)}</pre></div>
    </div>
    <div class="pane">
      <div class="pane-hdr">
        Response <span class="pane-title">HTTP ${d.status || '—'}</span>
        ${respJson ? `<div class="pane-view-toggle">
          <button id="resp-btn-raw"    class="${respMode==='raw'?'on':''}"    onclick="_setPaneView('resp','raw')">Raw</button>
          <button id="resp-btn-pretty" class="${respMode==='pretty'?'on':''}" onclick="_setPaneView('resp','pretty')">Pretty</button>
        </div>` : ''}
      </div>
      <div class="code-area" id="pane-resp-area"><pre>${fmtResp(d, respMode)}</pre></div>
    </div>
  </div>`;
}

// Builds the "HTTP Evidence" <details> block for one finding. Shared by both
// the per-card path (agent/active-scan findings with their own probe pair)
// and the hoisted-once path (passive findings that share one entry's evidence).
function _buildHttpEvidenceDetails(f) {
  const hasProbeF = f.probe_request || f.probe_response;
  if (!(f.raw_request || f.raw_response || hasProbeF)) return '';
  const baselineLabel = hasProbeF ? 'Baseline (original request, no payload)' : 'Request';
  return `<details style="margin-top:8px" open>
    <summary style="cursor:pointer;font-size:10px;color:var(--txt2);user-select:none">
      HTTP Evidence${hasProbeF ? ' · <span style="color:#4caf50;font-size:9px">Baseline + Exploit Proof</span>' : ''}
    </summary>
    ${f.raw_request ? `<div style="margin-top:6px">
      <div style="display:flex;align-items:center;gap:6px;margin-bottom:2px">
        <span style="font-size:9px;color:var(--txt2);text-transform:uppercase;letter-spacing:.4px">${baselineLabel}</span>
        ${hasProbeF ? '' : `<button class="tbtn" style="font-size:9px;padding:1px 6px;margin-left:auto"
          onclick="repLoadRaw(${JSON.stringify(f.raw_request)})">Send to Repeater</button>`}
      </div>
      <pre style="margin:0;padding:8px;background:#0a0a1a;border:1px solid var(--bdr);border-radius:3px;
                  font-size:10px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;
                  color:#7eb8f7;max-height:220px">${esc(f.raw_request)}</pre>
    </div>` : ''}
    ${f.raw_response ? `<div style="margin-top:6px">
      <div style="font-size:9px;color:var(--txt2);margin-bottom:2px;text-transform:uppercase;letter-spacing:.4px">Response</div>
      <pre style="margin:0;padding:8px;background:#0a1a0a;border:1px solid var(--bdr);border-radius:3px;
                  font-size:10px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;
                  color:#7ef7a0;max-height:180px">${esc(f.raw_response)}</pre>
    </div>` : ''}
    ${hasProbeF ? `<div style="margin-top:10px;padding:5px 8px;background:#0a200a;border-left:2px solid #4caf50;border-radius:2px;
                      font-size:9px;color:#4caf50;display:flex;align-items:center;gap:8px">
      <span>Exploit Proof — probe with payload injected</span>
      <button class="tbtn" style="font-size:9px;padding:1px 6px;margin-left:auto;color:#4caf50;border-color:#2a5a2a"
        onclick="repLoadRaw(${JSON.stringify(f.probe_request || f.raw_request)})">Send Probe to Repeater</button>
    </div>
    ${f.probe_request ? `<div style="margin-top:6px">
      <div style="font-size:9px;color:#4caf50;margin-bottom:2px;text-transform:uppercase;letter-spacing:.4px">Probe Request</div>
      <pre style="margin:0;padding:8px;background:#0a1500;border:1px solid #2a5a2a;border-radius:3px;
                  font-size:10px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;
                  color:#7eb8f7;max-height:220px">${esc(f.probe_request)}</pre>
    </div>` : ''}
    ${f.probe_response ? `<div style="margin-top:6px">
      <div style="font-size:9px;color:#4caf50;margin-bottom:2px;text-transform:uppercase;letter-spacing:.4px">Probe Response</div>
      <pre style="margin:0;padding:8px;background:#0a1a0a;border:1px solid #2a5a2a;border-radius:3px;
                  font-size:10px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;
                  color:#7ef7a0;max-height:180px">${esc(f.probe_response)}</pre>
    </div>` : ''}` : ''}
  </details>`;
}

function buildFindingsHtml(d) {
  const fs = d.findings || [];
  if (!fs.length) {
    return `<div class="empty">${
      d.queued_for_scan
        ? 'Scan in progress...'
        : 'Not scanned yet.\nClick "Scan selected" or "Scan all" to analyse this request.'
    }</div>`;
  }

  // Findings with their own probe pair (agent/active-scan) always keep their
  // own full evidence block — that evidence is genuinely distinct per finding.
  // Findings with no probe pair are typically N passive rules that all fired
  // off the exact same one request/response — when 2+ of those share
  // byte-identical raw_request+raw_response, render that pair once, above the
  // card list, instead of repeating it verbatim in every card.
  const passiveFindings = fs.filter(f => !(f.probe_request || f.probe_response));
  const evidenceCounts = new Map();
  for (const f of passiveFindings) {
    const key = (f.raw_request || '') + ' ' + (f.raw_response || '');
    if (!key.trim()) continue;
    evidenceCounts.set(key, (evidenceCounts.get(key) || 0) + 1);
  }
  let sharedEvidenceKey = null;
  let sharedEvidenceHtml = '';
  for (const [key, count] of evidenceCounts) {
    if (count > 1) { sharedEvidenceKey = key; break; }
  }
  if (sharedEvidenceKey) {
    const sample = passiveFindings.find(f =>
      (f.raw_request || '') + ' ' + (f.raw_response || '') === sharedEvidenceKey
    );
    sharedEvidenceHtml = `<div style="margin-bottom:10px">
      <div style="font-size:10px;color:var(--txt2);margin-bottom:4px">
        Shared by ${evidenceCounts.get(sharedEvidenceKey)} findings below — same intercepted request/response:
      </div>
      ${_buildHttpEvidenceDetails(sample)}
    </div>`;
  }

  return (sharedEvidenceHtml ? sharedEvidenceHtml : '') + '<div class="findings-wrap">' + fs.map(f => {
    const sev = esc(f.severity || 'low');
    const s = sev[0].toUpperCase();
    const confirmed = f.confirmed ? 'vuln' : '';
    const _VBY2 = {
      ai:'AI validated','passive+ai':'Passive+AI',pattern:'Pattern match',passive:'Passive',imported:'Imported',
      browser:'Browser confirmed',time_based:'Time-based',oob_callback:'OOB callback',
      error_pattern:'Error pattern',file_match:'File match',secret_pattern:'Secret pattern',response_diff:'Response diff',
    };
    const _VBY2_CLASS = {
      ai:'vbdg-ai','passive+ai':'vbdg-pai',pattern:'vbdg-pattern',passive:'vbdg-passive',imported:'vbdg-imported',
      browser:'vbdg-browser',time_based:'vbdg-time_based',oob_callback:'vbdg-oob_callback',
      error_pattern:'vbdg-error_pattern',file_match:'vbdg-file_match',secret_pattern:'vbdg-secret_pattern',response_diff:'vbdg-response_diff',
    };
    const _vbyRaw3 = f.validated_by;
    const _vbyList3 = Array.isArray(_vbyRaw3) ? _vbyRaw3 : (_vbyRaw3 ? [_vbyRaw3] : ['passive']);
    const vLabel = _vbyList3.map(v => _VBY2[v] || v).join(' + ');

    const metaRows = [];
    if (f.parameter) metaRows.push(`<div style="margin-top:6px;font-size:10px">
      <span style="color:var(--txt2)">Parameter:</span>
      <code style="color:var(--orange);margin-left:4px">${esc(f.parameter)}</code>
    </div>`);
    if (f.payload) metaRows.push(`<div style="margin-top:4px;font-size:10px">
      <span style="color:var(--txt2)">Payload:</span>
      <code style="color:var(--yellow);margin-left:4px;word-break:break-all">${esc(f.payload)}</code>
    </div>`);
    if (f.evidence) metaRows.push(`<div style="margin-top:6px;font-size:10px;color:var(--txt2);line-height:1.5;word-break:break-all">${esc(f.evidence)}</div>`);
    if (f.snippet) {
      const lineLabel = f.line_no ? `Line ${f.line_no}` : 'Context';
      metaRows.push(`<div style="margin-top:6px">
        <div style="font-size:9px;color:var(--txt2);margin-bottom:2px;text-transform:uppercase;letter-spacing:.4px">${lineLabel}</div>
        <pre style="margin:0;padding:8px;background:#111;border:1px solid var(--bdr);border-radius:3px;
                    font-size:10px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;
                    color:var(--txt)">${esc(f.snippet)}</pre>
      </div>`);
    }
    if (f.reasoning) metaRows.push(`<div style="margin-top:6px;font-size:10px;color:var(--txt2);font-style:italic;line-height:1.5">${esc(f.reasoning)}</div>`);
    if (f.cwe) metaRows.push(`<div style="margin-top:6px;font-size:10px;color:var(--txt3,var(--txt2))">${esc(f.cwe)}</div>`);
    const hasProbeF = f.probe_request || f.probe_response;
    const thisEvidenceKey = (f.raw_request || '') + ' ' + (f.raw_response || '');
    const isSharedEvidence = !hasProbeF && sharedEvidenceKey && thisEvidenceKey === sharedEvidenceKey;
    if (isSharedEvidence) {
      metaRows.push(`<div style="margin-top:8px;font-size:10px;color:var(--txt2);font-style:italic">See shared HTTP evidence above</div>`);
    } else if (f.raw_request || f.raw_response || hasProbeF) {
      metaRows.push(_buildHttpEvidenceDetails(f));
    }

    const _brReasonLabel = {
      'csp_or_sink': 'JS did not execute (CSP, different sink, or alert suppressed)',
      'timeout':     'Browser timed out loading the page',
      'confirmed':   'JS executed in browser',
    };
    const _brReason = f.browser_confirm_reason || '';
    const _brTooltip = _brReasonLabel[_brReason] || (_brReason.startsWith('error:') ? _brReason.slice(6) : '');
    const browserBadge = f.browser_confirmed === true
      ? `<span style="margin-left:8px;font-size:9px;padding:1px 5px;border-radius:3px;background:#1a3a1a;color:#4caf50;border:1px solid #4caf50"
               title="JS executed in browser">Browser confirmed</span>`
      : f.browser_confirmed === false
        ? `<span style="margin-left:8px;font-size:9px;padding:1px 5px;border-radius:3px;background:#3a2a0a;color:#ff9800;border:1px solid #ff9800;cursor:help"
                 title="${esc(_brTooltip)}">${
                   _brReason === 'timeout' ? 'Browser timeout' :
                   _brReason === 'csp_or_sink' ? 'JS not executed' :
                   _brReason.startsWith('error:') ? 'Browser error' :
                   'Browser not confirmed'
                 }</span>`
        : '';

    return `<div class="fcard ${confirmed}">
      <div class="ftitle">${esc(f.title || 'Finding')}</div>
      <div class="fmeta">
        <span class="fsev s${s}">${sev}</span>
        <span style="margin-left:4px">${esc(f.attack_type || '')}</span>
        ${_vbyList3.map(v => v === 'ai' && f.dismissed
          ? `<span class="vbdg vbdg-dismissed" title="AI reviewed and rejected this finding">AI rejected</span>`
          : `<span class="vbdg ${_VBY2_CLASS[v]||'vbdg-pattern'}" title="${(v === 'ai' && f.validated_at) ? esc('AI validated ' + f.validated_at.replace('T',' ').slice(0,16)) : 'Detection method: ' + esc(_VBY2[v]||v)}">${esc(_VBY2[v]||v)}</span>`
        ).join('')}
        ${browserBadge}
      </div>
      ${metaRows.join('')}
    </div>`;
  }).join('') + '</div>';
}

// ── JSON collapsible tree ───────────────────────────────────────────────
const _paneViewMode = { req: 'raw', resp: 'raw', gql: false };

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
  const areaId = pane === 'req' ? 'pane-req-area' : 'pane-resp-area';
  const area = document.getElementById(areaId);
  if (!area || !detail) return;
  const pre = area.querySelector('pre');
  if (!pre) return;
  pre.innerHTML = pane === 'req' ? fmtReq(detail, mode) : fmtResp(detail, mode);
  ['raw','pretty'].forEach(m => {
    const btn = document.getElementById(`${pane}-btn-${m}`);
    if (btn) btn.classList.toggle('on', m === mode);
  });
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

function fmtReq(d, mode) {
  const h = Object.entries(d.request_headers || {})
    .map(([k, v]) => `<span class="hk">${esc(k)}</span>: <span class="hv">${esc(v)}</span>`)
    .join('\n');
  const body = d.request_body
    ? '\n\n' + (mode === 'pretty' && _isJsonBody(d.request_body)
        ? _fmtJsonTree(d.request_body)
        : esc(d.request_body))
    : '';
  return `<span class="hm">${esc(d.method)}</span> ${esc(d.url)}\n${h}${body}`;
}
function fmtResp(d, mode) {
  if (!d.status) return '<span style="color:var(--txt2)">No response</span>';
  const h = Object.entries(d.response_headers || {})
    .map(([k, v]) => `<span class="hk">${esc(k)}</span>: <span class="hv">${esc(v)}</span>`)
    .join('\n');
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

