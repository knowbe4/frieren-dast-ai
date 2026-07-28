// ── Extras sub-tabs (H1 Validator / Code / FedRAMP / Interactions / Decoder / JWT) ──
function switchExtrasSub(sub) {
  ['h1', 'code', 'fedramp', 'interactions', 'decoder', 'jwt'].forEach(s => {
    document.getElementById('extras-sub-' + s).style.display = s === sub ? 'flex' : 'none';
    document.getElementById('st-extras-' + s).classList.toggle('on', s === sub);
  });
  if (sub === 'h1')           h1LoadJobs();
  if (sub === 'code')         { codeRenderJobList(); if (_codeCurrentId) codeLoadResults(_codeCurrentId); }
  if (sub === 'fedramp')      fedrampLoad();
  if (sub === 'interactions') { interactionsLoadSessions(); _interactionsBadgeClear(); }
  if (sub === 'decoder')      decoderInit();
  if (sub === 'jwt')          jwtToggleSecret();
}

// ── Browse sub-tabs (Manual / Crawl) ─────────────────────────────────────
function switchBrowseSub(sub) {
  const panes = { manual: 'browse-sub-manual', crawl: 'browse-sub-crawl', discovery: 'browse-sub-discovery' };
  const tabs  = { manual: 'st-browse-manual', crawl: 'st-browse-crawl', discovery: 'st-browse-discovery' };
  for (const [key, paneId] of Object.entries(panes)) {
    document.getElementById(paneId).style.display = (key === sub) ? 'block' : 'none';
    document.getElementById(tabs[key]).classList.toggle('on', key === sub);
  }
  if (sub === 'manual')      { loadNamedSessions(); loadNamedBrowsers(); }
  else if (sub === 'crawl')  updateCrawlCookieStatus();
}

// ── AI sub-tabs ────────────────────────────────────────────────────────
function switchAiSub(sub) {
  const displays = { suggestions: 'block', settings: 'block' };
  ['suggestions', 'settings'].forEach(s => {
    document.getElementById('ai-sub-' + s).style.display = s === sub ? displays[s] : 'none';
    document.getElementById('st-ai-' + s).classList.toggle('on', s === sub);
  });
  if (sub === 'suggestions') { loadAiSuggestions(); loadAiIntelSummary(); }
  if (sub === 'settings')    { loadAiPanel(); loadScanConfig(); }
}

let _autoScanEnabled = false;

function toggleAutoScan(cb) {
  _autoScanEnabled = cb.checked;
  fetch('/api/ai/auto-scan', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({enabled: _autoScanEnabled}),
  });
}

async function loadAiIntelSummary() {
  try {
    const r = await fetch('/api/ai/session-intelligence');
    if (!r.ok) return;
    const data = await r.json();
    const hosts = Object.keys(data);
    if (!hosts.length) {
      document.getElementById('ai-intel-summary').innerHTML =
        '<div style="color:var(--txt2);font-size:11px;margin-bottom:8px">No session intelligence yet.</div>';
      return;
    }
    let html = '<div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px">';
    for (const host of hosts) {
      const d = data[host];
      const chips = [];
      if (d.confirmed_vulns?.length)      chips.push(`<span style="background:rgba(239,83,80,.18);color:#ef5350;padding:2px 7px;border-radius:10px;font-size:10px">${d.confirmed_vulns.length} confirmed</span>`);
      if (d.effective_attack_types?.length) chips.push(`<span style="background:rgba(102,187,106,.15);color:#66bb6a;padding:2px 7px;border-radius:10px;font-size:10px">works: ${d.effective_attack_types.join(', ')}</span>`);
      if (d.waf_observations?.length)     chips.push(`<span style="background:rgba(255,167,38,.15);color:#ffa726;padding:2px 7px;border-radius:10px;font-size:10px">${d.waf_observations.length} WAF signals</span>`);
      if (d.rate_limit_observed)          chips.push(`<span style="background:rgba(171,71,188,.15);color:#ab47bc;padding:2px 7px;border-radius:10px;font-size:10px">rate-limited</span>`);
      html += `<div style="background:var(--bg2);border:1px solid var(--bdr);border-radius:4px;padding:8px 12px;min-width:200px">
        <div style="font-size:11px;font-weight:600;color:var(--txt);margin-bottom:5px">${host}</div>
        <div style="display:flex;flex-wrap:wrap;gap:4px">${chips.join('') || '<span style="color:var(--txt2);font-size:10px">scanning...</span>'}</div>
      </div>`;
    }
    html += '</div>';
    document.getElementById('ai-intel-summary').innerHTML = html;
  } catch(e) {}
}

const _SUGG_PER_PAGE = 15;
let _suggAll = [];
let _suggPage = 0;

function _renderSuggPage() {
  const wrap = document.getElementById('ai-suggestions-wrap');
  const pager = document.getElementById('sugg-pager');
  const lbl   = document.getElementById('sugg-page-lbl');
  if (!_suggAll.length) {
    wrap.innerHTML = '<div style="color:var(--txt2);font-size:11px;padding:12px 0">No suggestions yet — the AI will populate this as it analyses traffic through the proxy.</div>';
    if (pager) pager.style.display = 'none';
    return;
  }
  const total      = _suggAll.length;
  const totalPages = Math.ceil(total / _SUGG_PER_PAGE);
  const start      = _suggPage * _SUGG_PER_PAGE;
  const slice      = _suggAll.slice(start, start + _SUGG_PER_PAGE);

  let html = `<div class="tbl-wrap" style="overflow-x:auto;border:1px solid var(--bdr);border-radius:4px">
  <table id="sugg-table" style="width:100%;border-collapse:collapse;font-size:11px;table-layout:fixed">
    <thead><tr style="background:var(--bg3)">
      <th style="padding:5px 8px;text-align:left;border-bottom:1px solid var(--bdr);width:120px;position:relative;overflow:hidden;white-space:nowrap">Attack<div class="col-resizer" onclick="event.stopPropagation()"></div></th>
      <th style="padding:5px 8px;text-align:left;border-bottom:1px solid var(--bdr);width:340px;position:relative;overflow:hidden;white-space:nowrap">Hypothesis<div class="col-resizer" onclick="event.stopPropagation()"></div></th>
      <th style="padding:5px 8px;text-align:left;border-bottom:1px solid var(--bdr);width:260px;position:relative;overflow:hidden;white-space:nowrap">Target<div class="col-resizer" onclick="event.stopPropagation()"></div></th>
      <th style="padding:5px 8px;text-align:left;border-bottom:1px solid var(--bdr);width:120px;position:relative;overflow:hidden;white-space:nowrap">Parameter<div class="col-resizer" onclick="event.stopPropagation()"></div></th>
      <th style="padding:5px 8px;text-align:left;border-bottom:1px solid var(--bdr);width:220px;position:relative;overflow:hidden;white-space:nowrap">Body Preview<div class="col-resizer" onclick="event.stopPropagation()"></div></th>
      <th style="padding:5px 8px;text-align:left;border-bottom:1px solid var(--bdr);width:96px;position:relative">Action</th>
    </tr></thead><tbody>`;

  for (const s of slice) {
    const status = s.status || 'pending';
    let actionHtml;
    if (status === 'queued') {
      actionHtml = '<span style="background:rgba(102,187,106,.15);color:#66bb6a;padding:2px 8px;border-radius:10px;font-size:10px">queued</span>';
    } else if (status === 'confirmed') {
      actionHtml = '<span style="background:rgba(239,83,80,.18);color:#ef5350;padding:2px 8px;border-radius:10px;font-size:10px">confirmed</span>';
    } else if (status === 'safe') {
      actionHtml = '<span style="background:rgba(100,100,100,.15);color:var(--txt2);padding:2px 8px;border-radius:10px;font-size:10px">safe</span>';
    } else {
      actionHtml = `<button class="tbtn pri" style="font-size:10px;padding:2px 9px" onclick="testSuggestion(${JSON.stringify(s.host)},${JSON.stringify(s.method||'GET')},${JSON.stringify(s.path)},${JSON.stringify(s.attack_type)},${JSON.stringify(s.parameter||'')})">Test Now</button>`;
    }
    const hyp       = esc(s.hypothesis || s.rationale || '');
    const target    = esc((s.method||'GET') + ' ' + (s.host||'') + (s.path||''));
    const param     = esc(s.parameter || '—');
    const bodyPrev  = esc(s.body_preview || '');
    const attack    = esc(s.attack_type || '');
    html += `<tr style="border-bottom:1px solid var(--bdr)">
      <td style="padding:5px 8px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;color:var(--acc)" title="${attack}">${attack}</td>
      <td style="padding:5px 8px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;color:var(--txt2)" title="${hyp}">${hyp}</td>
      <td style="padding:5px 8px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;font-family:monospace;color:var(--txt2)" title="${target}">${target}</td>
      <td style="padding:5px 8px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;font-family:monospace;color:var(--orange)" title="${param}">${param}</td>
      <td style="padding:5px 8px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;font-family:monospace;color:var(--txt2);font-size:10px" title="${bodyPrev}">${bodyPrev}</td>
      <td style="padding:5px 8px">${actionHtml}</td>
    </tr>`;
  }
  html += '</tbody></table></div>';
  wrap.innerHTML = html;

  if (pager) {
    pager.style.display = totalPages > 1 ? 'flex' : 'none';
    if (lbl) lbl.textContent = `Page ${_suggPage + 1} / ${totalPages}  (${total} suggestions)`;
    pager.querySelector('button:first-child').disabled = _suggPage === 0;
    pager.querySelector('button:last-child').disabled  = _suggPage >= totalPages - 1;
  }
}

function suggPage(delta) {
  const total = Math.ceil(_suggAll.length / _SUGG_PER_PAGE);
  _suggPage = Math.max(0, Math.min(_suggPage + delta, total - 1));
  _renderSuggPage();
}

async function loadAiSuggestions() {
  try {
    const [sr, ar] = await Promise.all([
      fetch('/api/ai/suggestions'),
      fetch('/api/ai/auto-scan'),
    ]);
    if (ar.ok) {
      const as = await ar.json();
      _autoScanEnabled = as.enabled;
      document.getElementById('ai-auto-scan').checked = as.enabled;
    }
    if (!sr.ok) return;
    const data = await sr.json();
    _suggAll  = data.suggestions || [];
    _suggPage = 0;
    _renderSuggPage();
  } catch(e) { console.error('loadAiSuggestions:', e); }
}

async function scanAllSuggestions() {
  const btn = document.getElementById('ai-scan-all-btn');
  btn.disabled = true;
  try {
    const r = await fetch('/api/ai/suggestions/scan-all', {method:'POST'});
    const d = await r.json();
    if ((d.queued || 0) > 0) {
      showToast(`${d.message} — check Scan tab for progress`);
      // Switch to Scan tab after a short delay so user sees the queue
      setTimeout(() => { switchMain('scan'); }, 1200);
    } else {
      showToast(d.message || 'Nothing to queue');
    }
    await loadAiSuggestions();
  } catch(e) { showToast('Error queuing suggestions'); }
  finally { btn.disabled = false; }
}

// ── AI panel (settings sub-tab) ────────────────────────────────────────
async function loadAiPanel() {
  try {
    const [agentsR, graphR, ctxR, tmR, suggR] = await Promise.all([
      fetch('/api/ai/agents'),
      fetch('/api/service-graph'),
      fetch('/api/ai/app-context'),
      fetch('/api/ai/threat-models'),
      fetch('/api/ai/suggestions'),
    ]);
    const agentsData = await agentsR.json();
    const graphData = await graphR.json();
    const ctxData   = ctxR.ok ? await ctxR.json() : {};
    const tmData    = tmR.ok  ? await tmR.json()  : {};
    const suggData  = suggR.ok ? await suggR.json() : {};

    // App context
    const ctxEl = document.getElementById('ai-app-context');
    if (ctxEl) {
      const hosts = Object.keys(ctxData);
      if (!hosts.length) {
        ctxEl.innerHTML = '<div style="color:var(--txt2);font-size:11px">No app context yet — requires 15+ requests through proxy.</div>';
      } else {
        const _prioColor = {high:'var(--red)',medium:'var(--orange)',low:'var(--txt2)'};
        ctxEl.innerHTML = hosts.map(host => {
          const p = ctxData[host];
          const hyps = (p.vuln_hypotheses || []);
          const ts = p.last_analysed_at ? new Date(p.last_analysed_at * 1000).toLocaleTimeString() : '—';
          return `<div style="background:var(--bg2);border:1px solid var(--bdr);border-radius:4px;
                              padding:12px 14px;margin-bottom:12px;font-size:11px">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;flex-wrap:wrap">
              <span style="font-weight:700;color:var(--blue)">${esc(host)}</span>
              ${p.app_type ? `<span style="color:var(--txt2)">${esc(p.app_type)}</span>` : ''}
              ${p.auth_model ? `<span style="background:var(--bg3);border:1px solid var(--bdr);border-radius:3px;padding:1px 7px;color:var(--green)">${esc(p.auth_model)}</span>` : ''}
              <span style="color:var(--txt3);font-size:10px;margin-left:auto">analysed ${esc(ts)} · ${p.analysis_count||0}x · ${p.entry_count_at_analysis||0} reqs</span>
            </div>
            ${p.resource_types?.length ? `<div style="margin-bottom:6px"><span style="color:var(--txt2)">Resources: </span>${p.resource_types.map(r=>`<span style="background:var(--bg3);border-radius:3px;padding:1px 6px;margin-right:4px">${esc(r)}</span>`).join('')}</div>` : ''}
            ${p.privilege_levels?.length ? `<div style="margin-bottom:6px"><span style="color:var(--txt2)">Roles: </span>${p.privilege_levels.map(r=>`<span style="background:var(--bg3);border-radius:3px;padding:1px 6px;margin-right:4px">${esc(r)}</span>`).join('')}</div>` : ''}
            ${p.interesting_flows?.length ? `<div style="margin-bottom:8px;color:var(--txt2)">Flows: ${p.interesting_flows.slice(0,4).map(f=>`<em>${esc(f)}</em>`).join(' · ')}</div>` : ''}
            ${hyps.length ? `
              <div style="font-weight:600;margin-bottom:4px;color:var(--txt2)">Vulnerability hypotheses (${hyps.length})</div>
              ${hyps.map(h => {
                const epMatch = h.endpoint.match(/^(\w+)\s+(\/\S*)/);
                const hMethod = epMatch ? epMatch[1] : 'GET';
                const hPath   = epMatch ? epMatch[2] : h.endpoint;
                const sugg = (suggData.suggestions||[]).find(s =>
                  s.host === host && s.path === hPath && s.attack_type === h.attack_type
                );
                const statusBadge = sugg
                  ? (sugg.status === 'queued'
                      ? `<span style="color:var(--orange);font-size:10px">queued</span>`
                      : `<button onclick="testSuggestion(${JSON.stringify(host)},${JSON.stringify(hMethod)},${JSON.stringify(hPath)},${JSON.stringify(h.attack_type)},${JSON.stringify(h.parameter||'')})"
                                style="font-size:9px;padding:1px 6px;background:var(--blue);color:#fff;border:none;border-radius:3px;cursor:pointer">Test Now</button>`)
                  : '';
                return `
                <div style="display:flex;align-items:baseline;gap:8px;padding:3px 0;border-top:1px solid var(--bdr3,#252525)">
                  <span style="color:${_prioColor[h.priority]||'var(--txt2)'};font-size:10px;text-transform:uppercase;width:44px;flex-shrink:0">${esc(h.priority)}</span>
                  <span style="color:var(--orange);width:90px;flex-shrink:0;font-family:monospace">${esc(h.attack_type)}</span>
                  <span style="color:var(--txt);font-family:monospace;white-space:nowrap">${esc(h.endpoint)}</span>
                  ${h.parameter !== '*' ? `<span style="color:var(--blue)">[${esc(h.parameter)}]</span>` : ''}
                  <span style="color:var(--txt2);font-size:10px;flex:1">${esc(h.rationale)}</span>
                  ${statusBadge}
                </div>`;
              }).join('')}` : '<div style="color:var(--txt3);font-size:10px">No hypotheses yet.</div>'}
          </div>`;
        }).join('');
      }
    }

    // Threat models
    const tmEl = document.getElementById('ai-threat-models');
    if (tmEl) {
      const tmHosts = Object.keys(tmData);
      if (!tmHosts.length) {
        tmEl.innerHTML = '<div style="color:var(--txt2);font-size:11px">No threat model yet — requires 15+ requests through proxy.</div>';
      } else {
        tmEl.innerHTML = tmHosts.map(host => {
          const m = tmData[host];
          const ts = m.last_analysed_at ? new Date(m.last_analysed_at * 1000).toLocaleTimeString() : '—';
          const _section = (label, items, color) => items?.length
            ? `<div style="margin-bottom:6px">
                <span style="color:var(--txt2);font-weight:600">${label}: </span>
                <ul style="margin:4px 0 0 0;padding-left:18px">
                  ${items.map(i => `<li style="color:${color};padding:1px 0">${esc(i)}</li>`).join('')}
                </ul>
               </div>`
            : '';
          return `<div style="background:var(--bg2);border:1px solid var(--bdr);border-radius:4px;
                              padding:12px 14px;margin-bottom:12px;font-size:11px">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;flex-wrap:wrap">
              <span style="font-weight:700;color:var(--blue)">${esc(host)}</span>
              <span style="color:var(--txt3);font-size:10px;margin-left:auto">analysed ${esc(ts)} · ${m.analysis_count||0}x</span>
            </div>
            ${_section('Security invariants', m.security_invariants, 'var(--green)')}
            ${_section('Not vulnerabilities', m.not_vulnerabilities, 'var(--txt2)')}
            ${_section('High-risk surfaces', m.high_risk_surfaces, 'var(--orange)')}
            ${_section('Trust boundaries', m.trust_boundaries, 'var(--txt)')}
          </div>`;
        }).join('');
      }
    }

    // Service graph
    const graphEl = document.getElementById('ai-service-graph');
    if (graphEl && graphData.groups) {
      const multiGroups = graphData.groups.filter(g => g.hosts.length > 1);
      if (!multiGroups.length) {
        graphEl.innerHTML = `<div style="color:var(--txt2);font-size:11px">
          No multi-host groups detected yet. Browse the application to accumulate traffic.
        </div>`;
      } else {
        graphEl.innerHTML = multiGroups.map(g => `
          <div style="background:var(--bg2);border:1px solid var(--bdr);border-radius:4px;
                      padding:10px 14px;margin-bottom:10px;font-size:11px">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
              <span style="color:var(--txt2)">Group</span>
              <code style="color:var(--orange)">${esc(g.id)}</code>
              ${g.manually_managed ? '<span style="color:var(--blue);font-size:10px">[manual]</span>' : ''}
            </div>
            <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:6px">
              ${g.hosts.map(h => `
                <span style="background:var(--bg3);border:1px solid var(--bdr);border-radius:3px;
                             padding:2px 8px;color:var(--txt)">
                  ${esc(h)}
                  <button onclick="splitHost('${esc(h)}')" style="background:none;border:none;
                    color:var(--txt3);cursor:pointer;font-size:10px;padding:0 0 0 4px"
                    title="Split out of group">✕</button>
                </span>`).join('')}
            </div>
            <div style="color:var(--txt3);font-size:10px">${esc(g.detection_signals.slice(-3).join(' · '))}</div>
          </div>`).join('') +
          `<div style="margin-top:8px;display:flex;gap:8px;align-items:center">
            <input id="merge-host-a" placeholder="host-a.example.com"
              style="flex:1;background:var(--bg2);border:1px solid var(--bdr);color:var(--txt);
                     padding:4px 8px;border-radius:3px;font-size:11px">
            <input id="merge-host-b" placeholder="host-b.example.com"
              style="flex:1;background:var(--bg2);border:1px solid var(--bdr);color:var(--txt);
                     padding:4px 8px;border-radius:3px;font-size:11px">
            <button class="tbtn" onclick="mergeHosts()">Merge</button>
          </div>`;
      }
    }

    // Payload sources
    const payloadEl = document.getElementById('ai-payload-sources');
    if (payloadEl && agentsData.payload_files) {
      payloadEl.innerHTML = `
        <table style="width:100%;border-collapse:collapse;font-size:11px">
          <thead>
            <tr style="color:var(--txt2);border-bottom:1px solid var(--bdr)">
              <th style="text-align:left;padding:4px 8px;font-weight:500">File</th>
              <th style="text-align:left;padding:4px 8px;font-weight:500">Categories</th>
              <th style="text-align:right;padding:4px 8px;font-weight:500">Total payloads</th>
            </tr>
          </thead>
          <tbody>
            ${agentsData.payload_files.map(f => `
              <tr style="border-bottom:1px solid var(--bdr3,var(--bdr))">
                <td style="padding:5px 8px;font-family:monospace;color:var(--orange)">${esc(f.file)}</td>
                <td style="padding:5px 8px;color:var(--txt2)">${esc(f.groups.join(', '))}</td>
                <td style="padding:5px 8px;text-align:right;color:var(--txt)">${f.count}</td>
              </tr>`).join('')}
          </tbody>
        </table>`;
    }

    await loadAiLog();

  } catch(e) {
    console.error('loadAiPanel:', e);
  }
}

// ── AI activity log ────────────────────────────────────────────────────
let _aiLogTimer = null;

function toggleAiLogAuto(cb) {
  if (cb.checked) {
    _aiLogTimer = setInterval(loadAiLog, 5000);
  } else {
    clearInterval(_aiLogTimer);
    _aiLogTimer = null;
  }
}

async function loadAiLog() {
  const el = document.getElementById('ai-activity-log');
  if (!el) return;
  try {
    const r = await fetch('/api/ai/log');
    const data = await r.json();
    const events = data.events || [];
    if (!events.length) {
      el.innerHTML = '<div style="color:var(--txt2);padding:10px 14px">No agent scans yet.</div>';
      return;
    }
    el.innerHTML = events.map(ev => {
      const d = new Date(ev.ts * 1000);
      const ts = d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});

      // Operation / discriminator (GraphQL operationName or URL tail)
      const opLabel = ev.operation
        ? `<span style="background:var(--bg3);border:1px solid #4a3a6a;border-radius:3px;padding:1px 7px;color:#c792ea;font-size:10px;margin-left:6px">${esc(ev.operation)}</span>`
        : '';

      // URL — truncate path for display but show full in title
      const urlObj = (() => { try { return new URL(ev.url); } catch { return null; } })();
      const urlDisplay = urlObj
        ? `<span style="color:var(--txt2)">${esc(urlObj.host)}</span><span style="color:var(--txt)">${esc(urlObj.pathname)}</span>`
        : `<span style="color:var(--txt)">${esc(ev.url)}</span>`;

      // Parameters tested
      const params = (ev.params || []);
      const paramsHtml = params.length
        ? `<div style="margin-top:4px;font-size:10px;color:var(--txt2)">Params: ${
            params.map(p => `<code style="color:var(--orange);margin-right:4px">${esc(p)}</code>`).join('')
          }</div>`
        : '';

      // Agent badges
      const confirmed_count = (ev.outcomes || []).filter(o => o.confirmed).length;
      const agents = (ev.agents_selected || []).map(a => {
        const hasVuln = (ev.outcomes || []).some(o => o.attack_type === a && o.confirmed);
        const color = hasVuln ? 'color:#ff6b6b;border-color:#ff6b6b' : 'color:var(--orange);border-color:var(--bdr)';
        return `<span style="background:var(--bg3);border:1px solid;border-radius:3px;padding:1px 6px;margin-right:3px;font-size:10px;${color}">${esc(a)}</span>`;
      }).join('');

      // Outcomes — only show agents that found something, collapse the rest
      const vuln_outcomes = (ev.outcomes || []).filter(o => o.finding_title);
      const clean_count = (ev.outcomes || []).filter(o => !o.finding_title).length;
      const outcomesHtml = vuln_outcomes.map(o => {
        const badge = o.confirmed
          ? `<span style="color:#ff6b6b;font-weight:600">confirmed</span>`
          : `<span style="color:var(--txt2)">not confirmed</span>`;
        const reasoning = o.reasoning
          ? `<span style="color:var(--txt2);font-style:italic;margin-left:6px;font-size:10px">${esc(o.reasoning)}</span>`
          : '';
        return `<div style="padding:3px 0;font-size:11px">
          <span style="color:var(--txt2)">${esc(o.agent)}</span>
          <span style="color:var(--txt2);margin:0 4px">→</span>
          <span style="color:var(--yellow)">${esc(o.finding_title)}</span>
          <span style="color:var(--txt2);margin:0 4px">·</span>${badge}${reasoning}
        </div>`;
      }).join('');
      const cleanLine = clean_count
        ? `<div style="font-size:10px;color:var(--txt3,var(--txt2));margin-top:2px">${clean_count} agent${clean_count>1?'s':''} — no findings</div>`
        : '';

      const borderColor = confirmed_count > 0 ? '#ff6b6b' : 'var(--bdr)';
      return `<div style="border-bottom:1px solid var(--bdr);border-left:3px solid ${borderColor};padding:8px 14px;margin-bottom:0">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;flex-wrap:wrap">
          <span style="color:var(--txt2);font-size:10px;white-space:nowrap">${esc(ts)}</span>
          <span style="font-weight:700;font-size:11px;color:var(--blue)">${esc(ev.method)}</span>
          <span style="font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:440px"
                title="${esc(ev.url)}">${urlDisplay}</span>
          ${opLabel}
        </div>
        ${paramsHtml}
        <div style="margin:5px 0">${agents}</div>
        ${ev.plan_reason ? `<div style="color:var(--txt2);font-size:10px;margin-bottom:4px;font-style:italic">${esc(ev.plan_reason)}</div>` : ''}
        <div style="padding-left:8px;border-left:2px solid var(--bdr)">${outcomesHtml}${cleanLine}</div>
      </div>`;
    }).join('');
  } catch(e) {
    el.innerHTML = `<div style="color:var(--txt2);padding:10px 14px">Failed to load log: ${esc(String(e))}</div>`;
  }
}

async function mergeHosts() {
  const a = document.getElementById('merge-host-a')?.value.trim();
  const b = document.getElementById('merge-host-b')?.value.trim();
  if (!a || !b) { showToast('Enter both hosts'); return; }
  const r = await fetch('/api/service-graph/merge', {
    method: 'POST',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify({host_a: a, host_b: b}),
  });
  if (r.ok) { showToast(`Merged ${a} and ${b}`); loadAiPanel(); }
  else showToast('Merge failed');
}

async function splitHost(host) {
  const r = await fetch('/api/service-graph/split', {
    method: 'POST',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify({host}),
  });
  if (r.ok) { showToast(`Split ${host} into its own group`); loadAiPanel(); }
  else showToast('Split failed');
}

