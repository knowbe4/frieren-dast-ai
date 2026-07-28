// ── Code Analysis ────────────────────────────────────────────────────────────

let _codeCurrentId = null;
let _codePolling = null;
let _codeActiveTab = 'endpoints';
let _codeSources = [''];  // at least one row

function _codeRenderSources() {
  const container = document.getElementById('code-sources-list');
  container.innerHTML = '';
  _codeSources.forEach((val, idx) => {
    const row = document.createElement('div');
    row.style.cssText = 'display:flex;gap:4px;align-items:center';
    const inp = document.createElement('input');
    inp.type = 'text';
    inp.placeholder = '/path/to/repo  or  https://gitlab.com/group/project';
    inp.value = val;
    inp.style.cssText = 'flex:1;background:var(--bg2);border:1px solid var(--bdr);color:var(--txt);padding:5px 8px;border-radius:3px;font-size:10px';
    inp.oninput = () => { _codeSources[idx] = inp.value; };
    row.appendChild(inp);
    if (_codeSources.length > 1) {
      const btn = document.createElement('button');
      btn.className = 'tbtn del';
      btn.textContent = 'x';
      btn.style.cssText = 'font-size:9px;padding:2px 6px;flex-shrink:0';
      btn.onclick = () => { _codeSources.splice(idx, 1); _codeRenderSources(); };
      row.appendChild(btn);
    }
    container.appendChild(row);
  });
}

function codeAddSource() {
  _codeSources.push('');
  _codeRenderSources();
}

// Initialize source rows (script runs after DOM so call directly)
_codeRenderSources();

const _codeSevColor = {
  critical: 'var(--red)',
  high:     '#f97316',
  medium:   'var(--yellow)',
  low:      'var(--txt2)',
};

const _codeMethodColor = {
  GET:    '#4ade80',
  POST:   '#60a5fa',
  PUT:    '#f97316',
  PATCH:  '#a78bfa',
  DELETE: 'var(--red)',
};

function codeSelectTab(tab) {
  _codeActiveTab = tab;
  ['endpoints', 'patterns', 'hypotheses'].forEach(t => {
    document.getElementById('code-pane-' + t).style.display = t === tab ? 'block' : 'none';
    const el = document.getElementById('code-rt-' + t);
    el.style.borderBottomColor = t === tab ? 'var(--acc2)' : 'transparent';
    el.style.color = t === tab ? 'var(--txt)' : 'var(--txt2)';
  });
  // When switching to hypotheses tab, immediately refresh status and start polling
  if (tab === 'hypotheses' && _codeCurrentId) {
    _pollHypStatus();
    _startHypStatusPoll();
  } else if (tab !== 'hypotheses') {
    _stopHypStatusPoll();
  }
}

function _codeSetStatus(msg, color) {
  const el = document.getElementById('code-status-msg');
  if (el) { el.textContent = msg; el.style.color = color || 'var(--txt2)'; }
}

async function codeStartAnalysis() {
  const sources = _codeSources.map(s => s.trim()).filter(Boolean);
  const token   = document.getElementById('code-token-input').value.trim();
  if (!sources.length) { _codeSetStatus('Add at least one repository path or URL.', 'var(--red)'); return; }

  document.getElementById('code-load-btn').disabled = true;
  _codeSetStatus('Loading files…', 'var(--yellow)');

  const targetUrl = (document.getElementById('code-target-url')?.value || '').trim();
  const resp = await fetch('/api/code/analyze', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({sources, gitlab_token: token, target_url: targetUrl}),
  });
  const data = await resp.json();
  if (data.error) { _codeSetStatus('Error: ' + data.error, 'var(--red)'); document.getElementById('code-load-btn').disabled = false; return; }

  _codeCurrentId = data.analysis_id;
  codeRenderJobList();
  codeStartPolling(data.analysis_id, 'load');
  codeSelectTab('patterns');
}

async function codeEnrich() {
  if (!_codeCurrentId) { _codeSetStatus('Load a repository first.', 'var(--red)'); return; }
  document.getElementById('code-enrich-btn').disabled = true;
  _codeSetStatus('Starting AI enrichment…', 'var(--yellow)');

  const resp = await fetch('/api/code/enrich/' + _codeCurrentId, { method: 'POST' });
  const data = await resp.json();
  if (data.error) { _codeSetStatus('Error: ' + data.error, 'var(--red)'); document.getElementById('code-enrich-btn').disabled = false; return; }

  codeStartPolling(_codeCurrentId, 'enrich');
}

function codeStartPolling(id, phase) {
  if (!id) return;
  if (_codePolling) clearInterval(_codePolling);
  const terminalStates = phase === 'load'
    ? ['scanned', 'error']
    : ['enriched', 'error'];

  _codePolling = setInterval(async () => {
    const s = await fetch('/api/code/status/' + id).then(r => r.json()).catch(() => ({}));
    codeRenderJobList();

    const statusLabels = {
      scanning: 'Scanning files…',
      scanned:  'Scan complete — patterns found.',
      enriching: 'AI enrichment running…',
      enriched:  'AI enrichment complete.',
      error:     'Error: ' + (s.error || 'unknown'),
    };
    const st = s.status || '';
    if (!st) { clearInterval(_codePolling); _codePolling = null; return; }
    _codeSetStatus(statusLabels[st] || st, st === 'error' ? 'var(--red)' : st.endsWith('ed') ? '#4ade80' : 'var(--yellow)');

    if (terminalStates.includes(s.status)) {
      clearInterval(_codePolling);
      _codePolling = null;
      document.getElementById('code-load-btn').disabled = false;
      document.getElementById('code-enrich-btn').disabled = false;
      if (s.status !== 'error') {
        await codeLoadResults(id);
        // In AI mode, auto-validate all hypotheses after enrich completes
        if (_aiMode && phase === 'enrich') codeValidateAllHypotheses();
      }
    }
  }, 2000);
}

async function codeValidateAllHypotheses() {
  if (!_codeCurrentId) { showToast('No analysis loaded', true); return; }
  const btn = event?.target;
  if (btn) { btn.disabled = true; btn.textContent = '…'; }
  const r = await fetch('/api/code/results/' + _codeCurrentId).then(r => r.json()).catch(() => null);
  if (!r || !r.hypotheses?.length) {
    if (btn) { btn.disabled = false; btn.textContent = 'Validate All'; }
    showToast('No hypotheses to validate', true);
    return;
  }
  let queued = 0;
  for (const h of r.hypotheses) {
    try {
      const resp = await fetch('/api/code/validate-hypothesis', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          method: h.method || 'GET',
          path: h.endpoint_path || '/',
          host: '',
          vuln_type: h.vuln_type || '',
          notes: h.reasoning || '',
          suggested_payload: h.suggested_payload || '',
          analysis_id: _codeCurrentId,
        }),
      });
      if (resp.ok) queued++;
    } catch(_) {}
  }
  if (btn) { btn.disabled = false; btn.textContent = 'Validate All'; }
  if (queued) {
    showToast(`Queued ${queued} hypothesis validation(s) — check Scan tab`);
    _startHypStatusPoll();
    setTimeout(() => { switchMain('scan'); }, 1500);
  }
}

function _buildHypStatusBadge(status) {
  const _map = {
    queued:    ['#1a2a1a','#66bb6a','Queued'],
    scanning:  ['#1a1a2a','#60a5fa','Scanning…'],
    confirmed: ['#2a0a0a','#ef5350','Confirmed'],
    safe:      ['#0a1a0a','#4caf50','Safe — no vuln'],
    error:     ['#2a1a0a','#ff9800','Scan error'],
    pending:   ['#1a1a1a','var(--txt2)','Waiting for URL'],
  };
  const [bg, color, label] = _map[status] || [];
  if (!label) return '';
  return `<span class="hyp-status-badge" style="font-size:9px;padding:1px 6px;border-radius:3px;background:${bg};color:${color};border:1px solid ${color}">${label}</span>`;
}

function _buildHypCard(h, statusOverride) {
  const color = _codeSevColor[h.severity] || 'var(--txt)';
  const status = statusOverride ?? h.scan_status ?? '';

  // Status badge
  const badge = _buildHypStatusBadge(status);

  // Finding results
  const findings = h.findings || [];
  const findingsHtml = findings.length ? `
    <div style="margin-top:8px;border-top:1px solid var(--bdr);padding-top:6px">
      ${findings.map(f => {
        const vbyRaw = f.validated_by;
        const vbyList = Array.isArray(vbyRaw) ? vbyRaw : (vbyRaw ? [vbyRaw] : []);
        const _VBY_L = {ai:'AI validated',browser:'Browser confirmed',time_based:'Time-based',oob_callback:'OOB callback',error_pattern:'Error pattern',file_match:'File match',secret_pattern:'Secret pattern',response_diff:'Response diff',pattern:'Pattern match',passive:'Passive',imported:'Imported'};
        const _VBY_C = {ai:'vbdg-ai',browser:'vbdg-browser',time_based:'vbdg-time_based',oob_callback:'vbdg-oob_callback',error_pattern:'vbdg-error_pattern',file_match:'vbdg-file_match',secret_pattern:'vbdg-secret_pattern',response_diff:'vbdg-response_diff',pattern:'vbdg-pattern',passive:'vbdg-passive',imported:'vbdg-imported'};
        const vBadges = vbyList.map(v => {
          const _t = (v === 'ai' && f.validated_at) ? ` title="${esc('AI validated ' + f.validated_at.replace('T',' ').slice(0,16))}"` : '';
          return `<span class="vbdg ${_VBY_C[v]||'vbdg-pattern'}"${_t}>${esc(_VBY_L[v]||v)}</span>`;
        }).join('');
        const importBadge = f.import_status === 'confirmed' ? '<span style="margin-left:4px;font-size:9px;padding:1px 4px;border-radius:3px;background:#1a3a1a;color:#4caf50;border:1px solid #4caf50">Replay confirmed</span>'
          : f.import_status === 'unconfirmed' ? '<span style="margin-left:4px;font-size:9px;padding:1px 4px;border-radius:3px;background:#3a2a0a;color:#ff9800;border:1px solid #ff9800">Replay unconfirmed</span>' : '';
        return `<div style="font-size:10px;margin-bottom:4px">
          <span style="color:${_SEV_COLOR[f.severity?.toLowerCase()]||'var(--txt2)'}">● </span>
          <strong>${esc(f.title)}</strong> ${vBadges}${importBadge}
          ${f.reasoning ? `<div style="color:var(--txt2);font-style:italic;margin-top:2px;margin-left:12px">${esc(f.reasoning)}</div>` : ''}
        </div>`;
      }).join('')}
    </div>` : '';

  const _validateBtn = `<button class="tbtn" style="font-size:9px;padding:2px 8px"
      onclick="codeSendToH1('${esc(h.endpoint_path)}','${esc(h.vuln_type)}','${esc(h.reasoning)}','${esc(h.suggested_payload)}','${esc(h.method||'GET')}')">${status === 'confirmed' || status === 'safe' ? 'Re-validate' : 'Validate'}</button>`;
  const _viewBtn = h.scan_entry_id
    ? `<button class="tbtn" style="font-size:9px;padding:2px 8px" onclick="goToEntry('${esc(h.scan_entry_id)}')">View request →</button>`
    : '';
  const actionBtn = (status === 'confirmed' || status === 'safe' || status === 'error')
    ? `<div style="margin-left:auto;display:flex;gap:4px">${_viewBtn}${_validateBtn}</div>`
    : _aiMode
      ? '<span style="margin-left:auto;font-size:9px;color:var(--green)">queued</span>'
      : `<div style="margin-left:auto">${_validateBtn}</div>`;

  return `
    <div style="display:flex;gap:8px;align-items:center;margin-bottom:6px">
      <span style="color:${color};font-weight:600;font-size:10px">${esc(h.severity.toUpperCase())}</span>
      <span style="font-size:11px;font-weight:600">${esc(h.vuln_type)}</span>
      <span style="font-family:monospace;font-size:10px;color:var(--accent)">${esc(h.endpoint_path)}</span>
      ${badge}
      ${actionBtn}
    </div>
    <div style="font-size:10px;color:var(--txt2);margin-bottom:4px">${esc(h.reasoning)}</div>
    <div style="font-family:monospace;font-size:9px;color:var(--txt2);background:var(--bg);padding:4px 6px;border-radius:3px">${esc(h.suggested_payload)}</div>
    ${findingsHtml}`;
}

let _hypStatusPollTimer = null;
function _startHypStatusPoll() {
  if (_hypStatusPollTimer) return;  // already polling
  _hypStatusPollTimer = setInterval(_pollHypStatus, 4000);
}
function _stopHypStatusPoll() {
  if (_hypStatusPollTimer) { clearInterval(_hypStatusPollTimer); _hypStatusPollTimer = null; }
}
async function _pollHypStatus() {
  if (!_codeCurrentId) { _stopHypStatusPoll(); return; }
  const data = await fetch(`/api/code/${_codeCurrentId}/scan-status`).then(r => r.json()).catch(() => null);
  if (!data || !data.hypotheses) return;

  let allDone = true;
  data.hypotheses.forEach(h => {
    if (!h.scan_status || h.scan_status === 'queued' || h.scan_status === 'scanning' || h.scan_status === 'pending') {
      allDone = false;
    }
    // Find the card and update it
    const cardId = `hyp-card-${h.endpoint_path}-${h.vuln_type}`.replace(/[^a-z0-9-]/gi, '_');
    const card = document.getElementById(cardId);
    if (card && h.scan_status) {
      // Only update the status badge — don't rebuild the whole card (would wipe expanded reasoning)
      const badge = card.querySelector('.hyp-status-badge');
      const newBadge = _buildHypStatusBadge(h.scan_status);
      if (badge) badge.outerHTML = newBadge;
      else if (newBadge) {
        // Badge not yet present (first status update) — insert after vuln_type span
        const titleRow = card.querySelector('div');
        if (titleRow) titleRow.insertAdjacentHTML('beforeend', newBadge);
      }
    }
  });
  if (allDone) _stopHypStatusPoll();
}

function codeAddExtraUrl() {
  const container = document.getElementById('code-extra-urls');
  if (!container) return;
  const row = document.createElement('div');
  row.style.cssText = 'display:flex;gap:4px';
  row.innerHTML = `<input type="text" placeholder="https://api.example.com"
    style="flex:1;min-width:0;background:var(--bg2);border:1px solid var(--bdr);color:var(--txt);padding:4px 8px;border-radius:3px;font-size:10px">
    <button class="tbtn del" style="font-size:9px;padding:1px 6px;flex-shrink:0" onclick="this.parentElement.remove()">✕</button>`;
  container.appendChild(row);
  row.querySelector('input').focus();
}

function _codeGetExtraUrls() {
  return Array.from(document.querySelectorAll('#code-extra-urls input'))
    .map(i => i.value.trim()).filter(Boolean);
}

async function codeSetTarget() {
  if (!_codeCurrentId) return;
  const url = (document.getElementById('code-target-url')?.value || '').trim();
  const extra = _codeGetExtraUrls();
  const r = await fetch(`/api/code/${_codeCurrentId}/target`, {
    method: 'PATCH',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify({target_url: url, extra_target_urls: extra}),
  });
  const d = await r.json().catch(() => ({}));
  if (r.ok) {
    const total = [url, ...extra].filter(Boolean).length;
    showToast(total ? `${total} target URL(s) set` : 'Target cleared');
  } else {
    showToast('Error: ' + (d.error || r.status), true);
  }
}

async function codeLoadResults(id) {
  const data = await fetch('/api/code/results/' + id).then(r => r.json()).catch(() => null);
  if (!data) return;
  _codeCurrentId = id;
  // Populate target URL field from stored analysis
  const targetEl = document.getElementById('code-target-url');
  if (targetEl && data.target_url) targetEl.value = data.target_url;
  // Restore extra target URLs
  const extraContainer = document.getElementById('code-extra-urls');
  if (extraContainer) {
    extraContainer.innerHTML = '';
    (data.extra_target_urls || []).forEach(u => {
      if (!u) return;
      const row = document.createElement('div');
      row.style.cssText = 'display:flex;gap:4px';
      row.innerHTML = `<input type="text" value="${esc(u)}"
        style="flex:1;min-width:0;background:var(--bg2);border:1px solid var(--bdr);color:var(--txt);padding:4px 8px;border-radius:3px;font-size:10px">
        <button class="tbtn del" style="font-size:9px;padding:1px 6px;flex-shrink:0" onclick="this.parentElement.remove()">✕</button>`;
      extraContainer.appendChild(row);
    });
  }
  // Build host index from current proxy entries for validate-hypothesis
  window._codeHosts = {};
  Object.values(entries).forEach(e => { if (e.host) window._codeHosts[e.host] = 1; });

  const statusColors = { scanned: '#4ade80', enriched: '#60a5fa', scanning: 'var(--yellow)', enriching: 'var(--yellow)', error: 'var(--red)' };
  const statusEl = document.getElementById('code-status-msg');
  if (statusEl) {
    statusEl.textContent = { scanned: 'Loaded. Patterns ready. Click "AI Enrich" for endpoint extraction and hypotheses.', enriched: 'AI enrichment complete.', error: 'Error: ' + (data.error || '') }[data.status] || data.status;
    statusEl.style.color = statusColors[data.status] || 'var(--txt2)';
  }

  document.getElementById('code-stats').textContent =
    `${data.files_scanned} files · ${data.endpoints.length} endpoints · ${data.pattern_matches.length} patterns · ${data.hypotheses.length} hypotheses`;

  // Endpoints
  const tbody = document.getElementById('code-endpoints-body');
  const etable = document.getElementById('code-endpoints-table');
  const eempty = document.getElementById('code-endpoints-empty');
  tbody.innerHTML = '';
  if (data.endpoints.length) {
    etable.style.display = 'table';
    eempty.style.display = 'none';
    data.endpoints.forEach(ep => {
      const color = _codeMethodColor[ep.method] || 'var(--txt)';
      const params = ep.params.length ? ep.params.join(', ') : '—';
      const tr = document.createElement('tr');
      tr.style.borderBottom = '1px solid var(--bdr)';
      tr.innerHTML = `
        <td style="padding:4px 8px"><span style="color:${color};font-weight:600">${esc(ep.method)}</span></td>
        <td style="padding:4px 8px;font-family:monospace">${esc(ep.path)}</td>
        <td style="padding:4px 8px;color:var(--txt2)">${esc(ep.controller)}</td>
        <td style="padding:4px 8px;color:var(--txt2);font-size:9px">${esc(params)}</td>
        <td style="padding:4px 8px">
          <button class="tbtn" style="font-size:9px;padding:2px 6px"
            onclick="codeValidateEndpoint('${esc(ep.method)}','${esc(ep.path)}','${esc(ep.notes)}','${esc(ep.vuln_type||'')}')">Validate</button>
        </td>`;
      tbody.appendChild(tr);
    });
  } else {
    etable.style.display = 'none';
    eempty.style.display = 'block';
    eempty.textContent = data.error ? 'Error: ' + data.error : 'No endpoints found.';
  }

  // Patterns
  const ptbody = document.getElementById('code-patterns-body');
  const ptable = document.getElementById('code-patterns-table');
  const pempty = document.getElementById('code-patterns-empty');
  ptbody.innerHTML = '';
  if (data.pattern_matches.length) {
    ptable.style.display = 'table';
    pempty.style.display = 'none';
    data.pattern_matches.forEach(pm => {
      const color = _codeSevColor[pm.severity] || 'var(--txt)';
      const tr = document.createElement('tr');
      tr.style.borderBottom = '1px solid var(--bdr)';
      tr.innerHTML = `
        <td style="padding:4px 8px"><span style="color:${color};font-weight:600">${esc(pm.severity)}</span></td>
        <td style="padding:4px 8px">${esc(pm.title)}</td>
        <td style="padding:4px 8px;color:var(--txt2);font-size:9px;font-family:monospace">${esc(pm.file_path)}</td>
        <td style="padding:4px 8px;color:var(--txt2)">${pm.line_number}</td>
        <td style="padding:4px 8px;font-family:monospace;font-size:9px;color:var(--txt2)">${esc(pm.line_content)}</td>`;
      ptbody.appendChild(tr);
    });
  } else {
    ptable.style.display = 'none';
    pempty.style.display = 'block';
    pempty.textContent = 'No insecure patterns found.';
  }

  // Hypotheses — only rebuild if analysis changed or no cards exist yet.
  // If cards already exist (same analysis), only update the status badge in-place
  // to avoid wiping the expanded reasoning text when the user switches tabs.
  const hbody = document.getElementById('code-hypotheses-body');
  const hempty = document.getElementById('code-hypotheses-empty');
  const existingCards = hbody.querySelectorAll('[id^="hyp-card-"]');
  const needsRebuild = existingCards.length !== data.hypotheses.length
    || (existingCards.length === 0 && data.hypotheses.length > 0);

  if (data.hypotheses.length) {
    hempty.style.display = 'none';
    const htoolbar = document.getElementById('code-hypotheses-toolbar');
    if (htoolbar) {
      htoolbar.style.display = 'flex';
      const hcnt = document.getElementById('code-hyp-count');
      if (hcnt) hcnt.textContent = `${data.hypotheses.length} hypothesis${data.hypotheses.length !== 1 ? 'es' : ''}`;
    }
    if (needsRebuild) {
      hbody.innerHTML = '';
      data.hypotheses.forEach(h => {
        const div = document.createElement('div');
        div.id = `hyp-card-${esc(h.endpoint_path)}-${esc(h.vuln_type)}`.replace(/[^a-z0-9-]/gi, '_');
        div.style.cssText = 'border:1px solid var(--bdr);border-radius:4px;padding:10px 12px;margin-bottom:8px;background:var(--bg2)';
        div.innerHTML = _buildHypCard(h);
        hbody.appendChild(div);
      });
    } else {
      // Just update the status badge without touching the rest of the card
      data.hypotheses.forEach(h => {
        const cardId = `hyp-card-${esc(h.endpoint_path)}-${esc(h.vuln_type)}`.replace(/[^a-z0-9-]/gi, '_');
        const card = document.getElementById(cardId);
        if (card && h.scan_status) {
          const badge = card.querySelector('.hyp-status-badge');
          if (badge) badge.outerHTML = _buildHypStatusBadge(h.scan_status);
        }
      });
    }
    // Start polling scan status if any hypothesis has been queued
    if (data.hypotheses.some(h => h.scan_entry_id || h.scan_status)) {
      _startHypStatusPoll();
    }
  } else {
    hempty.style.display = 'block';
    hempty.textContent = 'No hypotheses generated. Click "AI Enrich" to generate hypotheses from endpoints.';
  }
}

async function codeRenderJobList() {
  const raw = await fetch('/api/code/list').then(r => r.json()).catch(() => []);
  const list = Array.isArray(raw) ? raw : [];
  const container = document.getElementById('code-job-list');
  container.innerHTML = '';
  list.forEach(job => {
    const isActive = job.analysis_id === _codeCurrentId;
    const statusColor = job.status === 'completed' ? '#4ade80' : job.status === 'error' ? 'var(--red)' : 'var(--yellow)';
    const srcs = job.sources || (job.source ? [job.source] : []);
    const srcLabel = srcs.length === 1
      ? (srcs[0].length > 45 ? '...' + srcs[0].slice(-42) : srcs[0])
      : `${srcs.length} repositories`;
    const srcDetail = srcs.length > 1
      ? srcs.map(s => s.length > 40 ? '...' + s.slice(-37) : s).join('\n')
      : '';
    const div = document.createElement('div');
    div.style.cssText = `padding:7px 12px;cursor:pointer;border-bottom:1px solid var(--bdr);background:${isActive ? 'var(--bg2)' : 'transparent'}`;
    div.title = srcDetail;
    div.onclick = () => { _codeCurrentId = job.analysis_id; codeLoadResults(job.analysis_id); };
    div.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center">
        <span style="color:${statusColor};font-size:9px;font-weight:600">${job.status.toUpperCase()}</span>
        <span style="font-size:9px;color:var(--txt2)">${job.files_scanned} files</span>
      </div>
      <div style="font-size:10px;margin-top:2px;font-family:monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(srcLabel)}</div>
      <div style="font-size:9px;color:var(--txt2);margin-top:2px">${job.endpoints} endpoints · ${job.pattern_matches} patterns · ${job.hypotheses} hypotheses</div>`;
    container.appendChild(div);
  });
}

let _codeSearchTimer = null;

function codeSearch(q) {
  clearTimeout(_codeSearchTimer);
  const container = document.getElementById('code-search-results');
  if (!q || q.length < 2) { container.innerHTML = ''; return; }
  _codeSearchTimer = setTimeout(async () => {
    const aid = _codeCurrentId ? `&analysis_id=${encodeURIComponent(_codeCurrentId)}` : '';
    const results = await fetch(`/api/code/search?q=${encodeURIComponent(q)}${aid}&limit=15`).then(r => r.json()).catch(() => []);
    container.innerHTML = '';
    if (!results.length) {
      container.innerHTML = '<div style="font-size:9px;color:var(--txt2);padding:4px">No matches.</div>';
      return;
    }
    results.forEach(r => {
      const div = document.createElement('div');
      div.style.cssText = 'padding:4px 6px;cursor:pointer;border-radius:3px;border-bottom:1px solid var(--bdr)';
      div.onmouseenter = () => div.style.background = 'var(--bg4)';
      div.onmouseleave = () => div.style.background = '';
      div.onclick = () => codeOpenFile(r.analysis_id, r.file_path);
      div.innerHTML = `
        <div style="font-size:9px;font-family:monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--txt)">${esc(r.file_path)}</div>
        ${r.preview ? `<div style="font-size:9px;color:var(--txt2);font-family:monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(r.preview)}</div>` : ''}`;
      container.appendChild(div);
    });
  }, 300);
}

async function codeOpenFile(analysisId, filePath) {
  const data = await fetch(`/api/code/file?analysis_id=${encodeURIComponent(analysisId)}&path=${encodeURIComponent(filePath)}`).then(r => r.json()).catch(() => null);
  if (!data || data.error) return;
  // Show file content in a simple overlay
  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:9999;display:flex;align-items:center;justify-content:center';
  overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };
  const box = document.createElement('div');
  box.style.cssText = 'background:var(--bg);border:1px solid var(--bdr);border-radius:4px;width:80%;max-width:900px;height:70vh;display:flex;flex-direction:column;overflow:hidden';
  box.innerHTML = `
    <div style="display:flex;align-items:center;padding:8px 12px;border-bottom:1px solid var(--bdr);flex-shrink:0">
      <span style="font-size:11px;font-family:monospace;flex:1;overflow:hidden;text-overflow:ellipsis">${esc(filePath)}</span>
      <button class="tbtn" onclick="this.closest('.code-overlay').remove()" style="font-size:10px;padding:2px 8px">Close</button>
    </div>
    <pre style="flex:1;overflow:auto;padding:12px;font-size:11px;line-height:1.5;margin:0;white-space:pre-wrap;word-break:break-all">${esc(data.content)}</pre>`;
  box.classList.add('code-overlay');
  overlay.appendChild(box);
  document.body.appendChild(overlay);
}

async function codeSendToH1(path, vulnType, reasoning, payload, method) {
  const btn = event?.target;
  if (btn) { btn.disabled = true; btn.textContent = '…'; }
  try {
    const r = await fetch('/api/code/validate-hypothesis', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        method: method || 'GET',
        path,
        host: '',
        vuln_type: vulnType,
        notes: reasoning,
        suggested_payload: payload || '',
        analysis_id: _codeCurrentId,
      }),
    });
    const d = await r.json();
    if (!r.ok) {
      showToast('Error: ' + (d.error || r.status), true);
    } else {
      showToast(d.message || 'Queued for AI validation');
      if (d.method_downgraded) showToast('Note: method downgraded to GET for safety', false);
      setTimeout(() => { switchMain('scan'); }, 800);
    }
  } catch(e) {
    showToast('Error: ' + e.message, true);
  }
  if (btn) { btn.disabled = false; btn.textContent = 'Validate'; }
}

async function codeValidateEndpoint(method, path, notes, vulnType) {
  const btn = event?.target;
  if (btn) { btn.disabled = true; btn.textContent = '…'; }

  try {
    const r = await fetch('/api/code/validate-hypothesis', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ method, path, host: '', vuln_type: vulnType || '', notes, analysis_id: _codeCurrentId }),
    });
    const d = await r.json();
    if (!r.ok) {
      showToast('Validation error: ' + (d.error || r.status), true);
    } else {
      showToast(d.message || 'Queued for AI validation');
      if (d.method_downgraded) showToast('Note: method downgraded to GET for safety', false);
      setTimeout(() => { switchMain('scan'); }, 800);
    }
  } catch(e) {
    showToast('Error: ' + e.message, true);
  }

  if (btn) { btn.disabled = false; btn.textContent = 'Validate'; }
}

