// ── Mode switcher ──────────────────────────────────────────────────────────
let _aiMode = false;
let _autoScanBeforeAiMode = false; // remember checkbox state before AI mode

async function setMode(mode) {
  _aiMode = mode === 'ai';
  await fetch('/api/mode', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ai_mode: _aiMode }),
  });

  const manual = document.getElementById('pill-manual');
  const ai     = document.getElementById('pill-ai');
  const autoScanCb = document.getElementById('ai-auto-scan');

  if (_aiMode) {
    manual.classList.remove('on'); ai.classList.add('on');
    ai.style.background = 'var(--green)';
    // Save current auto-scan state and enable it in AI mode
    if (autoScanCb) {
      _autoScanBeforeAiMode = autoScanCb.checked;
      autoScanCb.checked = true;
      toggleAutoScan(autoScanCb);
    }
    showToast('AI mode — auto-scanning all in-scope traffic');
  } else {
    ai.classList.remove('on'); ai.style.background = '';
    manual.classList.add('on');
    // Restore auto-scan to what it was before AI mode
    if (autoScanCb) {
      autoScanCb.checked = _autoScanBeforeAiMode;
      toggleAutoScan(autoScanCb);
    }
    showToast('Manual mode');
  }
}

// Restore mode state on connect
async function loadMode() {
  try {
    const r = await fetch('/api/mode');
    const d = await r.json();
    if (d.ai_mode) setMode('ai'); else setMode('manual');
  } catch(_) {}
}

// ── Intercept mode ──────────────────────────────────────────────────────────

let _interceptEnabled     = false;
let _interceptRespEnabled = false;
let _interceptQueue       = [];
let _interceptSelId       = null;
let _interceptActiveTab   = 'request';   // 'request' | 'response'

async function interceptLoadStatus() {
  try {
    const r = await fetch('/api/intercept/status');
    const d = await r.json();
    _interceptEnabled     = d.enabled;
    _interceptRespEnabled = d.intercept_response || false;
    _interceptUpdateBtn();
    if (d.queue_size > 0) {
      const qr = await fetch('/api/intercept/queue');
      _interceptQueue = await qr.json();
      _interceptRenderQueue();
      _interceptUpdateBadge(d.queue_size);
      if (!_interceptSelId && _interceptQueue.length > 0) {
        _interceptSelectReq(_interceptQueue[0].id);
      }
    }
  } catch(_) {}
}

async function interceptToggle() {
  const r = await fetch('/api/intercept/toggle', {
    method: 'POST', headers: {'content-type':'application/json'}, body: '{}'
  });
  const d = await r.json();
  _interceptEnabled = d.enabled;
  _interceptUpdateBtn();
  showToast(_interceptEnabled ? 'Intercept ON — requests will pause for review' : 'Intercept OFF — pending requests forwarded');
  if (_interceptEnabled) switchProxySub('intercept');
}

async function interceptToggleResponse(checked) {
  const body = checked !== undefined ? JSON.stringify({enabled: checked}) : '{}';
  const r = await fetch('/api/intercept/toggle-response', {
    method: 'POST', headers: {'content-type':'application/json'}, body,
  });
  const d = await r.json();
  _interceptRespEnabled = d.intercept_response;
  _interceptUpdateBtn();
}

function _interceptUpdateBtn() {
  const btn = document.getElementById('intercept-toggle-btn');
  if (btn) {
    btn.classList.toggle('on', _interceptEnabled);
    btn.textContent = _interceptEnabled ? 'Intercept ON' : 'Intercept';
  }
  const chk = document.getElementById('intercept-resp-chk');
  if (chk) chk.checked = _interceptRespEnabled;
}

function _interceptUpdateBadge(count) {
  const badge = document.getElementById('intercept-badge');
  if (!badge) return;
  badge.textContent = count > 0 ? String(count) : '';
  badge.classList.toggle('on', count > 0);
}

function _interceptSwitchTab(tab) {
  _interceptActiveTab = tab;
  document.getElementById('ie-tab-req').classList.toggle('on', tab === 'request');
  document.getElementById('ie-tab-resp').classList.toggle('on', tab === 'response');
  const req = _interceptQueue.find(r => r.id === _interceptSelId);
  if (req) _interceptPopulateEditor(req);
}

function _interceptRenderQueue() {
  const list  = document.getElementById('intercept-queue-list');
  const count = document.getElementById('iq-count');
  if (!list) return;
  if (count) count.textContent = `${_interceptQueue.length} pending`;
  if (!_interceptQueue.length) {
    list.innerHTML = `<div style="padding:20px;color:var(--txt2);font-size:11px;text-align:center">${
      _interceptEnabled ? 'No requests intercepted yet.' : 'Intercept is OFF.'
    }</div>`;
    _interceptSelId = null;
    _interceptClearEditor();
    return;
  }
  list.innerHTML = _interceptQueue.map(req => {
    const on    = req.id === _interceptSelId ? ' on' : '';
    const phase = req.phase === 'response' ? '<span style="font-size:9px;color:var(--orange);margin-left:3px">[resp]</span>' : '';
    return `<div class="iq-item${on}" onclick="_interceptSelectReq('${req.id}')">
      <span class="cm ${esc(req.method)} iq-method">${esc(req.method)}</span>
      <span class="iq-url" title="${esc(req.url)}">${esc(req.host)}${esc(req.path)}</span>${phase}
    </div>`;
  }).join('');
}

function _interceptSelectReq(id) {
  _interceptSelId = id;
  _interceptRenderQueue();
  const req = _interceptQueue.find(r => r.id === id);
  if (!req) { _interceptClearEditor(); return; }
  // For response-phase items, default to response tab
  if (req.phase === 'response' && _interceptActiveTab === 'request') {
    _interceptSwitchTab('response');
    return;  // _interceptSwitchTab calls _interceptPopulateEditor
  }
  _interceptPopulateEditor(req);
}

function _interceptPopulateEditor(req) {
  const titleEl   = document.getElementById('ie-title');
  const dropBtn   = document.getElementById('ie-drop-btn');
  const fwdBtn    = document.getElementById('ie-fwd-btn');
  const textarea  = document.getElementById('intercept-raw');
  if (!textarea) return;

  if (titleEl) titleEl.textContent = `${req.method} ${req.host}${req.path}`;
  if (dropBtn) dropBtn.disabled = false;
  if (fwdBtn)  fwdBtn.disabled  = false;

  if (_interceptActiveTab === 'response' && req.resp_status != null) {
    // Render response
    const hdrs = Object.entries(req.resp_headers || {})
      .filter(([k]) => !['content-length','transfer-encoding','connection'].includes(k.toLowerCase()))
      .map(([k,v]) => `${k}: ${v}`).join('\r\n');
    const bodyPart = req.resp_body ? `\r\n\r\n${req.resp_body}` : '';
    textarea.value = `HTTP/1.1 ${req.resp_status} OK\r\n${hdrs}${bodyPart}`;
  } else {
    // Render request
    const hdrs = Object.entries(req.headers || {})
      .filter(([k]) => !['host','content-length','transfer-encoding','connection'].includes(k.toLowerCase()))
      .map(([k,v]) => `${k}: ${v}`).join('\r\n');
    const hostHdr  = `host: ${req.host}`;
    const bodyPart = req.body ? `\r\n\r\n${req.body}` : '';
    textarea.value = `${req.method} ${req.url}\r\n${hostHdr}\r\n${hdrs}${bodyPart}`;
  }
}

function _interceptClearEditor() {
  const el = document.getElementById('intercept-raw');
  if (el) el.value = '';
  const t = document.getElementById('ie-title');
  if (t) t.textContent = '';
  const d = document.getElementById('ie-drop-btn');
  if (d) d.disabled = true;
  const f = document.getElementById('ie-fwd-btn');
  if (f) f.disabled = true;
}

function _interceptParseRaw(raw) {
  const lines = raw.split(/\r?\n/);
  const [method, url] = (lines[0] || '').split(' ');
  const headers = {};
  let bodyStart = -1;
  for (let i = 1; i < lines.length; i++) {
    if (!lines[i].trim()) { bodyStart = i + 1; break; }
    const colon = lines[i].indexOf(':');
    if (colon > 0) headers[lines[i].slice(0,colon).trim().toLowerCase()] = lines[i].slice(colon+1).trim();
  }
  const body = bodyStart >= 0 ? lines.slice(bodyStart).join('\n').trim() || null : null;
  return { method: method || 'GET', url: url || '', headers, body };
}

function _interceptParseRawResponse(raw) {
  const lines = raw.split(/\r?\n/);
  const statusMatch = (lines[0] || '').match(/HTTP\/\S+\s+(\d+)/);
  const status = statusMatch ? parseInt(statusMatch[1]) : 200;
  const headers = {};
  let bodyStart = -1;
  for (let i = 1; i < lines.length; i++) {
    if (!lines[i].trim()) { bodyStart = i + 1; break; }
    const colon = lines[i].indexOf(':');
    if (colon > 0) headers[lines[i].slice(0,colon).trim().toLowerCase()] = lines[i].slice(colon+1).trim();
  }
  const body = bodyStart >= 0 ? lines.slice(bodyStart).join('\n').trim() || null : null;
  return { status, headers, body };
}

async function interceptForward() {
  if (!_interceptSelId) return;
  const raw = document.getElementById('intercept-raw').value;
  const req = _interceptQueue.find(r => r.id === _interceptSelId);
  const id  = _interceptSelId;
  _interceptSelId = null;

  if (_interceptActiveTab === 'response' && req?.phase === 'response') {
    const modified = _interceptParseRawResponse(raw);
    await fetch(`/api/intercept/${id}/forward-response`, {
      method: 'POST', headers: {'content-type':'application/json'},
      body: JSON.stringify(modified),
    });
  } else {
    const modified = _interceptParseRaw(raw);
    await fetch(`/api/intercept/${id}/forward`, {
      method: 'POST', headers: {'content-type':'application/json'},
      body: JSON.stringify(modified),
    });
  }
}

async function interceptDrop() {
  if (!_interceptSelId) return;
  const id = _interceptSelId;
  _interceptSelId = null;
  await fetch(`/api/intercept/${id}/drop`, { method: 'POST' });
}

async function interceptForwardAll() {
  const r = await fetch('/api/intercept/forward-all', { method: 'POST' });
  const d = await r.json();
  showToast(`Forwarded ${d.forwarded} request(s)`);
}

// ── Match & Replace ──────────────────────────────────────────────────────────

let _mrRules = [];

async function loadMatchReplace() {
  try {
    const r = await fetch('/api/settings/match-replace');
    _mrRules = await r.json();
    _renderMrTable();
  } catch(_) {}
}

function showAddMrForm() {
  const f = document.getElementById('add-mr-form');
  if (!f) return;
  f.style.display = f.style.display === 'none' ? 'block' : 'none';
  if (f.style.display === 'block') {
    document.getElementById('mr-match').value   = '';
    document.getElementById('mr-replace').value = '';
    document.getElementById('mr-comment').value = '';
  }
}

async function saveMrRule() {
  const rule = {
    enabled: true,
    scope:   document.getElementById('mr-scope').value,
    type:    document.getElementById('mr-type').value,
    match:   document.getElementById('mr-match').value.trim(),
    replace: document.getElementById('mr-replace').value,
    comment: document.getElementById('mr-comment').value.trim(),
  };
  if (!rule.match && rule.type !== 'header') {
    showToast('Match regex is required for body/url rules'); return;
  }
  await fetch('/api/settings/match-replace', {
    method: 'POST', headers: {'content-type':'application/json'}, body: JSON.stringify(rule)
  });
  document.getElementById('add-mr-form').style.display = 'none';
  await loadMatchReplace();
  showToast('Match & Replace rule added');
}

async function deleteMrRule(idx) {
  await fetch('/api/settings/match-replace', {
    method: 'DELETE', headers: {'content-type':'application/json'},
    body: JSON.stringify({index: idx})
  });
  await loadMatchReplace();
}

async function toggleMrRule(idx, enabled) {
  await fetch('/api/settings/match-replace/toggle', {
    method: 'POST', headers: {'content-type':'application/json'},
    body: JSON.stringify({index: idx, enabled})
  });
  await loadMatchReplace();
}

function _renderMrTable() {
  const tbody = document.getElementById('tbody-mr');
  const empty = document.getElementById('empty-mr');
  if (!tbody) return;
  if (!_mrRules.length) {
    tbody.innerHTML = '';
    if (empty) empty.style.display = '';
    return;
  }
  if (empty) empty.style.display = 'none';
  tbody.innerHTML = _mrRules.map((r, i) => `
    <tr style="border-bottom:1px solid var(--bdr);opacity:${r.enabled ? 1 : 0.45}">
      <td style="padding:3px 6px;text-align:center">
        <input type="checkbox" ${r.enabled ? 'checked' : ''} style="accent-color:var(--acc)"
               onchange="toggleMrRule(${i}, this.checked)">
      </td>
      <td style="padding:3px 8px;white-space:nowrap;font-size:11px">${esc(r.scope)}</td>
      <td style="padding:3px 8px;white-space:nowrap;font-size:11px">${esc(r.type)}</td>
      <td style="padding:3px 8px;font-size:11px;font-family:monospace;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(r.match)}">${esc(r.match) || '<em style="color:var(--txt2)">any</em>'}</td>
      <td style="padding:3px 8px;font-size:11px;font-family:monospace;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(r.replace)}">${esc(r.replace)}</td>
      <td style="padding:3px 8px;font-size:11px;color:var(--txt2);max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.comment)}</td>
      <td style="padding:3px 4px;text-align:center">
        <button class="tbtn" style="font-size:9px;padding:1px 5px;color:#ff6b6b;border-color:#7a2020" onclick="deleteMrRule(${i})">x</button>
      </td>
    </tr>`).join('');
}

