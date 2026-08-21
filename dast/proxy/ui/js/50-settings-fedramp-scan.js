// ── settings ───────────────────────────────────────────────────────────
async function loadSettings() {
  const r = await fetch('/api/settings');
  const s = await r.json();
  const rules = s.scope_rules || [];
  renderScopeTable(rules.filter(r => r.kind === 'include'), 'include', 'tbody-include', 'empty-include');
  renderScopeTable(rules.filter(r => r.kind === 'exclude'), 'exclude', 'tbody-exclude', 'empty-exclude');
  renderBypassList(s.bypass_domains || []);
  renderExtList(s.hidden_extensions || []);
  populatePresetDropdown();
}

function _protocolLabel(p) {
  if (!p || p === 'any') return 'Any';
  return p.toUpperCase();
}

function renderScopeTable(rules, kind, tbodyId, emptyId) {
  const tbody = document.getElementById(tbodyId);
  const emptyEl = document.getElementById(emptyId);
  // Compute absolute indices from the full rules list (needed for API calls)
  fetch('/api/settings').then(r => r.json()).then(s => {
    const allRules = s.scope_rules || [];
    const rows = allRules.reduce((acc, rule, idx) => {
      if (rule.kind === kind) acc.push({ rule, idx });
      return acc;
    }, []);
    if (rows.length === 0) {
      tbody.innerHTML = '';
      emptyEl.style.display = 'block';
      return;
    }
    emptyEl.style.display = 'none';
    tbody.innerHTML = rows.map(({ rule, idx }) => {
      const chkId = `chk-rule-${idx}`;
      const checked = rule.enabled ? 'checked' : '';
      const rowStyle = rule.enabled ? '' : 'opacity:0.45';
      return `<tr style="border-bottom:1px solid var(--bdr);${rowStyle}" id="rule-row-${idx}">
        <td style="padding:4px 6px;text-align:center">
          <input type="checkbox" id="${chkId}" ${checked} onchange="toggleScopeRule(${idx}, this.checked)">
        </td>
        <td style="padding:4px 8px;color:var(--txt2)">${esc(_protocolLabel(rule.protocol))}</td>
        <td style="padding:4px 8px;font-family:monospace;color:var(--orange)">${esc(rule.host || '*')}</td>
        <td style="padding:4px 8px;color:var(--txt2)">${esc(rule.port || '*')}</td>
        <td style="padding:4px 8px;font-family:monospace;color:var(--txt2)">${esc(rule.file || '/*')}</td>
        <td style="padding:4px 6px;text-align:center">
          <button class="tbtn del" style="padding:1px 7px;font-size:10px" onclick="removeScopeRule(${idx})">x</button>
        </td>
      </tr>`;
    }).join('');
  });
}

function showAddScopeForm(kind) {
  const formId = `add-${kind}-form`;
  const el = document.getElementById(formId);
  if (el.style.display !== 'none') { el.style.display = 'none'; return; }
  el.style.display = 'block';
  el.innerHTML = `
    <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap;padding:6px 0;border:1px solid var(--bdr);border-radius:3px;padding:6px 8px;background:var(--bg2)">
      <select id="inp-${kind}-proto" style="background:var(--bg);border:1px solid var(--bdr);color:var(--txt);padding:3px 6px;border-radius:3px;font-size:11px">
        <option value="any">Any</option>
        <option value="https">HTTPS</option>
        <option value="http">HTTP</option>
      </select>
      <input id="inp-${kind}-host" placeholder="Host / IP range (e.g. *.example.com)"
             style="flex:2;min-width:140px;background:var(--bg);border:1px solid var(--bdr);color:var(--txt);padding:3px 7px;border-radius:3px;font-family:monospace;font-size:11px">
      <input id="inp-${kind}-port" placeholder="Port (e.g. 443)"
             style="width:80px;background:var(--bg);border:1px solid var(--bdr);color:var(--txt);padding:3px 7px;border-radius:3px;font-size:11px">
      <input id="inp-${kind}-file" placeholder="File (e.g. /api/.*)"
             style="flex:2;min-width:100px;background:var(--bg);border:1px solid var(--bdr);color:var(--txt);padding:3px 7px;border-radius:3px;font-family:monospace;font-size:11px">
      <button class="tbtn pri" style="font-size:10px;padding:3px 10px" onclick="submitAddScopeRule('${kind}')">Add</button>
      <button class="tbtn" style="font-size:10px;padding:3px 10px" onclick="document.getElementById('${formId}').style.display='none'">Cancel</button>
    </div>`;
}

async function submitAddScopeRule(kind) {
  const rule = {
    enabled:  true,
    protocol: document.getElementById(`inp-${kind}-proto`).value,
    host:     document.getElementById(`inp-${kind}-host`).value.trim(),
    port:     document.getElementById(`inp-${kind}-port`).value.trim(),
    file:     document.getElementById(`inp-${kind}-file`).value.trim(),
    kind:     kind,
  };
  if (!rule.host) { alert('Host is required'); return; }
  await fetch('/api/settings/scope', {
    method: 'POST',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify({ rule }),
  });
  document.getElementById(`add-${kind}-form`).style.display = 'none';
  loadSettings();
}

async function removeScopeRule(index) {
  await fetch('/api/settings/scope', {
    method: 'DELETE',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify({ index }),
  });
  loadSettings();
}

async function toggleScopeRule(index, enabled) {
  await fetch(`/api/settings/scope/${index}`, {
    method: 'PATCH',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify({ enabled }),
  });
  loadSettings();
}

// ── project settings / presets ─────────────────────────────────────────
async function populatePresetDropdown() {
  const sel = document.getElementById('sel-preset');
  if (!sel) return;
  const r = await fetch('/api/projects');
  if (!r.ok) return;
  const projects = await r.json();
  const current = sel.value;
  sel.innerHTML = '<option value="">Load preset...</option>' +
    projects.map(p => `<option value="${esc(p.id)}">${esc(p.name)} (${p.rule_count} rules)</option>`).join('');
  if (current) sel.value = current;
}
async function loadPreset(sel) {
  const id = sel.value;
  sel.value = '';
  if (!id) return;
  const r = await fetch(`/api/projects/${encodeURIComponent(id)}/load`, { method: 'POST' });
  if (r.ok) {
    loadSettings();
    showToast('Preset loaded');
  } else {
    showToast('Failed to load preset', true);
  }
}
async function saveProject() {
  const name = document.getElementById('inp-project-name').value.trim();
  if (!name) { showToast('Enter a settings name', true); return; }
  const r = await fetch('/api/projects', {
    method: 'POST',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify({ name }),
  });
  if (r.ok) {
    const d = await r.json();
    showToast('Settings saved to: ' + (d.path || name));
  } else {
    showToast('Save failed', true);
  }
}


function renderBypassList(items) {
  const el = document.getElementById('list-bypass');
  if (!items.length) {
    el.innerHTML = '<div style="padding:4px 8px;font-size:10px;color:var(--txt2)">None configured</div>';
    return;
  }
  el.innerHTML = items.map(d =>
    `<div style="display:flex;align-items:center;padding:2px 8px;border-bottom:1px solid var(--bdr)">
      <span style="flex:1;font-size:11px;color:var(--txt);font-family:monospace">${esc(d)}</span>
      <button class="tbtn del" style="padding:1px 6px;font-size:10px;flex-shrink:0" onclick="removeBypass('${esc(d)}')">x</button>
    </div>`).join('');
}
function renderExtList(items) {
  const el = document.getElementById('list-ext');
  if (!items.length) {
    el.innerHTML = '<div style="padding:4px 8px;font-size:10px;color:var(--txt2)">None configured</div>';
    el.style.display = 'block';
    return;
  }
  // Render as chips for compact display
  el.innerHTML = items.map(e =>
    `<div style="display:inline-flex;align-items:center;gap:3px;background:var(--bg3);border:1px solid var(--bdr);
                border-radius:3px;padding:1px 4px 1px 7px;font-size:10px;font-family:monospace;color:var(--txt)">
      ${esc(e)}
      <button style="background:none;border:none;color:var(--txt2);cursor:pointer;padding:0 2px;font-size:11px;line-height:1"
              onclick="removeExt('${esc(e)}')" title="Remove">x</button>
    </div>`).join('');
}
async function addBypass() {
  const v = document.getElementById('inp-bypass').value.trim();
  if (!v) return;
  await fetch('/api/settings/bypass', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({domain: v}) });
  document.getElementById('inp-bypass').value = '';
  loadSettings();
}
async function removeBypass(d) {
  await fetch('/api/settings/bypass', { method:'DELETE', headers:{'content-type':'application/json'}, body: JSON.stringify({domain: d}) });
  loadSettings();
}
async function addExt() {
  const v = document.getElementById('inp-ext').value.trim();
  if (!v) return;
  await fetch('/api/settings/extension', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({ext: v}) });
  document.getElementById('inp-ext').value = '';
  loadSettings();
}
async function removeExt(e) {
  await fetch('/api/settings/extension', { method:'DELETE', headers:{'content-type':'application/json'}, body: JSON.stringify({ext: e}) });
  loadSettings();
}
document.addEventListener('keydown', e => {
  if (e.key === 'Enter') {
    if (document.activeElement?.id === 'inp-bypass') addBypass();
    if (document.activeElement?.id === 'inp-ext')    addExt();
  }
});
// ── FedRAMP Assessment ──────────────────────────────────────────────────────

const _AV_LABELS = {
  'AV-1': 'External to Corporate (Phishing)',
  'AV-2': 'External to Target System (Application)',
  'AV-3': 'Tenant to Management System',
  'AV-4': 'Tenant-to-Tenant Isolation',
  'AV-5': 'Mobile Application',
  'AV-6': 'Client-Side Application',
};
const _STATUS_ICON = { pending: '○', running: '◌', passed: '●', failed: '✗', skipped: '—', na: '∅' };
const _STATUS_COLOR = { pending: 'var(--txt2)', running: 'var(--yellow)', passed: 'var(--green)', failed: 'var(--red)', skipped: 'var(--txt2)', na: 'var(--txt3)' };
const _COV_COLOR = { auto: 'var(--green)', manual: 'var(--yellow)', partial: 'var(--orange)' };

async function fedrampLoad() {
  const r = await fetch('/api/fedramp/status').then(r => r.json()).catch(() => null);
  if (!r) return;
  // Pre-fill targets from known hosts if field is empty
  const targetsEl = document.getElementById('fedramp-targets');
  if (targetsEl && !targetsEl.value) {
    const knownHosts = Object.keys(hosts).filter(h => !h.includes('dast-ai') && hosts[h]?.ids?.length > 2);
    if (knownHosts.length) targetsEl.value = knownHosts.join(', ');
  }
  const el = document.getElementById('fedramp-checklist');
  const prog = document.getElementById('fedramp-progress');
  prog.textContent = `${r.progress.done}/${r.progress.total} complete (${r.progress.percent}%)`;

  let html = '';
  for (const [av, label] of Object.entries(_AV_LABELS)) {
    const items = r.attack_vectors[av] || [];
    if (!items.length) continue;
    const avDone = items.filter(i => ['passed','failed','skipped','na'].includes(i.status)).length;
    const avTotal = items.length;
    html += `<div style="margin-bottom:20px">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
        <strong style="font-size:var(--fs-base);color:var(--txt)">${av}</strong>
        <span style="font-size:var(--fs-sm);color:var(--txt2)">${esc(label)}</span>
        <span style="font-size:var(--fs-xs);color:var(--txt2);margin-left:auto">${avDone}/${avTotal}</span>
      </div>`;
    for (const item of items) {
      const icon = _STATUS_ICON[item.status] || '○';
      const color = _STATUS_COLOR[item.status] || 'var(--txt2)';
      const covColor = _COV_COLOR[item.coverage] || 'var(--txt2)';
      html += `<div style="border:1px solid var(--bdr);border-radius:4px;padding:8px 12px;margin-bottom:6px;background:var(--bg2)">
        <div style="display:flex;align-items:center;gap:8px;cursor:pointer" onclick="fedrampToggleDetail('${esc(item.id)}')">
          <span style="color:${color};font-size:14px" title="${item.status}">${icon}</span>
          <span style="font-size:var(--fs-sm);font-weight:600;color:var(--txt)">${esc(item.title)}</span>
          <span style="font-size:var(--fs-xs);color:${covColor};padding:1px 6px;border:1px solid ${covColor};border-radius:3px">${item.coverage}</span>
          <span style="font-size:var(--fs-xs);color:var(--txt2)">${item.mitre_id} ${esc(item.mitre_name)}</span>
          ${item.findings_count ? `<span style="font-size:var(--fs-xs);color:var(--red);margin-left:auto">${item.findings_count} finding${item.findings_count!==1?'s':''}</span>` : ''}
        </div>
        <div id="fedramp-detail-${item.id}" style="display:none;margin-top:8px;padding-top:8px;border-top:1px solid var(--bdr)">
          <p style="font-size:var(--fs-xs);color:var(--txt2);margin-bottom:8px">${esc(item.description)}</p>
          ${item.agent_types.length ? `<div style="font-size:var(--fs-xs);color:var(--txt2);margin-bottom:6px">Agents: ${item.agent_types.map(a => `<code style="background:var(--bg3);padding:1px 4px;border-radius:2px">${a}</code>`).join(' ')}</div>` : ''}
          ${item.evidence ? `<div style="font-size:var(--fs-xs);color:var(--green);margin-bottom:6px">Evidence: ${esc(item.evidence)}</div>` : ''}
          ${item.scanned_count ? `<div style="font-size:var(--fs-xs);color:var(--txt2);margin-bottom:6px">Scanned: ${item.scanned_count} URL(s)</div>` : ''}
          ${(item.tested_urls && item.tested_urls.length) ? `<div style="margin-bottom:8px;max-height:120px;overflow-y:auto;border:1px solid var(--bdr);border-radius:3px;background:var(--bg)">
            ${item.tested_urls.map(u => `<div style="padding:3px 8px;font-size:var(--fs-xs);border-bottom:1px solid #222;display:flex;gap:6px;align-items:center">
              <span style="color:${u.confirmed ? 'var(--red)' : 'var(--green)'};font-weight:600">${u.confirmed ? 'VULN' : 'SAFE'}</span>
              <span style="color:var(--txt2)">${esc(u.method)}</span>
              <span style="color:var(--txt);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1" title="${esc(u.url)}">${esc(u.url)}</span>
              ${u.finding ? `<span style="color:var(--orange);font-size:9px">${esc(u.finding)}</span>` : ''}
            </div>`).join('')}
          </div>` : ''}
          <div style="display:flex;gap:6px;align-items:center;margin-top:6px">
            <select style="font-size:var(--fs-xs);background:var(--bg);border:1px solid var(--bdr);color:var(--txt);padding:2px 6px;border-radius:3px"
                    onchange="fedrampSetStatus('${item.id}',this.value)">
              <option value="pending" ${item.status==='pending'?'selected':''}>Pending</option>
              <option value="passed" ${item.status==='passed'?'selected':''}>Passed</option>
              <option value="failed" ${item.status==='failed'?'selected':''}>Failed</option>
              <option value="skipped" ${item.status==='skipped'?'selected':''}>Skipped</option>
              <option value="na" ${item.status==='na'?'selected':''}>N/A</option>
            </select>
            <input type="text" placeholder="Add evidence note..." value="${esc(item.note)}"
                   style="flex:1;font-size:var(--fs-xs);background:var(--bg);border:1px solid var(--bdr);color:var(--txt);padding:3px 8px;border-radius:3px"
                   onblur="fedrampSetNote('${item.id}',this.value)">
          </div>
        </div>
      </div>`;
    }
    html += '</div>';
  }
  el.innerHTML = html;
}

function fedrampToggleDetail(id) {
  const el = document.getElementById('fedramp-detail-' + id);
  if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
}

async function fedrampSetStatus(id, status) {
  await fetch('/api/fedramp/toggle', {
    method: 'POST', headers: {'content-type':'application/json'},
    body: JSON.stringify({id, status})
  });
  fedrampLoad();
}

async function fedrampSetNote(id, note) {
  await fetch('/api/fedramp/note', {
    method: 'POST', headers: {'content-type':'application/json'},
    body: JSON.stringify({id, note})
  });
}

async function fedrampRun() {
  const btn = event?.target;
  if (btn) { btn.disabled = true; btn.textContent = 'Running...'; }
  const targetsInput = document.getElementById('fedramp-targets')?.value.trim() || '';
  const targets = targetsInput ? targetsInput.split(',').map(h => h.trim()).filter(Boolean) : [];
  try {
    const r = await fetch('/api/fedramp/run', {
      method: 'POST', headers: {'content-type':'application/json'},
      body: JSON.stringify({attack_vectors: ['AV-2', 'AV-3'], target_hosts: targets})
    });
    const d = await r.json();
    if (!r.ok) { showToast(d.error || 'Failed', true); return; }
    showToast(d.message);
    setTimeout(fedrampLoad, 2000);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Run Assessment'; }
  }
}

async function fedrampExport() {
  try {
    const r = await fetch('/api/fedramp/report');
    if (!r.ok) { showToast('Failed to generate report', true); return; }
    const html = await r.text();
    const blob = new Blob([html], {type: 'text/html'});
    const url = URL.createObjectURL(blob);
    window.open(url, '_blank');
    showToast('Report opened in new tab');
  } catch(e) {
    showToast('Error: ' + e.message, true);
  }
}

async function fedrampReset() {
  if (!confirm('Reset all FedRAMP checklist progress?')) return;
  await fetch('/api/fedramp/reset', {method:'POST'});
  fedrampLoad();
  showToast('Assessment reset');
}

// ── Setup ──────────────────────────────────────────────────────────────────

// Current proxy listener bind host/port, cached from /api/status so the editor
// can preselect the right radio and prefill the port when opened.
let _currentBindHost = '127.0.0.1';
let _currentBindPort = null;

function _isLoopbackHost(h) {
  h = (h || '').trim().toLowerCase();
  return h === '127.0.0.1' || h === 'localhost' || h === '::1' || h.startsWith('127.');
}

// The host implied by the currently-selected radio ("" if incomplete).
function _selectedBindHost() {
  const mode = (document.querySelector('input[name="bind-mode"]:checked') || {}).value;
  if (mode === 'loopback') return '127.0.0.1';
  if (mode === 'all') return '0.0.0.0';
  if (mode === 'specific') return (document.getElementById('bind-host-input').value || '').trim();
  return '';
}

function _refreshBindHostWarning() {
  const warn = document.getElementById('bind-host-warning');
  if (!warn) return;
  const h = _selectedBindHost();
  if (h && !_isLoopbackHost(h)) {
    warn.style.display = 'block';
    warn.textContent = 'Warning: binding to ' + h + ' turns Frieren into an open proxy '
      + 'reachable by other machines on the network. Only do this on a trusted network.';
  } else {
    warn.style.display = 'none';
  }
}

function onBindModeChange() {
  const input = document.getElementById('bind-host-input');
  const specific = (document.querySelector('input[name="bind-mode"]:checked') || {}).value === 'specific';
  if (input) { input.disabled = !specific; if (specific) input.focus(); }
  _refreshBindHostWarning();
}

function openListenerEditor() {
  const editor = document.getElementById('listener-editor');
  if (!editor) return;
  editor.style.display = 'block';
  // Preselect the radio matching the current bind host.
  const h = _currentBindHost;
  let mode = 'specific';
  if (h === '127.0.0.1' || h === '::1' || h === 'localhost') mode = 'loopback';
  else if (h === '0.0.0.0' || h === '::') mode = 'all';
  const radio = document.querySelector(`input[name="bind-mode"][value="${mode}"]`);
  if (radio) radio.checked = true;
  const input = document.getElementById('bind-host-input');
  if (input) input.value = (mode === 'specific') ? h : '';
  const portInput = document.getElementById('bind-port-input');
  if (portInput) portInput.value = _currentBindPort || '';
  onBindModeChange();
}

function closeListenerEditor() {
  const editor = document.getElementById('listener-editor');
  if (editor) editor.style.display = 'none';
}

async function updateSetupPort() {
  const iface = document.getElementById('listener-interface');
  if (!iface) return;
  // Read the actual proxy listen host/port from the backend — the runner may bump
  // the port via _find_free_port when 8080 is busy, and the bind host is
  // user-configurable, so we must not guess from the URL.
  let host = '127.0.0.1', port = null;
  try {
    const s = await (await fetch('/api/status')).json();
    if (s && s.proxy_port) { host = s.proxy_host || host; port = s.proxy_port; }
  } catch (e) { /* fall back below */ }
  if (!port) port = (parseInt(location.port) || 8088) - 8;  // best-effort fallback
  _currentBindHost = host;
  _currentBindPort = port;
  iface.textContent = `${host}:${port}`;
}

async function applyBindHost() {
  const btn = document.getElementById('bind-host-apply');
  const host = _selectedBindHost();
  if (!host) { showToast('Enter a bind address'); return; }
  const portRaw = (document.getElementById('bind-port-input') || {}).value;
  const payload = { host };
  if (portRaw !== undefined && String(portRaw).trim() !== '') {
    const port = parseInt(portRaw, 10);
    if (!(port >= 1 && port <= 65535)) { showToast('Port must be between 1 and 65535'); return; }
    payload.port = port;
  }
  if (btn) { btn.disabled = true; btn.textContent = 'Applying…'; }
  try {
    const r = await fetch('/api/settings/bind-host', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const res = await r.json();
    if (!r.ok || res.error) {
      showToast('Bind failed: ' + (res.error || 'unknown error'));
    } else {
      if (res.applied === false) showToast('Saved — applies on proxy restart');
      else showToast(`Proxy now listening on ${res.host}:${res.port}`);
      closeListenerEditor();
    }
    await updateSetupPort();
  } catch (e) {
    showToast('Bind failed: ' + e);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Apply'; }
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('bind-host-apply');
  const input = document.getElementById('bind-host-input');
  if (btn) btn.addEventListener('click', applyBindHost);
  if (input) input.addEventListener('keydown', (e) => { if (e.key === 'Enter') applyBindHost(); });
});

// ── scan ───────────────────────────────────────────────────────────────
function toggleAll(chk) {
  document.querySelectorAll('.rchk').forEach(c => c.checked = chk.checked);
  updateSelBtn();
}
function updateSelBtn() {
  document.getElementById('btn-sel').disabled =
    ![...document.querySelectorAll('.rchk')].some(c => c.checked);
}
document.addEventListener('change', e => { if (e.target.classList.contains('rchk')) updateSelBtn(); });

async function scanSelected() {
  const ids = [...document.querySelectorAll('.rchk:checked')].map(c => c.dataset.id);
  if (!ids.length) return;
  const r = await fetch('/api/scan', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({ ids }) });
  const d = await r.json();
  showToast(`Queued ${d.queued} request${d.queued !== 1 ? 's' : ''} for AI scan`);
  updateStats();
}
async function scanAll() {
  const r = await fetch('/api/scan', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({ scan_all: true }) });
  const d = await r.json();
  showToast(`Queued ${d.queued} request${d.queued !== 1 ? 's' : ''} for AI scan`);
  updateStats();
}
async function clearSession() {
  if (!await confirmDlg('Clear all captured requests? This cannot be undone.')) return;
  await fetch('/api/clear', { method: 'POST' });
  Object.keys(entries).forEach(k => delete entries[k]);
  Object.keys(hosts).forEach(k => delete hosts[k]);
  order.length = 0; seq = 0; selId = null; detail = null; selHost = null;
  selSmId = null; smDetail = null; selSmHost = null;
  document.getElementById('tbody').innerHTML = '';
  document.getElementById('hosts-list').innerHTML =
    '<div class="host-all on" id="host-all" onclick="selectHost(null)">All hosts</div>';
  document.getElementById('dbody').innerHTML =
    '<div class="empty" id="empty-msg">Select a request to inspect it</div>';
  document.getElementById('sm-tbody').innerHTML = '';
  document.getElementById('sm-hosts-list').innerHTML = '';
  document.getElementById('sm-detail-body').innerHTML =
    '<div class="empty">Select a request from the table above</div>';
  updateStats();
}

// ── stats ──────────────────────────────────────────────────────────────
function updateStats() {
  // Only count real traffic in topbar — exclude agent probes (they are attack attempts, not app traffic)
  const realEntries = order.filter(id => entries[id]?.source !== 'agent');
  const total   = realEntries.length;
  const vuln    = realEntries.filter(id => entries[id]?.scan_result === 'vulnerable').length;
  const queued  = order.filter(id => entries[id]?.queued_for_scan && !entries[id]?.scan_result).length;
}

