// ── setup ──────────────────────────────────────────────────────────────
async function updateSetupAiStatus() {
  const el = document.getElementById('setup-ai-status');
  if (!el) return;
  try {
    const r = await fetch('/api/status');
    const s = await r.json();
    if (s.ai_enabled) {
      el.innerHTML = `
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
          <div style="width:8px;height:8px;border-radius:50%;background:var(--green);flex-shrink:0"></div>
          <span style="color:var(--green);font-weight:600">AI connected</span>
        </div>
        <div style="color:var(--txt2)">Model: <span style="color:var(--txt)">${esc(s.ai_model_label || _modelLabel(s.ai_model))}</span></div>
        ${s.aws_identity ? `<div style="color:var(--txt2)">AWS identity: <span style="color:var(--txt)">${esc(s.aws_identity)}</span></div>` : ''}
        <div style="color:var(--txt2);margin-top:4px">Attack types: <span style="color:var(--orange)">${(s.attack_types||[]).join(', ')}</span></div>
        <div style="color:var(--txt2);margin-top:4px;font-size:10px">
          Scan all = proxy requests → fuzzing (xss, sqli, idor…) + AI analysis via Bedrock Claude → findings in dashboard
        </div>`;
    } else {
      el.innerHTML = `
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
          <div style="width:8px;height:8px;border-radius:50%;background:var(--red);flex-shrink:0"></div>
          <span style="color:var(--red);font-weight:600">AI not connected</span>
        </div>
        <div style="color:var(--txt2)">Error: <span style="color:var(--red)">${esc(s.ai_error || 'AWS credentials not found')}</span></div>
        <div style="color:var(--txt2);margin-top:6px;font-size:10px">
          Set AWS_PROFILE in your terminal before starting the proxy (<code style="color:var(--orange)">export AWS_PROFILE=&lt;name&gt;</code>),
          then run <code style="color:var(--orange)">aws sso login --profile &lt;name&gt;</code>. Scans will run without AI until connected.
        </div>`;
    }
  } catch(e) {
    el.innerHTML = '<span style="color:var(--txt2)">Status unavailable</span>';
  }
}


// ── AI status ──────────────────────────────────────────────────────────
function _modelLabel(modelId) {
  if (!modelId) return 'unknown';
  // Extract the human-readable model name from any format:
  //   us.anthropic.claude-sonnet-4-5-20250929-v1:0  → sonnet 4.5
  //   arn:aws:bedrock:...:foundation-model/anthropic.claude-haiku-4-5  → haiku 4.5
  //   anthropic.claude-opus-4-7-20251001-v1:0  → opus 4.7
  const m = modelId.match(/claude-(opus|sonnet|haiku)-(\d+)-?(\d+)?/i);
  if (m) {
    const family = m[1].toLowerCase();
    const major  = m[2];
    const minor  = m[3] || '0';
    return `${family} ${major}.${minor}`;
  }
  // Fallback: last path segment, strip date suffix and version
  return modelId.split(/[/:.]/).filter(Boolean).pop()
    .replace(/-\d{8}.*$/, '').replace(/^anthropic-/, '') || modelId;
}

let _aiOfflinePollTimer = null;

function _setAiOfflineBanner(show) {
  const banner = document.getElementById('ai-offline-banner');
  if (show) {
    banner.classList.add('on');
    // Poll every 30s so the banner disappears automatically if the user runs
    // aws sso login without clicking Resume
    if (!_aiOfflinePollTimer) {
      _aiOfflinePollTimer = setInterval(_pollAiAvailability, 30000);
    }
  } else {
    banner.classList.remove('on');
    if (_aiOfflinePollTimer) { clearInterval(_aiOfflinePollTimer); _aiOfflinePollTimer = null; }
  }
}

async function _pollAiAvailability() {
  try {
    const r = await fetch('/api/ai/availability');
    const d = await r.json();
    if (d.available) { _setAiOfflineBanner(false); loadAiStatus(); }
  } catch(e) { /* ignore */ }
}

async function resumeAi() {
  const btn = document.getElementById('ai-resume-btn');
  const msg = document.getElementById('ai-resume-msg');
  btn.disabled = true;
  msg.style.display = '';
  msg.textContent = 'Checking credentials...';
  try {
    const r = await fetch('/api/ai/resume', { method: 'POST' });
    const d = await r.json();
    if (d.ok) {
      _setAiOfflineBanner(false);
      loadAiStatus();
      msg.style.display = 'none';
    } else {
      msg.textContent = d.error || 'Still unavailable — run aws sso login first';
      btn.disabled = false;
    }
  } catch(e) {
    msg.textContent = 'Request failed';
    btn.disabled = false;
  }
}

async function loadAppVersion() {
  try {
    const r = await fetch('/api/version');
    const d = await r.json();
    const el = document.getElementById('app-version');
    if (el && d.version) el.textContent = 'v' + d.version;
  } catch (_) {}
}

async function loadAiStatus() {
  try {
    const r = await fetch('/api/status');
    const s = await r.json();
    const dot = document.getElementById('ai-dot');
    const lbl = document.getElementById('ai-lbl');
    if (s.ai_enabled) {
      dot.style.background = 'var(--green)';
      const model = s.ai_model_label || _modelLabel(s.ai_model);
      // Show tiered model info if non-default tiers are active
      let tierSuffix = '';
      try {
        const cfg = await fetch('/api/scan-config').then(r => r.json());
        const fast = cfg.fast_model_id ? _modelLabel(cfg.fast_model_id) : null;
        const val  = cfg.validation_model_id ? _modelLabel(cfg.validation_model_id) : null;
        if (fast || val) {
          const parts = [];
          if (fast) parts.push(`fast:${fast}`);
          if (val)  parts.push(`val:${val}`);
          tierSuffix = ` [${parts.join(' · ')}]`;
        }
      } catch(_) {}
      lbl.textContent = `AI: ${model}${tierSuffix}${s.aws_identity ? ' · ' + s.aws_identity : ''}`;
      lbl.style.color  = 'var(--txt)';
      lbl.title = `Model: ${s.ai_model}\nAttack types: ${(s.attack_types||[]).join(', ')}`;
    } else {
      dot.style.background = 'var(--red)';
      lbl.textContent = 'AI: not connected';
      lbl.style.color  = 'var(--red)';
      lbl.title = s.ai_error || 'AWS credentials not found';
    }

    // Check if scan queue is paused due to credential expiry
    try {
      const ra = await fetch('/api/ai/availability');
      const da = await ra.json();
      _setAiOfflineBanner(!da.available && da.scan_queue_paused);
    } catch(e) { /* ignore */ }
  } catch (e) {
    document.getElementById('ai-lbl').textContent = 'AI: unknown';
    setTimeout(loadAiStatus, 3000);
  }
}

// ── file picker handlers ───────────────────────────────────────────────

async function onSessionFileSelected(event) {
  const file = event.target.files[0];
  event.target.value = '';  // reset so same file can be picked again
  if (!file) return;
  let data;
  try { data = JSON.parse(await file.text()); } catch(e) {
    showToast('Invalid JSON file', true); return;
  }
  if (!await confirmDlg(`Load session "${data.name || file.name}"? This will replace the current HTTP history.`)) return;
  const r = await fetch('/api/sessions/import', {
    method: 'POST',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify(data),
  });
  if (!r.ok) { showToast('Import failed', true); return; }
  const result = await r.json();
  const sessionName = result.name || data.name || file.name.replace(/\.json$/, '');
  document.getElementById('session-name').value = sessionName;

  // Persist to server so auto-save has a session_id to overwrite
  const saveR = await fetch('/api/sessions', {
    method: 'POST',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify({ name: sessionName, session_id: result.id || null }),
  });
  if (saveR.ok) {
    const saved = await saveR.json();
    _setCurrentSession(saved.id, sessionName);
    _showAutoSaveLabel(true);
  }

  const re = await fetch('/api/entries');
  const list = await re.json();
  Object.keys(entries).forEach(k => delete entries[k]);
  order.length = 0;
  list.forEach(e => { entries[e.id] = e; order.push(e.id); });
  rebuildTable();
  rebuildHosts();
  rebuildSitemap();
  updateStats();
  showToast('Session loaded: ' + sessionName + ' (' + result.entry_count + ' requests)');
}

async function onSettingsFileSelected(event) {
  const file = event.target.files[0];
  event.target.value = '';
  if (!file) return;
  let data;
  try { data = JSON.parse(await file.text()); } catch(e) {
    showToast('Invalid JSON file', true); return;
  }
  const r = await fetch('/api/settings/import', {
    method: 'POST',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify(data),
  });
  if (!r.ok) { showToast('Import failed', true); return; }
  const name = data.name || file.name.replace(/\.json$/,'');
  document.getElementById('inp-project-name').value = name;
  loadSettings();
  showToast('Settings loaded: ' + name);
}

// ── sessions ────────────────────────────────────────────────────────────

function showSessionsPanel() {
  document.getElementById('sessions-overlay').style.display = 'flex';
  // pre-fill name input from current session name
  document.getElementById('new-session-name').value =
    document.getElementById('session-name').value || 'Untitled session';
  loadSessionsList();
}

function hideSessionsPanel() {
  document.getElementById('sessions-overlay').style.display = 'none';
}

async function loadSessionsList() {
  const el = document.getElementById('sessions-list');
  try {
    const r = await fetch('/api/sessions');
    const list = await r.json();
    if (!list.length) {
      el.innerHTML = '<div class="empty">No saved sessions yet.\nSave the current session to start.</div>';
      return;
    }
    el.innerHTML = list.map(s => `
      <div style="display:flex;align-items:center;gap:8px;padding:8px 18px;
                  border-bottom:1px solid var(--bdr);font-size:12px;">
        <div style="flex:1;min-width:0">
          <div style="font-weight:600;color:var(--txt);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">
            ${esc(s.name)}
          </div>
          <div style="color:var(--txt2);font-size:10px;margin-top:2px">
            ${fmtDate(s.created_at)} · ${s.entry_count} requests · ${fmtBytes(s.file_size)}
            ${s.description ? ' · ' + esc(s.description) : ''}
          </div>
        </div>
        <button class="tbtn pri" onclick="loadSession('${esc(s.id)}','${esc(s.name)}')">Open</button>
        <a class="tbtn" href="/api/sessions/${esc(s.id)}/download" download="${esc(s.name)}.json"
           style="text-decoration:none">Export</a>
        <button class="tbtn del" onclick="deleteSession('${esc(s.id)}')">Delete</button>
      </div>`).join('');
  } catch(e) {
    el.innerHTML = '<div class="empty">Failed to load sessions</div>';
  }
}

async function _exportSessionJson(name, desc) {
  const r = await fetch('/api/sessions/export', {
    method: 'POST',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify({ name, description: desc || '' }),
  });
  if (!r.ok) throw new Error('Export failed');
  return await r.text();
}

// ── auto-save ────────────────────────────────────────────────────────────────
let _autoSaveHandle = null;
let _autoSaveFileHandle = null;  // FileSystemFileHandle from showSaveFilePicker
let _currentSessionId = null;    // server-side session ID for overwrite saves

function _setCurrentSession(id, name) {
  _currentSessionId = id;
  if (id) {
    localStorage.setItem('dast-session-id', id);
    if (name) localStorage.setItem('dast-session-name', name);
    // Stamp the owning proxy process so this session is only resumed by the
    // same run (see reconcileSessionBoot). Set only on an explicit save/load.
    if (_bootId) localStorage.setItem('dast-session-boot', _bootId);
    _showAutoSaveLabel(true);
    _maybeStartAutoSave();
  } else {
    localStorage.removeItem('dast-session-id');
    localStorage.removeItem('dast-session-name');
    localStorage.removeItem('dast-session-boot');
  }
}

function _autoSaveAvailable() {
  return _autoSaveFileHandle !== null || !window.showSaveFilePicker;
}

function _showAutoSaveLabel(show) {
  document.getElementById('autosave-lbl').style.display = show ? '' : 'none';
  if (!show) {
    document.getElementById('autosave-ts').style.display = 'none';
    document.getElementById('autosave-chk').checked = false;
    if (_autoSaveHandle) { clearInterval(_autoSaveHandle); _autoSaveHandle = null; }
  }
}

async function _doAutoSave() {
  const name = document.getElementById('session-name').value.trim() || 'Untitled session';
  try {
    // Priority 1: server-side save (overwrites same session file)
    if (_currentSessionId) {
      const r = await fetch('/api/sessions', {
        method: 'POST',
        headers: {'content-type': 'application/json'},
        body: JSON.stringify({ name, session_id: _currentSessionId }),
      });
      if (r.ok) {
        const d = await r.json();
        if (d.id) _setCurrentSession(d.id, name);
      }
    // Priority 2: file system handle (user chose Save As to a local file)
    } else if (_autoSaveFileHandle) {
      const text = await _exportSessionJson(name, '');
      const writable = await _autoSaveFileHandle.createWritable();
      await writable.write(text);
      await writable.close();
    } else {
      return; // nothing to save to yet
    }
    const ts = new Date().toLocaleTimeString();
    const el = document.getElementById('autosave-ts');
    el.style.display = '';
    el.textContent = 'Saved ' + ts;
  } catch(e) {
    // Silently ignore — don't interrupt the user
  }
}

function toggleAutoSave(enabled) {
  if (_autoSaveHandle) { clearInterval(_autoSaveHandle); _autoSaveHandle = null; }
  if (enabled) {
    _autoSaveHandle = setInterval(_doAutoSave, 5 * 60 * 1000);
    showToast('Auto-save enabled — every 5 minutes');
  } else {
    document.getElementById('autosave-ts').style.display = 'none';
    showToast('Auto-save disabled');
  }
}

// Start auto-save as soon as _currentSessionId is available — no click required
function _maybeStartAutoSave() {
  if (_currentSessionId && !_autoSaveHandle) {
    const cb = document.getElementById('autosave-chk');
    if (cb) cb.checked = true;
    _autoSaveHandle = setInterval(_doAutoSave, 5 * 60 * 1000);
  }
}
// ─────────────────────────────────────────────────────────────────────────────

async function saveSessionAs() {
  const name = document.getElementById('session-name').value.trim() || 'Untitled session';
  try {
    const json = await _exportSessionJson(name, '');
    await _saveFileAs(json, name);
  } catch(e) {
    showToast('Save failed: ' + e.message, true);
  }
}

async function saveNamedSessionAs() {
  const name = document.getElementById('new-session-name').value.trim() || 'Untitled session';
  const desc = document.getElementById('new-session-desc').value.trim();
  try {
    const json = await _exportSessionJson(name, desc);
    await _saveFileAs(json, name);
    document.getElementById('session-name').value = name;
  } catch(e) {
    showToast('Save failed: ' + e.message, true);
  }
}

async function _saveFileAs(text, suggestedName) {
  const safeName = suggestedName.replace(/[^a-z0-9_\-]/gi, '_') || 'session';
  if (window.showSaveFilePicker) {
    // Native OS file picker (Chromium) — keep the handle for auto-save
    const handle = await window.showSaveFilePicker({
      suggestedName: safeName + '.json',
      types: [{ description: 'Frieren DAST-AI Session', accept: { 'application/json': ['.json'] } }],
    });
    const writable = await handle.createWritable();
    await writable.write(text);
    await writable.close();
    _autoSaveFileHandle = handle;
    showToast('Session saved.');
  } else {
    // Fallback: trigger browser download
    const blob = new Blob([text], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = safeName + '.json';
    a.click();
    URL.revokeObjectURL(url);
    showToast('Session downloaded.');
  }
  // Reveal auto-save checkbox after first successful save
  _showAutoSaveLabel(true);
}

async function loadSession(id, name) {
  if (!await confirmDlg(`Load session "${name}"? This will replace the current HTTP history.`)) return;
  const r = await fetch('/api/sessions/' + id + '/load', { method: 'POST' });
  if (r.ok) {
    const data = await r.json();
    _setCurrentSession(data.id || id, data.name);
    _showAutoSaveLabel(true);
    document.getElementById('session-name').value = data.name;
    hideSessionsPanel();
    // reload all entries from server
    const re = await fetch('/api/entries');
    const list = await re.json();
    Object.keys(entries).forEach(k => delete entries[k]);
    order.length = 0;
    list.forEach(e => { entries[e.id] = e; order.push(e.id); });
    rebuildTable();
    rebuildHosts();
    rebuildSitemap();
    updateStats();
    showToast('Session loaded: ' + data.name + ' (' + data.entry_count + ' requests)');
  } else {
    showToast('Load failed', true);
  }
}

async function deleteSession(id) {
  if (!await confirmDlg('Delete this session? This cannot be undone.')) return;
  await fetch('/api/sessions/' + id, { method: 'DELETE' });
  loadSessionsList();
}

function fmtDate(iso) {
  if (!iso) return '';
  try {
    const d = new Date(iso);
    return d.toLocaleString(undefined, { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit' });
  } catch { return iso; }
}

function fmtBytes(n) {
  if (!n) return '';
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n/1024).toFixed(0) + ' KB';
  return (n/1048576).toFixed(1) + ' MB';
}

// Returns a Promise<boolean> — resolves true on Confirm, false on Cancel.
function confirmDlg(message) {
  return new Promise(resolve => {
    const overlay = document.createElement('div');
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.65);z-index:9999;display:flex;align-items:center;justify-content:center';
    const box = document.createElement('div');
    box.style.cssText = 'background:var(--bg);border:1px solid var(--bdr);border-radius:4px;padding:20px 24px;min-width:300px;max-width:420px;display:flex;flex-direction:column;gap:16px;box-shadow:0 8px 32px rgba(0,0,0,.5)';
    box.innerHTML = `
      <div style="font-size:13px;color:var(--txt);line-height:1.5">${esc(message)}</div>
      <div style="display:flex;gap:8px;justify-content:flex-end">
        <button class="tbtn" id="_cdlg_cancel">Cancel</button>
        <button class="tbtn del" id="_cdlg_confirm">Confirm</button>
      </div>`;
    overlay.appendChild(box);
    document.body.appendChild(overlay);
    const cleanup = val => { overlay.remove(); resolve(val); };
    box.querySelector('#_cdlg_cancel').onclick  = () => cleanup(false);
    box.querySelector('#_cdlg_confirm').onclick = () => cleanup(true);
    overlay.onclick = e => { if (e.target === overlay) cleanup(false); };
    box.querySelector('#_cdlg_cancel').focus();
  });
}

function showToast(msg, isError) {
  let t = document.getElementById('toast');
  if (!t) {
    t = document.createElement('div');
    t.id = 'toast';
    t.style.cssText = 'position:fixed;bottom:24px;right:24px;padding:8px 16px;border-radius:4px;' +
      'font-size:12px;z-index:9999;transition:opacity .3s;pointer-events:none';
    document.body.appendChild(t);
  }
  t.textContent = msg;
  t.style.background = isError ? 'var(--red)' : 'var(--green)';
  t.style.color = '#fff';
  t.style.opacity = '1';
  clearTimeout(t._timer);
  t._timer = setTimeout(() => { t.style.opacity = '0'; }, 2500);
}

// close overlay on background click
document.getElementById('sessions-overlay').addEventListener('click', function(e) {
  if (e.target === this) hideSessionsPanel();
});

