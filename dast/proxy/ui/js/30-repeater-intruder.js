// ── tab switching ──────────────────────────────────────────────────────
function switchMain(tab) {
  ['overview', 'proxy', 'browse', 'ai', 'scan', 'plugins', 'graphql', 'repeater', 'intruder', 'logs', 'extras'].forEach(t => {
    document.getElementById('panel-' + t).classList.toggle('on', t === tab);
    document.getElementById('mt-' + t).classList.toggle('on', t === tab);
  });
  if (tab === 'graphql') gqlLoadEndpoints();
  if (tab === 'extras') {
    // Re-fire the currently active Extras sub-tab's load call (mirrors the old
    // per-top-level-tab dispatch for h1/code/fedramp/interactions).
    const activeSub = ['h1', 'code', 'fedramp', 'interactions'].find(
      s => document.getElementById('st-extras-' + s).classList.contains('on')
    );
    if (activeSub) switchExtrasSub(activeSub);
  }
  if (tab === 'logs')     loadLogs();
  if (tab === 'plugins')  loadPlugins();
  if (tab === 'scan')     loadScanQueue();
  if (tab === 'ai') {
    // Re-fire the currently active AI sub-tab's load call.
    const activeSub = ['suggestions', 'settings'].find(
      s => document.getElementById('st-ai-' + s).classList.contains('on')
    );
    if (activeSub) switchAiSub(activeSub);
  }
  if (tab === 'overview') loadOverview();
  if (tab === 'browse') {
    // Re-fire the currently active Browse sub-tab's load call (mirrors the old
    // per-top-level-tab dispatch for the folded-in Crawl tab).
    const isManualActive = document.getElementById('st-browse-manual').classList.contains('on');
    switchBrowseSub(isManualActive ? 'manual' : 'crawl');
  }
  if (tab === 'proxy') {
    // Re-fire the currently active Proxy sub-tab's load call (mirrors the old
    // per-top-level-tab dispatch for the folded-in Target tab, plus the
    // existing Settings-on-first-open behavior).
    const activeSub = ['history', 'intercept', 'sitemap', 'issues', 'psettings'].find(
      s => document.getElementById('st-' + s).classList.contains('on')
    );
    if (activeSub) switchProxySub(activeSub);
  }
}

// ── Repeater tabs ───────────────────────────────────────────────────────────
// Each tab: { id, label, method, url, headers, body, response, status }
const _repTabs = [];
let _repActiveId = null;
let _repTabSeq = 0;

function _repTabPaneId(id) { return 'rep-pane-' + id; }
function _repTabBtnId(id)  { return 'rep-tab-' + id; }

function repNewTab(data) {
  const id    = ++_repTabSeq;
  const label = data?.label || ('Request ' + id);
  _repTabs.push({ id, label,
    method:   data?.method   || 'GET',
    url:      data?.url      || '',
    headers:  data?.headers  || '',
    body:     data?.body     || '',
    response: '',
    status:   '',
    followRedirects: false,
    // Per-tab request/response history (browser-style back/forward). Each entry
    // snapshots the request AND its response so navigating restores both.
    history:  [],
    histIdx:  -1,
  });
  _repRenderStrip();
  _repActivate(id);
  return id;
}

function _repRenderStrip() {
  const strip = document.getElementById('rep-tab-strip');
  if (!strip) return;
  // Remove old tab buttons (keep the "+ New" button at the end)
  strip.querySelectorAll('.rep-tab-btn').forEach(el => el.remove());
  const newBtn = strip.querySelector('button');
  _repTabs.forEach(tab => {
    const btn = document.createElement('div');
    btn.className = 'rep-tab-btn' + (tab.id === _repActiveId ? ' rep-tab-active' : '');
    btn.id = _repTabBtnId(tab.id);
    btn.innerHTML = `<span class="rep-tab-label" title="${esc(tab.label)}">${esc(tab.label)}</span>`
      + `<span class="rep-tab-close" data-id="${tab.id}" title="Close">✕</span>`;
    btn.onclick = e => {
      if (e.target.classList.contains('rep-tab-close')) return;
      _repActivate(tab.id);
    };
    btn.querySelector('.rep-tab-close').onclick = e => {
      e.stopPropagation();
      _repCloseTab(tab.id);
    };
    strip.insertBefore(btn, newBtn);
  });
}

function _repBuildPane(tab) {
  const pane = document.createElement('div');
  pane.id = _repTabPaneId(tab.id);
  pane.style.cssText = 'display:none;flex-direction:column;flex:1;overflow:hidden';

  // URL toolbar
  const toolbar = document.createElement('div');
  toolbar.style.cssText = 'display:flex;align-items:center;gap:8px;padding:6px 14px;background:var(--bg2);border-bottom:1px solid var(--bdr);flex-shrink:0';
  toolbar.innerHTML = `
    <button id="rep-back-${tab.id}" class="tbtn" onclick="_repHistNav(${tab.id},-1)" title="Previous request (back)" disabled style="padding:3px 8px">‹</button>
    <button id="rep-fwd-${tab.id}" class="tbtn" onclick="_repHistNav(${tab.id},1)" title="Next request (forward)" disabled style="padding:3px 8px">›</button>
    <select id="rep-method-${tab.id}" style="background:var(--bg);border:1px solid var(--bdr);color:var(--txt);padding:3px 6px;border-radius:3px;font-family:inherit;font-size:11px;width:90px">
      ${['GET','POST','PUT','PATCH','DELETE','OPTIONS','HEAD'].map(m =>
        `<option${m===tab.method?' selected':''}>${m}</option>`).join('')}
    </select>
    <input id="rep-url-${tab.id}" value="${esc(tab.url)}" placeholder="https://example.com/path"
      style="flex:1;background:var(--bg);border:1px solid var(--bdr);color:var(--txt);padding:4px 8px;border-radius:3px;font-family:inherit;font-size:11px">
    <label style="font-size:10px;color:var(--txt2);display:flex;align-items:center;gap:3px;white-space:nowrap;cursor:pointer" title="Follow 3xx redirects automatically">
      <input type="checkbox" id="rep-follow-${tab.id}"${tab.followRedirects?' checked':''} style="margin:0"> follow redirects
    </label>
    <button class="tbtn pri" onclick="_repSendTab(${tab.id})">Send</button>
    <button class="tbtn" onclick="_repClearTab(${tab.id})">Clear</button>
    <span id="rep-status-${tab.id}" style="font-size:10px;color:var(--txt2);min-width:90px"></span>`;
  pane.appendChild(toolbar);

  // Left (request) | drag handle | Right (response)
  const split = document.createElement('div');
  split.style.cssText = 'display:flex;flex:1;overflow:hidden';

  // Left pane — headers (top) + drag handle + body (bottom)
  const left = document.createElement('div');
  left.id = `rep-left-${tab.id}`;
  left.style.cssText = 'flex:1;display:flex;flex-direction:column;overflow:hidden;min-width:120px';

  const hdrLabel = document.createElement('div');
  hdrLabel.style.cssText = 'padding:4px 14px;font-size:10px;color:var(--txt2);background:var(--bg2);border-bottom:1px solid var(--bdr);flex-shrink:0';
  hdrLabel.textContent = 'Headers (one per line):';

  const hdrArea = document.createElement('textarea');
  hdrArea.id = `rep-headers-${tab.id}`;
  hdrArea.spellcheck = false;
  hdrArea.placeholder = 'Content-Type: application/json\nAuthorization: Bearer token';
  hdrArea.value = tab.headers;
  hdrArea.style.cssText = 'flex:1;resize:none;background:var(--bg);border:none;border-bottom:1px solid var(--bdr);color:var(--txt);font-family:monospace;font-size:11px;padding:8px 14px;outline:none;min-height:40px';

  // Horizontal drag handle between headers and body
  const hDrag = document.createElement('div');
  hDrag.className = 'rep-hdrag';
  hDrag.title = 'Drag to resize';

  const bodyLabel = document.createElement('div');
  bodyLabel.style.cssText = 'padding:4px 14px;font-size:10px;color:var(--txt2);background:var(--bg2);border-bottom:1px solid var(--bdr);flex-shrink:0';
  bodyLabel.textContent = 'Body:';

  const bodyArea = document.createElement('textarea');
  bodyArea.id = `rep-body-${tab.id}`;
  bodyArea.spellcheck = false;
  bodyArea.placeholder = '{"query": "...", "variables": {}}';
  bodyArea.value = tab.body;
  bodyArea.style.cssText = 'flex:1;resize:none;background:var(--bg);border:none;color:var(--txt);font-family:monospace;font-size:11px;padding:8px 14px;outline:none;min-height:40px';

  left.appendChild(hdrLabel);
  left.appendChild(hdrArea);
  left.appendChild(hDrag);
  left.appendChild(bodyLabel);
  left.appendChild(bodyArea);

  // Vertical drag handle between left and right
  const vDrag = document.createElement('div');
  vDrag.className = 'rep-vdrag';
  vDrag.title = 'Drag to resize';

  // Right pane — response
  const right = document.createElement('div');
  right.id = `rep-right-${tab.id}`;
  right.style.cssText = 'flex:1;display:flex;flex-direction:column;overflow:hidden;min-width:120px';

  const respLabel = document.createElement('div');
  respLabel.style.cssText = 'padding:3px 10px;font-size:10px;color:var(--txt2);background:var(--bg2);border-bottom:1px solid var(--bdr);flex-shrink:0;display:flex;align-items:center';
  respLabel.innerHTML = `Response <div class="pane-view-toggle" id="rep-resp-toggle-${tab.id}" style="display:none">` +
    `<button id="rep-resp-btn-raw-${tab.id}" class="on" onclick="_setRepView(${tab.id},'raw')">Raw</button>` +
    `<button id="rep-resp-btn-pretty-${tab.id}" onclick="_setRepView(${tab.id},'pretty')">Pretty</button>` +
    `</div>`;

  const respPre = document.createElement('pre');
  respPre.id = `rep-response-${tab.id}`;
  respPre.style.cssText = 'flex:1;margin:0;padding:8px 14px;overflow:auto;font-size:11px;color:var(--txt);white-space:pre-wrap;word-break:break-all';
  respPre.innerHTML = tab.response
    ? esc(tab.response)
    : '<span style="color:var(--txt2)">Send a request to see the response here.</span>';

  right.appendChild(respLabel);
  right.appendChild(respPre);

  split.appendChild(left);
  split.appendChild(vDrag);
  split.appendChild(right);
  pane.appendChild(split);

  // Wire up horizontal drag (headers ↕ body)
  _repWireHDrag(hDrag, hdrArea, bodyArea);
  // Wire up vertical drag (request ↔ response)
  _repWireVDrag(vDrag, left, right);

  return pane;
}

function _repWireHDrag(handle, topEl, botEl) {
  handle.addEventListener('mousedown', e => {
    e.preventDefault();
    const startY   = e.clientY;
    const startTop = topEl.getBoundingClientRect().height;
    function onMove(ev) {
      const delta = ev.clientY - startY;
      const newH  = Math.max(40, startTop + delta);
      topEl.style.flex = 'none';
      topEl.style.height = newH + 'px';
    }
    function onUp() {
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
    }
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  });
}

function _repWireVDrag(handle, leftEl, rightEl) {
  handle.addEventListener('mousedown', e => {
    e.preventDefault();
    const container = handle.parentElement;
    const totalW    = container.getBoundingClientRect().width;
    const startX    = e.clientX;
    const startLeft = leftEl.getBoundingClientRect().width;
    function onMove(ev) {
      const delta   = ev.clientX - startX;
      const newLeft = Math.max(120, Math.min(totalW - 120 - 6, startLeft + delta));
      leftEl.style.flex  = 'none';
      leftEl.style.width = newLeft + 'px';
      rightEl.style.flex = '1';
    }
    function onUp() {
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
    }
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  });
}

function _repActivate(id) {
  const content = document.getElementById('rep-tab-content');
  if (!content) return;
  _repActiveId = id;

  // Save state from previously active pane before switching
  _repTabs.forEach(tab => {
    const pane = document.getElementById(_repTabPaneId(tab.id));
    if (!pane) {
      // Pane not yet created — create it now (lazy)
      const newPane = _repBuildPane(tab);
      content.appendChild(newPane);
    }
  });

  // Show/hide panes and update strip
  _repTabs.forEach(tab => {
    const pane = document.getElementById(_repTabPaneId(tab.id));
    if (pane) pane.style.display = tab.id === id ? 'flex' : 'none';
    const btn = document.getElementById(_repTabBtnId(tab.id));
    if (btn) btn.className = 'rep-tab-btn' + (tab.id === id ? ' rep-tab-active' : '');
  });
  // Sync back/forward enabled state for the now-visible pane.
  _repUpdateHistButtons(id);
}

function _repCloseTab(id) {
  const idx = _repTabs.findIndex(t => t.id === id);
  if (idx === -1) return;
  _repTabs.splice(idx, 1);
  const pane = document.getElementById(_repTabPaneId(id));
  if (pane) pane.remove();
  _repRenderStrip();
  if (_repTabs.length === 0) {
    _repActiveId = null;
  } else {
    const next = _repTabs[Math.min(idx, _repTabs.length - 1)];
    _repActivate(next.id);
  }
}

async function _repSendTab(id) {
  const tab = _repTabs.find(t => t.id === id);
  if (!tab) return;
  const method  = document.getElementById(`rep-method-${id}`)?.value || tab.method;
  const url     = (document.getElementById(`rep-url-${id}`)?.value || '').trim();
  const hdrsRaw = document.getElementById(`rep-headers-${id}`)?.value || '';
  const body    = (document.getElementById(`rep-body-${id}`)?.value || '').trim();
  const followRedirects = !!document.getElementById(`rep-follow-${id}`)?.checked;
  const respEl  = document.getElementById(`rep-response-${id}`);
  const stEl    = document.getElementById(`rep-status-${id}`);
  if (!url) { if (stEl) stEl.textContent = 'Enter a URL'; return; }
  tab.followRedirects = followRedirects;

  const headers = {};
  for (const line of hdrsRaw.split('\n')) {
    const idx2 = line.indexOf(':');
    if (idx2 > 0) headers[line.slice(0,idx2).trim()] = line.slice(idx2+1).trim();
  }

  // Auto-label tab with host after first send
  try {
    const u = new URL(url);
    tab.label = u.hostname + u.pathname.replace(/\/$/, '');
    if (tab.label.length > 28) tab.label = tab.label.slice(0, 26) + '…';
    _repRenderStrip();
  } catch(_) {}

  if (stEl) { stEl.textContent = 'Sending…'; stEl.style.color = 'var(--txt2)'; }
  if (respEl) respEl.innerHTML = '<span style="color:var(--txt2)">Waiting…</span>';

  try {
    const r = await fetch('/api/repeater/send', {
      method: 'POST',
      headers: {'content-type': 'application/json'},
      body: JSON.stringify({ method, url, headers, body: body || null, follow_redirects: followRedirects }),
    });
    const data = await r.json();
    if (stEl) {
      const hops = (data.redirect_chain || []).length;
      stEl.textContent = `HTTP ${data.status}  ${data.elapsed_ms}ms` + (hops ? `  (${hops} redirect${hops>1?'s':''})` : '');
      stEl.style.color = data.status < 400 ? 'var(--green)' : 'var(--red)';
    }
    const respHeaders = Object.entries(data.headers || {}).map(([k,v]) => `${k}: ${v}`).join('\n');
    // When redirects were followed, show the hop chain so the operator can see
    // where the request ended up (final_url differs from the requested url).
    let chainNote = '';
    if ((data.redirect_chain || []).length) {
      chainNote = '// Redirect chain:\n'
        + data.redirect_chain.map(u => `//   → ${u}`).join('\n')
        + `\n//   → ${data.final_url} (final)\n\n`;
    }
    const respText = `HTTP/1.1 ${data.status}\n${respHeaders}\n\n${chainNote}${data.body || ''}`;
    tab._rawText  = respText;
    tab._viewMode = 'raw';
    if (respEl) respEl.textContent = respText;
    tab.response = respText;
    tab.status   = `HTTP ${data.status}`;
    // Show Raw/Pretty toggle only when body is JSON
    const toggleEl = document.getElementById(`rep-resp-toggle-${id}`);
    if (toggleEl) {
      toggleEl.style.display = _isJsonBody(data.body || '') ? '' : 'none';
      // Reset to Raw
      ['raw','pretty'].forEach(m => {
        const btn = document.getElementById(`rep-resp-btn-${m}-${id}`);
        if (btn) btn.classList.toggle('on', m === 'raw');
      });
    }
    // Snapshot this request+response into the tab's history for back/forward nav.
    _repHistPush(tab, {
      method, url, headers: hdrsRaw, body, followRedirects,
      response: respText, status: tab.status,
    });
  } catch(e) {
    if (stEl) { stEl.textContent = 'Error'; stEl.style.color = 'var(--red)'; }
    if (respEl) respEl.textContent = String(e);
  }
}

// ── per-tab request history (browser-style back/forward) ────────────────────
const _REP_HIST_MAX = 50;

function _repHistPush(tab, snapshot) {
  // If the user navigated back and then sent a new request, drop the forward
  // entries — the new request becomes the new head (matches browser history).
  if (tab.histIdx < tab.history.length - 1) {
    tab.history = tab.history.slice(0, tab.histIdx + 1);
  }
  tab.history.push(snapshot);
  if (tab.history.length > _REP_HIST_MAX) tab.history.shift();
  tab.histIdx = tab.history.length - 1;
  _repUpdateHistButtons(tab.id);
}

function _repHistNav(id, dir) {
  const tab = _repTabs.find(t => t.id === id);
  if (!tab) return;
  const nextIdx = tab.histIdx + dir;
  if (nextIdx < 0 || nextIdx >= tab.history.length) return;
  tab.histIdx = nextIdx;
  const snap = tab.history[nextIdx];

  // Restore request fields + response from the snapshot.
  const methodEl = document.getElementById(`rep-method-${id}`);
  const urlEl    = document.getElementById(`rep-url-${id}`);
  const hdrEl    = document.getElementById(`rep-headers-${id}`);
  const bodyEl   = document.getElementById(`rep-body-${id}`);
  const followEl = document.getElementById(`rep-follow-${id}`);
  const respEl   = document.getElementById(`rep-response-${id}`);
  const stEl     = document.getElementById(`rep-status-${id}`);
  if (methodEl) methodEl.value = snap.method;
  if (urlEl)    urlEl.value    = snap.url;
  if (hdrEl)    hdrEl.value    = snap.headers;
  if (bodyEl)   bodyEl.value   = snap.body;
  if (followEl) followEl.checked = !!snap.followRedirects;
  if (respEl)   respEl.textContent = snap.response || '';
  if (stEl) {
    stEl.textContent = snap.status ? snap.status + `  (history ${nextIdx+1}/${tab.history.length})` : '';
    stEl.style.color = 'var(--txt2)';
  }
  // Keep tab state in sync so switching tabs doesn't lose the restored view.
  tab.method = snap.method; tab.url = snap.url; tab.headers = snap.headers;
  tab.body = snap.body; tab.followRedirects = !!snap.followRedirects;
  tab.response = snap.response || ''; tab.status = snap.status || '';
  tab._rawText = snap.response || '';
  _repUpdateHistButtons(id);
}

function _repUpdateHistButtons(id) {
  const tab = _repTabs.find(t => t.id === id);
  if (!tab) return;
  const back = document.getElementById(`rep-back-${id}`);
  const fwd  = document.getElementById(`rep-fwd-${id}`);
  if (back) back.disabled = tab.histIdx <= 0;
  if (fwd)  fwd.disabled  = tab.histIdx >= tab.history.length - 1;
}

function _repClearTab(id) {
  const tab = _repTabs.find(t => t.id === id);
  if (!tab) return;
  const u = document.getElementById(`rep-url-${id}`);
  const h = document.getElementById(`rep-headers-${id}`);
  const b = document.getElementById(`rep-body-${id}`);
  const r = document.getElementById(`rep-response-${id}`);
  const s = document.getElementById(`rep-status-${id}`);
  if (u) u.value = '';
  if (h) h.value = '';
  if (b) b.value = '';
  if (r) r.innerHTML = '<span style="color:var(--txt2)">Send a request to see the response here.</span>';
  if (s) { s.textContent = ''; s.style.color = ''; }
  tab.response = ''; tab.status = '';
}

// Legacy shims so existing callers (itrLoadFromRepeater etc.) still work
function repSend()  { if (_repActiveId) _repSendTab(_repActiveId); }
function repClear() { if (_repActiveId) _repClearTab(_repActiveId); }

// ── Send to AI ──────────────────────────────────────────────────────────────
function openSendToAI() {
  if (!detail) return;
  const pop = document.getElementById('send-ai-popover');
  document.getElementById('send-ai-note').value = '';
  pop.style.display = pop.style.display === 'none' ? 'block' : 'none';
}
function closeSendToAI() {
  document.getElementById('send-ai-popover').style.display = 'none';
}
async function confirmSendToAI() {
  if (!detail) return;
  const note = document.getElementById('send-ai-note').value.trim();
  closeSendToAI();
  const resp = await fetch('/api/manual/send-to-ai', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ entry_id: detail.id, note })
  });
  if (resp.ok) {
    showToast('Queued for AI analysis');
  } else {
    showToast('Failed to queue', 'error');
  }
}
// Close popover on outside click (btn-send-ai removed — triggered via context menu only)
document.addEventListener('click', e => {
  const pop = document.getElementById('send-ai-popover');
  if (pop && !pop.contains(e.target)) {
    pop.style.display = 'none';
  }
});

function repLoadEntry(entryId) {
  fetch('/api/entry/' + entryId).then(r => r.json()).then(d => {
    const hdrs = Object.entries(d.request_headers || {})
      .filter(([k]) => !['host','content-length','transfer-encoding','connection'].includes(k.toLowerCase()))
      .map(([k,v]) => `${k}: ${v}`).join('\n');
    let label = (d.method || 'GET') + ' ' + (d.url || '');
    try { const u = new URL(d.url); label = (d.method||'GET') + ' ' + u.hostname + u.pathname; } catch(_) {}
    if (label.length > 32) label = label.slice(0, 30) + '…';
    repNewTab({ method: d.method || 'GET', url: d.url || '', headers: hdrs, body: d.request_body || '', label });
    switchMain('repeater');
  });
}

function repLoadRaw(rawHttp) {
  // Parse a raw HTTP request string (e.g. from agent probe_request) into Repeater.
  // Format: "METHOD url HTTP/1.1\r\nHeader: value\r\n...\r\n\r\nbody"
  if (!rawHttp) return;
  try {
    const [headPart, ...bodyParts] = rawHttp.split(/\r?\n\r?\n/);
    const body = bodyParts.join('\n\n');
    const lines = headPart.split(/\r?\n/);
    const firstLine = lines[0] || '';
    const parts = firstLine.split(' ');
    const method = parts[0] || 'GET';
    let url = parts[1] || '';

    // Parse headers to get Host
    const headerLines = lines.slice(1);
    let host = '';
    const filteredHeaders = [];
    for (const line of headerLines) {
      const idx = line.indexOf(':');
      if (idx < 0) continue;
      const k = line.slice(0, idx).trim().toLowerCase();
      const v = line.slice(idx + 1).trim();
      if (k === 'host') { host = v; continue; }
      if (['content-length','transfer-encoding','connection'].includes(k)) continue;
      filteredHeaders.push(`${line.slice(0, idx).trim()}: ${v}`);
    }

    // Build full URL if it's a path only
    if (url.startsWith('/') && host) {
      const scheme = host.includes(':443') || !host.includes(':') ? 'https' : 'http';
      url = `${scheme}://${host}${url}`;
    }

    let label = method + ' ' + url;
    try { const u = new URL(url); label = method + ' ' + u.hostname + u.pathname; } catch(_) {}
    if (label.length > 32) label = label.slice(0, 30) + '…';

    repNewTab({ method, url, headers: filteredHeaders.join('\n'), body, label });
    switchMain('repeater');
  } catch(_) {}
}

// ── intruder ───────────────────────────────────────────────────────────
let _itrJobId = null;
let _itrPollTimer = null;
let _itrResultCount = 0;

// Show/hide the custom-payloads textarea based on payload source selection
document.querySelectorAll('input[name="itr-payload-src"]').forEach(el => {
  el.addEventListener('change', () => {
    const isCustom = document.querySelector('input[name="itr-payload-src"]:checked')?.value === 'custom';
    document.getElementById('itr-custom-payloads').style.display = isCustom ? 'block' : 'none';
  });
});

function itrMarkSelection() {
  const ta = document.getElementById('itr-body');
  const start = ta.selectionStart;
  const end   = ta.selectionEnd;
  if (start === end) { alert('Select text in the Body field first, then click Mark selection.'); return; }
  const before  = ta.value.slice(0, start);
  const sel     = ta.value.slice(start, end);
  const after   = ta.value.slice(end);
  ta.value = before + '§' + sel + '§' + after;
  ta.selectionStart = start;
  ta.selectionEnd   = end + 2;
  ta.focus();
}

function itrClear() {
  document.getElementById('itr-url').value = '';
  document.getElementById('itr-headers').value = '';
  document.getElementById('itr-body').value = '';
  _itrResetResults();
  document.getElementById('itr-status').textContent = 'status: idle';
}

function itrLoadFromRepeater() {
  const id = _repActiveId;
  if (!id) return;
  document.getElementById('itr-method').value  = document.getElementById(`rep-method-${id}`)?.value || 'GET';
  document.getElementById('itr-url').value     = document.getElementById(`rep-url-${id}`)?.value || '';
  document.getElementById('itr-headers').value = document.getElementById(`rep-headers-${id}`)?.value || '';
  document.getElementById('itr-body').value    = document.getElementById(`rep-body-${id}`)?.value || '';
}

function itrLoadEntry(entryId) {
  fetch('/api/entry/' + entryId).then(r => r.json()).then(d => {
    document.getElementById('itr-method').value = d.method || 'GET';
    document.getElementById('itr-url').value = d.url || '';
    const hdrs = Object.entries(d.request_headers || {})
      .filter(([k]) => !['host','content-length','transfer-encoding','connection'].includes(k.toLowerCase()))
      .map(([k,v]) => `${k}: ${v}`).join('\n');
    document.getElementById('itr-headers').value = hdrs;
    document.getElementById('itr-body').value = d.request_body || '';
    switchMain('intruder');
  });
}

function _itrResetResults() {
  _itrResultCount = 0;
  document.getElementById('itr-result-count').textContent = '0';
  document.getElementById('itr-results-tbody').innerHTML =
    '<tr><td colspan="7" style="padding:12px 10px;color:var(--txt2);font-family:inherit">No results yet — configure and start an attack above.</td></tr>';
}

async function itrStartAttack() {
  const method  = document.getElementById('itr-method').value;
  const url     = document.getElementById('itr-url').value.trim();
  if (!url) { alert('Enter a target URL first.'); return; }

  const headersRaw = document.getElementById('itr-headers').value;
  const body       = document.getElementById('itr-body').value;
  const attackTypes = Array.from(document.querySelectorAll('.itr-type-cb:checked')).map(cb => cb.value);
  if (attackTypes.length === 0) { alert('Select at least one attack type.'); return; }

  const aiMode       = document.querySelector('input[name="itr-ai-mode"]:checked')?.value || 'full';
  const payloadSrc   = document.querySelector('input[name="itr-payload-src"]:checked')?.value || 'yaml';
  const customPayloads = document.getElementById('itr-custom-payloads').value;

  // Reset UI
  _itrResetResults();
  document.getElementById('itr-status').textContent = 'status: starting...';
  document.getElementById('itr-start-btn').disabled = true;
  document.getElementById('itr-stop-btn').disabled  = false;
  const bar = document.getElementById('itr-progress-bar');
  const fill = document.getElementById('itr-progress-fill');
  bar.style.display = 'block';
  fill.style.width = '0%';

  try {
    const resp = await fetch('/api/intruder/run', {
      method: 'POST',
      headers: {'content-type': 'application/json'},
      body: JSON.stringify({
        method, url, headers_raw: headersRaw, body,
        attack_types: attackTypes, ai_mode: aiMode,
        payload_source: payloadSrc, custom_payloads: customPayloads,
      }),
    });
    const data = await resp.json();
    if (data.error) { _itrDone('error: ' + data.error); return; }
    _itrJobId = data.job_id;
    _itrPoll();
  } catch (e) {
    _itrDone('request failed: ' + e.message);
  }
}

function _itrPoll() {
  if (!_itrJobId) return;
  clearTimeout(_itrPollTimer);
  _itrPollTimer = setTimeout(async () => {
    try {
      const r = await fetch('/api/intruder/results/' + _itrJobId);
      const data = await r.json();
      _itrRenderResults(data.results || []);
      const prog = data.progress || {};
      const done  = prog.done  || 0;
      const total = prog.total || 0;
      const pct   = total > 0 ? Math.round((done / total) * 100) : 0;
      document.getElementById('itr-progress-fill').style.width = pct + '%';
      if (data.status === 'running') {
        document.getElementById('itr-status').textContent =
          `status: running — ${done} / ${total} requests...`;
        _itrPoll();
      } else {
        _itrDone(`status: ${data.status} — ${done} requests sent`);
      }
    } catch (e) {
      _itrDone('poll error: ' + e.message);
    }
  }, 600);
}

function _itrDone(msg) {
  document.getElementById('itr-status').textContent = msg;
  document.getElementById('itr-start-btn').disabled = false;
  document.getElementById('itr-stop-btn').disabled  = true;
  clearTimeout(_itrPollTimer);
}

async function itrStopAttack() {
  if (!_itrJobId) return;
  try {
    await fetch('/api/intruder/stop/' + _itrJobId, { method: 'POST' });
    document.getElementById('itr-status').textContent = 'status: stopping...';
    document.getElementById('itr-stop-btn').disabled = true;
  } catch (e) { /* ignore */ }
}

function _itrRenderResults(results) {
  if (!results || results.length === 0) return;
  _itrResultCount = results.length;
  document.getElementById('itr-result-count').textContent = String(results.length);
  const tbody = document.getElementById('itr-results-tbody');
  tbody.innerHTML = '';
  for (const r of results) {
    const tr = document.createElement('tr');
    const rowColor = r.finding ? 'background:rgba(220,50,50,.12)' :
                     r.hit     ? 'background:rgba(255,140,0,.12)' : '';
    if (rowColor) tr.style.cssText = rowColor;
    const payload = String(r.payload || '').slice(0, 80).replace(/</g,'&lt;').replace(/>/g,'&gt;');
    const finding = r.finding_title
      ? `<span style="color:var(--red);font-weight:600">${r.finding_title.replace(/</g,'&lt;')}</span>` : '';
    const hitBadge = r.hit ? '<span style="color:var(--orange);font-weight:600">YES</span>' : '';
    tr.innerHTML = `
      <td style="padding:3px 8px;border-bottom:1px solid var(--bdr)">${r.n}</td>
      <td style="padding:3px 8px;border-bottom:1px solid var(--bdr);max-width:220px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis" title="${payload}">${payload}</td>
      <td style="padding:3px 8px;border-bottom:1px solid var(--bdr)">${r.status_code ?? ''}</td>
      <td style="padding:3px 8px;border-bottom:1px solid var(--bdr)">${r.duration_ms ?? ''}</td>
      <td style="padding:3px 8px;border-bottom:1px solid var(--bdr)">${r.length_bytes ?? ''}</td>
      <td style="padding:3px 8px;border-bottom:1px solid var(--bdr)">${hitBadge}</td>
      <td style="padding:3px 8px;border-bottom:1px solid var(--bdr)">${finding}</td>
    `;
    tbody.appendChild(tr);
  }
}

