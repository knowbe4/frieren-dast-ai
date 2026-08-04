// ── state ──────────────────────────────────────────────────────────────
const entries = {};
const order   = [];
const hosts   = {};
let seq       = 0;
let selId     = null;
let selHost   = null;
let dtab      = 'rr';
let detail    = null;
let selSmHost = null;
let selSmId   = null;
let smDtab    = 'rr';
let smDetail  = null;
let sortCol   = null;   // null = newest-first (insertion order)
let sortDir   = 'desc'; // 'asc' | 'desc'

// ── column visibility ─────────────────────────────────────────────────
const _COL_VIS_KEY = 'dast-col-vis';

function _colVisDefaults() {
  // default: all visible except "cz" (ms)
  return { c1: true, csrc: true, cm: true, cs: true, ch: true, cp: true, cb: true, cpl: true, cz: false };
}

function _loadColVis() {
  try {
    const saved = JSON.parse(localStorage.getItem(_COL_VIS_KEY) || 'null');
    return saved ? Object.assign(_colVisDefaults(), saved) : _colVisDefaults();
  } catch { return _colVisDefaults(); }
}

function _saveColVis(vis) {
  try { localStorage.setItem(_COL_VIS_KEY, JSON.stringify(vis)); } catch {}
}

function applyColVis() {
  const vis = {};
  document.querySelectorAll('#col-menu input[data-col]').forEach(chk => {
    vis[chk.dataset.col] = chk.checked;
  });
  _saveColVis(vis);
  _applyColVisToDOM(vis);
}

function _applyColVisToDOM(vis) {
  // Build a CSS rule hiding each column class that is off.
  // We use a <style> tag so both <th> and every <td> in that column hide together.
  let css = '';
  for (const [cls, on] of Object.entries(vis)) {
    if (!on) css += `th.${cls}, td.${cls} { display: none; } `;
  }
  let el = document.getElementById('col-vis-style');
  if (!el) {
    el = document.createElement('style');
    el.id = 'col-vis-style';
    document.head.appendChild(el);
  }
  el.textContent = css;
}

function toggleColMenu() {
  const menu = document.getElementById('col-menu');
  menu.style.display = menu.style.display === 'none' ? '' : 'none';
}

// Close col-menu on outside click
document.addEventListener('click', e => {
  const menu = document.getElementById('col-menu');
  if (!menu) return;
  if (menu.style.display !== 'none' && !menu.parentElement.contains(e.target)) {
    menu.style.display = 'none';
  }
});

// Initialise on load
(function initColVis() {
  const vis = _loadColVis();
  // Sync checkboxes to saved state
  document.querySelectorAll('#col-menu input[data-col]').forEach(chk => {
    chk.checked = vis[chk.dataset.col] !== false;
  });
  _applyColVisToDOM(vis);
})();

// ── column resize ─────────────────────────────────────────────────────
(function initColResize() {
  let dragging = null; // { th, startX, startW }
  document.addEventListener('mousedown', e => {
    if (!e.target.classList.contains('col-resizer')) return;
    const th = e.target.closest('th');
    dragging = { th, startX: e.clientX, startW: th.offsetWidth, handle: e.target };
    e.target.classList.add('dragging');
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
    e.preventDefault();
  });
  document.addEventListener('mousemove', e => {
    if (!dragging) return;
    const w = Math.max(40, dragging.startW + e.clientX - dragging.startX);
    dragging.th.style.width = w + 'px';
  });
  document.addEventListener('mouseup', () => {
    if (!dragging) return;
    dragging.handle.classList.remove('dragging');
    document.body.style.cursor = '';
    document.body.style.userSelect = '';
    dragging = null;
  });
})();

// ── panel resize (hosts | list | detail columns) ──────────────────────
(function initPanelResize() {
  function makeResizer(resizerId, getLeft, getRight, minLeft, minRight, storageKey) {
    const handle = document.getElementById(resizerId);
    if (!handle) return;
    let dragging = false, startX = 0, startLeftW = 0, startRightW = 0;

    // Restore persisted width for the RIGHT panel
    if (storageKey) {
      const saved = localStorage.getItem('dast-col-' + storageKey);
      if (saved) {
        const right = getRight();
        if (right) { right.style.width = saved + 'px'; right.style.flex = 'none'; }
      }
    }

    handle.addEventListener('mousedown', e => {
      const left  = getLeft();
      const right = getRight();
      if (!left || !right) return;
      dragging   = true;
      startX     = e.clientX;
      startLeftW = left.offsetWidth;
      startRightW = right.offsetWidth;
      handle.classList.add('dragging');
      document.body.style.cursor    = 'col-resize';
      document.body.style.userSelect = 'none';
      e.preventDefault();
    });

    document.addEventListener('mousemove', e => {
      if (!dragging) return;
      const left  = getLeft();
      const right = getRight();
      if (!left || !right) return;
      const delta = e.clientX - startX;
      const newLeftW  = Math.max(minLeft,  startLeftW  + delta);
      const newRightW = Math.max(minRight, startRightW - delta);
      left.style.width  = newLeftW  + 'px';
      left.style.flex   = 'none';
      right.style.width = newRightW + 'px';
      right.style.flex  = 'none';
    });

    document.addEventListener('mouseup', () => {
      if (!dragging) return;
      dragging = false;
      handle.classList.remove('dragging');
      document.body.style.cursor    = '';
      document.body.style.userSelect = '';
      if (storageKey) {
        const right = getRight();
        if (right) localStorage.setItem('dast-col-' + storageKey, right.offsetWidth);
      }
    });
  }

  // proxy: left resizer (hosts ↔ list)
  makeResizer('proxy-resizer-left',
    () => document.getElementById('proxy-hosts-col'),
    () => document.getElementById('list-col'),
    80, 200
  );

  // proxy: right resizer (list ↔ detail) — width persisted in localStorage
  makeResizer('proxy-resizer-right',
    () => document.getElementById('list-col'),
    () => document.getElementById('proxy-detail-col'),
    200, 280,
    'proxy-detail'
  );

  // target: left resizer (hosts ↔ right content)
  makeResizer('target-resizer-left',
    () => document.getElementById('target-hosts-col'),
    () => document.getElementById('target-right-col'),
    80, 200
  );
})();

// ── auto sidebar resize (single fixed-width sidebar + flex:1 content) ──────
// Any element marked `data-rz="<key>"` gets a drag handle injected right after
// it. Dragging adjusts ONLY that sidebar's width; the flex:1 sibling absorbs
// the rest. Width persists to localStorage under 'dast-rz-<key>'. Unlike
// makeResizer (proxy's dual-panel layout, pre-placed handles), this scans the
// DOM and works for the single-sidebar layouts in GraphQL / Extras / Interactions.
(function initSidebarResize() {
  function attach(sidebar) {
    const key = sidebar.getAttribute('data-rz');
    if (!key || sidebar._rzWired) return;
    sidebar._rzWired = true;

    // Minimum width: honour the sidebar's own min-width, floor at 120px.
    const cssMin = parseInt(getComputedStyle(sidebar).minWidth, 10);
    const minWidth = Number.isFinite(cssMin) && cssMin > 0 ? cssMin : 120;

    // Restore persisted width (overrides any %/px width from the style attr).
    const saved = localStorage.getItem('dast-rz-' + key);
    if (saved) {
      sidebar.style.width = saved + 'px';
      sidebar.style.flex = 'none';
    }

    const handle = document.createElement('div');
    handle.className = 'panel-resizer';
    sidebar.insertAdjacentElement('afterend', handle);

    let dragging = false, startX = 0, startW = 0;
    handle.addEventListener('mousedown', e => {
      dragging = true;
      startX = e.clientX;
      startW = sidebar.offsetWidth;
      handle.classList.add('dragging');
      document.body.style.cursor = 'col-resize';
      document.body.style.userSelect = 'none';
      e.preventDefault();
    });
    document.addEventListener('mousemove', e => {
      if (!dragging) return;
      const w = Math.max(minWidth, startW + e.clientX - startX);
      sidebar.style.width = w + 'px';
      sidebar.style.flex = 'none';
    });
    document.addEventListener('mouseup', () => {
      if (!dragging) return;
      dragging = false;
      handle.classList.remove('dragging');
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      localStorage.setItem('dast-rz-' + key, sidebar.offsetWidth);
    });
  }

  document.querySelectorAll('[data-rz]').forEach(attach);
})();

// ── WebSocket ──────────────────────────────────────────────────────────
let _lastKnownEntryCount = 0;
let _wsHeartbeatTimer = null;
let _wsReconnectDelay = 2000;

// Identity of the proxy process we are talking to. A persisted session id is
// only resumed when it was stamped with this same boot id (see
// reconcileSessionBoot). Shared across the concatenated UI scripts.
let _bootId = null;
let _bootReconcilePromise = null;

// Drop any persisted session id that does NOT belong to the running proxy
// process. localStorage is keyed by origin (127.0.0.1:<port>), so a restart or
// a second project on the same port would otherwise silently resume a stale
// session and overwrite its file with the new run's traffic. A session id is
// only ever stamped with a boot id after an explicit save or load, so a fresh
// launch always starts on a clean untitled session.
async function reconcileSessionBoot() {
  try {
    const r = await fetch('/api/boot-id');
    if (!r.ok) return;
    const d = await r.json();
    _bootId = d.boot_id || null;
    if (_bootId && localStorage.getItem('dast-session-boot') !== _bootId) {
      localStorage.removeItem('dast-session-id');
      localStorage.removeItem('dast-session-name');
      localStorage.removeItem('dast-session-boot');
    }
  } catch (_) {}
}

async function loadAllEntries() {
  try {
    const r = await fetch('/api/entries');
    if (!r.ok) return;
    const list = await r.json();
    if (!list.length) return;
    let added = 0;
    list.forEach(e => {
      if (entries[e.id]) {
        e._seq = entries[e.id]._seq;
        entries[e.id] = e;
      } else {
        seq++;
        e._seq = seq;
        entries[e.id] = e;
        order.push(e.id);
        added++;
      }
      updateHostIndex(e, false);
    });
    _lastKnownEntryCount = list.length;
    if (added > 0) {
      rebuildTable();
      rebuildHosts();
      rebuildSitemap();
      updateStats();
    }

    // Only restore a session that belongs to the running proxy process.
    try { await (_bootReconcilePromise || Promise.resolve()); } catch (_) {}
    const savedId   = localStorage.getItem('dast-session-id');
    const savedName = localStorage.getItem('dast-session-name');
    if (savedId && !_currentSessionId) {
      _currentSessionId = savedId;
      _showAutoSaveLabel(true);
      _maybeStartAutoSave();
      if (savedName) {
        const nameEl = document.getElementById('session-name');
        if (nameEl && nameEl.value === 'Untitled session') nameEl.value = savedName;
      }
    }
  } catch(_) {}
}

function connect() {
  const ws = new WebSocket(`ws://${location.host}/ws`);

  // Client-side heartbeat — send a ping every 25s to keep the connection alive
  // through proxies, firewalls, and browser idle throttling.
  function _startHeartbeat() {
    _stopHeartbeat();
    _wsHeartbeatTimer = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        try { ws.send('ping'); } catch(_) {}
      }
    }, 25000);
  }
  function _stopHeartbeat() {
    if (_wsHeartbeatTimer) { clearInterval(_wsHeartbeatTimer); _wsHeartbeatTimer = null; }
  }

  ws.onopen = () => {
    dot(true);
    _wsReconnectDelay = 2000;  // reset backoff on successful connect
    _startHeartbeat();
    loadAiStatus();
    loadAppVersion();
    loadMode();
    interceptLoadStatus();
    // Eager plugin fetch so plugin-gated tabs (e.g. GraphQL) hide/show
    // correctly even before the user ever opens the Plugins tab.
    loadPlugins();
    // Resolve the proxy's boot id before restoring any persisted session, so a
    // stale session from another run/project is never silently resumed.
    _bootReconcilePromise = reconcileSessionBoot();
    // Always reload entries on reconnect — we may have missed updates while disconnected
    loadAllEntries();
  };

  ws.onclose = () => {
    dot(false);
    _stopHeartbeat();
    // Exponential backoff: 2s → 4s → 8s → cap at 30s
    setTimeout(connect, _wsReconnectDelay);
    _wsReconnectDelay = Math.min(_wsReconnectDelay * 2, 30000);
  };

  ws.onerror = () => {
    // onerror is always followed by onclose — let onclose handle reconnect
    dot(false);
    _stopHeartbeat();
  };
  ws.onmessage = e => {
    // "pong" is a keepalive reply — no processing needed
    if (e.data === 'pong') return;
    const msg = JSON.parse(e.data);
    // Server-side keepalive ping — ignore
    if (msg.type === 'keepalive') return;
    if (msg.type === 'intercept_status') {
      _interceptEnabled = msg.enabled;
      if (msg.intercept_response !== undefined) _interceptRespEnabled = msg.intercept_response;
      _interceptUpdateBtn();
      return;
    }
    if (msg.type === 'intercept_queue') {
      _interceptQueue = msg.queue || [];
      _interceptRenderQueue();
      _interceptUpdateBadge(msg.queue_size || 0);
      // Auto-select first item if none selected
      if (!_interceptSelId && _interceptQueue.length > 0) {
        _interceptSelectReq(_interceptQueue[0].id);
      }
      // Auto-switch to intercept tab when a request arrives and intercept is on
      if (_interceptEnabled && msg.queue_size > 0) {
        const proxyOpen = document.getElementById('panel-proxy')?.classList.contains('on');
        const interceptOpen = document.getElementById('proxy-intercept')?.style.display === 'flex';
        if (proxyOpen && !interceptOpen) switchProxySub('intercept');
      }
      return;
    }
    if (msg.type === 'interaction') {
      _interactionsOnWsEvent(msg);
      return;
    }
    const entry = msg;
    const prev  = entries[entry.id];
    const isNew = !prev;
    if (!isNew) entry._seq = prev._seq; // preserve sequence number on update
    entries[entry.id] = entry;
    if (isNew) { seq++; entry._seq = seq; order.unshift(entry.id); }
    updateHostIndex(entry, isNew);
    renderRow(entry, isNew);
    if (isNew && sortCol) rebuildTbody();
    renderHostItem(entry.host);
    updateStats();
    if (selId   === entry.id)   refreshDetail(entry.id);
    if (selSmId === entry.id)   refreshSmDetail(entry.id);
    if (selSmHost === entry.host) renderSmContents(entry.host);
    // In AI mode: when a passive or pattern finding arrives on an unscanned entry, queue for active scan
    if (_aiMode && !entry.queued_for_scan && !entry.scan_result && entry.source !== 'out-of-scope') {
      const _vbyHas = (f, ...vals) => { const v = f.validated_by; return Array.isArray(v) ? vals.some(x => v.includes(x)) : vals.includes(v); };
      const hasNewUnvalidated = (entry.findings || []).some(f =>
        _vbyHas(f, 'passive', 'pattern') &&
        !f.confirmed &&
        !(prev?.findings || []).some(pf => pf.title === f.title && pf.attack_type === f.attack_type)
      );
      if (hasNewUnvalidated) {
        fetch('/api/manual/send-to-ai', {
          method: 'POST',
          headers: {'content-type': 'application/json'},
          body: JSON.stringify({ entry_id: entry.id, note: 'auto-queued: unvalidated finding needs active confirmation' }),
        }).catch(() => {});
      }
    }
    // Notify when a manually-queued (Send to AI) scan finishes
    if (entry.ai_queued && entry.scan_result && (!prev || !prev.scan_result)) {
      const method = entry.method || '';
      const path   = (entry.path || entry.url || '').slice(0, 60);
      if (entry.scan_result === 'vulnerable') {
        const n = (entry.findings || []).length;
        showToast(`AI scan: ${n} finding${n !== 1 ? 's' : ''} — ${method} ${path}`, false);
      } else if (entry.scan_result === 'safe') {
        showToast(`AI scan: no findings — ${method} ${path}`, false);
      }
    }
  };
}
function dot(on) {
  document.getElementById('ws-dot').className = on ? 'on' : '';
  document.getElementById('ws-lbl').textContent = on ? 'connected' : 'disconnected';
}

// ── column sort ────────────────────────────────────────────────────────
const _SORT_KEY = {
  seq:    e => e._seq ?? 0,
  method: e => e.method || '',
  status: e => e.status || 0,
  host:   e => e.host || '',
  path:   e => e.path || '',
  ms:     e => e.duration_ms ?? 0,
};

function setSort(col) {
  if (sortCol === col) {
    if (sortDir === 'asc') {
      sortDir = 'desc';
    } else {
      // third click resets to no sort (newest first)
      sortCol = null;
      sortDir = 'desc';
      updateSortHeaders();
      rebuildTbody();
      return;
    }
  } else {
    sortCol = col;
    sortDir = 'asc'; // first click always asc (1→N, a→z, 0→999)
  }
  updateSortHeaders();
  rebuildTbody();
}

function updateSortHeaders() {
  ['seq','method','status','host','path','ms'].forEach(c => {
    const th = document.getElementById('th-' + c);
    if (!th) return;
    th.classList.toggle('sort-on', sortCol === c);
    const existing = th.querySelector('.sort-arrow');
    if (existing) existing.remove();
    if (sortCol === c) {
      const arrow = document.createElement('span');
      arrow.className = 'sort-arrow';
      arrow.textContent = sortDir === 'asc' ? '▲' : '▼';
      th.appendChild(arrow);
    }
  });
}

function getSortedOrder() {
  // order[0] = newest (unshift on arrival). Default: newest first = order as-is.
  if (!sortCol) return [...order];
  const fn = _SORT_KEY[sortCol];
  return [...order].sort((a, b) => {
    const va = fn(entries[a] || {});
    const vb = fn(entries[b] || {});
    if (va < vb) return sortDir === 'asc' ? -1 : 1;
    if (va > vb) return sortDir === 'asc' ? 1 : -1;
    return 0;
  });
}

function rebuildTbody() {
  const tbody = document.getElementById('tbody');
  const sorted = getSortedOrder();
  // Reorder existing rows without re-rendering (preserves event listeners)
  for (const id of sorted) {
    const tr = document.getElementById('row-' + id);
    if (tr) tbody.appendChild(tr); // appendChild moves existing nodes
  }
  applyFilter();
}

function rebuildTable() {
  // Full re-render after bulk load (session import/load).
  // order[0] = newest. Assign seq so #1 = oldest, #N = newest.
  seq = order.length;
  order.forEach((id, i) => { if (entries[id]) entries[id]._seq = order.length - i; });
  document.getElementById('tbody').innerHTML = '';
  Object.keys(hosts).forEach(k => delete hosts[k]);
  document.getElementById('hosts-list').innerHTML =
    '<div class="host-all on" id="host-all" onclick="selectHost(null)">All hosts</div>';
  // Iterate oldest-first so prepend() produces newest-at-top when sortCol is null.
  for (const id of [...order].reverse()) {
    const e = entries[id];
    if (!e) continue;
    updateHostIndex(e, true);
    renderRow(e, true);
    renderHostItem(e.host);
  }
  if (sortCol) rebuildTbody(); // reorder by active sort column
  applyFilter();
  updateStats();
}

function rebuildHosts() { /* host sidebar already rebuilt inside rebuildTable */ }
function rebuildSitemap() { /* sitemap is rebuilt lazily when the tab opens */ }

// ── host index ─────────────────────────────────────────────────────────
function updateHostIndex(entry, isNew) {
  if (!hosts[entry.host]) hosts[entry.host] = { ids: [], vulnCount: 0 };
  const h = hosts[entry.host];
  if (isNew) h.ids.push(entry.id);
  h.vulnCount = h.ids.filter(id => entries[id]?.scan_result === 'vulnerable').length;
  // Track if this host is exclusively OOS
  h.allOos = h.ids.every(id => entries[id]?.source === 'out-of-scope');
}

// ── proxy hosts sidebar ────────────────────────────────────────────────
function renderHostItem(host) {
  const h = hosts[host];
  let el = document.getElementById('hi-' + CSS.escape(host));
  if (!el) {
    el = document.createElement('div');
    el.className = 'host-item';
    el.id = 'hi-' + CSS.escape(host);
    el.onclick = () => selectHost(host);
    document.getElementById('hosts-list').appendChild(el);
  }
  el.className = 'host-item' + (selHost === host ? ' on' : '');
  // Show host only if it has at least one entry that would be visible given current filter
  // Default to false (hide OOS) if checkbox not yet in DOM
  const oosOn = document.getElementById('chk-src-oos')?.checked ?? false;
  // A host is visible only if it has at least one real (non-imported, non-OOS) entry,
  // or OOS is toggled on. Hosts that only exist because of import-findings synthetic
  // entries are hidden — they don't represent real observed traffic.
  const hasRealEntry = h.ids.some(id => {
    const e = entries[id];
    if (!e) return false;
    if (e.source === 'out-of-scope') return oosOn;
    if (e.source === 'imported') return false;
    return true;
  });
  el.style.display = hasRealEntry ? '' : 'none';
  const visibleIds = h.ids.filter(id => {
    const e = entries[id];
    if (!e) return false;
    if (e.source === 'out-of-scope') return oosOn;
    if (e.source === 'imported') return false;
    return true;
  });
  const crawlerIds = visibleIds.filter(id => entries[id]?.source === 'crawler');
  const crawlBadge = crawlerIds.length ? `<span class="host-cnt" style="color:var(--blue)" title="Crawler requests">C:${crawlerIds.length}</span>` : '';
  el.innerHTML = `<div class="host-name" title="${esc(host)}">${esc(host)}</div>
    <div class="host-meta">
      <span class="host-cnt">${visibleIds.length} req</span>
      ${crawlBadge}
    </div>
    <div class="host-actions" style="display:none;gap:4px;margin-top:3px">
      <button class="tbtn" style="font-size:10px;padding:1px 6px"
        onclick="event.stopPropagation();crawlHost('${esc(host)}')">Crawl</button>
      <button class="tbtn" style="font-size:10px;padding:1px 6px"
        onclick="event.stopPropagation();scanHost('${esc(host)}')">Scan all</button>
    </div>`;
  el.onmouseenter = () => el.querySelector('.host-actions').style.display = 'flex';
  el.onmouseleave = () => el.querySelector('.host-actions').style.display = 'none';
}

function selectHost(host) {
  selHost = host;
  document.getElementById('host-all').className = 'host-all' + (host === null ? ' on' : '');
  Object.keys(hosts).forEach(h => {
    const el = document.getElementById('hi-' + CSS.escape(h));
    if (el) el.className = 'host-item' + (h === host ? ' on' : '');
  });
  applyFilter();
}

// ── proxy request table ────────────────────────────────────────────────
const _SRC_TAG = {
  proxy:          '<span class="src-tag src-proxy"    title="Manual browser via proxy">proxy</span>',
  browse:         '<span class="src-tag src-browse"   title="Headless browse session">browse</span>',
  crawler:        '<span class="src-tag src-crawler"  title="SPA crawler">crawl</span>',
  agent:          '<span class="src-tag src-agent"    title="AI agent probe (LLM-driven)">agent</span>',
  scan:           '<span class="src-tag src-scan"     title="Deterministic scan probe (code-driven)">scan</span>',
  imported:       '<span class="src-tag src-imported" title="Imported finding replay">import</span>',
  'out-of-scope': '<span class="src-tag src-oos"      title="Outside configured scope">oos</span>',
};

function renderRow(entry, isNew) {
  let tr = document.getElementById('row-' + entry.id);
  const sc  = entry.status ? 's' + String(entry.status)[0] : '';
  const rc  = entry.scan_result === 'vulnerable' ? 'r-v'
            : entry.scan_result === 'safe'       ? 'r-s'
            : entry.queued_for_scan              ? 'r-q'
            : entry.source === 'crawler'         ? 'r-c'
            : entry.source === 'out-of-scope'    ? 'r-oos' : '';
  const srcTag = _SRC_TAG[entry.source] || _SRC_TAG.proxy;
  const scanBdg = entry.queued_for_scan && !entry.scan_result ? '<span class="sbdg q">queued</span>' : '';
  // Probe legend: a scanner request injects a test value to observe how the
  // endpoint reacts. Detection is based on the RESPONSE (reflected value,
  // redirect Location, error signature, timing), never on the probe reaching a
  // real destination — reserved test hosts like *.invalid never resolve, so
  // nothing is actually visited. This tooltip stops probe rows (e.g. a
  // redirect_url=//dast-redirect-canary.invalid open-redirect probe) from
  // looking like the tool trying to fetch a nonsense URL.
  const _isProbe = (entry.source === 'agent' || entry.source === 'scan') && !!entry.probe_payload;
  const _probeTip = 'Security probe: this value was injected to test how the endpoint reacts. '
    + 'Detection is based on the server\'s RESPONSE, not on reaching this address. '
    + 'Reserved test hosts (.invalid) never resolve, so nothing is actually visited.';
  const probeBdg = _isProbe
    ? `<span class="sbdg" style="background:#3b6ea5;color:#e8f0ff;margin-right:4px" title="${esc(_probeTip)}">probe</span>`
    : '';
  const bodyCell = entry.body_preview
    ? `<span title="${esc(entry.body_preview)}">${esc(entry.body_preview.slice(0,80))}${entry.body_preview.length > 80 ? '…' : ''}</span>`
    : '';
  if (isNew) {
    tr = document.createElement('tr');
    tr.id = 'row-' + entry.id;
    tr.onclick = () => selectRow(entry.id);
    const tbody = document.getElementById('tbody');
    if (sortCol) {
      tbody.appendChild(tr); // rebuildTbody will reorder
    } else {
      tbody.prepend(tr);     // no sort: newest at top
    }
  }
  tr.className = rc + (selId === entry.id ? ' on' : '');
  tr.innerHTML = `
    <td class="c0"><input type="checkbox" class="rchk" data-id="${esc(entry.id)}"
      onclick="event.stopPropagation();updateSelBtn()"></td>
    <td class="c1">${entry._seq ?? ''}</td>
    <td class="csrc">${srcTag}</td>
    <td class="cm ${esc(entry.method)}">${esc(entry.method)}</td>
    <td class="cs ${sc}">${entry.status || ''}</td>
    <td class="ch" title="${esc(entry.host)}">${esc(entry.host)}</td>
    <td class="cp" title="${esc(entry.path)}">${esc(entry.path)}${scanBdg}</td>
    <td class="cb">${bodyCell}</td>
    <td class="cpl">${entry.ai_queued ? '<span class="sbdg" style="background:#EF9F27;color:#0a0a1a;margin-right:4px" title="Manually queued for AI scan">AI</span>' : ''}${probeBdg}${entry.probe_payload ? `<span title="${esc(_isProbe ? _probeTip : entry.probe_payload)}">${esc(entry.probe_payload.slice(0,40))}${entry.probe_payload.length > 40 ? '…' : ''}</span>` : ''}</td>
    <td class="cz" style="${entry.duration_ms > 2000 ? 'color:var(--red)' : entry.duration_ms > 500 ? 'color:var(--yellow)' : ''}">${entry.duration_ms != null ? entry.duration_ms.toFixed(0) : ''}</td>`;
  applyFilterRow(tr, entry);
  if (selId === entry.id) tr.classList.add('on');
}

// ── filter ─────────────────────────────────────────────────────────────
function toggleOos() {
  const hiddenChk = document.getElementById('chk-src-oos');
  const labelChk  = document.getElementById('chk-oos-label');
  // Sync both checkboxes
  const newState = labelChk ? labelChk.checked : !hiddenChk.checked;
  hiddenChk.checked = newState;
  if (labelChk) labelChk.checked = newState;
  applyFilter();
  _renderOosHosts();
}

function _renderOosHosts() {
  // Re-render all host items so visibility reflects current OOS checkbox state
  Object.keys(hosts).forEach(host => renderHostItem(host));
}

function applyFilter() {
  document.querySelectorAll('#tbody tr').forEach(tr => {
    const id = tr.id.replace('row-', '');
    if (entries[id]) applyFilterRow(tr, entries[id]);
  });
}
function applyFilterRow(tr, e) {
  const q       = document.getElementById('filter').value.toLowerCase();
  const hConn   = document.getElementById('chk-conn').checked;
  const hVuln   = document.getElementById('chk-vuln').checked;
  const showProxy   = document.getElementById('chk-src-proxy').checked;
  const showBrowse  = document.getElementById('chk-src-browse').checked;
  const showCrawler = document.getElementById('chk-src-crawler').checked;
  const showAgent   = document.getElementById('chk-src-agent').checked;
  const showScan    = document.getElementById('chk-src-scan').checked;
  const showOos     = document.getElementById('chk-src-oos').checked;
  const src = e.source || 'proxy';
  const srcOk = (src === 'proxy'          && showProxy)
             || (src === 'browse'         && showBrowse)
             || (src === 'crawler'        && showCrawler)
             || (src === 'agent'          && showAgent)
             || (src === 'scan'           && showScan)
             || (src === 'imported'       && showProxy)
             || (src === 'out-of-scope'   && showOos);
  const show = srcOk
             && (!q || e.path.toLowerCase().includes(q) || (e.body_preview || '').toLowerCase().includes(q) || (e.probe_payload || '').toLowerCase().includes(q))
             && (selHost === null || e.host === selHost)
             && !(hConn && e.method === 'CONNECT')
             && !(hVuln && e.scan_result !== 'vulnerable');
  tr.style.display = show ? '' : 'none';
}

// ── proxy row selection ────────────────────────────────────────────────
function selectRow(id) {
  if (selId) document.getElementById('row-' + selId)?.classList.remove('on');
  selId = id;
  document.getElementById('row-' + id)?.classList.add('on');
  document.getElementById('empty-msg')?.remove();
  refreshDetail(id);
}

async function refreshDetail(id) {
  const r = await fetch('/api/entry/' + id);
  detail = await r.json();
  _paneViewMode.req  = 'raw';
  _paneViewMode.resp = 'raw';
  _paneViewMode.gql  = false;
  renderDetail();
}

function setDTab(t) {
  dtab = t;
  document.querySelectorAll('#dtabs .dtab').forEach(d => d.classList.remove('on'));
  document.getElementById('dt-' + t).classList.add('on');
  renderDetail();
}

function renderDetail() {
  if (!detail) return;
  document.getElementById('dbody').innerHTML =
    dtab === 'rr' ? buildRRHtml(detail) : buildFindingsHtml(detail);
  // Update passive bar visibility
  const passiveFindings = (detail.findings || []).filter(f =>
    f.validated_by === 'passive' || f.validated_by === 'passive+ai'
  );
  const bar = document.getElementById('passive-bar');
  const barTxt = document.getElementById('passive-bar-txt');
  if (bar) {
    if (passiveFindings.length > 0 && dtab !== 'findings') {
      const names = passiveFindings.slice(0, 2).map(f => f.title || f.attack_type).join(', ');
      const extra = passiveFindings.length > 2 ? ` +${passiveFindings.length - 2} more` : '';
      barTxt.textContent = `passive: ${names}${extra}`;
      bar.style.display = 'flex';
    } else {
      bar.style.display = 'none';
    }
  }
}

// ── target site map ────────────────────────────────────────────────────
function renderSmHostList() {
  const list = document.getElementById('sm-hosts-list');
  const showOos = document.getElementById('sm-chk-oos')?.checked ?? false;
  list.innerHTML = '';
  for (const host of Object.keys(hosts).sort()) {
    const h = hosts[host];
    // Filter OOS-only hosts unless checkbox is on
    const visibleIds = h.ids.filter(id => {
      const e = entries[id];
      if (!e) return false;
      return e.source !== 'out-of-scope' || showOos;
    });
    if (!visibleIds.length) continue;
    const el = document.createElement('div');
    el.className = 'host-item' + (selSmHost === host ? ' on' : '');
    el.id = 'smh-' + CSS.escape(host);
    el.onclick = () => selectSmHost(host);
    const crawlerCnt = visibleIds.filter(id => entries[id]?.source === 'crawler').length;
    el.innerHTML = `<div class="host-name" title="${esc(host)}">${esc(host)}</div>
      <div class="host-meta">
        <span class="host-cnt">${visibleIds.length} req</span>
        ${crawlerCnt ? `<span class="host-cnt" style="color:var(--blue)" title="Crawler">C:${crawlerCnt}</span>` : ''}
      </div>
      <div class="host-actions" style="display:none;gap:4px;margin-top:3px">
        <button class="tbtn" style="font-size:10px;padding:1px 6px"
          onclick="event.stopPropagation();crawlHost('${esc(host)}')">Crawl</button>
        <button class="tbtn" style="font-size:10px;padding:1px 6px"
          onclick="event.stopPropagation();scanHost('${esc(host)}')">Scan all</button>
      </div>`;
    el.onmouseenter = () => el.querySelector('.host-actions').style.display = 'flex';
    el.onmouseleave = () => el.querySelector('.host-actions').style.display = 'none';
    list.appendChild(el);
  }
}

function selectSmHost(host) {
  selSmHost = host;
  document.querySelectorAll('[id^="smh-"]').forEach(el => {
    el.className = 'host-item' + (el.id === 'smh-' + CSS.escape(host) ? ' on' : '');
  });
  renderSmContents(host);
}

function renderSmContents(host) {
  const tbody = document.getElementById('sm-tbody');
  const h = hosts[host];
  if (!h) return;
  const showOos = document.getElementById('sm-chk-oos')?.checked ?? false;
  // Remove rows that don't belong to this host, then rebuild
  const existing = new Set([...tbody.querySelectorAll('tr')].map(r => r.id.replace('smrow-', '')));
  const current  = new Set(h.ids);
  for (const id of existing) {
    if (!current.has(id)) {
      document.getElementById('smrow-' + id)?.remove();
    }
  }
  // add new rows
  for (const id of h.ids) {
    const e = entries[id];
    if (!e) continue;
    if (!showOos && e.source === 'out-of-scope') continue;
    const sc = e.status ? 's' + String(e.status)[0] : '';
    let tr = document.getElementById('smrow-' + id);
    if (!tr) {
      tr = document.createElement('tr');
      tr.id = 'smrow-' + id;
      tr.onclick = () => selectSmRow(id);
      tbody.appendChild(tr);
    }
    tr.className = selSmId === id ? 'on' : '';
    tr.innerHTML = `
      <td class="cm ${esc(e.method)}">${esc(e.method)}</td>
      <td title="${esc(e.path)}">${esc(e.path)}</td>
      <td class="cs ${sc}">${e.status || ''}</td>
      <td class="cz">${e.duration_ms != null ? e.duration_ms.toFixed(0) : ''}</td>`;
  }
}

function selectSmRow(id) {
  if (selSmId) document.getElementById('smrow-' + selSmId)?.classList.remove('on');
  selSmId = id;
  document.getElementById('smrow-' + id)?.classList.add('on');
  refreshSmDetail(id);
}

async function refreshSmDetail(id) {
  const r = await fetch('/api/entry/' + id);
  smDetail = await r.json();
  renderSmDetail();
}

function setSmDTab(t) {
  smDtab = t;
  document.querySelectorAll('#sm-detail-body').forEach(() => {});
  document.getElementById('sdt-rr').classList.toggle('on', t === 'rr');
  document.getElementById('sdt-findings').classList.toggle('on', t === 'findings');
  renderSmDetail();
}

function renderSmDetail() {
  if (!smDetail) return;
  document.getElementById('sm-detail-body').innerHTML =
    smDtab === 'rr' ? buildRRHtml(smDetail) : buildFindingsHtml(smDetail);
}

