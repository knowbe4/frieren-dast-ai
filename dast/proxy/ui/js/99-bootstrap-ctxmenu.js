// ── Context menu ────────────────────────────────────────────────────────────

(function() {
  let _ctxId = null;

  function getMenu() { return document.getElementById('ctx-menu'); }

  function hideMenu() {
    const m = getMenu();
    if (m) m.classList.remove('visible');
    _ctxId = null;
  }

  function showMenu(x, y, entryId) {
    _ctxId = entryId;
    const m = getMenu();
    if (!m) return;
    m.classList.add('visible');
    // Keep inside viewport
    const vw = window.innerWidth, vh = window.innerHeight;
    const mw = m.offsetWidth || 190, mh = m.offsetHeight || 160;
    m.style.left = (x + mw > vw ? vw - mw - 8 : x) + 'px';
    m.style.top  = (y + mh > vh ? vh - mh - 8 : y) + 'px';
  }

  document.addEventListener('DOMContentLoaded', () => {
    // Attach right-click to the HTTP history tbody via delegation
    const tbody = document.getElementById('tbody');
    if (tbody) {
      tbody.addEventListener('contextmenu', e => {
        const tr = e.target.closest('tr[id^="row-"]');
        if (!tr) return;
        e.preventDefault();
        const id = tr.id.replace('row-', '');
        selectRow(id);
        showMenu(e.clientX, e.clientY, id);
      });
    }

    // Attach right-click to the request/response detail panel
    const detailCol = document.getElementById('proxy-detail-col');
    if (detailCol) {
      detailCol.addEventListener('contextmenu', e => {
        // Don't hijack right-click inside the findings cards (handled below)
        if (e.target.closest('.iissue[id^="iissue-"]')) return;
        if (!selId) return;
        e.preventDefault();
        showMenu(e.clientX, e.clientY, selId);
      });
    }

    // Attach right-click to the issues/findings panel via delegation
    document.addEventListener('contextmenu', e => {
      const card = e.target.closest('.iissue[id^="iissue-"]');
      if (!card) return;
      const entryId = card.dataset.entryId;
      if (!entryId) return;
      e.preventDefault();
      showMenu(e.clientX, e.clientY, entryId);
    });

    // Close on any click outside
    document.addEventListener('click', e => {
      const m = getMenu();
      if (m && !m.contains(e.target)) hideMenu();
    });
    document.addEventListener('keydown', e => { if (e.key === 'Escape') hideMenu(); });
  });

  window._ctxSendRepeater = function() {
    if (_ctxId) { repLoadEntry(_ctxId); hideMenu(); switchMain('repeater'); }
  };
  window._ctxSendIntruder = function() {
    if (_ctxId) { itrLoadEntry(_ctxId); hideMenu(); switchMain('intruder'); }
  };
  window._ctxSendAI = function() {
    if (_ctxId) {
      const entry = entries[_ctxId];
      if (entry) { selId = _ctxId; detail = entry; }
      hideMenu();
      openSendToAI();
    }
  };
  window._ctxCopyUrl = function() {
    if (_ctxId) {
      const entry = entries[_ctxId];
      if (entry) navigator.clipboard.writeText(entry.url).catch(() => {});
      hideMenu();
    }
  };
  // Single-quote a shell argument, escaping embedded single quotes the
  // POSIX way: close the quote, emit an escaped quote, reopen the quote.
  function _shQuote(s) {
    return `'${String(s ?? '').replace(/'/g, `'\\''`)}'`;
  }

  function _buildCurlCommand(d) {
    const parts = ['curl', '-i', '-s', '-k'];
    const method = (d.method || 'GET').toUpperCase();
    if (method !== 'GET') parts.push('-X', _shQuote(method));
    for (const [k, v] of Object.entries(d.request_headers || {})) {
      if (['content-length', 'transfer-encoding', 'connection'].includes(k.toLowerCase())) continue;
      parts.push('-H', _shQuote(`${k}: ${v}`));
    }
    if (d.request_body) parts.push('--data-raw', _shQuote(d.request_body));
    parts.push(_shQuote(d.url || ''));
    return parts.join(' ');
  }

  window._ctxCopyCurl = async function() {
    const id = _ctxId;
    if (!id) return;
    hideMenu();
    try {
      const r = await fetch('/api/entry/' + id);
      const d = await r.json();
      await navigator.clipboard.writeText(_buildCurlCommand(d));
      showToast('cURL command copied');
    } catch(_) {
      showToast('Failed to copy cURL command', true);
    }
  };

  window._ctxReproduceBrowser = async function() {
    const id = _ctxId;
    if (!id) return;
    hideMenu();
    const link = `${location.origin}/api/reproduce/${id}`;
    try {
      await navigator.clipboard.writeText(link);
      showToast('Reproduce link copied');
    } catch(_) {
      showToast('Failed to copy reproduce link', true);
    }
  };
})();

