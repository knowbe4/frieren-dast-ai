// ── First-run onboarding ─────────────────────────────────────────────────────
// New users landed on an empty dashboard with no idea that Frieren is a proxy
// they must route their browser through, nor what manual/AI mode means. This
// shows a short welcome the first time (remembered in localStorage) and can be
// reopened anytime from the "?" button in the top bar. Self-contained: it builds
// its own overlay and handles Escape, so it needs no markup in index.html.

(function () {
  'use strict';

  const SEEN_KEY = 'dast-onboarded';

  function proxyPort() {
    // The real port is rendered into the setup tab; fall back to the default.
    const el = document.getElementById('setup-proxy-port');
    const val = el && el.textContent && el.textContent.trim();
    return val || '8080';
  }

  function openProxySetup() {
    dismiss();
    if (typeof switchMain === 'function') switchMain('proxy');
    if (typeof switchProxySub === 'function') switchProxySub('psettings');
  }

  let _overlay = null;
  function dismiss() {
    try { localStorage.setItem(SEEN_KEY, '1'); } catch (_) {}
    if (_overlay) { document.removeEventListener('keydown', onKey, true); _overlay.remove(); _overlay = null; }
  }
  function onKey(e) { if (e.key === 'Escape') { e.preventDefault(); dismiss(); } }

  function showOnboarding() {
    if (_overlay) return;
    const port = proxyPort();
    _overlay = document.createElement('div');
    _overlay.className = 'modal-overlay';
    _overlay.setAttribute('role', 'dialog');
    _overlay.setAttribute('aria-modal', 'true');
    _overlay.setAttribute('aria-label', 'Getting started');
    _overlay.innerHTML = `
      <div class="modal" style="width:560px;max-width:94vw">
        <div class="modal-hdr">
          <span style="flex:1">Welcome to Frieren DAST-AI</span>
          <button class="tbtn" id="_ob_close" aria-label="Close">✕</button>
        </div>
        <div class="modal-body" style="font-size:12px;line-height:1.7;color:var(--txt)">
          <p style="margin-bottom:14px;color:var(--txt2)">
            Frieren is a proxy-driven scanner: it sits between your browser and the
            target, then hunts for real, exploitable vulnerabilities in what you browse.
            Three steps to start:
          </p>
          <ol style="margin:0 0 16px 18px;padding:0;display:flex;flex-direction:column;gap:10px">
            <li><strong>Point your browser at the proxy</strong> —
              <code style="color:var(--orange)">127.0.0.1:${port}</code>.</li>
            <li><strong>Install the CA certificate</strong> once, so intercepted HTTPS is trusted.
              Both live under <strong>Proxy &rarr; Settings</strong>.</li>
            <li><strong>Browse the target.</strong> Requests stream into
              <strong>Proxy &rarr; HTTP history</strong>; confirmed findings land in
              <strong>Proxy &rarr; Issues</strong>.</li>
          </ol>
          <div class="card" style="padding:10px 12px;margin-bottom:14px">
            <div style="display:flex;gap:8px;align-items:baseline">
              <span class="mode-pill on" style="pointer-events:none">manual</span>
              <span style="color:var(--txt2)">scan only what you pick.</span>
            </div>
            <div style="display:flex;gap:8px;align-items:baseline;margin-top:6px">
              <span class="mode-pill on" style="pointer-events:none">ai</span>
              <span style="color:var(--txt2)">auto-scan every in-scope request as it arrives.</span>
            </div>
          </div>
          <p style="color:var(--txt3);font-size:11px;margin-bottom:16px">
            Tabs are grouped: <strong>Triage</strong>, <strong>Capture</strong>,
            <strong>Analyze</strong>, <strong>Tools</strong>. Reopen this guide anytime
            from the <strong>?</strong> in the top bar.
          </p>
          <div style="display:flex;gap:8px;justify-content:flex-end">
            <button class="tbtn" id="_ob_setup">Open proxy setup</button>
            <button class="tbtn pri" id="_ob_done">Get started</button>
          </div>
        </div>
      </div>`;
    document.body.appendChild(_overlay);
    _overlay.addEventListener('click', function (e) { if (e.target === _overlay) dismiss(); });
    _overlay.querySelector('#_ob_close').onclick = dismiss;
    _overlay.querySelector('#_ob_done').onclick = dismiss;
    _overlay.querySelector('#_ob_setup').onclick = openProxySetup;
    document.addEventListener('keydown', onKey, true);
    _overlay.querySelector('#_ob_done').focus();
  }

  // Public entry points.
  window.showOnboarding = showOnboarding;

  document.addEventListener('DOMContentLoaded', function () {
    const helpBtn = document.getElementById('help-btn');
    if (helpBtn) helpBtn.addEventListener('click', showOnboarding);
    let seen = false;
    try { seen = !!localStorage.getItem(SEEN_KEY); } catch (_) {}
    if (!seen) setTimeout(showOnboarding, 400);
  });
})();
