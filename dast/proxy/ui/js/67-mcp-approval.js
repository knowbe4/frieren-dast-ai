// MCP request approval (Burp-style). When the MCP server tries to send to an
// out-of-scope target, the dashboard raises a modal so a human can Allow Once /
// Always Allow Host / Deny. Mirrors the login needs-human human-in-loop pattern.

function _mcpApprovalEsc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
    ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
}

function _mcpApprovalEnsureModal() {
  let overlay = document.getElementById('mcp-approval-overlay');
  if (overlay) return overlay;
  overlay = document.createElement('div');
  overlay.id = 'mcp-approval-overlay';
  overlay.style.cssText =
    'display:none;position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,0.55);' +
    'align-items:center;justify-content:center;';
  overlay.innerHTML =
    '<div style="background:var(--bg1,#1b1b1b);border:1px solid var(--bd,#333);border-radius:8px;' +
    'padding:20px 22px;max-width:520px;width:90%;box-shadow:0 8px 30px rgba(0,0,0,0.5);">' +
    '<div style="font-weight:600;font-size:15px;margin-bottom:8px;">MCP request approval</div>' +
    '<div style="color:var(--txt2,#aaa);font-size:13px;margin-bottom:6px;">' +
    'An MCP client wants to send a request to a target that is <b>out of scope</b>:</div>' +
    '<div id="mcp-approval-target" style="font-family:monospace;font-size:13px;background:var(--bg2,#111);' +
    'padding:8px 10px;border-radius:5px;margin-bottom:14px;word-break:break-all;"></div>' +
    '<div style="display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap;">' +
    '<button id="mcp-approval-deny" style="padding:7px 12px;">Deny</button>' +
    '<button id="mcp-approval-once" style="padding:7px 12px;">Allow Once</button>' +
    '<button id="mcp-approval-host" style="padding:7px 12px;font-weight:600;">Always Allow Host</button>' +
    '</div></div>';
  document.body.appendChild(overlay);

  const send = (decision) => {
    fetch('/api/mcp/approval-resume', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({decision}),
    }).catch(() => {}).finally(() => { overlay.style.display = 'none'; });
  };
  overlay.querySelector('#mcp-approval-deny').onclick = () => send('deny');
  overlay.querySelector('#mcp-approval-once').onclick = () => send('allow_once');
  overlay.querySelector('#mcp-approval-host').onclick = () => send('always_host');
  return overlay;
}

function _mcpApprovalShow(msg) {
  const overlay = _mcpApprovalEnsureModal();
  const target = overlay.querySelector('#mcp-approval-target');
  const hostPort = msg.host + (msg.port ? ':' + msg.port : '');
  target.innerHTML = '<b>' + _mcpApprovalEsc(msg.method || 'GET') + '</b> ' +
    _mcpApprovalEsc(hostPort) + '<br><span style="color:var(--txt2,#888);">' +
    _mcpApprovalEsc(msg.url || '') + '</span>';
  overlay.style.display = 'flex';
}

function _mcpApprovalConnectWs() {
  try {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(`${proto}://${location.host}/ws/mcp-approval`);
    ws.onmessage = (ev) => {
      let msg; try { msg = JSON.parse(ev.data); } catch (e) { return; }
      if (msg.type === 'approval_needed') {
        _mcpApprovalShow(msg);
      } else if (msg.type === 'approval_resolved') {
        const overlay = document.getElementById('mcp-approval-overlay');
        if (overlay) overlay.style.display = 'none';
      }
    };
    ws.onclose = () => setTimeout(_mcpApprovalConnectWs, 3000);
  } catch (e) { /* best-effort */ }
}
_mcpApprovalConnectWs();
