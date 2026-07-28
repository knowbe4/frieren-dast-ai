// ── Decoder / Encoder — client-side transform toolbelt ──────────────────
// All transforms run in the browser; no request ever leaves the page.

const _DECODER_OPS = [
  { id: 'b64-enc',   label: 'Base64 encode',  fn: s => _b64encode(s) },
  { id: 'b64-dec',   label: 'Base64 decode',  fn: s => _b64decode(s) },
  { id: 'b64url-enc',label: 'Base64URL encode',fn: s => _b64encode(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'') },
  { id: 'b64url-dec',label: 'Base64URL decode',fn: s => _b64decode(_b64urlPad(s.replace(/-/g,'+').replace(/_/g,'/'))) },
  { id: 'url-enc',   label: 'URL encode',     fn: s => encodeURIComponent(s) },
  { id: 'url-dec',   label: 'URL decode',     fn: s => decodeURIComponent(s.replace(/\+/g,' ')) },
  { id: 'url-enc-all',label:'URL encode (all)',fn: s => Array.from(s).map(c => '%' + c.charCodeAt(0).toString(16).padStart(2,'0').toUpperCase()).join('') },
  { id: 'html-enc',  label: 'HTML encode',    fn: s => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;') },
  { id: 'html-dec',  label: 'HTML decode',    fn: s => _htmlDecode(s) },
  { id: 'hex-enc',   label: 'Hex encode',     fn: s => Array.from(new TextEncoder().encode(s)).map(b => b.toString(16).padStart(2,'0')).join('') },
  { id: 'hex-dec',   label: 'Hex decode',     fn: s => _hexDecode(s) },
  { id: 'jwt-dec',   label: 'JWT decode',     fn: s => _jwtDecodeText(s) },
];

let _decoderOp = 'b64-dec';

function _b64encode(s) {
  return btoa(unescape(encodeURIComponent(s)));
}
function _b64decode(s) {
  return decodeURIComponent(escape(atob(s.trim())));
}
function _b64urlPad(s) {
  const pad = s.length % 4;
  return pad ? s + '='.repeat(4 - pad) : s;
}
function _htmlDecode(s) {
  const el = document.createElement('textarea');
  el.innerHTML = s;
  return el.value;
}
function _hexDecode(s) {
  const clean = s.replace(/[^0-9a-fA-F]/g, '');
  const bytes = [];
  for (let i = 0; i + 1 < clean.length; i += 2) bytes.push(parseInt(clean.slice(i, i + 2), 16));
  return new TextDecoder().decode(new Uint8Array(bytes));
}
function _jwtDecodeText(s) {
  const parts = s.trim().split('.');
  if (parts.length < 2) throw new Error('not a JWT (need header.payload)');
  const hdr = JSON.parse(_b64decode(_b64urlPad(parts[0].replace(/-/g,'+').replace(/_/g,'/'))));
  const pl  = JSON.parse(_b64decode(_b64urlPad(parts[1].replace(/-/g,'+').replace(/_/g,'/'))));
  return 'HEADER:\n' + JSON.stringify(hdr, null, 2) + '\n\nPAYLOAD:\n' + JSON.stringify(pl, null, 2);
}

function decoderInit() {
  const ops = document.getElementById('dec-ops');
  if (ops && !ops.dataset.built) {
    ops.innerHTML = _DECODER_OPS.map(op =>
      `<div class="dec-op" id="dec-op-${op.id}" onclick="decoderPick('${op.id}')"
            style="padding:5px 14px;font-size:11px;cursor:pointer;color:var(--txt)">${op.label}</div>`
    ).join('');
    ops.dataset.built = '1';
  }
  decoderPick(_decoderOp);
}

function decoderPick(id) {
  _decoderOp = id;
  _DECODER_OPS.forEach(op => {
    const el = document.getElementById('dec-op-' + op.id);
    if (el) el.style.background = op.id === id ? 'var(--bg3)' : 'transparent';
  });
  decoderRun();
}

// Map raw JS exceptions to short, human-readable reasons per transform kind.
function _decoderFriendlyError(op) {
  if (op.id.startsWith('b64')) return 'Not valid Base64 — check for stray characters or padding.';
  if (op.id.startsWith('url')) return 'Not valid URL-encoded text — check for a lone % or bad %XX sequence.';
  if (op.id.startsWith('hex')) return 'Not valid hex — expected pairs of 0-9 / a-f.';
  if (op.id === 'jwt-dec')     return 'Not a valid JWT — expected header.payload with Base64URL JSON.';
  return 'Input could not be transformed.';
}

function decoderRun() {
  const input  = document.getElementById('dec-input').value;
  const out     = document.getElementById('dec-output');
  const op      = _DECODER_OPS.find(o => o.id === _decoderOp);
  if (!op) return;
  if (!input) { out.textContent = ''; out.style.color = 'var(--txt2)'; return; }
  try {
    out.textContent = op.fn(input);
    out.style.color = 'var(--orange)';
  } catch (e) {
    out.textContent = _decoderFriendlyError(op);
    out.style.color = 'var(--txt2)';
  }
}

function decoderCopy() {
  const out = document.getElementById('dec-output').textContent;
  if (out) navigator.clipboard.writeText(out).then(() => showToast('Copied output'));
}

// ── JWT editor — decode, edit, re-sign, send to Repeater ─────────────────
let _jwtLastToken = '';

function jwtToggleSecret() {
  const mode = document.getElementById('jwt-mode').value;
  const row  = document.getElementById('jwt-secret-row');
  if (row) row.style.display = mode === 'none' ? 'none' : 'block';
}

function jwtDecode() {
  const raw = document.getElementById('jwt-input').value.trim();
  const msg = document.getElementById('jwt-decode-msg');
  if (!raw) { msg.textContent = ''; return; }
  try {
    const parts = raw.split('.');
    if (parts.length < 2) throw new Error('need at least header.payload');
    const hdr = JSON.parse(_b64decode(_b64urlPad(parts[0].replace(/-/g,'+').replace(/_/g,'/'))));
    const pl  = JSON.parse(_b64decode(_b64urlPad(parts[1].replace(/-/g,'+').replace(/_/g,'/'))));
    document.getElementById('jwt-header').value  = JSON.stringify(hdr, null, 2);
    document.getElementById('jwt-payload').value = JSON.stringify(pl, null, 2);
    const alg = (hdr.alg || '').toLowerCase();
    const sel = document.getElementById('jwt-mode');
    if (['hs256','hs384','hs512','none'].includes(alg)) { sel.value = alg; jwtToggleSecret(); }
    msg.style.color = 'var(--green)';
    msg.textContent = 'Decoded (alg=' + (hdr.alg || '?') + '). Edit header/payload below, then Build token.';
  } catch (e) {
    msg.style.color = 'var(--txt2)';
    msg.textContent = 'Not a valid JWT — expected header.payload with Base64URL-encoded JSON.';
  }
}

async function jwtBuild() {
  const msg = document.getElementById('jwt-build-msg');
  const out = document.getElementById('jwt-output');
  let header, payload;
  try {
    header  = JSON.parse(document.getElementById('jwt-header').value || '{}');
    payload = JSON.parse(document.getElementById('jwt-payload').value || '{}');
  } catch (e) {
    msg.style.color = 'var(--txt2)';
    msg.textContent = 'Header or payload is not valid JSON — fix the highlighted text and try again.';
    return;
  }
  const mode   = document.getElementById('jwt-mode').value;
  const secret = mode === 'none' ? null : document.getElementById('jwt-secret').value;
  msg.style.color = 'var(--txt2)';
  msg.textContent = 'Building...';
  try {
    const r = await fetch('/api/jwt/build', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ header, payload, mode, secret }),
    });
    const d = await r.json();
    if (!r.ok || d.error) throw new Error(d.error || ('HTTP ' + r.status));
    _jwtLastToken = d.token;
    out.textContent = d.token;
    msg.style.color = 'var(--green)';
    msg.textContent = 'Signed with ' + mode + '.';
  } catch (e) {
    out.textContent = '';
    msg.style.color = 'var(--txt2)';
    msg.textContent = 'Could not build the token — check the header, payload, and signing mode.';
  }
}

function jwtCopy() {
  if (_jwtLastToken) navigator.clipboard.writeText(_jwtLastToken).then(() => showToast('Copied token'));
}

function jwtToRepeater() {
  if (!_jwtLastToken) { showToast('Build a token first'); return; }
  repNewTab({
    method: 'GET',
    url: '',
    headers: 'Authorization: Bearer ' + _jwtLastToken,
    body: '',
    label: 'JWT probe',
  });
  switchMain('repeater');
}
