pub const PEER_PAGE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MESHLINK // PEER</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#000;color:#00ff41;font-family:'Courier New',Courier,monospace;font-size:14px;padding:16px}
h1{font-size:18px;letter-spacing:4px;border-bottom:1px solid #00ff41;padding-bottom:6px;margin-bottom:16px}
h2{font-size:13px;letter-spacing:2px;color:#00cc33;margin:20px 0 8px}
#auth{display:flex;gap:8px;margin-bottom:20px}
#auth input{background:#000;border:1px solid #00ff41;color:#00ff41;font-family:inherit;font-size:13px;padding:6px 10px;width:340px;outline:none}
#auth input:focus{border-color:#fff}
button{background:#000;border:1px solid #00ff41;color:#00ff41;cursor:pointer;font-family:inherit;font-size:12px;letter-spacing:1px;padding:6px 14px}
button:hover{background:#00ff41;color:#000}
button.danger{border-color:#ff4141;color:#ff4141}
button.danger:hover{background:#ff4141;color:#000}
#status-bar{display:flex;gap:24px;padding:8px 12px;border:1px solid #003300;background:#001100;margin-bottom:20px;flex-wrap:wrap}
.stat{display:flex;flex-direction:column}
.stat-label{font-size:10px;color:#006600;letter-spacing:1px}
.stat-value{font-size:16px;font-weight:bold}
table{width:100%;border-collapse:collapse;margin-bottom:20px}
th{text-align:left;padding:4px 8px;font-size:11px;letter-spacing:1px;color:#006600;border-bottom:1px solid #003300}
td{padding:5px 8px;border-bottom:1px solid #001100;font-size:12px}
tr:hover td{background:#001100}
.badge{display:inline-block;padding:1px 6px;font-size:10px;letter-spacing:1px}
.badge-active{color:#00ff41;border:1px solid #00ff41}
.badge-stale{color:#ffaa00;border:1px solid #ffaa00}
.badge-registered{color:#00aaff;border:1px solid #00aaff}
.badge-deregistered{color:#555;border:1px solid #555}
#error{color:#ff4141;margin-bottom:10px;min-height:18px;font-size:12px}
#rotate-section{border:1px solid #003300;padding:12px;margin-top:10px}
#rotate-result{margin-top:8px;font-size:12px;color:#00aaff;word-break:break-all}
#auth-wall{margin-top:60px;text-align:center}
#auth-wall h2{font-size:20px;letter-spacing:6px;color:#00ff41;margin-bottom:20px}
#auth-wall input{width:400px;padding:10px;margin-right:8px}
#main{display:none}
pre{background:#001100;border:1px solid #003300;padding:10px;font-size:11px;overflow-x:auto}
</style>
</head>
<body>
<h1>// MESHLINK PEER INTERFACE</h1>

<div id="auth-wall">
  <h2>AUTHENTICATE</h2>
  <div>
    <input type="password" id="wall-token" placeholder="enter token" autocomplete="off">
    <button onclick="login()">CONNECT</button>
  </div>
  <div id="auth-error" style="color:#ff4141;margin-top:10px;min-height:18px"></div>
</div>

<div id="main">
  <div id="error"></div>

  <div id="status-bar">
    <div class="stat"><span class="stat-label">NODE ID</span><span class="stat-value" id="s-nodeid">—</span></div>
    <div class="stat"><span class="stat-label">VIRTUAL IP</span><span class="stat-value" id="s-vip">—</span></div>
    <div class="stat"><span class="stat-label">UPTIME</span><span class="stat-value" id="s-uptime">—</span></div>
    <div class="stat"><span class="stat-label">PEERS</span><span class="stat-value" id="s-peers">—</span></div>
    <div class="stat"><span class="stat-label">COORD</span><span class="stat-value" id="s-coord">—</span></div>
  </div>

  <h2>PEERS</h2>
  <table>
    <thead><tr><th>VIRTUAL IP</th><th>STATUS</th><th>ENDPOINT</th><th>TX BYTES</th><th>RX BYTES</th></tr></thead>
    <tbody id="peer-table"></tbody>
  </table>

  <h2>CONFIG</h2>
  <pre id="config-display">loading…</pre>

  <h2>TOKEN MANAGEMENT</h2>
  <div id="rotate-section">
    <p style="font-size:12px;color:#006600;margin-bottom:10px">
      Rotating generates a new auth token, saves it locally, and notifies the coord server.
      The old token is immediately invalid. Requires write token.
    </p>
    <button class="danger" onclick="rotateToken()">ROTATE TOKEN</button>
    <div id="rotate-result"></div>
  </div>
</div>

<script>
const TOKEN_KEY = 'meshlink_peer_token';
let token = '';

function showError(msg) {
  document.getElementById('error').textContent = msg ? '! ' + msg : '';
}

function badge(status) {
  return '<span class="badge badge-' + status + '">' + status.toUpperCase() + '</span>';
}

function fmtBytes(n) {
  if (n === undefined || n === null) return '—';
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1048576).toFixed(1) + ' MB';
}

async function api(path, method, body) {
  const opts = {
    method: method || 'GET',
    headers: {'Authorization': 'Bearer ' + token}
  };
  if (body) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const r = await fetch(path, opts);
  if (r.status === 401 || r.status === 403) {
    localStorage.removeItem(TOKEN_KEY);
    location.reload();
  }
  return r;
}

async function loadStatus() {
  try {
    const r = await api('/api/status');
    if (!r.ok) { showError('status fetch failed'); return; }
    const d = await r.json();
    document.getElementById('s-nodeid').textContent = (d.node_id || '').substring(0, 12) + '…';
    document.getElementById('s-vip').textContent = d.virtual_ip || '—';
    document.getElementById('s-uptime').textContent = fmtUptime(d.uptime_secs);
    document.getElementById('s-peers').textContent = d.peer_count ?? '—';
    document.getElementById('s-coord').textContent = d.coord_server || '—';
  } catch(e) { showError('status: ' + e.message); }
}

function fmtUptime(s) {
  if (!s && s !== 0) return '—';
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  return [h,m,sec].map(v => String(v).padStart(2,'0')).join(':');
}

async function loadPeers() {
  try {
    const r = await api('/api/peers');
    if (!r.ok) return;
    const peers = await r.json();
    const tbody = document.getElementById('peer-table');
    tbody.innerHTML = '';
    if (!peers || !peers.length) {
      tbody.innerHTML = '<tr><td colspan="5" style="color:#555">no peers</td></tr>';
      return;
    }
    peers.forEach(p => {
      const tr = document.createElement('tr');
      tr.innerHTML =
        '<td>' + (p.virtual_ip || '—') + '</td>' +
        '<td>' + badge(p.status || 'unknown') + '</td>' +
        '<td>' + (p.endpoint || '—') + '</td>' +
        '<td>' + fmtBytes(p.tx_bytes) + '</td>' +
        '<td>' + fmtBytes(p.rx_bytes) + '</td>';
      tbody.appendChild(tr);
    });
  } catch(e) { /* non-fatal */ }
}

async function loadConfig() {
  try {
    const r = await api('/api/config');
    if (!r.ok) return;
    const d = await r.json();
    document.getElementById('config-display').textContent = JSON.stringify(d, null, 2);
  } catch(e) { /* non-fatal */ }
}

async function rotateToken() {
  const el = document.getElementById('rotate-result');
  el.textContent = 'rotating…';
  try {
    const r = await api('/api/token/rotate', 'POST');
    if (!r.ok) {
      const err = await r.json().catch(() => ({error: 'unknown'}));
      el.style.color = '#ff4141';
      el.textContent = 'failed: ' + (err.error || r.status);
      return;
    }
    const d = await r.json();
    localStorage.setItem(TOKEN_KEY, d.new_token);
    token = d.new_token;
    el.style.color = '#00ff41';
    el.textContent = 'new token: ' + d.new_token + '\n(saved to localStorage — update config files manually)';
  } catch(e) {
    el.style.color = '#ff4141';
    el.textContent = 'error: ' + e.message;
  }
}

async function verifyToken(tok) {
  const r = await fetch('/api/status', {
    headers: {'Authorization': 'Bearer ' + tok}
  });
  return r.status !== 401 && r.status !== 403;
}

async function login() {
  const tok = document.getElementById('wall-token').value.trim();
  if (!tok) return;
  const ok = await verifyToken(tok);
  if (!ok) {
    document.getElementById('auth-error').textContent = 'invalid token';
    return;
  }
  localStorage.setItem(TOKEN_KEY, tok);
  token = tok;
  document.getElementById('auth-wall').style.display = 'none';
  document.getElementById('main').style.display = 'block';
  refresh();
}

function refresh() {
  loadStatus();
  loadPeers();
  loadConfig();
}

(async () => {
  const stored = localStorage.getItem(TOKEN_KEY);
  if (stored) {
    const ok = await verifyToken(stored);
    if (ok) {
      token = stored;
      document.getElementById('auth-wall').style.display = 'none';
      document.getElementById('main').style.display = 'block';
      refresh();
      setInterval(refresh, 15000);
      return;
    }
    localStorage.removeItem(TOKEN_KEY);
  }
})();
</script>
</body>
</html>"#;
