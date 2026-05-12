pub const ADMIN_PAGE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MESHLINK // ADMIN</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --g:#00ff41;--g2:#00aa2a;--g3:#003b0f;
  --r:#ff2222;--y:#ffaa00;--b:#0088ff;
  --bg:#000;--bg2:#050505;--border:#00ff41
}
body{background:var(--bg);color:var(--g);font-family:"Courier New",Courier,monospace;font-size:13px;line-height:1.4;overflow-x:hidden}

/* ── AUTH SCREEN ─────────────────────────────────────── */
#auth{position:fixed;inset:0;background:#000;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:20px;z-index:999}
#auth.hidden{display:none}
#auth pre{color:var(--g2);font-size:11px;text-align:center;line-height:1.2}
#auth h1{font-size:22px;letter-spacing:10px;border-bottom:2px solid var(--g);padding-bottom:8px}
#auth label{font-size:11px;letter-spacing:3px;color:var(--g2)}
#auth input{
  width:380px;background:#000;color:var(--g);
  border:2px solid var(--g);padding:10px 14px;
  font-family:inherit;font-size:14px;outline:none
}
#auth input:focus{border-color:#fff;color:#fff}
#auth button{
  width:380px;background:var(--g);color:#000;
  border:none;padding:10px;font-family:inherit;
  font-size:14px;font-weight:bold;letter-spacing:4px;cursor:pointer
}
#auth button:hover{background:#fff}
#auth-err{color:var(--r);font-size:12px;letter-spacing:2px;min-height:16px}

/* ── MAIN ────────────────────────────────────────────── */
#main{display:none;min-height:100vh;flex-direction:column}
#main.visible{display:flex}

header{
  border-bottom:2px solid var(--g);padding:10px 16px;
  display:flex;justify-content:space-between;align-items:center;
  background:var(--bg2);position:sticky;top:0;z-index:10
}
header h1{font-size:15px;letter-spacing:6px}
#hdr-right{display:flex;align-items:center;gap:16px;font-size:11px}
#conn-dot{
  display:inline-block;width:10px;height:10px;
  background:var(--r);margin-right:6px
}
#conn-dot.on{background:var(--g);animation:blink 2s step-end infinite}
@keyframes blink{50%{opacity:0}}
#logout-btn{
  background:none;color:var(--r);border:1px solid var(--r);
  padding:3px 10px;font-family:inherit;font-size:11px;cursor:pointer;letter-spacing:2px
}
#logout-btn:hover{background:var(--r);color:#000}

/* ── STATS BAR ───────────────────────────────────────── */
#stats{
  display:flex;gap:0;border-bottom:1px solid var(--g3);
  background:var(--bg2)
}
.stat{
  flex:1;padding:10px 16px;border-right:1px solid var(--g3);
  font-size:11px;letter-spacing:1px
}
.stat:last-child{border-right:none}
.stat-val{font-size:22px;font-weight:bold;color:var(--g);display:block;margin-top:2px}
.stat-val.warn{color:var(--y)}
.stat-val.danger{color:var(--r)}

/* ── PEER TABLE ──────────────────────────────────────── */
#content{padding:16px;flex:1}
#scan-info{font-size:10px;color:var(--g3);margin-bottom:10px;letter-spacing:1px}
table{width:100%;border-collapse:collapse;border:2px solid var(--g)}
thead tr{background:var(--g)}
th{
  color:#000;text-align:left;padding:6px 10px;
  font-size:11px;letter-spacing:3px;font-weight:bold;
  border-right:1px solid var(--g3)
}
th:last-child{border-right:none}
td{
  padding:8px 10px;border-bottom:1px solid var(--g3);
  border-right:1px solid var(--g3);vertical-align:top
}
td:last-child{border-right:none}
tr:last-child td{border-bottom:none}
tr.flash{animation:rowflash .6s ease}
@keyframes rowflash{0%{background:var(--g);color:#000}100%{background:transparent;color:var(--g)}}

.st{font-weight:bold;letter-spacing:1px}
.st-active{color:var(--g)}
.st-stale{color:var(--y)}
.st-registered{color:var(--b)}
.st-deregistered{color:var(--r)}

.ports{display:flex;flex-wrap:wrap;gap:3px;max-width:320px}
.port{
  display:inline-block;padding:1px 5px;
  font-size:11px;font-weight:bold
}
.port-up{background:var(--g);color:#000}
.port-dn{border:1px solid var(--g3);color:var(--g3)}
.no-range{color:var(--g3);font-style:italic;font-size:11px}

/* ── EMPTY / LOADING ─────────────────────────────────── */
#empty{text-align:center;padding:60px;color:var(--g3);font-size:16px;letter-spacing:4px;display:none}
#ticker{
  border-top:1px solid var(--g3);padding:6px 16px;
  font-size:10px;color:var(--g3);letter-spacing:1px;
  font-family:inherit;height:24px;overflow:hidden
}
</style>
</head>
<body>

<!-- ── AUTH ──────────────────────────────────────────────────────── -->
<div id="auth">
<pre>
 __  __ _____ ___ _  _ _    ___ _  _ _  _
|  \/  | ____/ __| || | |  |_ _| \| | |/ /
| |\/| |  _| \__ \ __ | |__ | || .` | ' &lt;
|_|  |_|___||___/_||_|____|___|_|\_|_|\_\
</pre>
<h1>// ADMIN //</h1>
<label for="tok-in">ADMIN TOKEN</label>
<input id="tok-in" type="password" placeholder="enter admin token" autocomplete="off">
<div id="auth-err"></div>
<button id="auth-btn">AUTHENTICATE</button>
</div>

<!-- ── MAIN ──────────────────────────────────────────────────────── -->
<div id="main">
  <header>
    <h1>MESHLINK // ADMIN CONSOLE</h1>
    <div id="hdr-right">
      <span><span id="conn-dot"></span><span id="conn-label">DISCONNECTED</span></span>
      <button id="logout-btn">LOGOUT</button>
    </div>
  </header>

  <div id="stats">
    <div class="stat">PEERS TOTAL<span id="s-total" class="stat-val">—</span></div>
    <div class="stat">ACTIVE<span id="s-active" class="stat-val">—</span></div>
    <div class="stat">STALE<span id="s-stale" class="stat-val warn">—</span></div>
    <div class="stat">SERVICES UP<span id="s-up" class="stat-val">—</span></div>
    <div class="stat">SERVICES DOWN<span id="s-down" class="stat-val danger">—</span></div>
  </div>

  <div id="content">
    <div id="scan-info">LAST SCAN: —</div>
    <table id="tbl">
      <thead>
        <tr>
          <th>NODE</th>
          <th>VIRTUAL IP</th>
          <th>STATUS</th>
          <th>LAST SEEN</th>
          <th>ENDPOINT</th>
          <th>SERVICES (PORTS)</th>
        </tr>
      </thead>
      <tbody id="tbody"></tbody>
    </table>
    <div id="empty">NO PEERS REGISTERED</div>
  </div>

  <div id="ticker">&nbsp;</div>
</div>

<script>
// ── State ────────────────────────────────────────────────────────────
let token = '';
let es = null;
let peers = {};    // node_id → PeerSnapshot
let prevPeers = {}; // for change detection

// ── DOM refs ─────────────────────────────────────────────────────────
const authEl   = document.getElementById('auth');
const mainEl   = document.getElementById('main');
const tokIn    = document.getElementById('tok-in');
const authBtn  = document.getElementById('auth-btn');
const authErr  = document.getElementById('auth-err');
const connDot  = document.getElementById('conn-dot');
const connLbl  = document.getElementById('conn-label');
const tbody    = document.getElementById('tbody');
const emptyEl  = document.getElementById('empty');
const scanInfo = document.getElementById('scan-info');
const ticker   = document.getElementById('ticker');

// ── Auth ─────────────────────────────────────────────────────────────
function clientSideCheck(tok) {
  // Client-side: token must be non-empty.
  // The server validates it independently on every request.
  return typeof tok === 'string' && tok.trim().length > 0;
}

function showAuth(msg) {
  teardownSse();
  mainEl.classList.remove('visible');
  authEl.classList.remove('hidden');
  authErr.textContent = msg || '';
  tokIn.value = '';
}

function showMain() {
  authEl.classList.add('hidden');
  mainEl.classList.add('visible');
}

async function doLogin(tok) {
  if (!clientSideCheck(tok)) {
    authErr.textContent = 'TOKEN MUST NOT BE EMPTY';
    return;
  }
  authErr.textContent = 'VERIFYING...';

  // Server-side check: try the services endpoint
  let ok = false;
  try {
    const r = await fetch('/api/v1/admin/services', {
      headers: { 'Authorization': 'Bearer ' + tok }
    });
    ok = r.ok;
    if (r.status === 401) {
      authErr.textContent = 'INVALID TOKEN';
      return;
    }
    if (!r.ok) {
      authErr.textContent = 'SERVER ERROR ' + r.status;
      return;
    }
    const data = await r.json();
    applySnapshot(data);
  } catch(e) {
    authErr.textContent = 'CONNECTION FAILED';
    return;
  }

  token = tok;
  localStorage.setItem('ml_admin_token', tok);
  showMain();
  setupSse();
}

authBtn.addEventListener('click', () => doLogin(tokIn.value.trim()));
tokIn.addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(tokIn.value.trim()); });
document.getElementById('logout-btn').addEventListener('click', () => {
  localStorage.removeItem('ml_admin_token');
  token = '';
  showAuth('');
});

// ── SSE ──────────────────────────────────────────────────────────────
function setupSse() {
  teardownSse();
  // EventSource doesn't support custom headers — token goes in query param.
  // The server validates it independently (not from a cookie or session).
  es = new EventSource('/api/v1/admin/stream?token=' + encodeURIComponent(token));

  es.onopen = () => {
    connDot.classList.add('on');
    connLbl.textContent = 'LIVE';
    tick('SSE STREAM CONNECTED');
  };
  es.onmessage = e => {
    try {
      const data = JSON.parse(e.data);
      applySnapshot(data);
    } catch(_) {}
  };
  es.onerror = () => {
    connDot.classList.remove('on');
    connLbl.textContent = 'RECONNECTING...';
    tick('SSE STREAM LOST — RECONNECTING');
  };
  es.addEventListener('auth-error', () => {
    showAuth('SESSION EXPIRED — RE-AUTHENTICATE');
  });
}

function teardownSse() {
  if (es) { es.close(); es = null; }
  connDot.classList.remove('on');
  connLbl.textContent = 'DISCONNECTED';
}

// ── Render ───────────────────────────────────────────────────────────
function relTime(iso) {
  if (!iso) return '—';
  const sec = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (sec < 5)  return 'just now';
  if (sec < 60) return sec + 's ago';
  if (sec < 3600) return Math.floor(sec/60) + 'm ago';
  return Math.floor(sec/3600) + 'h ago';
}

function statusClass(s) {
  const m = {active:'st-active',stale:'st-stale',registered:'st-registered',deregistered:'st-deregistered'};
  return m[s] || '';
}

function renderPorts(ports) {
  if (!ports || !ports.length) return '<span class="no-range">no range</span>';
  return '<div class="ports">' + ports.map(p =>
    `<span class="port ${p.up?'port-up':'port-dn'}">${p.port}</span>`
  ).join('') + '</div>';
}

function applySnapshot(list) {
  if (!Array.isArray(list)) return;

  let newPeers = {};
  list.forEach(p => { newPeers[p.node_id] = p; });

  // Stats
  const total   = list.length;
  const active  = list.filter(p => p.status === 'active').length;
  const stale   = list.filter(p => p.status === 'stale').length;
  const portsUp = list.reduce((n,p)=>n+(p.ports||[]).filter(x=>x.up).length, 0);
  const portsDn = list.reduce((n,p)=>n+(p.ports||[]).filter(x=>!x.up).length, 0);

  document.getElementById('s-total').textContent  = total;
  document.getElementById('s-active').textContent = active;
  document.getElementById('s-stale').textContent  = stale;
  document.getElementById('s-up').textContent     = portsUp;
  document.getElementById('s-down').textContent   = portsDn;

  const latestScan = list.map(p=>p.scanned_at).filter(Boolean).sort().reverse()[0];
  if (latestScan) scanInfo.textContent = 'LAST SCAN: ' + new Date(latestScan).toLocaleTimeString();

  emptyEl.style.display = total === 0 ? 'block' : 'none';
  document.getElementById('tbl').style.display = total === 0 ? 'none' : '';

  // Sort: active first, then by node name
  list.sort((a,b) => {
    const order = {active:0,registered:1,stale:2,deregistered:3};
    const oa = order[a.status]??9, ob = order[b.status]??9;
    if (oa !== ob) return oa - ob;
    return (a.node_name||a.node_id).localeCompare(b.node_name||b.node_id);
  });

  // Diff render: update changed rows, add new, remove old
  const existingRows = {};
  tbody.querySelectorAll('tr[data-id]').forEach(r => { existingRows[r.dataset.id] = r; });

  const seen = new Set();
  list.forEach((p, i) => {
    seen.add(p.node_id);
    const bare = p.virtual_ip.split('/')[0];
    const changed = !prevPeers[p.node_id] ||
      prevPeers[p.node_id].status !== p.status ||
      JSON.stringify(prevPeers[p.node_id].ports) !== JSON.stringify(p.ports);

    const html = `
      <td><b>${p.node_name||'—'}</b><br><span style="color:var(--g3);font-size:10px">${p.node_id.slice(0,8)}</span></td>
      <td>${bare}</td>
      <td><span class="st ${statusClass(p.status)}">${p.status.toUpperCase()}</span></td>
      <td>${relTime(p.last_heartbeat)}</td>
      <td style="font-size:11px;color:var(--g2)">${p.endpoint||'—'}</td>
      <td>${renderPorts(p.ports)}</td>
    `;

    let row = existingRows[p.node_id];
    if (!row) {
      row = document.createElement('tr');
      row.dataset.id = p.node_id;
      // Insert at correct sorted position
      const rows = tbody.querySelectorAll('tr[data-id]');
      if (i < rows.length) {
        tbody.insertBefore(row, rows[i]);
      } else {
        tbody.appendChild(row);
      }
    }
    if (changed) {
      row.innerHTML = html;
      row.classList.remove('flash');
      void row.offsetWidth; // reflow to restart animation
      row.classList.add('flash');
      if (prevPeers[p.node_id]) {
        tick(`UPDATE: ${p.node_name||p.node_id.slice(0,8)} → ${p.status.toUpperCase()}`);
      }
    }
  });

  // Remove rows for peers no longer present
  Object.entries(existingRows).forEach(([id, row]) => {
    if (!seen.has(id)) row.remove();
  });

  prevPeers = newPeers;
  peers = newPeers;
}

// Refresh relative timestamps every 10 seconds
setInterval(() => {
  tbody.querySelectorAll('tr[data-id]').forEach(row => {
    const id = row.dataset.id;
    if (peers[id]) {
      const tds = row.querySelectorAll('td');
      if (tds[3]) tds[3].textContent = relTime(peers[id].last_heartbeat);
    }
  });
}, 10000);

// ── Ticker ───────────────────────────────────────────────────────────
const tickLog = [];
function tick(msg) {
  const t = new Date().toLocaleTimeString();
  tickLog.unshift(`[${t}] ${msg}`);
  if (tickLog.length > 1) tickLog.length = 1;
  ticker.textContent = tickLog[0];
}

// ── Boot ─────────────────────────────────────────────────────────────
(function boot() {
  const saved = localStorage.getItem('ml_admin_token');
  if (saved && clientSideCheck(saved)) {
    tokIn.value = saved;
    doLogin(saved);
  } else {
    showAuth('');
  }
})();
</script>
</body>
</html>
"#;
