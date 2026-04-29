import './style.css';
import './app.css';

// ---- Types ----
interface UIMessage {
  id: string;
  from: string;
  fromId: string;
  content: string;
  room: string;
  ts: number;
  encrypted: boolean;
  onion: boolean;
}

interface UIPeer {
  id: string;
  addr: string;
  reputation: number;
  latencyMs: number;
}

interface UINodeInfo {
  nodeId: string;
  listenAddr: string;
  powToken: string;
}

interface MetricsSnapshot {
  sent: number;
  received: number;
  dropped: number;
  delivery_rate: number;
  active_peers: number;
  avg_latency_ms: number;
  p99_latency_ms: number;
  throughput_bps: number;
  censorship_mode: boolean;
  drop_rate: number;
}

// ---- Wails bindings ----
declare const window: Window & {
  go: {
    main: {
      App: {
        GetNodeInfo: () => Promise<UINodeInfo>;
        ConnectPeer: (addr: string) => Promise<string>;
        GetPeers: () => Promise<UIPeer[]>;
        SendMessage: (room: string, content: string, useOnion: boolean) => Promise<string>;
        GetMessages: (room: string) => Promise<UIMessage[]>;
        GetMetrics: () => Promise<string>;
        SetCensorshipSimulation: (enabled: boolean, dropRate: number) => Promise<string>;
        AddBootstrap: (addr: string) => Promise<string>;
        GetNetworkSummary: () => Promise<string>;
      };
    };
  };
  runtime: {
    EventsOn: (event: string, cb: (data: unknown) => void) => void;
  };
};

// ---- State ----
let currentRoom = 'general';
let useOnion = false;

// ---- DOM Refs ----
const app = document.getElementById('app')!;

app.innerHTML = `
<div class="layout">
  <!-- Sidebar -->
  <aside class="sidebar">
    <div class="sidebar-header">
      <span class="logo-text">chat<span class="accent">0</span></span>
      <span class="shield-icon" title="End-to-end encrypted">🔒</span>
    </div>

    <div class="node-info" id="nodeInfo">
      <div class="label">Node ID</div>
      <div class="value mono" id="nodeId">…</div>
      <div class="label">Listen</div>
      <div class="value mono" id="listenAddr">…</div>
      <div class="label">PoW Token</div>
      <div class="value mono small" id="powToken">solving…</div>
    </div>

    <div class="section-title">Rooms</div>
    <ul class="room-list" id="roomList">
      <li class="room active" data-room="general">🌐 general</li>
      <li class="room" data-room="secure">🔐 secure</li>
      <li class="room" data-room="anon">👻 anon</li>
    </ul>

    <div class="section-title">Peers <span class="peer-count" id="peerCount">0</span></div>
    <ul class="peer-list" id="peerList"></ul>

    <div class="section-title">Connect</div>
    <div class="connect-box">
      <input id="connectAddr" class="input-small" placeholder="host:port" />
      <button class="btn-small" id="connectBtn">Connect</button>
    </div>

    <div class="section-title">Bootstrap</div>
    <div class="connect-box">
      <input id="bootstrapAddr" class="input-small" placeholder="seed host:port" />
      <button class="btn-small" id="bootstrapBtn">Add</button>
    </div>

    <div class="section-title">Options</div>
    <label class="toggle-row">
      <input type="checkbox" id="onionToggle" />
      <span>Onion routing</span>
    </label>
    <label class="toggle-row">
      <input type="checkbox" id="censorToggle" />
      <span>Censorship sim</span>
    </label>
    <div class="drop-row" id="dropRow" style="display:none">
      Drop rate: <input type="range" id="dropRate" min="0" max="100" value="30" style="width:80px">
      <span id="dropPct">30%</span>
    </div>
  </aside>

  <!-- Main chat -->
  <main class="chat-area">
    <div class="chat-header">
      <span id="roomTitle">#general</span>
      <span class="routing-badge" id="routingBadge">Direct E2E</span>
    </div>

    <div class="messages" id="messages"></div>

    <div class="input-area">
      <input class="msg-input" id="msgInput" placeholder="Type a message…" autocomplete="off" />
      <button class="btn-send" id="sendBtn">Send</button>
    </div>

    <div class="status-bar" id="statusBar">Initialising…</div>
  </main>

  <!-- Metrics panel -->
  <div class="metrics-panel" id="metricsPanel">
    <div class="section-title">Network Metrics</div>
    <div class="metric-row"><span>Peers</span><span id="mPeers">—</span></div>
    <div class="metric-row"><span>Sent</span><span id="mSent">—</span></div>
    <div class="metric-row"><span>Received</span><span id="mRecv">—</span></div>
    <div class="metric-row"><span>Dropped</span><span id="mDropped">—</span></div>
    <div class="metric-row"><span>Delivery</span><span id="mDelivery">—</span></div>
    <div class="metric-row"><span>Avg lat</span><span id="mAvgLat">—</span></div>
    <div class="metric-row"><span>P99 lat</span><span id="mP99">—</span></div>
    <div class="metric-row"><span>Bandwidth</span><span id="mBw">—</span></div>
    <div class="metric-row"><span>Censorship</span><span id="mCensor">OFF</span></div>
  </div>
</div>
`;

// ---- Helpers ----
function appendMessage(msg: UIMessage) {
  const container = document.getElementById('messages')!;
  const el = document.createElement('div');
  el.className = 'message' + (msg.from === 'me' ? ' me' : '');
  const time = new Date(msg.ts).toLocaleTimeString();
  const badge = msg.onion ? '🧅' : '🔒';
  const from = msg.from === 'me' ? 'You' : msg.fromId.substring(0, 8);
  el.innerHTML = `
    <div class="msg-meta">${badge} <span class="msg-from">${from}</span> <span class="msg-time">${time}</span></div>
    <div class="msg-body">${escapeHtml(msg.content)}</div>
  `;
  container.appendChild(el);
  container.scrollTop = container.scrollHeight;
}

function escapeHtml(s: string) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function renderPeers(peers: UIPeer[]) {
  const list = document.getElementById('peerList')!;
  document.getElementById('peerCount')!.textContent = String(peers.length);
  list.innerHTML = peers.map(p => `
    <li class="peer-item" title="${p.addr}">
      <span class="peer-dot" style="background:${repColor(p.reputation)}"></span>
      <span class="peer-id">${p.id.substring(0, 10)}…</span>
      <span class="peer-lat">${p.latencyMs > 0 ? p.latencyMs + 'ms' : '—'}</span>
    </li>
  `).join('');
}

function repColor(rep: number) {
  if (rep >= 70) return '#4ade80';
  if (rep >= 40) return '#facc15';
  return '#f87171';
}

function updateMetrics(snap: MetricsSnapshot) {
  document.getElementById('mPeers')!.textContent = String(snap.active_peers);
  document.getElementById('mSent')!.textContent = String(snap.sent);
  document.getElementById('mRecv')!.textContent = String(snap.received);
  document.getElementById('mDropped')!.textContent = String(snap.dropped);
  document.getElementById('mDelivery')!.textContent = snap.delivery_rate.toFixed(1) + '%';
  document.getElementById('mAvgLat')!.textContent = snap.avg_latency_ms.toFixed(1) + 'ms';
  document.getElementById('mP99')!.textContent = snap.p99_latency_ms.toFixed(1) + 'ms';
  document.getElementById('mBw')!.textContent = (snap.throughput_bps / 1024).toFixed(1) + ' KB/s';
  document.getElementById('mCensor')!.textContent = snap.censorship_mode
    ? `ON (${(snap.drop_rate * 100).toFixed(0)}%)`
    : 'OFF';
}

function switchRoom(room: string) {
  currentRoom = room;
  document.getElementById('roomTitle')!.textContent = '#' + room;
  document.querySelectorAll('.room').forEach(el => {
    el.classList.toggle('active', el.getAttribute('data-room') === room);
  });
  document.getElementById('messages')!.innerHTML = '';
  window.go.main.App.GetMessages(room).then(msgs => msgs.forEach(appendMessage));
}

// ---- Event wiring ----
document.querySelectorAll('.room').forEach(el => {
  el.addEventListener('click', () => switchRoom(el.getAttribute('data-room')!));
});

document.getElementById('sendBtn')!.addEventListener('click', sendMessage);
document.getElementById('msgInput')!.addEventListener('keydown', (e: KeyboardEvent) => {
  if (e.key === 'Enter') sendMessage();
});

function sendMessage() {
  const input = document.getElementById('msgInput') as HTMLInputElement;
  const content = input.value.trim();
  if (!content) return;
  input.value = '';
  window.go.main.App.SendMessage(currentRoom, content, useOnion).then(result => {
    document.getElementById('statusBar')!.textContent = result;
  });
}

document.getElementById('connectBtn')!.addEventListener('click', () => {
  const addr = (document.getElementById('connectAddr') as HTMLInputElement).value.trim();
  if (!addr) return;
  window.go.main.App.ConnectPeer(addr).then(r => {
    document.getElementById('statusBar')!.textContent = r;
  });
});

document.getElementById('bootstrapBtn')!.addEventListener('click', () => {
  const addr = (document.getElementById('bootstrapAddr') as HTMLInputElement).value.trim();
  if (!addr) return;
  window.go.main.App.AddBootstrap(addr).then(r => {
    document.getElementById('statusBar')!.textContent = r;
  });
});

document.getElementById('onionToggle')!.addEventListener('change', (e) => {
  useOnion = (e.target as HTMLInputElement).checked;
  const badge = document.getElementById('routingBadge')!;
  badge.textContent = useOnion ? '🧅 Onion 3-hop' : 'Direct E2E';
  badge.className = 'routing-badge' + (useOnion ? ' onion' : '');
});

document.getElementById('censorToggle')!.addEventListener('change', (e) => {
  const enabled = (e.target as HTMLInputElement).checked;
  const dropRow = document.getElementById('dropRow')!;
  dropRow.style.display = enabled ? 'flex' : 'none';
  const dropRate = parseInt((document.getElementById('dropRate') as HTMLInputElement).value) / 100;
  window.go.main.App.SetCensorshipSimulation(enabled, dropRate).then(r => {
    document.getElementById('statusBar')!.textContent = r;
  });
});

document.getElementById('dropRate')!.addEventListener('input', (e) => {
  const pct = (e.target as HTMLInputElement).value;
  document.getElementById('dropPct')!.textContent = pct + '%';
  window.go.main.App.SetCensorshipSimulation(true, parseInt(pct) / 100);
});

// ---- Runtime events ----
window.runtime.EventsOn('chat:message', (data: unknown) => {
  const msg = data as UIMessage;
  if (msg.room === currentRoom) {
    appendMessage(msg);
  }
});

window.runtime.EventsOn('peer:join', () => {
  window.go.main.App.GetPeers().then(renderPeers);
});

window.runtime.EventsOn('peer:leave', () => {
  window.go.main.App.GetPeers().then(renderPeers);
});

// ---- Init ----
window.go.main.App.GetNodeInfo().then(info => {
  document.getElementById('nodeId')!.textContent = info.nodeId;
  document.getElementById('listenAddr')!.textContent = info.listenAddr;
  document.getElementById('powToken')!.textContent = info.powToken.substring(0, 16) + '…';
});

window.go.main.App.GetMessages(currentRoom).then(msgs => msgs.forEach(appendMessage));

// Refresh loop
setInterval(() => {
  window.go.main.App.GetPeers().then(renderPeers);
  window.go.main.App.GetMetrics().then(raw => {
    try { updateMetrics(JSON.parse(raw)); } catch { }
  });
  window.go.main.App.GetNetworkSummary().then(s => {
    document.getElementById('statusBar')!.textContent = s;
  });
}, 3000);
