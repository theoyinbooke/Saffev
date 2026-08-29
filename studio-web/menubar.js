/* =============================================================================
   Saffev menu-bar panel — app logic.

   Runs inside the tray app's WKWebView, served by the Studio (same origin, token
   injected as window.__SAFFEV_TOKEN__). Everything it shows comes from the
   existing /api/* endpoints; nothing is computed server-side for it.

   Host protocol (see src/cli/tray_panel.rs):
     page → host : window.ipc.postMessage(JSON.stringify({cmd, ...}))
     host → page : window.__saffevHost.setState(state) / onShow() / onHide() /
                   notice({kind,title,detail})
   ============================================================================= */
(() => {
  'use strict';

  const TOKEN = window.__SAFFEV_TOKEN__ || '';
  const $ = (sel, root) => (root || document).querySelector(sel);
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  function ipc(msg) {
    try { if (window.ipc && window.ipc.postMessage) window.ipc.postMessage(JSON.stringify(msg)); } catch (e) { /* not hosted */ }
  }

  async function api(path, opts) {
    opts = opts || {};
    const headers = { Accept: 'application/json' };
    if (TOKEN) headers['Authorization'] = 'Bearer ' + TOKEN;
    let body = opts.body;
    if (body != null && typeof body !== 'string') { body = JSON.stringify(body); headers['Content-Type'] = 'application/json'; }
    const res = await fetch('/api' + path, { method: opts.method || 'GET', headers, body, cache: 'no-store' });
    if (!res.ok) {
      let payload = null; try { payload = await res.json(); } catch (e) { /* no body */ }
      const err = new Error((payload && payload.message) || ('HTTP ' + res.status));
      err.status = res.status; err.code = payload && payload.error;
      throw err;
    }
    return res.status === 204 ? null : res.json();
  }

  /* ---- formatting ------------------------------------------------------- */
  const compact = (n) => {
    if (n == null || isNaN(n)) return '·';
    n = Number(n);
    if (Math.abs(n) >= 1e9) return (n / 1e9).toFixed(n >= 1e10 ? 0 : 1) + 'B';
    if (Math.abs(n) >= 1e6) return (n / 1e6).toFixed(n >= 1e7 ? 0 : 1) + 'M';
    if (Math.abs(n) >= 1e4) return (n / 1e3).toFixed(0) + 'K';
    if (Math.abs(n) >= 1e3) return (n / 1e3).toFixed(1) + 'K';
    return Number.isInteger(n) ? String(n) : n.toFixed(1);
  };
  const money = (v) => {
    if (v == null || isNaN(v)) return '·';
    v = Number(v);
    if (v === 0) return '$0';
    if (v > 0 && v < 0.01) return '<$0.01';
    if (v < 10) return '$' + v.toFixed(2);
    if (v < 1000) return '$' + v.toFixed(v < 100 ? 1 : 0);
    return '$' + Math.round(v).toLocaleString();
  };
  const bytes = (n) => {
    if (n == null) return '·';
    const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0; n = Number(n);
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i === 0 ? n : n.toFixed(n < 10 ? 1 : 0)) + ' ' + u[i];
  };
  const ago = (ts) => {
    if (!ts) return '·';
    const d = Date.now() - ts;
    if (d < 45e3) return 'just now';
    if (d < 3600e3) return Math.round(d / 60e3) + 'm ago';
    if (d < 86400e3) return Math.round(d / 3600e3) + 'h ago';
    return Math.round(d / 86400e3) + 'd ago';
  };
  const dur = (ms) => {
    if (ms == null || ms < 0) return '·';
    const m = Math.round(ms / 60e3);
    if (m < 1) return '<1m';
    if (m < 60) return m + 'm';
    const h = Math.floor(m / 60);
    if (h < 48) return h + 'h ' + (m % 60) + 'm';
    return Math.round(h / 24) + 'd';
  };
  const durShort = (ms) => {
    if (ms == null || ms < 0) return '·';
    const m = Math.round(ms / 60e3);
    return m < 60 ? m + 'm' : Math.round(m / 60) + 'h';
  };
  const days = (ms) => {
    if (ms == null) return null;
    const d = Math.ceil(ms / 86400e3);
    return d <= 0 ? 'today' : d === 1 ? 'tomorrow' : 'in ' + d + 'd';
  };
  const todayUtc = () => new Date().toISOString().slice(0, 10);
  const shortPath = (p) => {
    if (!p) return '';
    const home = host.homeDir || '';
    let out = home && p.startsWith(home) ? '~' + p.slice(home.length) : p;
    if (out.length > 34) { const parts = out.split('/'); out = parts.length > 3 ? parts[0] + '/…/' + parts.slice(-2).join('/') : out; }
    return out;
  };
  const clamp = (x, a, b) => Math.max(a, Math.min(b, x));

  const PII_LABEL = {
    email: 'Email', phone: 'Phone', credit_card: 'Card', api_key: 'API key', ip_address: 'IP address',
    private_key: 'Private key', jwt: 'JWT', connection_string: 'Conn. string', ssn: 'SSN', iban: 'IBAN',
    mac_address: 'MAC', env_assignment: 'Env secret', crypto_wallet: 'Wallet', custom: 'Custom',
  };
  const SECRET_KINDS = ['api_key', 'private_key', 'jwt', 'connection_string', 'env_assignment', 'credit_card', 'crypto_wallet'];
  const piiLabel = (k) => PII_LABEL[k] || String(k || '').replace(/_/g, ' ');

  /* ---- icons (stroke, currentColor) ------------------------------------- */
  const svg = (paths, extra) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" ${extra || ''}>${paths}</svg>`;
  const ICON = {
    overview: svg('<path d="M2 12h4l3 8 4-16 3 8h6"/>'),
    keep: svg('<path d="M3 7h18v3H3z"/><path d="M5 10v9h14v-9"/><path d="M10 14h4"/>'),
    privacy: svg('<path d="M12 3 4 6v6c0 5 3.4 8.4 8 9 4.6-.6 8-4 8-9V6l-8-3Z"/><path d="m9 12 2 2 4-4"/>'),
    spend: svg('<circle cx="12" cy="12" r="9"/><path d="M14.5 9.3A2.6 2.6 0 0 0 12 8c-1.6 0-2.6.8-2.6 1.9 0 2.6 5.2 1.3 5.2 4 0 1.2-1.1 2.1-2.6 2.1a2.8 2.8 0 0 1-2.7-1.5M12 6.5V8m0 8v1.5"/>'),
    alerts: svg('<path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.7 21a2 2 0 0 1-3.4 0"/>'),
    pin: svg('<path d="M12 17v5"/><path d="M9 3h6l-1 6 3 3H7l3-3-1-6Z"/>'),
    play: svg('<path d="M7 4v16l13-8Z"/>'),
    stop: svg('<rect x="6" y="6" width="12" height="12" rx="2"/>'),
    restart: svg('<path d="M20 12a8 8 0 1 1-2.3-5.7"/><path d="M20 3v5h-5"/>'),
    logs: svg('<path d="M6 3h9l4 4v14H6z"/><path d="M14 3v5h5M9 13h6M9 17h6"/>'),
    quit: svg('<path d="M12 3v9"/><path d="M6.3 7A8 8 0 1 0 17.7 7"/>'),
    login: svg('<path d="M4 20V4h9l7 7v9z"/><path d="M8 20v-6h8v6"/><path d="M8 4v4h6"/>'),
    backup: svg('<path d="M4 14v4a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-4"/><path d="M12 4v12"/><path d="m7 11 5 5 5-5"/>'),
    engine: svg('<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>'),
    shield: svg('<path d="M12 3 4 6v6c0 5 3.4 8.4 8 9 4.6-.6 8-4 8-9V6l-8-3Z"/>'),
    check: svg('<path d="m5 12 4 4L19 7"/>'),
    warn: svg('<path d="M12 3 2 20h20L12 3Z"/><path d="M12 10v4M12 17h.01"/>'),
    info: svg('<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>'),
    open: svg('<path d="M14 4h6v6"/><path d="M20 4 11 13"/><path d="M19 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1h5"/>'),
    update: svg('<path d="M12 20V8"/><path d="m6 14 6 6 6-6"/><path d="M4 4h16"/>'),
    bolt: svg('<path d="M13 2 4 14h7l-1 8 9-12h-7l1-8Z"/>'),
    sun: svg('<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>'),
    moon: svg('<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"/>'),
    settings: svg('<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2h-4V21a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 3 14H2.8v-4H3a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1A1.7 1.7 0 0 0 9 4.6 1.7 1.7 0 0 0 10 3V2.8h4V3a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2v4H21a1.7 1.7 0 0 0-1.6 1Z"/>'),
  };

  /* ---- state ------------------------------------------------------------ */
  const TABS = [
    { id: 'overview', label: 'Overview', icon: ICON.overview },
    { id: 'keep', label: 'Keep', icon: ICON.keep },
    { id: 'privacy', label: 'Privacy', icon: ICON.privacy },
    { id: 'spend', label: 'Spend', icon: ICON.spend },
    { id: 'alerts', label: 'Alerts', icon: ICON.alerts },
  ];
  const DAY = 86400e3;
  const LOADERS = {
    live: () => api('/live'),
    an7: () => api('/analytics?rangeMs=' + 7 * DAY),
    engines: () => api('/engines'),
    agents: () => api('/agents'),
    verify: () => api('/archive/verify'),
    privacy: () => api('/privacy'),
    aprivacy: () => api('/agents/privacy'),
    ausage: () => api('/agents/analytics'),
    update: () => api('/update'),
    settings: () => api('/settings'),
  };
  const NEEDS = {
    overview: ['live', 'an7', 'engines', 'ausage', 'agents'],
    keep: ['agents', 'verify', 'settings'],
    privacy: ['privacy', 'live', 'aprivacy', 'settings'],
    spend: ['ausage', 'agents', 'an7'],
    alerts: ['live', 'an7', 'engines', 'agents', 'verify', 'update', 'settings'],
  };
  const ALL = Object.keys(LOADERS);

  let host = { appName: 'Saffev', version: '', studioUrl: '', running: null, status: 'starting', statusText: 'Connecting…', loginEnabled: false, pinned: false };
  let tab = 'overview';
  try { tab = localStorage.getItem('saffev.panel.tab') || 'overview'; } catch (e) { /* storage blocked */ }
  if (!TABS.some((t) => t.id === tab)) tab = 'overview';
  let settingsOpen = false;
  let visible = true;
  // Theme: '' follows the OS; 'light' / 'dark' is an explicit choice, kept per
  // viewer and echoed to the host so the offline card matches.
  let theme = '';
  try { theme = localStorage.getItem('saffev.panel.theme') || ''; } catch (e) { /* storage blocked */ }
  function applyTheme() {
    if (theme) document.documentElement.setAttribute('data-theme', theme);
    else document.documentElement.removeAttribute('data-theme');
  }
  const effectiveTheme = () => theme || (window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  function setTheme(choice) {
    theme = ['light', 'dark'].includes(choice) ? choice : '';
    try {
      if (theme) localStorage.setItem('saffev.panel.theme', theme);
      else localStorage.removeItem('saffev.panel.theme');
    } catch (e) { /* storage blocked */ }
    applyTheme();
    ipc({ cmd: 'set_theme', theme });
    render();
  }
  function toggleTheme() { setTheme(effectiveTheme() === 'dark' ? 'light' : 'dark'); }
  applyTheme();
  let spendMode = 'cost';   // area chart: 'cost' | 'tokens'
  const data = {};
  const failed = {};
  let stale = false;
  let pollTimer = null;
  let signals = [];           // live SSE signals seen while open (newest first)
  let dismissed = new Set();  // alert keys the user dismissed this session
  let busy = {};              // action → true while in flight
  let noticeTimer = null;
  let firstPaint = true;

  /* ---- data ------------------------------------------------------------- */
  // Progressive: every endpoint paints as soon as it lands. A cold agent scan
  // can take seconds; the gauges must not wait for it.
  const inflight = {};
  // Per-key sequence: a response only lands if it is the newest request for
  // that key, so a slow earlier fetch can never overwrite a forced reload.
  const seq = {};
  let renderQueued = false;
  function queueRender() {
    if (renderQueued) return;
    renderQueued = true;
    requestAnimationFrame(() => { renderQueued = false; render(); });
  }
  // Heavy endpoints (agent scans, archive verify, 7-day analytics) are
  // refreshed at most this often; only the cheap `live` read polls every tick.
  const HEAVY_TTL = 45000;
  const fetchedAt = {};
  async function load(keys, force) {
    const uniq = Array.from(new Set(keys)).filter((k) => force || (!inflight[k] && (k === 'live' || !fetchedAt[k] || Date.now() - fetchedAt[k] > HEAVY_TTL)));
    let anyFail = false, anyOk = false;
    await Promise.all(uniq.map(async (k) => {
      const mine = (seq[k] = (seq[k] || 0) + 1);
      inflight[k] = true;
      try {
        const v = await LOADERS[k]();
        if (seq[k] !== mine) return;
        data[k] = v; delete failed[k]; delete failed.auth; anyOk = true; fetchedAt[k] = Date.now();
      } catch (e) {
        if (seq[k] !== mine) return;
        failed[k] = e; anyFail = true;
        if (e && (e.status === 401 || e.status === 403)) failed.auth = true;
      }
      if (seq[k] === mine) inflight[k] = false;
      queueRender();
    }));
    stale = anyFail && !anyOk;
    queueRender();
  }
  function refresh(all) {
    const keys = all ? ALL : settingsOpen ? ['settings', 'live'] : NEEDS[tab].concat(['live']);
    return load(keys, false);
  }
  function startPolling() {
    stopPolling();
    pollTimer = setInterval(() => { if (visible && document.visibilityState !== 'hidden') refresh(false); }, 6000);
    connectStream();
  }
  function stopPolling() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = null;
    disconnectStream();
  }

  /* ---- live stream (signals + quick refresh) ---------------------------- */
  let streamCtrl = null, streamRetry = 0, liveDebounce = null;
  function connectStream() {
    disconnectStream();
    runStream();
  }
  function disconnectStream() {
    if (streamCtrl) { try { streamCtrl.abort(); } catch (e) { /* closed */ } }
    streamCtrl = null;
  }
  async function runStream() {
    if (!visible) return;
    const ctrl = new AbortController();
    streamCtrl = ctrl;
    const headers = { Accept: 'text/event-stream' };
    if (TOKEN) headers['Authorization'] = 'Bearer ' + TOKEN;
    try {
      const res = await fetch('/api/stream', { headers, signal: ctrl.signal, cache: 'no-store' });
      if (!res.ok || !res.body) throw new Error('stream HTTP ' + res.status);
      streamRetry = 0;
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        let idx;
        while ((idx = buf.indexOf('\n\n')) >= 0) {
          const frame = buf.slice(0, idx); buf = buf.slice(idx + 2);
          const dataLine = frame.split('\n').filter((l) => l.startsWith('data:')).map((l) => l.slice(5).trim()).join('\n');
          if (!dataLine) continue;
          let msg = null; try { msg = JSON.parse(dataLine); } catch (e) { continue; }
          onStreamEvent(msg);
        }
      }
    } catch (e) {
      if (ctrl.signal.aborted) return;
    }
    if (streamCtrl !== ctrl || !visible) return;
    streamRetry = Math.min(streamRetry + 1, 6);
    setTimeout(runStream, 1000 * Math.pow(2, streamRetry));
  }
  function onStreamEvent(msg) {
    if (!msg || !msg.type) return;
    if (msg.type === 'signal') {
      signals.unshift({ kind: msg.kind, title: msg.title, detail: msg.detail, ts: msg.ts || Date.now() });
      signals = signals.slice(0, 12);
      render();
      return;
    }
    if (msg.type === 'finished' || msg.type === 'pii' || msg.type === 'requestStarted') {
      clearTimeout(liveDebounce);
      liveDebounce = setTimeout(() => load(['live']), 1200);
    }
  }

  /* ---- derived: alerts -------------------------------------------------- */
  function deriveAlerts() {
    const out = [];
    const push = (a) => { if (!dismissed.has(a.key)) out.push(a); };
    const live = data.live, an7 = data.an7, eng = data.engines, ag = data.agents, ver = data.verify, up = data.update;

    if (host.status === 'failed') push({ key: 'svc', sev: 'danger', title: 'Service failed to start', detail: 'See the log for the cause.', action: { label: 'Open logs', cmd: 'logs' } });
    else if (host.status === 'stopped') push({ key: 'svc', sev: 'warn', title: 'Service is stopped', detail: '', action: { label: 'Start', cmd: 'start' } });

    if (ver && ver.intact === false) push({ key: 'integrity', sev: 'danger', title: 'Archive integrity broken', detail: ver.brokenAt ? 'at ' + ver.brokenAt : '', action: { label: 'Inspect', route: '#/agents' } });
    if (eng && eng.exposure && eng.exposure.exposed) push({ key: 'exposure', sev: 'danger', title: 'Engine reachable from the network', detail: eng.exposure.boundTo ? 'bound to ' + eng.exposure.boundTo : '', action: { label: 'Engines', route: '#/engines' } });

    if (ag && Array.isArray(ag.atRisk)) {
      ag.atRisk.forEach((r) => {
        if (r.overdue > 0) push({ key: 'overdue:' + r.tool, sev: 'danger', title: r.overdue + ' ' + r.label + ' session' + (r.overdue === 1 ? '' : 's') + ' past the deletion line', detail: 'Not preserved yet.', action: { label: 'Back up', act: 'backup' } });
        else if (r.expiringSoon > 0) push({ key: 'expiring:' + r.tool, sev: 'warn', title: r.expiringSoon + ' ' + r.label + ' session' + (r.expiringSoon === 1 ? '' : 's') + ' expiring soon', detail: r.soonestExpiryTs ? 'Soonest ' + (days(r.soonestExpiryTs - Date.now()) || '') : '', action: { label: 'Back up', act: 'backup' } });
      });
      if (ag.archive && ag.archive.enabled === false) push({ key: 'archive-off', sev: 'warn', title: 'Preservation is off', detail: '', action: { label: 'Turn on', act: 'preserve' } });
    }
    if (live && live.piiFindingsToday > 0) push({ key: 'pii-today', sev: 'warn', title: live.piiFindingsToday + ' leak' + (live.piiFindingsToday === 1 ? '' : 's') + ' caught today', detail: '', action: { label: 'Review', route: '#/history' } });
    if (an7 && an7.failedRequests > 0) push({ key: 'failed', sev: 'info', title: an7.failedRequests + ' failed request' + (an7.failedRequests === 1 ? '' : 's') + ' this week', detail: '', action: { label: 'History', route: '#/history' } });
    if (an7 && Array.isArray(an7.insights)) {
      an7.insights.forEach((ins, i) => {
        const sev = /danger|high|critical/i.test(ins.severity) ? 'danger' : /warn|medium/i.test(ins.severity) ? 'warn' : 'info';
        push({ key: 'insight:' + i + ':' + ins.title, sev, title: ins.title, detail: ins.detail, action: { label: 'Analytics', route: '#/analytics' } });
      });
    }
    if (up && up.updateAvailable) push({ key: 'update', sev: 'info', title: 'Saffev ' + up.latestVersion + ' is available', detail: '', action: { label: 'Releases', cmd: 'update' } });

    signals.forEach((s, i) => push({ key: 'signal:' + s.ts + ':' + i, sev: /exposure|spike|risk/i.test(s.kind || '') ? 'warn' : 'info', title: s.title || s.kind, detail: s.detail, ts: s.ts, live: true }));

    const rank = { danger: 0, warn: 1, info: 2 };
    out.sort((a, b) => (rank[a.sev] - rank[b.sev]) || ((b.ts || 0) - (a.ts || 0)));
    return out;
  }

  /* ---- components ------------------------------------------------------- */
  function gauge(o) {
    const f = clamp(Number(o.frac) || 0, 0, 1);
    const L = Math.PI * 40;
    const th = Math.PI * (1 - f);
    const nx = 50 + 27 * Math.cos(th), ny = 52 - 27 * Math.sin(th);
    return `<div class="gauge sev-${o.sev || 'brand'}" title="${esc(o.title || '')}">
      <div class="g-lbl">${esc(o.label)}</div>
      <svg class="g-arc" viewBox="4 8 92 48" aria-hidden="true">
        <path class="g-track" d="M10 52 A40 40 0 0 1 90 52"/>
        <path class="g-fill" d="M10 52 A40 40 0 0 1 90 52" stroke-dasharray="${L.toFixed(2)}" stroke-dashoffset="${(L * (1 - f)).toFixed(2)}"/>
        <line class="g-needle" x1="50" y1="52" x2="${nx.toFixed(1)}" y2="${ny.toFixed(1)}"/>
        <circle class="g-pivot" cx="50" cy="52" r="3"/>
      </svg>
      <div class="g-val">${esc(o.value)}</div>
      <div class="g-sub">${esc(o.sub || '')}</div>
    </div>`;
  }
  const chip = (cls, text) => `<span class="chip ${cls}"><span class="d"></span>${esc(text)}</span>`;
  const lbl = (text, link) => `<div class="lbl">${esc(text)}<span class="spacer"></span>${link ? `<button class="link" data-route="${esc(link.route)}">${esc(link.label)} ›</button>` : ''}</div>`;
  const stat = (k, n, small) => `<div class="stat"><div class="k">${esc(k)}</div><div class="n">${esc(n)}${small ? `<small>${esc(small)}</small>` : ''}</div></div>`;
  function bars(items, fmt, cls) {
    if (!items.length) return '<div class="empty">Nothing yet</div>';
    const max = Math.max.apply(null, items.map((i) => i.value)) || 1;
    return `<div class="bars">${items.map((i) => `<div class="bar ${i.cls || cls || ''}"><div class="k" title="${esc(i.label)}">${esc(i.label)}</div><div class="track"><div class="fill" style="width:${Math.max(2, (i.value / max) * 100).toFixed(1)}%"></div></div><div class="v">${esc(fmt(i.value))}</div></div>`).join('')}</div>`;
  }
  const pending = (key, what) => failed[key]
    ? `<div class="card danger"><h4>Couldn’t load ${esc(what)}</h4><p>${esc(failed[key].message || String(failed[key]))}</p></div>`
    : `<div class="empty"><span class="spin" style="display:inline-block;vertical-align:-2px;margin-right:6px"></span>Loading ${esc(what)}…</div>`;
  function alertCard(a) {
    const act = a.action ? `<div class="row-actions">${a.action.route ? `<button class="btn sm" data-route="${esc(a.action.route)}">${esc(a.action.label)}</button>` : a.action.cmd ? `<button class="btn sm" data-cmd="${esc(a.action.cmd)}">${esc(a.action.label)}</button>` : `<button class="btn sm" data-act="${esc(a.action.act)}">${esc(a.action.label)}</button>`}<button class="btn sm ghost" data-dismiss="${esc(a.key)}">Dismiss</button></div>` : `<div class="row-actions"><button class="btn sm ghost" data-dismiss="${esc(a.key)}">Dismiss</button></div>`;
    const sevChip = a.sev === 'danger' ? chip('danger', 'urgent') : a.sev === 'warn' ? chip('warn', 'attention') : chip('', 'info');
    return `<div class="alert ${a.sev}"><div class="head"><h4>${esc(a.title)}</h4>${a.ts ? `<span class="when">${esc(ago(a.ts))}</span>` : a.live ? '<span class="when">live</span>' : ''}${sevChip}</div>${a.detail ? `<p>${esc(a.detail)}</p>` : ''}${act}</div>`;
  }

  /* ---- area chart (daily spend) ----------------------------------------- */
  // Monotone cubic interpolation (Fritsch–Carlson): smooth like the reference,
  // never overshoots below zero between two zero days.
  function monotonePath(pts) {
    const n = pts.length;
    if (n === 0) return '';
    if (n === 1) return `M${pts[0][0]} ${pts[0][1]}`;
    const dx = [], dy = [], m = [];
    for (let i = 0; i < n - 1; i++) { dx.push(pts[i + 1][0] - pts[i][0]); dy.push(pts[i + 1][1] - pts[i][1]); m.push(dx[i] === 0 ? 0 : dy[i] / dx[i]); }
    const t = [m[0]];
    for (let i = 1; i < n - 1; i++) t.push(m[i - 1] * m[i] <= 0 ? 0 : (m[i - 1] + m[i]) / 2);
    t.push(m[n - 2]);
    for (let i = 0; i < n - 1; i++) {
      if (m[i] === 0) { t[i] = 0; t[i + 1] = 0; continue; }
      const a = t[i] / m[i], b = t[i + 1] / m[i], h = Math.hypot(a, b);
      if (h > 3) { t[i] = 3 * a / h * m[i]; t[i + 1] = 3 * b / h * m[i]; }
    }
    let d = `M${pts[0][0].toFixed(1)} ${pts[0][1].toFixed(1)}`;
    for (let i = 0; i < n - 1; i++) {
      const h = dx[i] / 3;
      d += ` C${(pts[i][0] + h).toFixed(1)} ${(pts[i][1] + t[i] * h).toFixed(1)} ${(pts[i + 1][0] - h).toFixed(1)} ${(pts[i + 1][1] - t[i + 1] * h).toFixed(1)} ${pts[i + 1][0].toFixed(1)} ${pts[i + 1][1].toFixed(1)}`;
    }
    return d;
  }
  const CAT_VARS = ['--cat-1', '--cat-2', '--cat-3', '--cat-4', '--cat-5', '--cat-6'];
  const MAX_SERIES = 6;
  // Build stacked series from /agents/analytics.dailyByTool: one series per
  // tool ordered by 30-day total (fixed colour order, never re-cycled), the
  // rest folded into "Other". rows: [{date, values:[per-series], total}].
  function stackedSeries(au, mode) {
    const days = Array.isArray(au && au.dailyByTool) ? au.dailyByTool : [];
    const labels = (au && au.toolLabels) || {};
    const pick = (row) => (mode === 'tokens' ? row.tokensByTool : row.costByTool) || {};
    // Colour follows the tool, never its rank in the current measure: the
    // series order (and so each tool's colour) is fixed by 30-day cost, with
    // tokens as the tiebreak for unpriced tools, in BOTH modes.
    const totals = {}, costT = {}, tokT = {};
    days.forEach((d) => {
      const m = pick(d); Object.keys(m).forEach((k) => { totals[k] = (totals[k] || 0) + (m[k] || 0); });
      const c = d.costByTool || {}; Object.keys(c).forEach((k) => { costT[k] = (costT[k] || 0) + (c[k] || 0); });
      const t = d.tokensByTool || {}; Object.keys(t).forEach((k) => { tokT[k] = (tokT[k] || 0) + (t[k] || 0); });
    });
    const ordered = Object.keys(totals).filter((k) => totals[k] > 0)
      .sort((a, b) => ((costT[b] || 0) - (costT[a] || 0)) || ((tokT[b] || 0) - (tokT[a] || 0)) || a.localeCompare(b));
    const head = ordered.slice(0, MAX_SERIES), tail = ordered.slice(MAX_SERIES);
    const series = head.map((k, i) => ({ key: k, label: labels[k] || k, color: `var(${CAT_VARS[i]})`, total: totals[k] }));
    if (tail.length) series.push({ key: '__other', label: 'Other (' + tail.length + ')', color: 'var(--cat-other)', total: tail.reduce((a, k) => a + totals[k], 0) });
    const rows = days.map((d) => {
      const m = pick(d);
      const values = head.map((k) => m[k] || 0);
      if (tail.length) values.push(tail.reduce((a, k) => a + (m[k] || 0), 0));
      return { date: d.date, values, total: values.reduce((a, v) => a + v, 0) };
    });
    return { series, rows };
  }
  // Layered areas: every tool is drawn from the baseline on its own, largest
  // total painted first (underneath), translucent gradient fills so overlaps
  // show through, a crisp 2px line on each. Not stacked — the y scale is the
  // biggest single-tool day, so each layer reads as its own shape.
  const CHART_W = 328, CHART_H = 150, CHART_TOP = 6, CHART_BOTTOM = 16;
  function stackedChart(series, rows, fmt) {
    const W = CHART_W, H = CHART_H, top = CHART_TOP, bottom = CHART_BOTTOM;
    const plotH = H - top - bottom;
    const max = Math.max.apply(null, rows.flatMap((r) => r.values).concat([0]));
    const yMax = max > 0 ? max * 1.06 : 1;
    const x = (i) => (rows.length === 1 ? W / 2 : (i / Math.max(1, rows.length - 1)) * W);
    const y = (v) => top + plotH - (v / yMax) * plotH;
    const base = (top + plotH).toFixed(1);
    const order = series.map((sr, k) => k).sort((a, b) => series[b].total - series[a].total);
    const layers = rows.length ? order.map((k) => {
      const pts = rows.map((r, i) => [x(i), y(r.values[k])]);
      const line = monotonePath(pts);
      return `<path class="layer" fill="url(#lg${k})" d="${line} L${pts[pts.length - 1][0].toFixed(1)} ${base} L${pts[0][0].toFixed(1)} ${base} Z"/><path class="layer-line" stroke="${series[k].color}" d="${line}"/>`;
    }).join('') : '';
    const defs = series.map((sr, k) => `<linearGradient id="lg${k}" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="${sr.color}" stop-opacity=".55"/><stop offset="100%" stop-color="${sr.color}" stop-opacity=".06"/></linearGradient>`).join('');
    const ticks = [0.5, 1].map((f) => ({ v: max * f, yy: y(max * f) }));
    const label = (d) => { const p = d.split('-'); return ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][+p[1] - 1] + ' ' + (+p[2]); };
    const xl = rows.length ? [[0, 'start'], [Math.floor((rows.length - 1) / 2), 'middle'], [rows.length - 1, 'end']] : [];
    return `<div class="chart" data-chart="spend">
      <svg class="chart-svg" viewBox="0 0 ${W} ${H}" width="100%" height="${H}" aria-label="Daily ${fmt === money ? 'cost' : 'tokens'} by tool, last ${rows.length} days">
        <defs>${defs}</defs>
        ${max > 0 ? ticks.map((t) => `<line class="grid" x1="0" x2="${W}" y1="${t.yy.toFixed(1)}" y2="${t.yy.toFixed(1)}"/>`).join('') : ''}
        ${layers}
        ${max > 0 ? ticks.map((t) => `<text class="ytick" x="0" y="${(t.yy - 3).toFixed(1)}">${esc(fmt(t.v))}</text>`).join('') : ''}
        <line class="grid base" x1="0" x2="${W}" y1="${base}" y2="${base}"/>
        <line class="xhair off" x1="0" x2="0" y1="${top}" y2="${base}"/>
        ${series.map((sr, k) => `<circle class="dot off" data-k="${k}" r="3" cx="0" cy="0" fill="${sr.color}"/>`).join('')}
        ${xl.map(([i, anchor]) => `<text class="xtick" x="${x(i).toFixed(1)}" y="${H - 3}" text-anchor="${anchor}">${esc(label(rows[i].date))}</text>`).join('')}
      </svg>
      <div class="chart-tip" hidden></div>
    </div>`;
  }
  // Wire hover after the chart is in the DOM. Nearest-day crosshair + per-tool readout.
  function bindChart(series, rows, fmt) {
    const host = $('[data-chart=spend]');
    if (!host || !rows.length) return;
    const svg = host.querySelector('svg'), xh = svg.querySelector('.xhair'), dots = Array.from(svg.querySelectorAll('.dot')), tip = host.querySelector('.chart-tip');
    const W = CHART_W, H = CHART_H, top = CHART_TOP, bottom = CHART_BOTTOM, plotH = H - top - bottom;
    const max = Math.max.apply(null, rows.flatMap((r) => r.values).concat([0])), yMax = max > 0 ? max * 1.06 : 1;
    const show = (ev) => {
      const r = svg.getBoundingClientRect();
      const fx = (ev.clientX - r.left) / r.width;
      const i = Math.max(0, Math.min(rows.length - 1, Math.round(fx * (rows.length - 1))));
      const px = rows.length === 1 ? W / 2 : (i / (rows.length - 1)) * W;
      xh.setAttribute('x1', px); xh.setAttribute('x2', px); xh.classList.remove('off');
      dots.forEach((d, k) => { const v = rows[i].values[k]; d.setAttribute('cx', px); d.setAttribute('cy', top + plotH - (v / yMax) * plotH); d.classList.toggle('off', !(v > 0)); });
      const parts = series.map((sr, k) => ({ sr, v: rows[i].values[k] })).filter((p) => p.v > 0).sort((a, b) => b.v - a.v).slice(0, 4);
      tip.innerHTML = `<b>${esc(fmt(rows[i].total))}</b><span>${esc(rows[i].date)}</span>${parts.length ? `<div class="rows">${parts.map((p) => `<span><i style="background:${p.sr.color}"></i>${esc(p.sr.label)}<b>${esc(fmt(p.v))}</b></span>`).join('')}</div>` : ''}`;
      tip.hidden = false;
      const tw = tip.offsetWidth, leftPx = Math.max(0, Math.min(r.width - tw, (px / W) * r.width - tw / 2));
      tip.style.left = leftPx + 'px';
    };
    const hide = () => { xh.classList.add('off'); dots.forEach((d) => d.classList.add('off')); tip.hidden = true; };
    svg.addEventListener('mousemove', show);
    svg.addEventListener('mouseleave', hide);
  }
  let chartBinding = null;

  /* ---- tabs ------------------------------------------------------------- */
  function viewOverview() {
    const live = data.live || {}, an7 = data.an7 || {}, eng = data.engines, us = (data.ausage && data.ausage.usage) || null;
    const today = live.requestsToday || 0;
    const avg7 = (an7.totalRequests || 0) / 7;
    const pToday = live.piiFindingsToday || 0;
    const pAvg = (an7.piiFindings || 0) / 7;
    const plan = us && us.plan;
    const active = us && Array.isArray(us.blocks) ? us.blocks.find((b) => b.isActive && !b.isGap) : null;

    const g1 = gauge({ label: 'Requests', value: compact(today), frac: avg7 > 0 ? today / (2 * avg7) : (today > 0 ? 0.5 : 0), sev: 'brand', sub: avg7 > 0 ? 'today · avg ' + compact(avg7) + '/day' : (today ? 'today · first day' : 'nothing routed yet'), title: 'Proxied requests since midnight; the arc compares against twice the 7-day daily average.' });
    const pSev = pToday === 0 ? 'brand' : (pToday > Math.max(2, 2 * pAvg) ? 'danger' : 'warn');
    const g2 = gauge({ label: 'Leaks caught', value: compact(pToday), frac: pAvg > 0 ? pToday / (2 * pAvg) : (pToday > 0 ? 0.6 : 0), sev: pSev, sub: pToday === 0 ? 'none today' : 'today · avg ' + compact(pAvg) + '/day', title: 'PII findings in today’s traffic (hashed spans only; the raw values are never stored).' });
    let g3;
    if (plan && plan.blockCostAllowanceUsd > 0) {
      const f = plan.usedFraction || 0;
      g3 = gauge({ label: 'Block spend', value: money(plan.spentUsd), frac: f, sev: f < 0.7 ? 'brand' : f < 1 ? 'warn' : 'danger', sub: '/ ' + money(plan.blockCostAllowanceUsd) + ' · ' + durShort(plan.resetsInMs) + ' left', title: 'Estimated cost of the current 5-hour billing block vs the plan allowance (' + plan.plan + ').' });
    } else if (active) {
      g3 = gauge({ label: 'Block spend', value: money(active.totals && active.totals.costUsd), frac: 0, sev: 'brand', sub: 'no plan baseline yet', title: 'Estimated cost of the current 5-hour block. Set a plan in Settings for an allowance.' });
    } else {
      g3 = gauge({ label: 'Block spend', value: '·', frac: 0, sev: 'brand', sub: 'no usage today', title: 'Coding-agent spend, priced on-device.' });
    }

    // Engine + exposure line
    let engineHtml = '';
    if (eng && Array.isArray(eng.engines)) {
      const a = eng.engines.find((e) => e.isActive) || eng.engines[0];
      const exposed = eng.exposure && eng.exposure.exposed;
      engineHtml = `<div class="card tight"><div class="row" style="padding:2px 0;border:0">
        <span class="muted" style="width:16px;height:16px;flex:none">${ICON.engine}</span>
        <div class="main"><div class="t">${a ? esc(a.engine + (a.version ? ' ' + a.version : '')) : 'No engine detected'}</div>
        <div class="s">${a ? esc((a.health || 'unknown') + ' · :' + a.publicPort) : 'No engine running'}</div></div>
        ${exposed ? chip('danger', 'network-reachable') : chip('ok', 'localhost only')}
      </div></div>`;
    }

    // Recent activity
    const recent = Array.isArray(live.recent) ? live.recent.slice(0, 4) : [];
    const rows = recent.length ? recent.map((r) => {
      const secret = (r.piiKinds || []).some((k) => SECRET_KINDS.includes(k));
      return `<div class="row clickable" data-route="#/history">
        <div class="main"><div class="t">${esc(r.sourceApp || 'unknown app')} <span class="muted">→</span> ${esc(r.model || r.endpoint || '·')}</div>
        <div class="s">${esc(ago(r.ts))}${r.latencyMs != null ? ' · ' + compact(r.latencyMs) + ' ms' : ''}${r.outputTokens != null ? ' · ' + compact(r.outputTokens) + ' tok out' : ''}${r.status && r.status >= 400 ? ' · failed' : ''}</div></div>
        ${r.piiCount > 0 ? chip(secret ? 'gold' : 'danger', r.piiCount + ' PII') : (r.safetyFlagged ? chip('warn', 'flagged') : '')}
      </div>`;
    }).join('') : '<div class="empty">No requests yet</div>';

    // Suggestions from analytics insights
    const insights = Array.isArray(an7.insights) ? an7.insights.slice(0, 2) : [];
    const sugg = insights.length ? insights.map((ins) => {
      const sev = /danger|high|critical/i.test(ins.severity) ? 'danger' : /warn|medium/i.test(ins.severity) ? 'warn' : 'info';
      return `<div class="alert ${sev}"><div class="head"><h4>${esc(ins.title)}</h4>${sev === 'danger' ? chip('danger', 'urgent') : sev === 'warn' ? chip('warn', 'attention') : ''}</div><p>${esc(ins.detail)}</p><div class="row-actions"><button class="btn sm" data-route="#/analytics">Open analytics</button></div></div>`;
    }).join('') : '';

    return `<div class="gauges">${g1}${g2}${g3}</div>
      ${engineHtml}
      ${lbl('Now', { label: 'Live', route: '#/live' })}<div class="rows">${rows}</div>
      ${sugg ? lbl('Suggestions', { label: 'All', route: '#/analytics' }) + sugg : ''}`;
  }

  function viewKeep() {
    const ag = data.agents, ver = data.verify, st = data.settings || {};
    if (!ag) return pending('agents', 'preservation status');
    const ar = ag.archive || {};
    const atRisk = (ag.atRisk || []).filter((r) => r.total > 0 || r.expiringSoon > 0 || r.overdue > 0);
    const tools = (ag.tools || []).filter((t) => t.present).sort((a, b) => b.sessions - a.sessions);

    let integrity = '';
    if (ver) {
      integrity = ver.intact
        ? chip('ok', 'chain intact · ' + compact(ver.entries) + ' entries')
        : chip('danger', 'tampering detected');
    }
    const hero = ar.enabled === false
      ? `<div class="card warn"><h4>Preservation is off</h4><p>Sessions live only as long as each tool keeps them.</p><div class="row-actions"><button class="btn sm primary" data-act="preserve" ${busy.preserve ? 'disabled' : ''}>${busy.preserve ? 'Turning on…' : 'Turn on'}</button></div></div>`
      : `<div class="hero"><span class="big">${compact(ar.count)}</span><span class="unit">sessions preserved</span></div>
         <div class="small dim">${compact(ar.messages)} messages · ${bytes(ar.dbBytes)} on disk · ${ar.auto ? 'preserving automatically' : 'auto-preserve off'}</div>
         <div class="chips" style="margin-top:6px" title="${esc(ver && ver.proofStatement || '')}">${integrity}${ag.totalSessions != null ? chip('', compact(ag.totalSessions) + ' on disk across ' + tools.length + ' tools') : ''}</div>`;

    const hot = atRisk.filter((r) => r.overdue > 0 || r.expiringSoon > 0);
    const safe = atRisk.filter((r) => !(r.overdue > 0 || r.expiringSoon > 0));
    const aging = (hot.length ? hot.map((r) => {
      const right = r.overdue > 0 ? chip('danger', r.overdue + ' overdue') : chip('warn', r.expiringSoon + ' expiring');
      const soon = r.soonestExpiryTs ? ' · next ' + days(r.soonestExpiryTs - Date.now()) : '';
      return `<div class="row"><div class="main"><div class="t">${esc(r.label)}</div><div class="s">${r.days ? 'deleted after ' + r.days + ' days' : esc(r.note || '')}${esc(soon)} · not preserved</div></div>${right}</div>`;
    }).join('') : '<div class="empty">Nothing is close to its deletion line</div>')
      + (safe.length ? `<div class="row"><div class="main"><div class="t dim">${safe.length} tool${safe.length === 1 ? '' : 's'} safe</div><div class="s">${esc(safe.map((r) => r.label).join(' · '))}</div></div>${chip('ok', 'safe')}</div>` : '');

    const toolChips = tools.slice(0, 8).map((t) => chip('', t.label + ' ' + compact(t.sessions))).join('') + (tools.length > 8 ? chip('', '+' + (tools.length - 8)) : '');

    // One action: Back up = preserve anything new, then export the archive to
    // the chosen folder. Only offered while the archive has changed since the
    // last backup.
    const needs = ar.changedSinceBackup || (!ar.lastBackupTs && ar.count > 0);
    const backupBtn = busy.backup
      ? `<button class="btn primary sm" disabled>${ICON.backup} Backing up…</button>`
      : needs
        ? `<button class="btn primary sm" data-act="backup">${ICON.backup} Back up</button>`
        : `<button class="btn sm" disabled title="Nothing changed since the last backup">${ICON.check} Backed up${ar.lastBackupTs ? ' · ' + ago(ar.lastBackupTs) : ''}</button>`;
    const backupLine = ar.lastBackupTs
      ? `Last backup ${ago(ar.lastBackupTs)}${ar.lastBackupDir ? ' · ' + esc(shortPath(ar.lastBackupDir)) : ''}`
      : (ar.count > 0 ? 'Never backed up' : '');
    return `${hero}
      ${lbl('Aging · at risk', { label: 'Agents', route: '#/agents' })}<div class="rows">${aging}</div>
      ${tools.length ? lbl('Tools found') + `<div class="chips">${toolChips}</div>` : ''}
      <div class="row-actions" style="margin:0;align-items:center">${backupBtn}<span class="small muted" style="margin-left:4px">${backupLine}</span></div>
      <div class="row" style="border-top:1px solid var(--divider);margin-top:2px"><div class="main"><div class="s">Backup folder</div><div class="t mono" style="font-size:11.5px" title="${esc(st.exportDirEffective || '')}">${esc(shortPath(st.exportDirEffective || '~'))}</div></div><button class="btn sm" data-cmd="choose_export_dir" ${busy.chooseDir ? 'disabled' : ''}>Change…</button></div>`;
  }

  function viewPrivacy() {
    const pv = data.privacy, live = data.live || {}, ap = data.aprivacy, st = data.settings || {};
    if (!pv) return pending('privacy', 'privacy');
    const on = !!st.maskingEnabled, dry = !!st.maskingDryRun;
    const posture = !on ? { cls: '', t: 'Observe only', p: 'Nothing is redacted.' }
      : dry ? { cls: 'warn', t: 'Dry-run masking', p: 'Traffic passes unchanged.' }
      : { cls: 'ok', t: 'Live redaction', p: 'PII is redacted both ways.' };
    const blocks = Array.isArray(st.maskingBlockKinds) && st.maskingBlockKinds.length ? ' Blocking ' + st.maskingBlockKinds.map(piiLabel).join(', ') + '.' : '';
    const kinds = (pv.byKind || []).slice().sort((a, b) => b.count - a.count).slice(0, 6).map((k) => ({ label: piiLabel(k.kind), value: k.count, cls: SECRET_KINDS.includes(k.kind) ? 'danger' : '' }));

    return `<div class="card ${posture.cls}"><div class="head" style="display:flex;align-items:center;gap:8px"><span class="muted" style="width:16px;height:16px">${ICON.shield}</span><h4 style="flex:1;margin:0">${esc(posture.t)}</h4>${st.policy ? chip('', 'team policy') : ''}</div><p>${esc(posture.p + blocks)}</p><div class="row-actions"><button class="btn sm" data-route="#/settings">Settings</button></div></div>
      <div class="stats">${stat('Today', compact(live.piiFindingsToday || 0), 'in traffic')}${stat('All time', compact(pv.total || 0), 'findings')}</div>
      ${lbl('By kind · all time', { label: 'Report', route: '#/analytics/privacy' })}${bars(kinds, compact)}
      ${ap ? `<div class="card tight"><div class="row" style="border:0;padding:2px 0"><div class="main"><div class="t">${compact(ap.highSignalFindings)} in preserved transcripts</div><div class="s">${compact(ap.sessionsWithFindings)} sessions</div></div><button class="btn sm ghost" data-route="#/analytics/privacy">Open</button></div></div>` : ''}`;
  }

  function viewSpend() {
    const au = data.ausage, ag = data.agents, an7 = data.an7 || {};
    if (!au) return pending('ausage', 'spend');
    const us = au.usage;
    const monthly = us && us.monthly && us.monthly.length ? us.monthly[us.monthly.length - 1] : null;
    const today = us && us.daily ? us.daily.find((d) => d.date === todayUtc()) : null;
    const active = us && Array.isArray(us.blocks) ? us.blocks.find((b) => b.isActive && !b.isGap) : null;
    const plan = us && us.plan;
    const byTool = ((ag && ag.tools) || []).filter((t) => t.present && t.costUsd > 0).sort((a, b) => b.costUsd - a.costUsd).slice(0, 4).map((t) => ({ label: t.label, value: t.costUsd }));

    const heroHtml = `<div class="hero"><span class="big">${money(monthly ? monthly.totals.costUsd : au.totalCostUsd)}</span><span class="unit">${monthly ? 'this month (' + esc(monthly.month) + ')' : 'all time · coding agents'}</span></div>
      <div class="small dim">${today ? money(today.totals.costUsd) + ' today · ' : ''}${compact(au.totalTokens)} tokens · ${compact(au.totalSessions)} sessions</div>`;

    let block = '';
    if (active) {
      const b = active.burn || {};
      const f = plan && plan.blockCostAllowanceUsd > 0 ? (plan.usedFraction || 0) : null;
      block = `${lbl('Current 5-hour block', { label: 'Usage', route: '#/analytics/usage' })}
        <div class="stats four">${stat('Cost', money(active.totals.costUsd))}${stat('$ / hour', money(b.costPerHour))}${stat('tok/min', compact(b.tokensPerMinute))}${stat('Proj.', money(b.projectedCostUsd))}</div>
        ${f != null ? `<div class="card tight"><div class="row" style="border:0;padding:0"><div class="main"><div class="t">${Math.round(f * 100)}% of the ${esc(plan.plan)} allowance</div><div class="s">${money(plan.spentUsd)} of ${money(plan.blockCostAllowanceUsd)} · resets in ${dur(plan.resetsInMs)}</div></div></div><div class="progress ${f >= 1 ? 'danger' : f >= 0.7 ? 'warn' : ''}"><div class="fill" style="width:${Math.min(100, f * 100).toFixed(0)}%"></div></div></div>` : ''}`;
    } else {
      block = `${lbl('Current 5-hour block')}<div class="empty">Nothing in the last 5 hours</div>`;
    }

    const saved = an7.estCostSavedUsd != null ? `<div class="card tight"><div class="row" style="border:0;padding:2px 0"><div class="main"><div class="t">≈ ${money(an7.estCostSavedUsd)} kept local this week</div><div class="s">vs ${esc(an7.costBasis || 'cloud pricing')}</div></div></div></div>` : '';

    // Daily stacked-by-tool chart (last 30 days), Cost or Tokens.
    const st = stackedSeries(au, spendMode);
    const fmt = spendMode === 'tokens' ? compact : money;
    chartBinding = { series: st.series, rows: st.rows, fmt };
    const legend = st.series.length ? `<span class="legend inline">${st.series.map((sr) => `<span><i style="background:${sr.color}"></i>${esc(sr.label)}</span>`).join('')}</span>` : '';
    const chart = `<div class="lbl chart-head">Daily ${spendMode === 'tokens' ? 'tokens' : 'cost'}<span class="spacer"></span>
        <span class="seg" role="group" aria-label="Chart measure"><button class="${spendMode === 'cost' ? 'on' : ''}" data-mode="cost">Cost</button><button class="${spendMode === 'tokens' ? 'on' : ''}" data-mode="tokens">Tokens</button></span>${legend}</div>
      <div class="chart-flat">${stackedChart(st.series, st.rows, fmt)}</div>`;

    return `${heroHtml}${chart}${block}
      ${byTool.length ? lbl('By tool', { label: 'Agents', route: '#/agents' }) + bars(byTool, money) : ''}
      ${saved}`;
  }

  function viewAlerts() {
    const alerts = deriveAlerts();
    const list = alerts.length ? alerts.map(alertCard).join('') : `<div class="card ok"><div class="head" style="display:flex;gap:8px;align-items:center"><span style="width:16px;height:16px">${ICON.check}</span><h4 style="margin:0">All quiet</h4></div><p>Nothing needs you.</p></div>`;
    return list;
  }

  function governed(st, field) {
    const pol = st && st.policy;
    return !!(pol && pol.active && Array.isArray(pol.governs) && pol.governs.includes(field));
  }

  function settingSwitch(field, on, disabled, label) {
    return `<button class="switch ${on ? 'on' : ''}" role="switch" aria-checked="${on ? 'true' : 'false'}" aria-label="${esc(label)}" data-setting="${field}" data-next="${on ? 'false' : 'true'}" ${disabled || busy.settings ? 'disabled' : ''}><span></span></button>`;
  }

  function settingRow(title, detail, control) {
    return `<div class="setting-row"><div class="setting-copy"><div class="setting-title">${esc(title)}</div><div class="setting-detail">${esc(detail)}</div></div>${control}</div>`;
  }

  function viewSettings() {
    const st = data.settings;
    if (!st) return pending('settings', 'settings');
    const maskLocked = governed(st, 'masking.enabled');
    const dryLocked = governed(st, 'masking.dry_run');
    const archiveOn = !!st.archiveEnabled;
    const maskingOn = !!st.maskingEnabled;
    const themeChoice = theme || 'system';
    const policyNote = maskLocked || dryLocked
      ? `<div class="note policy-note">Some privacy controls are managed by your team policy.</div>`
      : '';

    return `<div class="settings-heading"><div><h3>Quick settings</h3><p>Saved until you change them.</p></div><button class="link" data-route="#/settings">Advanced settings ↗</button></div>
      <div class="settings-group">
        ${lbl('Startup')}
        ${settingRow('Open at login', 'Start quietly in the menu bar after you sign in.', settingSwitch('loginEnabled', !!host.loginEnabled, false, 'Open at login'))}
      </div>
      <div class="settings-group">
        ${lbl('Preservation')}
        ${settingRow('Preserve sessions', 'Keep a durable local copy of coding-agent history.', settingSwitch('archiveEnabled', archiveOn, false, 'Preserve sessions'))}
        ${settingRow('Preserve automatically', archiveOn ? 'Snapshot on start and periodically.' : 'Turn on preservation first.', settingSwitch('archiveAuto', !!st.archiveAuto, !archiveOn, 'Preserve automatically'))}
      </div>
      <div class="settings-group">
        ${lbl('Privacy')}
        ${settingRow('PII masking', maskLocked ? 'Managed by your team policy.' : (maskingOn ? 'On. Detected PII enters the masking pipeline.' : 'Off. Saffev observes but does not alter traffic.'), settingSwitch('maskingEnabled', maskingOn, maskLocked, 'PII masking'))}
        ${settingRow('Dry-run first', dryLocked ? 'Managed by your team policy.' : (!maskingOn ? 'Turn on masking first.' : (st.maskingDryRun ? 'Traffic stays unchanged while matches are recorded.' : 'Off. Matching PII is redacted before forwarding.')), settingSwitch('maskingDryRun', !!st.maskingDryRun, !maskingOn || dryLocked, 'Masking dry-run'))}
        ${policyNote}
      </div>
      <div class="settings-group">
        ${lbl('Appearance')}
        <div class="setting-row"><div class="setting-copy"><div class="setting-title">Panel theme</div><div class="setting-detail">System follows your current macOS appearance.</div></div>
          <div class="seg theme-seg" role="group" aria-label="Panel theme">
            <button class="${themeChoice === 'system' ? 'on' : ''}" data-theme-choice="system">System</button>
            <button class="${themeChoice === 'light' ? 'on' : ''}" data-theme-choice="light">Light</button>
            <button class="${themeChoice === 'dark' ? 'on' : ''}" data-theme-choice="dark">Dark</button>
          </div>
        </div>
      </div>`;
  }

  /* ---- render ----------------------------------------------------------- */
  function renderHeader() {
    $('#appName').textContent = host.appName || 'Saffev';
    const st = $('#status');
    const s = host.status || 'stopped';
    st.className = 'status ' + (s === 'running' && stale ? 'stale' : s);
    $('#statusText').textContent = s === 'running' ? (stale ? 'Reconnecting…' : 'Running') : (host.statusText || s);
    const pin = $('#btnPin');
    pin.innerHTML = ICON.pin;
    pin.setAttribute('aria-pressed', host.pinned ? 'true' : 'false');
    pin.title = host.pinned ? 'Unpin (close when clicking away)' : 'Keep the panel open';
    const settings = $('#btnSettings');
    settings.innerHTML = ICON.settings;
    settings.setAttribute('aria-pressed', settingsOpen ? 'true' : 'false');
    settings.title = settingsOpen ? 'Back to ' + TABS.find((t) => t.id === tab).label : 'Quick settings';
  }
  function renderTabs() {
    const alerts = deriveAlerts();
    const hot = alerts.filter((a) => a.sev !== 'info').length;
    const dangerN = alerts.filter((a) => a.sev === 'danger').length;
    $('#tabs').innerHTML = TABS.map((t) => `<button class="tab" role="tab" id="tab-${t.id}" data-tab="${t.id}" aria-selected="${!settingsOpen && t.id === tab}">${t.icon}<span>${t.label}</span>${t.id === 'alerts' && hot ? `<span class="badge ${dangerN ? 'danger' : ''}">${hot}</span>` : ''}</button>`).join('');
  }
  function renderBody() {
    const body = $('#body');
    let html;
    if (failed.auth) html = '<div class="card danger"><h4>Not authorized</h4><p>Restart the service and reopen.</p></div>';
    else if (host.running === false && !data.live) html = '<div class="empty">The service is stopped.</div>';
    else if (settingsOpen) html = viewSettings();
    else html = tab === 'overview' ? viewOverview() : tab === 'keep' ? viewKeep() : tab === 'privacy' ? viewPrivacy() : tab === 'spend' ? viewSpend() : viewAlerts();
    const scroll = body.scrollTop;
    body.innerHTML = `<div class="fade">${html}</div>`;
    body.scrollTop = scroll;
    if (tab === 'spend' && chartBinding) bindChart(chartBinding.series, chartBinding.rows, chartBinding.fmt);
  }
  function renderFooter() {
    const running = host.status === 'running';
    const starting = host.status === 'starting';
    $('#foot').innerHTML = `
      ${running ? `<button class="btn ghost" data-cmd="stop" title="Stop the proxy + Studio (the app stays in the menu bar)">${ICON.stop} Stop</button>` : `<button class="btn primary" data-cmd="start" ${starting ? 'disabled' : ''}>${ICON.play} ${starting ? 'Starting…' : 'Start'}</button>`}
      <button class="iconbtn" data-cmd="restart" title="Restart the service" aria-label="Restart" ${running ? '' : 'disabled'}>${ICON.restart}</button>
      <button class="iconbtn" data-cmd="logs" title="Open the daemon log" aria-label="Open logs">${ICON.logs}</button>
      <button class="iconbtn ${host.loginEnabled ? 'on' : ''}" data-cmd="toggle_login" title="${host.loginEnabled ? 'Opens at login · click to disable' : 'Open at login'}" aria-label="Open at login" aria-pressed="${host.loginEnabled ? 'true' : 'false'}">${ICON.login}</button>
      <button class="iconbtn" data-cmd="toggle_theme" title="${effectiveTheme() === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}" aria-label="Toggle light or dark mode">${effectiveTheme() === 'dark' ? ICON.sun : ICON.moon}</button>
      <span class="ver">${host.version ? 'v' + esc(host.version) : ''}</span>
      <span class="spacer"></span>
      <button class="iconbtn" data-cmd="quit" title="Quit the menu-bar app (the service keeps running)" aria-label="Quit">${ICON.quit}</button>`;
  }
  function render() {
    renderHeader();
    renderTabs();
    renderBody();
    renderFooter();
    reportHeight();
  }

  /* ---- notices ---------------------------------------------------------- */
  function notice(n) {
    const el = $('#notice');
    clearTimeout(noticeTimer);
    if (!n) { el.hidden = true; return; }
    el.className = 'notice ' + (n.kind || '');
    el.innerHTML = `${n.kind === 'busy' ? '<span class="spin"></span>' : ''}<b>${esc(n.title)}</b><span>${esc(n.detail || '')}</span>`;
    el.hidden = false;
    if (n.kind === 'ok' || n.kind === 'error') {
      const wasBackup = busy.backup;
      busy.backup = false; busy.preserve = false; renderBody(); renderTabs();
      if (wasBackup) load(['agents', 'verify'], true);
      noticeTimer = setTimeout(() => { el.hidden = true; reportHeight(); }, n.kind === 'error' ? 9000 : 5000);
    }
    reportHeight();
  }

  /* ---- actions ---------------------------------------------------------- */
  async function preserveNow() {
    if (busy.preserve) return;
    busy.preserve = true; renderBody();
    notice({ kind: 'busy', title: 'Preserving…', detail: '' });
    try {
      const ag = data.agents;
      if (ag && ag.archive && ag.archive.enabled === false) {
        // One click: turn preservation on (with auto snapshots) and run.
        await api('/settings', { method: 'PUT', body: { archiveEnabled: true, archiveAuto: true } });
      }
      const r = await api('/archive/run', { method: 'POST' });
      const n = r && (r.archived != null ? r.archived : r.sessions != null ? r.sessions : r.count);
      notice({ kind: 'ok', title: 'Preserved', detail: n != null ? n + ' session(s) written' : 'Up to date' });
      await load(['agents', 'verify', 'settings'], true);
    } catch (e) {
      notice({ kind: 'error', title: 'Preserve failed', detail: e.message || String(e) });
    }
    busy.preserve = false; renderBody();
  }

  // Back up = make sure everything new is in the archive, then hand the
  // export to the host (it runs `saffev backup` and reveals the folder).
  async function backupNow() {
    if (busy.backup) return;
    busy.backup = true; renderBody();
    notice({ kind: 'busy', title: 'Backing up…', detail: '' });
    try {
      const ag = data.agents;
      if (ag && ag.archive && ag.archive.enabled === false) {
        await api('/settings', { method: 'PUT', body: { archiveEnabled: true, archiveAuto: true } });
      }
      await api('/archive/run', { method: 'POST' });
    } catch (e) {
      busy.backup = false;
      notice({ kind: 'error', title: 'Backup failed', detail: e.message || String(e) });
      renderBody();
      return;
    }
    ipc({ cmd: 'backup' });
  }

  async function updateSetting(field, next) {
    if (busy.settings) return;
    if (field === 'loginEnabled') {
      ipc({ cmd: 'set_login', enabled: next });
      return;
    }
    if (field === 'maskingDryRun' && next === false) {
      const ok = window.confirm('Turn off dry-run? Detected PII will be redacted from requests and responses before they are forwarded.');
      if (!ok) return;
    }
    busy.settings = true; renderBody();
    try {
      const body = {}; body[field] = next;
      data.settings = await api('/settings', { method: 'PUT', body });
      fetchedAt.settings = Date.now();
      notice({ kind: 'ok', title: 'Setting saved', detail: 'Applied now and retained after restart.' });
    } catch (e) {
      notice({ kind: 'error', title: 'Setting not saved', detail: e.message || String(e) });
      await load(['settings'], true);
    }
    busy.settings = false; render();
  }

  document.addEventListener('click', (ev) => {
    const t = ev.target.closest('[data-tab],[data-route],[data-cmd],[data-act],[data-dismiss],[data-mode],[data-setting],[data-theme-choice]');
    if (!t) return;
    if (t.dataset.themeChoice) { setTheme(t.dataset.themeChoice); return; }
    if (t.dataset.setting) { updateSetting(t.dataset.setting, t.dataset.next === 'true'); return; }
    if (t.dataset.mode) { spendMode = t.dataset.mode; renderBody(); return; }
    if (t.dataset.tab) {
      tab = t.dataset.tab;
      settingsOpen = false;
      try { localStorage.setItem('saffev.panel.tab', tab); } catch (e) { /* storage blocked */ }
      render();
      refresh(false);
      return;
    }
    if (t.dataset.route != null) { ipc({ cmd: 'open', route: t.dataset.route }); return; }
    if (t.dataset.dismiss) { dismissed.add(t.dataset.dismiss); render(); return; }
    if (t.dataset.act === 'preserve') { preserveNow(); return; }
    if (t.dataset.act === 'backup') { backupNow(); return; }
    const cmd = t.dataset.cmd;
    if (cmd === 'toggle_login') { ipc({ cmd: 'set_login', enabled: !host.loginEnabled }); return; }
    if (cmd === 'toggle_theme') { toggleTheme(); return; }
    if (cmd === 'choose_export_dir') { busy.chooseDir = true; renderBody(); ipc({ cmd: 'choose_export_dir' }); return; }
    if (cmd === 'backup') { backupNow(); return; }
    if (cmd) ipc({ cmd });
  });
  $('#btnOpen').addEventListener('click', () => ipc({ cmd: 'open', route: '' }));
  $('#btnSettings').addEventListener('click', () => {
    settingsOpen = !settingsOpen;
    render();
    if (settingsOpen) load(['settings'], true);
    else refresh(false);
  });
  $('#btnPin').addEventListener('click', () => { host.pinned = !host.pinned; ipc({ cmd: 'set_pinned', pinned: host.pinned }); renderHeader(); });
  // Inside the tray's webview the WebKit context menu (Reload / Back…) is
  // noise on a widget; a plain browser tab keeps it.
  if (window.ipc) document.addEventListener('contextmenu', (e) => e.preventDefault());
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { ipc({ cmd: 'close' }); return; }
    const n = parseInt(e.key, 10);
    if ((e.metaKey || e.ctrlKey) && n >= 1 && n <= TABS.length) { tab = TABS[n - 1].id; settingsOpen = false; render(); refresh(false); e.preventDefault(); }
  });

  /* ---- height reporting ------------------------------------------------- */
  let heightRaf = null;
  function reportHeight() {
    if (heightRaf) cancelAnimationFrame(heightRaf);
    heightRaf = requestAnimationFrame(() => {
      heightRaf = null;
      const p = $('#panel');
      if (p) ipc({ cmd: 'resize', height: p.offsetHeight + 30 });
    });
  }
  if (window.ResizeObserver) new ResizeObserver(() => reportHeight()).observe($('#panel'));

  /* ---- host hooks ------------------------------------------------------- */
  window.__saffevHost = {
    setState(s) {
      const was = host.status;
      host = Object.assign({}, host, s || {});
      renderHeader(); renderFooter(); renderTabs();
      if (was !== host.status && host.status === 'running') refresh(true);
      if (settingsOpen || tab === 'alerts') renderBody();
    },
    onShow() { visible = true; refresh(true); startPolling(); },
    onHide() { visible = false; stopPolling(); },
    notice,
    // The host's native folder picker returned (null = cancelled). Save it as
    // the export destination; the Studio validates it (exists, writable).
    async exportDirChosen(path) {
      busy.chooseDir = false;
      if (!path) { renderBody(); return; }
      try {
        await api('/settings', { method: 'PUT', body: { exportDir: path } });
        notice({ kind: 'ok', title: 'Saved', detail: shortPath(path) });
        await load(['settings'], true);
      } catch (e) {
        notice({ kind: 'error', title: 'Not saved', detail: e.message || String(e) });
        renderBody();
      }
    },
  };

  /* ---- boot ------------------------------------------------------------- */
  render();
  ipc({ cmd: 'ready' });
  if (theme) ipc({ cmd: 'set_theme', theme });
  refresh(true).then(() => { firstPaint = false; });
  startPolling();
})();
