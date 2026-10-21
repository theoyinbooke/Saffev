/* =============================================================================
   Saffev menu-bar panel — app logic.

   Runs inside the tray app's WKWebView, served by the Studio (same origin, token
   injected as window.__SAFFEV_TOKEN__). Everything it shows comes from the
   existing /api/* endpoints; nothing is computed server-side for it.

   Four tabs (Today · Keep · Privacy · Spend) share one small component set
   (tile · row · head · chip · button · segmented · switch, see menubar.css).
   Alerts and Settings open as sub-pages with a back button.

   Host protocol (see src/cli/tray_panel.rs):
     page → host : window.ipc.postMessage(JSON.stringify({cmd, ...}))
     host → page : window.__saffevHost.setState(state) / onShow() / onHide() /
                   notice({kind,title,detail,revealPath}) / exportDirChosen(path)
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
    if (Math.abs(n) >= 1e4) return (n / 1e3).toFixed(0) + 'k';
    if (Math.abs(n) >= 1e3) return (n / 1e3).toFixed(1) + 'k';
    return Number.isInteger(n) ? n.toLocaleString('en-US') : n.toFixed(1);
  };
  const full = (n) => (n == null || isNaN(n) ? '·' : Math.round(Number(n)).toLocaleString('en-US'));
  const money = (v) => {
    if (v == null || isNaN(v)) return '·';
    v = Number(v);
    if (v === 0) return '$0';
    if (v > 0 && v < 0.01) return '<$0.01';
    if (v < 10) return '$' + v.toFixed(2);
    return '$' + Math.round(v).toLocaleString('en-US');
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
  const agoShort = (ts) => {
    if (!ts) return '';
    const d = Date.now() - ts;
    if (d < 45e3) return 'now';
    if (d < 3600e3) return Math.round(d / 60e3) + 'm';
    if (d < 86400e3) return Math.round(d / 3600e3) + 'h';
    return Math.round(d / 86400e3) + 'd';
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
  const inDays = (ms) => {
    if (ms == null) return '';
    const d = Math.ceil(ms / 86400e3);
    return d <= 0 ? 'today' : d === 1 ? '1 day' : d + ' days';
  };
  const clock = (ts) => {
    const d = new Date(ts), now = new Date();
    const hm = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    if (d.toDateString() === now.toDateString()) return hm;
    const tmr = new Date(now.getTime() + 86400e3);
    if (d.toDateString() === tmr.toDateString()) return 'tomorrow ' + hm;
    return d.toLocaleDateString([], { weekday: 'short' }) + ' ' + hm;
  };
  const todayUtc = () => new Date().toISOString().slice(0, 10);
  const shortPath = (p) => {
    if (!p) return '';
    const home = host.homeDir || '';
    let out = home && p.startsWith(home) ? '~' + p.slice(home.length) : p;
    out = out.replace('~/Library/Mobile Documents/com~apple~CloudDocs', 'iCloud Drive');
    const parts = out.split('/').filter(Boolean);
    if (out.length > 36 && parts.length > 2) out = (out.startsWith('/') ? '/' : '') + parts[0] + ' › … › ' + parts[parts.length - 1];
    else out = out.replace(/\//g, (m, i) => (i === 0 ? '/' : ' › ')).replace(/^\/ › /, '/');
    return out;
  };
  const monogram = (name) => {
    const w = String(name || '?').replace(/[^A-Za-z0-9 ]/g, ' ').trim().split(/\s+/).filter(Boolean);
    if (!w.length) return '?';
    if (w.length === 1) return w[0].slice(0, 2).replace(/^./, (c) => c.toUpperCase());
    return (w[0][0] + w[1][0]).toUpperCase();
  };
  const clamp = (x, a, b) => Math.max(a, Math.min(b, x));

  const PII_LABEL = {
    email: 'Emails', phone: 'Phone', credit_card: 'Card numbers', api_key: 'API keys', ip_address: 'IP address',
    private_key: 'Private keys', jwt: 'JWTs', connection_string: 'Conn. strings', ssn: 'SSNs', iban: 'IBANs',
    mac_address: 'MAC addresses', env_assignment: 'Env secrets', crypto_wallet: 'Wallets', custom: 'Custom',
  };
  const SECRET_KINDS = ['api_key', 'private_key', 'jwt', 'connection_string', 'env_assignment', 'credit_card', 'crypto_wallet'];
  const NOISY_KINDS = ['ip_address', 'phone'];
  const piiLabel = (k) => PII_LABEL[k] || String(k || '').replace(/_/g, ' ');
  const piiOne = (k) => piiLabel(k).replace(/s$/, '');

  /* ---- icons (stroke, currentColor) ------------------------------------- */
  const svg = (paths, extra) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" ${extra || ''}>${paths}</svg>`;
  const ICON = {
    bell: svg('<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/>'),
    open: svg('<path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>'),
    sliders: svg('<path d="M4 21v-7"/><path d="M4 10V3"/><path d="M12 21v-9"/><path d="M12 8V3"/><path d="M20 21v-5"/><path d="M20 12V3"/><path d="M1 14h6"/><path d="M9 8h6"/><path d="M17 16h6"/>'),
    back: svg('<path d="m15 18-6-6 6-6"/>', 'stroke-width="2"'),
    pin: svg('<path d="M12 17v5"/><path d="M9 3h6l-1 6 3 3H7l3-3-1-6Z"/>'),
    restart: svg('<path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5"/>'),
    logs: svg('<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6"/><path d="M8 13h8"/><path d="M8 17h5"/>'),
    power: svg('<path d="M12 2v10"/><path d="M18.4 6.6a9 9 0 1 1-12.8 0"/>'),
    play: '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M7 4.5v15l13-7.5z"/></svg>',
    pause: svg('<rect x="6" y="5" width="4" height="14" rx="1"/><rect x="14" y="5" width="4" height="14" rx="1"/>'),
    clock: svg('<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>', 'stroke-width="1.9"'),
    key: svg('<circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 9.3-9.3"/><path d="m16 7 3 3"/>', 'stroke-width="1.9"'),
    alert: svg('<path d="M12 3 2 20h20L12 3Z"/><path d="M12 10v4M12 17h.01"/>', 'stroke-width="1.9"'),
    info: svg('<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>', 'stroke-width="1.9"'),
    download: svg('<path d="M12 3v12"/><path d="m7 10 5 5 5-5"/><path d="M5 21h14"/>', 'stroke-width="1.9"'),
    check: svg('<path d="m5 12 5 5 9-10"/>', 'stroke-width="2.25"'),
    lock: svg('<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>', 'stroke-width="2"'),
    chip: svg('<rect x="4" y="4" width="16" height="16" rx="3"/><path d="M9 9h6v6H9z"/>'),
    shield: svg('<path d="M12 3 4 6v6c0 5 3.4 8.3 8 9 4.6-.7 8-4 8-9V6z"/>', 'stroke-width="1.9"'),
    drive: svg('<path d="M3 12h18"/><path d="M5.5 5h13l2.5 7v6a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1v-6z"/><path d="M7 16h.01"/><path d="M11 16h.01"/>', 'stroke-width="1.9"'),
    folder: svg('<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>'),
    archive: svg('<path d="M3 7h18v3H3z"/><path d="M5 10v9h14v-9"/><path d="M10 14h4"/>', 'stroke-width="1.9"'),
  };
  const MARK = '<svg viewBox="0 0 512 512" fill="currentColor" aria-hidden="true"><path d="M34 242H52C68 242 78 230 81 214L96 100C102 54 139 24 186 24H326C373 24 410 54 416 100L431 214C434 230 444 242 460 242H478V250H442C414 250 396 268 382 294C368 320 354 336 330 336C306 336 291 315 276 283L246 219C232 188 220 164 196 164C172 164 158 183 144 207C126 238 110 250 82 250H34Z"/><path d="M34 270H82C110 270 126 258 144 227C158 203 172 192 196 192C220 192 232 216 246 247L276 311C291 343 306 364 330 364C354 364 368 348 382 322C396 296 414 278 442 278H478V270H460C444 270 434 282 431 298L416 412C410 458 373 488 326 488H186C139 488 102 458 96 412L81 298C78 282 68 270 52 270Z"/></svg>';

  /* ---- state ------------------------------------------------------------ */
  const TABS = [
    { id: 'today', label: 'Today' },
    { id: 'keep', label: 'Keep' },
    { id: 'privacy', label: 'Privacy' },
    { id: 'spend', label: 'Spend' },
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
    today: ['live', 'an7', 'engines', 'ausage', 'agents', 'verify', 'update'],
    keep: ['agents', 'verify', 'settings'],
    privacy: ['privacy', 'live', 'aprivacy', 'settings'],
    spend: ['ausage', 'agents', 'an7'],
    alerts: ['live', 'an7', 'engines', 'agents', 'verify', 'update', 'settings'],
    settings: ['settings'],
  };
  const ALL = Object.keys(LOADERS);

  let host = { appName: 'Saffev', version: '', studioUrl: '', running: null, status: 'starting', statusText: 'Connecting…', loginEnabled: false, pinned: false };
  let tab = 'today';
  try { tab = localStorage.getItem('saffev.panel.tab') || 'today'; } catch (e) { /* storage blocked */ }
  if (tab === 'overview' || tab === 'alerts') tab = 'today';
  if (!TABS.some((t) => t.id === tab)) tab = 'today';
  // A sub-page over the tabs: null | 'alerts' | 'settings'.
  let page = null;
  // Inside the menu-bar app the page loads in a HIDDEN window (at launch and
  // after every service restart); it must not fetch or hold a stream until the
  // host says it is on screen (onShow). A plain browser tab is visible.
  let visible = !window.ipc;
  // Theme: '' follows the OS; 'light' / 'dark' is an explicit choice, kept per
  // viewer and echoed to the host so the offline card matches.
  let theme = '';
  try { theme = localStorage.getItem('saffev.panel.theme') || ''; } catch (e) { /* storage blocked */ }
  function applyTheme() {
    if (theme) document.documentElement.setAttribute('data-theme', theme);
    else document.documentElement.removeAttribute('data-theme');
  }
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
  applyTheme();
  let spendMode = 'cost';   // chart: 'cost' | 'tokens'
  const data = {};
  const failed = {};
  let stale = false;
  let pollTimer = null;
  let signals = [];           // live SSE signals seen while open (newest first)
  let dismissed = new Set();  // alert keys the user dismissed this session
  let busy = {};              // action → true while in flight
  let noticeTimer = null;

  /* ---- data ------------------------------------------------------------- */
  // Progressive: every endpoint paints as soon as it lands. A cold agent scan
  // can take seconds; the tiles must not wait for it.
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
  // Heavy endpoints are refreshed at most this often; only the cheap `live`
  // read polls every tick. The heaviest get longer: the integrity verdict
  // re-hashes the archive (the server reuses it while nothing changed), the
  // update check is a network call the server caches for hours, and the
  // privacy rollups only move when the archive does.
  const HEAVY_TTL = 45000;
  const TTL = { verify: 5 * 60000, update: 30 * 60000, privacy: 2 * 60000, aprivacy: 2 * 60000 };
  const fetchedAt = {};
  async function load(keys, force) {
    const uniq = Array.from(new Set(keys)).filter((k) => force || (!inflight[k] && (k === 'live' || !fetchedAt[k] || Date.now() - fetchedAt[k] > (TTL[k] || HEAVY_TTL))));
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
    const keys = all ? ALL : NEEDS[page || tab].concat(['live']);
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

    if (host.status === 'failed') push({ key: 'svc', sev: 'danger', title: 'Service failed to start', detail: 'The log has the cause', action: { label: 'Open logs', cmd: 'logs' } });

    if (ver && ver.intact === false) push({ key: 'integrity', sev: 'danger', title: 'Archive integrity broken', detail: ver.brokenAt || '', action: { label: 'Inspect', route: '#/agents' } });
    if (eng && eng.exposure && eng.exposure.exposed) push({ key: 'exposure', sev: 'danger', title: 'Engine reachable from the network', detail: eng.exposure.boundTo ? 'Bound to ' + eng.exposure.boundTo : '', action: { label: 'Engines', route: '#/engines' } });

    if (ag && Array.isArray(ag.atRisk)) {
      ag.atRisk.forEach((r) => {
        if (r.overdue > 0) push({ key: 'overdue:' + r.tool, sev: 'danger', title: r.overdue + ' ' + r.label + ' session' + (r.overdue === 1 ? '' : 's') + ' past the deletion line', detail: 'Not preserved', action: { label: 'Preserve', act: 'preserve' } });
        else if (r.expiringSoon > 0) push({ key: 'expiring:' + r.tool, sev: 'warn', title: r.expiringSoon + ' session' + (r.expiringSoon === 1 ? '' : 's') + ' expire' + (r.expiringSoon === 1 ? 's' : '') + (r.soonestExpiryTs ? ' in ' + inDays(r.soonestExpiryTs - Date.now()) : ' soon'), detail: r.label + ' · not preserved', action: { label: 'Preserve', act: 'preserve' } });
      });
      if (ag.archive && ag.archive.enabled === false) push({ key: 'archive-off', sev: 'warn', title: 'Preservation is off', detail: 'Sessions last as long as each tool keeps them', action: { label: 'Turn on', act: 'preserve' } });
      if (ag.archive && ag.archive.lastBackupError) push({ key: 'backup-error', sev: 'warn', title: 'Last backup failed', detail: ag.archive.lastBackupError, action: { label: 'Change folder', cmd: 'choose_export_dir' } });
    }
    if (live && live.piiFindingsToday > 0) push({ key: 'pii-today', sev: 'warn', title: live.piiFindingsToday + ' leak' + (live.piiFindingsToday === 1 ? '' : 's') + ' caught today', detail: 'In proxied traffic', action: { label: 'Review', route: '#/history' } });
    if (an7 && an7.failedRequests > 0) push({ key: 'failed', sev: 'info', title: an7.failedRequests + ' failed request' + (an7.failedRequests === 1 ? '' : 's') + ' this week', detail: '', action: { label: 'History', route: '#/history' } });
    if (an7 && Array.isArray(an7.insights)) {
      an7.insights.forEach((ins, i) => {
        const sev = /danger|high|critical/i.test(ins.severity) ? 'danger' : /warn|medium/i.test(ins.severity) ? 'warn' : 'info';
        push({ key: 'insight:' + i + ':' + ins.title, sev, title: ins.title, detail: ins.detail, action: { label: 'Analytics', route: '#/analytics' } });
      });
    }
    if (up && up.updateAvailable) push({ key: 'update', sev: 'info', title: 'Saffev ' + up.latestVersion + ' is available', detail: '', action: { label: 'Update', cmd: 'update' } });

    signals.forEach((s, i) => push({ key: 'signal:' + s.ts + ':' + i, sev: /exposure|spike|risk/i.test(s.kind || '') ? 'warn' : 'info', title: s.title || s.kind, detail: s.detail, ts: s.ts, live: true }));

    const rank = { danger: 0, warn: 1, info: 2 };
    out.sort((a, b) => (rank[a.sev] - rank[b.sev]) || ((b.ts || 0) - (a.ts || 0)));
    return out;
  }

  /* ---- components ------------------------------------------------------- */
  const chip = (cls, text, icon) => `<span class="chip ${cls || ''}">${icon || ''}${esc(text)}</span>`;
  const head = (title, aside) => `<div class="head"><h2>${esc(title)}</h2>${aside || ''}</div>`;
  const headLink = (label, route) => `<button class="link" data-route="${esc(route)}">${esc(label)}</button>`;
  const tile = (o) => `<div class="tile"${o.title ? ` title="${esc(o.title)}"` : ''}><span class="k">${esc(o.k)}</span><span class="v ${o.cls || ''}">${esc(o.v)}</span>${o.extra || ''}${o.s ? `<span class="s">${esc(o.s)}</span>` : ''}</div>`;
  const row = (o) => `<div class="row${o.click ? ' click' : ''}" ${o.click || ''}>${o.well != null ? `<span class="well ${o.wellCls || ''}">${o.well}</span>` : ''}${o.sw ? `<span class="sw" style="background:${o.sw}"></span>` : ''}<div class="main"><span class="t">${o.t}</span>${o.m ? `<span class="m">${esc(o.m)}</span>` : ''}</div>${o.trail || ''}</div>`;
  const actionAttrs = (a) => a.route != null ? `data-route="${esc(a.route)}"` : a.cmd ? `data-cmd="${esc(a.cmd)}"` : `data-act="${esc(a.act)}"`;
  const pending = (key, what) => failed[key]
    ? `<div class="card"><div class="err">${ICON.alert}<span>Couldn’t load ${esc(what)} · ${esc(failed[key].message || String(failed[key]))}</span></div></div>`
    : `<div class="loading"><span class="spin"></span>Loading ${esc(what)}…</div>`;
  const sevWell = { danger: 'danger', warn: 'warn', info: 'blue' };
  const sevIcon = (a) => /key|leak|PII/i.test(a.title) ? ICON.key : a.sev === 'info' ? (a.key === 'update' ? ICON.download : ICON.info) : a.sev === 'warn' ? ICON.clock : ICON.alert;

  /* ---- Today ------------------------------------------------------------ */
  function viewToday() {
    const live = data.live || {}, an7 = data.an7 || {}, eng = data.engines, us = (data.ausage && data.ausage.usage) || null;
    const today = live.requestsToday || 0;
    const ser = Array.isArray(an7.series) ? an7.series : [];
    const groups = [];
    if (ser.length) { const size = Math.max(1, Math.ceil(ser.length / 7)); for (let i = 0; i < ser.length; i += size) groups.push(ser.slice(i, i + size).reduce((a, b) => a + (b.requests || 0), 0)); }
    const gmax = Math.max(1, ...groups);
    const spark = groups.length > 1
      ? `<div class="spark" aria-hidden="true">${groups.map((g, i) => `<i class="${i === groups.length - 1 ? 'on' : ''}" style="height:${Math.max(2, Math.round((g / gmax) * 18))}px"></i>`).join('')}</div>`
      : '';
    const t1 = tile({ k: 'Requests', v: full(today), extra: spark, s: spark ? '' : (today ? 'today' : 'nothing routed yet'), title: 'Proxied requests since midnight; bars are the last 7 days' });

    const pToday = live.piiFindingsToday || 0;
    const pAvg = (an7.piiFindings || 0) / 7;
    const t2 = tile({ k: 'Leaks', v: full(pToday), cls: pToday > 0 ? 'danger' : '', s: pToday === 0 ? 'none today' : 'avg ' + compact(pAvg) + ' / day', title: 'PII found in today’s traffic (only hashes are stored)' });

    const plan = us && us.plan;
    const active = us && Array.isArray(us.blocks) ? us.blocks.find((b) => b.isActive && !b.isGap) : null;
    let t3;
    if (plan && plan.blockCostAllowanceUsd > 0) {
      const f = clamp(plan.usedFraction || 0, 0, 1);
      const cls = f >= 1 ? 'danger' : f >= 0.7 ? 'warn' : '';
      t3 = tile({ k: 'Block', v: money(plan.spentUsd), extra: `<span class="meter ${cls}"><i style="width:${(f * 100).toFixed(0)}%"></i></span>`, s: 'of ' + money(plan.blockCostAllowanceUsd) + ' · ' + dur(plan.resetsInMs) + ' left', title: 'Current 5-hour block vs the ' + plan.plan + ' allowance' });
    } else if (active) {
      t3 = tile({ k: 'Block', v: money(active.totals && active.totals.costUsd), s: 'no plan set', title: 'Current 5-hour block; set a plan in Studio for an allowance' });
    } else {
      t3 = tile({ k: 'Block', v: '$0', s: 'no usage now', title: 'Coding-agent spend, priced on this Mac' });
    }

    const top = deriveAlerts().find((a) => a.sev !== 'info' && a.action);
    const callout = top ? `<div class="callout ${top.sev === 'danger' ? 'danger' : ''}">
        <span class="well ${sevWell[top.sev]}">${sevIcon(top)}</span>
        <div class="main"><span class="t">${esc(top.title)}</span>${top.detail ? `<span class="m">${esc(top.detail)}</span>` : ''}</div>
        <button class="btn md ${top.sev === 'danger' ? 'danger' : 'warn'}" ${actionAttrs(top.action)} ${busy.preserve && top.action.act === 'preserve' ? 'disabled' : ''}>${esc(top.action.label)}</button>
      </div>` : '';

    const recent = Array.isArray(live.recent) ? live.recent.slice(0, 4) : [];
    const rows = recent.length ? recent.map((r) => {
      const kinds = r.piiKinds || [];
      const secret = kinds.find((k) => SECRET_KINDS.includes(k));
      const trail = r.piiCount > 0 ? chip('danger', secret ? piiOne(secret) : r.piiCount + ' PII')
        : r.status && r.status >= 400 ? chip('warn', 'failed')
        : r.safetyFlagged ? chip('warn', 'flagged') : '';
      const meta = [agoShort(r.ts), r.latencyMs != null ? compact(r.latencyMs) + ' ms' : '', r.outputTokens != null ? compact(r.outputTokens) + ' tok' : ''].filter(Boolean).join(' · ');
      return row({ well: esc(monogram(r.sourceApp || 'app')), t: `${esc(r.sourceApp || 'Unknown app')} <span class="arrow">→</span> ${esc(r.model || r.endpoint || '·')}`, m: meta, trail, click: 'data-route="#/history"' });
    }).join('') : '<div class="empty-row">No requests yet · point an app at the proxy</div>';

    let engine = '';
    if (eng && Array.isArray(eng.engines)) {
      const a = eng.engines.find((e) => e.isActive) || eng.engines[0];
      const exposed = eng.exposure && eng.exposure.exposed;
      engine = `<div class="inline">${ICON.chip}<span class="grow">${a ? esc(a.engine + (a.version ? ' ' + a.version : '') + ' · ' + (a.health || 'unknown')) : 'No engine running'}</span>${exposed ? `<span class="bad">${ICON.alert}Network-reachable</span>` : `<span class="ok">${ICON.lock}Local only</span>`}</div>`;
    }

    return `<div class="tiles">${t1}${t2}${t3}</div>
      ${callout}
      ${head('Live', headLink('History', '#/history'))}
      <div class="list">${rows}</div>
      ${engine}`;
  }

  /* ---- Keep ------------------------------------------------------------- */
  // One short line per tool; the source's own note is the fallback.
  const retentionLine = (r) => r.days ? 'Deletes after ' + r.days + ' days'
    : /keeps_all/i.test(r.kind) ? 'Keeps everything'
    : /churn/i.test(r.kind) ? 'Rotates old history'
    : (r.note || 'Retention unknown');
  const intervalLabel = (h) => h === 1 ? 'Hourly' : h === 24 ? 'Daily' : h === 168 ? 'Weekly' : 'Every ' + h + 'h';
  function viewKeep() {
    const ag = data.agents, ver = data.verify, st = data.settings || {};
    if (!ag) return pending('agents', 'preservation');
    const ar = ag.archive || {};

    let hero;
    if (ar.enabled === false) {
      hero = `<div class="card"><div class="row"><span class="well accent">${ICON.archive}</span><div class="main"><span class="t">Preservation is off</span><span class="m">Sessions last as long as each tool keeps them</span></div><button class="btn md primary" data-act="preserve" ${busy.preserve ? 'disabled' : ''}>${busy.preserve ? 'Turning on…' : 'Turn on'}</button></div></div>`;
    } else {
      const integrity = !ver || !ver.entries ? '' : ver.intact ? chip('ok', 'Chain intact', ICON.check) : chip('danger', 'Tampered', ICON.alert);
      hero = `<div class="hero">
          <div><div class="k">Preserved</div><div class="v"><b>${full(ar.count)}</b><span>session${ar.count === 1 ? '' : 's'}</span></div><div class="s">${compact(ar.messages)} messages · ${bytes(ar.dbBytes)}</div></div>
          <span title="${esc(ver && ver.proofStatement || '')}">${integrity}</span>
        </div>`;
    }

    const running = busy.backup || ar.backupRunning;
    const title = running ? 'Backing up…' : ar.lastBackupTs ? 'Backed up ' + ago(ar.lastBackupTs) : 'Not backed up yet';
    const kind = ar.lastBackupKind === 'incremental' ? 'Incremental' : ar.lastBackupKind === 'full' ? 'Full copy' : '';
    const meta = [kind, ar.nextBackupTs ? 'next ' + clock(ar.nextBackupTs) : (ar.backupAuto ? '' : 'automatic off')].filter(Boolean).join(' · ');
    const every = ar.backupAuto ? intervalLabel(ar.backupIntervalHours || 24) : 'Manual';
    let chain = '';
    if (ar.backupDepth != null && ar.backupFullEvery > 0) {
      const total = Math.min(ar.backupFullEvery + 1, 12), depth = Math.min(ar.backupDepth, total - 1);
      const segs = Array.from({ length: total }, (_, i) => `<i class="${i === 0 ? 'full' : i <= depth ? '' : 'todo'}"></i>`).join('');
      const left = ar.backupFullEvery - ar.backupDepth;
      chain = `<div class="chain" aria-hidden="true">${segs}</div>
        <div class="chain-cap"><span>${depth === 0 ? 'Full copy' : 'Full + ' + depth + ' change' + (depth === 1 ? '' : 's')}</span><span>${left > 0 ? 'New full copy in ' + left : 'Next one is a full copy'}</span></div>`;
    }
    const err = ar.lastBackupError ? `<div class="err">${ICON.alert}<span>${esc(ar.lastBackupError)}</span></div>` : '';
    const reveal = ar.lastBackupDir && window.ipc ? `<button class="btn" data-reveal="${esc(ar.lastBackupDir)}">Show in Finder</button>` : `<button class="btn" data-route="#/agents">Open archive</button>`;
    const backup = `<div class="card">
        <div class="row"><span class="well accent">${ICON.drive}</span><div class="main"><span class="t">${esc(title)}</span>${meta ? `<span class="m">${esc(meta)}</span>` : ''}</div>${chip('', every)}</div>
        ${chain}${err}
        <div class="dest">${ICON.folder}<span title="${esc(st.exportDirEffective || '')}">${esc(shortPath(st.exportDirEffective || '~') || '~')}</span><button class="link" data-cmd="choose_export_dir" ${busy.chooseDir ? 'disabled' : ''}>Change</button></div>
        <div class="pair"><button class="btn primary" data-act="backup" ${running ? 'disabled' : ''}>${running ? 'Backing up…' : 'Back up now'}</button>${reveal}</div>
      </div>`;

    const atRisk = (ag.atRisk || []).filter((r) => r.total > 0 || r.expiringSoon > 0 || r.overdue > 0)
      .sort((a, b) => (b.overdue - a.overdue) || (b.expiringSoon - a.expiringSoon) || (b.total - a.total));
    const clockRows = atRisk.length ? atRisk.slice(0, 5).map((r) => {
      const trail = r.overdue > 0 ? chip('danger', r.overdue + ' overdue')
        : r.expiringSoon > 0 ? chip('warn', r.expiringSoon + (r.soonestExpiryTs ? ' in ' + inDays(r.soonestExpiryTs - Date.now()) : ' expiring'))
        : chip('ok', 'Safe');
      return row({ well: esc(monogram(r.label)), t: esc(r.label), m: retentionLine(r), trail });
    }).join('') : `<div class="empty-row">${ar.count ? 'Every session is preserved' : 'Nothing near a deletion line'}</div>`;

    return `${hero}${backup}
      ${head('Deletion clock', headLink('Agents', '#/agents'))}
      <div class="list">${clockRows}</div>`;
  }

  /* ---- Privacy ---------------------------------------------------------- */
  function governed(st, field) {
    const pol = st && st.policy;
    return !!(pol && pol.active && Array.isArray(pol.governs) && pol.governs.includes(field));
  }
  function viewPrivacy() {
    const pv = data.privacy, live = data.live || {}, ap = data.aprivacy, st = data.settings || {};
    if (!pv) return pending('privacy', 'privacy');
    const on = !!st.maskingEnabled, dry = !!st.maskingDryRun;
    const posture = !on ? 'observe' : dry ? 'dry' : 'redact';
    const info = {
      observe: { t: 'Observe only', m: 'Findings logged. Nothing changes.', well: '' },
      dry: { t: 'Dry run', m: 'Matches recorded. Traffic unchanged.', well: 'warn' },
      redact: { t: 'Redacting', m: 'PII removed in both directions.', well: 'accent' },
    }[posture];
    const locked = governed(st, 'masking.enabled') || governed(st, 'masking.dry_run');
    const seg = [['observe', 'Observe'], ['dry', 'Dry run'], ['redact', 'Redact']].map(([id, label]) =>
      `<button role="radio" aria-checked="${posture === id}" data-posture="${id}" ${locked || busy.settings || !data.settings ? 'disabled' : ''}>${label}</button>`).join('');
    const card = `<div class="card posture">
        <div class="row"><span class="well ${info.well}">${ICON.shield}</span><div class="main"><span class="t">${info.t}</span><span class="m">${locked ? 'Set by your team policy' : info.m}</span></div></div>
        <div class="seg full inset" role="radiogroup" aria-label="Masking">${seg}</div>
      </div>`;

    const pToday = live.piiFindingsToday || 0;
    const tiles = `<div class="tiles">
        ${tile({ k: 'Today', v: full(pToday), cls: pToday > 0 ? 'danger' : '', s: 'in traffic' })}
        ${tile({ k: 'All time', v: compact(pv.total || 0), s: 'findings' })}
        ${tile({ k: 'Transcripts', v: ap ? compact(ap.highSignalFindings) : '·', s: ap ? 'in ' + compact(ap.sessionsWithFindings) + ' sessions' : 'preserved only', title: 'High-signal findings in preserved coding sessions' })}
      </div>`;

    const kinds = (pv.byKind || []).slice().sort((a, b) => b.count - a.count).slice(0, 6);
    const max = Math.max(1, ...kinds.map((k) => k.count));
    const anyNoisy = kinds.some((k) => NOISY_KINDS.includes(k.kind));
    const bars = kinds.length ? kinds.map((k) => {
      const cls = SECRET_KINDS.includes(k.kind) ? 'secret' : NOISY_KINDS.includes(k.kind) ? 'noisy' : '';
      return `<div class="kind ${cls}"><span class="k">${esc(piiLabel(k.kind))}</span><span class="track"><i style="width:${Math.max(3, (k.count / max) * 100).toFixed(1)}%"></i></span><span class="n">${compact(k.count)}</span></div>`;
    }).join('') : '<div class="empty-row" style="padding:6px 0">Nothing found yet</div>';

    const blocks = Array.isArray(st.maskingBlockKinds) && st.maskingBlockKinds.length
      ? `<div class="inline"><span class="bad">${ICON.lock}</span><span class="grow">Blocking ${esc(st.maskingBlockKinds.map(piiOne).join(', '))}</span><button class="link" data-page="settings">Edit</button></div>` : '';

    return `${card}${tiles}
      ${head('By kind', headLink('Full report', '#/analytics/privacy'))}
      <div class="list kinds">${bars}</div>
      ${anyNoisy ? '<div class="foot-note">Phone and IP often match version numbers and ports; shown dimmed.</div>' : ''}
      ${blocks}`;
  }

  /* ---- Spend ------------------------------------------------------------ */
  const CAT = ['var(--p-cat-1)', 'var(--p-cat-2)', 'var(--p-cat-3)', 'var(--p-cat-4)', 'var(--p-cat-5)'];
  // Series per tool, coloured by 30-day cost rank (fixed in BOTH modes, so a
  // tool keeps its colour when the measure flips); the rest fold into Other.
  function stackedSeries(au, mode) {
    const days = Array.isArray(au && au.dailyByTool) ? au.dailyByTool : [];
    const labels = (au && au.toolLabels) || {};
    const pick = (r) => (mode === 'tokens' ? r.tokensByTool : r.costByTool) || {};
    const costT = {}, tokT = {};
    days.forEach((d) => {
      Object.entries(d.costByTool || {}).forEach(([k, v]) => { costT[k] = (costT[k] || 0) + (v || 0); });
      Object.entries(d.tokensByTool || {}).forEach(([k, v]) => { tokT[k] = (tokT[k] || 0) + (v || 0); });
    });
    const keys = Array.from(new Set(Object.keys(costT).concat(Object.keys(tokT))))
      .filter((k) => (costT[k] || 0) > 0 || (tokT[k] || 0) > 0)
      .sort((a, b) => ((costT[b] || 0) - (costT[a] || 0)) || ((tokT[b] || 0) - (tokT[a] || 0)) || a.localeCompare(b));
    const head5 = keys.slice(0, CAT.length), tail = keys.slice(CAT.length);
    const series = head5.map((k, i) => ({ key: k, label: labels[k] || k, color: CAT[i] }));
    if (tail.length) series.push({ key: '__other', label: 'Other', color: 'var(--p-cat-6)' });
    const rows = days.map((d) => {
      const m = pick(d);
      const values = head5.map((k) => m[k] || 0);
      if (tail.length) values.push(tail.reduce((a, k) => a + (m[k] || 0), 0));
      return { date: d.date, values, total: values.reduce((a, v) => a + v, 0) };
    });
    return { series, rows, colorOf: (k) => (series.find((s) => s.key === k) || {}).color };
  }
  function viewSpend() {
    const au = data.ausage, ag = data.agents, an7 = data.an7 || {};
    if (!au) return pending('ausage', 'spend');
    const us = au.usage;
    const monthly = us && us.monthly && us.monthly.length ? us.monthly[us.monthly.length - 1] : null;
    const todayRow = us && us.daily ? us.daily.find((d) => d.date === todayUtc()) : null;
    const st = stackedSeries(au, spendMode);
    const rows = st.rows.slice(-14);
    const tok = spendMode === 'tokens';
    const fmt = tok ? compact : money;
    const sum30 = st.rows.reduce((a, r) => a + r.total, 0);

    const heroV = tok ? compact(sum30) : money(monthly ? monthly.totals.costUsd : au.totalCostUsd);
    const heroK = tok ? 'Tokens · 30 days' : (monthly ? 'This month' : 'All time');
    const heroS = tok ? compact(au.totalSessions) + ' sessions' : (todayRow ? money(todayRow.totals.costUsd) + ' today · ' : '') + 'priced on this Mac';
    const seg = [['cost', 'Cost'], ['tokens', 'Tokens']].map(([id, label]) => `<button role="radio" aria-checked="${spendMode === id}" data-mode="${id}">${label}</button>`).join('');
    const hero = `<div class="hero"><div><div class="k">${esc(heroK)}</div><div class="v"><b>${esc(heroV)}</b></div><div class="s">${esc(heroS)}</div></div><div class="seg" role="radiogroup" aria-label="Chart measure">${seg}</div></div>`;

    const max = Math.max(0, ...rows.map((r) => r.total));
    const chart = rows.length && max > 0
      ? `<div class="bars-chart" role="img" aria-label="Daily ${tok ? 'tokens' : 'cost'} by tool, last ${rows.length} days">${rows.map((r) =>
          `<div class="day" title="${esc(r.date)} · ${esc(fmt(r.total))}">${r.values.map((v, j) => v > 0 ? `<i style="height:${((v / max) * 100).toFixed(1)}%;background:${st.series[j].color}"></i>` : '').join('')}</div>`).join('')}</div>
         <div class="legend">${st.series.slice(0, 4).map((s) => `<span><i style="background:${s.color}"></i>${esc(s.label)}</span>`).join('')}<span class="end">${rows.length} days</span></div>`
      : '<div class="empty-row" style="padding:0">No coding-agent usage in the last 14 days</div>';

    const plan = us && us.plan;
    const active = us && Array.isArray(us.blocks) ? us.blocks.find((b) => b.isActive && !b.isGap) : null;
    let block;
    if (active) {
      const b = active.burn || {};
      const spent = active.totals && active.totals.costUsd;
      let meter = '';
      if (plan && plan.blockCostAllowanceUsd > 0) {
        const f = clamp(plan.usedFraction || 0, 0, 1);
        const proj = b.projectedCostUsd ? clamp(b.projectedCostUsd / plan.blockCostAllowanceUsd - f, 0, 1 - f) : 0;
        const cls = f >= 1 ? 'danger' : f >= 0.7 ? 'warn' : '';
        meter = `<span class="meter lg ${cls}"><i style="width:${(f * 100).toFixed(0)}%"></i><i class="proj" style="width:${(proj * 100).toFixed(0)}%"></i></span>
          <div class="cap"><span>${Math.round(f * 100)}% of ${esc(plan.plan)} allowance</span><span>${money(plan.blockCostAllowanceUsd)}</span></div>`;
      }
      block = `${head('This 5-hour block', plan ? `<span class="aside">resets in ${esc(dur(plan.resetsInMs))}</span>` : '')}
        <div class="card"><div class="quad">
          <div><b>${money(spent)}</b><span>spent</span></div>
          <div><b>${money(b.costPerHour)}</b><span>per hour</span></div>
          <div><b>${compact(b.tokensPerMinute)}</b><span>tok / min</span></div>
          <div><b>${money(b.projectedCostUsd)}</b><span>projected</span></div>
        </div>${meter}</div>`;
    } else {
      block = `${head('This 5-hour block')}<div class="list"><div class="empty-row">Nothing in the last 5 hours</div></div>`;
    }

    const tools = ((ag && ag.tools) || []).filter((t) => t.present && (tok ? t.tokens > 0 : t.costUsd > 0))
      .sort((a, b) => tok ? b.tokens - a.tokens : b.costUsd - a.costUsd).slice(0, 4);
    const totalV = tools.reduce((a, t) => a + (tok ? t.tokens : t.costUsd), 0) || 1;
    const toolRows = tools.length ? `<div class="list">${tools.map((t) => {
      const v = tok ? t.tokens : t.costUsd;
      return row({ sw: st.colorOf(t.tool) || 'var(--p-cat-6)', t: esc(t.label), trail: `<span class="share">${Math.round((v / totalV) * 100)}%</span><span class="val" style="width:64px;text-align:right">${esc(fmt(v))}</span>` });
    }).join('')}</div>` : '';
    const saved = an7.estCostSavedUsd > 0 ? `<div class="inline"><span class="ok">${ICON.check}</span><span class="grow">≈ ${money(an7.estCostSavedUsd)} kept local this week</span></div>` : '';

    return `${hero}<div class="card">${chart}</div>${block}${toolRows}${saved}`;
  }

  /* ---- Alerts (sub-page) ------------------------------------------------ */
  function viewAlerts() {
    const alerts = deriveAlerts();
    if (!alerts.length) {
      return `<div class="card empty-state"><span class="well lg accent">${ICON.check}</span><h1>All quiet</h1><p>New alerts land here, evaluated on this Mac.</p></div>`;
    }
    return alerts.map((a) => {
      const primary = a.action ? `<button class="btn sm ${a.sev === 'danger' ? 'danger' : a.sev === 'warn' ? 'warn' : ''}" ${actionAttrs(a.action)}>${esc(a.action.label)}</button>` : '';
      const when = a.ts ? agoShort(a.ts) : a.live ? 'live' : '';
      return `<article class="alert"><span class="well ${sevWell[a.sev]}">${sevIcon(a)}</span>
        <div class="main"><div><h2>${esc(a.title)}</h2>${a.detail ? `<div class="m">${esc(a.detail)}</div>` : ''}</div>
        <div class="acts">${primary}<button class="btn sm" data-dismiss="${esc(a.key)}">Dismiss</button></div></div>
        ${when ? `<span class="when">${esc(when)}</span>` : ''}</article>`;
    }).join('');
  }

  /* ---- Settings (sub-page) ---------------------------------------------- */
  const sw = (field, on, label, disabled) => `<button class="switch ${on ? 'on' : ''}" role="switch" aria-checked="${on ? 'true' : 'false'}" aria-label="${esc(label)}" data-setting="${field}" data-next="${on ? 'false' : 'true'}" ${disabled || busy.settings ? 'disabled' : ''}><span></span></button>`;
  const set = (label, sub, control, off) => `<div class="set${off ? ' off' : ''}"><div class="copy"><span>${esc(label)}</span>${sub ? `<small>${esc(sub)}</small>` : ''}</div>${control}</div>`;
  function viewSettings() {
    const st = data.settings;
    if (!st) return pending('settings', 'settings');
    const maskLocked = governed(st, 'masking.enabled');
    const dryLocked = governed(st, 'masking.dry_run');
    const archiveOn = !!st.archiveEnabled, maskingOn = !!st.maskingEnabled, autoBackup = !!st.backupAuto;
    const themeChoice = theme || 'system';
    const themeSeg = [['system', 'System'], ['light', 'Light'], ['dark', 'Dark']].map(([id, l]) => `<button role="radio" aria-checked="${themeChoice === id}" data-theme-choice="${id}">${l}</button>`).join('');
    const hours = st.backupIntervalHours || 24;
    const freqSeg = [[1, '1h'], [6, '6h'], [24, 'Daily'], [168, 'Weekly']].map(([h, l]) => `<button role="radio" aria-checked="${hours === h}" data-interval="${h}" ${!autoBackup || busy.settings ? 'disabled' : ''}>${l}</button>`).join('');
    return `<section class="group"><h2>General</h2><div class="list">
        ${set('Open at login', '', sw('loginEnabled', !!host.loginEnabled, 'Open at login'))}
        ${set('Appearance', '', `<div class="seg sm inset" role="radiogroup" aria-label="Appearance">${themeSeg}</div>`)}
      </div></section>
      <section class="group"><h2>Preservation</h2><div class="list">
        ${set('Preserve sessions', 'Encrypted copy of agent history', sw('archiveEnabled', archiveOn, 'Preserve sessions'))}
        ${set('Every 5 minutes', '', sw('archiveAuto', !!st.archiveAuto, 'Preserve automatically', !archiveOn), !archiveOn)}
      </div></section>
      <section class="group"><h2>Backups</h2><div class="list">
        ${set('Back up automatically', 'Only what changed since the last one', sw('backupAuto', autoBackup, 'Back up automatically'))}
        ${set('Frequency', '', `<div class="seg sm inset" role="radiogroup" aria-label="Backup frequency">${freqSeg}</div>`, !autoBackup)}
        ${set('Folder', shortPath(st.exportDirEffective || '~'), `<button class="btn sm" data-cmd="choose_export_dir" ${busy.chooseDir ? 'disabled' : ''}>Change</button>`)}
      </div></section>
      <section class="group"><h2>Privacy</h2><div class="list">
        ${set('PII masking', maskLocked ? 'Set by your team policy' : '', sw('maskingEnabled', maskingOn, 'PII masking', maskLocked))}
        ${set('Dry run first', dryLocked ? 'Set by your team policy' : 'Record matches, change nothing', sw('maskingDryRun', !!st.maskingDryRun, 'Masking dry run', !maskingOn || dryLocked), !maskingOn)}
      </div></section>
      <button class="studio-link" data-route="#/settings">Advanced settings in Studio ${ICON.open}</button>`;
  }

  /* ---- service stopped -------------------------------------------------- */
  function viewStopped() {
    const failedStart = host.status === 'failed';
    const starting = host.status === 'starting';
    const ar = data.agents && data.agents.archive;
    const safe = ar ? `<div class="list">
        ${ar.count ? row({ well: ICON.check, wellCls: 'accent', t: esc(full(ar.count) + ' sessions safe'), trail: '<span class="share">encrypted</span>' }) : ''}
        ${ar.lastBackupTs ? row({ well: ICON.check, wellCls: 'accent', t: esc('Last backup ' + ago(ar.lastBackupTs)), trail: '' }) : ''}
      </div>` : '';
    return `<div class="card empty-state">
        <span class="well lg ${failedStart ? 'danger' : ''}">${failedStart ? ICON.alert : ICON.pause}</span>
        <h1>${failedStart ? 'Saffev couldn’t start' : starting ? 'Starting…' : 'Recording is paused'}</h1>
        <p>${failedStart ? 'The log has the cause.' : 'Nothing new is captured or preserved.'}</p>
        <div class="pair"><button class="btn primary" data-cmd="start" ${starting ? 'disabled' : ''}>${ICON.play} ${starting ? 'Starting…' : 'Start'}</button><button class="btn" data-cmd="logs">Open logs</button></div>
      </div>${ar && (ar.count || ar.lastBackupTs) ? safe : ''}`;
  }

  /* ---- render ----------------------------------------------------------- */
  // Opened in a plain browser tab there is no host to report service state:
  // the API answering is the proof it runs.
  const hostStatus = () => (!window.ipc && data.live ? 'running' : host.status);
  const isStopped = () => host.running === false && !data.live;
  function renderHeader() {
    const hd = $('#hd');
    if (page) {
      hd.className = 'hd sub';
      const clear = page === 'alerts' && deriveAlerts().length ? '<button class="btn sm ghost" data-cmd="clear_alerts">Clear all</button>' : '';
      const aside = page === 'settings' ? '<span class="share" style="padding-right:4px;font-size:12px;color:var(--p-text-3)">Saved instantly</span>' : '';
      hd.innerHTML = `<button class="ib" data-page="" aria-label="Back">${ICON.back}</button><h1>${page === 'alerts' ? 'Alerts' : 'Settings'}</h1>${clear}${aside}`;
      return;
    }
    hd.className = 'hd';
    const s = hostStatus() || 'stopped';
    const cls = s === 'running' && stale ? 'stale' : s;
    const tools = data.agents && Array.isArray(data.agents.tools) ? data.agents.tools.filter((t) => t.present).length : 0;
    const text = s === 'running' ? (stale ? 'Reconnecting…' : tools ? 'Recording · ' + tools + ' tool' + (tools === 1 ? '' : 's') : 'Recording')
      : s === 'starting' ? 'Starting…' : s === 'failed' ? 'Failed to start' : 'Stopped';
    const alerts = deriveAlerts();
    const hot = alerts.filter((a) => a.sev !== 'info').length;
    const danger = alerts.some((a) => a.sev === 'danger');
    const badge = hot ? `<span class="badge ${danger ? '' : 'warn'}">${hot > 9 ? '9+' : hot}</span>` : '';
    hd.innerHTML = `<span class="mark ${s === 'running' ? '' : 'off'}">${MARK}</span>
      <div class="wm"><b>${esc(host.appName || 'Saffev')}</b><span class="status ${cls}"><span class="dot"></span>${esc(text)}</span></div>
      <button class="ib" data-page="alerts" aria-label="Alerts${hot ? ', ' + hot + ' need you' : ''}" title="Alerts">${ICON.bell}${badge}</button>
      <button class="ib" data-route="" aria-label="Open Studio" title="Open Studio">${ICON.open}</button>
      <button class="ib" data-page="settings" aria-label="Settings" title="Settings">${ICON.sliders}</button>`;
  }
  function renderTabs() {
    const nav = $('#tabs');
    nav.hidden = !!page || isStopped();
    nav.style.display = nav.hidden ? 'none' : '';
    nav.innerHTML = TABS.map((t) => `<button class="tab" role="tab" data-tab="${t.id}" aria-selected="${t.id === tab}">${t.label}</button>`).join('');
  }
  function renderBody() {
    const body = $('#body');
    let html;
    if (failed.auth) html = `<div class="card"><div class="err">${ICON.alert}<span>Not authorized · restart the service and reopen the panel</span></div></div>`;
    else if (isStopped() && page !== 'settings') html = viewStopped();
    else if (page === 'settings') html = viewSettings();
    else if (page === 'alerts') html = viewAlerts();
    else html = tab === 'today' ? viewToday() : tab === 'keep' ? viewKeep() : tab === 'privacy' ? viewPrivacy() : viewSpend();
    const scroll = body.scrollTop;
    body.innerHTML = `<div class="stack">${html}</div>`;
    body.scrollTop = scroll;
  }
  function renderFooter() {
    const foot = $('#foot');
    const port = (host.studioUrl || '').match(/:(\d+)\/?$/);
    const ver = (host.version ? 'v' + host.version : '') + (port ? ' · :' + port[1] : '');
    if (page === 'settings') {
      foot.innerHTML = `<span class="ver">${esc(ver)}</span><button class="btn sm ghost quit" data-cmd="quit" title="Quit the menu-bar app (the service keeps running)">Quit Saffev</button>`;
      return;
    }
    if (page === 'alerts') {
      foot.innerHTML = `<span class="ver">Evaluated on this Mac</span><button class="btn sm ghost" data-page="settings">Settings</button>`;
      return;
    }
    const running = hostStatus() === 'running';
    const starting = hostStatus() === 'starting';
    foot.innerHTML = `<span class="ver">${esc(ver)}</span>
      ${window.ipc ? `<button class="ib sm" data-cmd="pin" aria-label="Keep the panel open" aria-pressed="${host.pinned ? 'true' : 'false'}" title="${host.pinned ? 'Unpin' : 'Keep open'}">${ICON.pin}</button>` : ''}
      <button class="ib sm" data-cmd="restart" aria-label="Restart service" title="Restart service" ${running ? '' : 'disabled'}>${ICON.restart}</button>
      <button class="ib sm" data-cmd="logs" aria-label="Open logs" title="Open logs">${ICON.logs}</button>
      ${running ? `<button class="ib sm" data-cmd="stop" aria-label="Stop service" title="Stop service">${ICON.power}</button>`
        : `<button class="ib sm" data-cmd="start" aria-label="Start service" title="Start service" ${starting ? 'disabled' : ''}>${ICON.play}</button>`}`;
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
    const reveal = n.revealPath && window.ipc
      ? `<button class="btn sm" data-reveal="${esc(n.revealPath)}">Show in Finder</button>`
      : '';
    el.innerHTML = `${n.kind === 'busy' ? '<span class="spin"></span>' : ''}<b>${esc(n.title)}</b><span>${esc(n.detail || '')}</span>${reveal}`;
    el.hidden = false;
    if (n.kind === 'ok' || n.kind === 'error') {
      const wasBackup = busy.backup;
      busy.backup = false; busy.preserve = false; render();
      if (wasBackup) load(['agents', 'verify'], true);
      noticeTimer = setTimeout(() => { el.hidden = true; reportHeight(); }, n.kind === 'error' || n.revealPath ? 9000 : 4000);
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
      notice({ kind: 'ok', title: 'Preserved', detail: n ? n + ' session' + (n === 1 ? '' : 's') + ' written' : 'Already up to date' });
      await load(['agents', 'verify', 'settings'], true);
    } catch (e) {
      notice({ kind: 'error', title: 'Preserve failed', detail: e.message || String(e) });
    }
    busy.preserve = false; render();
  }

  // Back up = make sure everything new is in the archive, then ask the Studio
  // to write the backup (incremental when a chain exists). It runs in the
  // service, so the panel stays open and nothing steals focus; the folder is
  // one click away ("Show in Finder") instead of popping up on its own.
  async function backupNow() {
    if (busy.backup) return;
    busy.backup = true; renderBody();
    notice({ kind: 'busy', title: 'Backing up…', detail: 'Preserving new sessions first' });
    try {
      const ag = data.agents;
      if (ag && ag.archive && ag.archive.enabled === false) {
        await api('/settings', { method: 'PUT', body: { archiveEnabled: true, archiveAuto: true } });
      }
      await api('/archive/run', { method: 'POST' });
      notice({ kind: 'busy', title: 'Backing up…', detail: 'Only what changed since the last backup' });
      const r = await api('/backup', { method: 'POST', body: {} });
      const what = r.kind === 'unchanged' ? 'Already up to date'
        : r.kind === 'incremental' ? 'Incremental · ' + bytes(r.bytes)
        : 'Full copy · ' + bytes(r.bytes);
      notice({ kind: 'ok', title: r.kind === 'unchanged' ? 'Nothing new' : 'Backed up', detail: what, revealPath: r.dir });
    } catch (e) {
      notice({ kind: 'error', title: 'Backup failed', detail: e.message || String(e) });
    }
    busy.backup = false;
    await load(['agents'], true);
    render();
  }

  async function putSettings(body, okTitle) {
    if (busy.settings) return;
    busy.settings = true; renderBody();
    try {
      data.settings = await api('/settings', { method: 'PUT', body });
      fetchedAt.settings = Date.now();
      notice({ kind: 'ok', title: okTitle || 'Saved', detail: '' });
    } catch (e) {
      notice({ kind: 'error', title: 'Not saved', detail: e.message || String(e) });
      await load(['settings'], true);
    }
    busy.settings = false;
    load(['agents'], true);
    render();
  }
  function updateSetting(field, next) {
    if (field === 'loginEnabled') { ipc({ cmd: 'set_login', enabled: next }); return; }
    if (field === 'maskingDryRun' && next === false && !window.confirm('Turn off dry run? Detected PII will be redacted from requests and responses before they are forwarded.')) return;
    const body = {}; body[field] = next;
    putSettings(body);
  }
  function setPosture(p) {
    if (p === 'observe') putSettings({ maskingEnabled: false }, 'Observe only');
    else if (p === 'dry') putSettings({ maskingEnabled: true, maskingDryRun: true }, 'Dry run on');
    else if (window.confirm('Start redacting? Detected PII will be removed from requests and responses before they are forwarded.')) putSettings({ maskingEnabled: true, maskingDryRun: false }, 'Redacting');
  }
  function openPage(p) {
    page = p || null;
    render();
    refresh(false);
  }

  document.addEventListener('click', (ev) => {
    const t = ev.target.closest('[data-tab],[data-page],[data-route],[data-cmd],[data-act],[data-dismiss],[data-mode],[data-setting],[data-theme-choice],[data-reveal],[data-interval],[data-posture]');
    if (!t || t.disabled) return;
    const d = t.dataset;
    if (d.reveal) { ipc({ cmd: 'reveal', path: d.reveal }); return; }
    if (d.page != null) { openPage(d.page); return; }
    if (d.interval) { putSettings({ backupIntervalHours: parseInt(d.interval, 10) }, 'Backup frequency saved'); return; }
    if (d.posture) { setPosture(d.posture); return; }
    if (d.themeChoice) { setTheme(d.themeChoice); return; }
    if (d.setting) { updateSetting(d.setting, d.next === 'true'); return; }
    if (d.mode) { spendMode = d.mode; renderBody(); return; }
    if (d.tab) {
      tab = d.tab; page = null;
      try { localStorage.setItem('saffev.panel.tab', tab); } catch (e) { /* storage blocked */ }
      render();
      refresh(false);
      return;
    }
    if (d.route != null) { ipc({ cmd: 'open', route: d.route }); return; }
    if (d.dismiss) { dismissed.add(d.dismiss); render(); return; }
    if (d.act === 'preserve') { preserveNow(); return; }
    if (d.act === 'backup') { backupNow(); return; }
    const cmd = d.cmd;
    if (cmd === 'pin') { host.pinned = !host.pinned; ipc({ cmd: 'set_pinned', pinned: host.pinned }); renderFooter(); return; }
    if (cmd === 'clear_alerts') { deriveAlerts().forEach((a) => dismissed.add(a.key)); render(); return; }
    if (cmd === 'choose_export_dir') { busy.chooseDir = true; renderBody(); ipc({ cmd: 'choose_export_dir' }); return; }
    if (cmd) ipc({ cmd });
  });
  // Inside the tray's webview the WebKit context menu (Reload / Back…) is
  // noise on a widget; a plain browser tab keeps it.
  if (window.ipc) document.addEventListener('contextmenu', (e) => e.preventDefault());
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { if (page) openPage(null); else ipc({ cmd: 'close' }); return; }
    const n = parseInt(e.key, 10);
    if ((e.metaKey || e.ctrlKey) && n >= 1 && n <= TABS.length) { tab = TABS[n - 1].id; page = null; render(); refresh(false); e.preventDefault(); }
    if ((e.metaKey || e.ctrlKey) && e.key === ',') { openPage('settings'); e.preventDefault(); }
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
      if (was !== host.status && host.status === 'running') refresh(true);
      render();
    },
    onShow() { const was = visible; visible = true; refresh(true); if (!was || !pollTimer) startPolling(); },
    onHide() { visible = false; stopPolling(); if (page === 'alerts') page = null; },
    notice,
    // The host's native folder picker returned (null = cancelled). Save it as
    // the export destination; the Studio validates it (exists, writable).
    async exportDirChosen(path) {
      busy.chooseDir = false;
      if (!path) { renderBody(); return; }
      try {
        await api('/settings', { method: 'PUT', body: { exportDir: path } });
        notice({ kind: 'ok', title: 'Backup folder saved', detail: shortPath(path) });
        await load(['settings', 'agents'], true);
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
  // Hosted: wait for onShow (the host calls it when the panel opens, or right
  // after `ready` if it already is). Browser tab: start now.
  if (visible) {
    refresh(true);
    startPolling();
  }
})();
