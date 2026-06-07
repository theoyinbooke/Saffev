/* ============================================================================
   Saffev Studio SPA — app.js
   Static, no-build. Talks to the Studio HTTP API (camelCase JSON) and the
   SSE feed at GET /api/stream. All colours/spacing come from tokens.css; this
   file only structures data + behaviour.

   Wire contract (see src/studio/dto.rs):
     GET  /api/health   -> { app, version, proxyUp, mode }
     GET  /api/live     -> { recent:[HistoryItem], requestsToday, p50LatencyMs, piiFindingsToday }
     GET  /api/history  ?q&piiOnly&limit&beforeTs -> [HistoryItem]
     GET  /api/history/:id -> { item, findings:[PiiFindingView], prompt, response, payloadsDisabled }
     GET  /api/privacy  -> { byKind, byApp, byModel, total, maskingEnabled }
     GET  /api/engines  -> { engines:[EngineView], mode, exposure:ExposureReport }
     POST /api/engines/adopt  { engine, cooperative } -> EngineView
     POST /api/engines/revert { engine }              -> EngineView
     GET  /api/exposure -> ExposureReport
     GET  /api/settings -> SettingsView
     PUT  /api/settings { mode?, payloadStorage?, retention?, handover?, maskingEnabled?, maskingDryRun? } -> SettingsView
     GET  /api/update   -> { currentVersion, latestVersion, updateAvailable }  (GitHub release metadata only — nothing about the user leaves the device)
     POST /api/update   -> { updated, newVersion, message }
     GET  /api/stream   SSE of StreamEvent (tagged by `type`)

   Every /api/* call needs `Authorization: Bearer <install-token>` + an
   allowlisted Host. See getToken() for how the token is resolved.
   ============================================================================ */
(function () {
  'use strict';

  /* -------------------------------------------------------------------------
     Brand — single source of truth (mirrors design/brand.json).
     ------------------------------------------------------------------------- */
  const BRAND = { wordmark: 'Saffev', tagline: 'local ai studio', command: 'saffev' };

  /* -------------------------------------------------------------------------
     Token resolution. The Studio is loopback-only and single-user; the
     per-install bearer token lives in the OS keyring. The backend may inject
     it into the served index.html (window.__SAFFEV_TOKEN__ or a meta tag).
     We also accept ?token= (one-time, then persisted) and localStorage.
     ------------------------------------------------------------------------- */
  const TOKEN_KEY = 'saffev-token';
  function getToken() {
    if (window.__SAFFEV_TOKEN__) return window.__SAFFEV_TOKEN__;
    const meta = document.querySelector('meta[name="saffev-token"]');
    if (meta && meta.content) return meta.content;
    try {
      const u = new URL(window.location.href);
      const q = u.searchParams.get('token');
      if (q) {
        try { localStorage.setItem(TOKEN_KEY, q); } catch (e) {}
        // strip the token from the visible URL
        u.searchParams.delete('token');
        history.replaceState(null, '', u.pathname + u.search + u.hash);
        return q;
      }
      const ls = localStorage.getItem(TOKEN_KEY);
      if (ls) return ls;
    } catch (e) {}
    return '';
  }
  let TOKEN = getToken();

  /* -------------------------------------------------------------------------
     API client.
     ------------------------------------------------------------------------- */
  async function api(path, opts) {
    opts = opts || {};
    const headers = Object.assign({ Accept: 'application/json' }, opts.headers || {});
    if (TOKEN) headers['Authorization'] = 'Bearer ' + TOKEN;
    if (opts.body != null && typeof opts.body !== 'string') {
      opts.body = JSON.stringify(opts.body);
      headers['Content-Type'] = 'application/json';
    }
    const res = await fetch('/api' + path, {
      method: opts.method || 'GET',
      headers,
      body: opts.body,
    });
    if (!res.ok) {
      let payload = null;
      try { payload = await res.json(); } catch (e) {}
      const err = new Error((payload && payload.message) || ('HTTP ' + res.status));
      err.status = res.status;
      err.code = payload && payload.error;
      throw err;
    }
    if (res.status === 204) return null;
    return res.json();
  }

  /* -------------------------------------------------------------------------
     Small DOM + formatting helpers.
     ------------------------------------------------------------------------- */
  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    if (attrs) {
      for (const k in attrs) {
        if (k === 'class') node.className = attrs[k];
        else if (k === 'html') node.innerHTML = attrs[k];
        else if (k === 'text') node.textContent = attrs[k];
        else if (k.startsWith('on') && typeof attrs[k] === 'function') node.addEventListener(k.slice(2), attrs[k]);
        else if (attrs[k] === true) node.setAttribute(k, '');
        else if (attrs[k] != null && attrs[k] !== false) node.setAttribute(k, attrs[k]);
      }
    }
    if (children != null) {
      (Array.isArray(children) ? children : [children]).forEach((c) => {
        if (c == null) return;
        node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
      });
    }
    return node;
  }
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const fmtNum = (n) => (n == null ? '—' : Number(n).toLocaleString());
  function initials(name) {
    if (!name) return '?';
    const parts = String(name).trim().split(/[\s._-]+/).filter(Boolean);
    if (parts.length === 0) return '?';
    if (parts.length === 1) return parts[0].slice(0, 2);
    return (parts[0][0] + parts[1][0]);
  }
  function relTime(ms) {
    const d = Date.now() - ms;
    if (d < 5000) return 'just now';
    if (d < 60000) return Math.floor(d / 1000) + 's ago';
    if (d < 3600000) return Math.floor(d / 60000) + 'm ago';
    if (d < 86400000) return Math.floor(d / 3600000) + 'h ago';
    return new Date(ms).toLocaleDateString();
  }
  // Absolute timestamp for the traffic table. Today → HH:MM:SS (precise, since
  // live traffic is all "today"); older → "MMM D, HH:MM". Full date+time on hover.
  function fmtStamp(ms) {
    const d = new Date(ms);
    const now = new Date();
    const p2 = (n) => String(n).padStart(2, '0');
    const hms = p2(d.getHours()) + ':' + p2(d.getMinutes()) + ':' + p2(d.getSeconds());
    const sameDay = d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth() && d.getDate() === now.getDate();
    if (sameDay) return hms;
    const mon = d.toLocaleString(undefined, { month: 'short' });
    return mon + ' ' + d.getDate() + ', ' + p2(d.getHours()) + ':' + p2(d.getMinutes());
  }
  // human label for a PiiKind (snake_case on wire)
  const PII_LABEL = {
    email: 'Email address', phone: 'Phone number', credit_card: 'Credit card',
    api_key: 'API key / token', ip_address: 'IP address', custom: 'Custom pattern',
  };
  function piiLabel(kind, label) {
    if (kind === 'custom' && label) return label;
    return PII_LABEL[kind] || kind;
  }
  // Map a PiiKind to a colour role (gold for keys, danger otherwise).
  function piiRole(kind) { return kind === 'api_key' ? 'gold' : kind === 'ip_address' ? 'brand' : 'danger'; }
  function piiShort(kind) {
    return { email: 'EMAIL', phone: 'PHONE', credit_card: 'CARD', api_key: 'API-KEY', ip_address: 'IP', custom: 'CUSTOM' }[kind] || String(kind).toUpperCase();
  }

  /* SVG icon helpers (token-coloured via currentColor) */
  const ICON = {
    pulse: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 12h4l3 8 4-16 3 8h6"/></svg>',
    clock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>',
    shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3 5 6v5c0 4.5 3 7.5 7 9 4-1.5 7-4.5 7-9V6l-7-3Z"/></svg>',
    shieldAlert: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3 5 6v5c0 4.5 3 7.5 7 9 4-1.5 7-4.5 7-9V6l-7-3Z"/><path d="M12 9v4M12 16h.01"/></svg>',
    check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M5 12.5 10 17l9-10"/></svg>',
    mail: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/></svg>',
    key: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 7a4 4 0 1 0-3.9 5H21v3M17 12v3"/></svg>',
    card: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="5" width="20" height="14" rx="2"/><path d="M2 10h20"/></svg>',
    phone: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 4h4l2 5-3 2a12 12 0 0 0 5 5l2-3 5 2v4a2 2 0 0 1-2 2A16 16 0 0 1 3 6a2 2 0 0 1 2-2Z"/></svg>',
    globe: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.5 2.5 15 0 18M12 3c-2.5 2.5-2.5 15 0 18"/></svg>',
    server: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/></svg>',
    ollama: '<svg viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="9" r="3.4"/><path d="M5 20c0-3.6 3.1-6 7-6s7 2.4 7 6"/></svg>',
    restart: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-3-6.7M21 4v5h-5"/></svg>',
    revert: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 1 1 3 6.7M3 20v-5h5"/></svg>',
    alert: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3 2 20h20L12 3Z"/><path d="M12 9v4M12 17h.01"/></svg>',
    download: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3v12M7 11l5 4 5-4M5 20h14"/></svg>',
    chevL: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M15 6 9 12l6 6"/></svg>',
    chevR: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="m9 6 6 6-6 6"/></svg>',
    chevD: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="m6 9 6 6 6-6"/></svg>',
    copy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>',
    link: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/><path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1"/></svg>',
    terminal: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3M13 15h4"/></svg>',
    bolt: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2 4 14h6l-1 8 9-12h-6l1-8Z"/></svg>',
    plug: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 2v6M15 2v6M7 8h10v3a5 5 0 0 1-10 0V8ZM12 16v6"/></svg>',
    eye: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>',
    sparkles: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3v4M12 17v4M5 12H1M23 12h-4M6.3 6.3 3.5 3.5M20.5 20.5l-2.8-2.8M17.7 6.3l2.8-2.8M3.5 20.5l2.8-2.8"/></svg>',
  };
  function piiIcon(kind) {
    return { email: ICON.mail, api_key: ICON.key, credit_card: ICON.card, phone: ICON.phone, ip_address: ICON.globe }[kind] || ICON.shieldAlert;
  }

  /* -------------------------------------------------------------------------
     Theme toggle ([data-theme] mechanism from tokens.css; persisted).
     Default: follow OS (no attribute) until the user picks one.
     ------------------------------------------------------------------------- */
  const SUN = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="4.5"/><path d="M12 2v2M12 20v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M2 12h2M20 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4"/></svg>';
  const MOON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"/></svg>';
  const THEME_KEY = 'saffev-theme';
  function currentTheme() {
    const attr = document.documentElement.getAttribute('data-theme');
    if (attr) return attr;
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  function applyTheme(t) {
    document.documentElement.setAttribute('data-theme', t);
    const btn = $('#themeBtn');
    if (btn) btn.innerHTML = t === 'dark' ? SUN : MOON;
    try { localStorage.setItem(THEME_KEY, t); } catch (e) {}
  }
  function initTheme() {
    let saved = null;
    try { saved = localStorage.getItem(THEME_KEY); } catch (e) {}
    if (saved) applyTheme(saved);
    else {
      // leave attribute unset so OS scheme wins; set the button glyph to match.
      const btn = $('#themeBtn');
      if (btn) btn.innerHTML = currentTheme() === 'dark' ? SUN : MOON;
    }
    const btn = $('#themeBtn');
    if (btn) btn.addEventListener('click', () => applyTheme(currentTheme() === 'dark' ? 'light' : 'dark'));
  }

  /* -------------------------------------------------------------------------
     Banner (token/connection problems).
     ------------------------------------------------------------------------- */
  function showBanner(msg, kind) {
    const b = $('#banner');
    if (!b) return;
    b.className = 'banner' + (kind === 'danger' ? ' danger' : '');
    b.innerHTML = ICON.alert + '<span class="grow">' + esc(msg) + '</span>';
    b.hidden = false;
  }
  function hideBanner() { const b = $('#banner'); if (b) b.hidden = true; }

  /* -------------------------------------------------------------------------
     In-app auto-update (bottom-left).

     On load we GET /api/update; if a newer release exists we show a compact card
     in the sidebar foot: "Update available · vX → vY  [Update & restart]". One
     click installs it (POST /api/update), then relaunches the daemon
     (POST /api/restart) and reloads the Studio once it's back — no terminal.

     PRIVACY: GET /api/update contacts GitHub release metadata only — nothing
     about the user leaves the device. Fail-soft: any error leaves the slot hidden.
     ------------------------------------------------------------------------- */
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  async function checkForUpdate() {
    const foot = $('#updateFoot');
    if (!foot) return;
    let st;
    try { st = await api('/update'); } // { currentVersion, latestVersion, updateAvailable }
    catch (e) { return; } // optional — never surface as an error
    if (!st || !st.updateAvailable || !st.latestVersion) { foot.hidden = true; return; }
    renderFootUpdate(foot, st);
  }

  function renderFootUpdate(foot, st) {
    foot.hidden = false;
    foot.innerHTML = '';
    foot.appendChild(el('div', { class: 'ut', html: ICON.download + '<span>Update available</span>' }));
    const ver = el('div', { class: 'uv' });
    ver.appendChild(el('span', { text: 'v' + st.currentVersion }));
    ver.appendChild(document.createTextNode(' → '));
    ver.appendChild(el('span', { text: 'v' + st.latestVersion }));
    foot.appendChild(ver);
    const btn = el('button', { class: 'btn primary', html: ICON.download + '<span>Update &amp; restart</span>' });
    btn.addEventListener('click', () => applyAndRestart(foot, btn, st));
    foot.appendChild(btn);
  }

  function footMsg(foot, icon, title, detail) {
    foot.hidden = false;
    foot.innerHTML = '';
    foot.appendChild(el('div', { class: 'ut', html: icon + '<span>' + esc(title) + '</span>' }));
    if (detail) foot.appendChild(el('div', { class: 'umsg', text: detail }));
  }

  async function applyAndRestart(foot, btn, st) {
    setBusy(btn, true);
    footMsg(foot, ICON.download, 'Updating', 'Downloading & installing v' + st.latestVersion + '…');
    let res;
    try {
      res = await api('/update', { method: 'POST' }); // { updated, newVersion, message }
    } catch (e) {
      footMsg(foot, ICON.alert, 'Update failed', (e && e.message) || 'Could not install the update.');
      const retry = el('button', { class: 'btn', html: ICON.restart + '<span>Try again</span>' });
      retry.addEventListener('click', () => renderFootUpdate(foot, st));
      foot.appendChild(retry);
      return;
    }
    if (!res || !res.updated) {
      // Already current, or a dev build with no install receipt — show guidance.
      footMsg(foot, ICON.shield, 'Update', (res && res.message) || 'Already on the latest version.');
      return;
    }
    // Installed — relaunch the daemon and reload the Studio once it's back.
    footMsg(foot, ICON.restart, 'Restarting Saffev', 'Installed v' + res.newVersion + '. Relaunching…');
    try { await api('/restart', { method: 'POST' }); } catch (e) { /* server may drop mid-call — expected */ }
    await waitForRestartThenReload(foot);
  }

  async function waitForRestartThenReload(foot) {
    // The daemon goes down (~1–3s) then back up on the same port. Wait out the
    // down window, then poll /api/health until it answers, then reload.
    await sleep(2500);
    for (let i = 0; i < 40; i++) {
      try {
        const r = await fetch('/api/health', { headers: TOKEN ? { Authorization: 'Bearer ' + TOKEN } : {}, cache: 'no-store' });
        if (r.ok) { location.reload(); return; }
      } catch (e) { /* still down — keep polling */ }
      await sleep(1000);
    }
    footMsg(foot, ICON.check, 'Update installed', 'Saffev was relaunched — reload this page to continue.');
  }

  function handleApiError(e) {
    if (e && e.status === 401) {
      showBanner('Not authorized — the Studio token is missing or invalid. Run `' + BRAND.command + ' status` for the local URL with a token, or open Settings.', 'danger');
    } else if (e && e.status === 403) {
      showBanner('Blocked by Host allowlist — open the Studio at its loopback address (e.g. 127.0.0.1).', 'danger');
    } else {
      showBanner('Cannot reach the Studio backend: ' + (e && e.message ? e.message : 'unknown error') + '.', 'danger');
    }
  }

  /* -------------------------------------------------------------------------
     Shared request TABLE (Live + History).
     One single-line, clickable row per request. Columns are config-driven so
     Live can show a compact subset and History the full set while staying
     perfectly aligned: the header (reqHead) and every row (reqRow) read the
     same `--gtc` grid-template + identical gap/padding. Set `--gtc` on the
     enclosing `.ttable` wrapper (see gtcFor) so both inherit it.
     ------------------------------------------------------------------------- */
  const REQ_COLS = {
    app:      { label: 'Source',   w: 'minmax(110px,1.3fr)', r: false },
    model:    { label: 'Model',    w: 'minmax(78px,1fr)',    r: false },
    endpoint: { label: 'Endpoint', w: 'minmax(86px,1.1fr)',  r: false },
    lat:      { label: 'Latency',  w: '68px',                r: true },
    tokens:   { label: 'Tokens',   w: 'minmax(86px,auto)',   r: true },
    time:     { label: 'Time',     w: '92px',                r: true },
  };
  const LIVE_COLS = ['app', 'model', 'endpoint', 'lat', 'tokens', 'time'];
  const HIST_COLS = ['app', 'model', 'endpoint', 'lat', 'tokens', 'time'];
  function gtcFor(cols) { return cols.map((k) => REQ_COLS[k].w).join(' '); }

  // Column header strip. Lives ABOVE the scrolling body so it stays fixed.
  function reqHead(cols) {
    const head = el('div', { class: 'thead' });
    cols.forEach((k) => head.appendChild(el('div', { class: 'th' + (REQ_COLS[k].r ? ' r' : ''), text: REQ_COLS[k].label })));
    return head;
  }

  // One cell for `key`, populated from `item`.
  function reqCell(key, item) {
    if (key === 'app') {
      const cell = el('div', { class: 'tcell cell-app' });
      cell.appendChild(el('span', { class: 'nm', text: item.sourceApp || 'Unknown' }));
      // Collapse multiple PII kinds to "first + N" so the source column stays tidy.
      const kinds = item.piiKinds || [];
      if (kinds.length) {
        cell.appendChild(el('span', { class: 'piibadge' + (kinds[0] === 'api_key' ? ' key' : ''), 'data-k': kinds[0], text: piiShort(kinds[0]) }));
        if (kinds.length > 1) cell.appendChild(el('span', { class: 'piibadge more', title: kinds.slice(1).map(piiShort).join(', '), text: '+' + (kinds.length - 1) }));
      }
      return cell;
    }
    if (key === 'model') return el('div', { class: 'tcell cell-model', title: item.model || '', text: item.model || '—' });
    if (key === 'endpoint') return el('div', { class: 'tcell cell-endpoint', title: item.endpoint || '', text: item.endpoint || '—' });
    if (key === 'lat') return el('div', { class: 'tcell r cell-lat', text: item.latencyMs != null ? item.latencyMs + 'ms' : '' });
    if (key === 'tokens') {
      const up = item.inputTokens != null ? (item.inputTokensSrc === 'estimated' ? '~' : '') + fmtNum(item.inputTokens) + '↑' : '';
      const down = item.outputTokens != null ? (item.outputTokensSrc === 'estimated' ? '~' : '') + fmtNum(item.outputTokens) + '↓' : '';
      return el('div', { class: 'tcell r cell-tokens', text: [up, down].filter(Boolean).join('  ') || '—' });
    }
    if (key === 'time') return el('div', { class: 'tcell r cell-time', title: item.ts ? new Date(item.ts).toLocaleString() : '', text: item.ts ? fmtStamp(item.ts) : '' });
    return el('div', { class: 'tcell' });
  }

  // One clickable row. opts: { columns, streaming, enter }.
  function reqRow(item, opts) {
    opts = opts || {};
    const cols = opts.columns || HIST_COLS;
    const row = el('div', {
      class: 'trow' + (opts.streaming ? ' streaming' : '') + (opts.enter ? ' enter' : ''),
      'data-id': item.id, role: 'button', tabindex: '0',
    });
    cols.forEach((k) => row.appendChild(reqCell(k, item)));
    row.addEventListener('click', () => openDetail(item.id));
    row.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openDetail(item.id); } });
    return row;
  }

  /* -------------------------------------------------------------------------
     Detail drawer (History detail).
     ------------------------------------------------------------------------- */
  async function openDetail(id) {
    let detail;
    try { detail = await api('/history/' + encodeURIComponent(id)); }
    catch (e) { handleApiError(e); return; }
    closeDrawer();
    const bg = el('div', { class: 'drawer-bg', onclick: closeDrawer });
    const it = detail.item;
    const dl = el('dl', { class: 'kvgrid' });
    const kv = (k, v) => { dl.appendChild(el('dt', { text: k })); dl.appendChild(el('dd', { text: v })); };
    kv('App', it.sourceApp || 'Unknown');
    kv('Confidence', it.sourceConfidence);
    kv('Engine', it.engine);
    kv('Model', it.model || '—');
    kv('Endpoint', it.endpoint);
    kv('Streamed', it.stream ? 'yes' : 'no');
    kv('Input tokens', it.inputTokens != null ? (it.inputTokensSrc === 'estimated' ? '~' : '') + fmtNum(it.inputTokens) : '—');
    kv('Output tokens', it.outputTokens != null ? (it.outputTokensSrc === 'estimated' ? '~' : '') + fmtNum(it.outputTokens) : '—');
    kv('Latency', it.latencyMs != null ? it.latencyMs + 'ms' : '—');
    kv('TTFT', it.ttftMs != null ? it.ttftMs + 'ms' : '—');
    kv('Time', new Date(it.ts).toLocaleString());

    const body = el('div', {}, [
      el('button', { class: 'iconbtn close', onclick: closeDrawer, 'aria-label': 'Close', html: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 6 18 18M18 6 6 18"/></svg>' }),
      el('h2', { text: it.sourceApp || 'Unknown app' }),
      el('div', { class: 'muted', style: 'font-family:var(--font-mono);font-size:.78rem;margin-top:4px', text: it.id }),
      dl,
    ]);

    // findings
    if (detail.findings && detail.findings.length) {
      const fl = el('div', { class: 'payblk' }, [el('h4', { text: 'PII findings (observe-only)' })]);
      const list = el('div', { class: 'findlist' });
      detail.findings.forEach((f) => {
        const r = el('div', { class: 'find' });
        r.appendChild(el('span', { class: 'piibadge' + (f.kind === 'api_key' ? ' key' : ''), text: piiShort(f.kind) }));
        r.appendChild(el('span', { text: piiLabel(f.kind, f.label) + ' · ' + f.confidence + ' confidence' }));
        r.appendChild(el('span', { class: 'where', text: f.side + ' [' + f.start + '–' + f.end + ']' }));
        list.appendChild(r);
      });
      fl.appendChild(list);
      body.appendChild(fl);
    }

    // payloads
    if (detail.payloadsDisabled) {
      body.appendChild(el('div', { class: 'payblk' }, [
        el('h4', { text: 'Payloads' }),
        el('div', { class: 'expnote', html: ICON.shield + ' Metadata-only — raw prompt &amp; response are not stored (payload storage off).' }),
      ]));
    } else {
      if (detail.prompt != null) {
        body.appendChild(el('div', { class: 'payblk' }, [el('h4', { text: 'Prompt' }), el('pre', { text: detail.prompt })]));
      }
      if (detail.response != null) {
        body.appendChild(el('div', { class: 'payblk' }, [el('h4', { text: 'Response' }), el('pre', { text: detail.response })]));
      }
    }

    const drawer = el('div', { class: 'drawer', role: 'dialog', 'aria-modal': 'true' }, [body]);
    document.body.appendChild(bg);
    document.body.appendChild(drawer);
    document.addEventListener('keydown', escClose);
  }
  function escClose(e) { if (e.key === 'Escape') closeDrawer(); }
  function closeDrawer() {
    $$('.drawer, .drawer-bg').forEach((n) => n.remove());
    document.removeEventListener('keydown', escClose);
  }

  /* -------------------------------------------------------------------------
     State helpers.
     ------------------------------------------------------------------------- */
  function loadingState(msg) {
    return el('div', { class: 'card' }, [el('div', { class: 'state' }, [el('div', { class: 'spin' }), el('div', { class: 'sm', text: msg || 'Loading…' })])]);
  }
  function emptyState(big, sm) {
    return el('div', { class: 'card' }, [el('div', { class: 'state' }, [el('div', { class: 'big', text: big }), el('div', { class: 'sm', text: sm || '' })])]);
  }

  /* -------------------------------------------------------------------------
     Dropdown — design-system replacement for the native <select>. Follows the
     ARIA listbox keyboard pattern (Enter/Space/↑/↓/Home/End/Esc), closes on
     outside-click, one open at a time, fully token-themed. Used everywhere a
     native select used to be (History page size, Settings mode/handover/retention).

       dropdown(items, value, onChange, opts)
         items    : [{ value, label }]
         value    : current value (compared as String)
         onChange : (newValue) => void
         opts     : { ariaLabel, block, align: 'left'|'right' }
     ------------------------------------------------------------------------- */
  let _openDropdown = null;
  function closeAllDropdowns() { if (_openDropdown) _openDropdown(); }
  document.addEventListener('click', (e) => { if (_openDropdown && !(e.target.closest && e.target.closest('.dropdown'))) closeAllDropdowns(); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && _openDropdown) closeAllDropdowns(); });
  let _ddSeq = 0;

  function dropdown(items, value, onChange, opts) {
    opts = opts || {};
    const id = 'dd' + (++_ddSeq);
    const root = el('div', { class: 'dropdown' + (opts.block ? ' block' : '') });
    const cur = () => items.find((it) => String(it.value) === String(value)) || items[0] || { label: '—' };
    const labelSpan = el('span', { class: 'dd-label', text: cur().label });
    const trigger = el('button', {
      class: 'dd-trigger', type: 'button',
      'aria-haspopup': 'listbox', 'aria-expanded': 'false', 'aria-controls': id,
      'aria-label': opts.ariaLabel || 'Select',
    }, [labelSpan, el('span', { class: 'dd-caret', html: ICON.chevD })]);
    const menu = el('div', { class: 'dd-menu' + (opts.align === 'left' ? ' left' : ''), id: id, role: 'listbox', tabindex: '-1' });
    menu.hidden = true;

    let optEls = [];
    function build() {
      menu.innerHTML = '';
      optEls = items.map((it, i) => {
        const sel = String(it.value) === String(value);
        const o = el('div', {
          class: 'dd-opt' + (sel ? ' sel' : ''), role: 'option', id: id + '-o' + i,
          'data-value': it.value, 'aria-selected': sel ? 'true' : 'false',
        }, [el('span', { class: 'dd-check', html: sel ? ICON.check : '' }), el('span', { class: 'dd-opt-label', text: it.label })]);
        o.addEventListener('click', (e) => { e.stopPropagation(); choose(it.value); });
        o.addEventListener('mousemove', () => setActive(i));
        return o;
      });
      optEls.forEach((o) => menu.appendChild(o));
    }
    let active = -1;
    function setActive(i) {
      if (!optEls.length) return;
      active = (i + optEls.length) % optEls.length;
      optEls.forEach((o, idx) => o.classList.toggle('active', idx === active));
      trigger.setAttribute('aria-activedescendant', optEls[active].id);
      optEls[active].scrollIntoView({ block: 'nearest' });
    }
    function open() {
      if (!menu.hidden) return;
      closeAllDropdowns();
      build();
      menu.hidden = false;
      trigger.setAttribute('aria-expanded', 'true');
      root.classList.add('open');
      const i = items.findIndex((it) => String(it.value) === String(value));
      setActive(i < 0 ? 0 : i);
      _openDropdown = close;
    }
    function close() {
      if (menu.hidden) return;
      menu.hidden = true;
      trigger.setAttribute('aria-expanded', 'false');
      trigger.removeAttribute('aria-activedescendant');
      root.classList.remove('open');
      _openDropdown = null;
    }
    function choose(v) {
      value = v;
      labelSpan.textContent = cur().label;
      close();
      trigger.focus();
      if (onChange) onChange(v);
    }
    trigger.addEventListener('click', (e) => { e.stopPropagation(); menu.hidden ? open() : close(); });
    trigger.addEventListener('keydown', (e) => {
      if (menu.hidden) {
        if (['ArrowDown', 'ArrowUp', 'Enter', ' '].includes(e.key)) { e.preventDefault(); open(); }
        return;
      }
      if (e.key === 'ArrowDown') { e.preventDefault(); setActive(active + 1); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); setActive(active - 1); }
      else if (e.key === 'Home') { e.preventDefault(); setActive(0); }
      else if (e.key === 'End') { e.preventDefault(); setActive(optEls.length - 1); }
      else if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); if (items[active]) choose(items[active].value); }
      else if (e.key === 'Tab') { close(); }
    });
    root.appendChild(trigger);
    root.appendChild(menu);
    return root;
  }

  /* -------------------------------------------------------------------------
     Clipboard + copyable code block (used by the About page).
     ------------------------------------------------------------------------- */
  async function copyText(text) {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) { await navigator.clipboard.writeText(text); return true; }
    } catch (e) { /* fall through to legacy path */ }
    try {
      const ta = el('textarea', { style: 'position:fixed;opacity:0;top:0;left:0' });
      ta.value = text; document.body.appendChild(ta); ta.select();
      const ok = document.execCommand('copy'); ta.remove(); return ok;
    } catch (e) { return false; }
  }

  // A code/pre block with a Copy button. `opts`: { title, lang }.
  function copyBlock(text, opts) {
    opts = opts || {};
    const btn = el('button', { class: 'copybtn', type: 'button', 'aria-label': 'Copy to clipboard', html: ICON.copy + '<span>Copy</span>' });
    btn.addEventListener('click', async () => {
      const ok = await copyText(text);
      btn.classList.toggle('done', ok);
      btn.innerHTML = (ok ? ICON.check : ICON.copy) + '<span>' + (ok ? 'Copied' : 'Copy') + '</span>';
      setTimeout(() => { btn.classList.remove('done'); btn.innerHTML = ICON.copy + '<span>Copy</span>'; }, 1800);
    });
    const head = el('div', { class: 'codehead' }, [
      el('span', { class: 'codetitle', text: opts.title || (opts.lang || 'snippet') }),
      el('div', { class: 'spacer' }),
      btn,
    ]);
    return el('div', { class: 'codeblock' }, [head, el('pre', {}, [el('code', { text: text })])]);
  }

  /* -------------------------------------------------------------------------
     confirmModal — design-system confirmation dialog. Replaces the native
     window.confirm() everywhere so every prompt matches the Studio's look and
     theme (no browser chrome). Returns a Promise<boolean>.

       await confirmModal({ title, body, confirmLabel, cancelLabel, danger })

     Keyboard: Esc / backdrop = cancel, Enter = confirm. Body supports blank-line
     separated paragraphs.
     ------------------------------------------------------------------------- */
  function confirmModal(opts) {
    opts = opts || {};
    return new Promise((resolve) => {
      let done = false;
      const finish = (val) => {
        if (done) return;
        done = true;
        document.removeEventListener('keydown', onKey, true);
        bg.classList.add('closing');
        setTimeout(() => bg.remove(), 120);
        resolve(val);
      };
      const onKey = (e) => {
        if (e.key === 'Escape') { e.preventDefault(); finish(false); }
        else if (e.key === 'Enter') { e.preventDefault(); finish(true); }
        else if (e.key === 'Tab') {
          // simple focus trap between the two buttons
          const f = [cancelBtn, okBtn];
          const i = f.indexOf(document.activeElement);
          e.preventDefault();
          f[(i + (e.shiftKey ? f.length - 1 : 1)) % f.length].focus();
        }
      };

      const cancelBtn = el('button', { class: 'btn auto', type: 'button', text: opts.cancelLabel || 'Cancel' });
      cancelBtn.addEventListener('click', () => finish(false));
      const okBtn = el('button', { class: 'btn auto ' + (opts.danger ? 'danger' : 'primary'), type: 'button', text: opts.confirmLabel || 'Confirm' });
      okBtn.addEventListener('click', () => finish(true));

      const body = el('div', { class: 'modal-body' });
      String(opts.body || '').split('\n\n').forEach((para) => { if (para.trim()) body.appendChild(el('p', { text: para.trim() })); });

      const card = el('div', { class: 'modal', role: 'alertdialog', 'aria-modal': 'true' }, [
        el('div', { class: 'modal-ic ' + (opts.danger ? 'danger' : 'brand'), html: opts.danger ? ICON.alert : ICON.shield }),
        el('h2', { class: 'modal-title', text: opts.title || 'Are you sure?' }),
        body,
        el('div', { class: 'modal-actions' }, [cancelBtn, okBtn]),
      ]);
      const bg = el('div', { class: 'modal-bg' });
      bg.addEventListener('click', (e) => { if (e.target === bg) finish(false); });
      bg.appendChild(card);
      document.body.appendChild(bg);
      document.addEventListener('keydown', onKey, true);
      setTimeout(() => okBtn.focus(), 30);
    });
  }

  /* =========================================================================
     PAGE: LIVE
     ========================================================================= */
  const Live = {
    title: 'Live',
    sub: 'What your apps are doing with local models — right now.',
    stream: null,         // legacy handle (unused; fetch-reader drives the feed)
    _streamCtrl: null,    // AbortController for the in-flight stream fetch
    _streamTimer: null,   // reconnect backoff timer
    _stopStream: false,
    _streamRetry: 0,
    seen: {},             // id -> row element (for in-place updates)
    kpis: { requestsToday: 0, p50: null, pii: 0 },
    masking: { enabled: false, dryRun: true },  // synced from /api/settings
    _lastRecent: [],      // last recent window (for re-rendering the privacy lens)

    async render(view) {
      view.innerHTML = '';
      // KPI section
      const kpis = el('section', { class: 'grid kpis' }, [
        kpiCard('brand', ICON.pulse, 'Requests today', el('div', { class: 'val num', id: 'kpiReq', text: '—' }), el('div', { class: 'meta', id: 'kpiReqMeta', text: 'since midnight' })),
        kpiCard('gold', ICON.clock, 'Latency p50', el('div', { class: 'val num', id: 'kpiLat', html: '—' }), el('div', { class: 'meta mono', id: 'kpiLatMeta', text: 'recent window' })),
        kpiCard('danger', ICON.shieldAlert, 'PII findings', el('div', { class: 'val num', id: 'kpiPii', text: '—' }), el('div', { class: 'meta', id: 'kpiPiiMeta', text: 'observe-only · today' })),
        exposureHeroPlaceholder(),
      ]);
      kpis.className = 'grid kpis reveal';
      view.appendChild(kpis);

      // body: stream + side panels
      const streamCard = el('div', { class: 'card reveal', style: 'animation-delay:.3s' }, [
        el('div', { class: 'hrow' }, [
          el('h3', { text: 'Traffic stream' }),
          el('div', { class: 'spacer' }),
          el('span', { class: 'tag live off', id: 'liveTag', html: '<span class="blip"></span> Idle' }),
        ]),
        el('div', { class: 'ttable', style: '--gtc:' + gtcFor(LIVE_COLS) }, [
          reqHead(LIVE_COLS),
          el('div', { class: 'stream', id: 'stream' }),
        ]),
      ]);

      const side = el('div', { class: 'grid', style: 'align-content:start;gap:16px' }, [
        el('div', { class: 'card reveal', id: 'livePrivacy', style: 'animation-delay:.36s' }, [
          el('div', { class: 'hrow' }, [el('h3', { text: 'Privacy lens' }), el('div', { class: 'spacer' }), el('span', { class: 'tag', text: 'observe' })]),
          el('div', { id: 'livePrivacyBody' }, [el('div', { class: 'state sm', text: 'No findings yet.' })]),
        ]),
        el('div', { class: 'card engine reveal', id: 'liveEngine', style: 'animation-delay:.42s' }, [
          el('div', { class: 'state sm', text: 'Loading engine…' }),
        ]),
      ]);

      const body = el('section', { class: 'body livebody' }, [streamCard, side]);
      view.appendChild(body);
      view.appendChild(cliBlock());

      await this.refresh();
      this.connectStream();
    },

    async refresh() {
      try {
        const snap = await api('/live');
        hideBanner();
        this.kpis.requestsToday = snap.requestsToday;
        this.kpis.p50 = snap.p50LatencyMs;
        this.kpis.pii = snap.piiFindingsToday;
        setText('#kpiReq', fmtNum(snap.requestsToday));
        const lat = $('#kpiLat');
        if (lat) lat.innerHTML = snap.p50LatencyMs != null ? esc(snap.p50LatencyMs) + '<small>ms</small>' : '—';
        setText('#kpiPii', fmtNum(snap.piiFindingsToday));
        updatePiiBadge(snap.piiFindingsToday);

        // seed stream (newest first; render oldest→newest by appending in reverse)
        const stream = $('#stream');
        if (stream) {
          stream.innerHTML = '';
          this.seen = {};
          const recent = (snap.recent || []).slice(0, 8);
          if (recent.length === 0) {
            stream.appendChild(el('div', { class: 'state sm', style: 'padding:24px 6px', text: 'Waiting for traffic… run a prompt in any local-LLM app.' }));
          } else {
            recent.forEach((it) => {
              const row = reqRow(it, { columns: LIVE_COLS });
              this.seen[it.id] = row;
              stream.appendChild(row);
            });
          }
        }
        // privacy lens from recent
        this.renderPrivacyLens(snap.recent || []);
      } catch (e) { handleApiError(e); }

      // engine + exposure (best-effort, independent of /live)
      try {
        const ev = await api('/engines');
        this.renderEngine(ev);
        this.renderExposureHero(ev.exposure);
        setEnginePill(ev);
      } catch (e) { /* banner already covers hard failures */ }

      // masking state (best-effort) — keeps the Live toggle in sync with Settings.
      try {
        const s = await api('/settings');
        this.masking = { enabled: !!s.maskingEnabled, dryRun: !!s.maskingDryRun };
        this.renderMaskingBar();
      } catch (e) { /* leave the bar at its last-known state */ }
    },

    renderPrivacyLens(recent) {
      this._lastRecent = recent;
      const counts = {};
      recent.forEach((it) => (it.piiKinds || []).forEach((k) => { counts[k] = (counts[k] || 0) + 1; }));
      const body = $('#livePrivacyBody');
      if (!body) return;
      body.innerHTML = '';
      const kinds = Object.keys(counts).sort((a, b) => counts[b] - counts[a]);
      if (kinds.length === 0) {
        body.appendChild(el('div', { class: 'expnote', html: ICON.check + ' No PII observed in the recent window.' }));
      } else {
        // Keep the lens compact: show the top 2 kinds; link out for the rest so
        // the card never grows tall enough to drag the right column down.
        kinds.slice(0, 2).forEach((k) => {
          body.appendChild(el('div', { class: 'pii-row' }, [
            el('div', { class: 'swt ic ' + piiRole(k), html: piiIcon(k) }),
            el('div', {}, [el('div', { class: 'nm', text: piiLabel(k) }), el('div', { class: 'cf', text: 'observed' })]),
            el('div', { class: 'ct', text: String(counts[k]) }),
          ]));
        });
        const extra = kinds.length - 2;
        body.appendChild(el('a', { class: 'pii-more', href: '#/privacy', html: '<span>' + (extra > 0 ? '+' + extra + ' more · view full breakdown' : 'View full breakdown') + '</span>' + ICON.chevR }));
      }
      body.appendChild(el('div', { class: 'modebar', id: 'liveMaskBar' }));
      this.renderMaskingBar();
    },

    // Functional masking toggle, reflecting the real /api/settings state and
    // syncing with the Settings page. Masking is live-reloadable, so flipping it
    // here applies immediately (no restart).
    renderMaskingBar() {
      const bar = $('#liveMaskBar');
      if (!bar) return;
      const on = this.masking.enabled;
      const txt = on
        ? 'Masking is <b>on</b> · ' + (this.masking.dryRun ? 'dry-run (observing)' : 'live (redacting)')
        : 'Masking is <b>off</b> — observe only';
      const sw = el('button', { class: 'switch' + (on ? ' on' : ''), 'aria-label': 'Toggle PII masking', title: on ? 'Masking on — click to turn off' : 'Masking off — click to turn on' });
      sw.addEventListener('click', () => this.toggleMasking(!on, sw));
      bar.innerHTML = '';
      bar.appendChild(el('div', { class: 't', html: txt }));
      bar.appendChild(sw);
    },

    async toggleMasking(next, sw) {
      if (sw) sw.disabled = true;
      try {
        const updated = await api('/settings', { method: 'PUT', body: { maskingEnabled: next } });
        this.masking = { enabled: !!updated.maskingEnabled, dryRun: !!updated.maskingDryRun };
        hideBanner();
      } catch (e) { handleApiError(e); }
      this.renderMaskingBar();
    },

    renderEngine(ev) {
      const card = $('#liveEngine');
      if (!card) return;
      const eng = (ev.engines && ev.engines[0]) || null;
      card.innerHTML = '';
      if (!eng) {
        card.appendChild(el('div', { class: 'state sm', text: 'No engine detected.' }));
        return;
      }
      const healthPill = healthToPill(eng.health);
      card.appendChild(el('div', { class: 'hrow' }, [
        el('h3', { text: 'Engine' }), el('div', { class: 'spacer' }),
        el('span', { class: 'pill ' + healthPill.cls, style: 'box-shadow:none', html: '<span class="dot"></span> ' + esc(eng.health) }),
      ]));
      card.appendChild(el('div', { class: 'top' }, [
        el('div', { class: 'logo', html: ICON.ollama }),
        el('div', {}, [
          el('div', { class: 'nm', text: eng.engine + (eng.version ? ' ' + eng.version : '') }),
          el('div', { class: 'st', text: ev.mode + ' · ' + eng.adoptionState }),
        ]),
      ]));
      // Ports + exposure live on the Exposure KPI card and the Engines page;
      // keep this card compact (engine identity + Manage).
      card.appendChild(el('div', { class: 'btnrow' }, [
        el('a', { class: 'btn', href: '#/engines', html: ICON.server + ' Manage' }),
      ]));
    },

    renderExposureHero(exp) {
      const host = $('#exposureHero');
      if (!host) return;
      const exposed = exp.exposed;
      const card = el('div', { class: 'card kpi hero' + (exposed ? ' dangerhero' : ''), style: 'animation-delay:.26s' }, [
        el('div', { class: 'label' }, [el('span', { class: 'ic ' + (exposed ? 'danger' : 'safe'), html: exposed ? ICON.shieldAlert : ICON.shield }), document.createTextNode(' Exposure')]),
        el('div', { class: 'val' }, [
          el('span', { class: 'check', html: exposed ? ICON.alert : ICON.check }),
          document.createTextNode(exposed ? 'Exposed' : 'Localhost only'),
        ]),
        el('div', { class: 'meta', text: exp.detail || (exposed ? 'Reachable beyond this device' : 'Bound to 127.0.0.1 — not exposed') }),
      ]);
      host.replaceWith(card);
      card.id = 'exposureHero';
    },

    /* ---- SSE ----
       The wire contract gates /api/* with `Authorization: Bearer <token>`. The
       browser `EventSource` API cannot set request headers, so we consume the
       SSE stream with `fetch()` + a streaming `ReadableStream` reader, which can
       send the bearer header (same-origin → no CORS preflight). We parse the
       text/event-stream framing ourselves and auto-reconnect with backoff. */
    connectStream() {
      this.disconnectStream();
      this._stopStream = false;
      this._streamRetry = 0;
      this._runStream();
    },

    setLiveTag(state) {
      const tag = $('#liveTag');
      if (!tag) return;
      if (state === 'live') { tag.className = 'tag live'; tag.innerHTML = '<span class="blip"></span> Live'; }
      else if (state === 'reconnecting') { tag.className = 'tag live off'; tag.innerHTML = '<span class="blip"></span> Reconnecting…'; }
      else { tag.className = 'tag live off'; tag.innerHTML = '<span class="blip"></span> Idle'; }
    },

    async _runStream() {
      if (this._stopStream) return;
      const ctrl = new AbortController();
      this._streamCtrl = ctrl;
      const headers = { Accept: 'text/event-stream' };
      if (TOKEN) headers['Authorization'] = 'Bearer ' + TOKEN;
      // ?token= kept as a hint for any backend that also accepts a query token.
      const url = TOKEN ? '/api/stream?token=' + encodeURIComponent(TOKEN) : '/api/stream';
      try {
        const res = await fetch(url, { headers, signal: ctrl.signal, cache: 'no-store' });
        if (!res.ok || !res.body) {
          if (res.status === 401 || res.status === 403) { handleApiError({ status: res.status }); }
          throw new Error('stream HTTP ' + res.status);
        }
        hideBanner();
        this._streamRetry = 0;
        this.setLiveTag('live');
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buf = '';
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buf += decoder.decode(value, { stream: true });
          // SSE frames are separated by a blank line.
          let idx;
          while ((idx = buf.indexOf('\n\n')) !== -1) {
            const frame = buf.slice(0, idx);
            buf = buf.slice(idx + 2);
            this._handleFrame(frame);
          }
        }
      } catch (e) {
        if (this._stopStream || (e && e.name === 'AbortError')) return;
      }
      // Connection ended/failed — reconnect with capped backoff.
      if (this._stopStream) return;
      this.setLiveTag('reconnecting');
      this._streamRetry = Math.min(this._streamRetry + 1, 6);
      const delay = Math.min(1000 * Math.pow(2, this._streamRetry - 1), 15000);
      this._streamTimer = setTimeout(() => this._runStream(), delay);
    },

    // Parse one SSE frame ("data:" / multi-line "data:" / ignored "event:"/":").
    _handleFrame(frame) {
      const dataLines = [];
      frame.split('\n').forEach((line) => {
        if (line.startsWith('data:')) dataLines.push(line.slice(5).replace(/^ /, ''));
      });
      if (!dataLines.length) return;
      let msg;
      try { msg = JSON.parse(dataLines.join('\n')); } catch (e) { return; }
      this.onEvent(msg);
    },

    disconnectStream() {
      this._stopStream = true;
      if (this._streamTimer) { clearTimeout(this._streamTimer); this._streamTimer = null; }
      if (this._streamCtrl) { try { this._streamCtrl.abort(); } catch (e) {} this._streamCtrl = null; }
      this.stream = null;
    },

    onEvent(msg) {
      const stream = $('#stream');
      if (!stream) return;
      // clear any "waiting" placeholder
      const ph = stream.querySelector('.state'); if (ph) ph.remove();

      if (msg.type === 'requestStarted') {
        const it = msg.item;
        const row = reqRow(it, { columns: LIVE_COLS, streaming: it.stream, enter: true });
        this.seen[it.id] = row;
        stream.prepend(row);
        while (stream.children.length > 8) {
          const last = stream.lastElementChild;
          if (last && last.dataset.id) delete this.seen[last.dataset.id];
          last.remove();
        }
        this.bumpRequests();
        setTimeout(() => row.classList.remove('enter'), 1400);
      } else if (msg.type === 'token') {
        const row = this.seen[msg.id];
        if (row) row.classList.add('streaming');
      } else if (msg.type === 'finished') {
        const it = msg.item;
        const fresh = reqRow(it, { columns: LIVE_COLS });
        const old = this.seen[it.id];
        if (old && old.parentNode) { old.parentNode.replaceChild(fresh, old); }
        else { stream.prepend(fresh); }
        this.seen[it.id] = fresh;
      } else if (msg.type === 'pii') {
        // Badges render from the row item's piiKinds (collapsed to "first + N");
        // the live finding event just advances the KPI + privacy lens.
        this.bumpPii();
      }
    },

    bumpRequests() {
      this.kpis.requestsToday += 1;
      setText('#kpiReq', fmtNum(this.kpis.requestsToday));
    },
    bumpPii() {
      this.kpis.pii += 1;
      setText('#kpiPii', fmtNum(this.kpis.pii));
      updatePiiBadge(this.kpis.pii);
    },

    teardown() { this.disconnectStream(); },
  };

  function exposureHeroPlaceholder() {
    return el('div', { class: 'card kpi hero', id: 'exposureHero', style: 'animation-delay:.26s' }, [
      el('div', { class: 'label' }, [el('span', { class: 'ic safe', html: ICON.shield }), document.createTextNode(' Exposure')]),
      el('div', { class: 'val' }, [el('span', { class: 'check', html: ICON.check }), document.createTextNode('Checking…')]),
      el('div', { class: 'meta', text: 'Reading exposure doctor' }),
    ]);
  }

  function kpiCard(role, icon, label, valNode, metaNode) {
    return el('div', { class: 'card kpi reveal' }, [
      el('div', { class: 'label' }, [el('span', { class: 'ic ' + role, html: icon }), document.createTextNode(' ' + label)]),
      valNode,
      metaNode,
    ]);
  }

  function cliBlock() {
    const pre =
      '<span class="p">~</span> <span class="v">' + esc(BRAND.command) + ' status</span>\n' +
      '<span class="g">●</span> proxy      <span class="c">:11434</span> <span class="m">▸</span> ollama <span class="c">:11999</span>      <span class="g">healthy</span>\n' +
      '<span class="g">●</span> privacy    metadata-only <span class="m">·</span> encrypted (keyring)\n' +
      '<span class="g">●</span> exposure   localhost-only  <span class="g">✓ not exposed</span>\n' +
      '<span class="p">~</span> <span class="v">_</span>';
    return el('div', { class: 'cli reveal', style: 'animation-delay:.48s' }, [
      el('div', { class: 'bar' }, [
        el('div', { class: 'tl', html: '<i></i><i></i><i></i>' }),
        el('div', { class: 'ti', text: BRAND.command + ' — zsh — the CLI speaks the same language' }),
      ]),
      el('pre', { html: pre }),
    ]);
  }

  /* =========================================================================
     PAGE: HISTORY
     ========================================================================= */
  /* Paginated: instead of an endlessly-growing "Load older" list, History now
     shows ONE page of results in a fixed, internally-scrolling card and moves
     between pages with Prev/Next "tabs" + a rows-per-page drop-down. The API is
     cursor-based (`beforeTs`), so we keep fetched pages in `pages[]` and walk a
     `pageIndex`; going forward past the last fetched page fetches the next one. */
  const History = {
    title: 'History',
    sub: 'Every proxied exchange — searchable, filterable, on-device.',
    q: '', piiOnly: false, pageSize: 25,
    pages: [],        // fetched pages: array of arrays of HistoryItem (each non-empty)
    pageIndex: 0,     // which fetched page is currently shown (0-based)
    exhausted: false, // true once the last fetch returned < pageSize (no more pages)
    loading: false,

    async render(view) {
      this.q = ''; this.piiOnly = false; this.pages = []; this.pageIndex = 0; this.exhausted = false;
      view.innerHTML = '';

      // toolbar: search + PII-only + rows-per-page drop-down
      const search = el('input', { class: 'input', type: 'search', placeholder: 'Search app, model, or endpoint…', value: this.q });
      let t;
      search.addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => { this.q = search.value.trim(); this.reload(); }, 250); });
      const piiToggle = el('label', { class: 'chk' }, [
        (() => { const c = el('input', { type: 'checkbox' }); c.addEventListener('change', () => { this.piiOnly = c.checked; this.reload(); }); return c; })(),
        document.createTextNode('PII only'),
      ]);
      const sizeSel = dropdown(
        [10, 25, 50, 100].map((n) => ({ value: n, label: n + ' / page' })),
        this.pageSize,
        (v) => { this.pageSize = parseInt(v, 10); this.reload(); },
        { ariaLabel: 'Rows per page', align: 'right' }
      );
      const toolbar = el('div', { class: 'toolbar reveal' }, [search, piiToggle, sizeSel]);

      // bounded, internally-scrolling list card (columnar table; header fixed above the scroll body)
      const listCard = el('div', { class: 'card reveal', style: 'animation-delay:.06s' }, [
        el('div', { class: 'ttable', style: '--gtc:' + gtcFor(HIST_COLS) }, [
          reqHead(HIST_COLS),
          el('div', { class: 'list', id: 'histList' }),
        ]),
      ]);

      // pager: row-count + Prev / page indicator / Next
      const prevBtn = el('button', { class: 'pgbtn', id: 'histPrev', html: ICON.chevL + '<span>Prev</span>' });
      prevBtn.addEventListener('click', () => this.goPrev());
      const nextBtn = el('button', { class: 'pgbtn', id: 'histNext', html: '<span>Next</span>' + ICON.chevR });
      nextBtn.addEventListener('click', () => this.goNext());
      const pager = el('div', { class: 'pager reveal', style: 'animation-delay:.1s' }, [
        el('span', { class: 'count', id: 'histCount' }),
        el('div', { class: 'grow' }),
        el('div', { class: 'pgnav' }, [prevBtn, el('span', { class: 'pgind', id: 'histPgInd' }), nextBtn]),
      ]);

      view.appendChild(toolbar);
      view.appendChild(listCard);
      view.appendChild(pager);
      await this.reload();
    },

    async reload() {
      this.pages = []; this.pageIndex = 0; this.exhausted = false;
      const list = $('#histList');
      if (list) { list.innerHTML = ''; list.appendChild(el('div', { class: 'state' }, [el('div', { class: 'spin' }), el('div', { class: 'sm', text: 'Loading history…' })])); }
      this.setPagerDisabled(true);
      await this.fetchNextPage();
      this.renderPage();
    },

    // Fetch the page after the last one we hold (cursor = ts of its last row).
    async fetchNextPage() {
      if (this.loading || this.exhausted) return;
      this.loading = true;
      const params = new URLSearchParams();
      if (this.q) params.set('q', this.q);
      if (this.piiOnly) params.set('piiOnly', 'true');
      params.set('limit', String(this.pageSize));
      const last = this.pages[this.pages.length - 1];
      if (last && last.length) params.set('beforeTs', String(last[last.length - 1].ts));
      let rows;
      try { rows = await api('/history?' + params.toString()); hideBanner(); }
      catch (e) { handleApiError(e); this.loading = false; return; }
      if (rows.length < this.pageSize) this.exhausted = true;
      if (rows.length > 0) this.pages.push(rows);
      this.loading = false;
    },

    async goNext() {
      if (this.loading) return;
      if (this.pageIndex < this.pages.length - 1) { this.pageIndex++; this.renderPage(); return; }
      if (this.exhausted) return;
      this.setPagerDisabled(true);
      await this.fetchNextPage();
      if (this.pageIndex < this.pages.length - 1) this.pageIndex++;
      this.renderPage();
    },

    goPrev() {
      if (this.loading || this.pageIndex === 0) return;
      this.pageIndex--;
      this.renderPage();
    },

    renderPage() {
      const list = $('#histList');
      if (!list) return;
      const page = this.pages[this.pageIndex] || [];
      list.innerHTML = '';
      if (page.length === 0) {
        list.appendChild(el('div', { class: 'state' }, [
          el('div', { class: 'big', text: 'No matching exchanges' }),
          el('div', { class: 'sm', text: (this.q || this.piiOnly) ? 'Try clearing the filters.' : 'Traffic will appear here as your apps talk to local models.' }),
        ]));
      } else {
        page.forEach((it) => list.appendChild(reqRow(it, { columns: HIST_COLS })));
        list.scrollTop = 0;
      }

      // pager labels + button state
      const base = this.pageIndex * this.pageSize;
      const count = $('#histCount');
      if (count) {
        const totalLoaded = this.pages.reduce((a, p) => a + p.length, 0);
        count.textContent = page.length
          ? 'Showing ' + (base + 1) + '–' + (base + page.length) + (this.exhausted ? ' of ' + totalLoaded : '')
          : '';
      }
      const ind = $('#histPgInd');
      if (ind) { ind.innerHTML = ''; ind.appendChild(document.createTextNode('Page ')); ind.appendChild(el('b', { text: String(this.pageIndex + 1) })); }
      const prev = $('#histPrev'); if (prev) prev.disabled = this.pageIndex === 0;
      const next = $('#histNext'); if (next) next.disabled = (this.pageIndex >= this.pages.length - 1) && this.exhausted;
    },

    setPagerDisabled(d) {
      const prev = $('#histPrev'); if (prev) prev.disabled = d || this.pageIndex === 0;
      const next = $('#histNext'); if (next) next.disabled = d;
    },

    teardown() {},
  };

  /* =========================================================================
     PAGE: PRIVACY
     ========================================================================= */
  const Privacy = {
    title: 'Privacy',
    sub: 'Deterministic PII detection — observe-only, on this device.',

    async render(view) {
      view.innerHTML = '';
      view.appendChild(loadingState('Aggregating findings…'));
      let s;
      try { s = await api('/privacy'); hideBanner(); }
      catch (e) { handleApiError(e); view.innerHTML = ''; view.appendChild(emptyState('Could not load privacy data', e.message || '')); return; }
      view.innerHTML = '';

      const totalKinds = s.byKind || [];
      const maxKind = Math.max(1, ...totalKinds.map((b) => b.count));

      // KPI strip
      const reqSide = totalKinds.reduce((a, b) => a + (b.requestCount || 0), 0);
      const respSide = totalKinds.reduce((a, b) => a + (b.responseCount || 0), 0);
      const kpis = el('section', { class: 'grid kpis reveal' }, [
        kpiCard('danger', ICON.shieldAlert, 'Total findings', el('div', { class: 'val num', text: fmtNum(s.total) }), el('div', { class: 'meta', text: 'across retained window' })),
        kpiCard('warn', ICON.pulse, 'On request', el('div', { class: 'val num', text: fmtNum(reqSide) }), el('div', { class: 'meta', text: 'outbound to the model' })),
        kpiCard('brand', ICON.clock, 'On response', el('div', { class: 'val num', text: fmtNum(respSide) }), el('div', { class: 'meta', text: 'returned from the model' })),
        (() => {
          const masking = !!s.maskingEnabled;
          return el('div', { class: 'card kpi hero' + (masking ? '' : ''), style: '' }, [
            el('div', { class: 'label' }, [el('span', { class: 'ic safe', html: ICON.shield }), document.createTextNode(' Masking')]),
            el('div', { class: 'val' }, [el('span', { class: 'check', html: masking ? ICON.check : ICON.shield }), document.createTextNode(masking ? 'On' : 'Observe-only')]),
            el('div', { class: 'meta', text: masking ? 'Findings are masked' : 'Nothing is altered — detection only' }),
          ]);
        })(),
      ]);
      view.appendChild(kpis);

      // by kind
      const kindCard = el('div', { class: 'card reveal', style: 'animation-delay:.06s' }, [
        el('div', { class: 'hrow' }, [el('h3', { text: 'By type' }), el('div', { class: 'spacer' }), el('span', { class: 'tag', text: 'observe' })]),
      ]);
      if (totalKinds.length === 0) {
        kindCard.appendChild(el('div', { class: 'expnote', html: ICON.check + ' No PII detected in the retained window.' }));
      } else {
        totalKinds.slice().sort((a, b) => b.count - a.count).forEach((b) => {
          kindCard.appendChild(el('div', { class: 'pii-row' }, [
            el('div', { class: 'swt ic ' + piiRole(b.kind), html: piiIcon(b.kind) }),
            el('div', {}, [
              el('div', { class: 'nm', text: piiLabel(b.kind) }),
              el('div', { class: 'cf', text: fmtNum(b.requestCount) + ' request · ' + fmtNum(b.responseCount) + ' response' }),
            ]),
            el('div', { class: 'ct', text: fmtNum(b.count) }),
          ]));
        });
      }

      // by app + by model
      const breakdowns = el('section', { class: 'body', style: 'margin-top:16px' }, [
        kindCard,
        el('div', { class: 'grid', style: 'align-content:start;gap:16px' }, [
          breakdownCard('By app', s.byApp || []),
          breakdownCard('By model', s.byModel || []),
        ]),
      ]);
      view.appendChild(breakdowns);
      updatePiiBadge(s.total);
    },
    teardown() {},
  };

  function breakdownCard(title, list) {
    const card = el('div', { class: 'card reveal' }, [
      el('div', { class: 'hrow' }, [el('h3', { text: title })]),
    ]);
    if (!list.length) { card.appendChild(el('div', { class: 'state sm', text: 'No data yet.' })); return card; }
    const max = Math.max(1, ...list.map((x) => x.count));
    const wrap = el('div', { class: 'bk-list' });
    list.slice(0, 8).forEach((x) => {
      wrap.appendChild(el('div', { class: 'bk' }, [
        el('div', { class: 'nm', text: x.name || 'Unknown' }),
        el('div', { class: 'bar' }, [el('i', { style: 'width:' + Math.round((x.count / max) * 100) + '%' })]),
        el('div', { class: 'ct', text: fmtNum(x.count) }),
      ]));
    });
    card.appendChild(wrap);
    return card;
  }

  /* =========================================================================
     PAGE: ENGINES
     ========================================================================= */
  const Engines = {
    title: 'Engines',
    sub: 'Detected engines, exposure doctor, and adopt / revert controls.',
    busy: false,

    async render(view) {
      view.innerHTML = '';
      view.appendChild(loadingState('Detecting engines…'));
      await this.refresh(view);
    },

    async refresh(view) {
      view = view || $('#view');
      let ev;
      try { ev = await api('/engines'); hideBanner(); }
      catch (e) { handleApiError(e); view.innerHTML = ''; view.appendChild(emptyState('Could not load engines', e.message || '')); return; }
      view.innerHTML = '';
      setEnginePill(ev);

      // exposure doctor hero
      const exp = ev.exposure;
      const heroCls = exp.exposed ? ' dangerhero' : '';
      const hero = el('div', { class: 'card kpi hero' + heroCls + ' reveal' }, [
        el('div', { class: 'label' }, [el('span', { class: 'ic ' + (exp.exposed ? 'danger' : 'safe'), html: exp.exposed ? ICON.shieldAlert : ICON.shield }), document.createTextNode(' Exposure doctor')]),
        el('div', { class: 'val' }, [el('span', { class: 'check', html: exp.exposed ? ICON.alert : ICON.check }), document.createTextNode(exp.exposed ? 'Exposed' : 'Localhost only')]),
        el('div', { class: 'meta', text: exposureLine(exp) }),
        el('div', { class: 'meta mono', style: 'margin-top:6px', text: 'auth ' + (exp.tokenProtected ? 'protected' : 'unprotected') + (exp.boundTo ? ' · bound ' + exp.boundTo : '') }),
      ]);
      const heroWrap = el('section', { class: 'grid', style: 'grid-template-columns:repeat(2,1fr);margin-bottom:16px' }, [
        hero,
        el('div', { class: 'card reveal', style: 'animation-delay:.06s' }, [
          el('div', { class: 'hrow' }, [el('h3', { text: 'Mode' }), el('div', { class: 'spacer' }), el('span', { class: 'tag', text: ev.mode })]),
          el('div', { class: 'muted', style: 'font-size:.86rem;margin-top:8px', text: ev.mode === 'gateway'
            ? 'Gateway — Saffev supervises the engine and owns the public port, forwarding to a shadow port.'
            : 'Cooperative — apps point at Saffev; the engine keeps running independently. Universal, zero-config.' }),
        ]),
      ]);
      view.appendChild(heroWrap);

      // engine cards
      if (!ev.engines || ev.engines.length === 0) {
        view.appendChild(emptyState('No engines detected', 'Start your local LLM engine (e.g. Ollama on :11434) and refresh.'));
        return;
      }
      const grid = el('section', { class: 'grid', style: 'grid-template-columns:repeat(auto-fill,minmax(320px,1fr))' });
      ev.engines.forEach((eng) => grid.appendChild(this.engineCard(eng, ev.mode, exp)));
      view.appendChild(grid);
    },

    engineCard(eng, mode, exp) {
      const adopted = eng.adoptionState === 'adopted' || eng.adoptionState === 'cooperative';
      const healthPill = healthToPill(eng.health);
      const card = el('div', { class: 'card engine reveal' });
      card.appendChild(el('div', { class: 'hrow' }, [
        el('h3', { text: 'Engine' }), el('div', { class: 'spacer' }),
        el('span', { class: 'pill ' + healthPill.cls, style: 'box-shadow:none', html: '<span class="dot"></span> ' + esc(eng.health) }),
      ]));
      card.appendChild(el('div', { class: 'top' }, [
        el('div', { class: 'logo', html: ICON.ollama }),
        el('div', {}, [
          el('div', { class: 'nm', text: eng.engine + (eng.version ? ' ' + eng.version : '') }),
          el('div', { class: 'st', text: mode + ' · ' + eng.adoptionState }),
        ]),
      ]));
      const portsLine = el('div', { class: 'ports' });
      portsLine.innerHTML = '<span class="muted">public</span> :' + esc(eng.publicPort) +
        (eng.shadowPort != null ? ' <span class="arr">→</span> <span class="muted">shadow</span> :' + esc(eng.shadowPort) : '');
      card.appendChild(portsLine);
      card.appendChild(el('div', { class: 'expnote' + (exp.exposed ? ' danger' : ''), html: (exp.exposed ? ICON.alert : ICON.check) + ' ' + esc(exposureLine(exp)) }));

      // adopt / revert buttons
      const btnrow = el('div', { class: 'btnrow' });
      if (adopted) {
        const revertBtn = el('button', { class: 'btn', html: ICON.revert + ' Revert' });
        revertBtn.addEventListener('click', () => this.doRevert(eng.engine, revertBtn));
        const stateBtn = el('button', { class: 'btn primary', disabled: true, html: ICON.check + ' ' + (eng.adoptionState === 'cooperative' ? 'Cooperative' : 'Adopted') });
        btnrow.appendChild(revertBtn);
        btnrow.appendChild(stateBtn);
      } else {
        const coopBtn = el('button', { class: 'btn', text: 'Cooperative' });
        coopBtn.addEventListener('click', () => this.doAdopt(eng.engine, true, coopBtn));
        const adoptBtn = el('button', { class: 'btn primary', html: ICON.check + ' Adopt (Gateway)' });
        adoptBtn.addEventListener('click', () => this.doAdopt(eng.engine, false, adoptBtn));
        btnrow.appendChild(coopBtn);
        btnrow.appendChild(adoptBtn);
      }
      card.appendChild(btnrow);
      return card;
    },

    async doAdopt(engine, cooperative, btn) {
      if (this.busy) return; this.busy = true; setBusy(btn, true);
      try {
        await api('/engines/adopt', { method: 'POST', body: { engine, cooperative } });
        await this.refresh();
      } catch (e) { handleApiError(e); setBusy(btn, false); }
      this.busy = false;
    },
    async doRevert(engine, btn) {
      if (this.busy) return; this.busy = true; setBusy(btn, true);
      try {
        await api('/engines/revert', { method: 'POST', body: { engine } });
        await this.refresh();
      } catch (e) { handleApiError(e); setBusy(btn, false); }
      this.busy = false;
    },
    teardown() {},
  };

  /* =========================================================================
     PAGE: SETTINGS
     ========================================================================= */
  const Settings = {
    title: 'Settings',
    sub: 'Local configuration — written to the on-device config file.',
    saving: false,
    tab: 'general',  // preserved across re-draws so a toggle doesn't jump tabs

    async render(view) {
      view.innerHTML = '';
      view.appendChild(loadingState('Loading settings…'));
      let s;
      try { s = await api('/settings'); hideBanner(); }
      catch (e) { handleApiError(e); view.innerHTML = ''; view.appendChild(emptyState('Could not load settings', e.message || '')); return; }
      view.innerHTML = '';
      this.draw(view, s);
    },

    draw(view, s) {
      view.innerHTML = '';
      const TABS = [
        { key: 'general', label: 'General', icon: ICON.server },
        { key: 'privacy', label: 'Privacy & data', icon: ICON.shield },
        { key: 'system', label: 'System', icon: ICON.terminal },
      ];
      const bar = el('div', { class: 'tabbar reveal', role: 'tablist', 'aria-label': 'Settings sections' });
      TABS.forEach((t) => {
        const sel = this.tab === t.key;
        const b = el('button', { class: 'tab' + (sel ? ' active' : ''), type: 'button', role: 'tab', 'aria-selected': sel ? 'true' : 'false', html: t.icon + '<span>' + esc(t.label) + '</span>' });
        b.addEventListener('click', () => { if (this.tab !== t.key) { this.tab = t.key; this.draw(view, s); } });
        bar.appendChild(b);
      });
      view.appendChild(bar);

      const panel = el('div', { class: 'tabpanel reveal', role: 'tabpanel' });
      view.appendChild(panel);
      if (this.tab === 'privacy') this.panelPrivacy(panel, view, s);
      else if (this.tab === 'system') this.panelSystem(panel, view, s);
      else this.panelGeneral(panel, view, s);
    },

    panelGeneral(panel, view, s) {
      const card = el('div', { class: 'card reveal' }, [el('div', { class: 'hrow' }, [el('h3', { text: 'Interception' })])]);
      const modeSel = dropdown(
        [{ value: 'cooperative', label: 'Cooperative' }, { value: 'gateway', label: 'Gateway' }],
        s.mode, (v) => this.save(view, { mode: v }), { ariaLabel: 'Mode' }
      );
      card.appendChild(setRow('Mode', 'Cooperative (universal) or Gateway (supervised, owns the port).', el('div', { class: 'ctl' }, [modeSel])));
      const hoSel = dropdown(
        [{ value: 'handover', label: 'Handover' }, { value: 'stop', label: 'Stop' }],
        s.handover, (v) => this.save(view, { handover: v }), { ariaLabel: 'Handover policy' }
      );
      card.appendChild(setRow('Handover policy', 'On shutdown in Gateway mode: hand the engine back, or stop it.', el('div', { class: 'ctl' }, [hoSel])));
      panel.appendChild(card);
    },

    panelPrivacy(panel, view, s) {
      // Privacy & storage
      const privCard = el('div', { class: 'card reveal' }, [el('div', { class: 'hrow' }, [el('h3', { text: 'Privacy & storage' })])]);
      const sw = el('button', { class: 'switch' + (s.payloadStorage ? ' on' : ''), 'aria-label': 'Toggle payload storage' });
      sw.addEventListener('click', async () => {
        const next = !sw.classList.contains('on');
        if (next) {
          const ok = await confirmModal({
            title: 'Store raw payloads?',
            body: 'By default Saffev keeps metadata only.\n\nTurning this on records full prompts & responses on this device (still encrypted, on-device). This is an explicit, logged action.',
            confirmLabel: 'Store payloads', danger: true,
          });
          if (!ok) return;
        }
        this.save(view, { payloadStorage: next });
      });
      const payHint = s.payloadStorage
        ? 'On — full prompts & responses are retained on this device.'
        : 'Off — metadata-only (default). Raw payloads are never stored.';
      const payRow = setRow('Store raw payloads', payHint, el('div', { class: 'ctl' }, [sw]));
      if (s.payloadStorage) payRow.querySelector('.hint').classList.add('danger-note');
      privCard.appendChild(payRow);
      const retVal = retentionText(s.retention);
      const retSel = dropdown(
        [['age30', 'Age · 30 days'], ['age7', 'Age · 7 days'], ['age90', 'Age · 90 days'], ['size500', 'Size · 500 MB'], ['unlimited', 'Unlimited']].map(([v, t]) => ({ value: v, label: t })),
        retentionKey(s.retention), (v) => this.save(view, { retention: retentionFromKey(v) }), { ariaLabel: 'Retention' }
      );
      privCard.appendChild(setRow('Retention', 'How long exchanges are kept before pruning. Currently: ' + retVal + '.', el('div', { class: 'ctl' }, [retSel])));
      panel.appendChild(privCard);

      // PII masking (opt-in redaction, dry-run by default)
      const maskCard = el('div', { class: 'card reveal', style: 'animation-delay:.06s' }, [el('div', { class: 'hrow' }, [el('h3', { text: 'PII masking' })])]);
      const mEnable = el('button', { class: 'switch' + (s.maskingEnabled ? ' on' : ''), 'aria-label': 'Toggle PII masking' });
      mEnable.addEventListener('click', () => { const next = !mEnable.classList.contains('on'); this.save(view, { maskingEnabled: next }); });
      const enHint = s.maskingEnabled
        ? 'On — high-confidence PII detectors feed the masking pipeline.'
        : 'Off — observe-only (default). Traffic is never altered.';
      maskCard.appendChild(setRow('Enable masking', enHint, el('div', { class: 'ctl' }, [mEnable])));
      const mDry = el('button', { class: 'switch' + (s.maskingDryRun ? ' on' : ''), 'aria-label': 'Toggle masking dry-run' });
      if (!s.maskingEnabled) mDry.setAttribute('disabled', '');
      mDry.addEventListener('click', async () => {
        if (!s.maskingEnabled) return;
        const next = !mDry.classList.contains('on');
        if (!next) {
          const ok = await confirmModal({
            title: 'Turn off dry-run?',
            body: 'With dry-run off, high-confidence PII (email, card, API key, IP, phone) is redacted from request bodies BEFORE they reach the model. Responses and streaming are unaffected.\n\nFail-open: any error forwards the original request unchanged.',
            confirmLabel: 'Start redacting', danger: true,
          });
          if (!ok) return;
        }
        this.save(view, { maskingDryRun: next });
      });
      const dryHint = !s.maskingEnabled
        ? 'Enable masking first to choose dry-run vs live.'
        : (s.maskingDryRun
          ? 'On (default) — records what WOULD be masked; traffic is unchanged.'
          : 'Off — LIVE: high-confidence PII is redacted from requests before forwarding.');
      const dryRow = setRow('Dry-run', dryHint, el('div', { class: 'ctl' }, [mDry]));
      if (s.maskingEnabled && !s.maskingDryRun) dryRow.querySelector('.hint').classList.add('danger-note');
      maskCard.appendChild(dryRow);
      panel.appendChild(maskCard);
    },

    panelSystem(panel, view, s) {
      const sysCard = el('div', { class: 'card reveal' }, [el('div', { class: 'hrow' }, [el('h3', { text: 'System' })])]);
      sysCard.appendChild(setRow('Data directory', 'Config + encrypted database location.', el('div', { class: 'ctl' }, [el('span', { class: 'kv', text: s.dataDir })])));
      sysCard.appendChild(setRow('Proxy port', 'Where apps send local-LLM traffic.', el('div', { class: 'ctl' }, [el('span', { class: 'kv', text: ':' + s.proxyPort })])));
      sysCard.appendChild(setRow('Studio port', 'This control plane.', el('div', { class: 'ctl' }, [el('span', { class: 'kv', text: ':' + s.studioPort })])));
      const patterns = (s.customPatterns && s.customPatterns.length) ? s.customPatterns.join(', ') : 'none';
      sysCard.appendChild(setRow('Custom PII patterns', 'User-defined detectors (configured in the config file).', el('div', { class: 'ctl' }, [el('span', { class: 'kv', text: patterns })])));
      panel.appendChild(sysCard);
    },

    async save(view, update) {
      if (this.saving) return; this.saving = true;
      try {
        const updated = await api('/settings', { method: 'PUT', body: update });
        hideBanner();
        this.draw(view, updated);
      } catch (e) { handleApiError(e); }
      this.saving = false;
    },
    teardown() {},
  };

  /* =========================================================================
     PAGE: ABOUT & INTEGRATE
     A friendly, plain-language explainer + a developer integration guide,
     including a copyable prompt you can hand to an AI coding agent so it can
     wire any app's local-LLM traffic through Saffev.
     ========================================================================= */
  const REPO_URL = 'https://github.com/theoyinbooke/Saffev';
  const INSTALL_CMD = "curl --proto '=https' --tlsv1.2 -LsSf https://github.com/theoyinbooke/Saffev/releases/latest/download/saffev-installer.sh | sh";

  function aboutChip(icon, text) {
    return el('span', { class: 'about-chip', html: icon + '<span>' + esc(text) + '</span>' });
  }
  function featureCard(icon, role, title, desc) {
    return el('div', { class: 'feat' }, [
      el('div', { class: 'feat-ic ic ' + role, html: icon }),
      el('div', {}, [el('div', { class: 'feat-t', text: title }), el('div', { class: 'feat-d', text: desc })]),
    ]);
  }
  function aboutSection(icon, title, kicker) {
    const head = el('div', { class: 'about-sec-head' }, [
      el('span', { class: 'about-sec-ic', html: icon }),
      el('div', {}, [el('h3', { text: title }), kicker ? el('div', { class: 'about-sec-kicker', text: kicker }) : null]),
    ]);
    return head;
  }

  const About = {
    title: 'About & integrate',
    sub: 'What Saffev is, what it does, and how to point your apps — and AI agents — at it.',
    tab: 'overview',
    version: '', proxyPort: 8088, studioPort: 7100,
    TABS: [
      { k: 'overview', l: 'Overview', icon: ICON.eye },
      { k: 'start', l: 'Quick start', icon: ICON.download },
      { k: 'integrate', l: 'Integrate', icon: ICON.sparkles },
    ],

    async render(view) {
      view.innerHTML = '';
      // Best-effort live values; fail-soft to the documented defaults.
      try { const h = await api('/health'); this.version = h.version || ''; } catch (e) {}
      try { const s = await api('/settings'); this.proxyPort = s.proxyPort || this.proxyPort; this.studioPort = s.studioPort || this.studioPort; } catch (e) {}
      hideBanner();

      const bar = el('div', { class: 'tabbar reveal', role: 'tablist', 'aria-label': 'About sections' });
      this.TABS.forEach((t) => {
        const b = el('button', { class: 'tab' + (this.tab === t.k ? ' active' : ''), type: 'button', role: 'tab', 'data-k': t.k, html: t.icon + '<span>' + esc(t.l) + '</span>' });
        b.addEventListener('click', () => { if (this.tab !== t.k) { this.tab = t.k; this.draw(); } });
        bar.appendChild(b);
      });
      view.appendChild(bar);
      view.appendChild(el('div', { class: 'tabpanel', id: 'aboutPanel' }));
      this.draw();
    },

    draw() {
      const panel = $('#aboutPanel');
      if (!panel) return;
      $$('.tabbar .tab').forEach((b) => b.classList.toggle('active', b.dataset.k === this.tab));
      panel.innerHTML = '';
      const proxyUrl = 'http://localhost:' + this.proxyPort;
      const studioUrl = (window.location && window.location.origin) || ('http://localhost:' + this.studioPort);
      if (this.tab === 'start') {
        panel.appendChild(this.quickStart(proxyUrl, studioUrl));
        panel.appendChild(this.pointApp(proxyUrl));
      } else if (this.tab === 'integrate') {
        panel.appendChild(this.agentPrompt(proxyUrl, studioUrl));
        panel.appendChild(this.footer(this.version));
      } else {
        panel.appendChild(this.hero(this.version));
        panel.appendChild(this.features());
        panel.appendChild(this.howItWorks(this.proxyPort));
      }
    },

    hero(version) {
      return el('div', { class: 'card reveal about-hero' }, [
        el('span', { class: 'about-badge', html: ICON.eye + '<span>A glass box for local AI</span>' }),
        el('h2', { class: 'about-h1', text: 'See exactly what your apps send to local models — and keep it on this device.' }),
        el('p', { class: 'about-lead', text: 'Saffev is a transparent proxy that sits in front of your local LLM engine (like Ollama). Every request your apps make passes through it, so you can watch the traffic live, catch leaked personal data, and confirm nothing is exposed to the network — all on this device, encrypted, with no telemetry.' }),
        el('div', { class: 'about-chips' }, [
          aboutChip(ICON.shield, 'On-device only'),
          aboutChip(ICON.check, 'Encrypted at rest'),
          aboutChip(ICON.globe, 'No telemetry'),
          version ? aboutChip(ICON.bolt, 'v' + version) : null,
        ]),
      ]);
    },

    features() {
      const grid = el('div', { class: 'feat-grid' }, [
        featureCard(ICON.pulse, 'brand', 'Live traffic', 'A real-time stream of every request your apps make to local models — app, model, endpoint, latency, tokens.'),
        featureCard(ICON.clock, 'gold', 'History', 'Every proxied exchange, searchable and filterable, kept on-device with a retention policy you control.'),
        featureCard(ICON.shieldAlert, 'danger', 'Privacy lens', 'Deterministic detection of PII — email, credit card, API keys, IP, phone — flagged as it flows by.'),
        featureCard(ICON.globe, 'safe', 'Exposure doctor', 'Confirms the engine and Studio are bound to localhost only and not reachable from the network.'),
        featureCard(ICON.eye, 'brand', 'PII masking', 'Optionally redact high-confidence PII from requests before they reach the model (dry-run first).'),
        featureCard(ICON.server, 'gold', 'Cooperative & Gateway', 'Cooperative: apps point at Saffev (universal, zero-config). Gateway: Saffev supervises the engine port.'),
      ]);
      return el('div', { class: 'card reveal', style: 'animation-delay:.06s' }, [
        aboutSection(ICON.sparkles, 'What it does', 'Six things, all local'),
        grid,
      ]);
    },

    howItWorks(proxyPort) {
      const flow = el('div', { class: 'flow' }, [
        el('div', { class: 'flow-node' }, [el('div', { class: 'flow-t', text: 'Your app' }), el('div', { class: 'flow-d', text: 'set base URL → Saffev' })]),
        el('div', { class: 'flow-arrow', html: ICON.chevR }),
        el('div', { class: 'flow-node brandnode' }, [el('div', { class: 'flow-t', text: 'Saffev' }), el('div', { class: 'flow-d', text: ':' + proxyPort + ' · observes + guards' })]),
        el('div', { class: 'flow-arrow', html: ICON.chevR }),
        el('div', { class: 'flow-node' }, [el('div', { class: 'flow-t', text: 'Ollama' }), el('div', { class: 'flow-d', text: ':11434 · untouched' })]),
      ]);
      return el('div', { class: 'card reveal', style: 'animation-delay:.09s' }, [
        aboutSection(ICON.plug, 'How it works', 'Cooperative mode — a transparent pass-through'),
        flow,
        el('p', { class: 'about-p', text: 'Your app talks to Saffev instead of the engine directly. Saffev forwards every request unchanged to the real engine and streams the response straight back — recording only metadata on-device (never the raw prompt or response unless you explicitly turn that on).' }),
      ]);
    },

    quickStart(proxyUrl, studioUrl) {
      const card = el('div', { class: 'card reveal', style: 'animation-delay:.12s' }, [
        aboutSection(ICON.download, 'Quick start', 'Install, run, open'),
      ]);
      card.appendChild(el('div', { class: 'step' }, [el('span', { class: 'step-n', text: '1' }), el('div', { class: 'step-b' }, [el('div', { class: 'step-t', text: 'Install (macOS / Linux)' }), copyBlock(INSTALL_CMD, { title: 'terminal' })])]));
      card.appendChild(el('div', { class: 'step' }, [el('span', { class: 'step-n', text: '2' }), el('div', { class: 'step-b' }, [el('div', { class: 'step-t', text: 'Start it (zero-config — picks free ports, never grabs your engine)' }), copyBlock('saffev start', { title: 'terminal' })])]));
      card.appendChild(el('div', { class: 'step' }, [el('span', { class: 'step-n', text: '3' }), el('div', { class: 'step-b' }, [el('div', { class: 'step-t', text: 'Open the Studio' }), el('p', { class: 'about-p', html: 'This dashboard, at <a class="about-link" href="' + esc(studioUrl) + '">' + esc(studioUrl) + '</a>. Run <span class="kv">saffev status</span> anytime to see the exact ports.' })])]));
      return card;
    },

    pointApp(proxyUrl) {
      return el('div', { class: 'card reveal', style: 'animation-delay:.15s' }, [
        aboutSection(ICON.bolt, 'Point an app at Saffev', 'So its traffic shows up here'),
        el('p', { class: 'about-p', text: 'Set your app’s local-LLM base URL to the Saffev proxy. It forwards to your real Ollama, so nothing else changes. Use an environment variable so it’s easy to revert.' }),
        copyBlock('OLLAMA_BASE_URL=' + proxyUrl, { title: '.env  (Ollama-style)' }),
        el('p', { class: 'about-p', text: 'If your app uses the OpenAI-compatible API instead:' }),
        copyBlock('OPENAI_BASE_URL=' + proxyUrl + '/v1', { title: '.env  (OpenAI-compatible)' }),
      ]);
    },

    agentPrompt(proxyUrl, studioUrl) {
      const prompt =
'You are integrating an existing app with "Saffev" — a local, on-device AI observability\n' +
'& safety proxy that sits in front of a local LLM engine (e.g. Ollama). Saffev runs in\n' +
'"cooperative" mode: it listens on a local proxy port and transparently forwards every\n' +
'request to the real engine, recording only metadata on-device (no raw prompt/response\n' +
'unless the user opts in). It is a pure pass-through: request/response shapes, headers,\n' +
'model names, and streaming are unchanged.\n' +
'\n' +
'GOAL\n' +
'Make THIS app send its local-LLM / Ollama traffic THROUGH Saffev’s proxy instead of\n' +
'talking to the engine directly, without changing any app behavior.\n' +
'\n' +
'CONTEXT\n' +
'- Saffev proxy URL: ' + proxyUrl + '   (forwards to the real Ollama on :11434)\n' +
'- Saffev Studio (dashboard): ' + studioUrl + '\n' +
'- The exact proxy URL is also printed by:  saffev status\n' +
'\n' +
'STEPS\n' +
'1. Find where this app configures its model endpoint. Look for:\n' +
'   - env vars: OLLAMA_HOST, OLLAMA_BASE_URL, OPENAI_BASE_URL, OPENAI_API_BASE\n' +
'   - hardcoded URLs containing :11434, "localhost:11434", or "127.0.0.1:11434"\n' +
'   - SDK clients (ollama, openai, langchain, llamaindex, …) set with a base URL\n' +
'2. Repoint the base URL at the Saffev proxy. Prefer an env var so it is reversible:\n' +
'       OLLAMA_BASE_URL=' + proxyUrl + '\n' +
'   If the app uses the OpenAI-compatible API, use:\n' +
'       OPENAI_BASE_URL=' + proxyUrl + '/v1\n' +
'   If the URL is hardcoded, replace ONLY the origin (host:port) with ' + proxyUrl + ';\n' +
'   keep the path (e.g. /api/chat, /v1/chat/completions) exactly as-is.\n' +
'3. Do NOT change request bodies, headers, model names, or streaming behavior.\n' +
'4. Restart the app.\n' +
'\n' +
'VERIFY\n' +
'- Open ' + studioUrl + ', go to "Live", and trigger an action that calls the model.\n' +
'- A new row should appear in the Traffic stream. If it does, the integration works.\n' +
'\n' +
'RULES\n' +
'- Only use the PROXY port (from ' + proxyUrl + '); never point the app at the Studio port.\n' +
'- Keep a one-line way to revert (point the base URL back at http://localhost:11434).\n' +
'- Nothing about the user or the traffic leaves the device.\n' +
'\n' +
'OUTPUT\n' +
'Report the exact file and line you changed, and the one-line edit to revert.';
      return el('div', { class: 'card reveal', style: 'animation-delay:.18s' }, [
        aboutSection(ICON.sparkles, 'Give this to your AI coding agent', 'Copy → paste into Claude Code, Cursor, etc.'),
        el('p', { class: 'about-p', text: 'Hand this prompt to an AI coding agent working in your app’s repo. It has everything needed to wire the app through Saffev and verify it worked.' }),
        copyBlock(prompt, { title: 'prompt for your AI coding agent' }),
      ]);
    },

    footer(version) {
      const row = el('div', { class: 'about-foot' }, [
        el('a', { class: 'btn auto', href: REPO_URL, target: '_blank', rel: 'noopener', html: ICON.link + '<span>GitHub repository</span>' }),
        el('div', { class: 'spacer' }),
        el('span', { class: 'about-foot-meta', text: (version ? 'Saffev v' + version + ' · ' : 'Saffev · ') + 'MIT / Apache-2.0 · on-device, no telemetry' }),
      ]);
      return el('div', { class: 'card reveal', style: 'animation-delay:.21s' }, [row]);
    },

    teardown() {},
  };

  /* =========================================================================
     PAGE: ANALYTICS
     Granular, on-device analytics. Fetches a single aggregated report from
     /api/analytics for the selected window and renders it across tabs with the
     SVG chart toolkit (window.SaffevCharts). Nothing leaves the device.
     ========================================================================= */
  function anCard(titleText, sub, node, wide) {
    return el('div', { class: 'card reveal' + (wide ? ' span2' : '') }, [
      el('div', { class: 'hrow' }, [el('h3', { text: titleText }), el('div', { class: 'spacer' }), sub ? el('span', { class: 'tag', text: sub }) : null]),
      node,
    ]);
  }
  function anKpi(role, icon, label, value, subNode, spark) {
    return el('div', { class: 'card kpi reveal' }, [
      el('div', { class: 'label' }, [el('span', { class: 'ic ' + role, html: icon }), document.createTextNode(' ' + label)]),
      el('div', { class: 'val num', html: value }),
      subNode || null,
      spark ? el('div', { class: 'kpi-spark' }, [spark]) : null,
    ]);
  }
  function miniStat(label, value) {
    return el('div', { class: 'card kpi reveal' }, [el('div', { class: 'label', text: label }), el('div', { class: 'val num', html: value })]);
  }
  function deltaNode(cur, prev, goodUp) {
    if (prev == null || prev === 0) return el('div', { class: 'meta', text: cur > 0 ? 'new this period' : '—' });
    const pct = Math.round(((cur - prev) / prev) * 100);
    if (pct === 0) return el('div', { class: 'meta', text: 'no change vs prev' });
    const up = pct > 0;
    return el('div', { class: 'delta ' + (up === goodUp ? 'up' : 'down'), text: (up ? '▲ ' : '▼ ') + Math.abs(pct) + '% vs prev' });
  }
  const actionLabel = (a) => ({ Observed: 'Observed', WouldMask: 'Would mask (dry-run)', Masked: 'Masked' }[a] || a);
  function dataTable(headers, rows) {
    const gtc = headers.map((h, i) => (i === 0 ? 'minmax(120px,1.4fr)' : '1fr')).join(' ');
    const t = el('div', { class: 'ttable', style: '--gtc:' + gtc });
    const head = el('div', { class: 'thead' });
    headers.forEach((h, i) => head.appendChild(el('div', { class: 'th' + (i > 0 ? ' r' : ''), text: h })));
    t.appendChild(head);
    const body = el('div', { class: 'list', style: 'max-height:none' });
    if (!rows.length) body.appendChild(el('div', { class: 'state sm', text: 'No data.' }));
    rows.forEach((r) => {
      const tr = el('div', { class: 'trow', style: 'cursor:default' });
      r.forEach((c, i) => tr.appendChild(el('div', { class: 'tcell' + (i > 0 ? ' r' : ''), text: c })));
      body.appendChild(tr);
    });
    t.appendChild(body);
    return t;
  }
  function downloadFile(name, text, type) {
    try {
      const blob = new Blob([text], { type });
      const url = URL.createObjectURL(blob);
      const a = el('a', { href: url, download: name });
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1500);
    } catch (e) { /* ignore */ }
  }

  const Analytics = {
    title: 'Analytics',
    sub: 'Granular, on-device insight into your local-AI traffic — nothing leaves this device.',
    tab: 'overview',
    rangeMs: 24 * 60 * 60 * 1000,
    data: null,
    RANGES: [
      { value: 3600000, label: 'Last hour' },
      { value: 86400000, label: 'Last 24 hours' },
      { value: 604800000, label: 'Last 7 days' },
      { value: 2592000000, label: 'Last 30 days' },
    ],
    TABS: [
      { k: 'overview', l: 'Overview' },
      { k: 'usage', l: 'Usage' },
      { k: 'performance', l: 'Performance' },
      { k: 'privacy', l: 'Privacy' },
      { k: 'explorer', l: 'Explorer' },
    ],

    async render(view) {
      view.innerHTML = '';
      const tabs = el('div', { class: 'tabbar', role: 'tablist', 'aria-label': 'Analytics sections' });
      this.TABS.forEach((t) => {
        const b = el('button', { class: 'tab' + (this.tab === t.k ? ' active' : ''), type: 'button', role: 'tab', 'data-k': t.k, text: t.l });
        b.addEventListener('click', () => { if (this.tab !== t.k) { this.tab = t.k; this.renderTab(); } });
        tabs.appendChild(b);
      });
      const range = dropdown(this.RANGES, this.rangeMs, (v) => { this.rangeMs = parseInt(v, 10); this.reload(); }, { ariaLabel: 'Time range', align: 'right' });
      view.appendChild(el('div', { class: 'an-head reveal' }, [tabs, el('div', { class: 'spacer' }), el('span', { class: 'an-range-lbl', text: 'Window' }), range]));
      view.appendChild(el('div', { class: 'an-panel', id: 'anPanel' }));
      await this.reload();
    },

    async reload() {
      const panel = $('#anPanel');
      if (panel) { panel.innerHTML = ''; panel.appendChild(loadingState('Crunching analytics…')); }
      try {
        const tz = new Date().getTimezoneOffset();
        this.data = await api('/analytics?rangeMs=' + this.rangeMs + '&tzOffsetMin=' + tz);
        hideBanner();
      } catch (e) {
        handleApiError(e);
        if (panel) { panel.innerHTML = ''; panel.appendChild(emptyState('Could not load analytics', e.message || '')); }
        return;
      }
      this.renderTab();
    },

    renderTab() {
      $$('.an-head .tab').forEach((b) => b.classList.toggle('active', b.dataset.k === this.tab));
      const panel = $('#anPanel');
      if (!panel || !this.data) return;
      panel.innerHTML = '';
      const d = this.data;
      if (d.totalRequests === 0 && this.tab !== 'overview') {
        panel.appendChild(emptyState('No traffic in this window', 'Try a longer window, or point an app at the proxy (see About & integrate).'));
        return;
      }
      ({ overview: this.overview, usage: this.usage, performance: this.performance, privacy: this.privacy, explorer: this.explorer }[this.tab] || this.overview).call(this, panel, d);
    },

    xLabels(d) {
      const daily = d.bucketMs >= 86400000;
      return d.series.map((b) => {
        const dt = new Date(b.ts);
        const p2 = (n) => String(n).padStart(2, '0');
        return daily ? dt.toLocaleString(undefined, { month: 'short' }) + ' ' + dt.getDate() : p2(dt.getHours()) + ':' + p2(dt.getMinutes());
      });
    },

    overview(panel, d) {
      const C = window.SaffevCharts;
      const xl = this.xLabels(d);
      const kpis = el('section', { class: 'grid kpis reveal' }, [
        anKpi('brand', ICON.pulse, 'Requests', fmtNum(d.totalRequests), deltaNode(d.totalRequests, d.prevTotalRequests, true), C.sparkline(d.series.map((b) => b.requests))),
        anKpi('gold', ICON.bolt, 'Tokens', fmtNum(d.totalInputTokens + d.totalOutputTokens), el('div', { class: 'meta', text: fmtNum(d.totalInputTokens) + ' in · ' + fmtNum(d.totalOutputTokens) + ' out' }), C.sparkline(d.series.map((b) => b.inputTokens + b.outputTokens), { color: 'var(--gold)' })),
        anKpi('brand', ICON.clock, 'Latency p50', d.p50LatencyMs != null ? d.p50LatencyMs + '<small>ms</small>' : '—', deltaNode(d.p50LatencyMs, d.prevP50LatencyMs, false), C.sparkline(d.series.map((b) => b.p50LatencyMs || 0))),
        anKpi('danger', ICON.shieldAlert, 'PII findings', fmtNum(d.piiFindings), deltaNode(d.piiFindings, d.prevPiiFindings, false), C.sparkline(d.series.map((b) => b.pii), { color: 'var(--danger)' })),
      ]);
      panel.appendChild(kpis);
      const cost = el('div', { class: 'card reveal an-cost' }, [
        el('div', { class: 'label' }, [el('span', { class: 'ic safe', html: ICON.sparkles }), document.createTextNode(' Cloud cost avoided')]),
        el('div', { class: 'an-cost-val', text: '$' + (d.estCostSavedUsd || 0).toFixed(2) }),
        el('div', { class: 'meta', text: d.costBasis + ' · ' + fmtNum(d.totalInputTokens + d.totalOutputTokens) + ' tokens on-device' }),
      ]);
      const activity = anCard('Activity', 'requests over time', C.lineArea({ series: [{ name: 'Requests', values: d.series.map((b) => b.requests), color: 'var(--brand)' }], xLabels: xl }));
      panel.appendChild(el('section', { class: 'an-grid' }, [activity, cost]));
      panel.appendChild(this.insightsCard(d));
    },

    insightsCard(d) {
      const list = el('div', { class: 'insights' });
      if (!d.insights || !d.insights.length) list.appendChild(el('div', { class: 'state sm', style: 'padding:18px', text: 'No notable patterns yet — keep using local models and insights will appear.' }));
      else d.insights.forEach((i) => {
        const icon = i.severity === 'good' ? ICON.check : i.severity === 'warn' ? ICON.alert : ICON.sparkles;
        const role = i.severity === 'good' ? 'safe' : i.severity === 'warn' ? 'warn' : 'brand';
        list.appendChild(el('div', { class: 'insight' }, [
          el('div', { class: 'swt ic ' + role, html: icon }),
          el('div', {}, [el('div', { class: 'insight-t', text: i.title }), el('div', { class: 'insight-d', text: i.detail })]),
        ]));
      });
      return anCard('Insights', 'auto-generated', list, true);
    },

    usage(panel, d) {
      const C = window.SaffevCharts;
      const xl = this.xLabels(d);
      const grid = el('section', { class: 'an-grid' });
      grid.appendChild(anCard('Tokens over time', 'input vs output', C.lineArea({ series: [
        { name: 'Input', values: d.series.map((b) => b.inputTokens), color: 'var(--brand)' },
        { name: 'Output', values: d.series.map((b) => b.outputTokens), color: 'var(--gold)' },
      ], xLabels: xl }), true));
      grid.appendChild(anCard('By model', 'requests', C.hbars({ items: d.byModel.map((m) => ({ label: m.name, value: m.requests, suffix: ' req' })) })));
      grid.appendChild(anCard('By app', 'requests', C.hbars({ items: d.byApp.map((a) => ({ label: a.name, value: a.requests, suffix: ' req' })) })));
      grid.appendChild(anCard('By endpoint', 'share', C.donut({ items: d.byEndpoint.map((e) => ({ label: e.name, value: e.requests })), centerLabel: 'requests' })));
      grid.appendChild(anCard('Prompt size', 'input tokens / request', C.histogram({ bins: d.inputTokenHistogram, color: 'var(--brand)' })));
      grid.appendChild(anCard('Busiest hours', 'local time', C.heatmap({ cells: d.heatmap }), true));
      panel.appendChild(grid);
    },

    performance(panel, d) {
      const C = window.SaffevCharts;
      const xl = this.xLabels(d);
      panel.appendChild(el('section', { class: 'grid kpis reveal' }, [
        miniStat('p50 latency', d.p50LatencyMs != null ? d.p50LatencyMs + '<small>ms</small>' : '—'),
        miniStat('p90 latency', d.p90LatencyMs != null ? d.p90LatencyMs + '<small>ms</small>' : '—'),
        miniStat('p99 latency', d.p99LatencyMs != null ? d.p99LatencyMs + '<small>ms</small>' : '—'),
        miniStat('avg TTFT', d.avgTtftMs != null ? d.avgTtftMs + '<small>ms</small>' : '—'),
      ]));
      const grid = el('section', { class: 'an-grid' });
      grid.appendChild(anCard('Latency p50 over time', 'ms', C.lineArea({ series: [{ name: 'p50', values: d.series.map((b) => b.p50LatencyMs), color: 'var(--brand)' }], xLabels: xl }), true));
      grid.appendChild(anCard('Throughput by model', 'decode tokens/sec', C.hbars({ items: d.byModel.filter((m) => m.tokensPerSec != null).map((m) => ({ label: m.name, value: m.tokensPerSec, suffix: ' tok/s' })), fmt: (v) => v.toFixed(0) })));
      grid.appendChild(anCard('Time to first token', 'distribution', C.histogram({ bins: d.ttftHistogram, unit: 'ms', color: 'var(--brand)' })));
      grid.appendChild(anCard('Latency vs output', 'does length explain slowness?', C.scatter({ points: d.latencyVsOutput, xLabel: 'output tokens', yLabel: 'latency ms' }), true));
      const frColors = { stop: 'var(--safe)', length: 'var(--brand)', unknown: 'var(--text-3)', error: 'var(--danger)' };
      grid.appendChild(anCard('Finish reasons', 'why responses ended', C.hbars({ items: d.finishReasons.map((f) => ({ label: f.name, value: f.count, suffix: ' resp', color: frColors[f.name] || 'var(--gold)' })) }), true));
      panel.appendChild(grid);
      const wrap = el('div', { class: 'ttable', style: '--gtc:' + gtcFor(HIST_COLS) }, [reqHead(HIST_COLS), (() => {
        const b = el('div', { class: 'list', style: 'max-height:none' });
        if (!d.slowest.length) b.appendChild(el('div', { class: 'state sm', text: 'No completed exchanges.' }));
        else d.slowest.forEach((it) => b.appendChild(reqRow(it, { columns: HIST_COLS })));
        return b;
      })()]);
      panel.appendChild(anCard('Slowest exchanges', 'click a row for detail', wrap, true));
    },

    privacy(panel, d) {
      const C = window.SaffevCharts;
      const xl = this.xLabels(d);
      const grid = el('section', { class: 'an-grid' });
      grid.appendChild(anCard('PII findings over time', 'observe-only', C.lineArea({ series: [{ name: 'PII', values: d.series.map((b) => b.pii), color: 'var(--danger)' }], xLabels: xl }), true));
      grid.appendChild(anCard('By type', 'request + response', C.hbars({ items: d.piiByKind.map((k) => ({ label: piiLabel(k.kind), value: k.requestCount + k.responseCount, note: k.requestCount + ' req · ' + k.responseCount + ' resp' })), color: 'var(--danger)' })));
      grid.appendChild(anCard('Where it appears', 'into vs out of the model', C.donut({ items: [{ label: 'On request (to model)', value: d.piiRequestSide, color: 'var(--danger)' }, { label: 'On response (from model)', value: d.piiResponseSide, color: 'var(--gold)' }], centerLabel: 'findings' })));
      grid.appendChild(anCard('Top sources', 'apps sending PII', C.hbars({ items: d.piiByApp.map((a) => ({ label: a.name, value: a.count })), color: 'var(--danger)' })));
      grid.appendChild(anCard('Masking action', 'observed / dry-run / masked', C.donut({ items: d.piiByAction.map((a) => ({ label: actionLabel(a.name), value: a.count })), centerLabel: 'findings' })));
      panel.appendChild(grid);
    },

    explorer(panel, d) {
      panel.appendChild(el('div', { class: 'an-export reveal' }, [
        el('span', { class: 'muted', style: 'font-size:.86rem', text: 'Export the full report for this window:' }),
        el('div', { class: 'spacer' }),
        el('button', { class: 'btn auto', html: ICON.download + '<span>JSON</span>', onclick: () => downloadFile('saffev-analytics.json', JSON.stringify(d, null, 2), 'application/json') }),
        el('button', { class: 'btn auto', html: ICON.download + '<span>CSV (models)</span>', onclick: () => downloadFile('saffev-models.csv', this.csv(['Model', 'Requests', 'Input tokens', 'Output tokens', 'p50 ms', 'TTFT ms', 'tok/s'], d.byModel.map((m) => [m.name, m.requests, m.inputTokens, m.outputTokens, m.p50LatencyMs, m.avgTtftMs, m.tokensPerSec])), 'text/csv') }),
        el('button', { class: 'btn auto', html: ICON.download + '<span>CSV (apps)</span>', onclick: () => downloadFile('saffev-apps.csv', this.csv(['App', 'Requests', 'Input tokens', 'Output tokens', 'avg ms', 'PII'], d.byApp.map((a) => [a.name, a.requests, a.inputTokens, a.outputTokens, a.avgLatencyMs, a.pii])), 'text/csv') }),
      ]));
      const grid = el('section', { class: 'an-grid' });
      grid.appendChild(anCard('Models', 'full breakdown', dataTable(['Model', 'Requests', 'Input', 'Output', 'p50', 'TTFT', 'tok/s'], d.byModel.map((m) => [m.name, fmtNum(m.requests), fmtNum(m.inputTokens), fmtNum(m.outputTokens), m.p50LatencyMs != null ? m.p50LatencyMs + 'ms' : '—', m.avgTtftMs != null ? m.avgTtftMs + 'ms' : '—', m.tokensPerSec != null ? m.tokensPerSec.toFixed(0) : '—'])), true));
      grid.appendChild(anCard('Apps', 'full breakdown', dataTable(['App', 'Requests', 'Input', 'Output', 'avg latency', 'PII'], d.byApp.map((a) => [a.name, fmtNum(a.requests), fmtNum(a.inputTokens), fmtNum(a.outputTokens), a.avgLatencyMs != null ? a.avgLatencyMs + 'ms' : '—', fmtNum(a.pii)])), true));
      grid.appendChild(anCard('Endpoints', 'full breakdown', dataTable(['Endpoint', 'Requests', 'Input', 'Output', 'avg latency', 'PII'], d.byEndpoint.map((e) => [e.name, fmtNum(e.requests), fmtNum(e.inputTokens), fmtNum(e.outputTokens), e.avgLatencyMs != null ? e.avgLatencyMs + 'ms' : '—', fmtNum(e.pii)])), true));
      panel.appendChild(grid);
    },

    csv(headers, rows) {
      const esc2 = (v) => { const s2 = v == null ? '' : String(v); return /[",\n]/.test(s2) ? '"' + s2.replace(/"/g, '""') + '"' : s2; };
      return [headers.join(',')].concat(rows.map((r) => r.map(esc2).join(','))).join('\n');
    },

    teardown() {},
  };

  function setRow(label, hint, ctl) {
    return el('div', { class: 'setrow' }, [
      el('div', {}, [el('div', { class: 'lbl', text: label }), el('div', { class: 'hint', text: hint })]),
      ctl,
    ]);
  }

  // Retention enum: { kind:"age", days } | { kind:"size", mb } | { kind:"unlimited" }
  function retentionText(r) {
    if (!r) return 'unknown';
    if (r.kind === 'age') return r.days + ' days';
    if (r.kind === 'size') return r.mb + ' MB';
    return 'unlimited';
  }
  function retentionKey(r) {
    if (!r) return 'age30';
    if (r.kind === 'age') return 'age' + r.days;
    if (r.kind === 'size') return 'size' + r.mb;
    return 'unlimited';
  }
  function retentionFromKey(k) {
    if (k === 'unlimited') return { kind: 'unlimited' };
    if (k.startsWith('size')) return { kind: 'size', mb: parseInt(k.slice(4), 10) };
    return { kind: 'age', days: parseInt(k.slice(3), 10) };
  }

  /* -------------------------------------------------------------------------
     Shared small helpers used across pages.
     ------------------------------------------------------------------------- */
  function setText(sel, txt) { const n = $(sel); if (n) n.textContent = txt; }
  function updatePiiBadge(count) {
    const b = $('#navPiiBadge');
    if (!b) return;
    if (count && count > 0) { b.textContent = count > 99 ? '99+' : String(count); b.hidden = false; }
    else b.hidden = true;
  }
  function healthToPill(health) {
    if (health === 'healthy') return { cls: '' };
    if (health === 'starting') return { cls: 'warnpill' };
    return { cls: 'dangerpill' };
  }
  function exposureLine(exp) {
    if (!exp) return 'exposure unknown';
    if (exp.detail) return exp.detail;
    return exp.exposed ? 'Reachable beyond this device — review binding' : 'Bound to localhost — safe';
  }
  function setEnginePill(ev) {
    const txt = $('#enginePillText');
    const pill = $('#enginePill');
    if (!txt || !pill) return;
    const eng = ev.engines && ev.engines[0];
    if (!eng) { txt.textContent = 'no engine'; pill.className = 'pill mutedpill'; return; }
    const h = eng.health;
    pill.className = 'pill ' + (h === 'healthy' ? '' : h === 'starting' ? 'warnpill' : 'dangerpill');
    txt.textContent = eng.engine + ' · ' + eng.adoptionState;
  }
  function setBusy(btn, busy) {
    if (!btn) return;
    btn.disabled = busy;
    if (busy) { btn._label = btn.innerHTML; btn.innerHTML = '<span class="spin" style="width:15px;height:15px;border-width:2px;margin:0"></span>'; }
    else if (btn._label) { btn.innerHTML = btn._label; }
  }

  /* =========================================================================
     ROUTER
     ========================================================================= */
  const ROUTES = { live: Live, history: History, privacy: Privacy, analytics: Analytics, engines: Engines, settings: Settings, about: About };
  let activePage = null;

  function setActiveNav(route) {
    $$('.nav a').forEach((a) => a.classList.toggle('active', a.dataset.route === route));
  }

  async function navigate() {
    const hash = (location.hash || '#/live').replace(/^#\/?/, '');
    const route = ROUTES[hash] ? hash : 'live';
    const page = ROUTES[route];
    if (activePage && activePage.teardown) activePage.teardown();
    activePage = page;
    setActiveNav(route);
    setText('#pageTitle', page.title);
    setText('#pageSub', page.sub);
    closeDrawer();
    const view = $('#view');
    try { await page.render(view); }
    catch (e) { view.innerHTML = ''; view.appendChild(emptyState('Something went wrong', e.message || String(e))); }
  }

  /* =========================================================================
     BOOT
     ========================================================================= */
  function applyBrand() {
    document.title = BRAND.wordmark + ' — Studio';
    setText('#wmName', BRAND.wordmark);
    setText('#wmSub', BRAND.tagline);
  }

  function boot() {
    applyBrand();
    initTheme();
    if (!location.hash) location.hash = '#/live';
    window.addEventListener('hashchange', navigate);
    navigate();
    // Surface a friendly hint if no token is present at all.
    if (!TOKEN) {
      showBanner('No Studio token found. The desktop app opens with one automatically; if you opened this URL by hand, append ?token=<your-install-token>.', 'danger');
    } else {
      // Auto-check for a newer release (GitHub release metadata only — nothing
      // about the user leaves the device). Fail-soft: never blocks the UI.
      checkForUpdate();
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
