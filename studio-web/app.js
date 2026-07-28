/* ============================================================================
   Saffev Studio SPA · app.js
   Static, no-build. Talks to the Studio HTTP API (camelCase JSON) and the
   SSE feed at GET /api/stream. All colours/spacing come from tokens.css; this
   file only structures data + behaviour.

   Wire contract (see src/studio/dto.rs):
     GET  /api/health   -> { app, version, proxyUp, mode }
     GET  /api/live     -> { recent:[HistoryItem], requestsToday, p50LatencyMs, piiFindingsToday, lifetimeRequests }
     GET  /api/history  ?q&piiOnly&limit&beforeTs -> [HistoryItem]
     GET  /api/history/:id -> { item, findings:[PiiFindingView], prompt, response, payloadsDisabled }
     GET  /api/privacy  -> { byKind, byApp, byModel, total, maskingEnabled }
     GET  /api/engines  -> { engines:[EngineView], mode, exposure:ExposureReport }
     POST /api/engines/adopt  { engine, cooperative } -> EngineView
     POST /api/engines/revert { engine }              -> EngineView
     GET  /api/exposure -> ExposureReport
     GET  /api/settings -> SettingsView
     PUT  /api/settings { mode?, payloadStorage?, retention?, handover?, maskingEnabled?, maskingDryRun? } -> SettingsView
     GET  /api/update   -> { currentVersion, latestVersion, updateAvailable }  (GitHub release metadata only · nothing about the user leaves the device)
     POST /api/update   -> { updated, newVersion, message }
     GET  /api/stream   SSE of StreamEvent (tagged by `type`)

   Every /api/* call needs `Authorization: Bearer <install-token>` + an
   allowlisted Host. See getToken() for how the token is resolved.
   ============================================================================ */
(function () {
  'use strict';

  /* -------------------------------------------------------------------------
     Brand · single source of truth (mirrors design/brand.json).
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
  const fmtNum = (n) => (n == null ? '·' : Number(n).toLocaleString());
  const fmtBytes = (n) => {
    n = Number(n) || 0;
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(0) + ' KB';
    if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MB';
    return (n / 1073741824).toFixed(2) + ' GB';
  };
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
    private_key: 'Private key block', jwt: 'JWT', connection_string: 'Connection string',
    ssn: 'SSN', iban: 'IBAN', mac_address: 'MAC address',
    env_assignment: 'Config credential', crypto_wallet: 'Crypto wallet',
  };
  // Credential-bearing kinds — badge gold like api_key.
  const PII_SECRET_KINDS = ['api_key', 'private_key', 'jwt', 'connection_string', 'env_assignment'];
  function piiLabel(kind, label) {
    if (kind === 'custom' && label) return label;
    return PII_LABEL[kind] || kind;
  }
  // Map a PiiKind to a colour role (gold for secrets, danger otherwise).
  function piiRole(kind) { return PII_SECRET_KINDS.includes(kind) ? 'gold' : kind === 'ip_address' ? 'brand' : 'danger'; }
  function piiShort(kind) {
    return {
      email: 'EMAIL', phone: 'PHONE', credit_card: 'CARD', api_key: 'API-KEY', ip_address: 'IP',
      private_key: 'PRIV-KEY', jwt: 'JWT', connection_string: 'CONN-STR', ssn: 'SSN', iban: 'IBAN',
      mac_address: 'MAC', env_assignment: 'ENV-SECRET', crypto_wallet: 'WALLET', custom: 'CUSTOM',
    }[kind] || String(kind).toUpperCase();
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
    return {
      email: ICON.mail, api_key: ICON.key, credit_card: ICON.card, phone: ICON.phone, ip_address: ICON.globe,
      private_key: ICON.key, jwt: ICON.key, connection_string: ICON.plug, iban: ICON.card, mac_address: ICON.server,
      env_assignment: ICON.key, crypto_wallet: ICON.card,
    }[kind] || ICON.shieldAlert;
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
     (POST /api/restart) and reloads the Studio once it's back · no terminal.

     PRIVACY: GET /api/update contacts GitHub release metadata only · nothing
     about the user leaves the device. Fail-soft: any error leaves the slot hidden.
     ------------------------------------------------------------------------- */
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  async function checkForUpdate() {
    const foot = $('#updateFoot');
    if (!foot) return;
    let st;
    try { st = await api('/update'); } // { currentVersion, latestVersion, updateAvailable }
    catch (e) { return; } // optional · never surface as an error
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
    if (st.applySupported === false) {
      // This install can't self-apply (macOS .app from the DMG, or a dev
      // build) · show how it actually updates instead of a button that
      // would refuse.
      if (st.applyNote) foot.appendChild(el('div', { class: 'umsg', text: st.applyNote }));
      const link = el('a', { class: 'btn', href: st.releaseUrl || '#', target: '_blank', rel: 'noopener', html: ICON.download + '<span>View release</span>' });
      foot.appendChild(link);
      return;
    }
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
      // Already current, or a dev build with no install receipt · show guidance.
      footMsg(foot, ICON.shield, 'Update', (res && res.message) || 'Already on the latest version.');
      return;
    }
    // Installed · relaunch the daemon and reload the Studio once it's back.
    footMsg(foot, ICON.restart, 'Restarting Saffev', 'Installed v' + res.newVersion + '. Relaunching…');
    try { await api('/restart', { method: 'POST' }); } catch (e) { /* server may drop mid-call · expected */ }
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
      } catch (e) { /* still down · keep polling */ }
      await sleep(1000);
    }
    footMsg(foot, ICON.check, 'Update installed', 'Saffev was relaunched · reload this page to continue.');
  }

  function handleApiError(e) {
    if (e && e.status === 401) {
      showBanner('Not authorized · the Studio token is missing or invalid. Run `' + BRAND.command + ' status` for the local URL with a token, or open Settings.', 'danger');
    } else if (e && e.status === 403) {
      showBanner('Blocked by Host allowlist · open the Studio at its loopback address (e.g. 127.0.0.1).', 'danger');
    } else if (e && e.status && e.code) {
      // The backend answered with a structured refusal (409/404/400) — its
      // message says exactly what to do; show it verbatim, not as "unreachable".
      showBanner(e.message + '.', 'danger');
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
  // Accessible on/off switch (role=switch + aria-checked). Every toggle handler
  // re-renders its container, so the control is rebuilt with the fresh state.
  function switchBtn(on, ariaLabel, opts) {
    opts = opts || {};
    const attrs = { class: 'switch' + (on ? ' on' : ''), role: 'switch', 'aria-checked': on ? 'true' : 'false', 'aria-label': ariaLabel };
    if (opts.title) attrs.title = opts.title;
    const b = el('button', attrs);
    if (opts.disabled) b.setAttribute('disabled', '');
    return b;
  }

  // Width floors are sized to the header label / typical mono cell content —
  // their sum (plus gaps + row padding) must stay under the Live stream card's
  // track at common window widths, or the whole table scrolls sideways. Cells
  // ellipsize, and the `auto` maxes still grow for outlier values.
  const REQ_COLS = {
    app:      { label: 'Source',   w: 'minmax(78px,1fr)',    r: false },
    model:    { label: 'Model',    w: 'minmax(68px,1fr)',    r: false },
    endpoint: { label: 'Endpoint', w: 'minmax(78px,1.1fr)',  r: false },
    status:   { label: 'Status',   w: 'minmax(52px,auto)',   r: false },
    pii:      { label: 'PII',      w: 'minmax(36px,auto)',   r: false },
    lat:      { label: 'Latency',  w: '64px',                r: true },
    tokens:   { label: 'Tokens',   w: 'minmax(70px,auto)',   r: true },
    time:     { label: 'Time',     w: '74px',                r: true },
  };
  const LIVE_COLS = ['app', 'model', 'endpoint', 'status', 'pii', 'lat', 'tokens', 'time'];
  const HIST_COLS = ['app', 'model', 'endpoint', 'status', 'pii', 'lat', 'tokens', 'time'];
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
      // Source is just the app now — PII/safety live in their own column.
      const cell = el('div', { class: 'tcell cell-app' });
      cell.appendChild(el('span', { class: 'nm', text: item.sourceApp || 'Unknown' }));
      return cell;
    }
    if (key === 'pii') {
      const cell = el('div', { class: 'tcell cell-pii' });
      // Collapse multiple PII kinds to "first + N" to keep the column compact.
      const kinds = item.piiKinds || [];
      if (kinds.length) {
        cell.appendChild(el('span', { class: 'piibadge' + (PII_SECRET_KINDS.includes(kinds[0]) ? ' key' : ''), 'data-k': kinds[0], text: piiShort(kinds[0]) }));
        if (kinds.length > 1) cell.appendChild(el('span', { class: 'piibadge more', title: kinds.slice(1).map(piiShort).join(', '), text: '+' + (kinds.length - 1) }));
      }
      // Safety flag (eval pipeline) shares this signals column.
      if (item.safetyFlagged) cell.appendChild(el('span', { class: 'safetybadge', title: 'Safety flagged', text: '⚠ safety' }));
      if (!kinds.length && !item.safetyFlagged) cell.appendChild(el('span', { class: 'cell-dim', text: '·' }));
      return cell;
    }
    if (key === 'model') return el('div', { class: 'tcell cell-model', title: item.model || '', text: item.model || '·' });
    if (key === 'endpoint') return el('div', { class: 'tcell cell-endpoint', title: item.endpoint || '', text: item.endpoint || '·' });
    if (key === 'status') {
      // Failed → the reason (red); otherwise the HTTP status (muted), or blank.
      if (isFailed(item)) {
        const lbl = failLabel(item);
        return el('div', { class: 'tcell cell-status bad', title: lbl, text: lbl });
      }
      return el('div', { class: 'tcell cell-status', text: item.status != null ? String(item.status) : '' });
    }
    if (key === 'lat') return el('div', { class: 'tcell r cell-lat', text: item.latencyMs != null ? item.latencyMs + 'ms' : '' });
    if (key === 'tokens') {
      const up = item.inputTokens != null ? (item.inputTokensSrc === 'estimated' ? '~' : '') + fmtNum(item.inputTokens) + '↑' : '';
      const down = item.outputTokens != null ? (item.outputTokensSrc === 'estimated' ? '~' : '') + fmtNum(item.outputTokens) + '↓' : '';
      return el('div', { class: 'tcell r cell-tokens', text: [up, down].filter(Boolean).join('  ') || '·' });
    }
    if (key === 'time') return el('div', { class: 'tcell r cell-time', title: item.ts ? new Date(item.ts).toLocaleString() : '', text: item.ts ? fmtStamp(item.ts) : '' });
    return el('div', { class: 'tcell' });
  }

  // One clickable row. opts: { columns, streaming, enter }.
  // A request "failed" if it never reached the engine / errored mid-stream
  // (errorKind set) or the engine returned an HTTP error (status >= 400).
  function isFailed(item) {
    return !!(item && (item.errorKind || (item.status != null && item.status >= 400)));
  }
  // Human label for a PII finding's action (snake_case from /history/:id).
  function piiActionLabel(a) {
    return a === 'masked' ? 'masked' : a === 'would_mask' ? 'would mask' : 'observed';
  }

  // Short human label for a failed exchange (for badges/drawer).
  function failLabel(item) {
    if (item.errorKind === 'upstream_unreachable') return 'unreachable';
    if (item.errorKind === 'stream_error') return 'stream error';
    if (item.errorKind) return item.errorKind;
    if (item.status != null && item.status >= 400) return 'HTTP ' + item.status;
    return 'error';
  }

  function reqRow(item, opts) {
    opts = opts || {};
    const cols = opts.columns || HIST_COLS;
    const row = el('div', {
      class: 'trow' + (opts.streaming ? ' streaming' : '') + (opts.enter ? ' enter' : '') + (isFailed(item) ? ' failed' : '') + (item.safetyFlagged ? ' flagged' : ''),
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
    kv('Model', it.model || '·');
    kv('Endpoint', it.endpoint);
    kv('Streamed', it.stream ? 'yes' : 'no');
    kv('Input tokens', it.inputTokens != null ? (it.inputTokensSrc === 'estimated' ? '~' : '') + fmtNum(it.inputTokens) : '·');
    kv('Output tokens', it.outputTokens != null ? (it.outputTokensSrc === 'estimated' ? '~' : '') + fmtNum(it.outputTokens) : '·');
    kv('Latency', it.latencyMs != null ? it.latencyMs + 'ms' : '·');
    kv('TTFT', it.ttftMs != null ? it.ttftMs + 'ms' : '·');
    kv('Status', it.status != null ? String(it.status) : (it.errorKind ? 'no response' : '·'));
    if (isFailed(it)) kv('Outcome', failLabel(it));
    kv('Time', new Date(it.ts).toLocaleString());

    const body = el('div', {}, [
      el('button', { class: 'iconbtn close', onclick: closeDrawer, 'aria-label': 'Close', html: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 6 18 18M18 6 6 18"/></svg>' }),
      el('h2', { text: it.sourceApp || 'Unknown app' }),
      el('div', { class: 'muted', style: 'font-family:var(--font-mono);font-size:.78rem;margin-top:4px', text: it.id }),
      dl,
    ]);

    // findings
    if (detail.findings && detail.findings.length) {
      // Header reflects what actually happened to this exchange's findings.
      const anyMasked = detail.findings.some((f) => f.action === 'masked');
      const anyWould = detail.findings.some((f) => f.action === 'would_mask');
      const hdr = anyMasked ? 'PII findings (some redacted)' : anyWould ? 'PII findings (dry-run · would redact)' : 'PII findings (observe-only)';
      const fl = el('div', { class: 'payblk' }, [el('h4', { text: hdr })]);
      const list = el('div', { class: 'findlist' });
      detail.findings.forEach((f) => {
        const r = el('div', { class: 'find' });
        r.appendChild(el('span', { class: 'piibadge' + (PII_SECRET_KINDS.includes(f.kind) ? ' key' : ''), text: piiShort(f.kind) }));
        r.appendChild(el('span', { text: piiLabel(f.kind, f.label) + ' · ' + f.confidence + ' confidence' }));
        r.appendChild(el('span', { class: 'actchip act-' + (f.action || 'observed'), text: piiActionLabel(f.action) }));
        r.appendChild(el('span', { class: 'where', text: f.side + ' [' + f.start + '–' + f.end + ']' }));
        list.appendChild(r);
      });
      fl.appendChild(list);
      body.appendChild(fl);
    }

    // safety findings (eval pipeline)
    if (detail.safety && detail.safety.length) {
      const sf = el('div', { class: 'payblk' }, [el('h4', { text: 'Safety findings' })]);
      const list = el('div', { class: 'findlist' });
      detail.safety.forEach((s) => {
        const r = el('div', { class: 'find' });
        r.appendChild(el('span', { class: 'safetybadge', text: '⚠ ' + s.verdict }));
        r.appendChild(el('span', { text: safetyLabel(s.category) + (s.score != null ? ' · ' + s.score.toFixed(2) : '') }));
        r.appendChild(el('span', { class: 'where', text: s.guardModel }));
        list.appendChild(r);
      });
      sf.appendChild(list);
      body.appendChild(sf);
    }

    // quality scores (eval pipeline)
    if (detail.eval && detail.eval.length) {
      const ef = el('div', { class: 'payblk' }, [el('h4', { text: 'Quality (' + esc(detail.eval[0].judgeModel) + ')' })]);
      const list = el('div', { class: 'findlist' });
      detail.eval.forEach((e) => {
        const r = el('div', { class: 'find' });
        r.appendChild(el('span', { class: 'actchip ' + (e.band === 'good' ? 'act-masked' : 'act-would_mask'), text: e.band }));
        r.appendChild(el('span', { text: e.metric + (e.rationale ? ' · ' + e.rationale : '') }));
        list.appendChild(r);
      });
      ef.appendChild(list);
      body.appendChild(ef);
    }

    // payloads — the debugging core: see exactly what the app sent + received
    if (detail.payloadsDisabled) {
      const enableBtn = el('button', { class: 'btn primary auto', html: ICON.eye + '<span>Turn on payload capture</span>' });
      const enableNote = el('div', { class: 'meta', style: 'margin-top:10px', hidden: true });
      enableBtn.addEventListener('click', async () => {
        setBusy(enableBtn, true);
        try {
          await api('/settings', { method: 'PUT', body: { payloadStorage: true } });
          enableNote.hidden = false; enableNote.className = 'onboard-note ok';
          enableNote.innerHTML = ICON.check + ' On. New exchanges will include the prompt and response — open one after your next request.';
        } catch (e) {
          enableNote.hidden = false; enableNote.className = 'onboard-note warn';
          enableNote.innerHTML = ICON.alert + ' ' + esc(e.message || 'Could not enable payload capture.');
        }
        setBusy(enableBtn, false);
      });
      body.appendChild(el('div', { class: 'payblk' }, [
        el('h4', { text: 'Payloads' }),
        el('p', { class: 'about-p', style: 'margin-top:0', text: 'Raw prompt and response are not stored (metadata-only, the privacy default). Turn it on to inspect exactly what your apps send and receive — stored encrypted, on this device.' }),
        enableBtn, enableNote,
      ]));
    } else if (detail.prompt != null || detail.response != null) {
      const base = await proxyBaseUrl();
      const msgs = parseMessages(detail.prompt);
      const resp = extractResponse(detail.response);

      // Action row: reproduce or copy this exchange.
      body.appendChild(el('div', { class: 'drawer-actions' }, [
        detail.prompt != null ? drawerCopyBtn('Copy as cURL', () => curlFor(base, it.endpoint, detail.prompt)) : null,
        detail.prompt != null ? drawerCopyBtn('Copy prompt', () => (msgs ? msgs.map((m) => m.role + ': ' + m.content).join('\n\n') : detail.prompt)) : null,
        detail.response != null ? drawerCopyBtn('Copy response', () => (resp.text || detail.response)) : null,
      ]));

      if (detail.prompt != null) {
        const pb = el('div', { class: 'payblk' }, [el('h4', { text: 'Prompt' })]);
        if (msgs) {
          const chat = el('div', { class: 'chat' });
          msgs.forEach((m) => chat.appendChild(el('div', { class: 'msg msg-' + esc((m.role || '').toLowerCase()) }, [
            el('div', { class: 'msg-role', text: m.role }),
            el('div', { class: 'msg-body', text: m.content }),
          ])));
          pb.appendChild(chat);
        } else {
          pb.appendChild(el('pre', { text: detail.prompt }));
        }
        body.appendChild(pb);
      }
      if (detail.response != null) {
        const rb = el('div', { class: 'payblk' }, [el('h4', { text: 'Response' })]);
        if (resp.text) {
          rb.appendChild(el('div', { class: 'msg msg-assistant' }, [
            el('div', { class: 'msg-role', text: 'assistant' + (resp.streamed ? ' · streamed' : '') }),
            el('div', { class: 'msg-body', text: resp.text }),
          ]));
          const rawPre = el('pre', { text: detail.response, hidden: true, style: 'margin-top:10px' });
          const tog = el('button', { class: 'linkbtn', type: 'button', text: 'show raw' });
          tog.addEventListener('click', () => { rawPre.hidden = !rawPre.hidden; tog.textContent = rawPre.hidden ? 'show raw' : 'hide raw'; });
          rb.appendChild(tog); rb.appendChild(rawPre);
        } else {
          rb.appendChild(el('pre', { text: detail.response }));
        }
        body.appendChild(rb);
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
     Dropdown · design-system replacement for the native <select>. Follows the
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
    const cur = () => items.find((it) => String(it.value) === String(value)) || items[0] || { label: '·' };
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

  // ---- payload inspection helpers (drawer) --------------------------------
  // Cached proxy base for "Copy as cURL"; fetched once from /api/settings.
  let _proxyBaseCache = null;
  async function proxyBaseUrl() {
    if (_proxyBaseCache) return _proxyBaseCache;
    try { const s = await api('/settings'); _proxyBaseCache = 'http://localhost:' + (s.proxyPort || 8088); }
    catch (e) { _proxyBaseCache = 'http://localhost:8088'; }
    return _proxyBaseCache;
  }
  // Parse a raw request body into chat messages, best-effort. Handles the
  // { messages:[{role,content}] } shape (Ollama /api/chat + OpenAI) and the
  // { prompt } shape (Ollama /api/generate). null if it isn't one of those.
  function parseMessages(raw) {
    if (!raw) return null;
    let j; try { j = JSON.parse(raw); } catch (e) { return null; }
    if (Array.isArray(j.messages)) {
      return j.messages.map((m) => ({ role: m.role || 'user', content: typeof m.content === 'string' ? m.content : JSON.stringify(m.content, null, 2) }));
    }
    if (typeof j.prompt === 'string') return [{ role: 'user', content: j.prompt }];
    return null;
  }
  // Pull assistant text from one parsed response object (Ollama + OpenAI shapes).
  function respText(j, delta) {
    if (j == null || typeof j !== 'object') return null;
    if (typeof j.response === 'string') return j.response;                              // Ollama /api/generate
    if (j.message && typeof j.message.content === 'string') return j.message.content;   // Ollama /api/chat
    if (Array.isArray(j.choices) && j.choices[0]) {
      const c = j.choices[0];
      if (delta && c.delta && typeof c.delta.content === 'string') return c.delta.content; // OpenAI stream
      if (c.message && typeof c.message.content === 'string') return c.message.content;     // OpenAI non-stream
      if (typeof c.text === 'string') return c.text;                                        // OpenAI completions
    }
    return null;
  }
  // Extract the assistant's text from a raw response body (single JSON, or an
  // NDJSON / SSE stream). Returns { text, streamed }.
  function extractResponse(raw) {
    if (!raw) return { text: '', streamed: false };
    const trimmed = raw.trim();
    try { const t = respText(JSON.parse(trimmed)); if (t != null) return { text: t, streamed: false }; } catch (e) { /* stream */ }
    let out = '';
    trimmed.split('\n').forEach((line) => {
      let s = line.trim();
      if (!s) return;
      if (s.startsWith('data:')) s = s.slice(5).trim();
      if (s === '[DONE]') return;
      try { const t = respText(JSON.parse(s), true); if (t) out += t; } catch (e) {}
    });
    return { text: out, streamed: true };
  }
  // A cURL that reproduces this request against the Saffev proxy (so re-running
  // it is itself traced). Body is the exact raw request payload.
  function curlFor(base, endpoint, rawBody) {
    const bodyArg = rawBody ? " \\\n  -d '" + String(rawBody).replace(/'/g, "'\\''") + "'" : '';
    return 'curl ' + base + (endpoint || '') + " \\\n  -H 'Content-Type: application/json'" + bodyArg;
  }
  // A copy button for the drawer action row; `getText` may be sync or async.
  function drawerCopyBtn(label, getText) {
    const btn = el('button', { class: 'copybtn', type: 'button', html: ICON.copy + '<span>' + label + '</span>' });
    btn.addEventListener('click', async () => {
      const ok = await copyText(await getText());
      btn.classList.toggle('done', ok);
      btn.innerHTML = (ok ? ICON.check : ICON.copy) + '<span>' + (ok ? 'Copied' : label) + '</span>';
      setTimeout(() => { btn.classList.remove('done'); btn.innerHTML = ICON.copy + '<span>' + label + '</span>'; }, 1600);
    });
    return btn;
  }

  /* -------------------------------------------------------------------------
     confirmModal · design-system confirmation dialog. Replaces the native
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
    sub: 'What your apps are doing with local models · right now.',
    _streamCtrl: null,    // AbortController for the in-flight stream fetch
    _streamTimer: null,   // reconnect backoff timer
    _stopStream: false,
    _streamRetry: 0,
    seen: {},             // id -> row element (for in-place updates)
    kpis: { requestsToday: 0, p50: null, pii: 0 },
    masking: { enabled: false, dryRun: true },  // synced from /api/settings
    _lastRecent: [],      // last recent window (for re-rendering the privacy lens)
    proxyPort: 8088,      // proxy port (from /api/settings) for onboarding copy blocks
    _needOnboard: false,  // true until the first request is ever captured

    async render(view) {
      view.innerHTML = '';
      // Onboarding slot · filled when no traffic has ever been captured.
      view.appendChild(el('div', { id: 'onboard' }));

      // Thin metric strip — a single hairline-separated band of figures, so the
      // stream (not the KPIs) is the hero. Matches the design's "metric cells".
      const stat = (id, label, sub, valHtml) => el('div', { class: 'stat' }, [
        el('div', { class: 'stat-l', text: label }),
        el('div', { class: 'stat-v num', id, html: valHtml }),
        el('div', { class: 'stat-s', text: sub }),
      ]);
      view.appendChild(el('section', { class: 'statbar reveal' }, [
        stat('kpiReq', 'Requests', 'since midnight', '·'),
        stat('kpiLat', 'Latency p50', 'recent window', '·'),
        stat('kpiPii', 'PII findings', 'observing · today', '·'),
        stat('kpiPulse', 'Throughput', 'req / min · live', '0'),
      ]));

      // Cockpit — the traffic stream is the hero (fills the height); a slim rail
      // carries "now" context: exposure, engine, and the privacy lens.
      const streamCard = el('div', { class: 'card streamcard reveal', style: 'animation-delay:.06s' }, [
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
      const rail = el('div', { class: 'rail reveal', style: 'animation-delay:.12s' }, [
        exposureHeroPlaceholder(),
        el('div', { class: 'card engine', id: 'liveEngine' }, [el('div', { class: 'state sm', text: 'Loading engine…' })]),
        el('div', { class: 'card', id: 'livePrivacy' }, [
          el('div', { class: 'hrow' }, [el('h3', { text: 'Privacy lens' }), el('div', { class: 'spacer' }), el('span', { class: 'tag', text: 'observe' })]),
          el('div', { id: 'livePrivacyBody' }, [el('div', { class: 'state sm', text: 'No findings yet.' })]),
        ]),
      ]);
      view.appendChild(el('section', { class: 'cockpit' }, [streamCard, rail]));
      // Filled with live values by refresh(); starts as placeholders, never
      // fake data.
      view.appendChild(el('div', { id: 'cliMirror' }, [cliBlock(null)]));

      await this.refresh();
      this.connectStream();
      this.startPulse();
    },

    startPulse() {
      this._pulse = this._pulse || [];
      this.renderPulse();
      this._pulseTimer = setInterval(() => this.renderPulse(), 1500);
    },
    renderPulse() {
      const now = Date.now();
      this._pulse = (this._pulse || []).filter((t) => now - t < 60000);
      const c = $('#kpiPulse');
      if (c) c.textContent = String(this._pulse.length);
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
        if (lat) lat.innerHTML = snap.p50LatencyMs != null ? esc(snap.p50LatencyMs) + '<small>ms</small>' : '·';
        setText('#kpiPii', fmtNum(snap.piiFindingsToday));
        updatePiiBadge(snap.piiFindingsToday);

        // seed stream (newest first; render oldest→newest by appending in reverse)
        const stream = $('#stream');
        if (stream) {
          stream.innerHTML = '';
          this.seen = {};
          const recent = (snap.recent || []).slice(0, 14);
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
        // Onboarding: show the "point an app at the proxy" card until the very
        // first request is ever captured (lifetime total, not the 24h window).
        this._needOnboard = (snap.lifetimeRequests || 0) === 0;
        this.renderOnboard(this._needOnboard);
      } catch (e) { handleApiError(e); }

      // engine + exposure (best-effort, independent of /live)
      try {
        const ev = await api('/engines');
        this._ev = ev;
        this.renderEngine(ev);
        this.renderExposureHero(ev.exposure);
        setEnginePill(ev);
        this.renderCliMirror();
      } catch (e) {
        // Don't leave the cards stuck on their loading text · show a small
        // error/retry state instead.
        const engBox = $('#liveEngine');
        if (engBox) { engBox.innerHTML = ''; engBox.appendChild(el('div', { class: 'state sm', text: 'Could not load engine · retrying…' })); }
        const heroBox = $('#exposureHero');
        if (heroBox) { heroBox.innerHTML = ''; heroBox.appendChild(el('div', { class: 'state sm', text: 'Exposure check unavailable' })); }
      }

      // masking state (best-effort) · keeps the Live toggle in sync with Settings.
      try {
        const s = await api('/settings');
        this.masking = { enabled: !!s.maskingEnabled, dryRun: !!s.maskingDryRun };
        this.renderMaskingBar();
        // Pick up the real proxy port so onboarding copy-blocks are accurate.
        this.proxyPort = s.proxyPort || this.proxyPort;
        this._payloadStorage = !!s.payloadStorage;
        if (this._needOnboard) this.renderOnboard(true);
        this.renderCliMirror();
      } catch (e) { /* leave the bar at its last-known state */ }
    },

    // Rebuild the status-mirror terminal from the freshest data we hold.
    renderCliMirror() {
      const host = $('#cliMirror');
      if (!host) return;
      const ev = this._ev;
      const active = ev && (ev.engines || []).find((e) => e.isActive);
      host.innerHTML = '';
      host.appendChild(cliBlock({
        proxyPort: this.proxyPort,
        upstreamPort: active ? active.publicPort : null,
        health: active ? active.health : null,
        mode: ev ? ev.mode : null,
        payloadStorage: this._payloadStorage,
        exposed: ev && ev.exposure ? !!ev.exposure.exposed : null,
      }));
    },

    // Render (or clear) the "no traffic yet" onboarding card. Shows the easiest
    // path (`saffev run`) plus manual base-URL routing for both Ollama and LM
    // Studio, using the live proxy port. Cleared the moment traffic arrives.
    renderOnboard(show) {
      const host = $('#onboard');
      if (!host) return;
      host.innerHTML = '';
      if (!show) return;
      const proxyUrl = 'http://localhost:' + this.proxyPort;

      // Primary path: one click, no terminal. Fires a captured request through
      // the proxy so the stream + privacy lens light up immediately.
      const demoBtn = el('button', { class: 'btn primary auto', html: ICON.bolt + '<span>Send a test prompt</span>' });
      const demoNote = el('div', { class: 'onboard-note', hidden: true });
      demoBtn.addEventListener('click', async () => {
        setBusy(demoBtn, true);
        demoNote.hidden = false;
        demoNote.className = 'onboard-note';
        demoNote.innerHTML = '<span class="spin sm"></span> Sending a test prompt through Saffev…';
        try {
          const r = await api('/demo', { method: 'POST' });
          demoNote.className = 'onboard-note ' + (r.captured ? 'ok' : 'warn');
          demoNote.innerHTML = (r.captured ? ICON.check : ICON.alert) + ' ' + esc(r.note);
        } catch (e) {
          demoNote.className = 'onboard-note warn';
          demoNote.innerHTML = ICON.alert + ' ' + esc(e.message || 'Could not send the test prompt.');
        }
        setBusy(demoBtn, false);
        // On success the Live SSE shows the row + retires this card automatically.
      });

      host.appendChild(el('div', { class: 'card reveal' }, [
        el('div', { class: 'hrow' }, [
          el('h3', { text: 'No traffic captured yet' }),
          el('div', { class: 'spacer' }),
          el('span', { class: 'tag', text: 'setup' }),
        ]),
        el('p', { class: 'about-p', text: 'Saffev shows every request your apps send to local models. See it work right now — one click, no terminal:' }),
        el('div', { class: 'onboard-cta' }, [
          demoBtn,
          el('span', { class: 'onboard-cta-hint', text: 'Sends a sample prompt with fake PII through the proxy, so the traffic stream and privacy lens light up.' }),
        ]),
        demoNote,
        el('div', { class: 'onboard-sep', html: '<span>then trace your own app</span>' }),
        el('p', { class: 'about-p', text: 'Route any app through Saffev with no config edits:' }),
        copyBlock('saffev run -- <your app>', { title: 'terminal · traces any app' }),
        el('div', { class: 'meta', html: 'Or set the base URL: <span class="kv">OLLAMA_BASE_URL=' + esc(proxyUrl) + '</span> · <span class="kv">OPENAI_BASE_URL=' + esc(proxyUrl) + '/v1</span> · <a href="#/about">more ways to integrate →</a>' }),
      ]));
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
        body.appendChild(el('a', { class: 'pii-more', href: '#/analytics/privacy', html: '<span>' + (extra > 0 ? '+' + extra + ' more · view full breakdown' : 'View full breakdown') + '</span>' + ICON.chevR }));
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
        : 'Masking is <b>off</b> · observe only';
      const sw = switchBtn(on, 'Toggle PII masking', { title: on ? 'Masking on · click to turn off' : 'Masking off · click to turn on' });
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
      // Show the ACTIVE (proxied) engine, not just the first detected one.
      const engines = ev.engines || [];
      const eng = engines.find((e) => e.isActive) || engines[0] || null;
      card.innerHTML = '';
      if (!eng) {
        card.appendChild(el('div', { class: 'state sm', text: 'No engine detected.' }));
        return;
      }
      const name = engineDisplayName(eng.engine) || eng.engine;
      const healthPill = healthToPill(eng.health);
      card.appendChild(el('div', { class: 'hrow' }, [
        el('h3', { text: 'Engine' }), el('div', { class: 'spacer' }),
        el('span', { class: 'pill ' + healthPill.cls, style: 'box-shadow:none', html: '<span class="dot"></span> ' + esc(eng.health) }),
      ]));
      card.appendChild(el('div', { class: 'top' }, [
        el('div', { class: 'logo', html: ICON.server }),
        el('div', {}, [
          el('div', { class: 'nm', text: name + (eng.version ? ' ' + eng.version : '') }),
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
        el('div', { class: 'meta', text: exp.detail || (exposed ? 'Reachable beyond this device' : 'Bound to 127.0.0.1 · not exposed') }),
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
      // Connection ended/failed · reconnect with capped backoff.
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
    },

    onEvent(msg) {
      const stream = $('#stream');
      if (!stream) return;
      // clear any "waiting" placeholder
      const ph = stream.querySelector('.state'); if (ph) ph.remove();

      if (msg.type === 'requestStarted') {
        // Traffic has arrived · retire the onboarding card for good.
        if (this._needOnboard) { this._needOnboard = false; this.renderOnboard(false); }
        // Feed the throughput pulse (req/min over a rolling 60s window).
        this._pulse = this._pulse || []; this._pulse.push(Date.now()); this.renderPulse();
        const it = msg.item;
        const row = reqRow(it, { columns: LIVE_COLS, streaming: it.stream, enter: true });
        this.seen[it.id] = row;
        stream.prepend(row);
        // Keep the privacy lens live: fold this exchange into the recent window
        // and re-render, so request-side PII shows immediately (not only on the
        // next full refresh). Matters most right after the one-click demo.
        this._lastRecent = [it, ...(this._lastRecent || [])].slice(0, 50);
        this.renderPrivacyLens(this._lastRecent);
        while (stream.children.length > 14) {
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
      } else if (msg.type === 'safety') {
        // Eval runs asynchronously after the exchange finished · badge the row
        // retroactively if it's still on screen.
        const row = this.seen[msg.id];
        if (row) {
          row.classList.add('flagged');
          const piiCell = row.querySelector('.cell-pii');
          if (piiCell && !piiCell.querySelector('.safetybadge')) {
            const dim = piiCell.querySelector('.cell-dim');
            if (dim) dim.remove();
            piiCell.appendChild(el('span', { class: 'safetybadge', title: 'Safety flagged', text: '⚠ safety' }));
          }
        }
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

    teardown() { this.disconnectStream(); if (this._pulseTimer) { clearInterval(this._pulseTimer); this._pulseTimer = null; } },
  };

  function exposureHeroPlaceholder() {
    return el('div', { class: 'card kpi hero', id: 'exposureHero', style: 'animation-delay:.26s' }, [
      el('div', { class: 'label' }, [el('span', { class: 'ic safe', html: ICON.shield }), document.createTextNode(' Exposure')]),
      el('div', { class: 'val' }, [el('span', { class: 'check', html: ICON.check }), document.createTextNode('Checking…')]),
      el('div', { class: 'meta', text: 'Reading exposure doctor' }),
    ]);
  }

  // Metric-strip primitives (design's "metric cells") — one balanced hairline
  // band, used for every KPI row (Live, Analytics Overview / Privacy / Quality).
  // `sub` may be a string (→ mono .stat-s) or a prebuilt node (e.g. a delta).
  function statCell(label, valueHtml, sub, spark) {
    const subNode = typeof sub === 'string' ? el('div', { class: 'stat-s', text: sub }) : sub || null;
    return el('div', { class: 'stat' }, [
      el('div', { class: 'stat-l', text: label }),
      el('div', { class: 'stat-v num', html: valueHtml }),
      subNode,
      spark ? el('div', { class: 'stat-spark' }, [spark]) : null,
    ]);
  }
  function statStrip(cols, cells) {
    return el('section', { class: 'statbar reveal', style: '--cols:' + cols }, cells);
  }

  // A mirror of `saffev status` built from LIVE state (never hardcoded ports
  // or verdicts — a terminal that always says "healthy · not exposed" is a
  // decoration, not a status). `info`: { proxyPort, upstreamPort, health,
  // mode, payloadStorage, exposed } — any missing field renders as `·`.
  function cliBlock(info) {
    info = info || {};
    const port = (p) => (p != null ? ':' + p : '·');
    const healthy = info.health === 'healthy';
    const healthHtml = info.health
      ? '<span class="' + (healthy ? 'g' : 'r') + '">' + esc(info.health) + '</span>'
      : '<span class="m">·</span>';
    const modeLine = info.mode === 'gateway'
      ? 'gateway <span class="m">·</span> transparent capture on the engine port'
      : (info.mode ? 'cooperative <span class="m">·</span> captures traffic sent to the proxy' : '·');
    const privacyLine = info.payloadStorage
      ? 'payload capture on <span class="m">·</span> opt-in'
      : 'metadata-only <span class="m">·</span> raw text never stored';
    const exposureLine = info.exposed == null
      ? '<span class="m">·</span>'
      : (info.exposed
        ? '<span class="r">⚠ reachable beyond localhost</span>'
        : 'localhost-only  <span class="g">✓ not exposed</span>');
    const pre =
      '<span class="p">~</span> <span class="v">' + esc(BRAND.command) + ' status</span>\n' +
      '<span class="g">●</span> proxy      <span class="c">' + esc(port(info.proxyPort)) + '</span> <span class="m">▸</span> engine <span class="c">' + esc(port(info.upstreamPort)) + '</span>      ' + healthHtml + '\n' +
      '<span class="g">●</span> mode       ' + modeLine + '\n' +
      '<span class="g">●</span> privacy    ' + privacyLine + '\n' +
      '<span class="g">●</span> exposure   ' + exposureLine + '\n' +
      '<span class="p">~</span> <span class="v">_</span>';
    return el('div', { class: 'cli reveal', style: 'animation-delay:.48s' }, [
      el('div', { class: 'bar' }, [
        el('div', { class: 'tl', html: '<i></i><i></i><i></i>' }),
        el('div', { class: 'ti', text: BRAND.command + ' · zsh · the CLI speaks the same language' }),
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
    sub: 'Every proxied exchange · searchable, filterable, on-device.',
    q: '', piiOnly: false, failedOnly: false, pageSize: 25,
    pages: [],        // fetched pages: array of arrays of HistoryItem (each non-empty)
    pageIndex: 0,     // which fetched page is currently shown (0-based)
    exhausted: false, // true once the last fetch returned < pageSize (no more pages)
    loading: false,

    async render(view) {
      this.q = ''; this.scope = 'all'; this.piiOnly = false; this.failedOnly = false; this.pages = []; this.pageIndex = 0; this.exhausted = false;
      view.innerHTML = '';

      // Forensic filter bar: a prominent search field + a segmented scope facet
      // (All / With PII / Failed) + rows-per-page. Scope is exclusive — cleaner
      // than two independent checkboxes.
      const MAG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="10.5" cy="10.5" r="6.5"/><path d="M15.5 15.5 21 21"/></svg>';
      const search = el('input', { class: 'sf-input', type: 'search', placeholder: 'Search app, model, or endpoint…', value: this.q });
      let t;
      search.addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => { this.q = search.value.trim(); this.reload(); }, 250); });
      const searchField = el('div', { class: 'searchfield' }, [el('span', { class: 'sf-ic', html: MAG }), search]);

      const SCOPES = [['all', 'All'], ['pii', 'With PII'], ['failed', 'Failed']];
      const seg = el('div', { class: 'tabbar', role: 'tablist', 'aria-label': 'Filter scope', style: 'margin-bottom:0' });
      SCOPES.forEach(([k, l]) => {
        const b = el('button', { class: 'tab' + (this.scope === k ? ' active' : ''), type: 'button', 'data-scope': k, text: l });
        b.addEventListener('click', () => {
          if (this.scope === k) return;
          this.scope = k; this.piiOnly = k === 'pii'; this.failedOnly = k === 'failed';
          seg.querySelectorAll('.tab').forEach((x) => x.classList.toggle('active', x.dataset.scope === k));
          this.reload();
        });
        seg.appendChild(b);
      });

      const sizeSel = dropdown(
        [10, 25, 50, 100].map((n) => ({ value: n, label: n + ' / page' })),
        this.pageSize,
        (v) => { this.pageSize = parseInt(v, 10); this.reload(); },
        { ariaLabel: 'Rows per page', align: 'right' }
      );
      const toolbar = el('div', { class: 'filterbar reveal' }, [searchField, seg, el('div', { class: 'spacer' }), sizeSel]);

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
      if (this.failedOnly) params.set('failedOnly', 'true');
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
  // Rendered as the Analytics "Privacy" tab (never routed directly — bare
  // #/privacy redirects there). `an` is the Analytics page object, passed so
  // the tab can add window-scoped charts from /analytics data.
  const Privacy = {
    async render(view, an) {
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
      const on = !!s.maskingEnabled;
      const live = on && !s.maskingDryRun;
      // Three honest states: off, dry-run (observing), live (redacting).
      const maskVal = !on ? 'Observe-only' : live ? 'Live' : 'Dry-run';
      const maskSub = !on ? 'nothing is altered · detection only'
        : live ? 'high-confidence PII is redacted'
        : 'enabled, but observing · nothing redacted yet';
      const kpis = statStrip(4, [
        statCell('Total findings', fmtNum(s.total), 'across retained window'),
        statCell('On request', fmtNum(reqSide), 'outbound to the model'),
        statCell('On response', fmtNum(respSide), 'returned from the model'),
        statCell('Masking', maskVal, maskSub),
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

      // When rendered as the Analytics Privacy tab, `an` carries the analytics
      // window data — add the charts only that window can provide (time series
      // + side/action donuts). The by-type/app/model breakdowns above already
      // cover the rest, so nothing is duplicated.
      const d = an && an.data;
      if (d && (d.piiFindings || 0) > 0) {
        const C = window.SaffevCharts;
        const xl = an.xLabels(d);
        const grid = el('section', { class: 'an-grid', style: 'margin-top:16px' });
        grid.appendChild(anCard('PII findings over time', 'analytics window', C.lineArea({ series: [{ name: 'PII', values: d.series.map((b) => b.pii), color: 'var(--danger)' }], xLabels: xl }), true));
        grid.appendChild(anCard('Where it appears', 'into vs out of the model', C.donut({ items: [{ label: 'On request (to model)', value: d.piiRequestSide, color: 'var(--danger)' }, { label: 'On response (from model)', value: d.piiResponseSide, color: 'var(--gold)' }], centerLabel: 'findings' })));
        grid.appendChild(anCard('Masking action', 'observed / dry-run / masked', C.donut({ items: (d.piiByAction || []).map((a) => ({ label: actionLabel(a.name), value: a.count })), centerLabel: 'findings' })));
        view.appendChild(grid);
      }
      updatePiiBadge(s.total);
    },
    teardown() {},
  };

  /* Sub-label for the Tokens KPI. Per-row views mark an estimated count with a
     tilde, but this total blends engine-reported counts with ones we estimated,
     and this is the number people quote. Say so when any of it is estimated. */
  function tokenProvenance(d) {
    const total = (d.totalInputTokens || 0) + (d.totalOutputTokens || 0);
    const est = (d.estimatedInputTokens || 0) + (d.estimatedOutputTokens || 0);
    const base = fmtNum(d.totalInputTokens) + ' in · ' + fmtNum(d.totalOutputTokens) + ' out';
    if (!est || !total) return base;
    if (est >= total) return base + ' · all estimated';
    return base + ' · ' + Math.round((est / total) * 100) + '% estimated';
  }

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
    sub: 'How your apps reach the engine, and whether anything is exposed.',
    busy: false,

    async render(view) {
      view.innerHTML = '';
      view.appendChild(loadingState('Detecting engines…'));
      await this.refresh(view);
    },

    async refresh(view) {
      view = view || $('#view');
      let ev, s = null;
      try { ev = await api('/engines'); hideBanner(); }
      catch (e) { handleApiError(e); view.innerHTML = ''; view.appendChild(emptyState('Could not load engines', e.message || '')); return; }
      try { s = await api('/settings'); } catch (e) { /* proxy port is best-effort */ }
      view.innerHTML = '';
      setEnginePill(ev);

      // Connection topology hero — the whole point of the page: how traffic flows
      // (your apps → Saffev → engine), with exposure + mode woven onto the path.
      const exp = ev.exposure;
      const safe = !exp.exposed;
      const proxyPort = (s && s.proxyPort) || 8088;
      const activeEng = (ev.engines || []).find((e) => e.isActive);
      const engName = activeEng ? (engineDisplayName(activeEng.engine) || activeEng.engine) : 'Engine';
      const engPort = activeEng ? activeEng.publicPort : (ev.mode === 'gateway' && activeEng && activeEng.shadowPort) || '11434';
      const node = (t, d, brand) => el('div', { class: 'flow-node' + (brand ? ' brandnode' : '') }, [
        el('div', { class: 'flow-t', text: t }), el('div', { class: 'flow-d', text: d }),
      ]);
      const arrow = () => el('div', { class: 'flow-arrow', html: ICON.chevR });
      const topo = el('div', { class: 'card reveal' }, [
        el('div', { class: 'hrow' }, [
          el('h3', { text: 'Connection' }), el('div', { class: 'spacer' }),
          el('span', { class: 'tag', text: ev.mode }),
          el('span', { class: 'pill ' + (safe ? '' : 'dangerpill'), style: 'margin-left:8px', html: '<span class="dot"></span> ' + (safe ? 'localhost only' : 'exposed') }),
        ]),
        el('div', { class: 'flow', style: 'margin-top:16px' }, [
          node('Your apps', 'point base URL here', false), arrow(),
          node('Saffev', ':' + proxyPort + ' · observing', true), arrow(),
          node(engName, ':' + engPort + ' · untouched', false),
        ]),
        el('div', { class: 'expnote' + (safe ? '' : ' danger'), style: 'margin-top:14px', html: (safe ? ICON.check : ICON.alert) + ' ' + esc(exposureLine(exp)) + ' · auth ' + (exp.tokenProtected ? 'protected' : 'unprotected') }),
      ]);
      view.appendChild(topo);

      // Route an app + mode explainer (2-up, balanced).
      const base = 'http://localhost:' + proxyPort;
      const routeCard = el('div', { class: 'card reveal', style: 'animation-delay:.06s' }, [
        el('div', { class: 'hrow' }, [el('h3', { text: 'Route an app' }), el('div', { class: 'spacer' }), el('span', { class: 'tag', text: 'no config edits' })]),
        el('p', { class: 'about-p', style: 'margin-top:6px', text: 'Wrap any command so its LLM calls flow through Saffev:' }),
        (() => { const b = el('div', { class: 'ports', style: 'margin-top:2px' }); b.innerHTML = '<span class="muted">$</span> ' + esc(BRAND.command) + ' run <span class="arr">‹your app›</span>'; return b; })(),
        el('p', { class: 'about-p', style: 'margin-top:12px', text: 'Or set the base URL manually:' }),
        (() => { const b = el('div', { class: 'ports', style: 'margin-top:2px' }); b.innerHTML = '<span class="muted">OpenAI</span> ' + esc(base) + '/v1'; return b; })(),
        (() => { const b = el('div', { class: 'ports', style: 'margin-top:8px' }); b.innerHTML = '<span class="muted">Ollama</span> ' + esc(base); return b; })(),
      ]);
      const modeCard = el('div', { class: 'card reveal', style: 'animation-delay:.1s' }, [
        el('div', { class: 'hrow' }, [el('h3', { text: 'Mode' }), el('div', { class: 'spacer' }), el('span', { class: 'tag', text: ev.mode })]),
        el('div', { class: 'muted', style: 'font-size:.86rem;margin-top:8px;line-height:1.6', text: ev.mode === 'gateway'
          ? 'Gateway · Saffev supervises the engine and owns the public port, forwarding to a shadow port. Captures all engine traffic transparently.'
          : 'Cooperative · apps point at Saffev; the engine keeps running independently. Universal and zero-config. Only sees traffic sent to the proxy port.' }),
      ]);
      view.appendChild(el('section', { class: 'grid', style: 'grid-template-columns:1fr 1fr;margin:16px 0' }, [routeCard, modeCard]));

      // engine cards
      if (!ev.engines || ev.engines.length === 0) {
        view.appendChild(emptyState('No engines detected', 'Start your local LLM engine (Ollama on :11434 or LM Studio on :1234) and refresh.'));
        return;
      }
      const grid = el('section', { class: 'grid', style: 'grid-template-columns:repeat(auto-fit,minmax(320px,1fr))' });
      ev.engines.forEach((eng) => grid.appendChild(this.engineCard(eng, ev.mode, exp)));
      view.appendChild(grid);
    },

    engineCard(eng, mode, exp) {
      const active = !!eng.isActive;
      const managed = eng.adoptionState === 'adopted' || eng.adoptionState === 'cooperative';
      const healthPill = healthToPill(eng.health);
      const name = engineDisplayName(eng.engine) || eng.engine;
      const card = el('div', { class: 'card engine reveal' + (active ? '' : ' inactive') });
      card.appendChild(el('div', { class: 'hrow' }, [
        el('h3', { text: name }), el('div', { class: 'spacer' }),
        el('span', { class: 'tag' + (active ? ' oktag' : ''), text: active ? 'proxied' : 'detected' }),
        el('span', { class: 'pill ' + healthPill.cls, style: 'box-shadow:none;margin-left:8px', html: '<span class="dot"></span> ' + esc(eng.health) }),
      ]));
      card.appendChild(el('div', { class: 'top' }, [
        el('div', { class: 'logo', html: ICON.server }),
        el('div', {}, [
          el('div', { class: 'nm', text: name + (eng.version ? ' ' + eng.version : '') }),
          el('div', { class: 'st', text: active ? (mode + ' · Saffev forwards here') : 'running · not proxied' }),
        ]),
      ]));
      const portsLine = el('div', { class: 'ports' });
      portsLine.innerHTML = '<span class="muted">port</span> :' + esc(eng.publicPort) +
        (eng.shadowPort != null ? ' <span class="arr">→</span> <span class="muted">shadow</span> :' + esc(eng.shadowPort) : '');
      card.appendChild(portsLine);

      if (active) {
        card.appendChild(el('div', { class: 'expnote' + (exp.exposed ? ' danger' : ''), html: (exp.exposed ? ICON.alert : ICON.check) + ' ' + esc(exposureLine(exp)) }));
        // adopt / revert buttons
        const btnrow = el('div', { class: 'btnrow' });
        if (managed) {
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
      } else {
        // A second running engine Saffev isn't forwarding to. Explain how to
        // route it · no adopt/revert (only the active upstream is managed).
        card.appendChild(el('div', { class: 'expnote', html: ICON.plug + ' Saffev is forwarding to the active engine. To trace this one, run an app through it with <span class="kv">saffev run</span>, or set <span class="kv">upstream = ' + esc(eng.publicPort) + '</span> in your config and restart.' }));
      }
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
    sub: 'Local configuration · written to the on-device config file.',
    saving: false,
    tab: 'general',  // preserved across re-draws so a toggle doesn't jump tabs
    _restartNote: null,       // set when a restart-required field was changed
    _pendingUpdate: null,     // requested restart-required values (mode/ports)

    async render(view) {
      view.innerHTML = '';
      view.appendChild(loadingState('Loading settings…'));
      // Fresh load = the running config; any prior pending change is either
      // applied (post-restart) or moot.
      this._restartNote = null;
      this._pendingUpdate = null;
      let s;
      try { s = await api('/settings'); hideBanner(); }
      catch (e) { handleApiError(e); view.innerHTML = ''; view.appendChild(emptyState('Could not load settings', e.message || '')); return; }
      view.innerHTML = '';
      this.draw(view, s);
    },

    draw(view, s) {
      view.innerHTML = '';
      // Reflect a pending restart-required change (mode/ports) in the controls,
      // even though the backend still reports the currently-RUNNING value.
      if (this._pendingUpdate) s = Object.assign({}, s, this._pendingUpdate);
      if (this._restartNote) {
        view.appendChild(el('div', { class: 'card reveal', style: 'margin-bottom:14px' }, [
          el('div', { class: 'expnote warn-expnote', html: ICON.bolt + ' ' + esc(this._restartNote) }),
        ]));
      }
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

      // Deep-link focus (`#/settings/<tab>/<section>`): scroll to the named
      // card and flash it so the user lands on the exact control they were
      // sent to (e.g. the Agents "Turn on Preservation" banner). One-shot.
      if (this._focus) {
        const target = panel.querySelector('[data-focus="' + this._focus + '"]');
        this._focus = null;
        if (target) {
          // Let the entrance animation place the card before scrolling to it.
          setTimeout(() => {
            target.scrollIntoView({ behavior: 'smooth', block: 'center' });
            target.classList.add('focus-flash');
            setTimeout(() => target.classList.remove('focus-flash'), 2400);
          }, 80);
        }
      }
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
      const sw = switchBtn(s.payloadStorage, 'Toggle payload storage');
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
        ? 'On · full prompts & responses are retained on this device.'
        : 'Off · metadata-only (default). Raw payloads are never stored.';
      const payRow = setRow('Store raw payloads', payHint, el('div', { class: 'ctl' }, [sw]));
      if (s.payloadStorage) payRow.querySelector('.hint').classList.add('danger-note');
      privCard.appendChild(payRow);
      const retVal = retentionText(s.retention);
      const retItems = [['age30', 'Age · 30 days'], ['age7', 'Age · 7 days'], ['age90', 'Age · 90 days'], ['size500', 'Size · 500 MB'], ['unlimited', 'Unlimited']].map(([v, t]) => ({ value: v, label: t }));
      const curKey = retentionKey(s.retention);
      // A config-file value outside the presets (e.g. Age · 14 days) would else
      // silently show the first option · surface the actual current value.
      if (!retItems.some((i) => i.value === curKey)) retItems.unshift({ value: curKey, label: retVal + ' (current)' });
      const retSel = dropdown(
        retItems,
        curKey, (v) => this.save(view, { retention: retentionFromKey(v) }), { ariaLabel: 'Retention' }
      );
      privCard.appendChild(setRow('Retention', 'How long exchanges are kept before pruning. Currently: ' + retVal + '.', el('div', { class: 'ctl' }, [retSel])));
      panel.appendChild(privCard);

      /* A shared team policy outranks this page. Say so at the top, name the
         file, and disable the controls it governs — a switch that looks live but
         silently does nothing is worse than one that says no. */
      const pol = s.policy || null;
      const governed = (f) => !!(pol && pol.active && (pol.governs || []).includes(f));
      if (pol) {
        const card = el('div', { class: 'card reveal policycard' + (pol.active ? '' : ' bad') });
        card.appendChild(el('div', { class: 'hrow' }, [el('h3', { text: pol.active ? 'Team policy in force' : 'Team policy NOT applied' })]));
        if (pol.active) {
          card.appendChild(el('p', { class: 'about-p', text: (pol.description ? pol.description + ' · ' : '') + 'Settings named by this policy are managed there, not here.' }));
          card.appendChild(el('p', { class: 'about-p', text: 'Governs: ' + ((pol.governs || []).join(', ') || 'nothing') }));
        } else {
          card.appendChild(el('p', { class: 'about-p', text: 'You are NOT protected by this policy. ' + (pol.error || '') }));
        }
        card.appendChild(el('code', { class: 'digest', text: pol.path }));
        panel.appendChild(card);
      }

      // PII masking (opt-in redaction, dry-run by default)
      const maskCard = el('div', { class: 'card reveal', style: 'animation-delay:.06s' }, [el('div', { class: 'hrow' }, [el('h3', { text: 'PII masking' })])]);
      const mEnable = switchBtn(s.maskingEnabled, 'Toggle PII masking', { disabled: governed('masking.enabled') });
      mEnable.addEventListener('click', () => { if (governed('masking.enabled')) return; const next = !mEnable.classList.contains('on'); this.save(view, { maskingEnabled: next }); });
      const enHint = governed('masking.enabled') ? 'Set by your team policy.' : s.maskingEnabled
        ? 'On · high-confidence PII detectors feed the masking pipeline.'
        : 'Off · observe-only (default). Traffic is never altered.';
      maskCard.appendChild(setRow('Enable masking', enHint, el('div', { class: 'ctl' }, [mEnable])));
      const mDry = switchBtn(s.maskingDryRun, 'Toggle masking dry-run', { disabled: !s.maskingEnabled || governed('masking.dry_run') });
      mDry.addEventListener('click', async () => {
        if (!s.maskingEnabled || governed('masking.dry_run')) return;
        const next = !mDry.classList.contains('on');
        if (!next) {
          const ok = await confirmModal({
            title: 'Turn off dry-run?',
            body: 'With dry-run off, high-confidence PII (email, card, API key, IP, phone) is redacted from requests BEFORE they reach the model, and from responses on the way back \u00b7 including streams, via a bounded holdback that catches spans straddling chunks.\n\nFail-open: any error forwards the original traffic unchanged.',
            confirmLabel: 'Start redacting', danger: true,
          });
          if (!ok) return;
        }
        this.save(view, { maskingDryRun: next });
      });
      const dryHint = governed('masking.dry_run')
        ? 'Set by your team policy.'
        : !s.maskingEnabled
        ? 'Enable masking first to choose dry-run vs live.'
        : (s.maskingDryRun
          ? 'On (default) · records what WOULD be masked; traffic is unchanged.'
          : 'Off · LIVE: high-confidence PII is redacted from requests before forwarding.');
      const dryRow = setRow('Dry-run', dryHint, el('div', { class: 'ctl' }, [mDry]));
      if (s.maskingEnabled && !s.maskingDryRun) dryRow.querySelector('.hint').classList.add('danger-note');
      maskCard.appendChild(dryRow);

      /* Blocking: for the things that must not reach a model at all, where
         "we replaced it for you" is the wrong answer. Nothing is blocked unless
         the user picks a kind here AND dry-run is off. */
      const BLOCKABLE = [
        { k: 'api_key', l: 'API keys' },
        { k: 'credit_card', l: 'Cards' },
        { k: 'email', l: 'Emails' },
        { k: 'phone', l: 'Phones' },
        { k: 'ip_address', l: 'IP addresses' },
      ];
      const current = new Set(s.maskingBlockKinds || []);
      const chips = el('div', { class: 'chiprow' });
      BLOCKABLE.forEach((b) => {
        const on = current.has(b.k);
        const chip = el('button', {
          class: 'chip' + (on ? ' on' : ''), type: 'button',
          'aria-pressed': on ? 'true' : 'false', text: b.l,
          disabled: !s.maskingEnabled || governed('masking.block_kinds'),
        });
        chip.addEventListener('click', async () => {
          if (!s.maskingEnabled || governed('masking.block_kinds')) return;
          const next = new Set(current);
          if (on) next.delete(b.k);
          else {
            const ok = await confirmModal({
              title: 'Block ' + b.l.toLowerCase() + '?',
              body: 'Requests containing ' + b.l.toLowerCase() + ' will be STOPPED and never sent to the model. The calling app gets a clear error explaining why.\n\nThis only takes effect while dry-run is off. Nothing else changes: internal errors still forward normally, so Saffev can never break your traffic by accident.',
              confirmLabel: 'Block them', danger: true,
            });
            if (!ok) return;
            next.add(b.k);
          }
          this.save(view, { maskingBlockKinds: Array.from(next) });
        });
        chips.appendChild(chip);
      });
      const blockHint = governed('masking.block_kinds')
        ? 'Set by your team policy.'
        : !s.maskingEnabled
        ? 'Enable masking first.'
        : (current.size === 0
          ? 'Nothing is blocked (default). Masking quietly redacts instead. Pick a kind here only if it must never reach a model at all.'
          : (s.maskingDryRun
            ? 'Selected, but dry-run is on, so these are only recorded as "would block". Turn off dry-run to actually stop them.'
            : 'LIVE · requests containing these are stopped and never reach the model.'));
      const blockRow = setRow('Block outright', blockHint, chips);
      if (s.maskingEnabled && !s.maskingDryRun && current.size) blockRow.querySelector('.hint').classList.add('danger-note');
      maskCard.appendChild(blockRow);
      panel.appendChild(maskCard);

      // Evaluation (eval pipeline: safety guard + judge). Async, off hot path.
      const evalCard = el('div', { class: 'card reveal', 'data-focus': 'evaluation', style: 'animation-delay:.12s' }, [el('div', { class: 'hrow' }, [el('h3', { text: 'Evaluation' })])]);
      const evEnable = switchBtn(s.evalEnabled, 'Toggle evaluation');
      evEnable.addEventListener('click', () => this.save(view, { evalEnabled: !evEnable.classList.contains('on') }));
      const evHint = s.evalEnabled
        ? 'On · sampled exchanges are scored asynchronously, on-device (never blocks your model).'
        : 'Off · no evaluation. Turn on to score traffic for safety (and quality later).';
      evalCard.appendChild(setRow('Enable evaluation', evHint, el('div', { class: 'ctl' }, [evEnable])));

      const safEnable = switchBtn(s.evalSafety, 'Toggle safety guard', { disabled: !s.evalEnabled });
      safEnable.addEventListener('click', () => { if (!s.evalEnabled) return; this.save(view, { evalSafety: !safEnable.classList.contains('on') }); });
      const safHint = !s.evalEnabled ? 'Enable evaluation first.' : 'Deterministic keyword/pattern safety floor (deterministic:v2) · cheap, no model, runs on all exchanges.';
      evalCard.appendChild(setRow('Safety guard', safHint, el('div', { class: 'ctl' }, [safEnable])));

      // Quality judge (model-backed, opt-in). Needs a judge model configured.
      const qEnable = switchBtn(s.evalQuality, 'Toggle quality judge', { disabled: !s.evalEnabled });
      qEnable.addEventListener('click', () => { if (!s.evalEnabled) return; this.save(view, { evalQuality: !qEnable.classList.contains('on') }); });
      const qHint = !s.evalEnabled ? 'Enable evaluation first.'
        : (s.evalJudgeModel ? 'LLM-as-judge on your own engine · sampled + concurrency-gated so it never thrashes the model.' : 'Set a judge model below to activate.');
      evalCard.appendChild(setRow('Quality judge', qHint, el('div', { class: 'ctl' }, [qEnable])));

      const modelInput = el('input', { class: 'input', type: 'text', placeholder: 'e.g. qwen3.5:2b', value: s.evalJudgeModel || '' });
      if (!s.evalEnabled) modelInput.setAttribute('disabled', '');
      let mt;
      modelInput.addEventListener('input', () => { clearTimeout(mt); mt = setTimeout(() => this.save(view, { evalJudgeModel: modelInput.value.trim() }), 600); });
      evalCard.appendChild(setRow('Judge model', 'A small model on your running engine (Ollama/LM Studio) to score quality. Leave blank to disable.', el('div', { class: 'ctl' }, [modelInput])));

      const rateSel = dropdown(
        [['0', 'Off'], ['0.1', '10%'], ['0.25', '25%'], ['0.5', '50%'], ['1', '100%']].map(([v, t]) => ({ value: v, label: t })),
        String(s.evalSampleRate), (v) => this.save(view, { evalSampleRate: parseFloat(v) }), { ariaLabel: 'Judge sampling' }
      );
      evalCard.appendChild(setRow('Judge sampling', 'Fraction of exchanges sent to the model judge. The safety guard always runs on all exchanges when enabled.', el('div', { class: 'ctl' }, [rateSel])));
      panel.appendChild(evalCard);

      // AI analysis (optional Codex app-server backend). The ONLY feature that
      // sends content off-device — strictly opt-in, and only on an explicit click.
      const aiCard = el('div', { class: 'card reveal', 'data-focus': 'analysis', style: 'animation-delay:.16s' }, [el('div', { class: 'hrow' }, [el('h3', {}, [el('span', { class: 'aiblk-ic', html: ICON.sparkles }), document.createTextNode(' AI analysis')])])]);
      const aiEnable = switchBtn(s.analysisEnabled, 'Toggle AI analysis', { disabled: !s.analysisAvailable });
      aiEnable.addEventListener('click', () => { if (!s.analysisAvailable) return; this.save(view, { analysisEnabled: !aiEnable.classList.contains('on') }); });
      const aiHint = !s.analysisAvailable
        ? 'Codex not detected on this machine. Install the Codex CLI and sign in to enable AI summaries.'
        : (s.analysisEnabled
          ? 'On · this is the ONLY feature in Saffev that sends your content off this device. When you click Summarize on a session, its full text is uploaded to OpenAI through your own Codex sign-in. Never automatic, never in the background, and never without that click.'
          : 'Off · nothing leaves the device. Turning this on permits session text to be sent to OpenAI through your own Codex, but only on an explicit click.');
      aiCard.appendChild(setRow('Enable AI analysis', aiHint, el('div', { class: 'ctl' }, [aiEnable])));
      panel.appendChild(aiCard);

      // Preservation archive — durable local copy that survives source deletion.
      const arCard = el('div', { class: 'card reveal', 'data-focus': 'preservation', style: 'animation-delay:.2s' }, [el('div', { class: 'hrow' }, [el('h3', { text: 'Preservation' })])]);
      const arEnable = switchBtn(s.archiveEnabled, 'Toggle preservation archive');
      arEnable.addEventListener('click', () => this.save(view, { archiveEnabled: !arEnable.classList.contains('on') }));
      const arHint = s.archiveEnabled
        ? 'On · Saffev keeps a durable, encrypted copy of your agent history that survives the source apps deleting theirs. Local-only, nothing leaves the device.'
        : 'Off · your history lives only in each tool, subject to its deletion policy. Turn on to keep your own copy.';
      arCard.appendChild(setRow('Enable preservation', arHint, el('div', { class: 'ctl' }, [arEnable])));
      const arAuto = switchBtn(s.archiveAuto, 'Toggle automatic snapshots', { disabled: !s.archiveEnabled });
      arAuto.addEventListener('click', () => { if (!s.archiveEnabled) return; this.save(view, { archiveAuto: !arAuto.classList.contains('on') }); });
      arCard.appendChild(setRow('Automatic snapshots', !s.archiveEnabled ? 'Enable preservation first.' : 'Snapshot on start and periodically, so the archive stays current without a manual click.', el('div', { class: 'ctl' }, [arAuto])));
      // Redaction is lossy, so the copy says so plainly rather than selling it.
      const arRedact = switchBtn(s.archiveRedact, 'Toggle archive redaction', { disabled: !s.archiveEnabled });
      arRedact.addEventListener('click', () => { if (!s.archiveEnabled) return; this.save(view, { archiveRedact: !arRedact.classList.contains('on') }); });
      arCard.appendChild(setRow('Redact secrets in the archive',
        !s.archiveEnabled ? 'Enable preservation first.'
          : s.archiveRedact
            ? 'On · detected secrets are replaced with a placeholder before being stored. Safer, but lossy: the original text is not kept anywhere, and your archive may be the last copy. Existing sessions are re-archived redacted on the next snapshot.'
            : 'Off · transcripts are preserved exactly as they were, secrets included. Turn on to keep a safe copy rather than a complete one.',
        el('div', { class: 'ctl' }, [arRedact])));
      panel.appendChild(arCard);
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
        // Mode/ports don't apply live · settings_put persists them but returns the
        // STILL-RUNNING values, so the control would silently snap back. Surface a
        // persistent "restart to apply" note and keep the requested value shown.
        if (updated.restartRequired && updated.restartRequired.length) {
          this._pendingUpdate = Object.assign({}, this._pendingUpdate, update);
          this._restartNote = updated.restartNote
            || ('Saved. Restart Saffev to apply: ' + updated.restartRequired.join(', ') + '.');
        }
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
  // Masthead signal line (dot + mono text) for the About hero's right column.
  function heroSig(text, dim) {
    return el('span', { class: 'hero-sig' + (dim ? ' dim' : '') }, [
      el('span', { class: 'hero-sig-dot' }), document.createTextNode(text),
    ]);
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

  // Map an engine's wire name to a display label, or null when unrecognized /
  // absent (callers fall back to the generic "Ollama or LM Studio" wording).
  function engineDisplayName(name) {
    const n = (name || '').toLowerCase();
    if (n === 'ollama') return 'Ollama';
    if (n === 'lmstudio' || n === 'lm studio') return 'LM Studio';
    return null;
  }

  const About = {
    title: 'About & integrate',
    sub: 'What Saffev is, what it does, and how to point your apps (and AI agents) at it.',
    tab: 'overview',
    version: '', proxyPort: 8088, studioPort: 7100,
    engineName: null, upstreamPort: null,
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
      // Detect the running engine so copy + the flow diagram name the real one
      // (Ollama or LM Studio); fall back to generic wording when unknown.
      try { const ev = await api('/engines'); const e0 = ev.engines && ev.engines[0]; if (e0) { this.engineName = engineDisplayName(e0.engine); this.upstreamPort = e0.publicPort || null; } } catch (e) {}
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
        panel.appendChild(this.frameworkSnippets(proxyUrl));
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
        el('div', { class: 'about-hero-main' }, [
          el('span', { class: 'about-badge', html: ICON.eye + '<span>A glass box for local AI</span>' }),
          el('h2', { class: 'about-h1', text: 'See exactly what your apps send to local models.' }),
          el('p', { class: 'about-lead', text: 'A transparent proxy in front of your local engine (Ollama or LM Studio). Watch traffic live, catch leaked data and failed calls, and confirm nothing leaves the network. Everything stays on this device.' }),
        ]),
        el('div', { class: 'about-hero-side' }, [
          heroSig('On-device only'),
          heroSig('Encrypted at rest'),
          heroSig('No telemetry'),
          version ? heroSig('v' + version, true) : null,
        ]),
      ]);
    },

    features() {
      const grid = el('div', { class: 'feat-grid' }, [
        featureCard(ICON.pulse, 'brand', 'Live traffic', 'A real-time stream of every request your apps make to local models · app, model, endpoint, latency, tokens, and HTTP status (failed calls flagged).'),
        featureCard(ICON.clock, 'gold', 'History', 'Every proxied exchange, searchable and filterable, kept on-device with a retention policy you control.'),
        featureCard(ICON.shieldAlert, 'danger', 'Privacy lens', 'Deterministic detection of PII (email, credit card, API keys, IP, phone) flagged as it flows by.'),
        featureCard(ICON.globe, 'safe', 'Exposure doctor', 'Confirms the engine and Studio are bound to localhost only, not reachable from the network.'),
        featureCard(ICON.eye, 'brand', 'PII masking', 'Optionally redact high-confidence PII from requests and non-streamed responses before it reaches the model or your app. Dry-run first.'),
        featureCard(ICON.server, 'gold', 'Cooperative & Gateway', 'Cooperative: apps point at Saffev (universal, zero-config, Ollama + LM Studio). Gateway: Saffev supervises the engine port (Ollama on Linux).'),
      ]);
      return el('div', { class: 'card reveal', style: 'animation-delay:.06s' }, [
        aboutSection(ICON.sparkles, 'What it does', 'Six things, all local'),
        grid,
      ]);
    },

    howItWorks(proxyPort) {
      // Name the real engine when detected; else stay engine-neutral.
      const engineTitle = this.engineName || 'Your engine';
      const engineDesc = this.upstreamPort
        ? ':' + this.upstreamPort + ' · untouched'
        : 'Ollama :11434 / LM Studio :1234 · untouched';
      const flow = el('div', { class: 'flow' }, [
        el('div', { class: 'flow-node' }, [el('div', { class: 'flow-t', text: 'Your app' }), el('div', { class: 'flow-d', text: 'set base URL → Saffev' })]),
        el('div', { class: 'flow-arrow', html: ICON.chevR }),
        el('div', { class: 'flow-node brandnode' }, [el('div', { class: 'flow-t', text: 'Saffev' }), el('div', { class: 'flow-d', text: ':' + proxyPort + ' · observes + guards' })]),
        el('div', { class: 'flow-arrow', html: ICON.chevR }),
        el('div', { class: 'flow-node' }, [el('div', { class: 'flow-t', text: engineTitle }), el('div', { class: 'flow-d', text: engineDesc })]),
      ]);
      return el('div', { class: 'card reveal', style: 'animation-delay:.09s' }, [
        aboutSection(ICON.plug, 'How it works', 'Cooperative mode · a transparent pass-through'),
        flow,
        el('p', { class: 'about-p', text: 'Your app talks to Saffev instead of the engine directly. Saffev forwards every request unchanged to the real engine and streams the response straight back · recording only metadata on-device (never the raw prompt or response unless you explicitly turn that on).' }),
      ]);
    },

    quickStart(proxyUrl, studioUrl) {
      const card = el('div', { class: 'card reveal', style: 'animation-delay:.12s' }, [
        aboutSection(ICON.download, 'Quick start', 'Install, run, open'),
      ]);
      card.appendChild(el('div', { class: 'step' }, [el('span', { class: 'step-n', text: '1' }), el('div', { class: 'step-b' }, [el('div', { class: 'step-t', text: 'Install (macOS / Linux)' }), copyBlock(INSTALL_CMD, { title: 'terminal' })])]));
      card.appendChild(el('div', { class: 'step' }, [el('span', { class: 'step-n', text: '2' }), el('div', { class: 'step-b' }, [el('div', { class: 'step-t', text: 'Start it (zero-config · picks free ports, never grabs your engine)' }), copyBlock('saffev start', { title: 'terminal' })])]));
      card.appendChild(el('div', { class: 'step' }, [el('span', { class: 'step-n', text: '3' }), el('div', { class: 'step-b' }, [el('div', { class: 'step-t', text: 'Open the Studio' }), el('p', { class: 'about-p', html: 'This dashboard, at <a class="about-link" href="' + esc(studioUrl) + '">' + esc(studioUrl) + '</a>. Run <span class="kv">saffev status</span> anytime to see the exact ports.' })])]));
      return card;
    },

    pointApp(proxyUrl) {
      return el('div', { class: 'card reveal', style: 'animation-delay:.15s' }, [
        aboutSection(ICON.bolt, 'Point an app at Saffev', 'So its traffic shows up here'),
        el('p', { class: 'about-p', text: 'Easiest · wrap the command and Saffev injects the base-URL env vars for you (works for Ollama and LM Studio):' }),
        copyBlock('saffev run -- <your app>', { title: 'terminal · traces any app' }),
        el('p', { class: 'about-p', text: 'Or set your app’s local-LLM base URL to the Saffev proxy yourself. It forwards to your real engine, so nothing else changes. Use an environment variable so it’s easy to revert.' }),
        copyBlock('OLLAMA_BASE_URL=' + proxyUrl, { title: '.env  (Ollama)' }),
        el('p', { class: 'about-p', text: 'If your app uses the OpenAI-compatible API (including LM Studio):' }),
        copyBlock('OPENAI_BASE_URL=' + proxyUrl + '/v1', { title: '.env  (LM Studio / OpenAI-compatible)' }),
      ]);
    },

    frameworkSnippets(proxyUrl) {
      const openai = proxyUrl + '/v1';
      const snip = (title, code) => copyBlock(code, { title });
      return el('div', { class: 'card reveal' }, [
        aboutSection(ICON.sparkles, 'Framework snippets', 'Copy-paste for popular setups'),
        el('p', { class: 'about-p', text: 'Point the base URL at Saffev; it forwards to your real engine unchanged, so nothing else about your app changes.' }),
        el('div', { class: 'snip-grid' }, [
          snip('OpenAI SDK · Python', 'from openai import OpenAI\nclient = OpenAI(base_url="' + openai + '", api_key="local")'),
          snip('OpenAI SDK · Node', 'import OpenAI from "openai";\nconst client = new OpenAI({\n  baseURL: "' + openai + '",\n  apiKey: "local",\n});'),
          snip('Ollama · Python', 'from ollama import Client\nclient = Client(host="' + proxyUrl + '")'),
          snip('LangChain · Python', 'from langchain_openai import ChatOpenAI\nllm = ChatOpenAI(base_url="' + openai + '", api_key="local")'),
          snip('LlamaIndex · Python', 'from llama_index.llms.openai_like import OpenAILike\nllm = OpenAILike(api_base="' + openai + '", api_key="local")'),
          snip('curl', 'curl ' + proxyUrl + '/api/generate \\\n  -d \'{"model":"llama3.2","prompt":"hello"}\''),
        ]),
      ]);
    },

    agentPrompt(proxyUrl, studioUrl) {
      const prompt =
'You are integrating an existing app with "Saffev" · a local, on-device AI observability\n' +
'& safety proxy that sits in front of a local LLM engine (Ollama or LM Studio). Saffev\n' +
'runs in "cooperative" mode: it listens on a local proxy port and transparently forwards\n' +
'every request to the real engine, recording only metadata on-device (no raw prompt/\n' +
'response unless the user opts in). It is a pure pass-through: request/response shapes,\n' +
'headers, model names, and streaming are unchanged.\n' +
'\n' +
'GOAL\n' +
'Make THIS app send its local-LLM traffic THROUGH Saffev’s proxy instead of talking to\n' +
'the engine directly, without changing any app behavior.\n' +
'\n' +
'CONTEXT\n' +
'- Saffev proxy URL: ' + proxyUrl + '   (forwards to your real engine · Ollama on\n' +
'  :11434 or LM Studio on :1234)\n' +
'- Saffev Studio (dashboard): ' + studioUrl + '\n' +
'- The exact proxy URL is also printed by:  saffev status\n' +
'\n' +
'STEPS\n' +
'1. Find where this app configures its model endpoint. Look for:\n' +
'   - env vars: OLLAMA_HOST, OLLAMA_BASE_URL, OPENAI_BASE_URL, OPENAI_API_BASE\n' +
'   - hardcoded URLs containing :11434 or :1234 (localhost / 127.0.0.1)\n' +
'   - SDK clients (ollama, openai, langchain, llamaindex, …) set with a base URL\n' +
'2. Repoint the base URL at the Saffev proxy. Prefer an env var so it is reversible:\n' +
'       OLLAMA_BASE_URL=' + proxyUrl + '            (Ollama-style clients)\n' +
'       OPENAI_BASE_URL=' + proxyUrl + '/v1         (OpenAI-compatible clients / LM Studio)\n' +
'   If the URL is hardcoded, replace ONLY the origin (host:port) with ' + proxyUrl + ';\n' +
'   keep the path (e.g. /api/chat, /v1/chat/completions) exactly as-is.\n' +
'   Tip: `saffev run -- <your start command>` injects these env vars for you · no edits.\n' +
'3. Do NOT change request bodies, headers, model names, or streaming behavior.\n' +
'4. Restart the app.\n' +
'\n' +
'VERIFY\n' +
'- Open ' + studioUrl + ', go to "Live", and trigger an action that calls the model.\n' +
'- A new row should appear in the Traffic stream. If it does, the integration works.\n' +
'\n' +
'RULES\n' +
'- Only use the PROXY port (from ' + proxyUrl + '); never point the app at the Studio port.\n' +
'- Keep a one-line way to revert (point the base URL back at the engine · e.g.\n' +
'  http://localhost:11434 for Ollama, http://localhost:1234 for LM Studio).\n' +
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
  function deltaNode(cur, prev, goodUp) {
    if (prev == null || prev === 0) return el('div', { class: 'meta', text: cur > 0 ? 'new this period' : '·' });
    const pct = Math.round(((cur - prev) / prev) * 100);
    if (pct === 0) return el('div', { class: 'meta', text: 'no change vs prev' });
    const up = pct > 0;
    return el('div', { class: 'delta ' + (up === goodUp ? 'up' : 'down'), text: (up ? '▲ ' : '▼ ') + Math.abs(pct) + '% vs prev' });
  }
  const actionLabel = (a) => ({ observed: 'Observed', would_mask: 'Would mask (dry-run)', masked: 'Masked' }[a] || a);
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
    sub: 'Granular, on-device insight into your local-AI traffic · nothing leaves this device.',
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
      { k: 'quality', l: 'Quality' },
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
      if (!panel) return;
      panel.innerHTML = '';
      // Privacy + Quality are folded in as tabs; they own their own data + empty
      // states (fetched from /privacy and /quality), so they render directly and
      // bypass the analytics-window empty guard below.
      if (this.tab === 'privacy') { Privacy.render(panel, this); return; }
      if (this.tab === 'quality') { Quality.draw(panel, this.rangeMs); return; }
      if (!this.data) return;
      const d = this.data;
      if (d.totalRequests === 0 && this.tab !== 'overview') {
        panel.appendChild(emptyState('No traffic in this window', 'Try a longer window, or point an app at the proxy (see About & integrate).'));
        return;
      }
      ({ overview: this.overview, usage: this.usage, performance: this.performance, explorer: this.explorer }[this.tab] || this.overview).call(this, panel, d);
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
      // One balanced metric band (design's "metric cells"), even at 5 cells —
      // no orphan card. mono label · big tabular number · delta · sparkline.
      const kpis = statStrip(5, [
        statCell('Requests', fmtNum(d.totalRequests), deltaNode(d.totalRequests, d.prevTotalRequests, true), C.sparkline(d.series.map((b) => b.requests))),
        statCell('Tokens', fmtNum(d.totalInputTokens + d.totalOutputTokens), tokenProvenance(d), C.sparkline(d.series.map((b) => b.inputTokens + b.outputTokens), { color: 'var(--gold)' })),
        statCell('Latency p50', d.p50LatencyMs != null ? d.p50LatencyMs + '<small>ms</small>' : '·', deltaNode(d.p50LatencyMs, d.prevP50LatencyMs, false), C.sparkline(d.series.map((b) => b.p50LatencyMs || 0))),
        statCell('PII findings', fmtNum(d.piiFindings), deltaNode(d.piiFindings, d.prevPiiFindings, false), C.sparkline(d.series.map((b) => b.pii), { color: 'var(--danger)' })),
        statCell('Failed', fmtNum(d.failedRequests || 0), deltaNode(d.failedRequests, d.prevFailedRequests, false), C.sparkline(d.series.map((b) => b.failed || 0), { color: 'var(--danger)' })),
      ]);
      panel.appendChild(kpis);
      const cost = el('div', { class: 'card reveal an-cost' }, [
        el('div', { class: 'label' }, [el('span', { class: 'ic safe', html: ICON.sparkles }), document.createTextNode(' Cloud cost avoided')]),
        el('div', { class: 'an-cost-val', text: '$' + (d.estCostSavedUsd || 0).toFixed(2) }),
        el('div', { class: 'meta', text: d.costBasis + ' · ' + fmtNum(d.totalInputTokens + d.totalOutputTokens) + ' tokens on-device' }),
      ]);
      const activity = anCard('Activity', 'requests over time', C.lineArea({ series: [{ name: 'Requests', values: d.series.map((b) => b.requests), color: 'var(--brand)' }], xLabels: xl }));
      panel.appendChild(el('section', { class: 'an-grid' }, [activity, cost]));
      // Failures over time · only worth a chart when there are any.
      if ((d.failedRequests || 0) > 0) {
        panel.appendChild(anCard('Failures over time', 'errors + HTTP ≥ 400', C.lineArea({ series: [{ name: 'Failed', values: d.series.map((b) => b.failed || 0), color: 'var(--danger)' }], xLabels: xl }), true));
      }
      panel.appendChild(this.insightsCard(d));
      // Coverage footer: what this window actually spans.
      panel.appendChild(el('div', { class: 'an-asof', text: fmtNum(d.activeApps) + ' apps · ' + fmtNum(d.activeModels) + ' models · as of ' + new Date(d.generatedTs).toLocaleString() }));
    },

    insightsCard(d) {
      const list = el('div', { class: 'insights' });
      if (!d.insights || !d.insights.length) list.appendChild(el('div', { class: 'state sm', style: 'padding:18px', text: 'No notable patterns yet · keep using local models and insights will appear.' }));
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
      const ms = (v) => (v != null ? v + '<small>ms</small>' : '·');
      panel.appendChild(statStrip(4, [
        statCell('p50 latency', ms(d.p50LatencyMs), 'median'),
        statCell('p90 latency', ms(d.p90LatencyMs), '90th percentile'),
        statCell('p99 latency', ms(d.p99LatencyMs), '99th percentile'),
        statCell('avg TTFT', ms(d.avgTtftMs), 'time to first token'),
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

    explorer(panel, d) {
      panel.appendChild(el('div', { class: 'an-export reveal' }, [
        el('span', { class: 'muted', style: 'font-size:.86rem', text: 'Export the full report for this window:' }),
        el('div', { class: 'spacer' }),
        el('button', { class: 'btn auto', html: ICON.download + '<span>JSON</span>', onclick: () => downloadFile('saffev-analytics.json', JSON.stringify(d, null, 2), 'application/json') }),
        el('button', { class: 'btn auto', html: ICON.download + '<span>CSV (models)</span>', onclick: () => downloadFile('saffev-models.csv', this.csv(['Model', 'Requests', 'Input tokens', 'Output tokens', 'p50 ms', 'TTFT ms', 'tok/s'], d.byModel.map((m) => [m.name, m.requests, m.inputTokens, m.outputTokens, m.p50LatencyMs, m.avgTtftMs, m.tokensPerSec])), 'text/csv') }),
        el('button', { class: 'btn auto', html: ICON.download + '<span>CSV (apps)</span>', onclick: () => downloadFile('saffev-apps.csv', this.csv(['App', 'Requests', 'Input tokens', 'Output tokens', 'avg ms', 'PII'], d.byApp.map((a) => [a.name, a.requests, a.inputTokens, a.outputTokens, a.avgLatencyMs, a.pii])), 'text/csv') }),
      ]));
      const grid = el('section', { class: 'an-grid' });
      grid.appendChild(anCard('Models', 'full breakdown', dataTable(['Model', 'Requests', 'Input', 'Output', 'p50', 'TTFT', 'tok/s'], d.byModel.map((m) => [m.name, fmtNum(m.requests), fmtNum(m.inputTokens), fmtNum(m.outputTokens), m.p50LatencyMs != null ? m.p50LatencyMs + 'ms' : '·', m.avgTtftMs != null ? m.avgTtftMs + 'ms' : '·', m.tokensPerSec != null ? m.tokensPerSec.toFixed(0) : '·'])), true));
      grid.appendChild(anCard('Apps', 'full breakdown', dataTable(['App', 'Requests', 'Input', 'Output', 'avg latency', 'PII'], d.byApp.map((a) => [a.name, fmtNum(a.requests), fmtNum(a.inputTokens), fmtNum(a.outputTokens), a.avgLatencyMs != null ? a.avgLatencyMs + 'ms' : '·', fmtNum(a.pii)])), true));
      grid.appendChild(anCard('Endpoints', 'full breakdown', dataTable(['Endpoint', 'Requests', 'Input', 'Output', 'avg latency', 'PII'], d.byEndpoint.map((e) => [e.name, fmtNum(e.requests), fmtNum(e.inputTokens), fmtNum(e.outputTokens), e.avgLatencyMs != null ? e.avgLatencyMs + 'ms' : '·', fmtNum(e.pii)])), true));
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
    return exp.exposed ? 'Reachable beyond this device · review binding' : 'Bound to localhost · safe';
  }
  function setEnginePill(ev) {
    const txt = $('#enginePillText');
    const pill = $('#enginePill');
    if (!txt || !pill) return;
    const engines = ev.engines || [];
    // The header pill reflects the ACTIVE (proxied) engine, not just the first.
    const eng = engines.find((e) => e.isActive) || engines[0];
    if (!eng) { txt.textContent = 'no engine'; pill.className = 'pill mutedpill'; return; }
    const h = eng.health;
    pill.className = 'pill ' + (h === 'healthy' ? '' : h === 'starting' ? 'warnpill' : 'dangerpill');
    txt.textContent = (engineDisplayName(eng.engine) || eng.engine) + ' · ' + eng.adoptionState;
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
  // Human label for a safety category.
  function safetyLabel(cat) {
    return ({
      self_harm: 'Self-harm', violence: 'Violence', weapons: 'Weapons',
      illicit: 'Illicit drugs', financial_crime: 'Financial crime',
      malware: 'Malware / hacking', harassment: 'Harassment', csae: 'CSAE',
    })[cat] || cat.replace(/_/g, ' ');
  }

  /* =========================================================================
     PAGE: QUALITY & SAFETY  (eval pipeline)
     ========================================================================= */
  // Rendered as the Analytics "Quality" tab (never routed directly — bare
  // #/quality redirects there); the window comes from the Analytics range
  // dropdown via draw()'s `rangeMs`.
  const Quality = {
    rangeMs: 24 * 60 * 60 * 1000,
    async draw(container, rangeMs) {
      const body = container;
      const range = rangeMs || this.rangeMs;
      if (!body) return;
      body.innerHTML = '';
      body.appendChild(loadingState('Loading evaluations…'));
      let d;
      try { d = await api('/quality?rangeMs=' + range); hideBanner(); }
      catch (e) { handleApiError(e); body.innerHTML = ''; body.appendChild(emptyState('Could not load quality data', e.message || '')); return; }
      body.innerHTML = '';

      if (!d.evalEnabled) {
        body.appendChild(el('div', { class: 'card reveal' }, [
          aboutSection(ICON.shieldAlert, 'Evaluation is off', 'Turn it on to score traffic for safety'),
          el('p', { class: 'about-p', text: 'The eval pipeline scores sampled exchanges for safety (and, optionally, quality) · asynchronously and on-device, never blocking your model. It is off by default.' }),
          el('a', { class: 'btn primary', href: '#/settings/privacy/evaluation', html: ICON.check + '<span>Enable in Settings</span>' }),
        ]));
        return;
      }

      const C = window.SaffevCharts;
      const coverage = d.requestsInWindow > 0 ? Math.round((d.judgedInWindow / d.requestsInWindow) * 100) : 0;
      const kpis = statStrip(4, [
        statCell('Flagged', fmtNum(d.totalFlagged), 'safety guard', C.sparkline(d.series.map((b) => b.flagged), { color: 'var(--danger)' })),
        statCell('Judged', fmtNum(d.judgedInWindow), coverage + '% of ' + fmtNum(d.requestsInWindow) + ' requests', C.sparkline(d.series.map((b) => b.good + b.weak), { color: 'var(--brand)' })),
        statCell('Quality judge', d.qualityEnabled ? 'On' : 'Off', 'sampling ' + Math.round((d.sampleRate || 0) * 100) + '%'),
        statCell('Judge load', fmtNum(d.judgeInflight), 'in-flight · ' + fmtNum(d.judgeDropped) + ' shed'),
      ]);
      body.appendChild(kpis);

      // Safety flags over time · only meaningful once there are flags.
      const xl = d.series.map((b) => new Date(b.ts));
      if (d.totalFlagged > 0) {
        body.appendChild(el('div', { class: 'card reveal', style: 'animation-delay:.06s' }, [
          el('div', { class: 'hrow' }, [el('h3', { text: 'Safety flags over time' }), el('div', { class: 'spacer' }), el('span', { class: 'tag', text: 'safety' })]),
          C.lineArea({ series: [{ name: 'Flagged', values: d.series.map((b) => b.flagged), color: 'var(--danger)' }], xLabels: xl }),
        ]));
      }
      // Quality good/weak over time · only once the judge has scored anything.
      if (d.totalJudged > 0) {
        body.appendChild(el('div', { class: 'card reveal', style: 'animation-delay:.08s' }, [
          el('div', { class: 'hrow' }, [el('h3', { text: 'Quality over time' }), el('div', { class: 'spacer' }), el('span', { class: 'tag', text: 'judge' })]),
          C.lineArea({ series: [
            { name: 'Good', values: d.series.map((b) => b.good), color: 'var(--safe)' },
            { name: 'Weak', values: d.series.map((b) => b.weak), color: 'var(--gold)' },
          ], xLabels: xl }),
        ]));
      }

      const catCard = el('div', { class: 'card reveal', style: 'animation-delay:.1s' }, [
        el('div', { class: 'hrow' }, [el('h3', { text: 'Flagged by category' }), el('div', { class: 'spacer' }), el('span', { class: 'tag', text: 'safety' })]),
      ]);
      if (!d.byCategory || !d.byCategory.length) catCard.appendChild(el('div', { class: 'expnote', html: ICON.check + ' No safety flags in this window.' }));
      else catCard.appendChild(C.hbars({ items: d.byCategory.map((c) => ({ label: safetyLabel(c.name), value: c.count, suffix: ' flag', color: 'var(--danger)' })) }));
      body.appendChild(catCard);

      if (d.evalByMetric && d.evalByMetric.length) {
        const qCard = el('div', { class: 'card reveal', style: 'animation-delay:.12s' }, [
          el('div', { class: 'hrow' }, [el('h3', { text: 'Quality by metric' }), el('div', { class: 'spacer' }), el('span', { class: 'tag', text: 'judge' })]),
        ]);
        d.evalByMetric.forEach((m) => {
          const total = (m.good || 0) + (m.weak || 0);
          const pct = total ? Math.round((m.good / total) * 100) : 0;
          qCard.appendChild(el('div', { class: 'pii-row' }, [
            el('div', { class: 'swt ic safe', html: ICON.check }),
            el('div', {}, [el('div', { class: 'nm', text: m.metric.charAt(0).toUpperCase() + m.metric.slice(1) }), el('div', { class: 'cf', text: fmtNum(m.good) + ' good · ' + fmtNum(m.weak) + ' weak' })]),
            el('div', { class: 'ct', text: pct + '%' }),
          ]));
        });
        body.appendChild(qCard);
      }

      const listCard = el('div', { class: 'card reveal', style: 'animation-delay:.14s' }, [
        el('div', { class: 'hrow' }, [el('h3', { text: 'Recent flagged exchanges' }), el('div', { class: 'spacer' })]),
      ]);
      if (!d.recentFlagged || !d.recentFlagged.length) {
        listCard.appendChild(el('div', { class: 'state sm', style: 'padding:18px', text: 'None flagged yet.' }));
      } else {
        const tbl = el('div', { class: 'ttable', style: '--gtc:' + gtcFor(HIST_COLS) }, [reqHead(HIST_COLS), el('div', { class: 'list' })]);
        const listBody = tbl.querySelector('.list');
        d.recentFlagged.forEach((it) => listBody.appendChild(reqRow(it, { columns: HIST_COLS })));
        listCard.appendChild(tbl);
      }
      body.appendChild(listCard);
    },
    teardown() {},
  };

  /* =========================================================================
     PAGE: AGENTS — read AI coding tools' local session history on-device
     ========================================================================= */
  const AGENT_ICON = {
    claude_code: ICON.pulse, codex: ICON.bolt, opencode: ICON.server, cursor: ICON.eye,
    vscode: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m8 9-3 3 3 3M16 9l3 3-3 3M13 7l-2 10"/></svg>',
    gemini: ICON.sparkles, copilot: ICON.terminal, cline: ICON.bolt, aider: ICON.terminal, goose: ICON.ollama,
  };
  function toolBadge(tool, label) {
    return el('span', { class: 'toolbadge tb-' + tool, text: label });
  }
  const AGENT_COLS = [
    { label: 'Source', w: '.6fr' },
    { label: 'Session', w: '2.2fr' },
    { label: 'Model', w: '1fr' },
    { label: 'Msgs', w: '.5fr', r: true },
    { label: 'Tokens', w: '.75fr', r: true },
    { label: 'Cost', w: '.6fr', r: true },
    { label: 'Updated', w: '.8fr', r: true },
  ];
  /* Render one search excerpt. The store wraps matched terms in ‹ › rather than
     markup, so the transcript stays plain text all the way here and we build the
     highlight as DOM nodes. Never use innerHTML on this: it is verbatim content
     from the user's own transcripts. */
  function snippetLine(snip) {
    const line = el('span', { class: 'snip' });
    let rest = String(snip);
    let guard = 0;
    while (rest.length && guard++ < 64) {
      const open = rest.indexOf('‹');
      if (open < 0) break;
      const close = rest.indexOf('›', open + 1);
      if (close < 0) break;
      if (open > 0) line.appendChild(document.createTextNode(rest.slice(0, open)));
      line.appendChild(el('mark', { text: rest.slice(open + 1, close) }));
      rest = rest.slice(close + 1);
    }
    if (rest.length) line.appendChild(document.createTextNode(rest));
    return line;
  }

  function agentGtc() { return AGENT_COLS.map((c) => c.w).join(' '); }
  function agentHead() {
    const head = el('div', { class: 'thead' });
    AGENT_COLS.forEach((c) => head.appendChild(el('div', { class: 'th' + (c.r ? ' r' : ''), text: c.label })));
    return head;
  }

  const Agents = {
    title: 'Agents',
    sub: 'Own your AI history. Read on-device, see what each tool is about to delete, and keep a durable copy that is yours.',
    q: '', tool: '',
    tab: 'sessions',
    rangeMs: 0,
    TABS: [{ k: 'sessions', l: 'Sessions' }, { k: 'privacy', l: 'Privacy' }, { k: 'usage', l: 'Usage' }],
    RANGES: [
      { value: 0, label: 'All time' },
      { value: 7 * 86400000, label: 'Last 7 days' },
      { value: 30 * 86400000, label: 'Last 30 days' },
      { value: 90 * 86400000, label: 'Last 90 days' },
    ],
    _tools: [],

    async render(view) {
      this.q = ''; this.tool = '';
      view.innerHTML = '';
      view.appendChild(loadingState('Reading coding-agent history…'));
      let ov;
      try { ov = await api('/agents'); hideBanner(); }
      catch (e) { handleApiError(e); view.innerHTML = ''; view.appendChild(emptyState('Could not read agent history', e.message || '')); return; }
      view.innerHTML = '';
      this._tools = ov.tools;
      this._analysis = ov.analysis || { available: false, enabled: false };
      this._atRisk = ov.atRisk || [];
      this._archive = ov.archive || { enabled: false, count: 0, bytes: 0 };

      // Overview metric strip.
      view.appendChild(statStrip(4, [
        statCell('Sessions', fmtNum(ov.totalSessions), 'across all tools'),
        statCell('Preserved', fmtNum(this._archive.count), this._archive.enabled ? fmtBytes(this._archive.bytes) : 'archive off'),
        statCell('Est. cost', '$' + (ov.totalCostUsd || 0).toFixed(2), 'vs cloud pricing'),
        statCell('Tools', String(ov.tools.filter((t) => t.present).length), 'detected on-device'),
      ]));

      // Preservation banner — the wedge: surface at-risk history + archive state.
      view.appendChild(this.preserveBanner());

      // Per-tool source cards.
      const present = ov.tools.filter((t) => t.present);
      if (!present.length) {
        view.appendChild(el('div', { class: 'card reveal' }, [
          aboutSection(ICON.eye, 'No coding agents detected', 'Nothing to read yet'),
          el('p', { class: 'about-p', text: 'Saffev reads local session history from Claude Code, Codex, OpenCode, and Cursor — on-device, nothing leaves the machine. None were found in their usual locations.' }),
        ]));
        return;
      }
      view.appendChild(this.toolTable(present));

      // Sessions / Privacy / Usage share this page: they are three questions
      // about the same history, not three different places.
      this._present = present;
      const tabs = el('div', { class: 'tabbar', role: 'tablist', 'aria-label': 'Agents sections' });
      this.TABS.forEach((t) => {
        const b = el('button', { class: 'tab' + (this.tab === t.k ? ' active' : ''), type: 'button', role: 'tab', 'data-k': t.k, text: t.l });
        b.addEventListener('click', () => { if (this.tab !== t.k) { this.tab = t.k; this.renderTab(); } });
        tabs.appendChild(b);
      });
      view.appendChild(el('div', { class: 'an-head reveal' }, [tabs]));
      view.appendChild(el('div', { class: 'an-panel', id: 'agentPanel' }));
      await this.renderTab();
    },

    async renderTab() {
      $$('.an-head .tab').forEach((b) => b.classList.toggle('active', b.dataset.k === this.tab));
      const panel = $('#agentPanel');
      if (!panel) return;
      panel.innerHTML = '';
      if (this.tab === 'privacy') return this.privacyTab(panel);
      if (this.tab === 'usage') return this.usageTab(panel);
      return this.sessionsTab(panel);
    },

    async sessionsTab(panel) {
      // Filter bar: search + source (tool) facet.
      const MAG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="10.5" cy="10.5" r="6.5"/><path d="M15.5 15.5 21 21"/></svg>';
      const search = el('input', { class: 'sf-input', type: 'search', placeholder: 'Search inside conversations, titles, projects…', value: this.q });
      let t; search.addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => { this.q = search.value.trim(); this.reloadSessions(); }, 250); });
      const scopes = [{ value: '', label: 'All sources' }].concat((this._present || []).map((t) => ({ value: t.tool, label: t.label })));
      const seg = dropdown(scopes, this.tool, (v) => { if (this.tool === v) return; this.tool = v; this.reloadSessions(); }, { ariaLabel: 'Filter by source' });
      panel.appendChild(el('div', { class: 'filterbar reveal' }, [
        el('div', { class: 'searchfield' }, [el('span', { class: 'sf-ic', html: MAG }), search]),
        seg,
      ]));
      // Say plainly how far search reaches. Searching what was SAID needs a
      // preserved copy; titles and projects are always searchable.
      panel.appendChild(el('div', { class: 'searchnote reveal', text: this._archive.enabled && this._archive.count
        ? 'Searching inside ' + fmtNum(this._archive.count) + ' preserved conversations · titles and projects across all sources.'
        : 'Searching titles and projects only. Turn on Preservation to search what was actually said.' }));

      // Session list.
      panel.appendChild(el('div', { class: 'card reveal', style: 'animation-delay:.06s' }, [
        el('div', { class: 'ttable', style: '--gtc:' + agentGtc() }, [
          agentHead(),
          el('div', { class: 'list', id: 'agentList' }),
        ]),
      ]));
      await this.reloadSessions();
    },

    /* The screenshot screen: what have I been pasting into AI tools?
       Deliberately leads with the kinds worth trusting (API keys, cards, emails)
       and shows the pattern-only kinds separately, clearly marked. Inflating the
       headline with thousands of maybe-IP-addresses would train people to ignore
       the whole report. */
    async privacyTab(panel) {
      panel.appendChild(loadingState('Scanning preserved conversations…'));
      let d;
      try { d = await api('/agents/privacy?rangeMs=' + this.rangeMs); hideBanner(); }
      catch (e) { handleApiError(e); panel.innerHTML = ''; panel.appendChild(emptyState('Could not build the privacy report', e.message || '')); return; }
      panel.innerHTML = '';

      if (!d.coverage.archiveEnabled) {
        panel.appendChild(emptyState(
          'Preservation is off',
          'The privacy report reads your preserved copy, so there is nothing to scan yet. Turn on Preservation to see what you have been sharing with AI tools.'
        ));
        return;
      }

      const range = dropdown(this.RANGES, this.rangeMs, (v) => { this.rangeMs = parseInt(v, 10); this.renderTab(); }, { ariaLabel: 'Time range', align: 'right' });
      panel.appendChild(el('div', { class: 'an-head reveal' }, [
        el('div', { class: 'spacer' }), el('span', { class: 'an-range-lbl', text: 'Window' }), range,
      ]));

      panel.appendChild(statStrip(4, [
        statCell('You shared', fmtNum(d.highSignalUserSide), 'secrets you pasted in'),
        statCell('Found total', fmtNum(d.highSignalFindings), 'incl. model replies'),
        statCell('Sessions affected', fmtNum(d.sessionsWithFindings), 'of ' + fmtNum(d.coverage.preserved) + ' preserved'),
        statCell('Low confidence', fmtNum(d.totalFindings - d.highSignalFindings), 'pattern-only matches'),
      ]));

      // Honest framing sits directly under the numbers, not in a footnote.
      panel.appendChild(el('div', { class: 'searchnote reveal', text:
        'Scanned ' + fmtNum(d.coverage.preserved) + ' of ' + fmtNum(d.coverage.total) + ' sessions on this machine. '
        + 'Counts and kinds only, never the secret itself.' }));

      if (!d.totalFindings) {
        panel.appendChild(emptyState('Nothing found', 'No personal data or credentials were detected in your preserved conversations for this window.'));
        return;
      }

      // Reuses the shared breakdown card, with one addition: a kind that
      // over-matches on code is marked inline so the bar length never reads as
      // "you leaked this many secrets".
      const kindCard = breakdownCard('What was found', d.byKind);
      d.byKind.slice(0, 8).forEach((k, i) => {
        if (!k.noisy) return;
        const nm = kindCard.querySelectorAll('.bk .nm')[i];
        if (nm) nm.appendChild(el('span', { class: 'hitbadge', style: 'margin-left:8px', title: 'Pattern-only match. Version numbers, ports and ids in source code often look like these.', text: 'low conf' }));
      });
      panel.appendChild(el('section', { class: 'body', style: 'margin-top:0' }, [
        kindCard,
        breakdownCard('Which tool', d.byTool),
      ]));
      panel.appendChild(el('div', { style: 'margin-top:16px' }, [breakdownCard('Which project', d.byProject)]));

      // Drill-down: the sessions to actually go and look at.
      const COLS = [
        { label: 'Source', w: 'minmax(120px,1fr)' },
        { label: 'Session', w: 'minmax(220px,2.4fr)' },
        { label: 'Kinds', w: 'minmax(180px,1.6fr)' },
        { label: 'You shared', w: 'minmax(90px,.8fr)', r: true },
        { label: 'Total', w: 'minmax(70px,.6fr)', r: true },
      ];
      const head = el('div', { class: 'thead' }, COLS.map((c) => el('div', { class: 'th' + (c.r ? ' r' : ''), text: c.label })));
      const list = el('div', { class: 'list' });
      d.topSessions.forEach((s) => {
        const row = el('div', { class: 'trow', tabindex: '0' }, [
          el('div', { class: 'tcell' }, [toolBadge(s.tool, s.label)]),
          el('div', { class: 'tcell' }, [el('span', { class: 'nm', title: s.project || '', text: s.title || 'Untitled session' })]),
          el('div', { class: 'tcell' }, [el('span', { class: 'cell-model', text: s.kinds.join(' · ') || '·' })]),
          el('div', { class: 'tcell r num', text: fmtNum(s.userSide) }),
          el('div', { class: 'tcell r num', text: fmtNum(s.findings) }),
        ]);
        row.addEventListener('click', () => this.openDetail(s.sessionId));
        row.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); this.openDetail(s.sessionId); } });
        list.appendChild(row);
      });
      panel.appendChild(el('div', { class: 'card reveal', style: 'padding:0;overflow:hidden' }, [
        el('div', { class: 'ttable', style: '--gtc:' + COLS.map((c) => c.w).join(' ') }, [head, list]),
      ]));
    },

    /* Usage across coding agents. The data behind this was already computed and
       served by the API; it simply had no screen until now. */
    async usageTab(panel) {
      panel.appendChild(loadingState('Adding up usage…'));
      let d;
      try { d = await api('/agents/analytics'); hideBanner(); }
      catch (e) { handleApiError(e); panel.innerHTML = ''; panel.appendChild(emptyState('Could not load usage', e.message || '')); return; }
      panel.innerHTML = '';

      panel.appendChild(statStrip(4, [
        statCell('Sessions', fmtNum(d.totalSessions), 'across all tools'),
        statCell('Tokens', fmtNum(d.totalTokens), 'in + out'),
        statCell('Tool calls', fmtNum(d.totalToolCalls), 'actions taken'),
        statCell('Est. cost', '$' + (d.totalCostUsd || 0).toFixed(2), 'at list prices'),
      ]));
      panel.appendChild(el('div', { class: 'searchnote reveal', text:
        'Cost is an estimate from public list prices for the model each session reported. Locally-run models cost nothing and are counted as $0.' }));

      const table = (title, rows, nameOf) => {
        const COLS = [
          { label: title, w: 'minmax(180px,2fr)' },
          { label: 'Sessions', w: 'minmax(80px,.7fr)', r: true },
          { label: 'Tokens', w: 'minmax(100px,1fr)', r: true },
          { label: 'Est. cost', w: 'minmax(90px,.8fr)', r: true },
        ];
        const head = el('div', { class: 'thead' }, COLS.map((c) => el('div', { class: 'th' + (c.r ? ' r' : ''), text: c.label })));
        const list = el('div', { class: 'list' });
        rows.forEach((r) => list.appendChild(el('div', { class: 'trow static' }, [
          el('div', { class: 'tcell' }, [nameOf(r)]),
          el('div', { class: 'tcell r num', text: fmtNum(r.sessions) }),
          el('div', { class: 'tcell r num', text: fmtNum(r.tokens) }),
          el('div', { class: 'tcell r num', text: r.costUsd > 0 ? '$' + r.costUsd.toFixed(2) : '·' }),
        ])));
        return el('div', { class: 'card reveal', style: 'padding:0;overflow:hidden;margin-bottom:16px' }, [
          el('div', { class: 'ttable', style: '--gtc:' + COLS.map((c) => c.w).join(' ') }, [head, list]),
        ]);
      };

      panel.appendChild(table('By tool', d.byTool.filter((t) => t.present), (r) => toolBadge(r.tool, r.label)));
      panel.appendChild(table('By model', d.byModel.slice(0, 20), (r) => el('span', { class: 'cell-model', text: r.model })));
    },

    // Per-tool overview as a compact table (one row per tool) — scales cleanly to
    // any number of tools and keeps the big token/cost numbers aligned.
    toolTable(present) {
      const COLS = [
        { label: 'Source', w: 'minmax(150px,1.5fr)' },
        { label: 'Sessions', w: 'minmax(72px,.7fr)', r: true },
        { label: 'Retention', w: 'minmax(130px,1.2fr)' },
        { label: 'Tokens', w: 'minmax(96px,1fr)', r: true },
        { label: 'Est. cost', w: 'minmax(84px,.8fr)', r: true },
      ];
      const head = el('div', { class: 'thead' }, COLS.map((c) => el('div', { class: 'th' + (c.r ? ' r' : ''), text: c.label })));
      const list = el('div', { class: 'list' });
      present.forEach((t) => {
        const risk = (this._atRisk || []).find((r) => r.tool === t.tool);
        let retText = '', retWarn = false, retTitle = '';
        if (risk) {
          retTitle = risk.note;
          const atrisk = (risk.overdue || 0) + (risk.expiringSoon || 0);
          if (risk.kind === 'age_days' && atrisk > 0) { retWarn = true; retText = atrisk + ' at risk · ' + risk.days + 'd'; }
          else if (risk.kind === 'age_days') retText = 'deletes after ' + risk.days + 'd';
          else if (risk.kind === 'keeps_all') retText = 'no auto-delete';
          else if (risk.kind === 'churn') retText = 'rotates old chats';
        }
        const row = el('div', { class: 'trow static' }, [
          el('div', { class: 'tcell' }, [el('span', { class: 'tt-src' }, [
            el('span', { class: 'tt-ic tb-' + t.tool, html: AGENT_ICON[t.tool] || ICON.server }),
            el('span', { class: 'tt-nm', text: t.label }),
          ])]),
          el('div', { class: 'tcell r num', text: fmtNum(t.sessions) }),
          el('div', { class: 'tcell' }, [
            retText
              ? el('span', { class: 'retline' + (retWarn ? ' warn' : ''), title: retTitle }, [el('span', { class: 'retdot' }), document.createTextNode(retText)])
              : el('span', { class: 'cell-dim', text: '·' }),
          ]),
          el('div', { class: 'tcell r num', text: fmtNum(t.tokens) }),
          el('div', { class: 'tcell r num', text: '$' + (t.costUsd || 0).toFixed(2) }),
        ]);
        list.appendChild(row);
      });
      return el('div', { class: 'card reveal tooltbl', style: 'margin-bottom:16px;padding:0;overflow:hidden' }, [
        el('div', { class: 'ttable', style: '--gtc:' + COLS.map((c) => c.w).join(' ') }, [head, list]),
      ]);
    },

    // The wedge: make invisible data loss visible + offer to preserve it.
    preserveBanner() {
      const risks = this._atRisk || [];
      const arch = this._archive || {};
      const overdue = risks.reduce((a, r) => a + (r.overdue || 0), 0);
      const soon = risks.reduce((a, r) => a + (r.expiringSoon || 0), 0);
      const atrisk = overdue + soon;
      const wrap = el('div', { class: 'card reveal preserve' + (atrisk > 0 && !arch.enabled ? ' preserve-warn' : '') });
      wrap.appendChild(el('div', { class: 'preserve-left' }, [
        el('span', { class: 'preserve-ic', html: ICON.shield || ICON.eye }),
        el('div', { class: 'preserve-text' }, [
          el('span', { class: 'preserve-title', text: 'Preservation' }),
          el('span', { class: 'preserve-sub', text: this.preserveMsg(atrisk, overdue, soon, arch) }),
        ]),
      ]));
      const actions = el('div', { class: 'preserve-actions' });
      if (arch.enabled) {
        // Integrity status as a compact chip so the banner stays one line —
        // the full sentence (and head digest) lives in the tooltip.
        actions.appendChild(el('span', { class: 'integrity-chip', id: 'integrityLine', text: 'verifying…', title: 'Checking the archive integrity chain…' }));
        const btn = el('button', { class: 'btn sm brand', type: 'button', id: 'archiveNowBtn', text: 'Archive now' });
        btn.addEventListener('click', () => this.archiveNow(btn));
        actions.appendChild(btn);
      } else {
        actions.appendChild(el('a', { class: 'btn sm brand', href: '#/settings/privacy/preservation', text: 'Turn on Preservation' }));
      }
      const exp = el('button', { class: 'btn ghost sm', type: 'button', text: 'Export all' });
      exp.addEventListener('click', () => this.exportAll(exp));
      actions.appendChild(exp);
      if (arch.enabled) {
        const aud = el('button', { class: 'btn ghost sm', type: 'button', title: 'Write a folder containing the transcripts, the integrity chain, and how to check it', text: 'Audit bundle' });
        aud.addEventListener('click', () => this.auditBundle(aud));
        actions.appendChild(aud);
        this.loadIntegrity();
      }
      wrap.appendChild(actions);
      return wrap;
    },

    async loadIntegrity() {
      let v;
      try { v = await api('/archive/verify'); } catch { const c = $('#integrityLine'); if (c) c.hidden = true; return; }
      const chip = $('#integrityLine');
      if (!chip) return;
      if (!v.entries) {
        chip.className = 'integrity-chip';
        chip.textContent = 'not verified yet';
        chip.title = 'The integrity chain has no entries yet — sessions preserved by an older version predate it. Archive now writes the first entries.';
      } else if (v.intact) {
        chip.className = 'integrity-chip ok';
        chip.textContent = '✓ verified';
        chip.title = fmtNum(v.entries) + ' preservation events across ' + fmtNum(v.sessions) + ' sessions, unaltered since they were kept.'
          + (v.headDigest ? '\nHead digest: ' + v.headDigest.slice(0, 16) + ' — record it elsewhere to anchor the archive at this point in time.' : '');
      } else {
        chip.className = 'integrity-chip bad';
        chip.textContent = '⚠ integrity failed';
        chip.title = v.brokenAt || 'The archive does not match what was recorded.';
      }
    },

    async auditBundle(btn) {
      const orig = btn.textContent;
      btn.disabled = true; btn.textContent = 'Building…';
      try {
        const r = await api('/archive/audit', { method: 'POST' });
        showBanner('Audit bundle written to ' + r.dir + ' · ' + fmtNum(r.sessions) + ' transcripts · integrity ' + (r.intact ? 'verified' : 'FAILED'), r.intact ? '' : 'danger');
      } catch (e) { handleApiError(e); }
      btn.disabled = false; btn.textContent = orig;
    },

    async exportAll(btn) {
      const orig = btn.textContent;
      btn.disabled = true; btn.textContent = 'Exporting…';
      try {
        const r = await api('/archive/export', { method: 'POST', body: { format: 'md' } });
        showBanner('Exported ' + fmtNum(r.count) + ' sessions to ' + r.dir + (r.errors ? ' · ' + r.errors + ' failed' : ''));
      } catch (e) { handleApiError(e); }
      btn.disabled = false; btn.textContent = orig;
    },

    preserveMsg(atrisk, overdue, soon, arch) {
      if (atrisk > 0) {
        const parts = [];
        if (overdue) parts.push(overdue + ' already overdue');
        if (soon) parts.push(soon + ' within 7 days');
        const risk = atrisk + ' session' + (atrisk === 1 ? '' : 's') + ' scheduled for deletion by your tools (' + parts.join(' · ') + ').';
        return arch.enabled
          ? risk + ' ' + fmtNum(arch.count) + ' preserved here · ' + fmtBytes(arch.bytes) + '.'
          : risk + ' Nothing is backed up yet.';
      }
      return arch.enabled
        ? fmtNum(arch.count) + ' sessions preserved · ' + fmtBytes(arch.bytes) + '. Your history is safe here even if the tools delete theirs.'
        : 'Your tools delete their own history on their own clocks. Turn on Preservation to keep a durable, on-device copy.';
    },

    async archiveNow(btn) {
      const orig = btn.innerHTML;
      btn.disabled = true; btn.textContent = 'Archiving…';
      try {
        const r = await api('/archive/run', { method: 'POST' });
        showBanner('Archived ' + fmtNum(r.archived) + ' new · ' + fmtNum(r.skipped) + ' unchanged' + (r.deletedDetected ? ' · ' + r.deletedDetected + ' deleted from source, preserved here' : ''));
        this.render($('#view')); // refresh counts + banner
      } catch (e) {
        handleApiError(e); btn.disabled = false; btn.innerHTML = orig;
      }
    },

    // Download a session in an open format (auth-gated fetch → blob download).
    exportBtn(id, fmt, label) {
      const b = el('button', { class: 'btn ghost sm', type: 'button', text: label });
      b.addEventListener('click', async () => {
        b.disabled = true;
        try {
          const res = await fetch('/api/agents/sessions/' + encodeURIComponent(id) + '/export?format=' + fmt, { headers: TOKEN ? { Authorization: 'Bearer ' + TOKEN } : {} });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          const blob = await res.blob();
          const cd = res.headers.get('content-disposition') || '';
          const m = cd.match(/filename="([^"]+)"/);
          const name = m ? m[1] : (id.replace(/:/g, '_') + '.' + fmt);
          const url = URL.createObjectURL(blob);
          const a = el('a', { href: url, download: name });
          document.body.appendChild(a); a.click(); a.remove();
          setTimeout(() => URL.revokeObjectURL(url), 1000);
        } catch (e) { showBanner('Export failed: ' + (e.message || ''), 'danger'); }
        b.disabled = false;
      });
      return b;
    },

    async reloadSessions() {
      const list = $('#agentList');
      if (!list) return;
      list.innerHTML = ''; list.appendChild(el('div', { class: 'state' }, [el('div', { class: 'spin' }), el('div', { class: 'sm', text: 'Loading sessions…' })]));
      let rows;
      try { rows = await api('/agents/sessions?limit=500' + (this.tool ? '&tool=' + encodeURIComponent(this.tool) : '') + (this.q ? '&q=' + encodeURIComponent(this.q) : '')); }
      catch (e) { list.innerHTML = ''; list.appendChild(el('div', { class: 'state sm', text: e.message || 'Could not load.' })); return; }
      list.innerHTML = '';
      if (!rows.length) { list.appendChild(el('div', { class: 'state sm', style: 'padding:28px', text: this.q ? 'No sessions match.' : 'No sessions.' })); return; }
      rows.forEach((s) => list.appendChild(this.row(s)));
    },

    row(s) {
      const row = el('div', { class: 'trow', tabindex: '0', 'data-id': s.id });
      const cell = (c, node) => { const d = el('div', { class: 'tcell' + (c.r ? ' r' : '') }); d.appendChild(node); return d; };
      row.appendChild(cell(AGENT_COLS[0], toolBadge(s.tool, s.label)));
      const title = el('div', { class: 'cell-app' }, [el('span', { class: 'nm', title: s.project || '', text: s.title || 'Untitled session' })]);
      if (s.sourceDeleted) title.appendChild(el('span', { class: 'presbadge deleted', title: 'Deleted from the source app · preserved by Saffev', text: 'preserved' }));
      else if (s.preserved) title.appendChild(el('span', { class: 'presbadge', title: 'A durable copy is in your archive', text: 'archived' }));
      if (s.piiCount > 0) title.appendChild(el('span', { class: 'piibadge key', title: s.piiCount + ' PII findings', text: 'PII' }));
      if (s.matchCount > 0) title.appendChild(el('span', { class: 'hitbadge', title: s.matchCount + ' matching message' + (s.matchCount === 1 ? '' : 's'), text: s.matchCount + ' hit' + (s.matchCount === 1 ? '' : 's') }));
      // A content match shows WHY it matched, right in the row.
      let titleNode = title;
      if (s.snippets && s.snippets.length) {
        const stack = el('div', { class: 'cellstack' }, [title]);
        s.snippets.slice(0, 2).forEach((sn) => stack.appendChild(snippetLine(sn)));
        titleNode = stack;
      }
      row.appendChild(cell(AGENT_COLS[1], titleNode));
      row.appendChild(cell(AGENT_COLS[2], el('span', { class: 'cell-model', text: s.model || '·' })));
      row.appendChild(cell(AGENT_COLS[3], el('span', { class: 'cell-tokens', text: fmtNum(s.messageCount) })));
      row.appendChild(cell(AGENT_COLS[4], el('span', { class: 'cell-tokens', text: fmtNum(s.inputTokens + s.outputTokens) })));
      row.appendChild(cell(AGENT_COLS[5], el('span', { class: 'cell-lat', text: s.costUsd > 0 ? '$' + s.costUsd.toFixed(2) : '·' })));
      row.appendChild(cell(AGENT_COLS[6], el('span', { class: 'cell-time', text: s.updatedTs ? new Date(s.updatedTs).toLocaleDateString() : '·' })));
      row.addEventListener('click', () => this.openDetail(s.id));
      row.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); this.openDetail(s.id); } });
      return row;
    },

    async openDetail(id) {
      let d;
      try { d = await api('/agents/sessions/' + encodeURIComponent(id)); }
      catch (e) { handleApiError(e); return; }
      closeDrawer();
      const s = d.session;
      const bg = el('div', { class: 'drawer-bg', onclick: closeDrawer });
      const dl = el('dl', { class: 'kvgrid' });
      const kv = (k, v) => { dl.appendChild(el('dt', { text: k })); dl.appendChild(el('dd', { text: v })); };
      kv('Source', s.label);
      kv('Model', s.model || '·');
      kv('Project', s.project || '·');
      if (s.gitBranch) kv('Branch', s.gitBranch);
      kv('Messages', fmtNum(s.messageCount));
      kv('Tool calls', fmtNum(s.toolCallCount));
      kv('Tokens', fmtNum(s.inputTokens) + ' in · ' + fmtNum(s.outputTokens) + ' out' + (s.cacheTokens ? ' · ' + fmtNum(s.cacheTokens) + ' cache' : ''));
      if (s.costUsd > 0) kv('Est. cost', '$' + s.costUsd.toFixed(2));
      kv('Updated', new Date(s.updatedTs).toLocaleString());

      const tags = el('div', { class: 'hrow', style: 'margin-top:6px;gap:6px;flex-wrap:wrap' }, [toolBadge(s.tool, s.label)]);
      if (s.sourceDeleted) tags.appendChild(el('span', { class: 'presbadge deleted', text: 'preserved · deleted from source' }));
      else if (s.preserved) tags.appendChild(el('span', { class: 'presbadge', text: 'archived' }));
      const body = el('div', {}, [
        el('button', { class: 'iconbtn close', onclick: closeDrawer, 'aria-label': 'Close', html: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 6 18 18M18 6 6 18"/></svg>' }),
        el('h2', { text: s.title || 'Untitled session' }),
        tags,
        dl,
      ]);

      // Export — the session is yours to keep, in open formats.
      const exportRow = el('div', { class: 'exprow' }, [
        el('span', { class: 'exp-l', text: 'Export' }),
        this.exportBtn(s.id, 'md', 'Markdown'),
        this.exportBtn(s.id, 'json', 'JSON'),
      ]);
      body.appendChild(exportRow);

      // AI summary (optional Codex backend).
      body.appendChild(this.summarizeSection(s));

      // PII lens: what secrets were pasted into this agent.
      if (d.pii && d.pii.length) {
        const byKind = {};
        d.pii.forEach((f) => { byKind[f.kind] = (byKind[f.kind] || 0) + 1; });
        const fl = el('div', { class: 'payblk' }, [el('h4', { text: 'Privacy lens · ' + d.pii.length + ' findings' })]);
        const list = el('div', { class: 'findlist' });
        Object.keys(byKind).sort((a, b) => byKind[b] - byKind[a]).forEach((k) => {
          list.appendChild(el('div', { class: 'find' }, [
            el('span', { class: 'piibadge' + (PII_SECRET_KINDS.includes(k) ? ' key' : ''), text: piiShort(k) }),
            el('span', { text: piiLabel(k) }),
            el('span', { class: 'where', text: byKind[k] + '×' }),
          ]));
        });
        fl.appendChild(list);
        body.appendChild(fl);
      }

      // Transcript.
      const tb = el('div', { class: 'payblk' }, [el('h4', { text: 'Transcript' })]);
      const chat = el('div', { class: 'chat' });
      d.messages.slice(0, 400).forEach((m) => {
        const roleLabel = m.kind === 'tool_use' ? (m.toolName || 'tool') + ' (call)' : m.kind === 'tool_result' ? 'tool result' : m.kind === 'thinking' ? m.role + ' · thinking' : m.role;
        chat.appendChild(el('div', { class: 'msg msg-' + esc(m.role) + (m.kind === 'thinking' ? ' msg-think' : '') }, [
          el('div', { class: 'msg-role', text: roleLabel }),
          el('div', { class: 'msg-body', text: m.content }),
        ]));
      });
      if (d.messages.length > 400) tb.appendChild(el('div', { class: 'meta', style: 'margin-bottom:8px', text: 'Showing first 400 of ' + fmtNum(d.messages.length) + ' messages.' }));
      tb.appendChild(chat);
      body.appendChild(tb);
      body.appendChild(el('div', { class: 'meta', style: 'margin-top:14px;word-break:break-all', text: 'Source: ' + s.sourcePath }));

      const drawer = el('div', { class: 'drawer', role: 'dialog', 'aria-modal': 'true' }, [body]);
      document.body.appendChild(bg); document.body.appendChild(drawer);
      document.addEventListener('keydown', escClose);
    },
    // The optional "Summarize this session" block. Shown only when the Codex
    // backend is present; explains the opt-in when it's off.
    summarizeSection(s) {
      const a = this._analysis || { available: false, enabled: false };
      if (!a.available) return el('span', { style: 'display:none' });
      const wrap = el('div', { class: 'payblk aiblk' }, [
        el('h4', {}, [el('span', { class: 'aiblk-ic', html: ICON.sparkles }), document.createTextNode(' AI summary')]),
      ]);
      if (!a.enabled) {
        wrap.appendChild(el('div', { class: 'ai-hint' }, [
          document.createTextNode('Summarize this session using your Codex subscription. This is the one feature that sends your content off this device. '),
          el('a', { href: '#/settings/privacy/analysis', text: 'Enable in Settings' }),
          document.createTextNode('.'),
        ]));
        return wrap;
      }
      // Everything else in Saffev stays on the machine. This one does not, so it
      // says so at the point of use, in full, rather than in a footnote.
      wrap.appendChild(el('div', { class: 'ai-warn' }, [
        el('strong', { text: 'This leaves your device.' }),
        document.createTextNode(' Clicking below uploads this session’s full text to OpenAI through your own Codex sign-in, and it is the only part of Saffev that sends your content anywhere. Nothing is sent until you click.'),
      ]));
      const out = el('div', { class: 'ai-out' });
      const btn = el('button', { class: 'btn ai-btn', type: 'button' }, [
        el('span', { class: 'aiblk-ic', html: ICON.sparkles }),
        document.createTextNode(' Send to OpenAI and summarize'),
      ]);
      btn.addEventListener('click', () => this.runSummary(s.id, out, btn));
      wrap.appendChild(btn);
      wrap.appendChild(el('div', { class: 'ai-note', text: 'Uses your ChatGPT subscription · sandboxed, read-only, no tools' }));
      wrap.appendChild(out);
      return wrap;
    },

    async runSummary(id, out, btn) {
      btn.disabled = true;
      out.innerHTML = '';
      out.appendChild(el('div', { class: 'state' }, [
        el('div', { class: 'spin' }),
        el('div', { class: 'sm', text: 'Analyzing with Codex… (usually 10-30s)' }),
      ]));
      try {
        const r = await api('/agents/sessions/' + encodeURIComponent(id) + '/summarize', { method: 'POST' });
        out.innerHTML = '';
        out.appendChild(el('div', { class: 'ai-summary', html: mdLite(r.summary) }));
        out.appendChild(el('div', { class: 'ai-note', text: 'via ' + (r.model || 'Codex') + ' · ' + ((r.elapsedMs || 0) / 1000).toFixed(1) + 's' }));
        btn.textContent = '';
        btn.appendChild(el('span', { class: 'aiblk-ic', html: ICON.sparkles }));
        btn.appendChild(document.createTextNode(' Regenerate'));
      } catch (e) {
        out.innerHTML = '';
        out.appendChild(el('div', { class: 'ai-err', text: e.message || 'Summary failed.' }));
      }
      btn.disabled = false;
    },

    teardown() {},
  };

  // Minimal, XSS-safe markdown for AI output: escapes first, then applies bold,
  // inline code, bullet lists, and bold-only lines as small headings.
  function mdLite(src) {
    const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const inline = (s) => esc(s).replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>').replace(/`([^`]+)`/g, '<code>$1</code>');
    let html = '', inList = false;
    for (const raw of String(src || '').split('\n')) {
      const line = raw.replace(/\s+$/, '');
      const li = line.match(/^\s*[-*]\s+(.*)$/);
      if (li) { if (!inList) { html += '<ul>'; inList = true; } html += '<li>' + inline(li[1]) + '</li>'; continue; }
      if (inList) { html += '</ul>'; inList = false; }
      if (!line.trim()) continue;
      const h = line.match(/^\s*\*\*(.+?)\*\*:?\s*$/);
      if (h) { html += '<h5>' + esc(h[1]) + '</h5>'; continue; }
      html += '<p>' + inline(line) + '</p>';
    }
    if (inList) html += '</ul>';
    return html;
  }

  // Privacy + Quality are folded into Analytics tabs (see navigate() redirects);
  // they stay as objects (Analytics renders their bodies) but aren't top-level routes.
  /* =========================================================================
     PAGE: TIMELINE — one record of everything AI touched on this machine.

     Saffev knows about AI activity two different ways: calls proxied through it,
     and coding-agent sessions read off disk. Those used to be separate pages with
     separate searches, so you had to already know which half your memory lived in
     before you could go looking for it. This is the page that removes that.
     ========================================================================= */
  const Timeline = {
    title: 'Timeline',
    sub: 'Everything AI touched on this machine, in order · proxied calls and coding sessions together.',
    q: '', kind: '', rangeMs: 0,
    RANGES: [
      { value: 0, label: 'All time' },
      { value: 86400000, label: 'Last 24 hours' },
      { value: 7 * 86400000, label: 'Last 7 days' },
      { value: 30 * 86400000, label: 'Last 30 days' },
    ],
    SCOPES: [
      { value: '', label: 'Everything' },
      { value: 'proxy', label: 'Proxied calls' },
      { value: 'agent', label: 'Coding sessions' },
    ],

    async render(view) {
      view.innerHTML = '';
      const MAG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="10.5" cy="10.5" r="6.5"/><path d="M15.5 15.5 21 21"/></svg>';
      const search = el('input', { class: 'sf-input', type: 'search', placeholder: 'Search everything…', value: this.q });
      let t; search.addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => { this.q = search.value.trim(); this.reload(); }, 250); });
      view.appendChild(el('div', { class: 'filterbar reveal' }, [
        el('div', { class: 'searchfield' }, [el('span', { class: 'sf-ic', html: MAG }), search]),
        dropdown(this.SCOPES, this.kind, (v) => { if (this.kind === v) return; this.kind = v; this.reload(); }, { ariaLabel: 'Filter by source' }),
        dropdown(this.RANGES, this.rangeMs, (v) => { this.rangeMs = parseInt(v, 10); this.reload(); }, { ariaLabel: 'Time range', align: 'right' }),
      ]));
      view.appendChild(el('div', { class: 'searchnote reveal', id: 'tlNote' }));
      view.appendChild(el('div', { class: 'card reveal', style: 'padding:0;overflow:hidden' }, [
        el('div', { class: 'ttable', style: '--gtc:' + this.gtc() }, [
          el('div', { class: 'thead' }, this.COLS.map((c) => el('div', { class: 'th' + (c.r ? ' r' : ''), text: c.label }))),
          el('div', { class: 'list', id: 'tlList' }),
        ]),
      ]));
      await this.reload();
    },

    COLS: [
      { label: 'Source', w: 'minmax(140px,1.1fr)' },
      { label: 'What', w: 'minmax(260px,2.6fr)' },
      { label: 'Model', w: 'minmax(130px,1.1fr)' },
      { label: 'Tokens', w: 'minmax(90px,.8fr)', r: true },
      { label: 'When', w: 'minmax(120px,1fr)', r: true },
    ],
    gtc() { return this.COLS.map((c) => c.w).join(' '); },

    async reload() {
      const list = $('#tlList');
      if (!list) return;
      list.innerHTML = ''; list.appendChild(el('div', { class: 'state' }, [el('div', { class: 'spin' }), el('div', { class: 'sm', text: 'Gathering…' })]));
      let d;
      try {
        d = await api('/timeline?limit=250'
          + (this.q ? '&q=' + encodeURIComponent(this.q) : '')
          + (this.kind ? '&kind=' + this.kind : '')
          + (this.rangeMs ? '&rangeMs=' + this.rangeMs : ''));
        hideBanner();
      } catch (e) {
        handleApiError(e);
        list.innerHTML = ''; list.appendChild(el('div', { class: 'state sm', text: e.message || 'Could not load.' }));
        return;
      }

      const note = $('#tlNote');
      if (note) {
        note.textContent = fmtNum(d.proxyCount) + ' proxied call' + (d.proxyCount === 1 ? '' : 's')
          + ' · ' + fmtNum(d.agentCount) + ' coding session' + (d.agentCount === 1 ? '' : 's')
          + (this.q
            ? (d.contentSearch
              ? ' · searching inside preserved conversations as well as metadata.'
              : ' · searching metadata only. Turn on Preservation to search what was actually said.')
            : '.');
      }

      list.innerHTML = '';
      if (!d.entries.length) {
        list.appendChild(el('div', { class: 'state sm', style: 'padding:28px', text: this.q ? 'Nothing matches.' : 'Nothing recorded yet.' }));
        return;
      }
      d.entries.forEach((e) => list.appendChild(this.row(e)));
    },

    row(e) {
      const row = el('div', { class: 'trow', tabindex: '0' });
      const cell = (c, node) => { const dv = el('div', { class: 'tcell' + (c.r ? ' r' : '') }); dv.appendChild(node); return dv; };

      // The source badge is what makes the merge readable: every row says plainly
      // where it came from.
      const src = e.kind === 'agent'
        ? toolBadge(e.source, e.label)
        : el('span', { class: 'tt-src' }, [
            el('span', { class: 'tt-ic', html: ICON.server }),
            el('span', { class: 'tt-nm', text: e.label }),
          ]);
      row.appendChild(cell(this.COLS[0], src));

      const what = el('div', { class: 'cell-app' }, [el('span', { class: 'nm', title: e.project || '', text: e.title })]);
      if (e.failed) what.appendChild(el('span', { class: 'piibadge', text: 'failed' }));
      if (e.piiCount > 0) what.appendChild(el('span', { class: 'piibadge key', title: e.piiCount + ' PII findings', text: 'PII' }));
      if (e.safetyFlagged) what.appendChild(el('span', { class: 'safetybadge', title: 'Safety flagged', text: '⚠ safety' }));
      if (e.preserved) what.appendChild(el('span', { class: 'presbadge', title: 'A durable copy is in your archive', text: 'archived' }));
      let whatNode = what;
      if (e.snippets && e.snippets.length) {
        const stack = el('div', { class: 'cellstack' }, [what]);
        e.snippets.slice(0, 2).forEach((sn) => stack.appendChild(snippetLine(sn)));
        whatNode = stack;
      }
      row.appendChild(cell(this.COLS[1], whatNode));

      row.appendChild(cell(this.COLS[2], el('span', { class: 'cell-model', title: e.model || '', text: e.model || '·' })));
      row.appendChild(cell(this.COLS[3], el('span', { class: 'cell-tokens', text: fmtNum(e.inputTokens + e.outputTokens) })));
      row.appendChild(cell(this.COLS[4], el('span', { class: 'cell-time', title: new Date(e.ts).toLocaleString(), text: fmtStamp(e.ts) })));

      // Each row opens the right detail view for its kind.
      const open = () => { if (e.kind === 'agent') Agents.openDetail(e.id); else openDetail(e.id); };
      row.addEventListener('click', open);
      row.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); open(); } });
      return row;
    },
  };

  const ROUTES = { timeline: Timeline, live: Live, history: History, agents: Agents, analytics: Analytics, engines: Engines, settings: Settings, about: About };
  let activePage = null;

  function setActiveNav(route) {
    $$('.nav a').forEach((a) => a.classList.toggle('active', a.dataset.route === route));
  }

  async function navigate() {
    let raw = (location.hash || '#/live').replace(/^#\/?/, '');
    // Consolidated pages redirect to their Analytics tab (deep links still work).
    const REDIRECT = { privacy: 'analytics/privacy', quality: 'analytics/quality' };
    if (!raw.includes('/') && REDIRECT[raw]) raw = REDIRECT[raw];
    const [seg, sub, extra] = raw.split('/');
    const route = ROUTES[seg] ? seg : 'live';
    const page = ROUTES[route];
    // A `#/analytics/<tab>` deep link opens Analytics on that tab.
    if (route === 'analytics' && sub && Analytics.TABS.some((t) => t.k === sub)) Analytics.tab = sub;
    // A `#/settings/<tab>[/<section>]` deep link opens Settings on that tab and
    // scrolls to + highlights the named section card (e.g. the "Turn on
    // Preservation" banner lands the user on the exact toggle).
    if (route === 'settings' && sub) {
      if (['general', 'privacy', 'system'].includes(sub)) Settings.tab = sub;
      Settings._focus = extra || null;
    }
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
  /* =========================================================================
     LEAK ALERTS — a live, on-device signal when a high-confidence secret (API
     key, credit card) flows through the proxy. Its own lightweight SSE so alerts
     fire on ANY page, not just Live. Nothing leaves the device.
     ========================================================================= */
  const LEAK_KINDS = { api_key: 'API key', credit_card: 'Credit card' };
  function ensureToastHost() {
    let h = $('#toastHost');
    if (!h) { h = el('div', { class: 'toast-host', id: 'toastHost' }); document.body.appendChild(h); }
    return h;
  }
  const LeakAlerts = {
    log: [], unseen: 0, _stop: false, _retry: 0, _ctrl: null,
    init() { this._stop = false; this.wireBell(); this._run(); },
    async _run() {
      if (this._stop || !TOKEN) return;
      const ctrl = new AbortController(); this._ctrl = ctrl;
      const headers = { Accept: 'text/event-stream', Authorization: 'Bearer ' + TOKEN };
      try {
        const res = await fetch('/api/stream?token=' + encodeURIComponent(TOKEN), { headers, signal: ctrl.signal, cache: 'no-store' });
        if (!res.ok || !res.body) throw new Error('alert stream ' + res.status);
        this._retry = 0;
        const reader = res.body.getReader(); const dec = new TextDecoder(); let buf = '';
        for (;;) {
          const { value, done } = await reader.read(); if (done) break;
          buf += dec.decode(value, { stream: true });
          let idx;
          while ((idx = buf.indexOf('\n\n')) !== -1) { const frame = buf.slice(0, idx); buf = buf.slice(idx + 2); this._frame(frame); }
        }
      } catch (e) { /* reconnect below */ }
      if (this._stop) return;
      const delay = Math.min(1500 * Math.pow(2, this._retry++), 20000);
      setTimeout(() => this._run(), delay);
    },
    _frame(frame) {
      const lines = [];
      frame.split('\n').forEach((l) => { if (l.startsWith('data:')) lines.push(l.slice(5).replace(/^ /, '')); });
      if (!lines.length) return;
      let msg; try { msg = JSON.parse(lines.join('\n')); } catch (e) { return; }
      if (msg.type === 'pii' && msg.finding) this.consider(msg.finding, msg.id);
    },
    consider(f, id) {
      if (!LEAK_KINDS[f.kind]) return;                    // only alert on secrets
      if (f.confidence && f.confidence !== 'high') return; // and only high-confidence
      const rec = { kind: f.kind, id, ts: Date.now(), side: f.side };
      this.log.unshift(rec); this.log = this.log.slice(0, 30);
      this.unseen++; this.updateBell(); this.toast(rec);
    },
    toast(rec) {
      const host = ensureToastHost();
      const label = LEAK_KINDS[rec.kind] || 'Secret';
      const t = el('div', { class: 'toast' });
      t.appendChild(el('span', { class: 'toast-ic', html: ICON.shieldAlert }));
      t.appendChild(el('div', { class: 'toast-b' }, [
        el('div', { class: 'toast-t', text: label + ' in a ' + (rec.side === 'response' ? 'response' : 'prompt') }),
        el('div', { class: 'toast-d', text: 'High-confidence secret observed on-device. Click to inspect.' }),
      ]));
      const x = el('button', { class: 'toast-x', type: 'button', 'aria-label': 'Dismiss', text: '✕' });
      x.addEventListener('click', (e) => { e.stopPropagation(); t.remove(); });
      t.appendChild(x);
      t.addEventListener('click', () => { t.remove(); openDetail(rec.id); });
      host.appendChild(t);
      setTimeout(() => { t.classList.add('out'); setTimeout(() => t.remove(), 300); }, 9000);
    },
    updateBell() {
      const bell = $('#alertBell'); if (!bell) return;
      bell.hidden = false;
      const c = $('#alertCount');
      if (c) { c.hidden = this.unseen === 0; c.textContent = this.unseen > 9 ? '9+' : String(this.unseen); }
    },
    wireBell() {
      const bell = $('#alertBell'); if (!bell || bell._wired) return; bell._wired = true;
      bell.addEventListener('click', (e) => { e.stopPropagation(); this.toggleMenu(); });
    },
    toggleMenu() {
      const existing = $('#alertMenu');
      if (existing) { existing.remove(); return; }
      this.unseen = 0; this.updateBell();
      const m = el('div', { class: 'alert-menu', id: 'alertMenu' }, [el('div', { class: 'alert-menu-h', text: 'Recent leaks' })]);
      if (!this.log.length) m.appendChild(el('div', { class: 'alert-menu-empty', text: 'No secrets detected this session.' }));
      else this.log.forEach((r) => {
        const row = el('button', { class: 'alert-item', type: 'button' }, [
          el('span', { class: 'piibadge key', text: LEAK_KINDS[r.kind] }),
          el('span', { class: 'alert-item-t', text: r.side === 'response' ? 'response' : 'prompt' }),
          el('span', { class: 'alert-item-time', text: new Date(r.ts).toLocaleTimeString() }),
        ]);
        row.addEventListener('click', () => { const mm = $('#alertMenu'); if (mm) mm.remove(); openDetail(r.id); });
        m.appendChild(row);
      });
      const bell = $('#alertBell'); bell.appendChild(m);
      setTimeout(() => document.addEventListener('click', function off(ev) {
        const mm = $('#alertMenu');
        if (mm && !bell.contains(ev.target)) { mm.remove(); document.removeEventListener('click', off); }
      }), 0);
    },
  };

  function applyBrand() {
    document.title = BRAND.wordmark + ' · Studio';
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
      // Auto-check for a newer release (GitHub release metadata only · nothing
      // about the user leaves the device). Fail-soft: never blocks the UI.
      checkForUpdate();
      // Live leak alerts (its own SSE, on-device only) fire on any page.
      LeakAlerts.init();
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
