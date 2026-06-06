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
     Shared row renderer (Live + History share the "traffic row" look).
     ------------------------------------------------------------------------- */
  function reqRow(item, opts) {
    opts = opts || {};
    const streaming = !!opts.streaming;
    const node = el('div', {
      class: 'req' + (streaming ? ' streaming' : '') + (opts.enter ? ' enter' : ''),
      'data-id': item.id,
    });

    const lead = el('div', { class: 'lead', text: initials(item.sourceApp) });

    const appLine = el('div', { class: 'app' });
    appLine.appendChild(document.createTextNode(item.sourceApp || 'Unknown'));
    if (item.sourceConfidence === 'pid' && !item.sourceApp) {
      appLine.appendChild(el('span', { class: 'det', style: 'display:inline;margin:0', text: 'by pid' }));
    }
    // PII badges
    (item.piiKinds || []).forEach((k) => {
      appLine.appendChild(el('span', { class: 'piibadge' + (k === 'api_key' ? ' key' : ''), text: piiShort(k) }));
    });

    const detBits = [];
    if (item.model) detBits.push(esc(item.model));
    const det = el('div', { class: 'det' });
    det.innerHTML = (item.model ? esc(item.model) + ' · ' : '') +
      '<span class="ep">' + esc(item.endpoint) + '</span>' +
      (item.stream ? ' · streaming' : '');

    const mid = el('div', { class: 'mid' }, [appLine, det]);

    const right = el('div', { class: 'right' });
    const lat = el('div', { class: 'lat' });
    lat.textContent = item.latencyMs != null ? item.latencyMs + 'ms' : (streaming ? '' : '—');
    const up = item.inputTokens != null ? (item.inputTokensSrc === 'estimated' ? '~' : '') + fmtNum(item.inputTokens) + ' ↑' : '';
    const down = item.outputTokens != null ? (item.outputTokensSrc === 'estimated' ? '~' : '') + fmtNum(item.outputTokens) + ' ↓' : '';
    const tk = el('div', { class: 'tk', text: [up, down].filter(Boolean).join(' · ') || ' ' });
    right.appendChild(lat); right.appendChild(tk);

    node.appendChild(lead); node.appendChild(mid); node.appendChild(right);
    node.addEventListener('click', () => openDetail(item.id));
    return node;
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
        el('div', { class: 'stream', id: 'stream' }),
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

      const body = el('section', { class: 'body' }, [streamCard, side]);
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
              const row = reqRow(it, {});
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
    },

    renderPrivacyLens(recent) {
      const counts = {};
      recent.forEach((it) => (it.piiKinds || []).forEach((k) => { counts[k] = (counts[k] || 0) + 1; }));
      const body = $('#livePrivacyBody');
      if (!body) return;
      body.innerHTML = '';
      const kinds = Object.keys(counts);
      if (kinds.length === 0) {
        body.appendChild(el('div', { class: 'expnote', html: ICON.check + ' No PII observed in the recent window.' }));
      } else {
        kinds.sort((a, b) => counts[b] - counts[a]).forEach((k) => {
          body.appendChild(el('div', { class: 'pii-row' }, [
            el('div', { class: 'swt ic ' + piiRole(k), html: piiIcon(k) }),
            el('div', {}, [el('div', { class: 'nm', text: piiLabel(k) }), el('div', { class: 'cf', text: 'observed' })]),
            el('div', { class: 'ct', text: String(counts[k]) }),
          ]));
        });
      }
      body.appendChild(el('div', { class: 'modebar' }, [
        el('div', { class: 't', html: 'Masking is <b>off</b> — observe only' }),
        el('button', { class: 'switch', disabled: true, title: 'Masking is not available in this version', 'aria-label': 'Masking off (disabled)' }),
      ]));
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
      const portsLine = el('div', { class: 'ports' });
      portsLine.innerHTML = '<span class="muted">public</span> :' + esc(eng.publicPort) +
        (eng.shadowPort != null ? ' <span class="arr">→</span> <span class="muted">shadow</span> :' + esc(eng.shadowPort) : '');
      card.appendChild(portsLine);
      const exp = ev.exposure;
      card.appendChild(el('div', { class: 'expnote' + (exp.exposed ? ' danger' : ''), html: (exp.exposed ? ICON.alert : ICON.check) + ' ' + esc(exposureLine(exp)) }));
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
        const row = reqRow(it, { streaming: it.stream, enter: true });
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
        const fresh = reqRow(it, {});
        const old = this.seen[it.id];
        if (old && old.parentNode) { old.parentNode.replaceChild(fresh, old); }
        else { stream.prepend(fresh); }
        this.seen[it.id] = fresh;
      } else if (msg.type === 'pii') {
        const row = this.seen[msg.id];
        if (row) {
          const appLine = row.querySelector('.app');
          if (appLine && !appLine.querySelector('.piibadge[data-k="' + msg.finding.kind + '"]')) {
            const b = el('span', { class: 'piibadge' + (msg.finding.kind === 'api_key' ? ' key' : ''), 'data-k': msg.finding.kind, text: piiShort(msg.finding.kind) });
            appLine.appendChild(b);
          }
        }
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
  const History = {
    title: 'History',
    sub: 'Every proxied exchange — searchable, filterable, on-device.',
    q: '', piiOnly: false, items: [], loading: false, exhausted: false,

    async render(view) {
      this.q = ''; this.piiOnly = false; this.items = []; this.exhausted = false;
      view.innerHTML = '';
      const search = el('input', { class: 'input', type: 'search', placeholder: 'Search app, model, or endpoint…', value: this.q });
      let t;
      search.addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => { this.q = search.value.trim(); this.reload(); }, 250); });
      const piiToggle = el('label', { class: 'chk' }, [
        (() => { const c = el('input', { type: 'checkbox' }); c.addEventListener('change', () => { this.piiOnly = c.checked; this.reload(); }); return c; })(),
        document.createTextNode('PII only'),
      ]);
      const toolbar = el('div', { class: 'toolbar reveal' }, [search, piiToggle]);
      const listCard = el('div', { class: 'card reveal', style: 'animation-delay:.06s' }, [el('div', { class: 'list', id: 'histList' })]);
      const more = el('div', { style: 'margin-top:14px;text-align:center' }, [
        el('button', { class: 'btn auto', id: 'histMore', style: 'display:none;margin:0 auto', text: 'Load older' }),
      ]);
      view.appendChild(toolbar);
      view.appendChild(listCard);
      view.appendChild(more);
      $('#histMore').addEventListener('click', () => this.loadMore());
      await this.reload();
    },

    async reload() {
      this.items = []; this.exhausted = false;
      const list = $('#histList');
      if (list) { list.innerHTML = ''; list.appendChild(el('div', { class: 'state' }, [el('div', { class: 'spin' }), el('div', { class: 'sm', text: 'Loading history…' })])); }
      await this.loadMore(true);
    },

    async loadMore(fresh) {
      if (this.loading || this.exhausted) return;
      this.loading = true;
      const params = new URLSearchParams();
      if (this.q) params.set('q', this.q);
      if (this.piiOnly) params.set('piiOnly', 'true');
      params.set('limit', '50');
      if (!fresh && this.items.length) params.set('beforeTs', String(this.items[this.items.length - 1].ts));
      let rows;
      try { rows = await api('/history?' + params.toString()); hideBanner(); }
      catch (e) { handleApiError(e); this.loading = false; return; }
      const list = $('#histList');
      if (fresh && list) list.innerHTML = '';
      if (rows.length < 50) this.exhausted = true;
      if (fresh && rows.length === 0) {
        if (list) list.appendChild(el('div', { class: 'state' }, [el('div', { class: 'big', text: 'No matching exchanges' }), el('div', { class: 'sm', text: this.q || this.piiOnly ? 'Try clearing the filters.' : 'Traffic will appear here as your apps talk to local models.' })]));
      }
      rows.forEach((it) => { this.items.push(it); if (list) list.appendChild(reqRow(it, {})); });
      this.loading = false;
      const more = $('#histMore');
      if (more) more.style.display = this.exhausted || rows.length === 0 ? 'none' : 'inline-flex';
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
      const card = el('div', { class: 'card reveal' }, [el('div', { class: 'hrow' }, [el('h3', { text: 'Interception' })])]);

      // mode
      const modeSel = el('select', { class: 'select' });
      [['cooperative', 'Cooperative'], ['gateway', 'Gateway']].forEach(([v, t]) => {
        const o = el('option', { value: v, text: t }); if (s.mode === v) o.selected = true; modeSel.appendChild(o);
      });
      modeSel.addEventListener('change', () => this.save(view, { mode: modeSel.value }));
      card.appendChild(setRow('Mode', 'Cooperative (universal) or Gateway (supervised, owns the port).', el('div', { class: 'ctl' }, [modeSel])));

      // handover
      const hoSel = el('select', { class: 'select' });
      [['handover', 'Handover'], ['stop', 'Stop']].forEach(([v, t]) => {
        const o = el('option', { value: v, text: t }); if (s.handover === v) o.selected = true; hoSel.appendChild(o);
      });
      hoSel.addEventListener('change', () => this.save(view, { handover: hoSel.value }));
      card.appendChild(setRow('Handover policy', 'On shutdown in Gateway mode: hand the engine back, or stop it.', el('div', { class: 'ctl' }, [hoSel])));

      view.appendChild(card);

      // Privacy card
      const privCard = el('div', { class: 'card reveal', style: 'animation-delay:.06s' }, [el('div', { class: 'hrow' }, [el('h3', { text: 'Privacy & storage' })])]);

      // payload storage toggle
      const sw = el('button', { class: 'switch' + (s.payloadStorage ? ' on' : ''), 'aria-label': 'Toggle payload storage' });
      sw.addEventListener('click', () => {
        const next = !sw.classList.contains('on');
        if (next && !confirm('Store raw prompts & responses on this device?\n\nBy default Saffev keeps metadata only. Turning this on records full payloads (still on-device, encrypted). This is an explicit, logged action.')) return;
        this.save(view, { payloadStorage: next });
      });
      const payCtl = el('div', { class: 'ctl' }, [sw]);
      const payHint = s.payloadStorage
        ? 'On — full prompts & responses are retained on this device.'
        : 'Off — metadata-only (default). Raw payloads are never stored.';
      const payRow = setRow('Store raw payloads', payHint, payCtl);
      if (s.payloadStorage) payRow.querySelector('.hint').classList.add('danger-note');
      privCard.appendChild(payRow);

      // retention
      const retVal = retentionText(s.retention);
      const retSel = el('select', { class: 'select' });
      [['age30', 'Age · 30 days'], ['age7', 'Age · 7 days'], ['age90', 'Age · 90 days'], ['size500', 'Size · 500 MB'], ['unlimited', 'Unlimited']].forEach(([v, t]) => {
        const o = el('option', { value: v, text: t }); retSel.appendChild(o);
      });
      retSel.value = retentionKey(s.retention);
      retSel.addEventListener('change', () => this.save(view, { retention: retentionFromKey(retSel.value) }));
      privCard.appendChild(setRow('Retention', 'How long exchanges are kept before pruning. Currently: ' + retVal + '.', el('div', { class: 'ctl' }, [retSel])));

      view.appendChild(privCard);

      // Masking card (opt-in PII redaction, dry-run by default).
      const maskCard = el('div', { class: 'card reveal', style: 'animation-delay:.09s' }, [el('div', { class: 'hrow' }, [el('h3', { text: 'PII masking' })])]);

      // master enable toggle
      const mEnable = el('button', { class: 'switch' + (s.maskingEnabled ? ' on' : ''), 'aria-label': 'Toggle PII masking' });
      mEnable.addEventListener('click', () => {
        const next = !mEnable.classList.contains('on');
        this.save(view, { maskingEnabled: next });
      });
      const enHint = s.maskingEnabled
        ? 'On — high-confidence PII detectors feed the masking pipeline.'
        : 'Off — observe-only (default). Traffic is never altered.';
      maskCard.appendChild(setRow('Enable masking', enHint, el('div', { class: 'ctl' }, [mEnable])));

      // dry-run toggle (only meaningful when enabled)
      const mDry = el('button', { class: 'switch' + (s.maskingDryRun ? ' on' : ''), 'aria-label': 'Toggle masking dry-run' });
      if (!s.maskingEnabled) mDry.setAttribute('disabled', '');
      mDry.addEventListener('click', () => {
        if (!s.maskingEnabled) return;
        const next = !mDry.classList.contains('on');
        // Leaving dry-run turns on real request redaction — confirm explicitly.
        if (!next && !confirm('Turn OFF dry-run and start redacting requests?\n\nWith dry-run off, high-confidence PII (email, card, API key, IP, phone) is removed from request bodies BEFORE they reach the model. Responses and streaming are unaffected. Fail-open: any error forwards the original request.')) return;
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

      view.appendChild(maskCard);

      // Read-only system card
      const sysCard = el('div', { class: 'card reveal', style: 'animation-delay:.12s' }, [el('div', { class: 'hrow' }, [el('h3', { text: 'System' })])]);
      sysCard.appendChild(setRow('Data directory', 'Config + encrypted database location.', el('div', { class: 'ctl' }, [el('span', { class: 'kv', text: s.dataDir })])));
      sysCard.appendChild(setRow('Proxy port', 'Where apps send local-LLM traffic.', el('div', { class: 'ctl' }, [el('span', { class: 'kv', text: ':' + s.proxyPort })])));
      sysCard.appendChild(setRow('Studio port', 'This control plane.', el('div', { class: 'ctl' }, [el('span', { class: 'kv', text: ':' + s.studioPort })])));
      const patterns = (s.customPatterns && s.customPatterns.length) ? s.customPatterns.join(', ') : 'none';
      sysCard.appendChild(setRow('Custom PII patterns', 'User-defined detectors (configured in the config file).', el('div', { class: 'ctl' }, [el('span', { class: 'kv', text: patterns })])));
      view.appendChild(sysCard);
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
  const ROUTES = { live: Live, history: History, privacy: Privacy, engines: Engines, settings: Settings };
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
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
