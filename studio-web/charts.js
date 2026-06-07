/* ============================================================================
   Saffev Studio — charts.js
   A tiny, dependency-free, theme-aware SVG chart toolkit for the Analytics page.
   No CDN, no build — pure SVG so it stays offline and on-brand (colors come from
   tokens.css via var(...) so charts follow light/dark automatically).

   Exposes `window.SaffevCharts` with:
     lineArea, bars, hbars, donut, heatmap, scatter, histogram, sparkline
   Each returns an <svg> (or wrapper) element ready to append. Hover detail uses
   native <title> tooltips (robust, zero-maintenance).
   ============================================================================ */
(function () {
  'use strict';
  const NS = 'http://www.w3.org/2000/svg';

  function s(tag, attrs, kids) {
    const n = document.createElementNS(NS, tag);
    if (attrs) for (const k in attrs) { if (attrs[k] != null) n.setAttribute(k, attrs[k]); }
    if (kids != null) (Array.isArray(kids) ? kids : [kids]).forEach((c) => {
      if (c == null) return;
      n.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
    });
    return n;
  }
  const titleEl = (t) => s('title', {}, String(t));
  const PALETTE = ['var(--brand)', 'var(--gold)', 'var(--safe)', 'var(--danger)', 'var(--warn)', 'var(--text-2)'];

  function niceMax(v) {
    if (!isFinite(v) || v <= 0) return 1;
    const p = Math.pow(10, Math.floor(Math.log10(v)));
    const f = v / p;
    const nf = f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10;
    return nf * p;
  }
  const fmtNum = (n) => {
    if (n == null) return '';
    const a = Math.abs(n);
    if (a >= 1e9) return (n / 1e9).toFixed(1) + 'B';
    if (a >= 1e6) return (n / 1e6).toFixed(1) + 'M';
    if (a >= 1e3) return (n / 1e3).toFixed(a >= 1e4 ? 0 : 1) + 'k';
    return String(Math.round(n * 10) / 10);
  };
  function svgRoot(w, h, cls) {
    return s('svg', { viewBox: `0 0 ${w} ${h}`, class: 'chart ' + (cls || ''), preserveAspectRatio: 'none', width: '100%', height: h });
  }
  const empty = (msg) => { const d = document.createElement('div'); d.className = 'chart-empty'; d.textContent = msg || 'No data in this window.'; return d; };

  /* -------- line / area (time series, one or more series) ----------------- */
  function lineArea(opts) {
    const series = (opts.series || []).filter((x) => x.values && x.values.length);
    if (!series.length || !series.some((s2) => s2.values.some((v) => v != null))) return empty();
    const W = 720, H = 240, pl = 46, pr = 14, pt = 14, pb = 26;
    const n = series[0].values.length;
    const iw = W - pl - pr, ih = H - pt - pb;
    let max = 0;
    series.forEach((se) => se.values.forEach((v) => { if (v != null && v > max) max = v; }));
    max = niceMax(max);
    const x = (i) => pl + (n <= 1 ? iw / 2 : (i / (n - 1)) * iw);
    const y = (v) => pt + ih - (v / max) * ih;
    const svg = svgRoot(W, H, 'chart-line');
    // gridlines + y labels
    for (let g = 0; g <= 4; g++) {
      const gy = pt + (g / 4) * ih;
      svg.appendChild(s('line', { x1: pl, y1: gy, x2: W - pr, y2: gy, class: 'grid' }));
      svg.appendChild(s('text', { x: pl - 8, y: gy + 3, class: 'axlabel', 'text-anchor': 'end' }, fmtNum(max * (1 - g / 4))));
    }
    // x labels (first / mid / last)
    const xl = opts.xLabels || [];
    [0, Math.floor((n - 1) / 2), n - 1].forEach((i) => {
      if (xl[i]) svg.appendChild(s('text', { x: x(i), y: H - 6, class: 'axlabel', 'text-anchor': i === 0 ? 'start' : i === n - 1 ? 'end' : 'middle' }, xl[i]));
    });
    series.forEach((se, si) => {
      const color = se.color || PALETTE[si % PALETTE.length];
      const pts = se.values.map((v, i) => [x(i), y(v == null ? 0 : v)]);
      if (se.area !== false) {
        let d = `M ${pts[0][0]} ${pt + ih}`;
        pts.forEach((p) => (d += ` L ${p[0]} ${p[1]}`));
        d += ` L ${pts[pts.length - 1][0]} ${pt + ih} Z`;
        svg.appendChild(s('path', { d, fill: color, 'fill-opacity': '0.12', stroke: 'none' }));
      }
      let dl = '';
      pts.forEach((p, i) => (dl += (i ? ' L ' : 'M ') + p[0] + ' ' + p[1]));
      svg.appendChild(s('path', { d: dl, fill: 'none', stroke: color, 'stroke-width': '2', 'stroke-linejoin': 'round', 'stroke-linecap': 'round' }));
      // hover dots
      se.values.forEach((v, i) => {
        if (v == null) return;
        const c = s('circle', { cx: x(i), cy: y(v), r: 7, fill: 'transparent', class: 'hot' });
        c.appendChild(titleEl((se.name ? se.name + ' · ' : '') + (xl[i] ? xl[i] + ': ' : '') + fmtNum(v)));
        svg.appendChild(c);
      });
    });
    return svg;
  }

  /* -------- vertical bars (histograms / categorical counts) --------------- */
  function bars(opts) {
    const items = opts.items || [];
    if (!items.length || !items.some((i) => i.value > 0)) return empty();
    const W = 720, H = 230, pl = 46, pr = 14, pt = 14, pb = 38;
    const iw = W - pl - pr, ih = H - pt - pb;
    let max = niceMax(Math.max(...items.map((i) => i.value)));
    const bw = iw / items.length;
    const svg = svgRoot(W, H, 'chart-bars');
    for (let g = 0; g <= 4; g++) {
      const gy = pt + (g / 4) * ih;
      svg.appendChild(s('line', { x1: pl, y1: gy, x2: W - pr, y2: gy, class: 'grid' }));
      svg.appendChild(s('text', { x: pl - 8, y: gy + 3, class: 'axlabel', 'text-anchor': 'end' }, fmtNum(max * (1 - g / 4))));
    }
    items.forEach((it, i) => {
      const h = (it.value / max) * ih;
      const bx = pl + i * bw + bw * 0.16;
      const w = bw * 0.68;
      const r = s('rect', { x: bx, y: pt + ih - h, width: w, height: Math.max(h, 0.5), rx: 4, fill: it.color || 'var(--brand)', class: 'bar' });
      r.appendChild(titleEl(it.label + ': ' + fmtNum(it.value)));
      svg.appendChild(r);
      svg.appendChild(s('text', { x: bx + w / 2, y: H - 22, class: 'axlabel', 'text-anchor': 'middle' }, it.label));
      if (it.sublabel) svg.appendChild(s('text', { x: bx + w / 2, y: H - 10, class: 'axlabel dim', 'text-anchor': 'middle' }, it.sublabel));
    });
    return svg;
  }

  /* -------- horizontal bars (rankings: by app/model/endpoint/kind) -------- */
  function hbars(opts) {
    const items = (opts.items || []).slice(0, opts.limit || 10);
    if (!items.length) return empty();
    const max = Math.max(1, ...items.map((i) => i.value));
    const wrap = document.createElement('div');
    wrap.className = 'hbars';
    items.forEach((it, i) => {
      const row = document.createElement('div');
      row.className = 'hbar';
      const nm = document.createElement('div'); nm.className = 'hbar-nm'; nm.textContent = it.label; nm.title = it.label;
      const track = document.createElement('div'); track.className = 'hbar-track';
      const fill = document.createElement('div'); fill.className = 'hbar-fill';
      fill.style.width = Math.max(2, (it.value / max) * 100) + '%';
      if (it.color) fill.style.background = it.color;
      track.appendChild(fill);
      const val = document.createElement('div'); val.className = 'hbar-val'; val.textContent = (opts.fmt ? opts.fmt(it.value) : fmtNum(it.value)) + (it.suffix || '');
      row.appendChild(nm); row.appendChild(track); row.appendChild(val);
      if (it.note) { const note = document.createElement('div'); note.className = 'hbar-note'; note.textContent = it.note; row.appendChild(note); }
      wrap.appendChild(row);
    });
    return wrap;
  }

  /* -------- donut (distribution) ------------------------------------------ */
  function donut(opts) {
    const items = (opts.items || []).filter((i) => i.value > 0);
    if (!items.length) return empty();
    const total = items.reduce((a, b) => a + b.value, 0);
    const W = 220, H = 220, cx = 110, cy = 110, rO = 96, rI = 60;
    // A donut must stay circular — keep aspect (unlike the width-filling charts).
    const svg = s('svg', { viewBox: `0 0 ${W} ${H}`, class: 'chart chart-donut', preserveAspectRatio: 'xMidYMid meet' });
    let ang = -Math.PI / 2;
    const arc = (a0, a1, ro, ri) => {
      const large = a1 - a0 > Math.PI ? 1 : 0;
      const p = (a, r) => [cx + r * Math.cos(a), cy + r * Math.sin(a)];
      const [x0, y0] = p(a0, ro), [x1, y1] = p(a1, ro), [x2, y2] = p(a1, ri), [x3, y3] = p(a0, ri);
      return `M ${x0} ${y0} A ${ro} ${ro} 0 ${large} 1 ${x1} ${y1} L ${x2} ${y2} A ${ri} ${ri} 0 ${large} 0 ${x3} ${y3} Z`;
    };
    items.forEach((it, i) => {
      const frac = it.value / total;
      const a1 = ang + frac * Math.PI * 2;
      const path = s('path', { d: arc(ang, a1 - 0.012, rO, rI), fill: it.color || PALETTE[i % PALETTE.length] });
      path.appendChild(titleEl(it.label + ': ' + fmtNum(it.value) + ' (' + Math.round(frac * 100) + '%)'));
      svg.appendChild(path);
      ang = a1;
    });
    svg.appendChild(s('text', { x: cx, y: cy - 4, class: 'donut-c', 'text-anchor': 'middle' }, fmtNum(total)));
    svg.appendChild(s('text', { x: cx, y: cy + 14, class: 'donut-l', 'text-anchor': 'middle' }, opts.centerLabel || 'total'));
    const wrap = document.createElement('div'); wrap.className = 'donut-wrap';
    wrap.appendChild(svg);
    const leg = document.createElement('div'); leg.className = 'legend';
    items.forEach((it, i) => {
      const l = document.createElement('div'); l.className = 'leg';
      const sw = document.createElement('span'); sw.className = 'leg-sw'; sw.style.background = it.color || PALETTE[i % PALETTE.length];
      const tx = document.createElement('span'); tx.className = 'leg-tx'; tx.textContent = it.label + ' · ' + fmtNum(it.value);
      l.appendChild(sw); l.appendChild(tx); leg.appendChild(l);
    });
    wrap.appendChild(leg);
    return wrap;
  }

  /* -------- heatmap (day-of-week × hour) ---------------------------------- */
  function heatmap(opts) {
    const cells = opts.cells || [];
    const grid = {};
    let max = 0;
    cells.forEach((c) => { grid[c.dow + ':' + c.hour] = c.count; if (c.count > max) max = c.count; });
    if (max === 0) return empty();
    const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    const W = 720, H = 200, pl = 36, pt = 10, pb = 22, pr = 8;
    const iw = W - pl - pr, ih = H - pt - pb;
    const cw = iw / 24, ch = ih / 7;
    const svg = svgRoot(W, H, 'chart-heat');
    for (let d = 0; d < 7; d++) {
      svg.appendChild(s('text', { x: pl - 6, y: pt + d * ch + ch / 2 + 3, class: 'axlabel', 'text-anchor': 'end' }, days[d]));
      for (let h = 0; h < 24; h++) {
        const v = grid[d + ':' + h] || 0;
        const op = v === 0 ? 0.06 : 0.18 + 0.82 * (v / max);
        const rect = s('rect', { x: pl + h * cw + 1, y: pt + d * ch + 1, width: cw - 2, height: ch - 2, rx: 3, fill: 'var(--brand)', 'fill-opacity': op.toFixed(3) });
        rect.appendChild(titleEl(days[d] + ' ' + h + ':00 — ' + v + ' request' + (v === 1 ? '' : 's')));
        svg.appendChild(rect);
      }
    }
    [0, 6, 12, 18, 23].forEach((h) => svg.appendChild(s('text', { x: pl + h * cw + cw / 2, y: H - 6, class: 'axlabel', 'text-anchor': 'middle' }, h)));
    return svg;
  }

  /* -------- scatter (output tokens vs latency) ---------------------------- */
  function scatter(opts) {
    const pts = opts.points || [];
    if (!pts.length) return empty();
    const W = 720, H = 240, pl = 50, pr = 14, pt = 14, pb = 30;
    const iw = W - pl - pr, ih = H - pt - pb;
    const xmax = niceMax(Math.max(...pts.map((p) => p.x), 1));
    const ymax = niceMax(Math.max(...pts.map((p) => p.y), 1));
    const X = (v) => pl + (v / xmax) * iw;
    const Y = (v) => pt + ih - (v / ymax) * ih;
    const svg = svgRoot(W, H, 'chart-scatter');
    for (let g = 0; g <= 4; g++) {
      const gy = pt + (g / 4) * ih;
      svg.appendChild(s('line', { x1: pl, y1: gy, x2: W - pr, y2: gy, class: 'grid' }));
      svg.appendChild(s('text', { x: pl - 8, y: gy + 3, class: 'axlabel', 'text-anchor': 'end' }, fmtNum(ymax * (1 - g / 4))));
    }
    [0, 0.5, 1].forEach((f) => svg.appendChild(s('text', { x: pl + f * iw, y: H - 6, class: 'axlabel', 'text-anchor': f === 0 ? 'start' : f === 1 ? 'end' : 'middle' }, fmtNum(xmax * f))));
    svg.appendChild(s('text', { x: pl + iw / 2, y: H - 6, class: 'axlabel dim', 'text-anchor': 'middle' }, opts.xLabel || ''));
    pts.forEach((p) => {
      const c = s('circle', { cx: X(p.x), cy: Y(p.y), r: 3.5, fill: 'var(--brand)', 'fill-opacity': '0.5', class: 'dot' });
      c.appendChild(titleEl((opts.xLabel || 'x') + ' ' + fmtNum(p.x) + ' · ' + (opts.yLabel || 'y') + ' ' + fmtNum(p.y)));
      svg.appendChild(c);
    });
    return svg;
  }

  /* -------- histogram (binned distribution) ------------------------------- */
  function histogram(opts) {
    const binsIn = opts.bins || [];
    const items = binsIn.map((b) => ({
      label: b.hi >= 4294967295 || b.hi == null ? b.lo + (opts.unit || '') + '+' : b.lo + '–' + b.hi,
      value: b.count,
      color: opts.color || 'var(--gold)',
    }));
    return bars({ items });
  }

  /* -------- sparkline (tiny inline trend for KPI cards) ------------------- */
  function sparkline(values, opts) {
    opts = opts || {};
    const vals = (values || []).map((v) => (v == null ? 0 : v));
    const W = 120, H = 34;
    const svg = svgRoot(W, H, 'spark');
    svg.removeAttribute('height'); svg.setAttribute('height', H); svg.setAttribute('preserveAspectRatio', 'none');
    if (!vals.length || !vals.some((v) => v > 0)) return svg;
    const max = Math.max(...vals) || 1;
    const x = (i) => (vals.length <= 1 ? W / 2 : (i / (vals.length - 1)) * (W - 2) + 1);
    const y = (v) => H - 3 - (v / max) * (H - 6);
    const color = opts.color || 'var(--brand)';
    let d = '', area = `M ${x(0)} ${H}`;
    vals.forEach((v, i) => { d += (i ? ' L ' : 'M ') + x(i) + ' ' + y(v); area += ` L ${x(i)} ${y(v)}`; });
    area += ` L ${x(vals.length - 1)} ${H} Z`;
    svg.appendChild(s('path', { d: area, fill: color, 'fill-opacity': '0.14', stroke: 'none' }));
    svg.appendChild(s('path', { d, fill: 'none', stroke: color, 'stroke-width': '1.6', 'stroke-linejoin': 'round', 'stroke-linecap': 'round' }));
    return svg;
  }

  window.SaffevCharts = { lineArea, bars, hbars, donut, heatmap, scatter, histogram, sparkline, fmtNum };
})();
