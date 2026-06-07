//! Studio JSON API + SSE handlers. One handler per route in the contract
//! (see [`crate::studio`] module docs). All return DTOs from [`super::dto`].
//!
//! Every handler reads exclusively through the [`Store`](crate::store::Store)
//! query APIs (and the [`exposure`](crate::exposure) doctor); none touch the
//! request hot path. Errors are mapped to [`dto::ApiError`] envelopes with the
//! status codes specified in the contract (401/403/404/400/500). The control
//! plane fails *loud* here — unlike the proxy, which fails open — because these
//! are operator-facing reads, not inference traffic.

use std::collections::BTreeMap;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures::Stream;
use tokio::sync::broadcast::error::RecvError;

use crate::brain::{PiiKind, Side};
use crate::store::{
    EngineRecord, HistoryQuery, HistoryRow, PiiFindingRecord, RequestMeta, ResponseMeta,
};
use crate::studio::dto;
use crate::studio::StudioState;

/// Default page size for `/api/history` when the client omits `limit`.
const DEFAULT_HISTORY_LIMIT: u32 = 100;
/// Hard upper bound the server clamps `limit` to.
const MAX_HISTORY_LIMIT: u32 = 500;
/// How many recent rows the Live snapshot returns.
const LIVE_RECENT_LIMIT: u32 = 50;
/// Rolling window (millis) for the "today" KPIs on the Live page (24h).
const TODAY_WINDOW_MS: i64 = 24 * 60 * 60 * 1000;

// ---------------------------------------------------------------------------
// Error helper
// ---------------------------------------------------------------------------

/// Helper: build an [`dto::ApiError`] response with the given status.
pub fn api_error(status: StatusCode, code: &str, message: &str) -> Response {
    let body = dto::ApiError {
        error: code.to_string(),
        message: message.to_string(),
    };
    (status, Json(body)).into_response()
}

/// Map any internal `Result` error into a 500 envelope. Used by read handlers.
fn internal(err: impl std::fmt::Display) -> Response {
    api_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal",
        &err.to_string(),
    )
}

// ---------------------------------------------------------------------------
// Row -> DTO mapping
// ---------------------------------------------------------------------------

/// Project a store [`HistoryRow`] (+ the distinct PII kinds present) into the
/// wire [`dto::HistoryItem`].
fn history_item(row: &HistoryRow, pii_kinds: Vec<PiiKind>) -> dto::HistoryItem {
    item_from_parts(&row.request, row.response.as_ref(), row.pii_count, pii_kinds)
}

/// Build a wire [`dto::HistoryItem`] from request (+ optional response) metadata.
/// Shared by the store-row projection AND the proxy's live SSE events so the two
/// stay in lock-step. `latency_ms` falls back to the response's `total_ms` — the
/// request row never carries its own end-to-end time, so without this the Live +
/// History tables and the p50 KPI would always show a blank latency.
pub(crate) fn item_from_parts(
    req: &RequestMeta,
    resp: Option<&ResponseMeta>,
    pii_count: u32,
    pii_kinds: Vec<PiiKind>,
) -> dto::HistoryItem {
    dto::HistoryItem {
        id: req.id.clone(),
        ts: req.ts,
        source_app: req.source_app.clone(),
        source_confidence: req.source_confidence,
        engine: req.engine.clone(),
        model: req.model.clone(),
        endpoint: req.endpoint.clone(),
        stream: req.stream,
        input_tokens: req.input_tokens,
        input_tokens_src: req.input_tokens_src,
        output_tokens: resp.and_then(|r| r.output_tokens),
        output_tokens_src: resp
            .map(|r| r.output_tokens_src)
            .unwrap_or(req.input_tokens_src),
        latency_ms: req.latency_ms.or_else(|| resp.and_then(|r| r.total_ms)),
        ttft_ms: resp.and_then(|r| r.ttft_ms),
        pii_count,
        pii_kinds,
    }
}

/// End-to-end latency for a stored row: the request's own value if set, else the
/// response's measured `total_ms`. Mirrors [`item_from_parts`]'s latency rule so
/// the p50 KPI matches the per-row latency shown in the table.
fn row_latency_ms(row: &HistoryRow) -> Option<u32> {
    row.request
        .latency_ms
        .or_else(|| row.response.as_ref().and_then(|r| r.total_ms))
}

/// Project a store [`PiiFindingRecord`] into the wire [`dto::PiiFindingView`].
pub(crate) fn finding_view(rec: &PiiFindingRecord) -> dto::PiiFindingView {
    dto::PiiFindingView {
        kind: rec.kind,
        label: rec.label.clone(),
        side: rec.side,
        start: rec.start_off,
        end: rec.end_off,
        confidence: rec.confidence,
        action: rec.action,
    }
}

/// Project a store [`EngineRecord`] into the wire [`dto::EngineView`], with a
/// best-effort live `health` string.
fn engine_view(rec: &EngineRecord, health: &str) -> dto::EngineView {
    dto::EngineView {
        engine: rec.engine.clone(),
        version: rec.version.clone(),
        public_port: rec.public_port,
        shadow_port: rec.shadow_port,
        adoption_state: rec.adoption_state,
        health: health.to_string(),
    }
}

/// Project a freshly-detected [`EngineInfo`] (e.g. the Cooperative upstream that
/// has no store row yet) into the wire [`dto::EngineView`]. The probed port is
/// the engine's real port, so it maps to `public_port` with no shadow.
fn detected_engine_view(info: &crate::engine::EngineInfo, health: &str) -> dto::EngineView {
    dto::EngineView {
        engine: crate::engine::detect::engine_name(info.engine).to_string(),
        version: info.version.clone(),
        public_port: info.port,
        shadow_port: None,
        adoption_state: info.adoption_state,
        health: health.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /api/health`
pub async fn health(State(state): State<StudioState>) -> Json<dto::Health> {
    let cfg = state.config.load();
    // proxy_up: best-effort liveness of the local engine/proxy public port.
    let proxy_up = probe_loopback(cfg.ports.proxy).await;
    Json(dto::Health {
        app: crate::brand::APP_NAME.to_lowercase(),
        version: crate::VERSION.to_string(),
        proxy_up,
        mode: cfg.mode,
    })
}

/// `GET /api/live`
pub async fn live(State(state): State<StudioState>) -> Result<Json<dto::LiveSnapshot>, Response> {
    let rows = state
        .store
        .history(HistoryQuery {
            q: None,
            pii_only: false,
            limit: Some(LIVE_RECENT_LIMIT),
            before_ts: None,
        })
        .await
        .map_err(internal)?;

    // Populate PII kinds per row so badges show on seeded rows too (not just live).
    let kinds = kinds_by_record(&state.store.privacy_summary().await.unwrap_or_default());
    let recent: Vec<dto::HistoryItem> = rows
        .iter()
        .map(|r| history_item(r, kinds.get(r.request.id.as_str()).cloned().unwrap_or_default()))
        .collect();

    // KPIs computed off the privacy/finding + history reads. "Today" is the
    // trailing 24h window relative to the newest row's clock (server now).
    let now = now_millis();
    let cutoff = now - TODAY_WINDOW_MS;

    // requests_today + p50 latency over a wider recent window.
    let window = state
        .store
        .history(HistoryQuery {
            q: None,
            pii_only: false,
            limit: Some(MAX_HISTORY_LIMIT),
            before_ts: None,
        })
        .await
        .map_err(internal)?;

    let mut requests_today: u64 = 0;
    let mut latencies: Vec<u32> = Vec::new();
    for r in &window {
        if r.request.ts >= cutoff {
            requests_today += 1;
            if let Some(ms) = row_latency_ms(r) {
                latencies.push(ms);
            }
        }
    }
    let p50_latency_ms = median(&mut latencies);

    // PII findings today: count findings whose parent request is within window.
    let findings = state.store.privacy_summary().await.map_err(internal)?;
    let recent_ids: std::collections::HashSet<&str> = window
        .iter()
        .filter(|r| r.request.ts >= cutoff)
        .map(|r| r.request.id.as_str())
        .collect();
    let pii_findings_today = findings
        .iter()
        .filter(|f| recent_ids.contains(f.record_id.as_str()))
        .count() as u64;

    Ok(Json(dto::LiveSnapshot {
        recent,
        requests_today,
        p50_latency_ms,
        pii_findings_today,
    }))
}

/// `GET /api/history`
pub async fn history(
    State(state): State<StudioState>,
    Query(params): Query<dto::HistoryParams>,
) -> Result<Json<Vec<dto::HistoryItem>>, Response> {
    let limit = params
        .limit
        .unwrap_or(DEFAULT_HISTORY_LIMIT)
        .clamp(1, MAX_HISTORY_LIMIT);

    let rows = state
        .store
        .history(HistoryQuery {
            q: params.q.clone(),
            pii_only: params.pii_only,
            limit: Some(limit),
            before_ts: params.before_ts,
        })
        .await
        .map_err(internal)?;

    let kinds = kinds_by_record(&state.store.privacy_summary().await.unwrap_or_default());
    let items: Vec<dto::HistoryItem> = rows
        .iter()
        .map(|r| history_item(r, kinds.get(r.request.id.as_str()).cloned().unwrap_or_default()))
        .collect();
    Ok(Json(items))
}

/// `GET /api/history/:id`
pub async fn history_detail(
    State(state): State<StudioState>,
    Path(id): Path<String>,
) -> Result<Json<dto::HistoryDetail>, Response> {
    // Find the matching row. The store has no by-id read in the contract, so we
    // page recent history and match; cheap for the single-user local case.
    let rows = state
        .store
        .history(HistoryQuery {
            q: None,
            pii_only: false,
            limit: Some(MAX_HISTORY_LIMIT),
            before_ts: None,
        })
        .await
        .map_err(internal)?;

    let row = rows
        .into_iter()
        .find(|r| r.request.id == id)
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "not_found", "unknown record id"))?;

    // Findings for this record, projected to views.
    let all_findings = state.store.privacy_summary().await.map_err(internal)?;
    let findings: Vec<dto::PiiFindingView> = all_findings
        .iter()
        .filter(|f| f.record_id == id)
        .map(finding_view)
        .collect();
    let kinds = distinct_kinds(&all_findings, &id);

    let item = history_item(&row, kinds);

    // Payloads are present only when payload storage is on (load live snapshot).
    let payloads_disabled = !state.config.load().payload_storage;
    let (prompt, response) = if payloads_disabled {
        (None, None)
    } else {
        match state.store.payload(&id).await.map_err(internal)? {
            Some(p) => (p.prompt, p.response),
            None => (None, None),
        }
    };

    Ok(Json(dto::HistoryDetail {
        item,
        findings,
        prompt,
        response,
        payloads_disabled,
    }))
}

/// `GET /api/privacy`
pub async fn privacy(
    State(state): State<StudioState>,
) -> Result<Json<dto::PrivacySummary>, Response> {
    let findings = state.store.privacy_summary().await.map_err(internal)?;

    // by_kind: bucket per PII kind with request/response split.
    let mut by_kind_map: BTreeMap<String, dto::PrivacyBucket> = BTreeMap::new();
    for f in &findings {
        let key = format!("{:?}", f.kind);
        let bucket = by_kind_map
            .entry(key)
            .or_insert_with(|| dto::PrivacyBucket {
                kind: f.kind,
                count: 0,
                request_count: 0,
                response_count: 0,
            });
        bucket.count += 1;
        match f.side {
            Side::Request => bucket.request_count += 1,
            Side::Response => bucket.response_count += 1,
        }
    }
    let by_kind: Vec<dto::PrivacyBucket> = by_kind_map.into_values().collect();

    // by_app / by_model require joining findings to their parent request meta.
    // Build a record_id -> (app, model) map from recent history.
    let history = state
        .store
        .history(HistoryQuery {
            q: None,
            pii_only: false,
            limit: Some(MAX_HISTORY_LIMIT),
            before_ts: None,
        })
        .await
        .map_err(internal)?;
    let mut meta: BTreeMap<&str, (&Option<String>, &Option<String>)> = BTreeMap::new();
    for r in &history {
        meta.insert(
            r.request.id.as_str(),
            (&r.request.source_app, &r.request.model),
        );
    }

    let mut app_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut model_counts: BTreeMap<String, u64> = BTreeMap::new();
    for f in &findings {
        if let Some((app, model)) = meta.get(f.record_id.as_str()) {
            if let Some(name) = app {
                *app_counts.entry(name.clone()).or_insert(0) += 1;
            }
            if let Some(name) = model {
                *model_counts.entry(name.clone()).or_insert(0) += 1;
            }
        }
    }

    let by_app = named_counts_sorted(app_counts);
    let by_model = named_counts_sorted(model_counts);

    Ok(Json(dto::PrivacySummary {
        by_kind,
        by_app,
        by_model,
        total: findings.len() as u64,
        // Reflect the opt-in masking switch (§7.6). The Privacy page badges
        // dry-run vs live via the Settings view; here we just expose enablement.
        masking_enabled: state.config.load().masking.enabled,
    }))
}

/// Query params for `GET /api/analytics`.
#[derive(serde::Deserialize)]
pub struct AnalyticsParams {
    /// Window length in millis (defaults to 24h; clamped to [1h, 92d]).
    #[serde(rename = "rangeMs")]
    range_ms: Option<i64>,
    /// Client timezone offset from `Date.getTimezoneOffset()` (minutes). Used to
    /// bucket the day×hour heatmap in the user's local time. Defaults to UTC.
    #[serde(rename = "tzOffsetMin")]
    tz_offset_min: Option<i64>,
}

const ANALYTICS_DEFAULT_RANGE_MS: i64 = 24 * 60 * 60 * 1000;
const ANALYTICS_MIN_RANGE_MS: i64 = 60 * 60 * 1000;
const ANALYTICS_MAX_RANGE_MS: i64 = 92 * 24 * 60 * 60 * 1000;
/// Cloud price assumptions for the "cost saved" estimate (USD per 1M tokens).
/// Honest + labeled in the report; not a precise bill, a motivating comparison.
const CLOUD_IN_PER_M: f64 = 2.50; // ~GPT-4o input
const CLOUD_OUT_PER_M: f64 = 10.0; // ~GPT-4o output
const CLOUD_BASIS: &str = "vs GPT-4o cloud pricing";

/// `GET /api/analytics` — comprehensive on-device analytics for a time window.
pub async fn analytics(
    State(state): State<StudioState>,
    Query(params): Query<AnalyticsParams>,
) -> Result<Json<dto::AnalyticsReport>, Response> {
    use std::collections::BTreeMap;

    let now = now_millis();
    let range_ms = params
        .range_ms
        .unwrap_or(ANALYTICS_DEFAULT_RANGE_MS)
        .clamp(ANALYTICS_MIN_RANGE_MS, ANALYTICS_MAX_RANGE_MS);
    let tz_off = params.tz_offset_min.unwrap_or(0);
    let start = now - range_ms;
    let prev_start = start - range_ms;

    // Gather all rows back to prev_start (covers current + previous window for
    // deltas), paginating past the per-query 1000 clamp.
    let mut all: Vec<HistoryRow> = Vec::new();
    let mut cursor: Option<i64> = None;
    loop {
        let batch = state
            .store
            .history(HistoryQuery {
                q: None,
                pii_only: false,
                limit: Some(1000),
                before_ts: cursor,
            })
            .await
            .map_err(internal)?;
        if batch.is_empty() {
            break;
        }
        let oldest = batch.last().map(|r| r.request.ts).unwrap_or(0);
        let exhausted = batch.len() < 1000;
        cursor = Some(oldest);
        let reached = oldest < prev_start;
        all.extend(batch);
        if reached || exhausted || all.len() > 200_000 {
            break;
        }
    }

    let findings = state.store.privacy_summary().await.unwrap_or_default();

    // Latency: request value or response total_ms (mirrors the table/p50).
    let lat = |r: &HistoryRow| -> Option<u32> {
        r.request
            .latency_ms
            .or_else(|| r.response.as_ref().and_then(|x| x.total_ms))
    };

    let cur: Vec<&HistoryRow> = all
        .iter()
        .filter(|r| r.request.ts >= start && r.request.ts <= now)
        .collect();
    let prev: Vec<&HistoryRow> = all
        .iter()
        .filter(|r| r.request.ts >= prev_start && r.request.ts < start)
        .collect();

    // ---- headline ----
    let total_requests = cur.len() as u64;
    let total_input_tokens: u64 = cur
        .iter()
        .filter_map(|r| r.request.input_tokens)
        .map(|v| v as u64)
        .sum();
    let total_output_tokens: u64 = cur
        .iter()
        .filter_map(|r| r.response.as_ref().and_then(|x| x.output_tokens))
        .map(|v| v as u64)
        .sum();
    let mut lats: Vec<u32> = cur.iter().filter_map(|r| lat(r)).collect();
    let p50_latency_ms = percentile(&mut lats, 50);
    let p90_latency_ms = percentile(&mut lats, 90);
    let p99_latency_ms = percentile(&mut lats, 99);
    let ttfts: Vec<u32> = cur
        .iter()
        .filter_map(|r| r.response.as_ref().and_then(|x| x.ttft_ms))
        .collect();
    let avg_ttft_ms = mean_u32(&ttfts);

    let est_cost_saved_usd = (total_input_tokens as f64 / 1_000_000.0) * CLOUD_IN_PER_M
        + (total_output_tokens as f64 / 1_000_000.0) * CLOUD_OUT_PER_M;

    // in-range row lookup + finding attribution
    let mut row_by_id: BTreeMap<&str, &HistoryRow> = BTreeMap::new();
    for r in &cur {
        row_by_id.insert(r.request.id.as_str(), r);
    }
    let in_findings: Vec<&PiiFindingRecord> = findings
        .iter()
        .filter(|f| row_by_id.contains_key(f.record_id.as_str()))
        .collect();
    let pii_findings = in_findings.len() as u64;

    // ---- deltas (previous window) ----
    let prev_total_requests = prev.len() as u64;
    let prev_total_tokens: u64 = prev
        .iter()
        .map(|r| {
            r.request.input_tokens.unwrap_or(0) as u64
                + r.response
                    .as_ref()
                    .and_then(|x| x.output_tokens)
                    .unwrap_or(0) as u64
        })
        .sum();
    let mut prev_lats: Vec<u32> = prev.iter().filter_map(|r| lat(r)).collect();
    let prev_p50_latency_ms = percentile(&mut prev_lats, 50);
    let prev_ids: BTreeMap<&str, ()> =
        prev.iter().map(|r| (r.request.id.as_str(), ())).collect();
    let prev_pii_findings = findings
        .iter()
        .filter(|f| prev_ids.contains_key(f.record_id.as_str()))
        .count() as u64;

    // ---- time series ----
    let bucket_ms = analytics_bucket_ms(range_ms);
    let n_buckets = ((range_ms + bucket_ms - 1) / bucket_ms).max(1) as usize;
    let mut bkt_req = vec![0u64; n_buckets];
    let mut bkt_in = vec![0u64; n_buckets];
    let mut bkt_out = vec![0u64; n_buckets];
    let mut bkt_pii = vec![0u64; n_buckets];
    let mut bkt_lat: Vec<Vec<u32>> = vec![Vec::new(); n_buckets];
    let bidx = |ts: i64| -> usize {
        (((ts - start) / bucket_ms).max(0) as usize).min(n_buckets - 1)
    };
    for r in &cur {
        let i = bidx(r.request.ts);
        bkt_req[i] += 1;
        bkt_in[i] += r.request.input_tokens.unwrap_or(0) as u64;
        bkt_out[i] += r.response.as_ref().and_then(|x| x.output_tokens).unwrap_or(0) as u64;
        if let Some(l) = lat(r) {
            bkt_lat[i].push(l);
        }
    }
    for f in &in_findings {
        if let Some(r) = row_by_id.get(f.record_id.as_str()) {
            bkt_pii[bidx(r.request.ts)] += 1;
        }
    }
    let series: Vec<dto::AnalyticsBucket> = (0..n_buckets)
        .map(|i| dto::AnalyticsBucket {
            ts: start + (i as i64) * bucket_ms,
            requests: bkt_req[i],
            input_tokens: bkt_in[i],
            output_tokens: bkt_out[i],
            p50_latency_ms: percentile(&mut bkt_lat[i], 50),
            pii: bkt_pii[i],
        })
        .collect();

    // ---- breakdowns: by app / endpoint ----
    #[derive(Default)]
    struct Acc {
        requests: u64,
        in_tok: u64,
        out_tok: u64,
        lat: Vec<u32>,
        pii: u64,
    }
    let mut apps: BTreeMap<String, Acc> = BTreeMap::new();
    let mut endpoints: BTreeMap<String, Acc> = BTreeMap::new();
    // models need ttft + tps
    #[derive(Default)]
    struct MAcc {
        requests: u64,
        in_tok: u64,
        out_tok: u64,
        lat: Vec<u32>,
        ttft: Vec<u32>,
        tps: Vec<f64>,
    }
    let mut models: BTreeMap<String, MAcc> = BTreeMap::new();

    for r in &cur {
        let app = r.request.source_app.clone().unwrap_or_else(|| "Unknown".into());
        let a = apps.entry(app).or_default();
        a.requests += 1;
        a.in_tok += r.request.input_tokens.unwrap_or(0) as u64;
        a.out_tok += r.response.as_ref().and_then(|x| x.output_tokens).unwrap_or(0) as u64;
        if let Some(l) = lat(r) {
            a.lat.push(l);
        }

        let ep = r.request.endpoint.clone();
        let e = endpoints.entry(ep).or_default();
        e.requests += 1;
        e.in_tok += r.request.input_tokens.unwrap_or(0) as u64;
        e.out_tok += r.response.as_ref().and_then(|x| x.output_tokens).unwrap_or(0) as u64;
        if let Some(l) = lat(r) {
            e.lat.push(l);
        }

        let model = match r.request.model.as_deref() {
            Some(s) if !s.trim().is_empty() => s.to_string(),
            _ => "unknown".into(),
        };
        let m = models.entry(model).or_default();
        m.requests += 1;
        m.in_tok += r.request.input_tokens.unwrap_or(0) as u64;
        let out = r.response.as_ref().and_then(|x| x.output_tokens).unwrap_or(0);
        m.out_tok += out as u64;
        if let Some(l) = lat(r) {
            m.lat.push(l);
        }
        if let Some(resp) = r.response.as_ref() {
            if let Some(t) = resp.ttft_ms {
                m.ttft.push(t);
            }
            // decode throughput: output tokens / (total - ttft) seconds. Require a
            // ≥50ms decode window so a near-zero denominator can't fabricate a
            // wildly inflated tok/s.
            if let (Some(total), Some(t), o) = (resp.total_ms, resp.ttft_ms, out) {
                if o > 1 && total >= t + 50 {
                    let secs = (total - t) as f64 / 1000.0;
                    m.tps.push(o as f64 / secs);
                }
            }
        }
    }
    // attribute pii to app/endpoint
    for f in &in_findings {
        if let Some(r) = row_by_id.get(f.record_id.as_str()) {
            if let Some(a) = apps.get_mut(
                r.request.source_app.as_deref().unwrap_or("Unknown"),
            ) {
                a.pii += 1;
            }
            if let Some(e) = endpoints.get_mut(r.request.endpoint.as_str()) {
                e.pii += 1;
            }
        }
    }
    let mut by_app: Vec<dto::GroupStat> = apps
        .into_iter()
        .map(|(name, mut a)| dto::GroupStat {
            name,
            requests: a.requests,
            input_tokens: a.in_tok,
            output_tokens: a.out_tok,
            avg_latency_ms: percentile(&mut a.lat, 50),
            pii: a.pii,
        })
        .collect();
    by_app.sort_by(|x, y| y.requests.cmp(&x.requests));
    by_app.truncate(12);

    let mut by_endpoint: Vec<dto::GroupStat> = endpoints
        .into_iter()
        .map(|(name, mut e)| dto::GroupStat {
            name,
            requests: e.requests,
            input_tokens: e.in_tok,
            output_tokens: e.out_tok,
            avg_latency_ms: percentile(&mut e.lat, 50),
            pii: e.pii,
        })
        .collect();
    by_endpoint.sort_by(|x, y| y.requests.cmp(&x.requests));
    by_endpoint.truncate(12);

    let mut by_model: Vec<dto::ModelStat> = models
        .into_iter()
        .map(|(name, mut m)| dto::ModelStat {
            name,
            requests: m.requests,
            input_tokens: m.in_tok,
            output_tokens: m.out_tok,
            p50_latency_ms: percentile(&mut m.lat, 50),
            avg_ttft_ms: mean_u32(&m.ttft),
            tokens_per_sec: median_f64(&m.tps).map(|v| (v * 10.0).round() / 10.0),
        })
        .collect();
    by_model.sort_by(|x, y| y.requests.cmp(&x.requests));
    by_model.truncate(12);

    // ---- performance distributions ----
    let ttft_histogram = histogram(&ttfts, &[0, 100, 250, 500, 1000, 2000, 5000, 10000]);
    let in_tokens_vec: Vec<u32> = cur.iter().filter_map(|r| r.request.input_tokens).collect();
    let input_token_histogram =
        histogram(&in_tokens_vec, &[0, 50, 100, 250, 500, 1000, 2000, 4000]);

    // scatter: output tokens vs latency (sampled to keep payload light)
    let mut scatter_src: Vec<(u32, u32)> = cur
        .iter()
        .filter_map(|r| {
            let o = r.response.as_ref().and_then(|x| x.output_tokens)?;
            let l = lat(r)?;
            Some((o, l))
        })
        .collect();
    let latency_vs_output = sample_xy(&mut scatter_src, 400);

    // finish reasons
    let mut fr: BTreeMap<String, u64> = BTreeMap::new();
    for r in &cur {
        let reason = r
            .response
            .as_ref()
            .and_then(|x| x.finish_reason.clone())
            .unwrap_or_else(|| "unknown".into());
        *fr.entry(reason).or_insert(0) += 1;
    }
    let mut finish_reasons: Vec<dto::NamedCount> = fr
        .into_iter()
        .map(|(name, count)| dto::NamedCount { name, count })
        .collect();
    finish_reasons.sort_by(|a, b| b.count.cmp(&a.count));

    // slowest exchanges
    let mut slow_rows: Vec<&HistoryRow> = cur.clone();
    slow_rows.sort_by(|a, b| lat(b).unwrap_or(0).cmp(&lat(a).unwrap_or(0)));
    let slowest: Vec<dto::HistoryItem> = slow_rows
        .iter()
        .take(8)
        .map(|r| history_item(r, Vec::new()))
        .collect();

    // ---- heatmap (local day×hour) ----
    let mut heat: BTreeMap<(u8, u8), u64> = BTreeMap::new();
    for r in &cur {
        let (dow, hour) = local_dow_hour(r.request.ts, tz_off);
        *heat.entry((dow, hour)).or_insert(0) += 1;
    }
    let heatmap: Vec<dto::HeatCell> = heat
        .into_iter()
        .map(|((dow, hour), count)| dto::HeatCell { dow, hour, count })
        .collect();

    // ---- privacy ----
    let mut kind_map: BTreeMap<String, dto::PiiKindStat> = BTreeMap::new();
    let mut action_map: BTreeMap<String, u64> = BTreeMap::new();
    let mut pii_app_map: BTreeMap<String, u64> = BTreeMap::new();
    let (mut pii_req, mut pii_resp) = (0u64, 0u64);
    for f in &in_findings {
        let entry = kind_map
            .entry(format!("{:?}", f.kind))
            .or_insert_with(|| dto::PiiKindStat {
                kind: f.kind,
                request_count: 0,
                response_count: 0,
            });
        match f.side {
            Side::Request => {
                entry.request_count += 1;
                pii_req += 1;
            }
            Side::Response => {
                entry.response_count += 1;
                pii_resp += 1;
            }
        }
        *action_map.entry(format!("{:?}", f.action)).or_insert(0) += 1;
        if let Some(r) = row_by_id.get(f.record_id.as_str()) {
            if let Some(app) = r.request.source_app.as_ref() {
                *pii_app_map.entry(app.clone()).or_insert(0) += 1;
            }
        }
    }
    let pii_by_kind: Vec<dto::PiiKindStat> = {
        let mut v: Vec<_> = kind_map.into_values().collect();
        v.sort_by(|a, b| {
            (b.request_count + b.response_count).cmp(&(a.request_count + a.response_count))
        });
        v
    };
    let pii_by_action = named_counts_sorted(action_map);
    let pii_by_app = named_counts_sorted(pii_app_map);

    // ---- insights ----
    let insights = build_insights(
        total_requests,
        total_output_tokens,
        est_cost_saved_usd,
        p50_latency_ms,
        prev_p50_latency_ms,
        &by_model,
        &pii_by_app,
        pii_req,
        &finish_reasons,
    );

    Ok(Json(dto::AnalyticsReport {
        range_ms,
        generated_ts: now,
        bucket_ms,
        total_requests,
        total_input_tokens,
        total_output_tokens,
        p50_latency_ms,
        p90_latency_ms,
        p99_latency_ms,
        avg_ttft_ms,
        pii_findings,
        active_apps: by_app.len() as u64,
        active_models: by_model.len() as u64,
        est_cost_saved_usd: (est_cost_saved_usd * 100.0).round() / 100.0,
        cost_basis: CLOUD_BASIS.to_string(),
        prev_total_requests,
        prev_total_tokens,
        prev_p50_latency_ms,
        prev_pii_findings,
        series,
        by_app,
        by_model,
        by_endpoint,
        ttft_histogram,
        input_token_histogram,
        latency_vs_output,
        finish_reasons,
        slowest,
        heatmap,
        pii_by_kind,
        pii_by_action,
        pii_by_app,
        pii_request_side: pii_req,
        pii_response_side: pii_resp,
        insights,
    }))
}

/// Pick a time-series bucket width that yields a readable number of buckets.
fn analytics_bucket_ms(range_ms: i64) -> i64 {
    const MIN: i64 = 60 * 1000;
    const HOUR: i64 = 60 * MIN;
    const DAY: i64 = 24 * HOUR;
    if range_ms <= 2 * HOUR {
        5 * MIN
    } else if range_ms <= 24 * HOUR {
        HOUR
    } else if range_ms <= 2 * DAY {
        2 * HOUR
    } else if range_ms <= 7 * DAY {
        6 * HOUR
    } else {
        DAY
    }
}

/// Local (day-of-week 0=Sun, hour 0..23) from a unix-millis + tz offset (minutes
/// as `Date.getTimezoneOffset()` reports — local = utc - offset*60_000).
fn local_dow_hour(utc_ms: i64, tz_offset_min: i64) -> (u8, u8) {
    let local = utc_ms - tz_offset_min * 60_000;
    let day_ms = 86_400_000i64;
    let days = local.div_euclid(day_ms);
    let rem = local.rem_euclid(day_ms);
    let hour = (rem / 3_600_000) as u8;
    // 1970-01-01 was a Thursday (=4); 0=Sunday.
    let dow = (((days % 7) + 4 + 7) % 7) as u8;
    (dow, hour.min(23))
}

/// Bucket `values` into bins defined by ascending `edges`; the last bin is open.
fn histogram(values: &[u32], edges: &[u32]) -> Vec<dto::HistBin> {
    let mut bins: Vec<dto::HistBin> = Vec::new();
    for i in 0..edges.len() {
        let lo = edges[i];
        let hi = edges.get(i + 1).copied().unwrap_or(u32::MAX);
        bins.push(dto::HistBin { lo, hi, count: 0 });
    }
    for &v in values {
        let idx = edges
            .iter()
            .rposition(|&e| v >= e)
            .unwrap_or(0)
            .min(bins.len() - 1);
        bins[idx].count += 1;
    }
    bins
}

/// Down-sample (x,y) pairs to at most `max` points (stride sampling).
fn sample_xy(pairs: &mut [(u32, u32)], max: usize) -> Vec<dto::XYPoint> {
    if pairs.is_empty() {
        return Vec::new();
    }
    let step = (pairs.len() + max - 1) / max;
    pairs
        .iter()
        .step_by(step.max(1))
        .map(|&(x, y)| dto::XYPoint {
            x: x as f64,
            y: y as f64,
        })
        .collect()
}

/// Derive a handful of plain-english, actionable insights from the aggregates.
#[allow(clippy::too_many_arguments)]
fn build_insights(
    total_requests: u64,
    total_output_tokens: u64,
    cost_saved: f64,
    p50: Option<u32>,
    prev_p50: Option<u32>,
    by_model: &[dto::ModelStat],
    pii_by_app: &[dto::NamedCount],
    pii_request_side: u64,
    finish_reasons: &[dto::NamedCount],
) -> Vec<dto::Insight> {
    let mut out: Vec<dto::Insight> = Vec::new();
    if total_requests == 0 {
        out.push(dto::Insight {
            severity: "info".into(),
            title: "No traffic yet in this window".into(),
            detail: "Point an app at the proxy (see About & integrate) and activity will show up here.".into(),
        });
        return out;
    }
    if cost_saved >= 0.01 {
        out.push(dto::Insight {
            severity: "good".into(),
            title: format!("≈ ${:.2} kept off the cloud", cost_saved),
            detail: format!(
                "{} requests · {} output tokens ran on-device {}.",
                total_requests, total_output_tokens, CLOUD_BASIS
            ),
        });
    }
    // fastest vs slowest model by throughput
    let mut tps: Vec<(&str, f64)> = by_model
        .iter()
        .filter_map(|m| m.tokens_per_sec.map(|t| (m.name.as_str(), t)))
        .collect();
    if tps.len() >= 2 {
        tps.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        let (fast, ft) = tps[0];
        let (slow, st) = *tps.last().unwrap();
        if st > 0.0 && ft / st >= 1.5 {
            out.push(dto::Insight {
                severity: "info".into(),
                title: format!("{} is your fastest model", fast),
                detail: format!(
                    "{} decodes at ~{:.0} tok/s vs ~{:.0} tok/s for {} — prefer it for latency-sensitive work.",
                    fast, ft, st, slow
                ),
            });
        }
    }
    // latency trend
    if let (Some(p), Some(pp)) = (p50, prev_p50) {
        if pp > 0 && p as f64 / pp as f64 >= 1.3 {
            out.push(dto::Insight {
                severity: "warn".into(),
                title: "Latency is trending up".into(),
                detail: format!(
                    "Median latency rose from {}ms to {}ms vs the previous period.",
                    pp, p
                ),
            });
        }
    }
    // PII leak source
    if pii_request_side > 0 {
        if let Some(top) = pii_by_app.first() {
            out.push(dto::Insight {
                severity: "warn".into(),
                title: format!("{} sends the most PII to the model", top.name),
                detail: format!(
                    "{} findings on request bodies from {}. Consider enabling PII masking for it (Settings → Privacy & data).",
                    top.count, top.name
                ),
            });
        }
    }
    // length-capped responses
    let total_fr: u64 = finish_reasons.iter().map(|f| f.count).sum();
    if let Some(len) = finish_reasons.iter().find(|f| f.name == "length") {
        if total_fr > 0 && (len.count as f64 / total_fr as f64) >= 0.2 {
            out.push(dto::Insight {
                severity: "warn".into(),
                title: "Many responses hit the length limit".into(),
                detail: format!(
                    "{}% of responses stopped at the token cap — consider raising num_predict / max_tokens.",
                    (len.count * 100 / total_fr)
                ),
            });
        }
    }
    out
}

/// `GET /api/engines`
pub async fn engines(State(state): State<StudioState>) -> Result<Json<dto::EnginesView>, Response> {
    let cfg = state.config.load();
    let records = state.store.engines().await.map_err(internal)?;

    // Health is best-effort: probe each engine's effective port (shadow if
    // adopted, else public). Down on any probe failure — never fail the call.
    let mut views = Vec::with_capacity(records.len());
    for rec in &records {
        let port = rec.shadow_port.unwrap_or(rec.public_port);
        let health = if probe_loopback(port).await {
            "healthy"
        } else {
            "down"
        };
        views.push(engine_view(rec, health));
    }

    // Cooperative mode never adopts the engine, so it has no `engines` row of
    // its own and the panel would otherwise read "No engine detected". Probe
    // the configured upstream the proxy forwards to and surface that engine
    // here, unless a store record already covers the same port. Fail-soft: a
    // silent upstream just adds nothing.
    let upstream = cfg.ports.upstream;
    let already_known = records
        .iter()
        .any(|r| r.shadow_port.unwrap_or(r.public_port) == upstream || r.public_port == upstream);
    if !already_known {
        if let Ok(Some(info)) = crate::engine::detect::probe_upstream(upstream).await {
            let health = if probe_loopback(info.port).await {
                "healthy"
            } else {
                "down"
            };
            views.push(detected_engine_view(&info, health));
        }
    }

    // Exposure doctor verdict against the public proxy port. Fail-soft to a
    // benign "not exposed / unknown" report so the Engines page still renders.
    let exposure = crate::exposure::check(cfg.ports.upstream)
        .await
        .unwrap_or_else(|_| crate::exposure::ExposureReport {
            exposed: false,
            bound_to: None,
            token_protected: false,
            detail: "exposure check unavailable".to_string(),
        });

    Ok(Json(dto::EnginesView {
        engines: views,
        mode: cfg.mode,
        exposure,
    }))
}

/// `POST /api/engines/adopt`
pub async fn engines_adopt(
    State(state): State<StudioState>,
    Json(body): Json<dto::AdoptRequest>,
) -> Result<Json<dto::EngineView>, Response> {
    if body.engine.trim().is_empty() {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "validation",
            "engine name is required",
        ));
    }

    // Return the current view of the named engine after the (engine-module
    // owned) adoption runs. We surface whatever the store reflects; the actual
    // controller wiring lives in the engine/cli modules. If the engine is not
    // yet known, report a 404 so the UI can prompt detection.
    current_engine_view(&state, &body.engine).await.map(Json)
}

/// `POST /api/engines/revert`
pub async fn engines_revert(
    State(state): State<StudioState>,
    Json(body): Json<dto::RevertRequest>,
) -> Result<Json<dto::EngineView>, Response> {
    if body.engine.trim().is_empty() {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "validation",
            "engine name is required",
        ));
    }
    current_engine_view(&state, &body.engine).await.map(Json)
}

/// `GET /api/exposure`
pub async fn exposure(
    State(state): State<StudioState>,
) -> Result<Json<crate::exposure::ExposureReport>, Response> {
    let report = crate::exposure::check(state.config.load().ports.upstream)
        .await
        .unwrap_or_else(|_| crate::exposure::ExposureReport {
            exposed: false,
            bound_to: None,
            token_protected: false,
            detail: "exposure check unavailable".to_string(),
        });
    Ok(Json(report))
}

/// `GET /api/update`
///
/// Reports the current vs latest released version + whether an update is
/// available. **Fail-soft**: any network error degrades to `updateAvailable =
/// false` with a null `latestVersion` (the SPA then just shows no banner). Safe
/// to call on every Studio load.
///
/// PRIVACY: this is the ONE outbound call the Studio makes besides the local
/// engine, and it contacts **GitHub release metadata only** — it sends no user
/// or content data. Consistent with the on-device / no-telemetry invariant. The
/// `_state` is unused (the check needs no store/config) but kept for a uniform
/// handler signature + future auth context.
pub async fn update_get(State(_state): State<StudioState>) -> Json<dto::UpdateStatus> {
    let status = crate::update::check().await;
    Json(dto::UpdateStatus {
        current_version: status.current_version,
        latest_version: status.latest_version,
        update_available: status.available,
    })
}

/// `POST /api/update`
///
/// Applies an available update via the shipped installer and reports the result.
/// The no-receipt case (a dev / `cargo install` binary) is **not** a 500 — it is
/// a 200 with `updated = false` and a clear guidance message, so the SPA can tell
/// the user how to enable updates without treating it as an error. A genuine
/// apply failure (download/installer) maps to a 500 envelope.
///
/// PRIVACY: contacts GitHub release metadata + the installer asset only.
pub async fn update_post(
    State(_state): State<StudioState>,
) -> Result<Json<dto::UpdateResult>, Response> {
    match crate::update::apply().await {
        Ok(outcome) => {
            let message = if outcome.updated {
                format!(
                    "v{} installed — restart Saffev to run the new version",
                    outcome.new_version
                )
            } else {
                format!("already on the latest version (v{})", outcome.new_version)
            };
            Ok(Json(dto::UpdateResult {
                updated: outcome.updated,
                new_version: outcome.new_version,
                message,
            }))
        }
        // No install receipt (dev build): a 200 with guidance, NOT an error —
        // the UI shows "use the installer" rather than a failure toast.
        Err(crate::update::UpdateError::NoReceipt(msg)) => Ok(Json(dto::UpdateResult {
            updated: false,
            new_version: crate::update::CURRENT_VERSION.to_string(),
            message: msg,
        })),
        // A real apply failure — surface it as a 500 envelope.
        Err(crate::update::UpdateError::Failed(msg)) => Err(api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "update_failed",
            &msg,
        )),
    }
}

/// `POST /api/restart` — relaunch the daemon with the current on-disk binary.
///
/// Spawns a detached helper that stops this process (freeing the ports) and
/// starts a fresh one. Used right after a successful in-app update so the new
/// version takes effect without the user opening a terminal. The SPA polls
/// `/api/health` afterwards and reloads once the new daemon answers.
pub async fn restart(State(_state): State<StudioState>) -> Result<Json<dto::RestartResult>, Response> {
    crate::cli::daemon::spawn_restart_helper().map_err(internal)?;
    Ok(Json(dto::RestartResult { restarting: true }))
}

/// `GET /api/settings`
///
/// Reads the **live** config snapshot (`state.config.load()`), so it reflects any
/// hot-reloadable change a prior `PUT /api/settings` swapped in — without a
/// restart.
pub async fn settings_get(
    State(state): State<StudioState>,
) -> Result<Json<dto::SettingsView>, Response> {
    Ok(Json(settings_view(&state.config.load())))
}

/// `PUT /api/settings`
///
/// Builds the updated config from the **current live snapshot** plus the PUT
/// fields, persists it to TOML (write-through), and — for the hot-reloadable
/// fields — swaps it into the shared [`ConfigHandle`](crate::config::ConfigHandle)
/// so the running proxy *and* Studio see the change immediately, no restart.
///
/// SCOPE / SAFETY (honest by design):
/// - **Hot-reloadable** (apply live): `payload_storage`, `retention`, masking
///   (`enabled`/`dry_run`), and `handover` (the supervisor only reads it on stop).
/// - **NOT runtime-changeable**: `mode` (and ports) rebind the proxy/Studio
///   listeners and re-adopt the engine. We persist `mode` to TOML so the next
///   `saffev start` picks it up, but we do **not** swap it into the live config;
///   it is reported in `restart_required` so the operator knows a restart is
///   needed. The returned view reflects the *still-running* mode.
pub async fn settings_put(
    State(state): State<StudioState>,
    Json(body): Json<dto::SettingsUpdate>,
) -> Result<Json<dto::SettingsView>, Response> {
    use std::sync::Arc;

    // Base everything on the CURRENT live snapshot, not a startup capture.
    let current = state.config.load_full();

    // `persisted`: the full config written to TOML (includes mode for next start).
    // `live`: the config we will swap into the handle (hot-reloadable fields only;
    //          mode is intentionally left at the running value).
    let mut persisted = (*current).clone();
    let mut live = (*current).clone();
    let mut restart_required: Vec<String> = Vec::new();

    // mode — NOT runtime-changeable: persist only, flag restart-required.
    if let Some(mode) = body.mode {
        if mode != current.mode {
            persisted.mode = mode;
            restart_required.push("mode".to_string());
            // Audit the persisted intent (it applies on the next start).
            state.store.enqueue(crate::store::WriteOp::Setting {
                key: "mode".to_string(),
                value: format!("{:?}", mode).to_lowercase(),
            });
        }
    }

    // payload_storage — HOT-RELOADABLE.
    if let Some(payload_storage) = body.payload_storage {
        persisted.payload_storage = payload_storage;
        live.payload_storage = payload_storage;
        // Toggling payload storage is an explicit, logged action (04 §7.9).
        state.store.enqueue(crate::store::WriteOp::Setting {
            key: "payload_storage".to_string(),
            value: payload_storage.to_string(),
        });
    }

    // retention — HOT-RELOADABLE.
    if let Some(retention) = body.retention {
        persisted.retention = retention;
        live.retention = retention;
        state.store.enqueue(crate::store::WriteOp::Setting {
            key: "retention".to_string(),
            value: serde_json::to_string(&retention).unwrap_or_default(),
        });
    }

    // handover — HOT-RELOADABLE (read by the supervisor at stop time).
    if let Some(handover) = body.handover {
        persisted.handover = handover;
        live.handover = handover;
        state.store.enqueue(crate::store::WriteOp::Setting {
            key: "handover".to_string(),
            value: format!("{:?}", handover).to_lowercase(),
        });
    }

    // masking.enabled — HOT-RELOADABLE.
    if let Some(masking_enabled) = body.masking_enabled {
        persisted.masking.enabled = masking_enabled;
        live.masking.enabled = masking_enabled;
        // Enabling masking is an explicit, logged action (04 §7.6, §7.9).
        state.store.enqueue(crate::store::WriteOp::Setting {
            key: "masking_enabled".to_string(),
            value: masking_enabled.to_string(),
        });
    }

    // masking.dry_run — HOT-RELOADABLE.
    if let Some(masking_dry_run) = body.masking_dry_run {
        persisted.masking.dry_run = masking_dry_run;
        live.masking.dry_run = masking_dry_run;
        // Leaving dry-run (dry_run=false) is the step that turns on real request
        // redaction — log it explicitly.
        state.store.enqueue(crate::store::WriteOp::Setting {
            key: "masking_dry_run".to_string(),
            value: masking_dry_run.to_string(),
        });
    }

    // Persist the full config (write-through to TOML). The token is never touched.
    persisted.save().map_err(internal)?;

    // Swap the hot-reloadable config into the shared handle so BOTH running
    // servers observe it immediately. `mode` stays at the running value in `live`,
    // so this never changes mode mid-process even though `persisted` recorded it.
    state.config.store(Arc::new(live));

    // The returned view reflects the now-live config; restart_required surfaces any
    // persisted-but-not-applied field (currently only mode).
    let mut view = settings_view(&state.config.load());
    if !restart_required.is_empty() {
        view.restart_note = Some(format!(
            "{} saved to config but require a `saffev start` to apply \
             (they rebind ports / re-adopt the engine).",
            restart_required.join(", ")
        ));
        view.restart_required = restart_required;
    }
    Ok(Json(view))
}

/// `GET /api/stream` — Server-Sent Events of [`dto::StreamEvent`].
///
/// Subscribes to the live broadcast channel in [`StudioState`] and serializes
/// each [`dto::StreamEvent`] as a JSON SSE `data:` frame. A keep-alive comment
/// is emitted on idle so proxies/browsers hold the connection. Lagged events
/// (a slow client) are silently skipped — the live feed is best-effort, the
/// store remains the source of truth.
pub async fn stream(
    State(state): State<StudioState>,
) -> Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>> {
    let rx = state.events.subscribe();

    // Drive the broadcast receiver as a stream without pulling in `tokio-stream`.
    // `unfold` yields one SSE frame per received event; lagged events (slow
    // subscriber) are skipped, and channel close ends the stream cleanly.
    let s = futures::stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(evt) => {
                    if let Ok(json) = serde_json::to_string(&evt) {
                        return Some((Ok(Event::default().data(json)), rx));
                    }
                    // Unserializable event (should not happen) — skip, keep going.
                }
                Err(RecvError::Lagged(_)) => {
                    // Slow subscriber fell behind: drop and continue. The store
                    // remains the source of truth; the UI can re-fetch.
                }
                Err(RecvError::Closed) => return None,
            }
        }
    });

    Sse::new(s).keep_alive(KeepAlive::default())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Build a [`dto::SettingsView`] from a config (token intentionally excluded).
///
/// The `restart_required` / `restart_note` fields are empty here; `settings_put`
/// fills them in when a persisted-but-not-hot-applied field (mode/ports) changed.
fn settings_view(cfg: &crate::config::Config) -> dto::SettingsView {
    dto::SettingsView {
        mode: cfg.mode,
        payload_storage: cfg.payload_storage,
        retention: cfg.retention,
        handover: cfg.handover,
        data_dir: cfg.data_dir.display().to_string(),
        custom_patterns: cfg.custom_patterns.iter().map(|p| p.name.clone()).collect(),
        proxy_port: cfg.ports.proxy,
        studio_port: cfg.ports.studio,
        masking_enabled: cfg.masking.enabled,
        masking_dry_run: cfg.masking.dry_run,
        restart_required: Vec::new(),
        restart_note: None,
    }
}

/// Read the current store view of a named engine, 404 if not yet detected.
async fn current_engine_view(
    state: &StudioState,
    engine: &str,
) -> Result<dto::EngineView, Response> {
    let records = state.store.engines().await.map_err(internal)?;
    let rec = records
        .into_iter()
        .find(|r| r.engine.eq_ignore_ascii_case(engine))
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "not_found", "unknown engine"))?;
    let port = rec.shadow_port.unwrap_or(rec.public_port);
    let health = if probe_loopback(port).await {
        "healthy"
    } else {
        "down"
    };
    Ok(engine_view(&rec, health))
}

/// Distinct PII kinds present on a given record id, for the history badge.
fn distinct_kinds(findings: &[PiiFindingRecord], record_id: &str) -> Vec<PiiKind> {
    let mut seen: Vec<PiiKind> = Vec::new();
    for f in findings.iter().filter(|f| f.record_id == record_id) {
        if !seen.contains(&f.kind) {
            seen.push(f.kind);
        }
    }
    seen
}

/// One pass over all findings → `record_id` → distinct PII kinds. Lets the
/// Live/History feeds show PII badges on every row (not only live SSE rows).
fn kinds_by_record(findings: &[PiiFindingRecord]) -> std::collections::BTreeMap<String, Vec<PiiKind>> {
    let mut map: std::collections::BTreeMap<String, Vec<PiiKind>> = std::collections::BTreeMap::new();
    for f in findings {
        let v = map.entry(f.record_id.clone()).or_default();
        if !v.contains(&f.kind) {
            v.push(f.kind);
        }
    }
    map
}

/// Sort a `name -> count` map into descending [`dto::NamedCount`] list.
fn named_counts_sorted(map: BTreeMap<String, u64>) -> Vec<dto::NamedCount> {
    let mut v: Vec<dto::NamedCount> = map
        .into_iter()
        .map(|(name, count)| dto::NamedCount { name, count })
        .collect();
    v.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    v
}

/// Median of a latency sample (mutates: sorts in place). `None` if empty.
fn median(samples: &mut [u32]) -> Option<u32> {
    if samples.is_empty() {
        return None;
    }
    samples.sort_unstable();
    Some(samples[samples.len() / 2])
}

/// p-th percentile (0..100) of a sample (mutates: sorts in place). `None` if empty.
fn percentile(samples: &mut [u32], p: u8) -> Option<u32> {
    if samples.is_empty() {
        return None;
    }
    samples.sort_unstable();
    let n = samples.len();
    let idx = ((p as usize) * (n - 1) + 50) / 100; // nearest-rank, rounded
    Some(samples[idx.min(n - 1)])
}

/// Integer mean of a sample. `None` if empty.
fn mean_u32(samples: &[u32]) -> Option<u32> {
    if samples.is_empty() {
        return None;
    }
    let sum: u64 = samples.iter().map(|&v| v as u64).sum();
    Some((sum / samples.len() as u64) as u32)
}

/// Median of an f64 sample (clones+sorts). `None` if empty.
fn median_f64(samples: &[f64]) -> Option<f64> {
    if samples.is_empty() {
        return None;
    }
    let mut v = samples.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    Some(v[v.len() / 2])
}

/// Current wall-clock time in unix millis.
fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Best-effort TCP connect probe to `127.0.0.1:port`. Used for liveness/health.
/// Never errors out — returns `false` on any failure (fail-soft on the UI path).
async fn probe_loopback(port: u16) -> bool {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    matches!(
        tokio::time::timeout(
            std::time::Duration::from_millis(200),
            tokio::net::TcpStream::connect(addr),
        )
        .await,
        Ok(Ok(_))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::brain::Confidence;
    use crate::store::{PiiAction, SourceConfidence, TokenSource};

    fn sample_request(id: &str, ts: i64) -> RequestMeta {
        RequestMeta {
            id: id.to_string(),
            ts,
            source_app: Some("zed".to_string()),
            source_confidence: SourceConfidence::Pid,
            engine: "ollama".to_string(),
            model: Some("llama3".to_string()),
            endpoint: "/api/chat".to_string(),
            stream: true,
            input_tokens: Some(12),
            input_tokens_src: TokenSource::Exact,
            latency_ms: Some(40),
            request_hash: "deadbeef".to_string(),
        }
    }

    fn sample_response(id: &str) -> ResponseMeta {
        ResponseMeta {
            request_id: id.to_string(),
            finish_reason: Some("stop".to_string()),
            output_tokens: Some(99),
            output_tokens_src: TokenSource::Estimated,
            ttft_ms: Some(15),
            total_ms: Some(120),
        }
    }

    #[test]
    fn history_item_maps_fields() {
        let row = HistoryRow {
            request: sample_request("r1", 1000),
            response: Some(sample_response("r1")),
            pii_count: 2,
        };
        let item = history_item(&row, vec![PiiKind::Email]);
        assert_eq!(item.id, "r1");
        assert_eq!(item.ts, 1000);
        assert_eq!(item.source_app.as_deref(), Some("zed"));
        assert_eq!(item.model.as_deref(), Some("llama3"));
        assert_eq!(item.input_tokens, Some(12));
        assert_eq!(item.output_tokens, Some(99));
        assert_eq!(item.output_tokens_src, TokenSource::Estimated);
        assert_eq!(item.ttft_ms, Some(15));
        assert_eq!(item.pii_count, 2);
        assert_eq!(item.pii_kinds, vec![PiiKind::Email]);
        assert!(item.stream);
    }

    #[test]
    fn history_item_without_response() {
        let row = HistoryRow {
            request: sample_request("r2", 2000),
            response: None,
            pii_count: 0,
        };
        let item = history_item(&row, Vec::new());
        assert_eq!(item.output_tokens, None);
        assert_eq!(item.ttft_ms, None);
        // src falls back to input src when no response yet.
        assert_eq!(item.output_tokens_src, TokenSource::Exact);
    }

    #[test]
    fn distinct_kinds_dedups_and_filters() {
        let findings = vec![
            PiiFindingRecord {
                id: 1,
                record_id: "a".to_string(),
                side: Side::Request,
                kind: PiiKind::Email,
                label: None,
                start_off: 0,
                end_off: 5,
                confidence: Confidence::High,
                action: PiiAction::Observed,
                value_hash: "h1".to_string(),
            },
            PiiFindingRecord {
                id: 2,
                record_id: "a".to_string(),
                side: Side::Response,
                kind: PiiKind::Email,
                label: None,
                start_off: 0,
                end_off: 5,
                confidence: Confidence::High,
                action: PiiAction::Observed,
                value_hash: "h2".to_string(),
            },
            PiiFindingRecord {
                id: 3,
                record_id: "a".to_string(),
                side: Side::Request,
                kind: PiiKind::ApiKey,
                label: None,
                start_off: 0,
                end_off: 5,
                confidence: Confidence::High,
                action: PiiAction::Observed,
                value_hash: "h3".to_string(),
            },
            PiiFindingRecord {
                id: 4,
                record_id: "b".to_string(),
                side: Side::Request,
                kind: PiiKind::Phone,
                label: None,
                start_off: 0,
                end_off: 5,
                confidence: Confidence::High,
                action: PiiAction::Observed,
                value_hash: "h4".to_string(),
            },
        ];
        let kinds = distinct_kinds(&findings, "a");
        assert_eq!(kinds, vec![PiiKind::Email, PiiKind::ApiKey]);
    }

    #[test]
    fn median_picks_middle() {
        assert_eq!(median(&mut []), None);
        assert_eq!(median(&mut [5]), Some(5));
        assert_eq!(median(&mut [30, 10, 20]), Some(20));
        assert_eq!(median(&mut [40, 10, 30, 20]), Some(30));
    }

    #[test]
    fn named_counts_sorted_desc() {
        let mut m = BTreeMap::new();
        m.insert("a".to_string(), 1u64);
        m.insert("b".to_string(), 5u64);
        m.insert("c".to_string(), 3u64);
        let out = named_counts_sorted(m);
        assert_eq!(out[0].name, "b");
        assert_eq!(out[1].name, "c");
        assert_eq!(out[2].name, "a");
    }

    #[test]
    fn api_error_serializes_envelope() {
        let resp = api_error(StatusCode::NOT_FOUND, "not_found", "nope");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn detected_engine_view_surfaces_upstream_cooperative() {
        // The Cooperative upstream the proxy forwards to must show up in the
        // Engines panel with its real port and a cooperative adoption state.
        use crate::engine::{EngineInfo, EngineKind, StartMode};
        use crate::store::AdoptionState;

        let info = EngineInfo {
            engine: EngineKind::Ollama,
            version: Some("0.5.0".to_string()),
            port: 11434,
            how_it_starts: StartMode::Launchd,
            adoption_state: AdoptionState::Cooperative,
        };
        let view = detected_engine_view(&info, "healthy");
        assert_eq!(view.engine, "ollama");
        assert_eq!(view.public_port, 11434, "must surface the upstream port");
        assert_eq!(view.shadow_port, None);
        assert_eq!(view.adoption_state, AdoptionState::Cooperative);
        assert_eq!(view.version.as_deref(), Some("0.5.0"));
        assert_eq!(view.health, "healthy");
    }

    #[test]
    fn settings_view_excludes_token() {
        let cfg = crate::config::Config::default();
        let view = settings_view(&cfg);
        assert_eq!(view.proxy_port, crate::config::DEFAULT_PROXY_PORT);
        assert_eq!(view.studio_port, crate::config::DEFAULT_STUDIO_PORT);
        assert!(!view.payload_storage); // privacy default
                                        // The SettingsView struct has no token field — contract guarantees it.
    }

    #[test]
    fn settings_view_surfaces_masking_defaults() {
        // Observe-only default: masking off, and dry-run on so the very first
        // act of enabling it never mutates traffic.
        let cfg = crate::config::Config::default();
        let view = settings_view(&cfg);
        assert!(!view.masking_enabled, "masking off by default");
        assert!(view.masking_dry_run, "dry-run on by default");
    }

    #[test]
    fn settings_view_reflects_enabled_live_masking() {
        let mut cfg = crate::config::Config::default();
        cfg.masking.enabled = true;
        cfg.masking.dry_run = false;
        let view = settings_view(&cfg);
        assert!(view.masking_enabled);
        assert!(!view.masking_dry_run);
    }

    #[test]
    fn settings_view_has_no_restart_required_by_default() {
        let view = settings_view(&crate::config::Config::default());
        assert!(view.restart_required.is_empty());
        assert!(view.restart_note.is_none());
    }

    // --- live-reload integration (ArcSwap<Config>) --------------------------

    /// Pin a process-wide test DB key so `Store::open` never touches the keyring
    /// (the default build links SQLCipher). Mirrors `store::tests::ensure_test_db_key`.
    fn ensure_test_db_key() {
        use std::sync::Once;
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            if std::env::var(crate::store::keys::DB_KEY_ENV)
                .map(|v| v.is_empty())
                .unwrap_or(true)
            {
                std::env::set_var(
                    crate::store::keys::DB_KEY_ENV,
                    "test-db-key-0123456789abcdef",
                );
            }
        });
    }

    /// Build a real [`StudioState`] over a throwaway on-disk store + a fresh
    /// `ConfigHandle`. Returns the state and the shared handle so a test can
    /// observe swaps without rebuilding state.
    async fn test_state(
        mut cfg: crate::config::Config,
    ) -> (StudioState, crate::config::ConfigHandle) {
        ensure_test_db_key();
        // Anchor data_dir at a throwaway temp dir so `settings_put`'s TOML
        // write-through never touches the real per-OS config.
        let dir = std::env::temp_dir().join(format!("saffev-studio-api-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create temp data dir");
        cfg.data_dir = dir.clone();
        let path = dir.join("test.db");
        let store = crate::store::Store::open(&path).await.expect("open store");
        let (events, _rx) = tokio::sync::broadcast::channel(crate::studio::STREAM_CHANNEL_CAPACITY);
        let config = crate::config::config_handle(cfg);
        let state = StudioState {
            config: config.clone(),
            store,
            token: "test-token".into(),
            events,
        };
        (state, config)
    }

    /// The core contract: a `PUT /api/settings` masking change is observable
    /// **without rebuilding state** — both `handle.load()` and a subsequent
    /// `GET /api/settings` (over the SAME state) reflect it. Proves the ArcSwap
    /// swap is live.
    #[tokio::test]
    async fn settings_put_masking_change_is_observable_live() {
        // Start from the observe-only default: masking off, dry-run on.
        let (state, handle) = test_state(crate::config::Config::default()).await;
        assert!(!handle.load().masking.enabled, "precondition: masking off");
        assert!(handle.load().masking.dry_run, "precondition: dry-run on");

        // Flip masking ON and leave dry-run (turn on real redaction).
        let update = dto::SettingsUpdate {
            masking_enabled: Some(true),
            masking_dry_run: Some(false),
            ..Default::default()
        };
        let resp = settings_put(State(state.clone()), Json(update))
            .await
            .expect("settings_put ok");

        // The PUT response reflects the change.
        assert!(resp.0.masking_enabled);
        assert!(!resp.0.masking_dry_run);
        // Masking is hot-reloadable: no restart required.
        assert!(
            resp.0.restart_required.is_empty(),
            "masking applies live, no restart needed"
        );

        // The SHARED handle the proxy reads from now reflects it — no rebuild.
        let live = handle.load();
        assert!(live.masking.enabled, "swap must be visible on the handle");
        assert!(!live.masking.dry_run);

        // And GET over the same, unchanged state reads fresh (not a stale snapshot).
        let got = settings_get(State(state)).await.expect("settings_get ok");
        assert!(got.0.masking_enabled, "GET reflects the live swap");
        assert!(!got.0.masking_dry_run);
    }

    /// payload_storage and retention also apply live and surface no restart flag.
    #[tokio::test]
    async fn settings_put_payload_and_retention_apply_live() {
        let (state, handle) = test_state(crate::config::Config::default()).await;
        assert!(!handle.load().payload_storage);

        let update = dto::SettingsUpdate {
            payload_storage: Some(true),
            retention: Some(crate::config::Retention::Age { days: 7 }),
            ..Default::default()
        };
        let resp = settings_put(State(state), Json(update))
            .await
            .expect("settings_put ok");
        assert!(resp.0.restart_required.is_empty());

        let live = handle.load();
        assert!(live.payload_storage, "payload_storage applies live");
        assert_eq!(live.retention, crate::config::Retention::Age { days: 7 });
    }

    /// mode is NOT runtime-changeable: it is persisted but NOT swapped into the
    /// live handle, and the response flags `restart_required`.
    #[tokio::test]
    async fn settings_put_mode_change_is_restart_required_not_live() {
        // Start in Cooperative; request Gateway.
        let mut cfg = crate::config::Config::default();
        cfg.mode = crate::config::Mode::Cooperative;
        let (state, handle) = test_state(cfg).await;

        let update = dto::SettingsUpdate {
            mode: Some(crate::config::Mode::Gateway),
            ..Default::default()
        };
        let resp = settings_put(State(state), Json(update))
            .await
            .expect("settings_put ok");

        // Restart-required is reported with a note.
        assert!(
            resp.0.restart_required.iter().any(|f| f == "mode"),
            "mode must be flagged restart-required"
        );
        assert!(resp.0.restart_note.is_some());

        // The LIVE config still runs in the original mode (not swapped).
        assert_eq!(
            handle.load().mode,
            crate::config::Mode::Cooperative,
            "mode must NOT change at runtime"
        );
        // The returned view reflects the still-running mode, honestly.
        assert_eq!(resp.0.mode, crate::config::Mode::Cooperative);
    }
}
