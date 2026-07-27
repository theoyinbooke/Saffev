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
    let mut item = item_from_parts(
        &row.request,
        row.response.as_ref(),
        row.pii_count,
        pii_kinds,
    );
    item.safety_flagged = row.safety_count > 0;
    item
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
        status: resp.and_then(|r| r.status),
        error_kind: resp.and_then(|r| r.error_kind.clone()),
        // Live rows don't know their safety status yet (eval is async); the store
        // projection (history_item) sets this, and a Safety stream event updates
        // live rows retroactively.
        safety_flagged: false,
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
fn engine_view(rec: &EngineRecord, health: &str, is_active: bool) -> dto::EngineView {
    dto::EngineView {
        engine: rec.engine.clone(),
        version: rec.version.clone(),
        public_port: rec.public_port,
        shadow_port: rec.shadow_port,
        adoption_state: rec.adoption_state,
        health: health.to_string(),
        is_active,
    }
}

/// Project a freshly-detected [`EngineInfo`] (a running engine with no store row
/// yet — the Cooperative upstream, or a second engine like LM Studio) into the
/// wire [`dto::EngineView`]. The probed port is the engine's real port, so it
/// maps to `public_port` with no shadow.
fn detected_engine_view(
    info: &crate::engine::EngineInfo,
    health: &str,
    is_active: bool,
) -> dto::EngineView {
    dto::EngineView {
        engine: crate::engine::detect::engine_name(info.engine).to_string(),
        version: info.version.clone(),
        public_port: info.port,
        shadow_port: None,
        adoption_state: info.adoption_state,
        health: health.to_string(),
        is_active,
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
            failed_only: false,
            limit: Some(LIVE_RECENT_LIMIT),
            before_ts: None,
        })
        .await
        .map_err(internal)?;

    // Populate PII kinds per row so badges show on seeded rows too (not just live).
    let kinds = kinds_by_record(&state.store.privacy_summary().await.unwrap_or_default());
    let recent: Vec<dto::HistoryItem> = rows
        .iter()
        .map(|r| {
            history_item(
                r,
                kinds
                    .get(r.request.id.as_str())
                    .cloned()
                    .unwrap_or_default(),
            )
        })
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
            failed_only: false,
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

    // Lifetime total — distinguishes "never captured anything" (show onboarding)
    // from a merely empty recent window.
    let lifetime_requests = state.store.request_count().await.map_err(internal)?;

    Ok(Json(dto::LiveSnapshot {
        recent,
        requests_today,
        p50_latency_ms,
        pii_findings_today,
        lifetime_requests,
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
            failed_only: params.failed_only,
            limit: Some(limit),
            before_ts: params.before_ts,
        })
        .await
        .map_err(internal)?;

    let kinds = kinds_by_record(&state.store.privacy_summary().await.unwrap_or_default());
    let items: Vec<dto::HistoryItem> = rows
        .iter()
        .map(|r| {
            history_item(
                r,
                kinds
                    .get(r.request.id.as_str())
                    .cloned()
                    .unwrap_or_default(),
            )
        })
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
            failed_only: false,
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

    // Safety findings for this record (eval pipeline), projected to views.
    let safety: Vec<dto::SafetyView> = state
        .store
        .safety_for(&id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|s| dto::SafetyView {
            category: s.category,
            verdict: s.verdict,
            guard_model: s.guard_model,
            score: s.score,
        })
        .collect();

    // Quality-judge scores for this record (eval pipeline), projected to views.
    let eval: Vec<dto::EvalView> = state
        .store
        .eval_for(&id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|e| dto::EvalView {
            metric: e.metric,
            band: e.band,
            rationale: e.rationale,
            judge_model: e.judge_model,
        })
        .collect();

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
        safety,
        eval,
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
            failed_only: false,
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

    let masking = &state.config.load().masking;
    Ok(Json(dto::PrivacySummary {
        by_kind,
        by_app,
        by_model,
        total: findings.len() as u64,
        // Reflect the opt-in masking switch (§7.6) AND whether it's dry-run, so
        // the Privacy page can say "observing" vs "redacting".
        masking_enabled: masking.enabled,
        masking_dry_run: masking.dry_run,
    }))
}

/// `GET /api/quality` — the eval pipeline's safety/quality summary + time series.
pub async fn quality(
    State(state): State<StudioState>,
    Query(params): Query<AnalyticsParams>,
) -> Result<Json<dto::QualityReport>, Response> {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::atomic::Ordering::Relaxed;

    let cfg = state.config.load();
    let now = now_millis();
    let range_ms = params
        .range_ms
        .unwrap_or(ANALYTICS_DEFAULT_RANGE_MS)
        .clamp(ANALYTICS_MIN_RANGE_MS, ANALYTICS_MAX_RANGE_MS);
    let start = now - range_ms;
    let bucket_ms = analytics_bucket_ms(range_ms);
    let n_buckets = ((range_ms + bucket_ms - 1) / bucket_ms).max(1) as usize;
    let bidx =
        |ts: i64| -> usize { (((ts - start) / bucket_ms).max(0) as usize).min(n_buckets - 1) };

    // Safety findings in the window → by category + per-bucket distinct-flagged.
    let safety = state.store.safety_findings().await.map_err(internal)?;
    let mut by_cat: BTreeMap<String, u64> = BTreeMap::new();
    let mut flagged: BTreeSet<String> = BTreeSet::new();
    // Track (bucket, record) pairs so a record with 2 categories counts once.
    let mut bkt_flagged: Vec<BTreeSet<&str>> = vec![BTreeSet::new(); n_buckets];
    for f in &safety {
        if f.ts < start {
            continue;
        }
        *by_cat.entry(f.category.clone()).or_insert(0) += 1;
        flagged.insert(f.record_id.clone());
        bkt_flagged[bidx(f.ts)].insert(f.record_id.as_str());
    }
    let by_category = named_counts_sorted(by_cat);
    let total_flagged = flagged.len() as u64;

    // Eval scores in the window → per-metric good/weak + per-bucket good/weak.
    let evals = state.store.eval_scores().await.map_err(internal)?;
    let mut judged: BTreeSet<String> = BTreeSet::new();
    let mut metric_bands: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut bkt_good = vec![0u64; n_buckets];
    let mut bkt_weak = vec![0u64; n_buckets];
    for e in &evals {
        if e.ts < start {
            continue;
        }
        judged.insert(e.record_id.clone());
        let entry = metric_bands.entry(e.metric.clone()).or_insert((0, 0));
        let i = bidx(e.ts);
        if e.band == "good" {
            entry.0 += 1;
            bkt_good[i] += 1;
        } else {
            entry.1 += 1;
            bkt_weak[i] += 1;
        }
    }
    let total_judged = judged.len() as u64;
    let judged_in_window = total_judged;
    let eval_by_metric: Vec<dto::MetricBands> = metric_bands
        .into_iter()
        .map(|(metric, (good, weak))| dto::MetricBands { metric, good, weak })
        .collect();

    let series: Vec<dto::QualityBucket> = (0..n_buckets)
        .map(|i| dto::QualityBucket {
            ts: start + (i as i64) * bucket_ms,
            flagged: bkt_flagged[i].len() as u64,
            good: bkt_good[i],
            weak: bkt_weak[i],
        })
        .collect();

    // Recent flagged exchanges + in-window request count (coverage denominator).
    let rows = state
        .store
        .history(HistoryQuery {
            limit: Some(MAX_HISTORY_LIMIT),
            ..Default::default()
        })
        .await
        .map_err(internal)?;
    let requests_in_window = rows.iter().filter(|r| r.request.ts >= start).count() as u64;
    let kinds = kinds_by_record(&state.store.privacy_summary().await.unwrap_or_default());
    let recent_flagged: Vec<dto::HistoryItem> = rows
        .iter()
        .filter(|r| r.safety_count > 0)
        .take(50)
        .map(|r| {
            history_item(
                r,
                kinds
                    .get(r.request.id.as_str())
                    .cloned()
                    .unwrap_or_default(),
            )
        })
        .collect();

    let m = &state.eval_metrics;
    Ok(Json(dto::QualityReport {
        range_ms,
        generated_ts: now,
        bucket_ms,
        series,
        requests_in_window,
        judged_in_window,
        eval_enabled: cfg.eval.enabled,
        safety_enabled: cfg.eval.safety,
        quality_enabled: cfg.eval.quality,
        sample_rate: cfg.eval.sample_rate,
        total_flagged,
        by_category,
        total_judged,
        eval_by_metric,
        judge_inflight: m.inflight.load(Relaxed),
        judge_completed: m.completed.load(Relaxed),
        judge_dropped: m.dropped.load(Relaxed),
        recent_flagged,
    }))
}

/// Query params for endpoints that take only a time window.
#[derive(serde::Deserialize)]
pub struct RangeParams {
    /// Window length in millis. Omitted or 0 means "everything".
    #[serde(rename = "rangeMs")]
    range_ms: Option<i64>,
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
// The cloud price assumptions behind the "cost saved" estimate now live in
// `config.pricing`, so a published price change can be corrected without waiting
// for a release. They remain an estimate, and the report keeps saying so.

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
                failed_only: false,
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

    // Provenance of those totals. Per-row views already mark an estimated count
    // with a tilde, but the headline numbers silently blended engine-reported
    // counts with ones we estimated from a bundled tokenizer — and the headline
    // is the number people quote. Carry the split so the UI can qualify it.
    let estimated_input_tokens: u64 = cur
        .iter()
        .filter(|r| r.request.input_tokens_src == crate::store::TokenSource::Estimated)
        .filter_map(|r| r.request.input_tokens)
        .map(|v| v as u64)
        .sum();
    let estimated_output_tokens: u64 = cur
        .iter()
        .filter_map(|r| r.response.as_ref())
        .filter(|x| x.output_tokens_src == crate::store::TokenSource::Estimated)
        .filter_map(|x| x.output_tokens)
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

    let pricing = &state.config.load().pricing;
    let est_cost_saved_usd = (total_input_tokens as f64 / 1_000_000.0) * pricing.cloud_input_per_m
        + (total_output_tokens as f64 / 1_000_000.0) * pricing.cloud_output_per_m;
    let cloud_basis = format!("vs {}", pricing.cloud_label);

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

    // Failed exchanges in-window: transport error (error_kind set) or HTTP >= 400.
    let failed_requests = cur
        .iter()
        .filter(|r| {
            r.response.as_ref().is_some_and(|resp| {
                resp.error_kind.is_some() || resp.status.is_some_and(|s| s >= 400)
            })
        })
        .count() as u64;

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
    let prev_ids: BTreeMap<&str, ()> = prev.iter().map(|r| (r.request.id.as_str(), ())).collect();
    let prev_pii_findings = findings
        .iter()
        .filter(|f| prev_ids.contains_key(f.record_id.as_str()))
        .count() as u64;
    let prev_failed_requests = prev
        .iter()
        .filter(|r| {
            r.response.as_ref().is_some_and(|resp| {
                resp.error_kind.is_some() || resp.status.is_some_and(|s| s >= 400)
            })
        })
        .count() as u64;

    // ---- time series ----
    let bucket_ms = analytics_bucket_ms(range_ms);
    let n_buckets = ((range_ms + bucket_ms - 1) / bucket_ms).max(1) as usize;
    let mut bkt_req = vec![0u64; n_buckets];
    let mut bkt_in = vec![0u64; n_buckets];
    let mut bkt_out = vec![0u64; n_buckets];
    let mut bkt_pii = vec![0u64; n_buckets];
    let mut bkt_failed = vec![0u64; n_buckets];
    let mut bkt_lat: Vec<Vec<u32>> = vec![Vec::new(); n_buckets];
    let bidx =
        |ts: i64| -> usize { (((ts - start) / bucket_ms).max(0) as usize).min(n_buckets - 1) };
    for r in &cur {
        let i = bidx(r.request.ts);
        bkt_req[i] += 1;
        bkt_in[i] += r.request.input_tokens.unwrap_or(0) as u64;
        bkt_out[i] += r
            .response
            .as_ref()
            .and_then(|x| x.output_tokens)
            .unwrap_or(0) as u64;
        if r.response
            .as_ref()
            .is_some_and(|resp| resp.error_kind.is_some() || resp.status.is_some_and(|s| s >= 400))
        {
            bkt_failed[i] += 1;
        }
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
            failed: bkt_failed[i],
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
        let app = r
            .request
            .source_app
            .clone()
            .unwrap_or_else(|| "Unknown".into());
        let a = apps.entry(app).or_default();
        a.requests += 1;
        a.in_tok += r.request.input_tokens.unwrap_or(0) as u64;
        a.out_tok += r
            .response
            .as_ref()
            .and_then(|x| x.output_tokens)
            .unwrap_or(0) as u64;
        if let Some(l) = lat(r) {
            a.lat.push(l);
        }

        let ep = r.request.endpoint.clone();
        let e = endpoints.entry(ep).or_default();
        e.requests += 1;
        e.in_tok += r.request.input_tokens.unwrap_or(0) as u64;
        e.out_tok += r
            .response
            .as_ref()
            .and_then(|x| x.output_tokens)
            .unwrap_or(0) as u64;
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
        let out = r
            .response
            .as_ref()
            .and_then(|x| x.output_tokens)
            .unwrap_or(0);
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
            if let Some(a) = apps.get_mut(r.request.source_app.as_deref().unwrap_or("Unknown")) {
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
        // Use the wire (snake_case) name so the frontend has one canonical form
        // for a finding's action everywhere (drawer + analytics).
        let action_name = match f.action {
            crate::store::PiiAction::Observed => "observed",
            crate::store::PiiAction::WouldMask => "would_mask",
            crate::store::PiiAction::Masked => "masked",
            crate::store::PiiAction::WouldBlock => "would_block",
            crate::store::PiiAction::Blocked => "blocked",
        };
        *action_map.entry(action_name.to_string()).or_insert(0) += 1;
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
        &cloud_basis,
    );

    Ok(Json(dto::AnalyticsReport {
        range_ms,
        generated_ts: now,
        bucket_ms,
        total_requests,
        total_input_tokens,
        estimated_input_tokens,
        estimated_output_tokens,
        total_output_tokens,
        p50_latency_ms,
        p90_latency_ms,
        p99_latency_ms,
        avg_ttft_ms,
        pii_findings,
        failed_requests,
        active_apps: by_app.len() as u64,
        active_models: by_model.len() as u64,
        est_cost_saved_usd: (est_cost_saved_usd * 100.0).round() / 100.0,
        cost_basis: cloud_basis.clone(),
        prev_total_requests,
        prev_total_tokens,
        prev_p50_latency_ms,
        prev_pii_findings,
        prev_failed_requests,
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
    cloud_basis: &str,
) -> Vec<dto::Insight> {
    let mut out: Vec<dto::Insight> = Vec::new();
    if total_requests == 0 {
        out.push(dto::Insight {
            severity: "info".into(),
            title: "No traffic yet in this window".into(),
            detail:
                "Point an app at the proxy (see About & integrate) and activity will show up here."
                    .into(),
        });
        return out;
    }
    if cost_saved >= 0.01 {
        out.push(dto::Insight {
            severity: "good".into(),
            title: format!("≈ ${:.2} kept off the cloud", cost_saved),
            detail: format!(
                "{} requests · {} output tokens ran on-device {}.",
                total_requests, total_output_tokens, cloud_basis
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
                    "{} decodes at ~{:.0} tok/s vs ~{:.0} tok/s for {}. Prefer it for latency-sensitive work.",
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
                    "{}% of responses stopped at the token cap. Consider raising num_predict / max_tokens.",
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

    // The port the proxy actually forwards to right now: the shadow port in
    // Gateway mode, else the configured upstream. The engine on this port is the
    // "active" one; other running engines are shown but marked inactive.
    let active_port = match cfg.mode {
        crate::config::Mode::Gateway => cfg.ports.shadow,
        crate::config::Mode::Cooperative => cfg.ports.upstream,
    };

    // Health is best-effort: probe each engine's effective port (shadow if
    // adopted, else public). Down on any probe failure — never fail the call.
    let mut views = Vec::with_capacity(records.len() + 2);
    let mut covered_ports: Vec<u16> = Vec::new();
    for rec in &records {
        let port = rec.shadow_port.unwrap_or(rec.public_port);
        let health = if probe_loopback(port).await {
            "healthy"
        } else {
            "down"
        };
        let is_active = port == active_port || rec.public_port == active_port;
        views.push(engine_view(rec, health, is_active));
        covered_ports.push(rec.public_port);
        if let Some(sp) = rec.shadow_port {
            covered_ports.push(sp);
        }
    }

    // Surface EVERY running local engine (Ollama on :11434, LM Studio on :1234,
    // …), not just the configured upstream — so a second engine shows its own
    // card. Skip ports already covered by a store record. The one on `active_port`
    // is badged active; the rest are "detected · not proxied". Fail-soft: a silent
    // port simply adds nothing.
    if let Ok(detected) = crate::engine::detect::detect_all().await {
        for info in &detected {
            if covered_ports.contains(&info.port) {
                continue;
            }
            let health = if probe_loopback(info.port).await {
                "healthy"
            } else {
                "down"
            };
            views.push(detected_engine_view(info, health, info.port == active_port));
            covered_ports.push(info.port);
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

/// Canonical lowercase engine name for request matching + messages. Mirrors the
/// `engines` table convention (`ollama` / `lmstudio`).
fn engine_kind_name(kind: crate::engine::EngineKind) -> &'static str {
    match kind {
        crate::engine::EngineKind::Ollama => "ollama",
        crate::engine::EngineKind::LmStudio => "lmstudio",
        crate::engine::EngineKind::Unknown => "unknown",
    }
}

/// `POST /api/engines/adopt`
///
/// Actually drives the engine controller (the same path as `saffev adopt`):
/// - `cooperative: true` records the engine as cooperatively managed — no
///   system changes, ever (the CooperativeController's adopt is a documented
///   no-op that yields an empty journal).
/// - `cooperative: false` (Gateway) is gated **before** touching anything:
///   LM Studio has no systemd unit to rebind, Gateway requires `mode =
///   "gateway"` (restart-required, set in Settings), and only the Linux
///   systemd controller can adopt. Each gate returns a 409 explaining exactly
///   what to do instead — never a silent no-op or a silent downgrade.
///
/// Failures from the controller surface as errors; fail-open governs model
/// TRAFFIC, not control-plane honesty (same stance as the CLI's non-zero
/// exits).
pub async fn engines_adopt(
    State(state): State<StudioState>,
    Json(body): Json<dto::AdoptRequest>,
) -> Result<Json<dto::EngineView>, Response> {
    let requested = body.engine.trim().to_ascii_lowercase();
    if requested.is_empty() {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "validation",
            "engine name is required",
        ));
    }

    let cfg = state.config.load();

    // Gate the Gateway path up front, before any detection or system work, so
    // the user gets the *real* blocker as the error — not a downgrade.
    if !body.cooperative {
        if requested == "lmstudio" {
            return Err(api_error(
                StatusCode::CONFLICT,
                "gateway_unsupported",
                "Gateway adoption isn't supported for LM Studio (no systemd unit \
                 to rebind). Use Cooperative mode: point the app at the proxy or \
                 wrap it with `saffev run`.",
            ));
        }
        if cfg.mode != crate::config::Mode::Gateway {
            return Err(api_error(
                StatusCode::CONFLICT,
                "gateway_requires_mode",
                "Gateway adoption requires mode = \"gateway\". Set the mode in \
                 Settings, restart Saffev, then adopt.",
            ));
        }
        if !crate::engine::default_controller(&cfg).can_adopt() {
            return Err(api_error(
                StatusCode::CONFLICT,
                "gateway_unavailable",
                "Gateway adoption is Linux/systemd-only. On this host Saffev \
                 runs cooperatively: point apps at the proxy or use `saffev run`.",
            ));
        }
    }

    // Find the running engine we were asked to adopt.
    let detected = crate::engine::detect::detect_all()
        .await
        .map_err(internal)?;
    let info = detected
        .into_iter()
        .find(|i| engine_kind_name(i.engine) == requested)
        .ok_or_else(|| {
            api_error(
                StatusCode::NOT_FOUND,
                "not_found",
                &format!("no running {requested} engine detected — start it and try again"),
            )
        })?;

    // Cooperative requests must use the cooperative controller even on a
    // Linux/Gateway host — clicking "Cooperative" must never touch systemd.
    let controller: Box<dyn crate::engine::EngineController> = if body.cooperative {
        Box::new(crate::engine::cooperative::CooperativeController)
    } else {
        crate::engine::default_controller(&cfg)
    };

    crate::engine::adopt::run_adoption(controller.as_ref(), &info, &state.store)
        .await
        .map_err(|e| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "adopt_failed",
                &format!("adoption failed — the host was not changed: {e}"),
            )
        })?;

    // The journal is recorded via the async write queue; flush so the view we
    // return (and the UI's immediate refresh) reflects the new state.
    let _ = state.store.flush().await;
    current_engine_view(&state, &requested).await.map(Json)
}

/// `POST /api/engines/revert`
///
/// Replays the stored adoption journal in reverse (same path as `saffev
/// revert`) and records the engine as reverted. A Gateway journal can only be
/// undone by the systemd controller — if the current mode/host can't provide
/// one, this refuses loudly rather than recording "reverted" while the machine
/// is still adopted.
pub async fn engines_revert(
    State(state): State<StudioState>,
    Json(body): Json<dto::RevertRequest>,
) -> Result<Json<dto::EngineView>, Response> {
    let requested = body.engine.trim().to_ascii_lowercase();
    if requested.is_empty() {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "validation",
            "engine name is required",
        ));
    }

    let records = state.store.engines().await.map_err(internal)?;
    let rec = records
        .into_iter()
        .find(|r| r.engine.eq_ignore_ascii_case(&requested))
        .ok_or_else(|| {
            api_error(
                StatusCode::NOT_FOUND,
                "not_found",
                &format!("no adoption record for {requested} — nothing to revert"),
            )
        })?;

    let journal: Vec<crate::engine::JournalEntry> =
        serde_json::from_str(&rec.journal_json).unwrap_or_default();

    let cfg = state.config.load();
    let controller: Box<dyn crate::engine::EngineController> = if journal.is_empty() {
        // Cooperative record: nothing was changed on the system; reverting just
        // clears the managed state.
        Box::new(crate::engine::cooperative::CooperativeController)
    } else {
        let c = crate::engine::default_controller(&cfg);
        if !c.can_adopt() {
            return Err(api_error(
                StatusCode::CONFLICT,
                "gateway_required_for_revert",
                "this engine was adopted in Gateway mode — set mode = \"gateway\" \
                 (Linux) and restart, or run `saffev revert` on this host, so the \
                 system changes can actually be undone",
            ));
        }
        c
    };

    let kind = match rec.engine.as_str() {
        "ollama" => crate::engine::EngineKind::Ollama,
        "lmstudio" => crate::engine::EngineKind::LmStudio,
        _ => crate::engine::EngineKind::Unknown,
    };
    let info = crate::engine::EngineInfo {
        engine: kind,
        version: rec.version.clone(),
        port: rec.public_port,
        how_it_starts: crate::engine::StartMode::Unknown,
        adoption_state: rec.adoption_state,
    };

    crate::engine::adopt::run_revert(controller.as_ref(), &info, &journal, &state.store)
        .await
        .map_err(|e| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "revert_failed",
                &format!("revert failed — the host may still be adopted: {e}"),
            )
        })?;

    let _ = state.store.flush().await;
    current_engine_view(&state, &requested).await.map(Json)
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
    // Report up front whether POST /api/update can self-apply here, so the SPA
    // offers the right affordance: the one-click button, or honest guidance +
    // a release link (DMG .app installs, dev builds).
    let (apply_supported, apply_note, release_url) = match crate::update::apply_capability() {
        Ok(()) => (true, None, None),
        Err(e) => (
            false,
            Some(e.to_string()),
            Some(crate::update::RELEASES_URL.to_string()),
        ),
    };
    Json(dto::UpdateStatus {
        current_version: status.current_version,
        latest_version: status.latest_version,
        update_available: status.available,
        apply_supported,
        apply_note,
        release_url,
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
                    "v{} installed. Restart Saffev to run the new version",
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
        // No install receipt (dev build) or a DMG .app install: a 200 with
        // guidance, NOT an error — the UI shows how this install updates
        // rather than a failure toast.
        Err(crate::update::UpdateError::NoReceipt(msg))
        | Err(crate::update::UpdateError::UnsupportedInstall(msg)) => Ok(Json(dto::UpdateResult {
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
pub async fn restart(
    State(_state): State<StudioState>,
) -> Result<Json<dto::RestartResult>, Response> {
    crate::cli::daemon::spawn_restart_helper().map_err(internal)?;
    Ok(Json(dto::RestartResult { restarting: true }))
}

/// `POST /api/demo` — the one-click "send a test prompt" affordance.
///
/// Fires a real chat request **through the proxy** to the local engine, with
/// synthetic PII in the prompt (a test email, a Luhn-valid test card, an IP), so
/// a captured exchange appears live in the Studio — with the privacy lens lit up
/// — without the user opening a terminal or re-routing an app. This is the
/// zero-friction "aha": it converts the empty first-run dashboard into a working
/// demonstration in one click.
///
/// Only ever contacts loopback (the proxy + the engine), consistent with the
/// on-device invariant. Fail-soft: any error resolves to a `DemoResult` note,
/// never a 500 — the worst case is a helpful message.
pub async fn demo(State(state): State<StudioState>) -> Json<dto::DemoResult> {
    let cfg = state.config.load();
    let proxy = format!("http://127.0.0.1:{}", cfg.ports.proxy);
    let engine = format!("http://127.0.0.1:{}", cfg.ports.upstream);

    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let model = detect_demo_model(&client, &engine).await;

    // Synthetic, obviously-fake PII so the privacy lens lights up on the request
    // side regardless of whether the engine has a model installed. 4111… is the
    // standard Visa test number (Luhn-valid).
    let prompt = "Reply with just OK to confirm: email jane.doe@example.com, \
                  card 4111 1111 1111 1111 was charged $12.00, from 192.168.1.42.";
    let use_model = model.clone().unwrap_or_else(|| "llama3.2".to_string());
    let body = serde_json::json!({
        "model": use_model,
        "messages": [{ "role": "user", "content": prompt }],
        "stream": false,
        "think": false,
        "options": { "num_predict": 24 },
    });

    let sent = client
        .post(format!("{proxy}/api/chat"))
        .json(&body)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await;

    match sent {
        Ok(_) => Json(dto::DemoResult {
            captured: true,
            model: model.clone(),
            note: if model.is_some() {
                "Sent a test prompt through Saffev. It appears above, with the email, card, and IP flagged by the privacy lens.".into()
            } else {
                "Sent a test prompt through Saffev. It appears above with PII flagged. No model is installed, so the engine call failed — pull one (e.g. `ollama pull llama3.2`) to see a full response.".into()
            },
        }),
        Err(e) if e.is_connect() => Json(dto::DemoResult {
            captured: false,
            model,
            note: "Could not reach Saffev's proxy. Is the daemon running?".into(),
        }),
        // A timeout still means the request reached the proxy and was captured
        // (RequestStarted is teed before the engine is contacted).
        Err(_) => Json(dto::DemoResult {
            captured: true,
            model,
            note: "Sent — the request reached Saffev and was captured. The engine was slow or errored, but the exchange is above.".into(),
        }),
    }
}

/// Best-effort: pick an installed **generative** model on the engine (Ollama
/// `/api/tags`, then OpenAI/LM-Studio `/v1/models`). Prefers a chat model —
/// embedding models (which can't answer a chat request) are only used as a last
/// resort. `None` if nothing is installed or the engine is unreachable.
async fn detect_demo_model(client: &reqwest::Client, engine: &str) -> Option<String> {
    let t = std::time::Duration::from_secs(3);
    // `first non-embedding, else first` over a list of name strings.
    let pick = |names: Vec<String>| -> Option<String> {
        names
            .iter()
            .find(|n| !is_embedding_model(n))
            .or_else(|| names.first())
            .cloned()
    };
    if let Ok(v) = client
        .get(format!("{engine}/api/tags"))
        .timeout(t)
        .send()
        .await
    {
        if let Ok(j) = v.json::<serde_json::Value>().await {
            let names: Vec<String> = j["models"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|m| m["name"].as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            if let Some(n) = pick(names) {
                return Some(n);
            }
        }
    }
    if let Ok(v) = client
        .get(format!("{engine}/v1/models"))
        .timeout(t)
        .send()
        .await
    {
        if let Ok(j) = v.json::<serde_json::Value>().await {
            let names: Vec<String> = j["data"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|m| m["id"].as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            if let Some(n) = pick(names) {
                return Some(n);
            }
        }
    }
    None
}

/// Heuristic: does this model name look like an embedding model (which can't
/// answer a chat request)? Used so the demo prefers a generative model.
fn is_embedding_model(name: &str) -> bool {
    let n = name.to_lowercase();
    n.contains("embed") || n.contains("minilm") || n.contains("nomic")
}

// ===== Agents (coding-tool session history, on-device) ==========================

/// Default detector for scanning coding-agent transcripts for PII ("what did I
/// paste into my agent"). Built once; default patterns only.
static AGENT_DETECTOR: once_cell::sync::Lazy<Option<crate::brain::pii::Detector>> =
    once_cell::sync::Lazy::new(|| crate::brain::pii::Detector::new(&[]).ok());

/// Query for `GET /api/agents/sessions`.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentSessionsParams {
    /// Free-text filter over title/project/model.
    pub q: Option<String>,
    /// Restrict to one tool key.
    pub tool: Option<String>,
    /// Cap the number returned.
    pub limit: Option<usize>,
    /// When true, only sessions preserved in the archive.
    pub preserved: Option<bool>,
}

/// Ceiling on how many sessions one content search resolves. Generous relative
/// to any realistic page of results, bounded so a one-letter query cannot pull
/// the whole archive into memory.
const CONTENT_SEARCH_SESSION_CAP: usize = 300;

fn agent_session_view(s: &crate::agents::AgentSession, pii_count: u32) -> dto::AgentSessionView {
    dto::AgentSessionView {
        id: s.id.clone(),
        tool: s.tool.key().to_string(),
        label: s.tool.label().to_string(),
        title: s.title.clone(),
        project: s.project.clone(),
        git_branch: s.git_branch.clone(),
        model: s.model.clone(),
        started_ts: s.started_ts,
        updated_ts: s.updated_ts,
        message_count: s.message_count,
        tool_call_count: s.tool_call_count,
        input_tokens: s.input_tokens,
        output_tokens: s.output_tokens,
        cache_tokens: s.cache_tokens,
        cost_usd: crate::agents::cost_usd(
            s.model.as_deref(),
            s.input_tokens,
            s.output_tokens,
            s.cache_tokens,
        ),
        pii_count,
        source_path: s.source_path.clone(),
        preserved: false,
        source_deleted: false,
        snippets: Vec::new(),
        match_count: 0,
    }
}

/// Build a session view from an archived (preserved) session — used for sessions
/// the source app has deleted (resurrected from the archive).
fn archived_session_view(a: &crate::store::ArchivedSession) -> dto::AgentSessionView {
    let tool = crate::agents::split_id(&a.id)
        .map(|(t, _)| t)
        .unwrap_or(crate::agents::AgentTool::ClaudeCode);
    dto::AgentSessionView {
        id: a.id.clone(),
        tool: a.tool.clone(),
        label: tool.label().to_string(),
        title: a.title.clone(),
        project: a.project.clone(),
        git_branch: a.git_branch.clone(),
        model: a.model.clone(),
        started_ts: a.started_ts,
        updated_ts: a.updated_ts,
        message_count: a.message_count,
        tool_call_count: a.tool_call_count,
        input_tokens: a.input_tokens,
        output_tokens: a.output_tokens,
        cache_tokens: a.cache_tokens,
        cost_usd: crate::agents::cost_usd(
            a.model.as_deref(),
            a.input_tokens,
            a.output_tokens,
            a.cache_tokens,
        ),
        pii_count: 0,
        source_path: a.source_path.clone().unwrap_or_default(),
        preserved: true,
        source_deleted: a.source_deleted,
        snippets: Vec::new(),
        match_count: 0,
    }
}

fn tool_stat_view(t: &crate::agents::ToolStat) -> dto::AgentToolStat {
    dto::AgentToolStat {
        tool: t.tool.key().to_string(),
        label: t.tool.label().to_string(),
        present: t.present,
        sessions: t.sessions,
        tokens: t.tokens,
        cost_usd: t.cost_usd,
        last_active: t.last_active,
    }
}

fn agent_msg_view(m: &crate::agents::AgentMessage) -> dto::AgentMessageView {
    use crate::agents::{MessageKind, Role};
    dto::AgentMessageView {
        role: match m.role {
            Role::User => "user",
            Role::Assistant => "assistant",
            Role::Tool => "tool",
            Role::System => "system",
        }
        .into(),
        kind: match m.kind {
            MessageKind::Text => "text",
            MessageKind::Thinking => "thinking",
            MessageKind::ToolUse => "tool_use",
            MessageKind::ToolResult => "tool_result",
        }
        .into(),
        content: m.content.clone(),
        ts: m.ts,
        tool_name: m.tool_name.clone(),
    }
}

fn agent_finding_view(f: &crate::brain::Finding) -> dto::PiiFindingView {
    dto::PiiFindingView {
        kind: f.kind,
        label: f.label.clone(),
        side: f.side,
        start: f.start,
        end: f.end,
        confidence: f.confidence,
        action: crate::store::PiiAction::Observed,
    }
}

fn at_risk_view(r: &crate::agents::retention::AtRisk) -> dto::AtRiskView {
    use crate::agents::retention::RetentionKind;
    dto::AtRiskView {
        tool: r.tool.key().to_string(),
        label: r.tool.label().to_string(),
        kind: match r.policy.kind {
            RetentionKind::AgeDays => "age_days",
            RetentionKind::Churn => "churn",
            RetentionKind::KeepsAll => "keeps_all",
            RetentionKind::Unknown => "unknown",
        }
        .to_string(),
        days: r.policy.days,
        note: r.policy.note.clone(),
        total: r.total,
        expiring_soon: r.expiring_soon,
        overdue: r.overdue,
        soonest_expiry_ts: r.soonest_expiry_ts,
    }
}

/// `GET /api/agents` — which coding tools are present + rollups + at-risk + archive.
pub async fn agents(State(state): State<StudioState>) -> Json<dto::AgentsOverview> {
    // List once; derive tool stats + at-risk from the same pass.
    let sessions = tokio::task::spawn_blocking(crate::agents::all_sessions)
        .await
        .unwrap_or_default();
    let tools = crate::agents::tool_stats(&sessions);
    let at_risk = crate::agents::at_risk_report(&sessions);
    let total_sessions = tools.iter().map(|t| t.sessions).sum();
    let total_tokens = tools.iter().map(|t| t.tokens).sum();
    let total_cost_usd = tools.iter().map(|t| t.cost_usd).sum();
    let archived = state.store.archive_stats().await.unwrap_or_default();
    let cfg = state.config.load();
    Json(dto::AgentsOverview {
        tools: tools.iter().map(tool_stat_view).collect(),
        total_sessions,
        total_tokens,
        total_cost_usd,
        analysis: dto::AnalysisStatus {
            available: crate::agents::codex_server::is_available(),
            enabled: cfg.analysis.enabled,
            model: cfg.analysis.model.clone(),
        },
        at_risk: at_risk.iter().map(at_risk_view).collect(),
        archive: dto::ArchiveStatusView {
            enabled: cfg.archive.enabled,
            auto: cfg.archive.auto,
            count: archived.count,
            messages: archived.messages,
            bytes: archived.bytes,
        },
    })
}

/// Build a compact, cost-bounded transcript for the summarizer: `role: text`
/// lines, capped to `max_chars` by keeping the head and tail (the middle is where
/// long sessions are most repetitive).
fn compact_transcript(d: &crate::agents::AgentSessionDetail, max_chars: usize) -> String {
    use crate::agents::Role;
    let mut lines: Vec<String> = Vec::new();
    for m in &d.messages {
        let who = match m.role {
            Role::User => "user",
            Role::Assistant => "assistant",
            Role::Tool => "tool",
            Role::System => "system",
        };
        let body = m.content.trim();
        if body.is_empty() {
            continue;
        }
        // Tool/thinking blocks: keep only a short marker so they don't dominate.
        let snippet = match m.kind {
            crate::agents::MessageKind::ToolUse | crate::agents::MessageKind::ToolResult => {
                format!(
                    "[{} {}]",
                    m.tool_name.as_deref().unwrap_or("tool"),
                    crate::agents::claude_code::truncate(body, 160)
                )
            }
            _ => crate::agents::claude_code::truncate(body, 1200),
        };
        lines.push(format!("{who}: {snippet}"));
    }
    let full = lines.join("\n");
    if full.len() <= max_chars {
        return full;
    }
    // Keep head + tail around a marker.
    let half = max_chars / 2;
    let head: String = full.chars().take(half).collect();
    let tail: String = full
        .chars()
        .rev()
        .take(half)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{head}\n\n[... transcript truncated ...]\n\n{tail}")
}

/// `POST /api/agents/sessions/:id/summarize` — AI summary via the user's Codex.
///
/// Gated on `analysis.enabled` (opt-in). Fail-open: any backend error returns a
/// clean 4xx/5xx envelope, never a panic.
pub async fn agents_summarize(
    State(state): State<StudioState>,
    Path(id): Path<String>,
) -> Result<Json<dto::SummaryResult>, Response> {
    let cfg = state.config.load();
    if !cfg.analysis.enabled {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "analysis_disabled",
            "AI analysis is off. Enable it in Settings (uses your Codex subscription).",
        ));
    }
    if !crate::agents::codex_server::is_available() {
        return Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "codex_unavailable",
            "Codex is not installed or not signed in on this machine.",
        ));
    }
    let detail = crate::agents::detail(&id)
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "not_found", "unknown session id"))?;

    let transcript = compact_transcript(&detail, 24_000);
    if transcript.is_empty() {
        return Err(api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "empty_session",
            "This session has no readable content to summarize.",
        ));
    }
    let prompt = format!(
        "You are analyzing a transcript from an AI coding-agent session, for the developer who ran it. \
Write a concise, skimmable summary. Cover, with short headings or bullets:\n\
- Goal: what they were trying to do\n\
- Outcome: what was actually accomplished\n\
- Key changes/decisions: notable edits, files, or technical choices\n\
- Loose ends: anything unresolved or worth following up\n\
Be specific and grounded in the transcript. Do not use any tools; reply with the summary only.\n\n\
TRANSCRIPT (source: {}):\n{}",
        detail.session.tool.label(),
        transcript
    );

    let model = cfg.analysis.model.clone();
    let timeout = std::time::Duration::from_millis(cfg.analysis.timeout_ms);
    let out = tokio::task::spawn_blocking(move || {
        crate::agents::codex_server::run_prompt(&prompt, model.as_deref(), timeout)
    })
    .await
    .map_err(|_| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "join_error",
            "analysis task failed",
        )
    })?;

    match out {
        Ok(c) => Ok(Json(dto::SummaryResult {
            summary: c.text,
            model: c.model,
            elapsed_ms: c.elapsed_ms,
        })),
        Err(e) => Err(api_error(StatusCode::BAD_GATEWAY, "codex_error", &e)),
    }
}

/// `GET /api/agents/sessions` — source-tagged session list (newest first).
///
/// Unified view: live sessions (flagged `preserved` when a copy is in the archive)
/// **plus** sessions the source app deleted that Saffev has kept ("resurrected"
/// from the archive, flagged `sourceDeleted`).
pub async fn agents_sessions(
    State(state): State<StudioState>,
    Query(p): Query<AgentSessionsParams>,
) -> Json<Vec<dto::AgentSessionView>> {
    let q = p.q.unwrap_or_default().to_lowercase();
    let live = tokio::task::spawn_blocking(crate::agents::all_sessions)
        .await
        .unwrap_or_default();
    let archived = state.store.archived_sessions().await.unwrap_or_default();

    let live_ids: std::collections::HashSet<&str> = live.iter().map(|s| s.id.as_str()).collect();
    let archived_ids: std::collections::HashSet<&str> =
        archived.iter().map(|a| a.id.as_str()).collect();

    let mut out: Vec<dto::AgentSessionView> = Vec::with_capacity(live.len() + archived.len());
    for s in &live {
        let mut v = agent_session_view(s, 0);
        v.preserved = archived_ids.contains(s.id.as_str());
        out.push(v);
    }
    // Resurrected: archived sessions the source deleted and are no longer live.
    for a in &archived {
        if a.source_deleted && !live_ids.contains(a.id.as_str()) {
            out.push(archived_session_view(a));
        }
    }
    out.sort_by(|a, b| b.updated_ts.cmp(&a.updated_ts));

    if let Some(tool) = p.tool.as_deref() {
        out.retain(|v| v.tool == tool);
    }
    if !q.is_empty() {
        // Search is two things at once, and users should not have to know which.
        //
        // 1. Metadata (title / project / model / tool) — works for every session,
        //    archived or not, because it comes from the cheap list parse.
        // 2. Content (what was actually said) — served by the archive's full-text
        //    index, so it covers PRESERVED sessions. Scanning every live
        //    transcript per keystroke would mean re-parsing hundreds of megabytes,
        //    which is exactly the cost the archive exists to pay once.
        //
        // A session matching either way is kept; content matches also carry the
        // excerpts that explain the hit. When content search finds nothing because
        // nothing is preserved yet, this degrades to the old metadata-only
        // behavior rather than failing.
        let content: std::collections::HashMap<String, crate::store::ArchiveSearchHit> = state
            .store
            .search_archive(&q, CONTENT_SEARCH_SESSION_CAP)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|h| (h.session_id.clone(), h))
            .collect();

        out.retain(|v| {
            content.contains_key(&v.id)
                || format!(
                    "{} {} {} {}",
                    v.title.as_deref().unwrap_or(""),
                    v.project.as_deref().unwrap_or(""),
                    v.model.as_deref().unwrap_or(""),
                    v.label
                )
                .to_lowercase()
                .contains(&q)
        });
        for v in out.iter_mut() {
            if let Some(hit) = content.get(&v.id) {
                v.snippets = hit.snippets.clone();
                v.match_count = hit.match_count;
            }
        }
    }
    if p.preserved == Some(true) {
        out.retain(|v| v.preserved);
    }
    if let Some(lim) = p.limit {
        out.truncate(lim);
    }
    Json(out)
}

/// Rebuild an [`crate::agents::AgentSessionDetail`] from an archived session so
/// the detail handler is uniform across live and resurrected sessions.
fn archived_to_detail(a: crate::store::ArchivedSession) -> crate::agents::AgentSessionDetail {
    use crate::agents::{AgentMessage, AgentSession, AgentSessionDetail, MessageKind, Role};
    let tool = crate::agents::split_id(&a.id)
        .map(|(t, _)| t)
        .unwrap_or(crate::agents::AgentTool::ClaudeCode);
    let parse_role = |s: &str| match s {
        "assistant" => Role::Assistant,
        "tool" => Role::Tool,
        "system" => Role::System,
        _ => Role::User,
    };
    let parse_kind = |s: &str| match s {
        "thinking" => MessageKind::Thinking,
        "tool_use" => MessageKind::ToolUse,
        "tool_result" => MessageKind::ToolResult,
        _ => MessageKind::Text,
    };
    let session = AgentSession {
        id: a.id,
        tool,
        title: a.title,
        project: a.project,
        git_branch: a.git_branch,
        model: a.model,
        started_ts: a.started_ts,
        updated_ts: a.updated_ts,
        message_count: a.message_count,
        tool_call_count: a.tool_call_count,
        input_tokens: a.input_tokens,
        output_tokens: a.output_tokens,
        cache_tokens: a.cache_tokens,
        source_path: a.source_path.unwrap_or_default(),
    };
    let messages = a
        .messages
        .into_iter()
        .map(|m| AgentMessage {
            role: parse_role(&m.role),
            kind: parse_kind(&m.kind),
            content: m.content,
            ts: m.ts,
            tool_name: m.tool_name,
        })
        .collect();
    AgentSessionDetail { session, messages }
}

/// `GET /api/agents/sessions/:id` — full transcript + on-device PII lens.
///
/// Reads the live source first; if the source app has deleted it, falls back to
/// the archive (resurrected). Flags `preserved` / `sourceDeleted` accordingly.
pub async fn agents_detail(
    State(state): State<StudioState>,
    Path(id): Path<String>,
) -> Result<Json<dto::AgentSessionDetailView>, Response> {
    let id2 = id.clone();
    let live = tokio::task::spawn_blocking(move || crate::agents::detail(&id2))
        .await
        .ok()
        .flatten();
    let (d, preserved, source_deleted) = match live {
        Some(d) => {
            let idx = state.store.archived_index().await.unwrap_or_default();
            (d, idx.contains_key(&id), false)
        }
        None => {
            let a = state
                .store
                .archived_detail(&id)
                .await
                .ok()
                .flatten()
                .ok_or_else(|| {
                    api_error(StatusCode::NOT_FOUND, "not_found", "unknown session id")
                })?;
            let sd = a.source_deleted;
            (archived_to_detail(a), true, sd)
        }
    };
    // Scan the transcript for PII (what was pasted into the agent). Dedupe by
    // (kind, value-hash) so a repeated secret counts once, and cap the total.
    let mut pii = Vec::new();
    if let Some(det) = AGENT_DETECTOR.as_ref() {
        let mut seen: std::collections::HashSet<(crate::brain::PiiKind, String)> =
            std::collections::HashSet::new();
        'outer: for m in &d.messages {
            let side = match m.role {
                crate::agents::Role::Assistant => crate::brain::Side::Response,
                _ => crate::brain::Side::Request,
            };
            for f in det.scan(side, &m.content) {
                if seen.insert((f.kind, f.value_hash.clone())) {
                    pii.push(agent_finding_view(&f));
                    if pii.len() >= 200 {
                        break 'outer;
                    }
                }
            }
        }
    }
    let mut session = agent_session_view(&d.session, pii.len() as u32);
    session.preserved = preserved;
    session.source_deleted = source_deleted;
    let messages = d.messages.iter().map(agent_msg_view).collect();
    Ok(Json(dto::AgentSessionDetailView {
        session,
        messages,
        pii,
    }))
}

/// `POST /api/archive/run` — trigger a snapshot into the archive (gated on enabled).
pub async fn archive_run(
    State(state): State<StudioState>,
) -> Result<Json<crate::agents::archive::SnapshotSummary>, Response> {
    let cfg = state.config.load();
    if !cfg.archive.enabled {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "archive_disabled",
            "Preservation is off. Enable it in Settings to archive your history.",
        ));
    }
    // If the user asked for redaction and the detector will not build, refuse
    // rather than archive raw secrets under a setting that says otherwise.
    let redaction = crate::agents::archive::Redaction::from_config(&cfg).map_err(|e| {
        api_error(
            StatusCode::BAD_REQUEST,
            "redaction_unavailable",
            &format!(
                "Redaction is on but a PII pattern failed to compile, so nothing was archived \
                 (archiving would have stored unredacted text): {e}"
            ),
        )
    })?;
    let summary = crate::agents::archive::run_snapshot(&state.store, redaction)
        .await
        .map_err(internal)?;
    Ok(Json(summary))
}

/// Query params for `GET /api/timeline`.
#[derive(serde::Deserialize)]
pub struct TimelineParams {
    /// Free-text query. Matches proxy metadata, session metadata, and (for
    /// preserved sessions) what was actually said.
    pub q: Option<String>,
    /// Window length in millis; omitted or 0 means everything.
    #[serde(rename = "rangeMs")]
    pub range_ms: Option<i64>,
    /// Restrict to one side: `proxy` or `agent`.
    pub kind: Option<String>,
    pub limit: Option<usize>,
}

/// `GET /api/timeline` — everything AI touched on this machine, in order.
///
/// Merges the two halves of what Saffev knows: model calls that went through the
/// proxy, and coding-agent sessions read from disk. A user should not have to
/// know which of those a memory lives in to go looking for it.
pub async fn timeline(
    State(state): State<StudioState>,
    Query(p): Query<TimelineParams>,
) -> Result<Json<dto::TimelineView>, Response> {
    let q = p.q.unwrap_or_default().trim().to_lowercase();
    let limit = p.limit.unwrap_or(200).clamp(1, 1_000);
    let range_ms = p.range_ms.unwrap_or(0).max(0);
    let since = if range_ms > 0 {
        crate::agents::now_ms() - range_ms
    } else {
        0
    };
    let want_proxy = p.kind.as_deref() != Some("agent");
    let want_agent = p.kind.as_deref() != Some("proxy");

    let mut entries: Vec<dto::TimelineEntry> = Vec::new();
    let mut proxy_count = 0u32;
    let mut agent_count = 0u32;

    // --- proxied exchanges ---
    if want_proxy {
        let rows = state
            .store
            .history(crate::store::HistoryQuery {
                q: if q.is_empty() { None } else { Some(q.clone()) },
                limit: Some(limit as u32),
                ..Default::default()
            })
            .await
            .map_err(internal)?;
        for r in rows {
            if r.request.ts < since {
                continue;
            }
            proxy_count += 1;
            let resp = r.response.as_ref();
            let failed = resp
                .map(|x| x.error_kind.is_some() || x.status.map(|s| s >= 400).unwrap_or(false))
                .unwrap_or(false);
            entries.push(dto::TimelineEntry {
                kind: dto::TimelineKind::Proxy,
                ts: r.request.ts,
                source: r
                    .request
                    .source_app
                    .clone()
                    .unwrap_or_else(|| "Unknown".into()),
                label: r
                    .request
                    .source_app
                    .clone()
                    .unwrap_or_else(|| "Unknown app".into()),
                title: r.request.endpoint.clone(),
                model: r.request.model.clone(),
                project: None,
                input_tokens: r.request.input_tokens.unwrap_or(0) as u64,
                output_tokens: resp.and_then(|x| x.output_tokens).unwrap_or(0) as u64,
                pii_count: r.pii_count,
                failed,
                safety_flagged: r.safety_count > 0,
                preserved: false,
                snippets: Vec::new(),
                id: r.request.id,
            });
        }
    }

    // --- coding-agent sessions ---
    if want_agent {
        let sessions = tokio::task::spawn_blocking(crate::agents::all_sessions)
            .await
            .unwrap_or_default();
        let archived_ids: std::collections::HashSet<String> = state
            .store
            .archived_index()
            .await
            .unwrap_or_default()
            .into_keys()
            .collect();

        // Content search reaches preserved sessions (same reasoning as the
        // Agents page: scanning every live transcript per query is the cost the
        // archive exists to pay once).
        let content: std::collections::HashMap<String, crate::store::ArchiveSearchHit> =
            if q.is_empty() {
                Default::default()
            } else {
                state
                    .store
                    .search_archive(&q, CONTENT_SEARCH_SESSION_CAP)
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .map(|h| (h.session_id.clone(), h))
                    .collect()
            };

        for s in sessions {
            if s.updated_ts < since {
                continue;
            }
            let matches = q.is_empty()
                || content.contains_key(&s.id)
                || format!(
                    "{} {} {}",
                    s.title.as_deref().unwrap_or(""),
                    s.project.as_deref().unwrap_or(""),
                    s.model.as_deref().unwrap_or("")
                )
                .to_lowercase()
                .contains(&q);
            if !matches {
                continue;
            }
            agent_count += 1;
            let hit = content.get(&s.id);
            entries.push(dto::TimelineEntry {
                kind: dto::TimelineKind::Agent,
                ts: s.updated_ts,
                source: s.tool.key().to_string(),
                label: s.tool.label().to_string(),
                title: s
                    .title
                    .clone()
                    .unwrap_or_else(|| "Untitled session".to_string()),
                model: s.model.clone(),
                project: s.project.clone(),
                input_tokens: s.input_tokens,
                output_tokens: s.output_tokens,
                pii_count: 0,
                failed: false,
                safety_flagged: false,
                preserved: archived_ids.contains(&s.id),
                snippets: hit.map(|h| h.snippets.clone()).unwrap_or_default(),
                id: s.id.clone(),
            });
        }
    }

    entries.sort_by(|a, b| b.ts.cmp(&a.ts));
    let content_search = state
        .store
        .archive_stats()
        .await
        .map(|s| s.count > 0)
        .unwrap_or(false);
    entries.truncate(limit);

    Ok(Json(dto::TimelineView {
        entries,
        proxy_count,
        agent_count,
        content_search,
    }))
}

/// `GET /api/archive/verify` — walk the integrity chain and report the result.
pub async fn archive_verify(
    State(state): State<StudioState>,
) -> Result<Json<dto::ArchiveIntegrityView>, Response> {
    let v = state.store.verify_archive().await.map_err(internal)?;
    Ok(Json(dto::ArchiveIntegrityView {
        entries: v.entries,
        sessions: v.sessions,
        intact: v.intact,
        broken_at: v.broken_at,
        altered_sessions: v.altered_sessions,
        head_digest: v.head_digest,
        head_ts: v.head_ts,
    }))
}

/// `POST /api/archive/audit` — write an audit bundle to a folder on disk.
///
/// The point is to be handed to someone else. A reviewer who has never run
/// Saffev should be able to open the folder and check the claims themselves:
/// the transcripts, the integrity chain, what each digest covers, and how to
/// recompute them. So the bundle carries a README explaining the method,
/// including its limits.
pub async fn archive_audit(
    State(state): State<StudioState>,
) -> Result<Json<dto::AuditExportResult>, Response> {
    if !state.config.load().archive.enabled {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "archive_disabled",
            "Preservation is off, so there is nothing to audit.",
        ));
    }

    let integrity = state.store.verify_archive().await.map_err(internal)?;
    let log = state.store.archive_log().await.map_err(internal)?;
    let sessions = state.store.archived_sessions().await.map_err(internal)?;

    let stamp = crate::agents::now_ms();
    let dir = crate::agents::home().join(format!("Saffev-Audit-{stamp}"));
    let transcripts = dir.join("transcripts");
    std::fs::create_dir_all(&transcripts).map_err(|e| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "export_failed",
            &format!("could not create {}: {e}", dir.display()),
        )
    })?;

    // The chain, verbatim, so it can be recomputed independently.
    let chain: Vec<serde_json::Value> = log
        .iter()
        .map(|e| {
            serde_json::json!({
                "seq": e.seq,
                "ts": e.ts,
                "sessionId": e.session_id,
                "contentDigest": e.content_digest,
                "prevDigest": e.prev_digest,
                "entryDigest": e.entry_digest,
            })
        })
        .collect();

    let manifest = serde_json::json!({
        "tool": crate::brand::APP_NAME,
        "version": crate::VERSION,
        "generatedTs": stamp,
        "integrity": {
            "intact": integrity.intact,
            "entries": integrity.entries,
            "sessions": integrity.sessions,
            "brokenAt": integrity.broken_at,
            "alteredSessions": integrity.altered_sessions,
            "headDigest": integrity.head_digest,
            "headTs": integrity.head_ts,
        },
        "chain": chain,
    });
    write_export(&dir.join("manifest.json"), &manifest.to_string())?;
    write_export(&dir.join("README.md"), &audit_readme(&integrity))?;

    // One readable transcript per session, named by its id so a manifest entry
    // points at a file the reviewer can actually open.
    let mut written = 0u32;
    let mut errors = 0u32;
    for s in &sessions {
        match state.store.archived_detail(&s.id).await {
            Ok(Some(full)) => {
                let detail = archived_to_detail(full);
                let name = format!("{}.md", s.id.replace(':', "_"));
                if write_export(
                    &transcripts.join(name),
                    &crate::agents::export::to_markdown(&detail),
                )
                .is_ok()
                {
                    written += 1;
                } else {
                    errors += 1;
                }
            }
            _ => errors += 1,
        }
    }

    Ok(Json(dto::AuditExportResult {
        dir: dir.to_string_lossy().to_string(),
        sessions: written,
        errors,
        intact: integrity.intact,
        head_digest: integrity.head_digest,
    }))
}

fn write_export(path: &std::path::Path, body: &str) -> Result<(), Response> {
    std::fs::write(path, body).map_err(|e| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "export_failed",
            &format!("could not write {}: {e}", path.display()),
        )
    })
}

/// The explanation that ships inside the audit bundle. Written for someone who
/// has never seen this tool, and honest about what the evidence does not prove.
fn audit_readme(v: &crate::store::ArchiveIntegrity) -> String {
    let verdict = if v.intact {
        "INTACT — every entry recomputed correctly and every archived session still \
         matches what was recorded when it was preserved."
    } else {
        "NOT INTACT — see `brokenAt` in manifest.json."
    };
    format!(
        "# {app} audit bundle\n\n\
         ## What this is\n\n\
         A copy of the AI coding sessions preserved on this machine, plus the integrity \
         chain that shows they have not been altered since they were preserved.\n\n\
         - `transcripts/` — one Markdown file per session.\n\
         - `manifest.json` — the full integrity chain and the verification result.\n\n\
         ## Verification result\n\n\
         {verdict}\n\n\
         - Entries in the chain: {entries}\n\
         - Sessions covered: {sessions}\n\
         - Head digest: `{head}`\n\n\
         ## How the chain works\n\n\
         Every time a session is preserved, one entry is appended to a log. Each entry \
         contains a SHA-256 digest of that session's stored content, and a SHA-256 digest \
         of itself that also covers the previous entry's digest. Changing, inserting, or \
         removing any entry therefore breaks every entry after it.\n\n\
         To check it yourself, walk `chain` in order and confirm that:\n\n\
         1. each entry's `prevDigest` equals the previous entry's `entryDigest` (empty for \
         the first), and\n\
         2. `entryDigest` = SHA-256 of `seq`, `ts`, `sessionId`, `contentDigest` and \
         `prevDigest`, each followed by a zero byte.\n\n\
         ## What this does not prove\n\n\
         This shows the archive is internally consistent and has not been edited by \
         anything that did not also rewrite the whole chain. It is **not** proof against \
         someone who controls this machine and recomputes every digest deliberately. \
         Proving that would need the head digest to be recorded somewhere outside this \
         machine at the time of preservation. If you need that, record the head digest \
         above with a third party and compare it later.\n",
        app = crate::brand::APP_NAME,
        verdict = verdict,
        entries = v.entries,
        sessions = v.sessions,
        head = v.head_digest.as_deref().unwrap_or("(nothing archived)"),
    )
}

/// Query for the export endpoint.
#[derive(Debug, serde::Deserialize)]
pub struct ExportParams {
    /// `md` | `json` (default `md`).
    pub format: Option<String>,
}

/// `GET /api/agents/sessions/:id/export?format=md|json` — download one session.
pub async fn agents_export(
    State(state): State<StudioState>,
    Path(id): Path<String>,
    Query(p): Query<ExportParams>,
) -> Result<Response, Response> {
    let format = crate::agents::export::Format::parse(p.format.as_deref().unwrap_or("md"))
        .ok_or_else(|| {
            api_error(
                StatusCode::BAD_REQUEST,
                "bad_format",
                "format must be md or json",
            )
        })?;

    // Live first, else archive.
    let id2 = id.clone();
    let live = tokio::task::spawn_blocking(move || crate::agents::detail(&id2))
        .await
        .ok()
        .flatten();
    let detail = match live {
        Some(d) => d,
        None => {
            let a = state
                .store
                .archived_detail(&id)
                .await
                .ok()
                .flatten()
                .ok_or_else(|| {
                    api_error(StatusCode::NOT_FOUND, "not_found", "unknown session id")
                })?;
            archived_to_detail(a)
        }
    };
    let body = crate::agents::export::render(&detail, format);
    let filename = format!(
        "{}.{}",
        crate::agents::export::safe_filename(&detail),
        format.ext()
    );
    Ok((
        [
            (
                axum::http::header::CONTENT_TYPE,
                format.content_type().to_string(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        body,
    )
        .into_response())
}

/// Body for `POST /api/archive/export`.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportAllBody {
    /// `md` | `json` (default `md`).
    pub format: Option<String>,
    /// Restrict to one tool key.
    pub tool: Option<String>,
    /// Destination directory (default `~/Saffev-Export`).
    pub dest: Option<String>,
}

fn write_session_export(
    dir: &std::path::Path,
    d: &crate::agents::AgentSessionDetail,
    format: crate::agents::export::Format,
) -> std::io::Result<()> {
    let sub = dir.join(d.session.tool.key());
    std::fs::create_dir_all(&sub)?;
    let path = sub.join(format!(
        "{}.{}",
        crate::agents::export::safe_filename(d),
        format.ext()
    ));
    std::fs::write(path, crate::agents::export::render(d, format))
}

/// `POST /api/archive/export` — export every session to a folder on disk (one
/// file per session, foldered by tool). Exports from the archive when populated
/// (fast, and includes sessions the source has deleted); otherwise reads live
/// sources. It's the user's data, in open formats, theirs to keep.
pub async fn archive_export(
    State(state): State<StudioState>,
    Json(body): Json<ExportAllBody>,
) -> Result<Json<dto::ExportSummary>, Response> {
    let format = crate::agents::export::Format::parse(body.format.as_deref().unwrap_or("md"))
        .ok_or_else(|| {
            api_error(
                StatusCode::BAD_REQUEST,
                "bad_format",
                "format must be md or json",
            )
        })?;
    let dir = body
        .dest
        .filter(|d| !d.trim().is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| crate::agents::home().join("Saffev-Export"));
    std::fs::create_dir_all(&dir).map_err(internal)?;
    let tool = body.tool.filter(|t| !t.is_empty());

    let has_archive = state
        .store
        .archive_stats()
        .await
        .map(|s| s.count > 0)
        .unwrap_or(false);
    let (count, errors) = if has_archive {
        let mut count = 0u32;
        let mut errors = 0u32;
        for a in state.store.archived_sessions().await.map_err(internal)? {
            if tool.as_deref().map(|t| a.tool != t).unwrap_or(false) {
                continue;
            }
            match state.store.archived_detail(&a.id).await {
                Ok(Some(full)) => {
                    let detail = archived_to_detail(full);
                    if write_session_export(&dir, &detail, format).is_ok() {
                        count += 1;
                    } else {
                        errors += 1;
                    }
                }
                _ => errors += 1,
            }
        }
        (count, errors)
    } else {
        let dir2 = dir.clone();
        tokio::task::spawn_blocking(move || {
            let mut count = 0u32;
            let mut errors = 0u32;
            for s in crate::agents::all_sessions() {
                if tool.as_deref().map(|t| s.tool.key() != t).unwrap_or(false) {
                    continue;
                }
                match crate::agents::detail(&s.id) {
                    Some(d) => {
                        if write_session_export(&dir2, &d, format).is_ok() {
                            count += 1;
                        } else {
                            errors += 1;
                        }
                    }
                    None => errors += 1,
                }
            }
            (count, errors)
        })
        .await
        .map_err(|_| internal(crate::Error::Store("export task failed".into())))?
    };

    Ok(Json(dto::ExportSummary {
        count,
        errors,
        dir: dir.display().to_string(),
    }))
}

/// `GET /api/agents/analytics` — cross-session rollups (by tool, by model).
/// `GET /api/agents/privacy?rangeMs=…`
///
/// The cross-history privacy report: what kinds of secrets appear in your
/// preserved coding-agent transcripts, in which tools and projects, and which
/// sessions to look at. `rangeMs` bounds the window; omit it for everything.
///
/// Scans the archive rather than the live files (see `agents::privacy`), and
/// reports its own coverage so the numbers are never mistaken for a full sweep.
pub async fn agents_privacy(
    State(state): State<StudioState>,
    Query(p): Query<RangeParams>,
) -> Json<dto::AgentPrivacyReport> {
    let cfg = state.config.load();
    let range_ms = p.range_ms.unwrap_or(0).max(0);
    let r = crate::agents::privacy::report(&state.store, &cfg, range_ms).await;

    let group = |g: &crate::agents::privacy::NamedCount| dto::AgentPiiGroup {
        name: g.name.clone(),
        count: g.count,
    };

    Json(dto::AgentPrivacyReport {
        generated_ts: r.generated_ts,
        range_ms: r.range_ms,
        sessions_with_findings: r.sessions_with_findings,
        total_findings: r.total_findings,
        user_side_findings: r.user_side_findings,
        high_signal_findings: r.high_signal_findings,
        high_signal_user_side: r.high_signal_user_side,
        by_kind: r
            .by_kind
            .iter()
            .map(|k| dto::AgentPiiKind {
                name: k.name.clone(),
                count: k.count,
                noisy: k.noisy,
            })
            .collect(),
        by_tool: r
            .by_tool
            .iter()
            .map(|g| dto::AgentPiiGroup {
                // Tools are stored by key; show the human label.
                name: crate::agents::split_id(&format!("{}:x", g.name))
                    .map(|(t, _)| t.label().to_string())
                    .unwrap_or_else(|| g.name.clone()),
                count: g.count,
            })
            .collect(),
        by_project: r.by_project.iter().map(group).collect(),
        top_sessions: r
            .top_sessions
            .iter()
            .map(|s| dto::AgentPiiSession {
                session_id: s.session_id.clone(),
                tool: s.tool.clone(),
                label: crate::agents::split_id(&s.session_id)
                    .map(|(t, _)| t.label().to_string())
                    .unwrap_or_else(|| s.tool.clone()),
                title: s.title.clone(),
                project: s.project.clone(),
                updated_ts: s.updated_ts,
                findings: s.findings,
                user_side: s.user_side,
                kinds: s.kinds.clone(),
            })
            .collect(),
        coverage: dto::AgentPiiCoverage {
            preserved: r.coverage.preserved,
            total: r.coverage.total,
            archive_enabled: cfg.archive.enabled,
        },
    })
}

pub async fn agents_analytics(State(_state): State<StudioState>) -> Json<dto::AgentAnalytics> {
    let sessions = crate::agents::all_sessions();
    let by_tool = crate::agents::detected();
    let total_sessions = sessions.len() as u32;
    let total_tokens: u64 = sessions
        .iter()
        .map(|s| s.input_tokens + s.output_tokens)
        .sum();
    let total_tool_calls: u64 = sessions.iter().map(|s| s.tool_call_count as u64).sum();
    let total_cost_usd: f64 = by_tool.iter().map(|t| t.cost_usd).sum();

    let mut models: BTreeMap<String, (u32, u64, f64)> = BTreeMap::new();
    for s in &sessions {
        let name = s.model.clone().unwrap_or_else(|| "unknown".into());
        let e = models.entry(name).or_insert((0, 0, 0.0));
        e.0 += 1;
        e.1 += s.input_tokens + s.output_tokens;
        e.2 += crate::agents::cost_usd(
            s.model.as_deref(),
            s.input_tokens,
            s.output_tokens,
            s.cache_tokens,
        );
    }
    let mut by_model: Vec<dto::AgentModelStat> = models
        .into_iter()
        .map(
            |(model, (sessions, tokens, cost_usd))| dto::AgentModelStat {
                model,
                sessions,
                tokens,
                cost_usd,
            },
        )
        .collect();
    by_model.sort_by(|a, b| b.tokens.cmp(&a.tokens));

    Json(dto::AgentAnalytics {
        total_sessions,
        total_tokens,
        total_cost_usd,
        total_tool_calls,
        by_tool: by_tool.iter().map(tool_stat_view).collect(),
        by_model,
    })
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

    // A shared team policy outranks the Studio. Refuse rather than silently
    // accept-then-ignore: a switch that appears to flip but does nothing is worse
    // than one that says no.
    for (field, requested) in [
        ("masking.enabled", body.masking_enabled.is_some()),
        ("masking.dry_run", body.masking_dry_run.is_some()),
        ("masking.block_kinds", body.masking_block_kinds.is_some()),
    ] {
        if requested && crate::policy::governs(field) {
            return Err(api_error(
                StatusCode::CONFLICT,
                "governed_by_policy",
                &format!(
                    "`{field}` is set by your team policy and cannot be changed here. \
                     Edit the policy file instead."
                ),
            ));
        }
    }

    // masking.block_kinds — HOT-RELOADABLE. The one setting that can stop a
    // user's request, so it is logged explicitly like the other protective ones.
    if let Some(kinds) = body.masking_block_kinds.clone() {
        persisted.masking.block_kinds = kinds.clone();
        live.masking.block_kinds = kinds.clone();
        state.store.enqueue(crate::store::WriteOp::Setting {
            key: "masking_block_kinds".to_string(),
            value: serde_json::to_string(&kinds).unwrap_or_default(),
        });
    }

    // Eval pipeline toggles — all hot-reloadable (the worker reads config live).
    if let Some(v) = body.eval_enabled {
        persisted.eval.enabled = v;
        live.eval.enabled = v;
        state.store.enqueue(crate::store::WriteOp::Setting {
            key: "eval_enabled".to_string(),
            value: v.to_string(),
        });
    }
    if let Some(v) = body.eval_safety {
        persisted.eval.safety = v;
        live.eval.safety = v;
    }
    if let Some(v) = body.eval_quality {
        persisted.eval.quality = v;
        live.eval.quality = v;
    }
    if let Some(v) = body.eval_sample_rate {
        let v = v.clamp(0.0, 1.0);
        persisted.eval.sample_rate = v;
        live.eval.sample_rate = v;
    }
    if let Some(v) = body.eval_judge_model {
        // Empty string clears the model (judge goes inert).
        let m = v.trim();
        let val = (!m.is_empty()).then(|| m.to_string());
        persisted.eval.judge_model = val.clone();
        live.eval.judge_model = val;
    }

    // AI-analysis backend — hot-reloadable. Enabling permits sending session text
    // to OpenAI via the user's Codex, so log it as an explicit action.
    if let Some(v) = body.analysis_enabled {
        persisted.analysis.enabled = v;
        live.analysis.enabled = v;
        state.store.enqueue(crate::store::WriteOp::Setting {
            key: "analysis_enabled".to_string(),
            value: v.to_string(),
        });
    }

    // Preservation archive — hot-reloadable, opt-in, local-only.
    if let Some(v) = body.archive_enabled {
        persisted.archive.enabled = v;
        live.archive.enabled = v;
        state.store.enqueue(crate::store::WriteOp::Setting {
            key: "archive_enabled".to_string(),
            value: v.to_string(),
        });
    }
    // archive.redact — HOT-RELOADABLE. Changing it also rewrites what is already
    // stored on the next snapshot (the archive change key includes this setting),
    // so a user who turns it on does not keep a pile of raw transcripts they now
    // believe are safe.
    if let Some(v) = body.archive_redact {
        persisted.archive.redact = v;
        live.archive.redact = v;
        state.store.enqueue(crate::store::WriteOp::Setting {
            key: "archive_redact".to_string(),
            value: v.to_string(),
        });
    }
    if let Some(v) = body.archive_auto {
        persisted.archive.auto = v;
        live.archive.auto = v;
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
        masking_block_kinds: cfg.masking.block_kinds.clone(),
        policy: crate::policy::current(),
        eval_enabled: cfg.eval.enabled,
        eval_safety: cfg.eval.safety,
        eval_quality: cfg.eval.quality,
        eval_sample_rate: cfg.eval.sample_rate,
        eval_judge_model: cfg.eval.judge_model.clone(),
        analysis_enabled: cfg.analysis.enabled,
        analysis_available: crate::agents::codex_server::is_available(),
        archive_enabled: cfg.archive.enabled,
        archive_auto: cfg.archive.auto,
        archive_redact: cfg.archive.redact,
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
    let cfg = state.config.load();
    let active_port = match cfg.mode {
        crate::config::Mode::Gateway => cfg.ports.shadow,
        crate::config::Mode::Cooperative => cfg.ports.upstream,
    };
    let is_active = port == active_port || rec.public_port == active_port;
    Ok(engine_view(&rec, health, is_active))
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
fn kinds_by_record(
    findings: &[PiiFindingRecord],
) -> std::collections::BTreeMap<String, Vec<PiiKind>> {
    let mut map: std::collections::BTreeMap<String, Vec<PiiKind>> =
        std::collections::BTreeMap::new();
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
            status: Some(200),
            error_kind: None,
        }
    }

    #[test]
    fn history_item_maps_fields() {
        let row = HistoryRow {
            request: sample_request("r1", 1000),
            response: Some(sample_response("r1")),
            pii_count: 2,
            safety_count: 0,
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
            safety_count: 0,
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
        let view = detected_engine_view(&info, "healthy", true);
        assert_eq!(view.engine, "ollama");
        assert_eq!(view.public_port, 11434, "must surface the upstream port");
        assert_eq!(view.shadow_port, None);
        assert_eq!(view.adoption_state, AdoptionState::Cooperative);
        assert_eq!(view.version.as_deref(), Some("0.5.0"));
        assert_eq!(view.health, "healthy");
        assert!(view.is_active, "the upstream engine is the active one");
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
            eval_metrics: std::sync::Arc::new(crate::proxy::EvalMetrics::default()),
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
