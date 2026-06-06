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
    let req: &RequestMeta = &row.request;
    let resp: Option<&ResponseMeta> = row.response.as_ref();
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
        latency_ms: req.latency_ms,
        ttft_ms: resp.and_then(|r| r.ttft_ms),
        pii_count: row.pii_count,
        pii_kinds,
    }
}

/// Project a store [`PiiFindingRecord`] into the wire [`dto::PiiFindingView`].
fn finding_view(rec: &PiiFindingRecord) -> dto::PiiFindingView {
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
    // proxy_up: best-effort liveness of the local engine/proxy public port.
    let proxy_up = probe_loopback(state.config.ports.proxy).await;
    Json(dto::Health {
        app: crate::brand::APP_NAME.to_lowercase(),
        version: crate::VERSION.to_string(),
        proxy_up,
        mode: state.config.mode,
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

    let recent: Vec<dto::HistoryItem> = rows.iter().map(|r| history_item(r, Vec::new())).collect();

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
            if let Some(ms) = r.request.latency_ms {
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

    let items: Vec<dto::HistoryItem> = rows.iter().map(|r| history_item(r, Vec::new())).collect();
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

    // Payloads are present only when payload storage is on.
    let payloads_disabled = !state.config.payload_storage;
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
        masking_enabled: state.config.masking.enabled,
    }))
}

/// `GET /api/engines`
pub async fn engines(State(state): State<StudioState>) -> Result<Json<dto::EnginesView>, Response> {
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
    let upstream = state.config.ports.upstream;
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
    let exposure = crate::exposure::check(state.config.ports.upstream)
        .await
        .unwrap_or_else(|_| crate::exposure::ExposureReport {
            exposed: false,
            bound_to: None,
            token_protected: false,
            detail: "exposure check unavailable".to_string(),
        });

    Ok(Json(dto::EnginesView {
        engines: views,
        mode: state.config.mode,
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
    let report = crate::exposure::check(state.config.ports.upstream)
        .await
        .unwrap_or_else(|_| crate::exposure::ExposureReport {
            exposed: false,
            bound_to: None,
            token_protected: false,
            detail: "exposure check unavailable".to_string(),
        });
    Ok(Json(report))
}

/// `GET /api/settings`
pub async fn settings_get(
    State(state): State<StudioState>,
) -> Result<Json<dto::SettingsView>, Response> {
    Ok(Json(settings_view(&state.config)))
}

/// `PUT /api/settings`
///
/// Note: this write-through persists to the TOML config, but the running proxy
/// and Studio hold an immutable `Arc<Config>` snapshot taken at startup, so
/// changes to traffic-affecting toggles (mode, payload storage, retention, and
/// PII masking) take effect on the **next `saffev start`**, not mid-process. The
/// returned [`dto::SettingsView`] reflects the just-saved file; a subsequent
/// `GET /api/settings` reflects the still-running snapshot until restart.
pub async fn settings_put(
    State(state): State<StudioState>,
    Json(body): Json<dto::SettingsUpdate>,
) -> Result<Json<dto::SettingsView>, Response> {
    // Apply the partial update onto a clone of the effective config, persist it
    // (write-through to TOML), and mirror critical toggles into the settings
    // table for audit. The token is never read or written here.
    let mut cfg = (*state.config).clone();

    if let Some(mode) = body.mode {
        cfg.mode = mode;
        state.store.enqueue(crate::store::WriteOp::Setting {
            key: "mode".to_string(),
            value: format!("{:?}", mode).to_lowercase(),
        });
    }
    if let Some(payload_storage) = body.payload_storage {
        cfg.payload_storage = payload_storage;
        // Toggling payload storage is an explicit, logged action (04 §7.9).
        state.store.enqueue(crate::store::WriteOp::Setting {
            key: "payload_storage".to_string(),
            value: payload_storage.to_string(),
        });
    }
    if let Some(retention) = body.retention {
        cfg.retention = retention;
        state.store.enqueue(crate::store::WriteOp::Setting {
            key: "retention".to_string(),
            value: serde_json::to_string(&retention).unwrap_or_default(),
        });
    }
    if let Some(handover) = body.handover {
        cfg.handover = handover;
        state.store.enqueue(crate::store::WriteOp::Setting {
            key: "handover".to_string(),
            value: format!("{:?}", handover).to_lowercase(),
        });
    }
    if let Some(masking_enabled) = body.masking_enabled {
        cfg.masking.enabled = masking_enabled;
        // Enabling masking is an explicit, logged action (04 §7.6, §7.9).
        state.store.enqueue(crate::store::WriteOp::Setting {
            key: "masking_enabled".to_string(),
            value: masking_enabled.to_string(),
        });
    }
    if let Some(masking_dry_run) = body.masking_dry_run {
        cfg.masking.dry_run = masking_dry_run;
        // Leaving dry-run (dry_run=false) is the step that turns on real request
        // redaction — log it explicitly.
        state.store.enqueue(crate::store::WriteOp::Setting {
            key: "masking_dry_run".to_string(),
            value: masking_dry_run.to_string(),
        });
    }

    cfg.save().map_err(internal)?;

    Ok(Json(settings_view(&cfg)))
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
}
