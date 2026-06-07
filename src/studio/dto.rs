//! Studio HTTP API data-transfer objects — the wire contract.
//!
//! These structs are the JSON shapes exchanged with the SPA. Both the backend
//! and frontend agents code to them verbatim. **Do not change a field without
//! updating both sides.** All are `serde`-(de)serializable. Field naming is
//! `camelCase` on the wire (matching the SPA's JS conventions).

use serde::{Deserialize, Serialize};

use crate::brain::{Confidence, PiiKind, Side};
use crate::config::{HandoverPolicy, Mode, Retention};
use crate::store::{AdoptionState, PiiAction, SourceConfidence, TokenSource};

/// `GET /api/health` — liveness + identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Health {
    /// Always `"saffev"`.
    pub app: String,
    /// Crate version.
    pub version: String,
    /// Whether the proxy is currently serving.
    pub proxy_up: bool,
    /// Active interception mode.
    pub mode: Mode,
}

/// One row in the live/history feeds — a single proxied exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryItem {
    /// Request id (uuid).
    pub id: String,
    /// Timestamp (unix millis).
    pub ts: i64,
    /// Source application name, or null.
    pub source_app: Option<String>,
    /// Attribution confidence.
    pub source_confidence: SourceConfidence,
    /// Engine name.
    pub engine: String,
    /// Model, if known.
    pub model: Option<String>,
    /// Endpoint path.
    pub endpoint: String,
    /// Whether it streamed.
    pub stream: bool,
    /// Input tokens, if known.
    pub input_tokens: Option<u32>,
    /// Provenance of input tokens (`~` shown for estimated).
    pub input_tokens_src: TokenSource,
    /// Output tokens, if known.
    pub output_tokens: Option<u32>,
    /// Provenance of output tokens.
    pub output_tokens_src: TokenSource,
    /// End-to-end latency (millis).
    pub latency_ms: Option<u32>,
    /// Time to first token (millis).
    pub ttft_ms: Option<u32>,
    /// Count of PII findings on this exchange.
    pub pii_count: u32,
    /// Distinct PII kinds present (for badges), e.g. `["email","api_key"]`.
    pub pii_kinds: Vec<PiiKind>,
}

/// `GET /api/live` — current snapshot of recent activity + headline KPIs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveSnapshot {
    /// Most recent exchanges (newest first).
    pub recent: Vec<HistoryItem>,
    /// Requests in the last 24h.
    pub requests_today: u64,
    /// Median latency (millis) over the recent window.
    pub p50_latency_ms: Option<u32>,
    /// PII findings in the last 24h.
    pub pii_findings_today: u64,
}

/// `GET /api/history` query parameters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryParams {
    /// Free-text filter (app/model/endpoint).
    pub q: Option<String>,
    /// Only exchanges with PII findings.
    #[serde(default)]
    pub pii_only: bool,
    /// Page size (server clamps).
    pub limit: Option<u32>,
    /// Cursor: rows with `ts` strictly before this (millis).
    pub before_ts: Option<i64>,
}

/// One PII finding as shown in the History detail + Privacy page.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PiiFindingView {
    /// PII category.
    pub kind: PiiKind,
    /// Custom-pattern label, if any.
    pub label: Option<String>,
    /// Side it was found on.
    pub side: Side,
    /// Start offset.
    pub start: usize,
    /// End offset.
    pub end: usize,
    /// Confidence.
    pub confidence: Confidence,
    /// What masking did with this span: `observed` (logged only), `would_mask`
    /// (dry-run preview, traffic unchanged), or `masked` (redacted before
    /// forwarding). Lets the Studio/Privacy view show the masking outcome (§7.6).
    pub action: PiiAction,
}

/// `GET /api/history/:id` — full detail for one exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryDetail {
    /// The summary row.
    pub item: HistoryItem,
    /// PII findings on this exchange.
    pub findings: Vec<PiiFindingView>,
    /// Raw prompt, present only when payload storage is on.
    pub prompt: Option<String>,
    /// Raw response, present only when payload storage is on.
    pub response: Option<String>,
    /// True when payload storage was off, so prompt/response are intentionally null.
    pub payloads_disabled: bool,
}

/// One bucket in the Privacy page breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyBucket {
    /// PII category.
    pub kind: PiiKind,
    /// Total count for this kind.
    pub count: u64,
    /// Count on the request side.
    pub request_count: u64,
    /// Count on the response side.
    pub response_count: u64,
}

/// `GET /api/privacy` — aggregated PII view.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacySummary {
    /// Per-kind breakdown.
    pub by_kind: Vec<PrivacyBucket>,
    /// Per-app finding counts (`appName -> count`).
    pub by_app: Vec<NamedCount>,
    /// Per-model finding counts.
    pub by_model: Vec<NamedCount>,
    /// Total findings across the retained window.
    pub total: u64,
    /// Whether opt-in masking is currently enabled (§7.6; false in v0).
    pub masking_enabled: bool,
}

/// A `(name, count)` pair for breakdown lists.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NamedCount {
    /// The name (app or model).
    pub name: String,
    /// The count.
    pub count: u64,
}

/// One engine as shown on the Engines page.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineView {
    /// Engine name.
    pub engine: String,
    /// Version, if known.
    pub version: Option<String>,
    /// Public port the proxy owns.
    pub public_port: u16,
    /// Shadow port (Gateway), if any.
    pub shadow_port: Option<u16>,
    /// Adoption state.
    pub adoption_state: AdoptionState,
    /// Live health string (`healthy` / `starting` / `down`).
    pub health: String,
}

/// `GET /api/engines` — engines + the exposure result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnginesView {
    /// Detected / managed engines.
    pub engines: Vec<EngineView>,
    /// Current mode.
    pub mode: Mode,
    /// Exposure doctor verdict.
    pub exposure: crate::exposure::ExposureReport,
}

/// `POST /api/engines/adopt` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdoptRequest {
    /// Engine to adopt (e.g. `ollama`).
    pub engine: String,
    /// Force Cooperative mode instead of Gateway.
    #[serde(default)]
    pub cooperative: bool,
}

/// `POST /api/engines/revert` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevertRequest {
    /// Engine to revert.
    pub engine: String,
}

/// `GET /api/settings` — current settings (token never included).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsView {
    /// Interception mode.
    pub mode: Mode,
    /// Whether raw payloads are stored (privacy default: false).
    pub payload_storage: bool,
    /// Retention policy.
    pub retention: Retention,
    /// Supervisor handover policy.
    pub handover: HandoverPolicy,
    /// Data directory (display only).
    pub data_dir: String,
    /// Custom PII pattern labels currently configured.
    pub custom_patterns: Vec<String>,
    /// Proxy port.
    pub proxy_port: u16,
    /// Studio port.
    pub studio_port: u16,
    /// Opt-in PII masking master switch (04 §7.6; observe-only default: false).
    pub masking_enabled: bool,
    /// Masking dry-run: when true (default), record what *would* be masked but
    /// forward traffic unchanged. Only `enabled && !dry_run` redacts requests.
    pub masking_dry_run: bool,
    /// Fields whose new value was persisted to TOML but is **not** applied to the
    /// running process because it cannot be safely changed at runtime — `mode` and
    /// the ports rebind the listeners / re-adopt the engine. Empty when the last
    /// update was fully hot-applied. Each entry is the changed field name (e.g.
    /// `"mode"`, `"proxy_port"`). The values shown above for these fields reflect
    /// the **still-running** config until the next `saffev start`.
    #[serde(default)]
    pub restart_required: Vec<String>,
    /// Human-readable note when `restart_required` is non-empty (else `None`).
    #[serde(default)]
    pub restart_note: Option<String>,
}

/// `PUT /api/settings` — partial update; only present fields change. Toggling
/// `payloadStorage` on is an explicit, logged user action.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsUpdate {
    /// New mode.
    pub mode: Option<Mode>,
    /// New payload-storage flag.
    pub payload_storage: Option<bool>,
    /// New retention policy.
    pub retention: Option<Retention>,
    /// New handover policy.
    pub handover: Option<HandoverPolicy>,
    /// Toggle opt-in PII masking (04 §7.6). Enabling is an explicit user action.
    pub masking_enabled: Option<bool>,
    /// Toggle masking dry-run. Setting this to `false` turns on real request
    /// redaction — the only traffic-mutating action in v1.
    pub masking_dry_run: Option<bool>,
}

/// SSE payload pushed on `/api/stream`. Tagged by `type` so the SPA can switch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum StreamEvent {
    /// A new exchange started (live row appears).
    RequestStarted {
        /// The (partial) item; response fields may be null until finished.
        item: HistoryItem,
    },
    /// A streamed token chunk arrived (for the blinking-caret live row).
    Token {
        /// Exchange id.
        id: String,
    },
    /// The exchange finished (row settles with final timing/tokens).
    Finished {
        /// The completed item.
        item: HistoryItem,
    },
    /// A PII finding was observed on a live exchange.
    Pii {
        /// Exchange id.
        id: String,
        /// The finding.
        finding: PiiFindingView,
    },
}

/// `GET /api/update` — in-app update availability.
///
/// PRIVACY: producing this contacts GitHub release metadata ONLY — no user or
/// content data leaves the device (the on-device invariant). Fail-soft: on any
/// network error `latestVersion` is null and `updateAvailable` is false.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateStatus {
    /// The version this Studio's binary currently is (`CARGO_PKG_VERSION`).
    pub current_version: String,
    /// The latest released version, or null if it couldn't be determined
    /// (offline / no release / not installed via the installer).
    pub latest_version: Option<String>,
    /// Whether a newer release than `currentVersion` is available. Always false
    /// when `latestVersion` is null (never claim an update we can't confirm).
    pub update_available: bool,
}

/// `POST /api/update` — result of applying an update.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateResult {
    /// Whether an update was actually installed (false = already current).
    pub updated: bool,
    /// The version now installed (or current, if already up to date).
    pub new_version: String,
    /// A human-readable note for the UI to display (success or guidance).
    pub message: String,
}

/// `POST /api/restart` — acknowledgement that a relaunch was scheduled. The
/// daemon stops + starts itself via a detached helper; the SPA then polls
/// `/api/health` and reloads once it's back.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestartResult {
    /// Always true when the relaunch helper was spawned successfully.
    pub restarting: bool,
}

/// Uniform error envelope for any failed `/api/*` call.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiError {
    /// Machine-readable code (e.g. `unauthorized`, `bad_host`, `not_found`).
    pub error: String,
    /// Human-readable message.
    pub message: String,
}

// ===========================================================================
// Analytics (`GET /api/analytics?rangeMs=...`)
//
// A single comprehensive report for the selected time window, computed entirely
// on-device from the encrypted store. The SPA renders every chart from this.
// ===========================================================================

/// The full analytics report for one time window.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalyticsReport {
    /// Window length requested (millis).
    pub range_ms: i64,
    /// Server clock when computed (unix millis) — the window is `[now-range, now]`.
    pub generated_ts: i64,
    /// Bucket width used for the time series (millis).
    pub bucket_ms: i64,

    // ---- headline KPIs ----
    pub total_requests: u64,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub p50_latency_ms: Option<u32>,
    pub p90_latency_ms: Option<u32>,
    pub p99_latency_ms: Option<u32>,
    pub avg_ttft_ms: Option<u32>,
    pub pii_findings: u64,
    pub active_apps: u64,
    pub active_models: u64,
    /// Estimated $ saved vs cloud pricing (see `cost_basis`).
    pub est_cost_saved_usd: f64,
    /// Label describing the pricing assumption (e.g. "GPT-4o pricing").
    pub cost_basis: String,

    // ---- deltas vs the immediately-preceding window of equal length ----
    pub prev_total_requests: u64,
    pub prev_total_tokens: u64,
    pub prev_p50_latency_ms: Option<u32>,
    pub prev_pii_findings: u64,

    // ---- time series (one entry per bucket, ascending) ----
    pub series: Vec<AnalyticsBucket>,

    // ---- breakdowns ----
    pub by_app: Vec<GroupStat>,
    pub by_model: Vec<ModelStat>,
    pub by_endpoint: Vec<GroupStat>,

    // ---- performance ----
    pub ttft_histogram: Vec<HistBin>,
    pub input_token_histogram: Vec<HistBin>,
    pub latency_vs_output: Vec<XYPoint>,
    pub finish_reasons: Vec<NamedCount>,
    pub slowest: Vec<HistoryItem>,

    // ---- usage patterns ----
    /// Local day-of-week (0=Sun..6=Sat) × hour (0..23) request counts.
    pub heatmap: Vec<HeatCell>,

    // ---- privacy ----
    pub pii_by_kind: Vec<PiiKindStat>,
    pub pii_by_action: Vec<NamedCount>,
    pub pii_by_app: Vec<NamedCount>,
    pub pii_request_side: u64,
    pub pii_response_side: u64,

    // ---- plain-english, actionable insights ----
    pub insights: Vec<Insight>,
}

/// One time bucket of the activity series.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalyticsBucket {
    /// Bucket start (unix millis).
    pub ts: i64,
    pub requests: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub p50_latency_ms: Option<u32>,
    pub pii: u64,
}

/// Aggregate stats for a named group (app or endpoint).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupStat {
    pub name: String,
    pub requests: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub avg_latency_ms: Option<u32>,
    pub pii: u64,
}

/// Per-model performance + usage.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelStat {
    pub name: String,
    pub requests: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub p50_latency_ms: Option<u32>,
    pub avg_ttft_ms: Option<u32>,
    /// Decode throughput (output tokens / second), median over the model's
    /// completed streamed/non-streamed exchanges.
    pub tokens_per_sec: Option<f64>,
}

/// A histogram bin.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistBin {
    /// Inclusive lower edge.
    pub lo: u32,
    /// Exclusive upper edge (or u32::MAX for the open last bin).
    pub hi: u32,
    pub count: u64,
}

/// A scatter point (output tokens vs latency).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct XYPoint {
    pub x: f64,
    pub y: f64,
}

/// One heatmap cell.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeatCell {
    /// 0=Sunday .. 6=Saturday (local).
    pub dow: u8,
    /// 0..23 (local).
    pub hour: u8,
    pub count: u64,
}

/// PII findings for one kind, split by side.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PiiKindStat {
    pub kind: PiiKind,
    pub request_count: u64,
    pub response_count: u64,
}

/// An actionable insight derived from the data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Insight {
    /// `good` | `info` | `warn` — drives the icon/color.
    pub severity: String,
    pub title: String,
    pub detail: String,
}
