//! Studio HTTP API data-transfer objects — the wire contract.
//!
//! These structs are the JSON shapes exchanged with the SPA. Both the backend
//! and frontend agents code to them verbatim. **Do not change a field without
//! updating both sides.** All are `serde`-(de)serializable. Field naming is
//! `camelCase` on the wire (matching the SPA's JS conventions).

use serde::{Deserialize, Serialize};

use crate::brain::{Confidence, PiiKind, Side};
use crate::config::{HandoverPolicy, Mode, Retention};
use crate::store::{AdoptionState, SourceConfidence, TokenSource};

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

/// Uniform error envelope for any failed `/api/*` call.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiError {
    /// Machine-readable code (e.g. `unauthorized`, `bad_host`, `not_found`).
    pub error: String,
    /// Human-readable message.
    pub message: String,
}
