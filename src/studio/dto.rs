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
    /// Upstream HTTP status, if a response was received (`null` = never reached
    /// the engine).
    pub status: Option<u16>,
    /// Transport-level failure tag (`upstream_unreachable` / `stream_error`), or
    /// `null` for a normal HTTP response. A row is "failed" when `error_kind` is
    /// set OR `status >= 400`.
    pub error_kind: Option<String>,
    /// True when the eval pipeline flagged a safety category on this exchange
    /// (for the row's safety badge). Async — set on stored rows; live rows get it
    /// via a `Safety` stream event after evaluation completes.
    #[serde(default)]
    pub safety_flagged: bool,
}

/// One quality-judge score as shown in the History detail drawer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvalView {
    /// Metric (e.g. `relevance`).
    pub metric: String,
    /// Banded verdict (e.g. `good` / `weak`).
    pub band: String,
    /// Optional short rationale.
    pub rationale: Option<String>,
    /// The judge model.
    pub judge_model: String,
}

/// One safety finding as shown in the History detail drawer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SafetyView {
    /// Category flagged (e.g. `self_harm`).
    pub category: String,
    /// Banded verdict (e.g. `flagged`).
    pub verdict: String,
    /// The guard that produced it (e.g. `deterministic:v1`).
    pub guard_model: String,
    /// Optional numeric score (model guards only).
    pub score: Option<f32>,
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
    /// Total requests ever recorded. `0` means no traffic has been captured yet
    /// (the Studio shows the onboarding / "point an app at the proxy" card).
    pub lifetime_requests: u64,
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
    /// Only failed exchanges (transport error / HTTP >= 400).
    #[serde(default)]
    pub failed_only: bool,
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
    /// Safety findings on this exchange (eval pipeline).
    #[serde(default)]
    pub safety: Vec<SafetyView>,
    /// Quality-judge scores on this exchange (eval pipeline).
    #[serde(default)]
    pub eval: Vec<EvalView>,
    /// Raw prompt, present only when payload storage is on.
    pub prompt: Option<String>,
    /// Raw response, present only when payload storage is on.
    pub response: Option<String>,
    /// True when payload storage was off, so prompt/response are intentionally null.
    pub payloads_disabled: bool,
}

/// One time bucket in the Quality page series.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QualityBucket {
    /// Bucket start (unix millis).
    pub ts: i64,
    /// Distinct exchanges flagged by the safety guard in this bucket.
    pub flagged: u64,
    /// Quality scores banded `good` in this bucket.
    pub good: u64,
    /// Quality scores banded `weak` in this bucket.
    pub weak: u64,
}

/// `GET /api/quality` — the eval pipeline's safety/quality summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QualityReport {
    /// Window length (millis) + when computed + bucket width, for the series.
    pub range_ms: i64,
    pub generated_ts: i64,
    pub bucket_ms: i64,
    /// Time series over the window (ascending).
    pub series: Vec<QualityBucket>,
    /// Requests in the window (coverage denominator).
    pub requests_in_window: u64,
    /// Distinct exchanges judged in the window (coverage numerator).
    pub judged_in_window: u64,
    /// Whether the eval pipeline is enabled.
    pub eval_enabled: bool,
    /// Whether the deterministic safety guard is on.
    pub safety_enabled: bool,
    /// Whether the model-backed quality judge is on (Phase 4).
    pub quality_enabled: bool,
    /// LLM-judge sampling fraction (0..1).
    pub sample_rate: f32,
    /// Distinct exchanges with at least one safety flag.
    pub total_flagged: u64,
    /// Safety findings bucketed by category (descending).
    pub by_category: Vec<NamedCount>,
    /// Distinct exchanges the quality judge scored.
    pub total_judged: u64,
    /// Quality scores bucketed by metric (good vs weak counts).
    pub eval_by_metric: Vec<MetricBands>,
    /// Judge calls currently in flight (contention gauge).
    pub judge_inflight: u32,
    /// Judge calls that ran to completion (lifetime).
    pub judge_completed: u64,
    /// Judge calls dropped because all concurrency slots were busy (lifetime).
    pub judge_dropped: u64,
    /// Recent flagged exchanges (for the table).
    pub recent_flagged: Vec<HistoryItem>,
}

/// Good/weak counts for one quality metric.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricBands {
    /// Metric name (e.g. `relevance`).
    pub metric: String,
    /// Count banded `good`.
    pub good: u64,
    /// Count banded anything else (weak).
    pub weak: u64,
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
    /// When masking is enabled, whether it is dry-run (observe only, nothing
    /// redacted) vs live (redacting). Lets the UI say "observing" vs "redacting".
    pub masking_dry_run: bool,
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
    /// True when this is the engine the proxy currently forwards to (the active
    /// upstream). Other detected engines are shown but marked inactive.
    pub is_active: bool,
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
    /// PII kinds that stop a request outright instead of being masked. Empty
    /// (default) means nothing is ever blocked.
    #[serde(default)]
    pub masking_block_kinds: Vec<PiiKind>,
    /// The shared team policy in force, if any. When present and active, the
    /// settings it names are read-only here and the UI says why.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<crate::policy::PolicyStatus>,
    /// Eval pipeline master switch (off by default).
    #[serde(default)]
    pub eval_enabled: bool,
    /// Run the deterministic safety guard when eval is on.
    #[serde(default)]
    pub eval_safety: bool,
    /// Run the model-backed quality judge when eval is on (Phase 4).
    #[serde(default)]
    pub eval_quality: bool,
    /// LLM-judge sampling fraction (0..1).
    #[serde(default)]
    pub eval_sample_rate: f32,
    /// Model the quality judge asks (on the user's own engine). Empty = unset
    /// (the judge is inert until a model is chosen).
    #[serde(default)]
    pub eval_judge_model: Option<String>,
    /// AI-analysis backend master switch (Codex + ChatGPT subscription). Off by
    /// default; the only feature that sends session text off-device.
    #[serde(default)]
    pub analysis_enabled: bool,
    /// Whether the Codex backend is even usable here (binary present + authed).
    /// When false, the toggle is moot (nothing to enable).
    #[serde(default)]
    pub analysis_available: bool,
    /// Preservation archive master switch (opt-in).
    #[serde(default)]
    pub archive_enabled: bool,
    /// Auto-snapshot on start + periodically.
    #[serde(default)]
    pub archive_auto: bool,
    /// Replace detected secrets with a placeholder before archiving (opt-in, lossy).
    #[serde(default)]
    pub archive_redact: bool,
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
    #[serde(default)]
    pub masking_block_kinds: Option<Vec<PiiKind>>,
    /// Toggle the eval pipeline (safety guard + judge). Async, off hot path.
    pub eval_enabled: Option<bool>,
    /// Toggle the deterministic safety guard.
    pub eval_safety: Option<bool>,
    /// Toggle the model-backed quality judge (Phase 4).
    pub eval_quality: Option<bool>,
    /// Set the LLM-judge sampling fraction (0..1).
    pub eval_sample_rate: Option<f32>,
    /// Set the quality-judge model (empty string clears it).
    pub eval_judge_model: Option<String>,
    /// Toggle the AI-analysis backend (Codex + subscription). Enabling is an
    /// explicit user action — it permits sending session text to OpenAI via Codex.
    pub analysis_enabled: Option<bool>,
    /// Toggle the Preservation archive (durable local copy of agent history).
    pub archive_enabled: Option<bool>,
    /// Toggle automatic snapshots.
    pub archive_auto: Option<bool>,
    #[serde(default)]
    pub archive_redact: Option<bool>,
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
    /// A safety guard flagged a (now-evaluated) exchange. Arrives asynchronously
    /// after the exchange finished — the Live/History row badges retroactively.
    Safety {
        /// Exchange id.
        id: String,
        /// Category flagged (e.g. `self_harm`).
        category: String,
        /// Banded verdict (e.g. `flagged`).
        verdict: String,
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
    /// Whether `POST /api/update` can actually self-apply on this install.
    /// False for dev/`cargo install` builds (no receipt) and for the macOS
    /// `.app` (DMG) install, where self-update would touch the wrong binary.
    pub apply_supported: bool,
    /// When `applySupported` is false: the guidance to show instead of the
    /// update button (how this install updates).
    pub apply_note: Option<String>,
    /// When `applySupported` is false: where to get the update by hand (the
    /// releases page).
    pub release_url: Option<String>,
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

/// `POST /api/demo` result — the one-click "send a test prompt" outcome. The
/// demo fires a real chat request (with synthetic PII in the prompt) THROUGH the
/// proxy to the local engine, so a captured exchange appears live in the Studio
/// without the user touching a terminal.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DemoResult {
    /// True if the request reached the proxy (and was therefore captured),
    /// regardless of whether the engine produced a completion.
    pub captured: bool,
    /// The model the demo used, if one was detected on the engine.
    pub model: Option<String>,
    /// Short human note for the UI (what happened / what to do next).
    pub note: String,
}

/// One coding tool's presence + rollup (Agents overview).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentToolStat {
    /// Stable key (`claude_code`, `codex`, `opencode`, `cursor`).
    pub tool: String,
    /// Human label.
    pub label: String,
    /// History present on this machine?
    pub present: bool,
    /// Session count (as listed; may be capped).
    pub sessions: u32,
    /// Total tokens (in + out) across listed sessions.
    pub tokens: u64,
    /// Estimated USD cost across listed sessions.
    pub cost_usd: f64,
    /// Most recent activity (unix millis).
    pub last_active: i64,
}

/// Whether the optional AI-analysis backend (Codex + subscription) is present
/// and enabled — drives the "Summarize" affordance in the UI.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisStatus {
    /// Codex is installed and authenticated on this machine.
    pub available: bool,
    /// The user has opted the feature on in Settings.
    pub enabled: bool,
    /// Configured model, if pinned (`None` = Codex default).
    pub model: Option<String>,
}

/// One tool's retention behavior + what's at risk (Preservation awareness).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AtRiskView {
    pub tool: String,
    pub label: String,
    /// `age_days` | `churn` | `keeps_all` | `unknown`.
    pub kind: String,
    /// Age cutoff in days when `kind == age_days`.
    pub days: Option<u32>,
    /// Plain-language description.
    pub note: String,
    pub total: u32,
    pub expiring_soon: u32,
    pub overdue: u32,
    pub soonest_expiry_ts: Option<i64>,
}

/// Archive footprint + switches (Preservation).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveStatusView {
    pub enabled: bool,
    pub auto: bool,
    /// Sessions preserved.
    pub count: u64,
    /// Messages preserved.
    pub messages: u64,
    /// Approximate bytes stored.
    pub bytes: u64,
}

/// `GET /api/agents` — the Agents overview.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentsOverview {
    /// Per-tool stats (all tools, present or not).
    pub tools: Vec<AgentToolStat>,
    pub total_sessions: u32,
    pub total_tokens: u64,
    pub total_cost_usd: f64,
    /// AI-analysis backend status.
    pub analysis: AnalysisStatus,
    /// Per-tool retention + at-risk breakdown.
    pub at_risk: Vec<AtRiskView>,
    /// Archive footprint + switches.
    pub archive: ArchiveStatusView,
}

/// `POST /api/archive/export` — bulk export result.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportSummary {
    /// Sessions written.
    pub count: u32,
    /// Sessions that failed to write.
    pub errors: u32,
    /// Absolute destination directory.
    pub dir: String,
}

/// `POST /api/agents/sessions/:id/summarize` — an AI summary of one session.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SummaryResult {
    /// The generated summary text.
    pub summary: String,
    /// Model that produced it, if known.
    pub model: Option<String>,
    /// Wall-clock time (millis).
    pub elapsed_ms: u64,
}

/// A source-tagged coding-agent session summary.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentSessionView {
    pub id: String,
    /// Source tool key + label (the tag).
    pub tool: String,
    pub label: String,
    pub title: Option<String>,
    pub project: Option<String>,
    pub git_branch: Option<String>,
    pub model: Option<String>,
    pub started_ts: i64,
    pub updated_ts: i64,
    pub message_count: u32,
    pub tool_call_count: u32,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_tokens: u64,
    pub cost_usd: f64,
    /// PII findings on this session (present in detail; 0 in list for speed).
    pub pii_count: u32,
    /// The file the session was read from (source tag).
    pub source_path: String,
    /// A durable copy exists in Saffev's archive.
    #[serde(default)]
    pub preserved: bool,
    /// The source app has deleted its copy; Saffev's archive is the only one left.
    #[serde(default)]
    pub source_deleted: bool,
    /// Excerpts showing why this session matched a content search. Empty unless
    /// the current query matched inside the transcript. Matched terms are wrapped
    /// in `‹` … `›` for the UI to mark up.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub snippets: Vec<String>,
    /// How many messages in this session matched the content search (0 if the
    /// session matched on metadata only).
    #[serde(default)]
    pub match_count: u32,
}

/// One message in a session transcript.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentMessageView {
    pub role: String,
    pub kind: String,
    pub content: String,
    pub ts: Option<i64>,
    pub tool_name: Option<String>,
}

/// `GET /api/agents/sessions/:id` — full transcript + PII lens.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentSessionDetailView {
    pub session: AgentSessionView,
    pub messages: Vec<AgentMessageView>,
    /// PII findings across the transcript (what was pasted into the agent).
    pub pii: Vec<PiiFindingView>,
}

/// Per-model rollup for the Agents analytics.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentModelStat {
    pub model: String,
    pub sessions: u32,
    pub tokens: u64,
    pub cost_usd: f64,
}

/// `GET /api/agents/analytics` — cross-session rollups.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentAnalytics {
    pub total_sessions: u32,
    pub total_tokens: u64,
    pub total_cost_usd: f64,
    pub total_tool_calls: u64,
    pub by_tool: Vec<AgentToolStat>,
    pub by_model: Vec<AgentModelStat>,
    /// ccusage-parity usage engine (G3): per-request events from Claude Code
    /// JSONL — daily rows, 5-hour billing blocks, live burn, plan progress.
    /// `None` when no per-request usage data exists on this machine.
    pub usage: Option<UsageReport>,
}

/// The G3 usage report (Claude Code per-request data; UTC grouping).
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageReport {
    /// The pricing table's verification date — surfaced so pricing drift is
    /// documented, never silent.
    pub pricing_as_of: String,
    /// Recent UTC days (capped), newest last.
    pub daily: Vec<crate::agents::usage::DailyRow>,
    /// Recent 5-hour billing blocks (capped), gaps included, newest last.
    pub blocks: Vec<crate::agents::usage::Block>,
    /// Overall totals across all events.
    pub totals: crate::agents::usage::Tally,
    /// Progress within the ACTIVE billing block against the configured plan
    /// (None when no block is active or no plan is configured).
    pub plan: Option<PlanProgress>,
}

/// Locally-computed plan usage for the active 5-hour block. The allowances
/// are configured estimates (plans are not published as exact token grants);
/// the label always says what the number is compared to.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanProgress {
    /// Plan name ("pro", "max5x", "max20x", or custom).
    pub plan: String,
    /// Estimated cost allowance per 5-hour block (USD, configured).
    pub block_cost_allowance_usd: f64,
    /// Cost spent in the active block so far.
    pub spent_usd: f64,
    /// spent / allowance, clamped to [0, 1+].
    pub used_fraction: f64,
    /// Millis until the active block resets.
    pub resets_in_ms: i64,
}

// ===========================================================================
// Agent privacy report (`GET /api/agents/privacy?rangeMs=...`)
//
// The cross-history answer to "where did I leak a secret?", computed over the
// preserved archive. Counts and kinds only — never the matched text.
// ===========================================================================

/// A `(name, count)` pair for the grouped breakdowns.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentPiiGroup {
    pub name: String,
    pub count: u64,
}

/// A per-kind count, flagged when the kind over-matches on source code so the UI
/// can show it without letting it inflate the headline.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentPiiKind {
    pub name: String,
    pub count: u64,
    pub noisy: bool,
}

/// One session containing findings, for the drill-down table.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentPiiSession {
    pub session_id: String,
    pub tool: String,
    pub label: String,
    pub title: Option<String>,
    pub project: Option<String>,
    pub updated_ts: i64,
    pub findings: u32,
    /// Of those, how many were in a message the user wrote.
    pub user_side: u32,
    pub kinds: Vec<String>,
}

/// How much of the history the scan could see. Surfaced so the report never
/// implies it examined sessions it could not reach.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentPiiCoverage {
    /// Sessions preserved in the archive (what was scanned).
    pub preserved: u32,
    /// Sessions visible on this machine in total.
    pub total: u32,
    /// True when the archive is off, so the report is empty for that reason
    /// rather than because nothing was found.
    pub archive_enabled: bool,
}

/// The whole-history privacy report.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentPrivacyReport {
    pub generated_ts: i64,
    pub range_ms: i64,
    pub sessions_with_findings: u32,
    pub total_findings: u64,
    /// Findings in messages the user wrote.
    pub user_side_findings: u64,
    /// Findings excluding kinds that over-match on code — the number worth
    /// showing a person.
    pub high_signal_findings: u64,
    /// The headline: high-signal findings in messages the user wrote.
    pub high_signal_user_side: u64,
    pub by_kind: Vec<AgentPiiKind>,
    pub by_tool: Vec<AgentPiiGroup>,
    pub by_project: Vec<AgentPiiGroup>,
    pub top_sessions: Vec<AgentPiiSession>,
    pub coverage: AgentPiiCoverage,
}

// ===========================================================================
// Unified timeline (`GET /api/timeline`)
//
// Saffev sees AI activity two different ways: model calls proxied through it,
// and coding-agent sessions read off disk. They were separate pages with
// separate searches, so nobody could ask one question and get one answer. This
// is the single chronological record of everything AI touched on this machine.
// ===========================================================================

/// Where a timeline entry came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TimelineKind {
    /// A model call that went through the proxy.
    Proxy,
    /// A coding-agent session read from that tool's own history.
    Agent,
}

/// One entry in the unified timeline.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineEntry {
    /// Id, routed back to the right detail view by `kind`.
    pub id: String,
    pub kind: TimelineKind,
    /// When it happened (unix millis).
    pub ts: i64,
    /// Where it came from, for the badge: an app name for proxied calls, a tool
    /// key for agent sessions.
    pub source: String,
    /// Human label for `source`.
    pub label: String,
    /// One-line description: the endpoint, or the session title.
    pub title: String,
    pub model: Option<String>,
    /// Project, for agent sessions.
    pub project: Option<String>,
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// PII findings recorded against this entry, when known.
    pub pii_count: u32,
    /// The exchange failed (transport error or HTTP >= 400).
    #[serde(default)]
    pub failed: bool,
    /// The safety guard flagged this exchange.
    #[serde(default)]
    pub safety_flagged: bool,
    /// A durable copy exists in the archive (agent sessions).
    #[serde(default)]
    pub preserved: bool,
    /// Excerpts explaining a content-search match.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub snippets: Vec<String>,
}

/// `GET /api/timeline` — the merged record, plus what it could see.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineView {
    pub entries: Vec<TimelineEntry>,
    /// Proxied exchanges considered.
    pub proxy_count: u32,
    /// Agent sessions considered.
    pub agent_count: u32,
    /// True when content search was available (i.e. something is preserved), so
    /// the UI can say what the search actually covered.
    pub content_search: bool,
}

/// `GET /api/archive/verify` — the integrity-chain verdict.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveIntegrityView {
    /// Entries in the chain.
    pub entries: u64,
    /// Distinct sessions covered.
    pub sessions: u64,
    /// Everything recomputed correctly and nothing was altered after the fact.
    pub intact: bool,
    /// Plain-language description of the first problem found, if any.
    pub broken_at: Option<String>,
    /// Sessions whose stored content no longer matches what was recorded.
    pub altered_sessions: Vec<String>,
    /// Newest entry digest — the value to record elsewhere to anchor the archive.
    pub head_digest: Option<String>,
    pub head_ts: Option<i64>,
}

/// `POST /api/archive/audit` — where the bundle was written.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditExportResult {
    pub dir: String,
    pub sessions: u32,
    pub errors: u32,
    pub intact: bool,
    pub head_digest: Option<String>,
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
    /// How much of `total_input_tokens` was ESTIMATED by the bundled tokenizer
    /// rather than reported by the engine. Surfaced so a headline number is never
    /// presented as exact when part of it is a guess.
    #[serde(default)]
    pub estimated_input_tokens: u64,
    /// Same, for `total_output_tokens`.
    #[serde(default)]
    pub estimated_output_tokens: u64,
    pub p50_latency_ms: Option<u32>,
    pub p90_latency_ms: Option<u32>,
    pub p99_latency_ms: Option<u32>,
    pub avg_ttft_ms: Option<u32>,
    pub pii_findings: u64,
    /// Requests that failed (transport error, or HTTP status >= 400) in-window.
    pub failed_requests: u64,
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
    pub prev_failed_requests: u64,

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
    /// Failed exchanges (transport error / HTTP >= 400) in this bucket.
    pub failed: u64,
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
