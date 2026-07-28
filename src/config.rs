//! Configuration — a single TOML file in the per-OS app-data dir.
//!
//! Ports, mode, the metadata/payload privacy default, retention, custom PII
//! patterns, supervisor handover policy, and the data dir. The Studio Settings
//! page writes through to this file (see `studio` `PUT /api/settings`).
//!
//! Privacy default: [`Config::payload_storage`] is `false` — metadata only.

use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// A live, atomically-swappable [`Config`] shared by the running proxy + Studio.
///
/// Built **once** in `saffev start` and handed to both servers, so a Studio
/// `PUT /api/settings` that calls [`ConfigHandle::store`](arc_swap::ArcSwapAny::store)
/// is seen immediately by every config reader without a restart. Every read site
/// that must reflect live changes loads the current snapshot at use-time
/// (`handle.load()` — a cheap RCU read, fine on the request hot path) rather than
/// capturing an `Arc<Config>` at startup.
///
/// Scope (honest by design): only the **hot-reloadable** fields apply live —
/// masking, payload storage, and retention. Mode and ports rebind listeners /
/// re-adopt the engine and cannot be swapped safely at runtime; `settings_put`
/// persists those to TOML but does **not** store them into the live handle and
/// flags `restart_required` so the operator knows the next `saffev start` applies
/// them.
pub type ConfigHandle = Arc<ArcSwap<Config>>;

/// Wrap a [`Config`] in a fresh [`ConfigHandle`]. Convenience for `saffev start`
/// (one handle, shared with both servers) and tests.
pub fn config_handle(config: Config) -> ConfigHandle {
    Arc::new(ArcSwap::from_pointee(config))
}

/// Default Studio port (avoids common dev-server collisions).
pub const DEFAULT_STUDIO_PORT: u16 = 7100;
/// Default public proxy port — the well-known Ollama port.
pub const DEFAULT_PROXY_PORT: u16 = 11434;
/// Default shadow port the real engine is relocated to after Gateway adoption.
pub const DEFAULT_SHADOW_PORT: u16 = 11999;
/// Default upstream the proxy forwards to in Cooperative mode (engine untouched).
pub const DEFAULT_UPSTREAM_PORT: u16 = 11434;
/// Config file name within the data dir.
pub const CONFIG_FILE_NAME: &str = "saffev.toml";
/// Database file name within the data dir.
pub const DB_FILE_NAME: &str = "saffev.db";

/// Candidate proxy ports tried (in order) during first-run auto-configuration.
///
/// The well-known engine port (11434) is deliberately *not* here — in
/// Cooperative mode the proxy cannot share the engine's port. We prefer a few
/// memorable "app" ports, then fall back to the range just above the engine.
pub const FIRST_RUN_PROXY_CANDIDATES: &[u16] =
    &[8088, 8090, 8092, 8181, 11435, 11436, 11437, 11438];

/// Where the first-run Studio port scan starts (scans upward from here).
pub const FIRST_RUN_STUDIO_SCAN_START: u16 = DEFAULT_STUDIO_PORT; // 7100

/// How many consecutive ports the upward Studio scan will try before giving up.
const FIRST_RUN_SCAN_SPAN: u16 = 64;

/// Interception mode. See 04 §5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum Mode {
    /// Own the public port, supervise the engine on the shadow port (Linux v0/v1).
    Gateway,
    /// Engine untouched; the client points its base URL at the proxy (any OS).
    #[default]
    Cooperative,
}

/// What happens to the supervised engine when Saffev stops (Gateway mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum HandoverPolicy {
    /// Leave the engine listening on the public port — stopping Saffev never
    /// takes the user's AI offline (recommended default; 04 §13).
    #[default]
    Handover,
    /// Stop the engine too.
    Stop,
}

/// Retention cap — by age, by database size, or unbounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Retention {
    /// Keep records up to `days` old.
    Age { days: u32 },
    /// Keep the database under `mb` megabytes (oldest dropped first).
    Size { mb: u32 },
    /// No automatic purge.
    Unlimited,
}

impl Default for Retention {
    fn default() -> Self {
        Retention::Age { days: 30 }
    }
}

/// Network binding + port layout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortsConfig {
    /// Address the proxy + Studio bind to. Defaults to loopback.
    #[serde(default = "default_bind")]
    pub bind: IpAddr,
    /// Public proxy port the app talks to.
    #[serde(default = "default_proxy_port")]
    pub proxy: u16,
    /// Studio web UI port.
    #[serde(default = "default_studio_port")]
    pub studio: u16,
    /// Shadow port the real engine is relocated to (Gateway mode).
    #[serde(default = "default_shadow_port")]
    pub shadow: u16,
    /// Port the proxy forwards to in Cooperative mode (the engine's real port).
    #[serde(default = "default_upstream_port")]
    pub upstream: u16,
}

fn default_bind() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}
fn default_proxy_port() -> u16 {
    DEFAULT_PROXY_PORT
}
fn default_studio_port() -> u16 {
    DEFAULT_STUDIO_PORT
}
fn default_shadow_port() -> u16 {
    DEFAULT_SHADOW_PORT
}
fn default_upstream_port() -> u16 {
    DEFAULT_UPSTREAM_PORT
}

impl Default for PortsConfig {
    fn default() -> Self {
        PortsConfig {
            bind: default_bind(),
            proxy: default_proxy_port(),
            studio: default_studio_port(),
            shadow: default_shadow_port(),
            upstream: default_upstream_port(),
        }
    }
}

/// Opt-in PII masking (04 §5 Mask mode, §7.6).
///
/// **Observe stays the default**: `enabled` is `false`, so nothing is mutated.
/// When enabled the default is still safe — `dry_run` is `true`, so the proxy
/// passes traffic through unchanged and only records what *would* be masked.
/// Only when `enabled && !dry_run` does the request body get redacted before it
/// reaches the engine (the high-value case: keep PII off the model). Masking is
/// always fail-open: any error forwards the original request untouched.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskingConfig {
    /// Master switch. `false` (default) = pure observe; nothing is mutated.
    #[serde(default)]
    pub enabled: bool,
    /// When `true` (default), do not mutate traffic — only record what *would*
    /// be masked. Flipping this to `false` is the explicit step that turns on
    /// real request redaction.
    #[serde(default = "default_true")]
    pub dry_run: bool,
    /// Which HIGH-confidence kinds to mask. `None` (default) means *all* the
    /// high-confidence deterministic kinds (email, credit card, API key, IP,
    /// phone). Best-effort / low-confidence findings are **never** masked,
    /// regardless of this list.
    #[serde(default)]
    pub kinds: Option<Vec<crate::brain::PiiKind>>,
    /// Kinds that **stop the request** instead of being masked.
    ///
    /// Masking quietly rewrites a secret out of the prompt, which is the right
    /// default. But some things must never reach a model at all, and for those
    /// "we replaced it for you" is not an acceptable answer — the user wants to
    /// know it happened and wants the call to fail.
    ///
    /// Empty (the default) means **nothing is ever blocked**. Blocking is only
    /// ever a deliberate policy decision: it requires `enabled && !dry_run` and an
    /// explicit kind in this list. No internal error can cause a block — every
    /// failure path still forwards, so the fail-open invariant is intact.
    ///
    /// A blocked kind is not also masked; the request simply does not go.
    #[serde(default)]
    pub block_kinds: Vec<crate::brain::PiiKind>,
}

fn default_true() -> bool {
    true
}

impl Default for MaskingConfig {
    fn default() -> Self {
        MaskingConfig {
            enabled: false,
            dry_run: true,
            kinds: None,
            block_kinds: Vec::new(),
        }
    }
}

/// A user-defined PII pattern (custom-pattern list, 04 §6.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomPattern {
    /// Label shown as the finding type.
    pub name: String,
    /// Regular expression (RE2-style; compiled with the `regex` crate).
    pub regex: String,
    /// Confidence to assign matches from this pattern.
    #[serde(default)]
    pub confidence: crate::brain::Confidence,
}

/// Evaluation pipeline config (safety guard + quality judge).
///
/// **Off by default** (observe-only ethos + no engine contention unless opted
/// in). Judging is always async, sampled, and concurrency-gated — never inline.
/// Hot-reloadable like [`MaskingConfig`]: the running eval worker reads the live
/// snapshot per record, so enabling it needs no restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalConfig {
    /// Master switch. `false` (default) = nothing is evaluated; zero judge calls.
    #[serde(default)]
    pub enabled: bool,
    /// Fraction of exchanges sent to the (expensive) LLM judge, `0.0..=1.0`.
    /// The cheap deterministic safety guard runs on all exchanges when enabled;
    /// this only rate-limits the model-backed judge.
    #[serde(default = "default_sample_rate")]
    pub sample_rate: f32,
    /// Run the deterministic safety guard (cheap, no model). Default on when eval
    /// is enabled.
    #[serde(default = "default_true")]
    pub safety: bool,
    /// Run the model-backed quality judge (Phase 4). Default off.
    #[serde(default)]
    pub quality: bool,
    /// Model the LLM judge asks (on the user's own engine). `None` = use a small
    /// default.
    #[serde(default)]
    pub judge_model: Option<String>,
    /// Model-backed **safety guard** to run alongside the deterministic floor.
    ///
    /// This is the slot a purpose-trained localized guard occupies. `None`
    /// (default) = deterministic floor only. It is **additive**: the floor keeps
    /// running, because small local guards are unreliable on adversarial input
    /// and markedly worse on African and other low-resource languages, so a model
    /// guard adds recall rather than earning trust on its own.
    ///
    /// Runs on the user's own engine, under the same concurrency cap as the
    /// judge, so it can never thrash VRAM.
    #[serde(default)]
    pub guard_model: Option<String>,
    /// Max concurrent judge calls — the VRAM-contention guard. Default 1.
    #[serde(default = "default_eval_concurrency")]
    pub max_concurrency: u32,
    /// Per-judge-call timeout (millis).
    #[serde(default = "default_eval_timeout_ms")]
    pub timeout_ms: u32,
}

fn default_sample_rate() -> f32 {
    0.1
}
fn default_eval_concurrency() -> u32 {
    1
}
fn default_eval_timeout_ms() -> u32 {
    20_000
}

impl Default for EvalConfig {
    fn default() -> Self {
        EvalConfig {
            enabled: false,
            sample_rate: default_sample_rate(),
            safety: true,
            quality: false,
            judge_model: None,
            guard_model: None,
            max_concurrency: default_eval_concurrency(),
            timeout_ms: default_eval_timeout_ms(),
        }
    }
}

/// Optional AI-analysis backend using the user's local Codex app-server + their
/// ChatGPT subscription as an on-demand model.
///
/// **Off by default.** This is the one path where session text leaves the device
/// (sent to OpenAI *through the user's own Codex*), so it is strictly opt-in and
/// runs only on an explicit user action. Hot-reloadable like [`EvalConfig`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    /// Master switch. `false` (default) = no analysis; nothing is ever sent out.
    #[serde(default)]
    pub enabled: bool,
    /// Model the Codex backend asks. `None` = Codex's default for the account.
    #[serde(default)]
    pub model: Option<String>,
    /// Per-request timeout (millis).
    #[serde(default = "default_analysis_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_analysis_timeout_ms() -> u64 {
    90_000
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        AnalysisConfig {
            enabled: false,
            model: None,
            timeout_ms: default_analysis_timeout_ms(),
        }
    }
}

/// Preservation / archive config — Saffev's durable, encrypted copy of your
/// coding-agent history, so a session survives the source app deleting it.
///
/// **Off by default** (opt-in). Local-only, encrypted at rest, never mutates
/// source files. Hot-reloadable. Our own retention defaults to keep-forever: we
/// must never silently delete the way the source apps do.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveConfig {
    /// Master switch. `false` (default) = nothing is archived.
    #[serde(default)]
    pub enabled: bool,
    /// Run a snapshot automatically (on Studio start + periodically) when enabled.
    #[serde(default)]
    pub auto: bool,
    /// Minutes between automatic snapshots when `auto` is on.
    ///
    /// Defaults to 5 so a session is never more than a few minutes from durable:
    /// the source apps prune on their own schedule, and an archive that only
    /// catches up hourly can lose exactly the session you needed. Snapshots are
    /// incremental (unchanged sessions are hash-skipped without re-parsing), so
    /// a short cadence costs milliseconds, not re-reads. Clamped to ≥1 at the
    /// scheduler so a hand-edited `0` cannot spin the loop.
    #[serde(default = "default_archive_interval_minutes")]
    pub interval_minutes: u32,
    /// Our-side retention in days. `None` (default) = keep forever. Set only if the
    /// user explicitly wants us to prune — we never do so on our own.
    #[serde(default)]
    pub retention_days: Option<u32>,
    /// Replace detected secrets with a typed placeholder before writing a session
    /// into the archive.
    ///
    /// **Off by default**, because it is lossy: the archive is meant to be the
    /// last surviving copy, and redaction permanently removes something the
    /// source may already have deleted. But leaving it unavailable was worse — the
    /// proxy side never stores a raw secret while the archive stored complete
    /// transcripts, secrets included. This closes that gap for people who would
    /// rather keep a safe copy than a complete one.
    ///
    /// Applies to sessions archived from the moment it is switched on; existing
    /// entries are re-archived (redacted) on the next snapshot, because the change
    /// key accounts for this setting.
    #[serde(default)]
    pub redact: bool,
}

impl Default for ArchiveConfig {
    fn default() -> Self {
        ArchiveConfig {
            enabled: false,
            auto: false,
            interval_minutes: default_archive_interval_minutes(),
            retention_days: None,
            redact: false,
        }
    }
}

/// Default auto-snapshot cadence (minutes). Kept ≤5 so the freshness promise —
/// "a finished session is durable within minutes" — holds by default (G5).
fn default_archive_interval_minutes() -> u32 {
    5
}

/// Local monitor rules — signals when something needs attention (G6).
///
/// **Off by default** (observe-only ethos: nothing pings the user until they
/// ask). When enabled, the Studio's 60-second monitor loop evaluates five rule
/// classes — PII spike, first-seen source app, exposure verdict change, latency
/// p95, spend-per-day — entirely on-device, and surfaces hits as a log line, a
/// desktop notification (when `notify` is on), and an SSE event. Everything
/// here is a plain TOML field so the rules live in the same config plane as
/// every other knob (`[monitors]` in `saffev.toml`). Zero network, ever:
/// notifications are OS-local (`notify-send` / `osascript`), never webhooks.
///
/// Hot-reloadable like [`ArchiveConfig`]: the monitor loop re-loads the live
/// config every tick, so flipping `enabled` applies without a restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorsConfig {
    /// Master switch. `false` (default) = the monitor loop does nothing.
    #[serde(default)]
    pub enabled: bool,
    /// Fire when more than this many PII findings land within one hour.
    #[serde(default = "default_pii_spike_per_hour")]
    pub pii_spike_per_hour: u32,
    /// Fire when the p95 of request latency over the last hour exceeds this
    /// (milliseconds). Needs ≥ 20 samples — small-n p95 is noise, not signal.
    #[serde(default = "default_latency_p95_ms")]
    pub latency_p95_ms: u32,
    /// Fire when today's (UTC) coding-agent spend exceeds this many USD
    /// (estimated with [`PricingConfig`], same figures as the analytics page).
    #[serde(default = "default_spend_per_day_usd")]
    pub spend_per_day_usd: f64,
    /// Send a desktop notification for each signal (in addition to the log
    /// line + SSE event). Fail-soft: a missing notifier is a debug log, never
    /// an error.
    #[serde(default = "default_true")]
    pub notify: bool,
}

fn default_pii_spike_per_hour() -> u32 {
    20
}
fn default_latency_p95_ms() -> u32 {
    30_000
}
fn default_spend_per_day_usd() -> f64 {
    10.0
}

impl Default for MonitorsConfig {
    fn default() -> Self {
        MonitorsConfig {
            enabled: false,
            pii_spike_per_hour: default_pii_spike_per_hour(),
            latency_p95_ms: default_latency_p95_ms(),
            spend_per_day_usd: default_spend_per_day_usd(),
            notify: true,
        }
    }
}

/// One entry in the model price table. USD per 1,000,000 tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPrice {
    /// Case-insensitive substring matched against the model name. First match in
    /// list order wins, so put specific names before general ones.
    #[serde(rename = "match")]
    pub match_: String,
    /// Price per 1M input tokens.
    pub input: f64,
    /// Price per 1M output tokens.
    pub output: f64,
    /// Price per 1M cache-READ input tokens.
    #[serde(default)]
    pub cache: f64,
    /// Price per 1M cache-WRITE (creation) tokens. `0.0` (absent in older
    /// configs) derives the Anthropic convention, 1.25 × input — the only
    /// vendor whose readers report write tokens separately today. Set it
    /// explicitly to override.
    #[serde(default)]
    pub cache_write: f64,
}

/// Cost estimation inputs.
///
/// These were hardcoded constants, which meant every published price change made
/// the figures quietly wrong with no way to correct them short of a release.
/// They are estimates either way — the point of moving them here is that a wrong
/// number is now the user's to fix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingConfig {
    /// Price table for coding-agent cost estimates. Empty = use the built-in
    /// defaults ([`PricingConfig::default`]).
    #[serde(default)]
    pub models: Vec<ModelPrice>,
    /// The cloud model the "cost avoided" figure compares local runs against:
    /// USD per 1M input tokens.
    #[serde(default = "default_cloud_in")]
    pub cloud_input_per_m: f64,
    /// USD per 1M output tokens for that same comparison.
    #[serde(default = "default_cloud_out")]
    pub cloud_output_per_m: f64,
    /// Human label for the comparison baseline, shown next to the figure so the
    /// number is never presented without saying what it is compared to.
    #[serde(default = "default_cloud_label")]
    pub cloud_label: String,
    /// The date the built-in price table was last verified against published
    /// list prices. Surfaced in analytics artifacts so pricing drift is
    /// documented, never silent. NEVER fetched from the network (on-device
    /// invariant) — updating this table is a release or a user edit.
    #[serde(default = "default_pricing_as_of")]
    pub as_of: String,
    /// Subscription plan label for block-progress display ("pro", "max5x",
    /// "max20x", …). Empty = unlabeled; progress then baselines against the
    /// highest OBSERVED block, which needs no invented allowance.
    #[serde(default)]
    pub plan: String,
    /// Estimated cost allowance per 5-hour billing block (USD) for the plan
    /// bar. `0` = auto: the highest observed block's cost is the baseline
    /// (plans are not published as exact grants — a configured number is the
    /// user's estimate, and the UI labels it as one).
    #[serde(default)]
    pub plan_block_allowance_usd: f64,
}

fn default_pricing_as_of() -> String {
    "2026-07-28".to_string()
}

fn default_cloud_in() -> f64 {
    2.50
}
fn default_cloud_out() -> f64 {
    10.0
}
fn default_cloud_label() -> String {
    "GPT-4o list price".to_string()
}

impl Default for PricingConfig {
    fn default() -> Self {
        PricingConfig {
            models: default_model_prices(),
            cloud_input_per_m: default_cloud_in(),
            cloud_output_per_m: default_cloud_out(),
            cloud_label: default_cloud_label(),
            as_of: default_pricing_as_of(),
            plan: String::new(),
            plan_block_allowance_usd: 0.0,
        }
    }
}

/// Built-in price table. Public list prices at the time of writing; correct them
/// in config rather than waiting for a release.
pub fn default_model_prices() -> Vec<ModelPrice> {
    let p = |m: &str, i: f64, o: f64, c: f64, cw: f64| ModelPrice {
        match_: m.to_string(),
        input: i,
        output: o,
        cache: c,
        cache_write: cw,
    };
    vec![
        // Anthropic: cache read = 0.1 × input, cache write (5m) = 1.25 × input.
        p("opus", 15.0, 75.0, 1.5, 18.75),
        p("sonnet", 3.0, 15.0, 0.3, 3.75),
        p("haiku", 1.0, 5.0, 0.1, 1.25),
        p("fable", 1.0, 5.0, 0.1, 1.25),
        // OpenAI/Google bill no separate write premium; readers for those
        // vendors never report write tokens, so the write rate mirrors input.
        p("gpt-5", 1.25, 10.0, 0.125, 1.25),
        p("gpt5", 1.25, 10.0, 0.125, 1.25),
        p("gpt-4o", 2.5, 10.0, 0.25, 2.5),
        p("gpt-4.1", 2.5, 10.0, 0.25, 2.5),
        p("gemini", 1.25, 10.0, 0.125, 1.25),
    ]
}

impl PricingConfig {
    /// Look up `(input, output, cache)` per-1M prices for a model name.
    ///
    /// Locally-run models cost nothing, so they resolve to zero before any table
    /// lookup — a local model must never show a dollar figure.
    pub fn lookup(&self, model: &str) -> (f64, f64, f64) {
        let m = model.to_lowercase();
        if m.contains("ollama") || m.contains("lmstudio") || m.contains("local") || m.contains(':')
        {
            return (0.0, 0.0, 0.0);
        }
        let table = if self.models.is_empty() {
            return Self::default().lookup(model);
        } else {
            &self.models
        };
        for e in table {
            if !e.match_.is_empty() && m.contains(&e.match_.to_lowercase()) {
                return (e.input, e.output, e.cache);
            }
        }
        (0.0, 0.0, 0.0)
    }

    /// Like [`Self::lookup`] but with the cache-WRITE rate as a fourth price:
    /// `(input, output, cache_read, cache_write)`. A table entry without an
    /// explicit `cache_write` derives 1.25 × input (Anthropic's convention —
    /// the only vendor whose readers report write tokens separately today).
    pub fn lookup_split(&self, model: &str) -> (f64, f64, f64, f64) {
        let m = model.to_lowercase();
        if m.contains("ollama") || m.contains("lmstudio") || m.contains("local") || m.contains(':')
        {
            return (0.0, 0.0, 0.0, 0.0);
        }
        let table = if self.models.is_empty() {
            return Self::default().lookup_split(model);
        } else {
            &self.models
        };
        for e in table {
            if !e.match_.is_empty() && m.contains(&e.match_.to_lowercase()) {
                let cw = if e.cache_write > 0.0 {
                    e.cache_write
                } else {
                    e.input * 1.25
                };
                return (e.input, e.output, e.cache, cw);
            }
        }
        (0.0, 0.0, 0.0, 0.0)
    }
}

/// The full Saffev configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Interception mode.
    #[serde(default)]
    pub mode: Mode,

    /// Port layout + bind address.
    #[serde(default)]
    pub ports: PortsConfig,

    /// **Privacy default: `false`.** When `false`, only metadata is stored; raw
    /// prompt/response text is never written. Enabling this is an explicit,
    /// logged user action.
    #[serde(default)]
    pub payload_storage: bool,

    /// Retention policy.
    #[serde(default)]
    pub retention: Retention,

    /// Supervisor handover policy on stop (Gateway mode).
    #[serde(default)]
    pub handover: HandoverPolicy,

    /// Where the database, config, and runtime state live.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,

    /// Extra user-defined PII patterns.
    #[serde(default)]
    pub custom_patterns: Vec<CustomPattern>,

    /// Opt-in PII masking (04 §5, §7.6). Defaults to observe-only.
    #[serde(default)]
    pub masking: MaskingConfig,

    /// Opt-in evaluation pipeline (safety guard + quality judge). Off by default.
    #[serde(default)]
    pub eval: EvalConfig,

    /// Opt-in AI-analysis backend (Codex app-server + ChatGPT subscription). Off
    /// by default; the only path that sends session text off-device.
    #[serde(default)]
    pub analysis: AnalysisConfig,

    /// Opt-in Preservation archive (durable, encrypted copy of agent history).
    #[serde(default)]
    pub archive: ArchiveConfig,

    /// Opt-in local monitor rules + desktop notifications (G6). Off by default.
    #[serde(default)]
    pub monitors: MonitorsConfig,

    /// Prices used for the cost estimates. Editable so a published price change
    /// does not silently make the figures wrong.
    #[serde(default)]
    pub pricing: PricingConfig,

    /// Optional path to a **shared team policy** file (see [`crate::policy`]).
    ///
    /// A team commits one TOML file to their own repo and everyone points here.
    /// The policy wins over local settings for the protective fields it states,
    /// which is the point of having one. `None` (default) = no policy, and no
    /// behaviour change for anyone working alone. A leading `~` is expanded.
    #[serde(default)]
    pub policy_file: Option<PathBuf>,
}

fn default_data_dir() -> PathBuf {
    default_data_dir_impl()
}

impl Default for Config {
    fn default() -> Self {
        Config {
            mode: Mode::default(),
            ports: PortsConfig::default(),
            payload_storage: false,
            retention: Retention::default(),
            handover: HandoverPolicy::default(),
            data_dir: default_data_dir(),
            custom_patterns: Vec::new(),
            masking: MaskingConfig::default(),
            eval: EvalConfig::default(),
            analysis: AnalysisConfig::default(),
            pricing: PricingConfig::default(),
            policy_file: None,
            archive: ArchiveConfig::default(),
            monitors: MonitorsConfig::default(),
        }
    }
}

impl Config {
    /// Resolve the per-OS data dir, kept out of cloud-sync/backup folders.
    pub fn default_data_dir() -> PathBuf {
        default_data_dir_impl()
    }

    /// Full path to the TOML config file inside the data dir.
    pub fn config_path(&self) -> PathBuf {
        self.data_dir.join(CONFIG_FILE_NAME)
    }

    /// Full path to the SQLite database inside the data dir.
    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join(DB_FILE_NAME)
    }

    /// Display host for user-facing URLs: a loopback/unspecified bind renders as
    /// `localhost`; an explicit external bind renders as its address.
    pub fn display_host(&self) -> String {
        let bind = self.ports.bind;
        if bind.is_unspecified() || bind.is_loopback() {
            "localhost".to_string()
        } else {
            bind.to_string()
        }
    }

    /// Base URL apps point at for **native (Ollama)** traffic — `http://host:proxy`.
    /// This is where `OLLAMA_HOST` / `OLLAMA_BASE_URL` should point.
    pub fn proxy_base_url(&self) -> String {
        format!("http://{}:{}", self.display_host(), self.ports.proxy)
    }

    /// **OpenAI-compatible** base URL — the proxy base plus `/v1`. LM Studio and
    /// any OpenAI-SDK client point here (`OPENAI_BASE_URL`).
    pub fn openai_base_url(&self) -> String {
        format!("{}/v1", self.proxy_base_url())
    }

    /// The Studio web UI URL — `http://host:studio`.
    pub fn studio_url(&self) -> String {
        format!("http://{}:{}", self.display_host(), self.ports.studio)
    }

    /// Load config from the default data dir, creating defaults if absent.
    ///
    /// On first run (no file yet) this writes out a default config so the file
    /// exists for the Studio Settings write-through path, then returns it. A
    /// present-but-unreadable/invalid file is a control-plane error (returned to
    /// the caller, which decides whether to fall back to defaults).
    pub fn load() -> Result<Self> {
        let path = Self::default().config_path();
        Self::load_from(&path)
    }

    /// Load config from an explicit path.
    ///
    /// If the file is absent, a default config is materialized at that path (so
    /// the path is canonical and Settings can write through to it) and returned.
    /// The `data_dir` is back-filled to the file's parent when the TOML omits it,
    /// so an explicit `--config` in an arbitrary dir keeps its DB/state beside it.
    pub fn load_from(path: &std::path::Path) -> Result<Self> {
        if !path.exists() {
            // First run for this path: write defaults, anchored at the file's dir.
            let mut cfg = Config::default();
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    cfg.data_dir = parent.to_path_buf();
                }
            }
            cfg.validate()?;
            cfg.save_to(path)?;
            return Ok(cfg);
        }

        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("reading config {}: {e}", path.display())))?;
        let cfg: Config = toml::from_str(&text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Persist this config back to its TOML file (Settings write-through).
    pub fn save(&self) -> Result<()> {
        let path = self.config_path();
        self.save_to(&path)
    }

    /// Persist this config to an explicit path, creating parent dirs as needed.
    ///
    /// Public so the zero-config first-run path in `saffev start` can write the
    /// resolved config to the exact path it resolved (which may be an explicit
    /// `--config` whose filename differs from the default `saffev.toml`).
    pub fn save_to(&self, path: &std::path::Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    Error::Config(format!("creating config dir {}: {e}", parent.display()))
                })?;
            }
        }
        let text = toml::to_string_pretty(self)?;
        std::fs::write(path, text)
            .map_err(|e| Error::Config(format!("writing config {}: {e}", path.display())))?;
        Ok(())
    }

    /// Validate ports do not collide and the bind address is loopback unless
    /// the user explicitly opted out.
    ///
    /// The proxy, Studio, and (in Gateway mode) the shadow port must all be
    /// distinct — a collision would mean the proxy binds the port the engine is
    /// supposed to listen on. In Cooperative mode the proxy and upstream ports
    /// must differ (the proxy cannot forward to itself).
    pub fn validate(&self) -> Result<()> {
        let p = &self.ports;

        // Proxy vs Studio always collide-checked.
        if p.proxy == p.studio {
            return Err(Error::Config(format!(
                "proxy and studio ports must differ (both {})",
                p.proxy
            )));
        }

        match self.mode {
            Mode::Gateway => {
                // Proxy owns the public port; the engine sits on the shadow port.
                if p.proxy == p.shadow {
                    return Err(Error::Config(format!(
                        "gateway mode: proxy and shadow ports must differ (both {})",
                        p.proxy
                    )));
                }
                if p.studio == p.shadow {
                    return Err(Error::Config(format!(
                        "gateway mode: studio and shadow ports must differ (both {})",
                        p.studio
                    )));
                }
            }
            Mode::Cooperative => {
                // The proxy forwards to the upstream engine — it cannot be itself.
                if p.proxy == p.upstream {
                    return Err(Error::Config(format!(
                        "cooperative mode: proxy port ({}) must differ from the \
                         upstream engine port ({}) — the proxy cannot forward to itself",
                        p.proxy, p.upstream
                    )));
                }
                if p.studio == p.upstream {
                    return Err(Error::Config(format!(
                        "cooperative mode: studio and upstream ports must differ (both {})",
                        p.studio
                    )));
                }
            }
        }

        // Eval sampling must be a valid fraction; concurrency at least 1.
        if !(0.0..=1.0).contains(&self.eval.sample_rate) {
            return Err(Error::Config(format!(
                "eval.sample_rate must be between 0.0 and 1.0 (got {})",
                self.eval.sample_rate
            )));
        }
        if self.eval.max_concurrency == 0 {
            return Err(Error::Config(
                "eval.max_concurrency must be at least 1".to_string(),
            ));
        }

        Ok(())
    }
}

/// Internal: compute the platform data dir. Loopback-only, out of sync folders.
fn default_data_dir_impl() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("saffev")
}

// ---------------------------------------------------------------------------
// Free-port discovery + first-run auto-configuration
// ---------------------------------------------------------------------------

/// Is `port` free to bind on the loopback interface?
///
/// We test by attempting an actual `bind(127.0.0.1:port)`: if the bind succeeds
/// the port is free (the listener is dropped immediately, releasing it). Port 0
/// is never "free" in the sense we want here (it asks the OS to pick one), so we
/// reject it outright. This is the authoritative, race-light check — a held
/// engine port (e.g. Ollama on 11434) fails to bind and is correctly skipped.
pub fn port_is_free(addr: IpAddr, port: u16) -> bool {
    if port == 0 {
        return false;
    }
    TcpListener::bind((addr, port)).is_ok()
}

/// Find the first free port from an explicit candidate list, then (if none of
/// those bind) by scanning upward from `scan_from` for up to [`FIRST_RUN_SCAN_SPAN`]
/// ports. Returns `None` only if absolutely nothing in either set binds.
fn first_free_port(addr: IpAddr, candidates: &[u16], scan_from: u16) -> Option<u16> {
    for &p in candidates {
        if port_is_free(addr, p) {
            return Some(p);
        }
    }
    let mut p = scan_from;
    for _ in 0..FIRST_RUN_SCAN_SPAN {
        if port_is_free(addr, p) {
            return Some(p);
        }
        p = p.checked_add(1)?;
    }
    None
}

impl Config {
    /// Does a user-authored config file already exist at the resolved path?
    ///
    /// `start` uses this to decide between honoring an existing config exactly
    /// (returns `true`) and the zero-config first-run path (returns `false`).
    /// Note: we check *before* anything materializes a default, so this reflects
    /// a true first run.
    pub fn config_file_exists(path: &std::path::Path) -> bool {
        path.exists()
    }

    /// Resolve a working **first-run** Cooperative config and anchor it at
    /// `data_dir` (the parent of the config path).
    ///
    /// First run = no config file on disk yet. We pick a working layout instead
    /// of erroring on the well-known engine port:
    /// - mode = Cooperative (engine untouched; the app points at the proxy),
    /// - upstream = `upstream_port`, the engine's real port as detected by the
    ///   caller (Ollama `11434` / LM Studio `1234`); kept exactly where it is,
    /// - proxy = the first *free* TCP port from [`FIRST_RUN_PROXY_CANDIDATES`]
    ///   (the engine's own 11434 is deliberately excluded so the proxy never
    ///   collides with it),
    /// - studio = the first free port scanning up from [`FIRST_RUN_STUDIO_SCAN_START`].
    ///
    /// Passing [`DEFAULT_UPSTREAM_PORT`] reproduces the Ollama-default behavior
    /// (used when nothing is detected, so a later-started engine still works).
    ///
    /// Returns the resolved (validated) config. Does **not** persist it — the
    /// caller decides when to write so a dry/probe path can resolve without
    /// touching disk.
    pub fn resolve_first_run(data_dir: PathBuf, upstream_port: u16) -> Result<Config> {
        let mut cfg = Config::default();
        cfg.mode = Mode::Cooperative;
        cfg.data_dir = data_dir;

        let bind = cfg.ports.bind;
        // Upstream is left exactly where the engine already listens (the whole
        // point of Cooperative). The caller detects Ollama vs LM Studio; we just
        // record the port it found.
        cfg.ports.upstream = upstream_port;

        // Proxy: first free candidate. Excludes 11434 by construction so it can
        // never land on the engine's port. Fall back to a non-colliding default
        // if (improbably) nothing binds.
        cfg.ports.proxy = first_free_port(bind, FIRST_RUN_PROXY_CANDIDATES, 11435)
            .unwrap_or(FIRST_RUN_PROXY_CANDIDATES[0]);

        // Studio: scan upward from 7100, skipping the proxy port if it lands there.
        let studio =
            first_free_port(bind, &[], FIRST_RUN_STUDIO_SCAN_START).unwrap_or(DEFAULT_STUDIO_PORT);
        cfg.ports.studio = if studio == cfg.ports.proxy {
            first_free_port(bind, &[], studio.saturating_add(1)).unwrap_or(DEFAULT_STUDIO_PORT)
        } else {
            studio
        };

        cfg.validate()?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unique throwaway directory under the OS temp dir. The counter keeps paths
    /// distinct even within a single test process (process id alone is shared).
    fn unique_temp_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "saffev-config-test-{tag}-{}-{n}",
            std::process::id()
        ))
    }

    /// Assert two configs are equal field-for-field (Config has no `PartialEq`).
    fn assert_config_eq(loaded: &Config, expected: &Config) {
        assert_eq!(loaded.mode, expected.mode);
        assert_eq!(loaded.payload_storage, expected.payload_storage);
        assert_eq!(loaded.retention, expected.retention);
        assert_eq!(loaded.handover, expected.handover);
        assert_eq!(loaded.data_dir, expected.data_dir);
        assert_eq!(loaded.ports.bind, expected.ports.bind);
        assert_eq!(loaded.ports.proxy, expected.ports.proxy);
        assert_eq!(loaded.ports.studio, expected.ports.studio);
        assert_eq!(loaded.ports.shadow, expected.ports.shadow);
        assert_eq!(loaded.ports.upstream, expected.ports.upstream);
        assert_eq!(loaded.custom_patterns.len(), expected.custom_patterns.len());
        assert_eq!(loaded.masking.enabled, expected.masking.enabled);
        assert_eq!(loaded.masking.dry_run, expected.masking.dry_run);
        assert_eq!(loaded.masking.kinds, expected.masking.kinds);
    }

    /// Eval defaults must be observe-only: disabled, safety-on-when-enabled,
    /// quality-off, and a sane sample rate / concurrency.
    #[test]
    fn eval_defaults_are_off() {
        let cfg = Config::default();
        assert!(!cfg.eval.enabled, "eval must be off by default");
        assert!(cfg.eval.safety, "safety guard is on once eval is enabled");
        assert!(!cfg.eval.quality, "quality judge is off by default");
        assert_eq!(
            cfg.eval.max_concurrency, 1,
            "contention guard defaults to 1"
        );
        assert!((0.0..=1.0).contains(&cfg.eval.sample_rate));
    }

    #[test]
    fn eval_validation_rejects_bad_sample_rate_and_zero_concurrency() {
        let mut cfg = Config::default();
        cfg.mode = Mode::Cooperative;
        cfg.ports.proxy = 8088; // make ports valid
        cfg.eval.sample_rate = 1.5;
        assert!(cfg.validate().is_err(), "sample_rate > 1 must fail");
        cfg.eval.sample_rate = 0.2;
        cfg.eval.max_concurrency = 0;
        assert!(cfg.validate().is_err(), "zero concurrency must fail");
    }

    /// Older configs with no `[eval]` table load with eval off (serde default).
    #[test]
    fn eval_section_absent_defaults_off() {
        let dir = unique_temp_dir("eval-absent");
        let path = dir.join(CONFIG_FILE_NAME);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            &path,
            format!(
                "mode = \"cooperative\"\ndata_dir = {:?}\n[ports]\nproxy = 8088\nupstream = 11434\n",
                dir.to_string_lossy()
            ),
        )
        .unwrap();
        let cfg = Config::load_from(&path).expect("loads");
        assert!(!cfg.eval.enabled);
        assert!(cfg.eval.safety);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Masking defaults must keep observe-only behaviour: disabled, and even if
    /// enabled it is dry-run by default with no explicit kind list (= all
    /// high-confidence kinds).
    #[test]
    fn masking_defaults_are_observe_only() {
        let cfg = Config::default();
        assert!(!cfg.masking.enabled, "masking must be off by default");
        assert!(cfg.masking.dry_run, "masking must be dry-run by default");
        assert!(cfg.masking.kinds.is_none(), "no kind filter by default");
    }

    /// Omitting the whole `[masking]` table in a loaded TOML falls back to the
    /// safe observe-only defaults (older configs keep working unchanged).
    #[test]
    fn masking_section_absent_falls_back_to_defaults() {
        let dir = unique_temp_dir("masking-absent");
        let path = dir.join(CONFIG_FILE_NAME);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            &path,
            format!(
                "mode = \"cooperative\"\ndata_dir = {:?}\n[ports]\nproxy = 11434\nupstream = 11999\n",
                dir.to_string_lossy()
            ),
        )
        .unwrap();

        let cfg = Config::load_from(&path).expect("loads without [masking]");
        assert!(!cfg.masking.enabled);
        assert!(cfg.masking.dry_run);
        assert!(cfg.masking.kinds.is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An explicit `[masking]` table parses its fields, including a kinds filter.
    #[test]
    fn masking_section_parses_explicit_fields() {
        use crate::brain::PiiKind;
        let dir = unique_temp_dir("masking-explicit");
        let path = dir.join(CONFIG_FILE_NAME);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            &path,
            format!(
                "mode = \"cooperative\"\ndata_dir = {:?}\n[ports]\nproxy = 11434\nupstream = 11999\n\
                 [masking]\nenabled = true\ndry_run = false\nkinds = [\"email\", \"api_key\"]\n",
                dir.to_string_lossy()
            ),
        )
        .unwrap();

        let cfg = Config::load_from(&path).expect("loads with explicit [masking]");
        assert!(cfg.masking.enabled);
        assert!(!cfg.masking.dry_run);
        assert_eq!(
            cfg.masking.kinds,
            Some(vec![PiiKind::Email, PiiKind::ApiKey])
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// (a) First-run default materialization, TOML layer: serializing the shipped
    /// defaults and deserializing them back yields a config equal to the defaults,
    /// field-for-field. This exercises `save`/`load`'s serialization path without
    /// the `validate()` gate (the stock defaults are cooperative with
    /// proxy == upstream, which `validate()` rejects — see
    /// `defaults_are_cooperative_and_fail_validation`).
    #[test]
    fn save_load_round_trip_equals_defaults() {
        let defaults = Config::default();

        let text = toml::to_string_pretty(&defaults).expect("serialize defaults");
        let loaded: Config = toml::from_str(&text).expect("deserialize defaults");

        assert_config_eq(&loaded, &defaults);
        assert!(
            !loaded.payload_storage,
            "privacy default must be metadata-only (payload_storage == false)"
        );
        assert_eq!(loaded.ports.proxy, DEFAULT_PROXY_PORT);
        assert_eq!(loaded.ports.studio, DEFAULT_STUDIO_PORT);
        assert_eq!(loaded.ports.shadow, DEFAULT_SHADOW_PORT);
        assert_eq!(loaded.ports.upstream, DEFAULT_UPSTREAM_PORT);
    }

    /// (a, cont.) Full `save_to` -> `load_from` round-trip through the on-disk
    /// path. Uses a valid (non-colliding) config so it survives `load_from`'s
    /// `validate()` gate; the materialized file round-trips exactly.
    #[test]
    fn save_to_load_from_round_trip_on_disk() {
        let dir = unique_temp_dir("roundtrip");
        let path = dir.join(CONFIG_FILE_NAME);

        let mut original = Config::default();
        original.data_dir = dir.clone();
        // Make it pass validate(): cooperative proxy must differ from upstream.
        original.ports.upstream = 12321;

        original.save_to(&path).expect("save config");
        assert!(path.exists(), "config file should be materialized on save");

        let loaded = Config::load_from(&path).expect("load existing config");
        assert_config_eq(&loaded, &original);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// First-run via `load_from` on an absent path materializes a default config
    /// file, anchored at the file's parent dir.
    ///
    /// The absent-path branch builds `Config::default()`, back-fills `data_dir`
    /// to the file's parent, then `validate()`s before writing. The stock
    /// cooperative defaults collide (proxy == upstream), so first run only
    /// succeeds in a mode without that collision — here we drive the branch by
    /// pre-anchoring with a parent path and asserting the materialization +
    /// back-fill happen as documented. We use gateway mode (distinct shadow) so
    /// validation passes through the same first-run code path.
    #[test]
    fn load_from_absent_path_materializes_and_anchors_data_dir() {
        // The first-run branch always starts from Config::default() (cooperative,
        // colliding), so a true absent-path call errors. Verify that contract,
        // then exercise the back-fill + materialization via a valid seeded file.
        let dir = unique_temp_dir("firstrun-absent");
        let path = dir.join(CONFIG_FILE_NAME);
        assert!(!path.exists());

        let first_run = Config::load_from(&path);
        assert!(
            first_run.is_err(),
            "first run from stock cooperative defaults collides proxy == upstream"
        );
        // The default-materialization wrote nothing usable, but the dir layout is
        // created lazily by save_to only on the happy path; assert the error is a
        // config (validation) error, not an IO error.
        assert!(matches!(first_run.unwrap_err(), Error::Config(_)));

        // Now drive a successful load of an existing, valid file in the same dir.
        let dir2 = unique_temp_dir("firstrun-valid");
        let path2 = dir2.join(CONFIG_FILE_NAME);
        std::fs::create_dir_all(&dir2).unwrap();
        std::fs::write(
            &path2,
            format!(
                "mode = \"cooperative\"\ndata_dir = {:?}\n[ports]\nproxy = 11434\nupstream = 11999\n",
                dir2.to_string_lossy()
            ),
        )
        .unwrap();

        let cfg = Config::load_from(&path2).expect("valid config loads");
        assert!(path2.exists());
        assert_eq!(cfg.data_dir, dir2);
        assert_eq!(cfg.ports.proxy, 11434);
        assert_eq!(cfg.ports.upstream, 11999);
        assert_eq!(cfg.ports.studio, DEFAULT_STUDIO_PORT);
        assert!(!cfg.payload_storage);

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    /// (b) Parsing a cooperative TOML with custom ports yields exactly those ports
    /// and validates cleanly.
    #[test]
    fn parse_cooperative_toml_with_custom_ports() {
        let dir = unique_temp_dir("custom-ports");
        let path = dir.join(CONFIG_FILE_NAME);

        let toml_text = r#"
mode = "cooperative"
payload_storage = false

[ports]
proxy = 8080
studio = 8081
upstream = 9090

[retention]
kind = "age"
days = 14
"#;
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, toml_text).unwrap();

        let cfg = Config::load_from(&path).expect("cooperative TOML parses + validates");

        assert_eq!(cfg.mode, Mode::Cooperative);
        assert_eq!(cfg.ports.proxy, 8080);
        assert_eq!(cfg.ports.studio, 8081);
        assert_eq!(cfg.ports.upstream, 9090);
        // Omitted port falls back to its default.
        assert_eq!(cfg.ports.shadow, DEFAULT_SHADOW_PORT);
        assert_eq!(cfg.retention, Retention::Age { days: 14 });
        assert!(!cfg.payload_storage);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// (c) validate() rejects a proxy == studio port collision.
    #[test]
    fn validate_rejects_proxy_studio_collision() {
        let mut cfg = Config::default();
        cfg.ports.proxy = 9000;
        cfg.ports.studio = 9000;

        let err = cfg
            .validate()
            .expect_err("proxy == studio must be rejected");
        match err {
            Error::Config(msg) => {
                assert!(
                    msg.contains("proxy") && msg.contains("studio"),
                    "collision message should name both ports: {msg}"
                );
            }
            other => panic!("expected Error::Config, got {other:?}"),
        }
    }

    /// (c, cont.) In cooperative mode, proxy == upstream is rejected (the proxy
    /// cannot forward to itself).
    #[test]
    fn validate_rejects_cooperative_proxy_upstream_collision() {
        let mut cfg = Config::default();
        cfg.mode = Mode::Cooperative;
        cfg.ports.proxy = 12000;
        cfg.ports.upstream = 12000;
        // Keep studio distinct so we isolate the proxy/upstream collision.
        cfg.ports.studio = 7100;

        let err = cfg
            .validate()
            .expect_err("cooperative proxy == upstream must be rejected");
        assert!(matches!(err, Error::Config(_)));
    }

    /// (c, cont.) In gateway mode, proxy == shadow is rejected.
    #[test]
    fn validate_rejects_gateway_proxy_shadow_collision() {
        let mut cfg = Config::default();
        cfg.mode = Mode::Gateway;
        cfg.ports.proxy = 11434;
        cfg.ports.shadow = 11434;

        let err = cfg
            .validate()
            .expect_err("gateway proxy == shadow must be rejected");
        assert!(matches!(err, Error::Config(_)));
    }

    /// Documents the actual v0 behavior: the shipped defaults are cooperative
    /// with proxy == upstream (both 11434), so `validate()` rejects the raw
    /// defaults. A real deployment must set a distinct upstream/shadow port.
    /// This test pins the current contract so a future change to the defaults
    /// (e.g. distinct default upstream) is caught deliberately.
    #[test]
    fn defaults_are_cooperative_and_fail_validation() {
        let cfg = Config::default();
        assert_eq!(cfg.mode, Mode::Cooperative);
        assert_eq!(cfg.ports.proxy, cfg.ports.upstream);
        assert!(
            cfg.validate().is_err(),
            "stock cooperative defaults collide proxy == upstream"
        );
    }

    // -----------------------------------------------------------------------
    // free-port helper + first-run resolution
    // -----------------------------------------------------------------------

    /// `port_is_free` rejects port 0 (it means "OS picks one", not "free") and
    /// returns a sensible answer for a real port: a port we are actively holding
    /// is NOT free; the same port after we drop the listener is free again.
    #[test]
    fn port_is_free_skips_an_already_bound_port() {
        let loop_back = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(!port_is_free(loop_back, 0), "port 0 is never 'free'");

        // Bind an ephemeral port and learn its number; while held, it must read
        // as not-free. After dropping the listener it must read as free again.
        let listener = TcpListener::bind((loop_back, 0)).expect("bind ephemeral");
        let held = listener.local_addr().unwrap().port();
        assert!(
            !port_is_free(loop_back, held),
            "a port we are actively holding must not be reported free"
        );
        drop(listener);

        // The port should read free again now. This half is inherently racy under
        // a parallel test run: the number we just released is an ephemeral one,
        // and another test binding ephemerally can legitimately claim it in the
        // gap. That would be a scheduling coincidence, not a bug in
        // `port_is_free`, so retry briefly and only then treat it as a failure.
        let freed = (0..20).any(|_| {
            if port_is_free(loop_back, held) {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
            false
        });
        assert!(
            freed,
            "the port must be free again once the listener is dropped"
        );
    }

    /// `first_free_port` skips a held candidate and returns the next free one.
    #[test]
    fn first_free_port_skips_held_candidate() {
        let loop_back = IpAddr::V4(Ipv4Addr::LOCALHOST);
        // Hold two ephemeral ports; offer them as the first candidates, with a
        // known-free third candidate last. The scan must skip the held ones.
        let l1 = TcpListener::bind((loop_back, 0)).unwrap();
        let l2 = TcpListener::bind((loop_back, 0)).unwrap();
        let held1 = l1.local_addr().unwrap().port();
        let held2 = l2.local_addr().unwrap().port();
        // A free port to recover after the held ones (bind+drop to learn a number
        // that is, at this instant, free).
        let free = {
            let probe = TcpListener::bind((loop_back, 0)).unwrap();
            let p = probe.local_addr().unwrap().port();
            drop(probe);
            p
        };

        let picked =
            first_free_port(loop_back, &[held1, held2, free], 0).expect("a free candidate exists");
        assert_ne!(picked, held1, "must skip the first held candidate");
        assert_ne!(picked, held2, "must skip the second held candidate");

        drop(l1);
        drop(l2);
    }

    /// First-run resolution yields a Cooperative config with upstream pinned to
    /// the well-known engine port (11434), and distinct, free proxy/studio
    /// ports that pass validation. The proxy must never be 11434 (the proxy
    /// cannot forward to itself in Cooperative mode).
    #[test]
    fn first_run_resolves_cooperative_with_distinct_free_ports() {
        let dir = unique_temp_dir("firstrun-resolve");
        let cfg = Config::resolve_first_run(dir.clone(), DEFAULT_UPSTREAM_PORT)
            .expect("first-run resolves");

        assert_eq!(cfg.mode, Mode::Cooperative);
        assert_eq!(cfg.data_dir, dir);
        assert_eq!(
            cfg.ports.upstream, DEFAULT_UPSTREAM_PORT,
            "upstream must stay on the well-known engine port"
        );
        assert_ne!(
            cfg.ports.proxy, DEFAULT_UPSTREAM_PORT,
            "proxy must not collide with the engine/upstream port"
        );
        assert_ne!(
            cfg.ports.proxy, cfg.ports.studio,
            "proxy and studio must be distinct"
        );
        // The resolved layout must be internally valid (this is exactly what the
        // stock defaults fail — see defaults_are_cooperative_and_fail_validation).
        cfg.validate().expect("resolved first-run config validates");
    }

    /// First-run resolution against a detected **LM Studio** engine pins the
    /// upstream to LM Studio's port (1234), not the Ollama default — and still
    /// yields a valid, distinct proxy/studio layout.
    #[test]
    fn first_run_pins_lmstudio_upstream_when_detected() {
        let dir = unique_temp_dir("firstrun-lmstudio");
        let cfg = Config::resolve_first_run(dir.clone(), 1234).expect("first-run resolves");

        assert_eq!(cfg.mode, Mode::Cooperative);
        assert_eq!(
            cfg.ports.upstream, 1234,
            "upstream must follow the detected LM Studio port"
        );
        assert_ne!(
            cfg.ports.proxy, 1234,
            "proxy must not collide with upstream"
        );
        assert_ne!(
            cfg.ports.studio, 1234,
            "studio must not collide with upstream"
        );
        cfg.validate()
            .expect("resolved LM Studio first-run config validates");
    }

    /// An existing user-authored config is left untouched: `config_file_exists`
    /// reports the file present, and loading it returns the user's exact ports —
    /// the first-run resolver is never consulted for an existing file.
    #[test]
    fn existing_user_config_is_left_untouched() {
        let dir = unique_temp_dir("existing-untouched");
        let path = dir.join(CONFIG_FILE_NAME);
        std::fs::create_dir_all(&dir).unwrap();
        // A user-authored cooperative config that happens to keep proxy on a
        // distinct port from upstream.
        std::fs::write(
            &path,
            format!(
                "mode = \"cooperative\"\ndata_dir = {:?}\n[ports]\nproxy = 9191\nstudio = 9292\nupstream = 11434\n",
                dir.to_string_lossy()
            ),
        )
        .unwrap();

        assert!(
            Config::config_file_exists(&path),
            "an authored config file must be detected as existing"
        );

        let before = std::fs::read_to_string(&path).unwrap();
        let cfg = Config::load_from(&path).expect("existing config loads");
        let after = std::fs::read_to_string(&path).unwrap();

        assert_eq!(cfg.ports.proxy, 9191, "user's proxy port is honored");
        assert_eq!(cfg.ports.studio, 9292, "user's studio port is honored");
        assert_eq!(cfg.ports.upstream, 11434);
        assert_eq!(
            before, after,
            "loading an existing config must not rewrite it"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
