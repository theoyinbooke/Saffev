//! Signals — local monitor rules that say when something needs attention (G6).
//!
//! Five rule classes, evaluated entirely on-device against the store (and two
//! caller-supplied observations), never against a cloud:
//!
//! 1. **PII spike** — more findings in the last hour than the configured
//!    threshold (`monitors.pii_spike_per_hour`).
//! 2. **New source app** — a `source_app` never seen before starts sending
//!    traffic through the proxy.
//! 3. **Exposure change** — the engine's exposure verdict flips (localhost ↔
//!    reachable-from-the-network).
//! 4. **Latency p95** — the 95th-percentile latency over the last hour exceeds
//!    the threshold. Requires ≥ [`MIN_P95_SAMPLES`] samples: a p95 over a
//!    handful of requests is noise, and a noisy monitor trains people to
//!    ignore it.
//! 5. **Spend per day** — today's (UTC) estimated coding-agent spend (the G3
//!    figures) exceeds the threshold.
//!
//! ## Testability shape
//!
//! [`evaluate`] takes the *observations* that would otherwise require touching
//! the host — the exposure verdict and today's spend — as plain inputs, so
//! every rule is unit-testable with a fixture store and two `Option`s. The
//! scheduler (`studio::spawn_monitor_scheduler`) and `saffev status --check`
//! supply the real values ([`crate::exposure::check`], [`spend_today`]).
//!
//! ## Dedup — a monitor that repeats itself is an alarm, not a signal
//!
//! [`MonitorState`] persists in the store's `settings` table (one JSON value
//! under [`STATE_KEY`]) so dedup survives restarts:
//!
//! - Threshold rules (PII / latency / spend) fire **once per time bucket** —
//!   hour buckets for the hourly windows, the UTC date for spend. The
//!   condition persisting inside a bucket stays quiet; a new bucket where it
//!   still holds is genuinely new information and fires again.
//! - New-app fires **once per app, ever** (the seen-set is the dedup).
//! - Exposure-change fires **once per flip** (state transition, not level).

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::config::{Config, PricingConfig};
use crate::store::{HistoryQuery, Store};

/// Settings-table key the persisted [`MonitorState`] JSON lives under.
pub const STATE_KEY: &str = "monitor_state";

/// Minimum latency samples in the window before the p95 rule may fire.
pub const MIN_P95_SAMPLES: usize = 20;

/// One hour in milliseconds — the window for the PII and latency rules.
const HOUR_MS: i64 = 60 * 60 * 1000;

/// How long a fired dedupe key is remembered before being pruned (7 days).
/// Every bucketed key is stale long before this; pruning only bounds growth.
const FIRED_TTL_MS: i64 = 7 * 24 * HOUR_MS;

/// How many recent history rows one evaluation reads. Generous for an hour of
/// local traffic; bounded so a tick can never drag the whole table into memory.
const HISTORY_SCAN_LIMIT: u32 = 2000;

/// The five monitor rule classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    /// PII findings in the last hour exceeded the threshold.
    PiiSpike,
    /// A source app was seen for the first time.
    NewSourceApp,
    /// The engine exposure verdict changed since the last evaluation.
    ExposureChange,
    /// p95 latency over the last hour exceeded the threshold.
    LatencyP95,
    /// Today's estimated spend exceeded the threshold.
    SpendPerDay,
}

impl SignalKind {
    /// Stable machine name (dedupe-key prefix + SSE payload).
    pub fn as_str(self) -> &'static str {
        match self {
            SignalKind::PiiSpike => "pii_spike",
            SignalKind::NewSourceApp => "new_source_app",
            SignalKind::ExposureChange => "exposure_change",
            SignalKind::LatencyP95 => "latency_p95",
            SignalKind::SpendPerDay => "spend_per_day",
        }
    }
}

/// One fired monitor signal — what the notification / log line / SSE carries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signal {
    /// Which rule class fired.
    pub kind: SignalKind,
    /// Short human headline (the notification title).
    pub title: String,
    /// One-line detail with the numbers that tripped the rule.
    pub detail: String,
    /// When it fired (unix millis).
    pub ts: i64,
}

/// Persistent monitor memory — the dedup substrate.
///
/// Stored as one JSON value in the store's `settings` table so it survives
/// restarts (a monitor that re-fires everything on every boot is noise).
/// Unknown fields are ignored and missing ones default, so the shape can grow.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MonitorState {
    /// Every `source_app` ever observed. Membership *is* the new-app dedup.
    pub seen_apps: HashSet<String>,
    /// Exposure verdict at the last evaluation (`None` = never observed).
    pub last_exposure: Option<bool>,
    /// Dedupe key → fire timestamp for the bucketed threshold rules.
    pub fired: HashMap<String, i64>,
    /// Whether the seen-apps set has been seeded. The very first evaluation
    /// seeds every already-present app *silently* — announcing the entire
    /// existing history as "new" the moment monitors are switched on would be
    /// pure noise.
    pub initialized: bool,
}

impl MonitorState {
    /// Load the persisted state, or a fresh default when absent/corrupt.
    /// Fail-soft: a broken JSON blob resets the state (worst case: one round
    /// of duplicate signals) rather than killing the monitor loop.
    pub async fn load(store: &Store) -> MonitorState {
        match store.get_setting(STATE_KEY).await {
            Ok(Some(json)) => serde_json::from_str(&json).unwrap_or_default(),
            Ok(None) => MonitorState::default(),
            Err(e) => {
                tracing::debug!(target: "saffev::signals", "monitor state load failed: {e}");
                MonitorState::default()
            }
        }
    }

    /// Persist the state through the store's single writer (best-effort,
    /// fail-open like every other write).
    pub fn save(&self, store: &Store) {
        match serde_json::to_string(self) {
            Ok(json) => store.enqueue(crate::store::WriteOp::Setting {
                key: STATE_KEY.to_string(),
                value: json,
            }),
            Err(e) => {
                tracing::debug!(target: "saffev::signals", "monitor state serialize failed: {e}")
            }
        }
    }

    /// Record a dedupe key; `true` when it had not fired within its TTL (i.e.
    /// the caller should emit the signal). Prunes stale keys as a side effect.
    fn fire_once(&mut self, key: String, now_ms: i64) -> bool {
        self.fired.retain(|_, ts| now_ms - *ts < FIRED_TTL_MS);
        if self.fired.contains_key(&key) {
            return false;
        }
        self.fired.insert(key, now_ms);
        true
    }
}

/// Evaluate all five monitor rules against the store + supplied observations.
///
/// `exposed` is the current exposure verdict (`None` = could not determine —
/// the rule then holds its state rather than inventing a flip). `spend_today_usd`
/// is today's (UTC) estimated spend (`None` = no usage data). Both are inputs,
/// not probes, so the rules are pure enough to unit test; callers pass
/// [`crate::exposure::check`]'s verdict and [`spend_today`]'s figure.
///
/// The caller owns persisting `state` afterwards ([`MonitorState::save`]) —
/// keeping the store write out of here means a test can assert dedup without
/// a writer round-trip between calls.
pub async fn evaluate(
    store: &Store,
    cfg: &Config,
    now_ms: i64,
    exposed: Option<bool>,
    spend_today_usd: Option<f64>,
    state: &mut MonitorState,
) -> Vec<Signal> {
    let mut out = Vec::new();

    // One bounded read serves the three history-backed rules. Fail-soft: a
    // read error means "no rows this tick", never a dead monitor loop.
    let rows = store
        .history(HistoryQuery {
            limit: Some(HISTORY_SCAN_LIMIT),
            ..HistoryQuery::default()
        })
        .await
        .unwrap_or_else(|e| {
            tracing::debug!(target: "saffev::signals", "monitor history read failed: {e}");
            Vec::new()
        });
    let hour_ago = now_ms - HOUR_MS;
    let recent: Vec<_> = rows.iter().filter(|r| r.request.ts >= hour_ago).collect();
    let hour_bucket = now_ms.div_euclid(HOUR_MS);

    // --- rule 1 · PII findings spike (last hour vs threshold) ---------------
    let pii_last_hour: u64 = recent.iter().map(|r| u64::from(r.pii_count)).sum();
    if pii_last_hour > u64::from(cfg.monitors.pii_spike_per_hour)
        && state.fire_once(format!("pii_spike:{hour_bucket}"), now_ms)
    {
        out.push(Signal {
            kind: SignalKind::PiiSpike,
            title: "PII findings spike".into(),
            detail: format!(
                "{pii_last_hour} PII findings in the last hour (threshold {})",
                cfg.monitors.pii_spike_per_hour
            ),
            ts: now_ms,
        });
    }

    // --- rule 2 · new source app (first time ever seen) ---------------------
    // Scans the whole fetched window, not just the last hour: an app that
    // appeared between ticks must not slip through. First run seeds silently.
    let apps = rows.iter().filter_map(|r| r.request.source_app.as_deref());
    if !state.initialized {
        state.seen_apps.extend(apps.map(str::to_string));
        state.initialized = true;
    } else {
        for app in apps {
            if state.seen_apps.insert(app.to_string()) {
                out.push(Signal {
                    kind: SignalKind::NewSourceApp,
                    title: "New app is using your models".into(),
                    detail: format!("\"{app}\" sent traffic through Saffev for the first time"),
                    ts: now_ms,
                });
            }
        }
    }

    // --- rule 3 · exposure verdict change (state transition) ----------------
    if let Some(now_exposed) = exposed {
        if let Some(prev) = state.last_exposure {
            if prev != now_exposed {
                let (title, detail) = if now_exposed {
                    (
                        "Engine is now EXPOSED to the network",
                        "The engine's bind changed from localhost-only to network-reachable. \
                         Run `saffev doctor` to fix it.",
                    )
                } else {
                    (
                        "Engine exposure resolved",
                        "The engine is bound to localhost only again.",
                    )
                };
                out.push(Signal {
                    kind: SignalKind::ExposureChange,
                    title: title.into(),
                    detail: detail.into(),
                    ts: now_ms,
                });
            }
        }
        // Record the observation either way; an Unknown (`None`) verdict never
        // overwrites real state, so a transient probe failure cannot fake a flip.
        state.last_exposure = Some(now_exposed);
    }

    // --- rule 4 · latency p95 over the last hour ----------------------------
    let mut latencies: Vec<u32> = recent.iter().filter_map(|r| r.request.latency_ms).collect();
    if latencies.len() >= MIN_P95_SAMPLES {
        latencies.sort_unstable();
        // Nearest-rank p95: smallest value with ≥95% of samples at or below it.
        let idx = (latencies.len() * 95).div_ceil(100) - 1;
        let p95 = latencies[idx];
        if p95 > cfg.monitors.latency_p95_ms
            && state.fire_once(format!("latency_p95:{hour_bucket}"), now_ms)
        {
            out.push(Signal {
                kind: SignalKind::LatencyP95,
                title: "Latency p95 over threshold".into(),
                detail: format!(
                    "p95 {p95}ms over the last hour ({} samples, threshold {}ms)",
                    latencies.len(),
                    cfg.monitors.latency_p95_ms
                ),
                ts: now_ms,
            });
        }
    }

    // --- rule 5 · spend per day (UTC, the G3 estimate) -----------------------
    if let Some(spend) = spend_today_usd {
        let day = utc_date(now_ms);
        if spend > cfg.monitors.spend_per_day_usd
            && state.fire_once(format!("spend_per_day:{day}"), now_ms)
        {
            out.push(Signal {
                kind: SignalKind::SpendPerDay,
                title: "Daily spend over threshold".into(),
                detail: format!(
                    "≈${spend:.2} estimated coding-agent spend today (threshold ${:.2})",
                    cfg.monitors.spend_per_day_usd
                ),
                ts: now_ms,
            });
        }
    }

    out
}

/// Today's (UTC) estimated coding-agent spend, from the same G3 machinery the
/// analytics page uses (Claude Code JSONL + the configured price table).
///
/// `None` when there are no usage events at all (fresh machine — the spend rule
/// then has nothing to say). Pure local file reading; zero network. Blocking
/// file IO — call from a blocking context (the scheduler wraps it in
/// `spawn_blocking`).
pub fn spend_today(
    pricing: &PricingConfig,
    projects_dir: &std::path::Path,
    now_ms: i64,
) -> Option<f64> {
    let events = crate::agents::usage::claude_code_events(projects_dir);
    if events.is_empty() {
        return None;
    }
    let today = utc_date(now_ms);
    let spent = crate::agents::usage::daily(&events, pricing)
        .into_iter()
        .find(|d| d.date == today)
        .map(|d| d.totals.cost_usd)
        .unwrap_or(0.0);
    Some(spent)
}

/// UTC calendar date (`YYYY-MM-DD`) of a unix-millis timestamp — the spend
/// rule's day bucket, matching G3's `daily --timezone UTC` semantics.
fn utc_date(ts_ms: i64) -> String {
    let t = time::OffsetDateTime::from_unix_timestamp(ts_ms / 1000)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    format!("{:04}-{:02}-{:02}", t.year(), u8::from(t.month()), t.day())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{
        PiiAction, PiiFindingRecord, RequestMeta, SourceConfidence, TokenSource, WriteOp,
    };

    /// Pin a DB key so `Store::open` never touches the OS keyring in tests
    /// (same pattern as `store::tests::ensure_test_db_key`).
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

    async fn tmp_store() -> Store {
        ensure_test_db_key();
        let mut p = std::env::temp_dir();
        p.push(format!("saffev-signals-test-{}.db", uuid::Uuid::new_v4()));
        Store::open(&p).await.expect("open test store")
    }

    fn req(id: &str, ts: i64, app: &str, latency_ms: Option<u32>) -> RequestMeta {
        RequestMeta {
            id: id.to_string(),
            ts,
            source_app: Some(app.to_string()),
            source_confidence: SourceConfidence::Pid,
            engine: "ollama".into(),
            model: Some("llama3".into()),
            endpoint: "/api/chat".into(),
            stream: false,
            input_tokens: None,
            input_tokens_src: TokenSource::Estimated,
            latency_ms,
            request_hash: "deadbeef".into(),
            req_bytes: None,
            user_agent: None,
            content_type: None,
            temperature: None,
            top_p: None,
            max_tokens: None,
            msg_count: None,
            has_system: None,
            tool_count: None,
        }
    }

    fn finding(record_id: &str, n: usize) -> PiiFindingRecord {
        PiiFindingRecord {
            id: 0,
            record_id: record_id.to_string(),
            side: crate::brain::Side::Request,
            kind: crate::brain::PiiKind::Email,
            label: None,
            start_off: n,
            end_off: n + 5,
            confidence: crate::brain::Confidence::High,
            action: PiiAction::Observed,
            value_hash: format!("h{n}"),
        }
    }

    /// A state that has already been seeded, so new-app assertions are about
    /// the rule and not about first-run seeding.
    fn seeded_state() -> MonitorState {
        MonitorState {
            initialized: true,
            ..MonitorState::default()
        }
    }

    const NOW: i64 = 1_753_600_000_000; // fixed "now" for deterministic buckets

    fn kinds(signals: &[Signal]) -> Vec<SignalKind> {
        signals.iter().map(|s| s.kind).collect()
    }

    #[tokio::test]
    async fn pii_spike_fires_and_dedupes_within_the_hour_bucket() {
        let store = tmp_store().await;
        store.enqueue(WriteOp::Request(req("r1", NOW - 60_000, "cursor", None)));
        // Default threshold is 20/hour; 21 findings trips it.
        store.enqueue(WriteOp::PiiFindings(
            (0..21).map(|n| finding("r1", n)).collect(),
        ));
        store.flush().await.unwrap();

        let cfg = Config::default();
        let mut state = seeded_state();
        // Pre-seed the app so only the PII rule is under test here.
        state.seen_apps.insert("cursor".into());

        let first = evaluate(&store, &cfg, NOW, None, None, &mut state).await;
        assert_eq!(kinds(&first), vec![SignalKind::PiiSpike]);

        // Same hour bucket → suppressed.
        let second = evaluate(&store, &cfg, NOW + 60_000, None, None, &mut state).await;
        assert!(second.is_empty(), "same-bucket re-fire must dedupe");

        // Next hour bucket with the condition still true → fires again (new info).
        let next_hour = evaluate(&store, &cfg, NOW + HOUR_MS, None, None, &mut state).await;
        // The findings are now > 1h old relative to NOW + HOUR_MS only if their
        // ts fell out of the window; r1 is at NOW - 60s, so it did. No fire.
        assert!(next_hour.is_empty());
    }

    #[tokio::test]
    async fn pii_below_threshold_stays_quiet() {
        let store = tmp_store().await;
        store.enqueue(WriteOp::Request(req("r1", NOW - 60_000, "cursor", None)));
        store.enqueue(WriteOp::PiiFindings(
            (0..20).map(|n| finding("r1", n)).collect(), // exactly the threshold
        ));
        store.flush().await.unwrap();
        let cfg = Config::default();
        let mut state = seeded_state();
        state.seen_apps.insert("cursor".into());
        let got = evaluate(&store, &cfg, NOW, None, None, &mut state).await;
        assert!(got.is_empty(), "= threshold must not fire (rule is >)");
    }

    #[tokio::test]
    async fn new_source_app_fires_once_ever() {
        let store = tmp_store().await;
        store.enqueue(WriteOp::Request(req("r1", NOW - 30_000, "aider", None)));
        store.flush().await.unwrap();

        let cfg = Config::default();
        let mut state = seeded_state();

        let first = evaluate(&store, &cfg, NOW, None, None, &mut state).await;
        assert_eq!(kinds(&first), vec![SignalKind::NewSourceApp]);
        assert!(first[0].detail.contains("aider"));

        // Same app again — even hours later — never re-fires.
        let later = evaluate(&store, &cfg, NOW + 3 * HOUR_MS, None, None, &mut state).await;
        assert!(later.is_empty(), "seen app must never re-fire");
    }

    #[tokio::test]
    async fn first_run_seeds_existing_apps_silently() {
        let store = tmp_store().await;
        store.enqueue(WriteOp::Request(req("r1", NOW - 30_000, "cursor", None)));
        store.enqueue(WriteOp::Request(req("r2", NOW - 20_000, "cline", None)));
        store.flush().await.unwrap();

        let cfg = Config::default();
        let mut state = MonitorState::default(); // fresh: initialized == false
        let got = evaluate(&store, &cfg, NOW, None, None, &mut state).await;
        assert!(got.is_empty(), "first run must seed, not announce history");
        assert!(state.initialized);
        assert!(state.seen_apps.contains("cursor") && state.seen_apps.contains("cline"));
    }

    #[tokio::test]
    async fn exposure_change_fires_on_flip_only() {
        let store = tmp_store().await;
        let cfg = Config::default();
        let mut state = seeded_state();

        // First observation is baseline, not a change.
        let baseline = evaluate(&store, &cfg, NOW, Some(false), None, &mut state).await;
        assert!(baseline.is_empty());

        // Flip to exposed → fires.
        let flipped = evaluate(&store, &cfg, NOW + 1, Some(true), None, &mut state).await;
        assert_eq!(kinds(&flipped), vec![SignalKind::ExposureChange]);
        assert!(flipped[0].title.contains("EXPOSED"));

        // Still exposed → deduped (level, not edge).
        let held = evaluate(&store, &cfg, NOW + 2, Some(true), None, &mut state).await;
        assert!(held.is_empty(), "unchanged verdict must not re-fire");

        // An Unknown probe must not fake a flip when the verdict returns.
        let unknown = evaluate(&store, &cfg, NOW + 3, None, None, &mut state).await;
        assert!(unknown.is_empty());
        let back = evaluate(&store, &cfg, NOW + 4, Some(false), None, &mut state).await;
        assert_eq!(kinds(&back), vec![SignalKind::ExposureChange]);
        assert!(back[0].title.contains("resolved"));
    }

    #[tokio::test]
    async fn latency_p95_needs_min_samples_then_fires_and_dedupes() {
        let store = tmp_store().await;
        let cfg = Config::default(); // threshold 30_000ms
        let mut state = seeded_state();
        state.seen_apps.insert("cursor".into());

        // 19 slow samples: below the sample floor → silent even though slow.
        for i in 0..19 {
            store.enqueue(WriteOp::Request(req(
                &format!("s{i}"),
                NOW - 10_000 - i,
                "cursor",
                Some(45_000),
            )));
        }
        store.flush().await.unwrap();
        let too_few = evaluate(&store, &cfg, NOW, None, None, &mut state).await;
        assert!(
            too_few.is_empty(),
            "p95 on <{MIN_P95_SAMPLES} samples is noise"
        );

        // The 20th sample crosses the floor → fires.
        store.enqueue(WriteOp::Request(req(
            "s19",
            NOW - 9_000,
            "cursor",
            Some(45_000),
        )));
        store.flush().await.unwrap();
        let fired = evaluate(&store, &cfg, NOW, None, None, &mut state).await;
        assert_eq!(kinds(&fired), vec![SignalKind::LatencyP95]);

        // Same hour bucket → deduped.
        let again = evaluate(&store, &cfg, NOW + 60_000, None, None, &mut state).await;
        assert!(again.is_empty());
    }

    #[tokio::test]
    async fn spend_per_day_fires_and_dedupes_per_utc_day() {
        let store = tmp_store().await;
        let cfg = Config::default(); // threshold $10/day
        let mut state = seeded_state();

        let fired = evaluate(&store, &cfg, NOW, None, Some(12.5), &mut state).await;
        assert_eq!(kinds(&fired), vec![SignalKind::SpendPerDay]);
        assert!(fired[0].detail.contains("12.50"));

        // Same UTC day → deduped, even though spend keeps climbing.
        let again = evaluate(&store, &cfg, NOW + HOUR_MS, None, Some(15.0), &mut state).await;
        assert!(again.is_empty());

        // Next UTC day over threshold → fires again.
        let next_day = evaluate(
            &store,
            &cfg,
            NOW + 24 * HOUR_MS,
            None,
            Some(11.0),
            &mut state,
        )
        .await;
        assert_eq!(kinds(&next_day), vec![SignalKind::SpendPerDay]);

        // Under threshold stays quiet.
        let quiet = evaluate(
            &store,
            &cfg,
            NOW + 48 * HOUR_MS,
            None,
            Some(3.0),
            &mut state,
        )
        .await;
        assert!(quiet.is_empty());
    }

    #[tokio::test]
    async fn state_round_trips_through_the_settings_table() {
        let store = tmp_store().await;
        let mut state = seeded_state();
        state.seen_apps.insert("aider".into());
        state.last_exposure = Some(true);
        state.fired.insert("pii_spike:1".into(), NOW);
        state.save(&store);
        store.flush().await.unwrap();

        let loaded = MonitorState::load(&store).await;
        assert!(loaded.initialized);
        assert!(loaded.seen_apps.contains("aider"));
        assert_eq!(loaded.last_exposure, Some(true));
        assert!(loaded.fired.contains_key("pii_spike:1"));
    }

    #[test]
    fn spend_today_is_none_without_usage_data() {
        let dir = std::env::temp_dir().join(format!("saffev-empty-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(spend_today(&PricingConfig::default(), &dir, NOW), None);
    }
}
