//! G6 gauntlet harness — signals: local monitors & notifications
//! (docs/gauntlets/GAUNTLETS.md §G6).
//!
//! One command, reproducible:
//!
//! ```text
//! cargo test --test signals_bench -- --nocapture
//! ```
//!
//! Constructs a fixture store that trips **all five** monitor rule classes at
//! once — PII spike, new source app, exposure verdict change, latency p95,
//! spend-per-day — then evaluates twice and enforces the rubric floors:
//!
//! - (a) every rule FIRES on the first evaluation and DEDUPLICATES on the
//!   second (same inputs, minutes later — the noisy re-fire case);
//! - (b) zero outbound network: every input is a local store read or a
//!   caller-supplied observation, and the notifier command spec is a local
//!   subprocess (asserted structurally below);
//! - (c) the rules live in the same TOML plane as everything else
//!   (`[monitors]` round-trips through the `Config` TOML serializer).
//!
//! Emits `bench/signals-results.json` — committed, and pinned by
//! `.github/workflows/signals-bench.yml` (`git diff --exit-code`) so the
//! artifact can never drift from what the code actually does.

use std::collections::BTreeMap;
use std::path::Path;

use saffev::config::Config;
use saffev::signals::{self, MonitorState, SignalKind};
use saffev::store::{
    PiiAction, PiiFindingRecord, RequestMeta, SourceConfidence, Store, TokenSource, WriteOp,
};

/// Fixed "now" so hour/day dedupe buckets are deterministic across runs.
const NOW: i64 = 1_753_600_000_000;
const MINUTE_MS: i64 = 60_000;

fn tmp_db() -> std::path::PathBuf {
    // Fixed key via the documented env override so the bench needs no keyring.
    std::env::set_var("SAFFEV_DB_KEY", "g6-signals-bench-key-0123456789abcd");
    std::env::temp_dir().join(format!("saffev-signals-bench-{}.db", uuid::Uuid::new_v4()))
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
        request_hash: "g6bench".into(),
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
        side: saffev::brain::Side::Request,
        kind: saffev::brain::PiiKind::Email,
        label: None,
        start_off: n,
        end_off: n + 5,
        confidence: saffev::brain::Confidence::High,
        action: PiiAction::Observed,
        value_hash: format!("g6-{n}"),
    }
}

#[tokio::test]
async fn signals_floors() {
    let cfg = Config::default(); // thresholds: 20 PII/h · 30_000ms p95 · $10/day

    // ---- fixture: one store tripping all five rules ---------------------------
    let store = Store::open(&tmp_db()).await.expect("open temp store");
    // 25 recent slow requests from a NEVER-seen app "aider": trips latency p95
    // (25 ≥ 20-sample floor, p95 = 45s > 30s) AND new-source-app together.
    for i in 0..25u32 {
        store.enqueue(WriteOp::Request(req(
            &format!("g6-{i}"),
            NOW - 10 * MINUTE_MS - i64::from(i),
            "aider",
            Some(45_000),
        )));
    }
    // 21 PII findings within the hour: trips the spike rule (> 20).
    store.enqueue(WriteOp::PiiFindings(
        (0..21).map(|n| finding("g6-0", n)).collect(),
    ));
    store.flush().await.expect("flush fixture writes");

    // Monitor memory as a running install would have it: seeded (so "aider" is
    // judged by the rule, not by first-run seeding) and previously not exposed
    // (so the Some(true) observation below is a genuine verdict flip).
    let mut state = MonitorState {
        initialized: true,
        last_exposure: Some(false),
        ..MonitorState::default()
    };

    // Exposure + spend are observations (inputs), exactly as the scheduler and
    // `status --check` supply them — $42 estimated spend trips $10/day.
    let exposed = Some(true);
    let spend = Some(42.0);

    // ---- rubric (a): all five fire… -------------------------------------------
    let first = signals::evaluate(&store, &cfg, NOW, exposed, spend, &mut state).await;
    let fired: Vec<SignalKind> = first.iter().map(|s| s.kind).collect();
    let all = [
        SignalKind::PiiSpike,
        SignalKind::NewSourceApp,
        SignalKind::ExposureChange,
        SignalKind::LatencyP95,
        SignalKind::SpendPerDay,
    ];
    for kind in all {
        assert!(
            fired.contains(&kind),
            "rule {kind:?} did not fire; got {fired:?}"
        );
    }
    assert_eq!(first.len(), 5, "each rule fires exactly once: {fired:?}");

    // ---- …and deduplicate ------------------------------------------------------
    // Same conditions five minutes later (same hour bucket / same UTC day /
    // same app / unchanged verdict): a monitor that repeats itself is an alarm.
    let second = signals::evaluate(
        &store,
        &cfg,
        NOW + 5 * MINUTE_MS,
        exposed,
        spend,
        &mut state,
    )
    .await;
    assert!(
        second.is_empty(),
        "every rule must dedupe on re-evaluation; re-fired: {:?}",
        second.iter().map(|s| s.kind).collect::<Vec<_>>()
    );

    // Dedup must survive a restart: round-trip the state through the store's
    // settings table (the persistence the scheduler and --check use).
    state.save(&store);
    store.flush().await.expect("flush state");
    let mut reloaded = MonitorState::load(&store).await;
    let third = signals::evaluate(
        &store,
        &cfg,
        NOW + 6 * MINUTE_MS,
        exposed,
        spend,
        &mut reloaded,
    )
    .await;
    assert!(third.is_empty(), "dedup must survive a state reload");

    // ---- rubric (b): zero outbound network -------------------------------------
    // Structural: the notifier is a local subprocess (notify-send / osascript),
    // never a URL/webhook. Platforms without one are an explicit no-op.
    if let Some((program, args)) = saffev::notify::command_spec("t", "b") {
        assert!(
            program == "notify-send" || program == "osascript",
            "notifier must be a local OS binary, got {program}"
        );
        assert!(
            !args
                .iter()
                .any(|a| a.contains("http://") || a.contains("https://")),
            "notifier argv must not carry URLs"
        );
    }

    // ---- rubric (c): same TOML config plane -------------------------------------
    // `[monitors]` round-trips through the same serializer as every other knob.
    let toml_text = toml::to_string_pretty(&cfg).expect("config serializes");
    assert!(
        toml_text.contains("[monitors]"),
        "monitors must serialize as a [monitors] TOML section"
    );
    let parsed: Config = toml::from_str(&toml_text).expect("config parses back");
    assert_eq!(
        parsed.monitors.pii_spike_per_hour,
        cfg.monitors.pii_spike_per_hour
    );
    assert_eq!(parsed.monitors.latency_p95_ms, cfg.monitors.latency_p95_ms);
    assert_eq!(
        parsed.monitors.spend_per_day_usd,
        cfg.monitors.spend_per_day_usd
    );

    // ---- artifact ----------------------------------------------------------------
    // BTreeMap keys → stable ordering → byte-stable JSON, so CI's
    // `git diff --exit-code` proves the committed artifact matches the code.
    let mut rules = BTreeMap::new();
    for kind in all {
        rules.insert(
            kind.as_str(),
            serde_json::json!({
                "fired": fired.contains(&kind),
                "deduped": !second.iter().any(|s| s.kind == kind),
            }),
        );
    }
    let results = serde_json::json!({
        "gauntlet": "G6 signals — local monitors & notifications",
        "command": "cargo test --test signals_bench -- --nocapture",
        "rules": rules,
        "zero_network": "all rule inputs are local store reads or caller-supplied \
    observations; notifications are local subprocesses (notify-send / osascript), \
    never webhooks; no rule path constructs a URL or opens a socket",
        "config_plane": "toml [monitors] (saffev.toml — same plane as every other setting)",
        "dedup": "threshold rules once per hour/day bucket; new-app once ever; \
    exposure once per verdict flip; state persisted in the store settings table",
    });
    let out = Path::new(env!("CARGO_MANIFEST_DIR")).join("bench/signals-results.json");
    std::fs::write(
        &out,
        format!("{}\n", serde_json::to_string_pretty(&results).unwrap()),
    )
    .expect("write bench artifact");
    println!(
        "G6 signals bench: all five rules fired + deduped · artifact at {}",
        out.display()
    );
}
