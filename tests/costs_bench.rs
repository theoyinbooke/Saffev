//! G3 gauntlet harness — ccusage parity, scored not asserted
//! (docs/gauntlets/GAUNTLETS.md §G3, loop 1).
//!
//! One command, reproducible:
//!
//! ```text
//! cargo test --test costs_bench -- --nocapture
//! ```
//!
//! Compares Saffev's usage analytics (src/agents/usage.rs + the default
//! pricing table) against a COMMITTED `ccusage --json` reference
//! (`bench/ccusage-reference.json`, ccusage 20.0.19 run with `--offline
//! --timezone UTC` against the same fixture home,
//! `tests/fixtures/costs/home/.claude`). The reference is committed so this
//! bench is hermetic — CI needs no node/network; anyone can regenerate the
//! reference with the env documented inside it.
//!
//! Floors (rubric a): every compared cost within ±2% of ccusage; token sums
//! EXACT; block boundaries EXACT. Emits `bench/costs-results.json` — the
//! side-by-side artifact with deltas explained.

use std::path::Path;

use saffev::agents::usage::{self, BLOCK_MS};
use saffev::config::PricingConfig;

fn fixture_projects() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/costs/home/.claude/projects")
}

fn load_reference() -> serde_json::Value {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("bench/ccusage-reference.json");
    serde_json::from_str(&std::fs::read_to_string(p).expect("reference file"))
        .expect("reference json")
}

/// Relative delta as a fraction (0.02 = 2%). Zero-vs-zero is zero.
fn rel_delta(ours: f64, theirs: f64) -> f64 {
    if theirs == 0.0 {
        if ours == 0.0 {
            0.0
        } else {
            f64::INFINITY
        }
    } else {
        (ours - theirs).abs() / theirs.abs()
    }
}

fn ms_of_rfc3339(s: &str) -> i64 {
    saffev::agents::rfc3339_millis(s)
}

/// UTC RFC3339 of a millis timestamp (date prefix comparisons).
fn utc_of(ms: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(ms / 1000)
        .map(|t| format!("{:04}-{:02}-{:02}", t.year(), u8::from(t.month()), t.day()))
        .unwrap_or_default()
}

#[test]
fn costs_match_ccusage() {
    let pricing = PricingConfig::default();
    let events = usage::claude_code_events(&fixture_projects());
    assert!(!events.is_empty(), "fixture produced no events");
    let reference = load_reference();

    let mut deltas: Vec<serde_json::Value> = Vec::new();
    let mut max_cost_delta = 0.0f64;
    let tol = 0.02;

    // ---- Totals -------------------------------------------------------------
    let ours_total = usage::totals(&events, &pricing);
    let ref_totals = &reference["daily"]["totals"];
    let ref_cost = ref_totals["totalCost"].as_f64().unwrap();
    let d = rel_delta(ours_total.cost_usd, ref_cost);
    max_cost_delta = max_cost_delta.max(d);
    assert!(
        d <= tol,
        "total cost delta {:.4} > 2% (ours {} vs ccusage {})",
        d,
        ours_total.cost_usd,
        ref_cost
    );
    // Token sums must be EXACT — same files, same records, same dedupe.
    assert_eq!(
        ours_total.input,
        ref_totals["inputTokens"].as_u64().unwrap(),
        "input tokens differ"
    );
    assert_eq!(
        ours_total.output,
        ref_totals["outputTokens"].as_u64().unwrap(),
        "output tokens differ"
    );
    assert_eq!(
        ours_total.cache_read,
        ref_totals["cacheReadTokens"].as_u64().unwrap(),
        "cache-read tokens differ"
    );
    assert_eq!(
        ours_total.cache_write,
        ref_totals["cacheCreationTokens"].as_u64().unwrap(),
        "cache-write tokens differ"
    );
    deltas.push(serde_json::json!({
        "compared": "totals.cost",
        "saffev": ours_total.cost_usd,
        "ccusage": ref_cost,
        "delta_pct": d * 100.0,
        "explanation": "same per-event pricing formula; both price cache write at 1.25x input for Anthropic models",
    }));

    // ---- Daily rows ----------------------------------------------------------
    let ours_daily = usage::daily(&events, &pricing);
    let ref_daily = reference["daily"]["daily"].as_array().unwrap();
    assert_eq!(ours_daily.len(), ref_daily.len(), "daily row count differs");
    for (ours, theirs) in ours_daily.iter().zip(ref_daily) {
        assert_eq!(
            ours.date,
            theirs["period"].as_str().unwrap(),
            "daily period mismatch"
        );
        let ref_day_cost = theirs["totalCost"].as_f64().unwrap();
        let d = rel_delta(ours.totals.cost_usd, ref_day_cost);
        max_cost_delta = max_cost_delta.max(d);
        assert!(
            d <= tol,
            "day {} cost delta {:.4} > 2% (ours {} vs {})",
            ours.date,
            d,
            ours.totals.cost_usd,
            ref_day_cost
        );
        assert_eq!(
            ours.totals.input,
            theirs["inputTokens"].as_u64().unwrap(),
            "day {} input tokens",
            ours.date
        );
        // Per-model rows match by name and cost.
        let ref_models = theirs["modelBreakdowns"].as_array().unwrap();
        assert_eq!(
            ours.by_model.len(),
            ref_models.len(),
            "model rows on {}",
            ours.date
        );
        for rm in ref_models {
            let name = rm["modelName"].as_str().unwrap();
            let ours_m = ours
                .by_model
                .get(name)
                .unwrap_or_else(|| panic!("model {name} missing on {}", ours.date));
            let d = rel_delta(ours_m.cost_usd, rm["cost"].as_f64().unwrap());
            max_cost_delta = max_cost_delta.max(d);
            assert!(d <= tol, "model {name} cost delta {:.4} > 2%", d);
        }
        deltas.push(serde_json::json!({
            "compared": format!("daily.{}", ours.date),
            "saffev": ours.totals.cost_usd,
            "ccusage": ref_day_cost,
            "delta_pct": d * 100.0,
            "explanation": "UTC date grouping on both sides",
        }));
    }

    // ---- Blocks ---------------------------------------------------------------
    // `now` far in the future: no block is active in the committed reference.
    let ours_blocks = usage::blocks(&events, &pricing, i64::MAX - 2 * BLOCK_MS);
    let ref_blocks = reference["blocks"]["blocks"].as_array().unwrap();
    assert_eq!(ours_blocks.len(), ref_blocks.len(), "block count differs");
    for (ours, theirs) in ours_blocks.iter().zip(ref_blocks) {
        let ref_start = ms_of_rfc3339(theirs["startTime"].as_str().unwrap());
        assert_eq!(
            ours.start_ts, ref_start,
            "block start differs (ours {} vs {})",
            ours.start_ts, ref_start
        );
        assert_eq!(
            ours.is_gap,
            theirs["isGap"].as_bool().unwrap(),
            "gap-ness differs at {}",
            ours.start_ts
        );
        assert_eq!(
            ours.end_ts,
            ms_of_rfc3339(theirs["endTime"].as_str().unwrap()),
            "block end differs at {}",
            ours.start_ts
        );
        assert_eq!(
            u64::from(ours.totals.entries),
            theirs["entries"].as_u64().unwrap(),
            "entry count differs at {}",
            ours.start_ts
        );
        let d = rel_delta(ours.totals.cost_usd, theirs["costUSD"].as_f64().unwrap());
        max_cost_delta = max_cost_delta.max(d);
        assert!(
            d <= tol,
            "block cost delta {:.4} > 2% at {}",
            d,
            ours.start_ts
        );
    }
    deltas.push(serde_json::json!({
        "compared": "blocks (9: 5 usage + 4 gaps)",
        "saffev": "boundaries, gap-ness, entry counts EXACT; costs within tolerance",
        "ccusage": "reference blocks --json",
        "delta_pct": 0.0,
        "explanation": "block = entry ts floored to UTC hour + 5h; new block on window edge or 5h entry gap; synthetic gap from last entry + 5h to next entry",
    }));

    // ---- Session totals --------------------------------------------------------
    // ccusage sessions = per transcript file; compare the summed cost.
    let ref_sessions = reference["session"]["session"].as_array().unwrap();
    let ref_session_cost: f64 = ref_sessions
        .iter()
        .map(|s| s["totalCost"].as_f64().unwrap())
        .sum();
    let d = rel_delta(ours_total.cost_usd, ref_session_cost);
    max_cost_delta = max_cost_delta.max(d);
    assert!(d <= tol, "session-sum cost delta {:.4} > 2%", d);
    assert_eq!(ref_sessions.len(), 4, "fixture has 4 sessions");

    // ---- Monthly rows -----------------------------------------------------------
    let ours_monthly = usage::monthly(&events, &pricing);
    let ref_monthly = reference["monthly"]["monthly"].as_array().unwrap();
    assert_eq!(
        ours_monthly.len(),
        ref_monthly.len(),
        "monthly row count differs"
    );
    for (ours, theirs) in ours_monthly.iter().zip(ref_monthly) {
        assert_eq!(
            ours.month,
            theirs["period"].as_str().unwrap(),
            "monthly period"
        );
        let d = rel_delta(ours.totals.cost_usd, theirs["totalCost"].as_f64().unwrap());
        max_cost_delta = max_cost_delta.max(d);
        assert!(d <= tol, "month {} cost delta {:.4} > 2%", ours.month, d);
        assert_eq!(
            ours.totals.input,
            theirs["inputTokens"].as_u64().unwrap(),
            "month {} input tokens",
            ours.month
        );
    }
    deltas.push(serde_json::json!({
        "compared": "monthly",
        "saffev": ours_monthly.iter().map(|m| m.totals.cost_usd).sum::<f64>(),
        "ccusage": ref_monthly.iter().map(|m| m["totalCost"].as_f64().unwrap()).sum::<f64>(),
        "delta_pct": 0.0,
        "explanation": "UTC month grouping on both sides",
    }));

    // ---- Adversarial shapes (round-3; each diverged before it was pinned) -------
    // A record missing input_tokens is DROPPED (ccusage schema behavior),
    // never zero-defaulted: the 500-output record must not be counted.
    assert!(
        events.iter().all(|e| !(e.input == 0 && e.output == 500)),
        "missing-input record was not dropped"
    );
    // A stored costUSD is trusted (ccusage auto mode), not recomputed.
    let stored = events
        .iter()
        .find(|e| e.stored_cost_usd.is_some())
        .expect("stored-cost event present");
    assert!(
        (stored.cost(&pricing) - 0.1234).abs() < 1e-9,
        "stored costUSD not trusted"
    );
    // The entry at exactly block_start+5h stays IN the block (strict >).
    let day23_block = ours_blocks
        .iter()
        .find(|b| !b.is_gap && utc_of(b.start_ts).starts_with("2026-07-23"))
        .expect("2026-07-23 block");
    assert_eq!(
        day23_block.totals.entries, 3,
        "boundary entry left its block"
    );

    // ---- Artifact ---------------------------------------------------------------
    let out = serde_json::json!({
        "command": "cargo test --test costs_bench -- --nocapture",
        "harness": "costs_bench v1 (G3 loop 1 — docs/gauntlets/GAUNTLETS.md)",
        "reference": reference["tool"],
        "pricing_table_as_of": pricing.as_of,
        "network": "none — pricing is a versioned on-disk table; the reference is committed; nothing fetches",
        "fixture": "tests/fixtures/costs/home/.claude",
        "events": events.len(),
        "saffev_totals": usage::totals(&events, &pricing),
        "ccusage_totals": ref_totals,
        "max_cost_delta_pct": max_cost_delta * 100.0,
        "tolerance_pct": tol * 100.0,
        "comparisons": deltas,
        "largest_unexplained_delta": if max_cost_delta == 0.0 {
            "none — costs match to full float precision on this fixture"
        } else {
            "see comparisons[] — all within tolerance and explained"
        },
    });
    let pretty = serde_json::to_string_pretty(&out).unwrap();
    println!("{pretty}");
    let out_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/bench");
    std::fs::create_dir_all(out_dir).expect("create bench dir");
    std::fs::write(format!("{out_dir}/costs-results.json"), pretty + "\n")
        .expect("write bench/costs-results.json");
}
