//! Per-request usage analytics — the ccusage-parity engine (G3).
//!
//! Session-level aggregates (AgentSession) cannot produce daily reports or
//! 5-hour billing blocks: those need PER-REQUEST usage events with
//! timestamps. This module extracts them from Claude Code's JSONL (each
//! assistant record carries `message.usage` + `timestamp`), dedupes the way
//! ccusage does (by `message.id` + `requestId` — retried/re-streamed records
//! appear twice), and aggregates into the three report shapes the G3 bar
//! names: daily, 5-hour billing blocks (with live burn), and totals.
//!
//! The block algorithm mirrors ccusage's observed behavior exactly (pinned
//! by `tests/costs_bench.rs` against a committed `ccusage --json` reference):
//! a block starts at the entry's timestamp floored to the UTC hour and spans
//! 5 hours; a new block starts when an entry lands at/after block start + 5h
//! OR at/after 5h since the previous entry; between two blocks a synthetic
//! GAP block runs from `previous actual end + 5h` to the next entry (only
//! when that interval is positive). A block is ACTIVE when `now` is before
//! both its end and `last entry + 5h`; burn/projection exist only for the
//! active block.
//!
//! Costs price cache READ and cache WRITE tokens separately
//! ([`crate::config::PricingConfig::lookup_split`]) — pricing writes at the
//! read rate understated real Anthropic histories by ~15%. Everything here
//! is pure local file reading + arithmetic; nothing fetches.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

use serde_json::Value;

use crate::config::PricingConfig;

/// Five hours, the Anthropic billing-block window ccusage reports.
pub const BLOCK_MS: i64 = 5 * 60 * 60 * 1000;

/// One priced API request (an assistant record with usage).
#[derive(Debug, Clone, serde::Serialize)]
pub struct UsageEvent {
    /// Unix millis.
    pub ts: i64,
    pub model: String,
    /// Non-cached input tokens (Anthropic's `input_tokens` is already
    /// non-cached).
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
    pub session_id: String,
    pub project: Option<String>,
}

impl UsageEvent {
    /// Price this event with read/write cache rates.
    pub fn cost(&self, pricing: &PricingConfig) -> f64 {
        let (pin, pout, pread, pwrite) = pricing.lookup_split(&self.model);
        (self.input as f64 * pin
            + self.output as f64 * pout
            + self.cache_read as f64 * pread
            + self.cache_write as f64 * pwrite)
            / 1_000_000.0
    }
}

/// Extract usage events from a Claude Code projects dir
/// (`~/.claude/projects`). Dedupe follows ccusage: a `(message.id,
/// requestId)` pair seen twice is the same billed request re-written.
pub fn claude_code_events(projects_dir: &Path) -> Vec<UsageEvent> {
    let mut out = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let Ok(slugs) = fs::read_dir(projects_dir) else {
        return out;
    };
    for slug in slugs.flatten() {
        let Ok(files) = fs::read_dir(slug.path()) else {
            continue;
        };
        for f in files.flatten() {
            let p = f.path();
            if p.extension().map(|e| e != "jsonl").unwrap_or(true) {
                continue;
            }
            let Ok(file) = fs::File::open(&p) else { continue };
            let session_id = p
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            let mut project: Option<String> = None;
            for line in BufReader::new(file).lines() {
                let Ok(line) = line else { continue };
                let Ok(v) = serde_json::from_str::<Value>(line.trim()) else {
                    continue;
                };
                if project.is_none() {
                    project = v.get("cwd").and_then(Value::as_str).map(String::from);
                }
                if v.get("type").and_then(Value::as_str) != Some("assistant") {
                    continue;
                }
                let Some(msg) = v.get("message") else { continue };
                let Some(usage) = msg.get("usage") else { continue };
                let ts = v
                    .get("timestamp")
                    .and_then(Value::as_str)
                    .map(super::rfc3339_millis)
                    .unwrap_or(0);
                if ts <= 0 {
                    continue;
                }
                let msg_id = msg.get("id").and_then(Value::as_str).unwrap_or("");
                let req_id = v.get("requestId").and_then(Value::as_str).unwrap_or("");
                if !msg_id.is_empty() || !req_id.is_empty() {
                    if !seen.insert((msg_id.to_string(), req_id.to_string())) {
                        continue; // retried/re-streamed duplicate
                    }
                }
                let g = |k: &str| usage.get(k).and_then(Value::as_u64).unwrap_or(0);
                out.push(UsageEvent {
                    ts,
                    model: msg
                        .get("model")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    input: g("input_tokens"),
                    output: g("output_tokens"),
                    cache_read: g("cache_read_input_tokens"),
                    cache_write: g("cache_creation_input_tokens"),
                    session_id: session_id.clone(),
                    project: project.clone(),
                });
            }
        }
    }
    out.sort_by_key(|e| e.ts);
    out
}

/// Token + cost sums (one aggregation cell).
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Tally {
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
    pub cost_usd: f64,
    pub entries: u32,
}

impl Tally {
    fn add(&mut self, e: &UsageEvent, pricing: &PricingConfig) {
        self.input += e.input;
        self.output += e.output;
        self.cache_read += e.cache_read;
        self.cache_write += e.cache_write;
        self.cost_usd += e.cost(pricing);
        self.entries += 1;
    }
    pub fn total_tokens(&self) -> u64 {
        self.input + self.output + self.cache_read + self.cache_write
    }
}

/// One day's usage (UTC date), with per-model breakdown.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DailyRow {
    /// `YYYY-MM-DD` (UTC).
    pub date: String,
    pub totals: Tally,
    pub by_model: BTreeMap<String, Tally>,
}

/// UTC calendar date of a unix-millis timestamp.
fn utc_date(ts: i64) -> String {
    let t = time::OffsetDateTime::from_unix_timestamp(ts / 1000)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    format!("{:04}-{:02}-{:02}", t.year(), u8::from(t.month()), t.day())
}

/// Group events into UTC daily rows (ccusage `daily --timezone UTC`).
pub fn daily(events: &[UsageEvent], pricing: &PricingConfig) -> Vec<DailyRow> {
    let mut days: BTreeMap<String, DailyRow> = BTreeMap::new();
    for e in events {
        let date = utc_date(e.ts);
        let row = days.entry(date.clone()).or_insert_with(|| DailyRow {
            date,
            totals: Tally::default(),
            by_model: BTreeMap::new(),
        });
        row.totals.add(e, pricing);
        row.by_model.entry(e.model.clone()).or_default().add(e, pricing);
    }
    days.into_values().collect()
}

/// Live-burn figures for the active block.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BurnRate {
    /// Tokens per minute over the block so far.
    pub tokens_per_minute: f64,
    /// USD per hour over the block so far.
    pub cost_per_hour: f64,
    /// Cost projected to the block's end at the current rate.
    pub projected_cost_usd: f64,
    /// Tokens projected to the block's end at the current rate.
    pub projected_tokens: u64,
}

/// One 5-hour billing block (or a synthetic gap between blocks).
#[derive(Debug, Clone, serde::Serialize)]
pub struct Block {
    /// Block start (unix millis; entry ts floored to the UTC hour).
    pub start_ts: i64,
    /// Nominal end: `start + 5h` (for gaps: the next entry's ts).
    pub end_ts: i64,
    /// Timestamp of the last entry actually in the block (None for gaps).
    pub actual_end_ts: Option<i64>,
    pub is_gap: bool,
    pub is_active: bool,
    pub totals: Tally,
    pub models: Vec<String>,
    /// Present only on the active block.
    pub burn: Option<BurnRate>,
}

/// Group events into 5-hour billing blocks, ccusage-compatible (see module
/// docs for the algorithm). `now_ms` decides the active block and its burn.
pub fn blocks(events: &[UsageEvent], pricing: &PricingConfig, now_ms: i64) -> Vec<Block> {
    let floor_hour = |ts: i64| ts - ts.rem_euclid(3_600_000);
    let mut out: Vec<Block> = Vec::new();
    let mut cur: Option<Block> = None;
    let mut last_entry_ts = 0i64;
    let mut model_set: Vec<String> = Vec::new();

    let close =
        |cur: &mut Option<Block>, out: &mut Vec<Block>, models: &mut Vec<String>, last: i64| {
            if let Some(mut b) = cur.take() {
                b.actual_end_ts = Some(last);
                b.models = std::mem::take(models);
                out.push(b);
            }
        };

    for e in events {
        let needs_new = match &cur {
            None => true,
            Some(b) => e.ts >= b.start_ts + BLOCK_MS || e.ts - last_entry_ts >= BLOCK_MS,
        };
        if needs_new {
            let prev_end = cur.as_ref().map(|_| last_entry_ts);
            close(&mut cur, &mut out, &mut model_set, last_entry_ts);
            // Synthetic gap from the previous block's expiry to this entry.
            if let Some(prev_last) = prev_end {
                let gap_start = prev_last + BLOCK_MS;
                if gap_start < e.ts {
                    out.push(Block {
                        start_ts: gap_start,
                        end_ts: e.ts,
                        actual_end_ts: None,
                        is_gap: true,
                        is_active: false,
                        totals: Tally::default(),
                        models: Vec::new(),
                        burn: None,
                    });
                }
            }
            cur = Some(Block {
                start_ts: floor_hour(e.ts),
                end_ts: floor_hour(e.ts) + BLOCK_MS,
                actual_end_ts: None,
                is_gap: false,
                is_active: false,
                totals: Tally::default(),
                models: Vec::new(),
                burn: None,
            });
        }
        if let Some(b) = cur.as_mut() {
            b.totals.add(e, pricing);
            if !e.model.is_empty() && !model_set.contains(&e.model) {
                model_set.push(e.model.clone());
            }
        }
        last_entry_ts = e.ts;
    }
    close(&mut cur, &mut out, &mut model_set, last_entry_ts);

    // Activity + burn: only the final real block can be active.
    if let Some(b) = out.iter_mut().rev().find(|b| !b.is_gap) {
        if now_ms < b.end_ts && now_ms - b.actual_end_ts.unwrap_or(0) < BLOCK_MS {
            b.is_active = true;
            let elapsed_ms = (now_ms - b.start_ts).max(60_000); // ≥1 min, no div-by-0 spikes
            let mins = elapsed_ms as f64 / 60_000.0;
            let hours = mins / 60.0;
            let tokens = b.totals.total_tokens() as f64;
            let tpm = tokens / mins;
            let cph = b.totals.cost_usd / hours;
            let block_hours = BLOCK_MS as f64 / 3_600_000.0;
            b.burn = Some(BurnRate {
                tokens_per_minute: tpm,
                cost_per_hour: cph,
                projected_cost_usd: cph * block_hours,
                projected_tokens: (tpm * block_hours * 60.0) as u64,
            });
        }
    }
    out
}

/// Overall totals across events.
pub fn totals(events: &[UsageEvent], pricing: &PricingConfig) -> Tally {
    let mut t = Tally::default();
    for e in events {
        t.add(e, pricing);
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(ts: i64, model: &str, i: u64, o: u64, cr: u64, cw: u64) -> UsageEvent {
        UsageEvent {
            ts,
            model: model.into(),
            input: i,
            output: o,
            cache_read: cr,
            cache_write: cw,
            session_id: "s".into(),
            project: None,
        }
    }

    #[test]
    fn cache_write_is_priced_at_the_write_rate() {
        let p = PricingConfig::default();
        // opus: in 15, out 75, read 1.5, write 18.75 per 1M.
        let e = ev(1_000_000, "claude-opus-4-1", 1_000_000, 0, 0, 1_000_000);
        assert!((e.cost(&p) - (15.0 + 18.75)).abs() < 1e-9);
    }

    #[test]
    fn blocks_split_on_window_and_gap_with_synthetic_gaps() {
        let p = PricingConfig::default();
        let h = 3_600_000i64;
        // Entry at 08:10, then 09:45 (same block), then 14:02 next day-ish
        // (new block + gap).
        let events = vec![
            ev(8 * h + 10 * 60_000, "claude-opus-4-1", 100, 10, 0, 0),
            ev(9 * h + 45 * 60_000, "claude-opus-4-1", 100, 10, 0, 0),
            ev(30 * h + 2 * 60_000, "claude-opus-4-1", 100, 10, 0, 0),
        ];
        let blocks = blocks(&events, &p, i64::MAX - BLOCK_MS * 2);
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].start_ts, 8 * h, "floored to the hour");
        assert_eq!(blocks[0].end_ts, 13 * h);
        assert_eq!(blocks[0].totals.entries, 2);
        assert!(blocks[1].is_gap);
        assert_eq!(
            blocks[1].start_ts,
            9 * h + 45 * 60_000 + BLOCK_MS,
            "gap starts at last entry + 5h"
        );
        assert_eq!(blocks[1].end_ts, 30 * h + 2 * 60_000, "gap ends at next entry");
        assert_eq!(blocks[2].start_ts, 30 * h);
        assert!(!blocks[2].is_active, "now is far past");
    }

    #[test]
    fn active_block_carries_burn_and_projection() {
        let p = PricingConfig::default();
        let start = 1_753_600_000_000i64; // arbitrary, not hour-aligned
        let events = vec![ev(start, "claude-sonnet-4-5", 1000, 500, 0, 0)];
        let now = start + 30 * 60_000; // 30 min in
        let blocks = blocks(&events, &p, now);
        let active = blocks.iter().find(|b| b.is_active).expect("active block");
        let burn = active.burn.as_ref().expect("burn on active block");
        assert!(burn.tokens_per_minute > 0.0);
        assert!(burn.projected_cost_usd > active.totals.cost_usd);
    }

    #[test]
    fn daily_groups_by_utc_date() {
        let p = PricingConfig::default();
        let day = 86_400_000i64;
        let events = vec![
            ev(day + 1000, "claude-haiku-4-5", 10, 1, 0, 0),
            ev(day + 2000, "claude-sonnet-4-5", 10, 1, 0, 0),
            ev(2 * day + 1000, "claude-haiku-4-5", 10, 1, 0, 0),
        ];
        let rows = daily(&events, &p);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].date, "1970-01-02");
        assert_eq!(rows[0].totals.entries, 2);
        assert_eq!(rows[0].by_model.len(), 2);
    }
}
