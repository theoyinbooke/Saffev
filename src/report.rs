//! `saffev report` — a local, offline privacy report (G4).
//!
//! Renders a Markdown report a security reviewer can read cold and answer
//! "what left this machine?" from alone: traffic (apps, models, engines),
//! PII findings by kind and by app, masking/blocking posture, network
//! exposure verdict, agent-session coverage, and archive integrity — each
//! section stating its MEASUREMENT BOUNDARY, because a privacy claim
//! without its boundary is marketing.
//!
//! Everything is read from the local store + config + OS socket table;
//! generating the report performs ZERO network calls (the report says so,
//! and the G4 critic verifies it). [`render`] is pure — data in, Markdown
//! out — so the committed sample (`docs/examples/privacy-report.md`)
//! regenerates deterministically under CI.

use std::collections::BTreeMap;

use crate::brain::{PiiKind, Side};
use crate::config::Config;
use crate::store::{ArchiveIntegrity, ArchiveStats, HistoryRow, PiiFindingRecord};

/// Everything the report reads, gathered by the caller (CLI/API) so the
/// renderer itself is pure and testable.
pub struct ReportInputs {
    /// Report generation time (unix millis) — injected for determinism.
    pub now_ms: i64,
    /// Covered period in days (history rows are already filtered to it).
    pub period_days: u32,
    /// App version string.
    pub version: String,
    /// History rows in the period, newest first.
    pub history: Vec<HistoryRow>,
    /// All PII findings joined to the period's requests.
    pub findings: Vec<PiiFindingRecord>,
    /// Map request-id → source app (for findings-by-app), derived from history.
    pub config: Config,
    /// Exposure verdict line (from `exposure::check`), e.g.
    /// "loopback only (127.0.0.1) — not reachable from the network".
    pub exposure_line: String,
    /// Whether the exposure check could run (false = unknown platform).
    pub exposure_known: bool,
    /// Archive integrity (chain verification result), if the archive is on.
    pub archive: Option<ArchiveIntegrity>,
    /// Archive size stats.
    pub archive_stats: Option<ArchiveStats>,
    /// Agent tools present on this machine: (label, session count).
    pub agent_tools: Vec<(String, u32)>,
}

/// UTC `YYYY-MM-DD HH:MM` of a millis timestamp.
fn utc(ts: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(ts / 1000)
        .map(|t| {
            format!(
                "{:04}-{:02}-{:02} {:02}:{:02} UTC",
                t.year(),
                u8::from(t.month()),
                t.day(),
                t.hour(),
                t.minute()
            )
        })
        .unwrap_or_else(|_| "unknown".into())
}

fn pct(n: usize, d: usize) -> String {
    if d == 0 {
        "0%".into()
    } else {
        format!("{:.0}%", n as f64 * 100.0 / d as f64)
    }
}

/// Render the full Markdown report. Pure: no IO, no clock, no network.
pub fn render(i: &ReportInputs) -> String {
    let mut out = String::with_capacity(8192);
    let total = i.history.len();
    let push = |out: &mut String, s: &str| {
        out.push_str(s);
        out.push('\n');
    };

    push(&mut out, &format!("# Saffev privacy report — last {} days", i.period_days));
    push(&mut out, "");
    push(
        &mut out,
        &format!(
            "Generated {} · saffev v{} · **generated offline — producing this report performs no network calls**",
            utc(i.now_ms),
            i.version
        ),
    );
    push(&mut out, "");

    // ---- Executive answer --------------------------------------------------
    push(&mut out, "## What left this machine?");
    push(&mut out, "");
    let masking = &i.config.masking;
    let payload = i.config.payload_storage;
    let blocked_kinds = masking.block_kinds.len();
    push(&mut out, &format!(
        "- **{total} model exchanges** were proxied in the period. The proxy forwards ONLY to the configured local engine port — a structural property of the configuration, not a per-request measurement (see Exposure below for whether anything else could reach that engine)."
    ));
    push(&mut out, &format!(
        "- Saffev stored **{}** for those exchanges. {}",
        if payload { "metadata AND payloads (explicitly enabled)" } else { "metadata only — raw prompt/response text was never written to disk" },
        if payload { "Payload storage is an explicit, logged user setting." } else { "" }
    ));
    let masked_line = match (masking.enabled, masking.dry_run) {
        (false, _) => "- **Masking was off** (observe-only): request bodies passed through unchanged; findings below are what a masking policy WOULD have caught.".to_string(),
        (true, true) => "- **Masking was in dry-run**: nothing was mutated; findings below record what WOULD have been redacted.".to_string(),
        (true, false) => format!("- **Masking was active**: matched spans were redacted before reaching the engine{}.",
            if blocked_kinds > 0 { format!(" and {blocked_kinds} kind(s) were configured to BLOCK the request entirely") } else { String::new() }),
    };
    push(&mut out, &masked_line);
    push(&mut out, "");
    push(&mut out, "> **Boundary:** this report covers traffic that went THROUGH the Saffev proxy and agent transcripts on THIS machine's disk. Traffic that bypassed the proxy (apps pointed directly at an engine or a cloud API) is invisible to it and is not claimed.");
    push(&mut out, "");

    // ---- Traffic -------------------------------------------------------------
    push(&mut out, "## Traffic");
    push(&mut out, "");
    let mut by_app: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_model: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_engine: BTreeMap<String, usize> = BTreeMap::new();
    let mut failed = 0usize;
    for r in &i.history {
        *by_app
            .entry(r.request.source_app.clone().unwrap_or_else(|| "unknown".into()))
            .or_default() += 1;
        *by_model
            .entry(r.request.model.clone().unwrap_or_else(|| "unspecified".into()))
            .or_default() += 1;
        *by_engine.entry(r.request.engine.clone()).or_default() += 1;
        let err = r
            .response
            .as_ref()
            .map(|resp| resp.error_kind.is_some() || resp.status.map(|s| s >= 400).unwrap_or(false))
            .unwrap_or(true);
        if err {
            failed += 1;
        }
    }
    push(&mut out, &format!("| | |\n|---|---|\n| Exchanges | {total} |\n| Failed / errored | {failed} ({}) |\n| Applications seen | {} |\n| Models used | {} |\n| Engines | {} |",
        pct(failed, total), by_app.len(), by_model.len(), by_engine.len()));
    push(&mut out, "");
    push(&mut out, "**By application** (requests):");
    push(&mut out, "");
    for (app, n) in &by_app {
        push(&mut out, &format!("- {app}: {n}"));
    }
    push(&mut out, "");
    push(&mut out, "**By model**:");
    push(&mut out, "");
    for (model, n) in &by_model {
        push(&mut out, &format!("- {model}: {n}"));
    }
    push(&mut out, "");
    push(&mut out, "> **Boundary:** application attribution is socket-PID based where possible (high confidence) and header-based otherwise; \"unknown\" rows had neither. History is read up to a 100,000-row cap before period filtering — periods busier than that are truncated, oldest first.");
    push(&mut out, "");

    // ---- Findings -------------------------------------------------------------
    push(&mut out, "## Sensitive-data findings");
    push(&mut out, "");
    let req_app: BTreeMap<&str, &str> = i
        .history
        .iter()
        .filter_map(|r| {
            r.request
                .source_app
                .as_deref()
                .map(|a| (r.request.id.as_str(), a))
        })
        .collect();
    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_finding_app: BTreeMap<String, usize> = BTreeMap::new();
    let mut request_side = 0usize;
    for f in &i.findings {
        let kind_label = kind_name(f.kind, f.label.as_deref());
        *by_kind.entry(kind_label).or_default() += 1;
        let app = req_app.get(f.record_id.as_str()).copied().unwrap_or("unknown");
        *by_finding_app.entry(app.to_string()).or_default() += 1;
        if f.side == Side::Request {
            request_side += 1;
        }
    }
    if i.findings.is_empty() {
        push(&mut out, "No sensitive-data findings in the period.");
    } else {
        push(&mut out, &format!(
            "**{} findings** across {} kinds — {} on the request side (outbound to the engine), {} on responses.",
            i.findings.len(), by_kind.len(), request_side, i.findings.len() - request_side
        ));
        push(&mut out, "");
        push(&mut out, "**By kind**:");
        push(&mut out, "");
        for (kind, n) in &by_kind {
            push(&mut out, &format!("- {kind}: {n}"));
        }
        push(&mut out, "");
        push(&mut out, "**By application**:");
        push(&mut out, "");
        for (app, n) in &by_finding_app {
            push(&mut out, &format!("- {app}: {n}"));
        }
    }
    push(&mut out, "");
    push(&mut out, "> **Boundary:** findings come from Saffev's deterministic detector suite (see `bench/pii-results.json` for its measured precision/recall on the public corpus). Only hashed spans are stored — the report never contains matched values.");
    push(&mut out, "");

    // ---- Exposure ---------------------------------------------------------------
    push(&mut out, "## Network exposure");
    push(&mut out, "");
    if i.exposure_known {
        push(&mut out, &format!("- {}", i.exposure_line));
    } else {
        push(&mut out, "- Exposure could not be determined on this platform (socket table unreadable) — treat as UNKNOWN, not as safe.");
    }
    push(&mut out, "");
    push(&mut out, "> **Boundary:** the verdict inspects the OS socket table at generation time; it says nothing about past bindings.");
    push(&mut out, "");

    // ---- Agent sessions -----------------------------------------------------------
    push(&mut out, "## Coding-agent sessions on this machine");
    push(&mut out, "");
    if i.agent_tools.is_empty() {
        push(&mut out, "No agent-tool histories detected.");
    } else {
        for (label, n) in &i.agent_tools {
            push(&mut out, &format!("- {label}: {n} sessions"));
        }
    }
    push(&mut out, "");
    push(&mut out, "> **Boundary:** session and archive counts are ALL-TIME, not period-scoped (tools do not index sessions by report period). Session counts come from each tool's own on-disk store (see `bench/agents-results.json` for the fixture-proven coverage per tool). Tools that encrypt their history (e.g. Windsurf) cannot be read and are not counted.");
    push(&mut out, "");

    // ---- Archive integrity ----------------------------------------------------------
    push(&mut out, "## Archive integrity");
    push(&mut out, "");
    match (&i.archive, &i.archive_stats) {
        (Some(a), stats) => {
            if a.intact {
                push(&mut out, &format!(
                    "- **INTACT** — {} chain entries over {} sessions recomputed correctly; no post-hoc edits detected.",
                    a.entries, a.sessions
                ));
            } else {
                push(&mut out, &format!(
                    "- **TAMPER DETECTED** — {}{}",
                    a.broken_at.as_deref().unwrap_or("chain verification failed"),
                    if a.altered_sessions.is_empty() {
                        String::new()
                    } else {
                        format!(" · altered sessions: {}", a.altered_sessions.join(", "))
                    }
                ));
            }
            if let Some(s) = stats {
                push(&mut out, &format!(
                    "- {} preserved sessions · {} messages · {} bytes",
                    s.count, s.messages, s.bytes
                ));
            }
        }
        _ => push(&mut out, "- Archive is not enabled — no preservation claims are made."),
    }
    push(&mut out, "");
    push(&mut out, "> **Boundary:** integrity is a SHA-256 hash chain over archived content; it proves the archive was not edited after capture, not that the source tools' files were unmodified before capture.");
    push(&mut out, "");

    // ---- Configuration appendix --------------------------------------------------------
    push(&mut out, "## Configuration at generation time");
    push(&mut out, "");
    push(&mut out, &format!("- Payload storage: **{}**", if payload { "ON (explicit)" } else { "off (default)" }));
    push(&mut out, &format!(
        "- Masking: **{}**",
        match (masking.enabled, masking.dry_run) {
            (false, _) => "off (observe-only)".to_string(),
            (true, true) => "enabled, dry-run".to_string(),
            (true, false) => "enabled, active".to_string(),
        }
    ));
    push(&mut out, &format!("- Retention: {:?}", i.config.retention));
    push(&mut out, &format!(
        "- Pricing table verified: {} (estimates only; never fetched)",
        i.config.pricing.as_of
    ));
    out
}

/// Human name for a finding kind (mirrors the Studio's labels).
fn kind_name(kind: PiiKind, label: Option<&str>) -> String {
    if let Some(l) = label {
        return l.to_string();
    }
    format!("{kind:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_renders_offline_with_boundaries() {
        let i = ReportInputs {
            now_ms: 1_753_700_000_000,
            period_days: 30,
            version: "0.7.1".into(),
            history: Vec::new(),
            findings: Vec::new(),
            config: Config::default(),
            exposure_line: "loopback only (127.0.0.1)".into(),
            exposure_known: true,
            archive: None,
            archive_stats: None,
            agent_tools: vec![("Claude Code".into(), 3)],
        };
        let md = render(&i);
        assert!(md.contains("What left this machine?"));
        assert!(md.contains("no network calls"));
        // Every section carries its measurement boundary.
        assert!(md.matches("**Boundary:**").count() >= 5);
        assert!(md.contains("metadata only"));
        assert!(md.contains("Claude Code: 3 sessions"));
        assert!(md.contains("Archive is not enabled"));
    }
}
