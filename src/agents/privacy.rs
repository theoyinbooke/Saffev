//! Whole-history privacy report — "across everything, where did I leak a secret?"
//!
//! Until this existed, PII in coding-agent history could only be seen one session
//! at a time, by opening it. That answers a question nobody asks. The question
//! people actually have is the aggregate one: *what have I been pasting into
//! these tools, and where?*
//!
//! ## Scope, stated honestly
//! The scan reads the **preserved archive**, not the live source files. Scanning
//! every live transcript per request would mean re-parsing hundreds of megabytes
//! on each page load, which is precisely the cost the archive exists to pay once.
//! So coverage is "your preserved sessions", and the report says so rather than
//! implying it saw everything.
//!
//! ## What is kept
//! Counts, kinds, and which session they were in. Never the matched text. The
//! privacy view must not itself become a second copy of the secret.

use std::collections::BTreeMap;

use crate::brain::PiiKind;
use crate::store::{ArchivePiiRow, Store};

/// A `(name, count)` pair for the grouped breakdowns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedCount {
    pub name: String,
    pub count: u64,
}

/// A per-kind count, flagged with how much to trust it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KindCount {
    pub name: String,
    pub count: u64,
    /// True for kinds that over-match on source code and should not be read as
    /// leaks without looking. See [`is_noisy_in_code`].
    pub noisy: bool,
}

/// Does this kind over-match on the contents of a coding session?
///
/// This matters more here than on the proxy side. A coding transcript is full of
/// version strings (`1.2.3.4`), ports, timestamps, durations and numeric ids, and
/// the IP and phone detectors are pattern-only — nothing validates them the way
/// Luhn validates a card or an entropy gate validates an API key. Measured on a
/// real 69k-message archive, IP and phone together were **83%** of all findings
/// while API keys were 0.1%.
///
/// So the report marks them rather than quietly inflating a headline number. A
/// privacy tool that cries wolf about 11,000 secrets teaches people to ignore it,
/// which is worse than not having the report at all.
pub fn is_noisy_in_code(kind: PiiKind) -> bool {
    matches!(kind, PiiKind::IpAddress | PiiKind::Phone)
}

/// One session that contains findings, for the drill-down table.
#[derive(Debug, Clone)]
pub struct SessionFindings {
    pub session_id: String,
    pub tool: String,
    pub title: Option<String>,
    pub project: Option<String>,
    pub updated_ts: i64,
    pub findings: u32,
    pub user_side: u32,
    /// Distinct kinds present, as display names, most frequent first.
    pub kinds: Vec<String>,
}

/// How much of the history the scan could actually see.
#[derive(Debug, Clone, Default)]
pub struct Coverage {
    /// Sessions preserved in the archive (what was scanned).
    pub preserved: u32,
    /// Sessions visible on this machine in total.
    pub total: u32,
}

/// The full cross-history privacy report for one time window.
#[derive(Debug, Clone, Default)]
pub struct PrivacyReport {
    pub generated_ts: i64,
    /// Window length in millis; 0 = everything.
    pub range_ms: i64,
    /// Sessions that contained at least one finding.
    pub sessions_with_findings: u32,
    pub total_findings: u64,
    /// Findings in messages the user wrote — the "what I pasted in" number.
    pub user_side_findings: u64,
    /// Findings excluding the kinds that over-match on code. This is the number
    /// worth putting in front of a person; `total_findings` is the raw tally.
    pub high_signal_findings: u64,
    /// Of the high-signal findings, those in messages the user wrote. The real
    /// headline: "you pasted N secrets into AI tools".
    pub high_signal_user_side: u64,
    pub by_kind: Vec<KindCount>,
    pub by_tool: Vec<NamedCount>,
    pub by_project: Vec<NamedCount>,
    /// Worst offenders first.
    pub top_sessions: Vec<SessionFindings>,
    pub coverage: Coverage,
}

/// How many sessions the drill-down table carries.
const TOP_SESSIONS: usize = 50;

/// Display name for a PII kind (custom patterns carry their own label).
fn kind_name(kind: PiiKind, label: Option<&str>) -> String {
    if let Some(l) = label {
        return l.to_string();
    }
    match kind {
        PiiKind::Email => "Email",
        PiiKind::Phone => "Phone",
        PiiKind::CreditCard => "Card",
        PiiKind::ApiKey => "API key",
        PiiKind::IpAddress => "IP address",
        PiiKind::Custom => "Custom",
    }
    .to_string()
}

/// Sort a name→count map into a descending list (ties broken by name so the
/// output is stable between runs).
fn ranked(map: BTreeMap<String, u64>) -> Vec<NamedCount> {
    let mut v: Vec<NamedCount> = map
        .into_iter()
        .map(|(name, count)| NamedCount { name, count })
        .collect();
    v.sort_by(|a, b| b.count.cmp(&a.count).then(a.name.cmp(&b.name)));
    v
}

/// Rank kinds with the trustworthy ones first, so the eye lands on API keys and
/// cards before it lands on a large pile of maybe-IP-addresses.
fn ranked_kinds(map: BTreeMap<String, (u64, bool)>) -> Vec<KindCount> {
    let mut v: Vec<KindCount> = map
        .into_iter()
        .map(|(name, (count, noisy))| KindCount { name, count, noisy })
        .collect();
    v.sort_by(|a, b| {
        a.noisy
            .cmp(&b.noisy)
            .then(b.count.cmp(&a.count))
            .then(a.name.cmp(&b.name))
    });
    v
}

/// Roll per-session scan rows up into the report. Pure, so it is unit-testable
/// without a database.
pub fn aggregate(rows: &[ArchivePiiRow], range_ms: i64, coverage: Coverage) -> PrivacyReport {
    // (count, noisy) per display name.
    let mut by_kind: BTreeMap<String, (u64, bool)> = BTreeMap::new();
    let mut by_tool: BTreeMap<String, u64> = BTreeMap::new();
    let mut by_project: BTreeMap<String, u64> = BTreeMap::new();
    let (mut total, mut user_side) = (0u64, 0u64);
    let (mut high_signal, mut high_signal_user) = (0u64, 0u64);

    for r in rows {
        total += r.findings as u64;
        user_side += r.user_side as u64;
        *by_tool.entry(r.tool.clone()).or_insert(0) += r.findings as u64;
        let project = r
            .project
            .as_deref()
            .filter(|p| !p.is_empty())
            .unwrap_or("(no project)");
        *by_project.entry(project.to_string()).or_insert(0) += r.findings as u64;

        let mut row_noisy = 0u64;
        for (kind, label, n) in &r.kinds {
            let noisy = is_noisy_in_code(*kind);
            let e = by_kind
                .entry(kind_name(*kind, label.as_deref()))
                .or_insert((0, noisy));
            e.0 += *n as u64;
            if noisy {
                row_noisy += *n as u64;
            } else {
                high_signal += *n as u64;
            }
        }
        // The per-session split of user vs assistant is not tracked per kind, so
        // apportion it by the row's high-signal share rather than inventing
        // precision we do not have.
        let row_total = r.findings as u64;
        if row_total > 0 {
            let hs = row_total.saturating_sub(row_noisy);
            high_signal_user += (r.user_side as u64).min(hs);
        }
    }

    let top_sessions = rows
        .iter()
        .take(TOP_SESSIONS)
        .map(|r| {
            let mut kinds: Vec<(String, u32)> = r
                .kinds
                .iter()
                .map(|(k, l, n)| (kind_name(*k, l.as_deref()), *n))
                .collect();
            kinds.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            SessionFindings {
                session_id: r.session_id.clone(),
                tool: r.tool.clone(),
                title: r.title.clone(),
                project: r.project.clone(),
                updated_ts: r.updated_ts,
                findings: r.findings,
                user_side: r.user_side,
                kinds: kinds.into_iter().map(|(n, _)| n).collect(),
            }
        })
        .collect();

    PrivacyReport {
        generated_ts: super::now_ms(),
        range_ms,
        sessions_with_findings: rows.len() as u32,
        total_findings: total,
        user_side_findings: user_side,
        high_signal_findings: high_signal,
        high_signal_user_side: high_signal_user,
        by_kind: ranked_kinds(by_kind),
        by_tool: ranked(by_tool),
        by_project: ranked(by_project),
        top_sessions,
        coverage,
    }
}

/// Cache key for a computed report: it must change whenever the archive changes,
/// the detector's patterns change, or the window changes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReportKey {
    archive: (u64, u64, u64),
    detector: u64,
    range_ms: i64,
}

fn report_cache() -> &'static std::sync::Mutex<Option<(ReportKey, PrivacyReport)>> {
    static C: std::sync::OnceLock<std::sync::Mutex<Option<(ReportKey, PrivacyReport)>>> =
        std::sync::OnceLock::new();
    C.get_or_init(|| std::sync::Mutex::new(None))
}

/// Stable signature of the user's custom-pattern list, so editing a pattern
/// invalidates a cached report instead of silently serving stale findings.
pub fn detector_signature(custom: &[crate::config::CustomPattern]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    for p in custom {
        p.name.hash(&mut h);
        p.regex.hash(&mut h);
    }
    custom.len().hash(&mut h);
    h.finish()
}

/// Compute (or reuse) the whole-history privacy report.
///
/// Scanning tens of thousands of messages with the full detector set is not free,
/// so the result is cached until the archive or the detector configuration
/// actually changes. Fail-soft: a detector that will not compile, or a store
/// error, yields an empty report rather than an error page.
pub async fn report(store: &Store, cfg: &crate::config::Config, range_ms: i64) -> PrivacyReport {
    let stats = store.archive_stats().await.unwrap_or_default();
    let key = ReportKey {
        archive: (stats.count, stats.messages, stats.bytes),
        detector: detector_signature(&cfg.custom_patterns),
        range_ms,
    };

    if let Ok(cache) = report_cache().lock() {
        if let Some((k, r)) = cache.as_ref() {
            if *k == key {
                return r.clone();
            }
        }
    }

    let Ok(detector) = crate::brain::pii::Detector::new(&cfg.custom_patterns) else {
        tracing::debug!(target: "saffev::agents", "privacy report: detector failed to compile");
        return PrivacyReport::default();
    };

    let since_ts = if range_ms > 0 {
        super::now_ms().saturating_sub(range_ms)
    } else {
        0
    };
    let rows = store
        .scan_archive_pii(std::sync::Arc::new(detector), since_ts)
        .await
        .unwrap_or_default();

    let coverage = Coverage {
        preserved: stats.count as u32,
        total: super::all_sessions().len() as u32,
    };
    let report = aggregate(&rows, range_ms, coverage);

    if let Ok(mut cache) = report_cache().lock() {
        *cache = Some((key, report.clone()));
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(
        id: &str,
        tool: &str,
        project: Option<&str>,
        findings: u32,
        user_side: u32,
        kinds: &[(PiiKind, u32)],
    ) -> ArchivePiiRow {
        ArchivePiiRow {
            session_id: id.into(),
            tool: tool.into(),
            title: Some("T".into()),
            project: project.map(String::from),
            updated_ts: 1000,
            findings,
            user_side,
            kinds: kinds.iter().map(|(k, n)| (*k, None, *n)).collect(),
        }
    }

    #[test]
    fn aggregate_rolls_up_every_dimension() {
        let rows = vec![
            row(
                "claude_code:a",
                "claude_code",
                Some("/one"),
                5,
                4,
                &[(PiiKind::ApiKey, 3), (PiiKind::Email, 2)],
            ),
            row(
                "codex:b",
                "codex",
                Some("/two"),
                2,
                0,
                &[(PiiKind::Email, 2)],
            ),
            row("codex:c", "codex", None, 1, 1, &[(PiiKind::ApiKey, 1)]),
        ];
        let r = aggregate(
            &rows,
            0,
            Coverage {
                preserved: 3,
                total: 10,
            },
        );

        assert_eq!(r.sessions_with_findings, 3);
        assert_eq!(r.total_findings, 8);
        // The headline claim: findings in messages the USER wrote.
        assert_eq!(r.user_side_findings, 5);

        // Kinds ranked, using display names.
        assert_eq!(r.by_kind[0].name, "API key");
        assert_eq!(r.by_kind[0].count, 4);
        assert_eq!(r.by_kind[1].name, "Email");
        assert_eq!(r.by_kind[1].count, 4);
        // Neither of these over-matches on code, so all findings are high-signal.
        assert!(r.by_kind.iter().all(|k| !k.noisy));
        assert_eq!(r.high_signal_findings, 8);

        // Tools and projects, with a stable label for "no project".
        assert_eq!(
            r.by_tool[0],
            NamedCount {
                name: "claude_code".into(),
                count: 5
            }
        );
        assert!(r
            .by_project
            .iter()
            .any(|p| p.name == "(no project)" && p.count == 1));

        // Coverage is reported, not implied.
        assert_eq!(r.coverage.preserved, 3);
        assert_eq!(r.coverage.total, 10);
    }

    #[test]
    fn custom_patterns_keep_their_label() {
        let mut r = row("codex:a", "codex", None, 1, 1, &[]);
        r.kinds = vec![(PiiKind::Custom, Some("Employee ID".into()), 2)];
        let out = aggregate(&[r], 0, Coverage::default());
        assert_eq!(out.by_kind[0].name, "Employee ID");
        assert_eq!(out.top_sessions[0].kinds, vec!["Employee ID".to_string()]);
    }

    /// The trust guard: a pile of pattern-only IP/phone hits must not inflate the
    /// number a person reads, and the trustworthy kinds must sort first.
    #[test]
    fn noisy_kinds_are_separated_from_the_headline() {
        let rows = vec![row(
            "claude_code:a",
            "claude_code",
            None,
            104,
            104,
            &[
                (PiiKind::IpAddress, 80),
                (PiiKind::Phone, 20),
                (PiiKind::ApiKey, 4),
            ],
        )];
        let r = aggregate(&rows, 0, Coverage::default());

        assert_eq!(r.total_findings, 104, "raw tally is still available");
        assert_eq!(r.high_signal_findings, 4, "only the validated kind counts");
        assert_eq!(r.high_signal_user_side, 4);

        // Trustworthy kinds lead, noisy ones follow and are flagged as such.
        assert_eq!(r.by_kind[0].name, "API key");
        assert!(!r.by_kind[0].noisy);
        assert!(r.by_kind[1].noisy && r.by_kind[2].noisy);
        assert_eq!(r.by_kind[1].name, "IP address");
    }

    #[test]
    fn noisy_classification_matches_what_over_matches_on_code() {
        assert!(is_noisy_in_code(PiiKind::IpAddress));
        assert!(is_noisy_in_code(PiiKind::Phone));
        // Validated (Luhn) or entropy-gated, so these are worth trusting.
        assert!(!is_noisy_in_code(PiiKind::CreditCard));
        assert!(!is_noisy_in_code(PiiKind::ApiKey));
        assert!(!is_noisy_in_code(PiiKind::Email));
        // A user's own pattern is their call, not ours to second-guess.
        assert!(!is_noisy_in_code(PiiKind::Custom));
    }

    #[test]
    fn empty_history_is_an_empty_report_not_an_error() {
        let r = aggregate(&[], 0, Coverage::default());
        assert_eq!(r.total_findings, 0);
        assert!(r.by_kind.is_empty());
        assert!(r.top_sessions.is_empty());
    }

    #[test]
    fn detector_signature_tracks_pattern_edits() {
        use crate::config::CustomPattern;
        let a = vec![CustomPattern {
            name: "x".into(),
            regex: "a+".into(),
            confidence: Default::default(),
        }];
        let b = vec![CustomPattern {
            name: "x".into(),
            regex: "b+".into(),
            confidence: Default::default(),
        }];
        assert_ne!(detector_signature(&a), detector_signature(&b));
        assert_eq!(detector_signature(&a), detector_signature(&a.clone()));
        assert_ne!(detector_signature(&a), detector_signature(&[]));
    }
}
