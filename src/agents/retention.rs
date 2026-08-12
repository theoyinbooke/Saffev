//! Retention awareness — what each coding tool does to its own history over time.
//!
//! The core insight of the Preservation layer: these tools treat your AI history
//! as disposable cache and delete it on their own clocks (Claude Code prunes
//! transcripts after `cleanupPeriodDays`, Cursor rotates its SQLite store to stay
//! bounded, etc.). Users can't see it happening and can't get it back. This module
//! models each tool's behavior and computes what is **at risk** so the UI can make
//! the invisible data loss visible, and the archive can prioritize it.

use super::{AgentSession, AgentTool};

/// How a source tool disposes of old history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionKind {
    /// Deletes entries older than a fixed age (see [`RetentionPolicy::days`]).
    AgeDays,
    /// Rotates/prunes to bound storage — no fixed per-entry expiry date.
    Churn,
    /// Keeps entries indefinitely by default.
    KeepsAll,
    /// Behavior not known.
    Unknown,
}

/// A tool's retention policy, with a human note for the UI.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetentionPolicy {
    /// Disposal mechanism.
    pub kind: RetentionKind,
    /// Age cutoff in days when `kind == AgeDays`.
    pub days: Option<u32>,
    /// Plain-language description for the UI.
    pub note: String,
}

impl RetentionPolicy {
    pub fn age_days(days: u32, note: impl Into<String>) -> Self {
        Self {
            kind: RetentionKind::AgeDays,
            days: Some(days),
            note: note.into(),
        }
    }
    pub fn churn(note: impl Into<String>) -> Self {
        Self {
            kind: RetentionKind::Churn,
            days: None,
            note: note.into(),
        }
    }
    pub fn keeps_all(note: impl Into<String>) -> Self {
        Self {
            kind: RetentionKind::KeepsAll,
            days: None,
            note: note.into(),
        }
    }
    pub fn unknown() -> Self {
        Self {
            kind: RetentionKind::Unknown,
            days: None,
            note: "Retention behavior unknown.".into(),
        }
    }
}

/// What is at risk for one tool, given its listed sessions.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AtRisk {
    /// The tool.
    pub tool: AgentTool,
    /// Its retention policy.
    pub policy: RetentionPolicy,
    /// Sessions total (as listed).
    pub total: u32,
    /// Sessions that cross the deletion line within the warning window.
    pub expiring_soon: u32,
    /// Sessions already past the deletion line (would be gone at the default cleanup).
    pub overdue: u32,
    /// Earliest upcoming deletion (unix millis), if age-based and any remain.
    pub soonest_expiry_ts: Option<i64>,
}

/// Milliseconds in a day.
const DAY_MS: i64 = 86_400_000;

/// How far ahead of a tool's deletion line counts as "expiring soon", in days.
/// One shared constant so the Agents page banner and the at-risk monitor
/// signal (G6) can never disagree about what "soon" means.
pub const AT_RISK_WARN_DAYS: i64 = 7;

/// Whether one session is at risk under `policy` at `now_ms`: it is past its
/// tool's deletion line already, or crosses it within `warn_days`. Only
/// age-based policies produce a date to be at risk of; churn/keeps-all/unknown
/// are never "at risk" in this sense (there is no line to warn about).
pub fn is_at_risk(policy: &RetentionPolicy, updated_ts: i64, now_ms: i64, warn_days: i64) -> bool {
    match (policy.kind, policy.days) {
        (RetentionKind::AgeDays, Some(days)) => {
            let expiry = updated_ts + days as i64 * DAY_MS;
            expiry <= now_ms + warn_days * DAY_MS
        }
        _ => false,
    }
}

/// The expiry timestamp (unix millis) a session would be deleted at under an
/// age-based `policy`; `None` for policies without a per-entry deadline.
pub fn expiry_ts(policy: &RetentionPolicy, updated_ts: i64) -> Option<i64> {
    match (policy.kind, policy.days) {
        (RetentionKind::AgeDays, Some(days)) => Some(updated_ts + days as i64 * DAY_MS),
        _ => None,
    }
}

/// Compute the at-risk breakdown for one tool from its sessions. `now_ms` is the
/// current wall clock; `warn_days` is how far ahead counts as "expiring soon".
pub fn at_risk_for(
    tool: AgentTool,
    policy: RetentionPolicy,
    sessions: &[&AgentSession],
    now_ms: i64,
    warn_days: i64,
) -> AtRisk {
    let total = sessions.len() as u32;
    let (mut expiring_soon, mut overdue, mut soonest) = (0u32, 0u32, None::<i64>);

    if policy.kind == RetentionKind::AgeDays {
        if let Some(days) = policy.days {
            let span = days as i64 * DAY_MS;
            for s in sessions {
                // A session is deleted when now >= updated_ts + span.
                let expiry = s.updated_ts + span;
                if expiry <= now_ms {
                    overdue += 1;
                } else {
                    if expiry <= now_ms + warn_days * DAY_MS {
                        expiring_soon += 1;
                    }
                    soonest = Some(soonest.map_or(expiry, |m| m.min(expiry)));
                }
            }
        }
    }

    AtRisk {
        tool,
        policy,
        total,
        expiring_soon,
        overdue,
        soonest_expiry_ts: soonest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::AgentSession;

    fn sess(tool: AgentTool, updated_ts: i64) -> AgentSession {
        AgentSession {
            id: AgentSession::make_id(tool, "x"),
            tool,
            title: None,
            project: None,
            git_branch: None,
            model: None,
            started_ts: updated_ts,
            updated_ts,
            message_count: 1,
            tool_call_count: 0,
            input_tokens: 0,
            output_tokens: 0,
            cache_tokens: 0,
            cache_write_tokens: 0,
            source_path: String::new(),
        }
    }

    #[test]
    fn age_based_at_risk_math() {
        let now = 1_000 * DAY_MS; // day 1000
        let policy = RetentionPolicy::age_days(30, "deletes after 30d");
        // updated at day 995 (age 5)  -> safe, expires day 1025
        // updated at day 975 (age 25) -> expiring soon (within 7d of the 30d line)
        // updated at day 965 (age 35) -> overdue
        let s_safe = sess(AgentTool::ClaudeCode, 995 * DAY_MS);
        let s_soon = sess(AgentTool::ClaudeCode, 975 * DAY_MS);
        let s_over = sess(AgentTool::ClaudeCode, 965 * DAY_MS);
        let all = [&s_safe, &s_soon, &s_over];
        let r = at_risk_for(AgentTool::ClaudeCode, policy, &all, now, 7);
        assert_eq!(r.total, 3);
        assert_eq!(r.overdue, 1);
        assert_eq!(r.expiring_soon, 1);
        // soonest upcoming expiry is the oldest not-yet-overdue = s_soon (day 1005)
        assert_eq!(r.soonest_expiry_ts, Some(1005 * DAY_MS));
    }

    #[test]
    fn churn_has_no_dates() {
        let now = 1_000 * DAY_MS;
        let s = sess(AgentTool::Cursor, 900 * DAY_MS);
        let r = at_risk_for(
            AgentTool::Cursor,
            RetentionPolicy::churn("rotates"),
            &[&s],
            now,
            7,
        );
        assert_eq!(r.overdue, 0);
        assert_eq!(r.expiring_soon, 0);
        assert_eq!(r.soonest_expiry_ts, None);
    }
}
