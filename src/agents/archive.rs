//! Preservation snapshot job — the durable backup that survives source deletion.
//!
//! Reads every present tool's sessions, and for anything **new or changed** since
//! the last run, writes a normalized copy into the encrypted archive store. It is
//! **incremental**: a cheap content hash from the session's list metadata skips
//! unchanged sessions without re-parsing their (possibly 66MB) transcript, so
//! repeat runs are near-free. It also does **deletion detection**: archived
//! sessions the source app has since removed are flagged `source_deleted` — we
//! never delete our copy, because being the last copy is the whole point.
//!
//! Runs off the hot path (Studio-side), inside `spawn_blocking`, and uses the
//! backpressure-safe [`Store::enqueue_blocking`] so no write is ever dropped.

use std::collections::{HashMap, HashSet};

use crate::store::{ArchivedMessage, ArchivedSession, Store, WriteOp};

use super::{AgentMessage, AgentSession, AgentSessionDetail, MessageKind, Role};

/// Outcome of one snapshot run.
#[derive(Debug, Clone, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotSummary {
    /// Sessions newly archived or re-archived (changed).
    pub archived: u32,
    /// Sessions unchanged since last run (skipped without re-parsing).
    pub skipped: u32,
    /// Archived sessions the source has since deleted (flagged, copy kept).
    pub deleted_detected: u32,
    /// Sessions that failed to parse (skipped, fail-open).
    pub errors: u32,
}

/// How a session's text is written into the archive.
#[derive(Clone)]
pub struct Redaction {
    /// When set, detected secrets are replaced with a typed placeholder before
    /// the transcript is stored.
    pub detector: Option<std::sync::Arc<crate::brain::pii::Detector>>,
}

impl Redaction {
    /// Store transcripts verbatim (the default, and what every existing archive
    /// contains).
    pub fn off() -> Self {
        Self { detector: None }
    }

    /// Build from config. A detector that fails to compile disables redaction
    /// rather than silently archiving nothing — but the caller is told, because
    /// quietly storing raw secrets when the user asked for redaction would be the
    /// worst possible failure mode.
    pub fn from_config(cfg: &crate::config::Config) -> crate::Result<Self> {
        if !cfg.archive.redact {
            return Ok(Self::off());
        }
        let d = crate::brain::pii::Detector::new(&cfg.custom_patterns)?;
        Ok(Self {
            detector: Some(std::sync::Arc::new(d)),
        })
    }

    fn is_on(&self) -> bool {
        self.detector.is_some()
    }

    /// Redact one message body, returning the text to store.
    fn apply(&self, role: Role, text: &str) -> String {
        let Some(d) = self.detector.as_ref() else {
            return text.to_string();
        };
        let side = if role == Role::User {
            crate::brain::Side::Request
        } else {
            crate::brain::Side::Response
        };
        let findings = d.scan(side, text);
        if findings.is_empty() {
            return text.to_string();
        }
        // `None` = all high-confidence kinds. Low-confidence spans are never
        // masked, so a loose guess can't eat real content.
        crate::brain::pii::mask(text, &findings, None).0
    }
}

/// Run one incremental snapshot into the archive. Off the hot path; heavy parsing
/// happens on the blocking pool.
pub async fn run_snapshot(store: &Store, redaction: Redaction) -> crate::Result<SnapshotSummary> {
    // Existing archive summaries (with content_hash + source_path + deleted flag)
    // drive both the incremental skip and accurate deletion detection.
    let existing = store.archived_sessions().await.unwrap_or_default();
    let store2 = store.clone();
    let summary = tokio::task::spawn_blocking(move || build(&store2, existing, &redaction))
        .await
        .map_err(|e| crate::Error::Store(format!("archive join: {e}")))?;
    store.flush().await?;
    Ok(summary)
}

fn build(store: &Store, existing: Vec<ArchivedSession>, redaction: &Redaction) -> SnapshotSummary {
    let now = super::now_ms();
    let sessions = super::all_sessions();
    let mut seen: HashSet<String> = HashSet::with_capacity(sessions.len());
    let mut summary = SnapshotSummary::default();
    let by_id: HashMap<&str, &ArchivedSession> =
        existing.iter().map(|a| (a.id.as_str(), a)).collect();

    for s in &sessions {
        seen.insert(s.id.clone());
        let hash = content_hash(s, redaction.is_on());
        if let Some(a) = by_id.get(s.id.as_str()) {
            if a.content_hash == hash {
                summary.skipped += 1;
                // The source is present again — clear any stale deleted flag.
                if a.source_deleted {
                    let _ = store.enqueue_blocking(WriteOp::MarkSourceDeleted {
                        id: s.id.clone(),
                        deleted: false,
                    });
                }
                continue; // unchanged — no re-parse
            }
        }
        match super::detail(&s.id) {
            Some(d) => {
                let archived = to_archived(&d, &hash, now, redaction);
                if store
                    .enqueue_blocking(WriteOp::ArchiveSession(Box::new(archived)))
                    .is_ok()
                {
                    summary.archived += 1;
                } else {
                    summary.errors += 1;
                }
            }
            None => summary.errors += 1,
        }
    }

    // Deletion detection: only flag an archived session whose **source file is
    // positively gone** (never just because it fell outside the capped live list).
    // File-backed tools have a `.jsonl` source_path; shared-DB tools do not, so we
    // conservatively never auto-flag those.
    for a in &existing {
        if seen.contains(&a.id) || a.source_deleted {
            continue;
        }
        if a.source_path
            .as_deref()
            .map(source_is_gone)
            .unwrap_or(false)
        {
            let _ = store.enqueue_blocking(WriteOp::MarkSourceDeleted {
                id: a.id.clone(),
                deleted: true,
            });
            summary.deleted_detected += 1;
        }
    }

    summary
}

/// A per-session file source (`.jsonl`) that no longer exists = the app pruned it.
/// Shared databases (Cursor/OpenCode) are never treated as gone.
fn source_is_gone(source_path: &str) -> bool {
    source_path.ends_with(".jsonl") && !std::path::Path::new(source_path).exists()
}

/// Cheap change key from list metadata — changes whenever a session grows or is
/// touched, so unchanged sessions skip re-parsing. Stable (FNV-1a) so it compares
/// correctly across daemon restarts.
///
/// `redacted` is part of the key on purpose. Turning redaction on has to rewrite
/// what is already stored, otherwise the user flips the switch, sees no error,
/// and keeps a pile of unredacted transcripts that they now believe are safe.
fn content_hash(s: &AgentSession, redacted: bool) -> String {
    fnv1a_hex(&format!(
        "{}|{}|{}|{}|{}|{}|r{}",
        s.updated_ts,
        s.message_count,
        s.tool_call_count,
        s.input_tokens,
        s.output_tokens,
        s.cache_tokens,
        u8::from(redacted)
    ))
}

fn fnv1a_hex(s: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

fn to_archived(
    d: &AgentSessionDetail,
    hash: &str,
    now: i64,
    redaction: &Redaction,
) -> ArchivedSession {
    let s = &d.session;
    let source_id = super::split_id(&s.id)
        .map(|(_, r)| r.to_string())
        .unwrap_or_else(|| s.id.clone());
    ArchivedSession {
        id: s.id.clone(),
        tool: s.tool.key().to_string(),
        source_id,
        title: s.title.clone(),
        project: s.project.clone(),
        git_branch: s.git_branch.clone(),
        model: s.model.clone(),
        started_ts: s.started_ts,
        updated_ts: s.updated_ts,
        message_count: s.message_count,
        tool_call_count: s.tool_call_count,
        input_tokens: s.input_tokens,
        output_tokens: s.output_tokens,
        cache_tokens: s.cache_tokens,
        source_path: Some(s.source_path.clone()).filter(|p| !p.is_empty()),
        content_hash: hash.to_string(),
        archived_ts: now,
        source_deleted: false,
        messages: d
            .messages
            .iter()
            .map(|m| msg_to_archived(m, redaction))
            .collect(),
    }
}

fn msg_to_archived(m: &AgentMessage, redaction: &Redaction) -> ArchivedMessage {
    ArchivedMessage {
        role: role_str(m.role).to_string(),
        kind: kind_str(m.kind).to_string(),
        content: redaction.apply(m.role, &m.content),
        ts: m.ts,
        tool_name: m.tool_name.clone(),
    }
}

/// Stable string form of a role (shared with export).
pub(crate) fn role_str(r: Role) -> &'static str {
    match r {
        Role::User => "user",
        Role::Assistant => "assistant",
        Role::Tool => "tool",
        Role::System => "system",
    }
}

/// Stable string form of a message kind (shared with export).
pub(crate) fn kind_str(k: MessageKind) -> &'static str {
    match k {
        MessageKind::Text => "text",
        MessageKind::Thinking => "thinking",
        MessageKind::ToolUse => "tool_use",
        MessageKind::ToolResult => "tool_result",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deletion_detection_is_conservative() {
        // A shared DB path is never treated as gone (avoids false positives).
        assert!(!source_is_gone("opencode.db"));
        assert!(!source_is_gone("/Users/me/Library/.../state.vscdb"));
        // A per-session .jsonl that doesn't exist = the app pruned it.
        assert!(source_is_gone("/nope/rollout-does-not-exist.jsonl"));
        // An existing .jsonl is present.
        let f = std::env::temp_dir().join(format!("saffev-live-{}.jsonl", uuid::Uuid::new_v4()));
        std::fs::write(&f, "x").unwrap();
        assert!(!source_is_gone(&f.to_string_lossy()));
        let _ = std::fs::remove_file(&f);
    }

    fn redacting() -> Redaction {
        Redaction {
            detector: Some(std::sync::Arc::new(
                crate::brain::pii::Detector::new(&[]).unwrap(),
            )),
        }
    }

    #[test]
    fn redaction_removes_secrets_but_keeps_the_conversation() {
        let r = redacting();
        let text = "deploy with sk-abc123XYZdef456GHIjkl789MNO and mail ops@example.com";
        let out = r.apply(Role::User, text);

        // The secret and the address are gone...
        assert!(!out.contains("sk-abc123XYZdef456GHIjkl789MNO"), "{out}");
        assert!(!out.contains("ops@example.com"), "{out}");
        // ...but the surrounding text (the reason to keep the session) survives.
        assert!(out.contains("deploy with"), "{out}");
        assert!(out.contains("and mail"), "{out}");
    }

    #[test]
    fn redaction_off_is_byte_for_byte_verbatim() {
        let text = "token sk-abc123XYZdef456GHIjkl789MNO stays";
        assert_eq!(Redaction::off().apply(Role::User, text), text);
    }

    #[test]
    fn redaction_leaves_clean_text_untouched() {
        let out = redacting().apply(Role::Assistant, "just some ordinary prose");
        assert_eq!(out, "just some ordinary prose");
    }

    /// Turning redaction on must invalidate what is already archived, or the user
    /// flips the switch and unknowingly keeps raw transcripts.
    #[test]
    fn toggling_redaction_forces_a_re_archive() {
        let s = AgentSession {
            id: AgentSession::make_id(super::super::AgentTool::Codex, "x"),
            tool: super::super::AgentTool::Codex,
            title: None,
            project: None,
            git_branch: None,
            model: None,
            started_ts: 1,
            updated_ts: 100,
            message_count: 4,
            tool_call_count: 2,
            input_tokens: 10,
            output_tokens: 20,
            cache_tokens: 0,
            source_path: String::new(),
        };
        assert_ne!(content_hash(&s, false), content_hash(&s, true));
        assert_eq!(content_hash(&s, true), content_hash(&s, true));
    }

    #[test]
    fn redaction_from_config_is_off_by_default() {
        let cfg = crate::config::Config::default();
        assert!(!Redaction::from_config(&cfg).unwrap().is_on());
    }

    #[test]
    fn redaction_from_config_turns_on_when_asked() {
        let mut cfg = crate::config::Config::default();
        cfg.archive.redact = true;
        assert!(Redaction::from_config(&cfg).unwrap().is_on());
    }

    /// A pattern that will not compile must surface as an error, so the caller
    /// can refuse to archive rather than store raw text under a "redact" setting.
    #[test]
    fn redaction_from_config_errors_on_a_bad_pattern() {
        let mut cfg = crate::config::Config::default();
        cfg.archive.redact = true;
        cfg.custom_patterns = vec![crate::config::CustomPattern {
            name: "broken".into(),
            regex: "([unclosed".into(),
            confidence: Default::default(),
        }];
        assert!(Redaction::from_config(&cfg).is_err());
    }

    #[test]
    fn hash_is_stable_and_sensitive() {
        let mut s = AgentSession {
            id: AgentSession::make_id(super::super::AgentTool::Codex, "x"),
            tool: super::super::AgentTool::Codex,
            title: None,
            project: None,
            git_branch: None,
            model: None,
            started_ts: 1,
            updated_ts: 100,
            message_count: 4,
            tool_call_count: 2,
            input_tokens: 10,
            output_tokens: 20,
            cache_tokens: 0,
            source_path: String::new(),
        };
        let h1 = content_hash(&s, false);
        assert_eq!(h1, content_hash(&s, false)); // stable
        s.message_count = 5;
        assert_ne!(h1, content_hash(&s, false)); // sensitive to growth
    }

    /// Manual: archives the real machine into a temp store, then re-runs (must be
    /// a full skip). `cargo test smoke_snapshot -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore]
    async fn smoke_snapshot() {
        std::env::set_var("SAFFEV_DB_KEY", "test-archive-key-0123456789abcdef");
        let path = std::env::temp_dir().join(format!("saffev-archive-{}.db", uuid::Uuid::new_v4()));
        let store = Store::open(&path).await.unwrap();

        let r1 = run_snapshot(&store, Redaction::off()).await.unwrap();
        eprintln!("run1: {r1:?}");
        let st = store.archive_stats().await.unwrap();
        eprintln!(
            "archive footprint: {} sessions · {} messages · {:.1} MB",
            st.count,
            st.messages,
            st.bytes as f64 / 1e6
        );

        let r2 = run_snapshot(&store, Redaction::off()).await.unwrap();
        eprintln!("run2 (expect all skipped): {r2:?}");
        assert_eq!(r2.archived, 0, "unchanged sessions must be skipped");
        assert!(st.count > 0, "should have archived something");

        let _ = std::fs::remove_file(&path);
    }
}
