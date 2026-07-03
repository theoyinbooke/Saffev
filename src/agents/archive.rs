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

/// Run one incremental snapshot into the archive. Off the hot path; heavy parsing
/// happens on the blocking pool.
pub async fn run_snapshot(store: &Store) -> crate::Result<SnapshotSummary> {
    // Existing archive summaries (with content_hash + source_path + deleted flag)
    // drive both the incremental skip and accurate deletion detection.
    let existing = store.archived_sessions().await.unwrap_or_default();
    let store2 = store.clone();
    let summary = tokio::task::spawn_blocking(move || build(&store2, existing))
        .await
        .map_err(|e| crate::Error::Store(format!("archive join: {e}")))?;
    store.flush().await?;
    Ok(summary)
}

fn build(store: &Store, existing: Vec<ArchivedSession>) -> SnapshotSummary {
    let now = super::now_ms();
    let sessions = super::all_sessions();
    let mut seen: HashSet<String> = HashSet::with_capacity(sessions.len());
    let mut summary = SnapshotSummary::default();
    let by_id: HashMap<&str, &ArchivedSession> =
        existing.iter().map(|a| (a.id.as_str(), a)).collect();

    for s in &sessions {
        seen.insert(s.id.clone());
        let hash = content_hash(s);
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
                let archived = to_archived(&d, &hash, now);
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
fn content_hash(s: &AgentSession) -> String {
    fnv1a_hex(&format!(
        "{}|{}|{}|{}|{}|{}",
        s.updated_ts,
        s.message_count,
        s.tool_call_count,
        s.input_tokens,
        s.output_tokens,
        s.cache_tokens
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

fn to_archived(d: &AgentSessionDetail, hash: &str, now: i64) -> ArchivedSession {
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
        messages: d.messages.iter().map(msg_to_archived).collect(),
    }
}

fn msg_to_archived(m: &AgentMessage) -> ArchivedMessage {
    ArchivedMessage {
        role: role_str(m.role).to_string(),
        kind: kind_str(m.kind).to_string(),
        content: m.content.clone(),
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
        let h1 = content_hash(&s);
        assert_eq!(h1, content_hash(&s)); // stable
        s.message_count = 5;
        assert_ne!(h1, content_hash(&s)); // sensitive to growth
    }

    /// Manual: archives the real machine into a temp store, then re-runs (must be
    /// a full skip). `cargo test smoke_snapshot -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore]
    async fn smoke_snapshot() {
        std::env::set_var("SAFFEV_DB_KEY", "test-archive-key-0123456789abcdef");
        let path = std::env::temp_dir().join(format!("saffev-archive-{}.db", uuid::Uuid::new_v4()));
        let store = Store::open(&path).await.unwrap();

        let r1 = run_snapshot(&store).await.unwrap();
        eprintln!("run1: {r1:?}");
        let st = store.archive_stats().await.unwrap();
        eprintln!(
            "archive footprint: {} sessions · {} messages · {:.1} MB",
            st.count,
            st.messages,
            st.bytes as f64 / 1e6
        );

        let r2 = run_snapshot(&store).await.unwrap();
        eprintln!("run2 (expect all skipped): {r2:?}");
        assert_eq!(r2.archived, 0, "unchanged sessions must be skipped");
        assert!(st.count > 0, "should have archived something");

        let _ = std::fs::remove_file(&path);
    }
}
