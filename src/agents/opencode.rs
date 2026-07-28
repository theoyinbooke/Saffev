//! OpenCode adapter — reads `~/.local/share/opencode/opencode.db` (SQLite).
//!
//! Canonical store since OpenCode ~1.2 (a legacy JSON tree may also exist, but is
//! a stale pre-migration copy — we prefer the DB). Tables: `session`, `message`,
//! `part`; identity is in columns, everything else is a JSON `data` blob (role,
//! `tokens{input,output,cache{read,write}}`, model, part `type`). Times are epoch
//! **milliseconds**. Read via a read-only snapshot (never touches the live DB).
//! Verified against a real DB on-disk.

use std::path::PathBuf;

use rusqlite::Connection;

use super::{
    home, with_sqlite_snapshot, AgentMessage, AgentReader, AgentSession, AgentSessionDetail,
    AgentTool, MessageKind, Role,
};

/// Reads OpenCode's SQLite history.
pub struct OpenCodeReader {
    db: PathBuf,
}

impl OpenCodeReader {
    /// Fixture seam: read an explicit database file. See
    /// `tests/agents_bench.rs`.
    pub fn with_db(db: PathBuf) -> Self {
        Self { db }
    }

    /// `$XDG_DATA_HOME/opencode/opencode.db` else `~/.local/share/opencode/opencode.db`.
    pub fn new() -> Self {
        let base = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home().join(".local/share"))
            .join("opencode");
        Self {
            db: base.join("opencode.db"),
        }
    }

    fn has_tables(conn: &Connection) -> bool {
        conn.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('session','message','part')",
            [],
            |r| r.get::<_, i64>(0),
        )
        .map(|n| n == 3)
        .unwrap_or(false)
    }

    /// Build a session summary from its row + aggregate queries.
    fn summary(
        conn: &Connection,
        id: &str,
        title: &str,
        dir: &str,
        created: i64,
        updated: i64,
    ) -> AgentSession {
        // Tokens: sum assistant message token fields (final per-message totals).
        let (inp, outp, cache, cache_w) = conn
            .query_row(
                "SELECT \
                   COALESCE(SUM(json_extract(data,'$.tokens.input')),0), \
                   COALESCE(SUM(json_extract(data,'$.tokens.output')),0), \
                   COALESCE(SUM(json_extract(data,'$.tokens.cache.read')),0) + COALESCE(SUM(json_extract(data,'$.tokens.cache.write')),0), \
                   COALESCE(SUM(json_extract(data,'$.tokens.cache.write')),0) \
                 FROM message WHERE session_id=?1 AND json_extract(data,'$.role')='assistant'",
                [id],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                },
            )
            .unwrap_or((0, 0, 0, 0));
        let msg_count = conn
            .query_row(
                "SELECT count(*) FROM message WHERE session_id=?1",
                [id],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0);
        let tool_count = conn
            .query_row(
                "SELECT count(*) FROM part WHERE session_id=?1 AND json_extract(data,'$.type')='tool'",
                [id],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0);
        // Primary model = provider/model of the most recent assistant message.
        let model: Option<String> = conn
            .query_row(
                "SELECT json_extract(data,'$.providerID') || '/' || json_extract(data,'$.modelID') \
                 FROM message WHERE session_id=?1 AND json_extract(data,'$.role')='assistant' \
                 ORDER BY time_created DESC LIMIT 1",
                [id],
                |r| r.get::<_, Option<String>>(0),
            )
            .ok()
            .flatten()
            .filter(|s| !s.starts_with("null"));

        AgentSession {
            id: AgentSession::make_id(AgentTool::OpenCode, id),
            tool: AgentTool::OpenCode,
            title: Some(title.to_string()).filter(|s| !s.is_empty()),
            project: Some(dir.to_string()).filter(|s| !s.is_empty()),
            git_branch: None,
            model,
            started_ts: created,
            updated_ts: if updated > 0 { updated } else { created },
            message_count: msg_count.max(0) as u32,
            tool_call_count: tool_count.max(0) as u32,
            input_tokens: inp.max(0) as u64,
            output_tokens: outp.max(0) as u64,
            cache_tokens: cache.max(0) as u64,
            cache_write_tokens: cache_w.max(0) as u64,
            source_path: "opencode.db".to_string(),
        }
    }
}

impl Default for OpenCodeReader {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentReader for OpenCodeReader {
    fn tool(&self) -> AgentTool {
        AgentTool::OpenCode
    }
    fn is_present(&self) -> bool {
        self.db.is_file()
    }
    fn list_sessions(&self) -> Vec<AgentSession> {
        with_sqlite_snapshot(&self.db, |conn| {
            if !Self::has_tables(conn) {
                return Some(Vec::new());
            }
            let mut stmt = conn
                .prepare("SELECT id, title, directory, time_created, time_updated FROM session")
                .ok()?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1).unwrap_or_default(),
                        r.get::<_, String>(2).unwrap_or_default(),
                        r.get::<_, i64>(3).unwrap_or(0),
                        r.get::<_, Option<i64>>(4).unwrap_or(None).unwrap_or(0),
                    ))
                })
                .ok()?;
            let mut out = Vec::new();
            for row in rows.flatten() {
                let (id, title, dir, created, updated) = row;
                out.push(Self::summary(conn, &id, &title, &dir, created, updated));
            }
            Some(out)
        })
        .unwrap_or_default()
    }
    fn retention(&self) -> super::retention::RetentionPolicy {
        super::retention::RetentionPolicy::keeps_all(
            "Kept in a local database; no automatic deletion.",
        )
    }
    fn source_fingerprint(&self) -> Option<u64> {
        Some(super::hash_files(super::db_paths(&self.db).into_iter()))
    }
    fn session_detail(&self, raw_id: &str) -> Option<AgentSessionDetail> {
        with_sqlite_snapshot(&self.db, |conn| {
            if !Self::has_tables(conn) {
                return None;
            }
            let (title, dir, created, updated) = conn
                .query_row(
                    "SELECT title, directory, time_created, time_updated FROM session WHERE id=?1",
                    [raw_id],
                    |r| {
                        Ok((
                            r.get::<_, String>(0).unwrap_or_default(),
                            r.get::<_, String>(1).unwrap_or_default(),
                            r.get::<_, i64>(2).unwrap_or(0),
                            r.get::<_, Option<i64>>(3).unwrap_or(None).unwrap_or(0),
                        ))
                    },
                )
                .ok()?;
            let session = Self::summary(conn, raw_id, &title, &dir, created, updated);

            // Messages in order; each message's body = its text parts + tool parts.
            let mut mstmt = conn
                .prepare(
                    "SELECT id, json_extract(data,'$.role'), json_extract(data,'$.modelID'), time_created \
                     FROM message WHERE session_id=?1 ORDER BY time_created, id",
                )
                .ok()?;
            let msgs: Vec<(String, String, i64)> = mstmt
                .query_map([raw_id], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Option<String>>(1)?
                            .unwrap_or_else(|| "assistant".into()),
                        r.get::<_, i64>(3).unwrap_or(0),
                    ))
                })
                .ok()?
                .flatten()
                .collect();

            let mut out: Vec<AgentMessage> = Vec::new();
            let mut pstmt = conn
                .prepare(
                    "SELECT json_extract(data,'$.type'), json_extract(data,'$.text'), \
                            json_extract(data,'$.tool'), json_extract(data,'$.state.output') \
                     FROM part WHERE message_id=?1 ORDER BY time_created, id",
                )
                .ok()?;
            for (mid, role_s, ts) in msgs {
                let role = if role_s == "user" {
                    Role::User
                } else {
                    Role::Assistant
                };
                let parts = pstmt
                    .query_map([&mid], |r| {
                        Ok((
                            r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                            r.get::<_, Option<String>>(1)?,
                            r.get::<_, Option<String>>(2)?,
                            r.get::<_, Option<String>>(3)?,
                        ))
                    })
                    .ok()?;
                for p in parts.flatten() {
                    let (ptype, text, tool, tool_out) = p;
                    match ptype.as_str() {
                        "text" => {
                            if let Some(t) = text.filter(|s| !s.is_empty()) {
                                out.push(AgentMessage {
                                    role,
                                    kind: MessageKind::Text,
                                    content: t,
                                    ts: Some(ts).filter(|v| *v > 0),
                                    tool_name: None,
                                });
                            }
                        }
                        "reasoning" => {
                            if let Some(t) = text.filter(|s| !s.is_empty()) {
                                out.push(AgentMessage {
                                    role,
                                    kind: MessageKind::Thinking,
                                    content: t,
                                    ts: Some(ts).filter(|v| *v > 0),
                                    tool_name: None,
                                });
                            }
                        }
                        "tool" => {
                            out.push(AgentMessage {
                                role: Role::Tool,
                                kind: MessageKind::ToolUse,
                                content: super::claude_code::truncate(
                                    &tool_out.unwrap_or_default(),
                                    2000,
                                ),
                                ts: Some(ts).filter(|v| *v > 0),
                                tool_name: tool,
                            });
                        }
                        _ => {}
                    }
                }
            }
            Some(AgentSessionDetail {
                session,
                messages: out,
            })
        })
    }
}
