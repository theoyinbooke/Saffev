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
        use std::collections::HashMap;
        with_sqlite_snapshot(&self.db, |conn| {
            if !Self::has_tables(conn) {
                return Some(Vec::new());
            }
            // Bulk-scan messages once and parse JSON in Rust (faster than 8x
            // `json_extract` per row AND skips corrupted JSON rows non-fatally).
            #[derive(Default)]
            struct MsgAgg {
                msg_count: i64,
                inp: i64,
                outp: i64,
                cache: i64,
                cache_w: i64,
                latest_ts: i64,
                model: Option<String>,
            }
            let mut msg_map: HashMap<String, MsgAgg> = HashMap::new();
            if let Ok(mut stmt) =
                conn.prepare("SELECT session_id, time_created, data FROM message")
            {
                if let Ok(rows) = stmt.query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1).unwrap_or(0),
                        r.get::<_, Option<String>>(2)?,
                    ))
                }) {
                    for (sid, ts, raw) in rows.flatten() {
                        let agg = msg_map.entry(sid).or_default();
                        agg.msg_count += 1;
                        let Some(raw) = raw else { continue };
                        let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) else {
                            continue;
                        };
                        if v.get("role").and_then(|x| x.as_str()) == Some("assistant") {
                            if let Some(tok) = v.get("tokens") {
                                agg.inp += tok.get("input").and_then(|x| x.as_i64()).unwrap_or(0);
                                agg.outp += tok.get("output").and_then(|x| x.as_i64()).unwrap_or(0);
                                if let Some(c) = tok.get("cache") {
                                    let cr = c.get("read").and_then(|x| x.as_i64()).unwrap_or(0);
                                    let cw = c.get("write").and_then(|x| x.as_i64()).unwrap_or(0);
                                    agg.cache += cr + cw;
                                    agg.cache_w += cw;
                                }
                            }
                            if ts >= agg.latest_ts {
                                if let (Some(p), Some(m)) = (
                                    v.get("providerID").and_then(|x| x.as_str()),
                                    v.get("modelID").and_then(|x| x.as_str()),
                                ) {
                                    if !p.is_empty() && !m.is_empty() {
                                        agg.latest_ts = ts;
                                        agg.model = Some(format!("{p}/{m}"));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Bulk-aggregate tool part counts once, skipping malformed JSON rows.
            let mut tool_map: HashMap<String, i64> = HashMap::new();
            if let Ok(mut stmt) = conn.prepare("SELECT session_id, data FROM part") {
                if let Ok(rows) = stmt.query_map([], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
                }) {
                    for (sid, raw) in rows.flatten() {
                        let Some(raw) = raw else { continue };
                        if !raw.contains("\"tool\"") {
                            continue;
                        }
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
                            if v.get("type").and_then(|x| x.as_str()) == Some("tool") {
                                *tool_map.entry(sid).or_default() += 1;
                            }
                        }
                    }
                }
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
            for (id, title, dir, created, updated) in rows.flatten() {
                let agg = msg_map.remove(&id).unwrap_or_default();
                let tool_count = tool_map.get(&id).copied().unwrap_or(0);
                out.push(AgentSession {
                    id: AgentSession::make_id(AgentTool::OpenCode, &id),
                    tool: AgentTool::OpenCode,
                    title: Some(title).filter(|s| !s.is_empty()),
                    project: Some(dir).filter(|s| !s.is_empty()),
                    git_branch: None,
                    model: agg.model,
                    started_ts: created,
                    updated_ts: if updated > 0 { updated } else { created },
                    message_count: agg.msg_count.max(0) as u32,
                    tool_call_count: tool_count.max(0) as u32,
                    input_tokens: agg.inp.max(0) as u64,
                    output_tokens: agg.outp.max(0) as u64,
                    cache_tokens: agg.cache.max(0) as u64,
                    cache_write_tokens: agg.cache_w.max(0) as u64,
                    source_path: "opencode.db".to_string(),
                });
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

            // Load all parts for the session in one query grouped by message_id
            // (eliminates M+1 per-message part queries and skips malformed JSON).
            type PartRow = (String, Option<String>, Option<String>, Option<String>);
            let mut parts_by_msg: std::collections::HashMap<String, Vec<PartRow>> =
                std::collections::HashMap::new();
            {
                let mut pstmt = conn
                    .prepare(
                        "SELECT message_id, data \
                         FROM part WHERE session_id=?1 ORDER BY time_created, id",
                    )
                    .ok()?;
                let parts = pstmt
                    .query_map([raw_id], |r| {
                        Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
                    })
                    .ok()?;
                for (mid, raw) in parts.flatten() {
                    let Some(raw) = raw else { continue };
                    let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) else {
                        continue;
                    };
                    let ptype = v
                        .get("type")
                        .and_then(|x| x.as_str())
                        .unwrap_or_default()
                        .to_string();
                    let text = v.get("text").and_then(|x| x.as_str()).map(String::from);
                    let tool = v.get("tool").and_then(|x| x.as_str()).map(String::from);
                    let tool_out = v
                        .get("state")
                        .and_then(|s| s.get("output"))
                        .and_then(|x| x.as_str())
                        .map(String::from);
                    parts_by_msg
                        .entry(mid)
                        .or_default()
                        .push((ptype, text, tool, tool_out));
                }
            }

            let mut out: Vec<AgentMessage> = Vec::new();
            for (mid, role_s, ts) in msgs {
                let role = if role_s == "user" {
                    Role::User
                } else {
                    Role::Assistant
                };
                let Some(parts) = parts_by_msg.remove(&mid) else {
                    continue;
                };
                for (ptype, text, tool, tool_out) in parts {
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
