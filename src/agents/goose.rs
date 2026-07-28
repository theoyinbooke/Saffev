//! Goose adapter — reads Block's `sessions.db` SQLite store.
//!
//! Format verified from block/goose source at a pinned commit (G2 round 8;
//! `crates/goose/src/session/session_manager.rs`, schema version 15):
//!
//! * `~/.local/share/goose/sessions/sessions.db` (Linux; macOS keeps the
//!   `Block/goose` path segment for backwards compat). Legacy pre-SQLite
//!   `*.jsonl` files in the same dir are auto-migrated INTO the db by goose
//!   itself on first run — this adapter reads the db only.
//! * `sessions`: `id` is `YYYYMMDD_N` (per-day counter), `name` is the
//!   display title, `working_dir`, `created_at`/`updated_at` (SQLite text
//!   timestamps), `provider_name` + `model_config_json.model_name`, token
//!   columns in current and `accumulated_*` variants (accumulated = summed
//!   across compactions — the real session totals; current = last window).
//!   `session_type` distinguishes real sessions from `sub_agent` side
//!   threads and `hidden` internals — both skipped, like every other
//!   adapter's side threads.
//! * `messages`: `role` is `user`/`assistant` only; `content_json` is a
//!   camelCase-tagged block array (`text` / `thinking` / `toolRequest` /
//!   `toolResponse`); `created_timestamp` is unix SECONDS (values above
//!   1e10 are already millis — goose's own reader applies the same rule).
//!
//! Token convention note: goose stores what each provider reports, so
//! `input_tokens` follows the provider's own convention (Anthropic excludes
//! cache; others may not) — recorded as-is, not "corrected".
//!
//! Tolerant: unparseable JSON blobs degrade to empty blocks, never fatal.

use std::path::PathBuf;

use rusqlite::Connection;
use serde_json::Value;

use super::{
    home, with_sqlite_snapshot, AgentMessage, AgentReader, AgentSession, AgentSessionDetail,
    AgentTool, MessageKind, Role,
};

/// Reads Goose's SQLite session store.
pub struct GooseReader {
    db: PathBuf,
}

impl GooseReader {
    /// Fixture seam: read an explicit database file. See
    /// `tests/agents_bench.rs`.
    pub fn with_db(db: PathBuf) -> Self {
        Self { db }
    }

    /// Platform `sessions.db` path.
    pub fn new() -> Self {
        let base = if cfg!(target_os = "macos") {
            home().join("Library/Application Support/Block/goose")
        } else if cfg!(target_os = "windows") {
            std::env::var_os("APPDATA")
                .map(PathBuf::from)
                .unwrap_or_else(|| home().join("AppData/Roaming"))
                .join("Block/goose/data")
        } else {
            std::env::var_os("XDG_DATA_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| home().join(".local/share"))
                .join("goose")
        };
        Self {
            db: base.join("sessions/sessions.db"),
        }
    }

    fn has_tables(conn: &Connection) -> bool {
        conn.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('sessions','messages')",
            [],
            |r| r.get::<_, i64>(0),
        )
        .map(|n| n == 2)
        .unwrap_or(false)
    }

    /// `YYYY-MM-DD HH:MM:SS[.fff]` SQLite text timestamp → millis.
    fn sqlite_ts_millis(s: &str) -> i64 {
        let iso = s.replacen(' ', "T", 1);
        let iso = if iso.ends_with('Z') { iso } else { iso + "Z" };
        super::rfc3339_millis(&iso)
    }

    /// Goose's own rule: seconds unless the value is already millis.
    fn secs_or_millis(v: i64) -> i64 {
        if v > 10_000_000_000 {
            v
        } else {
            v * 1000
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn summary(conn: &Connection, row: SessionRow) -> AgentSession {
        let msg_count = conn
            .query_row(
                "SELECT count(*) FROM messages WHERE session_id=?1",
                [&row.id],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0);
        let tool_count = conn
            .query_row(
                "SELECT COALESCE(SUM((LENGTH(content_json) - LENGTH(REPLACE(content_json, '\"toolRequest\"', ''))) / 13), 0) \
                 FROM messages WHERE session_id=?1",
                [&row.id],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0);
        let model = match (&row.provider, &row.model_name) {
            (Some(p), Some(m)) => Some(format!("{p}/{m}")),
            (None, Some(m)) => Some(m.clone()),
            _ => None,
        };
        AgentSession {
            id: AgentSession::make_id(AgentTool::Goose, &row.id),
            tool: AgentTool::Goose,
            title: row.name.filter(|s| !s.is_empty()),
            project: row.working_dir.filter(|s| !s.is_empty()),
            git_branch: None,
            model,
            started_ts: Self::sqlite_ts_millis(&row.created_at),
            updated_ts: Self::sqlite_ts_millis(&row.updated_at)
                .max(Self::sqlite_ts_millis(&row.created_at)),
            message_count: msg_count.max(0) as u32,
            tool_call_count: tool_count.max(0) as u32,
            input_tokens: row.inp.max(0) as u64,
            output_tokens: row.outp.max(0) as u64,
            cache_tokens: row.cache.max(0) as u64,
            source_path: "sessions.db".to_string(),
        }
    }
}

/// One row of the fields this adapter reads from `sessions`.
struct SessionRow {
    id: String,
    name: Option<String>,
    working_dir: Option<String>,
    created_at: String,
    updated_at: String,
    provider: Option<String>,
    model_name: Option<String>,
    inp: i64,
    outp: i64,
    cache: i64,
}

/// `SELECT` list shared by list/detail. Accumulated totals are the real
/// session numbers; fall back to the current-window columns when zero.
const SESSION_COLS: &str = "id, name, working_dir, created_at, updated_at, provider_name, \
     json_extract(model_config_json,'$.model_name'), \
     CASE WHEN COALESCE(accumulated_input_tokens,0) + COALESCE(accumulated_output_tokens,0) > 0 \
          THEN COALESCE(accumulated_input_tokens,0) ELSE COALESCE(input_tokens,0) END, \
     CASE WHEN COALESCE(accumulated_input_tokens,0) + COALESCE(accumulated_output_tokens,0) > 0 \
          THEN COALESCE(accumulated_output_tokens,0) ELSE COALESCE(output_tokens,0) END, \
     CASE WHEN COALESCE(accumulated_input_tokens,0) + COALESCE(accumulated_output_tokens,0) > 0 \
          THEN COALESCE(accumulated_cache_read_tokens,0) + COALESCE(accumulated_cache_write_tokens,0) \
          ELSE COALESCE(cache_read_tokens,0) + COALESCE(cache_write_tokens,0) END";

fn row_to_session(r: &rusqlite::Row<'_>) -> rusqlite::Result<SessionRow> {
    Ok(SessionRow {
        id: r.get(0)?,
        name: r.get(1).unwrap_or(None),
        working_dir: r.get(2).unwrap_or(None),
        created_at: r.get::<_, Option<String>>(3).unwrap_or(None).unwrap_or_default(),
        updated_at: r.get::<_, Option<String>>(4).unwrap_or(None).unwrap_or_default(),
        provider: r.get(5).unwrap_or(None),
        model_name: r.get(6).unwrap_or(None),
        inp: r.get(7).unwrap_or(0),
        outp: r.get(8).unwrap_or(0),
        cache: r.get(9).unwrap_or(0),
    })
}

impl Default for GooseReader {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentReader for GooseReader {
    fn tool(&self) -> AgentTool {
        AgentTool::Goose
    }
    fn is_present(&self) -> bool {
        self.db.is_file()
    }
    fn list_sessions(&self) -> Vec<AgentSession> {
        with_sqlite_snapshot(&self.db, |conn| {
            if !Self::has_tables(conn) {
                return Some(Vec::new());
            }
            let sql = format!(
                "SELECT {SESSION_COLS} FROM sessions \
                 WHERE COALESCE(session_type,'user') NOT IN ('sub_agent','hidden') \
                   AND archived_at IS NULL"
            );
            let mut stmt = conn.prepare(&sql).ok()?;
            let rows = stmt.query_map([], row_to_session).ok()?;
            let mut out = Vec::new();
            for row in rows.flatten() {
                out.push(Self::summary(conn, row));
            }
            Some(out)
        })
        .unwrap_or_default()
    }
    fn retention(&self) -> super::retention::RetentionPolicy {
        super::retention::RetentionPolicy::keeps_all(
            "Kept in a local SQLite database; sessions persist until archived/deleted.",
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
            let sql = format!("SELECT {SESSION_COLS} FROM sessions WHERE id=?1");
            let row = conn.query_row(&sql, [raw_id], row_to_session).ok()?;
            let session = Self::summary(conn, row);

            let mut stmt = conn
                .prepare(
                    "SELECT role, content_json, created_timestamp FROM messages \
                     WHERE session_id=?1 ORDER BY created_timestamp, id",
                )
                .ok()?;
            let rows: Vec<(String, String, i64)> = stmt
                .query_map([raw_id], |r| {
                    Ok((
                        r.get::<_, String>(0).unwrap_or_else(|_| "assistant".into()),
                        r.get::<_, String>(1).unwrap_or_default(),
                        r.get::<_, i64>(2).unwrap_or(0),
                    ))
                })
                .ok()?
                .flatten()
                .collect();

            let mut messages = Vec::new();
            for (role_s, content_json, ts_raw) in rows {
                let role = if role_s == "user" {
                    Role::User
                } else {
                    Role::Assistant
                };
                let ts = (ts_raw > 0).then(|| Self::secs_or_millis(ts_raw));
                // Unparseable content degrades to no blocks — never fatal.
                let Ok(blocks) = serde_json::from_str::<Value>(&content_json) else {
                    continue;
                };
                for b in blocks.as_array().map(|a| a.as_slice()).unwrap_or_default() {
                    match b.get("type").and_then(Value::as_str).unwrap_or("") {
                        "text" => {
                            let t = b.get("text").and_then(Value::as_str).unwrap_or("");
                            if !t.is_empty() {
                                messages.push(AgentMessage {
                                    role,
                                    kind: MessageKind::Text,
                                    content: t.to_string(),
                                    ts,
                                    tool_name: None,
                                });
                            }
                        }
                        "thinking" => {
                            let t = b.get("thinking").and_then(Value::as_str).unwrap_or("");
                            if !t.is_empty() {
                                messages.push(AgentMessage {
                                    role: Role::Assistant,
                                    kind: MessageKind::Thinking,
                                    content: t.to_string(),
                                    ts,
                                    tool_name: None,
                                });
                            }
                        }
                        "toolRequest" => {
                            let call = b.get("toolCall").and_then(|c| c.get("value"));
                            messages.push(AgentMessage {
                                role: Role::Assistant,
                                kind: MessageKind::ToolUse,
                                content: super::claude_code::truncate(
                                    &call
                                        .and_then(|c| c.get("arguments"))
                                        .map(Value::to_string)
                                        .unwrap_or_default(),
                                    2000,
                                ),
                                ts,
                                tool_name: call
                                    .and_then(|c| c.get("name"))
                                    .and_then(Value::as_str)
                                    .map(String::from),
                            });
                        }
                        "toolResponse" => {
                            let text = b
                                .get("toolResult")
                                .and_then(|r| r.get("value"))
                                .and_then(|v| v.get("content"))
                                .and_then(Value::as_array)
                                .map(|parts| {
                                    parts
                                        .iter()
                                        .filter_map(|p| p.get("text").and_then(Value::as_str))
                                        .collect::<Vec<_>>()
                                        .join("\n")
                                })
                                .unwrap_or_default();
                            if !text.is_empty() {
                                messages.push(AgentMessage {
                                    role: Role::Tool,
                                    kind: MessageKind::ToolResult,
                                    content: super::claude_code::truncate(&text, 2000),
                                    ts,
                                    tool_name: None,
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }
            Some(AgentSessionDetail { session, messages })
        })
    }
}
