//! Cursor adapter — reads `…/Cursor/User/globalStorage/state.vscdb` (SQLite).
//!
//! Modern schema: table `cursorDiskKV` with `composerData:<id>` session records
//! (name, createdAt, modelConfig.modelName, `fullConversationHeadersOnly[]`
//! ordered `{bubbleId,type}` where 1=user/2=assistant) and `bubbleId:<cid>:<bid>`
//! message bodies (`text`, `thinking.text`). Token/cost data is largely
//! server-side (mostly absent locally) — we mark it 0. Verified on-disk. Read via
//! a read-only snapshot.

use std::collections::HashMap;
use std::path::PathBuf;

use rusqlite::Connection;
use serde_json::Value;

use super::{
    home, with_sqlite_snapshot, AgentMessage, AgentReader, AgentSession, AgentSessionDetail,
    AgentTool, MessageKind, Role,
};

const MAX_LIST: usize = 400;

/// Reads Cursor's global-storage SQLite chat store.
pub struct CursorReader {
    db: PathBuf,
}

impl CursorReader {
    /// Fixture seam: read an explicit `state.vscdb`. See
    /// `tests/agents_bench.rs`.
    pub fn with_db(db: PathBuf) -> Self {
        Self { db }
    }

    /// Platform state.vscdb path (macOS / Linux / Windows).
    pub fn new() -> Self {
        let user_dir = if cfg!(target_os = "macos") {
            home().join("Library/Application Support/Cursor/User")
        } else if cfg!(target_os = "windows") {
            std::env::var_os("APPDATA")
                .map(PathBuf::from)
                .unwrap_or_else(|| home().join("AppData/Roaming"))
                .join("Cursor/User")
        } else {
            home().join(".config/Cursor/User")
        };
        Self {
            db: user_dir.join("globalStorage/state.vscdb"),
        }
    }

    fn session_from_composer(v: &Value, source: &str) -> Option<AgentSession> {
        let cid = v.get("composerId").and_then(Value::as_str)?;
        let title = v
            .get("name")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .or_else(|| {
                v.get("subtitle")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
            })
            .map(String::from);
        let model = v
            .get("modelConfig")
            .and_then(|m| m.get("modelName"))
            .and_then(Value::as_str)
            .map(String::from);
        let project = v
            .get("workspaceIdentifier")
            .and_then(|w| w.get("uri"))
            .and_then(|u| u.get("fsPath"))
            .and_then(Value::as_str)
            .map(String::from);
        let created = v.get("createdAt").and_then(Value::as_i64).unwrap_or(0);
        let updated = v
            .get("lastUpdatedAt")
            .and_then(Value::as_i64)
            .filter(|t| *t > 0)
            .unwrap_or(created);
        let msg_count = v
            .get("fullConversationHeadersOnly")
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0) as u32;

        Some(AgentSession {
            id: AgentSession::make_id(AgentTool::Cursor, cid),
            tool: AgentTool::Cursor,
            title,
            project,
            git_branch: None,
            model,
            started_ts: created,
            updated_ts: updated,
            message_count: msg_count,
            tool_call_count: 0, // counted in detail; tokens/tools are weak locally
            input_tokens: 0,
            output_tokens: 0,
            cache_tokens: 0,
            source_path: source.to_string(),
        })
    }
}

impl Default for CursorReader {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentReader for CursorReader {
    fn tool(&self) -> AgentTool {
        AgentTool::Cursor
    }
    fn is_present(&self) -> bool {
        self.db.is_file()
    }
    fn list_sessions(&self) -> Vec<AgentSession> {
        let src = self.db.to_string_lossy().to_string();
        with_sqlite_snapshot(&self.db, |conn: &Connection| {
            // `value` is TEXT (JSON) for composerData/bubbleId rows — read as String
            // (reading as bytes fails on the driver for these).
            let mut stmt = conn
                .prepare("SELECT value FROM cursorDiskKV WHERE key LIKE 'composerData:%'")
                .ok()?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0)).ok()?;
            let mut out = Vec::new();
            for blob in rows.flatten() {
                if let Ok(v) = serde_json::from_str::<Value>(&blob) {
                    if let Some(s) = Self::session_from_composer(&v, &src) {
                        if s.message_count > 0 {
                            out.push(s);
                        }
                    }
                }
            }
            out.sort_by(|a, b| b.updated_ts.cmp(&a.updated_ts));
            out.truncate(MAX_LIST);
            Some(out)
        })
        .unwrap_or_default()
    }
    fn retention(&self) -> super::retention::RetentionPolicy {
        super::retention::RetentionPolicy::churn(
            "Rotates old chats to keep its local database bounded.",
        )
    }
    fn source_fingerprint(&self) -> Option<u64> {
        Some(super::hash_files(super::db_paths(&self.db).into_iter()))
    }
    fn session_detail(&self, raw_id: &str) -> Option<AgentSessionDetail> {
        let src = self.db.to_string_lossy().to_string();
        with_sqlite_snapshot(&self.db, |conn: &Connection| {
            // Session record.
            let blob: String = conn
                .query_row(
                    "SELECT value FROM cursorDiskKV WHERE key = ?1",
                    [format!("composerData:{raw_id}")],
                    |r| r.get(0),
                )
                .ok()?;
            let composer: Value = serde_json::from_str(&blob).ok()?;
            let session = Self::session_from_composer(&composer, &src)?;

            // Fetch all bubbles for this composer into a map, then order by headers.
            let mut bubbles: HashMap<String, Value> = HashMap::new();
            {
                let mut bstmt = conn
                    .prepare("SELECT key, value FROM cursorDiskKV WHERE key LIKE ?1")
                    .ok()?;
                let rows = bstmt
                    .query_map([format!("bubbleId:{raw_id}:%")], |r| {
                        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                    })
                    .ok()?;
                for (key, blob) in rows.flatten() {
                    if let Some(bid) = key.rsplit(':').next() {
                        if let Ok(v) = serde_json::from_str::<Value>(&blob) {
                            bubbles.insert(bid.to_string(), v);
                        }
                    }
                }
            }

            let mut messages = Vec::new();
            let mut tool_count = 0u32;
            if let Some(headers) = composer
                .get("fullConversationHeadersOnly")
                .and_then(Value::as_array)
            {
                for h in headers {
                    let Some(bid) = h.get("bubbleId").and_then(Value::as_str) else {
                        continue;
                    };
                    let btype = h.get("type").and_then(Value::as_i64).unwrap_or(1);
                    let role = if btype == 2 {
                        Role::Assistant
                    } else {
                        Role::User
                    };
                    let Some(b) = bubbles.get(bid) else { continue };
                    let ts = b
                        .get("timingInfo")
                        .and_then(|t| t.get("clientEndTime"))
                        .and_then(Value::as_i64);
                    // Thinking (assistant) first, then the visible text.
                    if let Some(think) = b
                        .get("thinking")
                        .and_then(|t| t.get("text"))
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                    {
                        messages.push(AgentMessage {
                            role,
                            kind: MessageKind::Thinking,
                            content: think.to_string(),
                            ts,
                            tool_name: None,
                        });
                    }
                    let text = b
                        .get("text")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .or_else(|| lexical_text(b.get("richText")));
                    if let Some(t) = text {
                        messages.push(AgentMessage {
                            role,
                            kind: MessageKind::Text,
                            content: t,
                            ts,
                            tool_name: None,
                        });
                    }
                    if let Some(tool) = b.get("toolFormerData") {
                        if !tool.is_null() {
                            tool_count += 1;
                            messages.push(AgentMessage {
                                role: Role::Tool,
                                kind: MessageKind::ToolUse,
                                content: super::claude_code::truncate(&tool.to_string(), 1500),
                                ts,
                                tool_name: tool
                                    .get("name")
                                    .and_then(Value::as_str)
                                    .map(String::from),
                            });
                        }
                    }
                }
            }
            let mut session = session;
            session.tool_call_count = tool_count;
            Some(AgentSessionDetail { session, messages })
        })
    }
}

/// Extract plain text from Cursor's Lexical `richText` JSON (fallback when the
/// bubble's `.text` is empty).
fn lexical_text(rich: Option<&Value>) -> Option<String> {
    fn walk(node: &Value, out: &mut String) {
        if let Some(t) = node.get("text").and_then(Value::as_str) {
            out.push_str(t);
        }
        if let Some(children) = node.get("children").and_then(Value::as_array) {
            for c in children {
                walk(c, out);
            }
        }
    }
    let root = rich?.get("root")?;
    let mut out = String::new();
    walk(root, &mut out);
    Some(out).filter(|s| !s.is_empty())
}
