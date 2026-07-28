//! Cline adapter — reads VS Code globalStorage
//! `saoudrizwan.claude-dev/tasks/<taskId>/` + `state/taskHistory.json`.
//!
//! Format verified against the shipped Cline v3.89.2 tag (G2 round 6;
//! `apps/vscode/src/core/storage/disk.ts`, `shared/HistoryItem.ts`,
//! `shared/ExtensionMessage.ts`):
//!
//! * `tasks/<taskId>/api_conversation_history.json` — the richest
//!   transcript: an array of Anthropic-style `{role, content}` messages
//!   (content is a string or blocks: `text` / `thinking` / `tool_use` /
//!   `tool_result`), with Cline extensions `ts` (millis), `modelInfo`
//!   (`modelId`), `metrics`. Older tasks are plain MessageParams. Most
//!   historical tool calls are XML-ish text INSIDE text blocks (Cline's
//!   prompt format) — those stay text, honestly; native `tool_use` blocks
//!   appear for native-tool-calling models.
//! * `tasks/<taskId>/ui_messages.json` — the UI stream. Token usage lives
//!   here: `say: "api_req_started"` messages whose `text` is JSON
//!   `{tokensIn, tokensOut, cacheWrites, cacheReads, cost}` (Anthropic
//!   convention: `tokensIn` already excludes cache). The first
//!   `say: "task"` message's text is the task title.
//! * `state/taskHistory.json` — per-task aggregates `{id, ts, task,
//!   tokensIn, tokensOut, cacheWrites, cacheReads, totalCost,
//!   cwdOnTaskInitialization, modelId}`. This file superseded the old
//!   VS Code `state.vscdb` globalState key; ancient installs may have only
//!   the db copy, which this adapter does not chase.
//!
//! `<taskId>` is a millisecond-epoch string — the task's start time. A task
//! whose transcript is corrupt still lists from its `taskHistory` entry /
//! `ui_messages` (non-fatal degradation). Tolerant: bad files are skipped.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::{
    home, AgentMessage, AgentReader, AgentSession, AgentSessionDetail, AgentTool, MessageKind, Role,
};

/// One row from `state/taskHistory.json` (the fields this adapter uses).
#[derive(Default, Clone)]
struct HistoryRow {
    ts: i64,
    task: Option<String>,
    tokens_in: u64,
    tokens_out: u64,
    cache: u64,
    cwd: Option<String>,
    model: Option<String>,
}

/// Reads Cline's task stores from every VS Code flavor's globalStorage.
pub struct ClineReader {
    /// `…/globalStorage/saoudrizwan.claude-dev` roots (Code, Insiders, VSCodium).
    roots: Vec<PathBuf>,
}

impl ClineReader {
    /// Fixture seam: read explicit extension-storage roots. See
    /// `tests/agents_bench.rs`.
    pub fn with_roots(roots: Vec<PathBuf>) -> Self {
        Self { roots }
    }

    /// Platform globalStorage paths for Code / Insiders / VSCodium.
    pub fn new() -> Self {
        let flavors = ["Code", "Code - Insiders", "VSCodium"];
        let bases: Vec<PathBuf> = if cfg!(target_os = "macos") {
            let app = home().join("Library/Application Support");
            flavors.iter().map(|f| app.join(f)).collect()
        } else if cfg!(target_os = "windows") {
            let app = std::env::var_os("APPDATA")
                .map(PathBuf::from)
                .unwrap_or_else(|| home().join("AppData/Roaming"));
            flavors.iter().map(|f| app.join(f)).collect()
        } else {
            let cfg = home().join(".config");
            flavors.iter().map(|f| cfg.join(f)).collect()
        };
        let roots = bases
            .into_iter()
            .map(|b| b.join("User/globalStorage/saoudrizwan.claude-dev"))
            .filter(|p| p.is_dir())
            .collect();
        Self { roots }
    }

    /// Load `state/taskHistory.json` rows, keyed by task id.
    fn history(root: &Path) -> HashMap<String, HistoryRow> {
        let mut out = HashMap::new();
        let Ok(text) = fs::read_to_string(root.join("state/taskHistory.json")) else {
            return out;
        };
        let Ok(v) = serde_json::from_str::<Value>(&text) else {
            return out;
        };
        for item in v.as_array().map(|a| a.as_slice()).unwrap_or_default() {
            let Some(id) = item.get("id").and_then(Value::as_str) else {
                continue;
            };
            out.insert(
                id.to_string(),
                HistoryRow {
                    ts: item.get("ts").and_then(Value::as_i64).unwrap_or(0),
                    task: item
                        .get("task")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                        .map(String::from),
                    tokens_in: item.get("tokensIn").and_then(Value::as_u64).unwrap_or(0),
                    tokens_out: item.get("tokensOut").and_then(Value::as_u64).unwrap_or(0),
                    cache: item.get("cacheWrites").and_then(Value::as_u64).unwrap_or(0)
                        + item.get("cacheReads").and_then(Value::as_u64).unwrap_or(0),
                    cwd: item
                        .get("cwdOnTaskInitialization")
                        .and_then(Value::as_str)
                        .map(String::from),
                    model: item
                        .get("modelId")
                        .and_then(Value::as_str)
                        .map(String::from),
                },
            );
        }
        out
    }

    /// Fallbacks from `ui_messages.json`: title (first `say:"task"`), token
    /// sums (`api_req_started` JSON payloads), and last activity ts.
    fn ui_fallback(task_dir: &Path) -> (Option<String>, u64, u64, u64, i64) {
        let (mut title, mut inp, mut outp, mut cache, mut last_ts) = (None, 0u64, 0u64, 0u64, 0i64);
        let Ok(text) = fs::read_to_string(task_dir.join("ui_messages.json")) else {
            return (title, inp, outp, cache, last_ts);
        };
        let Ok(v) = serde_json::from_str::<Value>(&text) else {
            return (title, inp, outp, cache, last_ts);
        };
        for m in v.as_array().map(|a| a.as_slice()).unwrap_or_default() {
            if let Some(ts) = m.get("ts").and_then(Value::as_i64) {
                last_ts = last_ts.max(ts);
            }
            let say = m.get("say").and_then(Value::as_str).unwrap_or("");
            let text = m.get("text").and_then(Value::as_str).unwrap_or("");
            if say == "task" && title.is_none() && !text.is_empty() {
                title = Some(text.to_string());
            }
            if say == "api_req_started" {
                // `text` is a JSON-stringified payload; parse defensively.
                if let Ok(info) = serde_json::from_str::<Value>(text) {
                    inp += info.get("tokensIn").and_then(Value::as_u64).unwrap_or(0);
                    outp += info.get("tokensOut").and_then(Value::as_u64).unwrap_or(0);
                    cache += info.get("cacheWrites").and_then(Value::as_u64).unwrap_or(0)
                        + info.get("cacheReads").and_then(Value::as_u64).unwrap_or(0);
                }
            }
        }
        (title, inp, outp, cache, last_ts)
    }

    /// Parse the transcript. Returns `(messages, msg_count, tool_count,
    /// last_model, last_ts)` — empty on a corrupt file (non-fatal).
    fn transcript(task_dir: &Path, with_messages: bool) -> (Vec<AgentMessage>, u32, u32, Option<String>, i64) {
        let mut messages = Vec::new();
        let (mut msg_count, mut tool_count) = (0u32, 0u32);
        let mut model = None;
        let mut last_ts = 0i64;
        let Ok(text) = fs::read_to_string(task_dir.join("api_conversation_history.json")) else {
            return (messages, msg_count, tool_count, model, last_ts);
        };
        let Ok(v) = serde_json::from_str::<Value>(&text) else {
            return (messages, msg_count, tool_count, model, last_ts);
        };
        for m in v.as_array().map(|a| a.as_slice()).unwrap_or_default() {
            let role_s = m.get("role").and_then(Value::as_str).unwrap_or("");
            let role = match role_s {
                "user" => Role::User,
                "assistant" => Role::Assistant,
                _ => continue,
            };
            msg_count += 1;
            let ts = m.get("ts").and_then(Value::as_i64).filter(|t| *t > 0);
            if let Some(t) = ts {
                last_ts = last_ts.max(t);
            }
            if let Some(mi) = m
                .get("modelInfo")
                .and_then(|mi| mi.get("modelId"))
                .and_then(Value::as_str)
            {
                model = Some(mi.to_string()); // last wins
            }
            match m.get("content") {
                Some(Value::String(s)) => {
                    if with_messages && !s.is_empty() {
                        messages.push(AgentMessage {
                            role,
                            kind: MessageKind::Text,
                            content: s.clone(),
                            ts,
                            tool_name: None,
                        });
                    }
                }
                Some(Value::Array(blocks)) => {
                    for b in blocks {
                        let btype = b.get("type").and_then(Value::as_str).unwrap_or("");
                        match btype {
                            "text" => {
                                let t = b.get("text").and_then(Value::as_str).unwrap_or("");
                                if with_messages && !t.is_empty() {
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
                                if with_messages && !t.is_empty() {
                                    messages.push(AgentMessage {
                                        role: Role::Assistant,
                                        kind: MessageKind::Thinking,
                                        content: t.to_string(),
                                        ts,
                                        tool_name: None,
                                    });
                                }
                            }
                            "tool_use" => {
                                tool_count += 1;
                                if with_messages {
                                    messages.push(AgentMessage {
                                        role: Role::Assistant,
                                        kind: MessageKind::ToolUse,
                                        content: super::claude_code::truncate(
                                            &b.get("input").map(Value::to_string).unwrap_or_default(),
                                            2000,
                                        ),
                                        ts,
                                        tool_name: b
                                            .get("name")
                                            .and_then(Value::as_str)
                                            .map(String::from),
                                    });
                                }
                            }
                            "tool_result" => {
                                if with_messages {
                                    let content = match b.get("content") {
                                        Some(Value::String(s)) => s.clone(),
                                        Some(Value::Array(parts)) => parts
                                            .iter()
                                            .filter_map(|p| {
                                                p.get("text").and_then(Value::as_str)
                                            })
                                            .collect::<Vec<_>>()
                                            .join("\n"),
                                        _ => String::new(),
                                    };
                                    if !content.is_empty() {
                                        messages.push(AgentMessage {
                                            role: Role::Tool,
                                            kind: MessageKind::ToolResult,
                                            content: super::claude_code::truncate(&content, 2000),
                                            ts,
                                            tool_name: None,
                                        });
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        (messages, msg_count, tool_count, model, last_ts)
    }

    /// Build one task's session (summary or full detail).
    fn build(
        root: &Path,
        task_id: &str,
        row: Option<&HistoryRow>,
        with_messages: bool,
    ) -> Option<AgentSessionDetail> {
        let task_dir = root.join("tasks").join(task_id);
        let (messages, msg_count, tool_count, tmodel, tlast) =
            Self::transcript(&task_dir, with_messages);
        let (ui_title, ui_in, ui_out, ui_cache, ui_last) = Self::ui_fallback(&task_dir);
        // A task with a corrupt transcript still lists via its history row /
        // ui stream; a task with neither transcript nor metadata is nothing.
        if msg_count == 0 && row.is_none() && ui_title.is_none() {
            return None;
        }
        // The task id IS the start time (millisecond epoch).
        let started_ts = task_id.parse::<i64>().unwrap_or(0);
        let row_default = HistoryRow::default();
        let row = row.unwrap_or(&row_default);
        let (inp, outp, cache) = if row.tokens_in + row.tokens_out + row.cache > 0 {
            (row.tokens_in, row.tokens_out, row.cache)
        } else {
            (ui_in, ui_out, ui_cache)
        };
        let updated_ts = row.ts.max(tlast).max(ui_last).max(started_ts);
        let title = row
            .task
            .clone()
            .or(ui_title)
            .map(|t| super::claude_code::truncate(&t, 80));
        let session = AgentSession {
            id: AgentSession::make_id(AgentTool::Cline, task_id),
            tool: AgentTool::Cline,
            title,
            project: row.cwd.clone(),
            git_branch: None,
            model: row.model.clone().or(tmodel),
            started_ts,
            updated_ts,
            message_count: msg_count,
            tool_call_count: tool_count,
            input_tokens: inp,
            output_tokens: outp,
            cache_tokens: cache,
            source_path: task_dir.to_string_lossy().to_string(),
        };
        Some(AgentSessionDetail { session, messages })
    }

    /// All task dirs under a root, with that root's history rows.
    fn tasks(root: &Path) -> Vec<String> {
        let mut out = Vec::new();
        let Ok(dirs) = fs::read_dir(root.join("tasks")) else {
            return out;
        };
        for d in dirs.flatten() {
            if d.path().is_dir() {
                out.push(d.file_name().to_string_lossy().to_string());
            }
        }
        out
    }
}

impl Default for ClineReader {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentReader for ClineReader {
    fn tool(&self) -> AgentTool {
        AgentTool::Cline
    }
    fn is_present(&self) -> bool {
        self.roots.iter().any(|r| r.join("tasks").is_dir())
    }
    fn list_sessions(&self) -> Vec<AgentSession> {
        let mut out = Vec::new();
        for root in &self.roots {
            let history = Self::history(root);
            for task_id in Self::tasks(root) {
                if let Some(d) = Self::build(root, &task_id, history.get(&task_id), false) {
                    out.push(d.session);
                }
            }
        }
        out
    }
    fn retention(&self) -> super::retention::RetentionPolicy {
        super::retention::RetentionPolicy::keeps_all(
            "Tasks persist under VS Code globalStorage until deleted in Cline's UI.",
        )
    }
    fn source_fingerprint(&self) -> Option<u64> {
        let mut files = Vec::new();
        for root in &self.roots {
            files.push(root.join("state/taskHistory.json"));
            for t in Self::tasks(root) {
                files.push(root.join("tasks").join(&t).join("api_conversation_history.json"));
                files.push(root.join("tasks").join(&t).join("ui_messages.json"));
            }
        }
        Some(super::hash_files(files.into_iter()))
    }
    fn session_detail(&self, raw_id: &str) -> Option<AgentSessionDetail> {
        for root in &self.roots {
            if root.join("tasks").join(raw_id).is_dir() {
                let history = Self::history(root);
                return Self::build(root, raw_id, history.get(raw_id), true);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_with_corrupt_transcript_lists_from_history() {
        let dir = std::env::temp_dir().join(format!("saffev-cline-{}", uuid::Uuid::new_v4()));
        let root = dir.join("saoudrizwan.claude-dev");
        std::fs::create_dir_all(root.join("state")).unwrap();
        std::fs::create_dir_all(root.join("tasks/1753600100000")).unwrap();
        std::fs::write(
            root.join("state/taskHistory.json"),
            r#"[{"id":"1753600100000","ts":1753600200000,"task":"broken transcript task","tokensIn":500,"tokensOut":80,"cacheWrites":100,"cacheReads":50,"totalCost":0.01,"cwdOnTaskInitialization":"/home/dev/p","modelId":"claude-sonnet-4-20250514"}]"#,
        )
        .unwrap();
        std::fs::write(
            root.join("tasks/1753600100000/api_conversation_history.json"),
            "this is not json [{",
        )
        .unwrap();
        let reader = ClineReader::with_roots(vec![root]);
        let sessions = reader.list_sessions();
        assert_eq!(sessions.len(), 1);
        let s = &sessions[0];
        assert_eq!(s.title.as_deref(), Some("broken transcript task"));
        assert_eq!(s.input_tokens, 500);
        assert_eq!(s.cache_tokens, 150);
        assert_eq!(s.project.as_deref(), Some("/home/dev/p"));
        assert_eq!(s.started_ts, 1753600100000);
        assert_eq!(s.message_count, 0, "corrupt transcript honestly has no turns");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_task_history_falls_back_to_ui_messages() {
        let dir = std::env::temp_dir().join(format!("saffev-cline-{}", uuid::Uuid::new_v4()));
        let root = dir.join("saoudrizwan.claude-dev");
        std::fs::create_dir_all(root.join("tasks/1753600000000")).unwrap();
        std::fs::write(
            root.join("tasks/1753600000000/api_conversation_history.json"),
            r#"[{"role":"user","content":[{"type":"text","text":"add retry"}]},{"role":"assistant","content":[{"type":"text","text":"done"}],"ts":1753600012345}]"#,
        )
        .unwrap();
        std::fs::write(
            root.join("tasks/1753600000000/ui_messages.json"),
            r#"[{"ts":1753600000000,"type":"say","say":"task","text":"add retry"},{"ts":1753600001000,"type":"say","say":"api_req_started","text":"{\"tokensIn\":12480,\"tokensOut\":312,\"cacheWrites\":11200,\"cacheReads\":0,\"cost\":0.04}"}]"#,
        )
        .unwrap();
        let reader = ClineReader::with_roots(vec![root]);
        let sessions = reader.list_sessions();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].title.as_deref(), Some("add retry"));
        assert_eq!(sessions[0].input_tokens, 12480);
        assert_eq!(sessions[0].cache_tokens, 11200);
        std::fs::remove_dir_all(&dir).ok();
    }
}
