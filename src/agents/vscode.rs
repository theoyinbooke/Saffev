//! VS Code (GitHub Copilot Chat) adapter.
//!
//! Copilot Chat persists each session as an append-log at
//! `…/Code/User/workspaceStorage/<hash>/chatSessions/<uuid>.jsonl`, one
//! `{kind, v}` object per line: `kind:0` is the session header (sessionId,
//! creationDate), and later lines carry **full request records** — each a
//! complete turn with `message` (the user prompt), `response[]` (assistant
//! markdown + tool invocations), `modelId`, and `timestamp`.
//!
//! Rather than replay the log positionally (brittle), we **walk it collecting
//! request records** by shape (`requestId` + `message` + `response`), which
//! tolerates format drift. Verified against real sessions on-disk. Tokens are not
//! stored locally (like Cursor), so they are 0. Empty draft sessions (no
//! requests) are skipped.

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::{
    home, AgentMessage, AgentReader, AgentSession, AgentSessionDetail, AgentTool, MessageKind, Role,
};

const MAX_LIST: usize = 400;

/// Reads VS Code / Copilot Chat session logs across install flavors.
pub struct VsCodeReader {
    /// `…/User/workspaceStorage` dirs for Code / Insiders / VSCodium.
    roots: Vec<PathBuf>,
}

impl VsCodeReader {
    /// Fixture seam: read explicit `workspaceStorage` roots. See
    /// `tests/agents_bench.rs`.
    pub fn with_roots(roots: Vec<PathBuf>) -> Self {
        Self { roots }
    }

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
            .map(|b| b.join("User/workspaceStorage"))
            .filter(|p| p.is_dir())
            .collect();
        Self { roots }
    }

    /// All chat-session files, newest first, tagged with their workspace dir so we
    /// can resolve the project. Returns `(file, workspace_dir)`.
    fn session_files(&self) -> Vec<(std::time::SystemTime, PathBuf, PathBuf)> {
        let mut out = Vec::new();
        for root in &self.roots {
            let Ok(hashes) = fs::read_dir(root) else {
                continue;
            };
            for h in hashes.flatten() {
                let ws = h.path();
                let dir = ws.join("chatSessions");
                let Ok(files) = fs::read_dir(&dir) else {
                    continue;
                };
                for f in files.flatten() {
                    let p = f.path();
                    if p.extension().and_then(|e| e.to_str()) == Some("jsonl") {
                        let mtime = f
                            .metadata()
                            .and_then(|m| m.modified())
                            .unwrap_or(std::time::UNIX_EPOCH);
                        out.push((mtime, p, ws.clone()));
                    }
                }
            }
        }
        out.sort_by(|a, b| b.0.cmp(&a.0));
        out
    }

    /// Resolve a workspace dir → project path via its `workspace.json` `folder` URI.
    fn project_for(ws: &Path) -> Option<String> {
        let text = fs::read_to_string(ws.join("workspace.json")).ok()?;
        let v: Value = serde_json::from_str(&text).ok()?;
        let uri = v.get("folder").and_then(Value::as_str)?;
        Some(uri_to_path(uri))
    }

    fn parse(
        path: &Path,
        project: Option<String>,
        with_messages: bool,
    ) -> Option<AgentSessionDetail> {
        let file = fs::File::open(path).ok()?;
        let reader = BufReader::new(file);

        let mut session_id: Option<String> = None;
        let mut created = 0i64;
        let mut model: Option<String> = None;
        let mut title: Option<String> = None;
        let mut first_ts = 0i64;
        let mut last_ts = 0i64;
        let (mut msg_count, mut tool_count) = (0u32, 0u32);
        let mut messages: Vec<AgentMessage> = Vec::new();

        for line in reader.lines() {
            let Ok(line) = line else { continue };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Ok(entry) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            let kind = entry.get("kind").and_then(Value::as_i64).unwrap_or(-1);
            let v = entry.get("v");

            if kind == 0 {
                if let Some(base) = v {
                    session_id = base
                        .get("sessionId")
                        .and_then(Value::as_str)
                        .map(String::from);
                    created = base
                        .get("creationDate")
                        .and_then(Value::as_i64)
                        .unwrap_or(0);
                    if let Some(t) = base
                        .get("customTitle")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                    {
                        title = Some(t.to_string());
                    }
                }
            }

            // Collect request records anywhere in this line's value (kind:2 lines
            // are lists of them; the kind:0 base may also carry `requests`).
            let mut records = Vec::new();
            if let Some(v) = v {
                collect_records(v, &mut records);
            }
            for rec in records {
                if let Some(ts) = rec.get("timestamp").and_then(Value::as_i64) {
                    if first_ts == 0 {
                        first_ts = ts;
                    }
                    last_ts = last_ts.max(ts);
                }
                if let Some(m) = rec.get("modelId").and_then(Value::as_str) {
                    model = Some(m.to_string());
                }
                // User turn.
                let user = message_text(rec.get("message"));
                if let Some(u) = user.filter(|s| !s.is_empty()) {
                    msg_count += 1;
                    if title.is_none() {
                        title = Some(super::claude_code::truncate(&u, 80));
                    }
                    if with_messages {
                        messages.push(AgentMessage {
                            role: Role::User,
                            kind: MessageKind::Text,
                            content: u,
                            ts: rec.get("timestamp").and_then(Value::as_i64),
                            tool_name: None,
                        });
                    }
                }
                // Assistant turn: walk response parts in order, splitting on tools.
                if let Some(parts) = rec.get("response").and_then(Value::as_array) {
                    let mut acc = String::new();
                    let ts = rec.get("timestamp").and_then(Value::as_i64);
                    let mut flushed_any = false;
                    for part in parts {
                        if let Some((name, tool_text)) = tool_part(part) {
                            tool_count += 1;
                            if with_messages {
                                flush_assistant(&mut acc, ts, &mut messages, &mut flushed_any);
                                messages.push(AgentMessage {
                                    role: Role::Tool,
                                    kind: MessageKind::ToolUse,
                                    content: super::claude_code::truncate(&tool_text, 400),
                                    ts,
                                    tool_name: name,
                                });
                            }
                        } else if let Some(t) = part_text(part) {
                            acc.push_str(&t);
                        }
                    }
                    if with_messages {
                        flush_assistant(&mut acc, ts, &mut messages, &mut flushed_any);
                    }
                    if flushed_any || !parts.is_empty() {
                        msg_count += 1;
                    }
                }
            }
        }

        let id = session_id.unwrap_or_else(|| {
            path.file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default()
        });
        if first_ts == 0 {
            first_ts = created;
        }
        let session = AgentSession {
            id: AgentSession::make_id(AgentTool::VsCode, &id),
            tool: AgentTool::VsCode,
            title,
            project,
            git_branch: None,
            model,
            started_ts: if created > 0 { created } else { first_ts },
            updated_ts: last_ts.max(first_ts).max(created),
            message_count: msg_count,
            tool_call_count: tool_count,
            input_tokens: 0,
            output_tokens: 0,
            cache_tokens: 0,
            source_path: path.to_string_lossy().to_string(),
        };
        Some(AgentSessionDetail { session, messages })
    }
}

impl Default for VsCodeReader {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentReader for VsCodeReader {
    fn tool(&self) -> AgentTool {
        AgentTool::VsCode
    }
    fn is_present(&self) -> bool {
        !self.roots.is_empty()
    }
    fn list_sessions(&self) -> Vec<AgentSession> {
        let mut proj_cache: HashMap<PathBuf, Option<String>> = HashMap::new();
        self.session_files()
            .into_iter()
            .take(MAX_LIST)
            .filter_map(|(_, path, ws)| {
                let project = proj_cache
                    .entry(ws.clone())
                    .or_insert_with(|| Self::project_for(&ws))
                    .clone();
                Self::parse(&path, project, false)
            })
            .map(|d| d.session)
            .filter(|s| s.message_count > 0)
            .collect()
    }
    fn retention(&self) -> super::retention::RetentionPolicy {
        super::retention::RetentionPolicy::churn(
            "Chats can be removed when VS Code clears workspace storage.",
        )
    }
    fn source_fingerprint(&self) -> Option<u64> {
        Some(super::hash_files(
            self.session_files().into_iter().map(|(_, p, _)| p),
        ))
    }
    fn session_detail(&self, raw_id: &str) -> Option<AgentSessionDetail> {
        let (_, path, ws) = self.session_files().into_iter().find(|(_, p, _)| {
            p.file_stem()
                .map(|s| s.to_string_lossy() == raw_id)
                .unwrap_or(false)
        })?;
        let project = Self::project_for(&ws);
        Self::parse(&path, project, true)
    }
}

/// Recursively collect dicts that look like a chat request record (a complete
/// turn: has `requestId`, `message`, and `response`). Does not recurse into a
/// matched record.
fn collect_records<'a>(v: &'a Value, out: &mut Vec<&'a Value>) {
    match v {
        Value::Object(map) => {
            if map.contains_key("requestId")
                && map.contains_key("message")
                && map.contains_key("response")
            {
                out.push(v);
                return;
            }
            for child in map.values() {
                collect_records(child, out);
            }
        }
        Value::Array(arr) => {
            for child in arr {
                collect_records(child, out);
            }
        }
        _ => {}
    }
}

/// Extract the user prompt text from a request's `message` (`.text` or joined
/// `.parts[].text`).
fn message_text(msg: Option<&Value>) -> Option<String> {
    let msg = msg?;
    if let Some(t) = msg.get("text").and_then(Value::as_str) {
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    let parts = msg.get("parts").and_then(Value::as_array)?;
    let joined: String = parts
        .iter()
        .filter_map(|p| p.get("text").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("");
    (!joined.is_empty()).then_some(joined)
}

/// Text of a response part (markdown lives in `.value` as a string or
/// `{value: "..."}`); `None` for non-text parts.
fn part_text(part: &Value) -> Option<String> {
    match part.get("value") {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        Some(Value::Object(o)) => o
            .get("value")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(String::from),
        _ => None,
    }
}

/// If `part` is a tool invocation, return `(tool_name, display_text)`.
fn tool_part(part: &Value) -> Option<(Option<String>, String)> {
    let is_tool = part.get("toolCallId").is_some()
        || part.get("toolId").is_some()
        || part
            .get("kind")
            .and_then(Value::as_str)
            .map(|k| k.contains("tool") || k.contains("Tool"))
            .unwrap_or(false);
    if !is_tool {
        return None;
    }
    let name = part
        .get("toolId")
        .or_else(|| part.get("toolCallId"))
        .and_then(Value::as_str)
        .map(String::from);
    let text = part
        .get("invocationMessage")
        .or_else(|| part.get("pastTenseMessage"))
        .and_then(|m| m.get("value").or(Some(m)))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    Some((name, text))
}

/// Flush accumulated assistant markdown as one message.
fn flush_assistant(
    acc: &mut String,
    ts: Option<i64>,
    out: &mut Vec<AgentMessage>,
    flushed: &mut bool,
) {
    let t = acc.trim();
    if !t.is_empty() {
        out.push(AgentMessage {
            role: Role::Assistant,
            kind: MessageKind::Text,
            content: t.to_string(),
            ts,
            tool_name: None,
        });
        *flushed = true;
    }
    acc.clear();
}

/// `file:///Users/me/proj` → `/Users/me/proj` (best-effort percent-decode).
fn uri_to_path(uri: &str) -> String {
    let raw = uri.strip_prefix("file://").unwrap_or(uri);
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&raw[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_decode() {
        assert_eq!(
            uri_to_path("file:///Users/me/my%20proj"),
            "/Users/me/my proj"
        );
        assert_eq!(uri_to_path("/plain/path"), "/plain/path");
    }

    #[test]
    fn parses_a_copilot_session() {
        let dir = std::env::temp_dir().join(format!("saffev-vsc-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sess.jsonl");
        let l0 = r#"{"kind":0,"v":{"sessionId":"abc","creationDate":1700000000000}}"#;
        let l2 = r#"{"kind":2,"v":[{"requestId":"r1","timestamp":1700000001000,"modelId":"copilot/claude-sonnet-4.6","message":{"text":"fix the login bug"},"response":[{"kind":"markdownContent","value":"I fixed it."},{"kind":"toolInvocationSerialized","toolId":"readFile","invocationMessage":{"value":"Reading auth.ts"}}]}]}"#;
        std::fs::write(&path, format!("{l0}\n{l2}\n")).unwrap();

        let d = VsCodeReader::parse(&path, Some("/proj".into()), true).expect("parses");
        assert_eq!(d.session.tool, AgentTool::VsCode);
        assert!(d.session.id.starts_with("vscode:"));
        assert_eq!(
            d.session.model.as_deref(),
            Some("copilot/claude-sonnet-4.6")
        );
        assert_eq!(d.session.tool_call_count, 1);
        assert_eq!(d.session.project.as_deref(), Some("/proj"));
        assert!(d
            .session
            .title
            .as_deref()
            .unwrap()
            .contains("fix the login bug"));
        assert!(d.messages.iter().any(|m| matches!(m.role, Role::User)));
        assert!(d.messages.iter().any(|m| matches!(m.role, Role::Assistant)));
        assert!(d
            .messages
            .iter()
            .any(|m| matches!(m.kind, MessageKind::ToolUse)));
        std::fs::remove_dir_all(&dir).ok();
    }
}
