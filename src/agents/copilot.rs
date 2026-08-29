//! GitHub Copilot CLI adapter — reads `~/.copilot/session-state/<id>/` and
//! the legacy `~/.copilot/history-session-state/session_*.json`.
//!
//! Format verified against working third-party parsers + GitHub's own docs
//! and changelog (G2 round 5; the CLI itself is closed-source):
//!
//! * **Modern (v0.0.342+)** — one directory per session:
//!   `events.jsonl` is an append-only event stream with envelope
//!   `{type, id, parentId, timestamp, data}`; `workspace.yaml` is FLAT
//!   key-value metadata (id, cwd, branch, `name` = the session title,
//!   created_at/updated_at). Token totals are written ONCE, at
//!   `session.shutdown` (`tokenDetails.{input,cache_read,cache_write,output}
//!   .tokenCount` — separate buckets, Anthropic convention: `input` is
//!   non-cached). A hard-killed session has no shutdown record; per-message
//!   `assistant.message.outputTokens` is the honest fallback for output only.
//! * **Legacy (pre-0.0.342)** — one flat JSON per session,
//!   `session_<uuid>_<timestamp>.json`: `sessionId`, `startTime`,
//!   `selectedModel`, `chatMessages[]` (OpenAI-style role/content/
//!   tool_calls). No token counts exist in this generation. Resuming
//!   migrates a legacy session into `session-state/` and PRESERVES the
//!   original — listing dedupes by session id, modern wins.
//!
//! The ~56 KB persisted system prompt (`system.message`) and subagent
//! marker events are noise, skipped. Tolerant: bad lines are skipped.

use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::{
    home, AgentMessage, AgentReader, AgentSession, AgentSessionDetail, AgentTool, MessageKind, Role,
};

/// Reads GitHub Copilot CLI's session stores (both generations).
pub struct CopilotReader {
    /// `~/.copilot` (honors `COPILOT_HOME`).
    base: PathBuf,
}

impl CopilotReader {
    /// Fixture seam: read from an explicit `.copilot` dir. See
    /// `tests/agents_bench.rs`.
    pub fn with_root(copilot_home: PathBuf) -> Self {
        Self { base: copilot_home }
    }

    /// `$COPILOT_HOME` else `~/.copilot`.
    pub fn new() -> Self {
        let base = std::env::var_os("COPILOT_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home().join(".copilot"));
        Self { base }
    }

    /// Modern session dirs: `session-state/<id>/` containing `events.jsonl`.
    fn modern_sessions(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let Ok(dirs) = fs::read_dir(self.base.join("session-state")) else {
            return out;
        };
        for d in dirs.flatten() {
            let events = d.path().join("events.jsonl");
            if events.is_file() {
                out.push(events);
            }
        }
        out
    }

    /// Legacy flat files: `history-session-state/session_*.json`.
    fn legacy_sessions(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let Ok(files) = fs::read_dir(self.base.join("history-session-state")) else {
            return out;
        };
        for f in files.flatten() {
            let p = f.path();
            let name = f.file_name().to_string_lossy().to_string();
            if p.is_file() && name.starts_with("session_") && name.ends_with(".json") {
                out.push(p);
            }
        }
        out
    }

    /// Parse the flat `workspace.yaml` next to a modern `events.jsonl`.
    /// Returns `(title, cwd, created_ms, updated_ms)`. The file is flat
    /// `key: value` lines — a full YAML parser is not needed (values contain
    /// no nesting; timestamps contain colons, hence split on the FIRST).
    fn workspace_meta(events: &Path) -> (Option<String>, Option<String>, i64, i64) {
        let (mut title, mut cwd, mut created, mut updated) = (None, None, 0i64, 0i64);
        let Some(dir) = events.parent() else {
            return (title, cwd, created, updated);
        };
        let Ok(text) = fs::read_to_string(dir.join("workspace.yaml")) else {
            return (title, cwd, created, updated);
        };
        for line in text.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let trimmed = value.trim();
            // Single-quoted YAML scalars escape embedded quotes by doubling
            // them ('' -> '); unescape after stripping (G2 closing critic).
            let single_quoted =
                trimmed.len() >= 2 && trimmed.starts_with('\'') && trimmed.ends_with('\'');
            let value = trimmed.trim_matches(|c| c == '"' || c == '\'').to_string();
            let value = if single_quoted {
                value.replace("''", "'")
            } else {
                value
            };
            let value = value.as_str();
            if value.is_empty() {
                continue;
            }
            match key.trim() {
                "name" => title = Some(value.to_string()),
                "cwd" => cwd = Some(value.to_string()),
                "created_at" => created = super::rfc3339_millis(value),
                "updated_at" => updated = super::rfc3339_millis(value),
                _ => {}
            }
        }
        (title, cwd, created, updated)
    }

    /// Parse a modern `events.jsonl` session.
    fn parse_modern(path: &Path, with_messages: bool) -> Option<AgentSessionDetail> {
        let file = fs::File::open(path).ok()?;
        let (title, mut cwd, mut start_ts, mut updated_ts) = Self::workspace_meta(path);

        let mut session_id: Option<String> = None;
        let mut git_branch: Option<String> = None;
        let mut model: Option<String> = None; // last model_change / message wins
        let (mut inp, mut outp, mut cache, mut cache_w) = (0u64, 0u64, 0u64, 0u64);
        let mut per_msg_out = 0u64; // fallback when no shutdown record exists
        let mut saw_shutdown = false;
        let (mut msg_count, mut tool_count) = (0u32, 0u32);
        let mut first_user: Option<String> = None;
        let mut messages: Vec<AgentMessage> = Vec::new();

        for line in BufReader::new(file).lines() {
            let Ok(line) = line else { continue };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Ok(v) = serde_json::from_str::<Value>(line) else {
                continue; // tolerate truncated/garbage lines
            };
            let etype = v.get("type").and_then(Value::as_str).unwrap_or("");
            let ts = v
                .get("timestamp")
                .and_then(Value::as_str)
                .map(super::rfc3339_millis)
                .filter(|m| *m > 0);
            if let Some(t) = ts {
                if start_ts == 0 {
                    start_ts = t;
                }
                updated_ts = updated_ts.max(t);
            }
            let Some(data) = v.get("data") else { continue };

            match etype {
                "session.start" => {
                    session_id = data
                        .get("sessionId")
                        .and_then(Value::as_str)
                        .map(String::from)
                        .or(session_id);
                    let ctx = data.get("context");
                    if cwd.is_none() {
                        cwd = ctx
                            .and_then(|c| c.get("cwd"))
                            .and_then(Value::as_str)
                            .map(String::from);
                    }
                    git_branch = ctx
                        .and_then(|c| c.get("branch"))
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .or(git_branch);
                }
                "session.model_change" => {
                    if let Some(m) = data.get("newModel").and_then(Value::as_str) {
                        // "auto" is a routing mode, not a model name.
                        if m != "auto" {
                            model = Some(m.to_string());
                        }
                    }
                }
                "user.message" => {
                    // `content` is the RAW prompt; `transformedContent`
                    // carries injected wrappers — raw is the honest text.
                    let text = data
                        .get("content")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    msg_count += 1;
                    if first_user.is_none() && !text.is_empty() {
                        first_user = Some(text.to_string());
                    }
                    if with_messages && !text.is_empty() {
                        messages.push(AgentMessage {
                            role: Role::User,
                            kind: MessageKind::Text,
                            content: text.to_string(),
                            ts,
                            tool_name: None,
                        });
                    }
                }
                "assistant.message" => {
                    msg_count += 1;
                    if let Some(m) = data.get("model").and_then(Value::as_str) {
                        if m != "auto" {
                            model = Some(m.to_string());
                        }
                    }
                    per_msg_out += data
                        .get("outputTokens")
                        .and_then(Value::as_u64)
                        .unwrap_or(0);
                    if with_messages {
                        if let Some(r) = data
                            .get("reasoningText")
                            .and_then(Value::as_str)
                            .filter(|s| !s.is_empty())
                        {
                            messages.push(AgentMessage {
                                role: Role::Assistant,
                                kind: MessageKind::Thinking,
                                content: r.to_string(),
                                ts,
                                tool_name: None,
                            });
                        }
                    }
                    let text = data
                        .get("content")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    if with_messages && !text.is_empty() {
                        messages.push(AgentMessage {
                            role: Role::Assistant,
                            kind: MessageKind::Text,
                            content: text.to_string(),
                            ts,
                            tool_name: None,
                        });
                    }
                    for tr in data
                        .get("toolRequests")
                        .and_then(Value::as_array)
                        .map(|a| a.as_slice())
                        .unwrap_or_default()
                    {
                        tool_count += 1;
                        if with_messages {
                            let name = tr
                                .get("name")
                                .and_then(Value::as_str)
                                .unwrap_or("tool")
                                .to_string();
                            let args = tr
                                .get("arguments")
                                .map(Value::to_string)
                                .unwrap_or_default();
                            messages.push(AgentMessage {
                                role: Role::Assistant,
                                kind: MessageKind::ToolUse,
                                content: super::claude_code::truncate(&args, 2000),
                                ts,
                                tool_name: Some(name),
                            });
                        }
                    }
                }
                "tool.execution_complete" => {
                    if with_messages {
                        let out_text = data
                            .get("result")
                            .and_then(|r| r.get("content"))
                            .and_then(Value::as_str)
                            .unwrap_or_default();
                        if !out_text.is_empty() {
                            messages.push(AgentMessage {
                                role: Role::Tool,
                                kind: MessageKind::ToolResult,
                                content: super::claude_code::truncate(out_text, 2000),
                                ts,
                                tool_name: data
                                    .get("toolName")
                                    .and_then(Value::as_str)
                                    .map(String::from),
                            });
                        }
                    }
                }
                "session.shutdown" => {
                    // The one place full token totals exist. Separate
                    // buckets (Anthropic convention): `input` is non-cached.
                    if let Some(td) = data.get("tokenDetails") {
                        let bucket = |k: &str| {
                            td.get(k)
                                .and_then(|b| b.get("tokenCount"))
                                .and_then(Value::as_u64)
                                .unwrap_or(0)
                        };
                        inp = bucket("input");
                        cache_w = bucket("cache_write");
                        cache = bucket("cache_read") + cache_w;
                        outp = bucket("output");
                        saw_shutdown = true;
                    }
                }
                // system.message (persisted system prompt), turn markers,
                // subagent markers, telemetry — noise.
                _ => {}
            }
        }

        if !saw_shutdown {
            // Hard-killed session: per-message output is all that exists;
            // input honestly stays 0 rather than being estimated.
            outp = per_msg_out;
        }
        let raw_id = session_id.or_else(|| {
            // Fall back to the session directory's name (it IS the id).
            path.parent()
                .and_then(|d| d.file_name())
                .map(|n| n.to_string_lossy().to_string())
        })?;
        // A session with recorded token spend but zero surviving messages
        // (e.g. shutdown-only after truncation) must LIST — vanishing hides
        // real spend (G2 comprehensive critic's silent-drop finding). Only a
        // session with neither turns nor tokens is nothing.
        if msg_count == 0 && inp + outp + cache == 0 {
            return None;
        }
        let title = title.or_else(|| {
            first_user
                .as_deref()
                .map(|t| super::claude_code::truncate(t, 80))
        });
        let session = AgentSession {
            id: AgentSession::make_id(AgentTool::Copilot, &raw_id),
            tool: AgentTool::Copilot,
            title,
            project: cwd,
            git_branch,
            model,
            started_ts: start_ts,
            updated_ts: updated_ts.max(start_ts),
            message_count: msg_count,
            tool_call_count: tool_count,
            input_tokens: inp,
            output_tokens: outp,
            cache_tokens: cache,
            cache_write_tokens: cache_w,
            source_path: path.to_string_lossy().to_string(),
        };
        Some(AgentSessionDetail { session, messages })
    }

    /// Parse a legacy `session_<uuid>_<ts>.json` snapshot.
    fn parse_legacy(path: &Path, with_messages: bool) -> Option<AgentSessionDetail> {
        let text = fs::read_to_string(path).ok()?;
        let v: Value = serde_json::from_str(&text).ok()?;
        let raw_id = v
            .get("sessionId")
            .and_then(Value::as_str)
            .map(String::from)
            .or_else(|| {
                // `session_<uuid>_<ts>.json` — middle segment.
                path.file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .and_then(|s| {
                        s.strip_prefix("session_")
                            .and_then(|r| r.rsplit_once('_').map(|(id, _)| id.to_string()))
                    })
            })?;
        let start_ts = v
            .get("startTime")
            .and_then(Value::as_str)
            .map(super::rfc3339_millis)
            .unwrap_or(0);
        let model = v
            .get("selectedModel")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && *s != "auto")
            .map(String::from);

        let mut first_user: Option<String> = None;
        let (mut msg_count, mut tool_count) = (0u32, 0u32);
        let mut messages: Vec<AgentMessage> = Vec::new();
        for m in v
            .get("chatMessages")
            .and_then(Value::as_array)
            .map(|a| a.as_slice())
            .unwrap_or_default()
        {
            let role_s = m.get("role").and_then(Value::as_str).unwrap_or("");
            let content = m.get("content").and_then(Value::as_str).unwrap_or("");
            match role_s {
                "user" => {
                    msg_count += 1;
                    if first_user.is_none() && !content.is_empty() {
                        first_user = Some(content.to_string());
                    }
                    if with_messages && !content.is_empty() {
                        messages.push(AgentMessage {
                            role: Role::User,
                            kind: MessageKind::Text,
                            content: content.to_string(),
                            ts: None,
                            tool_name: None,
                        });
                    }
                }
                "assistant" => {
                    msg_count += 1;
                    if with_messages && !content.is_empty() {
                        messages.push(AgentMessage {
                            role: Role::Assistant,
                            kind: MessageKind::Text,
                            content: content.to_string(),
                            ts: None,
                            tool_name: None,
                        });
                    }
                    for tc in m
                        .get("tool_calls")
                        .and_then(Value::as_array)
                        .map(|a| a.as_slice())
                        .unwrap_or_default()
                    {
                        tool_count += 1;
                        if with_messages {
                            let name = tc
                                .get("function")
                                .and_then(|f| f.get("name"))
                                .or_else(|| tc.get("name"))
                                .and_then(Value::as_str)
                                .unwrap_or("tool")
                                .to_string();
                            let args = tc
                                .get("function")
                                .and_then(|f| f.get("arguments"))
                                .or_else(|| tc.get("arguments"))
                                .map(|a| match a {
                                    Value::String(s) => s.clone(),
                                    other => other.to_string(),
                                })
                                .unwrap_or_default();
                            messages.push(AgentMessage {
                                role: Role::Assistant,
                                kind: MessageKind::ToolUse,
                                content: super::claude_code::truncate(&args, 2000),
                                ts: None,
                                tool_name: Some(name),
                            });
                        }
                    }
                }
                "tool" => {
                    if with_messages && !content.is_empty() {
                        messages.push(AgentMessage {
                            role: Role::Tool,
                            kind: MessageKind::ToolResult,
                            content: super::claude_code::truncate(content, 2000),
                            ts: None,
                            tool_name: None,
                        });
                    }
                }
                _ => {}
            }
        }
        if msg_count == 0 {
            return None;
        }
        let session = AgentSession {
            id: AgentSession::make_id(AgentTool::Copilot, &raw_id),
            tool: AgentTool::Copilot,
            title: first_user
                .as_deref()
                .map(|t| super::claude_code::truncate(t, 80)),
            project: None, // the legacy snapshot records no cwd
            git_branch: None,
            model,
            started_ts: start_ts,
            updated_ts: start_ts,
            message_count: msg_count,
            tool_call_count: tool_count,
            // No token counts exist in the legacy generation.
            input_tokens: 0,
            output_tokens: 0,
            cache_tokens: 0,
            cache_write_tokens: 0,
            source_path: path.to_string_lossy().to_string(),
        };
        Some(AgentSessionDetail { session, messages })
    }
}

impl Default for CopilotReader {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentReader for CopilotReader {
    fn tool(&self) -> AgentTool {
        AgentTool::Copilot
    }
    fn is_present(&self) -> bool {
        self.base.join("session-state").is_dir() || self.base.join("history-session-state").is_dir()
    }
    fn list_sessions(&self) -> Vec<AgentSession> {
        let mut out: Vec<AgentSession> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        // Modern first: a resumed legacy session exists in BOTH stores
        // (migration preserves the original) — modern wins the dedupe.
        for p in self.modern_sessions() {
            if let Some(s) =
                super::cached_file_parse(&p, |p| Self::parse_modern(p, false).map(|d| d.session))
            {
                seen.insert(s.id.clone());
                out.push(s);
            }
        }
        for p in self.legacy_sessions() {
            if let Some(s) =
                super::cached_file_parse(&p, |p| Self::parse_legacy(p, false).map(|d| d.session))
            {
                if seen.insert(s.id.clone()) {
                    out.push(s);
                }
            }
        }
        out
    }
    fn retention(&self) -> super::retention::RetentionPolicy {
        super::retention::RetentionPolicy::keeps_all(
            "Sessions persist on disk; legacy sessions are migrated (and kept) on resume.",
        )
    }
    fn source_fingerprint(&self) -> Option<u64> {
        Some(super::hash_files(
            self.modern_sessions()
                .into_iter()
                .chain(self.legacy_sessions()),
        ))
    }
    fn session_detail(&self, raw_id: &str) -> Option<AgentSessionDetail> {
        // Modern: the directory name IS the session id.
        let events = self
            .base
            .join("session-state")
            .join(raw_id)
            .join("events.jsonl");
        if events.is_file() {
            if let Some(d) = Self::parse_modern(&events, true) {
                return Some(d);
            }
        }
        // Legacy: the filename embeds the id.
        for p in self.legacy_sessions() {
            if p.file_name()
                .map(|n| n.to_string_lossy().contains(raw_id))
                .unwrap_or(false)
            {
                if let Some(d) = Self::parse_legacy(&p, true) {
                    return Some(d);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_modern(dir: &Path, id: &str, with_shutdown: bool) -> PathBuf {
        let sdir = dir.join("session-state").join(id);
        std::fs::create_dir_all(&sdir).unwrap();
        std::fs::write(
            sdir.join("workspace.yaml"),
            "id: SID\ncwd: /home/dev/p\nbranch: main\nname: List files\nuser_named: false\ncreated_at: 2026-07-01T14:28:54.677Z\nupdated_at: 2026-07-01T14:31:30.280Z\n".replace("SID", id),
        )
        .unwrap();
        let mut lines = vec![
            format!(r#"{{"type":"session.start","id":"e1","timestamp":"2026-07-01T14:28:54.677Z","data":{{"sessionId":"{id}","version":1,"producer":"copilot-agent","context":{{"cwd":"/home/dev/p","branch":"main"}}}}}}"#),
            r#"{"type":"session.model_change","id":"e2","timestamp":"2026-07-01T14:28:54.700Z","data":{"newModel":"auto"}}"#.into(),
            r#"{"type":"user.message","id":"e3","timestamp":"2026-07-01T14:29:01.010Z","data":{"content":"list the files here","transformedContent":"<wrapped>list the files here</wrapped>"}}"#.into(),
            r#"{"type":"assistant.message","id":"e4","timestamp":"2026-07-01T14:29:03.200Z","data":{"content":"Listing now.","model":"claude-sonnet-4.5","reasoningText":"ls is enough","toolRequests":[{"toolCallId":"c1","name":"bash","arguments":{"command":"ls -la"}}],"outputTokens":42}}"#.into(),
            r#"{"type":"tool.execution_complete","id":"e5","timestamp":"2026-07-01T14:29:03.900Z","data":{"toolCallId":"c1","success":true,"result":{"content":"total 8"},"toolName":"bash"}}"#.into(),
        ];
        if with_shutdown {
            lines.push(r#"{"type":"session.shutdown","id":"e6","timestamp":"2026-07-01T14:31:30.280Z","data":{"shutdownType":"exit","tokenDetails":{"input":{"tokenCount":15230},"cache_read":{"tokenCount":12000},"cache_write":{"tokenCount":2100},"output":{"tokenCount":42}}}}"#.into());
        }
        let events = sdir.join("events.jsonl");
        std::fs::write(&events, lines.join("\n")).unwrap();
        events
    }

    #[test]
    fn parses_a_modern_session_with_shutdown_totals() {
        let dir = std::env::temp_dir().join(format!("saffev-cop-{}", uuid::Uuid::new_v4()));
        let events = write_modern(&dir, "0b6c2a9e-3f41-4d7a-9c1e-8a2b5d4f6e70", true);
        let d = CopilotReader::parse_modern(&events, true).expect("parses");
        assert_eq!(d.session.title.as_deref(), Some("List files"));
        assert_eq!(d.session.project.as_deref(), Some("/home/dev/p"));
        assert_eq!(d.session.git_branch.as_deref(), Some("main"));
        assert_eq!(d.session.model.as_deref(), Some("claude-sonnet-4.5"));
        assert_eq!(d.session.input_tokens, 15230);
        assert_eq!(d.session.cache_tokens, 14100);
        assert_eq!(d.session.output_tokens, 42);
        assert_eq!(d.session.tool_call_count, 1);
        assert!(d
            .messages
            .iter()
            .any(|m| matches!(m.kind, MessageKind::Thinking)));
        assert!(d
            .messages
            .iter()
            .any(|m| matches!(m.kind, MessageKind::ToolResult)));
        // Raw prompt, not the transformed wrapper.
        assert!(d
            .messages
            .iter()
            .any(|m| m.content == "list the files here"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn hard_killed_session_reports_only_per_message_output() {
        // No shutdown record: input honestly 0, output from outputTokens.
        let dir = std::env::temp_dir().join(format!("saffev-cop-{}", uuid::Uuid::new_v4()));
        let events = write_modern(&dir, "1b6c2a9e-3f41-4d7a-9c1e-8a2b5d4f6e71", false);
        let d = CopilotReader::parse_modern(&events, false).expect("parses");
        assert_eq!(d.session.input_tokens, 0);
        assert_eq!(d.session.output_tokens, 42);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn shutdown_only_session_lists_with_its_spend() {
        // Token spend with zero surviving messages must not vanish (G2
        // comprehensive critic's silent-drop finding).
        let dir = std::env::temp_dir().join(format!("saffev-cop-{}", uuid::Uuid::new_v4()));
        let sdir = dir.join("session-state/2c8e4b1a-5f63-4d9c-8e3a-000000000099");
        std::fs::create_dir_all(&sdir).unwrap();
        std::fs::write(
            sdir.join("events.jsonl"),
            r#"{"type":"session.shutdown","id":"e1","timestamp":"2026-07-02T10:00:00.000Z","data":{"shutdownType":"exit","tokenDetails":{"input":{"tokenCount":9000},"cache_read":{"tokenCount":0},"cache_write":{"tokenCount":0},"output":{"tokenCount":100}}}}"#,
        )
        .unwrap();
        let reader = CopilotReader::with_root(dir.clone());
        let sessions = reader.list_sessions();
        assert_eq!(sessions.len(), 1, "shutdown-only session vanished");
        assert_eq!(sessions[0].input_tokens, 9000);
        assert_eq!(sessions[0].message_count, 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn single_quoted_yaml_values_are_stripped() {
        let dir = std::env::temp_dir().join(format!("saffev-cop-{}", uuid::Uuid::new_v4()));
        let sdir = dir.join("session-state/3d9f5c2b-6a74-4e0d-9f4b-000000000098");
        std::fs::create_dir_all(&sdir).unwrap();
        std::fs::write(
            sdir.join("workspace.yaml"),
            "id: 3d9f5c2b-6a74-4e0d-9f4b-000000000098\ncwd: '/home/dev/spec chars'\nname: 'It''s quoted'\ncreated_at: 2026-07-02T10:00:00.000Z\nupdated_at: 2026-07-02T10:01:00.000Z\n",
        )
        .unwrap();
        std::fs::write(
            sdir.join("events.jsonl"),
            r#"{"type":"user.message","id":"e1","timestamp":"2026-07-02T10:00:01.000Z","data":{"content":"hi"}}"#,
        )
        .unwrap();
        let reader = CopilotReader::with_root(dir.clone());
        let sessions = reader.list_sessions();
        assert_eq!(sessions[0].project.as_deref(), Some("/home/dev/spec chars"));
        assert_eq!(sessions[0].title.as_deref(), Some("It's quoted"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn legacy_snapshot_parses_and_migrated_twin_dedupes() {
        let dir = std::env::temp_dir().join(format!("saffev-cop-{}", uuid::Uuid::new_v4()));
        let hist = dir.join("history-session-state");
        std::fs::create_dir_all(&hist).unwrap();
        // Legacy-only session.
        std::fs::write(
            hist.join("session_aaaa1111-0000-4000-8000-000000000001_1759500000.json"),
            r#"{"sessionId":"aaaa1111-0000-4000-8000-000000000001","startTime":"2025-10-01T10:00:00.000Z","selectedModel":"gpt-5","chatMessages":[{"role":"user","content":"legacy question"},{"role":"assistant","content":"legacy answer","tool_calls":[{"function":{"name":"bash","arguments":"{\"command\":\"pwd\"}"}}]},{"role":"tool","content":"/home/dev"}]}"#,
        )
        .unwrap();
        // A session that was MIGRATED: present in both stores.
        std::fs::write(
            hist.join("session_0b6c2a9e-3f41-4d7a-9c1e-8a2b5d4f6e70_1759500001.json"),
            r#"{"sessionId":"0b6c2a9e-3f41-4d7a-9c1e-8a2b5d4f6e70","startTime":"2025-10-01T11:00:00.000Z","chatMessages":[{"role":"user","content":"pre-migration copy"}]}"#,
        )
        .unwrap();
        write_modern(&dir, "0b6c2a9e-3f41-4d7a-9c1e-8a2b5d4f6e70", true);

        let reader = CopilotReader::with_root(dir.clone());
        let sessions = reader.list_sessions();
        assert_eq!(sessions.len(), 2, "migrated twin double-listed");
        let legacy = sessions
            .iter()
            .find(|s| s.id.ends_with("000000000001"))
            .expect("legacy session listed");
        assert_eq!(legacy.model.as_deref(), Some("gpt-5"));
        assert_eq!(legacy.tool_call_count, 1);
        assert_eq!(legacy.input_tokens, 0, "legacy has no token counts");
        // The migrated id resolves to the MODERN store.
        let modern = sessions
            .iter()
            .find(|s| s.id.ends_with("8a2b5d4f6e70"))
            .expect("modern session listed");
        assert!(modern.source_path.contains("session-state"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
