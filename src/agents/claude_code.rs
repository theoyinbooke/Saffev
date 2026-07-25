//! Claude Code adapter — reads `~/.claude/projects/<slug>/<session>.jsonl`.
//!
//! One JSONL file per session; the file stem is the session id. Each line is a
//! record with a `type` (`user`/`assistant`/`summary`/`file-history-snapshot`/…)
//! and, for messages, a `message` object carrying `role`, `model`, `usage`, and
//! a `content` array of `text`/`thinking`/`tool_use`/`tool_result` blocks.
//! Verified against real transcripts on-disk. Tolerant: bad lines are skipped.

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::{
    home, AgentMessage, AgentReader, AgentSession, AgentSessionDetail, AgentTool, MessageKind, Role,
};

/// Reads Claude Code's per-project JSONL transcripts.
pub struct ClaudeCodeReader {
    base: PathBuf,
}

impl ClaudeCodeReader {
    /// `~/.claude/projects` (honors `CLAUDE_CONFIG_DIR` if set).
    pub fn new() -> Self {
        let base = std::env::var_os("CLAUDE_CONFIG_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| home().join(".claude"))
            .join("projects");
        Self { base }
    }

    /// Every `<slug>/<session>.jsonl` under the projects dir.
    fn session_files(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let Ok(slugs) = fs::read_dir(&self.base) else {
            return out;
        };
        for slug in slugs.flatten() {
            let Ok(files) = fs::read_dir(slug.path()) else {
                continue;
            };
            for f in files.flatten() {
                let p = f.path();
                // Only `<uuid>.jsonl` session files — skip plugin/index `.jsonl`
                // and the `subagents/` subdir (side-thread transcripts).
                let is_session = p.extension().map(|e| e == "jsonl").unwrap_or(false)
                    && p.file_stem()
                        .map(|s| looks_like_uuid(&s.to_string_lossy()))
                        .unwrap_or(false);
                if is_session {
                    out.push(p);
                }
            }
        }
        out
    }

    /// Parse one session file. `with_messages` toggles building the transcript
    /// (skip it for fast list summaries).
    fn parse(&self, path: &Path, with_messages: bool) -> Option<AgentSessionDetail> {
        // Stream line-by-line: sessions can be tens of MB — never load whole.
        let file = fs::File::open(path).ok()?;
        let reader = BufReader::new(file);
        let raw_id = path.file_stem()?.to_string_lossy().to_string();

        let mut cwd: Option<String> = None;
        let mut git_branch: Option<String> = None;
        let mut title: Option<String> = None;
        let mut first_user: Option<String> = None;
        let mut model_counts: std::collections::HashMap<String, u32> = Default::default();
        let (mut inp, mut outp, mut cache) = (0u64, 0u64, 0u64);
        let (mut msg_count, mut tool_count) = (0u32, 0u32);
        let mut first_ts = i64::MAX;
        let mut last_ts = 0i64;
        let mut messages: Vec<AgentMessage> = Vec::new();

        for line in reader.lines() {
            let Ok(line) = line else { continue };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Ok(v) = serde_json::from_str::<Value>(line) else {
                continue; // tolerate a truncated/interleaved line
            };
            let rtype = v.get("type").and_then(Value::as_str).unwrap_or("");

            // Session-level context (present on message records).
            if cwd.is_none() {
                cwd = v.get("cwd").and_then(Value::as_str).map(String::from);
            }
            if git_branch.is_none() {
                git_branch = v
                    .get("gitBranch")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(String::from);
            }
            if let Some(ts) = v.get("timestamp").and_then(Value::as_str) {
                let ms = super::rfc3339_millis(ts);
                if ms > 0 {
                    first_ts = first_ts.min(ms);
                    last_ts = last_ts.max(ms);
                }
            }

            match rtype {
                "summary" => {
                    if let Some(s) = v.get("summary").and_then(Value::as_str) {
                        title = Some(s.to_string());
                    }
                }
                "ai-title" => {
                    if let Some(s) = v
                        .get("aiTitle")
                        .or_else(|| v.get("title"))
                        .and_then(Value::as_str)
                    {
                        title = Some(s.to_string());
                    }
                }
                "user" | "assistant" => {
                    let msg = v.get("message");
                    let ts = v
                        .get("timestamp")
                        .and_then(Value::as_str)
                        .map(super::rfc3339_millis)
                        .filter(|m| *m > 0);
                    if rtype == "assistant" {
                        if let Some(m) = msg {
                            if let Some(model) = m.get("model").and_then(Value::as_str) {
                                *model_counts.entry(model.to_string()).or_default() += 1;
                            }
                            if let Some(u) = m.get("usage") {
                                inp += u.get("input_tokens").and_then(Value::as_u64).unwrap_or(0);
                                outp += u.get("output_tokens").and_then(Value::as_u64).unwrap_or(0);
                                cache += u
                                    .get("cache_read_input_tokens")
                                    .and_then(Value::as_u64)
                                    .unwrap_or(0)
                                    + u.get("cache_creation_input_tokens")
                                        .and_then(Value::as_u64)
                                        .unwrap_or(0);
                            }
                        }
                    }
                    let role = if rtype == "assistant" {
                        Role::Assistant
                    } else {
                        Role::User
                    };
                    let blocks = extract_blocks(msg, role, ts);
                    // Count a "message" per record; tool blocks bump the tool count.
                    if blocks.iter().any(|b| b.role != Role::Tool) {
                        msg_count += 1;
                    }
                    tool_count += blocks
                        .iter()
                        .filter(|b| matches!(b.kind, MessageKind::ToolUse))
                        .count() as u32;
                    if first_user.is_none() && role == Role::User {
                        first_user = blocks
                            .iter()
                            .find(|b| {
                                matches!(b.kind, MessageKind::Text)
                                    && !is_injected_prompt(&b.content)
                            })
                            .map(|b| b.content.clone());
                    }
                    if with_messages {
                        messages.extend(blocks);
                    }
                }
                _ => {}
            }
        }

        if first_ts == i64::MAX {
            first_ts = last_ts;
        }
        let model = model_counts
            .into_iter()
            .max_by_key(|(_, c)| *c)
            .map(|(m, _)| m);
        let title = title.or_else(|| first_user.map(|s| truncate(&s, 80)));

        let session = AgentSession {
            id: AgentSession::make_id(AgentTool::ClaudeCode, &raw_id),
            tool: AgentTool::ClaudeCode,
            title,
            project: cwd,
            git_branch,
            model,
            started_ts: first_ts,
            updated_ts: last_ts,
            message_count: msg_count,
            tool_call_count: tool_count,
            input_tokens: inp,
            output_tokens: outp,
            cache_tokens: cache,
            source_path: path.to_string_lossy().to_string(),
        };
        Some(AgentSessionDetail { session, messages })
    }
}

impl Default for ClaudeCodeReader {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentReader for ClaudeCodeReader {
    fn tool(&self) -> AgentTool {
        AgentTool::ClaudeCode
    }
    fn is_present(&self) -> bool {
        self.base.is_dir()
    }
    fn list_sessions(&self) -> Vec<AgentSession> {
        // Cap to the most-recent files (by mtime) so a huge history doesn't make
        // the list scan unbounded; detail-by-id still reaches any session.
        let mut files: Vec<(std::time::SystemTime, PathBuf)> = self
            .session_files()
            .into_iter()
            .map(|p| {
                let m = fs::metadata(&p)
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::UNIX_EPOCH);
                (m, p)
            })
            .collect();
        files.sort_by(|a, b| b.0.cmp(&a.0));
        files
            .into_iter()
            .take(400)
            // Unchanged transcripts are answered from the per-file cache rather
            // than re-read (see `agents::cached_file_parse`).
            .filter_map(|(_, p)| {
                super::cached_file_parse(&p, |p| {
                    self.parse(p, false)
                        .map(|d| d.session)
                        .filter(|s| s.message_count > 0)
                })
            })
            .collect()
    }
    fn retention(&self) -> super::retention::RetentionPolicy {
        // Claude Code prunes transcripts older than `cleanupPeriodDays` (default
        // 30) on startup. Read the user's real setting; fall back to the default.
        let days = cleanup_period_days().unwrap_or(30);
        super::retention::RetentionPolicy::age_days(
            days,
            format!("Deletes transcripts after {days} days (cleanupPeriodDays)."),
        )
    }
    fn source_fingerprint(&self) -> Option<u64> {
        Some(super::hash_files(self.session_files().into_iter()))
    }
    fn session_detail(&self, raw_id: &str) -> Option<AgentSessionDetail> {
        let path = self
            .session_files()
            .into_iter()
            .find(|p| p.file_stem().map(|s| s == raw_id).unwrap_or(false))?;
        self.parse(&path, true)
    }
}

/// Extract message blocks from a Claude Code `message` object. `content` may be
/// a string (rare, user) or an array of typed blocks.
fn extract_blocks(msg: Option<&Value>, role: Role, ts: Option<i64>) -> Vec<AgentMessage> {
    let Some(msg) = msg else {
        return Vec::new();
    };
    let content = msg.get("content");
    match content {
        Some(Value::String(s)) => vec![AgentMessage {
            role,
            kind: MessageKind::Text,
            content: s.clone(),
            ts,
            tool_name: None,
        }],
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|b| block_to_message(b, role, ts))
            .collect(),
        _ => Vec::new(),
    }
}

fn block_to_message(b: &Value, role: Role, ts: Option<i64>) -> Option<AgentMessage> {
    let btype = b.get("type").and_then(Value::as_str).unwrap_or("");
    match btype {
        "text" => Some(AgentMessage {
            role,
            kind: MessageKind::Text,
            content: b.get("text").and_then(Value::as_str)?.to_string(),
            ts,
            tool_name: None,
        }),
        "thinking" => Some(AgentMessage {
            role,
            kind: MessageKind::Thinking,
            content: b.get("thinking").and_then(Value::as_str)?.to_string(),
            ts,
            tool_name: None,
        }),
        "tool_use" => {
            let name = b.get("name").and_then(Value::as_str).unwrap_or("tool");
            let input = b
                .get("input")
                .map(|i| serde_json::to_string(i).unwrap_or_default())
                .unwrap_or_default();
            Some(AgentMessage {
                role: Role::Assistant,
                kind: MessageKind::ToolUse,
                content: truncate(&input, 2000),
                ts,
                tool_name: Some(name.to_string()),
            })
        }
        "tool_result" => {
            let content = match b.get("content") {
                Some(Value::String(s)) => s.clone(),
                Some(v) => serde_json::to_string(v).unwrap_or_default(),
                None => String::new(),
            };
            Some(AgentMessage {
                role: Role::Tool,
                kind: MessageKind::ToolResult,
                content: truncate(&content, 4000),
                ts,
                tool_name: None,
            })
        }
        _ => None,
    }
}

/// Read `cleanupPeriodDays` from Claude Code's settings (`$CLAUDE_CONFIG_DIR` or
/// `~/.claude/settings.json`), if the user has set it.
fn cleanup_period_days() -> Option<u32> {
    let dir = std::env::var_os("CLAUDE_CONFIG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| super::home().join(".claude"));
    let text = fs::read_to_string(dir.join("settings.json")).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    v.get("cleanupPeriodDays")
        .and_then(serde_json::Value::as_u64)
        .map(|d| d as u32)
}

/// Is this a system-injected user message (caveat/command wrapper), which makes
/// a poor session title? Used only for the title fallback.
fn is_injected_prompt(s: &str) -> bool {
    let t = s.trim_start();
    t.starts_with("<local-command")
        || t.starts_with("<command-")
        || t.starts_with("Caveat:")
        || t.starts_with("<system-reminder")
}

/// Cheap check that a filename stem is a UUID (`8-4-4-4-12` hex), to skip
/// non-session `.jsonl` files (plugin/index) sitting in a project dir.
fn looks_like_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

/// Truncate to `max` chars (char-boundary safe), adding an ellipsis marker.
pub(crate) fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parses_a_session_fixture() {
        let dir = std::env::temp_dir().join(format!("saffev-cc-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("11111111-1111-1111-1111-111111111111.jsonl");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, r#"{{"type":"user","timestamp":"2026-07-02T06:21:40.000Z","cwd":"/tmp/proj","gitBranch":"main","sessionId":"11111111-1111-1111-1111-111111111111","message":{{"role":"user","content":"hello there"}}}}"#).unwrap();
        writeln!(f, r#"{{"type":"assistant","timestamp":"2026-07-02T06:21:42.000Z","message":{{"role":"assistant","model":"claude-opus-4-8","content":[{{"type":"text","text":"hi"}},{{"type":"tool_use","id":"t","name":"Bash","input":{{"cmd":"ls"}}}}],"usage":{{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":2,"cache_creation_input_tokens":1}}}}}}"#).unwrap();
        writeln!(f, r#"{{"type":"ai-title","sessionId":"11111111-1111-1111-1111-111111111111","aiTitle":"Say hi"}}"#).unwrap();
        writeln!(f, "not valid json — must be skipped").unwrap();
        drop(f);

        let reader = ClaudeCodeReader::new();
        let d = reader.parse(&path, true).expect("parses");
        assert_eq!(d.session.title.as_deref(), Some("Say hi"));
        assert_eq!(d.session.model.as_deref(), Some("claude-opus-4-8"));
        assert_eq!(d.session.input_tokens, 10);
        assert_eq!(d.session.output_tokens, 5);
        assert_eq!(d.session.cache_tokens, 3);
        assert_eq!(d.session.tool_call_count, 1);
        assert_eq!(d.session.project.as_deref(), Some("/tmp/proj"));
        assert_eq!(d.session.git_branch.as_deref(), Some("main"));
        assert_eq!(d.session.tool, AgentTool::ClaudeCode);
        assert!(d.session.id.starts_with("claude_code:"));
        assert!(d
            .messages
            .iter()
            .any(|m| matches!(m.kind, MessageKind::ToolUse)));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn injected_prompts_are_not_titles() {
        assert!(is_injected_prompt("<local-command-caveat>x"));
        assert!(is_injected_prompt("Caveat: things"));
        assert!(!is_injected_prompt("Fix the login bug"));
    }

    #[test]
    fn uuid_stems_only() {
        assert!(looks_like_uuid("11111111-1111-1111-1111-111111111111"));
        assert!(!looks_like_uuid("skill-injections"));
        assert!(!looks_like_uuid("short"));
    }
}
