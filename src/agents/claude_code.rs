//! Claude Code adapter — reads `~/.claude/projects/<slug>/<session>.jsonl`.
//!
//! One JSONL file per session; the file stem is the session id. Each line is a
//! record with a `type` (`user`/`assistant`/`summary`/`file-history-snapshot`/…)
//! and, for messages, a `message` object carrying `role`, `model`, `usage`, and
//! a `content` array of `text`/`thinking`/`tool_use`/`tool_result` blocks.
//! Verified against real transcripts on-disk. Tolerant: bad lines are skipped.

use std::fs;
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
    /// Fixture seam: read from an explicit projects dir instead of the
    /// platform location. The G2 harness (`tests/agents_bench.rs`)
    /// materializes committed fixtures into a temp dir and points here.
    pub fn with_root(projects_dir: PathBuf) -> Self {
        Self { base: projects_dir }
    }

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
    ///
    /// Incremental: a file that only grew since the last parse is read from
    /// where that parse stopped ([`super::tail`]), so a long active session
    /// costs its new lines, not its whole transcript, on every snapshot.
    fn parse(&self, path: &Path, with_messages: bool) -> Option<AgentSessionDetail> {
        let raw_id = path.file_stem()?.to_string_lossy().to_string();
        let flavour = if with_messages { "cc:full" } else { "cc:meta" };
        let state = super::tail::parse(path, flavour, || ParseState::new(with_messages))?;
        Some(state.finish(&raw_id, path))
    }
}

/// Everything a Claude Code parse accumulates, fed one line at a time — so it
/// can be resumed when the file grows.
#[derive(Clone)]
struct ParseState {
    with_messages: bool,
    cwd: Option<String>,
    git_branch: Option<String>,
    title: Option<String>,
    first_user: Option<String>,
    model_counts: std::collections::HashMap<String, u32>,
    inp: u64,
    outp: u64,
    cache: u64,
    cache_w: u64,
    msg_count: u32,
    tool_count: u32,
    first_ts: i64,
    last_ts: i64,
    messages: Vec<AgentMessage>,
}

impl ParseState {
    fn new(with_messages: bool) -> Self {
        ParseState {
            with_messages,
            cwd: None,
            git_branch: None,
            title: None,
            first_user: None,
            model_counts: Default::default(),
            inp: 0,
            outp: 0,
            cache: 0,
            cache_w: 0,
            msg_count: 0,
            tool_count: 0,
            first_ts: i64::MAX,
            last_ts: 0,
            messages: Vec::new(),
        }
    }

    fn finish(self, raw_id: &str, path: &Path) -> AgentSessionDetail {
        let first_ts = if self.first_ts == i64::MAX {
            self.last_ts
        } else {
            self.first_ts
        };
        // Highest count wins; ties go to the lexically smallest name so the
        // answer never depends on hash order.
        let model = self
            .model_counts
            .into_iter()
            .max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0)))
            .map(|(m, _)| m);
        let title = self
            .title
            .or_else(|| self.first_user.map(|s| truncate(&s, 80)));

        let session = AgentSession {
            id: AgentSession::make_id(AgentTool::ClaudeCode, raw_id),
            tool: AgentTool::ClaudeCode,
            title,
            project: self.cwd,
            git_branch: self.git_branch,
            model,
            started_ts: first_ts,
            updated_ts: self.last_ts,
            message_count: self.msg_count,
            tool_call_count: self.tool_count,
            input_tokens: self.inp,
            output_tokens: self.outp,
            cache_tokens: self.cache,
            cache_write_tokens: self.cache_w,
            source_path: path.to_string_lossy().to_string(),
        };
        AgentSessionDetail {
            session,
            messages: self.messages,
        }
    }
}

impl super::tail::LineState for ParseState {
    fn weight(&self) -> usize {
        super::tail::messages_weight(&self.messages)
    }

    fn feed(&mut self, line: &str) {
        let line = line.trim();
        if line.is_empty() {
            return;
        }
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            return; // tolerate a truncated/interleaved line
        };
        let rtype = v.get("type").and_then(Value::as_str).unwrap_or("");

        // Session-level context (present on message records).
        if self.cwd.is_none() {
            self.cwd = v.get("cwd").and_then(Value::as_str).map(String::from);
        }
        if self.git_branch.is_none() {
            self.git_branch = v
                .get("gitBranch")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(String::from);
        }
        if let Some(ts) = v.get("timestamp").and_then(Value::as_str) {
            let ms = super::rfc3339_millis(ts);
            if ms > 0 {
                self.first_ts = self.first_ts.min(ms);
                self.last_ts = self.last_ts.max(ms);
            }
        }

        match rtype {
            "summary" => {
                if let Some(s) = v.get("summary").and_then(Value::as_str) {
                    self.title = Some(s.to_string());
                }
            }
            "ai-title" => {
                if let Some(s) = v
                    .get("aiTitle")
                    .or_else(|| v.get("title"))
                    .and_then(Value::as_str)
                {
                    self.title = Some(s.to_string());
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
                            *self.model_counts.entry(model.to_string()).or_default() += 1;
                        }
                        if let Some(u) = m.get("usage") {
                            self.inp += u.get("input_tokens").and_then(Value::as_u64).unwrap_or(0);
                            self.outp +=
                                u.get("output_tokens").and_then(Value::as_u64).unwrap_or(0);
                            let cr = u
                                .get("cache_read_input_tokens")
                                .and_then(Value::as_u64)
                                .unwrap_or(0);
                            let cw = u
                                .get("cache_creation_input_tokens")
                                .and_then(Value::as_u64)
                                .unwrap_or(0);
                            self.cache += cr + cw;
                            self.cache_w += cw;
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
                    self.msg_count += 1;
                }
                self.tool_count += blocks
                    .iter()
                    .filter(|b| matches!(b.kind, MessageKind::ToolUse))
                    .count() as u32;
                if self.first_user.is_none() && role == Role::User {
                    self.first_user = blocks
                        .iter()
                        .find(|b| {
                            matches!(b.kind, MessageKind::Text) && !is_injected_prompt(&b.content)
                        })
                        .map(|b| b.content.clone());
                }
                if self.with_messages {
                    self.messages.extend(blocks);
                }
            }
            _ => {}
        }
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
pub(super) fn looks_like_uuid(s: &str) -> bool {
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

    /// Grow a transcript the way a live session does — line by line, each
    /// line written in two halves so a read can land mid-line — and after every
    /// write require the incremental parse to equal a fresh full parse (in
    /// both modes). The fresh parse reads a copy at a new path, so it cannot
    /// reuse any cached state.
    #[test]
    fn incremental_parse_matches_a_full_parse_as_the_file_grows() {
        let root = std::env::temp_dir().join(format!("saffev-tailcmp-{}", uuid::Uuid::new_v4()));
        let (live_dir, ref_dir) = (root.join("live"), root.join("ref"));
        std::fs::create_dir_all(&live_dir).unwrap();
        std::fs::create_dir_all(&ref_dir).unwrap();
        let name = "aaaaaaaa-aaaa-4aaa-8aaa-0000000000ff.jsonl";
        let live = live_dir.join(name);
        let reference = ref_dir.join(name);
        let mut text = String::new();
        for f in [
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/agents/claude_code/fixture-proj/aaaaaaaa-aaaa-4aaa-8aaa-000000000001.jsonl"),
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/agents/claude_code/fixture-proj/bbbbbbbb-bbbb-4bbb-8bbb-000000000002.jsonl"),
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/costs/home/.claude/projects/-home-dev-fixture-proj/dddd0004-0000-4000-8000-000000000004.jsonl"),
        ] {
            text.push_str(&std::fs::read_to_string(f).unwrap());
            if !text.ends_with('\n') {
                text.push('\n');
            }
        }
        let parse = |p: &Path, m: bool| ClaudeCodeReader::with_root(PathBuf::new()).parse(p, m);
        let check = |label: &str| {
            std::fs::copy(&live, &reference).unwrap();
            for with_messages in [true, false] {
                let mut inc = parse(&live, with_messages).expect("incremental parse");
                let mut full = parse(&reference, with_messages).expect("full parse");
                inc.session.source_path.clear();
                full.session.source_path.clear();
                assert_eq!(
                    serde_json::to_value(&inc).unwrap(),
                    serde_json::to_value(&full).unwrap(),
                    "{label} (messages: {with_messages})"
                );
            }
            // A new reference path each time: never a cached state.
            let _ = std::fs::remove_file(&reference);
            super::super::tail::forget(&reference);
        };
        std::fs::write(&live, b"").unwrap();
        for (i, line) in text.lines().enumerate() {
            let cut = line
                .char_indices()
                .nth(line.chars().count() / 2)
                .map(|(b, _)| b)
                .unwrap_or(0);
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&live)
                .unwrap();
            use std::io::Write;
            f.write_all(&line.as_bytes()[..cut]).unwrap();
            drop(f);
            check(&format!("line {i}, first half"));
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&live)
                .unwrap();
            f.write_all(&line.as_bytes()[cut..]).unwrap();
            f.write_all(b"\n").unwrap();
            drop(f);
            check(&format!("line {i}, complete"));
        }
        let _ = std::fs::remove_dir_all(&root);
    }
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
