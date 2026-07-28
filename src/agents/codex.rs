//! Codex CLI adapter — reads `~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl`.
//!
//! Each line is `{type, timestamp, payload}`. The canonical transcript is the
//! `response_item` stream (`message` items with `content[].text`); `event_msg`
//! `token_count` carries the running token totals; `turn_context` carries the
//! model; `session_meta` (first line) carries id/cwd/version. `session_index.jsonl`
//! provides fast titles by id. Verified against real rollouts on-disk. Tolerant:
//! unknown types skipped; append-order is authoritative.

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::{
    home, AgentMessage, AgentReader, AgentSession, AgentSessionDetail, AgentTool, MessageKind, Role,
};

/// Cap the number of (most-recent) sessions scanned for a list, to bound cost on
/// machines with thousands of rollouts. Detail-by-id is unaffected.
const MAX_LIST: usize = 400;

/// Reads Codex rollout transcripts.
pub struct CodexReader {
    base: PathBuf,
}

impl CodexReader {
    /// Fixture seam: read from an explicit Codex home (containing `sessions/`
    /// and optionally `session_index.jsonl`). See `tests/agents_bench.rs`.
    pub fn with_root(codex_home: PathBuf) -> Self {
        Self {
            base: codex_home.join("sessions"),
        }
    }

    /// `$CODEX_HOME/sessions` else `~/.codex/sessions`.
    pub fn new() -> Self {
        let home_dir = std::env::var_os("CODEX_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home().join(".codex"));
        Self {
            base: home_dir.join("sessions"),
        }
    }

    fn codex_home(&self) -> &Path {
        self.base.parent().unwrap_or(&self.base)
    }

    /// All rollout files under `sessions/YYYY/MM/DD/`, newest first (by mtime).
    fn rollouts(&self) -> Vec<PathBuf> {
        let mut files: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
        // Walk up to 3 dir levels (year/month/day).
        fn walk(dir: &Path, depth: u8, out: &mut Vec<(std::time::SystemTime, PathBuf)>) {
            let Ok(rd) = fs::read_dir(dir) else { return };
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() && depth < 3 {
                    walk(&p, depth + 1, out);
                } else if p.is_file()
                    && p.file_name()
                        .map(|n| {
                            let n = n.to_string_lossy();
                            n.starts_with("rollout-") && n.ends_with(".jsonl")
                        })
                        .unwrap_or(false)
                {
                    let mtime = e
                        .metadata()
                        .and_then(|m| m.modified())
                        .unwrap_or(std::time::UNIX_EPOCH);
                    out.push((mtime, p));
                }
            }
        }
        walk(&self.base, 0, &mut files);
        files.sort_by(|a, b| b.0.cmp(&a.0));
        files.into_iter().map(|(_, p)| p).collect()
    }

    /// Load `session_index.jsonl` into id → thread_name (best-effort titles).
    fn title_index(&self) -> HashMap<String, String> {
        let mut m = HashMap::new();
        if let Ok(text) = fs::read_to_string(self.codex_home().join("session_index.jsonl")) {
            for line in text.lines() {
                if let Ok(v) = serde_json::from_str::<Value>(line) {
                    if let (Some(id), Some(name)) = (
                        v.get("id").and_then(Value::as_str),
                        v.get("thread_name").and_then(Value::as_str),
                    ) {
                        m.insert(id.to_string(), name.replace('\n', " "));
                    }
                }
            }
        }
        m
    }

    fn parse(
        &self,
        path: &Path,
        titles: &HashMap<String, String>,
        with_messages: bool,
    ) -> Option<AgentSessionDetail> {
        let file = fs::File::open(path).ok()?;
        let reader = BufReader::new(file);

        let mut id: Option<String> = None;
        let mut cwd: Option<String> = None;
        let mut git_branch: Option<String> = None;
        let mut model: Option<String> = None;
        let mut first_user: Option<String> = None;
        let (mut inp, mut outp, mut cache) = (0u64, 0u64, 0u64);
        let (mut msg_count, mut tool_count) = (0u32, 0u32);
        let mut first_ts = 0i64;
        let mut last_ts = 0i64;
        let mut messages: Vec<AgentMessage> = Vec::new();

        for line in reader.lines() {
            let Ok(line) = line else { continue };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Ok(v) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            let rtype = v.get("type").and_then(Value::as_str).unwrap_or("");
            let outer_ts = v
                .get("timestamp")
                .and_then(Value::as_str)
                .map(super::rfc3339_millis)
                .filter(|m| *m > 0);
            if let Some(ts) = outer_ts {
                last_ts = last_ts.max(ts);
            }
            let payload = v.get("payload");

            match rtype {
                "session_meta" => {
                    if let Some(p) = payload {
                        if id.is_none() {
                            id = p
                                .get("id")
                                .or_else(|| p.get("session_id"))
                                .and_then(Value::as_str)
                                .map(String::from);
                        }
                        if cwd.is_none() {
                            cwd = p.get("cwd").and_then(Value::as_str).map(String::from);
                        }
                        if git_branch.is_none() {
                            git_branch = p
                                .get("git")
                                .and_then(|g| g.get("branch"))
                                .and_then(Value::as_str)
                                .filter(|s| !s.is_empty())
                                .map(String::from);
                        }
                        if first_ts == 0 {
                            first_ts = p
                                .get("timestamp")
                                .and_then(Value::as_str)
                                .map(super::rfc3339_millis)
                                .filter(|m| *m > 0)
                                .or(outer_ts)
                                .unwrap_or(0);
                        }
                    }
                }
                "turn_context" => {
                    if let Some(m) = payload.and_then(|p| p.get("model")).and_then(Value::as_str) {
                        model = Some(m.to_string()); // last wins
                    }
                }
                "event_msg" => {
                    if let Some(p) = payload {
                        if p.get("type").and_then(Value::as_str) == Some("token_count") {
                            if let Some(info) = p.get("info").filter(|i| !i.is_null()) {
                                if let Some(t) = info.get("total_token_usage") {
                                    // Running totals — last non-null wins (overwrite).
                                    //
                                    // Codex follows the OpenAI convention where
                                    // `input_tokens` is the TOTAL prompt and
                                    // `cached_input_tokens` is a subset of it.
                                    // `AgentSession::input_tokens` means
                                    // non-cached input, so subtract. Without this
                                    // the cached portion is counted twice — once
                                    // at full price and again as cache — which
                                    // overstated a real history's estimated cost
                                    // by more than 10x.
                                    let total_in = t
                                        .get("input_tokens")
                                        .and_then(Value::as_u64)
                                        .unwrap_or(inp + cache);
                                    outp = t
                                        .get("output_tokens")
                                        .and_then(Value::as_u64)
                                        .unwrap_or(outp);
                                    cache = t
                                        .get("cached_input_tokens")
                                        .and_then(Value::as_u64)
                                        .unwrap_or(cache);
                                    inp = total_in.saturating_sub(cache);
                                }
                            }
                        }
                    }
                }
                "response_item" => {
                    if let Some(p) = payload {
                        let ptype = p.get("type").and_then(Value::as_str).unwrap_or("");
                        match ptype {
                            "message" => {
                                let role_s = p.get("role").and_then(Value::as_str).unwrap_or("");
                                if role_s == "developer" {
                                    continue; // instructions preamble, not a turn
                                }
                                msg_count += 1;
                                let role = if role_s == "assistant" {
                                    Role::Assistant
                                } else {
                                    Role::User
                                };
                                let text = extract_text(p.get("content"));
                                if !text.is_empty() {
                                    if first_user.is_none() && role == Role::User {
                                        first_user = Some(text.clone());
                                    }
                                    if with_messages {
                                        messages.push(AgentMessage {
                                            role,
                                            kind: MessageKind::Text,
                                            content: text,
                                            ts: outer_ts,
                                            tool_name: None,
                                        });
                                    }
                                }
                            }
                            "function_call"
                            | "custom_tool_call"
                            | "web_search_call"
                            | "tool_search_call"
                            | "image_generation_call" => {
                                tool_count += 1;
                                if with_messages {
                                    let name = p
                                        .get("name")
                                        .and_then(Value::as_str)
                                        .unwrap_or(ptype)
                                        .to_string();
                                    let args = p
                                        .get("arguments")
                                        .or_else(|| p.get("input"))
                                        .map(|a| match a {
                                            Value::String(s) => s.clone(),
                                            other => other.to_string(),
                                        })
                                        .unwrap_or_default();
                                    messages.push(AgentMessage {
                                        role: Role::Assistant,
                                        kind: MessageKind::ToolUse,
                                        content: super::claude_code::truncate(&args, 2000),
                                        ts: outer_ts,
                                        tool_name: Some(name),
                                    });
                                }
                            }
                            "reasoning" => {
                                if with_messages {
                                    if let Some(sum) = p
                                        .get("summary")
                                        .and_then(Value::as_array)
                                        .map(|a| {
                                            a.iter()
                                                .filter_map(|s| {
                                                    s.get("text").and_then(Value::as_str)
                                                })
                                                .collect::<Vec<_>>()
                                                .join("\n")
                                        })
                                        .filter(|s| !s.is_empty())
                                    {
                                        messages.push(AgentMessage {
                                            role: Role::Assistant,
                                            kind: MessageKind::Thinking,
                                            content: sum,
                                            ts: outer_ts,
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

        let id = id.unwrap_or_else(|| {
            // Fallback for rollouts without a session_meta record. The
            // filename is `rollout-<timestamp>-<uuid>`; the id is the
            // trailing uuid — keeping the timestamp prefix broke the
            // title-index join and produced non-uuid ids (G2 round-1
            // critic).
            let stem = path
                .file_stem()
                .map(|s| s.to_string_lossy().replace("rollout-", ""))
                .unwrap_or_default();
            match stem.len().checked_sub(36) {
                Some(cut)
                    if stem.is_char_boundary(cut)
                        && super::claude_code::looks_like_uuid(&stem[cut..]) =>
                {
                    stem[cut..].to_string()
                }
                _ => stem,
            }
        });
        if first_ts == 0 {
            first_ts = last_ts;
        }
        let title = titles
            .get(&id)
            .cloned()
            .or_else(|| first_user.map(|s| super::claude_code::truncate(&s, 80)));

        let session = AgentSession {
            id: AgentSession::make_id(AgentTool::Codex, &id),
            tool: AgentTool::Codex,
            title,
            project: cwd,
            git_branch,
            model,
            started_ts: first_ts,
            updated_ts: last_ts.max(first_ts),
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

impl Default for CodexReader {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentReader for CodexReader {
    fn tool(&self) -> AgentTool {
        AgentTool::Codex
    }
    fn is_present(&self) -> bool {
        self.base.is_dir()
    }
    fn list_sessions(&self) -> Vec<AgentSession> {
        let titles = self.title_index();
        self.rollouts()
            .into_iter()
            .take(MAX_LIST)
            // A finished rollout never changes, so unchanged files are answered
            // from the per-file cache instead of being re-read. Without this,
            // listing re-parsed every rollout on every page load.
            .filter_map(|p| {
                super::cached_file_parse(&p, |p| {
                    self.parse(p, &titles, false)
                        .map(|d| d.session)
                        .filter(|s| s.message_count > 0)
                })
            })
            .collect()
    }
    fn retention(&self) -> super::retention::RetentionPolicy {
        super::retention::RetentionPolicy::keeps_all(
            "Keeps rollouts indefinitely (older sessions may be compacted/archived).",
        )
    }
    fn source_fingerprint(&self) -> Option<u64> {
        Some(super::hash_files(self.rollouts().into_iter()))
    }
    fn session_detail(&self, raw_id: &str) -> Option<AgentSessionDetail> {
        let titles = self.title_index();
        let path = self
            .rollouts()
            .into_iter()
            .find(|p| p.to_string_lossy().contains(raw_id))?;
        self.parse(&path, &titles, true)
    }
}

/// Concatenate `content[].text` (Codex Responses-API content items).
fn extract_text(content: Option<&Value>) -> String {
    let Some(Value::Array(arr)) = content else {
        return String::new();
    };
    arr.iter()
        .filter_map(|c| c.get("text").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("")
}
