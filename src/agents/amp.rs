//! Amp adapter — reads Sourcegraph Amp's local thread files
//! (`~/.local/share/amp/threads/T-<uuid>.json`).
//!
//! Format verified from recovered original TypeScript in Amp's npm bundles
//! plus two independent working parsers (ccusage's Amp adapter, Block's
//! thread-manager-for-amp) — G2 round 9. One pretty-printed JSON per
//! thread, written atomically. Honest boundary: the local dir is a
//! cache/mirror — threads also live server-side at ampcode.com, and
//! pre-Nov-2025 threads may exist ONLY on the server; this adapter reads
//! what is on disk, nothing else.
//!
//! Thread shape: `{id: "T-…", v, created (millis), title?, messages[],
//! env.initial.trees[] (project identity), usageLedger}`. Messages are a
//! role union — `user` (content blocks + `meta.sentAt`), `assistant`
//! (Anthropic-style snake_case blocks `text`/`thinking`/`tool_use`, plus
//! per-message `usage` in camelCase: `inputTokens` EXCLUDES cache;
//! `cacheCreationInputTokens`/`cacheReadInputTokens` are separate), and
//! `info` (summary markers — skipped). Tool results ride user messages as
//! `tool_result` blocks whose `run.status`/`run.result` carry the outcome.
//!
//! Tolerant: an unparseable thread file is skipped, never fatal.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::{
    home, AgentMessage, AgentReader, AgentSession, AgentSessionDetail, AgentTool, MessageKind, Role,
};

/// Reads Amp's local thread store.
pub struct AmpReader {
    /// `~/.local/share/amp/threads`.
    threads: PathBuf,
}

impl AmpReader {
    /// Fixture seam: read an explicit threads dir. See
    /// `tests/agents_bench.rs`.
    pub fn with_root(threads_dir: PathBuf) -> Self {
        Self { threads: threads_dir }
    }

    /// `$AMP_DATA_DIR/threads` else `$XDG_DATA_HOME/amp/threads` else
    /// `~/.local/share/amp/threads`.
    pub fn new() -> Self {
        let data = std::env::var_os("AMP_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                std::env::var_os("XDG_DATA_HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| home().join(".local/share"))
                    .join("amp")
            });
        Self {
            threads: data.join("threads"),
        }
    }

    /// Every `T-*.json` thread file.
    fn thread_files(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let Ok(files) = fs::read_dir(&self.threads) else {
            return out;
        };
        for f in files.flatten() {
            let p = f.path();
            let name = f.file_name().to_string_lossy().to_string();
            if p.is_file() && name.starts_with("T-") && name.ends_with(".json") {
                out.push(p);
            }
        }
        out
    }

    fn parse(path: &Path, with_messages: bool) -> Option<AgentSessionDetail> {
        let text = fs::read_to_string(path).ok()?;
        let v: Value = serde_json::from_str(&text).ok()?;
        let raw_id = v.get("id").and_then(Value::as_str).map(String::from).or_else(|| {
            path.file_stem().map(|s| s.to_string_lossy().to_string())
        })?;
        let created = v.get("created").and_then(Value::as_i64).unwrap_or(0);
        let title = v
            .get("title")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(String::from);
        // Project identity: the first workspace tree. `file://` URIs decode
        // to plain paths; other schemes keep the display name.
        let project = v
            .get("env")
            .and_then(|e| e.get("initial"))
            .and_then(|i| i.get("trees"))
            .and_then(Value::as_array)
            .and_then(|trees| trees.first())
            .and_then(|t| {
                t.get("uri")
                    .and_then(Value::as_str)
                    .and_then(|u| u.strip_prefix("file://").map(String::from))
                    .or_else(|| {
                        t.get("displayName").and_then(Value::as_str).map(String::from)
                    })
            });

        let mut updated = created;
        let mut model: Option<String> = None;
        let (mut inp, mut outp, mut cache) = (0u64, 0u64, 0u64);
        let (mut msg_count, mut tool_count) = (0u32, 0u32);
        let mut first_user: Option<String> = None;
        let mut messages: Vec<AgentMessage> = Vec::new();

        for m in v
            .get("messages")
            .and_then(Value::as_array)
            .map(|a| a.as_slice())
            .unwrap_or_default()
        {
            let role_s = m.get("role").and_then(Value::as_str).unwrap_or("");
            let ts = m
                .get("meta")
                .and_then(|meta| meta.get("sentAt"))
                .and_then(Value::as_i64)
                .filter(|t| *t > 0);
            if let Some(t) = ts {
                updated = updated.max(t);
            }
            match role_s {
                "user" | "assistant" => {}
                _ => continue, // info / summary markers
            }
            let role = if role_s == "user" {
                Role::User
            } else {
                Role::Assistant
            };
            let mut counted = false;
            if role == Role::Assistant {
                if let Some(u) = m.get("usage") {
                    inp += u.get("inputTokens").and_then(Value::as_u64).unwrap_or(0);
                    outp += u.get("outputTokens").and_then(Value::as_u64).unwrap_or(0);
                    cache += u
                        .get("cacheCreationInputTokens")
                        .and_then(Value::as_u64)
                        .unwrap_or(0)
                        + u.get("cacheReadInputTokens")
                            .and_then(Value::as_u64)
                            .unwrap_or(0);
                    if let Some(mdl) = u.get("model").and_then(Value::as_str) {
                        model = Some(mdl.to_string()); // last wins
                    }
                }
            }
            for b in m
                .get("content")
                .and_then(Value::as_array)
                .map(|a| a.as_slice())
                .unwrap_or_default()
            {
                match b.get("type").and_then(Value::as_str).unwrap_or("") {
                    "text" => {
                        let t = b.get("text").and_then(Value::as_str).unwrap_or("");
                        if t.is_empty() {
                            continue;
                        }
                        if !counted {
                            msg_count += 1;
                            counted = true;
                        }
                        if role == Role::User && first_user.is_none() {
                            first_user = Some(t.to_string());
                        }
                        if with_messages {
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
                        if let Some(t) = b
                            .get("thinking")
                            .and_then(Value::as_str)
                            .filter(|s| !s.is_empty())
                        {
                            if with_messages {
                                messages.push(AgentMessage {
                                    role: Role::Assistant,
                                    kind: MessageKind::Thinking,
                                    content: t.to_string(),
                                    ts,
                                    tool_name: None,
                                });
                            }
                        }
                    }
                    "tool_use" => {
                        tool_count += 1;
                        if !counted {
                            msg_count += 1;
                            counted = true;
                        }
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
                            let out_text = b
                                .get("run")
                                .and_then(|r| r.get("result"))
                                .map(|r| match r.get("output").and_then(Value::as_str) {
                                    Some(s) => s.to_string(),
                                    None => r.to_string(),
                                })
                                .unwrap_or_default();
                            if !out_text.is_empty() {
                                messages.push(AgentMessage {
                                    role: Role::Tool,
                                    kind: MessageKind::ToolResult,
                                    content: super::claude_code::truncate(&out_text, 2000),
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
        if msg_count == 0 {
            return None;
        }
        let title = title.or_else(|| {
            first_user
                .as_deref()
                .map(|t| super::claude_code::truncate(t, 80))
        });
        let session = AgentSession {
            id: AgentSession::make_id(AgentTool::Amp, &raw_id),
            tool: AgentTool::Amp,
            title,
            project,
            git_branch: None,
            model,
            started_ts: created,
            updated_ts: updated.max(created),
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

impl Default for AmpReader {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentReader for AmpReader {
    fn tool(&self) -> AgentTool {
        AgentTool::Amp
    }
    fn is_present(&self) -> bool {
        self.threads.is_dir()
    }
    fn list_sessions(&self) -> Vec<AgentSession> {
        self.thread_files()
            .into_iter()
            .filter_map(|p| {
                super::cached_file_parse(&p, |p| Self::parse(p, false).map(|d| d.session))
            })
            .collect()
    }
    fn retention(&self) -> super::retention::RetentionPolicy {
        super::retention::RetentionPolicy::keeps_all(
            "Local thread mirror persists; ampcode.com holds the server copy.",
        )
    }
    fn source_fingerprint(&self) -> Option<u64> {
        Some(super::hash_files(self.thread_files().into_iter()))
    }
    fn session_detail(&self, raw_id: &str) -> Option<AgentSessionDetail> {
        let direct = self.threads.join(format!("{raw_id}.json"));
        if direct.is_file() {
            return Self::parse(&direct, true);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garbage_thread_files_are_skipped() {
        let dir = std::env::temp_dir().join(format!("saffev-amp-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("T-broken.json"), "{{{ not json").unwrap();
        std::fs::write(
            dir.join("T-ok.json"),
            r#"{"v":1,"id":"T-ok","created":1753660000000,"messages":[{"role":"user","messageId":0,"content":[{"type":"text","text":"hi"}],"meta":{"sentAt":1753660000123}},{"role":"assistant","messageId":1,"content":[{"type":"text","text":"hello"}],"state":{"type":"complete"},"usage":{"inputTokens":10,"outputTokens":5,"cacheCreationInputTokens":1,"cacheReadInputTokens":2,"model":"claude-sonnet-4-5"}}]}"#,
        )
        .unwrap();
        let reader = AmpReader::with_root(dir.clone());
        let sessions = reader.list_sessions();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].input_tokens, 10);
        assert_eq!(sessions[0].cache_tokens, 3);
        assert_eq!(sessions[0].model.as_deref(), Some("claude-sonnet-4-5"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
