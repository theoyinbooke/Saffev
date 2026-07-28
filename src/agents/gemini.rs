//! Gemini CLI adapter — reads `~/.gemini/tmp/<project>/chats/session-*.jsonl`.
//!
//! Format verified against google-gemini/gemini-cli source (G2 round 3;
//! `packages/core/src/services/chatRecordingService.ts` + `chatRecordingTypes.ts`):
//!
//! * **v0.39+ (current)** — append-only JSONL. First line is a metadata
//!   record (`sessionId`, `projectHash`, `startTime`, `lastUpdated`, `kind`);
//!   message lines are full `MessageRecord`s; `{"$set":{…}}` lines patch the
//!   metadata (a `$set` carrying `messages` is a CHECKPOINT that replaces the
//!   whole message map); `{"$rewindTo":"<messageId>"}` discards that message
//!   AND everything after it (inclusive — the target is the turn being
//!   redone). When a message mutates (tokens attach, tool result arrives) the
//!   WHOLE record is re-appended with the same `id` — readers dedupe by id,
//!   last write wins, original position kept. Summing tokens without that
//!   dedupe double-counts.
//! * **v0.4–v0.38 (legacy)** — the same `ConversationRecord` as one JSON
//!   object in `session-*.json` (rewritten whole on every update).
//!
//! Roles are `user` / `gemini` (not `assistant`); `info`/`error`/`warning`
//! records are UI noise, skipped. Tool calls are EMBEDDED in the gemini
//! message's `toolCalls` array. Tokens are per-message `usageMetadata`
//! mappings where `input` is the TOTAL prompt and `cached` a subset of it —
//! the same convention as Codex, so non-cached input = `input - cached`.
//! `thoughts` tokens are generated output (billed as output) and count there.
//!
//! Project resolution: each `tmp/<project>/` dir carries a `.project_root`
//! marker (v0.29+) holding the owning absolute path; older hash-named dirs
//! fall back to the metadata record's `directories[0]`. Subagent transcripts
//! (`chats/<parentSessionId>/*.jsonl`, `kind: "subagent"`) are side threads —
//! skipped, like Claude Code's `subagents/`.
//!
//! Tolerant: bad lines are skipped, never fatal.

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::{
    home, AgentMessage, AgentReader, AgentSession, AgentSessionDetail, AgentTool, MessageKind, Role,
};

/// Reads Gemini CLI's per-project chat transcripts.
pub struct GeminiReader {
    /// `~/.gemini/tmp`.
    tmp: PathBuf,
}

impl GeminiReader {
    /// Fixture seam: read from an explicit `tmp` dir. See
    /// `tests/agents_bench.rs`.
    pub fn with_root(tmp_dir: PathBuf) -> Self {
        Self { tmp: tmp_dir }
    }

    /// `~/.gemini/tmp`.
    pub fn new() -> Self {
        Self {
            tmp: home().join(".gemini").join("tmp"),
        }
    }

    /// Every main-session transcript: `tmp/<project>/chats/session-*.json[l]`.
    /// Returns `(file, project_dir)` so the caller can resolve the project.
    fn session_files(&self) -> Vec<(PathBuf, PathBuf)> {
        let mut out = Vec::new();
        let Ok(projects) = fs::read_dir(&self.tmp) else {
            return out;
        };
        for proj in projects.flatten() {
            let pdir = proj.path();
            let chats = pdir.join("chats");
            let Ok(files) = fs::read_dir(&chats) else {
                continue;
            };
            for f in files.flatten() {
                let p = f.path();
                // Files only — subdirectories hold subagent side threads.
                if !p.is_file() {
                    continue;
                }
                let name = f.file_name().to_string_lossy().to_string();
                let is_session = name.starts_with("session-")
                    && (name.ends_with(".jsonl") || name.ends_with(".json"));
                if !is_session {
                    continue;
                }
                // Resuming a legacy `.json` migrates it by appending `l` to
                // the FILENAME (`x.json` → `x.jsonl`, same stem). If the
                // migrated twin exists, the `.json` is superseded — listing
                // both would double-count the session (G2 round-3 critic).
                if name.ends_with(".json") && p.with_extension("jsonl").is_file() {
                    continue;
                }
                out.push((p, pdir.clone()));
            }
        }
        out
    }

    /// The `.project_root` marker written by v0.29+ — the owning project's
    /// absolute path.
    fn project_for(project_dir: &Path) -> Option<String> {
        let text = fs::read_to_string(project_dir.join(".project_root")).ok()?;
        let t = text.trim();
        (!t.is_empty()).then(|| t.to_string())
    }

    /// Parse one transcript (either generation). `with_messages` toggles
    /// building the full transcript.
    fn parse(path: &Path, project_dir: &Path, with_messages: bool) -> Option<AgentSessionDetail> {
        // Replayed message log: order of first appearance, dedupe by id with
        // last-write-wins (the file re-appends a whole record on mutation).
        let mut order: Vec<String> = Vec::new();
        let mut by_id: HashMap<String, Value> = HashMap::new();
        let mut session_id: Option<String> = None;
        let mut start_ts = 0i64;
        let mut updated_ts = 0i64;
        let mut summary: Option<String> = None;

        let absorb_meta = |v: &Value, start: &mut i64, updated: &mut i64| {
            if let Some(s) = v.get("startTime").and_then(Value::as_str) {
                let ms = super::rfc3339_millis(s);
                if ms > 0 {
                    *start = ms;
                }
            }
            if let Some(s) = v.get("lastUpdated").and_then(Value::as_str) {
                let ms = super::rfc3339_millis(s);
                if ms > 0 {
                    *updated = (*updated).max(ms);
                }
            }
        };

        if path.extension().is_some_and(|e| e == "jsonl") {
            let file = fs::File::open(path).ok()?;
            for line in BufReader::new(file).lines() {
                let Ok(line) = line else { continue };
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let Ok(v) = serde_json::from_str::<Value>(line) else {
                    continue; // tolerate truncated/garbage lines
                };
                if let Some(set) = v.get("$set") {
                    absorb_meta(set, &mut start_ts, &mut updated_ts);
                    if let Some(s) = set.get("summary").and_then(Value::as_str) {
                        summary = Some(s.to_string());
                    }
                    // A `$set` carrying a `messages` array is a CHECKPOINT:
                    // the real reader clears and rebuilds the message map
                    // from it (G2 round-3 critic — keeping pre-checkpoint
                    // messages over-counts turns and tokens).
                    if let Some(msgs) = set.get("messages").and_then(Value::as_array) {
                        order.clear();
                        by_id.clear();
                        for m in msgs {
                            if let Some(id) = m.get("id").and_then(Value::as_str) {
                                if !by_id.contains_key(id) {
                                    order.push(id.to_string());
                                }
                                by_id.insert(id.to_string(), m.clone());
                            }
                        }
                    }
                    continue;
                }
                if let Some(target) = v.get("$rewindTo").and_then(Value::as_str) {
                    // INCLUSIVE: the real source removes "all messages from
                    // (and including) the specified ID" — the target is the
                    // message being redone (G2 round-3 critic; the first cut
                    // kept it and over-counted a turn per rewind).
                    if let Some(pos) = order.iter().position(|id| id == target) {
                        for dropped in order.drain(pos..) {
                            by_id.remove(&dropped);
                        }
                    }
                    continue;
                }
                if let Some(id) = v.get("id").and_then(Value::as_str) {
                    // Message record — upsert, keep first-appearance order.
                    if !by_id.contains_key(id) {
                        order.push(id.to_string());
                    }
                    by_id.insert(id.to_string(), v);
                    continue;
                }
                // Metadata record — the real `isPartialMetadataRecord`
                // requires BOTH sessionId and projectHash, and the CLI reads
                // first-line metadata: first wins, later imposters don't
                // rewrite the session identity (G2 round-3 critic).
                if v.get("sessionId").is_some() && v.get("projectHash").is_some() {
                    if session_id.is_none() {
                        session_id = v
                            .get("sessionId")
                            .and_then(Value::as_str)
                            .map(String::from);
                        absorb_meta(&v, &mut start_ts, &mut updated_ts);
                    } else {
                        // Still absorb a later lastUpdated (monotonic max).
                        let mut ignored_start = start_ts;
                        absorb_meta(&v, &mut ignored_start, &mut updated_ts);
                    }
                }
            }
        } else {
            // Legacy single-JSON ConversationRecord.
            let text = fs::read_to_string(path).ok()?;
            let v: Value = serde_json::from_str(&text).ok()?;
            session_id = v.get("sessionId").and_then(Value::as_str).map(String::from);
            absorb_meta(&v, &mut start_ts, &mut updated_ts);
            if let Some(s) = v.get("summary").and_then(Value::as_str) {
                summary = Some(s.to_string());
            }
            if let Some(msgs) = v.get("messages").and_then(Value::as_array) {
                for (i, m) in msgs.iter().enumerate() {
                    let id = m
                        .get("id")
                        .and_then(Value::as_str)
                        .map(String::from)
                        .unwrap_or_else(|| format!("legacy-{i}"));
                    if !by_id.contains_key(&id) {
                        order.push(id.clone());
                    }
                    by_id.insert(id, m.clone());
                }
            }
        }

        // Aggregate the FINAL (deduped, rewound) message set.
        let mut first_user: Option<String> = None;
        // (count, last-seen order) per model — the tie-break must be
        // deterministic (a bare HashMap max flapped between runs; G2
        // round-3 critic), and recency is the sensible tie-winner.
        let mut model_counts: HashMap<String, (u32, usize)> = HashMap::new();
        let mut model_seq = 0usize;
        let (mut inp, mut outp, mut cache) = (0u64, 0u64, 0u64);
        let (mut msg_count, mut tool_count) = (0u32, 0u32);
        let mut messages: Vec<AgentMessage> = Vec::new();

        for id in &order {
            let Some(m) = by_id.get(id) else { continue };
            let mtype = m.get("type").and_then(Value::as_str).unwrap_or("");
            let ts = m
                .get("timestamp")
                .and_then(Value::as_str)
                .map(super::rfc3339_millis)
                .filter(|ms| *ms > 0);
            if let Some(t) = ts {
                if start_ts == 0 {
                    start_ts = t;
                }
                updated_ts = updated_ts.max(t);
            }
            match mtype {
                "user" => {
                    msg_count += 1;
                    let text = extract_text(m.get("content"));
                    if first_user.is_none() && !text.is_empty() {
                        first_user = Some(text.clone());
                    }
                    if with_messages && !text.is_empty() {
                        messages.push(AgentMessage {
                            role: Role::User,
                            kind: MessageKind::Text,
                            content: text,
                            ts,
                            tool_name: None,
                        });
                    }
                }
                "gemini" => {
                    msg_count += 1;
                    if let Some(model) = m.get("model").and_then(Value::as_str) {
                        model_seq += 1;
                        let e = model_counts.entry(model.to_string()).or_insert((0, 0));
                        e.0 += 1;
                        e.1 = model_seq;
                    }
                    if let Some(t) = m.get("tokens").filter(|t| !t.is_null()) {
                        // Gemini's `input` is the TOTAL prompt; `cached` is a
                        // subset of it (Codex convention — counting both
                        // double-bills the cached portion). `tool` tokens
                        // (toolUsePromptTokenCount) are prompt-side and NOT
                        // included in `input` — they count as input.
                        // `thoughts` are generated tokens, billed as output.
                        let total_in = t.get("input").and_then(Value::as_u64).unwrap_or(0);
                        let cached = t.get("cached").and_then(Value::as_u64).unwrap_or(0);
                        inp += total_in.saturating_sub(cached)
                            + t.get("tool").and_then(Value::as_u64).unwrap_or(0);
                        cache += cached;
                        outp += t.get("output").and_then(Value::as_u64).unwrap_or(0)
                            + t.get("thoughts").and_then(Value::as_u64).unwrap_or(0);
                    }
                    if with_messages {
                        for th in m
                            .get("thoughts")
                            .and_then(Value::as_array)
                            .map(|a| a.as_slice())
                            .unwrap_or_default()
                        {
                            let subject = th.get("subject").and_then(Value::as_str).unwrap_or("");
                            let desc = th.get("description").and_then(Value::as_str).unwrap_or("");
                            let text = match (subject.is_empty(), desc.is_empty()) {
                                (false, false) => format!("{subject}: {desc}"),
                                (false, true) => subject.to_string(),
                                _ => desc.to_string(),
                            };
                            if !text.is_empty() {
                                messages.push(AgentMessage {
                                    role: Role::Assistant,
                                    kind: MessageKind::Thinking,
                                    content: text,
                                    ts,
                                    tool_name: None,
                                });
                            }
                        }
                    }
                    let text = extract_text(m.get("content"));
                    if with_messages && !text.is_empty() {
                        messages.push(AgentMessage {
                            role: Role::Assistant,
                            kind: MessageKind::Text,
                            content: text,
                            ts,
                            tool_name: None,
                        });
                    }
                    for tc in m
                        .get("toolCalls")
                        .and_then(Value::as_array)
                        .map(|a| a.as_slice())
                        .unwrap_or_default()
                    {
                        tool_count += 1;
                        if with_messages {
                            let name = tc
                                .get("name")
                                .and_then(Value::as_str)
                                .unwrap_or("tool")
                                .to_string();
                            let args = tc
                                .get("args")
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
                // info / error / warning — UI noise records, not turns.
                _ => {}
            }
        }
        if msg_count == 0 {
            // A metadata-only or fully-garbage file is not a session.
            if session_id.is_none() {
                return None;
            }
        }

        let raw_id = session_id.unwrap_or_else(|| {
            path.file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default()
        });
        let model = model_counts
            .into_iter()
            .max_by_key(|(_, (n, last))| (*n, *last))
            .map(|(m, _)| m);
        let title = summary
            .or_else(|| first_user.map(|t| super::claude_code::truncate(&t, 80)));
        let session = AgentSession {
            id: AgentSession::make_id(AgentTool::Gemini, &raw_id),
            tool: AgentTool::Gemini,
            title,
            project: Self::project_for(project_dir),
            git_branch: None,
            model,
            started_ts: start_ts,
            updated_ts: updated_ts.max(start_ts),
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

impl Default for GeminiReader {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentReader for GeminiReader {
    fn tool(&self) -> AgentTool {
        AgentTool::Gemini
    }
    fn is_present(&self) -> bool {
        self.tmp.is_dir()
    }
    fn list_sessions(&self) -> Vec<AgentSession> {
        self.session_files()
            .into_iter()
            .filter_map(|(p, pdir)| {
                super::cached_file_parse(&p, |p| {
                    Self::parse(p, &pdir, false)
                        .map(|d| d.session)
                        .filter(|s| s.message_count > 0)
                })
            })
            .collect()
    }
    fn retention(&self) -> super::retention::RetentionPolicy {
        // Transcripts live under a dir literally named `tmp/`; the CLI keeps
        // them across sessions but documents no retention contract.
        super::retention::RetentionPolicy::unknown()
    }
    fn source_fingerprint(&self) -> Option<u64> {
        Some(super::hash_files(
            self.session_files().into_iter().map(|(p, _)| p),
        ))
    }
    fn session_detail(&self, raw_id: &str) -> Option<AgentSessionDetail> {
        // Session files embed the id in the metadata record, and (for the
        // jsonl era) the first 8 chars in the filename. Cheapest correct
        // route: find the file whose parse yields the id.
        for (p, pdir) in self.session_files() {
            let name = p.file_name().map(|n| n.to_string_lossy().to_string());
            let quick_match = raw_id
                .get(..8)
                .zip(name.as_deref())
                .is_some_and(|(prefix, n)| n.contains(prefix));
            if quick_match {
                if let Some(d) = Self::parse(&p, &pdir, true) {
                    if d.session.id.ends_with(raw_id) {
                        return Some(d);
                    }
                }
            }
        }
        // Fallback: full scan (legacy files whose stem differs from the id).
        for (p, pdir) in self.session_files() {
            if let Some(d) = Self::parse(&p, &pdir, true) {
                if d.session.id.ends_with(raw_id) {
                    return Some(d);
                }
            }
        }
        None
    }
}

/// Extract text from a genai `PartListUnion`: `string | Part | Part[]`.
fn extract_text(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(parts)) => parts
            .iter()
            .filter_map(|p| p.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join(""),
        Some(Value::Object(o)) => o
            .get("text")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reappended_messages_dedupe_by_id_last_wins() {
        // The service re-appends the WHOLE record when tokens attach — a
        // reader that sums without deduping double-counts.
        let dir = std::env::temp_dir().join(format!("saffev-gem-{}", uuid::Uuid::new_v4()));
        let chats = dir.join("proj/chats");
        std::fs::create_dir_all(&chats).unwrap();
        std::fs::write(dir.join("proj/.project_root"), "/home/dev/p\n").unwrap();
        let p = chats.join("session-2026-07-28T09-15-11112222.jsonl");
        let lines = [
            r#"{"sessionId":"11112222-aaaa-4bbb-8ccc-000000000007","projectHash":"deadbeef","startTime":"2026-07-28T09:15:02.481Z","lastUpdated":"2026-07-28T09:15:02.481Z","kind":"main"}"#,
            r#"{"id":"m1","timestamp":"2026-07-28T09:15:02.501Z","type":"user","content":[{"text":"hello"}]}"#,
            // First append: no tokens yet.
            r#"{"id":"m2","timestamp":"2026-07-28T09:15:04.120Z","type":"gemini","content":"hi there","model":"gemini-2.5-pro"}"#,
            // Re-append, same id, now with tokens.
            r#"{"id":"m2","timestamp":"2026-07-28T09:15:04.120Z","type":"gemini","content":"hi there","model":"gemini-2.5-pro","tokens":{"input":2113,"output":38,"cached":1536,"thoughts":95,"total":2246}}"#,
            r#"{"$set":{"lastUpdated":"2026-07-28T09:15:06.010Z"}}"#,
        ];
        std::fs::write(&p, lines.join("\n")).unwrap();

        let d = GeminiReader::parse(&p, &dir.join("proj"), true).expect("parses");
        assert_eq!(d.session.message_count, 2, "re-append must not add a turn");
        // input is total prompt; non-cached = 2113 - 1536.
        assert_eq!(d.session.input_tokens, 577);
        assert_eq!(d.session.cache_tokens, 1536);
        // thoughts are generated tokens: 38 + 95.
        assert_eq!(d.session.output_tokens, 133);
        assert_eq!(d.session.project.as_deref(), Some("/home/dev/p"));
        assert_eq!(
            d.session.updated_ts,
            super::super::rfc3339_millis("2026-07-28T09:15:06.010Z")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rewind_is_inclusive_of_its_target() {
        // Real semantics (chatRecordingService.ts): "All messages from (and
        // including) the specified ID onwards are removed" — the target is
        // the turn being redone (G2 round-3 critic caught the exclusive
        // first cut).
        let dir = std::env::temp_dir().join(format!("saffev-gem-{}", uuid::Uuid::new_v4()));
        let chats = dir.join("proj/chats");
        std::fs::create_dir_all(&chats).unwrap();
        let p = chats.join("session-2026-07-28T10-00-22223333.jsonl");
        let lines = [
            r#"{"sessionId":"22223333-aaaa-4bbb-8ccc-000000000008","projectHash":"d","startTime":"2026-07-28T10:00:00.000Z","lastUpdated":"2026-07-28T10:00:00.000Z"}"#,
            r#"{"id":"m1","timestamp":"2026-07-28T10:00:01.000Z","type":"user","content":"first"}"#,
            // A TOKENED gemini turn that the rewind must also un-count.
            r#"{"id":"m2","timestamp":"2026-07-28T10:00:02.000Z","type":"gemini","content":"answer one","model":"gemini-2.5-flash","tokens":{"input":1000,"output":50,"cached":0,"total":1050}}"#,
            r#"{"id":"m3","timestamp":"2026-07-28T10:00:03.000Z","type":"user","content":"abandoned turn"}"#,
            r#"{"$rewindTo":"m2"}"#,
            r#"{"id":"m4","timestamp":"2026-07-28T10:00:05.000Z","type":"user","content":"second try"}"#,
        ];
        std::fs::write(&p, lines.join("\n")).unwrap();
        let d = GeminiReader::parse(&p, &dir.join("proj"), true).expect("parses");
        assert_eq!(d.session.message_count, 2, "target turn must be rewound too");
        assert_eq!(d.session.input_tokens, 0, "rewound tokens must not count");
        assert!(!d.messages.iter().any(|m| m.content == "answer one"));
        assert!(!d.messages.iter().any(|m| m.content == "abandoned turn"));
        assert!(d.messages.iter().any(|m| m.content == "second try"));
        // A rewind to a ghost id is a no-op, never fatal.
        std::fs::write(&p, format!("{}\n{{\"$rewindTo\":\"ghost\"}}", lines.join("\n"))).unwrap();
        assert!(GeminiReader::parse(&p, &dir.join("proj"), false).is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn set_messages_is_a_checkpoint_that_replaces_history() {
        // A $set carrying `messages` rebuilds the map from scratch — keeping
        // pre-checkpoint turns over-counts (G2 round-3 critic).
        let dir = std::env::temp_dir().join(format!("saffev-gem-{}", uuid::Uuid::new_v4()));
        let chats = dir.join("proj/chats");
        std::fs::create_dir_all(&chats).unwrap();
        let p = chats.join("session-2026-07-28T11-00-44445555.jsonl");
        let lines = [
            r#"{"sessionId":"44445555-aaaa-4bbb-8ccc-000000000010","projectHash":"d","startTime":"2026-07-28T11:00:00.000Z","lastUpdated":"2026-07-28T11:00:00.000Z"}"#,
            r#"{"id":"old1","timestamp":"2026-07-28T11:00:01.000Z","type":"user","content":"pre-checkpoint"}"#,
            r#"{"id":"old2","timestamp":"2026-07-28T11:00:02.000Z","type":"gemini","content":"pre","model":"gemini-2.5-pro","tokens":{"input":500,"output":10,"cached":0,"total":510}}"#,
            r#"{"$set":{"messages":[{"id":"new1","timestamp":"2026-07-28T11:00:03.000Z","type":"user","content":"post-checkpoint"}]}}"#,
        ];
        std::fs::write(&p, lines.join("\n")).unwrap();
        let d = GeminiReader::parse(&p, &dir.join("proj"), true).expect("parses");
        assert_eq!(d.session.message_count, 1);
        assert_eq!(d.session.input_tokens, 0, "pre-checkpoint tokens must not count");
        assert!(d.messages.iter().any(|m| m.content == "post-checkpoint"));
        assert!(!d.messages.iter().any(|m| m.content == "pre-checkpoint"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn metadata_is_first_wins_and_model_ties_break_by_recency() {
        let dir = std::env::temp_dir().join(format!("saffev-gem-{}", uuid::Uuid::new_v4()));
        let chats = dir.join("proj/chats");
        std::fs::create_dir_all(&chats).unwrap();
        let p = chats.join("session-2026-07-28T12-00-66667777.jsonl");
        let lines = [
            r#"{"sessionId":"66667777-aaaa-4bbb-8ccc-000000000011","projectHash":"d","startTime":"2026-07-28T12:00:00.000Z","lastUpdated":"2026-07-28T12:00:00.000Z"}"#,
            // A later sessionId-bearing imposter must not rewrite identity.
            r#"{"sessionId":"eeeeffff-0000-4000-8000-000000000099","projectHash":"x","startTime":"2020-01-01T00:00:00.000Z","lastUpdated":"2026-07-28T12:09:00.000Z"}"#,
            r#"{"id":"m1","timestamp":"2026-07-28T12:00:01.000Z","type":"user","content":"q1"}"#,
            r#"{"id":"m2","timestamp":"2026-07-28T12:00:02.000Z","type":"gemini","content":"a1","model":"gemini-2.5-flash"}"#,
            r#"{"id":"m3","timestamp":"2026-07-28T12:00:03.000Z","type":"gemini","content":"a2","model":"gemini-2.5-pro"}"#,
        ];
        std::fs::write(&p, lines.join("\n")).unwrap();
        let d = GeminiReader::parse(&p, &dir.join("proj"), false).expect("parses");
        assert!(d.session.id.ends_with("000000000011"), "identity is first-wins");
        assert_eq!(
            d.session.started_ts,
            super::super::rfc3339_millis("2026-07-28T12:00:00.000Z")
        );
        // 1-vs-1 model tie: recency wins, deterministically.
        assert_eq!(d.session.model.as_deref(), Some("gemini-2.5-pro"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn migrated_legacy_twin_is_not_double_listed() {
        // Resuming a legacy .json appends 'l' to the filename; both files
        // then exist for one sessionId — only the .jsonl must list.
        let dir = std::env::temp_dir().join(format!("saffev-gem-{}", uuid::Uuid::new_v4()));
        let chats = dir.join("proj/chats");
        std::fs::create_dir_all(&chats).unwrap();
        let meta = r#"{"sessionId":"88889999-aaaa-4bbb-8ccc-000000000012","projectHash":"d","startTime":"2026-07-28T13:00:00.000Z","lastUpdated":"2026-07-28T13:00:00.000Z"}"#;
        let msg = r#"{"id":"m1","timestamp":"2026-07-28T13:00:01.000Z","type":"user","content":"hi"}"#;
        std::fs::write(
            chats.join("session-2026-07-28T13-00-88889999.json"),
            r#"{"sessionId":"88889999-aaaa-4bbb-8ccc-000000000012","projectHash":"d","startTime":"2026-07-28T13:00:00.000Z","lastUpdated":"2026-07-28T13:00:00.000Z","messages":[{"id":"m1","timestamp":"2026-07-28T13:00:01.000Z","type":"user","content":"hi"}]}"#,
        )
        .unwrap();
        std::fs::write(
            chats.join("session-2026-07-28T13-00-88889999.jsonl"),
            format!("{meta}\n{msg}"),
        )
        .unwrap();
        let reader = GeminiReader::with_root(dir.clone());
        let sessions = reader.list_sessions();
        assert_eq!(sessions.len(), 1, "migration twin double-listed");
        assert!(sessions[0].source_path.ends_with(".jsonl"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn legacy_single_json_parses() {
        let dir = std::env::temp_dir().join(format!("saffev-gem-{}", uuid::Uuid::new_v4()));
        let chats = dir.join("proj/chats");
        std::fs::create_dir_all(&chats).unwrap();
        let p = chats.join("session-2026-01-10T12-00-33334444.json");
        std::fs::write(&p, r#"{"sessionId":"33334444-aaaa-4bbb-8ccc-000000000009","projectHash":"beef","startTime":"2026-01-10T12:00:00.000Z","lastUpdated":"2026-01-10T12:05:00.000Z","messages":[{"id":"a","timestamp":"2026-01-10T12:00:01.000Z","type":"user","content":"old format"},{"id":"b","timestamp":"2026-01-10T12:00:05.000Z","type":"gemini","content":"still readable","model":"gemini-2.0-pro","tokens":{"input":100,"output":20,"cached":0,"total":120}}]}"#).unwrap();
        let d = GeminiReader::parse(&p, &dir.join("proj"), true).expect("parses");
        assert_eq!(d.session.message_count, 2);
        assert_eq!(d.session.model.as_deref(), Some("gemini-2.0-pro"));
        assert_eq!(d.session.input_tokens, 100);
        // No .project_root marker → project honestly absent.
        assert!(d.session.project.is_none());
        std::fs::remove_dir_all(&dir).ok();
    }
}
