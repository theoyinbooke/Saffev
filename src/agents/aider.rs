//! Aider adapter — reads per-project `.aider.chat.history.md` transcripts.
//!
//! Aider has NO central session store (G2 round 7; verified against
//! Aider-AI/aider source at v0.86.x — `io.py` history writers, `args.py`
//! defaults, `utils.split_chat_history_markdown`): the markdown transcript
//! is appended at each project's git root. This adapter therefore differs
//! from every other reader in HOW it discovers data: a bounded walk under
//! the home directory (depth-capped, hidden/system/build dirs skipped,
//! total-dirs capped) looking for `.aider.chat.history.md`. The measurement
//! boundary is honest: projects outside the walk are not found.
//!
//! Parsing follows aider's OWN round-trip rules (`split_chat_history_markdown`,
//! used by `--restore-chat-history`):
//! * `# aider chat started at YYYY-MM-DD HH:MM:SS` — session delimiter
//!   (one per aider launch; second resolution, LOCAL time, no zone — treated
//!   as UTC, so absolute times are offset by the machine's zone).
//! * `#### ` prefix — user input (multiline input = consecutive `#### ` lines).
//! * `> ` prefix — tool/announcement output: `> Model: X with …` carries the
//!   model; `> Tokens: 4.2k sent, 312 received.` carries usage (counts are
//!   K-ROUNDED above 1000 by aider itself — irrecoverably lossy, recorded as
//!   approximate); `> Applied edit to <file>` is an edit event (the closest
//!   thing to a tool call this format has).
//! * everything else — assistant markdown, verbatim.
//!
//! Honest field notes: sessions have NO id on disk (synthesized from
//! project + header timestamp + occurrence index — stable across reads);
//! there are NO per-message timestamps (messages inherit the session
//! header); cache tokens are never reported. Tolerant: any unrecognized
//! line is just assistant text — nothing is fatal by construction.

use std::fs;
use std::path::{Path, PathBuf};

use super::{
    home, AgentMessage, AgentReader, AgentSession, AgentSessionDetail, AgentTool, MessageKind, Role,
};

/// Session delimiter prefix (verbatim from `io.py`).
const SESSION_HEADER: &str = "# aider chat started at ";
/// Bounded-walk caps: depth below each root, total directories visited.
const MAX_DEPTH: u8 = 4;
const MAX_DIRS: usize = 20_000;

/// Reads Aider's per-project markdown transcripts.
pub struct AiderReader {
    /// Directories to walk for `.aider.chat.history.md` files.
    roots: Vec<PathBuf>,
}

impl AiderReader {
    /// Fixture seam: walk explicit roots. See `tests/agents_bench.rs`.
    pub fn with_roots(roots: Vec<PathBuf>) -> Self {
        Self { roots }
    }

    /// Default: bounded walk under the home directory.
    pub fn new() -> Self {
        Self { roots: vec![home()] }
    }

    /// All `.aider.chat.history.md` files under the roots (bounded walk).
    fn history_files(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut visited = 0usize;
        for root in &self.roots {
            walk(root, 0, &mut visited, &mut out);
        }
        out
    }

    /// Parse one project's transcript into its sessions. `detail_for` picks
    /// one session index for full messages (None = summaries only).
    fn parse(path: &Path, detail_for: Option<usize>) -> Vec<AgentSessionDetail> {
        let Ok(text) = fs::read_to_string(path) else {
            return Vec::new();
        };
        let project = path
            .parent()
            .map(|p| p.to_string_lossy().to_string());
        let file_mtime = fs::metadata(path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);

        // Split into sessions on the header line.
        let mut sessions: Vec<(i64, Vec<&str>)> = Vec::new();
        for line in text.lines() {
            if let Some(stamp) = line.strip_prefix(SESSION_HEADER) {
                sessions.push((header_millis(stamp.trim()), Vec::new()));
                continue;
            }
            if let Some((_, lines)) = sessions.last_mut() {
                lines.push(line);
            }
            // Content before any header (torn file) is skipped — no session
            // context to attach it to.
        }

        let count = sessions.len();
        let mut out = Vec::new();
        for (idx, (start_ts, lines)) in sessions.iter().enumerate() {
            let with_messages = detail_for == Some(idx);
            // A session's end is the next session's start; the last session
            // ends at the file's mtime.
            let updated_ts = sessions
                .get(idx + 1)
                .map(|(next, _)| *next)
                .unwrap_or(file_mtime)
                .max(*start_ts);

            let mut title: Option<String> = None;
            let mut model: Option<String> = None;
            let (mut inp, mut outp) = (0u64, 0u64);
            let mut lossy_tokens = false;
            let (mut msg_count, mut tool_count) = (0u32, 0u32);
            let mut messages: Vec<AgentMessage> = Vec::new();
            // Accumulators for multi-line user / assistant blocks.
            let mut user_buf: Vec<String> = Vec::new();
            let mut asst_buf: Vec<String> = Vec::new();

            let flush_user = |buf: &mut Vec<String>,
                              msgs: &mut Vec<AgentMessage>,
                              count: &mut u32,
                              title: &mut Option<String>,
                              with_messages: bool,
                              ts: i64| {
                if buf.is_empty() {
                    return;
                }
                let text = buf.join("\n");
                buf.clear();
                if text.trim().is_empty() || text.trim() == "<blank>" {
                    return;
                }
                *count += 1;
                if title.is_none() {
                    *title = Some(super::claude_code::truncate(text.trim(), 80));
                }
                if with_messages {
                    msgs.push(AgentMessage {
                        role: Role::User,
                        kind: MessageKind::Text,
                        content: text,
                        ts: Some(ts),
                        tool_name: None,
                    });
                }
            };
            let flush_asst = |buf: &mut Vec<String>,
                              msgs: &mut Vec<AgentMessage>,
                              count: &mut u32,
                              with_messages: bool,
                              ts: i64| {
                if buf.is_empty() {
                    return;
                }
                let text = buf.join("\n").trim().to_string();
                buf.clear();
                if text.is_empty() {
                    return;
                }
                *count += 1;
                if with_messages {
                    msgs.push(AgentMessage {
                        role: Role::Assistant,
                        kind: MessageKind::Text,
                        content: text,
                        ts: Some(ts),
                        tool_name: None,
                    });
                }
            };

            for line in lines {
                if let Some(user) = line.strip_prefix("#### ") {
                    flush_asst(&mut asst_buf, &mut messages, &mut msg_count, with_messages, *start_ts);
                    // Markdown hard-break continuation of multi-line input.
                    user_buf.push(user.trim_end_matches("  ").to_string());
                } else if let Some(tool) = line.strip_prefix("> ") {
                    flush_user(&mut user_buf, &mut messages, &mut msg_count, &mut title, with_messages, *start_ts);
                    flush_asst(&mut asst_buf, &mut messages, &mut msg_count, with_messages, *start_ts);
                    let tool = tool.trim_end();
                    // Model announcements: `Model: X with …` / `Main model: X …`.
                    if let Some(rest) = tool
                        .strip_prefix("Model: ")
                        .or_else(|| tool.strip_prefix("Main model: "))
                    {
                        let name = rest
                            .split(" with ")
                            .next()
                            .unwrap_or(rest)
                            .split(',')
                            .next()
                            .unwrap_or(rest)
                            .trim();
                        if !name.is_empty() {
                            model = Some(name.to_string()); // last wins (/model switches)
                        }
                    } else if let Some(rest) = tool.strip_prefix("Tokens: ") {
                        // `Tokens: 4.2k sent, 312 received.` — k-rounded.
                        if let Some((sent, recv)) = parse_tokens_line(rest) {
                            inp += sent;
                            outp += recv;
                            if rest.contains('k') {
                                lossy_tokens = true;
                            }
                        }
                    } else if let Some(file) = tool.strip_prefix("Applied edit to ") {
                        tool_count += 1;
                        if with_messages {
                            messages.push(AgentMessage {
                                role: Role::Tool,
                                kind: MessageKind::ToolUse,
                                content: file.trim().to_string(),
                                ts: Some(*start_ts),
                                tool_name: Some("apply_edit".into()),
                            });
                        }
                    }
                    // Other announcements (repo, costs, commits) are noise.
                } else if line.starts_with("# ") {
                    // A stray heading (aider's own parser skips these).
                    flush_user(&mut user_buf, &mut messages, &mut msg_count, &mut title, with_messages, *start_ts);
                    flush_asst(&mut asst_buf, &mut messages, &mut msg_count, with_messages, *start_ts);
                } else {
                    flush_user(&mut user_buf, &mut messages, &mut msg_count, &mut title, with_messages, *start_ts);
                    asst_buf.push((*line).to_string());
                }
            }
            flush_user(&mut user_buf, &mut messages, &mut msg_count, &mut title, with_messages, *start_ts);
            flush_asst(&mut asst_buf, &mut messages, &mut msg_count, with_messages, *start_ts);

            if msg_count == 0 {
                continue; // header with no content — not a session
            }

            // Synthesized, stable id: project dir name + header stamp + index
            // (no id exists on disk — documented limitation).
            let proj_slug = path
                .parent()
                .and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "project".into());
            let raw_id = format!("{proj_slug}:{start_ts}:{idx}");
            let mut session = AgentSession {
                id: AgentSession::make_id(AgentTool::Aider, &raw_id),
                tool: AgentTool::Aider,
                title,
                project: project.clone(),
                git_branch: None,
                model,
                started_ts: *start_ts,
                updated_ts,
                message_count: msg_count,
                tool_call_count: tool_count,
                input_tokens: inp,
                output_tokens: outp,
                cache_tokens: 0, // never reported by the format
                source_path: path.to_string_lossy().to_string(),
            };
            let _ = count;
            if lossy_tokens {
                // The k-rounding is the format's, not ours; the coverage
                // table carries the note. Nothing to store per-session.
            }
            if session.updated_ts < session.started_ts {
                session.updated_ts = session.started_ts;
            }
            out.push(AgentSessionDetail { session, messages });
        }
        out
    }
}

/// Bounded directory walk: hidden dirs, VCS internals, and dependency/build
/// trees are skipped; depth and total-dirs capped.
fn walk(dir: &Path, depth: u8, visited: &mut usize, out: &mut Vec<PathBuf>) {
    if depth > MAX_DEPTH || *visited >= MAX_DIRS {
        return;
    }
    *visited += 1;
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        if p.is_dir() {
            if name.starts_with('.')
                || matches!(
                    name.as_str(),
                    "node_modules" | "target" | "dist" | "build" | "venv" | "__pycache__"
                        | "Library" | "AppData" | "snap"
                )
            {
                continue;
            }
            walk(&p, depth + 1, visited, out);
        } else if name == ".aider.chat.history.md" {
            out.push(p);
        }
    }
}

/// `YYYY-MM-DD HH:MM:SS` (local, no zone) → millis, treated as UTC.
fn header_millis(stamp: &str) -> i64 {
    let iso = stamp.replacen(' ', "T", 1) + "Z";
    super::rfc3339_millis(&iso)
}

/// Parse `4.2k sent, 312 received. Cost: …` → `(4200, 312)`. Token-based:
/// the count is the word before "sent"/"received", whatever follows on the
/// line (aider appends the Cost clause to the same line).
fn parse_tokens_line(rest: &str) -> Option<(u64, u64)> {
    let mut sent = None;
    let mut recv = None;
    let words: Vec<&str> = rest.split_whitespace().collect();
    for (i, w) in words.iter().enumerate() {
        let bare = w.trim_matches(|c: char| c == ',' || c == '.');
        if (bare == "sent" || bare == "received") && i > 0 {
            let count = parse_k(words[i - 1].trim_matches(|c: char| c == ',' || c == '.'));
            if bare == "sent" {
                sent = count;
            } else {
                recv = count;
            }
        }
    }
    Some((sent?, recv?))
}

/// `4.2k` → 4200; `312` → 312 (aider's `format_tokens` k-units).
fn parse_k(s: &str) -> Option<u64> {
    if let Some(k) = s.strip_suffix('k') {
        let f: f64 = k.trim().parse().ok()?;
        Some((f * 1000.0).round() as u64)
    } else {
        s.trim().parse().ok()
    }
}

impl Default for AiderReader {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentReader for AiderReader {
    fn tool(&self) -> AgentTool {
        AgentTool::Aider
    }
    fn is_present(&self) -> bool {
        !self.history_files().is_empty()
    }
    fn list_sessions(&self) -> Vec<AgentSession> {
        self.history_files()
            .into_iter()
            .flat_map(|p| Self::parse(&p, None))
            .map(|d| d.session)
            .collect()
    }
    fn retention(&self) -> super::retention::RetentionPolicy {
        super::retention::RetentionPolicy::keeps_all(
            "Append-only markdown at each project's git root; never rotated by aider.",
        )
    }
    fn source_fingerprint(&self) -> Option<u64> {
        Some(super::hash_files(self.history_files().into_iter()))
    }
    fn session_detail(&self, raw_id: &str) -> Option<AgentSessionDetail> {
        // raw id = "<proj-slug>:<start-millis>:<index>".
        let idx: usize = raw_id.rsplit(':').next()?.parse().ok()?;
        for p in self.history_files() {
            let all = Self::parse(&p, Some(idx));
            if let Some(d) = all.into_iter().find(|d| d.session.id.ends_with(raw_id)) {
                return Some(d);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sessions_by_aiders_own_rules() {
        let dir = std::env::temp_dir().join(format!("saffev-aider-{}", uuid::Uuid::new_v4()));
        let proj = dir.join("myproj");
        std::fs::create_dir_all(&proj).unwrap();
        let md = "\n# aider chat started at 2026-07-27 14:03:10\n\n> Aider v0.86.1  \n> Model: gpt-4o with diff edit format  \n> Git repo: .git with 217 files  \n\n#### add a retry to the fetch helper  \n#### make it exponential\n\nI'll add an exponential-backoff retry to `get()`:\n\n```typescript\nretry code here\n```\n\n> Tokens: 4.2k sent, 312 received. Cost: $0.01 message, $0.01 session.  \n> Applied edit to src/fetch.ts  \n\n# aider chat started at 2026-07-27 15:00:00\n\n> Main model: claude-sonnet-4-6 with diff edit format, prompt cache  \n\n#### second session question\n\nSecond session answer.\n\n> Tokens: 900 sent, 100 received.  \n";
        std::fs::write(proj.join(".aider.chat.history.md"), md).unwrap();

        let reader = AiderReader::with_roots(vec![dir.clone()]);
        let sessions = reader.list_sessions();
        assert_eq!(sessions.len(), 2);
        let s1 = &sessions[0];
        assert_eq!(s1.model.as_deref(), Some("gpt-4o"));
        assert_eq!(s1.input_tokens, 4200, "k-units expand");
        assert_eq!(s1.output_tokens, 312);
        assert_eq!(s1.tool_call_count, 1);
        assert!(s1.title.as_deref().unwrap().contains("add a retry"));
        assert!(s1.project.as_deref().unwrap().ends_with("myproj"));
        // Multi-line #### input is ONE user message.
        let d = reader.session_detail(s1.id.split_once(':').unwrap().1).expect("detail");
        let users: Vec<_> = d.messages.iter().filter(|m| m.role == Role::User).collect();
        assert_eq!(users.len(), 1);
        assert!(users[0].content.contains("make it exponential"));
        // Suffix-stripping on the second session's model line.
        let s2 = &sessions[1];
        assert_eq!(s2.model.as_deref(), Some("claude-sonnet-4-6"));
        assert_eq!(s2.input_tokens, 900);
        // Session 1 ends where session 2 starts.
        assert_eq!(s1.updated_ts, s2.started_ts);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn garbage_content_is_just_assistant_text_never_fatal() {
        let dir = std::env::temp_dir().join(format!("saffev-aider-{}", uuid::Uuid::new_v4()));
        let proj = dir.join("p2");
        std::fs::create_dir_all(&proj).unwrap();
        let md = "# aider chat started at 2026-07-27 16:00:00\n\n#### question\n\nanswer with \u{fffd} binary noise {{{ ]] not markdown\n";
        std::fs::write(proj.join(".aider.chat.history.md"), md).unwrap();
        let reader = AiderReader::with_roots(vec![dir.clone()]);
        let sessions = reader.list_sessions();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].message_count, 2);
        std::fs::remove_dir_all(&dir).ok();
    }
}
