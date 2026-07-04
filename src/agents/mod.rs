//! Coding-agent session observability — Direction 1 ("read the local history").
//!
//! Reads AI coding tools' **local session history on-device** (Claude Code,
//! Codex, OpenCode, Cursor) and exposes it as one common model for analysis.
//! Pure local file reading: **no network, no interception** — it fits the
//! on-device invariant exactly. Every session and message is **tagged with its
//! source** ([`AgentTool`] + the file it came from).
//!
//! ## Design
//! - Each tool has an [`AgentReader`] adapter that knows where that tool stores
//!   history and how to parse it. Adapters are tolerant of format drift (these
//!   formats are internal to each vendor and change between releases) — an
//!   unparseable record is skipped, never fatal.
//! - Reading is **on-demand**: the source files are the source of truth, so
//!   nothing is persisted. Session *lists* parse only metadata (fast); the full
//!   message transcript is parsed only on a detail request.
//! - Session ids are namespaced `"<tool-key>:<raw-id>"` so the API can route a
//!   detail request back to the right adapter.

use std::path::PathBuf;

pub mod archive;
pub mod claude_code;
pub mod codex;
pub mod codex_server;
pub mod cursor;
pub mod export;
pub mod opencode;
pub mod retention;
pub mod vscode;

/// A supported coding agent (the *source* of a session). The `#[serde]` repr is
/// the stable key used in session ids and the API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentTool {
    /// Anthropic Claude Code (`~/.claude/projects/**/*.jsonl`).
    ClaudeCode,
    /// OpenAI Codex CLI (`~/.codex/sessions/**/rollout-*.jsonl`).
    Codex,
    /// OpenCode / SST (`~/.local/share/opencode/**`).
    OpenCode,
    /// Cursor / Anysphere (`state.vscdb` SQLite).
    Cursor,
    /// VS Code / GitHub Copilot Chat (`workspaceStorage/**/chatSessions/*.jsonl`).
    VsCode,
}

impl AgentTool {
    /// Stable key used in namespaced session ids + the API (`claude_code`, …).
    pub fn key(self) -> &'static str {
        match self {
            AgentTool::ClaudeCode => "claude_code",
            AgentTool::Codex => "codex",
            AgentTool::OpenCode => "opencode",
            AgentTool::Cursor => "cursor",
            AgentTool::VsCode => "vscode",
        }
    }
    /// Human label for the UI.
    pub fn label(self) -> &'static str {
        match self {
            AgentTool::ClaudeCode => "Claude Code",
            AgentTool::Codex => "Codex",
            AgentTool::OpenCode => "OpenCode",
            AgentTool::Cursor => "Cursor",
            AgentTool::VsCode => "VS Code",
        }
    }
}

/// Role of a message in a transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    User,
    Assistant,
    Tool,
    System,
}

/// What a message block is (drives how the UI renders it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageKind {
    /// Ordinary text.
    Text,
    /// Model reasoning / thinking trace.
    Thinking,
    /// A tool/function invocation by the assistant.
    ToolUse,
    /// The result returned to the model from a tool.
    ToolResult,
}

/// One message in a session transcript (source-tagged via its parent session).
#[derive(Debug, Clone, serde::Serialize)]
pub struct AgentMessage {
    /// Who authored it.
    pub role: Role,
    /// What kind of block.
    pub kind: MessageKind,
    /// Text content (tool calls carry a compact JSON/summary here).
    pub content: String,
    /// Unix millis, if the record carried a timestamp.
    pub ts: Option<i64>,
    /// Tool name for `ToolUse`/`ToolResult`.
    pub tool_name: Option<String>,
}

/// A session summary — metadata only (parsed fast for lists). Tagged with its
/// [`AgentTool`] source and the file it came from.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AgentSession {
    /// Namespaced id: `"<tool-key>:<raw-id>"`.
    pub id: String,
    /// Source tool.
    pub tool: AgentTool,
    /// Best-effort human title (ai-title / summary / first user line).
    pub title: Option<String>,
    /// Project / working directory the session ran in.
    pub project: Option<String>,
    /// Git branch, if the tool records it.
    pub git_branch: Option<String>,
    /// Primary model used (most frequent / last seen).
    pub model: Option<String>,
    /// First activity (unix millis).
    pub started_ts: i64,
    /// Last activity (unix millis).
    pub updated_ts: i64,
    /// Message count.
    pub message_count: u32,
    /// Tool/function call count.
    pub tool_call_count: u32,
    /// Summed input tokens across the session (0 if the tool doesn't record it).
    pub input_tokens: u64,
    /// Summed output tokens.
    pub output_tokens: u64,
    /// Summed cache-read/creation tokens (Anthropic-style), 0 if n/a.
    pub cache_tokens: u64,
    /// The file/db this session was read from (the source tag).
    pub source_path: String,
}

impl AgentSession {
    /// Build a namespaced id from a tool + raw id.
    pub fn make_id(tool: AgentTool, raw: &str) -> String {
        format!("{}:{}", tool.key(), raw)
    }
}

/// Split a namespaced session id back into `(tool, raw_id)`.
pub fn split_id(id: &str) -> Option<(AgentTool, &str)> {
    let (key, raw) = id.split_once(':')?;
    let tool = match key {
        "claude_code" => AgentTool::ClaudeCode,
        "codex" => AgentTool::Codex,
        "opencode" => AgentTool::OpenCode,
        "cursor" => AgentTool::Cursor,
        "vscode" => AgentTool::VsCode,
        _ => return None,
    };
    Some((tool, raw))
}

/// A full session: summary + the ordered transcript.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AgentSessionDetail {
    /// The summary (re-derived when reading the full file).
    pub session: AgentSession,
    /// Ordered messages.
    pub messages: Vec<AgentMessage>,
}

/// An adapter that reads one coding tool's local history. Every method is
/// fail-soft: unreadable files/records are skipped, never panicked.
pub trait AgentReader: Send + Sync {
    /// Which tool this reads.
    fn tool(&self) -> AgentTool;
    /// Is this tool's history present on this machine?
    fn is_present(&self) -> bool;
    /// Session summaries (metadata only — parse cheaply). Newest first is nice
    /// but the caller re-sorts, so order is not contractual.
    fn list_sessions(&self) -> Vec<AgentSession>;
    /// Full transcript for one raw (un-namespaced) session id.
    fn session_detail(&self, raw_id: &str) -> Option<AgentSessionDetail>;
    /// What this tool does to its history over time (drives at-risk awareness).
    /// Default: unknown; readers override with their real behavior.
    fn retention(&self) -> retention::RetentionPolicy {
        retention::RetentionPolicy::unknown()
    }
    /// A cheap (stat-only, no content read) change key for this tool's sources,
    /// so the session list can be cached and only re-parsed when a file changes.
    /// `None` = not cacheable (the list stays always-fresh). See [`hash_files`].
    fn source_fingerprint(&self) -> Option<u64> {
        None
    }
}

/// A SQLite DB path plus its `-wal`/`-shm` sidecars — the fingerprint inputs for
/// DB-backed adapters (Cursor/OpenCode), so writes to the live DB invalidate the
/// list cache.
pub(crate) fn db_paths(db: &std::path::Path) -> Vec<PathBuf> {
    let mut v = vec![db.to_path_buf()];
    for ext in ["-wal", "-shm"] {
        let mut s = db.as_os_str().to_os_string();
        s.push(ext);
        v.push(PathBuf::from(s));
    }
    v
}

/// Hash a set of files by `(path, mtime-millis, size)` — the change key for the
/// list cache. Cheap: **stat-only, never reads contents**. Adapters build their
/// `source_fingerprint` from this.
pub(crate) fn hash_files(paths: impl Iterator<Item = PathBuf>) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut items: Vec<(String, i64, u64)> = paths
        .filter_map(|p| {
            let m = std::fs::metadata(&p).ok()?;
            let mtime = m
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0);
            Some((p.to_string_lossy().to_string(), mtime, m.len()))
        })
        .collect();
    items.sort();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    items.hash(&mut h);
    h.finish()
}

/// Current wall-clock time in unix millis (0 on the impossible pre-epoch error).
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Per-tool at-risk report over already-listed sessions (avoids re-listing).
pub fn at_risk_report(sessions: &[AgentSession]) -> Vec<retention::AtRisk> {
    let now = now_ms();
    readers()
        .iter()
        .filter(|r| r.is_present())
        .map(|r| {
            let tool = r.tool();
            let mine: Vec<&AgentSession> = sessions.iter().filter(|s| s.tool == tool).collect();
            retention::at_risk_for(tool, r.retention(), &mine, now, 7)
        })
        .collect()
}

/// The user's home directory (`$HOME`), or `.` as a fail-soft fallback.
pub fn home() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("."))
}

/// All registered readers, in display order.
pub fn readers() -> Vec<Box<dyn AgentReader>> {
    vec![
        Box::new(claude_code::ClaudeCodeReader::new()),
        Box::new(codex::CodexReader::new()),
        Box::new(opencode::OpenCodeReader::new()),
        Box::new(cursor::CursorReader::new()),
        Box::new(vscode::VsCodeReader::new()),
    ]
}

/// Per-tool presence + rollup, for the Agents overview.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ToolStat {
    /// The tool.
    pub tool: AgentTool,
    /// Whether its history is present on this machine.
    pub present: bool,
    /// Session count (as listed — may be capped).
    pub sessions: u32,
    /// Total tokens across listed sessions (in + out).
    pub tokens: u64,
    /// Estimated cost across listed sessions (USD).
    pub cost_usd: f64,
    /// Most recent activity (unix millis), 0 if none.
    pub last_active: i64,
}

/// Process-wide cache of the merged session list, keyed by a cheap source
/// fingerprint. Invalidated automatically when any source file changes.
fn list_cache() -> &'static std::sync::Mutex<Option<(u64, Vec<AgentSession>)>> {
    static C: std::sync::OnceLock<std::sync::Mutex<Option<(u64, Vec<AgentSession>)>>> =
        std::sync::OnceLock::new();
    C.get_or_init(|| std::sync::Mutex::new(None))
}

/// Combined fingerprint of all present sources; `None` if any present reader
/// can't be fingerprinted (then the list is not cached — always fresh).
fn source_fingerprint() -> Option<u64> {
    use std::hash::{Hash, Hasher};
    let mut items: Vec<(String, u64)> = Vec::new();
    for r in readers().iter().filter(|r| r.is_present()) {
        items.push((r.tool().key().to_string(), r.source_fingerprint()?));
    }
    items.sort();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    items.hash(&mut h);
    Some(h.finish())
}

/// Merged session list across all present tools (each already source-tagged),
/// newest first. **Cached** by a stat-only source fingerprint: re-parses only
/// when a source file changed since the last call, so repeat page loads are
/// instant (and Cursor avoids re-copying its large DB every time).
pub fn all_sessions() -> Vec<AgentSession> {
    let fp = source_fingerprint();
    if let Some(fp) = fp {
        if let Ok(guard) = list_cache().lock() {
            if let Some((cached_fp, sessions)) = guard.as_ref() {
                if *cached_fp == fp {
                    return sessions.clone();
                }
            }
        }
    }
    let mut out: Vec<AgentSession> = readers()
        .iter()
        .filter(|r| r.is_present())
        .flat_map(|r| r.list_sessions())
        .collect();
    out.sort_by(|a, b| b.updated_ts.cmp(&a.updated_ts));
    if let Some(fp) = fp {
        if let Ok(mut guard) = list_cache().lock() {
            *guard = Some((fp, out.clone()));
        }
    }
    out
}

/// Route a namespaced id to the owning reader and fetch the full transcript.
pub fn detail(id: &str) -> Option<AgentSessionDetail> {
    let (tool, raw) = split_id(id)?;
    readers()
        .iter()
        .find(|r| r.tool() == tool)
        .and_then(|r| r.session_detail(raw))
}

/// Per-tool overview: presence + session/token/cost rollups over the listed
/// sessions. Reuses one `all_sessions()` pass for the present tools.
pub fn detected() -> Vec<ToolStat> {
    tool_stats(&all_sessions())
}

/// Per-tool rollups from an already-listed sessions slice (so callers that need
/// several views can list once).
pub fn tool_stats(sessions: &[AgentSession]) -> Vec<ToolStat> {
    readers()
        .iter()
        .map(|r| {
            let tool = r.tool();
            let present = r.is_present();
            let mine: Vec<&AgentSession> = sessions.iter().filter(|s| s.tool == tool).collect();
            let tokens = mine.iter().map(|s| s.input_tokens + s.output_tokens).sum();
            let cost_usd = mine
                .iter()
                .map(|s| {
                    cost_usd(
                        s.model.as_deref(),
                        s.input_tokens,
                        s.output_tokens,
                        s.cache_tokens,
                    )
                })
                .sum();
            let last_active = mine.iter().map(|s| s.updated_ts).max().unwrap_or(0);
            ToolStat {
                tool,
                present,
                sessions: mine.len() as u32,
                tokens,
                cost_usd,
                last_active,
            }
        })
        .collect()
}

/// Rough public $/1M-token prices `(input, output, cache_read)` for a model, by
/// prefix. Cloud coding-agent models only; local/unknown models are free (0).
/// These are ESTIMATES for a "cost avoided / spent" ballpark, not billing.
fn price_per_m(model: &str) -> (f64, f64, f64) {
    let m = model.to_lowercase();
    // Local engines routed through a tool (OpenCode → Ollama) — no cloud cost.
    if m.contains("ollama") || m.contains("lmstudio") || m.contains("local") || m.contains(':') {
        return (0.0, 0.0, 0.0);
    }
    // Anthropic.
    if m.contains("opus") {
        return (15.0, 75.0, 1.5);
    }
    if m.contains("sonnet") {
        return (3.0, 15.0, 0.3);
    }
    if m.contains("haiku") || m.contains("fable") {
        return (1.0, 5.0, 0.1);
    }
    // OpenAI GPT-5 family (incl. codex).
    if m.contains("gpt-5") || m.contains("gpt5") {
        return (1.25, 10.0, 0.125);
    }
    if m.contains("gpt-4o") || m.contains("gpt-4.1") {
        return (2.5, 10.0, 0.25);
    }
    // Google Gemini.
    if m.contains("gemini") {
        return (1.25, 10.0, 0.125);
    }
    (0.0, 0.0, 0.0)
}

/// Estimated USD cost for a session's token usage (0 if the model is unknown/local).
pub fn cost_usd(model: Option<&str>, input: u64, output: u64, cache: u64) -> f64 {
    let Some(model) = model else { return 0.0 };
    let (pin, pout, pcache) = price_per_m(model);
    (input as f64 * pin + output as f64 * pout + cache as f64 * pcache) / 1_000_000.0
}

/// Read a possibly-live SQLite DB safely: copy it (plus any `-wal`/`-shm`) to a
/// temp dir, open the COPY read-only, run `f`, then clean up. This never touches
/// the tool's live database and resolves WAL frames correctly. Returns `None` on
/// any IO/SQLite error (fail-soft). The SQLCipher-linked `rusqlite` opens plain
/// (unkeyed) databases as ordinary SQLite, so no key is needed.
pub(crate) fn with_sqlite_snapshot<T>(
    db: &std::path::Path,
    f: impl FnOnce(&rusqlite::Connection) -> Option<T>,
) -> Option<T> {
    if !db.is_file() {
        return None;
    }
    let tmp = std::env::temp_dir().join(format!("saffev-agents-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&tmp).ok()?;
    let name = db.file_name()?;
    let dst = tmp.join(name);
    let copied = std::fs::copy(db, &dst).is_ok();
    if copied {
        // Copy the `-wal` so uncommitted frames are visible, but NOT the `-shm`
        // (wal-index): a stale/mismatched `-shm` makes SQLite ignore the WAL. With
        // only db + `-wal`, opening read-write triggers WAL recovery that rebuilds
        // a correct `-shm` in the temp dir.
        let mut side = db.as_os_str().to_os_string();
        side.push("-wal");
        let sidep = std::path::PathBuf::from(side);
        if sidep.is_file() {
            let mut dname = name.to_os_string();
            dname.push("-wal");
            let _ = std::fs::copy(&sidep, tmp.join(dname));
        }
    }
    let result = if copied {
        match rusqlite::Connection::open_with_flags(
            &dst,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ) {
            Ok(conn) => {
                // Fold the copied WAL into the main db so reads see the current
                // state (Cursor keeps a huge uncheckpointed WAL). Safe: this is a
                // throwaway copy; the live DB is never touched.
                let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
                f(&conn)
            }
            Err(e) => {
                if std::env::var_os("SAFFEV_AGENTS_DEBUG").is_some() {
                    eprintln!("[agents] sqlite open failed for {}: {e}", db.display());
                }
                None
            }
        }
    } else {
        if std::env::var_os("SAFFEV_AGENTS_DEBUG").is_some() {
            eprintln!("[agents] copy failed for {}", db.display());
        }
        None
    };
    let _ = std::fs::remove_dir_all(&tmp);
    result
}

/// Parse an RFC3339 timestamp string to unix millis (best-effort; 0 on failure).
pub fn rfc3339_millis(s: &str) -> i64 {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map(|t| (t.unix_timestamp_nanos() / 1_000_000) as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_namespacing_roundtrips() {
        let id = AgentSession::make_id(AgentTool::ClaudeCode, "abc-123");
        assert_eq!(id, "claude_code:abc-123");
        assert_eq!(split_id(&id), Some((AgentTool::ClaudeCode, "abc-123")));
        assert_eq!(split_id("codex:x:y"), Some((AgentTool::Codex, "x:y")));
        assert_eq!(split_id("bogus"), None);
        assert_eq!(split_id("unknown:1"), None);
    }

    #[test]
    fn rfc3339_parses() {
        assert!(rfc3339_millis("2026-07-02T12:00:00Z") > 0);
        assert_eq!(rfc3339_millis("not-a-date"), 0);
    }

    /// Manual smoke test against the real machine's history. Ignored by default
    /// (depends on local state): `cargo test smoke_agents -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn smoke_agents() {
        for r in readers() {
            if !r.is_present() {
                eprintln!("{}: not present", r.tool().label());
                continue;
            }
            let sessions = r.list_sessions();
            eprintln!("{}: {} sessions", r.tool().label(), sessions.len());
            if let Some(s) = sessions.iter().max_by_key(|s| s.updated_ts) {
                eprintln!(
                    "  latest: title={:?} model={:?} msgs={} tools={} tok={}in/{}out proj={:?}",
                    s.title,
                    s.model,
                    s.message_count,
                    s.tool_call_count,
                    s.input_tokens,
                    s.output_tokens,
                    s.project
                );
                if let Some((_, raw)) = split_id(&s.id) {
                    if let Some(d) = r.session_detail(raw) {
                        eprintln!(
                            "  detail: {} messages, first role {:?}",
                            d.messages.len(),
                            d.messages.first().map(|m| m.role)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn cost_estimation() {
        // Opus ~ $15 / 1M input.
        assert!(cost_usd(Some("claude-opus-4-8"), 1_000_000, 0, 0) > 14.0);
        // Local / Ollama models are free.
        assert_eq!(cost_usd(Some("ollama/gemma3:1b"), 1000, 1000, 0), 0.0);
        // Unknown / none → 0.
        assert_eq!(cost_usd(None, 100, 100, 0), 0.0);
    }

    /// Manual: prints the retention/at-risk report for the real machine.
    /// `cargo test smoke_at_risk -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn smoke_at_risk() {
        let sessions = all_sessions();
        for r in at_risk_report(&sessions) {
            let soon = r
                .soonest_expiry_ts
                .map(|t| format!("soonest≈{}d", (t - now_ms()) / 86_400_000))
                .unwrap_or_else(|| "—".into());
            eprintln!(
                "{:<12} {:?} total={} expiringSoon={} overdue={} {} :: {}",
                r.tool.label(),
                r.policy.kind,
                r.total,
                r.expiring_soon,
                r.overdue,
                soon,
                r.policy.note
            );
        }
    }

    /// Manual: confirm the list cache makes a repeat call much faster.
    /// `cargo test cache_speeds -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn cache_speeds_repeat_list() {
        let t0 = std::time::Instant::now();
        let a = all_sessions();
        let cold = t0.elapsed();
        let t1 = std::time::Instant::now();
        let b = all_sessions();
        let warm = t1.elapsed();
        eprintln!(
            "cold: {cold:?} ({} sessions) · warm (cached): {warm:?}",
            a.len()
        );
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn tool_keys_are_stable() {
        for t in [
            AgentTool::ClaudeCode,
            AgentTool::Codex,
            AgentTool::OpenCode,
            AgentTool::Cursor,
        ] {
            assert_eq!(split_id(&format!("{}:x", t.key())).unwrap().0, t);
        }
    }
}
