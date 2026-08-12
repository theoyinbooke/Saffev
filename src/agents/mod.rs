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

pub mod aider;
pub mod amp;
pub mod archive;
pub mod claude_code;
pub mod cline;
pub mod codex;
pub mod codex_server;
pub mod copilot;
pub mod cursor;
pub mod export;
pub mod gemini;
pub mod gitlink;
pub mod goose;
pub mod mirror;
pub mod opencode;
pub mod privacy;
pub mod retention;
pub mod roo;
pub mod usage;
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
    /// Google Gemini CLI (`~/.gemini/tmp/<project>/chats/session-*.jsonl`).
    Gemini,
    /// GitHub Copilot CLI (`~/.copilot/session-state/<id>/events.jsonl`).
    Copilot,
    /// Cline (VS Code globalStorage `saoudrizwan.claude-dev/tasks/<id>/`).
    Cline,
    /// Aider (per-project `.aider.chat.history.md` markdown transcripts).
    Aider,
    /// Goose / Block (`~/.local/share/goose/sessions/sessions.db` SQLite).
    Goose,
    /// Amp / Sourcegraph (`~/.local/share/amp/threads/T-*.json`).
    Amp,
    /// Roo Code (VS Code globalStorage `rooveterinaryinc.roo-cline/tasks/`).
    Roo,
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
            AgentTool::Gemini => "gemini",
            AgentTool::Copilot => "copilot",
            AgentTool::Cline => "cline",
            AgentTool::Aider => "aider",
            AgentTool::Goose => "goose",
            AgentTool::Amp => "amp",
            AgentTool::Roo => "roo",
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
            AgentTool::Gemini => "Gemini CLI",
            AgentTool::Copilot => "Copilot CLI",
            AgentTool::Cline => "Cline",
            AgentTool::Aider => "Aider",
            AgentTool::Goose => "Goose",
            AgentTool::Amp => "Amp",
            AgentTool::Roo => "Roo Code",
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
    /// Summed **non-cached** input tokens (0 if the tool doesn't record it).
    ///
    /// The contract is deliberate and every reader must honor it: vendors
    /// disagree here. Anthropic reports `input_tokens` already excluding cache
    /// reads; OpenAI reports a total prompt count with cached tokens as a subset.
    /// Readers of the second kind must subtract, or the cached portion gets
    /// counted (and priced) twice.
    pub input_tokens: u64,
    /// Summed output tokens.
    pub output_tokens: u64,
    /// Summed cache read/creation tokens, 0 if the tool does not report them.
    /// Disjoint from [`Self::input_tokens`].
    pub cache_tokens: u64,
    /// The cache-WRITE (creation) subset of [`Self::cache_tokens`], for
    /// adapters whose format splits them (Anthropic-family). Writes are
    /// billed at 1.25 × input vs 0.1 × for reads — merging them understated
    /// real histories (G3). 0 when the tool doesn't split; the whole cache
    /// sum is then priced at the read rate, documented.
    pub cache_write_tokens: u64,
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
        "gemini" => AgentTool::Gemini,
        "copilot" => AgentTool::Copilot,
        "cline" => AgentTool::Cline,
        "aider" => AgentTool::Aider,
        "goose" => AgentTool::Goose,
        "amp" => AgentTool::Amp,
        "roo" => AgentTool::Roo,
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

/// Upper bound on remembered per-file parses. Session metadata is tiny (a few
/// hundred bytes each), so this is a generous ceiling; crossing it simply clears
/// the cache, which costs one slow list and then recovers.
const FILE_CACHE_MAX: usize = 8_192;

/// One remembered parse: the `(mtime, size)` it was valid for, and the result
/// (`None` = the file did not yield a session, which is worth remembering too).
type FileCacheEntry = (i64, u64, Option<AgentSession>);

/// Path-keyed cache of per-file parse results.
type FileCache = std::sync::Mutex<std::collections::HashMap<PathBuf, FileCacheEntry>>;

/// Process-wide cache of per-file parse results, keyed by path, validated by the
/// file's `(mtime, size)`.
fn file_cache() -> &'static FileCache {
    static C: std::sync::OnceLock<FileCache> = std::sync::OnceLock::new();
    C.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Parse one session file's metadata, reusing the previous result when the file
/// has not changed.
///
/// This is what makes the session list usable on a real history. The outer
/// [`all_sessions`] cache is all-or-nothing: any single byte written by any tool
/// invalidates it, and one of these tools is usually writing right now, so in
/// practice it almost never hits and every page load re-read every file. On a
/// real machine that measured **27 seconds** per listing (Codex alone: 21s for
/// 399 rollups).
///
/// A finished session's file never changes again, so keying on `(mtime, size)`
/// makes all but the actively-written file a stat-only lookup. Failures are
/// cached too (as `None`), so an unparseable file is not re-read on every pass.
///
/// Fail-soft: if the file cannot be stat'ed we simply parse without caching.
pub(crate) fn cached_file_parse<F>(path: &std::path::Path, parse: F) -> Option<AgentSession>
where
    F: FnOnce(&std::path::Path) -> Option<AgentSession>,
{
    let key = std::fs::metadata(path).ok().map(|m| {
        let mtime = m
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        (mtime, m.len())
    });
    let Some((mtime, size)) = key else {
        return parse(path);
    };

    if let Ok(cache) = file_cache().lock() {
        if let Some((m, s, hit)) = cache.get(path) {
            if *m == mtime && *s == size {
                return hit.clone();
            }
        }
    }

    let parsed = parse(path);

    if let Ok(mut cache) = file_cache().lock() {
        if cache.len() >= FILE_CACHE_MAX {
            cache.clear();
        }
        cache.insert(path.to_path_buf(), (mtime, size, parsed.clone()));
    }
    parsed
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
            retention::at_risk_for(
                tool,
                r.retention(),
                &mine,
                now,
                retention::AT_RISK_WARN_DAYS,
            )
        })
        .collect()
}

/// Sessions at risk of deletion (past their tool's line or crossing it within
/// [`retention::AT_RISK_WARN_DAYS`]) whose ids are NOT in `archived_ids` — the
/// preservation gap the at-risk monitor signal announces. Returns the matching
/// sessions plus the soonest still-upcoming expiry among them (`None` when
/// every match is already past the line).
pub fn at_risk_unpreserved<'a>(
    sessions: &'a [AgentSession],
    archived_ids: &std::collections::HashSet<String>,
    now_ms: i64,
) -> (Vec<&'a AgentSession>, Option<i64>) {
    // Policy per tool, looked up once — not per session.
    let policies: std::collections::HashMap<AgentTool, retention::RetentionPolicy> = readers()
        .iter()
        .map(|r| (r.tool(), r.retention()))
        .collect();
    let (mut hits, mut soonest) = (Vec::new(), None::<i64>);
    for s in sessions {
        if archived_ids.contains(&s.id) {
            continue;
        }
        let Some(policy) = policies.get(&s.tool) else {
            continue;
        };
        if retention::is_at_risk(policy, s.updated_ts, now_ms, retention::AT_RISK_WARN_DAYS) {
            if let Some(expiry) = retention::expiry_ts(policy, s.updated_ts) {
                if expiry > now_ms {
                    soonest = Some(soonest.map_or(expiry, |m: i64| m.min(expiry)));
                }
            }
            hits.push(s);
        }
    }
    (hits, soonest)
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
        Box::new(gemini::GeminiReader::new()),
        Box::new(copilot::CopilotReader::new()),
        Box::new(cline::ClineReader::new()),
        Box::new(aider::AiderReader::new()),
        Box::new(goose::GooseReader::new()),
        Box::new(amp::AmpReader::new()),
        Box::new(roo::RooReader::new()),
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

/// Per-tool cache of a reader's session list, keyed by the tool's stable key and
/// validated by that reader's own source fingerprint.
type ListCache =
    std::sync::Mutex<std::collections::HashMap<&'static str, (u64, Vec<AgentSession>)>>;

/// Process-wide cache of each reader's session list, keyed by that reader's own
/// stat-only fingerprint.
///
/// Deliberately **per reader**, not one merged entry. A single combined
/// fingerprint means any tool writing anywhere invalidates everything, and on a
/// working machine one of these tools is nearly always writing — so a shared key
/// almost never hits and every reader pays full cost every time. Cursor in
/// particular re-copied its whole database because Claude Code appended a line.
fn list_cache() -> &'static ListCache {
    static C: std::sync::OnceLock<ListCache> = std::sync::OnceLock::new();
    C.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// One reader's sessions, served from cache while its own sources are unchanged.
/// A reader that cannot be fingerprinted is simply never cached (always fresh).
fn sessions_for(r: &dyn AgentReader) -> Vec<AgentSession> {
    let key = r.tool().key();
    let fp = r.source_fingerprint();
    if let Some(fp) = fp {
        if let Ok(cache) = list_cache().lock() {
            if let Some((cached_fp, sessions)) = cache.get(key) {
                if *cached_fp == fp {
                    return sessions.clone();
                }
            }
        }
    }
    let sessions = r.list_sessions();
    if let Some(fp) = fp {
        if let Ok(mut cache) = list_cache().lock() {
            cache.insert(key, (fp, sessions.clone()));
        }
    }
    sessions
}

/// Merged session list across all present tools (each already source-tagged),
/// newest first. Each reader is cached independently against its own sources, so
/// a busy tool never forces the quiet ones to be re-read.
pub fn all_sessions() -> Vec<AgentSession> {
    let mut out: Vec<AgentSession> = readers()
        .iter()
        .filter(|r| r.is_present())
        .flat_map(|r| sessions_for(r.as_ref()))
        .collect();
    out.sort_by(|a, b| b.updated_ts.cmp(&a.updated_ts));
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
                    cost_usd_split(
                        s.model.as_deref(),
                        s.input_tokens,
                        s.output_tokens,
                        s.cache_tokens,
                        s.cache_write_tokens,
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

/// Estimated USD cost for a session's token usage (0 if the model is unknown or
/// runs locally), using the built-in price table.
///
/// `input` must be the **non-cached** input count (see [`AgentSession::input_tokens`]);
/// pricing cached tokens at full input rate is exactly the mistake that inflated
/// a real history's estimate more than tenfold. The whole `cache` sum is priced
/// at the READ rate — call [`cost_usd_split`] when the write subset is known.
pub fn cost_usd(model: Option<&str>, input: u64, output: u64, cache: u64) -> f64 {
    cost_usd_with(
        &crate::config::PricingConfig::default(),
        model,
        input,
        output,
        cache,
    )
}

/// As [`cost_usd`], but against a caller-supplied (user-editable) price table.
pub fn cost_usd_with(
    pricing: &crate::config::PricingConfig,
    model: Option<&str>,
    input: u64,
    output: u64,
    cache: u64,
) -> f64 {
    let Some(model) = model else { return 0.0 };
    let (pin, pout, pcache) = pricing.lookup(model);
    (input as f64 * pin + output as f64 * pout + cache as f64 * pcache) / 1_000_000.0
}

/// As [`cost_usd`], with the cache-WRITE subset priced at the write rate
/// (1.25 × input, Anthropic convention) instead of the read rate — the
/// single pricing formula the usage engine and the session views now share
/// (G3: two diverging paths showed different dollars for the same activity).
/// `cache` is the TOTAL cache sum; `cache_write` its write subset.
pub fn cost_usd_split(
    model: Option<&str>,
    input: u64,
    output: u64,
    cache: u64,
    cache_write: u64,
) -> f64 {
    cost_usd_split_with(
        &crate::config::PricingConfig::default(),
        model,
        input,
        output,
        cache,
        cache_write,
    )
}

/// As [`cost_usd_split`], against a caller-supplied price table — the
/// session views pass the LIVE config so their dollars use the same table
/// as the usage report (G3 closing critic: the default-table shortcut was
/// one more way the two paths could disagree).
pub fn cost_usd_split_with(
    pricing: &crate::config::PricingConfig,
    model: Option<&str>,
    input: u64,
    output: u64,
    cache: u64,
    cache_write: u64,
) -> f64 {
    let Some(model) = model else { return 0.0 };
    let (pin, pout, pread, pwrite) = pricing.lookup_split(model);
    let reads = cache.saturating_sub(cache_write);
    (input as f64 * pin + output as f64 * pout + reads as f64 * pread + cache_write as f64 * pwrite)
        / 1_000_000.0
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

    /// Cached tokens are far cheaper than fresh input, so they must be priced as
    /// cache. Charging them at the input rate is what turned a real history's
    /// estimate into a five-figure number.
    #[test]
    fn cached_tokens_are_priced_as_cache_not_as_input() {
        // 1M cached vs 1M fresh input on Opus: $1.50 vs $15.00.
        let cached = cost_usd(Some("claude-opus-4-8"), 0, 0, 1_000_000);
        let fresh = cost_usd(Some("claude-opus-4-8"), 1_000_000, 0, 0);
        assert!((cached - 1.5).abs() < 0.01, "cached: {cached}");
        assert!((fresh - 15.0).abs() < 0.01, "fresh: {fresh}");
        assert!(cached < fresh / 5.0);
    }

    #[test]
    fn a_user_supplied_price_table_overrides_the_defaults() {
        let pricing = crate::config::PricingConfig {
            models: vec![crate::config::ModelPrice {
                match_: "opus".into(),
                input: 1.0,
                output: 2.0,
                cache: 0.5,
                cache_write: 0.0, // absent => derives 1.25 x input
            }],
            ..Default::default()
        };
        // 1M input at the user's $1.00, not the built-in $15.00.
        let c = cost_usd_with(&pricing, Some("claude-opus-4-8"), 1_000_000, 0, 0);
        assert!((c - 1.0).abs() < 0.001, "{c}");
        // A model missing from a user table costs nothing rather than guessing.
        assert_eq!(
            cost_usd_with(&pricing, Some("gpt-5.5"), 1_000_000, 0, 0),
            0.0
        );
        // Local models stay free regardless of the table.
        assert_eq!(
            cost_usd_with(&pricing, Some("ollama/x:1b"), 1_000, 0, 0),
            0.0
        );
    }

    #[test]
    fn an_empty_price_table_falls_back_to_the_built_ins() {
        let pricing = crate::config::PricingConfig {
            models: Vec::new(),
            ..Default::default()
        };
        let c = cost_usd_with(&pricing, Some("claude-opus-4-8"), 1_000_000, 0, 0);
        assert!((c - 15.0).abs() < 0.01, "{c}");
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

#[cfg(test)]
mod perf {
    use super::*;

    /// Manual: per-reader listing cost against the real machine, cold then warm.
    /// This is the check that caught the Agents page taking 27 seconds per load.
    /// `cargo test per_reader_timing -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn per_reader_timing() {
        for r in readers() {
            if !r.is_present() {
                continue;
            }
            let t = std::time::Instant::now();
            let n = r.list_sessions().len();
            let cold = t.elapsed();
            let t2 = std::time::Instant::now();
            let _ = r.list_sessions();
            let warm = t2.elapsed();
            eprintln!(
                "{:<12} cold {:>9.2?} · warm {:>9.2?}  ({n} sessions)",
                r.tool().label(),
                cold,
                warm
            );
        }
    }

    /// The per-file cache must return an identical result to an uncached parse,
    /// and must not re-invoke the parser for an unchanged file.
    #[test]
    fn file_cache_is_transparent_and_skips_unchanged() {
        let f = std::env::temp_dir().join(format!("saffev-fc-{}.jsonl", uuid::Uuid::new_v4()));
        std::fs::write(&f, "one").unwrap();

        let calls = std::sync::atomic::AtomicUsize::new(0);
        let make = |tag: &str| {
            let s = AgentSession {
                id: AgentSession::make_id(AgentTool::Codex, tag),
                tool: AgentTool::Codex,
                title: Some(tag.to_string()),
                project: None,
                git_branch: None,
                model: None,
                started_ts: 1,
                updated_ts: 2,
                message_count: 1,
                tool_call_count: 0,
                input_tokens: 0,
                output_tokens: 0,
                cache_tokens: 0,
                cache_write_tokens: 0,
                source_path: String::new(),
            };
            Some(s)
        };

        let a = cached_file_parse(&f, |_| {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            make("first")
        });
        assert_eq!(a.as_ref().unwrap().title.as_deref(), Some("first"));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);

        // Unchanged file: the parser must NOT run again, and the answer is same.
        let b = cached_file_parse(&f, |_| {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            make("second")
        });
        assert_eq!(b.as_ref().unwrap().title.as_deref(), Some("first"));
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "unchanged file must not be re-parsed"
        );

        // Changed file (different size) invalidates: the parser runs again.
        std::fs::write(&f, "one-plus-more").unwrap();
        let c = cached_file_parse(&f, |_| {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            make("third")
        });
        assert_eq!(c.as_ref().unwrap().title.as_deref(), Some("third"));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);

        let _ = std::fs::remove_file(&f);
    }

    /// A file that does not parse is remembered as a miss, so a broken record is
    /// not re-read on every single listing.
    #[test]
    fn file_cache_remembers_failures() {
        let f = std::env::temp_dir().join(format!("saffev-fc-{}.jsonl", uuid::Uuid::new_v4()));
        std::fs::write(&f, "garbage").unwrap();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        for _ in 0..3 {
            let got = cached_file_parse(&f, |_| {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                None
            });
            assert!(got.is_none());
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        let _ = std::fs::remove_file(&f);
    }

    /// A file that cannot be stat'ed still parses (fail-soft, just uncached).
    #[test]
    fn missing_file_still_parses_uncached() {
        let missing = std::env::temp_dir().join(format!("saffev-none-{}", uuid::Uuid::new_v4()));
        let calls = std::sync::atomic::AtomicUsize::new(0);
        for _ in 0..2 {
            let _ = cached_file_parse(&missing, |_| {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                None
            });
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }
}
