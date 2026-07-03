//! Encrypted SQLite storage — single-writer model.
//!
//! ## At-rest encryption (ON by default — acceptance §10.5)
//!
//! By default this crate links **bundled SQLCipher** (`rusqlite/bundled-sqlcipher`
//! via the `sqlcipher` cargo feature, which is in the `default` set). Every
//! connection — writer and readers alike — issues the `PRAGMA key` handshake
//! **before any other statement** ([`apply_key`]), so the on-disk database is
//! encrypted at rest. The key comes from the OS keyring (Keychain on macOS,
//! Secret Service / libsecret on Linux), or from the `SAFFEV_DB_KEY` env var
//! when set (headless/CI/dev — overrides the keyring; see [`keys`]).
//!
//! For a plain, unencrypted build (no system crypto, no key handshake) opt out:
//!
//! ```text
//! cargo build --no-default-features
//! ```
//!
//! In that case the database is **not** encrypted at rest — but the stock build
//! (and every release build) is, as §10.5 requires.
//!
//! ## Single-writer model
//!
//! All proxy paths emit events onto a bounded channel; exactly one dedicated
//! writer thread (via `spawn_blocking`) owns the `Connection` and performs every
//! write. WAL mode, `synchronous=NORMAL`. This is what keeps logging off the
//! request path.
//!
//! ## Metadata / payload split (privacy default)
//!
//! [`RequestMeta`] / [`ResponseMeta`] are always stored (no raw text).
//! [`Payload`] (raw prompt/response) is stored only when `payload_storage` is on.
//! Deleting payloads never breaks the Studio.

pub mod schema;

use std::path::Path;
use std::sync::Arc;

use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::brain::{Confidence, Finding, PiiKind, Side};
use crate::{Error, Result};

/// Bound on the single-writer channel. Generous: writes are tiny and the writer
/// is fast, but a bound keeps a misbehaving producer from growing memory without
/// limit. Enqueue is best-effort (`try_send`) so the request path never blocks.
const WRITER_QUEUE_CAPACITY: usize = 8192;

// ---------------------------------------------------------------------------
// Record structs that flow proxy -> store -> studio
// ---------------------------------------------------------------------------

/// Adoption state of a detected engine (the `adoption_state` enum, 04 §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdoptionState {
    /// Found, not managed.
    Detected,
    /// Proxy forwards to it; engine untouched.
    Cooperative,
    /// Gateway adoption complete; engine on the shadow port.
    Adopted,
    /// Previously adopted, now reverted to its exact prior state.
    Reverted,
}

/// Provenance of a token count (04 §7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenSource {
    /// Engine reported `usage` — trusted.
    Exact,
    /// Estimated off the hot path with a bundled tokenizer; shown with `~`.
    Estimated,
}

/// Confidence of source-app attribution (04 §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceConfidence {
    /// Resolved via socket PID lookup at connect.
    Pid,
    /// Resolved via `X-Client-Name` / `User-Agent` header.
    Header,
    /// Could not be resolved.
    Unknown,
}

/// `engines` row — detection + reversible adoption journal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineRecord {
    /// Row id (autoincrement).
    pub id: i64,
    /// Engine name (e.g. `ollama`).
    pub engine: String,
    /// Engine version, if known.
    pub version: Option<String>,
    /// Public port the proxy owns.
    pub public_port: u16,
    /// Shadow port the engine was relocated to (Gateway), if any.
    pub shadow_port: Option<u16>,
    /// Current adoption state.
    pub adoption_state: AdoptionState,
    /// Reversible record of every system change, as JSON.
    pub journal_json: String,
    /// Last update (unix seconds).
    pub updated_at: i64,
}

/// `requests` row — always stored, no raw prompt text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestMeta {
    /// UUID primary key, correlates everything for this exchange.
    pub id: String,
    /// Timestamp (unix millis).
    pub ts: i64,
    /// Resolved source application name.
    pub source_app: Option<String>,
    /// Confidence of the source-app attribution.
    pub source_confidence: SourceConfidence,
    /// Engine name.
    pub engine: String,
    /// Model name from the request body, if present.
    pub model: Option<String>,
    /// Endpoint path (e.g. `/api/chat`, `/v1/chat/completions`).
    pub endpoint: String,
    /// Whether the client requested streaming.
    pub stream: bool,
    /// Input token count, if known.
    pub input_tokens: Option<u32>,
    /// Provenance of `input_tokens`.
    pub input_tokens_src: TokenSource,
    /// End-to-end latency (millis).
    pub latency_ms: Option<u32>,
    /// Hash of the request body (never the body itself).
    pub request_hash: String,
}

/// `responses` row — keyed 1:1 to a [`RequestMeta`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMeta {
    /// FK to `requests.id`.
    pub request_id: String,
    /// Finish reason reported by the engine, if any.
    pub finish_reason: Option<String>,
    /// Output token count, if known.
    pub output_tokens: Option<u32>,
    /// Provenance of `output_tokens`.
    pub output_tokens_src: TokenSource,
    /// Time to first token (millis).
    pub ttft_ms: Option<u32>,
    /// Total generation time (millis).
    pub total_ms: Option<u32>,
    /// Upstream HTTP status code, if a response was received (`None` when the
    /// engine was never reached).
    pub status: Option<u16>,
    /// Transport-level failure tag when the exchange didn't complete as a normal
    /// HTTP response: `upstream_unreachable` (never connected) or `stream_error`
    /// (failed mid-stream). `None` for a normal HTTP response (including 4xx/5xx —
    /// those are conveyed by `status`).
    pub error_kind: Option<String>,
}

/// `payloads` row — raw text; written only when `payload_storage` is on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payload {
    /// FK to `requests.id`.
    pub request_id: String,
    /// Raw prompt text.
    pub prompt: Option<String>,
    /// Raw response text.
    pub response: Option<String>,
}

/// `pii_findings` row — type + offsets + hash; never the raw secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiFindingRecord {
    /// Row id (autoincrement).
    pub id: i64,
    /// FK to `requests.id`.
    pub record_id: String,
    /// Which side the match was on.
    pub side: Side,
    /// PII category.
    pub kind: PiiKind,
    /// For custom patterns, the label.
    pub label: Option<String>,
    /// Inclusive start offset.
    pub start_off: usize,
    /// Exclusive end offset.
    pub end_off: usize,
    /// Detector confidence.
    pub confidence: Confidence,
    /// `observed` (v0) or `masked` (when §7.6 lands).
    pub action: PiiAction,
    /// Hash of the matched value.
    pub value_hash: String,
}

/// What was done about a PII finding (04 §7.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PiiAction {
    /// Logged only (observe-mode default).
    Observed,
    /// Masking is enabled but in dry-run: the span *would* have been masked,
    /// but traffic was forwarded unchanged (opt-in preview, §7.6).
    WouldMask,
    /// Masked before forwarding to the engine (opt-in, live, §7.6).
    Masked,
}

impl PiiFindingRecord {
    /// Build a storable record from a brain [`Finding`] + its parent record id.
    ///
    /// `id` is `0` here (a placeholder); the writer relies on the SQLite
    /// `INTEGER PRIMARY KEY` autoincrement to assign the real row id. Carries the
    /// finding's `value_hash` verbatim — never the raw secret.
    pub fn from_finding(record_id: &str, finding: &Finding, action: PiiAction) -> Self {
        PiiFindingRecord {
            id: 0,
            record_id: record_id.to_string(),
            side: finding.side,
            kind: finding.kind,
            label: finding.label.clone(),
            start_off: finding.start,
            end_off: finding.end,
            confidence: finding.confidence,
            action,
            value_hash: finding.value_hash.clone(),
        }
    }
}

/// `safety_findings` row — a guard's banded verdict on one exchange (eval
/// pipeline). Written by the async eval worker, never inline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyFindingRecord {
    /// FK to `requests.id`.
    pub record_id: String,
    /// The guard that produced this (e.g. `deterministic:v1`, or a model name).
    pub guard_model: String,
    /// Safety category flagged (e.g. `self_harm`, `violence`, `hate`).
    pub category: String,
    /// Banded verdict — deliberately not a precise score (`flagged` / `safe`).
    pub verdict: String,
    /// Optional numeric score when a model provides one (`None` for deterministic).
    pub score: Option<f32>,
    /// When this was evaluated (unix millis).
    pub ts: i64,
}

/// `eval_scores` row — a judge's banded quality score on one exchange (eval
/// pipeline). Written by the async eval worker, never inline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalScoreRecord {
    /// FK to `requests.id`.
    pub record_id: String,
    /// The judge that produced this (model name).
    pub judge_model: String,
    /// Metric name (e.g. `relevance`, `coherence`).
    pub metric: String,
    /// Banded verdict (e.g. `good` / `weak`); avoids over-precise numerics.
    pub band: String,
    /// Optional short rationale.
    pub rationale: Option<String>,
    /// Whether this record was reached via sampling (vs evaluated in full).
    pub sampled: bool,
    /// When this was evaluated (unix millis).
    pub ts: i64,
}

/// A fully-assembled history row for the Studio (`GET /api/history`), joining
/// request + response metadata and a finding summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryRow {
    /// Request metadata.
    pub request: RequestMeta,
    /// Response metadata, if the exchange completed.
    pub response: Option<ResponseMeta>,
    /// Count of PII findings on this exchange (for the list badge).
    pub pii_count: u32,
    /// Count of safety findings on this exchange (for the list badge).
    pub safety_count: u32,
}

// ---------------------------------------------------------------------------
// The store: single-writer handle + the writer task
// ---------------------------------------------------------------------------

/// One event to persist, sent over the bounded channel to the single writer.
#[derive(Debug, Clone)]
pub enum WriteOp {
    /// Insert/update an engine journal row.
    Engine(EngineRecord),
    /// Insert request metadata.
    Request(RequestMeta),
    /// Fill in the request's input-token count once the engine reports it in the
    /// response (`prompt_eval_count`). A targeted UPDATE (not a REPLACE) so it
    /// never disturbs the row's other columns or the linked response.
    RequestUsage {
        id: String,
        input_tokens: Option<u32>,
        input_tokens_src: TokenSource,
    },
    /// Insert response metadata.
    Response(ResponseMeta),
    /// Insert a payload (only emitted when `payload_storage` is on).
    Payload(Payload),
    /// Insert a batch of PII findings for one record.
    PiiFindings(Vec<PiiFindingRecord>),
    /// Insert a batch of safety findings for one record (eval pipeline).
    SafetyFindings(Vec<SafetyFindingRecord>),
    /// Insert a batch of eval scores for one record (eval pipeline).
    EvalScores(Vec<EvalScoreRecord>),
    /// Upsert a setting key/value.
    Setting { key: String, value: String },
    /// Upsert an archived session + replace its messages (Preservation layer).
    ArchiveSession(Box<ArchivedSession>),
    /// Flag/unflag an archived session as deleted-from-source (we keep our copy).
    MarkSourceDeleted { id: String, deleted: bool },
}

/// A coding-agent session preserved in the durable archive. Messages are carried
/// on writes and detail reads; empty on list reads.
#[derive(Debug, Clone)]
pub struct ArchivedSession {
    pub id: String,
    pub tool: String,
    pub source_id: String,
    pub title: Option<String>,
    pub project: Option<String>,
    pub git_branch: Option<String>,
    pub model: Option<String>,
    pub started_ts: i64,
    pub updated_ts: i64,
    pub message_count: u32,
    pub tool_call_count: u32,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_tokens: u64,
    pub source_path: Option<String>,
    /// Incremental change key (hash of the normalized content).
    pub content_hash: String,
    pub archived_ts: i64,
    /// The source app has since deleted its copy; ours is the only one left.
    pub source_deleted: bool,
    pub messages: Vec<ArchivedMessage>,
}

/// One message in an archived transcript.
#[derive(Debug, Clone)]
pub struct ArchivedMessage {
    pub role: String,
    pub kind: String,
    pub content: String,
    pub ts: Option<i64>,
    pub tool_name: Option<String>,
}

/// Rollup of the archive's footprint (for storage awareness).
#[derive(Debug, Clone, Default)]
pub struct ArchiveStats {
    pub count: u64,
    pub messages: u64,
    pub bytes: u64,
}

/// A cloneable handle the proxy and control plane use to enqueue writes and run
/// reads. Cheap to clone; sending never blocks the request path (bounded,
/// best-effort enqueue — drops are logged, never surfaced).
///
/// Architecture (04 §7.1): exactly one OS thread owns the writer [`Connection`]
/// and drains the bounded channel; readers open short-lived connections on the
/// blocking pool (WAL lets readers run concurrently with the single writer).
#[derive(Clone)]
pub struct Store {
    inner: Arc<StoreInner>,
}

struct StoreInner {
    /// Bound to the single writer thread. `try_send` keeps the request path
    /// non-blocking (fail-open: a full queue drops the write, logged only).
    tx: mpsc::Sender<WriteOp>,
    /// Path to the on-disk DB, used to open read connections on demand.
    path: std::path::PathBuf,
}

impl Store {
    /// Open (creating if needed) the database at `path`, run migrations, and
    /// spawn the single writer thread. With the `sqlcipher` feature on (the
    /// default), this first performs the keyring/env-key `PRAGMA key` handshake
    /// — before migrations or any other statement touch the file.
    pub async fn open(path: &Path) -> Result<Self> {
        let path = path.to_path_buf();

        // Ensure the parent app-data dir exists before SQLite touches the file.
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    Error::Store(format!("creating data dir {}: {e}", parent.display()))
                })?;
            }
        }

        // Open + migrate the writer connection on the blocking pool so we never
        // stall the async runtime on disk I/O.
        let writer_path = path.clone();
        let conn = tokio::task::spawn_blocking(move || -> Result<Connection> {
            let conn = open_connection(&writer_path)?;
            schema::migrate(&conn)?;
            Ok(conn)
        })
        .await
        .map_err(|e| Error::Store(format!("writer init join: {e}")))??;

        let (tx, rx) = mpsc::channel::<WriteOp>(WRITER_QUEUE_CAPACITY);
        spawn_writer(conn, rx);

        Ok(Store {
            inner: Arc::new(StoreInner { tx, path }),
        })
    }

    /// Enqueue a write (best-effort, non-blocking; fail-open).
    ///
    /// Uses `try_send`: if the writer is saturated or gone, the write is dropped
    /// and logged — it is **never** allowed to block or fail the request path
    /// (the hard fail-open invariant).
    pub fn enqueue(&self, op: WriteOp) {
        if let Err(e) = self.inner.tx.try_send(op) {
            // Drop-and-log: logging must never break inference.
            tracing::warn!(target: "saffev::store", "dropped write op: {e}");
        }
    }

    /// Backpressure-safe enqueue for correctness-critical batch writes (the
    /// Preservation archive): blocks the calling thread until the writer has room
    /// instead of dropping. **Must** be called from a blocking context (inside
    /// `spawn_blocking`), never on the async runtime. `Err` only if the writer is
    /// gone.
    pub fn enqueue_blocking(&self, op: WriteOp) -> Result<()> {
        self.inner
            .tx
            .blocking_send(op)
            .map_err(|_| Error::Store("writer thread gone".into()))
    }

    /// Run a read query on a fresh connection on the blocking pool. WAL mode
    /// lets these run concurrently with the single writer.
    async fn read<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> Result<T> + Send + 'static,
    {
        let path = self.inner.path.clone();
        tokio::task::spawn_blocking(move || -> Result<T> {
            let conn = open_read_connection(&path)?;
            f(&conn)
        })
        .await
        .map_err(|e| Error::Store(format!("read join: {e}")))?
    }

    /// Flush: block until the writer has drained at least up to a fresh fence
    /// (test/control helper, not on the request path). Writes a unique fence
    /// value through the ordered channel, then polls a read connection until the
    /// writer has committed it — guaranteeing every op enqueued *before* this
    /// call is durable.
    #[doc(hidden)]
    pub async fn flush(&self) -> Result<()> {
        let fence = uuid::Uuid::new_v4().to_string();
        self.inner
            .tx
            .send(WriteOp::Setting {
                key: FLUSH_FENCE_KEY.to_string(),
                value: fence.clone(),
            })
            .await
            .map_err(|e| Error::Store(format!("flush enqueue: {e}")))?;

        // Poll until the fence value is visible (the channel is FIFO, so once
        // the writer has committed this fence, all prior ops are committed too).
        for _ in 0..1000 {
            if self.get_setting(FLUSH_FENCE_KEY).await? == Some(fence.clone()) {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        Err(Error::Store("flush timed out".into()))
    }

    /// Fetch a page of history rows for the Studio.
    pub async fn history(&self, query: HistoryQuery) -> Result<Vec<HistoryRow>> {
        self.read(move |conn| query_history(conn, &query)).await
    }

    /// Total number of requests ever recorded. Cheap `COUNT(*)`; used by the
    /// Studio to distinguish "no traffic captured yet" (show onboarding) from a
    /// merely empty recent window.
    pub async fn request_count(&self) -> Result<u64> {
        self.read(|conn| {
            let n: i64 = conn.query_row("SELECT count(*) FROM requests", [], |row| row.get(0))?;
            Ok(n.max(0) as u64)
        })
        .await
    }

    /// Fetch the full payload for one record (History detail; only when stored).
    pub async fn payload(&self, request_id: &str) -> Result<Option<Payload>> {
        let request_id = request_id.to_string();
        self.read(move |conn| {
            conn.query_row(
                "SELECT request_id, prompt, response FROM payloads WHERE request_id = ?1",
                [&request_id],
                |row| {
                    Ok(Payload {
                        request_id: row.get(0)?,
                        prompt: row.get(1)?,
                        response: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(Error::from)
        })
        .await
    }

    /// Aggregate PII findings for the Privacy page. Returns every finding row;
    /// the Studio layer buckets them by kind/side/app/model.
    pub async fn privacy_summary(&self) -> Result<Vec<PiiFindingRecord>> {
        self.read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, record_id, side, type, label, start_off, end_off, \
                 confidence, action, value_hash FROM pii_findings",
            )?;
            let rows = stmt
                .query_map([], row_to_pii_finding)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
    }

    /// All safety findings (eval pipeline). The Studio buckets them by category.
    pub async fn safety_findings(&self) -> Result<Vec<SafetyFindingRecord>> {
        self.read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT record_id, guard_model, category, verdict, score, ts \
                 FROM safety_findings",
            )?;
            let rows = stmt
                .query_map([], row_to_safety)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
    }

    /// Safety findings for one exchange (History detail drawer).
    pub async fn safety_for(&self, record_id: &str) -> Result<Vec<SafetyFindingRecord>> {
        let record_id = record_id.to_string();
        self.read(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT record_id, guard_model, category, verdict, score, ts \
                 FROM safety_findings WHERE record_id = ?1",
            )?;
            let rows = stmt
                .query_map([&record_id], row_to_safety)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
    }

    /// All eval scores (eval pipeline). The Studio buckets them by metric/band.
    pub async fn eval_scores(&self) -> Result<Vec<EvalScoreRecord>> {
        self.read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT record_id, judge_model, metric, band, rationale, sampled, ts \
                 FROM eval_scores",
            )?;
            let rows = stmt
                .query_map([], row_to_eval)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
    }

    /// Eval scores for one exchange (History detail drawer).
    pub async fn eval_for(&self, record_id: &str) -> Result<Vec<EvalScoreRecord>> {
        let record_id = record_id.to_string();
        self.read(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT record_id, judge_model, metric, band, rationale, sampled, ts \
                 FROM eval_scores WHERE record_id = ?1",
            )?;
            let rows = stmt
                .query_map([&record_id], row_to_eval)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
    }

    /// Read every engine journal row.
    pub async fn engines(&self) -> Result<Vec<EngineRecord>> {
        self.read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, engine, version, public_port, shadow_port, \
                 adoption_state, journal_json, updated_at FROM engines ORDER BY id",
            )?;
            let rows = stmt
                .query_map([], row_to_engine)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
    }

    /// Read a single setting.
    pub async fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let key = key.to_string();
        self.read(move |conn| {
            conn.query_row("SELECT value FROM settings WHERE key = ?1", [&key], |row| {
                row.get::<_, String>(0)
            })
            .optional()
            .map_err(Error::from)
        })
        .await
    }

    /// Archive index: `id -> content_hash` for every preserved session. The
    /// snapshot job uses this to skip unchanged sessions (incremental).
    pub async fn archived_index(&self) -> Result<std::collections::HashMap<String, String>> {
        self.read(|conn| {
            let mut stmt = conn.prepare("SELECT id, content_hash FROM archived_sessions")?;
            let rows = stmt
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows.into_iter().collect())
        })
        .await
    }

    /// All archived session summaries (no messages), newest first.
    pub async fn archived_sessions(&self) -> Result<Vec<ArchivedSession>> {
        self.read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id,tool,source_id,title,project,git_branch,model,started_ts,updated_ts, \
                 message_count,tool_call_count,input_tokens,output_tokens,cache_tokens, \
                 source_path,content_hash,archived_ts,source_deleted \
                 FROM archived_sessions ORDER BY updated_ts DESC",
            )?;
            let rows = stmt
                .query_map([], row_to_archived)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
    }

    /// One archived session with its full transcript, or `None`.
    pub async fn archived_detail(&self, id: &str) -> Result<Option<ArchivedSession>> {
        let id = id.to_string();
        self.read(move |conn| {
            let mut session = conn
                .query_row(
                    "SELECT id,tool,source_id,title,project,git_branch,model,started_ts,updated_ts, \
                     message_count,tool_call_count,input_tokens,output_tokens,cache_tokens, \
                     source_path,content_hash,archived_ts,source_deleted \
                     FROM archived_sessions WHERE id = ?1",
                    [&id],
                    row_to_archived,
                )
                .optional()?;
            if let Some(s) = session.as_mut() {
                let mut stmt = conn.prepare(
                    "SELECT role,kind,content,ts,tool_name FROM archived_messages \
                     WHERE session_id = ?1 ORDER BY seq",
                )?;
                s.messages = stmt
                    .query_map([&id], |r| {
                        Ok(ArchivedMessage {
                            role: r.get(0)?,
                            kind: r.get(1)?,
                            content: r.get(2)?,
                            ts: r.get(3)?,
                            tool_name: r.get(4)?,
                        })
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
            }
            Ok(session)
        })
        .await
    }

    /// Archive footprint: session count, message count, approximate bytes.
    pub async fn archive_stats(&self) -> Result<ArchiveStats> {
        self.read(|conn| {
            let (count, messages): (u64, u64) = conn.query_row(
                "SELECT COUNT(*), COALESCE(SUM(message_count),0) FROM archived_sessions",
                [],
                |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64)),
            )?;
            let bytes: u64 = conn.query_row(
                "SELECT COALESCE(SUM(LENGTH(content)),0) FROM archived_messages",
                [],
                |r| Ok(r.get::<_, i64>(0)? as u64),
            )?;
            Ok(ArchiveStats {
                count,
                messages,
                bytes,
            })
        })
        .await
    }

    /// Apply the retention policy (purge by age/size). Runs off the hot path on
    /// the blocking pool. Cascading deletes of `responses`/`payloads`/findings
    /// keyed to purged requests keep the store consistent.
    pub async fn enforce_retention(&self, retention: crate::config::Retention) -> Result<()> {
        use crate::config::Retention;

        // A purge is a write; route it through a dedicated short-lived writer
        // connection so it serializes naturally with the single-writer model
        // (it only deletes, never races metadata inserts for the same id).
        let path = self.inner.path.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = open_connection(&path)?;
            match retention {
                Retention::Unlimited => Ok(()),
                Retention::Age { days } => {
                    let now_ms = now_millis();
                    let cutoff = now_ms - (days as i64) * 86_400_000;
                    purge_requests_before(&conn, cutoff)
                }
                Retention::Size { mb } => {
                    let target_bytes = (mb as i64) * 1_024 * 1_024;
                    purge_to_size(&conn, target_bytes)
                }
            }
        })
        .await
        .map_err(|e| Error::Store(format!("retention join: {e}")))?
    }
}

/// Magic settings key used by [`Store::flush`] as an internal fence. Never read
/// by the Studio.
const FLUSH_FENCE_KEY: &str = "__saffev_flush_fence";

// ---------------------------------------------------------------------------
// Connection setup (writer + read)
// ---------------------------------------------------------------------------

/// Open a read/write connection and apply per-connection pragmas. With the
/// `sqlcipher` feature on, performs the keyring-key `PRAGMA key` handshake
/// **before** any other access (required by SQLCipher).
fn open_connection(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path).map_err(Error::from)?;
    apply_key(&conn)?;
    // Busy timeout so a brief writer/reader contention waits instead of erroring
    // (WAL makes this rare, but keeps fail-open behaviour honest).
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(conn)
}

/// Open a connection intended for reads. Same key handshake; WAL allows readers
/// to run concurrently with the single writer.
fn open_read_connection(path: &Path) -> Result<Connection> {
    open_connection(path)
}

/// SQLCipher key handshake. Active in the default build (`sqlcipher` feature on);
/// a no-op only under `--no-default-features`, where the DB is plain bundled
/// SQLite (acceptance §10.5 requires the encrypted default for release builds).
///
/// The key is read from the OS keyring, or the `SAFFEV_DB_KEY` env var when set
/// (headless/CI/dev override — see [`keys::get_or_create_db_key`]).
#[cfg(feature = "sqlcipher")]
fn apply_key(conn: &Connection) -> Result<()> {
    let key = keys::get_or_create_db_key()?;
    // PRAGMA key must run first, before touching any table. Use a quoted string
    // key (passphrase form); SQLCipher derives the actual key via KDF.
    conn.pragma_update(None, "key", key.as_str())?;
    // Sanity probe: this forces SQLCipher to attempt decryption now so a bad key
    // surfaces here (control-plane) rather than mid-query.
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
        row.get::<_, i64>(0)
    })?;
    Ok(())
}

#[cfg(not(feature = "sqlcipher"))]
#[inline]
fn apply_key(_conn: &Connection) -> Result<()> {
    Ok(())
}

// ---------------------------------------------------------------------------
// The single writer thread
// ---------------------------------------------------------------------------

/// Spawn the one dedicated writer. It owns `conn` for its whole life and drains
/// the channel until every `Store` handle is dropped (sender closed). Each op is
/// applied independently; a single failing write is logged and skipped — the
/// writer never dies on a bad row (fail-open).
fn spawn_writer(conn: Connection, mut rx: mpsc::Receiver<WriteOp>) {
    // A blocking OS thread, not a tokio task: rusqlite is sync and we want the
    // connection pinned to one thread for its entire lifetime.
    tokio::task::spawn_blocking(move || {
        while let Some(op) = rx.blocking_recv() {
            if let Err(e) = apply_write(&conn, &op) {
                tracing::warn!(target: "saffev::store", "write failed: {e}");
            }
        }
        tracing::debug!(target: "saffev::store", "writer thread exiting (channel closed)");
    });
}

/// Apply one [`WriteOp`] to the writer connection.
fn apply_write(conn: &Connection, op: &WriteOp) -> Result<()> {
    match op {
        WriteOp::Engine(e) => {
            // Upsert by engine name so re-detection updates the same row.
            conn.execute(
                "INSERT INTO engines \
                 (id, engine, version, public_port, shadow_port, adoption_state, journal_json, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
                 ON CONFLICT(id) DO UPDATE SET \
                   engine=excluded.engine, version=excluded.version, \
                   public_port=excluded.public_port, shadow_port=excluded.shadow_port, \
                   adoption_state=excluded.adoption_state, journal_json=excluded.journal_json, \
                   updated_at=excluded.updated_at",
                rusqlite::params![
                    if e.id == 0 { None } else { Some(e.id) },
                    e.engine,
                    e.version,
                    e.public_port,
                    e.shadow_port,
                    adoption_state_str(e.adoption_state),
                    e.journal_json,
                    e.updated_at,
                ],
            )?;
        }
        WriteOp::Request(r) => {
            conn.execute(
                "INSERT OR REPLACE INTO requests \
                 (id, ts, source_app, source_confidence, engine, model, endpoint, stream, \
                  input_tokens, input_tokens_src, latency_ms, request_hash) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                rusqlite::params![
                    r.id,
                    r.ts,
                    r.source_app,
                    source_confidence_str(r.source_confidence),
                    r.engine,
                    r.model,
                    r.endpoint,
                    r.stream as i64,
                    r.input_tokens,
                    token_source_str(r.input_tokens_src),
                    r.latency_ms,
                    r.request_hash,
                ],
            )?;
        }
        WriteOp::RequestUsage {
            id,
            input_tokens,
            input_tokens_src,
        } => {
            conn.execute(
                "UPDATE requests SET input_tokens = ?2, input_tokens_src = ?3 WHERE id = ?1",
                rusqlite::params![id, input_tokens, token_source_str(*input_tokens_src)],
            )?;
        }
        WriteOp::Response(r) => {
            // One response per request: replace any prior partial row.
            conn.execute(
                "DELETE FROM responses WHERE request_id = ?1",
                [&r.request_id],
            )?;
            conn.execute(
                "INSERT INTO responses \
                 (request_id, finish_reason, output_tokens, output_tokens_src, ttft_ms, total_ms, \
                  status, error_kind) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                rusqlite::params![
                    r.request_id,
                    r.finish_reason,
                    r.output_tokens,
                    token_source_str(r.output_tokens_src),
                    r.ttft_ms,
                    r.total_ms,
                    r.status,
                    r.error_kind,
                ],
            )?;
        }
        WriteOp::Payload(p) => {
            conn.execute(
                "INSERT OR REPLACE INTO payloads (request_id, prompt, response) \
                 VALUES (?1,?2,?3)",
                rusqlite::params![p.request_id, p.prompt, p.response],
            )?;
        }
        WriteOp::PiiFindings(findings) => {
            // Batch under one transaction for atomicity + speed.
            let tx = conn.unchecked_transaction()?;
            {
                let mut stmt = tx.prepare(
                    "INSERT INTO pii_findings \
                     (record_id, side, type, label, start_off, end_off, confidence, action, value_hash) \
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                )?;
                for f in findings {
                    stmt.execute(rusqlite::params![
                        f.record_id,
                        side_str(f.side),
                        pii_kind_str(f.kind),
                        f.label,
                        f.start_off as i64,
                        f.end_off as i64,
                        confidence_str(f.confidence),
                        pii_action_str(f.action),
                        f.value_hash,
                    ])?;
                }
            }
            tx.commit()?;
        }
        WriteOp::SafetyFindings(findings) => {
            let tx = conn.unchecked_transaction()?;
            {
                let mut stmt = tx.prepare(
                    "INSERT INTO safety_findings \
                     (record_id, guard_model, category, verdict, score, ts) \
                     VALUES (?1,?2,?3,?4,?5,?6)",
                )?;
                for f in findings {
                    stmt.execute(rusqlite::params![
                        f.record_id,
                        f.guard_model,
                        f.category,
                        f.verdict,
                        f.score,
                        f.ts,
                    ])?;
                }
            }
            tx.commit()?;
        }
        WriteOp::EvalScores(scores) => {
            let tx = conn.unchecked_transaction()?;
            {
                let mut stmt = tx.prepare(
                    "INSERT INTO eval_scores \
                     (record_id, judge_model, metric, band, rationale, sampled, ts) \
                     VALUES (?1,?2,?3,?4,?5,?6,?7)",
                )?;
                for s in scores {
                    stmt.execute(rusqlite::params![
                        s.record_id,
                        s.judge_model,
                        s.metric,
                        s.band,
                        s.rationale,
                        s.sampled as i64,
                        s.ts,
                    ])?;
                }
            }
            tx.commit()?;
        }
        WriteOp::Setting { key, value } => {
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?1, ?2) \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                rusqlite::params![key, value],
            )?;
        }
        WriteOp::ArchiveSession(s) => {
            // Idempotent upsert: replace the session row + its messages atomically.
            let tx = conn.unchecked_transaction()?;
            {
                tx.execute(
                    "DELETE FROM archived_messages WHERE session_id = ?1",
                    [&s.id],
                )?;
                tx.execute(
                    "INSERT OR REPLACE INTO archived_sessions \
                     (id,tool,source_id,title,project,git_branch,model,started_ts,updated_ts, \
                      message_count,tool_call_count,input_tokens,output_tokens,cache_tokens, \
                      source_path,content_hash,archived_ts,source_deleted) \
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
                    rusqlite::params![
                        s.id,
                        s.tool,
                        s.source_id,
                        s.title,
                        s.project,
                        s.git_branch,
                        s.model,
                        s.started_ts,
                        s.updated_ts,
                        s.message_count as i64,
                        s.tool_call_count as i64,
                        s.input_tokens as i64,
                        s.output_tokens as i64,
                        s.cache_tokens as i64,
                        s.source_path,
                        s.content_hash,
                        s.archived_ts,
                        s.source_deleted as i64,
                    ],
                )?;
                let mut stmt = tx.prepare(
                    "INSERT INTO archived_messages \
                     (session_id, seq, role, kind, content, ts, tool_name) \
                     VALUES (?1,?2,?3,?4,?5,?6,?7)",
                )?;
                for (i, m) in s.messages.iter().enumerate() {
                    stmt.execute(rusqlite::params![
                        s.id,
                        i as i64,
                        m.role,
                        m.kind,
                        m.content,
                        m.ts,
                        m.tool_name,
                    ])?;
                }
            }
            tx.commit()?;
        }
        WriteOp::MarkSourceDeleted { id, deleted } => {
            conn.execute(
                "UPDATE archived_sessions SET source_deleted = ?2 WHERE id = ?1",
                rusqlite::params![id, *deleted as i64],
            )?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Read queries
// ---------------------------------------------------------------------------

/// Build + run the history query with optional free-text + pii-only filters and
/// `before_ts` cursor paging. Joins responses + a per-request finding count.
fn query_history(conn: &Connection, query: &HistoryQuery) -> Result<Vec<HistoryRow>> {
    let limit = query.limit.unwrap_or(100).min(1000) as i64;

    // Dynamic WHERE assembled with bound params (never string-interpolated user
    // input — SQL injection safe).
    let mut wheres: Vec<String> = Vec::new();
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

    if let Some(before) = query.before_ts {
        wheres.push(format!("r.ts < ?{}", params.len() + 1));
        params.push(Box::new(before));
    }
    if let Some(q) = query.q.as_ref().filter(|s| !s.trim().is_empty()) {
        let like = format!("%{}%", q.trim());
        let base = params.len();
        wheres.push(format!(
            "(r.source_app LIKE ?{} OR r.model LIKE ?{} OR r.endpoint LIKE ?{} OR r.engine LIKE ?{})",
            base + 1,
            base + 2,
            base + 3,
            base + 4
        ));
        params.push(Box::new(like.clone()));
        params.push(Box::new(like.clone()));
        params.push(Box::new(like.clone()));
        params.push(Box::new(like));
    }

    let pii_count_expr =
        "(SELECT count(*) FROM pii_findings pf WHERE pf.record_id = r.id) AS pii_count";
    let safety_count_expr =
        "(SELECT count(*) FROM safety_findings sf WHERE sf.record_id = r.id) AS safety_count";

    if query.pii_only {
        wheres.push("(SELECT count(*) FROM pii_findings pf WHERE pf.record_id = r.id) > 0".into());
    }

    if query.failed_only {
        // A failed exchange: a transport error (error_kind set) or an HTTP error
        // status (>= 400) on the joined response row.
        wheres.push("(resp.error_kind IS NOT NULL OR resp.status >= 400)".into());
    }

    let where_clause = if wheres.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", wheres.join(" AND "))
    };

    let sql = format!(
        "SELECT \
           r.id, r.ts, r.source_app, r.source_confidence, r.engine, r.model, r.endpoint, \
           r.stream, r.input_tokens, r.input_tokens_src, r.latency_ms, r.request_hash, \
           resp.request_id, resp.finish_reason, resp.output_tokens, resp.output_tokens_src, \
           resp.ttft_ms, resp.total_ms, resp.status, resp.error_kind, \
           {pii_count_expr}, {safety_count_expr} \
         FROM requests r \
         LEFT JOIN responses resp ON resp.request_id = r.id \
         {where_clause} \
         ORDER BY r.ts DESC \
         LIMIT {limit}"
    );

    let mut stmt = conn.prepare(&sql)?;
    let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|b| b.as_ref()).collect();
    let rows = stmt
        .query_map(param_refs.as_slice(), row_to_history)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Map a joined history row.
fn row_to_history(row: &rusqlite::Row<'_>) -> rusqlite::Result<HistoryRow> {
    let request = RequestMeta {
        id: row.get(0)?,
        ts: row.get(1)?,
        source_app: row.get(2)?,
        source_confidence: parse_source_confidence(&row.get::<_, String>(3)?),
        engine: row.get(4)?,
        model: row.get(5)?,
        endpoint: row.get(6)?,
        stream: row.get::<_, i64>(7)? != 0,
        input_tokens: row.get(8)?,
        input_tokens_src: parse_token_source(&row.get::<_, String>(9)?),
        latency_ms: row.get(10)?,
        request_hash: row.get(11)?,
    };

    // responses.request_id is NULL when there's no joined response row.
    let response = match row.get::<_, Option<String>>(12)? {
        Some(req_id) => Some(ResponseMeta {
            request_id: req_id,
            finish_reason: row.get(13)?,
            output_tokens: row.get(14)?,
            output_tokens_src: row
                .get::<_, Option<String>>(15)?
                .map(|s| parse_token_source(&s))
                .unwrap_or(TokenSource::Exact),
            ttft_ms: row.get(16)?,
            total_ms: row.get(17)?,
            status: row.get(18)?,
            error_kind: row.get(19)?,
        }),
        None => None,
    };

    let pii_count: i64 = row.get(20)?;
    let safety_count: i64 = row.get(21)?;

    Ok(HistoryRow {
        request,
        response,
        pii_count: pii_count as u32,
        safety_count: safety_count as u32,
    })
}

/// Map a `safety_findings` row.
fn row_to_safety(row: &rusqlite::Row<'_>) -> rusqlite::Result<SafetyFindingRecord> {
    Ok(SafetyFindingRecord {
        record_id: row.get(0)?,
        guard_model: row.get(1)?,
        category: row.get(2)?,
        verdict: row.get(3)?,
        score: row.get(4)?,
        ts: row.get(5)?,
    })
}

/// Map an `eval_scores` row.
fn row_to_eval(row: &rusqlite::Row<'_>) -> rusqlite::Result<EvalScoreRecord> {
    Ok(EvalScoreRecord {
        record_id: row.get(0)?,
        judge_model: row.get(1)?,
        metric: row.get(2)?,
        band: row.get(3)?,
        rationale: row.get(4)?,
        sampled: row.get::<_, i64>(5)? != 0,
        ts: row.get(6)?,
    })
}

/// Map a `pii_findings` row.
fn row_to_pii_finding(row: &rusqlite::Row<'_>) -> rusqlite::Result<PiiFindingRecord> {
    Ok(PiiFindingRecord {
        id: row.get(0)?,
        record_id: row.get(1)?,
        side: parse_side(&row.get::<_, String>(2)?),
        kind: parse_pii_kind(&row.get::<_, String>(3)?),
        label: row.get(4)?,
        start_off: row.get::<_, i64>(5)? as usize,
        end_off: row.get::<_, i64>(6)? as usize,
        confidence: parse_confidence(&row.get::<_, String>(7)?),
        action: parse_pii_action(&row.get::<_, String>(8)?),
        value_hash: row.get(9)?,
    })
}

/// Map an `archived_sessions` row (messages filled separately). Column order must
/// match the SELECTs in `archived_sessions`/`archived_detail`.
fn row_to_archived(row: &rusqlite::Row<'_>) -> rusqlite::Result<ArchivedSession> {
    Ok(ArchivedSession {
        id: row.get(0)?,
        tool: row.get(1)?,
        source_id: row.get(2)?,
        title: row.get(3)?,
        project: row.get(4)?,
        git_branch: row.get(5)?,
        model: row.get(6)?,
        started_ts: row.get(7)?,
        updated_ts: row.get(8)?,
        message_count: row.get::<_, i64>(9)? as u32,
        tool_call_count: row.get::<_, i64>(10)? as u32,
        input_tokens: row.get::<_, i64>(11)? as u64,
        output_tokens: row.get::<_, i64>(12)? as u64,
        cache_tokens: row.get::<_, i64>(13)? as u64,
        source_path: row.get(14)?,
        content_hash: row.get(15)?,
        archived_ts: row.get(16)?,
        source_deleted: row.get::<_, i64>(17)? != 0,
        messages: Vec::new(),
    })
}

/// Map an `engines` row.
fn row_to_engine(row: &rusqlite::Row<'_>) -> rusqlite::Result<EngineRecord> {
    Ok(EngineRecord {
        id: row.get(0)?,
        engine: row.get(1)?,
        version: row.get(2)?,
        public_port: row.get::<_, i64>(3)? as u16,
        shadow_port: row.get::<_, Option<i64>>(4)?.map(|p| p as u16),
        adoption_state: parse_adoption_state(&row.get::<_, String>(5)?),
        journal_json: row.get(6)?,
        updated_at: row.get(7)?,
    })
}

// ---------------------------------------------------------------------------
// Retention
// ---------------------------------------------------------------------------

/// Delete every request (and its dependent rows) with `ts < cutoff`.
fn purge_requests_before(conn: &Connection, cutoff_ms: i64) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    // Children first (no ON DELETE CASCADE in the v1 DDL), then parents.
    tx.execute(
        "DELETE FROM responses WHERE request_id IN \
         (SELECT id FROM requests WHERE ts < ?1)",
        [cutoff_ms],
    )?;
    tx.execute(
        "DELETE FROM payloads WHERE request_id IN \
         (SELECT id FROM requests WHERE ts < ?1)",
        [cutoff_ms],
    )?;
    tx.execute(
        "DELETE FROM pii_findings WHERE record_id IN \
         (SELECT id FROM requests WHERE ts < ?1)",
        [cutoff_ms],
    )?;
    tx.execute("DELETE FROM requests WHERE ts < ?1", [cutoff_ms])?;
    tx.commit()?;
    Ok(())
}

/// Drop oldest requests until the DB file is under `target_bytes`. Deletes in
/// age-ordered batches, re-measuring after each batch.
fn purge_to_size(conn: &Connection, target_bytes: i64) -> Result<()> {
    const BATCH: i64 = 500;
    loop {
        let size = db_size_bytes(conn)?;
        if size <= target_bytes {
            break;
        }
        // Find the cutoff ts of the oldest BATCH requests.
        let cutoff: Option<i64> = conn
            .query_row(
                "SELECT ts FROM requests ORDER BY ts ASC LIMIT 1 OFFSET ?1",
                [BATCH],
                |row| row.get(0),
            )
            .optional()?;
        match cutoff {
            // Fewer than BATCH rows left and still over budget: purge everything.
            None => {
                let tx = conn.unchecked_transaction()?;
                tx.execute("DELETE FROM responses", [])?;
                tx.execute("DELETE FROM payloads", [])?;
                tx.execute("DELETE FROM pii_findings", [])?;
                tx.execute("DELETE FROM requests", [])?;
                tx.commit()?;
                break;
            }
            Some(cut) => {
                purge_requests_before(conn, cut)?;
                // Reclaim freed pages so the size check reflects the delete.
                conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
            }
        }
    }
    Ok(())
}

/// Approximate on-disk size in bytes via `page_count * page_size`.
fn db_size_bytes(conn: &Connection) -> Result<i64> {
    let page_count: i64 = conn.query_row("PRAGMA page_count", [], |row| row.get(0))?;
    let page_size: i64 = conn.query_row("PRAGMA page_size", [], |row| row.get(0))?;
    Ok(page_count * page_size)
}

// ---------------------------------------------------------------------------
// Enum <-> TEXT mapping (matches serde rename_all on the shared types)
// ---------------------------------------------------------------------------

fn adoption_state_str(s: AdoptionState) -> &'static str {
    match s {
        AdoptionState::Detected => "detected",
        AdoptionState::Cooperative => "cooperative",
        AdoptionState::Adopted => "adopted",
        AdoptionState::Reverted => "reverted",
    }
}

fn parse_adoption_state(s: &str) -> AdoptionState {
    match s {
        "cooperative" => AdoptionState::Cooperative,
        "adopted" => AdoptionState::Adopted,
        "reverted" => AdoptionState::Reverted,
        _ => AdoptionState::Detected,
    }
}

fn token_source_str(s: TokenSource) -> &'static str {
    match s {
        TokenSource::Exact => "exact",
        TokenSource::Estimated => "estimated",
    }
}

fn parse_token_source(s: &str) -> TokenSource {
    match s {
        "estimated" => TokenSource::Estimated,
        _ => TokenSource::Exact,
    }
}

fn source_confidence_str(s: SourceConfidence) -> &'static str {
    match s {
        SourceConfidence::Pid => "pid",
        SourceConfidence::Header => "header",
        SourceConfidence::Unknown => "unknown",
    }
}

fn parse_source_confidence(s: &str) -> SourceConfidence {
    match s {
        "pid" => SourceConfidence::Pid,
        "header" => SourceConfidence::Header,
        _ => SourceConfidence::Unknown,
    }
}

fn side_str(s: Side) -> &'static str {
    match s {
        Side::Request => "request",
        Side::Response => "response",
    }
}

fn parse_side(s: &str) -> Side {
    match s {
        "response" => Side::Response,
        _ => Side::Request,
    }
}

fn pii_kind_str(k: PiiKind) -> &'static str {
    match k {
        PiiKind::Email => "email",
        PiiKind::Phone => "phone",
        PiiKind::CreditCard => "credit_card",
        PiiKind::ApiKey => "api_key",
        PiiKind::IpAddress => "ip_address",
        PiiKind::Custom => "custom",
    }
}

fn parse_pii_kind(s: &str) -> PiiKind {
    match s {
        "email" => PiiKind::Email,
        "phone" => PiiKind::Phone,
        "credit_card" => PiiKind::CreditCard,
        "api_key" => PiiKind::ApiKey,
        "ip_address" => PiiKind::IpAddress,
        _ => PiiKind::Custom,
    }
}

fn confidence_str(c: Confidence) -> &'static str {
    match c {
        Confidence::High => "high",
        Confidence::Low => "low",
    }
}

fn parse_confidence(s: &str) -> Confidence {
    match s {
        "low" => Confidence::Low,
        _ => Confidence::High,
    }
}

fn pii_action_str(a: PiiAction) -> &'static str {
    match a {
        PiiAction::Observed => "observed",
        PiiAction::WouldMask => "would_mask",
        PiiAction::Masked => "masked",
    }
}

fn parse_pii_action(s: &str) -> PiiAction {
    match s {
        "would_mask" => PiiAction::WouldMask,
        "masked" => PiiAction::Masked,
        _ => PiiAction::Observed,
    }
}

/// Current wall-clock time in unix milliseconds.
fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Filter/paging for [`Store::history`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HistoryQuery {
    /// Free-text filter (app/model/endpoint).
    pub q: Option<String>,
    /// Only rows with at least one PII finding.
    pub pii_only: bool,
    /// Only failed exchanges (transport error, or HTTP status >= 400).
    pub failed_only: bool,
    /// Max rows to return.
    pub limit: Option<u32>,
    /// Return rows with `ts` strictly before this (millis) — cursor paging.
    pub before_ts: Option<i64>,
}

// ---------------------------------------------------------------------------
// Keyring key management
// ---------------------------------------------------------------------------

/// Keyring-backed secret management: the DB encryption key and the install token.
///
/// Secrets live in the OS keyring (Keychain on macOS, Secret Service / libsecret
/// on Linux) — never on disk, never in the config file. Both values are
/// generated lazily on first run and returned verbatim thereafter.
pub mod keys {
    use keyring::{Entry, Error as KeyringError};

    use crate::{Error, Result};

    /// Keyring service name under which Saffev stores its secrets.
    pub const KEYRING_SERVICE: &str = "saffev";
    /// Keyring entry name for the database encryption key (used with `sqlcipher`).
    pub const DB_KEY_ENTRY: &str = "db-key";
    /// Keyring entry name for the per-install Studio bearer token.
    pub const INSTALL_TOKEN_ENTRY: &str = "install-token";

    /// Fetch the DB key, generating + storing a fresh one on first run.
    ///
    /// 256 bits of entropy as lowercase hex — used as the SQLCipher passphrase
    /// when the `sqlcipher` feature is on.
    pub fn get_or_create_db_key() -> Result<String> {
        if let Some(k) = env_secret(DB_KEY_ENV) {
            return Ok(k);
        }
        get_or_create(DB_KEY_ENTRY)
    }

    /// Env override for the DB key (headless/CI/dev — bypasses the keyring).
    pub const DB_KEY_ENV: &str = "SAFFEV_DB_KEY";
    /// Env override for the install token (headless/CI/dev — bypasses the keyring).
    pub const INSTALL_TOKEN_ENV: &str = "SAFFEV_INSTALL_TOKEN";

    /// Fetch the install bearer token, generating one on first run. Gates the
    /// Studio + control endpoints (04 §7.8). Honors `SAFFEV_INSTALL_TOKEN` first
    /// (headless/CI/dev, and unsigned dev rebuilds), otherwise the OS keyring.
    pub fn get_or_create_install_token() -> Result<String> {
        if let Some(t) = env_secret(INSTALL_TOKEN_ENV) {
            return Ok(t);
        }
        get_or_create(INSTALL_TOKEN_ENTRY)
    }

    /// A non-empty secret from environment `var`, if set.
    fn env_secret(var: &str) -> Option<String> {
        std::env::var(var).ok().filter(|v| !v.is_empty())
    }

    /// Shared get-or-create: read the entry, and on `NoEntry` generate, store,
    /// and return a fresh random secret.
    fn get_or_create(entry_name: &str) -> Result<String> {
        let entry = Entry::new(KEYRING_SERVICE, entry_name)
            .map_err(|e| Error::Keyring(format!("opening keyring entry {entry_name}: {e}")))?;

        match entry.get_password() {
            Ok(secret) => Ok(secret),
            Err(KeyringError::NoEntry) => {
                let secret = generate_secret();
                entry.set_password(&secret).map_err(|e| {
                    Error::Keyring(format!("storing keyring entry {entry_name}: {e}"))
                })?;
                Ok(secret)
            }
            Err(e) => Err(Error::Keyring(format!(
                "reading keyring entry {entry_name}: {e}"
            ))),
        }
    }

    /// 256 bits of random hex (two v4 UUIDs concatenated, dashes stripped).
    fn generate_secret() -> String {
        let a = uuid::Uuid::new_v4().simple().to_string();
        let b = uuid::Uuid::new_v4().simple().to_string();
        format!("{a}{b}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Retention;

    /// Ensure a DB key is available for every test in this binary.
    ///
    /// With the `sqlcipher` feature on (the default), `Store::open` runs the
    /// `PRAGMA key` handshake using [`keys::get_or_create_db_key`], which would
    /// otherwise hit the OS keyring. Tests must not depend on the keyring, so we
    /// pin a fixed key via the `SAFFEV_DB_KEY` env override exactly once,
    /// process-wide, before any `Store::open`. Idempotent and parallel-safe (the
    /// value never changes once set, so a benign race just writes the same key).
    fn ensure_test_db_key() {
        use std::sync::Once;
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            if std::env::var(keys::DB_KEY_ENV)
                .map(|v| v.is_empty())
                .unwrap_or(true)
            {
                std::env::set_var(keys::DB_KEY_ENV, "test-db-key-0123456789abcdef");
            }
        });
    }

    fn tmp_db() -> std::path::PathBuf {
        ensure_test_db_key();
        let mut p = std::env::temp_dir();
        p.push(format!("saffev-store-test-{}.db", uuid::Uuid::new_v4()));
        p
    }

    fn req(id: &str, ts: i64) -> RequestMeta {
        RequestMeta {
            id: id.to_string(),
            ts,
            source_app: Some("test-app".into()),
            source_confidence: SourceConfidence::Pid,
            engine: "ollama".into(),
            model: Some("llama3".into()),
            endpoint: "/api/chat".into(),
            stream: true,
            input_tokens: Some(42),
            input_tokens_src: TokenSource::Exact,
            latency_ms: Some(120),
            request_hash: "deadbeef".into(),
        }
    }

    #[tokio::test]
    async fn open_runs_migrations_and_round_trips() {
        let path = tmp_db();
        let store = Store::open(&path).await.unwrap();

        store.enqueue(WriteOp::Request(req("r1", 1000)));
        store.enqueue(WriteOp::Response(ResponseMeta {
            request_id: "r1".into(),
            finish_reason: Some("stop".into()),
            output_tokens: Some(7),
            output_tokens_src: TokenSource::Estimated,
            ttft_ms: Some(30),
            total_ms: Some(110),
            status: Some(200),
            error_kind: None,
        }));
        store.flush().await.unwrap();

        let rows = store.history(HistoryQuery::default()).await.unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.request.id, "r1");
        assert_eq!(row.request.source_confidence, SourceConfidence::Pid);
        assert_eq!(row.request.input_tokens, Some(42));
        assert!(row.request.stream);
        let resp = row.response.as_ref().expect("response joined");
        assert_eq!(resp.finish_reason.as_deref(), Some("stop"));
        assert_eq!(resp.output_tokens_src, TokenSource::Estimated);
        assert_eq!(row.pii_count, 0);

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn archive_round_trips_and_marks_deleted() {
        let path = tmp_db();
        let store = Store::open(&path).await.unwrap();

        let sess = ArchivedSession {
            id: "claude_code:abc".into(),
            tool: "claude_code".into(),
            source_id: "abc".into(),
            title: Some("Fix login".into()),
            project: Some("/proj".into()),
            git_branch: Some("main".into()),
            model: Some("claude-opus-4-8".into()),
            started_ts: 1000,
            updated_ts: 2000,
            message_count: 2,
            tool_call_count: 1,
            input_tokens: 10,
            output_tokens: 5,
            cache_tokens: 2,
            source_path: Some("/x.jsonl".into()),
            content_hash: "h1".into(),
            archived_ts: 3000,
            source_deleted: false,
            messages: vec![
                ArchivedMessage {
                    role: "user".into(),
                    kind: "text".into(),
                    content: "hi".into(),
                    ts: Some(1000),
                    tool_name: None,
                },
                ArchivedMessage {
                    role: "assistant".into(),
                    kind: "text".into(),
                    content: "hello".into(),
                    ts: Some(1500),
                    tool_name: None,
                },
            ],
        };
        store.enqueue(WriteOp::ArchiveSession(Box::new(sess)));
        store.flush().await.unwrap();

        // Index (incremental change key), list, detail, stats.
        let idx = store.archived_index().await.unwrap();
        assert_eq!(idx.get("claude_code:abc").map(String::as_str), Some("h1"));
        let list = store.archived_sessions().await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].title.as_deref(), Some("Fix login"));
        let detail = store
            .archived_detail("claude_code:abc")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(detail.messages.len(), 2);
        assert_eq!(detail.messages[0].content, "hi");
        let stats = store.archive_stats().await.unwrap();
        assert_eq!(stats.count, 1);
        assert_eq!(stats.messages, 2);
        assert!(stats.bytes >= 7); // "hi" + "hello"

        // Idempotent re-archive (same id) replaces, doesn't duplicate.
        let mut again = detail.clone();
        again.content_hash = "h2".into();
        again.messages.truncate(1);
        store.enqueue(WriteOp::ArchiveSession(Box::new(again)));
        store.flush().await.unwrap();
        assert_eq!(store.archived_sessions().await.unwrap().len(), 1);
        assert_eq!(
            store
                .archived_detail("claude_code:abc")
                .await
                .unwrap()
                .unwrap()
                .messages
                .len(),
            1
        );

        // Deletion detection keeps our copy, flags it.
        store.enqueue(WriteOp::MarkSourceDeleted {
            id: "claude_code:abc".into(),
            deleted: true,
        });
        store.flush().await.unwrap();
        assert!(
            store
                .archived_detail("claude_code:abc")
                .await
                .unwrap()
                .unwrap()
                .source_deleted
        );

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn payload_split_respects_storage() {
        let path = tmp_db();
        let store = Store::open(&path).await.unwrap();

        store.enqueue(WriteOp::Request(req("r1", 1000)));
        // No payload written -> metadata-only default.
        store.flush().await.unwrap();
        assert!(store.payload("r1").await.unwrap().is_none());

        // When payload storage is on, a Payload op lands and is retrievable.
        store.enqueue(WriteOp::Payload(Payload {
            request_id: "r1".into(),
            prompt: Some("hello".into()),
            response: Some("world".into()),
        }));
        store.flush().await.unwrap();
        let p = store.payload("r1").await.unwrap().expect("payload present");
        assert_eq!(p.prompt.as_deref(), Some("hello"));
        assert_eq!(p.response.as_deref(), Some("world"));

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn pii_findings_round_trip_and_count() {
        let path = tmp_db();
        let store = Store::open(&path).await.unwrap();

        store.enqueue(WriteOp::Request(req("r1", 1000)));
        let finding = Finding {
            kind: PiiKind::Email,
            label: None,
            side: Side::Request,
            start: 5,
            end: 20,
            confidence: Confidence::High,
            value_hash: "abc123".into(),
        };
        store.enqueue(WriteOp::PiiFindings(vec![PiiFindingRecord::from_finding(
            "r1",
            &finding,
            PiiAction::Observed,
        )]));
        store.flush().await.unwrap();

        let rows = store.history(HistoryQuery::default()).await.unwrap();
        assert_eq!(rows[0].pii_count, 1);

        let summary = store.privacy_summary().await.unwrap();
        assert_eq!(summary.len(), 1);
        assert_eq!(summary[0].kind, PiiKind::Email);
        assert_eq!(summary[0].side, Side::Request);
        assert_eq!(summary[0].start_off, 5);
        assert_eq!(summary[0].action, PiiAction::Observed);
        assert_eq!(summary[0].value_hash, "abc123");

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn safety_and_eval_round_trip_and_history_count() {
        let path = tmp_db();
        let store = Store::open(&path).await.unwrap();

        store.enqueue(WriteOp::Request(req("r1", 1000)));
        store.enqueue(WriteOp::SafetyFindings(vec![SafetyFindingRecord {
            record_id: "r1".into(),
            guard_model: "deterministic:v1".into(),
            category: "self_harm".into(),
            verdict: "flagged".into(),
            score: None,
            ts: 1000,
        }]));
        store.enqueue(WriteOp::EvalScores(vec![EvalScoreRecord {
            record_id: "r1".into(),
            judge_model: "qwen3.5:2b".into(),
            metric: "relevance".into(),
            band: "good".into(),
            rationale: Some("on topic".into()),
            sampled: true,
            ts: 1000,
        }]));
        store.flush().await.unwrap();

        // History carries the safety count for the row badge.
        let rows = store.history(HistoryQuery::default()).await.unwrap();
        assert_eq!(rows[0].safety_count, 1);
        assert_eq!(rows[0].pii_count, 0);

        // Aggregate + per-record reads.
        let all_safety = store.safety_findings().await.unwrap();
        assert_eq!(all_safety.len(), 1);
        assert_eq!(all_safety[0].category, "self_harm");
        assert_eq!(all_safety[0].verdict, "flagged");

        let for_r1 = store.safety_for("r1").await.unwrap();
        assert_eq!(for_r1.len(), 1);
        assert!(store.safety_for("nope").await.unwrap().is_empty());

        let evals = store.eval_scores().await.unwrap();
        assert_eq!(evals.len(), 1);
        assert_eq!(evals[0].metric, "relevance");
        assert_eq!(evals[0].band, "good");
        assert!(evals[0].sampled);
        assert_eq!(store.eval_for("r1").await.unwrap().len(), 1);

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn history_filters_and_paging() {
        let path = tmp_db();
        let store = Store::open(&path).await.unwrap();

        // Three requests at increasing ts; one with a distinct model.
        store.enqueue(WriteOp::Request(req("a", 1000)));
        let mut b = req("b", 2000);
        b.model = Some("mistral".into());
        store.enqueue(WriteOp::Request(b));
        store.enqueue(WriteOp::Request(req("c", 3000)));
        // Attach a finding only to "c" so pii_only filters to it.
        store.enqueue(WriteOp::PiiFindings(vec![PiiFindingRecord {
            id: 0,
            record_id: "c".into(),
            side: Side::Response,
            kind: PiiKind::ApiKey,
            label: None,
            start_off: 0,
            end_off: 3,
            confidence: Confidence::High,
            action: PiiAction::Observed,
            value_hash: "h".into(),
        }]));
        store.flush().await.unwrap();

        // Newest-first ordering.
        let all = store.history(HistoryQuery::default()).await.unwrap();
        assert_eq!(
            all.iter()
                .map(|r| r.request.id.as_str())
                .collect::<Vec<_>>(),
            vec!["c", "b", "a"]
        );

        // Free-text on model.
        let q = store
            .history(HistoryQuery {
                q: Some("mistral".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].request.id, "b");

        // pii_only.
        let pii = store
            .history(HistoryQuery {
                pii_only: true,
                failed_only: false,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(pii.len(), 1);
        assert_eq!(pii[0].request.id, "c");

        // before_ts cursor (strictly before 3000 -> b, a).
        let page = store
            .history(HistoryQuery {
                before_ts: Some(3000),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(
            page.iter()
                .map(|r| r.request.id.as_str())
                .collect::<Vec<_>>(),
            vec!["b", "a"]
        );

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn settings_and_engines_round_trip() {
        let path = tmp_db();
        let store = Store::open(&path).await.unwrap();

        store.enqueue(WriteOp::Setting {
            key: "payload_storage".into(),
            value: "true".into(),
        });
        store.enqueue(WriteOp::Engine(EngineRecord {
            id: 0,
            engine: "ollama".into(),
            version: Some("0.1.0".into()),
            public_port: 11434,
            shadow_port: Some(11999),
            adoption_state: AdoptionState::Cooperative,
            journal_json: "[]".into(),
            updated_at: 12345,
        }));
        store.flush().await.unwrap();

        assert_eq!(
            store.get_setting("payload_storage").await.unwrap(),
            Some("true".into())
        );
        assert!(store.get_setting("nope").await.unwrap().is_none());

        let engines = store.engines().await.unwrap();
        assert_eq!(engines.len(), 1);
        assert_eq!(engines[0].engine, "ollama");
        assert_eq!(engines[0].adoption_state, AdoptionState::Cooperative);
        assert_eq!(engines[0].shadow_port, Some(11999));

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn enforce_retention_by_age_purges_old_rows() {
        let path = tmp_db();
        let store = Store::open(&path).await.unwrap();

        let now = now_millis();
        // Old request (40 days ago) + a fresh one.
        let old_ts = now - 40 * 86_400_000;
        store.enqueue(WriteOp::Request(req("old", old_ts)));
        store.enqueue(WriteOp::Payload(Payload {
            request_id: "old".into(),
            prompt: Some("x".into()),
            response: None,
        }));
        store.enqueue(WriteOp::Request(req("new", now)));
        store.flush().await.unwrap();

        store
            .enforce_retention(Retention::Age { days: 30 })
            .await
            .unwrap();

        let rows = store.history(HistoryQuery::default()).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].request.id, "new");
        // Dependent payload of the purged request is gone too.
        assert!(store.payload("old").await.unwrap().is_none());

        let _ = std::fs::remove_file(&path);
    }

    /// Encryption-at-rest proof (only meaningful with the `sqlcipher` feature,
    /// which is the default): a known plaintext secret written through the store
    /// must NOT appear in any on-disk byte (main DB + WAL/SHM sidecars), and
    /// opening the same file with a wrong or empty key must fail.
    #[cfg(feature = "sqlcipher")]
    #[tokio::test]
    async fn data_is_encrypted_at_rest_and_wrong_key_fails() {
        const SECRET: &str = "topsecret@example.com";

        let path = tmp_db();
        {
            let store = Store::open(&path).await.unwrap();
            // Persist the secret as raw payload text so it would land on disk
            // verbatim if the file were not encrypted.
            store.enqueue(WriteOp::Request(req("r1", 1000)));
            store.enqueue(WriteOp::Payload(Payload {
                request_id: "r1".into(),
                prompt: Some(format!("please email {SECRET} now")),
                response: Some(SECRET.into()),
            }));
            store.flush().await.unwrap();

            // Force everything out of the WAL into the main DB file so we also
            // exercise the encrypted main-file path (sidecars are checked too).
            let p = path.clone();
            tokio::task::spawn_blocking(move || {
                let conn = open_connection(&p).unwrap();
                conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                    .unwrap();
            })
            .await
            .unwrap();
        }

        // Scan the main DB file and any -wal/-shm sidecars: the plaintext secret
        // must not appear anywhere on disk.
        let secret_bytes = SECRET.as_bytes();
        let mut scanned_any = false;
        for suffix in ["", "-wal", "-shm"] {
            let candidate = if suffix.is_empty() {
                path.clone()
            } else {
                let mut s = path.as_os_str().to_os_string();
                s.push(suffix);
                std::path::PathBuf::from(s)
            };
            if let Ok(raw) = std::fs::read(&candidate) {
                scanned_any = true;
                assert!(
                    !contains_subslice(&raw, secret_bytes),
                    "plaintext secret leaked into {} ({} bytes)",
                    candidate.display(),
                    raw.len()
                );
            }
        }
        assert!(scanned_any, "expected at least the main DB file to exist");

        // Sanity: the file is non-trivial (it really has our data, encrypted).
        let main_len = std::fs::metadata(&path).unwrap().len();
        assert!(main_len > 0, "DB file should be non-empty");

        // Opening with a WRONG key must fail (decryption error on first read).
        {
            let conn = Connection::open(&path).unwrap();
            conn.pragma_update(None, "key", "the-wrong-key-deadbeef")
                .unwrap();
            let res = conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
                row.get::<_, i64>(0)
            });
            assert!(res.is_err(), "wrong key must not decrypt the database");
        }

        // Opening with an EMPTY key (i.e. treating it as plain SQLite) must fail
        // to read the encrypted header.
        {
            let conn = Connection::open(&path).unwrap();
            let res = conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
                row.get::<_, i64>(0)
            });
            assert!(res.is_err(), "no key must not read the encrypted database");
        }

        let _ = std::fs::remove_file(&path);
        let mut wal = path.as_os_str().to_os_string();
        wal.push("-wal");
        let _ = std::fs::remove_file(std::path::PathBuf::from(wal));
        let mut shm = path.as_os_str().to_os_string();
        shm.push("-shm");
        let _ = std::fs::remove_file(std::path::PathBuf::from(shm));
    }

    /// Naive substring search over raw bytes (no `str` assumptions — the DB file
    /// is binary).
    #[cfg(feature = "sqlcipher")]
    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || haystack.len() < needle.len() {
            return false;
        }
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[test]
    fn from_finding_carries_hash_not_secret() {
        let f = Finding {
            kind: PiiKind::CreditCard,
            label: Some("amex".into()),
            side: Side::Response,
            start: 1,
            end: 16,
            confidence: Confidence::High,
            value_hash: "hashed".into(),
        };
        let rec = PiiFindingRecord::from_finding("req-1", &f, PiiAction::Masked);
        assert_eq!(rec.record_id, "req-1");
        assert_eq!(rec.kind, PiiKind::CreditCard);
        assert_eq!(rec.label.as_deref(), Some("amex"));
        assert_eq!(rec.action, PiiAction::Masked);
        assert_eq!(rec.value_hash, "hashed");
        assert_eq!(rec.id, 0);
    }
}
