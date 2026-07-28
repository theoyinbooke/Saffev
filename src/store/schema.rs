//! SQLite schema as ordered migrations (04 §7.1).
//!
//! Each entry in [`MIGRATIONS`] is applied in order, gated by `PRAGMA user_version`.
//! The first migration is the verbatim DDL from the implementation plan.

use rusqlite::Connection;

use crate::Result;

/// Ordered DDL migrations. Index 0 is `user_version == 1`, etc.
pub const MIGRATIONS: &[&str] = &[
    // --- v1: initial schema (04 §7.1) ---
    r#"
    CREATE TABLE engines (
      id INTEGER PRIMARY KEY,
      engine TEXT,
      version TEXT,
      public_port INTEGER,
      shadow_port INTEGER,
      adoption_state TEXT,              -- detected|cooperative|adopted|reverted
      journal_json TEXT,               -- reversible record of every system change
      updated_at INTEGER
    );

    CREATE TABLE requests (
      id TEXT PRIMARY KEY,             -- uuid
      ts INTEGER,
      source_app TEXT,
      source_confidence TEXT,
      engine TEXT,
      model TEXT,
      endpoint TEXT,
      stream INTEGER,
      input_tokens INTEGER,
      input_tokens_src TEXT,           -- exact|estimated
      latency_ms INTEGER,
      request_hash TEXT
    );

    CREATE TABLE responses (
      request_id TEXT REFERENCES requests(id),
      finish_reason TEXT,
      output_tokens INTEGER,
      output_tokens_src TEXT,
      ttft_ms INTEGER,
      total_ms INTEGER
    );

    CREATE TABLE payloads (            -- OFF by default
      request_id TEXT PRIMARY KEY REFERENCES requests(id),
      prompt TEXT,
      response TEXT
    );

    CREATE TABLE pii_findings (
      id INTEGER PRIMARY KEY,
      record_id TEXT,
      side TEXT,                       -- request|response
      type TEXT,
      start_off INTEGER,
      end_off INTEGER,
      confidence TEXT,
      action TEXT,                     -- observed|masked
      value_hash TEXT                  -- never the raw secret
    );

    CREATE TABLE safety_findings (    -- schema ready; unused in v1
      id INTEGER PRIMARY KEY,
      record_id TEXT,
      guard_model TEXT,
      category TEXT,
      verdict TEXT,
      score REAL,
      ts INTEGER
    );

    CREATE TABLE eval_scores (        -- schema ready; unused in v1
      id INTEGER PRIMARY KEY,
      record_id TEXT,
      judge_model TEXT,
      metric TEXT,
      band TEXT,
      rationale TEXT,
      sampled INTEGER,
      ts INTEGER
    );

    CREATE TABLE settings (
      key TEXT PRIMARY KEY,
      value TEXT
    );

    CREATE INDEX idx_requests_ts ON requests(ts);
    CREATE INDEX idx_pii_record ON pii_findings(record_id);
    "#,
    // --- v2: add the custom-pattern `label` column ---
    //
    // The §7.1 sketch omits a label column, but the shared `store::PiiFindingRecord`
    // (and brain `Finding`) carry an `Option<String>` label for custom patterns.
    // We keep migration 0 byte-for-byte as the spec DDL and add the column here so
    // the persisted shape matches the contract type without rewriting history.
    r#"
    ALTER TABLE pii_findings ADD COLUMN label TEXT;
    "#,
    // --- v3: capture request outcome (HTTP status + transport failures) ---
    //
    // v1 recorded only the timing/tokens of a finished exchange, so a failed call
    // (upstream unreachable, timeout, HTTP 4xx/5xx, mid-stream error) was
    // indistinguishable from a success — exactly the case a developer opens the
    // tool to see. `status` is the upstream HTTP status (NULL when we never got
    // one); `error_kind` is a transport-level failure tag (`upstream_unreachable`
    // / `stream_error`), NULL for a normal HTTP response.
    r#"
    ALTER TABLE responses ADD COLUMN status INTEGER;
    ALTER TABLE responses ADD COLUMN error_kind TEXT;
    "#,
    // --- v4: indexes for the eval pipeline's per-record lookups ---
    //
    // `safety_findings` / `eval_scores` were created in v1 (schema-ready, unused).
    // The eval worker now writes them and the Studio drawer reads them by
    // `record_id`, so index that column on both — mirrors `idx_pii_record`.
    r#"
    CREATE INDEX IF NOT EXISTS idx_safety_record ON safety_findings(record_id);
    CREATE INDEX IF NOT EXISTS idx_eval_record ON eval_scores(record_id);
    "#,
    // --- v5: the Preservation archive (durable copy of coding-agent sessions) ---
    //
    // Coding tools delete their own history on their own clocks (Claude Code prunes
    // after `cleanupPeriodDays`, Cursor rotates its store). This is Saffev's durable,
    // encrypted-at-rest copy so a session survives the source app deleting it.
    // `content_hash` is the incremental change key; `source_deleted` marks entries
    // the source has since removed (we NEVER delete our copy for that reason).
    r#"
    CREATE TABLE archived_sessions (
        id              TEXT PRIMARY KEY,   -- namespaced "<tool>:<raw>"
        tool            TEXT NOT NULL,
        source_id       TEXT NOT NULL,      -- raw (un-namespaced) id
        title           TEXT,
        project         TEXT,
        git_branch      TEXT,
        model           TEXT,
        started_ts      INTEGER NOT NULL,
        updated_ts      INTEGER NOT NULL,
        message_count   INTEGER NOT NULL,
        tool_call_count INTEGER NOT NULL,
        input_tokens    INTEGER NOT NULL,
        output_tokens   INTEGER NOT NULL,
        cache_tokens    INTEGER NOT NULL,
        source_path     TEXT,
        content_hash    TEXT NOT NULL,
        archived_ts     INTEGER NOT NULL,
        source_deleted  INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE archived_messages (
        session_id TEXT NOT NULL,
        seq        INTEGER NOT NULL,
        role       TEXT NOT NULL,
        kind       TEXT NOT NULL,
        content    TEXT NOT NULL,
        ts         INTEGER,
        tool_name  TEXT,
        PRIMARY KEY (session_id, seq)
    );
    CREATE INDEX idx_archived_updated ON archived_sessions(updated_ts);
    CREATE INDEX idx_archived_tool ON archived_sessions(tool, source_id);
    "#,
    // --- v6: full-text search over preserved transcripts ---
    //
    // An archive you cannot search is a warehouse with the lights off. Until now
    // a session could only be found by its title, project, or model — never by
    // what was actually said in it. This is the index that fixes that.
    //
    // A standalone (not external-content) FTS5 table keeps the triggers trivial
    // and survives the archive's DELETE-then-INSERT upsert without special
    // casing. `session_id`/`seq` ride along UNINDEXED purely so a hit can be
    // mapped back to its session and position without a join.
    //
    // The backfill at the end indexes whatever is already archived, so upgrading
    // users get search over their existing history immediately rather than only
    // over sessions archived from here on.
    r#"
    CREATE VIRTUAL TABLE archived_messages_fts USING fts5(
        content,
        session_id UNINDEXED,
        seq        UNINDEXED,
        tokenize = 'unicode61 remove_diacritics 2'
    );

    CREATE TRIGGER archived_messages_fts_ai AFTER INSERT ON archived_messages BEGIN
        INSERT INTO archived_messages_fts (rowid, content, session_id, seq)
        VALUES (new.rowid, new.content, new.session_id, new.seq);
    END;

    CREATE TRIGGER archived_messages_fts_ad AFTER DELETE ON archived_messages BEGIN
        DELETE FROM archived_messages_fts WHERE rowid = old.rowid;
    END;

    CREATE TRIGGER archived_messages_fts_au AFTER UPDATE ON archived_messages BEGIN
        DELETE FROM archived_messages_fts WHERE rowid = old.rowid;
        INSERT INTO archived_messages_fts (rowid, content, session_id, seq)
        VALUES (new.rowid, new.content, new.session_id, new.seq);
    END;

    INSERT INTO archived_messages_fts (rowid, content, session_id, seq)
        SELECT rowid, content, session_id, seq FROM archived_messages;
    "#,
    // --- v7: tamper-evident archive (the hash chain) ---
    //
    // The archive's value is being the last surviving copy of a conversation. That
    // is only worth something if you can show it was not edited afterwards, so
    // every write appends one row here, each one committing to the row before it.
    // Change or remove any entry and every later `entry_digest` stops matching.
    //
    // This is an APPEND-ONLY LOG, deliberately separate from `archived_sessions`.
    // Sessions are upserted (a growing session is re-archived), so chaining the
    // mutable table itself would break on the first legitimate re-archive. The log
    // records each archival as an event instead, which re-archiving handles
    // naturally: you simply see the session archived twice, with both digests.
    r#"
    CREATE TABLE archive_log (
        seq            INTEGER PRIMARY KEY AUTOINCREMENT,
        ts             INTEGER NOT NULL,
        session_id     TEXT    NOT NULL,
        -- SHA-256 over the session's stored content at the moment it was written.
        content_digest TEXT    NOT NULL,
        -- The previous entry's `entry_digest` ("" for the first entry).
        prev_digest    TEXT    NOT NULL,
        -- SHA-256 over (seq, ts, session_id, content_digest, prev_digest).
        entry_digest   TEXT    NOT NULL
    );
    CREATE INDEX idx_archive_log_session ON archive_log(session_id);
    "#,
    // --- v8: one row per engine ---
    //
    // The engines writer always intended "upsert by engine name" but conflicted
    // on `id` while inserting NULL ids — so every adopt/revert/detection APPENDED
    // a row, and readers (`ORDER BY id`, find-first) returned the OLDEST record.
    // That made a revert invisible (state never changed in any view) and, worse,
    // could hand revert a STALE journal. Dedupe to the newest row per engine,
    // then enforce uniqueness so the writer's `ON CONFLICT(engine)` upsert works.
    r#"
    DELETE FROM engines WHERE id NOT IN (
        SELECT MAX(id) FROM engines GROUP BY engine
    );
    CREATE UNIQUE INDEX idx_engines_engine ON engines(engine);
    "#,
    // --- v9: widen the per-request record (G4) ---
    //
    // The History detail should answer "what exactly was this call?" without
    // ever storing content. These are METADATA-ONLY additions: body sizes,
    // truncated identifying headers, the sampling params the app asked for, and
    // shape counts of the request JSON (message/tool counts, system-prompt
    // presence) — never the text itself. `resp_bytes` is the TOTAL bytes
    // streamed to the client, counted per tee chunk, so it stays honest even
    // when the logger's capped buffer truncates a big stream.
    r#"
    ALTER TABLE requests ADD COLUMN req_bytes INTEGER;
    ALTER TABLE requests ADD COLUMN user_agent TEXT;
    ALTER TABLE requests ADD COLUMN content_type TEXT;
    ALTER TABLE requests ADD COLUMN temperature REAL;
    ALTER TABLE requests ADD COLUMN top_p REAL;
    ALTER TABLE requests ADD COLUMN max_tokens INTEGER;
    ALTER TABLE requests ADD COLUMN msg_count INTEGER;
    ALTER TABLE requests ADD COLUMN has_system INTEGER;
    ALTER TABLE requests ADD COLUMN tool_count INTEGER;
    ALTER TABLE responses ADD COLUMN resp_bytes INTEGER;
    "#,
];

/// Apply WAL + pragmas and run any outstanding migrations against `conn`.
/// Called once by the writer thread on the owning connection.
///
/// Pragmas (04 §7.1): WAL journal mode + `synchronous=NORMAL` keep logging off
/// the request path while staying crash-safe. Foreign keys are enabled so the
/// metadata/payload split stays referentially honest.
///
/// Migrations are gated by `PRAGMA user_version`: each entry in [`MIGRATIONS`]
/// not yet applied (index `>= current_version`) is executed inside a transaction
/// and `user_version` is bumped to match. This is idempotent — re-opening an
/// up-to-date DB is a no-op.
pub fn migrate(conn: &Connection) -> Result<()> {
    // WAL + NORMAL: durable enough, never blocks the writer on fsync per-row.
    // `query_row` because `journal_mode` returns the resulting mode as a row.
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;

    let current: u32 =
        conn.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))? as u32;
    let target = target_version();

    if current >= target {
        return Ok(());
    }

    for (idx, ddl) in MIGRATIONS.iter().enumerate() {
        let version = idx as u32 + 1;
        if version <= current {
            continue;
        }
        // Each migration is one batch of statements applied atomically.
        conn.execute_batch(&format!(
            "BEGIN; {ddl}; PRAGMA user_version = {version}; COMMIT;"
        ))?;
    }

    Ok(())
}

/// Current target schema version ([`MIGRATIONS`] length).
pub fn target_version() -> u32 {
    MIGRATIONS.len() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrate_creates_all_tables_and_sets_version() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();

        // user_version moved to the target.
        let v: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(v as u32, target_version());

        // Every table from 04 §7.1 exists.
        for table in [
            "engines",
            "requests",
            "responses",
            "payloads",
            "pii_findings",
            "safety_findings",
            "eval_scores",
            "settings",
        ] {
            let count: i64 = conn
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "table {table} should exist");
        }

        // Indexes exist.
        for index in ["idx_requests_ts", "idx_pii_record"] {
            let count: i64 = conn
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='index' AND name=?1",
                    [index],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "index {index} should exist");
        }
    }

    #[test]
    fn migrate_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        // Running again must not error or re-run DDL (which would fail on
        // duplicate table creation).
        migrate(&conn).unwrap();
        let v: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(v as u32, target_version());
    }
}
