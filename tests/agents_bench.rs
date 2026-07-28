//! G2 gauntlet harness — the fixture corpus that makes adapter claims
//! testable (docs/gauntlets/GAUNTLETS.md §G2, loop 1).
//!
//! One command, reproducible:
//!
//! ```text
//! cargo test --test agents_bench -- --nocapture
//! ```
//!
//! For every adapter this proves, from COMMITTED sanitized fixtures
//! (`tests/fixtures/agents/<tool>/`), extraction of the rubric fields —
//! session id, title, project, model, timestamps, per-message roles, token
//! counts — plus a corrupted-fixture case proving non-fatal degradation.
//! It emits `bench/agents-results.json`, the coverage-table artifact
//! (tool → fields), and enforces floors so coverage can only regress loudly.
//!
//! Honesty rule: token coverage is three-valued — proven against fixture
//! numbers, `absent_in_format` (VS Code: no token fields at all), or
//! `present_but_unpopulated` (Cursor: tokenCount fields exist, never
//! filled) — never claimed, never silently skipped.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use saffev::agents::aider::AiderReader;
use saffev::agents::amp::AmpReader;
use saffev::agents::claude_code::ClaudeCodeReader;
use saffev::agents::cline::ClineReader;
use saffev::agents::codex::CodexReader;
use saffev::agents::copilot::CopilotReader;
use saffev::agents::cursor::CursorReader;
use saffev::agents::gemini::GeminiReader;
use saffev::agents::goose::GooseReader;
use saffev::agents::opencode::OpenCodeReader;
use saffev::agents::roo::RooReader;
use saffev::agents::vscode::VsCodeReader;
use saffev::agents::{AgentReader, AgentSession, MessageKind, Role};

fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/agents")
        .join(rel)
}

/// Materialize a committed `.sql` fixture into a real SQLite file (SQL text
/// is the committed, reviewable form; a binary DB would be unauditable).
fn build_db(sql_rel: &str, name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("saffev-g2-{}", uuid_ish()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join(name);
    let conn = rusqlite::Connection::open(&db).unwrap();
    let sql = std::fs::read_to_string(fixture(sql_rel)).unwrap();
    conn.execute_batch(&sql).unwrap();
    db
}

/// Unique-enough temp suffix without Date::now (nanos of PID + counter).
fn uuid_ish() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    format!("{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed))
}

fn raw_id(session: &AgentSession) -> &str {
    session.id.split_once(':').map(|(_, r)| r).unwrap_or(&session.id)
}

/// Token-count coverage — three-valued because honesty demands it: `Proven`
/// against fixture numbers; `AbsentInFormat` when the on-disk format carries
/// no token fields at all (VS Code, verified); `PresentButUnpopulated` when
/// the fields exist but are never filled (Cursor — the round-1 critic
/// scanned 1,351 real bubbles: every tokenCount was zero). The distinction
/// matters: if Cursor starts populating them, "absent" would hide it.
#[derive(Default, Clone, Copy, PartialEq)]
enum TokenCoverage {
    #[default]
    Unchecked,
    Proven(bool),
    AbsentInFormat,
    PresentButUnpopulated,
}

/// The rubric-field checklist for one tool, serialized into the artifact.
#[derive(Default)]
struct Coverage {
    sessions_found: usize,
    session_id: bool,
    title: bool,
    project: bool,
    model: bool,
    /// The same honesty rule as tokens, for the model field: Roo Code does
    /// not persist the model id per task (only a mutable profile name in
    /// VS Code secrets) — recorded as absent, never guessed.
    model_absent_in_format: bool,
    timestamps: bool,
    roles: bool,
    token_counts: TokenCoverage,
    corrupted_nonfatal: bool,
    notes: Vec<String>,
}

impl Coverage {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "sessions_found": self.sessions_found,
            "fields": {
                "session_id": self.session_id,
                "title": self.title,
                "project": self.project,
                "model": if self.model_absent_in_format {
                    serde_json::json!("absent_in_format")
                } else {
                    serde_json::json!(self.model)
                },
                "timestamps": self.timestamps,
                "per_message_roles": self.roles,
                "token_counts": match self.token_counts {
                    TokenCoverage::Proven(b) => serde_json::json!(b),
                    TokenCoverage::AbsentInFormat => serde_json::json!("absent_in_format"),
                    TokenCoverage::PresentButUnpopulated => {
                        serde_json::json!("present_but_unpopulated")
                    }
                    TokenCoverage::Unchecked => serde_json::json!("UNCHECKED"),
                },
            },
            "corrupted_nonfatal": self.corrupted_nonfatal,
            "notes": self.notes,
        })
    }

    /// Every rubric field proven (token counts may be honestly absent or
    /// unpopulated — but never unchecked or failing).
    fn complete(&self) -> bool {
        self.session_id
            && self.title
            && self.project
            && (self.model || self.model_absent_in_format)
            && self.timestamps
            && self.roles
            && !matches!(
                self.token_counts,
                TokenCoverage::Proven(false) | TokenCoverage::Unchecked
            )
            && self.corrupted_nonfatal
    }
}

/// Shared field checks on a (session, detail-messages) pair.
fn check_common(
    cov: &mut Coverage,
    reader: &dyn AgentReader,
    good: &AgentSession,
    tool_key: &str,
) {
    cov.session_id = good.id.starts_with(&format!("{tool_key}:"));
    cov.title = good.title.as_deref().is_some_and(|t| !t.is_empty());
    cov.project = good.project.as_deref().is_some_and(|p| !p.is_empty());
    cov.model = good.model.as_deref().is_some_and(|m| !m.is_empty());
    cov.timestamps = good.started_ts > 0 && good.updated_ts >= good.started_ts;
    let detail = reader
        .session_detail(raw_id(good))
        .unwrap_or_else(|| panic!("{tool_key}: detail for {}", good.id));
    let has_user = detail.messages.iter().any(|m| matches!(m.role, Role::User));
    let has_assistant = detail
        .messages
        .iter()
        .any(|m| matches!(m.role, Role::Assistant));
    cov.roles = has_user && has_assistant;
    assert!(
        detail
            .messages
            .iter()
            .any(|m| matches!(m.kind, MessageKind::ToolUse)),
        "{tool_key}: tool use missing from detail"
    );
}

#[test]
fn agents_fixture_coverage() {
    let mut table: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    let mut complete = 0usize;

    // ---- Claude Code -------------------------------------------------------
    {
        let reader = ClaudeCodeReader::with_root(fixture("claude_code"));
        let sessions = reader.list_sessions();
        let mut cov = Coverage {
            sessions_found: sessions.len(),
            ..Default::default()
        };
        let good = sessions
            .iter()
            .find(|s| s.id.ends_with("000000000001"))
            .expect("claude_code: good session listed");
        check_common(&mut cov, &reader, good, "claude_code");
        cov.token_counts = TokenCoverage::Proven(
            good.input_tokens == 1200 && good.output_tokens == 340 && good.cache_tokens == 100,
        );
        assert_eq!(good.git_branch.as_deref(), Some("main"));
        // Corrupted fixture: garbage lines skipped, the one valid record
        // survives, nothing is fatal.
        let hurt = sessions
            .iter()
            .find(|s| s.id.ends_with("000000000002"))
            .expect("claude_code: corrupted session still listed");
        // The surviving record carries a timestamp — a partially-degraded
        // session must not report epoch-0 (round-1 critic's degenerate edge).
        cov.corrupted_nonfatal = hurt.message_count == 1 && hurt.started_ts > 0;
        table.insert("claude_code".into(), cov.to_json());
        complete += usize::from(cov.complete());
    }

    // ---- Codex CLI ---------------------------------------------------------
    {
        let reader = CodexReader::with_root(fixture("codex"));
        let sessions = reader.list_sessions();
        let mut cov = Coverage {
            sessions_found: sessions.len(),
            ..Default::default()
        };
        let good = sessions
            .iter()
            .find(|s| s.id.ends_with("000000000003"))
            .expect("codex: good session listed");
        check_common(&mut cov, &reader, good, "codex");
        assert_eq!(good.title.as_deref(), Some("Wire healthcheck"), "title from session_index");
        assert_eq!(good.git_branch.as_deref(), Some("feature/g2"));
        // OpenAI convention: input_tokens is TOTAL; adapter must subtract cache.
        cov.token_counts = TokenCoverage::Proven(
            good.input_tokens == 1100 && good.output_tokens == 260 && good.cache_tokens == 400,
        );
        let hurt = sessions
            .iter()
            .find(|s| s.id.ends_with("000000000004"))
            .expect("codex: corrupted rollout still listed");
        cov.corrupted_nonfatal = hurt.message_count == 1;
        // No session_meta in this rollout — the fallback id must be the bare
        // trailing uuid, not the whole timestamped stem (round-1 critic).
        assert_eq!(hurt.id, "codex:dddddddd-dddd-4ddd-8ddd-000000000004");
        table.insert("codex".into(), cov.to_json());
        complete += usize::from(cov.complete());
    }

    // ---- OpenCode ----------------------------------------------------------
    {
        let reader = OpenCodeReader::with_db(build_db("opencode/opencode.sql", "opencode.db"));
        let sessions = reader.list_sessions();
        let mut cov = Coverage {
            sessions_found: sessions.len(),
            ..Default::default()
        };
        let good = sessions
            .iter()
            .find(|s| s.id.ends_with("ses_good"))
            .expect("opencode: good session listed");
        check_common(&mut cov, &reader, good, "opencode");
        assert_eq!(good.model.as_deref(), Some("anthropic/claude-opus-4-8"));
        cov.token_counts = TokenCoverage::Proven(
            good.input_tokens == 900 && good.output_tokens == 150 && good.cache_tokens == 150,
        );
        // Corrupted data blob: json_extract degrades to NULL, session still
        // listed with zeroed aggregates — non-fatal.
        let hurt = sessions
            .iter()
            .find(|s| s.id.ends_with("ses_bad"))
            .expect("opencode: corrupted-blob session still listed");
        cov.corrupted_nonfatal = hurt.input_tokens == 0 && hurt.message_count == 1;
        table.insert("opencode".into(), cov.to_json());
        complete += usize::from(cov.complete());
    }

    // ---- Cursor ------------------------------------------------------------
    {
        let reader = CursorReader::with_db(build_db("cursor/state.sql", "state.vscdb"));
        let sessions = reader.list_sessions();
        let mut cov = Coverage {
            sessions_found: sessions.len(),
            ..Default::default()
        };
        let good = sessions
            .iter()
            .find(|s| s.id.ends_with("comp-0001"))
            .expect("cursor: good session listed");
        check_common(&mut cov, &reader, good, "cursor");
        // Cursor's bubbles carry tokenCount fields but they are never
        // populated (round-1 critic verified against 1,351 real bubbles) —
        // recorded as such, not claimed and not hidden behind "absent".
        cov.token_counts = TokenCoverage::PresentButUnpopulated;
        cov.notes
            .push("tokenCount fields exist but are never populated in real stores".into());
        // Corrupted composer blob: skipped in list, nothing fatal, the good
        // session is unaffected.
        cov.corrupted_nonfatal = sessions.iter().all(|s| !s.id.contains("comp-broken"));
        table.insert("cursor".into(), cov.to_json());
        complete += usize::from(cov.complete());
    }

    // ---- VS Code / Copilot Chat -------------------------------------------
    {
        let reader = VsCodeReader::with_roots(vec![fixture("vscode/workspaceStorage")]);
        let sessions = reader.list_sessions();
        let mut cov = Coverage {
            sessions_found: sessions.len(),
            ..Default::default()
        };
        let good = sessions
            .iter()
            .find(|s| s.id.ends_with("000000000005"))
            .expect("vscode: good session listed");
        check_common(&mut cov, &reader, good, "vscode");
        assert_eq!(good.project.as_deref(), Some("/home/dev/fixture-proj"));
        cov.token_counts = TokenCoverage::AbsentInFormat;
        cov.notes.push("format carries no token usage".into());
        let hurt = sessions
            .iter()
            .find(|s| s.id.ends_with("000000000006"))
            .expect("vscode: corrupted session still listed");
        cov.corrupted_nonfatal = hurt.message_count >= 1;
        table.insert("vscode".into(), cov.to_json());
        complete += usize::from(cov.complete());
    }

    // ---- Gemini CLI (round 3 — format verified against gemini-cli source) --
    {
        let reader = GeminiReader::with_root(fixture("gemini"));
        let sessions = reader.list_sessions();
        let mut cov = Coverage {
            sessions_found: sessions.len(),
            ..Default::default()
        };
        let good = sessions
            .iter()
            .find(|s| s.id.ends_with("00000000000a"))
            .expect("gemini: good session listed");
        check_common(&mut cov, &reader, good, "gemini");
        // The fixture re-appends the tokened message with the same id — a
        // reader that sums without deduping doubles these. `input` is the
        // TOTAL prompt (cached is a subset); `thoughts` count as output.
        cov.token_counts = TokenCoverage::Proven(
            good.input_tokens == (2113 - 1536) + (2290 - 2048)
                && good.output_tokens == 38 + 95 + 21
                && good.cache_tokens == 1536 + 2048,
        );
        assert_eq!(good.message_count, 3, "re-appended record must not add a turn");
        assert_eq!(good.project.as_deref(), Some("/home/dev/fixture-proj"));
        // Legacy pre-v0.39 single-JSON generation still parses.
        let legacy = sessions
            .iter()
            .find(|s| s.id.ends_with("00000000000c"))
            .expect("gemini: legacy .json session listed");
        assert_eq!(legacy.model.as_deref(), Some("gemini-2.0-pro"));
        // Subagent side threads (dirs under chats/) are skipped.
        assert!(
            sessions.iter().all(|s| !s.id.contains("sub-1")),
            "gemini: subagent thread must not list"
        );
        // Corrupted variant: garbage + binary + truncated lines skipped, the
        // $rewindTo honored INCLUSIVELY (real semantics: the target turn is
        // removed too — round-3 critic) — only the first user turn survives.
        let hurt = sessions
            .iter()
            .find(|s| s.id.ends_with("00000000000b"))
            .expect("gemini: corrupted session still listed");
        cov.corrupted_nonfatal = hurt.message_count == 1 && hurt.started_ts > 0;
        table.insert("gemini".into(), cov.to_json());
        complete += usize::from(cov.complete());
    }

    // ---- Copilot CLI (round 5 — both store generations) ---------------------
    {
        let reader = CopilotReader::with_root(fixture("copilot"));
        let sessions = reader.list_sessions();
        let mut cov = Coverage {
            sessions_found: sessions.len(),
            ..Default::default()
        };
        let good = sessions
            .iter()
            .find(|s| s.id.ends_with("8a2b5d4f6e70"))
            .expect("copilot: good session listed");
        check_common(&mut cov, &reader, good, "copilot");
        // Shutdown totals: separate buckets, `input` is non-cached.
        cov.token_counts = TokenCoverage::Proven(
            good.input_tokens == 15230
                && good.output_tokens == 42
                && good.cache_tokens == 12000 + 2100,
        );
        assert_eq!(good.title.as_deref(), Some("Add healthcheck endpoint"));
        assert_eq!(good.git_branch.as_deref(), Some("main"));
        // The migrated legacy twin of the good session must dedupe away —
        // modern wins; and the pre-migration copy must not surface.
        assert_eq!(
            sessions
                .iter()
                .filter(|s| s.id.ends_with("8a2b5d4f6e70"))
                .count(),
            1,
            "copilot: migration twin double-listed"
        );
        assert!(good.source_path.contains("session-state"));
        // Legacy-only session still parses (no tokens exist in that era).
        let legacy = sessions
            .iter()
            .find(|s| s.id.ends_with("000000000001"))
            .expect("copilot: legacy session listed");
        assert_eq!(legacy.model.as_deref(), Some("gpt-5"));
        assert_eq!(legacy.tool_call_count, 1);
        // Corrupted modern session (hard-killed, garbage + binary lines):
        // valid records survive; without a shutdown record input is honestly
        // 0 and output comes from per-message outputTokens.
        let hurt = sessions
            .iter()
            .find(|s| s.id.ends_with("9b3c6e5a7f81"))
            .expect("copilot: corrupted session still listed");
        cov.corrupted_nonfatal = hurt.message_count == 2
            && hurt.started_ts > 0
            && hurt.input_tokens == 0
            && hurt.output_tokens == 7;
        table.insert("copilot".into(), cov.to_json());
        complete += usize::from(cov.complete());
    }

    // ---- Cline (round 6 — verified against the shipped v3.89.2 tag) --------
    {
        let reader = ClineReader::with_roots(vec![fixture("cline")]);
        let sessions = reader.list_sessions();
        let mut cov = Coverage {
            sessions_found: sessions.len(),
            ..Default::default()
        };
        let good = sessions
            .iter()
            .find(|s| s.id.ends_with("1753600000000"))
            .expect("cline: good task listed");
        check_common(&mut cov, &reader, good, "cline");
        // Anthropic convention: tokensIn already excludes cache.
        cov.token_counts = TokenCoverage::Proven(
            good.input_tokens == 12480
                && good.output_tokens == 312
                && good.cache_tokens == 11200,
        );
        assert_eq!(good.title.as_deref(), Some("Add a retry to the fetch helper"));
        assert_eq!(good.started_ts, 1753600000000, "task id IS the start time");
        let detail = reader.session_detail("1753600000000").expect("detail");
        assert!(detail
            .messages
            .iter()
            .any(|m| matches!(m.kind, MessageKind::Thinking)));
        assert!(detail
            .messages
            .iter()
            .any(|m| matches!(m.kind, MessageKind::ToolResult)));
        // Corrupted transcript: the task still lists from its taskHistory
        // row — title, tokens, project intact; turns honestly 0.
        let hurt = sessions
            .iter()
            .find(|s| s.id.ends_with("1753600100000"))
            .expect("cline: corrupted task still listed");
        cov.corrupted_nonfatal = hurt.message_count == 0
            && hurt.input_tokens == 500
            && hurt.title.as_deref() == Some("Corrupted transcript task");
        table.insert("cline".into(), cov.to_json());
        complete += usize::from(cov.complete());
    }

    // ---- Aider (round 7 — honest-partial: markdown, no ids on disk) --------
    {
        let reader = AiderReader::with_roots(vec![fixture("aider")]);
        let sessions = reader.list_sessions();
        let mut cov = Coverage {
            sessions_found: sessions.len(),
            ..Default::default()
        };
        let good = sessions
            .iter()
            .find(|s| s.title.as_deref().is_some_and(|t| t.contains("healthcheck endpoint")))
            .expect("aider: good session listed");
        check_common(&mut cov, &reader, good, "aider");
        assert_eq!(good.model.as_deref(), Some("gpt-4o"));
        // k-rounded by aider itself — approximate, and recorded as such.
        cov.token_counts =
            TokenCoverage::Proven(good.input_tokens == 4200 && good.output_tokens == 312);
        cov.notes.push(
            "ids synthesized (none on disk); tokens k-rounded above 1000 by aider; \
             per-message timestamps absent (messages inherit the session header)"
                .into(),
        );
        // Second session in the same file: model suffixes stripped, Weak
        // model NOT mistaken for the main model.
        let s2 = sessions
            .iter()
            .find(|s| s.title.as_deref().is_some_and(|t| t.contains("tighten")))
            .expect("aider: second session listed");
        assert_eq!(s2.model.as_deref(), Some("claude-sonnet-4-6"));
        // Corrupted project: binary noise + unparseable token/model lines are
        // just assistant text / ignored announcements — never fatal.
        let hurt = sessions
            .iter()
            .find(|s| s.title.as_deref().is_some_and(|t| t.contains("before the noise")))
            .expect("aider: corrupted session still listed");
        // 1 user + 2 assistant blocks (the `> ` announcement lines split the
        // assistant text — correct per aider's own reading rules).
        cov.corrupted_nonfatal =
            hurt.message_count == 3 && hurt.input_tokens == 0 && hurt.model.is_none();
        table.insert("aider".into(), cov.to_json());
        complete += usize::from(cov.complete());
    }

    // ---- Goose (round 8 — the tenth tool; schema v15 from source) ----------
    {
        let reader = GooseReader::with_db(build_db("goose/sessions.sql", "sessions.db"));
        let sessions = reader.list_sessions();
        let mut cov = Coverage {
            sessions_found: sessions.len(),
            ..Default::default()
        };
        let good = sessions
            .iter()
            .find(|s| s.id.ends_with("20260715_1"))
            .expect("goose: good session listed");
        check_common(&mut cov, &reader, good, "goose");
        assert_eq!(good.model.as_deref(), Some("anthropic/claude-sonnet-4-5"));
        // Accumulated totals win over the current-window columns.
        cov.token_counts = TokenCoverage::Proven(
            good.input_tokens == 8500
                && good.output_tokens == 212
                && good.cache_tokens == 8000 + 300,
        );
        cov.notes.push(
            "input_tokens follows each provider's own convention (recorded as stored)".into(),
        );
        let detail = reader.session_detail("20260715_1").expect("detail");
        assert!(detail.messages.iter().any(|m| matches!(m.kind, MessageKind::Thinking)));
        assert!(detail.messages.iter().any(|m| matches!(m.kind, MessageKind::ToolResult)));
        // sub_agent side threads and archived sessions must not list.
        assert!(sessions.iter().all(|s| !s.id.ends_with("sub-1")), "sub_agent listed");
        assert!(sessions.iter().all(|s| !s.id.ends_with("arch-1")), "archived listed");
        // Corrupted content_json: the session lists with its aggregates, the
        // blob degrades to zero blocks in detail — never fatal.
        let hurt = sessions
            .iter()
            .find(|s| s.id.ends_with("20260715_2"))
            .expect("goose: corrupted-blob session still listed");
        let hurt_detail = reader.session_detail("20260715_2").expect("detail");
        cov.corrupted_nonfatal = hurt.message_count == 1
            && hurt.input_tokens == 50
            && hurt_detail.messages.is_empty();
        table.insert("goose".into(), cov.to_json());
        complete += usize::from(cov.complete());
    }

    // ---- Amp (round 9 — eleventh tool, margin above the bar) ---------------
    {
        let reader = AmpReader::with_root(fixture("amp"));
        let sessions = reader.list_sessions();
        let mut cov = Coverage {
            sessions_found: sessions.len(),
            ..Default::default()
        };
        let good = sessions
            .iter()
            .find(|s| s.id.ends_with("1d5e7a8b9c0d"))
            .expect("amp: good thread listed");
        check_common(&mut cov, &reader, good, "amp");
        assert_eq!(good.title.as_deref(), Some("Fix the flaky attribution test"));
        assert_eq!(good.project.as_deref(), Some("/home/dev/fixture-proj"));
        // Per-message usage, Anthropic camelCase: inputTokens excludes cache.
        cov.token_counts = TokenCoverage::Proven(
            good.input_tokens == 512
                && good.output_tokens == 96
                && good.cache_tokens == 2048 + 84000,
        );
        // The info/summary marker message is noise, not a turn.
        assert_eq!(good.message_count, 2);
        cov.notes.push(
            "local threads dir is a mirror; pre-Nov-2025 threads may exist only on ampcode.com"
                .into(),
        );
        let detail = reader
            .session_detail(&format!("T-{}", "3f2b9c1e-8a4d-4e6b-9c2f-1d5e7a8b9c0d"))
            .expect("detail");
        assert!(detail.messages.iter().any(|m| matches!(m.kind, MessageKind::Thinking)));
        assert!(detail.messages.iter().any(|m| matches!(m.kind, MessageKind::ToolResult)));
        // Corrupted (truncated) thread file: skipped, never fatal.
        cov.corrupted_nonfatal = sessions.iter().all(|s| !s.id.ends_with("T-corrupt"));
        table.insert("amp".into(), cov.to_json());
        complete += usize::from(cov.complete());
    }

    // ---- Roo Code (round 11 — twelfth tool; strict reading now ≥ 10) -------
    {
        let reader = RooReader::with_roots(vec![fixture("roo")]);
        let sessions = reader.list_sessions();
        let mut cov = Coverage {
            sessions_found: sessions.len(),
            ..Default::default()
        };
        let good = sessions
            .iter()
            .find(|s| s.id.ends_with("1748899000000"))
            .expect("roo: good task listed");
        check_common(&mut cov, &reader, good, "roo");
        // Roo does NOT persist the model per task (only a mutable profile
        // name in VS Code secrets) — honestly absent, never guessed.
        cov.model_absent_in_format = true;
        cov.notes
            .push("model id not persisted per task (profile name only) — absent, not guessed".into());
        // Roo convention: tokensIn INCLUDES cache — non-cached = 5230 − 5000.
        cov.token_counts = TokenCoverage::Proven(
            good.input_tokens == 230
                && good.output_tokens == 812
                && good.cache_tokens == 4100 + 900,
        );
        assert_eq!(good.title.as_deref(), Some("Fix the login bug"));
        assert_eq!(good.project.as_deref(), Some("/home/dev/fixture-proj"));
        // The tasks/_index.json cache is not a task dir.
        assert!(sessions.iter().all(|s| !s.id.contains("_index")));
        // Corrupted transcript: lists from history_item.json, turns honestly 0.
        let hurt = sessions
            .iter()
            .find(|s| s.id.ends_with("1748899100000"))
            .expect("roo: corrupted task still listed");
        cov.corrupted_nonfatal = hurt.message_count == 0
            && hurt.input_tokens == 500
            && hurt.cache_tokens == 200
            && hurt.title.as_deref() == Some("Corrupted transcript task");
        table.insert("roo".into(), cov.to_json());
        complete += usize::from(cov.complete());
    }

    // ---- SQLite binary-failure path (round-1 critic's blind spot) ----------
    // The .sql fixtures exercise blob-level corruption only; the snapshot
    // machinery's real hazards are a truncated database and a non-SQLite
    // file. Both must degrade to an empty list, never a panic.
    {
        let dir = std::env::temp_dir().join(format!("saffev-g2-{}", uuid_ish()));
        std::fs::create_dir_all(&dir).unwrap();
        let good_db = build_db("cursor/state.sql", "whole.vscdb");
        let bytes = std::fs::read(&good_db).unwrap();
        let truncated = dir.join("truncated.vscdb");
        std::fs::write(&truncated, &bytes[..bytes.len() / 2]).unwrap();
        let not_sqlite = dir.join("not-a-db.vscdb");
        std::fs::write(&not_sqlite, b"this is just text pretending to be a database").unwrap();
        for db in [truncated.clone(), not_sqlite.clone()] {
            assert!(
                CursorReader::with_db(db.clone()).list_sessions().is_empty(),
                "cursor: binary-corrupt db must degrade to empty, got sessions from {db:?}"
            );
            assert!(
                OpenCodeReader::with_db(db.clone()).list_sessions().is_empty(),
                "opencode: binary-corrupt db must degrade to empty, got sessions from {db:?}"
            );
            assert!(
                GooseReader::with_db(db.clone()).list_sessions().is_empty(),
                "goose: binary-corrupt db must degrade to empty, got sessions from {db:?}"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    // ---- Artifact ----------------------------------------------------------
    let out = serde_json::json!({
        "command": "cargo test --test agents_bench -- --nocapture",
        "harness": "agents_bench v1 (G2 loop 1 — docs/gauntlets/GAUNTLETS.md)",
        "fixtures": "tests/fixtures/agents/<tool>/ (committed, sanitized; SQLite tools as reviewable .sql)",
        "bar": "ccusage parses 15 agent CLIs; rubric wants >= 10 tools with fields proven",
        "tools": table,
        "tools_covered": complete,
    });
    let pretty = serde_json::to_string_pretty(&out).unwrap();
    println!("{pretty}");
    let out_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/bench");
    std::fs::create_dir_all(out_dir).expect("create bench dir");
    std::fs::write(format!("{out_dir}/agents-results.json"), pretty + "\n")
        .expect("write bench/agents-results.json");

    // ---- Floors ------------------------------------------------------------
    // Every currently-shipped adapter must prove the full rubric checklist.
    // Raising this floor is progress (new adapters); lowering it is a
    // regression the harness refuses.
    assert!(
        complete >= 12,
        "adapter coverage regressed: {complete} of 12 complete"
    );
}
