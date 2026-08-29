//! G5 gauntlet harness — preservation, scored not asserted by hand
//! (docs/gauntlets/GAUNTLETS.md §G5).
//!
//! One command, reproducible:
//!
//! ```text
//! cargo test --test preservation_bench -- --nocapture
//! ```
//!
//! Proves the four preservation claims with fixtures built inside the test —
//! nothing here reads the machine's real history and nothing touches the
//! network:
//!
//! - **freshness** — the default auto-snapshot cadence is ≤5 minutes and the
//!   scheduler's gate follows the live config (rubric a);
//! - **tamper** — editing an archived transcript behind the store's back is
//!   detected AND the altered session is named precisely (rubric b);
//! - **FTS** — one content search spans sessions from three different tools
//!   (rubric c);
//! - **git linkage** — sessions link to the commits made in their project
//!   during their window, ≥80% of linkable fixtures linked (rubric d).
//!
//! Emits `bench/preservation-results.json`. The artifact carries only stable
//! facts (no timestamps, paths, or hashes), so CI can `git diff --exit-code`
//! it against the committed copy.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use saffev::agents::gitlink::{self, CommitLink};
use saffev::config::{ArchiveConfig, Config};
use saffev::store::{ArchivedMessage, ArchivedSession, Store, WriteOp};

/// A term planted in every fixture transcript so one search can prove
/// cross-tool coverage. Unusual on purpose: it must never match real data if
/// someone points the bench at a non-temp store by mistake.
const PROBE: &str = "hermetic-preservation-probe";

/// Fixture window base (unix seconds). Fixed so the git fixture (and therefore
/// the linked percentage) is fully deterministic. The value is in the past;
/// git does not care either way.
const W0: i64 = 1_750_000_000;

fn tmp_path(stem: &str) -> PathBuf {
    std::env::temp_dir().join(format!("saffev-g5-{stem}-{}", uuid::Uuid::new_v4()))
}

/// One archived fixture session for `tool`, transcript carrying [`PROBE`].
fn fixture_session(tool: &str, raw: &str, extra: &str) -> ArchivedSession {
    let id = format!("{tool}:{raw}");
    ArchivedSession {
        id: id.clone(),
        tool: tool.into(),
        source_id: raw.into(),
        title: Some(format!("G5 fixture ({tool})")),
        project: Some("/tmp/g5-fixture-project".into()),
        git_branch: None,
        model: Some("test-model".into()),
        started_ts: W0 * 1000,
        updated_ts: (W0 + 300) * 1000,
        message_count: 2,
        tool_call_count: 0,
        input_tokens: 10,
        output_tokens: 20,
        cache_tokens: 0,
        source_path: None,
        content_hash: format!("hash-{id}"),
        archived_ts: (W0 + 400) * 1000,
        source_deleted: false,
        messages: vec![
            ArchivedMessage {
                role: "user".into(),
                kind: "text".into(),
                content: format!("please run the {PROBE} against {extra}"),
                ts: Some(W0 * 1000),
                tool_name: None,
            },
            ArchivedMessage {
                role: "assistant".into(),
                kind: "text".into(),
                content: format!("done — {extra} handled"),
                ts: Some((W0 + 60) * 1000),
                tool_name: None,
            },
        ],
    }
}

/// Run one git command in `dir` with a pinned identity, no global/system
/// config, and (optionally) pinned author+committer dates — hermetic on any
/// machine, including CI runners with exotic global gitconfig.
fn git(dir: &Path, date_secs: Option<i64>, args: &[&str]) {
    let mut cmd = std::process::Command::new("git");
    cmd.arg("-C")
        .arg(dir)
        .args(["-c", "user.name=g5", "-c", "user.email=g5@bench.local"])
        .args([
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=g5main",
        ])
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .args(args);
    if let Some(s) = date_secs {
        cmd.env("GIT_AUTHOR_DATE", format!("{s} +0000"))
            .env("GIT_COMMITTER_DATE", format!("{s} +0000"));
    }
    let out = cmd.output().expect("git available");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[tokio::test]
async fn preservation_floors() {
    // ---- freshness (rubric a) ------------------------------------------------
    // The default cadence must keep the "durable within minutes" promise: ≤5.
    let interval = ArchiveConfig::default().interval_minutes;
    assert!(
        (1..=5).contains(&interval),
        "default snapshot interval must be ≤5 min (got {interval})"
    );
    // The scheduler's gate follows the LIVE config: both switches required, and
    // flipping either one changes the next tick's decision.
    let mut cfg = Config::default();
    assert!(!saffev::studio::should_run(&cfg), "off by default");
    cfg.archive.enabled = true;
    assert!(
        !saffev::studio::should_run(&cfg),
        "enabled without auto = manual only"
    );
    cfg.archive.auto = true;
    assert!(
        saffev::studio::should_run(&cfg),
        "enabled + auto = snapshot"
    );
    cfg.archive.enabled = false;
    assert!(
        !saffev::studio::should_run(&cfg),
        "disabling stops the very next tick"
    );

    // ---- archive three sessions from three different tools --------------------
    // Fixed key via the documented env override so the bench needs no keyring.
    std::env::set_var("SAFFEV_DB_KEY", "g5-preservation-bench-key-0123456789");
    let db = tmp_path("store").with_extension("db");
    let store = Store::open(&db).await.expect("open temp store");
    let tools = ["aider", "claude_code", "codex"];
    for (tool, extra) in [
        ("claude_code", "login flow"),
        ("codex", "payment retries"),
        ("aider", "csv importer"),
    ] {
        store.enqueue(WriteOp::ArchiveSession(Box::new(fixture_session(
            tool, "g5", extra,
        ))));
    }
    store.flush().await.expect("flush archive writes");

    let v = store.verify_archive().await.expect("verify");
    assert!(v.intact, "fresh archive must verify: {:?}", v.broken_at);
    assert_eq!(v.sessions, 3);
    assert_eq!(v.entries, 3);

    // ---- FTS across three tools (rubric c) ------------------------------------
    // One search over what was SAID must surface all three tools' sessions.
    // (Before the tamper below, so the index reflects honest content.)
    let hits = store.search_archive(PROBE, 10).await.expect("search");
    let tools_matched: BTreeSet<String> = hits
        .iter()
        .filter_map(|h| h.session_id.split(':').next().map(str::to_string))
        .collect();
    assert_eq!(
        tools_matched,
        tools.iter().map(|t| t.to_string()).collect::<BTreeSet<_>>(),
        "content search must span all three tools"
    );
    let fts_tools_matched = tools_matched.len();

    // ---- tamper detection, named precisely (rubric b) --------------------------
    // Edit one archived transcript directly in the database file, the way
    // someone with the file (and the key) would — bypassing the store entirely.
    {
        let conn = rusqlite::Connection::open(&db).expect("raw open");
        // Same passphrase handshake the store uses; a no-op on a plain
        // (--no-default-features) build where the DB is unencrypted SQLite.
        conn.pragma_update(None, "key", "g5-preservation-bench-key-0123456789")
            .expect("pragma key");
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        conn.execute(
            "UPDATE archived_messages SET content = 'quietly rewritten by the bench' \
             WHERE session_id = 'codex:g5'",
            [],
        )
        .expect("tamper update");
    }
    let v = store.verify_archive().await.expect("verify after tamper");
    let tamper_detected = !v.intact;
    let named_precisely = v.altered_sessions == vec!["codex:g5".to_string()];
    assert!(tamper_detected, "an edited transcript must not verify");
    assert!(
        named_precisely,
        "the tampered session must be named exactly: {:?}",
        v.altered_sessions
    );
    assert!(v.broken_at.is_some(), "the failure must say where");
    let _ = std::fs::remove_file(&db);

    // ---- git linkage (rubric d) -------------------------------------------------
    // A temp repo with five commits inside a known window and one outside it.
    let repo = tmp_path("repo");
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, None, &["init", "-q"]);
    for i in 1..=5i64 {
        git(
            &repo,
            Some(W0 + 60 * i),
            &[
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                &format!("g5 commit {i}"),
            ],
        );
    }
    // The decoy: far outside every session window below.
    git(
        &repo,
        Some(W0 + 100_000),
        &["commit", "-q", "--allow-empty", "-m", "g5 decoy commit"],
    );

    // A window covering all five (pad 10 min) links exactly those five —
    // the decoy must not leak in.
    let all = gitlink::commits_for(
        &repo,
        None,
        W0 * 1000,
        (W0 + 400) * 1000,
        gitlink::DEFAULT_PAD_MS,
    );
    let summaries: BTreeSet<String> = all.iter().map(|c| c.summary.clone()).collect();
    assert_eq!(
        all.len(),
        5,
        "window must link exactly the 5 in-window commits"
    );
    assert_eq!(
        summaries,
        (1..=5)
            .map(|i| format!("g5 commit {i}"))
            .collect::<BTreeSet<_>>(),
        "the decoy commit outside the window must not link"
    );
    assert!(all.iter().all(|c| !c.hash.is_empty() && c.ts > 0));
    // The recorded branch works; a branch that no longer exists falls back to
    // HEAD instead of pretending the work vanished.
    assert_eq!(
        gitlink::commits_for(
            &repo,
            Some("g5main"),
            W0 * 1000,
            (W0 + 400) * 1000,
            gitlink::DEFAULT_PAD_MS
        )
        .len(),
        5
    );
    assert_eq!(
        gitlink::commits_for(
            &repo,
            Some("branch-rebased-away"),
            W0 * 1000,
            (W0 + 400) * 1000,
            gitlink::DEFAULT_PAD_MS
        )
        .len(),
        5,
        "missing branch must fall back to HEAD"
    );

    // Rubric floor: ≥80% of fixture sessions link to at least one commit.
    // Five sessions with windows over the repo activity, one whose project is
    // not a repository at all (fail-soft: it simply links nothing).
    let no_repo = tmp_path("norepo");
    std::fs::create_dir_all(&no_repo).unwrap();
    let session_windows: Vec<(&Path, i64, i64)> = vec![
        (&repo, W0, W0 + 90),        // covers commit 1
        (&repo, W0 + 90, W0 + 150),  // covers commit 2
        (&repo, W0 + 150, W0 + 210), // covers commit 3
        (&repo, W0 + 210, W0 + 270), // covers commit 4
        (&repo, W0 + 270, W0 + 400), // covers commit 5
        (&no_repo, W0, W0 + 400),    // no repo — honestly unlinked
    ];
    let linked = session_windows
        .iter()
        .map(|(p, a, b)| gitlink::commits_for(p, None, a * 1000, b * 1000, 0))
        .filter(|c: &Vec<CommitLink>| !c.is_empty())
        .count();
    let git_linked_pct = (linked as f64 / session_windows.len() as f64 * 1000.0).round() / 10.0;
    assert!(
        git_linked_pct >= 80.0,
        "≥80% of fixture sessions must link (got {git_linked_pct}%)"
    );
    let _ = std::fs::remove_dir_all(&repo);
    let _ = std::fs::remove_dir_all(&no_repo);

    // ---- artifact ------------------------------------------------------------
    // Stable facts only — no timestamps, paths, or digests — so the committed
    // copy diffs clean against any honest run of the same code.
    let out = serde_json::json!({
        "command": "cargo test --test preservation_bench -- --nocapture",
        "harness": "preservation_bench v1 (G5 — docs/gauntlets/GAUNTLETS.md §G5)",
        "network": "none — temp store, temp git repos, fixtures built in-test; nothing fetches",
        "freshness_interval_minutes": interval,
        "scheduler_gate": "studio::should_run — archive.enabled && archive.auto, re-read from the live config every tick",
        "tamper": {
            "sessions_archived": 3,
            "tools": tools,
            "detected": tamper_detected,
            "named_precisely": named_precisely,
        },
        "fts_tools_matched": fts_tools_matched,
        "git_linked_pct": git_linked_pct,
        "boundaries": "The chain proves self-consistency (any edit after capture breaks it), not \
                       resistance to an attacker who controls the machine and recomputes every \
                       digest — that needs the head digest anchored off-machine. Git linkage is \
                       time-window correlation (±10 min pad), not proof the session authored the \
                       commit. Freshness is the scheduler's default cadence; a stopped Studio \
                       archives nothing until it runs again.",
    });
    let pretty = serde_json::to_string_pretty(&out).unwrap();
    println!("{pretty}");
    let out_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/bench");
    std::fs::create_dir_all(out_dir).expect("create bench dir");
    std::fs::write(
        format!("{out_dir}/preservation-results.json"),
        pretty + "\n",
    )
    .expect("write bench/preservation-results.json");
}
