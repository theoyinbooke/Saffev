//! G6 live exit-code test — closes the closing critic's blind spot: the
//! `saffev status --check` non-zero exit was only asserted by reading code,
//! never by spawning the binary and inspecting `$?`.
//!
//! This seeds a real store with a PII-spike-tripping fixture, points a real
//! config at it, spawns the actual `saffev` binary, and asserts exit code 2
//! (signal fired) — then a clean store yields exit 0.

use std::process::Command;

use saffev::brain::{Confidence, PiiKind, Side};
use saffev::store::{
    PiiAction, PiiFindingRecord, RequestMeta, SourceConfidence, Store, TokenSource, WriteOp,
};

fn req(id: &str, ts: i64) -> RequestMeta {
    RequestMeta {
        id: id.into(),
        ts,
        source_app: Some("seed-app".into()),
        source_confidence: SourceConfidence::Header,
        engine: "ollama".into(),
        model: Some("qwen3:8b".into()),
        endpoint: "/api/chat".into(),
        stream: false,
        input_tokens: None,
        input_tokens_src: TokenSource::Estimated,
        latency_ms: Some(10),
        request_hash: "h".into(),
        req_bytes: None,
        user_agent: None,
        content_type: None,
        temperature: None,
        top_p: None,
        max_tokens: None,
        msg_count: None,
        has_system: None,
        tool_count: None,
    }
}

fn finding(record_id: &str, id: i64) -> PiiFindingRecord {
    PiiFindingRecord {
        id,
        record_id: record_id.into(),
        side: Side::Request,
        kind: PiiKind::Email,
        label: None,
        start_off: 0,
        end_off: 10,
        confidence: Confidence::High,
        value_hash: format!("h{id}"),
        action: PiiAction::Observed,
    }
}

/// Write a config TOML pointing data_dir at `dir` and return its path.
fn write_config(dir: &std::path::Path) -> std::path::PathBuf {
    // Distinct proxy/upstream ports so Config::load_from's cooperative-mode
    // validation passes — otherwise load falls back to the default config
    // (and the default data_dir), ignoring our fixture entirely.
    let toml = format!(
        "data_dir = \"{}\"\n[ports]\nproxy = 8088\nupstream = 11434\n[monitors]\nenabled = true\npii_spike_per_hour = 5\n",
        dir.display()
    );
    let path = dir.join("saffev.toml");
    std::fs::write(&path, toml).unwrap();
    path
}

/// Fixed DB key so neither this process nor the spawned binary touches the OS
/// keyring (headless keychain access hangs/prompts — the documented gotcha).
const DB_KEY: &str = "g6-exit-test-key-0123456789abcdef";

#[tokio::test]
async fn status_check_exits_2_on_a_fired_signal_and_0_when_clean() {
    std::env::set_var("SAFFEV_DB_KEY", DB_KEY);
    let dir = std::env::temp_dir().join(format!("saffev-g6exit-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg_path = write_config(&dir);
    let empty_claude = dir.join("empty-claude");
    std::fs::create_dir_all(empty_claude.join("projects")).unwrap();

    // A clean store first: no signals → exit 0.
    let db_path = dir.join("saffev.db");
    {
        let store = Store::open(&db_path).await.unwrap();
        store.flush().await.unwrap();
    }
    let clean = Command::new(env!("CARGO_BIN_EXE_saffev"))
        .args(["--config", cfg_path.to_str().unwrap(), "status", "--check"])
        .env("NO_COLOR", "1")
        .env("CLAUDE_CONFIG_DIR", &empty_claude)
        .env("SAFFEV_DB_KEY", DB_KEY)
        // Hermetic home: every agent reader resolves under the fixture dir, so
        // the machine's real session history can neither slow this test down
        // nor trip the sessions-at-risk rule in the "clean" case.
        .env("HOME", &dir)
        .output()
        .expect("spawn saffev");
    assert_eq!(
        clean.status.code(),
        Some(0),
        "clean store should exit 0; stderr: {}",
        String::from_utf8_lossy(&clean.stderr)
    );

    // Now trip the PII-spike rule: 6 findings in the last hour, threshold 5.
    {
        let store = Store::open(&db_path).await.unwrap();
        let now = saffev::agents::now_ms();
        store.enqueue(WriteOp::Request(req("r-spike", now - 60_000)));
        let findings: Vec<_> = (0..6).map(|i| finding("r-spike", i)).collect();
        store.enqueue(WriteOp::PiiFindings(findings));
        store.flush().await.unwrap();
    }
    let tripped = Command::new(env!("CARGO_BIN_EXE_saffev"))
        .args(["--config", cfg_path.to_str().unwrap(), "status", "--check"])
        .env("NO_COLOR", "1")
        .env("CLAUDE_CONFIG_DIR", &empty_claude)
        .env("SAFFEV_DB_KEY", DB_KEY)
        .env("HOME", &dir)
        .output()
        .expect("spawn saffev");
    assert_eq!(
        tripped.status.code(),
        Some(2),
        "a fired signal must exit 2; stdout: {}",
        String::from_utf8_lossy(&tripped.stdout)
    );
    assert!(
        String::from_utf8_lossy(&tripped.stdout).contains("pii"),
        "the fired signal line should name the pii rule"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
