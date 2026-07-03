//! Optional Codex app-server backend — uses the user's **local Codex + their
//! ChatGPT subscription** as an on-demand analysis model.
//!
//! This is the one code path where content leaves the device: session text is
//! sent to OpenAI *through the user's own Codex*. It is therefore **strictly
//! opt-in** (gated on [`crate::config::AnalysisConfig::enabled`]) and runs only on
//! an explicit user action.
//!
//! ## Hardening (the model can only produce text)
//! Each request spawns a throwaway `codex app-server` with:
//! - a **minimal `CODEX_HOME`**: the user's `auth.json` symlinked in, but a blank
//!   `config.toml` so **none of their MCP servers load** (fast boot, no tool
//!   surface);
//! - `sandbox = "read-only"` and `approvalPolicy = "never"`;
//! - **every tool/exec/file approval auto-declined**.
//!
//! So it cannot run a command, edit a file, hit the network (beyond Codex's own
//! model call), or use a tool — it can only answer. The process + temp home are
//! killed/removed when the request ends. Blocking; call from `spawn_blocking`.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

/// A completion produced by the Codex backend.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Completion {
    /// The generated text.
    pub text: String,
    /// The model that produced it, if known.
    pub model: Option<String>,
    /// Wall-clock time for the request (millis).
    pub elapsed_ms: u64,
}

/// Locate the `codex` binary (`$CODEX_BIN` override, else `PATH`).
pub fn codex_bin() -> Option<PathBuf> {
    if let Some(b) = std::env::var_os("CODEX_BIN") {
        let p = PathBuf::from(b);
        if p.is_file() {
            return Some(p);
        }
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join("codex"))
        .find(|c| c.is_file())
}

/// Is the Codex analysis backend usable on this machine? (binary present + the
/// user is authenticated). Cheap — no process spawned.
pub fn is_available() -> bool {
    codex_bin().is_some() && super::home().join(".codex/auth.json").is_file()
}

/// Owns the child process + throwaway home; kills/cleans up on drop so no path
/// (error, timeout, panic-unwind) leaks a process or temp dir.
struct Session {
    child: Child,
    home: PathBuf,
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

fn send_msg(stdin: &mut ChildStdin, v: &Value) -> Result<(), String> {
    let mut s = v.to_string();
    s.push('\n');
    stdin.write_all(s.as_bytes()).map_err(|e| e.to_string())?;
    stdin.flush().map_err(|e| e.to_string())
}

/// Run one prompt through a hardened, throwaway Codex session and return the
/// text. `Err` on any failure — callers must treat this as fail-open (analysis
/// is a best-effort enhancement, never load-bearing).
pub fn run_prompt(
    prompt: &str,
    model: Option<&str>,
    timeout: Duration,
) -> Result<Completion, String> {
    let start = Instant::now();
    let bin = codex_bin().ok_or("Codex binary not found on PATH")?;

    // Minimal CODEX_HOME: real auth, blank config (⇒ no MCP servers).
    let home = std::env::temp_dir().join(format!("saffev-codex-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&home).map_err(|e| e.to_string())?;
    let real = super::home().join(".codex");
    for f in ["auth.json", "version.json"] {
        let src = real.join(f);
        if src.exists() {
            #[cfg(unix)]
            let _ = std::os::unix::fs::symlink(&src, home.join(f));
            #[cfg(not(unix))]
            let _ = std::fs::copy(&src, home.join(f));
        }
    }
    let cfg = model
        .map(|m| format!("model = \"{m}\"\n"))
        .unwrap_or_default();
    let _ = std::fs::write(home.join("config.toml"), cfg);

    let mut child = Command::new(&bin)
        .arg("app-server")
        .env("CODEX_HOME", &home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn codex: {e}"))?;
    let mut stdin = child.stdin.take().ok_or("no stdin")?;
    let stdout = child.stdout.take().ok_or("no stdout")?;
    let mut session = Session { child, home };

    // Read stdout lines → channel; the thread ends when Codex closes stdout.
    let (tx, rx) = mpsc::channel::<Value>();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if let Ok(v) = serde_json::from_str::<Value>(&line) {
                if tx.send(v).is_err() {
                    break;
                }
            }
        }
    });

    let version = env!("CARGO_PKG_VERSION");
    send_msg(
        &mut stdin,
        &json!({"method":"initialize","id":0,"params":{"clientInfo":{"name":"saffev","title":"Saffev","version":version}}}),
    )?;
    send_msg(&mut stdin, &json!({"method":"initialized","params":{}}))?;

    let deadline = start + timeout;
    let mut tid: Option<String> = None;
    let mut text = String::new();
    let mut got_text = false;

    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err("Codex timed out".into());
        }
        let msg = match rx.recv_timeout(deadline - now) {
            Ok(m) => m,
            Err(mpsc::RecvTimeoutError::Timeout) => return Err("Codex timed out".into()),
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err("Codex exited".into()),
        };
        let id = msg.get("id").and_then(Value::as_i64);
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
        let result = msg.get("result");
        let error = msg.get("error");

        if id == Some(0) && result.is_some() {
            // Handshake done — start a hardened, read-only thread.
            send_msg(
                &mut stdin,
                &json!({"method":"thread/start","id":1,"params":{"approvalPolicy":"never","sandbox":"read-only"}}),
            )?;
        } else if id == Some(1) {
            if let Some(e) = error {
                return Err(format!("thread/start: {e}"));
            }
            tid = result
                .and_then(|r| r.get("thread"))
                .and_then(|t| t.get("id"))
                .and_then(Value::as_str)
                .map(String::from);
            let t = tid.as_deref().ok_or("no thread id")?;
            send_msg(
                &mut stdin,
                &json!({"method":"turn/start","id":2,"params":{"threadId":t,"input":[{"type":"text","text":prompt}]}}),
            )?;
        } else if id == Some(2) && error.is_some() {
            return Err(format!("turn/start: {}", error.unwrap()));
        } else if method == "item/agentMessage/delta" {
            if let Some(d) = msg
                .get("params")
                .and_then(|p| p.get("delta"))
                .and_then(Value::as_str)
            {
                text.push_str(d);
                got_text = true;
            }
        } else if method == "item/completed" {
            if let Some(it) = msg.get("params").and_then(|p| p.get("item")) {
                if it.get("type").and_then(Value::as_str) == Some("agentMessage") {
                    if let Some(t) = it.get("text").and_then(Value::as_str) {
                        text = t.to_string();
                        got_text = true;
                    }
                }
            }
        } else if method.ends_with("requestApproval") {
            // The model tried to use a tool/exec/file op — refuse. It stays text-only.
            if let Some(rid) = id {
                let _ = send_msg(
                    &mut stdin,
                    &json!({"id":rid,"result":{"decision":"decline"}}),
                );
            }
        } else if method == "turn/completed" {
            if got_text && !text.trim().is_empty() {
                break;
            }
            let status = msg
                .get("params")
                .and_then(|p| p.get("turn"))
                .and_then(|t| t.get("status"))
                .and_then(Value::as_str)
                .unwrap_or("completed");
            return Err(format!("Codex produced no text ({status})"));
        } else if method == "turn/failed" || method == "error" {
            let m = msg
                .get("params")
                .and_then(|p| p.get("error"))
                .and_then(|e| e.get("message"))
                .and_then(Value::as_str)
                .unwrap_or("turn failed");
            return Err(format!("Codex: {m}"));
        }
    }

    // Best-effort: drop the throwaway thread's rollout, then let `Session` reap
    // the process + temp home.
    if let Some(t) = &tid {
        let _ = send_msg(
            &mut stdin,
            &json!({"method":"thread/delete","id":9,"params":{"threadId":t}}),
        );
    }
    let _ = stdin.flush();
    drop(stdin);
    let _ = &mut session; // held to Drop (kills child, removes home)

    Ok(Completion {
        text: text.trim().to_string(),
        model: model.map(String::from),
        elapsed_ms: start.elapsed().as_millis() as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn availability_is_total() {
        // Must never panic regardless of machine state.
        let _ = is_available();
        let _ = codex_bin();
    }

    #[test]
    fn analysis_is_off_by_default() {
        // The privacy-sensitive backend must default off.
        assert!(!crate::config::Config::default().analysis.enabled);
        assert_eq!(crate::config::AnalysisConfig::default().timeout_ms, 90_000);
    }
}
