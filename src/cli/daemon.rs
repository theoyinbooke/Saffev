//! Daemon lifecycle helpers for `saffev start` / `saffev stop`.
//!
//! v0 ran the proxy + Studio in the foreground only; stopping meant Ctrl-C.
//! This module adds real backgrounding and a working stop:
//!
//! - **Background start** re-execs *this same binary* with `--foreground` via
//!   [`std::process::Command`] with detached stdio (no controlling terminal, no
//!   inherited stdout/stderr). This is the cleanest cross-platform path: no
//!   `fork`/`setsid` (which would require `unsafe`, and the crate is
//!   `#![forbid(unsafe_code)]`), no extra dependency. The child writes nothing to
//!   the parent's terminal; the parent prints the URL and returns promptly.
//! - A **PID file** (`saffev.pid` in `config.data_dir`) records the daemon's pid
//!   and the Studio URL so `stop` (and a future `status`) can find it.
//! - **Stop** reads the PID file, sends `SIGTERM` for a graceful shutdown (the
//!   servers run under [`tokio::select!`] on a signal future — see
//!   `commands::run_servers`), waits briefly for the process to exit, then
//!   removes the PID file. A **stale** PID file (the process is no longer alive)
//!   is handled gracefully: we just clean it up.
//!
//! Signaling and liveness go through the POSIX `kill` binary (`kill -0 <pid>` to
//! probe, `kill -TERM <pid>` to terminate) rather than `libc::kill`, again to
//! stay within safe Rust. `kill` is present on both macOS and Linux on the
//! default PATH (`/bin/kill`).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config::Config;
use crate::{Error, Result};

/// PID-file name within the data dir.
pub const PID_FILE_NAME: &str = "saffev.pid";

/// Parsed contents of a PID file: the daemon pid and the Studio URL it printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PidFile {
    /// The daemon process id.
    pub pid: u32,
    /// The Studio URL the daemon is serving (for `stop`/`status` to echo).
    pub url: String,
}

/// Full path to the PID file inside a config's data dir.
pub fn pid_path(cfg: &Config) -> PathBuf {
    cfg.data_dir.join(PID_FILE_NAME)
}

/// Serialize a [`PidFile`] to its on-disk text form: `pid` on the first line,
/// `url` on the second. A plain two-line format keeps it trivially greppable and
/// avoids pulling a serializer into the runtime-state path.
pub fn format_pid_file(pf: &PidFile) -> String {
    format!("{}\n{}\n", pf.pid, pf.url)
}

/// Parse a PID file's text. Accepts a bare-pid first line (url optional) so a
/// hand-written or truncated file still yields a usable pid. Returns `None` when
/// the first line is not a positive integer.
pub fn parse_pid_file(text: &str) -> Option<PidFile> {
    let mut lines = text.lines();
    let pid: u32 = lines.next()?.trim().parse().ok()?;
    if pid == 0 {
        return None;
    }
    let url = lines.next().unwrap_or("").trim().to_string();
    Some(PidFile { pid, url })
}

/// Write a PID file atomically-ish (write a temp sibling, then rename). The data
/// dir is created if needed. Best-effort fsync of the temp file before rename so
/// a crash mid-write can't leave a half-written PID file.
pub fn write_pid_file(path: &Path, pf: &PidFile) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let tmp = path.with_extension("pid.tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(format_pid_file(pf).as_bytes())?;
        let _ = f.sync_all();
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Read + parse a PID file. Returns `Ok(None)` when the file is absent (a normal,
/// not-running state); `Err` only on a real I/O failure reading an existing file.
/// A present-but-unparseable file yields `Ok(None)` (treated as stale/garbage).
pub fn read_pid_file(path: &Path) -> Result<Option<PidFile>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(parse_pid_file(&text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::Io(e)),
    }
}

/// Remove a PID file, ignoring an already-absent file.
pub fn remove_pid_file(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::Io(e)),
    }
}

/// Is the process with `pid` currently alive?
///
/// Uses `kill -0 <pid>`, which sends no signal but performs the same existence +
/// permission check the kernel would for a real signal. Exit status 0 means the
/// process exists (and we may signal it). This is the portable, unsafe-free
/// liveness probe on macOS + Linux. Our own pid (`saffev start` re-checking
/// itself) is short-circuited to `true`.
pub fn process_alive(pid: u32) -> bool {
    if pid == std::process::id() {
        return true;
    }
    std::process::Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Send `SIGTERM` to `pid` for a graceful shutdown. Returns `Ok(())` if the
/// signal was delivered (or the process was already gone), `Err` only if the
/// `kill` invocation itself failed to run.
pub fn send_sigterm(pid: u32) -> Result<()> {
    let status = std::process::Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(Error::Io)?;
    // A non-success status (e.g. ESRCH: no such process) means it's already gone,
    // which is fine for our purposes — the caller wants it stopped.
    let _ = status;
    Ok(())
}

/// Whether a PID file refers to a live process. `Some(true)` = running,
/// `Some(false)` = **stale** (file present, process gone), `None` = no file.
pub fn daemon_state(path: &Path) -> Result<Option<bool>> {
    match read_pid_file(path)? {
        Some(pf) => Ok(Some(process_alive(pf.pid))),
        None => Ok(None),
    }
}

/// Re-exec this binary in the background with `--foreground`, fully detached from
/// the controlling terminal. Returns the spawned child's pid.
///
/// The child inherits the same global flags (`--config`, `--no-color`) so it
/// loads the identical config the parent resolved. stdio is detached
/// (`null`) so the daemon never writes to the parent's terminal and the parent
/// can return immediately.
///
/// `no_open` is forwarded for symmetry; the detached child runs under
/// `--foreground`, which never opens a browser regardless, so this is belt-and-
/// braces (the parent is the one that opens the Studio).
pub fn spawn_background(config_path: Option<&Path>, no_color: bool, no_open: bool) -> Result<u32> {
    let exe = std::env::current_exe()
        .map_err(|e| Error::Other(anyhow::anyhow!("cannot locate current executable: {e}")))?;

    let mut cmd = std::process::Command::new(exe);
    if let Some(cfg) = config_path {
        cmd.arg("--config").arg(cfg);
    }
    if no_color {
        cmd.arg("--no-color");
    }
    cmd.arg("start").arg("--foreground");
    if no_open {
        cmd.arg("--no-open");
    }

    // Fully detach: no inherited stdio, no controlling terminal coupling.
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    let child = cmd
        .spawn()
        .map_err(|e| Error::Other(anyhow::anyhow!("failed to spawn background daemon: {e}")))?;

    Ok(child.id())
}

/// Wait up to `timeout` for `pid` to exit, polling every `poll`. Returns `true`
/// if the process is gone by the deadline, `false` if it's still alive.
pub async fn wait_for_exit(pid: u32, timeout: Duration, poll: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if !process_alive(pid) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(poll).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Unique throwaway dir under the OS temp dir (matches the config-test idiom).
    fn unique_temp_dir(tag: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "saffev-daemon-test-{tag}-{}-{n}",
            std::process::id()
        ))
    }

    #[test]
    fn format_then_parse_round_trips() {
        let pf = PidFile {
            pid: 4242,
            url: "http://localhost:7100".to_string(),
        };
        let text = format_pid_file(&pf);
        let back = parse_pid_file(&text).expect("parses");
        assert_eq!(back, pf);
    }

    #[test]
    fn parse_accepts_bare_pid_without_url() {
        let pf = parse_pid_file("12345\n").expect("bare pid parses");
        assert_eq!(pf.pid, 12345);
        assert_eq!(pf.url, "");
    }

    #[test]
    fn parse_rejects_non_numeric_and_zero() {
        assert!(parse_pid_file("not-a-pid\nhttp://x\n").is_none());
        assert!(parse_pid_file("0\nhttp://x\n").is_none());
        assert!(parse_pid_file("").is_none());
    }

    #[test]
    fn parse_tolerates_whitespace() {
        let pf = parse_pid_file("  77  \n  http://localhost:7100  \n").expect("parses");
        assert_eq!(pf.pid, 77);
        assert_eq!(pf.url, "http://localhost:7100");
    }

    #[test]
    fn write_read_remove_cycle() {
        let dir = unique_temp_dir("rw");
        let path = dir.join(PID_FILE_NAME);
        let pf = PidFile {
            pid: 9001,
            url: "http://localhost:7100".to_string(),
        };

        // Absent file reads as None (not running), not an error.
        assert_eq!(read_pid_file(&path).unwrap(), None);

        write_pid_file(&path, &pf).expect("write pid file");
        assert!(path.exists());

        let read = read_pid_file(&path).expect("read").expect("present");
        assert_eq!(read, pf);

        remove_pid_file(&path).expect("remove");
        assert!(!path.exists());
        // Removing an already-absent file is a no-op (not an error).
        remove_pid_file(&path).expect("idempotent remove");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn garbage_pid_file_reads_as_none() {
        let dir = unique_temp_dir("garbage");
        let path = dir.join(PID_FILE_NAME);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, "this is not a pid\n").unwrap();
        // A present-but-unparseable file degrades to None (treated as stale).
        assert_eq!(read_pid_file(&path).unwrap(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn current_process_is_alive() {
        // Our own pid must always probe alive (short-circuited, no `kill` needed).
        assert!(process_alive(std::process::id()));
    }

    #[test]
    fn unused_pid_is_not_alive() {
        // A very high pid that is effectively never allocated. `kill -0` against
        // it fails (ESRCH), so it must read as not-alive. (NB: pid 0 is *not* a
        // valid probe — on Unix it targets the caller's process group, which
        // exists, so `kill -0 0` succeeds. We never write pid 0 anyway:
        // parse_pid_file rejects it.)
        assert!(!process_alive(u32::MAX));
        assert!(!process_alive(u32::MAX - 1));
    }

    #[test]
    fn stale_detection_for_dead_pid() {
        // A PID file pointing at a definitely-dead pid is detected as stale
        // (Some(false)), not running and not absent.
        let dir = unique_temp_dir("stale");
        let path = dir.join(PID_FILE_NAME);
        // u32::MAX is not a live pid on any sane system.
        let dead = u32::MAX;
        assert!(!process_alive(dead));
        write_pid_file(
            &path,
            &PidFile {
                pid: dead,
                url: "http://localhost:7100".to_string(),
            },
        )
        .unwrap();
        assert_eq!(daemon_state(&path).unwrap(), Some(false), "should be stale");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_state_none_when_no_file() {
        let dir = unique_temp_dir("absent");
        let path = dir.join(PID_FILE_NAME);
        assert_eq!(daemon_state(&path).unwrap(), None);
    }

    #[test]
    fn live_pid_file_reports_running() {
        // A PID file pointing at *our own* pid reports running (Some(true)).
        let dir = unique_temp_dir("live");
        let path = dir.join(PID_FILE_NAME);
        write_pid_file(
            &path,
            &PidFile {
                pid: std::process::id(),
                url: "http://localhost:7100".to_string(),
            },
        )
        .unwrap();
        assert_eq!(daemon_state(&path).unwrap(), Some(true));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn wait_for_exit_returns_true_for_dead_pid() {
        // A dead pid is "exited" immediately.
        let gone = wait_for_exit(
            u32::MAX,
            Duration::from_millis(200),
            Duration::from_millis(10),
        )
        .await;
        assert!(gone);
    }

    #[tokio::test]
    async fn wait_for_exit_times_out_for_live_pid() {
        // Our own pid never exits during the test, so wait times out -> false.
        let gone = wait_for_exit(
            std::process::id(),
            Duration::from_millis(60),
            Duration::from_millis(10),
        )
        .await;
        assert!(!gone);
    }

    #[test]
    fn send_sigterm_to_dead_pid_is_ok() {
        // Signalling a non-existent process is not an error for our purposes
        // (the goal — "it's not running" — is already satisfied).
        assert!(send_sigterm(u32::MAX).is_ok());
    }
}
