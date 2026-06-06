//! Source-app attribution (04 §7.2).
//!
//! Layered, confidence-scored, computed **off the tee** (never inline):
//! 1. socket PID lookup at connect (highest confidence),
//! 2. `X-Client-Name` / `User-Agent` header fallback,
//! 3. `Unknown` otherwise.
//!
//! ## Platform gating
//!
//! The PID lookup is inherently OS-specific and is `cfg`-gated so the crate
//! compiles everywhere:
//!
//! * **Linux** — map the peer's `(addr, port)` to a socket inode via
//!   `/proc/net/tcp[6]`, then scan `/proc/<pid>/fd/*` for a symlink to
//!   `socket:[<inode>]`, and read the owning process name from
//!   `/proc/<pid>/comm`. No subprocess.
//! * **macOS / other unix** — fall back to `lsof`, the universally-present BSD
//!   tool, querying the listening side for the established connection's PID.
//! * **everything else** — no PID probe; we degrade to the header fallback.
//!
//! All probes are best-effort: any failure returns `Ok(None)` / `Unknown`, never
//! an error on the logging path (this runs off the tee, but it still must never
//! be able to break logging).

use std::net::SocketAddr;

use crate::store::SourceConfidence;
use crate::Result;

/// A resolved source application + how confident we are.
#[derive(Debug, Clone)]
pub struct SourceApp {
    /// Process / client name, if resolved.
    pub name: Option<String>,
    /// Confidence of the resolution.
    pub confidence: SourceConfidence,
}

/// Header carrying an explicit client name, honored before `User-Agent`.
pub const CLIENT_NAME_HEADER: &str = "x-client-name";

/// Resolve the connecting process from a local socket via PID lookup. Highest
/// confidence. Platform-specific under the hood (e.g. `/proc` on Linux).
///
/// `peer` is the remote end of the accepted connection (the *client's* source
/// address + ephemeral port), as seen by the proxy listener.
pub fn resolve_by_pid(peer: SocketAddr) -> Result<Option<String>> {
    Ok(pid_lookup(peer))
}

/// Resolve from request headers (`X-Client-Name`, then `User-Agent`).
///
/// Pure and unit-tested. Returns the first non-empty candidate, normalized
/// (trimmed; `User-Agent` reduced to its leading product token so
/// `"ollama/0.30.6 (..)"` becomes `"ollama"`).
pub fn resolve_by_header(headers: &axum::http::HeaderMap) -> Option<String> {
    if let Some(name) = headers
        .get(CLIENT_NAME_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return Some(name.to_string());
    }

    headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .and_then(normalize_user_agent)
}

/// Reduce a `User-Agent` to a friendly source-app name: its leading product
/// token, before any `/version` or whitespace. Empty/garbage → `None`.
fn normalize_user_agent(ua: &str) -> Option<String> {
    let ua = ua.trim();
    if ua.is_empty() {
        return None;
    }
    // Take the first whitespace-delimited token, then drop a trailing `/version`.
    let first = ua.split_whitespace().next().unwrap_or(ua);
    let product = first.split('/').next().unwrap_or(first).trim();
    if product.is_empty() {
        None
    } else {
        Some(product.to_string())
    }
}

/// Full layered resolution with an *optional* peer. Identical to [`resolve`]
/// when a peer is present; when the connect info was unavailable (`None`), the
/// PID layer is skipped and we resolve from headers (Header) then `Unknown`.
///
/// This is the entry point the off-path logger uses, since `ConnectInfo` may, in
/// principle, be absent.
pub fn resolve_opt(peer: Option<SocketAddr>, headers: &axum::http::HeaderMap) -> SourceApp {
    match peer {
        Some(peer) => resolve(peer, headers),
        None => match resolve_by_header(headers) {
            Some(name) => SourceApp {
                name: Some(name),
                confidence: SourceConfidence::Header,
            },
            None => SourceApp {
                name: None,
                confidence: SourceConfidence::Unknown,
            },
        },
    }
}

/// Full layered resolution: PID, then header, then `Unknown`.
pub fn resolve(peer: SocketAddr, headers: &axum::http::HeaderMap) -> SourceApp {
    // 1. Highest confidence: who actually owns the socket.
    if let Ok(Some(name)) = resolve_by_pid(peer) {
        return SourceApp {
            name: Some(name),
            confidence: SourceConfidence::Pid,
        };
    }

    // 2. Honor a client-declared identity.
    if let Some(name) = resolve_by_header(headers) {
        return SourceApp {
            name: Some(name),
            confidence: SourceConfidence::Header,
        };
    }

    // 3. Give up — but say so honestly.
    SourceApp {
        name: None,
        confidence: SourceConfidence::Unknown,
    }
}

// ---------------------------------------------------------------------------
// PID lookup — platform-gated, best-effort.
// ---------------------------------------------------------------------------

/// A loopback connection (peer addr is loopback) is required for PID lookup to
/// be meaningful — the owning process is local. Remote peers can never be mapped
/// to a local PID, so we skip the probe entirely.
fn is_local_peer(peer: SocketAddr) -> bool {
    peer.ip().is_loopback()
}

#[cfg(target_os = "linux")]
fn pid_lookup(peer: SocketAddr) -> Option<String> {
    if !is_local_peer(peer) {
        return None;
    }
    let inode = socket_inode_for_peer(peer)?;
    let pid = pid_for_socket_inode(inode)?;
    process_name_for_pid(pid)
}

/// Find the socket inode whose *remote* end matches `peer` in `/proc/net/tcp[6]`.
///
/// From the proxy's vantage the client connection appears as a row whose remote
/// address+port equals the client's `peer`. We match on that.
#[cfg(target_os = "linux")]
fn socket_inode_for_peer(peer: SocketAddr) -> Option<u64> {
    let want_port = peer.port();
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(contents) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in contents.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // local_address remote_address st ... inode is field index 9.
            if fields.len() < 10 {
                continue;
            }
            let remote = fields[2];
            let Some((_addr_hex, port_hex)) = remote.split_once(':') else {
                continue;
            };
            let Ok(rport) = u16::from_str_radix(port_hex, 16) else {
                continue;
            };
            if rport != want_port {
                continue;
            }
            if let Ok(inode) = fields[9].parse::<u64>() {
                return Some(inode);
            }
        }
    }
    None
}

/// Scan `/proc/<pid>/fd/*` for a symlink pointing at `socket:[<inode>]`.
#[cfg(target_os = "linux")]
fn pid_for_socket_inode(inode: u64) -> Option<u32> {
    let needle = format!("socket:[{inode}]");
    let proc = std::fs::read_dir("/proc").ok()?;
    for entry in proc.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        let fd_dir = format!("/proc/{pid}/fd");
        let Ok(fds) = std::fs::read_dir(&fd_dir) else {
            continue;
        };
        for fd in fds.flatten() {
            if let Ok(target) = std::fs::read_link(fd.path()) {
                if target.to_string_lossy() == needle {
                    return Some(pid);
                }
            }
        }
    }
    None
}

/// Read a process's friendly name from `/proc/<pid>/comm`.
#[cfg(target_os = "linux")]
fn process_name_for_pid(pid: u32) -> Option<String> {
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    let name = comm.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Hard cap on how long the `lsof` probe may run before we give up and fall
/// back to the header layer. Keeps a wedged subprocess from ever stalling the
/// logger task (this runs off the hot path, but must still be bounded).
#[cfg(all(unix, not(target_os = "linux")))]
const LSOF_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(750);

#[cfg(all(unix, not(target_os = "linux")))]
fn pid_lookup(peer: SocketAddr) -> Option<String> {
    if !is_local_peer(peer) {
        return None;
    }

    // Ask lsof for the established TCP connection whose source is the client's
    // ephemeral port. `-iTCP:<port>` matches either end; `-sTCP:ESTABLISHED`
    // narrows to live connections. `-Fcn` gives terse command (`c`) + name (`n`)
    // fields so we can correlate. Bounded by LSOF_TIMEOUT and fail-soft.
    let output = run_lsof_bounded(peer.port())?;
    if !output.status.success() && output.stdout.is_empty() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    parse_lsof_command_for_peer(&text, peer)
}

/// Run `lsof` for the given port with a wall-clock timeout, killing the child on
/// overrun. Returns `None` on spawn failure, timeout, or wait error — never
/// blocks indefinitely. Best-effort: a missing/slow `lsof` simply degrades to
/// the header fallback.
#[cfg(all(unix, not(target_os = "linux")))]
fn run_lsof_bounded(port: u16) -> Option<std::process::Output> {
    use std::io::Read;
    use std::process::{Command, Stdio};

    let mut child = Command::new("lsof")
        .args(["-nP", &format!("-iTCP:{port}"), "-sTCP:ESTABLISHED", "-Fcn"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
        .ok()?;

    let deadline = std::time::Instant::now() + LSOF_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = Vec::new();
                if let Some(mut out) = child.stdout.take() {
                    let _ = out.read_to_end(&mut stdout);
                }
                return Some(std::process::Output {
                    status,
                    stdout,
                    stderr: Vec::new(),
                });
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    // Timed out: reap the child and give up.
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

/// Parse lsof `-Fcn` records into the command-name owning the connection whose
/// endpoint matches `peer`. Pure; unit-tested.
///
/// lsof emits records grouped per process: a `p<pid>` then `c<command>`, then one
/// or more `f<fd>`/`n<addr>->...` lines. We track the current command and return
/// it when an `n` line references the client's ephemeral port.
#[cfg(all(unix, not(target_os = "linux")))]
fn parse_lsof_command_for_peer(text: &str, peer: SocketAddr) -> Option<String> {
    let port_token = format!(":{}", peer.port());
    let mut current_command: Option<String> = None;
    for line in text.lines() {
        if let Some(cmd) = line.strip_prefix('c') {
            current_command = Some(cmd.trim().to_string());
        } else if let Some(name) = line.strip_prefix('n') {
            // name looks like `local->remote`, e.g. `127.0.0.1:54321->127.0.0.1:11434`.
            // Match the source (local) side carrying the client's ephemeral port.
            let local = name.split("->").next().unwrap_or(name);
            if local.ends_with(&port_token) {
                if let Some(cmd) = &current_command {
                    if !cmd.is_empty() {
                        return Some(cmd.clone());
                    }
                }
            }
        }
    }
    None
}

/// No PID probe on non-unix targets; degrade to header fallback.
#[cfg(not(unix))]
fn pid_lookup(_peer: SocketAddr) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};
    use std::net::{IpAddr, Ipv4Addr};

    fn hm(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn header_prefers_x_client_name() {
        let h = hm(&[("x-client-name", "MyChatApp"), ("user-agent", "curl/8.0")]);
        assert_eq!(resolve_by_header(&h).as_deref(), Some("MyChatApp"));
    }

    #[test]
    fn header_falls_back_to_user_agent_product() {
        let h = hm(&[("user-agent", "ollama/0.30.6 (darwin arm64)")]);
        assert_eq!(resolve_by_header(&h).as_deref(), Some("ollama"));
    }

    #[test]
    fn header_user_agent_without_version() {
        let h = hm(&[("user-agent", "python-requests")]);
        assert_eq!(resolve_by_header(&h).as_deref(), Some("python-requests"));
    }

    #[test]
    fn header_trims_client_name() {
        let h = hm(&[("x-client-name", "  Spaced  ")]);
        assert_eq!(resolve_by_header(&h).as_deref(), Some("Spaced"));
    }

    #[test]
    fn header_empty_client_name_falls_through() {
        let h = hm(&[("x-client-name", "   "), ("user-agent", "curl/8.0")]);
        assert_eq!(resolve_by_header(&h).as_deref(), Some("curl"));
    }

    #[test]
    fn header_none_when_absent() {
        let h = HeaderMap::new();
        assert!(resolve_by_header(&h).is_none());
    }

    #[test]
    fn header_empty_user_agent_is_none() {
        let h = hm(&[("user-agent", "")]);
        assert!(resolve_by_header(&h).is_none());
    }

    #[test]
    fn normalize_user_agent_strips_version_and_suffix() {
        assert_eq!(
            normalize_user_agent("foo/1.2.3 bar").as_deref(),
            Some("foo")
        );
        assert_eq!(normalize_user_agent("foo").as_deref(), Some("foo"));
        assert_eq!(normalize_user_agent("   ").as_deref(), None);
        assert_eq!(normalize_user_agent("/1.0").as_deref(), None);
    }

    #[test]
    fn resolve_uses_header_when_pid_unavailable() {
        // A non-local peer can never resolve by PID, so resolve() must fall
        // through to the header layer and report Header confidence.
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 44444);
        let h = hm(&[("x-client-name", "RemoteClient")]);
        let resolved = resolve(peer, &h);
        assert_eq!(resolved.name.as_deref(), Some("RemoteClient"));
        assert_eq!(resolved.confidence, SourceConfidence::Header);
    }

    #[test]
    fn resolve_unknown_when_nothing_resolves() {
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 44444);
        let h = HeaderMap::new();
        let resolved = resolve(peer, &h);
        assert!(resolved.name.is_none());
        assert_eq!(resolved.confidence, SourceConfidence::Unknown);
    }

    #[test]
    fn resolve_opt_none_peer_uses_header() {
        // No peer (connect info unavailable) -> skip PID, honor the header.
        let h = hm(&[("x-client-name", "HeaderOnly")]);
        let resolved = resolve_opt(None, &h);
        assert_eq!(resolved.name.as_deref(), Some("HeaderOnly"));
        assert_eq!(resolved.confidence, SourceConfidence::Header);
    }

    #[test]
    fn resolve_opt_none_peer_no_header_is_unknown() {
        let resolved = resolve_opt(None, &HeaderMap::new());
        assert!(resolved.name.is_none());
        assert_eq!(resolved.confidence, SourceConfidence::Unknown);
    }

    #[test]
    fn resolve_opt_some_remote_peer_falls_through_to_header() {
        // A remote peer can never resolve by PID; resolve_opt must match resolve
        // and degrade to the header layer.
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 44444);
        let h = hm(&[("user-agent", "curl/8.0")]);
        let resolved = resolve_opt(Some(peer), &h);
        assert_eq!(resolved.name.as_deref(), Some("curl"));
        assert_eq!(resolved.confidence, SourceConfidence::Header);
    }

    #[test]
    fn non_local_peer_skips_pid_probe() {
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 5000);
        assert!(!is_local_peer(peer));
        // resolve_by_pid must not error and must yield None for a remote peer.
        assert_eq!(resolve_by_pid(peer).unwrap(), None);
    }

    #[test]
    fn loopback_peer_is_local() {
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000);
        assert!(is_local_peer(peer));
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    #[test]
    fn lsof_command_parser_matches_ephemeral_port() {
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 54321);
        let text = "p900\nciTerm2\nf7\nn127.0.0.1:54321->127.0.0.1:11434\n";
        assert_eq!(
            parse_lsof_command_for_peer(text, peer).as_deref(),
            Some("iTerm2")
        );
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    #[test]
    fn lsof_command_parser_no_match_wrong_port() {
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 11111);
        let text = "p900\nciTerm2\nf7\nn127.0.0.1:54321->127.0.0.1:11434\n";
        assert!(parse_lsof_command_for_peer(text, peer).is_none());
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    #[test]
    fn lsof_bounded_returns_fast_and_fail_soft_for_unused_port() {
        // No process owns port 1 as an established TCP peer; lsof returns no
        // matching rows. The probe must complete well within its timeout and the
        // parser must yield None — never hang, never error.
        let started = std::time::Instant::now();
        let out = run_lsof_bounded(1);
        // Whether lsof produced output or not, the call must return promptly.
        assert!(
            started.elapsed() < LSOF_TIMEOUT + std::time::Duration::from_secs(1),
            "lsof probe must respect its timeout"
        );
        if let Some(out) = out {
            let text = String::from_utf8_lossy(&out.stdout);
            let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
            assert!(parse_lsof_command_for_peer(&text, peer).is_none());
        }
    }
}
