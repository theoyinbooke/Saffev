//! Exposure / auth doctor — the acquisition hook (04 §7.4).
//!
//! Detect when the engine is bound to `0.0.0.0` / a public interface rather than
//! localhost (the documented pain: ~175K exposed Ollama servers, active
//! LLMjacking, real CVEs). Warn prominently in the Studio + CLI; offer a
//! one-click/one-command fix to rebind to localhost and/or front it with the
//! proxy's token auth.
//!
//! ## How the verdict is computed
//!
//! Deterministically, from the OS list of listening sockets — never a guess:
//!
//! 1. Enumerate which local address the engine's listener is bound to. On macOS
//!    we shell out to `lsof` (the universally-present BSD tool); on Linux we read
//!    `/proc/net/tcp` + `/proc/net/tcp6` directly (no subprocess). Both are
//!    cfg-gated so the crate compiles everywhere, with a graceful fallback when
//!    neither is available.
//! 2. Classify the bound address: a loopback / link-local address (`127.0.0.0/8`,
//!    `::1`) is **safe**; the wildcard (`0.0.0.0`, `::`, lsof's `*`) or any
//!    routable interface address is **exposed**.
//! 3. The pure classification lives in [`classify_binding`] so it is fully unit
//!    tested without touching the host.
//!
//! This module makes **no network calls** (honoring the on-device invariant); it
//! only inspects local kernel state and the local engine's bind address.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::Result;

/// The exposure verdict surfaced first-run in Studio + CLI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposureReport {
    /// Whether the engine is reachable from a non-loopback interface.
    pub exposed: bool,
    /// The interface/address the engine is bound to (e.g. `0.0.0.0:11434`).
    pub bound_to: Option<String>,
    /// Whether the proxy's token auth is fronting the engine.
    pub token_protected: bool,
    /// Human-readable detail for the UI.
    pub detail: String,
}

/// Where a listening socket is bound, distilled from the OS socket table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Binding {
    /// Bound to a loopback address only (`127.0.0.0/8`, `::1`). Safe.
    Loopback,
    /// Bound to the wildcard (`0.0.0.0`, `::`) — every interface. Exposed.
    Wildcard,
    /// Bound to a specific, routable interface address. Exposed.
    PublicAddr(IpAddr),
    /// No listener for the port was found in the OS socket table.
    NotListening,
    /// We could not determine the binding on this platform.
    Unknown,
}

/// Run the exposure check against the detected engine binding.
///
/// Fail-soft: any inability to read the OS socket table yields an `Unknown`
/// verdict that does *not* claim exposure (we never cry wolf), rather than an
/// error that would break the Studio Engines page.
pub async fn check(engine_port: u16) -> Result<ExposureReport> {
    // The socket-table read is blocking (subprocess / file IO); keep it off the
    // async runtime's reactor.
    let binding = tokio::task::spawn_blocking(move || binding_for_port(engine_port))
        .await
        .unwrap_or(Binding::Unknown);

    // v0 ships without the proxy token fronting the *engine* port itself; the
    // proxy passthrough is intentionally tokenless. So token_protected is false
    // until/unless a front is wired. Surfaced honestly here.
    let token_protected = false;

    Ok(classify_binding(engine_port, &binding, token_protected))
}

/// Pure verdict logic: turn a [`Binding`] into an [`ExposureReport`].
///
/// Separated out so the decision table is unit-testable with zero host access.
pub fn classify_binding(port: u16, binding: &Binding, token_protected: bool) -> ExposureReport {
    match binding {
        Binding::Loopback => ExposureReport {
            exposed: false,
            bound_to: Some(format!("127.0.0.1:{port}")),
            token_protected,
            detail: "Engine is bound to localhost only — not reachable from the network.".into(),
        },
        Binding::Wildcard => ExposureReport {
            exposed: true,
            bound_to: Some(format!("0.0.0.0:{port}")),
            token_protected,
            detail: format!(
                "Engine is listening on ALL network interfaces (0.0.0.0:{port}). \
                 Anyone who can reach this machine can use your models. \
                 Rebind it to 127.0.0.1, or front it with the proxy's token auth."
            ),
        },
        Binding::PublicAddr(addr) => ExposureReport {
            exposed: true,
            bound_to: Some(format!("{addr}:{port}")),
            token_protected,
            detail: format!(
                "Engine is bound to a routable interface ({addr}:{port}) and is \
                 reachable from the network. Rebind it to 127.0.0.1, or front it \
                 with the proxy's token auth."
            ),
        },
        Binding::NotListening => ExposureReport {
            exposed: false,
            bound_to: None,
            token_protected,
            detail: format!("No engine is currently listening on port {port}."),
        },
        Binding::Unknown => ExposureReport {
            exposed: false,
            bound_to: None,
            token_protected,
            detail: "Could not determine the engine's network binding on this platform.".into(),
        },
    }
}

/// Classify a single parsed bind IP into [`Binding`].
fn classify_addr(ip: IpAddr) -> Binding {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_unspecified() {
                Binding::Wildcard
            } else if v4.is_loopback() {
                Binding::Loopback
            } else {
                Binding::PublicAddr(ip)
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_unspecified() {
                Binding::Wildcard
            } else if v6.is_loopback() {
                Binding::Loopback
            } else {
                Binding::PublicAddr(ip)
            }
        }
    }
}

/// Discover what address the listener on `port` is bound to, using the most
/// permissive interpretation: if *any* listener is on the wildcard or a public
/// address, the port is exposed. Loopback wins only when every listener is
/// loopback. Blocking; call from `spawn_blocking`.
fn binding_for_port(port: u16) -> Binding {
    let addrs = listening_addrs_for_port(port);
    if addrs.is_empty() {
        // Distinguish "couldn't read the table" (Unknown) from "read it, nothing
        // there" (NotListening). On platforms with no probe we return Unknown.
        return if can_probe() {
            Binding::NotListening
        } else {
            Binding::Unknown
        };
    }

    // Fold to the worst case: Wildcard > PublicAddr > Loopback.
    let mut worst = Binding::Loopback;
    for ip in addrs {
        match classify_addr(ip) {
            Binding::Wildcard => return Binding::Wildcard,
            b @ Binding::PublicAddr(_) => worst = b,
            _ => {}
        }
    }
    worst
}

/// Whether this build has a real socket-table probe for the current OS.
fn can_probe() -> bool {
    cfg!(any(target_os = "linux", target_os = "macos"))
}

// ---------------------------------------------------------------------------
// Linux: read /proc/net/tcp + tcp6 directly (no subprocess).
// ---------------------------------------------------------------------------

/// Return every local IP that has a *listening* socket on `port`.
#[cfg(target_os = "linux")]
fn listening_addrs_for_port(port: u16) -> Vec<IpAddr> {
    let mut out = Vec::new();
    out.extend(proc_net_listeners("/proc/net/tcp", port, false));
    out.extend(proc_net_listeners("/proc/net/tcp6", port, true));
    out
}

/// Parse a `/proc/net/tcp[6]` table for listening sockets (state `0A`) on `port`.
#[cfg(target_os = "linux")]
fn proc_net_listeners(path: &str, port: u16, v6: bool) -> Vec<IpAddr> {
    use std::net::Ipv4Addr;

    let Ok(contents) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in contents.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let local = match fields.nth(1) {
            Some(l) => l,
            None => continue,
        };
        // State is field index 3 overall; we've consumed up to index 1, so the
        // next two fields are remote (2) then state (3).
        let _remote = fields.next();
        let state = match fields.next() {
            Some(s) => s,
            None => continue,
        };
        // 0A == TCP_LISTEN.
        if !state.eq_ignore_ascii_case("0A") {
            continue;
        }
        let Some((addr_hex, port_hex)) = local.split_once(':') else {
            continue;
        };
        let Ok(parsed_port) = u16::from_str_radix(port_hex, 16) else {
            continue;
        };
        if parsed_port != port {
            continue;
        }
        // The /proc IPv4 form stores the address little-endian; `to_be` converts
        // host-order back so loopback parses as 127.0.0.1.
        let ip = if v6 {
            parse_hex_ipv6(addr_hex).map(IpAddr::V6)
        } else {
            u32::from_str_radix(addr_hex, 16)
                .ok()
                .map(|n| IpAddr::V4(Ipv4Addr::from(n.to_be())))
        };
        if let Some(ip) = ip {
            out.push(ip);
        }
    }
    out
}

/// Parse the 32-hex-char little-endian-per-word IPv6 form in `/proc/net/tcp6`.
#[cfg(target_os = "linux")]
fn parse_hex_ipv6(hex: &str) -> Option<std::net::Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    // /proc stores four 32-bit words, each little-endian. Decode per word.
    for word in 0..4 {
        let chunk = &hex[word * 8..word * 8 + 8];
        let val = u32::from_str_radix(chunk, 16).ok()?;
        let le = val.to_le_bytes();
        bytes[word * 4..word * 4 + 4].copy_from_slice(&le);
    }
    Some(std::net::Ipv6Addr::from(bytes))
}

// ---------------------------------------------------------------------------
// macOS (+ other unix): shell out to lsof, the universally-present BSD tool.
// ---------------------------------------------------------------------------

#[cfg(all(unix, not(target_os = "linux")))]
fn listening_addrs_for_port(port: u16) -> Vec<IpAddr> {
    use std::process::Command;

    // -nP: no name/port resolution; -iTCP:<port> -sTCP:LISTEN: listening sockets
    // on this port; -Fn: terse, one field ('n' = name/address) per line.
    let output = Command::new("lsof")
        .args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN", "-Fn"])
        .output();
    let Ok(output) = output else {
        return Vec::new();
    };
    if !output.status.success() && output.stdout.is_empty() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&output.stdout);
    parse_lsof_names(&text, port)
}

/// Parse lsof `-Fn` output lines (`n<addr>:<port>` or `n*:<port>`) into bind IPs.
///
/// Pure; unit-tested. lsof prints the bind address in the `n` field, e.g.
/// `n127.0.0.1:11434`, `n*:11434`, `n[::1]:11434`, `n[::]:11434`.
#[cfg(all(unix, not(target_os = "linux")))]
fn parse_lsof_names(text: &str, port: u16) -> Vec<IpAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    let mut out = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix('n') else {
            continue;
        };
        // Split host from the trailing :port. For IPv6 the host is bracketed.
        let (host, port_str) = match rest.rsplit_once(':') {
            Some(parts) => parts,
            None => continue,
        };
        let Ok(parsed_port) = port_str.parse::<u16>() else {
            continue;
        };
        if parsed_port != port {
            continue;
        }
        let host = host.trim();
        let ip = if host == "*" {
            // lsof renders the unspecified address as '*'.
            Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        } else if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            inner.parse::<Ipv6Addr>().ok().map(IpAddr::V6)
        } else {
            host.parse::<IpAddr>().ok()
        };
        if let Some(ip) = ip {
            out.push(ip);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Fallback for any non-unix target: no probe available.
// ---------------------------------------------------------------------------

#[cfg(not(unix))]
fn listening_addrs_for_port(_port: u16) -> Vec<IpAddr> {
    Vec::new()
}

/// Apply the one-click fix: rebind the engine to localhost and/or enable the
/// proxy token front. Journaled like any other system change.
///
/// v0 scope: the *deterministic, reversible* engine rebind is platform- and
/// engine-specific (e.g. an `OLLAMA_HOST=127.0.0.1` env override applied via the
/// engine adoption journal on Linux/systemd). On macOS / Cooperative mode we
/// cannot rewrite another launcher's environment safely, so the fix is to put
/// Saffev's tokened proxy in front of the engine; this is surfaced to the user
/// rather than silently mutating their system. The concrete journaled mutation
/// is owned by `engine::adopt` / `engine::systemd`; this entry point is the
/// stable seam the Studio/CLI call.
pub async fn apply_fix(report: &ExposureReport) -> Result<()> {
    if !report.exposed {
        // Nothing to do — already safe. Idempotent success.
        return Ok(());
    }
    // The actual rebind is a journaled system change owned by the engine layer
    // and only available on platforms that can do it reversibly (Linux/systemd).
    // Until that is wired through, refuse loudly on the control plane rather than
    // pretend we fixed it.
    Err(crate::Error::Unsupported(
        "automated exposure fix is wired through the engine adoption journal \
         (Linux/systemd); on this platform, front the engine with Saffev's \
         tokened proxy or rebind the engine to 127.0.0.1 manually"
            .into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn loopback_is_not_exposed() {
        let r = classify_binding(11434, &Binding::Loopback, false);
        assert!(!r.exposed);
        assert_eq!(r.bound_to.as_deref(), Some("127.0.0.1:11434"));
        assert!(!r.token_protected);
        assert!(r.detail.to_lowercase().contains("localhost"));
    }

    #[test]
    fn wildcard_is_exposed() {
        let r = classify_binding(11434, &Binding::Wildcard, false);
        assert!(r.exposed);
        assert_eq!(r.bound_to.as_deref(), Some("0.0.0.0:11434"));
        assert!(r.detail.contains("ALL network interfaces"));
    }

    #[test]
    fn public_addr_is_exposed() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let r = classify_binding(11434, &Binding::PublicAddr(ip), false);
        assert!(r.exposed);
        assert_eq!(r.bound_to.as_deref(), Some("192.168.1.50:11434"));
    }

    #[test]
    fn not_listening_is_not_exposed() {
        let r = classify_binding(11434, &Binding::NotListening, false);
        assert!(!r.exposed);
        assert!(r.bound_to.is_none());
        assert!(r.detail.contains("No engine"));
    }

    #[test]
    fn unknown_does_not_claim_exposure() {
        // We never cry wolf when we genuinely don't know.
        let r = classify_binding(11434, &Binding::Unknown, false);
        assert!(!r.exposed);
        assert!(r.bound_to.is_none());
    }

    #[test]
    fn token_protected_flag_passes_through() {
        let r = classify_binding(11434, &Binding::Wildcard, true);
        assert!(r.exposed);
        assert!(r.token_protected);
    }

    #[test]
    fn classify_addr_ipv4() {
        assert_eq!(
            classify_addr(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            Binding::Wildcard
        );
        assert_eq!(
            classify_addr(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            Binding::Loopback
        );
        let pub_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(classify_addr(pub_ip), Binding::PublicAddr(pub_ip));
    }

    #[test]
    fn classify_addr_ipv6() {
        assert_eq!(
            classify_addr(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
            Binding::Wildcard
        );
        assert_eq!(
            classify_addr(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            Binding::Loopback
        );
    }

    #[test]
    fn apply_fix_noop_when_safe() {
        let report = ExposureReport {
            exposed: false,
            bound_to: Some("127.0.0.1:11434".into()),
            token_protected: false,
            detail: "safe".into(),
        };
        let res = futures::executor::block_on(apply_fix(&report));
        assert!(res.is_ok());
    }

    #[test]
    fn apply_fix_errors_when_exposed_unsupported_platform() {
        let report = ExposureReport {
            exposed: true,
            bound_to: Some("0.0.0.0:11434".into()),
            token_protected: false,
            detail: "exposed".into(),
        };
        let res = futures::executor::block_on(apply_fix(&report));
        assert!(matches!(res, Err(crate::Error::Unsupported(_))));
    }

    // lsof parser tests (macOS / non-linux unix path).
    #[cfg(all(unix, not(target_os = "linux")))]
    mod lsof {
        use super::super::parse_lsof_names;
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        #[test]
        fn parses_loopback() {
            let out = parse_lsof_names("p57945\ncollama\nf3\nn127.0.0.1:11434\n", 11434);
            assert_eq!(out, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);
        }

        #[test]
        fn parses_wildcard_star() {
            let out = parse_lsof_names("n*:11434\n", 11434);
            assert_eq!(out, vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)]);
        }

        #[test]
        fn parses_ipv6_loopback() {
            let out = parse_lsof_names("n[::1]:11434\n", 11434);
            assert_eq!(out, vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]);
        }

        #[test]
        fn parses_ipv6_wildcard() {
            let out = parse_lsof_names("n[::]:11434\n", 11434);
            assert_eq!(out, vec![IpAddr::V6(Ipv6Addr::UNSPECIFIED)]);
        }

        #[test]
        fn ignores_other_ports() {
            let out = parse_lsof_names("n127.0.0.1:9999\n", 11434);
            assert!(out.is_empty());
        }

        #[test]
        fn ignores_non_n_lines() {
            let out = parse_lsof_names("p1234\ncollama\nf3\n", 11434);
            assert!(out.is_empty());
        }
    }

    // /proc parser tests (Linux path).
    #[cfg(target_os = "linux")]
    mod proc {
        use super::super::parse_hex_ipv6;
        use std::net::Ipv6Addr;

        #[test]
        fn parses_ipv6_loopback_hex() {
            // ::1 in /proc/net/tcp6 little-endian-per-word form.
            let hex = "00000000000000000000000001000000";
            assert_eq!(parse_hex_ipv6(hex), Some(Ipv6Addr::LOCALHOST));
        }

        #[test]
        fn parses_ipv6_unspecified_hex() {
            let hex = "00000000000000000000000000000000";
            assert_eq!(parse_hex_ipv6(hex), Some(Ipv6Addr::UNSPECIFIED));
        }

        #[test]
        fn rejects_bad_length() {
            assert_eq!(parse_hex_ipv6("00"), None);
        }
    }
}
