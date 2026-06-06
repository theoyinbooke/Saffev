//! Engine detection (04 §5.1).
//!
//! Probe known ports (`11434`, `1234`), call identifying endpoints (`/api/tags`
//! for Ollama, `/v1/models` for LM Studio), check for installed binaries
//! (`ollama`, `lms`) and their service/agent definitions.
//!
//! Everything here is best-effort and never panics: a port that does not answer,
//! a binary that is not installed, or a malformed response just yields a
//! `None`/`Unknown`, never an error to the caller's control plane.

use std::time::Duration;

use crate::engine::{EngineInfo, EngineKind, StartMode};
use crate::store::AdoptionState;
use crate::Result;

/// Ports we probe by default (Ollama, LM Studio).
pub const KNOWN_PORTS: &[u16] = &[11434, 1234];

/// How long to wait on an identifying HTTP probe before giving up.
const PROBE_TIMEOUT: Duration = Duration::from_millis(800);

/// Build a short-timeout, loopback-only HTTP client for probing. On-device only:
/// no proxy, no redirect chasing off the local host.
fn probe_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(PROBE_TIMEOUT)
        .connect_timeout(PROBE_TIMEOUT)
        .no_proxy()
        .build()
        .unwrap_or_default()
}

/// Probe one port; return an [`EngineInfo`] if an engine answers.
///
/// We hit the identifying endpoint for whichever engine conventionally owns the
/// port, fall back to the other engine's endpoint, and finally report
/// [`EngineKind::Unknown`] if *something* is listening but is unrecognized.
pub async fn probe_port(port: u16) -> Result<Option<EngineInfo>> {
    // Detection only — adoption decisions happen later, against the store.
    probe_port_as(port, AdoptionState::Detected).await
}

/// Probe the configured upstream the proxy forwards to in Cooperative mode and,
/// if an engine answers there, surface it as a [`EngineInfo`] tagged
/// [`AdoptionState::Cooperative`].
///
/// In Cooperative mode Saffev never adopts the engine, so it has no `engines`
/// row of its own; without this the Studio "Engines" panel renders empty even
/// though the proxy is happily forwarding to a live engine. Probing the
/// upstream lets us show the engine Saffev actually proxies to. Best-effort and
/// loopback-only like the rest of detection: a silent port just yields `None`.
pub async fn probe_upstream(port: u16) -> Result<Option<EngineInfo>> {
    probe_port_as(port, AdoptionState::Cooperative).await
}

/// Probe one port, tagging any engine found with `adoption_state`.
async fn probe_port_as(port: u16, adoption_state: AdoptionState) -> Result<Option<EngineInfo>> {
    let client = probe_client();
    let kind = identify_with(&client, port).await;

    // Nothing listening / unrecognized-and-silent → no engine here.
    let Some(kind) = kind else {
        return Ok(None);
    };

    let version = probe_version(&client, port, kind).await;
    let how_it_starts = start_mode(kind).await.unwrap_or(StartMode::Unknown);

    Ok(Some(EngineInfo {
        engine: kind,
        version,
        port,
        how_it_starts,
        adoption_state,
    }))
}

/// Canonical lowercase engine name for the `engines` table / wire DTOs.
pub fn engine_name(kind: EngineKind) -> &'static str {
    match kind {
        EngineKind::Ollama => "ollama",
        EngineKind::LmStudio => "lmstudio",
        EngineKind::Unknown => "unknown",
    }
}

/// Identify the engine answering on `port` by calling its identifying endpoint.
pub async fn identify(port: u16) -> Result<EngineKind> {
    let client = probe_client();
    Ok(identify_with(&client, port)
        .await
        .unwrap_or(EngineKind::Unknown))
}

/// Identify the engine answering on `port` using a shared client.
///
/// Returns `Some(kind)` if a live HTTP server answers (recognized or not), and
/// `None` if the port is closed / unreachable. The recognized-vs-Unknown split
/// is by which identifying endpoint returns a 2xx with the expected shape.
async fn identify_with(client: &reqwest::Client, port: u16) -> Option<EngineKind> {
    // Order the checks by which engine conventionally owns the port so the happy
    // path is one request, but always try both before concluding "Unknown".
    let ollama_first = port == 11434;

    let ollama = async { is_ollama(client, port).await };
    let lmstudio = async { is_lmstudio(client, port).await };

    if ollama_first {
        if ollama.await {
            return Some(EngineKind::Ollama);
        }
        if lmstudio.await {
            return Some(EngineKind::LmStudio);
        }
    } else {
        if lmstudio.await {
            return Some(EngineKind::LmStudio);
        }
        if ollama.await {
            return Some(EngineKind::Ollama);
        }
    }

    // Something may still be listening but unrecognized; a bare TCP/HTTP touch
    // tells us whether the port is open at all.
    if port_responds(client, port).await {
        Some(EngineKind::Unknown)
    } else {
        None
    }
}

/// Ollama answers `GET /api/tags` with `{"models": [...]}`.
async fn is_ollama(client: &reqwest::Client, port: u16) -> bool {
    let url = format!("http://127.0.0.1:{port}/api/tags");
    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<serde_json::Value>().await {
            Ok(v) => v.get("models").map(|m| m.is_array()).unwrap_or(false),
            Err(_) => false,
        },
        _ => false,
    }
}

/// LM Studio answers `GET /v1/models` with `{"data": [...], "object": "list"}`.
async fn is_lmstudio(client: &reqwest::Client, port: u16) -> bool {
    let url = format!("http://127.0.0.1:{port}/v1/models");
    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<serde_json::Value>().await {
            Ok(v) => v.get("data").map(|d| d.is_array()).unwrap_or(false),
            Err(_) => false,
        },
        _ => false,
    }
}

/// Best-effort "is anything HTTP listening here?" used to mark an open-but-
/// unrecognized port as [`EngineKind::Unknown`] rather than absent.
async fn port_responds(client: &reqwest::Client, port: u16) -> bool {
    let url = format!("http://127.0.0.1:{port}/");
    // Any HTTP response (even 404) means a server is listening.
    client.get(&url).send().await.is_ok()
}

/// Pull a version string for a recognized engine, if it exposes one.
///
/// Ollama exposes `GET /api/version` → `{"version": "0.x.y"}`. LM Studio has no
/// stable version endpoint over HTTP, so we leave it `None`.
async fn probe_version(client: &reqwest::Client, port: u16, kind: EngineKind) -> Option<String> {
    match kind {
        EngineKind::Ollama => {
            let url = format!("http://127.0.0.1:{port}/api/version");
            let resp = client.get(&url).send().await.ok()?;
            if !resp.status().is_success() {
                return None;
            }
            let v: serde_json::Value = resp.json().await.ok()?;
            v.get("version")
                .and_then(|s| s.as_str())
                .map(|s| s.to_string())
        }
        EngineKind::LmStudio | EngineKind::Unknown => None,
    }
}

/// Determine how an engine is started on this host (service vs manual).
///
/// This is intentionally conservative and platform-gated:
/// - Linux: if a systemd unit for the engine exists, report [`StartMode::Systemd`].
/// - macOS: the Ollama menu-bar `.app` runs under launchd; report
///   [`StartMode::Launchd`] when a matching launch agent/daemon is present.
/// - Otherwise, if the engine's CLI binary is on `PATH`, assume it was started
///   manually ([`StartMode::Manual`]); else [`StartMode::Unknown`].
pub async fn start_mode(engine: EngineKind) -> Result<StartMode> {
    Ok(detect_start_mode(engine))
}

#[cfg(target_os = "linux")]
fn detect_start_mode(engine: EngineKind) -> StartMode {
    use std::path::Path;

    let unit = match engine {
        EngineKind::Ollama => "ollama.service",
        // LM Studio / unknown have no canonical systemd unit.
        _ => "",
    };

    if !unit.is_empty() {
        // Common locations for an installed unit file.
        let candidates = [
            format!("/etc/systemd/system/{unit}"),
            format!("/lib/systemd/system/{unit}"),
            format!("/usr/lib/systemd/system/{unit}"),
        ];
        if candidates.iter().any(|p| Path::new(p).exists()) {
            return StartMode::Systemd;
        }
    }

    if binary_on_path(engine) {
        StartMode::Manual
    } else {
        StartMode::Unknown
    }
}

#[cfg(target_os = "macos")]
fn detect_start_mode(engine: EngineKind) -> StartMode {
    use std::path::Path;

    // The Ollama macOS app ships a launchd agent; the .app itself self-relaunches.
    // We treat a present .app or launch agent as Launchd-managed.
    if matches!(engine, EngineKind::Ollama) {
        let app_present = Path::new("/Applications/Ollama.app").exists();
        let home = std::env::var("HOME").unwrap_or_default();
        let agent_present = !home.is_empty()
            && Path::new(&format!("{home}/Library/LaunchAgents")).exists()
            && launch_agent_exists(&home, "ollama");
        if app_present || agent_present {
            return StartMode::Launchd;
        }
    }

    if binary_on_path(engine) {
        StartMode::Manual
    } else {
        StartMode::Unknown
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn detect_start_mode(engine: EngineKind) -> StartMode {
    if binary_on_path(engine) {
        StartMode::Manual
    } else {
        StartMode::Unknown
    }
}

/// Scan `~/Library/LaunchAgents` for a plist whose name hints at the engine.
#[cfg(target_os = "macos")]
fn launch_agent_exists(home: &str, needle: &str) -> bool {
    let dir = format!("{home}/Library/LaunchAgents");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return false;
    };
    for entry in entries.flatten() {
        if let Some(name) = entry.file_name().to_str() {
            if name.to_ascii_lowercase().contains(needle) {
                return true;
            }
        }
    }
    false
}

/// Is the engine's CLI binary discoverable on `PATH`?
fn binary_on_path(engine: EngineKind) -> bool {
    let bin = match engine {
        EngineKind::Ollama => "ollama",
        EngineKind::LmStudio => "lms",
        EngineKind::Unknown => return false,
    };
    which_on_path(bin)
}

/// Minimal `which`: walk `PATH` entries and check for an executable file. Avoids
/// pulling in a dependency just to find a binary.
fn which_on_path(bin: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return true;
        }
        // On non-Windows the binary has no extension; this is enough.
    }
    false
}

/// Full detection sweep across [`KNOWN_PORTS`].
///
/// Probes every known port concurrently and returns one [`EngineInfo`] per live
/// engine. Best-effort: ports that don't answer are simply omitted.
pub async fn detect_all() -> Result<Vec<EngineInfo>> {
    let futures = KNOWN_PORTS.iter().map(|&port| probe_port(port));
    let results = futures::future::join_all(futures).await;

    let mut engines = Vec::new();
    for r in results {
        if let Ok(Some(info)) = r {
            engines.push(info);
        }
    }
    Ok(engines)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_ports_cover_ollama_and_lmstudio() {
        assert!(KNOWN_PORTS.contains(&11434), "Ollama port must be probed");
        assert!(KNOWN_PORTS.contains(&1234), "LM Studio port must be probed");
    }

    #[test]
    fn binary_on_path_unknown_is_false() {
        assert!(!binary_on_path(EngineKind::Unknown));
    }

    #[test]
    fn which_on_path_finds_sh() {
        // `sh` is on PATH on every unix host this targets.
        #[cfg(unix)]
        assert!(which_on_path("sh"));
    }

    #[test]
    fn which_on_path_rejects_nonsense() {
        assert!(!which_on_path("definitely-not-a-real-binary-zzz-9f3a"));
    }

    #[tokio::test]
    async fn probe_dead_port_returns_none() {
        // Port 1 is privileged and nothing is listening in tests → None, not Err.
        let res = probe_port(1).await;
        assert!(res.is_ok());
        assert!(res.unwrap().is_none());
    }

    #[tokio::test]
    async fn probe_upstream_dead_port_returns_none() {
        // No engine on a dead upstream → fail-soft None, never an error.
        let res = probe_upstream(1).await;
        assert!(res.is_ok());
        assert!(res.unwrap().is_none());
    }

    #[tokio::test]
    async fn probe_upstream_against_live_engine_tags_cooperative() {
        // Spin up a tiny loopback HTTP server that answers Ollama's identifying
        // and version endpoints, then assert that probing it as the upstream
        // surfaces an engine on that exact port, tagged Cooperative.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Serve a couple of requests (identify, then version) for one probe.
        tokio::spawn(async move {
            for _ in 0..4 {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let mut buf = [0u8; 1024];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let body = if req.contains("/api/version") {
                    "{\"version\":\"9.9.9\"}"
                } else {
                    // /api/tags identifying response.
                    "{\"models\":[]}"
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.flush().await;
            }
        });

        let info = probe_upstream(port)
            .await
            .expect("probe must not error")
            .expect("a live engine must be detected on the upstream port");

        assert_eq!(info.port, port, "detection must include the upstream port");
        assert_eq!(info.engine, EngineKind::Ollama);
        assert_eq!(info.adoption_state, AdoptionState::Cooperative);
    }

    #[tokio::test]
    async fn start_mode_never_errors() {
        for k in [
            EngineKind::Ollama,
            EngineKind::LmStudio,
            EngineKind::Unknown,
        ] {
            assert!(start_mode(k).await.is_ok());
        }
    }

    #[test]
    fn ollama_tags_shape_is_recognized() {
        // Document the contract is_ollama checks: a "models" array.
        let v: serde_json::Value = serde_json::json!({ "models": [] });
        assert!(v.get("models").map(|m| m.is_array()).unwrap_or(false));
    }

    #[test]
    fn lmstudio_models_shape_is_recognized() {
        let v: serde_json::Value = serde_json::json!({ "object": "list", "data": [] });
        assert!(v.get("data").map(|d| d.is_array()).unwrap_or(false));
    }
}
