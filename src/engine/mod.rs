//! Engine interception layer — the only per-OS code in the crate.
//!
//! One trait, [`EngineController`], with:
//! - a Linux systemd Gateway impl (`cfg(target_os = "linux")`), and
//! - a Cooperative impl that compiles and runs everywhere (the macOS default,
//!   and the universal fallback).
//!
//! Detection, adoption, supervision, and reversible revert. Every system change
//! is journaled (into the `engines` table) so revert can replay it in reverse.

pub mod adopt;
pub mod cooperative;
pub mod detect;
pub mod supervise;

#[cfg(target_os = "linux")]
pub mod systemd;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::store::AdoptionState;
use crate::Result;

/// A detected engine and how it runs (04 §5.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineInfo {
    /// Engine kind.
    pub engine: EngineKind,
    /// Version string, if probed.
    pub version: Option<String>,
    /// Port it currently listens on.
    pub port: u16,
    /// How it starts (service vs manual).
    pub how_it_starts: StartMode,
    /// Current adoption state.
    pub adoption_state: AdoptionState,
}

/// Supported engine kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EngineKind {
    /// Ollama (lead target).
    Ollama,
    /// LM Studio (Cooperative only, v2+).
    LmStudio,
    /// An unidentified engine answering on a known port.
    Unknown,
}

/// How an engine is started on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartMode {
    /// systemd service (Linux).
    Systemd,
    /// launchd agent (macOS menu-bar `.app`).
    Launchd,
    /// Started manually / by a shell (Homebrew CLI, `ollama serve`).
    Manual,
    /// Unknown.
    Unknown,
}

/// A single reversible system change, journaled for revert (04 §5.2/§5.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum JournalEntry {
    /// A file was written; revert deletes it (restoring `prior` if present).
    WroteFile {
        /// Path written.
        path: String,
        /// Prior contents to restore on revert, if the file existed.
        prior: Option<String>,
    },
    /// A service was disabled; revert re-enables it.
    DisabledAutostart {
        /// Service/unit name.
        unit: String,
    },
    /// A service was registered; revert removes it.
    RegisteredService {
        /// Service/unit name.
        unit: String,
    },
    /// An environment override was applied; revert removes it.
    SetEnvOverride {
        /// Variable name.
        key: String,
        /// Value set.
        value: String,
    },
}

/// Result of the supervisor health/readiness probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthState {
    /// Responding on its port.
    Healthy,
    /// Not yet ready / starting.
    Starting,
    /// Not responding.
    Down,
}

/// Per-OS interception strategy. The Cooperative impl works everywhere; the
/// systemd impl is Linux-only Gateway adoption.
#[async_trait]
pub trait EngineController: Send + Sync {
    /// Detect engines on this host (ports, binaries, services).
    async fn detect(&self) -> Result<Vec<EngineInfo>>;

    /// Whether this controller can perform Gateway adoption here.
    fn can_adopt(&self) -> bool;

    /// Perform adoption, returning the journal of changes made. Cooperative
    /// returns an empty journal (no system changes).
    async fn adopt(&self, info: &EngineInfo) -> Result<Vec<JournalEntry>>;

    /// Reverse a previously-recorded journal, restoring the prior state exactly.
    async fn revert(&self, journal: &[JournalEntry]) -> Result<()>;

    /// Probe engine health on its (shadow or real) port.
    async fn health(&self, info: &EngineInfo) -> Result<HealthState>;
}

/// Pick the right controller for this host: Cooperative everywhere; the systemd
/// controller is offered on Linux in Gateway mode. Returns a boxed trait object.
///
/// Selection rules (04 §2/§5):
/// - **Linux + `Mode::Gateway`** → the systemd controller (exactly-reversible
///   adoption of Ollama).
/// - **everything else** (any OS in Cooperative mode; macOS always; non-Linux)
///   → [`cooperative::CooperativeController`], the universal fallback.
pub fn default_controller(config: &crate::config::Config) -> Box<dyn EngineController> {
    #[cfg(target_os = "linux")]
    {
        if config.mode == crate::config::Mode::Gateway {
            return Box::new(systemd::SystemdController::new(
                config.ports.proxy,
                config.ports.shadow,
            ));
        }
    }

    // Cooperative is the macOS default and the universal fallback. The `config`
    // binding is otherwise only consumed on Linux/Gateway above.
    let _ = config;
    Box::new(cooperative::CooperativeController)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn default_controller_is_cooperative_in_cooperative_mode() {
        let mut cfg = Config::default();
        cfg.mode = crate::config::Mode::Cooperative;
        let ctrl = default_controller(&cfg);
        // Cooperative never adopts.
        assert!(!ctrl.can_adopt());
    }

    #[test]
    fn journal_entry_serde_round_trip() {
        // The journal is what revert replays; its serde shape is load-bearing.
        let entries = vec![
            JournalEntry::WroteFile {
                path: "/x".into(),
                prior: Some("old".into()),
            },
            JournalEntry::DisabledAutostart {
                unit: "ollama.service".into(),
            },
            JournalEntry::RegisteredService {
                unit: "saffev.service".into(),
            },
            JournalEntry::SetEnvOverride {
                key: "OLLAMA_HOST".into(),
                value: "127.0.0.1:11999".into(),
            },
        ];
        let json = serde_json::to_string(&entries).unwrap();
        // Tag is `op`, snake_case variants.
        assert!(json.contains("\"op\":\"wrote_file\""));
        assert!(json.contains("\"op\":\"disabled_autostart\""));
        assert!(json.contains("\"op\":\"registered_service\""));
        assert!(json.contains("\"op\":\"set_env_override\""));
        let back: Vec<JournalEntry> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 4);
    }
}
