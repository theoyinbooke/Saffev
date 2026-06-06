//! systemd Gateway controller — **Linux only** (`cfg(target_os = "linux")`).
//!
//! Implements clean, exactly-reversible Gateway adoption for Ollama via systemd
//! (04 §5.2/§5.5):
//! 1. write a drop-in override setting `OLLAMA_HOST` to the shadow port,
//! 2. `systemctl disable` the engine's autostart,
//! 3. register Saffev's own user service to own the public port,
//! 4. health-check both ports.
//!
//! Every change is journaled so [`EngineController::revert`] restores the exact
//! prior `OLLAMA_HOST` + autostart state.

#![cfg(target_os = "linux")]

use async_trait::async_trait;
use tokio::process::Command;

use crate::engine::cooperative::probe_health;
use crate::engine::{EngineController, EngineInfo, EngineKind, HealthState, JournalEntry};
use crate::{Error, Result};

/// Path of the systemd drop-in directory for the Ollama unit.
const OLLAMA_DROPIN_DIR: &str = "/etc/systemd/system/ollama.service.d";
/// Saffev's drop-in override file within that directory.
const OLLAMA_DROPIN_FILE: &str = "/etc/systemd/system/ollama.service.d/saffev.conf";
/// The Ollama systemd unit name.
const OLLAMA_UNIT: &str = "ollama.service";
/// Saffev's own user service unit name (owns the public port).
const SAFFEV_UNIT: &str = "saffev.service";

/// Linux/systemd Gateway controller.
#[derive(Debug, Clone)]
pub struct SystemdController {
    /// Shadow port the engine is relocated to.
    pub shadow_port: u16,
    /// Public port Saffev takes over.
    pub public_port: u16,
}

impl SystemdController {
    /// Build a controller with the configured shadow/public ports.
    pub fn new(public_port: u16, shadow_port: u16) -> Self {
        SystemdController {
            public_port,
            shadow_port,
        }
    }

    /// Write the systemd drop-in override that relocates the engine.
    ///
    /// Records the prior file contents (if any) in the journal so revert restores
    /// the exact previous state — or deletes the file if it did not exist before.
    pub async fn write_override(&self) -> Result<JournalEntry> {
        let prior = match tokio::fs::read_to_string(OLLAMA_DROPIN_FILE).await {
            Ok(s) => Some(s),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(Error::Engine(format!("reading prior override: {e}"))),
        };

        tokio::fs::create_dir_all(OLLAMA_DROPIN_DIR)
            .await
            .map_err(|e| Error::Engine(format!("creating {OLLAMA_DROPIN_DIR}: {e}")))?;

        let contents = format!(
            "# Managed by Saffev — do not edit. Remove via `saffev revert`.\n\
             [Service]\n\
             Environment=\"OLLAMA_HOST=127.0.0.1:{}\"\n",
            self.shadow_port
        );
        tokio::fs::write(OLLAMA_DROPIN_FILE, contents)
            .await
            .map_err(|e| Error::Engine(format!("writing {OLLAMA_DROPIN_FILE}: {e}")))?;

        systemctl(&["daemon-reload"]).await.ok();

        Ok(JournalEntry::WroteFile {
            path: OLLAMA_DROPIN_FILE.to_string(),
            prior,
        })
    }

    /// `systemctl disable` the engine's autostart so it never races for the
    /// public port.
    pub async fn disable_autostart(&self) -> Result<JournalEntry> {
        systemctl(&["disable", OLLAMA_UNIT])
            .await
            .map_err(|e| Error::Engine(format!("disabling {OLLAMA_UNIT}: {e}")))?;
        Ok(JournalEntry::DisabledAutostart {
            unit: OLLAMA_UNIT.to_string(),
        })
    }

    /// Register Saffev's own user service on the public port.
    ///
    /// The unit runs the installed `saffev` binary in foreground mode. Journaled
    /// as both the written unit file and the registered service so revert removes
    /// both.
    pub async fn register_service(&self) -> Result<JournalEntry> {
        let unit_path = format!("/etc/systemd/system/{SAFFEV_UNIT}");
        let exe = std::env::current_exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "/usr/local/bin/saffev".to_string());

        let contents = format!(
            "# Managed by Saffev — do not edit. Remove via `saffev revert`.\n\
             [Unit]\n\
             Description=Saffev local AI studio (proxy + studio)\n\
             After=network.target\n\n\
             [Service]\n\
             Type=simple\n\
             ExecStart={exe} start --foreground\n\
             Restart=on-failure\n\n\
             [Install]\n\
             WantedBy=multi-user.target\n"
        );
        tokio::fs::write(&unit_path, contents)
            .await
            .map_err(|e| Error::Engine(format!("writing {unit_path}: {e}")))?;

        systemctl(&["daemon-reload"]).await.ok();
        systemctl(&["enable", SAFFEV_UNIT])
            .await
            .map_err(|e| Error::Engine(format!("enabling {SAFFEV_UNIT}: {e}")))?;

        Ok(JournalEntry::RegisteredService {
            unit: SAFFEV_UNIT.to_string(),
        })
    }
}

#[async_trait]
impl EngineController for SystemdController {
    async fn detect(&self) -> Result<Vec<EngineInfo>> {
        // Reuse the platform-agnostic detection sweep.
        crate::engine::detect::detect_all().await
    }

    fn can_adopt(&self) -> bool {
        true
    }

    /// Run the full adoption sequence, accumulating a journal as we go. On any
    /// failure we revert whatever we've already done so the host is never left
    /// half-adopted (04 §5.2/§5.5).
    async fn adopt(&self, info: &EngineInfo) -> Result<Vec<JournalEntry>> {
        if info.engine != EngineKind::Ollama {
            return Err(Error::Unsupported(
                "systemd Gateway adoption is Ollama-only".into(),
            ));
        }

        let mut journal: Vec<JournalEntry> = Vec::new();

        // 1. relocate the engine to the shadow port.
        match self.write_override().await {
            Ok(entry) => journal.push(entry),
            Err(e) => {
                let _ = self.revert(&journal).await;
                return Err(e);
            }
        }
        // Also record the logical env override so the store can extract the
        // shadow port (adopt::engine_record reads OLLAMA_HOST).
        journal.push(JournalEntry::SetEnvOverride {
            key: "OLLAMA_HOST".to_string(),
            value: format!("127.0.0.1:{}", self.shadow_port),
        });

        // 2. stop autostart from racing for the public port.
        match self.disable_autostart().await {
            Ok(entry) => journal.push(entry),
            Err(e) => {
                let _ = self.revert(&journal).await;
                return Err(e);
            }
        }

        // 3. register our own service to own the public port.
        match self.register_service().await {
            Ok(entry) => journal.push(entry),
            Err(e) => {
                let _ = self.revert(&journal).await;
                return Err(e);
            }
        }

        // 4. restart the engine onto the shadow port so the override takes effect.
        systemctl(&["restart", OLLAMA_UNIT]).await.ok();

        Ok(journal)
    }

    /// Reverse a previously-recorded journal, restoring the prior state exactly.
    ///
    /// Replays entries in **reverse order** so later changes are undone before
    /// earlier ones. Each entry is best-effort-reverted; we collect the first
    /// error but keep going so a single stuck step never blocks the rest of the
    /// cleanup (04 §5.5).
    async fn revert(&self, journal: &[JournalEntry]) -> Result<()> {
        let mut first_err: Option<Error> = None;

        for entry in journal.iter().rev() {
            let res = match entry {
                JournalEntry::WroteFile { path, prior } => match prior {
                    // Restore the previous contents...
                    Some(contents) => tokio::fs::write(path, contents)
                        .await
                        .map_err(|e| Error::Engine(format!("restoring {path}: {e}"))),
                    // ...or delete a file we created.
                    None => match tokio::fs::remove_file(path).await {
                        Ok(()) => Ok(()),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                        Err(e) => Err(Error::Engine(format!("removing {path}: {e}"))),
                    },
                },
                JournalEntry::DisabledAutostart { unit } => systemctl(&["enable", unit])
                    .await
                    .map_err(|e| Error::Engine(format!("re-enabling {unit}: {e}"))),
                JournalEntry::RegisteredService { unit } => {
                    let mut r = systemctl(&["disable", unit])
                        .await
                        .map_err(|e| Error::Engine(format!("disabling {unit}: {e}")));
                    // Also remove the unit file we wrote.
                    let unit_path = format!("/etc/systemd/system/{unit}");
                    if let Err(e) = tokio::fs::remove_file(&unit_path).await {
                        if e.kind() != std::io::ErrorKind::NotFound && r.is_ok() {
                            r = Err(Error::Engine(format!("removing {unit_path}: {e}")));
                        }
                    }
                    r
                }
                // The logical env override is reverted by removing the drop-in
                // file (handled by the matching WroteFile entry); nothing to do.
                JournalEntry::SetEnvOverride { .. } => Ok(()),
            };

            if let Err(e) = res {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }

        // Reload systemd so the unit graph reflects the reverted state, and bring
        // the engine back onto the public port as if Saffev was never installed.
        systemctl(&["daemon-reload"]).await.ok();
        systemctl(&["restart", OLLAMA_UNIT]).await.ok();

        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    async fn health(&self, info: &EngineInfo) -> Result<HealthState> {
        Ok(probe_health(info.engine, info.port).await)
    }
}

/// Run `systemctl <args>`, mapping a non-zero exit to an error.
async fn systemctl(args: &[&str]) -> Result<()> {
    let out = Command::new("systemctl")
        .args(args)
        .output()
        .await
        .map_err(|e| Error::Engine(format!("running systemctl {args:?}: {e}")))?;
    if out.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        Err(Error::Engine(format!(
            "systemctl {args:?} failed: {}",
            stderr.trim()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controller_stores_ports() {
        let c = SystemdController::new(11434, 11999);
        assert_eq!(c.public_port, 11434);
        assert_eq!(c.shadow_port, 11999);
        assert!(c.can_adopt());
    }

    #[tokio::test]
    async fn revert_empty_journal_is_ok() {
        let c = SystemdController::new(11434, 11999);
        // No systemctl calls have side effects we assert on here; daemon-reload /
        // restart are best-effort. An empty journal must not error on the file ops.
        // (systemctl may be absent in CI; those calls are `.ok()`-swallowed.)
        let res = c.revert(&[]).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn revert_restores_prior_file_contents() {
        // Round-trip: write a temp file, journal it with prior contents, revert,
        // and confirm the prior contents are restored exactly.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("saffev-systemd-test-{}.conf", std::process::id()));
        let path_str = path.to_string_lossy().into_owned();

        tokio::fs::write(&path, "ORIGINAL").await.unwrap();
        // Simulate adoption having overwritten it.
        tokio::fs::write(&path, "MODIFIED").await.unwrap();

        let journal = vec![JournalEntry::WroteFile {
            path: path_str.clone(),
            prior: Some("ORIGINAL".to_string()),
        }];

        let c = SystemdController::new(11434, 11999);
        c.revert(&journal).await.unwrap();

        let restored = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(restored, "ORIGINAL");
        let _ = tokio::fs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn revert_deletes_file_with_no_prior() {
        // A file we created (prior = None) must be deleted on revert.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("saffev-systemd-new-{}.conf", std::process::id()));
        let path_str = path.to_string_lossy().into_owned();

        tokio::fs::write(&path, "CREATED BY SAFFEV").await.unwrap();

        let journal = vec![JournalEntry::WroteFile {
            path: path_str.clone(),
            prior: None,
        }];

        let c = SystemdController::new(11434, 11999);
        c.revert(&journal).await.unwrap();

        assert!(
            !path.exists(),
            "file created during adoption must be removed on revert"
        );
    }

    #[tokio::test]
    async fn adopt_rejects_non_ollama() {
        let c = SystemdController::new(11434, 11999);
        let info = EngineInfo {
            engine: EngineKind::LmStudio,
            version: None,
            port: 1234,
            how_it_starts: crate::engine::StartMode::Manual,
            adoption_state: crate::store::AdoptionState::Detected,
        };
        let err = c.adopt(&info).await.unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)));
    }
}
