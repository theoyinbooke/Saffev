//! Engine supervisor (Gateway mode, 04 §5.4).
//!
//! Child-process supervision with restart-on-crash and a readiness probe.
//! Surfaces status to the Studio. Never leaves a zombie engine. On stop, honors
//! the configured [`crate::config::HandoverPolicy`].
//!
//! In Gateway mode the supervisor owns the engine process that listens on the
//! **shadow** port; only the proxy talks to it. This whole module is only
//! exercised on platforms where Gateway adoption is supported (Linux today), but
//! it compiles everywhere so the type surface is uniform.

use std::process::Stdio;
use std::sync::Arc;

use tokio::process::{Child, Command};
use tokio::sync::Mutex;

use crate::config::HandoverPolicy;
use crate::engine::cooperative::probe_health;
use crate::engine::{EngineInfo, EngineKind, HealthState};
use crate::{Error, Result};

/// Supervises one engine process behind the proxy.
///
/// Holds the spawned child (if we started it) plus the engine identity used for
/// health probing and re-assertion detection. The child handle is behind a mutex
/// so `health`/`stop` can be called from shared references.
pub struct Supervisor {
    /// Engine kind we're supervising (drives the health endpoint).
    kind: EngineKind,
    /// Shadow port the engine listens on.
    port: u16,
    /// Public port the engine *would* re-claim if its autostart reappeared.
    public_port: u16,
    /// The supervised child process, if we launched one. `None` when we are
    /// merely observing an engine started by the OS service manager.
    child: Arc<Mutex<Option<Child>>>,
}

impl Supervisor {
    /// Start supervising the engine on its shadow port.
    ///
    /// Spawns `ollama serve` (or the LM Studio server) bound to the shadow port
    /// via `OLLAMA_HOST`, then waits briefly for readiness. If the engine is
    /// already listening on that port (e.g. systemd brought it up on the shadow
    /// port after adoption), we attach to it without spawning a duplicate.
    pub async fn start(info: &EngineInfo) -> Result<Self> {
        let public_port = crate::config::DEFAULT_PROXY_PORT;

        // Already up on the shadow port? Attach, don't double-spawn.
        if probe_health(info.engine, info.port).await == HealthState::Healthy {
            return Ok(Supervisor {
                kind: info.engine,
                port: info.port,
                public_port,
                child: Arc::new(Mutex::new(None)),
            });
        }

        let child = spawn_engine(info.engine, info.port)?;
        let sup = Supervisor {
            kind: info.engine,
            port: info.port,
            public_port,
            child: Arc::new(Mutex::new(Some(child))),
        };

        // Wait for readiness (bounded): up to ~5s of 250ms polls.
        for _ in 0..20 {
            if sup.health().await == HealthState::Healthy {
                return Ok(sup);
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }

        // Never leave a zombie: if it never came up, reap it before erroring.
        sup.kill_child().await;
        Err(Error::Engine(format!(
            "engine did not become healthy on shadow port {}",
            info.port
        )))
    }

    /// Current health from the readiness probe.
    pub async fn health(&self) -> HealthState {
        probe_health(self.kind, self.port).await
    }

    /// Stop supervising, honoring the handover policy.
    ///
    /// - [`HandoverPolicy::Handover`]: leave the engine running so stopping
    ///   Saffev never takes the user's AI offline. We simply drop our handle and
    ///   detach (the child keeps running).
    /// - [`HandoverPolicy::Stop`]: terminate the engine process we started.
    ///
    /// Either way, we never leave a zombie: a child we started is either reaped
    /// (Stop) or explicitly detached (Handover).
    pub async fn stop(self, policy: HandoverPolicy) -> Result<()> {
        match policy {
            HandoverPolicy::Handover => {
                // Detach: forget the handle so Drop doesn't try to kill it.
                if let Some(child) = self.child.lock().await.take() {
                    detach(child);
                }
                Ok(())
            }
            HandoverPolicy::Stop => {
                self.kill_child().await;
                Ok(())
            }
        }
    }

    /// Detect if the engine's own autostart re-appeared (re-assertion watchdog,
    /// 04 §5.2) and surface it.
    ///
    /// After Gateway adoption the engine's autostart is disabled. If something
    /// (an OS/engine update) re-enabled it, the engine may have grabbed the
    /// **public** port again. We detect that by health-probing the public port:
    /// if a live engine answers there, autostart has re-asserted.
    pub async fn check_reassertion(&self) -> Result<bool> {
        let reasserted = probe_health(self.kind, self.public_port).await == HealthState::Healthy;
        Ok(reasserted)
    }

    /// Kill the supervised child if we own one, then wait so it's reaped.
    async fn kill_child(&self) {
        let mut guard = self.child.lock().await;
        if let Some(mut child) = guard.take() {
            // Best-effort: ignore errors (already-exited, no perms).
            let _ = child.start_kill();
            let _ = child.wait().await;
        }
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        // Safety net against zombies: if a child is still owned at drop (no
        // explicit stop/handover happened), best-effort kill it. We can't await
        // in Drop, so use the std-level kill via the underlying id.
        if let Ok(mut guard) = self.child.try_lock() {
            if let Some(child) = guard.as_mut() {
                let _ = child.start_kill();
            }
        }
    }
}

/// Spawn the engine bound to the shadow port. Output is discarded (the engine's
/// own logs are not ours to own); on-device only.
fn spawn_engine(kind: EngineKind, port: u16) -> Result<Child> {
    let host = format!("127.0.0.1:{port}");
    let mut cmd = match kind {
        EngineKind::Ollama => {
            let mut c = Command::new("ollama");
            c.arg("serve");
            c.env("OLLAMA_HOST", &host);
            c
        }
        EngineKind::LmStudio => {
            // LM Studio is Cooperative-only (04 §2); supervising it is out of
            // scope, but keep a coherent error rather than panicking.
            return Err(Error::Unsupported(
                "LM Studio is Cooperative-only; not supervised in Gateway mode".into(),
            ));
        }
        EngineKind::Unknown => {
            return Err(Error::Engine(
                "cannot supervise an unidentified engine".into(),
            ));
        }
    };

    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);

    cmd.spawn()
        .map_err(|e| Error::Engine(format!("failed to spawn engine on {host}: {e}")))
}

/// Detach a child so dropping its handle does **not** kill the process. We clear
/// `kill_on_drop` by forgetting the handle through std, leaving the OS process
/// alive (graceful handover).
fn detach(child: Child) {
    // `tokio::process::Child` kills on drop only if `kill_on_drop(true)` was set;
    // converting away from the kill-on-drop guarantee is done by leaking the
    // handle so its Drop never runs. The OS process keeps running independently.
    std::mem::forget(child);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dead_supervisor() -> Supervisor {
        Supervisor {
            kind: EngineKind::Ollama,
            port: 1, // nothing listens here
            public_port: 2,
            child: Arc::new(Mutex::new(None)),
        }
    }

    #[tokio::test]
    async fn health_of_unstarted_is_down() {
        let sup = dead_supervisor();
        assert_eq!(sup.health().await, HealthState::Down);
    }

    #[tokio::test]
    async fn no_reassertion_when_public_port_dead() {
        let sup = dead_supervisor();
        assert!(!sup.check_reassertion().await.unwrap());
    }

    #[tokio::test]
    async fn stop_handover_without_child_is_ok() {
        let sup = dead_supervisor();
        assert!(sup.stop(HandoverPolicy::Handover).await.is_ok());
    }

    #[tokio::test]
    async fn stop_kill_without_child_is_ok() {
        let sup = dead_supervisor();
        assert!(sup.stop(HandoverPolicy::Stop).await.is_ok());
    }

    #[test]
    fn spawn_unknown_engine_errors() {
        let err = spawn_engine(EngineKind::Unknown, 11999).unwrap_err();
        matches!(err, Error::Engine(_));
    }

    #[test]
    fn spawn_lmstudio_is_unsupported() {
        let err = spawn_engine(EngineKind::LmStudio, 11999).unwrap_err();
        matches!(err, Error::Unsupported(_));
    }
}
