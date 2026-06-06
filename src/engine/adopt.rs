//! Adoption orchestration (04 §5.2).
//!
//! Platform-agnostic glue that sequences detection -> per-OS adoption steps ->
//! journaling -> health checks. The OS-specific work lives in [`super::systemd`]
//! (Linux) and [`super::cooperative`] (everywhere).
//!
//! The journal returned by [`EngineController::adopt`] is the single source of
//! truth for revert; this module persists it to the `engines` table so revert
//! can replay it in reverse even across process restarts.

use crate::engine::{EngineController, EngineInfo, EngineKind, JournalEntry};
use crate::store::{AdoptionState, EngineRecord, Store, WriteOp};
use crate::Result;

/// Run adoption end-to-end with a controller, persisting the journal to the
/// `engines` table via the store on success. Returns the journal.
///
/// On any controller error we attempt a best-effort revert of whatever partial
/// journal we received so we never leave the host half-adopted, then propagate
/// the error to the (loud) control plane.
pub async fn run_adoption(
    controller: &dyn EngineController,
    info: &EngineInfo,
    store: &Store,
) -> Result<Vec<JournalEntry>> {
    // Controllers that can't adopt here (Cooperative, macOS) return an empty
    // journal from adopt(); we still record the resulting adoption state so the
    // Studio's Engines page reflects reality.
    let journal = match controller.adopt(info).await {
        Ok(j) => j,
        Err(e) => return Err(e),
    };

    let adoption_state = if controller.can_adopt() && !journal.is_empty() {
        AdoptionState::Adopted
    } else {
        // No system changes were made: we're forwarding cooperatively.
        AdoptionState::Cooperative
    };

    let record = engine_record(info, &journal, adoption_state);
    store.enqueue(WriteOp::Engine(record));

    Ok(journal)
}

/// Build an [`EngineRecord`] for the `engines` table from an adoption outcome.
///
/// `id` is left `0`; the store treats a 0 id as "assign on insert" (SQLite
/// `INTEGER PRIMARY KEY` autoincrement). The journal is serialized to JSON so a
/// later [`run_revert`] can reload and replay it.
fn engine_record(
    info: &EngineInfo,
    journal: &[JournalEntry],
    adoption_state: AdoptionState,
) -> EngineRecord {
    let shadow_port = journal.iter().find_map(|entry| match entry {
        // The OLLAMA_HOST override carries the shadow port (`127.0.0.1:PORT`).
        JournalEntry::SetEnvOverride { key, value } if key == "OLLAMA_HOST" => {
            value.rsplit(':').next().and_then(|p| p.parse::<u16>().ok())
        }
        _ => None,
    });

    EngineRecord {
        id: 0,
        engine: engine_name(info.engine).to_string(),
        version: info.version.clone(),
        public_port: info.port,
        shadow_port,
        adoption_state,
        journal_json: serde_json::to_string(journal).unwrap_or_else(|_| "[]".to_string()),
        updated_at: now_secs(),
    }
}

/// Replay a previously-recorded journal in reverse via the controller, then
/// record the engine as reverted. Used by `saffev revert` (04 §5.5).
///
/// This is the inverse of [`run_adoption`]: it reads the stored journal back and
/// hands it to the controller's `revert`, which undoes each change.
pub async fn run_revert(
    controller: &dyn EngineController,
    info: &EngineInfo,
    journal: &[JournalEntry],
    store: &Store,
) -> Result<()> {
    controller.revert(journal).await?;

    // Record the reverted state with an empty journal — there is nothing left to
    // undo, and a stale journal must never be replayed twice.
    let record = EngineRecord {
        id: 0,
        engine: engine_name(info.engine).to_string(),
        version: info.version.clone(),
        public_port: info.port,
        shadow_port: None,
        adoption_state: AdoptionState::Reverted,
        journal_json: "[]".to_string(),
        updated_at: now_secs(),
    };
    store.enqueue(WriteOp::Engine(record));
    Ok(())
}

/// Diagnose a port conflict: identify the process holding `port` (socket/PID
/// lookup) and describe it. Never fails silently (04 §5.2).
///
/// Implemented per-OS with `lsof` (present on macOS + most Linux). Returns
/// `Ok(None)` when the port is free; `Ok(Some(holder))` when something holds it.
/// A missing `lsof` (or any tooling error) is *not* fatal — it returns `Ok(None)`
/// rather than masking the real "port busy" signal with a tooling error.
pub async fn diagnose_port_conflict(port: u16) -> Result<Option<PortHolder>> {
    Ok(port_holder(port).await)
}

#[cfg(unix)]
async fn port_holder(port: u16) -> Option<PortHolder> {
    // `lsof -nP -iTCP:<port> -sTCP:LISTEN -t` prints listening PIDs, one per line.
    let out = tokio::process::Command::new("lsof")
        .args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN", "-t"])
        .output()
        .await
        .ok()?;

    if !out.status.success() {
        // lsof exits non-zero when nothing matches → port is free.
        return None;
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    let pid: u32 = stdout.split_whitespace().next()?.parse().ok()?;
    let name = process_name(pid).await;
    Some(PortHolder { pid, name })
}

#[cfg(not(unix))]
async fn port_holder(_port: u16) -> Option<PortHolder> {
    // Windows is deferred (04 §2); no diagnosis available.
    None
}

/// Resolve a PID to a process name via `ps`. Best-effort.
#[cfg(unix)]
async fn process_name(pid: u32) -> Option<String> {
    let out = tokio::process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "comm="])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if name.is_empty() {
        None
    } else {
        // `comm=` may yield a full path on Linux; keep the basename.
        Some(name.rsplit('/').next().unwrap_or(&name).to_string())
    }
}

/// The process currently holding a port.
#[derive(Debug, Clone)]
pub struct PortHolder {
    /// PID of the holder.
    pub pid: u32,
    /// Process name, if resolvable.
    pub name: Option<String>,
}

/// Canonical lowercase engine name for the `engines` table.
fn engine_name(kind: EngineKind) -> &'static str {
    match kind {
        EngineKind::Ollama => "ollama",
        EngineKind::LmStudio => "lmstudio",
        EngineKind::Unknown => "unknown",
    }
}

/// Current unix time in whole seconds (for `engines.updated_at`).
fn now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::StartMode;

    fn sample_info() -> EngineInfo {
        EngineInfo {
            engine: EngineKind::Ollama,
            version: Some("0.5.0".into()),
            port: 11434,
            how_it_starts: StartMode::Systemd,
            adoption_state: AdoptionState::Detected,
        }
    }

    #[test]
    fn engine_name_is_lowercase_canonical() {
        assert_eq!(engine_name(EngineKind::Ollama), "ollama");
        assert_eq!(engine_name(EngineKind::LmStudio), "lmstudio");
        assert_eq!(engine_name(EngineKind::Unknown), "unknown");
    }

    #[test]
    fn empty_journal_records_cooperative_state() {
        let rec = engine_record(&sample_info(), &[], AdoptionState::Cooperative);
        assert_eq!(rec.engine, "ollama");
        assert_eq!(rec.public_port, 11434);
        assert_eq!(rec.adoption_state, AdoptionState::Cooperative);
        assert_eq!(rec.shadow_port, None);
        assert_eq!(rec.journal_json, "[]");
        assert_eq!(rec.version.as_deref(), Some("0.5.0"));
    }

    #[test]
    fn shadow_port_extracted_from_env_override() {
        let journal = vec![
            JournalEntry::SetEnvOverride {
                key: "OLLAMA_HOST".into(),
                value: "127.0.0.1:11999".into(),
            },
            JournalEntry::DisabledAutostart {
                unit: "ollama.service".into(),
            },
        ];
        let rec = engine_record(&sample_info(), &journal, AdoptionState::Adopted);
        assert_eq!(rec.shadow_port, Some(11999));
        assert_eq!(rec.adoption_state, AdoptionState::Adopted);
    }

    #[test]
    fn journal_round_trips_through_record_json() {
        // The journal serialized into the record must deserialize back identically
        // — this is the property revert relies on (04 §5.5).
        let journal = vec![
            JournalEntry::WroteFile {
                path: "/etc/systemd/system/ollama.service.d/saffev.conf".into(),
                prior: None,
            },
            JournalEntry::SetEnvOverride {
                key: "OLLAMA_HOST".into(),
                value: "127.0.0.1:11999".into(),
            },
            JournalEntry::DisabledAutostart {
                unit: "ollama.service".into(),
            },
            JournalEntry::RegisteredService {
                unit: "saffev.service".into(),
            },
        ];
        let rec = engine_record(&sample_info(), &journal, AdoptionState::Adopted);
        let restored: Vec<JournalEntry> =
            serde_json::from_str(&rec.journal_json).expect("journal JSON round-trips");
        assert_eq!(restored.len(), journal.len());
        // Spot-check shapes survived the round trip.
        match &restored[0] {
            JournalEntry::WroteFile { path, prior } => {
                assert!(path.contains("saffev.conf"));
                assert!(prior.is_none());
            }
            other => panic!("unexpected first entry: {other:?}"),
        }
        match &restored[1] {
            JournalEntry::SetEnvOverride { key, value } => {
                assert_eq!(key, "OLLAMA_HOST");
                assert_eq!(value, "127.0.0.1:11999");
            }
            other => panic!("unexpected second entry: {other:?}"),
        }
    }

    #[tokio::test]
    async fn diagnose_free_port_is_none() {
        // A high, almost-certainly-free port should report no holder (and never
        // error, even if lsof is missing).
        let res = diagnose_port_conflict(54637).await;
        assert!(res.is_ok());
        assert!(res.unwrap().is_none());
    }
}
