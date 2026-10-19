//! Backups — encrypted copies of the store written outside the data directory.
//!
//! One code path serves `saffev backup`, the panel's **Back up** button
//! (`POST /api/backup`) and the optional schedule (`[backup] auto`).
//!
//! ## Chains: full, then incremental
//!
//! A **full** backup is a `VACUUM INTO` snapshot of the whole store. Each later
//! backup is **incremental**: a small database holding only what was added or
//! re-archived since the previous link (see [`Store::backup_delta_to`]), plus a
//! manifest naming that previous link. So backing up every hour costs roughly
//! one hour of new activity, not the whole archive again. After
//! `[backup] full_every` incremental links the next backup starts a fresh chain,
//! which bounds how much a restore replays and how much one damaged file costs.
//!
//! Every link is a sibling folder in the destination:
//!
//! ```text
//! Saffev-Backup-20261019-090000/        full    (saffev.db, manifest.json, …)
//! Saffev-Backup-20261019-100000-incr/   delta   (delta.db,  manifest.json, …)
//! Saffev-Backup-20261019-110000-incr/   delta   (parent = the folder above)
//! ```
//!
//! `saffev restore <any link>` walks the parents back to the full copy and
//! replays the chain into a new database ([`restore`]).
//!
//! ## Safety properties
//!
//! - **Atomic.** A link is built in a hidden `.<name>.partial` folder and only
//!   renamed into place once complete; a failure removes the partial folder, so
//!   a half-written backup never looks like a real one.
//! - **Never into thin air.** The destination must already exist. An unplugged
//!   drive's mount point is NOT recreated on the internal disk.
//! - **Same key.** Every file is SQLCipher-encrypted under the store's key,
//!   which stays in the OS keychain and is never written into the folder.
//! - **Nothing deleted by default.** Old chains are pruned only when
//!   `[backup] keep_chains` is set, and only folders carrying our manifest.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::store::{BackupCursor, RestoreStats, Store, WriteOp};
use crate::{Error, Result};

/// Every backup folder starts with this.
pub const DIR_PREFIX: &str = "Saffev-Backup-";
pub const MANIFEST_FILE: &str = "manifest.json";
pub const FULL_DB_FILE: &str = "saffev.db";
pub const DELTA_DB_FILE: &str = "delta.db";
/// Manifest format version.
const FORMAT: u32 = 1;

/// Settings keys (in the store) the Studio and panel read.
pub const KEY_LAST_TS: &str = "last_backup_ts";
pub const KEY_LAST_DIR: &str = "last_backup_dir";
pub const KEY_LAST_CURSOR: &str = "last_backup_cursor";
pub const KEY_LAST_ERROR: &str = "last_backup_error";
/// When the schedule last found nothing new to back up.
pub const KEY_LAST_CHECK_TS: &str = "last_backup_check_ts";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Full,
    Incremental,
}

/// `manifest.json` in every backup folder.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub format: u32,
    pub kind: Kind,
    pub created_ms: i64,
    pub saffev_version: String,
    /// Schema `user_version` of the database file(s). A chain never mixes
    /// schemas: an upgrade starts a new chain.
    pub schema: u32,
    /// What this link covers up to; the next incremental starts here.
    pub cursor: BackupCursor,
    /// The previous link's folder name (a sibling). `None` for a full backup.
    pub parent: Option<String>,
    /// Links since the full backup: 0 for full, 1 for the first incremental…
    pub depth: u32,
    /// The database file in this folder.
    pub db_file: String,
    pub db_bytes: u64,
}

/// What the caller wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    /// Incremental when a usable chain exists, else full.
    Auto,
    /// Always start a new chain.
    Full,
}

/// What happened.
#[derive(Debug, Clone)]
pub enum Outcome {
    Written {
        dir: PathBuf,
        manifest: Manifest,
        /// Older chain folders removed under `keep_chains`.
        pruned: Vec<PathBuf>,
    },
    /// Nothing changed since the last backup, which is still current.
    Unchanged { dir: PathBuf },
}

impl Outcome {
    pub fn dir(&self) -> &Path {
        match self {
            Outcome::Written { dir, .. } | Outcome::Unchanged { dir } => dir,
        }
    }
}

/// One backup at a time per process (the button, the schedule and the API can
/// otherwise race). Separate processes stay safe: folder names are reserved
/// with an exclusive `create_dir`.
static RUNNING: AtomicBool = AtomicBool::new(false);

struct RunGuard;

impl RunGuard {
    fn acquire() -> Result<Self> {
        if RUNNING.swap(true, Ordering::AcqRel) {
            return Err(Error::Store("a backup is already running".into()));
        }
        Ok(RunGuard)
    }
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        RUNNING.store(false, Ordering::Release);
    }
}

/// Backups are one-at-a-time per process, so every test that runs one (here
/// and in the Studio API tests) takes turns on this.
#[cfg(test)]
pub(crate) static TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Is a backup running in this process right now?
pub fn is_running() -> bool {
    RUNNING.load(Ordering::Acquire)
}

/// Back up the store into `out` (default: the export destination).
///
/// Records the result in the store's settings (`last_backup_*`) so the Studio
/// and panel can say "backed up · 3h ago" and offer another backup only when
/// something changed. A failure is recorded as `last_backup_error`.
pub async fn run(
    store: &Store,
    cfg: &Config,
    out: Option<PathBuf>,
    req: Request,
) -> Result<Outcome> {
    let _guard = RunGuard::acquire()?;
    let result = run_locked(store, cfg, out, req).await;
    match &result {
        Ok(_) => store.enqueue(WriteOp::Setting {
            key: KEY_LAST_ERROR.into(),
            value: String::new(),
        }),
        Err(e) => store.enqueue(WriteOp::Setting {
            key: KEY_LAST_ERROR.into(),
            value: e.to_string(),
        }),
    }
    let _ = store.flush().await;
    result
}

async fn run_locked(
    store: &Store,
    cfg: &Config,
    out: Option<PathBuf>,
    req: Request,
) -> Result<Outcome> {
    let base = out.unwrap_or_else(|| cfg.export_base());
    if !base.is_dir() {
        return Err(Error::Store(format!(
            "the backup destination {} is not available (a missing folder or an unplugged drive) — \
             nothing was written",
            base.display()
        )));
    }

    let current_schema = crate::store::schema::target_version();
    let previous = match req {
        Request::Full => None,
        Request::Auto => {
            let last_dir = store.get_setting(KEY_LAST_DIR).await.ok().flatten();
            last_dir
                .map(PathBuf::from)
                .and_then(|d| usable_parent(&d, &base, current_schema, cfg.backup.full_every))
        }
    };

    if let Some((dir, m)) = &previous {
        if store.backup_cursor().await? == m.cursor {
            let now = now_ms();
            store.enqueue(WriteOp::Setting {
                key: KEY_LAST_CHECK_TS.into(),
                value: now.to_string(),
            });
            return Ok(Outcome::Unchanged { dir: dir.clone() });
        }
    }

    let now = time::OffsetDateTime::now_utc();
    let stamp = format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );
    let kind = if previous.is_some() {
        Kind::Incremental
    } else {
        Kind::Full
    };
    let name = match kind {
        Kind::Full => format!("{DIR_PREFIX}{stamp}"),
        Kind::Incremental => format!("{DIR_PREFIX}{stamp}-incr"),
    };
    let (staging, final_dir) = reserve(&base, &name)?;

    let built = build_link(
        store,
        cfg,
        &staging,
        kind,
        previous.as_ref().map(|(d, m)| (d.as_path(), m)),
    )
    .await;
    let manifest = match built {
        Ok(m) => m,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(e);
        }
    };
    if let Err(e) = std::fs::rename(&staging, &final_dir) {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(Error::Io(e));
    }

    store.enqueue(WriteOp::Setting {
        key: KEY_LAST_TS.into(),
        value: manifest.created_ms.to_string(),
    });
    store.enqueue(WriteOp::Setting {
        key: KEY_LAST_DIR.into(),
        value: final_dir.to_string_lossy().to_string(),
    });
    store.enqueue(WriteOp::Setting {
        key: KEY_LAST_CURSOR.into(),
        value: serde_json::to_string(&manifest.cursor).unwrap_or_default(),
    });

    let pruned = if manifest.kind == Kind::Full && cfg.backup.keep_chains > 0 {
        prune(&base, cfg.backup.keep_chains as usize, &final_dir)
    } else {
        Vec::new()
    };

    Ok(Outcome::Written {
        dir: final_dir,
        manifest,
        pruned,
    })
}

/// Write one link's files into `staging` and return its manifest.
async fn build_link(
    store: &Store,
    cfg: &Config,
    staging: &Path,
    kind: Kind,
    previous: Option<(&Path, &Manifest)>,
) -> Result<Manifest> {
    let (db_file, (schema, cursor), parent, depth) = match (kind, previous) {
        (Kind::Incremental, Some((pdir, pm))) => (
            DELTA_DB_FILE,
            store
                .backup_delta_to(staging.join(DELTA_DB_FILE), pm.cursor)
                .await?,
            pdir.file_name().map(|n| n.to_string_lossy().to_string()),
            pm.depth + 1,
        ),
        _ => (
            FULL_DB_FILE,
            store.backup_full_to(staging.join(FULL_DB_FILE)).await?,
            None,
            0,
        ),
    };
    let db_bytes = std::fs::metadata(staging.join(db_file))
        .map(|m| m.len())
        .unwrap_or(0);
    let cfg_copied = std::fs::copy(cfg.config_path(), staging.join("saffev.toml")).is_ok();

    let manifest = Manifest {
        format: FORMAT,
        kind: if parent.is_some() {
            Kind::Incremental
        } else {
            Kind::Full
        },
        created_ms: now_ms(),
        saffev_version: env!("CARGO_PKG_VERSION").to_string(),
        schema,
        cursor,
        parent,
        depth,
        db_file: db_file.to_string(),
        db_bytes,
    };
    let json = serde_json::to_vec_pretty(&manifest).map_err(|e| Error::Store(e.to_string()))?;
    std::fs::write(staging.join(MANIFEST_FILE), json).map_err(Error::Io)?;
    std::fs::write(
        staging.join("README.md"),
        readme(&manifest, cfg_copied, cfg),
    )
    .map_err(Error::Io)?;
    Ok(manifest)
}

/// Reserve a unique folder name: returns `(staging, final)`. The staging
/// folder is created exclusively, so two concurrent backups never share one.
fn reserve(base: &Path, name: &str) -> Result<(PathBuf, PathBuf)> {
    for n in 1..1000 {
        let candidate = if n == 1 {
            name.to_string()
        } else {
            format!("{name}-{n}")
        };
        let final_dir = base.join(&candidate);
        if final_dir.exists() {
            continue;
        }
        let staging = base.join(format!(".{candidate}.partial"));
        match std::fs::create_dir(&staging) {
            Ok(()) => return Ok((staging, final_dir)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Err(Error::Store(format!(
        "could not find a free backup folder name in {}",
        base.display()
    )))
}

/// Read a folder's manifest, if it has one.
pub fn read_manifest(dir: &Path) -> Option<Manifest> {
    let bytes = std::fs::read(dir.join(MANIFEST_FILE)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The previous backup, if a new incremental link can build on it: it lives
/// in `base`, its chain is complete on disk, its schema matches this binary,
/// and the chain has room for another link.
fn usable_parent(
    dir: &Path,
    base: &Path,
    schema: u32,
    full_every: u32,
) -> Option<(PathBuf, Manifest)> {
    if !same_dir(dir.parent()?, base) {
        return None;
    }
    let m = read_manifest(dir)?;
    if m.schema != schema || m.depth >= full_every {
        return None;
    }
    resolve_chain(dir).ok()?;
    Some((dir.to_path_buf(), m))
}

fn same_dir(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}

/// The files to replay for the backup in `dir`: the full copy, then every
/// delta after it, oldest first. A folder without a manifest is a backup from
/// before chains existed — a plain full copy.
pub fn resolve_chain(dir: &Path) -> Result<(PathBuf, Vec<PathBuf>)> {
    let Some(mut m) = read_manifest(dir) else {
        let db = dir.join(FULL_DB_FILE);
        if db.is_file() {
            return Ok((db, Vec::new()));
        }
        return Err(Error::Store(format!(
            "{} is not a Saffev backup (no manifest.json or saffev.db)",
            dir.display()
        )));
    };
    let schema = m.schema;
    let mut cur = dir.to_path_buf();
    let mut deltas = Vec::new();
    loop {
        let db = cur.join(&m.db_file);
        if !db.is_file() {
            return Err(Error::Store(format!(
                "{} is missing from the backup chain",
                db.display()
            )));
        }
        if m.schema != schema {
            return Err(Error::Store(format!(
                "{} has schema v{} but the chain is v{schema}",
                cur.display(),
                m.schema
            )));
        }
        match (m.kind, m.parent.clone()) {
            (Kind::Full, _) => {
                deltas.reverse();
                return Ok((db, deltas));
            }
            (Kind::Incremental, Some(parent)) => {
                let depth = m.depth;
                deltas.push(db);
                let parent_dir = cur
                    .parent()
                    .map(|p| p.join(&parent))
                    .ok_or_else(|| Error::Store("backup folder has no parent".into()))?;
                m = read_manifest(&parent_dir).ok_or_else(|| {
                    Error::Store(format!(
                        "{} (needed by {}) is missing or unreadable",
                        parent_dir.display(),
                        cur.display()
                    ))
                })?;
                if m.depth + 1 != depth {
                    return Err(Error::Store(format!(
                        "the backup chain at {} is out of order",
                        parent_dir.display()
                    )));
                }
                cur = parent_dir;
            }
            (Kind::Incremental, None) => {
                return Err(Error::Store(format!(
                    "{} is incremental but names no parent",
                    cur.display()
                )))
            }
        }
    }
}

/// Rebuild a database at `target` from the backup in `dir` (any link of a
/// chain). See [`crate::store::restore_backup_chain`].
pub fn restore(dir: &Path, target: &Path) -> Result<RestoreStats> {
    let (full, deltas) = resolve_chain(dir)?;
    crate::store::restore_backup_chain(&full, &deltas, target)
}

/// Delete chains older than the newest `keep`, never touching `current`'s
/// chain or any folder without our manifest. Returns what was removed.
fn prune(base: &Path, keep: usize, current: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(base) else {
        return Vec::new();
    };
    // (folder, manifest) for every backup folder of ours.
    let mut links: Vec<(PathBuf, Manifest)> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_dir()
                && p.file_name()
                    .map(|n| n.to_string_lossy().starts_with(DIR_PREFIX))
                    .unwrap_or(false)
        })
        .filter_map(|p| read_manifest(&p).map(|m| (p, m)))
        .collect();
    // Group each link under its chain's full backup.
    let root_of = |dir: &Path| -> Option<PathBuf> {
        let (full, _) = resolve_chain(dir).ok()?;
        full.parent().map(Path::to_path_buf)
    };
    let mut roots: Vec<(PathBuf, i64)> = links
        .iter()
        .filter(|(_, m)| m.kind == Kind::Full)
        .map(|(p, m)| (p.clone(), m.created_ms))
        .collect();
    let current_root = root_of(current);
    // Newest first, with the chain just written always counted first.
    roots.sort_by(|a, b| {
        let cur = |p: &PathBuf| current_root.as_ref() == Some(p);
        cur(&b.0).cmp(&cur(&a.0)).then(b.1.cmp(&a.1))
    });
    let keep_roots: Vec<PathBuf> = roots
        .iter()
        .take(keep.max(1))
        .map(|(p, _)| p.clone())
        .collect();
    let mut removed = Vec::new();
    links.sort_by_key(|l| std::cmp::Reverse(l.1.depth)); // children before parents
    for (dir, _) in &links {
        let Some(root) = root_of(dir) else { continue };
        if keep_roots.contains(&root) || current_root.as_ref() == Some(&root) {
            continue;
        }
        if std::fs::remove_dir_all(dir).is_ok() {
            removed.push(dir.clone());
        }
    }
    removed
}

fn readme(m: &Manifest, cfg_copied: bool, cfg: &Config) -> String {
    let created = time::OffsetDateTime::from_unix_timestamp(m.created_ms / 1000)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default();
    let what = match m.kind {
        Kind::Full => format!(
            "- `{FULL_DB_FILE}` — a complete, consistent snapshot of the store (proxy\n\
             \x20 history, findings, preserved sessions, integrity chain).\n"
        ),
        Kind::Incremental => format!(
            "- `{DELTA_DB_FILE}` — an INCREMENTAL backup: only what changed since\n\
             \x20 `{}` (link {} of its chain). On its own it is not a\n\
             \x20 complete store — keep every folder of the chain together.\n",
            m.parent.as_deref().unwrap_or("?"),
            m.depth
        ),
    };
    let config_line = if cfg_copied {
        "- `saffev.toml` — the config file at backup time.\n"
    } else {
        "- (no config file existed at backup time — defaults were in use)\n"
    };
    format!(
        "# Saffev backup — {created}\n\n\
         Created by Saffev v{version}, schema v{schema}. Contents:\n\n\
         {what}\
         - `manifest.json` — what this folder covers and which folder came before it.\n\
         {config_line}\n\
         Every database file here is SQLCipher-encrypted with the SAME key as the\n\
         source machine, and is useless without it.\n\n\
         ## The key — read this before you need it\n\n\
         The database key is deliberately NOT in this folder (a backup that\n\
         carries its own key is not encrypted in any meaningful sense). To\n\
         restore on another machine, bring the key yourself:\n\n\
         - macOS (on the source machine):\n\
         \x20 `security find-generic-password -s saffev -a db-key -w`\n\
         - Linux: the secret service entry with service `saffev`, user `db-key`\n\
         \x20 (e.g. `secret-tool lookup service saffev username db-key`).\n\
         - If you run Saffev with the `SAFFEV_DB_KEY` environment variable set,\n\
         \x20 that value IS the key.\n\n\
         ## Restore\n\n\
         1. Install Saffev on the new machine — but do NOT start it yet: a\n\
         \x20  first start would mint a fresh key that cannot open these files.\n\
         2. Put the key where Saffev looks: add it to the OS keychain (macOS:\n\
         \x20  `security add-generic-password -s saffev -a db-key -w '<key>'`)\n\
         \x20  or export `SAFFEV_DB_KEY` for every start.\n\
         3. Run `saffev restore \"<this folder>\"`. It replays the chain (the\n\
         \x20  full copy, then each incremental folder after it) into a new\n\
         \x20  database in the data directory ({data_dir}). Copy `saffev.toml`\n\
         \x20  into place too if you want the old settings.\n\
         4. `saffev start` — History, Agents, and the archive are exactly as\n\
         \x20  they were at the time of this backup.\n",
        version = m.saffev_version,
        schema = m.schema,
        data_dir = cfg.data_dir.display(),
    )
}

fn now_ms() -> i64 {
    (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64
}

/// Is an automatic backup due? `last_ms` is the newer of the last backup and
/// the last "nothing changed" check.
pub fn due(cfg: &Config, last_ms: Option<i64>, now_ms: i64) -> bool {
    if !cfg.backup.auto {
        return false;
    }
    let period = i64::from(cfg.backup.interval_hours.max(1)) * 3_600_000;
    match last_ms {
        None => true,
        Some(t) => now_ms.saturating_sub(t) >= period,
    }
}

#[cfg(test)]
// Tests take turns on TEST_SERIAL across awaits on purpose (one backup at a
// time per process); each test has its own runtime, so nothing deadlocks.
#[allow(clippy::await_holding_lock)]
mod tests {
    use super::*;
    use crate::store::{
        ArchivedMessage, ArchivedSession, RequestMeta, SourceConfidence, TokenSource,
    };

    use super::TEST_SERIAL as SERIAL;

    fn ensure_key() {
        if std::env::var(crate::store::keys::DB_KEY_ENV)
            .map(|v| v.is_empty())
            .unwrap_or(true)
        {
            std::env::set_var(
                crate::store::keys::DB_KEY_ENV,
                "test-db-key-0123456789abcdef",
            );
        }
    }

    struct Fixture {
        root: PathBuf,
        store: Store,
        cfg: Config,
        dest: PathBuf,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    async fn fixture() -> Fixture {
        ensure_key();
        let root =
            std::env::temp_dir().join(format!("saffev-backup-test-{}", uuid::Uuid::new_v4()));
        let data = root.join("data");
        let dest = root.join("dest");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::create_dir_all(&dest).unwrap();
        let cfg = Config {
            data_dir: data.clone(),
            export_dir: Some(dest.clone()),
            ..Config::default()
        };
        let store = Store::open(&data.join("saffev.db")).await.unwrap();
        Fixture {
            root,
            store,
            cfg,
            dest,
        }
    }

    fn session(id: &str, bodies: &[&str]) -> ArchivedSession {
        ArchivedSession {
            id: id.into(),
            tool: "claude_code".into(),
            source_id: id.into(),
            title: Some(format!("title {id}")),
            project: Some("/proj".into()),
            git_branch: None,
            model: None,
            started_ts: 1000,
            updated_ts: 2000 + bodies.len() as i64,
            message_count: bodies.len() as u32,
            tool_call_count: 0,
            input_tokens: 0,
            output_tokens: 0,
            cache_tokens: 0,
            source_path: None,
            content_hash: format!("h{}", bodies.len()),
            archived_ts: 3000,
            source_deleted: false,
            messages: bodies
                .iter()
                .map(|b| ArchivedMessage {
                    role: "user".into(),
                    kind: "text".into(),
                    content: (*b).into(),
                    ts: Some(1000),
                    tool_name: None,
                })
                .collect(),
        }
    }

    fn request(id: &str, ts: i64) -> RequestMeta {
        RequestMeta {
            id: id.into(),
            ts,
            source_app: Some("app".into()),
            source_confidence: SourceConfidence::Pid,
            engine: "ollama".into(),
            model: Some("llama3".into()),
            endpoint: "/api/chat".into(),
            stream: false,
            input_tokens: None,
            input_tokens_src: TokenSource::Estimated,
            latency_ms: Some(5),
            request_hash: String::new(),
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

    fn written(o: Outcome) -> (PathBuf, Manifest) {
        match o {
            Outcome::Written { dir, manifest, .. } => (dir, manifest),
            Outcome::Unchanged { dir } => {
                panic!("expected a new backup, got unchanged {}", dir.display())
            }
        }
    }

    #[tokio::test]
    async fn full_then_incremental_then_restore_round_trips() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = fixture().await;
        f.store.enqueue(WriteOp::ArchiveSession(Box::new(session(
            "a",
            &["alpha one", "alpha two"],
        ))));
        f.store.enqueue(WriteOp::Request(request("r1", 1_000)));
        f.store.flush().await.unwrap();

        let (full_dir, full) = written(run(&f.store, &f.cfg, None, Request::Auto).await.unwrap());
        assert_eq!(full.kind, Kind::Full);
        assert_eq!(full.depth, 0);
        assert!(full_dir.join(FULL_DB_FILE).is_file());
        assert!(full_dir.join("README.md").is_file());

        // Nothing new: the last backup is still current, no folder is written.
        let again = run(&f.store, &f.cfg, None, Request::Auto).await.unwrap();
        assert!(matches!(again, Outcome::Unchanged { ref dir } if *dir == full_dir));

        // New activity: a growing session, a new one, a new proxy request.
        f.store.enqueue(WriteOp::ArchiveSession(Box::new(session(
            "a",
            &["alpha one", "alpha two", "alpha three"],
        ))));
        f.store.enqueue(WriteOp::ArchiveSession(Box::new(session(
            "b",
            &["bravo zebracorn"],
        ))));
        f.store.enqueue(WriteOp::Request(request("r2", 2_000)));
        f.store.flush().await.unwrap();

        let (incr_dir, incr) = written(run(&f.store, &f.cfg, None, Request::Auto).await.unwrap());
        assert_eq!(incr.kind, Kind::Incremental);
        assert_eq!(incr.depth, 1);
        assert_eq!(
            incr.parent.as_deref(),
            full_dir.file_name().and_then(|n| n.to_str())
        );
        assert!(incr_dir.join(DELTA_DB_FILE).is_file());
        assert!(
            !incr_dir.join(FULL_DB_FILE).exists(),
            "an incremental link carries only the delta"
        );
        assert_ne!(incr.cursor, full.cursor);

        // Restoring the newest link replays full + delta.
        let target = f.root.join("restored").join("saffev.db");
        let stats = restore(&incr_dir, &target).unwrap();
        assert_eq!(stats.deltas_applied, 1);
        let restored = Store::open(&target).await.unwrap();
        let a = restored
            .archived_detail("a")
            .await
            .unwrap()
            .expect("a restored");
        assert_eq!(a.messages.len(), 3);
        assert_eq!(a.messages[2].content, "alpha three");
        assert!(restored.archived_detail("b").await.unwrap().is_some());
        let ids = restored.archived_ids().await.unwrap();
        assert_eq!(ids.len(), 2);
        let hist = restored
            .history(crate::store::HistoryQuery::default())
            .await
            .unwrap();
        let mut req_ids: Vec<String> = hist.iter().map(|h| h.request.id.clone()).collect();
        req_ids.sort();
        assert_eq!(req_ids, vec!["r1".to_string(), "r2".to_string()]);
        assert!(
            restored.verify_archive().await.unwrap().intact,
            "the chain survives a restore"
        );
        let hits = restored.search_archive("zebracorn", 10).await.unwrap();
        assert_eq!(
            hits.len(),
            1,
            "full-text search is rebuilt for restored messages"
        );

        // Restoring the full link alone gives the earlier state.
        let early = f.root.join("early.db");
        restore(&full_dir, &early).unwrap();
        let early = Store::open(&early).await.unwrap();
        assert_eq!(
            early
                .archived_detail("a")
                .await
                .unwrap()
                .unwrap()
                .messages
                .len(),
            2
        );
        assert!(early.archived_detail("b").await.unwrap().is_none());

        // Never overwrites.
        assert!(restore(&incr_dir, &target).is_err());
        // The settings say where the latest backup is.
        assert_eq!(
            f.store
                .get_setting(KEY_LAST_DIR)
                .await
                .unwrap()
                .map(PathBuf::from),
            Some(incr_dir)
        );
    }

    #[tokio::test]
    async fn missing_destination_writes_nothing_and_records_the_error() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = fixture().await;
        let gone = f.root.join("unplugged-drive");
        let err = run(&f.store, &f.cfg, Some(gone.clone()), Request::Auto)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not available"), "{err}");
        assert!(
            !gone.exists(),
            "an unplugged drive's path must not be recreated"
        );
        let recorded = f
            .store
            .get_setting(KEY_LAST_ERROR)
            .await
            .unwrap()
            .unwrap_or_default();
        assert!(recorded.contains("not available"));
    }

    #[tokio::test]
    async fn full_every_starts_a_new_chain_and_keep_chains_prunes_old_ones() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let mut f = fixture().await;
        f.cfg.backup.full_every = 1;
        f.cfg.backup.keep_chains = 1;
        // Not ours: must survive any pruning.
        let stranger = f.dest.join(format!("{DIR_PREFIX}handmade"));
        std::fs::create_dir_all(&stranger).unwrap();

        let mut dirs = Vec::new();
        for i in 0..3 {
            f.store
                .enqueue(WriteOp::Request(request(&format!("r{i}"), 1_000 + i)));
            f.store.flush().await.unwrap();
            let (dir, m) = written(run(&f.store, &f.cfg, None, Request::Auto).await.unwrap());
            dirs.push((dir, m.kind));
        }
        assert_eq!(
            dirs.iter().map(|(_, k)| *k).collect::<Vec<_>>(),
            vec![Kind::Full, Kind::Incremental, Kind::Full],
            "one incremental link per chain, then a fresh full copy"
        );
        assert!(
            !dirs[0].0.exists() && !dirs[1].0.exists(),
            "the older chain was pruned"
        );
        assert!(dirs[2].0.exists(), "the current chain is kept");
        assert!(
            stranger.exists(),
            "folders without our manifest are never deleted"
        );
        let leftovers: Vec<_> = std::fs::read_dir(&f.dest)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".partial"))
            .collect();
        assert!(leftovers.is_empty(), "no staging folders left behind");
    }

    #[tokio::test]
    async fn explicit_full_and_same_second_names_never_collide() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = fixture().await;
        let (a, _) = written(run(&f.store, &f.cfg, None, Request::Full).await.unwrap());
        let (b, mb) = written(run(&f.store, &f.cfg, None, Request::Full).await.unwrap());
        assert_eq!(mb.kind, Kind::Full);
        assert_ne!(a, b, "two backups in the same second get distinct folders");
        let (s1, d1) = reserve(&f.dest, "Saffev-Backup-x").unwrap();
        let (s2, d2) = reserve(&f.dest, "Saffev-Backup-x").unwrap();
        assert_ne!(s1, s2);
        assert_ne!(d1, d2);
    }

    #[tokio::test]
    async fn a_broken_chain_falls_back_to_a_full_backup() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = fixture().await;
        let (full_dir, _) = written(run(&f.store, &f.cfg, None, Request::Auto).await.unwrap());
        f.store.enqueue(WriteOp::Request(request("r1", 1_000)));
        f.store.flush().await.unwrap();
        let (incr_dir, _) = written(run(&f.store, &f.cfg, None, Request::Auto).await.unwrap());
        // The full copy disappears (deleted by hand, a failed sync…).
        std::fs::remove_dir_all(&full_dir).unwrap();
        assert!(
            resolve_chain(&incr_dir).is_err(),
            "a chain without its base cannot restore"
        );
        f.store.enqueue(WriteOp::Request(request("r2", 2_000)));
        f.store.flush().await.unwrap();
        let (_, m) = written(run(&f.store, &f.cfg, None, Request::Auto).await.unwrap());
        assert_eq!(
            m.kind,
            Kind::Full,
            "never build on a chain that cannot be restored"
        );
    }

    #[test]
    fn schedule_due_logic() {
        let mut cfg = Config::default();
        assert!(!due(&cfg, None, 0), "off by default");
        cfg.backup.auto = true;
        cfg.backup.interval_hours = 6;
        assert!(due(&cfg, None, 0), "never backed up");
        let h = 3_600_000;
        assert!(!due(&cfg, Some(10 * h), 15 * h));
        assert!(due(&cfg, Some(10 * h), 16 * h));
        cfg.backup.interval_hours = 0;
        assert!(due(&cfg, Some(10 * h), 11 * h), "0 is clamped to 1 hour");
    }
}
