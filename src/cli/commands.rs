//! CLI command handlers — thin orchestration that wires config -> store ->
//! engine -> proxy -> studio. Each renders with the [`crate::ui::palette`] voice
//! (calm, declarative, status-dot prefixed, monospaced and aligned — 05 §9).
//!
//! ## Resilience (the fail-open ethos applied to the control plane)
//!
//! Saffev is a single binary assembled from many modules that come online at
//! different times. The CLI must never hard-crash because a downstream module is
//! still a stub or because the proxy/engine isn't running: `saffev --help` and
//! `saffev status` must always produce sensible output. To that end every call
//! into another module that *might* be unfinished or unavailable is run through
//! [`guard`], which isolates it on a spawned task and converts a panic into a
//! graceful `None` (logged at debug). Where a status signal can be obtained
//! directly and cheaply (a TCP probe, the default config), the CLI does so
//! itself so the output is meaningful even when nothing else is wired yet.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::cli::{capture, daemon, Cli, EngineArg};
use crate::config::{Config, HandoverPolicy, Mode, Retention};
use crate::ui::palette::{ColorMode, Level, Painter};
use crate::Result;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Build a [`Painter`] honoring `--no-color` (and, transitively, `NO_COLOR` /
/// non-tty via [`ColorMode::detect`]).
fn painter(cli: &Cli) -> Painter {
    if cli.no_color {
        Painter::with_mode(ColorMode::None)
    } else {
        Painter::new()
    }
}

/// Run a future that may be backed by an unfinished module, isolating any panic
/// onto a spawned task. Returns `Some(value)` on success, `None` if the call
/// panicked or returned an error (both logged at debug). This is the control
/// plane's expression of the fail-open invariant: a stubbed or failing
/// dependency degrades a single status line, never the whole command.
async fn guard<F, T>(what: &str, fut: F) -> Option<T>
where
    F: std::future::Future<Output = Result<T>> + Send + 'static,
    T: Send + 'static,
{
    match tokio::spawn(fut).await {
        Ok(Ok(value)) => Some(value),
        Ok(Err(err)) => {
            tracing::debug!("{what} failed: {err}");
            None
        }
        Err(join_err) => {
            tracing::debug!("{what} unavailable (panicked: {join_err})");
            None
        }
    }
}

/// Run an infallible future that may be backed by an unfinished module.
async fn guard_infallible<F, T>(what: &str, fut: F) -> Option<T>
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    match tokio::spawn(fut).await {
        Ok(value) => Some(value),
        Err(join_err) => {
            tracing::debug!("{what} unavailable (panicked: {join_err})");
            None
        }
    }
}

/// Load the effective config, falling back to defaults if the loader is
/// unavailable or fails. `status`/`doctor` must work before any config exists.
async fn load_config(cli: &Cli) -> Config {
    let cli_config = cli.config.clone();
    // The load call runs inside a spawned task (via `guard_infallible`), so a
    // panic from an unfinished loader is isolated and surfaces as `None`.
    let loaded = guard_infallible("config load", async move {
        match cli_config {
            Some(path) => Config::load_from(&path),
            None => Config::load(),
        }
    })
    .await;

    match loaded {
        Some(Ok(cfg)) => cfg,
        Some(Err(err)) => {
            tracing::debug!("config load error, using defaults: {err}");
            Config::default()
        }
        None => Config::default(),
    }
}

/// Direct, dependency-free liveness probe: is something accepting TCP on
/// `addr:port`? Used so the status/doctor blocks reflect reality even when the
/// engine/proxy detection modules are not yet wired.
async fn port_listening(addr: IpAddr, port: u16) -> bool {
    let sock = SocketAddr::new(addr, port);
    matches!(
        tokio::time::timeout(
            Duration::from_millis(300),
            tokio::net::TcpStream::connect(sock)
        )
        .await,
        Ok(Ok(_))
    )
}

/// Map a [`Mode`] to its lowercase display string.
fn mode_str(mode: Mode) -> &'static str {
    match mode {
        Mode::Gateway => "gateway",
        Mode::Cooperative => "cooperative",
    }
}

/// One-line explanation of what a mode actually *captures* — the thing users
/// most often miss. Cooperative only sees traffic sent to the proxy port (so
/// apps must be pointed at it, e.g. via `saffev run`); Gateway owns the engine's
/// well-known port and captures everything transparently.
fn capture_note(mode: Mode) -> &'static str {
    match mode {
        Mode::Cooperative => "captures traffic sent to the proxy · route an app with `saffev run`",
        Mode::Gateway => "captures all engine traffic transparently · apps need no change",
    }
}

/// Map an [`EngineArg`] to its canonical lowercase name.
fn engine_name(engine: EngineArg) -> &'static str {
    match engine {
        EngineArg::Ollama => "ollama",
        EngineArg::Lmstudio => "lmstudio",
    }
}

/// Render a retention policy as a short human string.
fn retention_str(r: Retention) -> String {
    match r {
        Retention::Age { days } => format!("{days}d"),
        Retention::Size { mb } => format!("{mb}mb"),
        Retention::Unlimited => "unlimited".to_string(),
    }
}

/// Group an integer with thousands separators (`1284 -> "1,284"`), matching the
/// design's `~ 1,284 requests today` line.
fn group_thousands(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    let len = bytes.len();
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*b as char);
    }
    out
}

// ---------------------------------------------------------------------------
// status — the signature status block (05 §9)
// ---------------------------------------------------------------------------

/// `saffev status` — engines, ports, mode, health, exposure (the status block).
///
/// Renders exactly the design's block:
/// ```text
/// ~ saffev status
/// ● proxy      :11434 ▸ ollama :11999      healthy
/// ● privacy    metadata-only · keyring
/// ● exposure   localhost-only  ✓ not exposed
/// ~ 1,284 requests today · 38ms p50 · 6 PII findings
/// ```
/// Must work even when the proxy isn't running and downstream modules are stubs.
/// `saffev report` — generate the local privacy report (G4). Reads the
/// store + config + OS socket table; performs zero network calls.
pub async fn report(cli: &Cli, days: u32, out: Option<&std::path::Path>) -> Result<()> {
    let cfg = load_config(cli).await;
    let now_ms = crate::agents::now_ms();
    let since = now_ms - (days as i64) * 86_400_000;

    let store = crate::store::Store::open(&cfg.db_path()).await?;
    let mut history = store
        .history(crate::store::HistoryQuery {
            q: None,
            pii_only: false,
            failed_only: false,
            limit: Some(100_000),
            before_ts: None,
        })
        .await?;
    history.retain(|r| r.request.ts >= since);
    let ids: std::collections::HashSet<&str> =
        history.iter().map(|r| r.request.id.as_str()).collect();
    let findings: Vec<_> = store
        .privacy_summary()
        .await?
        .into_iter()
        .filter(|f| ids.contains(f.record_id.as_str()))
        .collect();

    // The ENGINE's port, mode-aware — the exposure verdict is about whether
    // the ENGINE is reachable from the network, and probing the proxy port
    // instead falsely reassured the reviewer (G4 critic: in Cooperative mode
    // the engine can be world-bound while the proxy is loopback).
    let engine_port = match cfg.mode {
        crate::config::Mode::Gateway => cfg.ports.shadow,
        crate::config::Mode::Cooperative => cfg.ports.upstream,
    };
    let exposure = crate::exposure::check(engine_port).await;
    let (exposure_line, exposure_known) = match &exposure {
        Ok(e) => (e.detail.clone(), true),
        Err(_) => (String::new(), false),
    };
    let (archive, archive_stats) = if cfg.archive.enabled {
        (
            store.verify_archive().await.ok(),
            store.archive_stats().await.ok(),
        )
    } else {
        (None, None)
    };
    let agent_tools = crate::agents::detected()
        .into_iter()
        .filter(|t| t.present)
        .map(|t| (t.tool.label().to_string(), t.sessions))
        .collect();

    let inputs = crate::report::ReportInputs {
        now_ms,
        period_days: days,
        version: crate::VERSION.to_string(),
        history,
        findings,
        config: cfg,
        exposure_line,
        exposure_known,
        archive,
        archive_stats,
        agent_tools,
    };
    let md = crate::report::render(&inputs);
    match out {
        Some(path) => {
            std::fs::write(path, &md).map_err(crate::Error::Io)?;
            println!("report written to {}", path.display());
        }
        None => println!("{md}"),
    }
    Ok(())
}

pub async fn status(cli: &Cli) -> Result<()> {
    let p = painter(cli);
    let cfg = load_config(cli).await;

    let bind = cfg.ports.bind;
    let proxy_port = cfg.ports.proxy;
    let upstream_port = match cfg.mode {
        Mode::Gateway => cfg.ports.shadow,
        Mode::Cooperative => cfg.ports.upstream,
    };

    // Header line: prompt glyph + echoed command.
    println!("{} {}", p.prompt("~"), p.value("saffev status"));

    // --- proxy line -------------------------------------------------------
    // Liveness is probed directly so the line is honest without the proxy
    // module. Upstream/engine name comes from detection when available.
    let proxy_up = port_listening(bind, proxy_port).await;
    let upstream_up = port_listening(bind, upstream_port).await;

    let engine_label = guard("engine detect", async move {
        crate::engine::detect::detect_all().await
    })
    .await
    .and_then(|engines| engines.into_iter().next())
    .map(|info| match info.engine {
        crate::engine::EngineKind::Ollama => "ollama".to_string(),
        crate::engine::EngineKind::LmStudio => "lmstudio".to_string(),
        crate::engine::EngineKind::Unknown => "engine".to_string(),
    })
    .unwrap_or_else(|| "ollama".to_string());

    let (proxy_dot, proxy_health) = match (proxy_up, upstream_up) {
        (true, _) => (Level::Ok, p.success("healthy")),
        (false, true) => (Level::Warn, p.warn("proxy down · engine up")),
        (false, false) => (Level::Err, p.error("not running")),
    };

    println!(
        "{} {}   {} {} {} {}      {}",
        p.dot(proxy_dot),
        p.label("proxy"),
        p.value(&format!(":{proxy_port}")),
        p.muted("▸"),
        p.label(&engine_label),
        p.value(&format!(":{upstream_port}")),
        proxy_health,
    );

    // --- mode line --------------------------------------------------------
    println!(
        "{} {}    {}",
        p.dot(Level::Ok),
        p.label("mode"),
        p.value(mode_str(cfg.mode)),
    );
    // Capture clarity: spell out exactly what this mode does and doesn't see.
    println!("{}      {}", p.muted("·"), p.muted(capture_note(cfg.mode)));

    // --- privacy line -----------------------------------------------------
    let privacy_state = if cfg.payload_storage {
        p.warn("payloads stored")
    } else {
        p.value("metadata-only")
    };
    // The DB is only encrypted at rest with `--features sqlcipher`; reflect the
    // honest build truth rather than overclaiming.
    let at_rest = if cfg!(feature = "sqlcipher") {
        "encrypted (keyring)"
    } else {
        "keyring"
    };
    println!(
        "{} {} {} {} {}",
        p.dot(Level::Ok),
        p.label("privacy"),
        privacy_state,
        p.muted("·"),
        p.muted(at_rest),
    );

    // --- exposure line ----------------------------------------------------
    let report = guard("exposure check", async move {
        crate::exposure::check(upstream_port).await
    })
    .await;

    let bound_local = bind.is_loopback();
    let (exp_dot, exp_left, exp_right) = match report {
        Some(r) => {
            if r.exposed {
                (
                    Level::Err,
                    r.bound_to.clone().unwrap_or_else(|| "0.0.0.0".to_string()),
                    p.error("⚠ exposed"),
                )
            } else {
                (
                    Level::Ok,
                    "localhost-only".to_string(),
                    p.success("✓ not exposed"),
                )
            }
        }
        // Fall back to the bind address we know from config.
        None if bound_local => (
            Level::Ok,
            "localhost-only".to_string(),
            p.success("✓ not exposed"),
        ),
        None => (Level::Warn, format!("{bind}"), p.warn("⚠ check exposure")),
    };
    println!(
        "{} {} {}  {}",
        p.dot(exp_dot),
        p.label("exposure"),
        p.value(&exp_left),
        exp_right,
    );

    // --- counts line ------------------------------------------------------
    // Pulled from the store when available; otherwise omitted gracefully.
    let stats = collect_stats(&cfg).await;
    match stats {
        Some(s) => {
            println!(
                "{} {} requests today {} {} p50 {} {} PII findings",
                p.prompt("~"),
                p.value(&group_thousands(s.requests_today)),
                p.muted("·"),
                p.value(
                    &s.p50
                        .map(|ms| format!("{ms}ms"))
                        .unwrap_or_else(|| "—".to_string())
                ),
                p.muted("·"),
                if s.pii_today > 0 {
                    p.error(&s.pii_today.to_string())
                } else {
                    p.value("0")
                },
            );
        }
        None => {
            println!("{} {}", p.prompt("~"), p.muted("no activity recorded yet"),);
            println!(
                "{} {} {}",
                p.muted("·"),
                p.muted("trace an app:"),
                p.value("saffev run -- <your app>"),
            );
        }
    }

    Ok(())
}

/// Aggregate counters for the status footer line. Best-effort: returns `None`
/// when the store is unavailable or empty.
struct Stats {
    requests_today: u64,
    p50: Option<u32>,
    pii_today: u64,
}

async fn collect_stats(cfg: &Config) -> Option<Stats> {
    let db_path = cfg.db_path();
    // Opening the store reads recent history; if the store module is a stub or
    // there's no DB yet, this degrades to `None` (the line is then omitted).
    let store = guard("store open", async move {
        crate::store::Store::open(&db_path).await
    })
    .await?;

    let rows = guard("store history", async move {
        store
            .history(crate::store::HistoryQuery {
                q: None,
                pii_only: false,
                failed_only: false,
                limit: Some(1000),
                before_ts: None,
            })
            .await
    })
    .await?;

    if rows.is_empty() {
        return None;
    }

    let now_ms = current_millis();
    let day_ms: i64 = 24 * 60 * 60 * 1000;
    let cutoff = now_ms - day_ms;

    let today: Vec<&crate::store::HistoryRow> =
        rows.iter().filter(|r| r.request.ts >= cutoff).collect();

    let requests_today = today.len() as u64;
    let pii_today: u64 = today.iter().map(|r| r.pii_count as u64).sum();

    // p50 latency over today's completed exchanges. The request row never carries
    // its own end-to-end time, so fall back to the response's measured total.
    let mut latencies: Vec<u32> = today
        .iter()
        .filter_map(|r| {
            r.request
                .latency_ms
                .or_else(|| r.response.as_ref().and_then(|x| x.total_ms))
        })
        .collect();
    latencies.sort_unstable();
    let p50 = if latencies.is_empty() {
        None
    } else {
        Some(latencies[latencies.len() / 2])
    };

    Some(Stats {
        requests_today,
        p50,
        pii_today,
    })
}

/// Current unix time in milliseconds (wall clock).
fn current_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// adopt / revert — engine controller
// ---------------------------------------------------------------------------

/// `saffev adopt` — run adoption (Gateway on Linux) or print Cooperative setup.
pub async fn adopt(cli: &Cli, engine: EngineArg, cooperative: bool) -> Result<()> {
    let p = painter(cli);
    let cfg = load_config(cli).await;
    let name = engine_name(engine);

    println!(
        "{} {}",
        p.prompt("~"),
        p.value(&format!("saffev adopt --engine {name}"))
    );

    // Detect the target engine first so adoption (or the cooperative snippet)
    // points at the right thing.
    let detected = guard("engine detect", async move {
        crate::engine::detect::detect_all().await
    })
    .await
    .unwrap_or_default();

    let mut can_gateway = !cooperative && controller_can_adopt(&cfg);

    // Gateway/transparent adoption is Ollama-only: it relies on a clean systemd
    // rebind of the engine's service, which LM Studio (a GUI app with no
    // equivalent unit) doesn't offer. LM Studio is fully supported in Cooperative
    // mode — point its OpenAI base URL at the proxy (or use `saffev run`).
    if engine == EngineArg::Lmstudio && can_gateway {
        println!(
            "{} {}",
            p.dot(Level::Warn),
            p.warn("Gateway adoption isn't supported for LM Studio — using Cooperative mode."),
        );
        can_gateway = false;
    }

    if !can_gateway {
        // Cooperative path: no system changes — print the copy-paste setup.
        let proxy_url = format!(
            "http://{}:{}",
            display_host(cfg.ports.bind),
            cfg.ports.proxy
        );
        println!(
            "{} {} {}",
            p.dot(Level::Ok),
            p.label("mode"),
            p.value("cooperative — no system changes"),
        );
        println!(
            "{} point your client's base URL at the proxy:",
            p.muted("·"),
        );

        // Render a snippet via the engine module when present; otherwise a
        // sane built-in fallback so adopt is always useful.
        let url_for_snippet = proxy_url.clone();
        let snippet = guard_infallible("setup snippet", async move {
            crate::engine::cooperative::setup_snippet("openai", &url_for_snippet)
        })
        .await
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default_setup_snippet(&proxy_url));

        for line in snippet.lines() {
            println!("    {}", p.value(line));
        }
        return Ok(());
    }

    // Gateway path: drive the controller. Persist the journal via the store.
    let target = detected
        .into_iter()
        .find(|info| engine_matches(info, engine));

    let Some(info) = target else {
        println!(
            "{} {} {}",
            p.dot(Level::Warn),
            p.label("adopt"),
            p.warn(&format!("no running {name} engine detected")),
        );
        return Ok(());
    };

    let db_path = cfg.db_path();
    let info_for_adopt = info.clone();
    let cfg_for_adopt = cfg.clone();
    let journal = guard("adoption", async move {
        let store = crate::store::Store::open(&db_path).await?;
        // Use the mode-appropriate controller: on Linux + Gateway this is the
        // SystemdController (relocates the engine to the shadow port, registers
        // Saffev on the public port — transparent capture); everywhere else it's
        // the cooperative no-op. `can_gateway` above already gates this branch to
        // Gateway mode, so we never touch the system in Cooperative mode.
        let controller = crate::engine::default_controller(&cfg_for_adopt);
        crate::engine::adopt::run_adoption(controller.as_ref(), &info_for_adopt, &store).await
    })
    .await;

    match journal {
        Some(entries) => {
            println!(
                "{} {} {} ({} change{})",
                p.dot(Level::Ok),
                p.label("adopted"),
                p.success(name),
                p.value(&entries.len().to_string()),
                if entries.len() == 1 { "" } else { "s" },
            );
            println!(
                "{} engine relocated to shadow {} · proxy owns {}",
                p.muted("·"),
                p.value(&format!(":{}", cfg.ports.shadow)),
                p.value(&format!(":{}", cfg.ports.proxy)),
            );
        }
        None => {
            println!(
                "{} {} {}",
                p.dot(Level::Err),
                p.label("adopt"),
                p.error("adoption unavailable on this host"),
            );
            // Exit non-zero. Fail-open governs the user's model TRAFFIC, not CLI
            // exit codes: a command that was asked to change the system and did
            // not must say so, or scripts and CI silently treat a failed adoption
            // as a successful one.
            return Err(crate::Error::Engine(
                "adoption failed — the host was not changed".into(),
            ));
        }
    }

    Ok(())
}

/// `saffev revert` — clean de-adoption (Linux), restoring exact prior state.
pub async fn revert(cli: &Cli, engine: EngineArg) -> Result<()> {
    let p = painter(cli);
    let cfg = load_config(cli).await;
    let name = engine_name(engine);

    println!(
        "{} {}",
        p.prompt("~"),
        p.value(&format!("saffev revert --engine {name}"))
    );

    if !controller_can_adopt(&cfg) {
        // Cooperative installs never made system changes — nothing to revert.
        println!(
            "{} {} {}",
            p.dot(Level::Ok),
            p.label("revert"),
            p.value("cooperative mode — nothing to revert"),
        );
        return Ok(());
    }

    let db_path = cfg.db_path();
    let target = name.to_string();
    let cfg_for_revert = cfg.clone();
    let result = guard("revert", async move {
        let store = crate::store::Store::open(&db_path).await?;
        let engines = store.engines().await?;
        let record = engines.into_iter().find(|e| e.engine == target);
        let Some(record) = record else {
            return Ok(false);
        };
        let journal: Vec<crate::engine::JournalEntry> =
            serde_json::from_str(&record.journal_json).unwrap_or_default();
        // Mode-appropriate controller so a Gateway adoption is undone by the
        // SystemdController (removes the drop-in + service, restores the engine
        // to the public port); cooperative no-op otherwise.
        let controller = crate::engine::default_controller(&cfg_for_revert);
        crate::engine::EngineController::revert(controller.as_ref(), &journal).await?;
        Ok(true)
    })
    .await;

    match result {
        Some(true) => println!(
            "{} {} {}",
            p.dot(Level::Ok),
            p.label("reverted"),
            p.success(&format!("{name} restored to its prior state")),
        ),
        Some(false) => println!(
            "{} {} {}",
            p.dot(Level::Warn),
            p.label("revert"),
            p.warn(&format!("no adoption journal found for {name}")),
        ),
        None => {
            println!(
                "{} {} {}",
                p.dot(Level::Err),
                p.label("revert"),
                p.error("revert unavailable on this host"),
            );
            // Non-zero for the same reason as `adopt`, and it matters more here:
            // a revert that quietly did nothing leaves someone's machine adopted
            // while telling them it is clean.
            return Err(crate::Error::Engine(
                "revert failed — the host may still be adopted".into(),
            ));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// start / stop — proxy + studio + supervisor
// ---------------------------------------------------------------------------

/// Resolve the config path `start` will use, matching `load_config`'s rules:
/// an explicit `--config` wins; otherwise the default data dir's `saffev.toml`.
fn start_config_path(cli: &Cli) -> std::path::PathBuf {
    match &cli.config {
        Some(path) => path.clone(),
        None => Config::default().config_path(),
    }
}

/// Detect which local engine to forward to on first run.
///
/// Probes the well-known engine ports ([`detect::KNOWN_PORTS`] — Ollama `11434`
/// first, then LM Studio `1234`) and returns the port of the first **recognized**
/// engine, preferring Ollama when both are up. An open-but-unrecognized port is
/// ignored. When nothing recognizable answers, falls back to the Ollama default
/// so a later-started engine still works without a config edit.
async fn detect_upstream_port() -> u16 {
    use crate::engine::detect;
    use crate::engine::EngineKind;

    let mut lmstudio_port: Option<u16> = None;
    for &port in detect::KNOWN_PORTS {
        if let Ok(Some(info)) = detect::probe_port(port).await {
            match info.engine {
                // Ollama wins outright (and KNOWN_PORTS lists it first anyway).
                EngineKind::Ollama => return port,
                EngineKind::LmStudio => {
                    lmstudio_port.get_or_insert(port);
                }
                EngineKind::Unknown => {}
            }
        }
    }
    lmstudio_port.unwrap_or(crate::config::DEFAULT_UPSTREAM_PORT)
}

/// The config `start` should run with, plus whether this was a true first run.
///
/// First run = no config file exists yet at the resolved path. We then
/// auto-configure a working Cooperative layout (free proxy/studio ports,
/// upstream kept on the well-known engine port) and **persist** it so later
/// runs are stable. When a config file already exists we honor it exactly,
/// loading via the normal path (falling back to defaults only if the loader is
/// unavailable, consistent with the rest of the CLI's fail-open posture).
async fn resolve_start_config(cli: &Cli) -> (Config, bool) {
    let path = start_config_path(cli);

    // True first run: no file on disk. Build a working layout and write it.
    if !Config::config_file_exists(&path) {
        let data_dir = path
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .map(|d| d.to_path_buf())
            .unwrap_or_else(Config::default_data_dir);

        // Detect which local engine is actually running so Cooperative forwards
        // to the right port — Ollama (11434) or LM Studio (1234). Falls back to
        // the Ollama default when nothing is up yet, so a later-started engine
        // still works without a config edit.
        let upstream_port = detect_upstream_port().await;

        match Config::resolve_first_run(data_dir, upstream_port) {
            Ok(cfg) => {
                // Persist so subsequent runs are stable + fast. Best-effort: a
                // failed write just means the next run re-resolves (still works).
                if let Err(e) = cfg.save_to(&path) {
                    tracing::debug!("could not persist first-run config {}: {e}", path.display());
                }
                return (cfg, true);
            }
            Err(e) => {
                // Could not resolve a working layout (improbable). Fall through to
                // the normal loader, which preserves the prior behavior.
                tracing::debug!("first-run resolution failed, using loader: {e}");
            }
        }
    }

    (load_config(cli).await, false)
}

/// `saffev start` — run the proxy + Studio (+ supervisor in Gateway mode).
///
/// In the foreground (`--foreground`) it binds both servers and blocks until
/// Ctrl-C or SIGTERM, writing a PID file so `saffev stop` can find it. Without
/// `--foreground` it re-execs itself detached into the background, prints the
/// Studio URL, and returns promptly (the backgrounded child writes the PID file).
///
/// **Zero-config first run.** When no config file exists yet, `start` does not
/// error on the well-known engine port; it auto-configures a working Cooperative
/// setup (free proxy/studio ports, upstream left on the engine) and persists it.
/// An existing user config is honored exactly. After a successful background
/// start the Studio is opened in the default browser (best-effort; suppressed by
/// `--no-open`, and never attempted under `--foreground` for CI/headless safety).
pub async fn start(cli: &Cli, foreground: bool, no_open: bool) -> Result<()> {
    let p = painter(cli);
    let (cfg, first_run) = resolve_start_config(cli).await;

    // Background path: detach a `--foreground` copy of ourselves, record its pid
    // + URL, print the URL, and return. The child then runs the foreground flow
    // below (which also writes the PID file, authoritative for the running pid).
    if !foreground {
        return start_background(cli, &cfg, &p, first_run, no_open).await;
    }

    println!("{} {}", p.prompt("~"), p.value("saffev start"));

    let proxy_addr = SocketAddr::new(cfg.ports.bind, cfg.ports.proxy);
    let studio_addr = SocketAddr::new(cfg.ports.bind, cfg.ports.studio);

    // Refuse to start if the proxy port is already taken by a foreign process.
    // On a first run the proxy port was just chosen to be free, so this never
    // fires there; it remains the guard for an existing user config whose proxy
    // port is now held (we keep the current "port in use / run doctor" message).
    let proxy_port = cfg.ports.proxy;
    if !first_run && port_listening(cfg.ports.bind, proxy_port).await {
        // Identify what holds the port so the operator can act. Capture only the
        // port value so `cfg` stays available for the messages below.
        let holder = guard("port diagnosis", async move {
            crate::engine::adopt::diagnose_port_conflict(proxy_port).await
        })
        .await
        .flatten();
        let ours = holder
            .as_ref()
            .is_some_and(|h| holder_is_saffev(h.name.as_deref()));
        let detail = match &holder {
            Some(h) => format!(
                "port {} held by {} (pid {})",
                proxy_port,
                h.name.as_deref().unwrap_or("unknown"),
                h.pid
            ),
            None => format!("port {proxy_port} already in use"),
        };
        println!(
            "{} {} {}",
            p.dot(Level::Err),
            p.label("start"),
            p.error(&detail)
        );
        if ours {
            // Another saffev already serves this port (possibly an orphaned
            // daemon whose pid file was lost) — point at the command that now
            // recovers both cases, instead of the generic doctor advice.
            println!(
                "{} another saffev is already running — run {} first",
                p.muted("·"),
                p.value("saffev stop"),
            );
        } else {
            println!(
                "{} run {} to diagnose, or adopt the engine first",
                p.muted("·"),
                p.value("saffev doctor"),
            );
        }
        return Ok(());
    }

    // The user-facing welcome summary (Studio URL, proxy base, engine status).
    // Under `--foreground` this prints to the live terminal; in the background
    // case the parent prints it instead (the child's stdio is detached).
    print_start_summary(&p, &cfg, first_run).await;

    // Record our pid + Studio URL so `saffev stop` can find and signal us. This
    // is the authoritative running pid (the foreground process actually serving),
    // whether we were launched directly with `--foreground` or re-execed into the
    // background by `start_background`. Best-effort: a failed write just means
    // `stop` falls back to its port-based path.
    let pid_path = daemon::pid_path(&cfg);
    let url = format!(
        "http://{}:{}",
        display_host(cfg.ports.bind),
        cfg.ports.studio
    );
    let pid_record = daemon::PidFile {
        pid: std::process::id(),
        url,
    };
    if let Err(e) = daemon::write_pid_file(&pid_path, &pid_record) {
        tracing::debug!("could not write pid file {}: {e}", pid_path.display());
    }

    println!(
        "{} {}",
        p.muted("·"),
        p.muted("press Ctrl-C (or `saffev stop`) to stop"),
    );

    // Assemble shared state and launch both servers. Each piece is guarded so a
    // stubbed builder can't abort the whole command; if neither server can be
    // built we report cleanly instead of panicking. The servers bind to the
    // ports in `cfg` themselves; the addresses above are for display only.
    let _ = (proxy_addr, studio_addr);
    let launched = run_servers(&cfg).await;

    // Clean up our PID file on the way out (graceful shutdown or bind failure) —
    // but only if it still records OUR pid. During an in-app update-restart the
    // successor daemon may already have written its own pid here; deleting that
    // would orphan it (`stop` couldn't find it and the next update would stick).
    if let Err(e) = daemon::remove_pid_file_if_owned(&pid_path, std::process::id()) {
        tracing::debug!("could not remove pid file {}: {e}", pid_path.display());
    }

    match launched {
        Ok(()) => {
            println!("{} {}", p.dot(Level::Ok), p.muted("stopped"));
            Ok(())
        }
        Err(err) => {
            tracing::debug!("server lifecycle ended: {err}");
            println!(
                "{} {} {}",
                p.dot(Level::Warn),
                p.label("start"),
                p.warn("server components not available in this build"),
            );
            Ok(())
        }
    }
}

/// Detach a `--foreground` copy of this binary into the background, print the
/// Studio URL, and return promptly. The backgrounded child runs the foreground
/// flow (binding the servers and writing the authoritative PID file).
///
/// We write a provisional PID file here too (child pid + URL) so a `stop` issued
/// immediately after start can still find the daemon before the child has
/// rewritten it; the child overwrites it with the same pid on startup.
async fn start_background(
    cli: &Cli,
    cfg: &Config,
    p: &Painter,
    first_run: bool,
    no_open: bool,
) -> Result<()> {
    println!("{} {}", p.prompt("~"), p.value("saffev start"));

    // Refuse to start a second daemon if one is already running (live PID file).
    let pid_path = daemon::pid_path(cfg);
    if let Ok(Some(true)) = daemon::daemon_state(&pid_path) {
        if let Ok(Some(existing)) = daemon::read_pid_file(&pid_path) {
            println!(
                "{} {} {}",
                p.dot(Level::Warn),
                p.label("start"),
                p.warn(&format!("already running (pid {})", existing.pid)),
            );
            if !existing.url.is_empty() {
                println!("{} studio at {}", p.muted("·"), p.value(&existing.url));
            }
            return Ok(());
        }
    }

    // Refuse to start if the proxy port is already taken by a foreign process.
    // Skipped on first run: the proxy port was just chosen to be free, and an
    // engine already holding the well-known port is the expected Cooperative
    // case — not a conflict.
    let proxy_port = cfg.ports.proxy;
    if !first_run && port_listening(cfg.ports.bind, proxy_port).await {
        // Identify the holder so the advice is actionable: another saffev
        // (e.g. an orphaned daemon whose pid file was lost) is recovered with
        // `saffev stop`; anything else keeps the doctor/adopt advice.
        let holder = guard("port diagnosis", async move {
            crate::engine::adopt::diagnose_port_conflict(proxy_port).await
        })
        .await
        .flatten();
        let ours = holder
            .as_ref()
            .is_some_and(|h| holder_is_saffev(h.name.as_deref()));
        let detail = match &holder {
            Some(h) => format!(
                "port {} held by {} (pid {})",
                proxy_port,
                h.name.as_deref().unwrap_or("unknown"),
                h.pid
            ),
            None => format!("port {proxy_port} already in use"),
        };
        println!(
            "{} {} {}",
            p.dot(Level::Err),
            p.label("start"),
            p.error(&detail),
        );
        if ours {
            println!(
                "{} another saffev is already running — run {} first",
                p.muted("·"),
                p.value("saffev stop"),
            );
        } else {
            println!(
                "{} run {} to diagnose, or adopt the engine first",
                p.muted("·"),
                p.value("saffev doctor"),
            );
        }
        return Ok(());
    }

    let url = format!(
        "http://{}:{}",
        display_host(cfg.ports.bind),
        cfg.ports.studio
    );

    // Re-exec ourselves detached, carrying the same global flags so the child
    // resolves the identical config. The child re-resolves config too, but since
    // we already persisted the first-run config above, the child sees a
    // present-and-valid file (no longer a first run for it). We carry `--no-open`
    // for completeness, though the detached child never opens a browser anyway.
    // Background daemons log their tracing stderr to `daemon.log` in the data
    // dir (rotated per start) — otherwise a detached daemon that dies leaves
    // nothing to diagnose.
    let log_path = daemon::log_path(&cfg);
    let pid = match daemon::spawn_background_child(
        cli.config.as_deref(),
        cli.no_color,
        no_open,
        Some(&log_path),
    ) {
        Ok(child) => child.id(),
        Err(e) => {
            tracing::debug!("daemonize failed: {e}");
            println!(
                "{} {} {}",
                p.dot(Level::Err),
                p.label("start"),
                p.error("could not start in the background"),
            );
            println!(
                "{} run {} to run attached instead",
                p.muted("·"),
                p.value("saffev start --foreground"),
            );
            return Ok(());
        }
    };

    // Provisional PID file (the child rewrites it on startup with the same pid).
    let pid_record = daemon::PidFile {
        pid,
        url: url.clone(),
    };
    if let Err(e) = daemon::write_pid_file(&pid_path, &pid_record) {
        tracing::debug!("could not write pid file {}: {e}", pid_path.display());
    }

    println!(
        "{} {} {} {} {}",
        p.dot(Level::Ok),
        p.label("started"),
        p.success(&format!("pid {pid}")),
        p.muted("·"),
        p.muted("background"),
    );

    // The full welcome summary: Studio URL, proxy base URL, engine status.
    print_start_summary(p, cfg, first_run).await;
    println!("{} run {} to stop", p.muted("·"), p.value("saffev stop"),);

    // Best-effort: open the Studio in the default browser. Suppressed by
    // `--no-open`; any failure is ignored (the URL is already printed above).
    if !no_open {
        open_in_browser(&url);
    }

    Ok(())
}

/// Print the friendly post-start summary in the calm palette: the **Studio URL**
/// (prominent), the **proxy base URL** apps point at (with the OpenAI `/v1`
/// note), and the **engine status** (detected via [`crate::engine::detect`], or
/// "not yet running"). On a first run we add a short note that a config was
/// written.
async fn print_start_summary(p: &Painter, cfg: &Config, first_run: bool) {
    let host = display_host(cfg.ports.bind);
    let studio_url = format!("http://{}:{}", host, cfg.ports.studio);
    let proxy_url = format!("http://{}:{}", host, cfg.ports.proxy);

    if first_run {
        println!(
            "{} {} {}",
            p.dot(Level::Ok),
            p.label("first run"),
            p.muted("auto-configured cooperative mode · config saved"),
        );
    }

    // Studio URL — the prominent line the user clicks.
    println!(
        "{} {}      {}",
        p.dot(Level::Ok),
        p.label("studio"),
        p.value(&studio_url),
    );

    // Proxy base — where apps point. Note the OpenAI-compatible base is /v1.
    println!(
        "{} {}       {} {} {}",
        p.dot(Level::Ok),
        p.label("proxy"),
        p.value(&proxy_url),
        p.muted("·"),
        p.muted("OpenAI base: /v1"),
    );

    // Engine status — detect on the configured upstream so the line reflects the
    // engine Saffev actually proxies to. Best-effort: never blocks the summary.
    let upstream_port = match cfg.mode {
        Mode::Gateway => cfg.ports.shadow,
        Mode::Cooperative => cfg.ports.upstream,
    };
    let engine = guard("engine detect", async move {
        crate::engine::detect::probe_upstream(upstream_port).await
    })
    .await
    .flatten();

    match engine {
        Some(info) => {
            let kind = match info.engine {
                crate::engine::EngineKind::Ollama => "ollama",
                crate::engine::EngineKind::LmStudio => "lmstudio",
                crate::engine::EngineKind::Unknown => "engine",
            };
            let version = info
                .version
                .as_deref()
                .map(|v| format!(" v{v}"))
                .unwrap_or_default();
            println!(
                "{} {}      {} {} {}",
                p.dot(Level::Ok),
                p.label("engine"),
                p.success(&format!("{kind}{version}")),
                p.muted("·"),
                p.value(&format!(":{upstream_port}")),
            );
        }
        None => {
            println!(
                "{} {}      {} {} {}",
                p.dot(Level::Warn),
                p.label("engine"),
                p.warn("not yet running"),
                p.muted("·"),
                p.muted(&format!("expected on :{upstream_port}")),
            );
        }
    }

    // The easy way to route an app's traffic here — no per-app config edits.
    // Works for Ollama and LM Studio alike.
    println!(
        "{} {} {}",
        p.muted("·"),
        p.muted("trace any app:"),
        p.value("saffev run -- <your app>"),
    );
}

/// Best-effort: open `url` in the OS default browser. Never blocks (spawns and
/// detaches), never propagates an error — opening the Studio is a convenience,
/// not a requirement. macOS uses `open`; other Unix uses `xdg-open`.
fn open_in_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let opener = "open";
    #[cfg(all(unix, not(target_os = "macos")))]
    let opener = "xdg-open";
    #[cfg(not(unix))]
    let opener = "";

    if opener.is_empty() {
        return;
    }

    let result = std::process::Command::new(opener)
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .stdin(std::process::Stdio::null())
        .spawn();
    if let Err(e) = result {
        tracing::debug!("could not open browser ({opener} {url}): {e}");
    }
}

/// Build state and run the proxy + Studio servers concurrently until shutdown
/// (Ctrl-C). Returns `Err` if the servers can't be constructed at all.
async fn run_servers(cfg: &Config) -> Result<()> {
    use std::sync::Arc;

    // Apply the shared team policy (if one is configured) BEFORE the config is
    // shared with either server, so the protective settings a team agreed on are
    // already in force by the time the first request can arrive. A policy that
    // failed to load never blocks startup, but the failure is recorded and
    // surfaced rather than swallowed — see `crate::policy`.
    let mut cfg_with_policy = cfg.clone();
    if let Some(status) = crate::policy::apply_and_record(&mut cfg_with_policy) {
        // Print, not just log: someone is relying on this file to protect them,
        // so both outcomes have to be visible without going looking for a log.
        if status.active {
            println!(
                "● policy     {} · governs {}",
                status.description.as_deref().unwrap_or(&status.path),
                if status.governs.is_empty() {
                    "nothing".to_string()
                } else {
                    status.governs.join(", ")
                }
            );
        } else {
            eprintln!(
                "● policy     NOT APPLIED · {} · {}",
                status.path,
                status.error.as_deref().unwrap_or("unknown error")
            );
        }
    }
    let cfg = &cfg_with_policy;

    // ONE live, swappable config handle shared by BOTH servers. A Studio
    // `PUT /api/settings` swaps it in place, so the proxy + Studio see
    // hot-reloadable changes (masking / payload / retention) without a restart.
    let config = crate::config::config_handle(cfg.clone());
    // A startup snapshot for the local wiring below (ports/mode that are read once
    // at bind time and are not hot-reloadable anyway).
    let cfg = config.load_full();

    // Open the store (shared by both servers). If the store is a stub this
    // bails to the caller, which reports gracefully.
    let db_path = cfg.db_path();
    let store = guard("store open", async move {
        crate::store::Store::open(&db_path).await
    })
    .await
    .ok_or_else(|| crate::Error::Store("store unavailable".into()))?;

    // Per-install bearer token for the Studio API.
    let token: Arc<str> = guard_infallible("install token", async {
        crate::store::keys::get_or_create_install_token().ok()
    })
    .await
    .flatten()
    .unwrap_or_default()
    .into();

    // Deterministic PII detector shared by the proxy.
    let detector = guard("detector build", {
        let patterns = cfg.custom_patterns.clone();
        async move { crate::brain::pii::Detector::new(&patterns) }
    })
    .await
    .ok_or_else(|| crate::Error::Proxy("detector unavailable".into()))?;
    let detector = Arc::new(detector);

    let upstream_port = match cfg.mode {
        Mode::Gateway => cfg.ports.shadow,
        Mode::Cooperative => cfg.ports.upstream,
    };
    let upstream: Arc<str> =
        format!("http://{}:{}", display_host(cfg.ports.bind), upstream_port).into();

    // Tee channel for proxy -> logger.
    let (tee, rx) = crate::proxy::tee_channel();

    // Eval channel for logger -> async eval worker (safety guard + judge).
    let (eval_tx, eval_rx) = crate::proxy::eval_channel();
    // Shared quality-judge runtime metrics (worker writes, Studio reads).
    let eval_metrics = std::sync::Arc::new(crate::proxy::EvalMetrics::default());

    // Studio live-event broadcast channel.
    let (events, _events_rx) =
        tokio::sync::broadcast::channel(crate::studio::STREAM_CHANNEL_CAPACITY);

    let proxy_state = crate::proxy::ProxyState {
        config: config.clone(),
        store: store.clone(),
        tee,
        detector,
        upstream,
        // Same broadcast channel the Studio SSE endpoint subscribes to, so live
        // exchanges from the proxy reach the Live page in real time.
        events: events.clone(),
        eval_tx,
    };
    let studio_state = crate::studio::StudioState {
        config,
        store,
        token,
        events: events.clone(),
        eval_metrics: eval_metrics.clone(),
    };

    // Drain the tee into the store off the request path.
    crate::proxy::ProxyServer::spawn_logger(proxy_state.clone(), rx);

    // Drain the eval channel: run the safety guard + quality judge off the path.
    crate::proxy::spawn_eval_worker(
        proxy_state.store.clone(),
        proxy_state.config.clone(),
        events,
        proxy_state.upstream.clone(),
        eval_metrics,
        eval_rx,
    );

    // Warm the coding-agent session cache in the background.
    //
    // The per-file parse cache lives in this process, so the FIRST listing after
    // a start pays the full read of every session file (measured at ~27s on a
    // real history). Doing it here means that cost is paid by an idle background
    // task at startup instead of by the operator's first click on the Agents
    // page. Purely a cache fill: no writes, nothing user-visible, and failure
    // just means the page warms lazily as before.
    {
        tokio::spawn(async move {
            let t = std::time::Instant::now();
            let n = tokio::task::spawn_blocking(|| crate::agents::all_sessions().len())
                .await
                .unwrap_or(0);
            tracing::debug!(
                target: "saffev::agents",
                "warmed session cache: {n} sessions in {:?}", t.elapsed()
            );
        });
    }

    // Background maintenance: retention pruning.
    //
    // Promised by the Settings copy ("how long exchanges are kept before
    // pruning") and live-reloadable: every tick re-reads the config handle, so
    // changing retention applies without a restart. Fail-open: a failed pass is
    // logged to the diagnostic log and the next tick tries again; nothing here
    // can touch the request hot path. Auto archive snapshots used to live on
    // this hourly tick too, but hourly is the wrong cadence for a freshness
    // promise — they moved to the Studio's own scheduler
    // (`studio::spawn_archive_scheduler`, default every 5 minutes, first tick
    // immediate = the on-start snapshot).
    {
        let store = proxy_state.store.clone();
        let config = proxy_state.config.clone();
        tokio::spawn(async move {
            // First retention pass shortly after start — the DB may already be
            // over policy from a long downtime.
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            let cfg = config.load();
            if maintenance_plan(&cfg) {
                if let Err(e) = store.enforce_retention(cfg.retention).await {
                    tracing::warn!(target: "saffev::store", "retention pass failed: {e}");
                }
            }

            let mut tick =
                tokio::time::interval(std::time::Duration::from_secs(MAINTENANCE_TICK_SECS));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await; // the first tick completes immediately — drop it
            loop {
                tick.tick().await;
                let cfg = config.load();
                if maintenance_plan(&cfg) {
                    if let Err(e) = store.enforce_retention(cfg.retention).await {
                        tracing::warn!(target: "saffev::store", "retention pass failed: {e}");
                    }
                }
            }
        });
    }

    // Run both servers concurrently under a shared graceful-shutdown signal.
    //
    // A `watch` channel fans the single shutdown trigger (Ctrl-C *or* SIGTERM)
    // out to both servers, which pass it into `axum::serve(..)
    // .with_graceful_shutdown(..)` so in-flight requests drain before the
    // listeners close. `saffev stop` sends SIGTERM; the foreground operator can
    // still press Ctrl-C. The select also exits if either server's bind fails.
    let proxy = crate::proxy::ProxyServer::new(proxy_state);
    let studio = crate::studio::StudioServer::new(studio_state);

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let proxy_shutdown = shutdown_signal(shutdown_rx.clone());
    let studio_shutdown = shutdown_signal(shutdown_rx);

    let proxy_task = tokio::spawn(async move { proxy.serve_with_shutdown(proxy_shutdown).await });
    let studio_task =
        tokio::spawn(async move { studio.serve_with_shutdown(studio_shutdown).await });

    // Trigger shutdown on Ctrl-C or SIGTERM, whichever comes first.
    tokio::select! {
        r = proxy_task => { let _ = r; }
        r = studio_task => { let _ = r; }
        _ = termination_signal() => {
            // Broadcast to both servers; ignore send errors (receivers may have
            // already dropped if a server exited first).
            let _ = shutdown_tx.send(true);
        }
    }

    Ok(())
}

/// Future that resolves on the first OS termination signal: Ctrl-C (SIGINT)
/// everywhere, plus SIGTERM on Unix (what `saffev stop` sends). On non-Unix it
/// is just Ctrl-C. Each branch is best-effort — a failed signal registration
/// simply never fires that branch rather than aborting startup.
async fn termination_signal() {
    #[cfg(unix)]
    {
        let ctrl_c = async {
            let _ = tokio::signal::ctrl_c().await;
        };
        let mut sigterm =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!("SIGTERM handler unavailable: {e}");
                    // Fall back to Ctrl-C only.
                    ctrl_c.await;
                    return;
                }
            };
        tokio::select! {
            _ = ctrl_c => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Adapt a `watch` receiver into a one-shot shutdown future suitable for
/// `with_graceful_shutdown`: resolves the first time the channel carries `true`
/// (or the sender drops). Each server gets its own clone.
async fn shutdown_signal(mut rx: tokio::sync::watch::Receiver<bool>) {
    // If it's already `true` (raced), return immediately; otherwise wait for the
    // next change to a truthy value. A dropped sender also ends the wait.
    if *rx.borrow() {
        return;
    }
    while rx.changed().await.is_ok() {
        if *rx.borrow() {
            return;
        }
    }
}

/// `saffev stop` — stop the proxy + Studio + supervisor.
///
/// Reads the PID file written by `start` and asks the OS to terminate the daemon,
/// then waits briefly for the process to exit and removes the PID file. On Unix
/// this is a graceful `SIGTERM` (the servers drain in-flight requests via
/// `with_graceful_shutdown`); on Windows it is `taskkill /T` (no SIGTERM
/// equivalent — less graceful, but the SQLite WAL keeps the store consistent —
/// see [`daemon::send_terminate`]). A **stale** PID file (the recorded process is
/// no longer alive) is cleaned up gracefully. When there is no PID file but a
/// Saffev-looking proxy is up, we report that the running instance is unmanaged
/// (foreground in another terminal: Ctrl-C there).
/// Is a port-holder's process name our own binary? Matches on the executable's
/// file name (the diagnosis may report a full path, e.g.
/// `/Users/you/.cargo/bin/saffev`), tolerating a Windows `.exe` suffix. Used to
/// decide whether an unmanaged port holder is a recoverable orphaned daemon.
fn holder_is_saffev(name: Option<&str>) -> bool {
    let Some(name) = name else { return false };
    let file = std::path::Path::new(name.trim())
        .file_name()
        .map(|f| f.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    file == crate::brand::APP_CMD || file == format!("{}.exe", crate::brand::APP_CMD)
}

pub async fn stop(cli: &Cli) -> Result<()> {
    let p = painter(cli);
    let cfg = load_config(cli).await;

    println!("{} {}", p.prompt("~"), p.value("saffev stop"));

    let pid_path = daemon::pid_path(&cfg);
    let record = match daemon::read_pid_file(&pid_path) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("reading pid file {} failed: {e}", pid_path.display());
            None
        }
    };

    // No PID file: probe the configured ports. If one is held by a *saffev*
    // process, that's an ORPHANED daemon (pid file lost to a crash, manual
    // delete, or a cleanup race) — recover it like a managed stop, so the
    // in-app "Update & restart" can never get stuck behind a missing pid file.
    // A foreign holder (or an unidentifiable one) keeps the honest warning:
    // we never terminate a process we can't attribute to ourselves.
    let Some(record) = record else {
        let studio_up = port_listening(cfg.ports.bind, cfg.ports.studio).await;
        let proxy_up = port_listening(cfg.ports.bind, cfg.ports.proxy).await;
        if !(studio_up || proxy_up) {
            println!(
                "{} {} {}",
                p.dot(Level::Ok),
                p.label("stop"),
                p.value("not running"),
            );
            return Ok(());
        }

        // Prefer the Studio port for attribution — only saffev ever serves it
        // (the proxy port could legitimately be a relocated engine in Gateway).
        let probe_port = if studio_up {
            cfg.ports.studio
        } else {
            cfg.ports.proxy
        };
        let holder = guard("port diagnosis", async move {
            crate::engine::adopt::diagnose_port_conflict(probe_port).await
        })
        .await
        .flatten();

        match holder {
            Some(h) if holder_is_saffev(h.name.as_deref()) => {
                println!(
                    "{} {} {}",
                    p.dot(Level::Warn),
                    p.label("stop"),
                    p.warn(&format!(
                        "orphaned daemon on port {} (pid {}, no pid file) — recovering",
                        probe_port, h.pid
                    )),
                );
                if let Err(e) = daemon::send_terminate(h.pid) {
                    tracing::debug!("terminating orphaned {} failed: {e}", h.pid);
                }
                let exited = daemon::wait_for_exit(
                    h.pid,
                    Duration::from_secs(5),
                    Duration::from_millis(100),
                )
                .await;
                if exited {
                    println!(
                        "{} {} {}",
                        p.dot(Level::Ok),
                        p.label("stopped"),
                        p.success(&format!("orphaned pid {} shut down gracefully", h.pid)),
                    );
                } else {
                    println!(
                        "{} {} {}",
                        p.dot(Level::Warn),
                        p.label("stop"),
                        p.warn(&format!(
                            "pid {} did not exit within 5s — re-run `saffev stop` to retry",
                            h.pid
                        )),
                    );
                }
            }
            _ => {
                println!(
                    "{} {} {}",
                    p.dot(Level::Warn),
                    p.label("stop"),
                    p.warn("running but unmanaged (no pid file) — press Ctrl-C in its terminal"),
                );
            }
        }
        return Ok(());
    };

    // Stale PID file: the recorded process is gone. Clean it up and report.
    if !daemon::process_alive(record.pid) {
        if let Err(e) = daemon::remove_pid_file(&pid_path) {
            tracing::debug!("removing stale pid file failed: {e}");
        }
        println!(
            "{} {} {}",
            p.dot(Level::Ok),
            p.label("stop"),
            p.value(&format!("not running (cleared stale pid {})", record.pid)),
        );
        return Ok(());
    }

    // In Gateway mode, stopping honors the handover policy so the engine never
    // goes offline unless explicitly configured to stop with Saffev. (The
    // supervisor itself applies the policy on shutdown; we surface it here.)
    if cfg.mode == Mode::Gateway {
        let policy = match cfg.handover {
            HandoverPolicy::Handover => "handover — engine stays serving",
            HandoverPolicy::Stop => "stop — engine stops with Saffev",
        };
        println!(
            "{} {} {}",
            p.dot(Level::Ok),
            p.label("handover"),
            p.value(policy)
        );
    }

    // Ask the OS to terminate the daemon (SIGTERM on unix; taskkill on Windows),
    // then wait briefly for the process to exit.
    if let Err(e) = daemon::send_terminate(record.pid) {
        tracing::debug!("terminating {} failed: {e}", record.pid);
    }

    let exited = daemon::wait_for_exit(
        record.pid,
        Duration::from_secs(5),
        Duration::from_millis(100),
    )
    .await;

    if exited {
        // The daemon removes its own PID file on clean exit; remove it here too
        // in case it couldn't — but only while it still records the pid we
        // stopped, so we can't race a successor that already wrote its own.
        if let Err(e) = daemon::remove_pid_file_if_owned(&pid_path, record.pid) {
            tracing::debug!("removing pid file after stop failed: {e}");
        }
        println!(
            "{} {} {}",
            p.dot(Level::Ok),
            p.label("stopped"),
            p.success(&format!("pid {} shut down gracefully", record.pid)),
        );
    } else {
        // Did not exit within the grace window. Leave the PID file in place so a
        // follow-up `stop` can retry; report rather than force-kill (fail-open:
        // we never escalate to SIGKILL automatically).
        println!(
            "{} {} {}",
            p.dot(Level::Warn),
            p.label("stop"),
            p.warn(&format!(
                "pid {} did not exit within 5s — re-run `saffev stop` to retry",
                record.pid
            )),
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// doctor — port conflicts + exposure + permissions
// ---------------------------------------------------------------------------

/// `saffev doctor` — port conflicts, exposed bindings, stuck engines, perms.
pub async fn doctor(cli: &Cli) -> Result<()> {
    let p = painter(cli);
    let cfg = load_config(cli).await;

    println!("{} {}", p.prompt("~"), p.value("saffev doctor"));

    let mut warnings = 0u32;

    // --- engine detection -------------------------------------------------
    let engines = guard("engine detect", async {
        crate::engine::detect::detect_all().await
    })
    .await
    .unwrap_or_default();
    if engines.is_empty() {
        // Fall back to a direct probe of the well-known ports.
        let ollama_up = port_listening(cfg.ports.bind, crate::config::DEFAULT_UPSTREAM_PORT).await;
        if ollama_up {
            println!(
                "{} {} engine answering on {} (kind unidentified)",
                p.dot(Level::Ok),
                p.label("engine"),
                p.value(&format!(":{}", crate::config::DEFAULT_UPSTREAM_PORT)),
            );
        } else {
            warnings += 1;
            println!(
                "{} {} {}",
                p.dot(Level::Warn),
                p.label("engine"),
                p.warn("no engine detected on known ports"),
            );
        }
    } else {
        for info in &engines {
            let kind = match info.engine {
                crate::engine::EngineKind::Ollama => "ollama",
                crate::engine::EngineKind::LmStudio => "lmstudio",
                crate::engine::EngineKind::Unknown => "unknown",
            };
            println!(
                "{} {} {} on {}{}",
                p.dot(Level::Ok),
                p.label("engine"),
                p.value(kind),
                p.value(&format!(":{}", info.port)),
                info.version
                    .as_deref()
                    .map(|v| format!(" v{v}"))
                    .unwrap_or_default(),
            );
        }
    }

    // --- capture mode -----------------------------------------------------
    // Make the Cooperative-vs-Gateway distinction explicit: which traffic is
    // actually being captured, and (in Cooperative) how to route an app.
    println!(
        "{} {} {} {} {}",
        p.dot(Level::Ok),
        p.label("mode"),
        p.value(mode_str(cfg.mode)),
        p.muted("·"),
        p.muted(capture_note(cfg.mode)),
    );

    // --- port-conflict check on the public proxy port ---------------------
    let proxy_port = cfg.ports.proxy;
    let proxy_busy = port_listening(cfg.ports.bind, proxy_port).await;
    if proxy_busy {
        let holder = guard("port diagnosis", async move {
            crate::engine::adopt::diagnose_port_conflict(proxy_port).await
        })
        .await
        .flatten();
        match holder {
            Some(h) => {
                let who = h.name.unwrap_or_else(|| "unknown".to_string());
                // The engine itself holding the port is fine (cooperative).
                let benign = cfg.mode == Mode::Cooperative;
                if benign {
                    println!(
                        "{} {} {} held by {} (pid {})",
                        p.dot(Level::Ok),
                        p.label("port"),
                        p.value(&format!(":{proxy_port}")),
                        p.value(&who),
                        p.value(&h.pid.to_string()),
                    );
                } else {
                    warnings += 1;
                    println!(
                        "{} {} {} held by {} (pid {}) — adopt to relocate",
                        p.dot(Level::Warn),
                        p.label("port"),
                        p.value(&format!(":{proxy_port}")),
                        p.warn(&who),
                        p.value(&h.pid.to_string()),
                    );
                }
            }
            None => {
                println!(
                    "{} {} {} in use",
                    p.dot(Level::Ok),
                    p.label("port"),
                    p.value(&format!(":{proxy_port}")),
                );
            }
        }
    } else {
        println!(
            "{} {} {} free",
            p.dot(Level::Ok),
            p.label("port"),
            p.value(&format!(":{proxy_port}")),
        );
    }

    // --- studio port ------------------------------------------------------
    let studio_busy = port_listening(cfg.ports.bind, cfg.ports.studio).await;
    println!(
        "{} {} {} {}",
        p.dot(Level::Ok),
        p.label("studio"),
        p.value(&format!(":{}", cfg.ports.studio)),
        if studio_busy {
            p.value("in use")
        } else {
            p.muted("free")
        },
    );

    // --- exposure ---------------------------------------------------------
    let upstream_port = match cfg.mode {
        Mode::Gateway => cfg.ports.shadow,
        Mode::Cooperative => cfg.ports.upstream,
    };
    let report = guard("exposure check", async move {
        crate::exposure::check(upstream_port).await
    })
    .await;
    match report {
        Some(r) if r.exposed => {
            warnings += 1;
            println!(
                "{} {} {}",
                p.dot(Level::Err),
                p.label("exposure"),
                p.error(&format!(
                    "engine exposed on {} — {}",
                    r.bound_to.clone().unwrap_or_else(|| "non-loopback".into()),
                    r.detail
                )),
            );
            println!(
                "{} run {} to rebind to localhost",
                p.muted("·"),
                p.value("saffev doctor --fix"),
            );
        }
        Some(_) => println!(
            "{} {} {}",
            p.dot(Level::Ok),
            p.label("exposure"),
            p.success("localhost-only ✓"),
        ),
        None => {
            // Fall back to the configured bind address.
            if cfg.ports.bind.is_loopback() {
                println!(
                    "{} {} {}",
                    p.dot(Level::Ok),
                    p.label("exposure"),
                    p.success("bound to loopback ✓"),
                );
            } else {
                warnings += 1;
                println!(
                    "{} {} {}",
                    p.dot(Level::Warn),
                    p.label("exposure"),
                    p.warn(&format!("bound to {} — verify exposure", cfg.ports.bind)),
                );
            }
        }
    }

    // --- data dir / permissions ------------------------------------------
    let data_dir = cfg.data_dir.clone();
    let dir_ok = data_dir.exists() || std::fs::create_dir_all(&data_dir).is_ok();
    if dir_ok {
        let writable = is_writable(&data_dir);
        if writable {
            println!(
                "{} {} {} {} retention {}",
                p.dot(Level::Ok),
                p.label("data"),
                p.value(&data_dir.display().to_string()),
                p.muted("·"),
                p.value(&retention_str(cfg.retention)),
            );
        } else {
            warnings += 1;
            println!(
                "{} {} {}",
                p.dot(Level::Warn),
                p.label("data"),
                p.warn(&format!("{} not writable", data_dir.display())),
            );
        }
    } else {
        warnings += 1;
        println!(
            "{} {} {}",
            p.dot(Level::Err),
            p.label("data"),
            p.error(&format!("cannot create {}", data_dir.display())),
        );
    }

    // --- summary ----------------------------------------------------------
    if warnings == 0 {
        println!("{} {}", p.dot(Level::Ok), p.success("all checks passed"));
    } else {
        println!(
            "{} {}",
            p.dot(Level::Warn),
            p.warn(&format!(
                "{warnings} issue{} found",
                if warnings == 1 { "" } else { "s" }
            )),
        );
    }

    Ok(())
}

/// Best-effort directory writability probe (creates and removes a temp file).
fn is_writable(dir: &std::path::Path) -> bool {
    let probe = dir.join(".saffev-write-probe");
    match std::fs::write(&probe, b"") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// logs — tail recent activity
// ---------------------------------------------------------------------------

/// `saffev logs` — stream recent activity. With `--follow`, poll for new rows.
pub async fn logs(cli: &Cli, follow: bool) -> Result<()> {
    let p = painter(cli);
    let cfg = load_config(cli).await;

    let db_path = cfg.db_path();
    let store = guard("store open", {
        let db_path = db_path.clone();
        async move { crate::store::Store::open(&db_path).await }
    })
    .await;

    let Some(store) = store else {
        println!(
            "{} {}",
            p.dot(Level::Warn),
            p.warn("no log store available yet (start Saffev to begin recording)"),
        );
        return Ok(());
    };

    // Initial page: most recent rows.
    let initial = guard("store history", {
        let store = store.clone();
        async move {
            store
                .history(crate::store::HistoryQuery {
                    q: None,
                    pii_only: false,
                    failed_only: false,
                    limit: Some(50),
                    before_ts: None,
                })
                .await
        }
    })
    .await
    .unwrap_or_default();

    if initial.is_empty() {
        println!("{} {}", p.muted("~"), p.muted("no activity recorded yet"));
    }

    // History comes newest-first; print oldest-first so a tail reads naturally.
    let mut seen_max_ts: i64 = 0;
    for row in initial.iter().rev() {
        print_log_row(&p, row);
        seen_max_ts = seen_max_ts.max(row.request.ts);
    }

    if !follow {
        return Ok(());
    }

    // Follow loop: poll for rows newer than the last seen ts. Resilient to the
    // store being a stub — any panic/err just yields no new rows.
    loop {
        tokio::time::sleep(Duration::from_millis(750)).await;
        let after = seen_max_ts;
        let batch = guard("store history follow", {
            let store = store.clone();
            async move {
                store
                    .history(crate::store::HistoryQuery {
                        q: None,
                        pii_only: false,
                        failed_only: false,
                        limit: Some(200),
                        before_ts: None,
                    })
                    .await
            }
        })
        .await
        .unwrap_or_default();

        let mut fresh: Vec<&crate::store::HistoryRow> =
            batch.iter().filter(|r| r.request.ts > after).collect();
        fresh.sort_by_key(|r| r.request.ts);
        for row in fresh {
            print_log_row(&p, row);
            seen_max_ts = seen_max_ts.max(row.request.ts);
        }
    }
}

/// Render one history row as a calm, aligned log line.
fn print_log_row(p: &Painter, row: &crate::store::HistoryRow) {
    let req = &row.request;
    let app = req.source_app.as_deref().unwrap_or("unknown");
    let model = req.model.as_deref().unwrap_or("—");
    let lat = req
        .latency_ms
        .map(|ms| format!("{ms}ms"))
        .unwrap_or_else(|| "—".to_string());
    let ts = format_clock(req.ts);

    let pii = if row.pii_count > 0 {
        format!(
            " {} {}",
            p.muted("·"),
            p.error(&format!("{} PII", row.pii_count))
        )
    } else {
        String::new()
    };

    println!(
        "{} {} {} {} {} {} {} {} {}{}",
        p.muted(&ts),
        p.success("●"),
        p.label(app),
        p.muted("▸"),
        p.value(model),
        p.muted(&req.endpoint),
        p.muted("·"),
        p.value(&lat),
        p.muted(if req.stream { "stream" } else { "unary" }),
        pii,
    );
}

/// Format a unix-millis timestamp as `HH:MM:SS` local-ish wall clock. Uses a
/// dependency-free seconds-of-day computation (good enough for a tail prefix).
fn format_clock(ts_millis: i64) -> String {
    let secs = (ts_millis / 1000).rem_euclid(86_400);
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

// ---------------------------------------------------------------------------
// update — in-app auto-update (axoupdater)
// ---------------------------------------------------------------------------

/// `saffev update` — check for and install a newer release.
///
/// Drives [`crate::update`], which reads the cargo-dist install receipt, queries
/// the latest GitHub release, and (re-)runs the shipped installer. With `--check`
/// it only reports availability.
///
/// PRIVACY: this contacts GitHub release metadata ONLY — no user or content data
/// leaves the device, consistent with the on-device invariant.
///
/// NO-RECEIPT (dev / `cargo install` builds): we print the current version and a
/// clear message that updates are available for installs done via the installer.
/// We never panic — the check is wrapped in [`guard_infallible`] for belt-and-
/// braces isolation, and the apply path returns a typed error we render calmly.
pub async fn update(cli: &Cli, check_only: bool) -> Result<()> {
    let p = painter(cli);

    println!(
        "{} {}",
        p.prompt("~"),
        p.value(if check_only {
            "saffev update --check"
        } else {
            "saffev update"
        })
    );

    // The check is fail-soft and never errors; still isolate it on a task so an
    // unexpected panic in a dependency can never abort the command.
    let status = guard_infallible("update check", crate::update::check())
        .await
        .unwrap_or_else(|| crate::update::UpdateStatus {
            current_version: crate::update::CURRENT_VERSION.to_string(),
            latest_version: None,
            available: false,
        });

    println!(
        "{} {} {}",
        p.dot(Level::Ok),
        p.label("current"),
        p.value(&format!("v{}", status.current_version)),
    );

    match (&status.latest_version, status.available) {
        // A newer release exists.
        (Some(latest), true) => {
            println!(
                "{} {} {}",
                p.dot(Level::Warn),
                p.label("latest"),
                p.warn(&format!("v{latest} available")),
            );
            if check_only {
                println!(
                    "{} run {} to install",
                    p.muted("·"),
                    p.value("saffev update"),
                );
                return Ok(());
            }
            apply_update(&p, &status.current_version).await;
        }
        // Up to date (latest known and equal/older).
        (Some(latest), false) => {
            println!(
                "{} {} {}",
                p.dot(Level::Ok),
                p.label("latest"),
                p.success(&format!("v{latest} — up to date")),
            );
        }
        // Couldn't determine the latest version (offline / no release / etc.).
        (None, _) => {
            println!(
                "{} {} {}",
                p.dot(Level::Warn),
                p.label("latest"),
                p.warn("couldn't check (offline or no release found)"),
            );
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Zero-config capture: `saffev run` / `env` / `shell`
// ---------------------------------------------------------------------------

/// Load the config the running daemon uses. Returns `None` on a true first run
/// (no config file yet): the stock default proxy port is the *engine's* port, so
/// injecting from a default config would misroute an app — callers must guide the
/// user to `saffev start` instead.
fn load_running_config(cli: &Cli) -> Option<Config> {
    let path = start_config_path(cli);
    if !Config::config_file_exists(&path) {
        return None;
    }
    Config::load_from(&path).ok()
}

/// Resolve the proxy config to inject into a child, honoring `--start`/`--require`.
///
/// Fail-open by design: we inject **only when the proxy is actually reachable**,
/// so we never point an app at a dead port and break its model calls. If the
/// proxy is down we (a) exit non-zero under `--require`, or (b) warn and return
/// `None` so the command still runs — just untraced. With `auto_start` we start
/// the daemon in the background and wait briefly for it to answer.
async fn resolve_capture_target(
    cli: &Cli,
    auto_start: bool,
    require: bool,
    p: &Painter,
) -> Option<Config> {
    if let Some(c) = load_running_config(cli) {
        if port_listening(c.ports.bind, c.ports.proxy).await {
            return Some(c);
        }
    }

    if auto_start {
        println!("{} {}", p.muted("·"), p.muted("starting Saffev…"));
        // Background start (no browser); first run also persists a fresh config.
        let _ = start(cli, false, true).await;
        if let Some(c) = load_running_config(cli) {
            for _ in 0..20 {
                if port_listening(c.ports.bind, c.ports.proxy).await {
                    return Some(c);
                }
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    }

    if require {
        println!(
            "{} {} {}",
            p.dot(Level::Err),
            p.label("run"),
            p.error("Saffev proxy is not reachable (--require) — run `saffev start` first."),
        );
        std::process::exit(1);
    }

    println!(
        "{} {}",
        p.dot(Level::Warn),
        p.warn("Saffev proxy isn't reachable — running without tracing. Run `saffev start`, or drop --no-start to auto-start."),
    );
    None
}

/// Apply the capture env (+ a placeholder OpenAI key when the user has none) to a
/// child process command, and print a one-line "tracing via …" confirmation.
fn apply_capture_env(c: &mut tokio::process::Command, cfg: &Config, p: &Painter, suffix: &str) {
    for (k, v) in capture::capture_env(cfg) {
        c.env(k, v);
    }
    // OpenAI SDKs refuse to construct a client without *some* key. Set a
    // placeholder only when the user hasn't provided one (never clobber a real key).
    if std::env::var_os("OPENAI_API_KEY").is_none() {
        c.env("OPENAI_API_KEY", capture::PLACEHOLDER_OPENAI_KEY);
    }
    println!(
        "{} {} {}",
        p.dot(Level::Ok),
        p.label("tracing"),
        p.muted(&format!("via {}{}", cfg.proxy_base_url(), suffix)),
    );
}

/// `saffev run -- <cmd…>` — run a command with LLM traffic routed through Saffev.
pub async fn run_cmd(
    cli: &Cli,
    auto_start: bool,
    require: bool,
    command: Vec<String>,
) -> Result<()> {
    let p = painter(cli);

    let (program, args) = match command.split_first() {
        Some((prog, rest)) => (prog.clone(), rest.to_vec()),
        None => {
            // clap enforces required=true; stay defensive.
            println!(
                "{} {}",
                p.dot(Level::Err),
                p.error("nothing to run — usage: saffev run -- <command> [args…]"),
            );
            return Ok(());
        }
    };

    let target = resolve_capture_target(cli, auto_start, require, &p).await;

    let mut c = tokio::process::Command::new(&program);
    c.args(&args);
    if let Some(cfg) = &target {
        apply_capture_env(&mut c, cfg, &p, "");
    }

    // Child inherits our stdio. Block on it and propagate its exit code so
    // `saffev run` is transparent in scripts and pipelines.
    match c.status().await {
        Ok(status) => std::process::exit(status.code().unwrap_or(0)),
        Err(e) => {
            println!(
                "{} {} {}",
                p.dot(Level::Err),
                p.label("run"),
                p.error(&format!("could not run `{program}`: {e}")),
            );
            Ok(())
        }
    }
}

/// `saffev shell` — launch an interactive shell with traffic routed through Saffev.
pub async fn shell_cmd(cli: &Cli, auto_start: bool) -> Result<()> {
    let p = painter(cli);
    let target = resolve_capture_target(cli, auto_start, false, &p).await;

    let program = interactive_shell();
    let mut c = tokio::process::Command::new(&program);
    if let Some(cfg) = &target {
        apply_capture_env(&mut c, cfg, &p, " — type `exit` to stop");
    } else {
        println!(
            "{} {}",
            p.dot(Level::Warn),
            p.warn("launching a normal shell (no tracing)."),
        );
    }

    match c.status().await {
        Ok(status) => std::process::exit(status.code().unwrap_or(0)),
        Err(e) => {
            println!(
                "{} {} {}",
                p.dot(Level::Err),
                p.label("shell"),
                p.error(&format!("could not launch `{program}`: {e}")),
            );
            Ok(())
        }
    }
}

/// `saffev env` — print eval-able shell exports (stdout stays pure; notes go to
/// stderr) that route this shell's LLM traffic through Saffev.
pub async fn env_cmd(cli: &Cli, shell: Option<String>, json: bool) -> Result<()> {
    let cfg = match load_running_config(cli) {
        Some(c) => c,
        None => {
            eprintln!(
                "# Saffev isn't set up yet — run `saffev start` first, then: eval \"$(saffev env)\""
            );
            std::process::exit(1);
        }
    };

    // Notes go to stderr so `eval "$(saffev env)"` only ever consumes exports.
    if !port_listening(cfg.ports.bind, cfg.ports.proxy).await {
        eprintln!(
            "# note: Saffev proxy ({}) isn't responding yet — start it with `saffev start`.",
            cfg.proxy_base_url()
        );
    }

    if json {
        println!("{}", capture::render_env_json(&cfg));
        return Ok(());
    }

    let fmt = match shell {
        Some(s) => match capture::EnvFormat::parse(&s) {
            Some(f) => f,
            None => {
                eprintln!("# unknown --shell '{s}' (use bash|zsh|fish|powershell)");
                std::process::exit(2);
            }
        },
        None => default_env_format(),
    };
    print!("{}", capture::render_env(&cfg, fmt));
    Ok(())
}

#[cfg(windows)]
fn default_env_format() -> capture::EnvFormat {
    capture::EnvFormat::PowerShell
}
#[cfg(not(windows))]
fn default_env_format() -> capture::EnvFormat {
    capture::EnvFormat::detect()
}

#[cfg(windows)]
fn interactive_shell() -> String {
    std::env::var("COMSPEC").unwrap_or_else(|_| "powershell.exe".to_string())
}
#[cfg(not(windows))]
fn interactive_shell() -> String {
    std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string())
}

/// Apply an available update, rendering progress + the no-receipt guidance.
/// Never panics: the typed [`crate::update::UpdateError`] is matched and printed.
async fn apply_update(p: &Painter, current: &str) {
    println!("{} {}", p.muted("·"), p.muted("downloading + installing…"));

    match crate::update::apply().await {
        Ok(outcome) if outcome.updated => {
            println!(
                "{} {} {}",
                p.dot(Level::Ok),
                p.label("updated"),
                p.success(&format!("v{current} → v{} installed", outcome.new_version)),
            );
            println!(
                "{} restart Saffev to run the new version ({})",
                p.muted("·"),
                p.value("saffev stop && saffev start"),
            );
        }
        // Apply ran but found nothing to do (raced with the check, or already
        // current). Report calmly rather than implying a failure.
        Ok(outcome) => {
            println!(
                "{} {} {}",
                p.dot(Level::Ok),
                p.label("update"),
                p.success(&format!("already on v{}", outcome.new_version)),
            );
        }
        // Dev / cargo-install build (no receipt) or the macOS DMG .app (which
        // updates by replacing the app): friendly guidance, never a crash.
        Err(crate::update::UpdateError::NoReceipt(msg))
        | Err(crate::update::UpdateError::UnsupportedInstall(msg)) => {
            println!(
                "{} {} {}",
                p.dot(Level::Warn),
                p.label("update"),
                p.warn(&msg),
            );
            println!(
                "{} releases: {}",
                p.muted("·"),
                p.value(crate::update::RELEASES_URL),
            );
        }
        // A genuine apply failure — surface it (the operator asked to update).
        Err(crate::update::UpdateError::Failed(msg)) => {
            println!(
                "{} {} {}",
                p.dot(Level::Err),
                p.label("update"),
                p.error(&format!("update failed: {msg}")),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// small shared bits
// ---------------------------------------------------------------------------

/// Whether Gateway adoption is available for this config/host. Gateway is
/// Linux-only in v0; everywhere else we run Cooperative.
fn controller_can_adopt(cfg: &Config) -> bool {
    cfg.mode == Mode::Gateway && cfg!(target_os = "linux")
}

/// Cadence of the background maintenance loop (retention pruning). Hourly:
/// retention policies are day/size-grained, so finer ticks buy nothing. Archive
/// snapshots run on their own, much faster clock — see
/// `studio::spawn_archive_scheduler`.
const MAINTENANCE_TICK_SECS: u64 = 60 * 60;

/// Whether a maintenance tick should prune under `cfg`.
///
/// Pure gate logic, split out so it is testable without running the loop:
/// prune unless retention is `Unlimited` (skipping avoids opening a writer
/// connection just to no-op).
fn maintenance_plan(cfg: &Config) -> bool {
    !matches!(cfg.retention, crate::config::Retention::Unlimited)
}

/// Does a detected engine match the requested [`EngineArg`]?
fn engine_matches(info: &crate::engine::EngineInfo, want: EngineArg) -> bool {
    matches!(
        (info.engine, want),
        (crate::engine::EngineKind::Ollama, EngineArg::Ollama)
            | (crate::engine::EngineKind::LmStudio, EngineArg::Lmstudio)
    )
}

/// Display host for URLs: unspecified binds (`0.0.0.0`) read better as
/// `localhost` in copy-paste snippets.
fn display_host(bind: IpAddr) -> String {
    if bind.is_unspecified() || bind.is_loopback() {
        "localhost".to_string()
    } else {
        bind.to_string()
    }
}

/// Built-in cooperative setup snippet, used when the engine module's snippet
/// renderer is unavailable. Points an OpenAI-compatible client at the proxy.
fn default_setup_snippet(proxy_url: &str) -> String {
    format!("export OPENAI_BASE_URL={proxy_url}/v1\nexport OPENAI_API_KEY=local")
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn maintenance_plan_gates_prune() {
        use crate::config::Retention;

        let mut cfg = Config::default();

        // Defaults: 30-day retention prunes.
        cfg.retention = Retention::default();
        assert!(maintenance_plan(&cfg));

        // Unlimited retention must not open a writer just to no-op.
        cfg.retention = Retention::Unlimited;
        assert!(!maintenance_plan(&cfg));

        // Size-based retention prunes too.
        cfg.retention = Retention::Size { mb: 512 };
        assert!(maintenance_plan(&cfg));

        // (Archive snapshot gating lives in `studio::should_run` now, next to
        // the scheduler that uses it.)
    }

    #[test]
    fn holder_is_saffev_matches_only_our_binary() {
        // Bare name, full path, and Windows .exe all attribute to us.
        assert!(holder_is_saffev(Some("saffev")));
        assert!(holder_is_saffev(Some("/Users/you/.cargo/bin/saffev")));
        assert!(holder_is_saffev(Some("saffev.exe"))); // Windows tasklist name
        assert!(holder_is_saffev(Some("  saffev  "))); // ps padding
                                                       // Foreign processes (and the unknown case) never match — we must not
                                                       // terminate something we can't attribute to ourselves.
        assert!(!holder_is_saffev(Some("ollama")));
        assert!(!holder_is_saffev(Some("/usr/local/bin/node")));
        assert!(!holder_is_saffev(Some("saffev-helper")));
        assert!(!holder_is_saffev(None));
    }

    #[test]
    fn group_thousands_formats() {
        assert_eq!(group_thousands(0), "0");
        assert_eq!(group_thousands(7), "7");
        assert_eq!(group_thousands(42), "42");
        assert_eq!(group_thousands(999), "999");
        assert_eq!(group_thousands(1_000), "1,000");
        assert_eq!(group_thousands(1_284), "1,284");
        assert_eq!(group_thousands(12_345), "12,345");
        assert_eq!(group_thousands(1_000_000), "1,000,000");
    }

    #[test]
    fn mode_and_engine_strings() {
        assert_eq!(mode_str(Mode::Gateway), "gateway");
        assert_eq!(mode_str(Mode::Cooperative), "cooperative");
        assert_eq!(engine_name(EngineArg::Ollama), "ollama");
        assert_eq!(engine_name(EngineArg::Lmstudio), "lmstudio");
    }

    #[test]
    fn retention_strings() {
        assert_eq!(retention_str(Retention::Age { days: 30 }), "30d");
        assert_eq!(retention_str(Retention::Size { mb: 500 }), "500mb");
        assert_eq!(retention_str(Retention::Unlimited), "unlimited");
    }

    #[test]
    fn display_host_normalizes() {
        assert_eq!(display_host(IpAddr::V4(Ipv4Addr::LOCALHOST)), "localhost");
        assert_eq!(display_host(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), "localhost");
        assert_eq!(
            display_host(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
            "192.168.1.10"
        );
    }

    #[test]
    fn format_clock_is_hms() {
        // 1 hour, 1 minute, 1 second past midnight UTC, in millis.
        let ts = (3600 + 60 + 1) * 1000;
        assert_eq!(format_clock(ts), "01:01:01");
        assert_eq!(format_clock(0), "00:00:00");
    }

    #[test]
    fn default_snippet_points_at_proxy() {
        let s = default_setup_snippet("http://localhost:11434");
        assert!(s.contains("http://localhost:11434/v1"));
        assert!(s.contains("OPENAI_BASE_URL"));
    }

    #[test]
    fn controller_can_adopt_requires_gateway() {
        let mut cfg = Config::default();
        cfg.mode = Mode::Cooperative;
        assert!(!controller_can_adopt(&cfg));
        cfg.mode = Mode::Gateway;
        // On non-Linux this is false; on Linux true. Assert it matches cfg!.
        assert_eq!(controller_can_adopt(&cfg), cfg!(target_os = "linux"));
    }

    #[tokio::test]
    async fn port_listening_false_for_unused_port() {
        // Port 1 on loopback is virtually never listening in CI.
        let up = port_listening(IpAddr::V4(Ipv4Addr::LOCALHOST), 1).await;
        assert!(!up);
    }

    #[tokio::test]
    async fn load_config_falls_back_to_defaults() {
        // A malformed config must still yield a usable default rather than
        // aborting the command. Hermetic by construction: it points at a temp
        // file, never the real data dir (`config: None` would read the operator's
        // actual config and make the assertion depend on this machine).
        let dir = std::env::temp_dir().join(format!("saffev-cfg-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("saffev.toml");
        std::fs::write(&path, "this is not = valid toml [[[").unwrap();

        let cli = Cli {
            config: Some(path),
            no_color: true,
            command: crate::cli::Command::Status,
        };
        let cfg = load_config(&cli).await;
        assert_eq!(cfg.ports.proxy, crate::config::DEFAULT_PROXY_PORT);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The other half of the contract: a well-formed explicit config is honored
    /// exactly, and its `data_dir` is anchored beside the file rather than in the
    /// operator's real data dir.
    #[tokio::test]
    async fn load_config_honors_an_explicit_path() {
        let dir = std::env::temp_dir().join(format!("saffev-cfg-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("saffev.toml");
        std::fs::write(
            &path,
            format!(
                "mode = \"cooperative\"\ndata_dir = {:?}\n\n\
                 [ports]\nproxy = 8188\nstudio = 7188\nupstream = 11434\nshadow = 11999\n",
                dir
            ),
        )
        .unwrap();

        let cli = Cli {
            config: Some(path),
            no_color: true,
            command: crate::cli::Command::Status,
        };
        let cfg = load_config(&cli).await;
        assert_eq!(cfg.ports.proxy, 8188);
        assert_eq!(cfg.ports.studio, 7188);
        assert_eq!(cfg.data_dir, dir);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Documents a real (and deliberate) sharp edge: [`Config::default`] is NOT a
    /// valid cooperative config, because the default proxy port and the default
    /// upstream port are both the well-known engine port. A usable first-run
    /// config comes from `resolve_first_run`, which picks a free proxy port. This
    /// is why `load_config`'s fallback is a last-resort shape, not a runnable one.
    #[test]
    fn default_config_is_not_a_runnable_cooperative_config() {
        let cfg = Config::default();
        assert_eq!(cfg.mode, Mode::Cooperative);
        assert_eq!(cfg.ports.proxy, cfg.ports.upstream);
        assert!(
            cfg.validate().is_err(),
            "default proxy == upstream must fail validation"
        );
    }

    #[tokio::test]
    async fn guard_catches_panic() {
        let out: Option<u32> = guard("panicky", async { panic!("boom") }).await;
        assert!(out.is_none());
        let ok: Option<u32> = guard("ok", async { Ok(7u32) }).await;
        assert_eq!(ok, Some(7));
    }

    #[test]
    fn capture_note_distinguishes_modes() {
        let coop = capture_note(Mode::Cooperative);
        let gw = capture_note(Mode::Gateway);
        assert_ne!(coop, gw);
        // Cooperative must point users at how to route an app; Gateway must say
        // it's transparent. These strings are the fix for "the step people miss".
        assert!(coop.contains("proxy") && coop.contains("saffev run"));
        assert!(gw.contains("all engine traffic") && gw.contains("transparent"));
    }
}
