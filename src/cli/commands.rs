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

use crate::cli::{Cli, EngineArg};
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

    // p50 latency over today's completed exchanges.
    let mut latencies: Vec<u32> = today.iter().filter_map(|r| r.request.latency_ms).collect();
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

    let can_gateway = !cooperative && controller_can_adopt(&cfg);

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
    let journal = guard("adoption", async move {
        let store = crate::store::Store::open(&db_path).await?;
        let controller = crate::engine::cooperative::CooperativeController;
        crate::engine::adopt::run_adoption(&controller, &info_for_adopt, &store).await
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
    let result = guard("revert", async move {
        let store = crate::store::Store::open(&db_path).await?;
        let engines = store.engines().await?;
        let record = engines.into_iter().find(|e| e.engine == target);
        let Some(record) = record else {
            return Ok(false);
        };
        let journal: Vec<crate::engine::JournalEntry> =
            serde_json::from_str(&record.journal_json).unwrap_or_default();
        let controller = crate::engine::cooperative::CooperativeController;
        crate::engine::EngineController::revert(&controller, &journal).await?;
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
        None => println!(
            "{} {} {}",
            p.dot(Level::Err),
            p.label("revert"),
            p.error("revert unavailable on this host"),
        ),
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// start / stop — proxy + studio + supervisor
// ---------------------------------------------------------------------------

/// `saffev start` — run the proxy + Studio (+ supervisor in Gateway mode).
///
/// In the foreground it binds both servers and blocks until Ctrl-C. Without
/// `--foreground` it still runs in the foreground for v0 (no daemonization yet)
/// but prints how to background it.
pub async fn start(cli: &Cli, foreground: bool) -> Result<()> {
    let p = painter(cli);
    let cfg = load_config(cli).await;

    println!("{} {}", p.prompt("~"), p.value("saffev start"));

    let proxy_addr = SocketAddr::new(cfg.ports.bind, cfg.ports.proxy);
    let studio_addr = SocketAddr::new(cfg.ports.bind, cfg.ports.studio);

    // Refuse to start if the proxy port is already taken by a foreign process.
    let proxy_port = cfg.ports.proxy;
    if port_listening(cfg.ports.bind, proxy_port).await {
        // Identify what holds the port so the operator can act. Capture only the
        // port value so `cfg` stays available for the messages below.
        let holder = guard("port diagnosis", async move {
            crate::engine::adopt::diagnose_port_conflict(proxy_port).await
        })
        .await
        .flatten();
        let detail = match holder {
            Some(h) => format!(
                "port {} held by {} (pid {})",
                proxy_port,
                h.name.unwrap_or_else(|| "unknown".to_string()),
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
        println!(
            "{} run {} to diagnose, or adopt the engine first",
            p.muted("·"),
            p.value("saffev doctor"),
        );
        return Ok(());
    }

    println!(
        "{} {} {} {} {}",
        p.dot(Level::Ok),
        p.label("proxy"),
        p.value(&proxy_addr.to_string()),
        p.muted("·"),
        p.label("studio"),
    );
    println!(
        "{} studio at {}",
        p.muted("·"),
        p.value(&format!(
            "http://{}:{}",
            display_host(cfg.ports.bind),
            cfg.ports.studio
        )),
    );

    if !foreground {
        println!(
            "{} {}",
            p.muted("·"),
            p.muted("running in the foreground (v0); press Ctrl-C to stop"),
        );
    }

    // Assemble shared state and launch both servers. Each piece is guarded so a
    // stubbed builder can't abort the whole command; if neither server can be
    // built we report cleanly instead of panicking. The servers bind to the
    // ports in `cfg` themselves; the addresses above are for display only.
    let _ = (proxy_addr, studio_addr);
    let launched = run_servers(&cfg).await;

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

/// Build state and run the proxy + Studio servers concurrently until shutdown
/// (Ctrl-C). Returns `Err` if the servers can't be constructed at all.
async fn run_servers(cfg: &Config) -> Result<()> {
    use std::sync::Arc;

    let cfg = Arc::new(cfg.clone());

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

    // Studio live-event broadcast channel.
    let (events, _events_rx) =
        tokio::sync::broadcast::channel(crate::studio::STREAM_CHANNEL_CAPACITY);

    let proxy_state = crate::proxy::ProxyState {
        config: cfg.clone(),
        store: store.clone(),
        tee,
        detector,
        upstream,
    };
    let studio_state = crate::studio::StudioState {
        config: cfg.clone(),
        store,
        token,
        events,
    };

    // Drain the tee into the store off the request path.
    crate::proxy::ProxyServer::spawn_logger(proxy_state.clone(), rx);

    // Run both servers concurrently; the first to exit (or Ctrl-C) ends start.
    let proxy = crate::proxy::ProxyServer::new(proxy_state);
    let studio = crate::studio::StudioServer::new(studio_state);

    let proxy_task = tokio::spawn(async move { proxy.serve().await });
    let studio_task = tokio::spawn(async move { studio.serve().await });
    let ctrl_c = tokio::signal::ctrl_c();

    tokio::select! {
        r = proxy_task => { let _ = r; }
        r = studio_task => { let _ = r; }
        _ = ctrl_c => {}
    }

    Ok(())
}

/// `saffev stop` — stop the proxy + Studio + supervisor.
///
/// v0 runs `start` in the foreground, so stopping is Ctrl-C in that terminal.
/// This command reports current liveness and how to stop a foreground instance.
pub async fn stop(cli: &Cli) -> Result<()> {
    let p = painter(cli);
    let cfg = load_config(cli).await;

    println!("{} {}", p.prompt("~"), p.value("saffev stop"));

    let proxy_up = port_listening(cfg.ports.bind, cfg.ports.proxy).await;
    let studio_up = port_listening(cfg.ports.bind, cfg.ports.studio).await;

    if !proxy_up && !studio_up {
        println!(
            "{} {} {}",
            p.dot(Level::Ok),
            p.label("stop"),
            p.value("not running"),
        );
        return Ok(());
    }

    // In Gateway mode, stopping honors the handover policy so the engine never
    // goes offline unless explicitly configured to stop with Saffev.
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

    println!(
        "{} {}",
        p.dot(Level::Warn),
        p.warn("Saffev runs in the foreground (v0) — press Ctrl-C in its terminal to stop"),
    );

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
// small shared bits
// ---------------------------------------------------------------------------

/// Whether Gateway adoption is available for this config/host. Gateway is
/// Linux-only in v0; everywhere else we run Cooperative.
fn controller_can_adopt(cfg: &Config) -> bool {
    cfg.mode == Mode::Gateway && cfg!(target_os = "linux")
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
        // With the config loader stubbed (panics), load_config must still yield
        // a usable default config rather than aborting.
        let cli = Cli {
            config: None,
            no_color: true,
            command: crate::cli::Command::Status,
        };
        let cfg = load_config(&cli).await;
        assert_eq!(cfg.ports.proxy, crate::config::DEFAULT_PROXY_PORT);
    }

    #[tokio::test]
    async fn guard_catches_panic() {
        let out: Option<u32> = guard("panicky", async { panic!("boom") }).await;
        assert!(out.is_none());
        let ok: Option<u32> = guard("ok", async { Ok(7u32) }).await;
        assert_eq!(ok, Some(7));
    }
}
