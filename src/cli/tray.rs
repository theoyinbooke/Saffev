//! macOS menu-bar app (Saffev.app) — feature `tray`, macOS-first.
//!
//! A lightweight supervisor over the existing daemon lifecycle ([`super::daemon`]):
//! it owns the macOS run loop, keeps the proxy + Studio running as a **child
//! process** (so this launcher needs no async runtime), and puts two things in
//! the status bar:
//!
//! - **Left-click → the panel** ([`super::tray_panel`]): a custom drop-down
//!   widget (stats, preservation aging, privacy posture, spend, alerts, and the
//!   service controls) rendered by a webview that loads `menubar.html` from the
//!   running Studio. Fully custom UI, no native menu chrome.
//! - **A plain menu** with the same actions on the non-macOS `tray` builds
//!   (there is no panel there). On macOS the status item deliberately has no
//!   native menu: see the note at the tray builder.
//!
//! No new server code; all objc unsafe lives inside `tray-icon`/`tao`/`wry`, so
//! `#![forbid(unsafe_code)]` still holds.
//!
//! Supervision contract (the part users rely on):
//! - spawned children are reaped (`try_wait`) so exited daemons never linger as
//!   zombies for the tray's lifetime;
//! - if the daemon dies **without** the user pressing Stop, the tray restarts
//!   it — bounded to [`MAX_RESTART_ATTEMPTS`] tries with a grace period, so a
//!   daemon that can't start (port taken, bad config) becomes a visible
//!   "failed" state instead of a silent restart loop;
//! - an explicit Stop is respected: no auto-restart until Start is clicked;
//! - background daemons log to `daemon.log` in the data dir (see
//!   [`daemon::log_path`]); "Open Logs" opens it, so a grey icon is
//!   diagnosable instead of a dead end.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tao::event::{Event, StartCause, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

use super::daemon;
use super::tray_panel::{sanitize_route, sanitize_theme, HostState, Panel, PanelMsg};
use crate::config::Config;

/// How many times the supervisor retries a daemon that died on its own before
/// giving up and showing a failed state. Reset by a successful run or by an
/// explicit Start click.
const MAX_RESTART_ATTEMPTS: u32 = 3;

/// How long after a spawn the daemon gets to write its pid file before "not
/// running" counts as a crash. Prevents double-spawns while it initializes
/// (keychain, DB open, port binds all happen in this window).
const SPAWN_GRACE: Duration = Duration::from_secs(10);

/// Everything that wakes the run loop besides OS events. Tray clicks and menu
/// picks arrive through handlers (so they're immediate, not polled on the next
/// tick); the panel's IPC and finished background jobs come the same way.
#[derive(Debug)]
pub enum UserEvent {
    Tray(TrayIconEvent),
    Menu(MenuEvent),
    Panel(PanelMsg),
    /// `saffev backup` finished: `Ok(folder)` or `Err(message)`.
    BackupDone(Result<PathBuf, String>),
    /// The folder picker closed: `Some(path)` or `None` (cancelled).
    ExportDirChosen(Option<PathBuf>),
}

/// Everything the supervisor tracks between ticks.
struct Supervisor {
    config_path: PathBuf,
    pid_path: PathBuf,
    log_path: PathBuf,
    /// The daemon we spawned, held so it can be reaped. `None` when the daemon
    /// predates the tray (CLI-started) or after it has been reaped.
    child: Option<std::process::Child>,
    /// The user clicked Stop: do not auto-restart until they click Start.
    user_stopped: bool,
    /// Crash-restart attempts since the last healthy run.
    attempts: u32,
    /// When we last spawned, for the grace period.
    last_spawn: Option<Instant>,
    /// Set when the restart budget is exhausted — shown in the status line.
    gave_up: bool,
}

impl Supervisor {
    fn new(config: &Config) -> Self {
        Self {
            config_path: config.config_path(),
            pid_path: daemon::pid_path(config),
            log_path: daemon::log_path(config),
            child: None,
            user_stopped: false,
            attempts: 0,
            last_spawn: None,
            gave_up: false,
        }
    }

    fn is_running(&self) -> bool {
        matches!(daemon::daemon_state(&self.pid_path), Ok(Some(true)))
    }

    /// Reap an exited child so it never lingers as a zombie.
    fn reap(&mut self) {
        if let Some(child) = &mut self.child {
            if matches!(child.try_wait(), Ok(Some(_))) {
                self.child = None;
            }
        }
    }

    fn spawn(&mut self) {
        if let Ok(child) = daemon::spawn_background_child(
            Some(&self.config_path),
            true,
            true,
            Some(&self.log_path),
        ) {
            self.child = Some(child);
        }
        self.last_spawn = Some(Instant::now());
    }

    /// Explicit Start click: fresh budget, then run if not already running.
    fn start(&mut self) {
        self.user_stopped = false;
        self.gave_up = false;
        self.attempts = 0;
        if !self.is_running() {
            self.spawn();
        }
    }

    /// Explicit Stop click: terminate and stand down (no auto-restart).
    fn stop(&mut self) {
        self.user_stopped = true;
        self.gave_up = false;
        if let Ok(Some(pf)) = daemon::read_pid_file(&self.pid_path) {
            let _ = daemon::send_terminate(pf.pid);
        }
    }

    fn restart(&mut self) {
        self.stop();
        std::thread::sleep(Duration::from_millis(600));
        self.start();
    }

    /// One supervision tick: reap, then restart a crashed daemon (bounded).
    fn tick(&mut self) {
        self.reap();

        let in_grace = self
            .last_spawn
            .map(|t| t.elapsed() < SPAWN_GRACE)
            .unwrap_or(false);
        let (respawn, attempts, gave_up) = plan_tick(
            self.is_running(),
            self.user_stopped,
            self.gave_up,
            self.attempts,
            in_grace,
        );
        self.attempts = attempts;
        self.gave_up = gave_up;
        if respawn {
            self.spawn();
        }
    }

    /// Whether a spawn is still inside its grace window (the "starting" state).
    fn is_starting(&self) -> bool {
        !self.is_running()
            && !self.user_stopped
            && !self.gave_up
            && self
                .last_spawn
                .map(|t| t.elapsed() < SPAWN_GRACE)
                .unwrap_or(false)
    }

    /// Machine-readable status for the panel.
    fn status_key(&self) -> &'static str {
        if self.is_running() {
            "running"
        } else if self.gave_up {
            "failed"
        } else if self.user_stopped {
            "stopped"
        } else if self.is_starting() || self.attempts > 0 {
            "starting"
        } else {
            "stopped"
        }
    }

    /// Status line for the menu.
    fn status_text(&self) -> &'static str {
        match self.status_key() {
            "running" => "● Running",
            "failed" => "△ Failed to start — see Open Logs",
            "starting" => "◌ Starting…",
            _ => "○ Stopped",
        }
    }
}

/// The pure decision for one supervision tick, split from the I/O so it is
/// testable: `(respawn, attempts, gave_up)`.
///
/// Rules, in order: a healthy run refills the budget; an explicit Stop or an
/// exhausted budget stands down; a fresh spawn gets its grace period; then a
/// dead daemon costs one attempt and is respawned — until the budget runs out,
/// which flips `gave_up` (surfaced as the failed state in the menu).
fn plan_tick(
    running: bool,
    user_stopped: bool,
    gave_up: bool,
    attempts: u32,
    in_grace: bool,
) -> (bool, u32, bool) {
    if running {
        return (false, 0, false);
    }
    if user_stopped || gave_up {
        return (false, attempts, gave_up);
    }
    if in_grace {
        return (false, attempts, false);
    }
    if attempts >= MAX_RESTART_ATTEMPTS {
        return (false, attempts, true);
    }
    (true, attempts + 1, false)
}

/// The actions both UIs (panel + fallback menu) can trigger.
#[derive(Debug, Clone, PartialEq)]
enum Action {
    OpenStudio(Option<String>),
    Start,
    Stop,
    Restart,
    Logs,
    Update,
    Backup,
    ChooseExportDir,
    SetLogin(Option<bool>),
    Quit,
}

/// Map a menu id to its action. The fallback menu has no routes.
fn menu_action(id: &str) -> Option<Action> {
    Some(match id {
        "open" => Action::OpenStudio(None),
        "start" => Action::Start,
        "stop" => Action::Stop,
        "restart" => Action::Restart,
        "logs" => Action::Logs,
        "update" => Action::Update,
        "backup" => Action::Backup,
        "login" => Action::SetLogin(None),
        "quit" => Action::Quit,
        _ => return None,
    })
}

/// Map a panel message to an action, or `None` for the panel-internal ones
/// (ready / close / pin / resize), which the loop handles itself.
fn panel_action(msg: &PanelMsg) -> Option<Action> {
    Some(match msg {
        PanelMsg::Open { route } => Action::OpenStudio(sanitize_route(route)),
        PanelMsg::Start => Action::Start,
        PanelMsg::Stop => Action::Stop,
        PanelMsg::Restart => Action::Restart,
        PanelMsg::Logs => Action::Logs,
        PanelMsg::Update => Action::Update,
        PanelMsg::Backup => Action::Backup,
        PanelMsg::ChooseExportDir => Action::ChooseExportDir,
        PanelMsg::SetLogin { enabled } => Action::SetLogin(Some(*enabled)),
        PanelMsg::Quit => Action::Quit,
        PanelMsg::Ready
        | PanelMsg::Close
        | PanelMsg::SetPinned { .. }
        | PanelMsg::SetTheme { .. }
        | PanelMsg::Resize { .. } => return None,
    })
}

/// Entry point for `saffev tray`. Runs synchronously on the main thread. Never
/// returns (the tao run loop `std::process::exit`s on Quit).
pub fn run_tray() -> ExitCode {
    let config = Config::load().unwrap_or_default();
    let studio_url = config.studio_url();
    let studio_port = config.ports.studio;
    let mut sup = Supervisor::new(&config);

    // Start the service on launch if it isn't already up.
    sup.start();

    #[allow(unused_mut)]
    let mut event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    // Menu-bar only: no Dock icon, no app switcher entry. The .app's Info.plist
    // already says LSUIElement; this makes a terminal `saffev tray` match it.
    #[cfg(target_os = "macos")]
    {
        use tao::platform::macos::{ActivationPolicy, EventLoopExtMacOS};
        event_loop.set_activation_policy(ActivationPolicy::Accessory);
    }
    let proxy = event_loop.create_proxy();

    // Route tray clicks + menu picks into the run loop as user events so they
    // are handled the moment they happen (the channels would only be drained
    // on the 2s tick). Must be installed BEFORE the tray/menu are built.
    {
        let p = Arc::new(Mutex::new(proxy.clone()));
        let p1 = p.clone();
        TrayIconEvent::set_event_handler(Some(move |ev: TrayIconEvent| {
            if let Ok(p) = p1.lock() {
                let _ = p.send_event(UserEvent::Tray(ev));
            }
        }));
        let p2 = p.clone();
        MenuEvent::set_event_handler(Some(move |ev: MenuEvent| {
            if let Ok(p) = p2.lock() {
                let _ = p.send_event(UserEvent::Menu(ev));
            }
        }));
    }

    let open_item = MenuItem::with_id("open", "Open Saffev Studio", true, None);
    let status_item = MenuItem::with_id("status", "Starting…", false, None);
    let start_item = MenuItem::with_id("start", "Start", true, None);
    let stop_item = MenuItem::with_id("stop", "Stop", true, None);
    let restart_item = MenuItem::with_id("restart", "Restart", true, None);
    let backup_item = MenuItem::with_id("backup", "Back Up Archive…", true, None);
    let logs_item = MenuItem::with_id("logs", "Open Logs", true, None);
    // A DMG-installed .app can't self-update in place (see
    // `update::APP_BUNDLE_MESSAGE`), so "check for updates" honestly means:
    // open the releases page where the new DMG lives.
    let update_item = MenuItem::with_id("update", "Check for Updates…", true, None);
    let login_item = CheckMenuItem::with_id("login", "Open at Login", true, login_enabled(), None);
    let quit_item = MenuItem::with_id("quit", "Quit Saffev", true, None);

    let menu = Menu::new();
    let _ = menu.append(&open_item);
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&status_item);
    let _ = menu.append(&start_item);
    let _ = menu.append(&stop_item);
    let _ = menu.append(&restart_item);
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&backup_item);
    let _ = menu.append(&logs_item);
    let _ = menu.append(&update_item);
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&login_item);
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&quit_item);

    let mut tray: Option<TrayIcon> = None;
    let mut panel: Option<Panel> = None;
    let mut last_state: Option<HostState> = None;
    let mut backup_running = false;
    let mut picker_open = false;
    // The viewer's theme choice, echoed from the Studio page so the offline
    // card renders the same way. In-memory only: the page persists it.
    let mut theme = String::new();
    let refresh = Duration::from_secs(2);

    let host_state =
        |sup: &Supervisor, panel: &Option<Panel>, studio_url: &str, theme: &str| HostState {
            app_name: crate::brand::APP_NAME.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            studio_url: studio_url.to_string(),
            running: sup.is_running(),
            status: sup.status_key().to_string(),
            status_text: sup
                .status_text()
                .trim_start_matches(['●', '○', '◌', '△', ' '])
                .to_string(),
            login_enabled: login_enabled(),
            pinned: panel.as_ref().map(|p| p.pinned).unwrap_or(false),
            theme: theme.to_string(),
            home_dir: crate::agents::home().to_string_lossy().to_string(),
        };

    // The supervision tick runs on a fixed deadline, checked on EVERY wake-up.
    // Re-arming `WaitUntil(now + refresh)` per event would let a busy webview
    // starve the timer (each event pushes the deadline out again).
    let mut next_tick = Instant::now() + refresh;

    event_loop.run(move |event, target, control_flow| {
        let now = Instant::now();
        if now >= next_tick {
            next_tick = now + refresh;
            sup.tick();
            if let Some(p) = panel.as_mut() {
                p.sync(sup.is_running());
            }
        }
        *control_flow = ControlFlow::WaitUntil(next_tick);

        let mut act: Option<Action> = None;

        match event {
            // macOS: the status item must be created after the app is initialized.
            Event::NewEvents(StartCause::Init) => {
                let mut builder = TrayIconBuilder::new()
                    .with_tooltip("Saffev — local AI studio")
                    .with_icon(status_icon(sup.is_running()))
                    // macOS template images are automatically rendered white
                    // or black for the current menu-bar appearance. The source
                    // stays a pure alpha mask, so it remains legible in either.
                    .with_icon_as_template(cfg!(target_os = "macos"));
                // macOS: NO native menu on the status item. tray-icon installs
                // the menu on the NSStatusItem itself, and AppKit pops it on
                // any click before the crate's `menu_on_left_click(false)`
                // override runs — verified with a synthesized click — so the
                // panel would never open. Left AND right click open the panel
                // (it carries every action, Quit included). Elsewhere there is
                // no panel, so the menu stays on the primary button.
                if !cfg!(target_os = "macos") {
                    builder = builder.with_menu(Box::new(menu.clone()));
                }
                tray = builder.build().ok();
                panel = Panel::new(target, proxy.clone(), &studio_url, studio_port);
                tracing::debug!(
                    "menu-bar: tray built: {}, panel built: {}",
                    tray.is_some(),
                    panel.is_some()
                );
            }
            Event::UserEvent(UserEvent::Tray(TrayIconEvent::Click {
                rect,
                button: MouseButton::Left | MouseButton::Right,
                button_state: MouseButtonState::Up,
                ..
            })) => {
                tracing::debug!(
                    "menu-bar: status item clicked at {:?} (panel present: {})",
                    rect.position,
                    panel.is_some()
                );
                let state = host_state(&sup, &panel, &studio_url, &theme);
                if let Some(p) = panel.as_mut() {
                    p.toggle(rect, &state);
                }
            }
            Event::UserEvent(UserEvent::Tray(_)) => {}
            Event::UserEvent(UserEvent::Menu(ev)) => {
                act = menu_action(ev.id.0.as_str());
                if act == Some(Action::SetLogin(None)) {
                    // The checkbox already flipped itself; apply what it shows.
                    act = Some(Action::SetLogin(Some(login_item.is_checked())));
                }
            }
            Event::UserEvent(UserEvent::Panel(msg)) => match &msg {
                PanelMsg::Ready => {
                    let state = host_state(&sup, &panel, &studio_url, &theme);
                    if let Some(p) = panel.as_mut() {
                        p.mark_ready();
                        p.push_state(&state);
                    }
                }
                PanelMsg::Close => {
                    if let Some(p) = panel.as_mut() {
                        p.hide();
                    }
                }
                PanelMsg::SetPinned { pinned } => {
                    if let Some(p) = panel.as_mut() {
                        p.set_pinned(*pinned);
                    }
                }
                PanelMsg::SetTheme { theme: t } => {
                    theme = sanitize_theme(t);
                }
                PanelMsg::Resize { height } => {
                    if let Some(p) = panel.as_mut() {
                        p.set_height(*height);
                    }
                }
                other => act = panel_action(other),
            },
            Event::UserEvent(UserEvent::BackupDone(result)) => {
                backup_running = false;
                let js = match &result {
                    Ok(dir) => {
                        // Show the folder: the point of a backup is knowing where it is.
                        let _ = std::process::Command::new("open").arg(dir).spawn();
                        format!(
                            "window.__saffevHost&&window.__saffevHost.notice&&window.__saffevHost.notice({});",
                            serde_json::json!({
                                "kind": "ok",
                                "title": "Backup written",
                                "detail": dir.display().to_string(),
                            })
                        )
                    }
                    Err(msg) => format!(
                        "window.__saffevHost&&window.__saffevHost.notice&&window.__saffevHost.notice({});",
                        serde_json::json!({
                            "kind": "error",
                            "title": "Backup failed",
                            "detail": msg,
                        })
                    ),
                };
                if let Some(p) = panel.as_ref() {
                    p.eval(&js);
                }
            }
            Event::UserEvent(UserEvent::ExportDirChosen(path)) => {
                picker_open = false;
                let json = serde_json::to_string(&path.map(|p| p.to_string_lossy().to_string()))
                    .unwrap_or_else(|_| "null".into());
                if let Some(p) = panel.as_ref() {
                    p.eval(&format!(
                        "window.__saffevHost&&window.__saffevHost.exportDirChosen&&window.__saffevHost.exportDirChosen({json});"
                    ));
                }
            }
            Event::WindowEvent {
                event: WindowEvent::Focused(false),
                ..
            } => {
                // The folder picker is a separate window; losing focus to it
                // must not close the panel its result goes back to.
                if !picker_open {
                    if let Some(p) = panel.as_mut() {
                        p.on_blur();
                    }
                }
            }
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                if let Some(p) = panel.as_mut() {
                    p.hide();
                }
            }
            _ => {}
        }

        if let Some(action) = act {
            match action {
                Action::OpenStudio(route) => {
                    let url = match route {
                        Some(r) => format!("{studio_url}/{r}"),
                        None => studio_url.clone(),
                    };
                    open_url(&url);
                    if let Some(p) = panel.as_mut() {
                        if !p.pinned {
                            p.hide();
                        }
                    }
                }
                Action::Start => sup.start(),
                Action::Stop => sup.stop(),
                Action::Restart => sup.restart(),
                Action::Logs => open_logs(&sup.log_path),
                Action::Update => open_url(crate::update::RELEASES_URL),
                Action::Backup => {
                    if !backup_running {
                        backup_running = true;
                        spawn_backup(sup.config_path.clone(), proxy.clone());
                        if let Some(p) = panel.as_ref() {
                            p.eval(
                                "window.__saffevHost&&window.__saffevHost.notice&&window.__saffevHost.notice({\"kind\":\"busy\",\"title\":\"Backing up…\",\"detail\":\"Encrypted copy of the archive + restore notes\"});",
                            );
                        }
                    }
                }
                Action::ChooseExportDir => {
                    if !picker_open {
                        picker_open = true;
                        spawn_folder_picker(proxy.clone());
                    }
                }
                Action::SetLogin(want) => {
                    set_login(want.unwrap_or_else(|| !login_enabled()));
                    // Re-sync the checkbox to what actually happened on disk, so
                    // a failed write can't leave it claiming a state it isn't in.
                    login_item.set_checked(login_enabled());
                }
                Action::Quit => {
                    // Quitting the menu-bar app leaves the service running by
                    // design (Quit != Stop). Use Stop to actually shut it down.
                    *control_flow = ControlFlow::Exit;
                }
            }
            if let Some(p) = panel.as_mut() {
                p.sync(sup.is_running());
            }
        }

        // Refresh the icon + fallback menu, and push state to the panel only
        // when something changed (the page re-renders on every push).
        let running = sup.is_running();
        if let Some(t) = &tray {
            let _ = t.set_icon_with_as_template(
                Some(status_icon(running)),
                cfg!(target_os = "macos"),
            );
        }
        status_item.set_text(sup.status_text());
        start_item.set_enabled(!running);
        stop_item.set_enabled(running);
        restart_item.set_enabled(running);
        backup_item.set_enabled(!backup_running);

        let state = host_state(&sup, &panel, &studio_url, &theme);
        if last_state.as_ref() != Some(&state) {
            if let Some(p) = panel.as_ref() {
                p.push_state(&state);
            }
            last_state = Some(state);
        }
    });
}

/// Native folder picker (AppleScript `choose folder`) on a worker thread. The
/// prompt is a constant; the only user-influenced value is the RESULT, which
/// is data. Cancel (non-zero exit) reports `None`.
fn spawn_folder_picker(proxy: tao::event_loop::EventLoopProxy<UserEvent>) {
    std::thread::spawn(move || {
        let out = std::process::Command::new("osascript")
            .arg("-e")
            .arg("POSIX path of (choose folder with prompt \"Where should Saffev keep backups and exports?\")")
            .output();
        let chosen = match out {
            Ok(o) if o.status.success() => {
                let p = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if p.is_empty() {
                    None
                } else {
                    Some(PathBuf::from(p.trim_end_matches('/')))
                }
            }
            _ => None,
        };
        let _ = proxy.send_event(UserEvent::ExportDirChosen(chosen));
    });
}

/// Run `saffev backup` as a child (it needs the store + keyring key, which the
/// daemon path owns) on a worker thread, and report the created folder.
fn spawn_backup(config_path: PathBuf, proxy: tao::event_loop::EventLoopProxy<UserEvent>) {
    std::thread::spawn(move || {
        let result = (|| -> Result<PathBuf, String> {
            let exe = daemon::current_exe_on_disk().map_err(|e| e.to_string())?;
            let out = std::process::Command::new(exe)
                .arg("--config")
                .arg(&config_path)
                .arg("--no-color")
                .arg("backup")
                .output()
                .map_err(|e| e.to_string())?;
            let stdout = String::from_utf8_lossy(&out.stdout);
            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr);
                let msg = stderr
                    .lines()
                    .chain(stdout.lines())
                    .last()
                    .unwrap_or("backup exited with an error");
                return Err(msg.trim().to_string());
            }
            // The command prints the folder it wrote; find the path on any line.
            stdout
                .lines()
                .flat_map(|l| l.split_whitespace())
                .map(|w| w.trim_matches(|c: char| c == '"' || c == '\'' || c == ':' || c == ','))
                .filter(|w| w.contains("Saffev-Backup-"))
                .map(PathBuf::from)
                .find(|p| p.is_dir())
                .ok_or_else(|| "backup finished but its folder was not reported".to_string())
        })();
        let _ = proxy.send_event(UserEvent::BackupDone(result));
    });
}

fn open_url(url: &str) {
    let _ = std::process::Command::new("open").arg(url).spawn();
}

/// Open the daemon log in the user's default viewer. Touch the file first so
/// `open` has something to open even before the first background run.
fn open_logs(path: &Path) {
    if !path.exists() {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(path, b"");
    }
    let _ = std::process::Command::new("open").arg(path).spawn();
}

/// A hand-rasterized 32×32 alpha mask of the canonical Saffev recorder mark.
/// `#` is fully opaque, `+` is the antialiased edge, and spaces are clear.
const STATUS_ICON_MASK: [&str; 32] = [
    "                                ",
    "          ++++++++++++          ",
    "        +##############+        ",
    "       ##################       ",
    "      +##################+      ",
    "      ####################      ",
    "      ####################      ",
    "      ####################      ",
    "     +####################+     ",
    "     +#############+++####+     ",
    "     +############+    ###+     ",
    "     +############ +##++##+     ",
    "     ############++#### +##     ",
    "     ############+###### ##     ",
    "    +###########+#######+ ++++  ",
    "      +#########+########+      ",
    "  +++++ #######+###########+++  ",
    "    +###+######+###########+    ",
    "     ###++####++###########     ",
    "     ####++##++############     ",
    "     +####    ############+     ",
    "     +#####+++############+     ",
    "     +####################+     ",
    "     +####################+     ",
    "      ####################      ",
    "      ####################      ",
    "      ####################      ",
    "      +##################+      ",
    "       ##################       ",
    "        +##############+        ",
    "          ++++++++++++          ",
    "                                ",
];

fn status_icon_rgba(running: bool) -> Vec<u8> {
    let rgb = if cfg!(target_os = "macos") {
        // NSImage template content is defined by alpha, not RGB.
        (0, 0, 0)
    } else if running {
        (17, 118, 110)
    } else {
        (128, 128, 128)
    };
    let mut rgba = Vec::with_capacity(32 * 32 * 4);
    for row in STATUS_ICON_MASK {
        for px in row.bytes() {
            let base_alpha = match px {
                b'#' => 255,
                b'+' => 128,
                _ => 0,
            };
            let alpha = if running {
                base_alpha
            } else {
                ((base_alpha as u16 * 112) / 255) as u8
            };
            rgba.extend_from_slice(&[rgb.0, rgb.1, rgb.2, alpha]);
        }
    }
    rgba
}

/// The canonical Saffev mark for the status item. On macOS this is installed
/// as a template image so AppKit supplies the correct menu-bar foreground.
fn status_icon(running: bool) -> Icon {
    Icon::from_rgba(status_icon_rgba(running), 32, 32).expect("valid icon")
}

// ----- Open at Login (a per-user LaunchAgent) -----

fn launch_agent_path() -> PathBuf {
    crate::agents::home().join("Library/LaunchAgents/com.saffev.launcher.plist")
}

fn login_enabled() -> bool {
    launch_agent_path().is_file()
}

fn set_login(enable: bool) {
    let path = launch_agent_path();
    if enable {
        let Ok(exe) = std::env::current_exe() else {
            return;
        };
        let plist = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.saffev.launcher</string>
  <key>ProgramArguments</key><array><string>{}</string><string>tray</string></array>
  <key>RunAtLoad</key><true/>
</dict></plist>
"#,
            exe.display()
        );
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if std::fs::write(&path, plist).is_ok() {
            let _ = std::process::Command::new("launchctl")
                .arg("load")
                .arg(&path)
                .status();
        } else {
            // The plist could not be written — remove any stale one so
            // `login_enabled()` (and the re-synced checkbox) reflect reality.
            let _ = std::fs::remove_file(&path);
        }
    } else {
        let _ = std::process::Command::new("launchctl")
            .arg("unload")
            .arg(&path)
            .status();
        let _ = std::fs::remove_file(&path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthy_run_refills_the_budget() {
        // Whatever the history, a running daemon resets attempts + gave_up.
        assert_eq!(plan_tick(true, false, false, 3, false), (false, 0, false));
        assert_eq!(plan_tick(true, true, true, 2, true), (false, 0, false));
    }

    #[test]
    fn explicit_stop_is_respected() {
        // Stopped by the user: never respawn, keep state as-is.
        assert_eq!(plan_tick(false, true, false, 0, false), (false, 0, false));
        assert_eq!(plan_tick(false, true, false, 2, false), (false, 2, false));
    }

    #[test]
    fn grace_period_defers_judgment() {
        // Just spawned: not running yet is NOT a crash.
        assert_eq!(plan_tick(false, false, false, 1, true), (false, 1, false));
    }

    #[test]
    fn crash_costs_one_attempt_until_the_budget_is_gone() {
        // Three crashes respawn…
        assert_eq!(plan_tick(false, false, false, 0, false), (true, 1, false));
        assert_eq!(plan_tick(false, false, false, 1, false), (true, 2, false));
        assert_eq!(plan_tick(false, false, false, 2, false), (true, 3, false));
        // …the fourth gives up (visible failed state), and stays given up.
        assert_eq!(plan_tick(false, false, false, 3, false), (false, 3, true));
        assert_eq!(plan_tick(false, false, true, 3, false), (false, 3, true));
    }

    #[test]
    fn both_uis_map_onto_the_same_actions() {
        assert_eq!(menu_action("start"), Some(Action::Start));
        assert_eq!(menu_action("backup"), Some(Action::Backup));
        assert_eq!(menu_action("bogus"), None);
        assert_eq!(panel_action(&PanelMsg::Stop), Some(Action::Stop));
        assert_eq!(
            panel_action(&PanelMsg::Open {
                route: "#/agents".into()
            }),
            Some(Action::OpenStudio(Some("#/agents".into())))
        );
        // A tampered route degrades to the Studio root, never to an argument.
        assert_eq!(
            panel_action(&PanelMsg::Open {
                route: "--evil".into()
            }),
            Some(Action::OpenStudio(None))
        );
        // Panel-internal messages are not actions.
        assert_eq!(panel_action(&PanelMsg::Ready), None);
        assert_eq!(panel_action(&PanelMsg::Resize { height: 1.0 }), None);
    }

    #[test]
    fn status_icon_is_the_canonical_transparent_mark() {
        assert!(STATUS_ICON_MASK.iter().all(|row| row.len() == 32));
        let running = status_icon_rgba(true);
        let stopped = status_icon_rgba(false);
        assert_eq!(running.len(), 32 * 32 * 4);
        assert_eq!(running[3], 0, "top-left must stay transparent");
        let running_alpha: u32 = running.iter().skip(3).step_by(4).map(|a| *a as u32).sum();
        let stopped_alpha: u32 = stopped.iter().skip(3).step_by(4).map(|a| *a as u32).sum();
        assert!(running_alpha > 0);
        assert!(
            stopped_alpha < running_alpha,
            "stopped state should be visibly dimmer"
        );
    }
}
