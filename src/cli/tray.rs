//! macOS menu-bar launcher (Saffev.app) — feature `tray`, macOS-first.
//!
//! A lightweight supervisor over the existing daemon lifecycle ([`super::daemon`]):
//! it owns the macOS run loop, keeps the proxy + Studio running as a **child
//! process** (so this launcher needs no async runtime), and offers a menu:
//! Open Studio · Start/Stop/Restart · Open Logs · Open at Login · Quit. No new
//! server code; all objc unsafe lives inside `tray-icon`/`tao`, so
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
use std::time::{Duration, Instant};

use tao::event::{Event, StartCause};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

use super::daemon;
use crate::config::Config;

/// How many times the supervisor retries a daemon that died on its own before
/// giving up and showing a failed state. Reset by a successful run or by an
/// explicit Start click.
const MAX_RESTART_ATTEMPTS: u32 = 3;

/// How long after a spawn the daemon gets to write its pid file before "not
/// running" counts as a crash. Prevents double-spawns while it initializes
/// (keychain, DB open, port binds all happen in this window).
const SPAWN_GRACE: Duration = Duration::from_secs(10);

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

    /// Status line for the menu.
    fn status_text(&self) -> &'static str {
        if self.is_running() {
            "● Running"
        } else if self.gave_up {
            "△ Failed to start — see Open Logs"
        } else if self.user_stopped {
            "○ Stopped"
        } else if self.attempts > 0 {
            "◌ Restarting…"
        } else {
            "○ Stopped"
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

/// Entry point for `saffev tray`. Runs synchronously on the main thread. Never
/// returns (the tao run loop `std::process::exit`s on Quit).
pub fn run_tray() -> ExitCode {
    let config = Config::load().unwrap_or_default();
    let studio_url = config.studio_url();
    let mut sup = Supervisor::new(&config);

    // Start the service on launch if it isn't already up.
    sup.start();

    let event_loop = EventLoopBuilder::<()>::new().build();

    let open_item = MenuItem::with_id("open", "Open Saffev Studio", true, None);
    let status_item = MenuItem::with_id("status", "Starting…", false, None);
    let start_item = MenuItem::with_id("start", "Start", true, None);
    let stop_item = MenuItem::with_id("stop", "Stop", true, None);
    let restart_item = MenuItem::with_id("restart", "Restart", true, None);
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
    let _ = menu.append(&logs_item);
    let _ = menu.append(&update_item);
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&login_item);
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&quit_item);

    let menu_channel = MenuEvent::receiver();
    let mut tray: Option<TrayIcon> = None;
    let refresh = Duration::from_secs(2);

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::WaitUntil(Instant::now() + refresh);

        match event {
            // macOS: the status item must be created after the app is initialized.
            Event::NewEvents(StartCause::Init) => {
                tray = TrayIconBuilder::new()
                    .with_menu(Box::new(menu.clone()))
                    .with_tooltip("Saffev — local AI studio")
                    .with_icon(status_icon(sup.is_running()))
                    .build()
                    .ok();
                refresh_ui(
                    &tray,
                    &status_item,
                    &start_item,
                    &stop_item,
                    &restart_item,
                    &sup,
                );
            }
            Event::NewEvents(StartCause::ResumeTimeReached { .. }) => {
                sup.tick();
                refresh_ui(
                    &tray,
                    &status_item,
                    &start_item,
                    &stop_item,
                    &restart_item,
                    &sup,
                );
            }
            _ => {}
        }

        while let Ok(ev) = menu_channel.try_recv() {
            match ev.id.0.as_str() {
                "open" => open_url(&studio_url),
                "start" => sup.start(),
                "stop" => sup.stop(),
                "restart" => sup.restart(),
                "logs" => open_logs(&sup.log_path),
                "update" => open_url(crate::update::RELEASES_URL),
                "login" => {
                    set_login(login_item.is_checked());
                    // Re-sync the checkbox to what actually happened on disk, so
                    // a failed write can't leave it claiming a state it isn't in.
                    login_item.set_checked(login_enabled());
                }
                "quit" => {
                    // Quitting the menu-bar app leaves the service running by
                    // design (Quit != Stop). Use Stop to actually shut it down.
                    *control_flow = ControlFlow::Exit;
                }
                _ => {}
            }
            refresh_ui(
                &tray,
                &status_item,
                &start_item,
                &stop_item,
                &restart_item,
                &sup,
            );
        }
    });
}

fn refresh_ui(
    tray: &Option<TrayIcon>,
    status_item: &MenuItem,
    start_item: &MenuItem,
    stop_item: &MenuItem,
    restart_item: &MenuItem,
    sup: &Supervisor,
) {
    let running = sup.is_running();
    if let Some(t) = tray {
        let _ = t.set_icon(Some(status_icon(running)));
    }
    status_item.set_text(sup.status_text());
    // Only the actions that can do something are clickable.
    start_item.set_enabled(!running);
    stop_item.set_enabled(running);
    restart_item.set_enabled(running);
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

/// A 32×32 target glyph — teal when running, dim grey when stopped.
fn status_icon(running: bool) -> Icon {
    let size = 32usize;
    let (r, g, b) = if running {
        (15u8, 118, 110)
    } else {
        (128, 128, 128)
    };
    let (cx, cy) = (15.5f32, 15.5f32);
    let mut rgba = vec![0u8; size * size * 4];
    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - cx;
            let dy = y as f32 - cy;
            let d = (dx * dx + dy * dy).sqrt();
            let on = (9.0..=13.0).contains(&d) || d <= 4.5;
            let i = (y * size + x) * 4;
            rgba[i] = r;
            rgba[i + 1] = g;
            rgba[i + 2] = b;
            rgba[i + 3] = if on { 255 } else { 0 };
        }
    }
    Icon::from_rgba(rgba, size as u32, size as u32).expect("valid icon")
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
}
