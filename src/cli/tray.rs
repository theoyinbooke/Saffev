//! macOS menu-bar launcher (Saffev.app) — feature `tray`, macOS-first.
//!
//! A lightweight supervisor over the existing daemon lifecycle ([`super::daemon`]):
//! it owns the macOS run loop, keeps the proxy + Studio running as a **child
//! process** (so this launcher needs no async runtime), and offers a menu:
//! Open Studio · Start/Stop/Restart · Open at Login · Quit. No new server code;
//! all objc unsafe lives inside `tray-icon`/`tao`, so `#![forbid(unsafe_code)]`
//! still holds.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use tao::event::{Event, StartCause};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

use super::daemon;
use crate::config::Config;

/// Entry point for `saffev tray`. Runs synchronously on the main thread. Never
/// returns (the tao run loop `std::process::exit`s on Quit).
pub fn run_tray() -> ExitCode {
    let config = Config::load().unwrap_or_default();
    let config_path = config.config_path();
    let pid_path = daemon::pid_path(&config);
    let studio_url = config.studio_url();

    // Start the service on launch if it isn't already up.
    ensure_running(&pid_path, &config_path);

    let event_loop = EventLoopBuilder::<()>::new().build();

    let open_item = MenuItem::with_id("open", "Open Saffev Studio", true, None);
    let status_item = MenuItem::with_id("status", "Starting…", false, None);
    let start_item = MenuItem::with_id("start", "Start", true, None);
    let stop_item = MenuItem::with_id("stop", "Stop", true, None);
    let restart_item = MenuItem::with_id("restart", "Restart", true, None);
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
                    .with_icon(status_icon(is_running(&pid_path)))
                    .build()
                    .ok();
                refresh_ui(&tray, &status_item, &pid_path);
            }
            Event::NewEvents(StartCause::ResumeTimeReached { .. }) => {
                refresh_ui(&tray, &status_item, &pid_path);
            }
            _ => {}
        }

        while let Ok(ev) = menu_channel.try_recv() {
            match ev.id.0.as_str() {
                "open" => open_url(&studio_url),
                "start" => ensure_running(&pid_path, &config_path),
                "stop" => stop_daemon(&pid_path),
                "restart" => {
                    stop_daemon(&pid_path);
                    std::thread::sleep(Duration::from_millis(600));
                    ensure_running(&pid_path, &config_path);
                }
                "login" => set_login(login_item.is_checked()),
                "quit" => {
                    // Quitting the menu-bar app leaves the service running by
                    // design (Quit != Stop). Use Stop to actually shut it down.
                    *control_flow = ControlFlow::Exit;
                }
                _ => {}
            }
            refresh_ui(&tray, &status_item, &pid_path);
        }
    });
}

fn is_running(pid_path: &Path) -> bool {
    matches!(daemon::daemon_state(pid_path), Ok(Some(true)))
}

fn ensure_running(pid_path: &Path, config_path: &Path) {
    if !is_running(pid_path) {
        let _ = daemon::spawn_background(Some(config_path), true, true);
    }
}

fn stop_daemon(pid_path: &Path) {
    if let Ok(Some(pf)) = daemon::read_pid_file(pid_path) {
        let _ = daemon::send_terminate(pf.pid);
    }
}

fn refresh_ui(tray: &Option<TrayIcon>, status_item: &MenuItem, pid_path: &Path) {
    let running = is_running(pid_path);
    if let Some(t) = tray {
        let _ = t.set_icon(Some(status_icon(running)));
    }
    status_item.set_text(if running {
        "● Running"
    } else {
        "○ Stopped"
    });
}

fn open_url(url: &str) {
    let _ = std::process::Command::new("open").arg(url).spawn();
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
        }
    } else {
        let _ = std::process::Command::new("launchctl")
            .arg("unload")
            .arg(&path)
            .status();
        let _ = std::fs::remove_file(&path);
    }
}
