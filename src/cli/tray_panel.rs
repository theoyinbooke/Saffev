//! Menu-bar drop-down panel — the widget that opens under the status item
//! (feature `tray`; the window itself is macOS-only).
//!
//! Clicking the status-bar icon toggles a borderless, always-on-top, transparent
//! window anchored under the icon that hosts a WKWebView. The webview loads
//! `menubar.html` **from the running Studio** (`http://localhost:<studio>/
//! menubar.html`), so the panel gets the install token injected the same way
//! the SPA does, calls `/api/*` same-origin (no CORS or keyring work in this
//! process), and shares the Studio design system. While the service is down
//! the webview shows a small embedded offline page (`tray_panel_offline.html`)
//! with Start / Logs / Quit — the panel must be useful precisely when Studio
//! cannot serve it.
//!
//! Protocol between host and page (both directions are plain JSON):
//! - page → host: `window.ipc.postMessage(JSON.stringify({cmd, ...}))`, parsed
//!   by [`parse_msg`] into [`PanelMsg`]. Unknown or malformed messages are
//!   ignored — the page is ours, but the host never trusts it with a shell
//!   string: routes are sanitized by [`sanitize_route`] before `open` sees them.
//! - host → page: `window.__saffevHost.setState(<HostState>)` on every change
//!   plus `onShow()` / `onHide()` so the page only polls while visible.
//!
//! Nothing here touches the proxy or the store: the panel is a client of the
//! Studio API like the browser is. All objc unsafe stays inside `tao`/`wry`.

use serde::{Deserialize, Serialize};

/// Logical panel width: a 380px card plus a 16px transparent margin each side
/// that carries the drop shadow (the window has no native shadow).
pub const PANEL_WIDTH: f64 = 412.0;
/// The page asks for its content height; these bound what the host grants.
pub const PANEL_MIN_HEIGHT: f64 = 320.0;
pub const PANEL_MAX_HEIGHT: f64 = 780.0;
pub const PANEL_DEFAULT_HEIGHT: f64 = 620.0;
/// Logical gap between the status item and the panel's top edge.
pub const ANCHOR_GAP: f64 = 2.0;
/// Keep the panel this far inside the screen edge when it can't be centred.
pub const SCREEN_MARGIN: f64 = 8.0;

/// Messages the page sends the host. `cmd` is the tag; extra fields per variant.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum PanelMsg {
    /// The page finished booting and wants the current [`HostState`].
    Ready,
    /// Open the Studio in the default browser, optionally at a hash route.
    Open {
        #[serde(default)]
        route: String,
    },
    Start,
    Stop,
    Restart,
    Logs,
    Update,
    /// Run `saffev backup` (encrypted copy + restore notes) and reveal it.
    Backup,
    /// Open the native folder picker for the export/backup destination; the
    /// result comes back to the page as `exportDirChosen(path|null)`, which
    /// saves it through the Studio API (validated there).
    ChooseExportDir,
    Quit,
    /// Hide the panel (Escape key).
    Close,
    SetLogin {
        enabled: bool,
    },
    /// A pinned panel stays open when it loses focus.
    SetPinned {
        pinned: bool,
    },
    /// The viewer's theme choice (`light` | `dark` | `` = follow the OS), so
    /// the offline card can match the Studio page.
    SetTheme {
        #[serde(default)]
        theme: String,
    },
    /// The page's content height (logical px, including the shadow margin).
    Resize {
        height: f64,
    },
}

/// Parse one IPC payload. Malformed input is `None`, never a panic or a
/// default action.
pub fn parse_msg(raw: &str) -> Option<PanelMsg> {
    serde_json::from_str(raw).ok()
}

/// Reduce a page-supplied Studio hash route to something safe to append to the
/// Studio URL: must start with `#/`, only `[A-Za-z0-9/_-]` after that, ≤ 80
/// chars. Anything else opens the Studio root. The route came from our own page,
/// but it still becomes an argument to `open` — untrusted strings never become
/// option text in a subprocess (the URL prefix makes a dash-leading value
/// impossible; this keeps it that way even if the prefix ever changes).
pub fn sanitize_route(route: &str) -> Option<String> {
    let body = route.strip_prefix("#/")?;
    if body.is_empty() || body.len() > 80 {
        return None;
    }
    if !body
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-'))
    {
        return None;
    }
    Some(format!("#/{body}"))
}

/// Clamp the height the page asked for into the host's bounds.
pub fn clamp_height(requested: f64) -> f64 {
    if !requested.is_finite() {
        return PANEL_DEFAULT_HEIGHT;
    }
    requested.clamp(PANEL_MIN_HEIGHT, PANEL_MAX_HEIGHT)
}

/// A rectangle in physical pixels, top-left origin (tao/tray-icon convention).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Px {
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
}

impl Px {
    pub fn contains(&self, x: f64, y: f64) -> bool {
        x >= self.x && x < self.x + self.w && y >= self.y && y < self.y + self.h
    }
}

/// Where to put the panel's top-left corner so it hangs centred under the
/// status item, pushed inside the screen when the icon sits near an edge.
/// All values physical pixels. Pure, so the geometry is unit-tested.
pub fn anchor_position(
    icon: Px,
    panel_w: f64,
    panel_h: f64,
    screen: Px,
    gap: f64,
    margin: f64,
) -> (f64, f64) {
    let centred = icon.x + icon.w / 2.0 - panel_w / 2.0;
    let min_x = screen.x + margin;
    let max_x = (screen.x + screen.w - panel_w - margin).max(min_x);
    let x = centred.clamp(min_x, max_x);
    let mut y = icon.y + icon.h + gap;
    // A very short screen: keep the bottom edge visible rather than the gap.
    let max_y = (screen.y + screen.h - panel_h - margin).max(screen.y);
    if y > max_y {
        y = max_y;
    }
    (x.round(), y.round())
}

/// What the host tells the page about itself (mirrors the tray menu state).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostState {
    pub app_name: String,
    pub version: String,
    pub studio_url: String,
    pub running: bool,
    /// `running` | `stopped` | `starting` | `failed`
    pub status: String,
    pub status_text: String,
    pub login_enabled: bool,
    pub pinned: bool,
    /// `light` | `dark` | `` (follow the OS).
    pub theme: String,
    /// The user's home directory, so the page can print `~/…` paths.
    pub home_dir: String,
}

/// Only the three values the pages understand; anything else means "OS".
pub fn sanitize_theme(theme: &str) -> String {
    match theme {
        "light" | "dark" => theme.to_string(),
        _ => String::new(),
    }
}

impl HostState {
    /// The JS statement that delivers this state to the page. The page may not
    /// have installed its hook yet (still loading) — guard, never throw.
    pub fn script(&self) -> String {
        let json = serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string());
        format!("window.__saffevHost&&window.__saffevHost.setState({json});")
    }
}

// ---------------------------------------------------------------------------
// macOS: the real window + webview.
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
pub use imp::Panel;

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use std::net::{SocketAddr, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use tao::dpi::{LogicalSize, PhysicalPosition};
    use tao::event_loop::{EventLoopProxy, EventLoopWindowTarget};
    use tao::platform::macos::WindowBuilderExtMacOS;
    use tao::window::{Window, WindowBuilder};
    use wry::{PageLoadEvent, WebView, WebViewBuilder};

    use crate::cli::tray::UserEvent;

    /// Shown while the service is down. Self-contained (inline CSS, no
    /// requests) so it renders with nothing listening.
    const OFFLINE_HTML: &str = include_str!("tray_panel_offline.html");

    /// Clicking the status item while the panel is open first blurs (hides) it,
    /// then delivers the click; a click this soon after a hide means "close",
    /// not "reopen".
    const REOPEN_DEBOUNCE: Duration = Duration::from_millis(350);
    /// Don't hammer `load_url` while Studio is still coming up.
    const RELOAD_BACKOFF: Duration = Duration::from_secs(6);
    /// TCP probe budget on the main thread. Only paid while the service is
    /// running but the Studio page isn't loaded yet.
    const PROBE_TIMEOUT: Duration = Duration::from_millis(120);

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Page {
        Offline,
        Studio,
    }

    pub struct Panel {
        window: Window,
        webview: WebView,
        page: Page,
        /// Set by the page-load handler when the Studio page finished loading.
        studio_loaded: Arc<AtomicBool>,
        last_load: Option<Instant>,
        hidden_at: Option<Instant>,
        /// Last anchor, re-applied after a resize (AppKit anchors resizes at the
        /// bottom-left; the panel must stay glued to the menu bar).
        anchor: Option<PhysicalPosition<f64>>,
        height: f64,
        pub pinned: bool,
        panel_url: String,
        studio_port: u16,
    }

    impl Panel {
        /// Build the (hidden) panel window + webview. Must run on the main
        /// thread inside the event loop (after `StartCause::Init`). Errors are
        /// logged and yield `None`: the menu still works without the panel.
        pub fn new(
            target: &EventLoopWindowTarget<UserEvent>,
            proxy: EventLoopProxy<UserEvent>,
            studio_url: &str,
            studio_port: u16,
        ) -> Option<Self> {
            let window = WindowBuilder::new()
                .with_title(crate::brand::APP_NAME)
                .with_decorations(false)
                .with_transparent(true)
                .with_always_on_top(true)
                .with_resizable(false)
                .with_visible(false)
                .with_visible_on_all_workspaces(true)
                .with_has_shadow(false)
                .with_inner_size(LogicalSize::new(PANEL_WIDTH, PANEL_DEFAULT_HEIGHT))
                .build(target)
                .map_err(|e| tracing::warn!("menu-bar panel: window failed: {e}"))
                .ok()?;

            let studio_loaded = Arc::new(AtomicBool::new(false));
            let loaded_flag = studio_loaded.clone();
            let panel_url = format!("{}/menubar.html", studio_url.trim_end_matches('/'));
            let studio_origin = studio_url.trim_end_matches('/').to_string();

            // The wry handlers must be Send + Sync; the proxy is Send, so a
            // mutex makes it shareable.
            let proxy = Arc::new(Mutex::new(proxy));
            let ipc_proxy = proxy.clone();

            let webview = WebViewBuilder::new()
                .with_transparent(true)
                .with_html(OFFLINE_HTML)
                .with_accept_first_mouse(true)
                .with_devtools(cfg!(debug_assertions))
                // Only the offline shell and our own Studio origin may load; a
                // link that escapes goes nowhere (deep links use the `open` IPC).
                .with_navigation_handler(move |url| {
                    url.starts_with(&studio_origin) || url.starts_with("about:")
                })
                .with_new_window_req_handler(|_, _| wry::NewWindowResponse::Deny)
                .with_on_page_load_handler(move |event, url| {
                    let finished = matches!(event, PageLoadEvent::Finished);
                    tracing::debug!(
                        "menu-bar panel: page load {} {url}",
                        if finished { "finished" } else { "started" }
                    );
                    if finished && url.starts_with("http") {
                        loaded_flag.store(true, Ordering::Relaxed);
                    }
                })
                .with_ipc_handler(move |req| {
                    if let Some(msg) = parse_msg(req.body()) {
                        if let Ok(p) = ipc_proxy.lock() {
                            let _ = p.send_event(UserEvent::Panel(msg));
                        }
                    }
                })
                .build(&window)
                .map_err(|e| tracing::warn!("menu-bar panel: webview failed: {e}"))
                .ok()?;

            Some(Self {
                window,
                webview,
                page: Page::Offline,
                studio_loaded,
                last_load: None,
                hidden_at: None,
                anchor: None,
                height: PANEL_DEFAULT_HEIGHT,
                pinned: false,
                panel_url,
                studio_port,
            })
        }

        pub fn is_visible(&self) -> bool {
            self.window.is_visible()
        }

        /// Left-click on the status item.
        pub fn toggle(&mut self, icon: tray_icon::Rect, state: &HostState) {
            tracing::debug!(
                "menu-bar panel: toggle (visible: {}, hidden_at: {:?})",
                self.is_visible(),
                self.hidden_at.map(|t| t.elapsed())
            );
            if self.is_visible() {
                self.hide();
                return;
            }
            if let Some(t) = self.hidden_at {
                if t.elapsed() < REOPEN_DEBOUNCE {
                    // The blur from this very click already hid us: stay hidden.
                    return;
                }
            }
            self.show(icon, state);
        }

        fn show(&mut self, icon: tray_icon::Rect, state: &HostState) {
            let icon_px = Px {
                x: icon.position.x,
                y: icon.position.y,
                w: icon.size.width as f64,
                h: icon.size.height as f64,
            };
            let (screen, scale) = self.screen_for(icon_px);
            let (x, y) = anchor_position(
                icon_px,
                PANEL_WIDTH * scale,
                self.height * scale,
                screen,
                ANCHOR_GAP * scale,
                SCREEN_MARGIN * scale,
            );
            let pos = PhysicalPosition::new(x, y);
            tracing::debug!(
                "menu-bar panel: show at {:?} (icon {:?}, screen {:?}, scale {scale})",
                pos,
                icon_px,
                screen
            );
            self.anchor = Some(pos);
            self.window
                .set_inner_size(LogicalSize::new(PANEL_WIDTH, self.height));
            self.window.set_outer_position(pos);
            self.window.set_visible(true);
            self.window.set_focus();
            self.push_state(state);
            let _ = self.webview.evaluate_script(
                "window.__saffevHost&&window.__saffevHost.onShow&&window.__saffevHost.onShow();",
            );
        }

        pub fn hide(&mut self) {
            if !self.is_visible() {
                return;
            }
            self.window.set_visible(false);
            self.hidden_at = Some(Instant::now());
            let _ = self.webview.evaluate_script(
                "window.__saffevHost&&window.__saffevHost.onHide&&window.__saffevHost.onHide();",
            );
        }

        /// The window lost key status. Pinned panels stay; others close like a
        /// popover.
        pub fn on_blur(&mut self) {
            if !self.pinned {
                self.hide();
            }
        }

        pub fn set_pinned(&mut self, pinned: bool) {
            self.pinned = pinned;
        }

        /// Grant (a clamped version of) the height the page asked for and keep
        /// the top edge where it was.
        pub fn set_height(&mut self, requested: f64) {
            let h = clamp_height(requested);
            if (h - self.height).abs() < 0.5 {
                return;
            }
            self.height = h;
            if self.is_visible() {
                self.window
                    .set_inner_size(LogicalSize::new(PANEL_WIDTH, self.height));
                if let Some(pos) = self.anchor {
                    self.window.set_outer_position(pos);
                }
            }
        }

        /// Keep the loaded page in step with the service: Studio page while it
        /// answers, the embedded offline shell otherwise. Called every tick.
        pub fn sync(&mut self, running: bool) {
            match (running, self.page) {
                (false, Page::Studio) | (false, Page::Offline) if self.page == Page::Studio => {
                    self.load_offline();
                }
                (false, _) => {}
                (true, Page::Offline) => {
                    if self.backoff_elapsed() && self.studio_answers() {
                        self.load_studio();
                    }
                }
                (true, Page::Studio) => {
                    // Loaded too early (Studio was binding): retry, bounded.
                    if !self.studio_loaded.load(Ordering::Relaxed)
                        && self.backoff_elapsed()
                        && self.studio_answers()
                    {
                        self.load_studio();
                    }
                }
            }
        }

        pub fn push_state(&self, state: &HostState) {
            self.eval(&state.script());
        }

        /// The page announced itself (`ready` IPC). For the Studio page this is
        /// the authoritative "loaded" signal — more reliable than the webview's
        /// navigation callback — so the reload loop stands down.
        pub fn mark_ready(&mut self) {
            if self.page == Page::Studio {
                self.studio_loaded.store(true, Ordering::Relaxed);
            }
        }

        /// Run a statement in the page. Failures are logged, never fatal.
        pub fn eval(&self, js: &str) {
            if let Err(e) = self.webview.evaluate_script(js) {
                tracing::debug!("menu-bar panel: evaluate_script failed: {e}");
            }
        }

        fn load_studio(&mut self) {
            tracing::debug!("menu-bar panel: loading {}", self.panel_url);
            self.studio_loaded.store(false, Ordering::Relaxed);
            self.last_load = Some(Instant::now());
            self.page = Page::Studio;
            if let Err(e) = self.webview.load_url(&self.panel_url) {
                tracing::debug!("menu-bar panel: load_url failed: {e}");
            }
        }

        fn load_offline(&mut self) {
            tracing::debug!("menu-bar panel: loading the offline shell");
            self.page = Page::Offline;
            self.studio_loaded.store(false, Ordering::Relaxed);
            self.last_load = Some(Instant::now());
            if let Err(e) = self.webview.load_html(OFFLINE_HTML) {
                tracing::debug!("menu-bar panel: load_html failed: {e}");
            }
        }

        fn backoff_elapsed(&self) -> bool {
            self.last_load
                .map(|t| t.elapsed() >= RELOAD_BACKOFF)
                .unwrap_or(true)
        }

        /// Cheap loopback probe: is anything listening on the Studio port? The
        /// daemon writes its pid file before Studio binds, so "running" alone
        /// is not "serving".
        fn studio_answers(&self) -> bool {
            let addr = SocketAddr::from(([127, 0, 0, 1], self.studio_port));
            TcpStream::connect_timeout(&addr, PROBE_TIMEOUT).is_ok()
        }

        /// The monitor under the status item (physical bounds + scale), falling
        /// back to the primary/first monitor.
        fn screen_for(&self, icon: Px) -> (Px, f64) {
            let (cx, cy) = (icon.x + icon.w / 2.0, icon.y + icon.h / 2.0);
            let to_px = |m: &tao::monitor::MonitorHandle| Px {
                x: m.position().x as f64,
                y: m.position().y as f64,
                w: m.size().width as f64,
                h: m.size().height as f64,
            };
            let mut fallback = None;
            for m in self.window.available_monitors() {
                let r = to_px(&m);
                if r.contains(cx, cy) {
                    return (r, m.scale_factor());
                }
                if fallback.is_none() {
                    fallback = Some((r, m.scale_factor()));
                }
            }
            if let Some(m) = self.window.primary_monitor() {
                return (to_px(&m), m.scale_factor());
            }
            fallback.unwrap_or((
                Px {
                    x: 0.0,
                    y: 0.0,
                    w: 1440.0,
                    h: 900.0,
                },
                self.window.scale_factor(),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Other platforms with `--features tray`: menu only, no panel. Same surface so
// the tray loop needs no cfg soup.
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "macos"))]
pub use stub::Panel;

#[cfg(not(target_os = "macos"))]
mod stub {
    use super::*;
    use tao::event_loop::{EventLoopProxy, EventLoopWindowTarget};

    use crate::cli::tray::UserEvent;

    pub struct Panel {
        pub pinned: bool,
    }

    impl Panel {
        pub fn new(
            _target: &EventLoopWindowTarget<UserEvent>,
            _proxy: EventLoopProxy<UserEvent>,
            _studio_url: &str,
            _studio_port: u16,
        ) -> Option<Self> {
            None
        }
        pub fn is_visible(&self) -> bool {
            false
        }
        pub fn toggle(&mut self, _icon: tray_icon::Rect, _state: &HostState) {}
        pub fn hide(&mut self) {}
        pub fn on_blur(&mut self) {}
        pub fn set_pinned(&mut self, pinned: bool) {
            self.pinned = pinned;
        }
        pub fn set_height(&mut self, _requested: f64) {}
        pub fn sync(&mut self, _running: bool) {}
        pub fn push_state(&self, _state: &HostState) {}
        pub fn mark_ready(&mut self) {}
        pub fn eval(&self, _js: &str) {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_command_shape() {
        assert_eq!(parse_msg(r#"{"cmd":"ready"}"#), Some(PanelMsg::Ready));
        assert_eq!(
            parse_msg(r##"{"cmd":"open","route":"#/agents"}"##),
            Some(PanelMsg::Open {
                route: "#/agents".into()
            })
        );
        assert_eq!(
            parse_msg(r#"{"cmd":"open"}"#),
            Some(PanelMsg::Open {
                route: String::new()
            })
        );
        assert_eq!(
            parse_msg(r#"{"cmd":"set_login","enabled":true}"#),
            Some(PanelMsg::SetLogin { enabled: true })
        );
        assert_eq!(
            parse_msg(r#"{"cmd":"set_pinned","pinned":false}"#),
            Some(PanelMsg::SetPinned { pinned: false })
        );
        assert_eq!(
            parse_msg(r#"{"cmd":"resize","height":512.5}"#),
            Some(PanelMsg::Resize { height: 512.5 })
        );
        assert_eq!(
            parse_msg(r#"{"cmd":"set_theme","theme":"dark"}"#),
            Some(PanelMsg::SetTheme {
                theme: "dark".into()
            })
        );
        assert_eq!(sanitize_theme("dark"), "dark");
        assert_eq!(sanitize_theme("light"), "light");
        assert_eq!(sanitize_theme("<script>"), "");
        for (raw, want) in [
            ("start", PanelMsg::Start),
            ("stop", PanelMsg::Stop),
            ("restart", PanelMsg::Restart),
            ("logs", PanelMsg::Logs),
            ("update", PanelMsg::Update),
            ("backup", PanelMsg::Backup),
            ("choose_export_dir", PanelMsg::ChooseExportDir),
            ("quit", PanelMsg::Quit),
            ("close", PanelMsg::Close),
        ] {
            assert_eq!(parse_msg(&format!(r#"{{"cmd":"{raw}"}}"#)), Some(want));
        }
    }

    #[test]
    fn malformed_ipc_is_ignored_not_defaulted() {
        // A bad payload must never turn into an action (Quit/Stop especially).
        assert_eq!(parse_msg(""), None);
        assert_eq!(parse_msg("quit"), None);
        assert_eq!(parse_msg(r#"{"cmd":"format_disk"}"#), None);
        assert_eq!(parse_msg(r#"{"cmd":"set_login"}"#), None);
        assert_eq!(parse_msg(r#"{"cmd":"resize","height":"tall"}"#), None);
    }

    #[test]
    fn routes_are_whitelisted() {
        assert_eq!(sanitize_route("#/agents"), Some("#/agents".into()));
        assert_eq!(
            sanitize_route("#/analytics/privacy"),
            Some("#/analytics/privacy".into())
        );
        assert_eq!(
            sanitize_route("#/settings/preservation"),
            Some("#/settings/preservation".into())
        );
        // Everything that isn't a plain hash route opens the root instead.
        assert_eq!(sanitize_route(""), None);
        assert_eq!(sanitize_route("#/"), None);
        assert_eq!(sanitize_route("/agents"), None);
        assert_eq!(sanitize_route("--output=x"), None);
        assert_eq!(sanitize_route("#/a?b=c"), None);
        assert_eq!(sanitize_route("#/a b"), None);
        assert_eq!(sanitize_route("#/évil"), None);
        assert_eq!(sanitize_route(&format!("#/{}", "a".repeat(81))), None);
    }

    #[test]
    fn height_is_bounded() {
        assert_eq!(clamp_height(100.0), PANEL_MIN_HEIGHT);
        assert_eq!(clamp_height(5000.0), PANEL_MAX_HEIGHT);
        assert_eq!(clamp_height(500.0), 500.0);
        assert_eq!(clamp_height(f64::NAN), PANEL_DEFAULT_HEIGHT);
        assert_eq!(clamp_height(f64::INFINITY), PANEL_DEFAULT_HEIGHT);
    }

    fn screen() -> Px {
        Px {
            x: 0.0,
            y: 0.0,
            w: 2880.0,
            h: 1800.0,
        }
    }

    #[test]
    fn panel_hangs_centred_under_the_icon() {
        // A 44px-wide icon at x=1400 on a 2x screen; 824px-wide panel.
        let icon = Px {
            x: 1400.0,
            y: 0.0,
            w: 44.0,
            h: 48.0,
        };
        let (x, y) = anchor_position(icon, 824.0, 1200.0, screen(), 4.0, 16.0);
        assert_eq!(x, 1400.0 + 22.0 - 412.0);
        assert_eq!(y, 52.0);
    }

    #[test]
    fn panel_is_pushed_inside_the_right_edge() {
        // Status items live at the far right — the common case.
        let icon = Px {
            x: 2800.0,
            y: 0.0,
            w: 44.0,
            h: 48.0,
        };
        let (x, _) = anchor_position(icon, 824.0, 1200.0, screen(), 4.0, 16.0);
        assert_eq!(x, 2880.0 - 824.0 - 16.0);
    }

    #[test]
    fn panel_is_pushed_inside_the_left_edge_and_secondary_screens() {
        // A monitor placed left of the main one has a negative origin.
        let left = Px {
            x: -1920.0,
            y: 0.0,
            w: 1920.0,
            h: 1080.0,
        };
        let icon = Px {
            x: -1900.0,
            y: 0.0,
            w: 30.0,
            h: 24.0,
        };
        let (x, y) = anchor_position(icon, 412.0, 600.0, left, 2.0, 8.0);
        assert_eq!(x, -1920.0 + 8.0);
        assert_eq!(y, 26.0);
    }

    #[test]
    fn short_screen_keeps_the_bottom_edge_visible() {
        let tiny = Px {
            x: 0.0,
            y: 0.0,
            w: 1200.0,
            h: 500.0,
        };
        let icon = Px {
            x: 600.0,
            y: 0.0,
            w: 30.0,
            h: 24.0,
        };
        let (_, y) = anchor_position(icon, 412.0, 600.0, tiny, 2.0, 8.0);
        // Can't fit below the bar; clamps to the top of the screen, never negative.
        assert_eq!(y, 0.0);
    }

    #[test]
    fn host_state_script_is_guarded_and_camel_cased() {
        let s = HostState {
            app_name: "Saffev".into(),
            version: "0.7.2".into(),
            studio_url: "http://localhost:7100".into(),
            running: true,
            status: "running".into(),
            status_text: "Running".into(),
            login_enabled: false,
            pinned: true,
            theme: "dark".into(),
            home_dir: "/Users/x".into(),
        };
        let js = s.script();
        assert!(js.starts_with("window.__saffevHost&&"));
        assert!(js.contains("\"studioUrl\":\"http://localhost:7100\""));
        assert!(js.contains("\"loginEnabled\":false"));
        assert!(js.contains("\"pinned\":true"));
    }
}
