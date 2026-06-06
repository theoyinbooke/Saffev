//! Studio — the local web UI server (04 §7.5).
//!
//! An `axum` router that serves the `rust-embed`'d SPA (`studio-web/`) plus a
//! JSON API and an SSE stream. Localhost-bound, **token-gated** on every
//! control/API endpoint (Host-header allowlist + strict CORS, 04 §7.8), single
//! user.
//!
//! ## THE STUDIO HTTP API CONTRACT
//!
//! Backend and frontend agents both code to this verbatim. The JSON shapes are
//! the [`dto`] types in this module — do not change them without updating both
//! sides. Auth: every `/api/*` route requires `Authorization: Bearer <token>`
//! (the per-install token from the keyring) and a Host in the allowlist.
//!
//! | Method | Route               | Request                  | Response (200)                |
//! |--------|---------------------|--------------------------|-------------------------------|
//! | GET    | `/api/health`       | —                        | [`dto::Health`]               |
//! | GET    | `/api/live`         | —                        | [`dto::LiveSnapshot`]         |
//! | GET    | `/api/history`      | query [`dto::HistoryParams`] | `Vec<`[`dto::HistoryItem`]`>` |
//! | GET    | `/api/history/:id`  | path id                  | [`dto::HistoryDetail`]        |
//! | GET    | `/api/privacy`      | —                        | [`dto::PrivacySummary`]       |
//! | GET    | `/api/engines`      | —                        | [`dto::EnginesView`]          |
//! | POST   | `/api/engines/adopt`| [`dto::AdoptRequest`]    | [`dto::EngineView`]           |
//! | POST   | `/api/engines/revert`| [`dto::RevertRequest`]  | [`dto::EngineView`]           |
//! | GET    | `/api/exposure`     | —                        | [`crate::exposure::ExposureReport`] |
//! | GET    | `/api/settings`     | —                        | [`dto::SettingsView`]         |
//! | PUT    | `/api/settings`     | [`dto::SettingsUpdate`]  | [`dto::SettingsView`]         |
//! | GET    | `/api/stream`       | — (SSE)                  | `text/event-stream` of [`dto::StreamEvent`] |
//!
//! Errors use [`dto::ApiError`] with the appropriate HTTP status (401 missing/
//! bad token, 403 bad Host, 404 unknown id, 400 validation, 500 internal).

pub mod api;
pub mod assets;
pub mod auth;
pub mod dto;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;

use crate::config::ConfigHandle;
use crate::store::Store;
use crate::{Error, Result};

/// Shared state for every Studio handler.
#[derive(Clone)]
pub struct StudioState {
    /// Live, swappable config shared with the proxy. Handlers load the current
    /// snapshot at use-time (`config.load()`) so a `PUT /api/settings` that swaps
    /// the handle is reflected by a subsequent `GET /api/settings` without a
    /// restart.
    pub config: ConfigHandle,
    /// Store handle for reads + setting writes.
    pub store: Store,
    /// Per-install bearer token required on every `/api/*` route.
    pub token: Arc<str>,
    /// Broadcast sender feeding the SSE `/api/stream` endpoint with live events.
    pub events: tokio::sync::broadcast::Sender<dto::StreamEvent>,
}

/// The Studio server.
pub struct StudioServer {
    state: StudioState,
}

impl StudioServer {
    /// Build the Studio server with shared state.
    pub fn new(state: StudioState) -> Self {
        StudioServer { state }
    }

    /// Build the full router: embedded assets + JSON API + SSE, with the auth /
    /// Host-allowlist / CORS layers applied to `/api/*`.
    ///
    /// Layering note: the security middleware (token → Host → CORS) is attached
    /// **only** to the `/api` subtree. The static SPA (and its assets) are served
    /// tokenless so the browser can bootstrap and then send the bearer token on
    /// every subsequent `fetch`. The passthrough proxy is an entirely separate
    /// server (port 11434) and is never gated here.
    pub fn router(&self) -> Router {
        // Studio port is read once when the router/CORS layer is built — ports are
        // not hot-reloadable (they would rebind the listener), so the startup
        // snapshot is authoritative here.
        let studio_port = self.state.config.load().ports.studio;

        // The JSON + SSE API subtree. All routes here are control-plane.
        let api = Router::new()
            .route("/health", get(api::health))
            .route("/live", get(api::live))
            .route("/history", get(api::history))
            .route("/history/:id", get(api::history_detail))
            .route("/privacy", get(api::privacy))
            .route("/engines", get(api::engines))
            .route("/engines/adopt", post(api::engines_adopt))
            .route("/engines/revert", post(api::engines_revert))
            .route("/exposure", get(api::exposure))
            .route("/settings", get(api::settings_get).put(api::settings_put))
            .route("/stream", get(api::stream))
            // Order matters: layers run outermost-first on the way in. We want
            // Host checked first (cheapest reject), then token, then CORS
            // handling on the response. `layer` stacks so the LAST `.layer`
            // added is the OUTERMOST. So add token (inner) then host (outer).
            .layer(axum::middleware::from_fn_with_state(
                self.state.clone(),
                auth::require_token,
            ))
            .layer(axum::middleware::from_fn_with_state(
                self.state.clone(),
                auth::require_host,
            ))
            .layer(auth::cors_layer(studio_port))
            .with_state(self.state.clone());

        // The SPA fallback serves embedded assets for everything that is not
        // `/api/*`. The served `index.html` gets the per-install token injected
        // (so opening the loopback URL self-authenticates); all other assets are
        // served as-is. The token is captured by the fallback closure.
        let token = self.state.token.clone();
        Router::new()
            .nest("/api", api)
            .fallback(move |uri: axum::http::Uri| {
                let token = token.clone();
                async move { assets::serve(uri, token).await }
            })
    }

    /// Bind to the configured Studio port and serve until the process is killed.
    ///
    /// Binds **loopback only** (the configured bind address, default
    /// `127.0.0.1`) — the Studio is never exposed to the network.
    pub async fn serve(self) -> Result<()> {
        // No external shutdown signal: serve until the task is aborted.
        self.serve_with_shutdown(std::future::pending::<()>()).await
    }

    /// Like [`serve`](Self::serve), but ends cleanly when `shutdown` resolves,
    /// letting in-flight requests drain via `with_graceful_shutdown` — the path
    /// `saffev stop` takes (SIGTERM → this future resolves).
    pub async fn serve_with_shutdown<S>(self, shutdown: S) -> Result<()>
    where
        S: std::future::Future<Output = ()> + Send + 'static,
    {
        // Bind/port are read once at bind time from the startup snapshot — ports
        // are not hot-reloadable.
        let cfg = self.state.config.load();
        let addr = SocketAddr::new(cfg.ports.bind, cfg.ports.studio);
        drop(cfg);
        let router = self.router();

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| Error::Studio(format!("failed to bind Studio on {addr}: {e}")))?;

        tracing::info!("Studio listening on http://{addr}");

        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown)
            .await
            .map_err(|e| Error::Studio(format!("Studio server error: {e}")))?;
        Ok(())
    }
}

/// Default broadcast capacity for the live SSE event channel.
pub const STREAM_CHANNEL_CAPACITY: usize = 1024;

#[cfg(test)]
mod tests {
    use super::*;

    // Store-free unit coverage for this module's behavior lives alongside the
    // logic it tests:
    //  - `studio::auth::tests`   — token + Host allowlist + CORS rejection.
    //  - `studio::api::tests`    — DTO mapping, settings projection, error envelope.
    //  - `studio::assets::tests` — embedded SPA serve + client-route fallback.
    // (`StudioState` requires a live `Store`, so full router smoke tests run as
    // integration tests in the assembled binary, not here.)

    #[test]
    fn stream_channel_capacity_is_sane() {
        assert!(STREAM_CHANNEL_CAPACITY >= 256);
    }

    #[test]
    fn studio_state_is_clone() {
        // The router clones `StudioState` into every layer + handler, so it must
        // stay cheaply cloneable (Arc/handle fields only).
        fn assert_clone<T: Clone>() {}
        assert_clone::<StudioState>();
    }
}
