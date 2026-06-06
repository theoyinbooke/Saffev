//! Integration test: the `/api/update` routes are token-gated like every other
//! control endpoint (04 §7.8 — control/Studio endpoints reject requests without
//! the install token and with a non-allowlisted Host; the passthrough path stays
//! tokenless). This exercises the REAL assembled Studio router + middleware
//! stack, not a stubbed handler.
//!
//! We deliberately only assert the auth-gating (401/403) responses, which are
//! network-free and deterministic. The authorized 200 path would make a live
//! GitHub release-metadata call, so it is left to the unit tests in
//! `src/update.rs` (which cover the version-compare + no-receipt logic offline).

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt; // for `oneshot`

use saffev::config::{config_handle, Config};
use saffev::store::Store;
use saffev::studio::{StudioServer, StudioState, STREAM_CHANNEL_CAPACITY};

/// The Studio port the test config + Host allowlist use.
const STUDIO_PORT: u16 = 7100;
/// The per-install token the router will require.
const TOKEN: &str = "test-install-token-abc123";

/// Build a real Studio router backed by a throwaway encrypted store.
async fn test_router() -> axum::Router {
    // Pin a DB key so `Store::open` never touches the OS keyring (sqlcipher is on
    // by default). Matches the convention in `src/store/mod.rs` tests.
    if std::env::var("SAFFEV_DB_KEY")
        .map(|v| v.is_empty())
        .unwrap_or(true)
    {
        std::env::set_var("SAFFEV_DB_KEY", "test-db-key-0123456789abcdef");
    }

    let mut cfg = Config::default();
    cfg.ports.studio = STUDIO_PORT;

    let mut db = std::env::temp_dir();
    db.push(format!("saffev-update-auth-{}.db", uuid::Uuid::new_v4()));
    let store = Store::open(&db).await.expect("open test store");

    let (events, _rx) = tokio::sync::broadcast::channel(STREAM_CHANNEL_CAPACITY);

    let state = StudioState {
        config: config_handle(cfg),
        store,
        token: TOKEN.into(),
        events,
    };
    StudioServer::new(state).router()
}

/// A request to `/api/update` with no Authorization header is rejected 401.
#[tokio::test]
async fn update_get_requires_token() {
    let router = test_router().await;
    let req = Request::builder()
        .method("GET")
        .uri("/api/update")
        .header(header::HOST, format!("127.0.0.1:{STUDIO_PORT}"))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "GET /api/update without a token must be 401"
    );
}

/// A wrong bearer token is rejected 401.
#[tokio::test]
async fn update_get_rejects_wrong_token() {
    let router = test_router().await;
    let req = Request::builder()
        .method("GET")
        .uri("/api/update")
        .header(header::HOST, format!("127.0.0.1:{STUDIO_PORT}"))
        .header(header::AUTHORIZATION, "Bearer not-the-real-token")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "GET /api/update with a wrong token must be 401"
    );
}

/// The POST apply route is gated identically.
#[tokio::test]
async fn update_post_requires_token() {
    let router = test_router().await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/update")
        .header(header::HOST, format!("127.0.0.1:{STUDIO_PORT}"))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "POST /api/update without a token must be 401"
    );
}

/// A correct token but a non-allowlisted Host is rejected 403 (DNS-rebinding /
/// other-local-app defense), so the update routes can't be reached cross-origin.
#[tokio::test]
async fn update_get_rejects_foreign_host() {
    let router = test_router().await;
    let req = Request::builder()
        .method("GET")
        .uri("/api/update")
        .header(header::HOST, "evil.example.com")
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "GET /api/update with a foreign Host must be 403"
    );
}
