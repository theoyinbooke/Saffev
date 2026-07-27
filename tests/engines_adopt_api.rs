//! Integration tests: `POST /api/engines/adopt` and `/api/engines/revert` are
//! wired to the real engine controller and fail LOUDLY when they cannot act —
//! never a silent no-op that leaves the UI spinner claiming success.
//!
//! Only the deterministic, network-free paths are asserted here: the Gateway
//! gates (409s) fire before any detection or system work, and the not-found
//! paths need no running engine. The adopt/revert happy paths drive systemd and
//! are covered by the Linux Gateway CI workflow + `src/engine` unit tests.

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
    if std::env::var("SAFFEV_DB_KEY")
        .map(|v| v.is_empty())
        .unwrap_or(true)
    {
        std::env::set_var("SAFFEV_DB_KEY", "test-db-key-0123456789abcdef");
    }

    let mut cfg = Config::default();
    cfg.ports.studio = STUDIO_PORT;

    let mut db = std::env::temp_dir();
    db.push(format!("saffev-engines-api-{}.db", uuid::Uuid::new_v4()));
    let store = Store::open(&db).await.expect("open test store");

    let (events, _rx) = tokio::sync::broadcast::channel(STREAM_CHANNEL_CAPACITY);

    let state = StudioState {
        config: config_handle(cfg),
        store,
        token: TOKEN.into(),
        events,
        eval_metrics: std::sync::Arc::new(saffev::proxy::EvalMetrics::default()),
    };
    StudioServer::new(state).router()
}

/// POST a JSON body to an API path with the valid token + allowlisted Host.
async fn post_json(router: axum::Router, path: &str, body: &str) -> (StatusCode, String) {
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::HOST, format!("127.0.0.1:{STUDIO_PORT}"))
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap_or_default();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// Gateway adoption while the config is in Cooperative mode must be refused
/// with an explanation, not silently downgraded or no-opped.
#[tokio::test]
async fn adopt_gateway_in_cooperative_mode_is_409() {
    let router = test_router().await;
    let (status, body) = post_json(
        router,
        "/api/engines/adopt",
        r#"{"engine":"ollama","cooperative":false}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "expected 409, body: {body}");
    assert!(
        body.contains("gateway"),
        "the error must name the real blocker (gateway mode), body: {body}"
    );
}

/// LM Studio has no systemd unit — Gateway adoption is refused on every
/// platform and in every mode, before the mode gate.
#[tokio::test]
async fn adopt_gateway_lmstudio_is_409_everywhere() {
    let router = test_router().await;
    let (status, body) = post_json(
        router,
        "/api/engines/adopt",
        r#"{"engine":"lmstudio","cooperative":false}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "expected 409, body: {body}");
    assert!(
        body.contains("LM Studio"),
        "the error must say LM Studio is unsupported, body: {body}"
    );
}

/// Adopting an engine that is not running (or not recognized) is a 404, not a
/// success view of nothing.
#[tokio::test]
async fn adopt_unknown_engine_is_404() {
    let router = test_router().await;
    // A name detection can never return, so this is deterministic even on a dev
    // machine with a live Ollama/LM Studio.
    let (status, body) = post_json(
        router,
        "/api/engines/adopt",
        r#"{"engine":"nonexistentengine","cooperative":true}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "expected 404, body: {body}");
}

/// Reverting an engine with no adoption record is a 404, not a fake "reverted".
#[tokio::test]
async fn revert_without_record_is_404() {
    let router = test_router().await;
    let (status, body) = post_json(router, "/api/engines/revert", r#"{"engine":"ollama"}"#).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "expected 404, body: {body}");
}

/// An empty engine name is a 400 validation error.
#[tokio::test]
async fn adopt_empty_engine_is_400() {
    let router = test_router().await;
    let (status, body) = post_json(
        router,
        "/api/engines/adopt",
        r#"{"engine":"  ","cooperative":true}"#,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "expected 400, body: {body}"
    );
}

/// The write endpoints stay token-gated like every other control endpoint.
#[tokio::test]
async fn adopt_requires_token() {
    let router = test_router().await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/engines/adopt")
        .header(header::HOST, format!("127.0.0.1:{STUDIO_PORT}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"engine":"ollama"}"#))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
