//! Embedded SPA assets — `studio-web/` baked into the binary via `rust-embed`.
//!
//! The SPA (derived from `design/option-a-calm-instrument.html`) is served from
//! the embedded `studio-web/` folder, with SPA-fallback to `index.html` for
//! client-side routes.
//!
//! Token injection: the Studio is loopback-only and single-user, but every
//! `/api/*` route requires the per-install bearer token. So that simply opening
//! the Studio URL "just works", we inject the token into the served
//! `index.html` as `window.__SAFFEV_TOKEN__` (the SPA's first token source).
//! The token never leaves the device — it is read from the OS keyring at
//! startup and embedded only into the loopback-served shell.

use axum::body::Body;
use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;
use std::sync::Arc;

/// The embedded Studio web root. Path is relative to the crate manifest dir.
#[derive(RustEmbed)]
#[folder = "studio-web/"]
pub struct StudioAssets;

/// Serve a static asset by path, falling back to `index.html` for SPA routes.
///
/// `token` is the per-install bearer token, injected into `index.html` so the
/// SPA can authenticate its `/api/*` calls without manual entry.
///
/// Resolution order:
/// 1. Try the exact path (sans leading `/`).
/// 2. If absent and the path has no file extension (a client-side route like
///    `/history` or `/privacy`), serve `index.html` so the SPA router can
///    take over.
/// 3. If a concrete asset (something with an extension, e.g. `/missing.js`) is
///    not found, return 404 — never mask a genuinely missing asset behind the
///    SPA shell.
pub async fn serve(uri: Uri, token: Arc<str>) -> Response {
    let path = uri.path().trim_start_matches('/');

    // Root request serves the SPA entry.
    let lookup = if path.is_empty() { "index.html" } else { path };

    if let Some(resp) = serve_embedded(lookup, &token) {
        return resp;
    }

    // SPA fallback: only for extension-less paths (client-side routes).
    let looks_like_file = lookup
        .rsplit('/')
        .next()
        .map(|seg| seg.contains('.'))
        .unwrap_or(false);
    if !looks_like_file {
        if let Some(resp) = serve_embedded("index.html", &token) {
            return resp;
        }
    }

    (StatusCode::NOT_FOUND, "not found").into_response()
}

/// Look up `path` in the embedded assets and build a response with the right
/// `Content-Type` (guessed from the extension) if present. `index.html` gets the
/// install token injected as `window.__SAFFEV_TOKEN__`.
fn serve_embedded(path: &str, token: &str) -> Option<Response> {
    let asset = StudioAssets::get(path)?;
    let mime = mime_guess::from_path(path).first_or_octet_stream();

    let body = if path == "index.html" {
        let html = String::from_utf8_lossy(&asset.data);
        Body::from(inject_token(&html, token))
    } else {
        Body::from(asset.data.into_owned())
    };

    let resp = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime.as_ref())
        // The shell carries a per-install secret; never let an intermediary cache it.
        .header(header::CACHE_CONTROL, "no-store")
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    Some(resp)
}

/// Insert `<script>window.__SAFFEV_TOKEN__=...;</script>` just before `</head>`
/// (or prepend it if there is no head). The token is JSON-encoded for safe JS
/// string escaping.
fn inject_token(html: &str, token: &str) -> String {
    let encoded = serde_json::to_string(token).unwrap_or_else(|_| "\"\"".to_string());
    let snippet = format!("<script>window.__SAFFEV_TOKEN__={encoded};</script>");
    if let Some(idx) = html.find("</head>") {
        let mut out = String::with_capacity(html.len() + snippet.len());
        out.push_str(&html[..idx]);
        out.push_str(&snippet);
        out.push_str(&html[idx..]);
        out
    } else {
        format!("{snippet}{html}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tok() -> Arc<str> {
        Arc::from("test-token-123")
    }

    #[tokio::test]
    async fn serves_index_at_root_with_token_injected() {
        let resp = serve("/".parse::<Uri>().unwrap(), tok()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(ct.starts_with("text/html"), "got content-type {ct}");
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8_lossy(&bytes);
        assert!(
            html.contains("window.__SAFFEV_TOKEN__=\"test-token-123\""),
            "token not injected into index.html"
        );
    }

    #[tokio::test]
    async fn falls_back_to_index_for_client_route() {
        // An extension-less path that does not exist as an asset must serve the
        // SPA shell (client-side routing) — with the token injected.
        let resp = serve("/history".parse::<Uri>().unwrap(), tok()).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn missing_concrete_asset_is_404() {
        let resp = serve("/nope.js".parse::<Uri>().unwrap(), tok()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn inject_places_script_before_head_close() {
        let out = inject_token("<head><title>x</title></head><body></body>", "abc");
        assert!(out.contains("window.__SAFFEV_TOKEN__=\"abc\";</script></head>"));
    }
}
