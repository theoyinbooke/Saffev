//! Studio security layers (04 §7.8).
//!
//! Per-install bearer token on every `/api/*` route, a Host-header allowlist,
//! and strict CORS limited to the Studio origin. The passthrough inference path
//! (the proxy) stays tokenless; only control/Studio/config endpoints are gated.
//!
//! The invariant from 04 §7.8 and acceptance §10.6: control/Studio endpoints
//! reject requests **without** the install token and **with** a non-allowlisted
//! Host; the passthrough path stays tokenless. None of these layers ever touch
//! the proxy router — they are applied only to the Studio `/api/*` subtree.

use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use tower_http::cors::CorsLayer;

use crate::studio::api::api_error;
use crate::studio::StudioState;

/// Header name for the per-install bearer token (`Authorization: Bearer ...`).
pub const AUTH_HEADER: &str = "authorization";

/// The `Bearer ` scheme prefix (case-insensitive scheme, exact whitespace).
const BEARER_PREFIX: &str = "Bearer ";

/// Build the set of allowlisted `Host` header values for the Studio port.
///
/// Localhost is not a security boundary, so we only accept the loopback hosts
/// (and the bare names browsers send) at the configured Studio port. Anything
/// else — a `0.0.0.0` bind reached over the LAN, a DNS-rebinding origin, another
/// app forging a `Host` — is rejected with 403.
pub fn host_allowlist(studio_port: u16) -> Vec<HeaderValue> {
    let hosts = [
        format!("localhost:{studio_port}"),
        format!("127.0.0.1:{studio_port}"),
        format!("[::1]:{studio_port}"),
        // Some clients omit the port when it is the default; include bare forms
        // so a correctly-bound loopback request is never spuriously rejected.
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "[::1]".to_string(),
    ];
    hosts
        .iter()
        .filter_map(|h| HeaderValue::from_str(h).ok())
        .collect()
}

/// Middleware: require a valid bearer token. Rejects with 401 otherwise.
///
/// Reads the expected token from [`StudioState`] (sourced from the OS keyring at
/// startup) and compares it in constant time against the presented bearer.
pub async fn require_token(State(state): State<StudioState>, req: Request, next: Next) -> Response {
    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix(BEARER_PREFIX));

    match presented {
        Some(token) if token_matches(token, state.token.as_ref()) => next.run(req).await,
        _ => api_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or invalid bearer token",
        ),
    }
}

/// Middleware: require an allowlisted Host header. Rejects with 403 otherwise.
///
/// Defends against DNS-rebinding and other-local-app attacks: even on loopback,
/// a request whose `Host` is not in the allowlist is refused before it can reach
/// a control handler.
pub async fn require_host(State(state): State<StudioState>, req: Request, next: Next) -> Response {
    let allow = host_allowlist(state.config.load().ports.studio);
    let host = req.headers().get(header::HOST);

    match host {
        Some(h) if allow.iter().any(|a| a == h) => next.run(req).await,
        _ => api_error(StatusCode::FORBIDDEN, "bad_host", "host not allowlisted"),
    }
}

/// Build the strict CORS layer (only the Studio origin).
///
/// Same-origin SPA + `fetch` calls do not require permissive CORS; we lock the
/// allowed origins to the exact loopback Studio origins and only permit the
/// methods + headers the API actually uses. No wildcards, no credentials beyond
/// the explicit bearer header.
pub fn cors_layer(studio_port: u16) -> CorsLayer {
    let origins: Vec<HeaderValue> = [
        format!("http://localhost:{studio_port}"),
        format!("http://127.0.0.1:{studio_port}"),
        format!("http://[::1]:{studio_port}"),
    ]
    .iter()
    .filter_map(|o| HeaderValue::from_str(o).ok())
    .collect();

    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::OPTIONS])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
}

/// Constant-time comparison of the presented token against the install token.
///
/// Avoids leaking the token length/contents via early-exit timing. Tokens are
/// UUIDs (fixed length in practice), but we still compare defensively.
pub fn token_matches(presented: &str, expected: &str) -> bool {
    let a = presented.as_bytes();
    let b = expected.as_bytes();
    // Fold the length difference into the accumulator so mismatched lengths
    // still take a full pass and always fail.
    let mut diff: u8 = (a.len() ^ b.len()) as u8;
    let n = a.len().max(b.len());
    for i in 0..n {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_matches_exact() {
        assert!(token_matches("abc123", "abc123"));
    }

    #[test]
    fn token_rejects_mismatch() {
        assert!(!token_matches("abc123", "abc124"));
        assert!(!token_matches("abc", "abc123"));
        assert!(!token_matches("abc123", "abc"));
        assert!(!token_matches("", "abc"));
        assert!(!token_matches("abc", ""));
    }

    #[test]
    fn token_matches_empty_pair() {
        // Two empty strings are technically equal; never used in practice
        // because the install token is always a generated UUID.
        assert!(token_matches("", ""));
    }

    #[test]
    fn host_allowlist_includes_studio_port_forms() {
        let allow = host_allowlist(7100);
        let want = HeaderValue::from_static("127.0.0.1:7100");
        assert!(allow.contains(&want));
        let want_local = HeaderValue::from_static("localhost:7100");
        assert!(allow.contains(&want_local));
    }

    #[test]
    fn host_allowlist_rejects_foreign_host() {
        let allow = host_allowlist(7100);
        let foreign = HeaderValue::from_static("evil.example.com");
        assert!(!allow.contains(&foreign));
        // A LAN address reaching a 0.0.0.0-bound port must not be allowlisted.
        let lan = HeaderValue::from_static("192.168.1.5:7100");
        assert!(!allow.contains(&lan));
    }

    #[test]
    fn cors_layer_builds() {
        // Smoke: constructing the layer must not panic on valid origins.
        let _ = cors_layer(7100);
    }
}
