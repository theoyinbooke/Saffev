//! Route handlers — one per mirrored endpoint, plus the catch-all.
//!
//! Every handler does the same shape of work: capture the request body for the
//! tee, forward verbatim to the upstream, stream the response back unchanged
//! while teeing chunks. They differ only in the canonical endpoint string used
//! for metadata. All forwarding goes through [`crate::proxy::upstream`].
//!
//! Keeping a named handler per route (rather than only the catch-all) lets the
//! router declare the exact mirrored surface from 04 §4.5 and gives each a stable
//! `endpoint` label for the store/Studio, while the catch-all guarantees an
//! unknown future engine route can never break us.

use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::response::Response;

use crate::proxy::upstream::forward_streaming;
use crate::proxy::ProxyState;

// --- Ollama-native (NDJSON) -------------------------------------------------

/// `POST /api/chat`
pub async fn api_chat(State(state): State<ProxyState>, req: Request<Body>) -> Response {
    forward_streaming(&state, "/api/chat", req).await
}

/// `POST /api/generate`
pub async fn api_generate(State(state): State<ProxyState>, req: Request<Body>) -> Response {
    forward_streaming(&state, "/api/generate", req).await
}

/// `GET /api/tags`
pub async fn api_tags(State(state): State<ProxyState>, req: Request<Body>) -> Response {
    forward_streaming(&state, "/api/tags", req).await
}

/// `POST /api/embeddings`
pub async fn api_embeddings(State(state): State<ProxyState>, req: Request<Body>) -> Response {
    forward_streaming(&state, "/api/embeddings", req).await
}

/// `POST /api/show`
pub async fn api_show(State(state): State<ProxyState>, req: Request<Body>) -> Response {
    forward_streaming(&state, "/api/show", req).await
}

/// `GET /api/ps`
pub async fn api_ps(State(state): State<ProxyState>, req: Request<Body>) -> Response {
    forward_streaming(&state, "/api/ps", req).await
}

// --- OpenAI-compatible (SSE) ------------------------------------------------

/// `POST /v1/chat/completions`
pub async fn v1_chat_completions(State(state): State<ProxyState>, req: Request<Body>) -> Response {
    forward_streaming(&state, "/v1/chat/completions", req).await
}

/// `POST /v1/completions`
pub async fn v1_completions(State(state): State<ProxyState>, req: Request<Body>) -> Response {
    forward_streaming(&state, "/v1/completions", req).await
}

/// `POST /v1/embeddings`
pub async fn v1_embeddings(State(state): State<ProxyState>, req: Request<Body>) -> Response {
    forward_streaming(&state, "/v1/embeddings", req).await
}

/// `GET /v1/models`
pub async fn v1_models(State(state): State<ProxyState>, req: Request<Body>) -> Response {
    forward_streaming(&state, "/v1/models", req).await
}

// --- Catch-all --------------------------------------------------------------

/// Any other path/method — reverse-proxied verbatim so an unknown engine route
/// can never break us. The canonical endpoint label is the request's own path.
pub async fn catch_all(State(state): State<ProxyState>, req: Request<Body>) -> Response {
    // Use the live path as the endpoint label; the forwarder re-derives the full
    // path + query from the URI anyway, so this is purely the metadata label.
    let endpoint = req.uri().path().to_string();
    forward_streaming(&state, &endpoint, req).await
}
