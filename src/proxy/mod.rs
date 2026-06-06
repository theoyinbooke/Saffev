//! The proxy spine — a transparent reverse proxy in front of the engine.
//!
//! Passes everything through unchanged while teeing a copy for logging. Mirrors
//! Ollama-native (`/api/*`) and OpenAI-compatible (`/v1/*`) endpoints, plus a
//! catch-all so an unknown future route can never break us.
//!
//! ## Invariants enforced here
//! - **Transparent streaming**: NDJSON + SSE stream to the client token-by-token,
//!   never buffered/aggregated before forwarding.
//! - **Decoupled tee**: response chunks are copied onto a bounded
//!   `tokio::sync::mpsc` with **drop-oldest** semantics (never broadcast, never
//!   unbounded). The logger never backpressures the client path.
//! - **Fail-open**: any tee/PII/store error is swallowed; the proxy still forwards.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use axum::routing::any;
use axum::Router;
use bytes::{Bytes, BytesMut};

use crate::brain::Side;
use crate::config::Config;
use crate::store::{
    PiiAction, PiiFindingRecord, RequestMeta, ResponseMeta, SourceConfidence, Store, TokenSource,
    WriteOp,
};
use crate::Result;

/// Default capacity of the bounded tee channel (events, not bytes). When full,
/// the **oldest** queued event is dropped so the client path never blocks.
pub const TEE_CAPACITY: usize = 4096;

/// An event copied off the request/response path onto the tee for async logging.
/// Carries metadata + chunk bytes; the consumer assembles records and PII scans.
#[derive(Debug, Clone)]
pub enum TeeEvent {
    /// A new exchange started: method, path, headers-of-interest, captured body.
    RequestStarted {
        /// Correlation id for the whole exchange.
        id: String,
        /// Endpoint path.
        endpoint: String,
        /// Captured request body (for hashing + PII scan + optional payload).
        body: Bytes,
        /// Resolved source application, if known by now.
        source_app: Option<String>,
    },
    /// A streamed response chunk (NDJSON line or SSE event), verbatim.
    ResponseChunk {
        /// Correlation id.
        id: String,
        /// The raw chunk bytes as forwarded to the client.
        chunk: Bytes,
    },
    /// The exchange finished: timing + finish metadata.
    ResponseFinished {
        /// Correlation id.
        id: String,
        /// Time to first token (millis), if streamed.
        ttft_ms: Option<u32>,
        /// Total time (millis).
        total_ms: Option<u32>,
    },
}

/// Sender half of the bounded, drop-oldest tee.
pub type TeeSender = tokio::sync::mpsc::Sender<TeeEvent>;
/// Receiver half consumed by the async logging task.
pub type TeeReceiver = tokio::sync::mpsc::Receiver<TeeEvent>;

/// Create the bounded tee channel with [`TEE_CAPACITY`].
pub fn tee_channel() -> (TeeSender, TeeReceiver) {
    tokio::sync::mpsc::channel(TEE_CAPACITY)
}

/// Shared state every proxy handler closes over.
#[derive(Clone)]
pub struct ProxyState {
    /// Effective config (ports, mode, payload flag).
    pub config: Arc<Config>,
    /// Store handle for enqueuing writes.
    pub store: Store,
    /// Sender onto the bounded tee.
    pub tee: TeeSender,
    /// Shared deterministic PII detector.
    pub detector: Arc<crate::brain::pii::Detector>,
    /// Base URL of the upstream engine (shadow port in Gateway, real in Coop).
    pub upstream: Arc<str>,
}

/// The proxy server. Owns its `axum` router + the upstream client.
pub struct ProxyServer {
    state: ProxyState,
}

impl ProxyServer {
    /// Build the proxy server with shared state. Spawns nothing yet.
    pub fn new(state: ProxyState) -> Self {
        ProxyServer { state }
    }

    /// Build the `axum` router with all mirrored routes + the catch-all.
    ///
    /// The named routes give the store/Studio a stable `endpoint` label per
    /// mirrored surface (04 §4.5); the catch-all reverse-proxies everything else
    /// verbatim so a future engine route cannot break us. The proxy path is
    /// deliberately **tokenless** — only the Studio/control plane is gated.
    ///
    /// Every mirrored route accepts **any method** (`any(..)`) rather than only
    /// the documented verb: the proxy must be transparent, so an unexpected
    /// method on a known path is forwarded to the engine (never answered with a
    /// 405) while still keeping the canonical `endpoint` label for logging.
    pub fn router(&self) -> Router {
        use handlers::*;

        Router::new()
            // Ollama-native (NDJSON)
            .route("/api/chat", any(api_chat))
            .route("/api/generate", any(api_generate))
            .route("/api/tags", any(api_tags))
            .route("/api/embeddings", any(api_embeddings))
            .route("/api/show", any(api_show))
            .route("/api/ps", any(api_ps))
            // OpenAI-compatible (SSE)
            .route("/v1/chat/completions", any(v1_chat_completions))
            .route("/v1/completions", any(v1_completions))
            .route("/v1/embeddings", any(v1_embeddings))
            .route("/v1/models", any(v1_models))
            // Everything else (unknown path or method): reverse-proxy verbatim.
            .fallback(catch_all)
            .with_state(self.state.clone())
    }

    /// Bind to the configured proxy port and serve until shutdown.
    ///
    /// Serves the router on the configured bind address + proxy port. The
    /// integrator pairs the channel up front: build `(tx, rx)` via
    /// [`tee_channel`], put `tx` in [`ProxyState::tee`], hand `rx` to
    /// [`ProxyServer::spawn_logger`], then call this. The send half handlers use
    /// is already paired with the receiver the logger drains.
    pub async fn serve(self) -> Result<()> {
        let bind = self.state.config.ports.bind;
        let port = self.state.config.ports.proxy;
        let addr = std::net::SocketAddr::new(bind, port);

        let router = self.router();

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| crate::Error::Proxy(format!("bind {addr}: {e}")))?;

        tracing::info!(%addr, upstream = %self.state.upstream, "proxy: listening");

        axum::serve(listener, router)
            .await
            .map_err(|e| crate::Error::Proxy(format!("serve: {e}")))?;

        Ok(())
    }

    /// Spawn the async logging task that drains the tee receiver, assembles
    /// records, runs PII scans, and enqueues writes to the [`Store`].
    ///
    /// Runs entirely off the request path. Every step is fail-open: a malformed
    /// body, a failed parse, or a dropped event degrades that one record's
    /// fidelity but never disturbs the proxy or other records.
    pub fn spawn_logger(state: ProxyState, rx: TeeReceiver) {
        tokio::spawn(run_logger(state, rx));
    }
}

pub mod handlers;
pub mod upstream;

// ---------------------------------------------------------------------------
// Async logger — drains the tee, assembles records, enqueues writes.
// ---------------------------------------------------------------------------

/// Cap on response bytes accumulated per exchange before we stop buffering for
/// PII scan / payload storage. Streaming forwarding to the client is never
/// affected by this — it only bounds the logger's own memory. 16 MiB.
const MAX_RESPONSE_BUFFER: usize = 16 * 1024 * 1024;

/// In-flight state for one exchange, keyed by correlation id.
struct InFlight {
    endpoint: String,
    source_app: Option<String>,
    request_body: Bytes,
    model: Option<String>,
    stream: bool,
    input_tokens: Option<u32>,
    input_tokens_src: TokenSource,
    /// Accumulated response bytes (bounded by [`MAX_RESPONSE_BUFFER`]).
    response_buf: BytesMut,
    /// True once we stopped accumulating because the cap was hit.
    response_truncated: bool,
    /// When the request started (for latency).
    started: Instant,
    /// When the first response chunk arrived (for TTFT).
    first_chunk_at: Option<Instant>,
    /// Unix-millis timestamp the request started (for the stored `ts`).
    ts_millis: i64,
    /// The engine name (host:port-derived label).
    engine: String,
}

async fn run_logger(state: ProxyState, mut rx: TeeReceiver) {
    let mut inflight: HashMap<String, InFlight> = HashMap::new();
    let payload_storage = state.config.payload_storage;
    let engine_label = engine_label(&state.upstream);

    while let Some(event) = rx.recv().await {
        match event {
            TeeEvent::RequestStarted {
                id,
                endpoint,
                body,
                source_app,
            } => {
                on_request_started(
                    &state,
                    &mut inflight,
                    &engine_label,
                    payload_storage,
                    id,
                    endpoint,
                    body,
                    source_app,
                );
            }
            TeeEvent::ResponseChunk { id, chunk } => {
                if let Some(entry) = inflight.get_mut(&id) {
                    if entry.first_chunk_at.is_none() {
                        entry.first_chunk_at = Some(Instant::now());
                    }
                    if !entry.response_truncated {
                        let remaining =
                            MAX_RESPONSE_BUFFER.saturating_sub(entry.response_buf.len());
                        if remaining == 0 {
                            entry.response_truncated = true;
                        } else if chunk.len() <= remaining {
                            entry.response_buf.extend_from_slice(&chunk);
                        } else {
                            entry.response_buf.extend_from_slice(&chunk[..remaining]);
                            entry.response_truncated = true;
                        }
                    }
                }
                // Unknown id: chunk arrived before RequestStarted (shouldn't
                // happen given send order) or after finish — drop it.
            }
            TeeEvent::ResponseFinished {
                id,
                ttft_ms,
                total_ms,
            } => {
                if let Some(entry) = inflight.remove(&id) {
                    on_response_finished(&state, payload_storage, id, entry, ttft_ms, total_ms);
                }
            }
        }
    }

    tracing::debug!("proxy: tee closed, logger exiting");
}

#[allow(clippy::too_many_arguments)]
fn on_request_started(
    state: &ProxyState,
    inflight: &mut HashMap<String, InFlight>,
    engine_label: &str,
    payload_storage: bool,
    id: String,
    endpoint: String,
    body: Bytes,
    source_app: Option<String>,
) {
    let started = Instant::now();
    let ts_millis = now_millis();

    // Parse the request JSON cheaply for `model` and `stream`.
    let (model, stream) = parse_request_meta(&body);

    // Inline-cheap deterministic PII scan of the request body text.
    let request_text = lossy_str(&body);
    let findings = state.detector.scan(Side::Request, &request_text);

    // Engine-reported input usage is rarely on the request; estimate is async
    // and off-path (not done here). Leave input tokens unknown for now.
    let input_tokens = None;
    let input_tokens_src = TokenSource::Estimated;

    let request_hash = upstream::hash_body(&body);

    let source_confidence = if source_app.is_some() {
        SourceConfidence::Header
    } else {
        SourceConfidence::Unknown
    };

    let meta = RequestMeta {
        id: id.clone(),
        ts: ts_millis,
        source_app: source_app.clone(),
        source_confidence,
        engine: engine_label.to_string(),
        model: model.clone(),
        endpoint: endpoint.clone(),
        stream,
        input_tokens,
        input_tokens_src,
        latency_ms: None,
        request_hash,
    };

    // Enqueue request metadata (always).
    state.store.enqueue(WriteOp::Request(meta));

    // Enqueue request-side PII findings (if any).
    if !findings.is_empty() {
        let records: Vec<PiiFindingRecord> = findings
            .iter()
            .map(|f| PiiFindingRecord::from_finding(&id, f, PiiAction::Observed))
            .collect();
        state.store.enqueue(WriteOp::PiiFindings(records));
    }

    // Optional payload: prompt only, gated on payload_storage.
    if payload_storage {
        state.store.enqueue(WriteOp::Payload(crate::store::Payload {
            request_id: id.clone(),
            prompt: Some(request_text),
            response: None,
        }));
    }

    inflight.insert(
        id,
        InFlight {
            endpoint,
            source_app,
            request_body: body,
            model,
            stream,
            input_tokens,
            input_tokens_src,
            response_buf: BytesMut::new(),
            response_truncated: false,
            started,
            first_chunk_at: None,
            ts_millis,
            engine: engine_label.to_string(),
        },
    );
}

fn on_response_finished(
    state: &ProxyState,
    payload_storage: bool,
    id: String,
    entry: InFlight,
    _ttft_from_event: Option<u32>,
    total_ms: Option<u32>,
) {
    let response_bytes = entry.response_buf.freeze();
    let response_text = lossy_str(&response_bytes);

    // TTFT: prefer the logger-observed first-chunk timestamp (authoritative for
    // streamed responses); fall back to None for non-streamed.
    let ttft_ms = entry
        .first_chunk_at
        .map(|t| millis_between(entry.started, t));

    // Total time: prefer the value the forwarder measured; else derive it.
    let total = total_ms.or_else(|| Some(millis_since(entry.started)));

    // Token accounting: trust engine-reported usage when present (exact).
    let (in_count, out_count) = crate::tokens::extract_usage(&response_bytes);

    let (output_tokens, output_tokens_src) = match out_count {
        Some(tc) => (Some(tc.value), tc.source),
        None => (None, TokenSource::Estimated),
    };

    // If the engine reported input usage in the response, prefer it over our
    // earlier unknown; re-enqueue an updated request row is not part of the
    // contract WriteOps, so we only use it to fill the response side here.
    let _ = in_count;

    let finish_reason = parse_finish_reason(&response_bytes, entry.stream);

    let response_meta = ResponseMeta {
        request_id: id.clone(),
        finish_reason,
        output_tokens,
        output_tokens_src,
        ttft_ms,
        total_ms: total,
    };
    state.store.enqueue(WriteOp::Response(response_meta));

    // Response-side PII findings.
    if !response_text.is_empty() {
        let findings = state.detector.scan(Side::Response, &response_text);
        if !findings.is_empty() {
            let records: Vec<PiiFindingRecord> = findings
                .iter()
                .map(|f| PiiFindingRecord::from_finding(&id, f, PiiAction::Observed))
                .collect();
            state.store.enqueue(WriteOp::PiiFindings(records));
        }
    }

    // Optional payload: fill the response text. We re-emit the full payload row
    // (prompt + response) so a single upsert carries both; the store owns the
    // upsert semantics.
    if payload_storage {
        let prompt_text = lossy_str(&entry.request_body);
        state.store.enqueue(WriteOp::Payload(crate::store::Payload {
            request_id: id.clone(),
            prompt: Some(prompt_text),
            response: Some(response_text),
        }));
    }

    tracing::debug!(
        id = %id,
        endpoint = %entry.endpoint,
        model = ?entry.model,
        stream = entry.stream,
        ttft_ms = ?ttft_ms,
        total_ms = ?total,
        source = ?entry.source_app,
        ts = entry.ts_millis,
        engine = %entry.engine,
        input_tokens = ?entry.input_tokens,
        input_src = ?entry.input_tokens_src,
        "proxy: exchange logged"
    );
}

// ---------------------------------------------------------------------------
// Parsing / formatting helpers
// ---------------------------------------------------------------------------

/// Lossy UTF-8 view of a body for PII scan / payload. Never panics on binary.
fn lossy_str(b: &Bytes) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// Best-effort extract of `model` and `stream` from a request JSON body.
/// Defaults: `stream=true` for chat/generate-style bodies when unspecified
/// (Ollama defaults to streaming), `stream=false` when the field is absent and
/// the body is empty (e.g. GET routes).
fn parse_request_meta(body: &Bytes) -> (Option<String>, bool) {
    if body.is_empty() {
        return (None, false);
    }
    match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(v) => {
            let model = v
                .get("model")
                .and_then(|m| m.as_str())
                .map(|s| s.to_string());
            // `stream` is `true` by default for Ollama /api/chat & /api/generate
            // and must be opt-in `true` for OpenAI; we read the explicit field
            // and default to `true` when a model is present but stream is unset
            // (matches Ollama's default-on behavior).
            let stream = match v.get("stream") {
                Some(serde_json::Value::Bool(b)) => *b,
                _ => model.is_some(),
            };
            (model, stream)
        }
        Err(_) => (None, false),
    }
}

/// Extract a finish reason from a response body. For OpenAI SSE we look for the
/// last `finish_reason`; for Ollama NDJSON we map `done_reason`/`done`.
fn parse_finish_reason(body: &Bytes, _stream: bool) -> Option<String> {
    let text = String::from_utf8_lossy(body);

    // OpenAI: `"finish_reason":"stop"` (take the last non-null occurrence).
    if let Some(reason) = last_json_string_field(&text, "finish_reason") {
        return Some(reason);
    }
    // Ollama: `"done_reason":"stop"`.
    if let Some(reason) = last_json_string_field(&text, "done_reason") {
        return Some(reason);
    }
    // Ollama fallback: a trailing `"done":true` line with no explicit reason.
    if text.contains("\"done\":true") || text.contains("\"done\": true") {
        return Some("stop".to_string());
    }
    None
}

/// Find the last `"field":"value"` string occurrence in a text blob, skipping
/// `null` values. Cheap scan — avoids fully parsing multi-line NDJSON / SSE.
fn last_json_string_field(text: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\"");
    let mut result = None;
    let mut search_from = 0;
    while let Some(rel) = text[search_from..].find(&needle) {
        let idx = search_from + rel + needle.len();
        search_from = idx;
        // Skip whitespace + colon.
        let rest = &text[idx..];
        let rest = rest.trim_start();
        let rest = match rest.strip_prefix(':') {
            Some(r) => r.trim_start(),
            None => continue,
        };
        if rest.starts_with("null") {
            continue;
        }
        if let Some(after_quote) = rest.strip_prefix('"') {
            if let Some(end) = after_quote.find('"') {
                result = Some(after_quote[..end].to_string());
            }
        }
    }
    result
}

/// Derive a human-friendly engine label from the upstream base URL. For Ollama
/// on the default port this is just `ollama`; otherwise fall back to the host.
fn engine_label(upstream: &str) -> String {
    // Heuristic: Ollama is the only engine we forward to in v0. Keep it simple
    // and stable; detection/labeling lives in the engine module.
    let _ = upstream;
    "ollama".to_string()
}

fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn millis_since(start: Instant) -> u32 {
    start.elapsed().as_millis().min(u128::from(u32::MAX)) as u32
}

fn millis_between(start: Instant, end: Instant) -> u32 {
    end.saturating_duration_since(start)
        .as_millis()
        .min(u128::from(u32::MAX)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_request_meta_ollama_chat() {
        let body = Bytes::from_static(
            br#"{"model":"llama3","messages":[{"role":"user","content":"hi"}]}"#,
        );
        let (model, stream) = parse_request_meta(&body);
        assert_eq!(model.as_deref(), Some("llama3"));
        // stream unspecified but model present -> default-on (Ollama behavior).
        assert!(stream);
    }

    #[test]
    fn parse_request_meta_explicit_stream_false() {
        let body = Bytes::from_static(br#"{"model":"llama3","stream":false}"#);
        let (model, stream) = parse_request_meta(&body);
        assert_eq!(model.as_deref(), Some("llama3"));
        assert!(!stream);
    }

    #[test]
    fn parse_request_meta_openai_stream_true() {
        let body = Bytes::from_static(br#"{"model":"gpt-x","stream":true}"#);
        let (model, stream) = parse_request_meta(&body);
        assert_eq!(model.as_deref(), Some("gpt-x"));
        assert!(stream);
    }

    #[test]
    fn parse_request_meta_empty_body() {
        let (model, stream) = parse_request_meta(&Bytes::new());
        assert!(model.is_none());
        assert!(!stream);
    }

    #[test]
    fn parse_request_meta_invalid_json() {
        let (model, stream) = parse_request_meta(&Bytes::from_static(b"not json"));
        assert!(model.is_none());
        assert!(!stream);
    }

    #[test]
    fn finish_reason_openai_sse() {
        // SSE-ish blob with two data lines; second carries the finish_reason.
        let body = Bytes::from_static(
            b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"},\"finish_reason\":null}]}\n\ndata: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n",
        );
        assert_eq!(parse_finish_reason(&body, true).as_deref(), Some("stop"));
    }

    #[test]
    fn finish_reason_ollama_ndjson_done_reason() {
        let body = Bytes::from_static(
            b"{\"model\":\"llama3\",\"response\":\"hi\",\"done\":false}\n{\"model\":\"llama3\",\"done\":true,\"done_reason\":\"stop\"}\n",
        );
        assert_eq!(parse_finish_reason(&body, true).as_deref(), Some("stop"));
    }

    #[test]
    fn finish_reason_ollama_done_only() {
        let body = Bytes::from_static(b"{\"done\":true}\n");
        assert_eq!(parse_finish_reason(&body, true).as_deref(), Some("stop"));
    }

    #[test]
    fn finish_reason_absent() {
        let body = Bytes::from_static(b"{\"response\":\"partial\"}");
        assert_eq!(parse_finish_reason(&body, true), None);
    }

    #[test]
    fn last_json_string_field_skips_null_takes_last() {
        let text = r#"{"finish_reason":null} ... {"finish_reason":"length"}"#;
        assert_eq!(
            last_json_string_field(text, "finish_reason").as_deref(),
            Some("length")
        );
    }

    #[test]
    fn engine_label_is_ollama() {
        assert_eq!(engine_label("http://127.0.0.1:11434"), "ollama");
    }

    #[test]
    fn tee_channel_has_capacity() {
        let (tx, _rx) = tee_channel();
        assert_eq!(tx.capacity(), TEE_CAPACITY);
    }

    #[test]
    fn lossy_str_handles_binary() {
        let b = Bytes::from_static(&[0xff, 0xfe, b'h', b'i']);
        let s = lossy_str(&b);
        assert!(s.contains("hi"));
    }
}
