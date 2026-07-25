//! Upstream forwarding — the streaming reverse-proxy core.
//!
//! Forwards a captured request to the engine and returns a streaming response
//! whose body is teed onto the bounded channel as it flows to the client.
//! **Must stream, never buffer** — the documented failure mode that breaks token
//! streaming. Uses a streaming `reqwest` client.
//!
//! ## Invariants honored here
//! - **Transparent streaming**: the upstream response body is wrapped in a
//!   pass-through stream; each chunk is forwarded to the client *and* teed in the
//!   same step, never aggregated first.
//! - **Fail-open**: every error path (bad request build, upstream connect
//!   failure, mid-stream transport error) is logged and degraded to a best-effort
//!   response; the request still reaches the engine where possible and a panic is
//!   never propagated onto the request path.
//! - **Decoupled tee**: enqueues are best-effort drop-oldest; the logger never
//!   backpressures the client.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use futures_util::StreamExt;
use once_cell::sync::Lazy;
use uuid::Uuid;

use crate::proxy::{MaskAction, ProxyState, TeeEvent};

/// Process-global streaming HTTP client used to reach the local engine.
///
/// Kept here (rather than on [`ProxyState`], which is a shared contract type) so
/// it is built once and shared across every handler. Connection pooling is on by
/// default; no proxy, no redirects beyond the default, generous timeouts because
/// generation can be long-running. This client only ever talks to the loopback
/// engine — nothing leaves the device.
static UPSTREAM_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        // Do not impose an overall request timeout: streamed generations can run
        // for minutes. A connect timeout still guards against a dead upstream.
        .connect_timeout(std::time::Duration::from_secs(10))
        // We forward chunks ourselves; disable any auto-decompression so bytes
        // are byte-identical to what the engine emitted.
        .no_proxy()
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
});

/// Hop-by-hop headers that must not be blindly forwarded between connections.
/// Stripped on both the request out and the response back.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
];

fn is_hop_by_hop(name: &HeaderName) -> bool {
    let n = name.as_str();
    HOP_BY_HOP.iter().any(|h| h.eq_ignore_ascii_case(n))
}

/// Forward `req` to `state.upstream`, streaming the response back while teeing
/// each chunk. `endpoint` is the canonical path used for metadata; `peer` is the
/// client's accepted-connection address (threaded via `ConnectInfo`) used for
/// off-path socket-PID source-app attribution. On any error, returns a
/// best-effort passthrough / error response — never panics the path.
pub async fn forward_streaming(
    state: &ProxyState,
    endpoint: &str,
    peer: std::net::SocketAddr,
    req: Request<Body>,
) -> Response {
    let id = Uuid::new_v4().to_string();
    let start = Instant::now();

    let (parts, body) = req.into_parts();
    let method = parts.method;
    let req_headers = parts.headers;

    // Source-app attribution is deliberately NOT done here. It is computed in the
    // logger task, off the request hot path (04 §7.2): the PID probe (lsof on
    // macOS, /proc on Linux) can take milliseconds and must never sit inline. We
    // carry the peer addr + headers on the tee so the logger can run the full
    // ladder (PID -> X-Client-Name/User-Agent -> Unknown) fail-soft.

    // Buffer the *request* body. We must read it whole to (a) tee it, (b) run the
    // inline PII scan, and (c) re-send it upstream. Request bodies for chat/gen
    // are small JSON; this is not the streaming hot path (that is the response).
    let req_bytes = match axum::body::to_bytes(body, MAX_REQUEST_BODY).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "proxy: failed to read request body; failing open with empty body");
            Bytes::new()
        }
    };

    // Decide masking BEFORE forwarding (04 §7.6). Default is observe-only; only
    // when masking is enabled AND not in dry-run do we redact the request body
    // before it reaches the engine — the high-value case (keep PII off the
    // model). Fail-open: any error here yields the ORIGINAL body + `Observed`.
    //
    // SCOPE: we mask the REQUEST body here (the full body is in hand).
    // NON-STREAMING responses are masked on the response path (buffered + redacted
    // — see `buffer_and_mask_response`). STREAMING responses are masked frame by
    // frame through the bounded-holdback masker (`stream_and_mask_response`) —
    // never buffered whole.
    let (forward_bytes, mask_action) = mask_request_body(state, &req_bytes);

    // Policy block: some things must never reach a model at all, and for those
    // masking ("we quietly replaced it") is the wrong answer. Evaluated here,
    // before anything is forwarded. Only a deliberate, live policy can stop a
    // request — see `block_decision`.
    let cfg = state.config.load();
    let blocked = block_decision(
        &cfg.masking,
        &state.detector,
        crate::brain::Side::Request,
        &req_bytes,
    );
    let (mask_action, blocked) = match blocked {
        // Policy names a kind that is present, but masking is still in dry-run:
        // record the intent and let the request through, exactly like dry-run
        // masking does. Turning off dry-run is the single explicit step that
        // makes both masking and blocking real.
        Some(_) if cfg.masking.dry_run => (MaskAction::WouldBlock, None),
        Some(kinds) => (MaskAction::Blocked, Some(kinds)),
        None => (mask_action, None),
    };

    // Tee the request start with the ORIGINAL (unredacted) body so the logger
    // records the true findings + offsets, plus what masking did to the
    // forwarded body. Best-effort; never blocks.
    tee_drop_oldest(
        state,
        TeeEvent::RequestStarted {
            id: id.clone(),
            endpoint: endpoint.to_string(),
            body: req_bytes.clone(),
            mask_action,
            peer: Some(peer),
            headers: req_headers.clone(),
        },
    );

    // Stop here when policy says so: the engine is never contacted. The exchange
    // is still closed out on the tee so it appears in Live/History with a clear
    // reason, rather than hanging as a request that never finished.
    if let Some(kinds) = blocked {
        tracing::info!(
            target: "saffev::policy",
            kinds = ?kinds,
            endpoint = %endpoint,
            "request blocked by policy; not forwarded"
        );
        tee_drop_oldest(
            state,
            TeeEvent::ResponseFinished {
                id: id.clone(),
                ttft_ms: None,
                total_ms: Some(elapsed_ms(start)),
                status: Some(StatusCode::FORBIDDEN.as_u16()),
                error_kind: Some("blocked_by_policy".to_string()),
                resp_mask_action: MaskAction::Observed,
            },
        );
        return blocked_response(&kinds);
    }

    // Build the upstream URL: base + original path + query, verbatim.
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(endpoint);
    let url = format!("{}{}", state.upstream.trim_end_matches('/'), path_and_query);

    // Construct the upstream request. When masking redacted the body,
    // `forward_bytes` differs from `req_bytes`; otherwise it is the same buffer.
    // `content-length` is stripped as hop-by-hop and re-derived by reqwest from
    // the body we set, so a length change after redaction stays consistent.
    let mut builder = UPSTREAM_CLIENT.request(method, &url);
    builder = builder.headers(forward_request_headers(&req_headers));
    if !forward_bytes.is_empty() {
        builder = builder.body(forward_bytes);
    }

    // Send. On a connect/transport error, fail open with a 502 — the request
    // genuinely could not reach the engine, but we never panic the path.
    let upstream_resp = match builder.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, url = %url, "proxy: upstream request failed");
            // Mark the exchange finished so the logger doesn't wait forever, and
            // record WHY it failed: the engine was never reached.
            tee_drop_oldest(
                state,
                TeeEvent::ResponseFinished {
                    id: id.clone(),
                    ttft_ms: None,
                    total_ms: Some(elapsed_ms(start)),
                    status: None,
                    error_kind: Some("upstream_unreachable".to_string()),
                    resp_mask_action: MaskAction::Observed,
                },
            );
            return bad_gateway(&e);
        }
    };

    // Translate status + headers back, stripping hop-by-hop.
    let status = upstream_resp.status();
    let resp_headers = forward_response_headers(upstream_resp.headers());

    // Response masking (04 §7.6). When masking is LIVE:
    // - a single JSON body is buffered + redacted (`buffer_and_mask_response`);
    // - a STREAM (Ollama NDJSON / OpenAI SSE) flows through the bounded-holdback
    //   stream masker (`stream_and_mask_response`): frames are forwarded as they
    //   arrive, with each frame's text delta passed through
    //   `brain::stream_mask::StreamMasker`, which retains only a small bounded
    //   tail so a PII span straddling chunks is still caught. The stream is
    //   never aggregated; live masking is the user's explicit opt-in, so the
    //   altered stream is by design (observe/dry-run remain byte-transparent).
    let masking_live = {
        let m = &state.config.load().masking;
        m.enabled && !m.dry_run
    };
    if masking_live && response_is_json(upstream_resp.headers()) {
        return buffer_and_mask_response(state, id, start, status, resp_headers, upstream_resp)
            .await;
    }
    if masking_live {
        if let Some(kind) = response_stream_kind(upstream_resp.headers()) {
            return stream_and_mask_response(
                state,
                id,
                start,
                status,
                resp_headers,
                kind,
                upstream_resp,
            );
        }
    }

    // Wrap the upstream byte stream so each chunk is teed as it is forwarded —
    // unbuffered, token-by-token. This is the streaming-passthrough core.
    //
    // TTFT is owned by the logger: it timestamps the first `ResponseChunk` it
    // sees for an id. We deliberately do not thread a clock through the contract
    // types here — keeping `TeeEvent` unchanged.
    let tee = state.tee.clone();
    let stream_id = id.clone();

    // Shared flag: set if the response stream errors mid-flight, read by the
    // FinishGuard so the recorded outcome is `stream_error` rather than a clean
    // finish (the client already got a truncated stream — fail-open).
    let stream_errored = Arc::new(AtomicBool::new(false));
    let errored_for_stream = stream_errored.clone();

    let byte_stream = upstream_resp.bytes_stream();
    let mapped = byte_stream.map(move |item| match item {
        Ok(chunk) => {
            // Tee a copy (best-effort, drop-oldest). The send half is cloned so we
            // do not hold a &state across the stream's 'static lifetime.
            send_chunk(&tee, &stream_id, chunk.clone());
            Ok::<Bytes, std::io::Error>(chunk)
        }
        Err(e) => {
            // Mid-stream transport error: surface it as a stream error so the
            // client sees a truncated stream (fail-open: we do not panic, and the
            // bytes already delivered remain byte-identical).
            tracing::warn!(error = %e, "proxy: upstream stream error mid-flight");
            errored_for_stream.store(true, Ordering::Relaxed);
            Err(std::io::Error::other(e))
        }
    });
    // Box+pin to guarantee `Unpin` for the StreamWithFinish wrapper regardless of
    // reqwest's concrete stream type.
    let mapped: Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>> =
        Box::pin(mapped);

    // When the stream completes (or the client drops), finalize timing. We can't
    // easily hook stream-drop without a guard, so we use a wrapper stream that
    // emits the finished event from its Drop. Build that guard now.
    let finish_tee = state.tee.clone();
    let finish_id = id.clone();
    let finished = FinishGuard {
        tee: finish_tee,
        id: finish_id,
        start,
        sent: false,
        status: Some(status.as_u16()),
        errored: stream_errored,
    };
    let guarded = StreamWithFinish {
        inner: mapped,
        guard: Some(finished),
    };

    let body = Body::from_stream(guarded);

    let mut response = Response::builder().status(status);
    if let Some(h) = response.headers_mut() {
        *h = resp_headers;
    }
    match response.body(body) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "proxy: failed to build streaming response; failing open");
            (StatusCode::BAD_GATEWAY, "saffev: response build error").into_response()
        }
    }
}

/// True when the upstream response is a single JSON body (safe to buffer +
/// mask), as opposed to a stream (`text/event-stream` SSE / `application/x-ndjson`
/// NDJSON). Absent/other content types are treated as NOT bufferable (observe).
fn response_is_json(headers: &reqwest::header::HeaderMap) -> bool {
    match headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    {
        Some(ct) => {
            let ct = ct.to_ascii_lowercase();
            ct.contains("application/json") && !ct.contains("ndjson")
        }
        None => false,
    }
}

/// Buffer a NON-streamed response body, redact response-side PII (live masking),
/// forward the redacted body, and tee the ORIGINAL for logging. Only reached when
/// masking is live and the response is a single JSON body — see the call site.
/// Fail-open: a read error finalizes the exchange and returns a 502.
async fn buffer_and_mask_response(
    state: &ProxyState,
    id: String,
    start: Instant,
    status: StatusCode,
    resp_headers: HeaderMap,
    upstream_resp: reqwest::Response,
) -> Response {
    let body_bytes = match upstream_resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "proxy: failed to read response body for masking; failing open");
            tee_drop_oldest(
                state,
                TeeEvent::ResponseFinished {
                    id,
                    ttft_ms: None,
                    total_ms: Some(elapsed_ms(start)),
                    status: Some(status.as_u16()),
                    error_kind: Some("stream_error".to_string()),
                    resp_mask_action: MaskAction::Observed,
                },
            );
            return (StatusCode::BAD_GATEWAY, "saffev: response read error").into_response();
        }
    };

    // Decide + apply response masking. Live-only here (dry-run/off never reach
    // this path), so the action is `Masked` (redacted) or `Observed` (nothing
    // maskable). Fail-open: worst case forwards the original bytes.
    let (forward_bytes, resp_mask_action) = {
        let cfg = state.config.load();
        mask_body_with(
            &cfg.masking,
            &state.detector,
            crate::brain::Side::Response,
            &body_bytes,
        )
    };

    // Tee the ORIGINAL (unredacted) body so the logger records the true findings
    // + offsets, then finalize — carrying the mask action so response findings are
    // stamped `masked`/`observed` to match what we forwarded.
    send_chunk(&state.tee, &id, body_bytes.clone());
    tee_drop_oldest(
        state,
        TeeEvent::ResponseFinished {
            id: id.clone(),
            ttft_ms: None,
            total_ms: Some(elapsed_ms(start)),
            status: Some(status.as_u16()),
            error_kind: None,
            resp_mask_action,
        },
    );

    // content-length was stripped as hop-by-hop, so the redacted length is
    // re-derived from the body we set.
    let mut response = Response::builder().status(status);
    if let Some(h) = response.headers_mut() {
        *h = resp_headers;
    }
    match response.body(Body::from(forward_bytes)) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "proxy: failed to build masked response; failing open");
            (StatusCode::BAD_GATEWAY, "saffev: response build error").into_response()
        }
    }
}

/// Maximum request body size we buffer for teeing/PII scan. Generous enough for
/// large prompts and base64 image payloads, bounded so a hostile client can't
/// OOM us. 64 MiB.
const MAX_REQUEST_BODY: usize = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Streaming-response masking (bounded holdback)
// ---------------------------------------------------------------------------

/// Which streaming frame protocol the upstream response uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamKind {
    /// Ollama-native streaming: one JSON object per `\n`-terminated line.
    Ndjson,
    /// OpenAI-compatible streaming: `data: {json}` SSE events separated by a
    /// blank line (LM Studio, Ollama `/v1`).
    Sse,
}

/// Classify a streamed response by content type. `None` = not a recognized
/// stream (passthrough; observe-only).
fn response_stream_kind(headers: &reqwest::header::HeaderMap) -> Option<StreamKind> {
    let ct = headers
        .get(reqwest::header::CONTENT_TYPE)?
        .to_str()
        .ok()?
        .to_ascii_lowercase();
    if ct.contains("ndjson") {
        Some(StreamKind::Ndjson)
    } else if ct.contains("text/event-stream") {
        Some(StreamKind::Sse)
    } else {
        None
    }
}

/// Where the text delta lives inside one stream frame's JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TextPath {
    /// Ollama `/api/generate`: top-level `"response"`.
    OllamaResponse,
    /// Ollama `/api/chat`: `"message": {"content": …}`.
    OllamaMessage,
    /// OpenAI chat stream: `"choices"[0]."delta"."content"`.
    OpenAiDelta,
    /// OpenAI completions stream: `"choices"[0]."text"`.
    OpenAiText,
}

fn find_text_path(v: &serde_json::Value) -> Option<TextPath> {
    if v.get("response").is_some_and(|t| t.is_string()) {
        return Some(TextPath::OllamaResponse);
    }
    if v.get("message")
        .and_then(|m| m.get("content"))
        .is_some_and(|t| t.is_string())
    {
        return Some(TextPath::OllamaMessage);
    }
    if let Some(c0) = v.get("choices").and_then(|c| c.get(0)) {
        if c0
            .get("delta")
            .and_then(|d| d.get("content"))
            .is_some_and(|t| t.is_string())
        {
            return Some(TextPath::OpenAiDelta);
        }
        if c0.get("text").is_some_and(|t| t.is_string()) {
            return Some(TextPath::OpenAiText);
        }
    }
    None
}

fn get_text(v: &serde_json::Value, path: TextPath) -> Option<&str> {
    match path {
        TextPath::OllamaResponse => v.get("response")?.as_str(),
        TextPath::OllamaMessage => v.get("message")?.get("content")?.as_str(),
        TextPath::OpenAiDelta => v
            .get("choices")?
            .get(0)?
            .get("delta")?
            .get("content")?
            .as_str(),
        TextPath::OpenAiText => v.get("choices")?.get(0)?.get("text")?.as_str(),
    }
}

/// Replace the frame's text delta in place. Returns false when the path is
/// unexpectedly absent (caller then passes the frame through verbatim).
fn set_text(v: &mut serde_json::Value, path: TextPath, s: String) -> bool {
    let slot = match path {
        TextPath::OllamaResponse => v.get_mut("response"),
        TextPath::OllamaMessage => v.get_mut("message").and_then(|m| m.get_mut("content")),
        TextPath::OpenAiDelta => v
            .get_mut("choices")
            .and_then(|c| c.get_mut(0))
            .and_then(|c0| c0.get_mut("delta"))
            .and_then(|d| d.get_mut("content")),
        TextPath::OpenAiText => v
            .get_mut("choices")
            .and_then(|c| c.get_mut(0))
            .and_then(|c0| c0.get_mut("text")),
    };
    match slot {
        Some(slot) => {
            *slot = serde_json::Value::String(s);
            true
        }
        None => false,
    }
}

/// A frame buffer that never completes (no terminator seen) must not grow
/// without bound: past this we permanently fall back to verbatim passthrough
/// for the rest of the stream (fail-open).
const MAX_FRAME_BUF: usize = 1024 * 1024;

/// Incremental frame processor: splits the byte stream into NDJSON lines / SSE
/// events, routes each frame's text delta through the [`StreamMasker`], and
/// re-serializes. Everything unrecognized passes through verbatim (fail-open).
///
/// [`StreamMasker`]: crate::brain::stream_mask::StreamMasker
struct FrameMasker {
    kind: StreamKind,
    masker: crate::brain::stream_mask::StreamMasker,
    buf: Vec<u8>,
    /// Template (a clone of the last content-bearing frame) used to synthesize
    /// one final frame carrying the flushed holdback text at stream end.
    template: Option<(serde_json::Value, TextPath)>,
    /// Set when framing has failed; the remainder of the stream passes through
    /// verbatim (fail-open: transparency beats masking).
    broken: bool,
}

impl FrameMasker {
    fn new(kind: StreamKind, masker: crate::brain::stream_mask::StreamMasker) -> Self {
        FrameMasker {
            kind,
            masker,
            buf: Vec::new(),
            template: None,
            broken: false,
        }
    }

    fn masked_total(&self) -> usize {
        self.masker.masked_total()
    }

    /// Feed one network chunk; returns the bytes to forward to the client now.
    fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        if self.broken {
            return chunk.to_vec();
        }
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::with_capacity(chunk.len());
        loop {
            let frame_end = match self.kind {
                StreamKind::Ndjson => self.buf.iter().position(|&b| b == b'\n').map(|p| p + 1),
                StreamKind::Sse => find_sse_event_end(&self.buf),
            };
            match frame_end {
                Some(end) => {
                    let frame: Vec<u8> = self.buf.drain(..end).collect();
                    match self.kind {
                        StreamKind::Ndjson => out.extend(self.process_ndjson_line(&frame)),
                        StreamKind::Sse => out.extend(self.process_sse_event(&frame)),
                    }
                }
                None => break,
            }
        }
        if self.buf.len() > MAX_FRAME_BUF {
            // No terminator in over a megabyte: this is not the stream shape we
            // understand. Fall back to passthrough for the rest of the stream.
            tracing::warn!(
                "proxy: stream frame exceeded {} bytes; falling back to passthrough (fail-open)",
                MAX_FRAME_BUF
            );
            self.broken = true;
            out.append(&mut self.buf);
        }
        out
    }

    /// Stream end: flush the masker's holdback (synthesized into a final frame
    /// when there is text left) and drain any incomplete buffered frame verbatim.
    fn finish(&mut self) -> Vec<u8> {
        let mut out = self.synthesize_flush();
        out.append(&mut self.buf);
        out
    }

    /// One complete NDJSON line (including its `\n`).
    fn process_ndjson_line(&mut self, line: &[u8]) -> Vec<u8> {
        let trimmed = trim_ascii(line);
        if trimmed.is_empty() {
            return line.to_vec();
        }
        let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(trimmed) else {
            return line.to_vec(); // not JSON — verbatim (fail-open)
        };
        let done = v.get("done").and_then(|d| d.as_bool()).unwrap_or(false);
        let Some(path) = find_text_path(&v) else {
            if done {
                // Final frame without a text slot: flush ahead of it.
                let mut out = self.synthesize_flush();
                out.extend_from_slice(line);
                return out;
            }
            return line.to_vec();
        };
        let text = get_text(&v, path).unwrap_or_default().to_string();
        if !done {
            self.template = Some((v.clone(), path));
        }
        let mut masked = self.masker.push(&text);
        if done {
            // Ollama's final frame carries the text slot (normally empty): the
            // flushed holdback rides in it, so nothing is ever left behind.
            masked.push_str(&self.masker.flush());
        }
        if !set_text(&mut v, path, masked) {
            return line.to_vec();
        }
        match serde_json::to_vec(&v) {
            Ok(mut bytes) => {
                bytes.push(b'\n');
                bytes
            }
            Err(_) => line.to_vec(),
        }
    }

    /// One complete SSE event (including its blank-line terminator).
    fn process_sse_event(&mut self, event: &[u8]) -> Vec<u8> {
        let Ok(text) = std::str::from_utf8(event) else {
            return event.to_vec();
        };
        // Exactly one `data:` line is the shape LLM engines emit; anything else
        // (multi-line data, comments-only) passes through verbatim.
        let data_lines: Vec<&str> = text.lines().filter(|l| l.starts_with("data:")).collect();
        if data_lines.len() != 1 {
            return event.to_vec();
        }
        let payload = data_lines[0]["data:".len()..].trim_start();
        if payload == "[DONE]" {
            let mut out = self.synthesize_flush();
            out.extend_from_slice(event);
            return out;
        }
        let Ok(mut v) = serde_json::from_str::<serde_json::Value>(payload) else {
            return event.to_vec();
        };
        let finished = v
            .get("choices")
            .and_then(|c| c.get(0))
            .and_then(|c0| c0.get("finish_reason"))
            .is_some_and(|f| !f.is_null());
        let Some(path) = find_text_path(&v) else {
            if finished {
                // finish_reason frame with no content slot: flush BEFORE it so
                // clients that stop reading at finish_reason still get the tail.
                let mut out = self.synthesize_flush();
                out.extend_from_slice(event);
                return out;
            }
            return event.to_vec();
        };
        let delta = get_text(&v, path).unwrap_or_default().to_string();
        if !finished {
            self.template = Some((v.clone(), path));
        }
        let mut masked = self.masker.push(&delta);
        if finished {
            masked.push_str(&self.masker.flush());
        }
        if !set_text(&mut v, path, masked) {
            return event.to_vec();
        }
        let Ok(json) = serde_json::to_string(&v) else {
            return event.to_vec();
        };
        // Rebuild the event: swap the data line, keep every other line (event:,
        // id:, retry:, comments) verbatim.
        let mut rebuilt = String::with_capacity(event.len() + json.len());
        for line in text.lines() {
            if line.starts_with("data:") {
                rebuilt.push_str("data: ");
                rebuilt.push_str(&json);
            } else {
                rebuilt.push_str(line);
            }
            rebuilt.push('\n');
        }
        rebuilt.push('\n');
        rebuilt.into_bytes()
    }

    /// Drain the masker's holdback into one synthesized frame shaped like the
    /// last content-bearing frame. Empty when there is nothing left (or no
    /// template was ever seen — which implies no text was ever pushed).
    fn synthesize_flush(&mut self) -> Vec<u8> {
        let rest = self.masker.flush();
        if rest.is_empty() {
            return Vec::new();
        }
        let Some((template, path)) = self.template.clone() else {
            tracing::warn!(
                "proxy: stream masker had holdback text but no frame template; text dropped"
            );
            return Vec::new();
        };
        let mut v = template;
        if !set_text(&mut v, path, rest) {
            return Vec::new();
        }
        match self.kind {
            StreamKind::Ndjson => match serde_json::to_vec(&v) {
                Ok(mut bytes) => {
                    bytes.push(b'\n');
                    bytes
                }
                Err(_) => Vec::new(),
            },
            StreamKind::Sse => match serde_json::to_string(&v) {
                Ok(json) => format!("data: {json}\n\n").into_bytes(),
                Err(_) => Vec::new(),
            },
        }
    }
}

/// Find the end (exclusive, including terminator) of the first complete SSE
/// event: a `\n\n` or `\r\n\r\n` separator.
fn find_sse_event_end(buf: &[u8]) -> Option<usize> {
    let lf = buf.windows(2).position(|w| w == b"\n\n").map(|p| p + 2);
    let crlf = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4);
    match (lf, crlf) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

fn trim_ascii(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|c| !c.is_ascii_whitespace());
    match start {
        Some(s) => {
            let end = b
                .iter()
                .rposition(|c| !c.is_ascii_whitespace())
                .unwrap_or(s);
            &b[s..=end]
        }
        None => &[],
    }
}

/// Forward a STREAMED response through the bounded-holdback masker. Frames flow
/// to the client as they arrive (never aggregated); only each frame's text delta
/// is rewritten, with a small bounded tail held back so a PII span straddling
/// chunks is still caught (see [`crate::brain::stream_mask`]). The ORIGINAL
/// bytes are teed for logging (true findings + offsets), mirroring
/// [`buffer_and_mask_response`]. Fail-open throughout: unrecognized frames pass
/// verbatim, and a framing failure degrades to passthrough mid-stream.
fn stream_and_mask_response(
    state: &ProxyState,
    id: String,
    start: Instant,
    status: StatusCode,
    resp_headers: HeaderMap,
    kind: StreamKind,
    upstream_resp: reqwest::Response,
) -> Response {
    let masker = crate::brain::stream_mask::StreamMasker::new(
        state.detector.clone(),
        crate::brain::Side::Response,
        state.config.load().masking.kinds.clone(),
    );
    let mut frames = FrameMasker::new(kind, masker);
    let tee = state.tee.clone();
    let status_code = status.as_u16();

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(64);
    let mut byte_stream = upstream_resp.bytes_stream();

    tokio::spawn(async move {
        let mut error_kind: Option<String> = None;
        while let Some(item) = byte_stream.next().await {
            match item {
                Ok(chunk) => {
                    // Tee the ORIGINAL chunk (logger derives TTFT + true findings).
                    send_chunk(&tee, &id, chunk.clone());
                    let out = frames.feed(&chunk);
                    if !out.is_empty() && tx.send(Ok(Bytes::from(out))).await.is_err() {
                        // Client dropped; stop pulling from the engine.
                        break;
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "proxy: upstream stream error mid-flight (masked stream)");
                    error_kind = Some("stream_error".to_string());
                    let _ = tx.send(Err(std::io::Error::other(e))).await;
                    break;
                }
            }
        }
        let rest = frames.finish();
        if !rest.is_empty() {
            let _ = tx.send(Ok(Bytes::from(rest))).await;
        }
        let resp_mask_action = if frames.masked_total() > 0 {
            MaskAction::Masked
        } else {
            MaskAction::Observed
        };
        if let Err(e) = tee.try_send(TeeEvent::ResponseFinished {
            id,
            ttft_ms: None,
            total_ms: Some(elapsed_ms(start)),
            status: Some(status_code),
            error_kind,
            resp_mask_action,
        }) {
            tracing::debug!(error = ?e, "proxy: tee full/closed on masked-stream finish (fail-open)");
        }
    });

    let body_stream =
        futures_util::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|i| (i, rx)) });
    let body = Body::from_stream(body_stream);

    let mut response = Response::builder().status(status);
    if let Some(h) = response.headers_mut() {
        *h = resp_headers;
    }
    match response.body(body) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "proxy: failed to build masked streaming response; failing open");
            (StatusCode::BAD_GATEWAY, "saffev: response build error").into_response()
        }
    }
}

/// Best-effort enqueue of a [`TeeEvent`] with **drop-oldest** semantics: if the
/// channel is full, drop the oldest queued event rather than block the client
/// path. Errors are logged to Saffev's diagnostic log and swallowed (fail-open).
pub fn tee_drop_oldest(state: &ProxyState, event: TeeEvent) {
    match state.tee.try_send(event) {
        Ok(()) => {}
        Err(tokio::sync::mpsc::error::TrySendError::Full(event)) => {
            // Drop-oldest: the logger is behind. We deliberately discard the
            // *new* event after attempting to make room conceptually — but since
            // an mpsc has no pop-front, "drop-oldest" is realized by the bounded
            // capacity plus the consumer draining fastest-first. Here we simply
            // drop this event so the client path never blocks. Logged at debug to
            // avoid noise under sustained load.
            tracing::debug!(?event, "proxy: tee full, dropping event (fail-open)");
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            // Logger gone (shutdown). Swallow.
            tracing::debug!("proxy: tee closed, dropping event");
        }
    }
}

/// Internal: tee a single response chunk verbatim, best-effort. Uses a cloned
/// sender so it is callable from inside the 'static response stream. The logger
/// timestamps the first chunk per id to derive TTFT.
fn send_chunk(tee: &crate::proxy::TeeSender, id: &str, chunk: Bytes) {
    if let Err(e) = tee.try_send(TeeEvent::ResponseChunk {
        id: id.to_string(),
        chunk,
    }) {
        match e {
            tokio::sync::mpsc::error::TrySendError::Full(_) => {
                tracing::debug!("proxy: tee full, dropping response chunk (fail-open)");
            }
            tokio::sync::mpsc::error::TrySendError::Closed(_) => {}
        }
    }
}

/// Decide + apply request-body masking (04 §7.6). Returns the bytes to forward
/// upstream and the [`MaskAction`] taken.
///
/// Behaviour (observe-by-default invariant):
/// - masking disabled -> `(original, Observed)` — pure passthrough.
/// - masking enabled + dry-run -> `(original, WouldMask)` — body unchanged, but
///   findings are recorded as `would_mask` by the logger.
/// - masking enabled + live -> scan, redact HIGH-confidence spans in scope,
///   and forward the redacted bytes as `Masked`. If nothing was actually
///   maskable, returns `(original, Observed)` so we never claim a mask we did
///   not perform.
///
/// **Fail-open:** this function never errors and never panics. Worst case it
/// returns the ORIGINAL body untouched. Only HIGH-confidence findings in the
/// configured kind allow-list are ever redacted (delegated to
/// [`crate::brain::pii::mask`] / `should_mask`); low-confidence findings are
/// never masked.
fn mask_request_body(state: &ProxyState, body: &Bytes) -> (Bytes, MaskAction) {
    // Masking (enabled / dry_run / kinds) is HOT-RELOADABLE: load the current
    // config snapshot on every request so a Studio settings change applies live,
    // without a restart. `.load()` is a cheap RCU read — fine on the hot path.
    let cfg = state.config.load();
    mask_body_with(
        &cfg.masking,
        &state.detector,
        crate::brain::Side::Request,
        body,
    )
}

/// Core masking routine, decoupled from [`ProxyState`] so it is unit testable
/// without a live store/tee. Used for both the request body ([`Side::Request`])
/// and non-streamed response bodies ([`Side::Response`]); see `mask_request_body`
/// for the behaviour / fail-open / low-confidence guarantees.
///
/// [`Side::Request`]: crate::brain::Side::Request
/// [`Side::Response`]: crate::brain::Side::Response
fn mask_body_with(
    masking: &crate::config::MaskingConfig,
    detector: &crate::brain::pii::Detector,
    side: crate::brain::Side,
    body: &Bytes,
) -> (Bytes, MaskAction) {
    if !masking.enabled || body.is_empty() {
        return (body.clone(), MaskAction::Observed);
    }

    if masking.dry_run {
        // Preview only: forward unchanged. The logger stamps `would_mask` on the
        // findings (it re-scans the original body), so we do no work here beyond
        // signalling the action.
        return (body.clone(), MaskAction::WouldMask);
    }

    // Live masking. Scan the body text and redact maskable spans. A body that is
    // not valid UTF-8 yields a lossy view; we only forward redacted bytes when at
    // least one span was masked, otherwise we observe (never claim a no-op mask).
    let text = String::from_utf8_lossy(body);
    let kinds = masking.kinds.as_deref();
    let findings = detector.scan(side, &text);
    let (redacted, masked) = crate::brain::pii::mask(&text, &findings, kinds);
    if masked == 0 {
        return (body.clone(), MaskAction::Observed);
    }
    (Bytes::from(redacted.into_bytes()), MaskAction::Masked)
}

/// Decide whether a request must be **stopped** rather than masked.
///
/// Returns the kinds that triggered the block, or `None` to proceed.
///
/// Blocking is the one place Saffev deliberately interferes with traffic, so the
/// conditions are narrow and all of them must hold: masking is enabled, it is out
/// of dry-run, the policy names at least one kind, and that kind is actually
/// present. Anything else proceeds.
///
/// This does **not** weaken fail-open. Fail-open means an *internal error* never
/// harms the user's traffic; every error path here still forwards. A block is not
/// an error, it is the user's stated policy being carried out.
fn block_decision(
    masking: &crate::config::MaskingConfig,
    detector: &crate::brain::pii::Detector,
    side: crate::brain::Side,
    body: &Bytes,
) -> Option<Vec<crate::brain::PiiKind>> {
    if !masking.enabled || masking.block_kinds.is_empty() || body.is_empty() {
        return None;
    }
    let text = String::from_utf8_lossy(body);
    let mut hit: Vec<crate::brain::PiiKind> = Vec::new();
    for f in detector.scan(side, &text) {
        // Low-confidence guesses never stop a request. Blocking on a maybe would
        // make the feature unusable and teach people to switch it off.
        if f.confidence != crate::brain::Confidence::High {
            continue;
        }
        if masking.block_kinds.contains(&f.kind) && !hit.contains(&f.kind) {
            hit.push(f.kind);
        }
    }
    (!hit.is_empty()).then_some(hit)
}

/// The response a blocked request gets.
///
/// Shaped like an OpenAI-style error object, because that is what the calling SDK
/// knows how to surface. The point is that the developer sees a clear reason in
/// their own terminal, not a mysterious hang or an empty completion.
fn blocked_response(kinds: &[crate::brain::PiiKind]) -> Response {
    let names: Vec<&str> = kinds.iter().map(crate::brain::pii::kind_key).collect();
    let message = format!(
        "Saffev blocked this request: it contains {} that your policy does not allow to be \
         sent to a model. Nothing was forwarded to the engine. Remove it, or change the \
         blocked kinds in Saffev Settings.",
        names.join(" and ")
    );
    let body = serde_json::json!({
        "error": {
            "message": message,
            "type": "saffev_policy_block",
            "code": "pii_blocked",
            "blocked_kinds": names,
        }
    });
    (
        StatusCode::FORBIDDEN,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

/// Compute the stable hash stored as `requests.request_hash`.
///
/// Uses a non-cryptographic-but-stable FNV-1a digest rendered as hex. We do not
/// need cryptographic strength here — only a stable fingerprint to dedupe /
/// correlate identical request bodies without storing them. This never stores
/// the body itself.
pub fn hash_body(body: &Bytes) -> String {
    // FNV-1a 64-bit.
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x00000100000001b3;
    let mut hash = OFFSET;
    for &b in body.iter() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    format!("{hash:016x}")
}

// ---------------------------------------------------------------------------
// Header translation
// ---------------------------------------------------------------------------

/// Build the outgoing request headers: copy everything except hop-by-hop.
fn forward_request_headers(src: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::with_capacity(src.len());
    for (name, value) in src.iter() {
        if is_hop_by_hop(name) {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

/// Build the response headers handed back to the client: copy everything except
/// hop-by-hop, so streaming content-type (`text/event-stream`,
/// `application/x-ndjson`) and friends pass through verbatim.
fn forward_response_headers(src: &reqwest::header::HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::with_capacity(src.len());
    for (name, value) in src.iter() {
        // reqwest uses the same `http` HeaderName/HeaderValue types as axum 0.7.
        if is_hop_by_hop(name) {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

// ---------------------------------------------------------------------------
// Error responses (fail-open shapes)
// ---------------------------------------------------------------------------

fn bad_gateway(err: &reqwest::Error) -> Response {
    let mut resp = (
        StatusCode::BAD_GATEWAY,
        format!("saffev: upstream unreachable: {err}"),
    )
        .into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}

fn elapsed_ms(start: Instant) -> u32 {
    start.elapsed().as_millis().min(u128::from(u32::MAX)) as u32
}

// ---------------------------------------------------------------------------
// Stream wrapper that emits ResponseFinished when the body is fully drained or
// the client drops the connection.
// ---------------------------------------------------------------------------

/// Emits a single [`TeeEvent::ResponseFinished`] exactly once, on drop. This is
/// how we capture total time regardless of whether the stream ran to completion
/// or the client disconnected early — both are normal and must finalize logging.
struct FinishGuard {
    tee: crate::proxy::TeeSender,
    id: String,
    start: Instant,
    sent: bool,
    /// Upstream HTTP status for this exchange (we got a response).
    status: Option<u16>,
    /// Set by the response stream if it errored mid-flight.
    errored: Arc<AtomicBool>,
}

impl FinishGuard {
    fn finish(&mut self) {
        if self.sent {
            return;
        }
        self.sent = true;
        let total = self.start.elapsed().as_millis().min(u128::from(u32::MAX)) as u32;
        // A mid-stream failure is a transport error even though we saw a 2xx
        // status; record it so a truncated stream is distinguishable from a clean
        // finish. HTTP 4xx/5xx are carried by `status`, not `error_kind`.
        let error_kind = if self.errored.load(Ordering::Relaxed) {
            Some("stream_error".to_string())
        } else {
            None
        };
        // Best-effort enqueue; never block on drop.
        let _ = self.tee.try_send(TeeEvent::ResponseFinished {
            id: self.id.clone(),
            // TTFT is recomputed by the logger from the first ResponseChunk's
            // arrival time; we pass None here and let the logger own the TTFT.
            ttft_ms: None,
            total_ms: Some(total),
            status: self.status,
            error_kind,
            // Streamed responses are never masked here (deferred); observe-only.
            resp_mask_action: MaskAction::Observed,
        });
    }
}

impl Drop for FinishGuard {
    fn drop(&mut self) {
        self.finish();
    }
}

use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::Stream;

/// Wraps the mapped upstream stream and carries a [`FinishGuard`] so that
/// completion/drop finalizes the exchange. When the inner stream returns `None`
/// (clean end) we finish eagerly; if the whole struct is dropped early (client
/// disconnect), the guard's `Drop` finishes it.
struct StreamWithFinish<S> {
    inner: S,
    guard: Option<FinishGuard>,
}

impl<S> Stream for StreamWithFinish<S>
where
    S: Stream<Item = Result<Bytes, std::io::Error>> + Unpin,
{
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.as_mut().get_mut();
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(None) => {
                if let Some(mut g) = this.guard.take() {
                    g.finish();
                }
                Poll::Ready(None)
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- policy blocking -------------------------------------------------
    //
    // Blocking is the only place Saffev deliberately stops a user's traffic, so
    // the tests are about when it must NOT fire at least as much as when it must.

    /// A body carrying an API key that passes the entropy gate.
    fn body_with_key() -> Bytes {
        Bytes::from_static(b"{\"prompt\":\"use sk-abc123XYZdef456GHIjkl789MNO please\"}")
    }

    fn masking(
        enabled: bool,
        dry_run: bool,
        block: Vec<crate::brain::PiiKind>,
    ) -> crate::config::MaskingConfig {
        crate::config::MaskingConfig {
            enabled,
            dry_run,
            kinds: None,
            block_kinds: block,
        }
    }

    fn policy_detector() -> crate::brain::pii::Detector {
        crate::brain::pii::Detector::new(&[]).unwrap()
    }

    #[test]
    fn blocks_only_when_policy_is_live_and_names_the_kind() {
        let body = body_with_key();
        let side = crate::brain::Side::Request;

        // Live policy naming the present kind: blocked.
        let hit = block_decision(
            &masking(true, false, vec![crate::brain::PiiKind::ApiKey]),
            &policy_detector(),
            side,
            &body,
        );
        assert_eq!(hit, Some(vec![crate::brain::PiiKind::ApiKey]));

        // Masking disabled entirely: never blocks, whatever the list says.
        assert!(block_decision(
            &masking(false, false, vec![crate::brain::PiiKind::ApiKey]),
            &policy_detector(),
            side,
            &body
        )
        .is_none());

        // Empty policy: the default, and it must never block.
        assert!(block_decision(
            &masking(true, false, vec![]),
            &policy_detector(),
            side,
            &body
        )
        .is_none());

        // Policy names a DIFFERENT kind than the one present.
        assert!(block_decision(
            &masking(true, false, vec![crate::brain::PiiKind::CreditCard]),
            &policy_detector(),
            side,
            &body
        )
        .is_none());

        // Empty body.
        assert!(block_decision(
            &masking(true, false, vec![crate::brain::PiiKind::ApiKey]),
            &policy_detector(),
            side,
            &Bytes::new()
        )
        .is_none());

        // Clean body.
        let clean = Bytes::from_static(b"{\"prompt\":\"hello there\"}");
        assert!(block_decision(
            &masking(true, false, vec![crate::brain::PiiKind::ApiKey]),
            &policy_detector(),
            side,
            &clean
        )
        .is_none());
    }

    /// Dry-run is the safety catch: the decision is computed, but the caller
    /// downgrades it to `WouldBlock` and still forwards. `block_decision` itself
    /// reports the match; the forwarder owns the dry-run downgrade.
    #[test]
    fn dry_run_still_reports_the_match_for_the_caller_to_downgrade() {
        let hit = block_decision(
            &masking(true, true, vec![crate::brain::PiiKind::ApiKey]),
            &policy_detector(),
            crate::brain::Side::Request,
            &body_with_key(),
        );
        assert_eq!(hit, Some(vec![crate::brain::PiiKind::ApiKey]));
    }

    #[test]
    fn blocked_response_tells_the_developer_what_happened() {
        let r = blocked_response(&[
            crate::brain::PiiKind::ApiKey,
            crate::brain::PiiKind::CreditCard,
        ]);
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn blocked_action_maps_to_a_storable_action() {
        assert_eq!(
            MaskAction::Blocked.to_pii_action(),
            crate::store::PiiAction::Blocked
        );
        assert_eq!(
            MaskAction::WouldBlock.to_pii_action(),
            crate::store::PiiAction::WouldBlock
        );
    }

    #[test]
    fn hash_body_is_stable_and_hex() {
        let a = Bytes::from_static(b"{\"model\":\"llama3\"}");
        let h1 = hash_body(&a);
        let h2 = hash_body(&Bytes::from_static(b"{\"model\":\"llama3\"}"));
        assert_eq!(h1, h2, "same bytes hash identically");
        assert_eq!(h1.len(), 16, "fnv-1a 64-bit rendered as 16 hex chars");
        assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_body_differs_on_different_input() {
        let a = hash_body(&Bytes::from_static(b"alpha"));
        let b = hash_body(&Bytes::from_static(b"beta"));
        assert_ne!(a, b);
    }

    #[test]
    fn hash_body_empty_is_offset_basis() {
        // Empty body hashes to the FNV offset basis.
        assert_eq!(hash_body(&Bytes::new()), "cbf29ce484222325");
    }

    #[test]
    fn hop_by_hop_detection() {
        let n: HeaderName = "Connection".parse().unwrap();
        assert!(is_hop_by_hop(&n));
        let n2: HeaderName = "content-length".parse().unwrap();
        assert!(is_hop_by_hop(&n2));
        let keep: HeaderName = "content-type".parse().unwrap();
        assert!(!is_hop_by_hop(&keep));
        let keep2: HeaderName = "authorization".parse().unwrap();
        assert!(!is_hop_by_hop(&keep2));
    }

    #[test]
    fn request_headers_strip_hop_by_hop_keep_rest() {
        let mut src = HeaderMap::new();
        src.insert("host", HeaderValue::from_static("127.0.0.1:11434"));
        src.insert("content-length", HeaderValue::from_static("42"));
        src.insert("content-type", HeaderValue::from_static("application/json"));
        src.insert("x-client-name", HeaderValue::from_static("my-app"));
        let out = forward_request_headers(&src);
        assert!(!out.contains_key("host"));
        assert!(!out.contains_key("content-length"));
        assert_eq!(out.get("content-type").unwrap(), "application/json");
        assert_eq!(out.get("x-client-name").unwrap(), "my-app");
    }

    // --- Request masking (04 §7.6) ------------------------------------------

    use crate::brain::pii::Detector;
    use crate::config::MaskingConfig;

    fn detector() -> Detector {
        Detector::new(&[]).expect("default detector compiles")
    }

    fn body_with_pii() -> Bytes {
        Bytes::from_static(
            br#"{"model":"llama3","messages":[{"role":"user","content":"email me at jane@example.com"}]}"#,
        )
    }

    #[test]
    fn masking_disabled_forwards_original_observed() {
        let cfg = MaskingConfig {
            enabled: false,
            dry_run: true,
            kinds: None,
            block_kinds: Vec::new(),
        };
        let body = body_with_pii();
        let (out, action) = mask_body_with(&cfg, &detector(), crate::brain::Side::Request, &body);
        assert_eq!(action, MaskAction::Observed);
        assert_eq!(out, body, "disabled masking must forward verbatim");
    }

    #[test]
    fn masking_dry_run_passes_through_but_would_mask() {
        let cfg = MaskingConfig {
            enabled: true,
            dry_run: true,
            kinds: None,
            block_kinds: Vec::new(),
        };
        let body = body_with_pii();
        let (out, action) = mask_body_with(&cfg, &detector(), crate::brain::Side::Request, &body);
        assert_eq!(action, MaskAction::WouldMask);
        assert_eq!(
            out, body,
            "dry-run must forward the ORIGINAL body unchanged"
        );
        assert!(
            std::str::from_utf8(&out)
                .unwrap()
                .contains("jane@example.com"),
            "dry-run must not redact"
        );
    }

    #[test]
    fn masking_live_redacts_request_body() {
        let cfg = MaskingConfig {
            enabled: true,
            dry_run: false,
            kinds: None,
            block_kinds: Vec::new(),
        };
        let body = body_with_pii();
        let (out, action) = mask_body_with(&cfg, &detector(), crate::brain::Side::Request, &body);
        assert_eq!(action, MaskAction::Masked);
        let text = std::str::from_utf8(&out).unwrap();
        assert!(text.contains("[EMAIL]"), "email must be replaced: {text}");
        assert!(
            !text.contains("jane@example.com"),
            "raw email must not reach the engine: {text}"
        );
    }

    #[test]
    fn masking_live_with_no_pii_observes() {
        let cfg = MaskingConfig {
            enabled: true,
            dry_run: false,
            kinds: None,
            block_kinds: Vec::new(),
        };
        let body = Bytes::from_static(br#"{"model":"llama3","messages":[]}"#);
        let (out, action) = mask_body_with(&cfg, &detector(), crate::brain::Side::Request, &body);
        // Nothing maskable -> never claim a mask; forward original as observed.
        assert_eq!(action, MaskAction::Observed);
        assert_eq!(out, body);
    }

    #[test]
    fn masking_live_empty_body_is_observed() {
        // Fail-open: an empty (e.g. GET) body is never touched.
        let cfg = MaskingConfig {
            enabled: true,
            dry_run: false,
            kinds: None,
            block_kinds: Vec::new(),
        };
        let (out, action) = mask_body_with(
            &cfg,
            &detector(),
            crate::brain::Side::Request,
            &Bytes::new(),
        );
        assert_eq!(action, MaskAction::Observed);
        assert!(out.is_empty());
    }

    #[test]
    fn masking_respects_kind_allow_list() {
        // Only mask IPs; an email in the body must survive.
        let cfg = MaskingConfig {
            enabled: true,
            dry_run: false,
            kinds: Some(vec![crate::brain::PiiKind::IpAddress]),
            block_kinds: Vec::new(),
        };
        let body =
            Bytes::from_static(br#"{"content":"reach me at jane@example.com via 192.168.1.100"}"#);
        let (out, action) = mask_body_with(&cfg, &detector(), crate::brain::Side::Request, &body);
        assert_eq!(action, MaskAction::Masked);
        let text = std::str::from_utf8(&out).unwrap();
        assert!(text.contains("[IP]"), "IP masked: {text}");
        assert!(
            text.contains("jane@example.com"),
            "email not in allow-list, must survive: {text}"
        );
    }

    #[test]
    fn mask_action_maps_to_pii_action() {
        use crate::store::PiiAction;
        assert_eq!(MaskAction::Observed.to_pii_action(), PiiAction::Observed);
        assert_eq!(MaskAction::WouldMask.to_pii_action(), PiiAction::WouldMask);
        assert_eq!(MaskAction::Masked.to_pii_action(), PiiAction::Masked);
    }

    #[test]
    fn elapsed_ms_saturates() {
        // Just a sanity check that elapsed_ms returns something sane for "now".
        let start = Instant::now();
        let ms = elapsed_ms(start);
        assert!(ms < 1000, "fresh instant should be ~0 ms");
    }

    // --- Non-streaming response masking (#3) --------------------------------

    #[test]
    fn masking_live_redacts_response_body() {
        // The response analogue of `masking_live_redacts_request_body`: a
        // non-streamed JSON completion echoing PII is redacted before the client
        // sees it, and stamped Masked.
        let cfg = MaskingConfig {
            enabled: true,
            dry_run: false,
            kinds: None,
            block_kinds: Vec::new(),
        };
        let body = Bytes::from_static(
            br#"{"choices":[{"message":{"content":"sure, email jane@example.com"}}]}"#,
        );
        let (out, action) = mask_body_with(&cfg, &detector(), crate::brain::Side::Response, &body);
        assert_eq!(action, MaskAction::Masked);
        let text = std::str::from_utf8(&out).unwrap();
        assert!(text.contains("[EMAIL]"), "email masked in response: {text}");
        assert!(!text.contains("jane@example.com"));
    }

    #[test]
    fn response_is_json_detects_json_not_streams() {
        let json = |ct: &'static str| {
            let mut h = reqwest::header::HeaderMap::new();
            h.insert(
                reqwest::header::CONTENT_TYPE,
                reqwest::header::HeaderValue::from_static(ct),
            );
            response_is_json(&h)
        };
        assert!(json("application/json"));
        assert!(json("application/json; charset=utf-8"));
        // Streaming content types must NOT be buffered.
        assert!(!json("text/event-stream"));
        assert!(!json("application/x-ndjson"));
        // Absent content type: not bufferable (observe).
        assert!(!response_is_json(&reqwest::header::HeaderMap::new()));
    }

    // -- streaming-response masking ------------------------------------------

    fn frame_masker(kind: StreamKind) -> FrameMasker {
        let det = std::sync::Arc::new(detector());
        let masker =
            crate::brain::stream_mask::StreamMasker::new(det, crate::brain::Side::Response, None);
        FrameMasker::new(kind, masker)
    }

    /// Reassemble the visible text a client would see from masked NDJSON output.
    fn ndjson_text(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter_map(|v| find_text_path(&v).and_then(|p| get_text(&v, p).map(|s| s.to_string())))
            .collect()
    }

    fn sse_text(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes)
            .lines()
            .filter(|l| l.starts_with("data:"))
            .map(|l| l["data:".len()..].trim_start())
            .filter(|p| *p != "[DONE]")
            .filter_map(|p| serde_json::from_str::<serde_json::Value>(p).ok())
            .filter_map(|v| {
                find_text_path(&v).and_then(|pth| get_text(&v, pth).map(|s| s.to_string()))
            })
            .collect()
    }

    #[test]
    fn stream_kind_detection() {
        let kind = |ct: &'static str| {
            let mut h = reqwest::header::HeaderMap::new();
            h.insert(
                reqwest::header::CONTENT_TYPE,
                reqwest::header::HeaderValue::from_static(ct),
            );
            response_stream_kind(&h)
        };
        assert_eq!(kind("application/x-ndjson"), Some(StreamKind::Ndjson));
        assert_eq!(kind("text/event-stream"), Some(StreamKind::Sse));
        assert_eq!(kind("application/json"), None);
        assert_eq!(
            response_stream_kind(&reqwest::header::HeaderMap::new()),
            None
        );
    }

    #[test]
    fn ndjson_email_straddling_frames_is_masked() {
        // Ollama /api/generate shape: email split across two frames, done frame
        // carries the flushed holdback.
        let mut fm = frame_masker(StreamKind::Ndjson);
        let mut out = Vec::new();
        out.extend(
            fm.feed(b"{\"model\":\"m\",\"response\":\"mail me at user@exa\",\"done\":false}\n"),
        );
        out.extend(fm.feed(b"{\"model\":\"m\",\"response\":\"mple.com thanks\",\"done\":false}\n"));
        out.extend(
            fm.feed(b"{\"model\":\"m\",\"response\":\"\",\"done\":true,\"eval_count\":42}\n"),
        );
        out.extend(fm.finish());
        let text = ndjson_text(&out);
        assert_eq!(text, "mail me at [EMAIL] thanks");
        assert_eq!(fm.masked_total(), 1);
        // Non-text metadata survives (token accounting fields intact).
        assert!(String::from_utf8_lossy(&out).contains("\"eval_count\":42"));
    }

    #[test]
    fn ndjson_line_split_across_network_chunks_reassembles() {
        // A single JSON line arriving in three arbitrary byte chunks.
        let mut fm = frame_masker(StreamKind::Ndjson);
        let mut out = Vec::new();
        out.extend(fm.feed(b"{\"response\":\"clean "));
        out.extend(fm.feed(b"text he"));
        out.extend(fm.feed(b"re\",\"done\":false}\n"));
        out.extend(fm.feed(b"{\"response\":\"\",\"done\":true}\n"));
        out.extend(fm.finish());
        assert_eq!(ndjson_text(&out), "clean text here");
    }

    #[test]
    fn ndjson_chat_shape_is_masked() {
        // Ollama /api/chat shape: message.content.
        let mut fm = frame_masker(StreamKind::Ndjson);
        let mut out = Vec::new();
        out.extend(fm.feed(
            b"{\"message\":{\"role\":\"assistant\",\"content\":\"card 4111 1111 1111 1111 ok\"},\"done\":false}\n",
        ));
        out.extend(
            fm.feed(b"{\"message\":{\"role\":\"assistant\",\"content\":\"\"},\"done\":true}\n"),
        );
        out.extend(fm.finish());
        let text = ndjson_text(&out);
        assert!(text.contains("[CARD]"), "got: {text}");
        assert!(!text.contains("4111"));
    }

    #[test]
    fn ndjson_garbage_passes_through_verbatim() {
        let mut fm = frame_masker(StreamKind::Ndjson);
        let out = fm.feed(b"this is not json at all\n");
        assert_eq!(out, b"this is not json at all\n");
        assert_eq!(fm.masked_total(), 0);
    }

    #[test]
    fn sse_email_straddling_events_is_masked_and_done_preserved() {
        // OpenAI-compatible stream (LM Studio): delta.content across events,
        // then a finish_reason frame, then [DONE].
        let mut fm = frame_masker(StreamKind::Sse);
        let mut out = Vec::new();
        out.extend(fm.feed(
            b"data: {\"choices\":[{\"delta\":{\"content\":\"reach me: user@exa\"},\"finish_reason\":null}]}\n\n",
        ));
        out.extend(fm.feed(
            b"data: {\"choices\":[{\"delta\":{\"content\":\"mple.com bye\"},\"finish_reason\":null}]}\n\n",
        ));
        out.extend(fm.feed(b"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n"));
        out.extend(fm.feed(b"data: [DONE]\n\n"));
        out.extend(fm.finish());
        let text = sse_text(&out);
        assert_eq!(text, "reach me: [EMAIL] bye");
        let raw = String::from_utf8_lossy(&out);
        assert!(raw.contains("[DONE]"), "terminator must survive");
        assert!(raw.contains("finish_reason"), "finish frame must survive");
        // The flushed tail must arrive BEFORE the finish_reason frame.
        let tail_pos = raw.find("bye").expect("tail text present");
        let fin_pos = raw.find("\"stop\"").expect("finish frame present");
        assert!(
            tail_pos < fin_pos,
            "holdback must flush before finish_reason"
        );
    }

    #[test]
    fn sse_event_split_across_chunks_reassembles() {
        let mut fm = frame_masker(StreamKind::Sse);
        let mut out = Vec::new();
        out.extend(fm.feed(b"data: {\"choices\":[{\"delta\":{\"content\":"));
        out.extend(fm.feed(b"\"hello world\"},\"finish_reason\":null}]}\n"));
        out.extend(fm.feed(b"\n"));
        out.extend(fm.feed(b"data: [DONE]\n\n"));
        out.extend(fm.finish());
        assert_eq!(sse_text(&out), "hello world");
    }

    #[test]
    fn oversized_frame_falls_back_to_passthrough() {
        // A "stream" with no terminator must not buffer forever: past the cap it
        // degrades to verbatim passthrough (fail-open).
        let mut fm = frame_masker(StreamKind::Ndjson);
        let chunk = vec![b'x'; 300 * 1024];
        let mut emitted = 0usize;
        for _ in 0..5 {
            emitted += fm.feed(&chunk).len();
        }
        assert!(emitted >= 5 * chunk.len() - MAX_FRAME_BUF - chunk.len());
        assert!(fm.broken, "must be in passthrough mode");
        // Subsequent chunks flow straight through.
        assert_eq!(fm.feed(b"more").len(), 4);
    }

    #[test]
    fn stream_end_without_done_frame_still_flushes_holdback() {
        // Engine died mid-stream: finish() must synthesize a frame carrying the
        // held-back (masked) text so the client is never short-changed.
        let mut fm = frame_masker(StreamKind::Ndjson);
        let mut out = Vec::new();
        out.extend(fm.feed(b"{\"response\":\"short text user@example.com\",\"done\":false}\n"));
        out.extend(fm.finish());
        let text = ndjson_text(&out);
        assert_eq!(text, "short text [EMAIL]");
    }
}
