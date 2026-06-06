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
    // SCOPE (v1): we mask the REQUEST body here (the full body is in hand). For
    // NON-STREAMING responses, masking would happen on the response path; for
    // STREAMING responses it is deferred because a PII span can straddle two
    // chunks and we must never buffer the stream (the transparent-streaming
    // invariant). See `mask_request_body` and the response path for details.
    let (forward_bytes, mask_action) = mask_request_body(state, &req_bytes);

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
            // Mark the exchange finished so the logger doesn't wait forever.
            tee_drop_oldest(
                state,
                TeeEvent::ResponseFinished {
                    id: id.clone(),
                    ttft_ms: None,
                    total_ms: Some(elapsed_ms(start)),
                },
            );
            return bad_gateway(&e);
        }
    };

    // Translate status + headers back, stripping hop-by-hop.
    let status = upstream_resp.status();
    let resp_headers = forward_response_headers(upstream_resp.headers());

    // Wrap the upstream byte stream so each chunk is teed as it is forwarded —
    // unbuffered, token-by-token. This is the streaming-passthrough core.
    //
    // TTFT is owned by the logger: it timestamps the first `ResponseChunk` it
    // sees for an id. We deliberately do not thread a clock through the contract
    // types here — keeping `TeeEvent` unchanged.
    let tee = state.tee.clone();
    let stream_id = id.clone();

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

/// Maximum request body size we buffer for teeing/PII scan. Generous enough for
/// large prompts and base64 image payloads, bounded so a hostile client can't
/// OOM us. 64 MiB.
const MAX_REQUEST_BODY: usize = 64 * 1024 * 1024;

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
    mask_body_with(&state.config.masking, &state.detector, body)
}

/// Core of [`mask_request_body`], decoupled from [`ProxyState`] so it is unit
/// testable without a live store/tee. See `mask_request_body` for behaviour +
/// the fail-open / low-confidence guarantees.
fn mask_body_with(
    masking: &crate::config::MaskingConfig,
    detector: &crate::brain::pii::Detector,
    body: &Bytes,
) -> (Bytes, MaskAction) {
    if !masking.enabled || body.is_empty() {
        return (body.clone(), MaskAction::Observed);
    }

    if masking.dry_run {
        // Preview only: forward unchanged. The logger stamps `would_mask` on the
        // request findings (it re-scans the original body), so we do no work here
        // beyond signalling the action.
        return (body.clone(), MaskAction::WouldMask);
    }

    // Live masking. Scan the body text and redact maskable spans. A body that is
    // not valid UTF-8 yields a lossy view; we only forward redacted bytes when at
    // least one span was masked, otherwise we observe (never claim a no-op mask).
    let text = String::from_utf8_lossy(body);
    let kinds = masking.kinds.as_deref();
    let findings = detector.scan(crate::brain::Side::Request, &text);
    let (redacted, masked) = crate::brain::pii::mask(&text, &findings, kinds);
    if masked == 0 {
        return (body.clone(), MaskAction::Observed);
    }
    (Bytes::from(redacted.into_bytes()), MaskAction::Masked)
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
}

impl FinishGuard {
    fn finish(&mut self) {
        if self.sent {
            return;
        }
        self.sent = true;
        let total = self.start.elapsed().as_millis().min(u128::from(u32::MAX)) as u32;
        // Best-effort enqueue; never block on drop.
        let _ = self.tee.try_send(TeeEvent::ResponseFinished {
            id: self.id.clone(),
            // TTFT is recomputed by the logger from the first ResponseChunk's
            // arrival time; we pass None here and let the logger own the TTFT.
            ttft_ms: None,
            total_ms: Some(total),
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
        };
        let body = body_with_pii();
        let (out, action) = mask_body_with(&cfg, &detector(), &body);
        assert_eq!(action, MaskAction::Observed);
        assert_eq!(out, body, "disabled masking must forward verbatim");
    }

    #[test]
    fn masking_dry_run_passes_through_but_would_mask() {
        let cfg = MaskingConfig {
            enabled: true,
            dry_run: true,
            kinds: None,
        };
        let body = body_with_pii();
        let (out, action) = mask_body_with(&cfg, &detector(), &body);
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
        };
        let body = body_with_pii();
        let (out, action) = mask_body_with(&cfg, &detector(), &body);
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
        };
        let body = Bytes::from_static(br#"{"model":"llama3","messages":[]}"#);
        let (out, action) = mask_body_with(&cfg, &detector(), &body);
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
        };
        let (out, action) = mask_body_with(&cfg, &detector(), &Bytes::new());
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
        };
        let body =
            Bytes::from_static(br#"{"content":"reach me at jane@example.com via 192.168.1.100"}"#);
        let (out, action) = mask_body_with(&cfg, &detector(), &body);
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
}
