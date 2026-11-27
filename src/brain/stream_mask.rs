//! Streaming PII masking — a bounded-holdback masker for token streams.
//!
//! The problem that kept streaming-response masking deferred: a PII span can
//! straddle two stream chunks (`"user@exa"` + `"mple.com"`), so masking chunk
//! by chunk misses it, and buffering the whole stream violates the
//! transparent-streaming invariant. The fix is a **bounded holdback**: hold
//! back only the last [`HOLDBACK_BYTES`] bytes of decoded text, scan the
//! rolling window with the deterministic detectors, and emit text only once it
//! is provably outside any maskable span. Latency cost is a constant tail —
//! the stream still flows token by token.
//!
//! Invariant posture:
//! - **Deterministic + microsecond-cheap**: each push rescans only the small
//!   retained tail plus the new delta (regex over ≤ ~[`MAX_TAIL_BYTES`] bytes).
//!   No model work, ever.
//! - **Fail-open**: never panics; a pathological tail is force-emitted rather
//!   than grown without bound. Worst case the original text passes through.
//! - **Metadata-only**: masked spans are replaced by typed placeholders; the
//!   raw secret is never retained here (findings hash it upstream).
//!
//! This module stays proxy-free (brain rule): it consumes plain text deltas
//! and returns plain text — framing (NDJSON/SSE) lives in the proxy.

use std::sync::Arc;

use crate::brain::pii::{mask, should_mask, Detector};
use crate::brain::{PiiKind, Side};

/// How much decoded text is held back from emission until it is provably not
/// the prefix of a maskable span. Must be ≥ the longest span a detector can
/// match: emails and API keys are the longest deterministic kinds (keys cap
/// around ~120 bytes with prefix + token), so 160 gives comfortable margin.
pub const HOLDBACK_BYTES: usize = 160;

/// Hard cap on the retained tail. If a straddling finding (or pathological
/// input) would keep the tail growing past this, we force-emit down to
/// [`HOLDBACK_BYTES`] instead — favouring transparency over a theoretical
/// unbounded buffer (fail-open).
pub const MAX_TAIL_BYTES: usize = 4096;

/// Left-context bytes retained (read-only) across cuts so context-sensitive
/// guards (`version 1.2.3.4`, mid-line YAML/TOML, phone `+`, IBAN prefix) keep
/// working after a holdback cut.
const CONTEXT_BYTES: usize = 48;

/// Incremental masker over a stream of decoded text deltas.
///
/// Feed deltas with [`push`], which returns the masked text that is now safe
/// to emit (possibly empty — the holdback). Call [`flush`] at stream end to
/// drain and mask the retained tail. The concatenation of all `push` outputs
/// plus the `flush` output equals the full masked text; on clean input it is
/// byte-identical to the concatenated deltas.
///
/// [`push`]: StreamMasker::push
/// [`flush`]: StreamMasker::flush
pub struct StreamMasker {
    detector: Arc<Detector>,
    side: Side,
    kinds: Option<Vec<PiiKind>>,
    /// Read-only raw context immediately preceding `tail` (up to `CONTEXT_BYTES`).
    prev_context: String,
    /// Raw (unmasked) text not yet emitted. Kept raw so offsets from rescans
    /// stay valid; masking is applied only at emission time.
    tail: String,
    /// True while suppressing a PEM private-key body whose header was already
    /// masked to `[PRIVATE_KEY]` (spanning beyond `MAX_TAIL_BYTES`) until its
    /// matching `-----END ... PRIVATE KEY-----` footer arrives.
    in_pem: bool,
    masked_total: usize,
}

impl StreamMasker {
    /// A masker for one stream. `kinds` mirrors the masking allow-list
    /// (`None` = all high-confidence kinds), snapshotted at stream start.
    pub fn new(detector: Arc<Detector>, side: Side, kinds: Option<Vec<PiiKind>>) -> Self {
        StreamMasker {
            detector,
            side,
            kinds,
            prev_context: String::new(),
            tail: String::new(),
            in_pem: false,
            masked_total: 0,
        }
    }

    /// Total spans masked so far (across all emissions).
    pub fn masked_total(&self) -> usize {
        self.masked_total
    }

    /// Append a decoded text delta; return the masked text now safe to emit.
    pub fn push(&mut self, delta: &str) -> String {
        self.tail.push_str(delta);
        if self.in_pem {
            return self.drain_pem_body();
        }
        self.emit_up_to_holdback()
    }

    /// Stream end: mask and drain everything still held back.
    pub fn flush(&mut self) -> String {
        if self.in_pem {
            let mut out = self.drain_pem_body();
            if self.in_pem {
                // Stream ended mid-PEM without an END banner; drop the raw key
                // body (we already emitted `[PRIVATE_KEY]` when entering `in_pem`).
                self.tail.clear();
                self.in_pem = false;
                return out;
            }
            out.push_str(&self.flush());
            return out;
        }
        if self.tail.is_empty() {
            return String::new();
        }
        let text = std::mem::take(&mut self.tail);
        let findings = self.scan_with_context(&text);
        let (masked, n) = mask(&text, &findings, self.kinds.as_deref());
        self.masked_total += n;
        self.prev_context.clear();
        masked
    }

    /// True if `kind` is enabled for live masking under this stream's config.
    fn kind_maskable(&self, kind: PiiKind) -> bool {
        self.kinds
            .as_ref()
            .map_or(true, |allowed| allowed.contains(&kind))
    }

    /// Scan `tail` with `prev_context` prepended so line-start and left-context
    /// guards stay accurate across cuts. Returns findings with offsets relative
    /// to `tail` (filtering out anything starting in `prev_context`).
    fn scan_with_context(&self, text: &str) -> Vec<crate::brain::Finding> {
        if self.prev_context.is_empty() {
            return self.detector.scan(self.side, text);
        }
        let prefix_len = self.prev_context.len();
        let mut combined = String::with_capacity(prefix_len + text.len());
        combined.push_str(&self.prev_context);
        combined.push_str(text);
        self.detector
            .scan(self.side, &combined)
            .into_iter()
            .filter(|f| f.start >= prefix_len)
            .map(|mut f| {
                f.start -= prefix_len;
                f.end -= prefix_len;
                f
            })
            .collect()
    }

    /// Consume raw PEM body bytes until `-----END ... PRIVATE KEY-----` arrives,
    /// then resume normal streaming on any trailing text after the footer.
    fn drain_pem_body(&mut self) -> String {
        if let Some(end_idx) = find_pem_end_after(&self.tail, 0) {
            self.tail.drain(..end_idx);
            self.prev_context.clear();
            self.in_pem = false;
            return self.emit_up_to_holdback();
        }
        // Keep only enough tail bytes to recognize a split `-----END ... PRIVATE KEY-----`.
        const PEM_END_KEEP: usize = 64;
        if self.tail.len() > PEM_END_KEEP {
            let mut drop_to = self.tail.len() - PEM_END_KEEP;
            while drop_to > 0 && !self.tail.is_char_boundary(drop_to) {
                drop_to -= 1;
            }
            self.tail.drain(..drop_to);
        }
        String::new()
    }

    /// Emit the prefix of `tail` that is outside the holdback window, masked.
    /// The cut never lands inside a maskable finding (it is moved back to the
    /// finding's start so the span stays whole in the tail for the next round),
    /// holds open PEM blocks and long `eyJ` JWTs, and always lands on a UTF-8
    /// char boundary.
    fn emit_up_to_holdback(&mut self) -> String {
        if self.tail.len() <= HOLDBACK_BYTES {
            return String::new();
        }
        let findings = self.scan_with_context(&self.tail);
        let text = self.tail.as_str();

        let default_cut = {
            let mut c = text.len() - HOLDBACK_BYTES;
            while c > 0 && !text.is_char_boundary(c) {
                c -= 1;
            }
            c
        };
        let mut cut = default_cut;

        // Snap `cut` backward up to 32 bytes to a whitespace boundary BEFORE
        // finding-straddle / PEM / JWT protection so tokens and context words
        // aren't sliced mid-word, while any space-containing finding (e.g. a
        // credit card or phone number) straddling the snapped cut is still
        // pulled back cleanly to `f.start` below.
        if cut > 0 {
            let mut floor = cut.saturating_sub(32);
            while floor < cut && !text.is_char_boundary(floor) {
                floor += 1;
            }
            if let Some(ws) = text[floor..cut]
                .rfind(|c: char| c.is_ascii_whitespace())
                .map(|rel| floor + rel + 1)
            {
                if ws > 0 {
                    cut = ws;
                }
            }
        }
        let mut open_pem_start: Option<usize> = None;

        // Never split a maskable span: if one straddles the cut, hold the whole
        // span back. For an unclosed `-----BEGIN ... PRIVATE KEY-----` header,
        // hold from its start so key material never leaks after the banner.
        for f in findings
            .iter()
            .filter(|f| should_mask(f, self.kinds.as_deref()))
        {
            if f.kind == PiiKind::PrivateKey && !text[f.start..f.end].contains("-----END ") {
                cut = cut.min(f.start);
                open_pem_start = Some(open_pem_start.map_or(f.start, |prev| prev.min(f.start)));
            } else if f.start < cut && f.end > cut {
                cut = f.start;
            }
        }

        // Hold back an incomplete long JWT (`eyJ...` still growing past 160B)
        // up to `MAX_TAIL_BYTES` so real OIDC/Auth0 JWTs don't lose `eyJ`.
        if self.kind_maskable(PiiKind::Jwt) {
            if let Some(jwt_start) = find_unclosed_jwt_start(text, cut) {
                cut = cut.min(jwt_start);
            }
        }

        // Handle oversized tails (> MAX_TAIL_BYTES).
        if text.len() - cut > MAX_TAIL_BYTES {
            if let Some(pem_start) = open_pem_start {
                // Emit anything cleanly before the PEM banner, emit one
                // `[PRIVATE_KEY]` placeholder, and enter `in_pem` suppression
                // so the multi-KB private key body never leaks in plaintext.
                let head = &text[..pem_start];
                let head_findings: Vec<_> = findings
                    .iter()
                    .filter(|f| f.end <= pem_start)
                    .cloned()
                    .collect();
                let (mut out, n) = mask(head, &head_findings, self.kinds.as_deref());
                out.push_str("[PRIVATE_KEY]");
                self.masked_total += n + 1;
                self.tail.drain(..pem_start);
                // Advance past the BEGIN marker itself so drain_pem_body only
                // searches for the END marker.
                let skip = self
                    .tail
                    .find("PRIVATE KEY-----")
                    .map(|p| p + "PRIVATE KEY-----".len())
                    .unwrap_or(0);
                self.tail.drain(..skip);
                self.prev_context.clear();
                self.in_pem = true;
                out.push_str(&self.drain_pem_body());
                return out;
            }
            // Fail-open bound for any other pathological straddler.
            cut = default_cut;
        }

        while cut > 0 && !text.is_char_boundary(cut) {
            cut -= 1;
        }
        if cut == 0 {
            return String::new();
        }

        let head = &text[..cut];
        // Only findings fully inside the head are masked now; ones fully in the
        // retained tail are rediscovered (raw text) on the next scan.
        let head_findings: Vec<_> = findings.iter().filter(|f| f.end <= cut).cloned().collect();
        let (masked_head, n) = mask(head, &head_findings, self.kinds.as_deref());
        self.masked_total += n;

        // Retain the last `CONTEXT_BYTES` of raw text before `cut` as read-only
        // left-context for the next scan.
        let mut ctx_start = cut.saturating_sub(CONTEXT_BYTES);
        while ctx_start < cut && !text.is_char_boundary(ctx_start) {
            ctx_start += 1;
        }
        self.prev_context.clear();
        self.prev_context.push_str(&text[ctx_start..cut]);

        self.tail.drain(..cut);
        masked_head
    }
}

/// If `text` contains a `-----END ... PRIVATE KEY-----` footer starting at or
/// after `from`, return the byte offset immediately after that footer.
fn find_pem_end_after(text: &str, from: usize) -> Option<usize> {
    let slice = &text[from..];
    let rel = slice.find("-----END ")?;
    let after_end = &slice[rel..];
    let tail_marker = "PRIVATE KEY-----";
    let end_rel = after_end.find(tail_marker)?;
    // Ensure it's a plausible single-line PEM footer (no newlines inside).
    let header_span = &after_end[..end_rel];
    if header_span.contains('\n') || header_span.len() > 48 {
        return None;
    }
    Some(from + rel + end_rel + tail_marker.len())
}

/// If an unbroken base64url JWT candidate (`eyJ...`) starts before `cut` and
/// extends across `cut` (so cutting at `cut` would slice off `eyJ` before the
/// 3rd segment finishes), return its start offset.
fn find_unclosed_jwt_start(text: &str, cut: usize) -> Option<usize> {
    let mut search_from = 0;
    while let Some(rel) = text[search_from..cut].find("eyJ") {
        let start = search_from + rel;
        // Word-boundary check on the left.
        let left_ok = start == 0
            || !text[..start]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
        if left_ok {
            let rest = &text[start..];
            let token_len = rest
                .bytes()
                .take_while(|&b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
                .count();
            if start + token_len > cut {
                return Some(start);
            }
        }
        search_from = start + 3;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn masker(kinds: Option<Vec<PiiKind>>) -> StreamMasker {
        let det = Arc::new(Detector::new(&[]).expect("default detector compiles"));
        StreamMasker::new(det, Side::Response, kinds)
    }

    /// Drive a masker with deltas and return the full reassembled output.
    fn run(m: &mut StreamMasker, deltas: &[&str]) -> String {
        let mut out = String::new();
        for d in deltas {
            out.push_str(&m.push(d));
        }
        out.push_str(&m.flush());
        out
    }

    #[test]
    fn clean_text_is_identity() {
        let mut m = masker(None);
        let deltas = ["Hello ", "world, ", "this is a perfectly ", "clean stream."];
        let out = run(&mut m, &deltas);
        assert_eq!(out, deltas.concat());
        assert_eq!(m.masked_total(), 0);
    }

    #[test]
    fn email_straddling_two_deltas_is_masked() {
        let mut m = masker(None);
        let out = run(&mut m, &["Contact me at user@exa", "mple.com for details."]);
        assert_eq!(out, "Contact me at [EMAIL] for details.");
        assert_eq!(m.masked_total(), 1);
    }

    #[test]
    fn email_straddling_many_tiny_deltas_is_masked() {
        // Token-by-token streaming: the realistic engine case.
        let text = "email: alice.wonder@example.co.uk done";
        let deltas: Vec<String> = text.chars().map(|c| c.to_string()).collect();
        let mut m = masker(None);
        let mut out = String::new();
        for d in &deltas {
            out.push_str(&m.push(d));
        }
        out.push_str(&m.flush());
        assert_eq!(out, "email: [EMAIL] done");
    }

    #[test]
    fn card_straddling_chunks_is_masked() {
        let mut m = masker(None);
        // Luhn-valid test number split mid-digits.
        let out = run(&mut m, &["card 4111 1111 ", "1111 1111 exp 12/28"]);
        assert!(out.contains("[CARD]"), "got: {out}");
        assert!(!out.contains("4111"));
    }

    #[test]
    fn long_clean_stream_emits_progressively() {
        // With enough clean text the masker must emit before flush (holdback
        // only retains a bounded tail).
        let mut m = masker(None);
        let chunk = "The quick brown fox jumps over the lazy dog. ";
        let mut emitted = String::new();
        for _ in 0..20 {
            emitted.push_str(&m.push(chunk));
        }
        assert!(
            emitted.len() >= 20 * chunk.len() - (HOLDBACK_BYTES + chunk.len()),
            "holdback must stay bounded; emitted only {} bytes",
            emitted.len()
        );
        emitted.push_str(&m.flush());
        assert_eq!(emitted, chunk.repeat(20));
    }

    #[test]
    fn kinds_filter_limits_masking() {
        // Only email in the allow-list: the IP must pass through verbatim.
        let mut m = masker(Some(vec![PiiKind::Email]));
        let out = run(&mut m, &["mail user@example.com ip 192.168.1.50 end"]);
        assert!(out.contains("[EMAIL]"), "got: {out}");
        assert!(out.contains("192.168.1.50"), "got: {out}");
    }

    #[test]
    fn multibyte_text_never_panics_and_roundtrips() {
        let mut m = masker(None);
        let text = "héllo wörld émoji 🦀🦀🦀 ünïcode ".repeat(12);
        let deltas: Vec<String> = text.chars().map(|c| c.to_string()).collect();
        let mut out = String::new();
        for d in &deltas {
            out.push_str(&m.push(d));
        }
        out.push_str(&m.flush());
        assert_eq!(out, text);
    }

    #[test]
    fn flush_masks_pii_entirely_inside_holdback() {
        // Short stream: everything stays in the tail until flush — flush must
        // still mask it.
        let mut m = masker(None);
        let emitted = m.push("key sk-abcdefghijklmnopqrstuvwxyz123456 end");
        let flushed = m.flush();
        let out = format!("{emitted}{flushed}");
        assert!(!out.contains("sk-abcdefghijklmnop"), "got: {out}");
    }

    #[test]
    fn tail_growth_is_bounded() {
        let mut m = masker(None);
        for _ in 0..500 {
            let _ = m.push("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        }
        assert!(
            m.tail.len() <= MAX_TAIL_BYTES + 64,
            "tail must stay bounded, got {}",
            m.tail.len()
        );
    }

    #[test]
    fn streams_pem_private_key_without_leaking_body() {
        // Test both normal (~600B) and oversized (>MAX_TAIL_BYTES) PEM blocks.
        for reps in [12usize, 100usize] {
            let mut m = masker(None);
            let mut pem = String::from("before -----BEGIN RSA PRIVATE KEY-----\n");
            for i in 0..reps {
                pem.push_str(&format!("MIIEowIBAAKCAQEAsecretKEYmaterial{i:04}abcdef0123456789\n"));
            }
            pem.push_str("-----END RSA PRIVATE KEY----- after");
            let mut out = String::new();
            for chunk in pem.as_bytes().chunks(24) {
                out.push_str(&m.push(std::str::from_utf8(chunk).unwrap()));
            }
            out.push_str(&m.flush());
            assert!(out.contains("before [PRIVATE_KEY] after"), "got: {out}");
            assert!(!out.contains("secretKEYmaterial"), "PEM body leaked: {out}");
        }
    }

    #[test]
    fn streams_long_jwt_over_holdback_without_leaking() {
        let mut m = masker(None);
        let header = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";
        let payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIiwic2NvcGUiOiJhZG1pbiB3cml0ZSByZWFkIiwiZXhwIjoxOTAwMDAwMDAwLCJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20vIiwiYXVkIjoic2FmZmV2LWFwaSJ9";
        let sig = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5cSignatureTailXYZ";
        let jwt = format!("{header}.{payload}.{sig}");
        assert!(jwt.len() > HOLDBACK_BYTES + 80);
        let full = format!("Authorization: Bearer {jwt} done");
        let mut out = String::new();
        for chunk in full.as_bytes().chunks(17) {
            out.push_str(&m.push(std::str::from_utf8(chunk).unwrap()));
        }
        out.push_str(&m.flush());
        assert_eq!(out, "Authorization: Bearer [JWT] done");
    }

    #[test]
    fn preserves_left_context_version_guard_across_cuts() {
        let mut m = masker(None);
        let pad = "a ".repeat(100);
        let full = format!("{pad}version 1.2.3.4 {pad}");
        let mut out = String::new();
        for chunk in full.as_bytes().chunks(13) {
            out.push_str(&m.push(std::str::from_utf8(chunk).unwrap()));
        }
        out.push_str(&m.flush());
        assert_eq!(out, full, "version 1.2.3.4 must not false-positive across cuts");
    }

    #[test]
    fn whitespace_snap_never_splits_space_separated_credit_card() {
        // Place a space-separated credit card right before `default_cut` followed
        // by non-whitespace so the 32-byte backward whitespace snap lands inside
        // the card. Finding-straddle protection must still pull `cut` before the
        // card so zero digits ever leak in plaintext.
        let card = "4111 1111 1111 1111";
        let tail_pad = "x".repeat(HOLDBACK_BYTES + 6);
        for prefix_len in [0usize, 1, 5, 11, 23] {
            let prefix = "p".repeat(prefix_len);
            // Non-word, non-whitespace punctuation `,` closes the card boundary
            // while still forcing the 32-byte backward whitespace snap to land
            // inside the card's spaces.
            let full = format!("{prefix}card={card},{tail_pad}");
            let mut m = masker(None);
            let mut out = String::new();
            out.push_str(&m.push(&full));
            out.push_str(&m.flush());
            assert!(
                out.contains("[CARD]") && !out.contains("4111"),
                "prefix_len={prefix_len} leaked card: {out}"
            );
        }
    }
}
