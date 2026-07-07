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
    /// Raw (unmasked) text not yet emitted. Kept raw so offsets from rescans
    /// stay valid; masking is applied only at emission time.
    tail: String,
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
            tail: String::new(),
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
        self.emit_up_to_holdback()
    }

    /// Stream end: mask and drain everything still held back.
    pub fn flush(&mut self) -> String {
        if self.tail.is_empty() {
            return String::new();
        }
        let text = std::mem::take(&mut self.tail);
        let findings = self.detector.scan(self.side, &text);
        let (masked, n) = mask(&text, &findings, self.kinds.as_deref());
        self.masked_total += n;
        masked
    }

    /// Emit the prefix of `tail` that is outside the holdback window, masked.
    /// The cut never lands inside a maskable finding (it is moved back to the
    /// finding's start so the span stays whole in the tail for the next round)
    /// and always lands on a UTF-8 char boundary.
    fn emit_up_to_holdback(&mut self) -> String {
        if self.tail.len() <= HOLDBACK_BYTES {
            return String::new();
        }
        let text = &self.tail;
        let findings = self.detector.scan(self.side, text);

        let mut cut = text.len() - HOLDBACK_BYTES;
        // Never split a maskable span: if one straddles the cut, hold the whole
        // span back. (Non-maskable findings may be split — they are forwarded
        // verbatim either way.)
        for f in findings
            .iter()
            .filter(|f| should_mask(f, self.kinds.as_deref()))
        {
            if f.start < cut && f.end > cut {
                cut = f.start;
            }
        }
        // Fail-open bound: a pathological straddler must not grow the tail
        // without limit — past MAX_TAIL_BYTES we force the plain holdback cut.
        if text.len() - cut > MAX_TAIL_BYTES {
            cut = text.len() - HOLDBACK_BYTES;
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
        self.tail = text[cut..].to_string();
        masked_head
    }
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
}
