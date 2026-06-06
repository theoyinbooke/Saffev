//! Token / usage accounting (04 §7.3).
//!
//! Trust the engine's `usage` when present (-> `exact`). Otherwise estimate
//! asynchronously **off the hot path** with a bundled per-model tokenizer
//! (-> `estimated`, displayed with a `~`). Never store dollar cost.
//!
//! NB: this is `src/tokens.rs` — token *accounting*, distinct from the design
//! tokens in `design/tokens.css`.
//!
//! ## What "usage" looks like on the wire
//!
//! Two engine dialects, both captured here from the **accumulated** response
//! body (we are called off the tee, never inline):
//!
//! * **Ollama native** (`/api/chat`, `/api/generate`) — the final object carries
//!   `prompt_eval_count` (input) and `eval_count` (output). Streaming responses
//!   are NDJSON; the terminal line (`"done": true`) holds the counts.
//! * **OpenAI-compatible** (`/v1/chat/completions`, `/v1/completions`) — a
//!   `usage` object with `prompt_tokens` / `completion_tokens`. Streaming clients
//!   must opt in (`stream_options.include_usage`), so it is frequently absent —
//!   that is exactly when we fall back to [`estimate`].
//!
//! Bodies may be a single JSON object, newline-delimited JSON, or SSE
//! (`data: {...}` lines). [`extract_usage`] handles all three and returns the
//! *last* usage it sees (the terminal/cumulative one).

use crate::store::TokenSource;
use crate::Result;

/// A counted or estimated token total + its provenance.
#[derive(Debug, Clone, Copy)]
pub struct TokenCount {
    /// The count.
    pub value: u32,
    /// Whether it came from the engine (`Exact`) or an estimate (`Estimated`).
    pub source: TokenSource,
}

impl TokenCount {
    /// An engine-reported, trusted count.
    pub fn exact(value: u32) -> Self {
        Self {
            value,
            source: TokenSource::Exact,
        }
    }

    /// A locally derived estimate (shown with a `~`).
    pub fn estimated(value: u32) -> Self {
        Self {
            value,
            source: TokenSource::Estimated,
        }
    }
}

/// Extract the engine-reported `usage` token counts from a response body, if any.
/// Returns `(input, output)` where present.
///
/// Both counts are always [`TokenSource::Exact`] — they come from the engine.
/// Either side may be `None` if the engine omitted it (e.g. a streaming
/// OpenAI-compatible response without `include_usage`).
pub fn extract_usage(body: &[u8]) -> (Option<TokenCount>, Option<TokenCount>) {
    let text = match std::str::from_utf8(body) {
        Ok(t) => t,
        // Lossy is fine — usage fields are ASCII; we only need to find them.
        Err(_) => return scan_text(&String::from_utf8_lossy(body)),
    };
    scan_text(text)
}

/// Scan a (possibly multi-line / SSE) body for the last usage record.
fn scan_text(text: &str) -> (Option<TokenCount>, Option<TokenCount>) {
    let mut input: Option<u32> = None;
    let mut output: Option<u32> = None;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        // SSE framing: payload rides on `data: {...}` lines; `[DONE]` is a sentinel.
        let json_str = match line.strip_prefix("data:") {
            Some(rest) => {
                let rest = rest.trim();
                if rest == "[DONE]" {
                    continue;
                }
                rest
            }
            None => line,
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(json_str) else {
            continue;
        };
        // Later records win (terminal/cumulative usage), so overwrite when found.
        if let (Some(i), Some(o)) = parse_usage_object(&value) {
            input = Some(i);
            output = Some(o);
        } else {
            // Allow one-sided presence (some engines report only one side).
            if let Some(i) = ollama_or_openai_input(&value) {
                input = Some(i);
            }
            if let Some(o) = ollama_or_openai_output(&value) {
                output = Some(o);
            }
        }
    }

    (input.map(TokenCount::exact), output.map(TokenCount::exact))
}

/// Try to read both sides at once; returns `(Some, Some)` only when both exist.
fn parse_usage_object(v: &serde_json::Value) -> (Option<u32>, Option<u32>) {
    (ollama_or_openai_input(v), ollama_or_openai_output(v))
}

/// Input tokens: OpenAI `usage.prompt_tokens` or Ollama `prompt_eval_count`.
fn ollama_or_openai_input(v: &serde_json::Value) -> Option<u32> {
    v.get("usage")
        .and_then(|u| u.get("prompt_tokens"))
        .and_then(as_u32)
        .or_else(|| v.get("prompt_eval_count").and_then(as_u32))
}

/// Output tokens: OpenAI `usage.completion_tokens` or Ollama `eval_count`.
fn ollama_or_openai_output(v: &serde_json::Value) -> Option<u32> {
    v.get("usage")
        .and_then(|u| u.get("completion_tokens"))
        .and_then(as_u32)
        .or_else(|| v.get("eval_count").and_then(as_u32))
}

/// Coerce a JSON number to `u32`, rejecting negatives / overflow / non-numbers.
fn as_u32(v: &serde_json::Value) -> Option<u32> {
    v.as_u64().and_then(|n| u32::try_from(n).ok())
}

/// Estimate token count for `text` under `model`, off the hot path. Marked
/// [`TokenSource::Estimated`].
///
/// v0 does **not** bundle per-model tokenizers (that is a deliberate TODO; a real
/// tokenizer would ship behind a feature so the guaranteed-green build stays
/// dependency-light). This provides a cheap, model-agnostic heuristic estimate
/// so the Studio can show a `~count` rather than nothing. It never gates anything
/// and is always marked [`TokenSource::Estimated`].
pub async fn estimate(_model: &str, text: &str) -> Result<TokenCount> {
    Ok(TokenCount::estimated(heuristic_token_estimate(text)))
}

/// A rough, deterministic token estimate: ~4 chars/token is the well-worn rule of
/// thumb for English BPE tokenizers. Empty text → 0. Always rounds up so any
/// non-empty text yields at least 1 token.
///
/// TODO(v1): replace with a bundled per-model tokenizer (e.g. tiktoken /
/// HF tokenizers) behind a cargo feature, keyed off `model`.
fn heuristic_token_estimate(text: &str) -> u32 {
    let chars = text.chars().count();
    if chars == 0 {
        return 0;
    }
    // ceil(chars / 4), saturating into u32.
    let est = chars.div_ceil(4);
    u32::try_from(est).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_ollama_native_usage() {
        let body = br#"{"model":"qwen3.5:0.8b","done":true,"done_reason":"stop","prompt_eval_count":13,"eval_count":28}"#;
        let (input, output) = extract_usage(body);
        let input = input.unwrap();
        let output = output.unwrap();
        assert_eq!(input.value, 13);
        assert_eq!(output.value, 28);
        assert!(matches!(input.source, TokenSource::Exact));
        assert!(matches!(output.source, TokenSource::Exact));
    }

    #[test]
    fn extracts_openai_compat_usage() {
        let body = br#"{"choices":[{"finish_reason":"stop"}],"usage":{"prompt_tokens":15,"completion_tokens":1507,"total_tokens":1522}}"#;
        let (input, output) = extract_usage(body);
        assert_eq!(input.unwrap().value, 15);
        assert_eq!(output.unwrap().value, 1507);
    }

    #[test]
    fn extracts_from_ndjson_stream_terminal_line() {
        // Streaming Ollama: many partial lines, counts only on the final one.
        let body = b"{\"message\":{\"content\":\"hel\"},\"done\":false}\n\
{\"message\":{\"content\":\"lo\"},\"done\":false}\n\
{\"done\":true,\"prompt_eval_count\":7,\"eval_count\":3}\n";
        let (input, output) = extract_usage(body);
        assert_eq!(input.unwrap().value, 7);
        assert_eq!(output.unwrap().value, 3);
    }

    #[test]
    fn extracts_from_sse_data_lines() {
        let body = b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n\
data: {\"choices\":[],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":4}}\n\n\
data: [DONE]\n\n";
        let (input, output) = extract_usage(body);
        assert_eq!(input.unwrap().value, 9);
        assert_eq!(output.unwrap().value, 4);
    }

    #[test]
    fn later_usage_wins() {
        // If two usage records appear, the terminal (cumulative) one is kept.
        let body = b"{\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1}}\n\
{\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":20}}\n";
        let (input, output) = extract_usage(body);
        assert_eq!(input.unwrap().value, 10);
        assert_eq!(output.unwrap().value, 20);
    }

    #[test]
    fn one_sided_usage_is_allowed() {
        let body = br#"{"prompt_eval_count":5}"#;
        let (input, output) = extract_usage(body);
        assert_eq!(input.unwrap().value, 5);
        assert!(output.is_none());
    }

    #[test]
    fn missing_usage_yields_none() {
        let body = br#"{"choices":[{"delta":{"content":"hi"}}]}"#;
        let (input, output) = extract_usage(body);
        assert!(input.is_none());
        assert!(output.is_none());
    }

    #[test]
    fn garbage_body_is_safe() {
        let (input, output) = extract_usage(b"not json at all \xff\xfe");
        assert!(input.is_none());
        assert!(output.is_none());
    }

    #[test]
    fn empty_body_yields_none() {
        let (input, output) = extract_usage(b"");
        assert!(input.is_none());
        assert!(output.is_none());
    }

    #[test]
    fn negative_or_overflow_counts_rejected() {
        let body = br#"{"prompt_eval_count":-1,"eval_count":99999999999999}"#;
        let (input, output) = extract_usage(body);
        assert!(input.is_none());
        assert!(output.is_none());
    }

    #[test]
    fn estimate_is_marked_estimated() {
        let tc = futures::executor::block_on(estimate("qwen3.5:0.8b", "hello world")).unwrap();
        assert!(matches!(tc.source, TokenSource::Estimated));
        // "hello world" = 11 chars -> ceil(11/4) = 3.
        assert_eq!(tc.value, 3);
    }

    #[test]
    fn estimate_empty_text_is_zero() {
        let tc = futures::executor::block_on(estimate("m", "")).unwrap();
        assert_eq!(tc.value, 0);
    }

    #[test]
    fn estimate_short_text_at_least_one() {
        let tc = futures::executor::block_on(estimate("m", "a")).unwrap();
        assert_eq!(tc.value, 1);
    }

    #[test]
    fn token_count_constructors() {
        assert!(matches!(TokenCount::exact(5).source, TokenSource::Exact));
        assert!(matches!(
            TokenCount::estimated(5).source,
            TokenSource::Estimated
        ));
    }
}
