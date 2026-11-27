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

use once_cell::sync::Lazy;
use tiktoken_rs::CoreBPE;

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

/// Scan a (possibly multi-line / pretty-printed / SSE) body for the last usage record.
fn scan_text(text: &str) -> (Option<TokenCount>, Option<TokenCount>) {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return (None, None);
    }

    // Fast path for single-document JSON responses (including pretty-printed
    // multi-line JSON from LM Studio / llama-server).
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
            let (i, o) = parse_usage_object(&value);
            return (i.map(TokenCount::exact), o.map(TokenCount::exact));
        }
    }

    // Streaming NDJSON / SSE: scan in reverse because cumulative usage rides on
    // the terminal frame(s), and pre-filter lines lacking usage keys to skip
    // parsing thousands of token-delta JSON frames.
    let mut input: Option<u32> = None;
    let mut output: Option<u32> = None;

    for raw_line in text.lines().rev() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
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
        if !json_str.contains("usage") && !json_str.contains("eval_count") {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(json_str) else {
            continue;
        };
        if input.is_none() {
            input = ollama_or_openai_input(&value);
        }
        if output.is_none() {
            output = ollama_or_openai_output(&value);
        }
        if input.is_some() && output.is_some() {
            break;
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

/// Bundled BPE tokenizer used for estimation, built once and reused.
///
/// `o200k_base` (the GPT-4o family vocabulary) is a solid general-purpose default.
/// It is NOT the exact tokenizer for Llama / Qwen / Mistral / etc., so any count
/// derived from it is always marked [`TokenSource::Estimated`] — but it is real
/// BPE tokenization, dramatically closer to the truth than a chars/4 rule of
/// thumb, and it is bundled (no network, consistent with the on-device invariant).
static BPE: Lazy<Option<CoreBPE>> = Lazy::new(|| tiktoken_rs::o200k_base().ok());

/// Count tokens in `text` with the bundled tokenizer, falling back to the
/// chars/4 heuristic if the tokenizer is somehow unavailable. Synchronous and
/// CPU-cheap; call it from the logger task (off the request hot path).
pub fn estimate_count(text: &str) -> u32 {
    if text.is_empty() {
        return 0;
    }
    match BPE.as_ref() {
        Some(bpe) => u32::try_from(bpe.encode_with_special_tokens(text).len()).unwrap_or(u32::MAX),
        None => heuristic_token_estimate(text),
    }
}

/// Estimate token count for `text` under `model`, off the hot path. Marked
/// [`TokenSource::Estimated`]. Uses the bundled BPE tokenizer ([`estimate_count`]).
pub async fn estimate(_model: &str, text: &str) -> Result<TokenCount> {
    Ok(TokenCount::estimated(estimate_count(text)))
}

/// A rough, deterministic token estimate: ~4 chars/token is the well-worn rule of
/// thumb for English BPE tokenizers. Empty text → 0. Always rounds up so any
/// non-empty text yields at least 1 token. Used only as a fallback when the
/// bundled tokenizer can't be built (see [`estimate_count`]).
fn heuristic_token_estimate(text: &str) -> u32 {
    let chars = text.chars().count();
    if chars == 0 {
        return 0;
    }
    // ceil(chars / 4), saturating into u32.
    let est = chars.div_ceil(4);
    u32::try_from(est).unwrap_or(u32::MAX)
}

/// Concatenate the **prompt** text from a request body, for estimation when the
/// engine did not report input usage. Handles chat (`messages[].content`, both
/// plain string and OpenAI content-part arrays), Ollama top-level `system`, and
/// completion (`prompt`) shapes across Ollama and OpenAI. Best-effort: an
/// unknown shape yields `""` (→ 0 tokens), never an error.
pub fn extract_prompt_text(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text.trim()) else {
        return String::new();
    };
    extract_prompt_text_from_value(&v)
}

/// Extract prompt text from an already-parsed request JSON [`serde_json::Value`],
/// avoiding redundant JSON DOM parses when the caller already parsed the body.
pub fn extract_prompt_text_from_value(v: &serde_json::Value) -> String {
    let mut out = String::new();
    // Ollama `/api/generate` top-level system prompt.
    if let Some(sys) = v.get("system").and_then(|s| s.as_str()) {
        push_sep(&mut out, sys);
    }
    // Chat: messages: [{ role, content }] (string OR OpenAI array-of-parts).
    if let Some(msgs) = v.get("messages").and_then(|m| m.as_array()) {
        for m in msgs {
            match m.get("content") {
                Some(serde_json::Value::String(c)) => push_sep(&mut out, c),
                Some(serde_json::Value::Array(parts)) => {
                    for part in parts {
                        if let Some(t) = part.get("text").and_then(|t| t.as_str()) {
                            push_sep(&mut out, t);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    // Completion: prompt is a string (or array of strings).
    match v.get("prompt") {
        Some(serde_json::Value::String(s)) => push_sep(&mut out, s),
        Some(serde_json::Value::Array(arr)) => {
            for p in arr {
                if let Some(s) = p.as_str() {
                    push_sep(&mut out, s);
                }
            }
        }
        _ => {}
    }
    out
}

/// Concatenate the **generated** text from a response body, for estimation when
/// the engine did not report output usage. Handles non-streamed (including
/// pretty-printed multi-line JSON) and streamed (NDJSON / SSE) Ollama and
/// OpenAI shapes. Best-effort.
pub fn extract_completion_text(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    // Single-document JSON (e.g. pretty-printed non-streaming response).
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
            append_completion_from(&v, &mut out);
            return out;
        }
    }
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
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
        let Ok(v) = serde_json::from_str::<serde_json::Value>(json_str) else {
            continue;
        };
        append_completion_from(&v, &mut out);
    }
    out
}

/// Pull generated text out of a single response JSON object into `out`.
fn append_completion_from(v: &serde_json::Value, out: &mut String) {
    // Ollama chat: { message: { content } }.
    if let Some(c) = v
        .get("message")
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
    {
        out.push_str(c);
    }
    // Ollama generate: { response }.
    if let Some(c) = v.get("response").and_then(|c| c.as_str()) {
        out.push_str(c);
    }
    // OpenAI: choices[].delta.content (stream) / message.content (final) / text.
    if let Some(choices) = v.get("choices").and_then(|c| c.as_array()) {
        for ch in choices {
            if let Some(c) = ch
                .get("delta")
                .and_then(|d| d.get("content"))
                .and_then(|c| c.as_str())
            {
                out.push_str(c);
            }
            if let Some(c) = ch
                .get("message")
                .and_then(|m| m.get("content"))
                .and_then(|c| c.as_str())
            {
                out.push_str(c);
            }
            if let Some(c) = ch.get("text").and_then(|c| c.as_str()) {
                out.push_str(c);
            }
        }
    }
}

/// Append `s` to `out` with a space separator when `out` is non-empty.
fn push_sep(out: &mut String, s: &str) {
    if !out.is_empty() {
        out.push(' ');
    }
    out.push_str(s);
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
        // Real BPE tokenization (o200k): "hello world" is a couple of tokens —
        // fewer than the character count, and always at least one.
        assert!(tc.value >= 1 && tc.value <= 11);
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
    fn tokenizer_beats_chars_over_four_on_real_text() {
        // BPE merges common words, so token count is well under chars/4-implied
        // upper bound and non-zero for real prose.
        let n = estimate_count("The quick brown fox jumps over the lazy dog.");
        assert!(n > 0 && n < 44);
    }

    #[test]
    fn extract_prompt_text_chat_and_completion() {
        let chat = br#"{"model":"llama3","messages":[{"role":"user","content":"hi there"},{"role":"assistant","content":"yo"}]}"#;
        assert_eq!(extract_prompt_text(chat), "hi there yo");
        let comp = br#"{"model":"llama3","prompt":"once upon a time"}"#;
        assert_eq!(extract_prompt_text(comp), "once upon a time");
        assert_eq!(extract_prompt_text(b"not json"), "");
    }

    #[test]
    fn extract_completion_text_streamed_and_final() {
        // Ollama NDJSON stream.
        let ndjson = b"{\"message\":{\"content\":\"hel\"},\"done\":false}\n{\"message\":{\"content\":\"lo\"},\"done\":true}\n";
        assert_eq!(extract_completion_text(ndjson), "hello");
        // OpenAI SSE stream.
        let sse = b"data: {\"choices\":[{\"delta\":{\"content\":\"foo\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\"bar\"}}]}\n\ndata: [DONE]\n\n";
        assert_eq!(extract_completion_text(sse), "foobar");
        // OpenAI non-streamed.
        let json = br#"{"choices":[{"message":{"content":"hello world"}}]}"#;
        assert_eq!(extract_completion_text(json), "hello world");
    }

    #[test]
    fn token_count_constructors() {
        assert!(matches!(TokenCount::exact(5).source, TokenSource::Exact));
        assert!(matches!(
            TokenCount::estimated(5).source,
            TokenSource::Estimated
        ));
    }

    #[test]
    fn handles_pretty_printed_json_and_array_form_prompt_content() {
        let pretty = br#"{
  "choices": [
    { "message": { "content": "pretty reply" } }
  ],
  "usage": {
    "prompt_tokens": 11,
    "completion_tokens": 22
  }
}"#;
        let (i, o) = extract_usage(pretty);
        assert_eq!(i.map(|c| c.value), Some(11));
        assert_eq!(o.map(|c| c.value), Some(22));
        assert_eq!(extract_completion_text(pretty), "pretty reply");

        let req = br#"{"system":"be terse","messages":[{"role":"user","content":[{"type":"text","text":"part one"},{"type":"image_url","image_url":{"url":"x"}},{"type":"text","text":"part two"}]}]}"#;
        assert_eq!(extract_prompt_text(req), "be terse part one part two");
    }
}
