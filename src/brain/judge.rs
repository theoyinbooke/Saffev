//! Model-backed quality judge (LLM-as-judge).
//!
//! Invoked **only** by the async eval worker — sampled, timed out, and
//! concurrency-gated by a semaphore so it never thrashes the engine (the
//! validated VRAM-contention risk). Emits **banded** verdicts, not precise
//! scores, because small local judges are noisy.
//!
//! Kept HTTP-free so `brain` stays embeddable: the actual model call is an
//! injected [`LlmBackend`]. The proxy supplies an impl that talks to the LOCAL
//! engine (loopback) — the on-device invariant still holds.

use async_trait::async_trait;

use super::{JudgeRecord, Score};

/// An async completion backend the judge calls. `brain` never does I/O itself;
/// the proxy provides an impl pointed at the local engine.
#[async_trait]
pub trait LlmBackend: Send + Sync {
    /// Return the model's completion for `prompt`, or `None` on any failure
    /// (timeout, transport error, bad status). The judge treats `None` as
    /// "no score" — fail-open.
    async fn complete(&self, prompt: &str) -> Option<String>;
}

/// The default judge: asks the model to band a small rubric, then parses the
/// reply leniently (small models rarely emit clean JSON).
pub struct RubricJudge;

impl RubricJudge {
    /// Evaluate one record. Returns banded [`Score`]s, or empty on any failure
    /// (missing text, backend error, unparseable reply) — always fail-open.
    /// Metrics: `relevance` + `coherence`.
    pub async fn evaluate(backend: &dyn LlmBackend, record: &JudgeRecord) -> Vec<Score> {
        // Quality judging needs both sides of the exchange.
        let (prompt, response) = match (&record.prompt, &record.response) {
            (Some(p), Some(r)) if !p.is_empty() && !r.is_empty() => (p, r),
            _ => return Vec::new(),
        };
        let rubric = build_rubric(prompt, response);
        let reply = match backend.complete(&rubric).await {
            Some(s) => s,
            None => return Vec::new(),
        };
        parse_scores(&reply)
    }
}

/// The metrics the rubric judges, in output order.
const METRICS: &[&str] = &["relevance", "coherence"];

/// Cap each side fed to the judge so the call stays cheap.
const MAX_SIDE_CHARS: usize = 2000;

fn build_rubric(prompt: &str, response: &str) -> String {
    let p = truncate(prompt, MAX_SIDE_CHARS);
    let r = truncate(response, MAX_SIDE_CHARS);
    format!(
        "You are a strict evaluation judge for an AI assistant. Rate the AI RESPONSE \
         to the USER PROMPT on two axes:\n\
         - relevance: does the response actually address the prompt?\n\
         - coherence: is the response clear and internally consistent?\n\
         Reply with ONLY a JSON object and nothing else:\n\
         {{\"relevance\":\"good|weak\",\"coherence\":\"good|weak\",\"notes\":\"<= 12 words\"}}\n\n\
         USER PROMPT:\n{p}\n\nAI RESPONSE:\n{r}\n"
    )
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max).collect();
        out.push('…');
        out
    }
}

/// Parse the judge's reply into banded scores. Deliberately robust: extracts each
/// `"key": "value"` field independently with a regex rather than requiring a
/// complete, valid JSON object. Small "thinking" models often emit a long
/// reasoning trace and then a JSON blob that gets truncated by the token cap
/// (`{"relevance":"good","coherence":"good",` with no closing brace) — this still
/// recovers the bands that ARE present, and drops anything incomplete.
fn parse_scores(reply: &str) -> Vec<Score> {
    let notes = field_str(reply, "notes").filter(|s| !s.is_empty());
    let mut out = Vec::new();
    for metric in METRICS {
        if let Some(band) = field_str(reply, metric) {
            out.push(Score {
                metric: (*metric).to_string(),
                band: normalize_band(&band),
                rationale: notes.clone(),
            });
        }
    }
    out
}

/// Extract a `"key": "value"` string field from possibly-partial JSON / prose.
/// Case-insensitive on the key; value must be a *complete* quoted string.
fn field_str(s: &str, key: &str) -> Option<String> {
    let pat = format!(r#"(?i)"{}"\s*:\s*"([^"]*)""#, regex::escape(key));
    let re = regex::Regex::new(&pat).ok()?;
    re.captures(s)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim().to_string())
}

/// Collapse a free-text band into the canonical `good` / `weak` set.
fn normalize_band(b: &str) -> String {
    match b.trim().to_ascii_lowercase().as_str() {
        "good" | "strong" | "great" | "pass" | "yes" | "high" => "good".to_string(),
        _ => "weak".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Canned(Option<String>);
    #[async_trait]
    impl LlmBackend for Canned {
        async fn complete(&self, _prompt: &str) -> Option<String> {
            self.0.clone()
        }
    }

    fn rec() -> JudgeRecord {
        JudgeRecord {
            record_id: "r1".into(),
            prompt: Some("what is 2+2?".into()),
            response: Some("4".into()),
            context: None,
        }
    }

    #[test]
    fn parses_clean_json() {
        let s = parse_scores(r#"{"relevance":"good","coherence":"weak","notes":"terse"}"#);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].metric, "relevance");
        assert_eq!(s[0].band, "good");
        assert_eq!(s[1].band, "weak");
        assert_eq!(s[0].rationale.as_deref(), Some("terse"));
    }

    #[test]
    fn parses_json_wrapped_in_prose() {
        let s = parse_scores("Sure! Here is my rating:\n{\"relevance\":\"GOOD\",\"coherence\":\"good\"} hope that helps");
        assert_eq!(s.len(), 2);
        assert!(s.iter().all(|x| x.band == "good"));
    }

    #[test]
    fn malformed_reply_yields_no_scores() {
        assert!(parse_scores("I think it was pretty good honestly").is_empty());
        assert!(parse_scores("").is_empty());
    }

    #[test]
    fn recovers_bands_from_truncated_json() {
        // A thinking model that ran out of tokens mid-JSON (no closing brace).
        let reply = "<think> the answer is Paris, relevant and clear </think>\n{\n\"relevance\": \"good\",\n\"coherence\": \"good\",";
        let s = parse_scores(reply);
        assert_eq!(
            s.len(),
            2,
            "both complete fields recovered despite truncation"
        );
        assert!(s.iter().all(|x| x.band == "good"));
    }

    #[test]
    fn unknown_band_is_weak() {
        assert_eq!(normalize_band("meh"), "weak");
        assert_eq!(normalize_band(" Good "), "good");
    }

    #[test]
    fn evaluate_needs_both_sides() {
        let backend = Canned(Some(r#"{"relevance":"good","coherence":"good"}"#.into()));
        let mut r = rec();
        r.response = None;
        let scores = futures::executor::block_on(RubricJudge::evaluate(&backend, &r));
        assert!(scores.is_empty(), "no response → no judgement");
    }

    #[test]
    fn evaluate_happy_path() {
        let backend = Canned(Some(
            r#"{"relevance":"good","coherence":"good","notes":"correct"}"#.into(),
        ));
        let scores = futures::executor::block_on(RubricJudge::evaluate(&backend, &rec()));
        assert_eq!(scores.len(), 2);
    }

    #[test]
    fn evaluate_backend_failure_is_fail_open() {
        let backend = Canned(None);
        let scores = futures::executor::block_on(RubricJudge::evaluate(&backend, &rec()));
        assert!(scores.is_empty());
    }
}
