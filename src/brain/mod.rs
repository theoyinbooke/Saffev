//! The brain — platform-independent judgment + PII.
//!
//! This module MUST NOT depend on the proxy existing. It is the code that later
//! compiles as an embeddable library (C-ABI / PyO3 / napi-rs). The fixture rule:
//! the same input produces the same findings whether routed through the gateway
//! or called via the embedded library.
//!
//! v0 ships:
//! - [`pii`] deterministic detectors (signatures only here; impl later).
//! - A [`Judge`] trait (the pluggable judgment socket) wired to [`NoopJudge`].
//!   No model-based judge ships in v0, and judges are *never* called inline —
//!   only via the async sampler.

pub mod pii;

use serde::{Deserialize, Serialize};

/// A category of detected PII.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PiiKind {
    /// Email address.
    Email,
    /// Phone number.
    Phone,
    /// Credit-card number (Luhn-validated).
    CreditCard,
    /// API key / token (prefix + Shannon-entropy threshold).
    ApiKey,
    /// IPv4 or IPv6 address.
    IpAddress,
    /// A user-defined custom pattern (carries its label).
    Custom,
}

/// How sure a detector is. High = deterministic, validated; Low = best-effort.
/// v0 ships only deterministic patterns to avoid over-flagging (04 §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Deterministic, validated (e.g. Luhn-passing card, entropy-passing key).
    #[default]
    High,
    /// Heuristic / best-effort (not shipped in v0; reserved for research R5).
    Low,
}

/// Which side of the exchange a finding came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Side {
    /// The request body (prompt).
    Request,
    /// The response body (completion).
    Response,
}

/// A single PII detection. **Never carries the raw matched secret** — only a
/// hashed/redacted representation is persisted (04 §6.1, §7.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Category of PII.
    pub kind: PiiKind,
    /// For [`PiiKind::Custom`], the pattern's label; else `None`.
    pub label: Option<String>,
    /// Which side this was found on.
    pub side: Side,
    /// Inclusive start byte/char offset into the scanned text.
    pub start: usize,
    /// Exclusive end byte/char offset into the scanned text.
    pub end: usize,
    /// Detector confidence.
    pub confidence: Confidence,
    /// A stable hash of the matched value (never the value itself).
    pub value_hash: String,
}

/// A judge's score on a record (research socket; unused in v0).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Score {
    /// Metric name (e.g. `relevance`, `coherence`).
    pub metric: String,
    /// Banded verdict (e.g. `good` / `weak`); avoids over-precise numerics.
    pub band: String,
    /// Optional rationale text.
    pub rationale: Option<String>,
}

/// A record handed to a judge for async evaluation. Deliberately minimal and
/// proxy-independent so the brain stays embeddable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgeRecord {
    /// Correlates back to the stored request id.
    pub record_id: String,
    /// Prompt text (only present when payload storage / sampling provides it).
    pub prompt: Option<String>,
    /// Response text (only present when available).
    pub response: Option<String>,
    /// Optional retrieval context, if the request carried one.
    pub context: Option<String>,
}

/// The pluggable judgment interface (04 §6.2). v0 wires this to [`NoopJudge`].
///
/// Implementations are invoked **only via the async sampler**, never inline.
#[async_trait::async_trait]
pub trait Judge: Send + Sync {
    /// Deterministic / cheap screen of a single side's text.
    fn screen(&self, side: Side, text: &str) -> Vec<Finding>;

    /// Model-based evaluation of a full record (async, sampled, off hot path).
    async fn evaluate(&self, record: &JudgeRecord) -> Vec<Score>;
}

/// The default, shipped judge: does nothing. Keeps the storage schema and the
/// Studio panels ready without shipping unreliable signal.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopJudge;

#[async_trait::async_trait]
impl Judge for NoopJudge {
    fn screen(&self, _side: Side, _text: &str) -> Vec<Finding> {
        Vec::new()
    }

    async fn evaluate(&self, _record: &JudgeRecord) -> Vec<Score> {
        Vec::new()
    }
}
