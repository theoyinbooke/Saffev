//! The brain — platform-independent judgment + PII.
//!
//! This module MUST NOT depend on the proxy existing. It is the code that later
//! compiles as an embeddable library (C-ABI / PyO3 / napi-rs). The fixture rule:
//! the same input produces the same findings whether routed through the gateway
//! or called via the embedded library.
//!
//! Ships:
//! - [`pii`] deterministic detectors.
//! - The pluggable judgment sockets: [`guard::SafetyGuard`] (deterministic
//!   floor + optional model guard) and [`judge::RubricJudge`] over an injected
//!   [`judge::LlmBackend`]. Judges/guards are *never* called inline — only via
//!   the async eval sampler.

pub mod guard;
pub mod judge;
pub mod pii;
pub mod stream_mask;

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
    /// PEM private-key block (`-----BEGIN … PRIVATE KEY-----`).
    PrivateKey,
    /// JSON Web Token (three dot-joined base64url segments).
    Jwt,
    /// Connection string / URL with embedded credentials (`scheme://user:pass@…`).
    ConnectionString,
    /// US Social Security Number (dashed form, structurally validated).
    Ssn,
    /// IBAN (ISO 7064 mod-97 validated).
    Iban,
    /// MAC address (colon or hyphen form).
    MacAddress,
    /// Config-file credential assignment — shell/`.env` (`DB_PASSWORD=…`),
    /// JSON (`"password": "…"`), YAML (`password: …`), TOML (`password = "…"`).
    /// (Wire name stays `env_assignment` — it predates the non-shell forms.)
    EnvAssignment,
    /// Cryptocurrency wallet address (base58check / bech32 / EVM hex).
    CryptoWallet,
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

// NOTE on pluggability: an earlier design had a `Judge` trait here "wired to a
// NoopJudge". That trait was never consumed — the real, wired sockets are:
//
// - **Safety**: the [`guard::SafetyGuard`] trait ([`guard::DeterministicGuard`]
//   floor + optional [`guard::ModelGuard`] selected by `[eval] guard_model`);
// - **Quality**: [`judge::RubricJudge`] running through an injected
//   [`judge::LlmBackend`] (the proxy supplies the engine-backed impl), enabled
//   by `[eval] quality` + `judge_model`.
//
// Both are invoked **only via the async eval sampler**, never inline. A
// purpose-trained local judge plugs in through those two seams, not a third.
