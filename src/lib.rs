//! # Saffev — the passive core
//!
//! A single Rust binary that sits in front of a local LLM engine (Ollama on
//! `127.0.0.1:11434`), transparently proxying and logging its traffic on-device.
//!
//! ## Hard invariants (enforced throughout this crate)
//!
//! - **Fail-open, always.** Any internal error (tee, PII, store, supervisor)
//!   is swallowed and logged to Saffev's own diagnostic log; the request still
//!   reaches the engine and the response still reaches the app.
//! - **Zero model-based work inline.** None ships in v0. Only deterministic,
//!   microsecond-cheap checks may run on the request path.
//! - **Transparent streaming.** Ollama NDJSON and OpenAI SSE stream through
//!   unchanged via a bounded, drop-oldest tee for logging.
//! - **Metadata-only by default.** Raw payloads are stored only behind an
//!   explicit opt-in (`payload_storage`).
//! - **Nothing leaves the device**, with exactly two named exceptions, both
//!   opt-in or content-free:
//!   1. The update check, which contacts GitHub release metadata only (a version
//!      number and an installer asset) and never sends user or content data.
//!   2. The optional AI summary (`agents::codex_server`), which sends a session's
//!      text to OpenAI through the user's own Codex sign-in. It is **off by
//!      default** and runs **only on an explicit click**. This is the one path
//!      where user content is transmitted, and it must stay loudly labelled
//!      wherever it is offered.
//!
//!   No other network call is permitted except to the local engine.
//!
//! ## Architecture split
//!
//! The platform-independent [`brain`] (PII, judgment interface, policy) is kept
//! strictly free of any dependency on the proxy existing, so it can later be
//! compiled as an embeddable library. The per-OS [`engine`] interception layer
//! is the only place with platform-specific code.

#![forbid(unsafe_code)]
#![allow(dead_code)]

pub mod agents;
pub mod attribution;
pub mod brain;
pub mod brand;
pub mod cli;
pub mod config;
pub mod engine;
pub mod error;
pub mod exposure;
pub mod policy;
pub mod proxy;
pub mod store;
pub mod studio;
pub mod tokens;
pub mod ui;
pub mod update;

pub use error::{Error, Result};

/// Crate version, surfaced in `status`, the Studio, and the CLI banner.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
