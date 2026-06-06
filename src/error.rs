//! The one crate-wide error type.
//!
//! Every fallible Saffev API returns [`Result<T>`]. Remember the fail-open
//! invariant: on the request path these errors are *logged and swallowed*, never
//! propagated to the client. They surface for real only in control-plane code
//! (CLI commands, store init, adoption) where failing loudly is correct.

use thiserror::Error;

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// The single Saffev error type.
#[derive(Debug, Error)]
pub enum Error {
    /// Configuration load / parse / validation failure.
    #[error("config error: {0}")]
    Config(String),

    /// Storage layer failure (open, migrate, query, write).
    #[error("store error: {0}")]
    Store(String),

    /// OS keyring access failure (DB key, install token).
    #[error("keyring error: {0}")]
    Keyring(String),

    /// Proxy / upstream transport failure (only ever logged, never surfaced).
    #[error("proxy error: {0}")]
    Proxy(String),

    /// Engine detection / adoption / supervision failure.
    #[error("engine error: {0}")]
    Engine(String),

    /// Studio HTTP server failure.
    #[error("studio error: {0}")]
    Studio(String),

    /// Exposure / auth doctor failure.
    #[error("exposure error: {0}")]
    Exposure(String),

    /// A feature was requested that is not available on this platform/build.
    #[error("unsupported: {0}")]
    Unsupported(String),

    /// I/O failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// JSON (de)serialization failure.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// SQLite failure.
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),

    /// TOML deserialization failure.
    #[error(transparent)]
    TomlDe(#[from] toml::de::Error),

    /// TOML serialization failure.
    #[error(transparent)]
    TomlSer(#[from] toml::ser::Error),

    /// Catch-all for anyhow-wrapped errors bubbling up from helpers.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
