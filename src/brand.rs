//! Brand constants — the single source of truth for the product name in code.
//!
//! Mirrors `design/brand.json`. If the name changes, update both. `argv[0]` and
//! the CLI wordmark banner read [`APP_CMD`]; the Studio title reads [`APP_NAME`].

/// Display / wordmark name.
pub const APP_NAME: &str = "Saffev";

/// CLI command + binary name.
pub const APP_CMD: &str = "saffev";

/// Short tagline shown under the wordmark.
pub const TAGLINE: &str = "local ai studio";
