//! In-app auto-update (the `saffev update` CLI + the Studio "Update" button).
//!
//! Thin, testable wrapper over [`axoupdater`]. It reads the **install receipt**
//! cargo-dist writes (because `install-updater = true` in `dist-workspace.toml`),
//! finds this install's release source, queries the latest GitHub release for
//! `github.com/theoyinbooke/Saffev`, decides whether an update is available, and
//! applies it by re-running the shipped installer.
//!
//! ## PRIVACY (consistent with the on-device / no-telemetry invariant)
//!
//! The update path is the **one** deliberate outbound network call besides the
//! local engine, and it is strictly limited to **public GitHub release metadata**
//! (`api.github.com` / `github.com` release assets). It sends **no** user data,
//! no prompts/responses, no usage counters, nothing about what you run through
//! Saffev — only an anonymous GET for the latest release version + the installer
//! script. The check is safe to run automatically on Studio load: it reveals
//! nothing about the user. See README "Nothing leaves the device".
//!
//! ## Fail-soft
//!
//! The *check* ([`check`]) never errors on a network failure — it returns an
//! [`UpdateStatus`] with `available = false` so the UI degrades quietly (offline,
//! GitHub down, rate-limited → "you're up to date / can't check right now",
//! never a crash). The *apply* ([`apply`]) does surface errors, because the
//! operator explicitly asked to update and wants to know if it failed.
//!
//! ## No-receipt case (dev / `cargo install` / `cargo build` binaries)
//!
//! A binary that was **not** installed via the cargo-dist installer has no
//! receipt. axoupdater returns [`axoupdater::AxoupdateError::NoReceipt`]; we map
//! that to [`UpdateError::NoReceipt`] and the callers print a clear, friendly
//! message ("updates are available for installs done via the installer") instead
//! of panicking. The current version is still reported so the UI stays useful.

use axoupdater::{AxoUpdater, AxoupdateError, ReleaseSource, ReleaseSourceType, Version};

/// The cargo-dist "app name" under which the install receipt is written. Matches
/// the binary/package name in `Cargo.toml` (`saffev`).
pub const APP_NAME: &str = "saffev";

/// GitHub `owner` for this repo's releases.
pub const REPO_OWNER: &str = "theoyinbooke";
/// GitHub `name` (repo) for this repo's releases.
pub const REPO_NAME: &str = "Saffev";

/// The compile-time version of *this* running binary (`CARGO_PKG_VERSION`).
pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Outcome of an update *check* — what the CLI prints and the Studio renders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateStatus {
    /// The version this binary currently is (compile-time `CARGO_PKG_VERSION`).
    pub current_version: String,
    /// The latest released version, if we could determine it. `None` when the
    /// check failed (offline / no receipt / GitHub unreachable) — the UI then
    /// shows "couldn't check" rather than a misleading "up to date".
    pub latest_version: Option<String>,
    /// Whether a newer release than [`current_version`](Self::current_version)
    /// is available. Always `false` when [`latest_version`](Self::latest_version)
    /// is `None` (fail-soft: we never claim an update we can't confirm).
    pub available: bool,
}

impl UpdateStatus {
    /// A fail-soft "couldn't determine" status: current known, latest unknown,
    /// nothing available. Used when there's no receipt or the network failed.
    fn unknown() -> Self {
        UpdateStatus {
            current_version: CURRENT_VERSION.to_string(),
            latest_version: None,
            available: false,
        }
    }
}

/// Result of an update *apply* — surfaced to the operator who asked for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyOutcome {
    /// Whether an update was actually installed (`false` = already current).
    pub updated: bool,
    /// The version installed (or the current version when already up to date).
    pub new_version: String,
}

/// Errors from the *apply* path (the check path is fail-soft and never errors).
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    /// This binary was not installed via the cargo-dist installer, so there is no
    /// install receipt to drive an in-place update. Build-from-source and
    /// `cargo install` binaries hit this — it is **not** a crash, just "use the
    /// installer for in-app updates". Carries the friendly guidance string.
    #[error("{0}")]
    NoReceipt(String),

    /// Any other failure while applying the update (download, installer exit,
    /// network). The message is safe to show the operator.
    #[error("{0}")]
    Failed(String),
}

/// The user-facing guidance shown when there's no install receipt. Single source
/// of truth so the CLI + Studio + tests stay in lockstep.
pub const NO_RECEIPT_MESSAGE: &str =
    "in-app updates are available for installs done via the installer; \
this looks like a dev or `cargo install` build — reinstall with the installer \
(see the README) to enable one-click updates";

/// Compare two semver-ish version strings: is `latest` strictly newer than
/// `current`? Falls back to a lexical compare if either fails to parse as
/// semver, so a malformed tag can never make us *claim* an update we shouldn't.
///
/// This is the deterministic core of the "is an update available?" decision and
/// is unit-tested without any network.
pub fn is_newer(current: &str, latest: &str) -> bool {
    let cur = normalize(current);
    let lat = normalize(latest);
    match (Version::parse(cur), Version::parse(lat)) {
        (Ok(c), Ok(l)) => l > c,
        // If we can't parse one side as semver, only treat it as "newer" when the
        // strings differ AND latest sorts strictly greater — conservative.
        _ => lat > cur && lat != cur,
    }
}

/// Strip a leading `v`/`V` from a tag-style version (`v0.2.0` -> `0.2.0`).
fn normalize(v: &str) -> &str {
    v.strip_prefix('v')
        .or_else(|| v.strip_prefix('V'))
        .unwrap_or(v)
}

/// The [`ReleaseSource`] for this repo's GitHub releases. Used to query the
/// latest version even before (or without) a receipt, so the check works for
/// dev builds too — only the *apply* truly needs the receipt.
fn release_source() -> ReleaseSource {
    ReleaseSource {
        release_type: ReleaseSourceType::GitHub,
        owner: REPO_OWNER.to_string(),
        name: REPO_NAME.to_string(),
        app_name: APP_NAME.to_string(),
    }
}

/// Build an [`AxoUpdater`] configured for this app, attempting to load the
/// install receipt. Returns `(updater, has_receipt)`. We always set the release
/// source + current version + name explicitly so the *check* works even with no
/// receipt; `has_receipt` tells the caller whether an in-place *apply* is
/// possible.
fn build_updater() -> (AxoUpdater, bool) {
    let mut updater = AxoUpdater::new_for(APP_NAME);
    // Try the receipt: on success this fills in source + current_version from the
    // real install. On NoReceipt (dev build) we proceed with explicit config.
    let has_receipt = updater.load_receipt_as(APP_NAME).is_ok();
    // Always pin the source + current version explicitly. For a real install this
    // matches the receipt; for a dev build it makes the *check* work anyway (only
    // apply truly needs the receipt).
    updater.set_release_source(release_source());
    let current = Version::parse(CURRENT_VERSION).unwrap_or_else(|_| Version::new(0, 0, 0));
    // `set_current_version` is fallible only in pathological cases; ignore the
    // (always-Ok here) Result so a future signature change can't crash us.
    let _ = updater.set_current_version(current);
    (updater, has_receipt)
}

/// Check whether a newer release is available. **Fail-soft**: any error (no
/// receipt, offline, GitHub unreachable, rate-limited) yields a status with
/// `available = false` rather than an `Err`, so the Studio can call this on every
/// load without risk. PRIVACY: contacts GitHub release metadata only.
pub async fn check() -> UpdateStatus {
    let (mut updater, _has_receipt) = build_updater();

    // Query the latest version. This is the single outbound metadata call.
    match updater.query_new_version().await {
        Ok(Some(latest)) => {
            let latest = latest.to_string();
            let available = is_newer(CURRENT_VERSION, &latest);
            UpdateStatus {
                current_version: CURRENT_VERSION.to_string(),
                latest_version: Some(latest),
                available,
            }
        }
        // No release found, or any error — degrade quietly to "couldn't check".
        Ok(None) | Err(_) => UpdateStatus::unknown(),
    }
}

/// Apply an available update by re-running the shipped installer. Requires the
/// install receipt (a real installer install); without it returns
/// [`UpdateError::NoReceipt`] so callers can show the friendly guidance. On
/// success returns the installed version; if already current, `updated = false`.
pub async fn apply() -> Result<ApplyOutcome, UpdateError> {
    let (mut updater, has_receipt) = build_updater();

    if !has_receipt {
        return Err(UpdateError::NoReceipt(NO_RECEIPT_MESSAGE.to_string()));
    }

    match updater.run().await {
        // An update was installed.
        Ok(Some(result)) => Ok(ApplyOutcome {
            updated: true,
            new_version: result.new_version.to_string(),
        }),
        // No update was needed — already current.
        Ok(None) => Ok(ApplyOutcome {
            updated: false,
            new_version: CURRENT_VERSION.to_string(),
        }),
        // Map a late-discovered NoReceipt to the friendly path; everything else
        // is a genuine apply failure the operator should see.
        Err(AxoupdateError::NoReceipt { .. }) => {
            Err(UpdateError::NoReceipt(NO_RECEIPT_MESSAGE.to_string()))
        }
        Err(e) => Err(UpdateError::Failed(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_newer_detects_upgrades() {
        assert!(is_newer("0.1.0", "0.2.0"));
        assert!(is_newer("0.1.0", "0.1.1"));
        assert!(is_newer("0.1.0", "1.0.0"));
        assert!(is_newer("1.2.3", "1.2.4"));
    }

    #[test]
    fn is_newer_rejects_same_or_older() {
        assert!(!is_newer("0.2.0", "0.2.0"));
        assert!(!is_newer("0.2.0", "0.1.0"));
        assert!(!is_newer("1.0.0", "0.9.9"));
        assert!(!is_newer("1.2.4", "1.2.3"));
    }

    #[test]
    fn is_newer_tolerates_v_prefix_on_either_side() {
        // GitHub tags are usually `vX.Y.Z`; CARGO_PKG_VERSION is bare.
        assert!(is_newer("0.1.0", "v0.2.0"));
        assert!(is_newer("v0.1.0", "0.2.0"));
        assert!(!is_newer("v0.2.0", "v0.2.0"));
        assert!(!is_newer("0.2.0", "v0.1.0"));
    }

    #[test]
    fn is_newer_handles_prerelease_ordering() {
        // semver: a prerelease is older than its release.
        assert!(is_newer("0.2.0-rc.1", "0.2.0"));
        assert!(!is_newer("0.2.0", "0.2.0-rc.1"));
    }

    #[test]
    fn is_newer_falls_back_lexically_for_nonsemver() {
        // Non-semver tags should never *spuriously* claim an update; equal stays
        // false, and only a strictly-greater string counts.
        assert!(!is_newer("nightly", "nightly"));
        assert!(is_newer("build-1", "build-2"));
    }

    #[test]
    fn unknown_status_is_failsoft() {
        let s = UpdateStatus::unknown();
        assert_eq!(s.current_version, CURRENT_VERSION);
        assert_eq!(s.latest_version, None);
        assert!(!s.available, "unknown latest must never claim available");
    }

    #[test]
    fn no_receipt_message_is_friendly_and_nonpanicking() {
        // The guidance must mention the installer so the user knows the fix.
        assert!(NO_RECEIPT_MESSAGE.contains("installer"));
        // And it must be an Error value, not a panic, when constructed.
        let e = UpdateError::NoReceipt(NO_RECEIPT_MESSAGE.to_string());
        assert!(e.to_string().contains("installer"));
    }

    #[test]
    fn current_version_matches_crate() {
        assert_eq!(CURRENT_VERSION, env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    async fn apply_without_receipt_is_graceful_not_panic() {
        // A `cargo test` binary was NOT installed via the cargo-dist installer,
        // so it has no install receipt. `apply()` must return the typed
        // NoReceipt error (with friendly guidance) BEFORE any network call —
        // never panic, never hang on the network. This is the no-receipt path
        // the CLI + Studio rely on.
        let result = super::apply().await;
        match result {
            Err(UpdateError::NoReceipt(msg)) => {
                assert!(msg.contains("installer"), "guidance must mention installer");
            }
            other => panic!("expected NoReceipt for a non-installed binary, got {other:?}"),
        }
    }

    #[test]
    fn release_source_points_at_this_repo() {
        let s = release_source();
        assert_eq!(s.owner, "theoyinbooke");
        assert_eq!(s.name, "Saffev");
        assert_eq!(s.app_name, "saffev");
        assert!(matches!(s.release_type, ReleaseSourceType::GitHub));
    }
}
