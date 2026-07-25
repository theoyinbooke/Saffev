//! Shared team policy — the honest half of "team mode".
//!
//! A team wants to agree on what must never be sent to a model. The usual answer
//! is a hosted control plane with accounts and sync, which would cost Saffev the
//! one claim nobody else can make: that nothing leaves your machine. So this is
//! the version that does not need a server.
//!
//! A policy is **a TOML file you commit to your own repo**. A lead writes it,
//! everyone points their Saffev at it, and every install honors the same rules
//! locally. No accounts, no sync, no telemetry, no way for anyone to see whether
//! you complied — because that would require reporting, and reporting means
//! shipping your activity somewhere.
//!
//! ## What a policy may set
//! Only the protective settings: masking posture, which kinds are blocked
//! outright, and shared custom patterns. It deliberately cannot set ports, data
//! directories, retention, or anything that would let a file in a repo reconfigure
//! someone's machine.
//!
//! ## Precedence
//! The policy **wins** over local settings for the fields it specifies. That is
//! the point: a rule an individual can silently switch off is not a policy. Fields
//! the policy leaves out stay under local control.
//!
//! ## When it cannot be loaded
//! A missing or invalid policy never blocks startup or traffic (fail-open still
//! governs), but it must never fail *silently* either — a protection policy that
//! quietly did not apply is worse than no policy, because everyone believes they
//! are covered. So the failure is recorded and surfaced in `status` and the
//! Studio rather than swallowed.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::brain::PiiKind;
use crate::config::{Config, CustomPattern};

/// The masking posture a policy may impose. Every field is optional: a policy
/// states only what it cares about.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyMasking {
    /// Force masking on (or off).
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Force dry-run on (or off). `false` is what makes protection real.
    #[serde(default)]
    pub dry_run: Option<bool>,
    /// Which kinds to mask. Omit for all high-confidence kinds.
    #[serde(default)]
    pub kinds: Option<Vec<PiiKind>>,
    /// Kinds that stop a request outright.
    #[serde(default)]
    pub block_kinds: Option<Vec<PiiKind>>,
}

/// A team policy file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Policy {
    /// Schema version, so a future format change can be detected rather than
    /// silently misread.
    #[serde(default)]
    pub version: Option<u32>,
    /// Human description, shown in the UI so people know which policy is active.
    #[serde(default)]
    pub description: Option<String>,
    /// Masking posture.
    #[serde(default)]
    pub masking: PolicyMasking,
    /// Shared custom PII patterns, appended to whatever the user has locally.
    #[serde(default)]
    pub custom_patterns: Vec<CustomPattern>,
}

/// The schema version this build understands.
pub const SUPPORTED_VERSION: u32 = 1;

/// What happened when we tried to apply a policy. Surfaced verbatim to the user;
/// never swallowed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyStatus {
    /// Where the policy was read from.
    pub path: String,
    /// Whether it loaded and applied.
    pub active: bool,
    /// Description from the file, if it had one.
    pub description: Option<String>,
    /// Plain-language reason when `active` is false.
    pub error: Option<String>,
    /// Which settings the policy is governing, for the UI to mark as locked.
    pub governs: Vec<String>,
}

impl Policy {
    /// Read a policy from disk.
    pub fn load(path: &Path) -> crate::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| crate::Error::Config(format!("reading policy {}: {e}", path.display())))?;
        let policy: Policy = toml::from_str(&text)
            .map_err(|e| crate::Error::Config(format!("parsing policy {}: {e}", path.display())))?;

        if let Some(v) = policy.version {
            if v > SUPPORTED_VERSION {
                return Err(crate::Error::Config(format!(
                    "policy {} declares version {v}, but this build understands up to \
                     {SUPPORTED_VERSION} — upgrade Saffev rather than running a policy it \
                     may misread",
                    path.display()
                )));
            }
        }

        // A pattern that will not compile would silently protect nothing, so it
        // is a policy error, not something to discover later.
        for p in &policy.custom_patterns {
            regex::Regex::new(&p.regex).map_err(|e| {
                crate::Error::Config(format!(
                    "policy {} has an invalid pattern {:?}: {e}",
                    path.display(),
                    p.name
                ))
            })?;
        }

        Ok(policy)
    }

    /// Apply this policy over `cfg`, returning the list of settings it governs.
    pub fn apply(&self, cfg: &mut Config) -> Vec<String> {
        let mut governs = Vec::new();

        if let Some(v) = self.masking.enabled {
            cfg.masking.enabled = v;
            governs.push("masking.enabled".into());
        }
        if let Some(v) = self.masking.dry_run {
            cfg.masking.dry_run = v;
            governs.push("masking.dry_run".into());
        }
        if let Some(v) = &self.masking.kinds {
            cfg.masking.kinds = Some(v.clone());
            governs.push("masking.kinds".into());
        }
        if let Some(v) = &self.masking.block_kinds {
            cfg.masking.block_kinds = v.clone();
            governs.push("masking.block_kinds".into());
        }
        if !self.custom_patterns.is_empty() {
            // Appended, not replaced: a team policy adds shared patterns without
            // deleting the ones an individual added for their own work.
            let existing: std::collections::HashSet<&str> = cfg
                .custom_patterns
                .iter()
                .map(|p| p.name.as_str())
                .collect();
            let mut added: Vec<CustomPattern> = self
                .custom_patterns
                .iter()
                .filter(|p| !existing.contains(p.name.as_str()))
                .cloned()
                .collect();
            if !added.is_empty() {
                cfg.custom_patterns.append(&mut added);
                governs.push("custom_patterns".into());
            }
        }

        governs
    }
}

/// Load and apply the configured policy, if any, returning what happened.
///
/// Returns `None` when no policy is configured — the default, and the case for
/// everyone not working in a team.
pub fn apply_configured(cfg: &mut Config) -> Option<PolicyStatus> {
    let path: PathBuf = expand_home(cfg.policy_file.as_ref()?);
    let path_str = path.display().to_string();

    match Policy::load(&path) {
        Ok(policy) => {
            let description = policy.description.clone();
            let governs = policy.apply(cfg);
            tracing::info!(
                target: "saffev::policy",
                path = %path_str,
                governs = ?governs,
                "team policy applied"
            );
            Some(PolicyStatus {
                path: path_str,
                active: true,
                description,
                error: None,
                governs,
            })
        }
        Err(e) => {
            // Loud, not silent. Someone believes they are covered by this file.
            tracing::error!(
                target: "saffev::policy",
                path = %path_str,
                "team policy NOT applied: {e}"
            );
            Some(PolicyStatus {
                path: path_str,
                active: false,
                description: None,
                error: Some(e.to_string()),
                governs: Vec::new(),
            })
        }
    }
}

/// Process-wide record of the policy applied at startup, so the CLI and the
/// Studio both report the same thing without threading it through every struct.
fn active_status() -> &'static std::sync::Mutex<Option<PolicyStatus>> {
    static S: std::sync::OnceLock<std::sync::Mutex<Option<PolicyStatus>>> =
        std::sync::OnceLock::new();
    S.get_or_init(|| std::sync::Mutex::new(None))
}

/// Apply the configured policy and remember the outcome for later reporting.
/// Call once, during startup, before the config handle is shared.
pub fn apply_and_record(cfg: &mut Config) -> Option<PolicyStatus> {
    let status = apply_configured(cfg);
    if let Ok(mut slot) = active_status().lock() {
        *slot = status.clone();
    }
    status
}

/// The policy applied at startup, if any.
pub fn current() -> Option<PolicyStatus> {
    active_status().lock().ok().and_then(|s| s.clone())
}

/// Is this setting currently governed by a policy? Used to refuse a Studio edit
/// that would silently undo a team rule.
pub fn governs(setting: &str) -> bool {
    current()
        .map(|s| s.active && s.governs.iter().any(|g| g == setting))
        .unwrap_or(false)
}

/// Expand a leading `~` so a policy path can be written portably in a config that
/// is itself shared between machines.
fn expand_home(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/") {
        return crate::agents::home().join(rest);
    }
    p.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(body: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("saffev-pol-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("saffev-policy.toml");
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn a_policy_overrides_local_settings() {
        let p = write(
            r#"
version = 1
description = "Acme engineering"

[masking]
enabled = true
dry_run = false
block_kinds = ["api_key"]
"#,
        );
        let policy = Policy::load(&p).unwrap();

        // Someone's local config has protection off — the default.
        let mut cfg = Config::default();
        assert!(!cfg.masking.enabled);
        assert!(cfg.masking.dry_run);
        assert!(cfg.masking.block_kinds.is_empty());

        let governs = policy.apply(&mut cfg);

        // The policy wins. A rule an individual can silently switch off is not a
        // policy.
        assert!(cfg.masking.enabled);
        assert!(!cfg.masking.dry_run);
        assert_eq!(cfg.masking.block_kinds, vec![PiiKind::ApiKey]);
        assert!(governs.contains(&"masking.enabled".to_string()));
        assert!(governs.contains(&"masking.block_kinds".to_string()));

        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn a_policy_only_governs_what_it_states() {
        let p = write("[masking]\nblock_kinds = [\"credit_card\"]\n");
        let policy = Policy::load(&p).unwrap();

        let mut cfg = Config::default();
        cfg.masking.enabled = true;
        cfg.masking.dry_run = true;

        let governs = policy.apply(&mut cfg);

        // Untouched fields stay under local control.
        assert!(cfg.masking.enabled);
        assert!(cfg.masking.dry_run);
        assert_eq!(governs, vec!["masking.block_kinds".to_string()]);

        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn shared_patterns_are_added_without_deleting_personal_ones() {
        let p = write(
            r#"
[[custom_patterns]]
name = "Employee ID"
regex = "EMP-[0-9]{6}"
"#,
        );
        let policy = Policy::load(&p).unwrap();

        let mut cfg = Config::default();
        cfg.custom_patterns = vec![CustomPattern {
            name: "My ticket ids".into(),
            regex: "TCK-[0-9]+".into(),
            confidence: Default::default(),
        }];

        policy.apply(&mut cfg);

        assert_eq!(cfg.custom_patterns.len(), 2);
        assert!(cfg
            .custom_patterns
            .iter()
            .any(|p| p.name == "My ticket ids"));
        assert!(cfg.custom_patterns.iter().any(|p| p.name == "Employee ID"));

        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn applying_twice_does_not_duplicate_patterns() {
        let p = write("[[custom_patterns]]\nname = \"X\"\nregex = \"x+\"\n");
        let policy = Policy::load(&p).unwrap();
        let mut cfg = Config::default();
        policy.apply(&mut cfg);
        policy.apply(&mut cfg);
        assert_eq!(cfg.custom_patterns.len(), 1);
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn an_invalid_pattern_is_a_policy_error_not_a_silent_no_op() {
        let p = write("[[custom_patterns]]\nname = \"bad\"\nregex = \"([unclosed\"\n");
        let err = Policy::load(&p).unwrap_err().to_string();
        assert!(err.contains("bad"), "{err}");
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn a_future_version_is_refused_rather_than_guessed_at() {
        let p = write("version = 999\n");
        let err = Policy::load(&p).unwrap_err().to_string();
        assert!(err.contains("999"), "{err}");
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn a_broken_policy_reports_loudly_instead_of_applying_nothing_quietly() {
        let p = write("this is not = valid toml [[[");
        let mut cfg = Config::default();
        cfg.policy_file = Some(p.clone());

        let status = apply_configured(&mut cfg).expect("a configured policy always reports");
        assert!(!status.active);
        assert!(status.error.is_some());
        assert!(status.governs.is_empty());
        // Traffic settings are untouched, so nothing breaks — but the user is told.
        assert!(!cfg.masking.enabled);

        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn a_missing_policy_file_reports_rather_than_silently_passing() {
        let mut cfg = Config::default();
        cfg.policy_file = Some(PathBuf::from("/nope/does-not-exist.toml"));
        let status = apply_configured(&mut cfg).expect("configured but missing must report");
        assert!(!status.active);
        assert!(status.error.is_some());
    }

    #[test]
    fn no_policy_configured_is_the_quiet_default() {
        let mut cfg = Config::default();
        assert!(apply_configured(&mut cfg).is_none());
    }

    #[test]
    fn home_relative_paths_expand() {
        let expanded = expand_home(Path::new("~/team/saffev-policy.toml"));
        assert!(expanded.is_absolute());
        assert!(!expanded.to_string_lossy().starts_with('~'));
        // A plain path is left exactly as-is.
        assert_eq!(
            expand_home(Path::new("/etc/saffev-policy.toml")),
            PathBuf::from("/etc/saffev-policy.toml")
        );
    }
}
