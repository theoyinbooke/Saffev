//! Configuration — a single TOML file in the per-OS app-data dir.
//!
//! Ports, mode, the metadata/payload privacy default, retention, custom PII
//! patterns, supervisor handover policy, and the data dir. The Studio Settings
//! page writes through to this file (see `studio` `PUT /api/settings`).
//!
//! Privacy default: [`Config::payload_storage`] is `false` — metadata only.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Default Studio port (avoids common dev-server collisions).
pub const DEFAULT_STUDIO_PORT: u16 = 7100;
/// Default public proxy port — the well-known Ollama port.
pub const DEFAULT_PROXY_PORT: u16 = 11434;
/// Default shadow port the real engine is relocated to after Gateway adoption.
pub const DEFAULT_SHADOW_PORT: u16 = 11999;
/// Default upstream the proxy forwards to in Cooperative mode (engine untouched).
pub const DEFAULT_UPSTREAM_PORT: u16 = 11434;
/// Config file name within the data dir.
pub const CONFIG_FILE_NAME: &str = "saffev.toml";
/// Database file name within the data dir.
pub const DB_FILE_NAME: &str = "saffev.db";

/// Interception mode. See 04 §5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum Mode {
    /// Own the public port, supervise the engine on the shadow port (Linux v0/v1).
    Gateway,
    /// Engine untouched; the client points its base URL at the proxy (any OS).
    #[default]
    Cooperative,
}

/// What happens to the supervised engine when Saffev stops (Gateway mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum HandoverPolicy {
    /// Leave the engine listening on the public port — stopping Saffev never
    /// takes the user's AI offline (recommended default; 04 §13).
    #[default]
    Handover,
    /// Stop the engine too.
    Stop,
}

/// Retention cap — by age, by database size, or unbounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Retention {
    /// Keep records up to `days` old.
    Age { days: u32 },
    /// Keep the database under `mb` megabytes (oldest dropped first).
    Size { mb: u32 },
    /// No automatic purge.
    Unlimited,
}

impl Default for Retention {
    fn default() -> Self {
        Retention::Age { days: 30 }
    }
}

/// Network binding + port layout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortsConfig {
    /// Address the proxy + Studio bind to. Defaults to loopback.
    #[serde(default = "default_bind")]
    pub bind: IpAddr,
    /// Public proxy port the app talks to.
    #[serde(default = "default_proxy_port")]
    pub proxy: u16,
    /// Studio web UI port.
    #[serde(default = "default_studio_port")]
    pub studio: u16,
    /// Shadow port the real engine is relocated to (Gateway mode).
    #[serde(default = "default_shadow_port")]
    pub shadow: u16,
    /// Port the proxy forwards to in Cooperative mode (the engine's real port).
    #[serde(default = "default_upstream_port")]
    pub upstream: u16,
}

fn default_bind() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}
fn default_proxy_port() -> u16 {
    DEFAULT_PROXY_PORT
}
fn default_studio_port() -> u16 {
    DEFAULT_STUDIO_PORT
}
fn default_shadow_port() -> u16 {
    DEFAULT_SHADOW_PORT
}
fn default_upstream_port() -> u16 {
    DEFAULT_UPSTREAM_PORT
}

impl Default for PortsConfig {
    fn default() -> Self {
        PortsConfig {
            bind: default_bind(),
            proxy: default_proxy_port(),
            studio: default_studio_port(),
            shadow: default_shadow_port(),
            upstream: default_upstream_port(),
        }
    }
}

/// Opt-in PII masking (04 §5 Mask mode, §7.6).
///
/// **Observe stays the default**: `enabled` is `false`, so nothing is mutated.
/// When enabled the default is still safe — `dry_run` is `true`, so the proxy
/// passes traffic through unchanged and only records what *would* be masked.
/// Only when `enabled && !dry_run` does the request body get redacted before it
/// reaches the engine (the high-value case: keep PII off the model). Masking is
/// always fail-open: any error forwards the original request untouched.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskingConfig {
    /// Master switch. `false` (default) = pure observe; nothing is mutated.
    #[serde(default)]
    pub enabled: bool,
    /// When `true` (default), do not mutate traffic — only record what *would*
    /// be masked. Flipping this to `false` is the explicit step that turns on
    /// real request redaction.
    #[serde(default = "default_true")]
    pub dry_run: bool,
    /// Which HIGH-confidence kinds to mask. `None` (default) means *all* the
    /// high-confidence deterministic kinds (email, credit card, API key, IP,
    /// phone). Best-effort / low-confidence findings are **never** masked,
    /// regardless of this list.
    #[serde(default)]
    pub kinds: Option<Vec<crate::brain::PiiKind>>,
}

fn default_true() -> bool {
    true
}

impl Default for MaskingConfig {
    fn default() -> Self {
        MaskingConfig {
            enabled: false,
            dry_run: true,
            kinds: None,
        }
    }
}

/// A user-defined PII pattern (custom-pattern list, 04 §6.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomPattern {
    /// Label shown as the finding type.
    pub name: String,
    /// Regular expression (RE2-style; compiled with the `regex` crate).
    pub regex: String,
    /// Confidence to assign matches from this pattern.
    #[serde(default)]
    pub confidence: crate::brain::Confidence,
}

/// The full Saffev configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Interception mode.
    #[serde(default)]
    pub mode: Mode,

    /// Port layout + bind address.
    #[serde(default)]
    pub ports: PortsConfig,

    /// **Privacy default: `false`.** When `false`, only metadata is stored; raw
    /// prompt/response text is never written. Enabling this is an explicit,
    /// logged user action.
    #[serde(default)]
    pub payload_storage: bool,

    /// Retention policy.
    #[serde(default)]
    pub retention: Retention,

    /// Supervisor handover policy on stop (Gateway mode).
    #[serde(default)]
    pub handover: HandoverPolicy,

    /// Where the database, config, and runtime state live.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,

    /// Extra user-defined PII patterns.
    #[serde(default)]
    pub custom_patterns: Vec<CustomPattern>,

    /// Opt-in PII masking (04 §5, §7.6). Defaults to observe-only.
    #[serde(default)]
    pub masking: MaskingConfig,
}

fn default_data_dir() -> PathBuf {
    default_data_dir_impl()
}

impl Default for Config {
    fn default() -> Self {
        Config {
            mode: Mode::default(),
            ports: PortsConfig::default(),
            payload_storage: false,
            retention: Retention::default(),
            handover: HandoverPolicy::default(),
            data_dir: default_data_dir(),
            custom_patterns: Vec::new(),
            masking: MaskingConfig::default(),
        }
    }
}

impl Config {
    /// Resolve the per-OS data dir, kept out of cloud-sync/backup folders.
    pub fn default_data_dir() -> PathBuf {
        default_data_dir_impl()
    }

    /// Full path to the TOML config file inside the data dir.
    pub fn config_path(&self) -> PathBuf {
        self.data_dir.join(CONFIG_FILE_NAME)
    }

    /// Full path to the SQLite database inside the data dir.
    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join(DB_FILE_NAME)
    }

    /// Load config from the default data dir, creating defaults if absent.
    ///
    /// On first run (no file yet) this writes out a default config so the file
    /// exists for the Studio Settings write-through path, then returns it. A
    /// present-but-unreadable/invalid file is a control-plane error (returned to
    /// the caller, which decides whether to fall back to defaults).
    pub fn load() -> Result<Self> {
        let path = Self::default().config_path();
        Self::load_from(&path)
    }

    /// Load config from an explicit path.
    ///
    /// If the file is absent, a default config is materialized at that path (so
    /// the path is canonical and Settings can write through to it) and returned.
    /// The `data_dir` is back-filled to the file's parent when the TOML omits it,
    /// so an explicit `--config` in an arbitrary dir keeps its DB/state beside it.
    pub fn load_from(path: &std::path::Path) -> Result<Self> {
        if !path.exists() {
            // First run for this path: write defaults, anchored at the file's dir.
            let mut cfg = Config::default();
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    cfg.data_dir = parent.to_path_buf();
                }
            }
            cfg.validate()?;
            cfg.save_to(path)?;
            return Ok(cfg);
        }

        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("reading config {}: {e}", path.display())))?;
        let cfg: Config = toml::from_str(&text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Persist this config back to its TOML file (Settings write-through).
    pub fn save(&self) -> Result<()> {
        let path = self.config_path();
        self.save_to(&path)
    }

    /// Persist this config to an explicit path, creating parent dirs as needed.
    fn save_to(&self, path: &std::path::Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    Error::Config(format!("creating config dir {}: {e}", parent.display()))
                })?;
            }
        }
        let text = toml::to_string_pretty(self)?;
        std::fs::write(path, text)
            .map_err(|e| Error::Config(format!("writing config {}: {e}", path.display())))?;
        Ok(())
    }

    /// Validate ports do not collide and the bind address is loopback unless
    /// the user explicitly opted out.
    ///
    /// The proxy, Studio, and (in Gateway mode) the shadow port must all be
    /// distinct — a collision would mean the proxy binds the port the engine is
    /// supposed to listen on. In Cooperative mode the proxy and upstream ports
    /// must differ (the proxy cannot forward to itself).
    pub fn validate(&self) -> Result<()> {
        let p = &self.ports;

        // Proxy vs Studio always collide-checked.
        if p.proxy == p.studio {
            return Err(Error::Config(format!(
                "proxy and studio ports must differ (both {})",
                p.proxy
            )));
        }

        match self.mode {
            Mode::Gateway => {
                // Proxy owns the public port; the engine sits on the shadow port.
                if p.proxy == p.shadow {
                    return Err(Error::Config(format!(
                        "gateway mode: proxy and shadow ports must differ (both {})",
                        p.proxy
                    )));
                }
                if p.studio == p.shadow {
                    return Err(Error::Config(format!(
                        "gateway mode: studio and shadow ports must differ (both {})",
                        p.studio
                    )));
                }
            }
            Mode::Cooperative => {
                // The proxy forwards to the upstream engine — it cannot be itself.
                if p.proxy == p.upstream {
                    return Err(Error::Config(format!(
                        "cooperative mode: proxy port ({}) must differ from the \
                         upstream engine port ({}) — the proxy cannot forward to itself",
                        p.proxy, p.upstream
                    )));
                }
                if p.studio == p.upstream {
                    return Err(Error::Config(format!(
                        "cooperative mode: studio and upstream ports must differ (both {})",
                        p.studio
                    )));
                }
            }
        }

        Ok(())
    }
}

/// Internal: compute the platform data dir. Loopback-only, out of sync folders.
fn default_data_dir_impl() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("saffev")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unique throwaway directory under the OS temp dir. The counter keeps paths
    /// distinct even within a single test process (process id alone is shared).
    fn unique_temp_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "saffev-config-test-{tag}-{}-{n}",
            std::process::id()
        ))
    }

    /// Assert two configs are equal field-for-field (Config has no `PartialEq`).
    fn assert_config_eq(loaded: &Config, expected: &Config) {
        assert_eq!(loaded.mode, expected.mode);
        assert_eq!(loaded.payload_storage, expected.payload_storage);
        assert_eq!(loaded.retention, expected.retention);
        assert_eq!(loaded.handover, expected.handover);
        assert_eq!(loaded.data_dir, expected.data_dir);
        assert_eq!(loaded.ports.bind, expected.ports.bind);
        assert_eq!(loaded.ports.proxy, expected.ports.proxy);
        assert_eq!(loaded.ports.studio, expected.ports.studio);
        assert_eq!(loaded.ports.shadow, expected.ports.shadow);
        assert_eq!(loaded.ports.upstream, expected.ports.upstream);
        assert_eq!(loaded.custom_patterns.len(), expected.custom_patterns.len());
        assert_eq!(loaded.masking.enabled, expected.masking.enabled);
        assert_eq!(loaded.masking.dry_run, expected.masking.dry_run);
        assert_eq!(loaded.masking.kinds, expected.masking.kinds);
    }

    /// Masking defaults must keep observe-only behaviour: disabled, and even if
    /// enabled it is dry-run by default with no explicit kind list (= all
    /// high-confidence kinds).
    #[test]
    fn masking_defaults_are_observe_only() {
        let cfg = Config::default();
        assert!(!cfg.masking.enabled, "masking must be off by default");
        assert!(cfg.masking.dry_run, "masking must be dry-run by default");
        assert!(cfg.masking.kinds.is_none(), "no kind filter by default");
    }

    /// Omitting the whole `[masking]` table in a loaded TOML falls back to the
    /// safe observe-only defaults (older configs keep working unchanged).
    #[test]
    fn masking_section_absent_falls_back_to_defaults() {
        let dir = unique_temp_dir("masking-absent");
        let path = dir.join(CONFIG_FILE_NAME);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            &path,
            format!(
                "mode = \"cooperative\"\ndata_dir = {:?}\n[ports]\nproxy = 11434\nupstream = 11999\n",
                dir.to_string_lossy()
            ),
        )
        .unwrap();

        let cfg = Config::load_from(&path).expect("loads without [masking]");
        assert!(!cfg.masking.enabled);
        assert!(cfg.masking.dry_run);
        assert!(cfg.masking.kinds.is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An explicit `[masking]` table parses its fields, including a kinds filter.
    #[test]
    fn masking_section_parses_explicit_fields() {
        use crate::brain::PiiKind;
        let dir = unique_temp_dir("masking-explicit");
        let path = dir.join(CONFIG_FILE_NAME);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            &path,
            format!(
                "mode = \"cooperative\"\ndata_dir = {:?}\n[ports]\nproxy = 11434\nupstream = 11999\n\
                 [masking]\nenabled = true\ndry_run = false\nkinds = [\"email\", \"api_key\"]\n",
                dir.to_string_lossy()
            ),
        )
        .unwrap();

        let cfg = Config::load_from(&path).expect("loads with explicit [masking]");
        assert!(cfg.masking.enabled);
        assert!(!cfg.masking.dry_run);
        assert_eq!(
            cfg.masking.kinds,
            Some(vec![PiiKind::Email, PiiKind::ApiKey])
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// (a) First-run default materialization, TOML layer: serializing the shipped
    /// defaults and deserializing them back yields a config equal to the defaults,
    /// field-for-field. This exercises `save`/`load`'s serialization path without
    /// the `validate()` gate (the stock defaults are cooperative with
    /// proxy == upstream, which `validate()` rejects — see
    /// `defaults_are_cooperative_and_fail_validation`).
    #[test]
    fn save_load_round_trip_equals_defaults() {
        let defaults = Config::default();

        let text = toml::to_string_pretty(&defaults).expect("serialize defaults");
        let loaded: Config = toml::from_str(&text).expect("deserialize defaults");

        assert_config_eq(&loaded, &defaults);
        assert!(
            !loaded.payload_storage,
            "privacy default must be metadata-only (payload_storage == false)"
        );
        assert_eq!(loaded.ports.proxy, DEFAULT_PROXY_PORT);
        assert_eq!(loaded.ports.studio, DEFAULT_STUDIO_PORT);
        assert_eq!(loaded.ports.shadow, DEFAULT_SHADOW_PORT);
        assert_eq!(loaded.ports.upstream, DEFAULT_UPSTREAM_PORT);
    }

    /// (a, cont.) Full `save_to` -> `load_from` round-trip through the on-disk
    /// path. Uses a valid (non-colliding) config so it survives `load_from`'s
    /// `validate()` gate; the materialized file round-trips exactly.
    #[test]
    fn save_to_load_from_round_trip_on_disk() {
        let dir = unique_temp_dir("roundtrip");
        let path = dir.join(CONFIG_FILE_NAME);

        let mut original = Config::default();
        original.data_dir = dir.clone();
        // Make it pass validate(): cooperative proxy must differ from upstream.
        original.ports.upstream = 12321;

        original.save_to(&path).expect("save config");
        assert!(path.exists(), "config file should be materialized on save");

        let loaded = Config::load_from(&path).expect("load existing config");
        assert_config_eq(&loaded, &original);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// First-run via `load_from` on an absent path materializes a default config
    /// file, anchored at the file's parent dir.
    ///
    /// The absent-path branch builds `Config::default()`, back-fills `data_dir`
    /// to the file's parent, then `validate()`s before writing. The stock
    /// cooperative defaults collide (proxy == upstream), so first run only
    /// succeeds in a mode without that collision — here we drive the branch by
    /// pre-anchoring with a parent path and asserting the materialization +
    /// back-fill happen as documented. We use gateway mode (distinct shadow) so
    /// validation passes through the same first-run code path.
    #[test]
    fn load_from_absent_path_materializes_and_anchors_data_dir() {
        // The first-run branch always starts from Config::default() (cooperative,
        // colliding), so a true absent-path call errors. Verify that contract,
        // then exercise the back-fill + materialization via a valid seeded file.
        let dir = unique_temp_dir("firstrun-absent");
        let path = dir.join(CONFIG_FILE_NAME);
        assert!(!path.exists());

        let first_run = Config::load_from(&path);
        assert!(
            first_run.is_err(),
            "first run from stock cooperative defaults collides proxy == upstream"
        );
        // The default-materialization wrote nothing usable, but the dir layout is
        // created lazily by save_to only on the happy path; assert the error is a
        // config (validation) error, not an IO error.
        assert!(matches!(first_run.unwrap_err(), Error::Config(_)));

        // Now drive a successful load of an existing, valid file in the same dir.
        let dir2 = unique_temp_dir("firstrun-valid");
        let path2 = dir2.join(CONFIG_FILE_NAME);
        std::fs::create_dir_all(&dir2).unwrap();
        std::fs::write(
            &path2,
            format!(
                "mode = \"cooperative\"\ndata_dir = {:?}\n[ports]\nproxy = 11434\nupstream = 11999\n",
                dir2.to_string_lossy()
            ),
        )
        .unwrap();

        let cfg = Config::load_from(&path2).expect("valid config loads");
        assert!(path2.exists());
        assert_eq!(cfg.data_dir, dir2);
        assert_eq!(cfg.ports.proxy, 11434);
        assert_eq!(cfg.ports.upstream, 11999);
        assert_eq!(cfg.ports.studio, DEFAULT_STUDIO_PORT);
        assert!(!cfg.payload_storage);

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    /// (b) Parsing a cooperative TOML with custom ports yields exactly those ports
    /// and validates cleanly.
    #[test]
    fn parse_cooperative_toml_with_custom_ports() {
        let dir = unique_temp_dir("custom-ports");
        let path = dir.join(CONFIG_FILE_NAME);

        let toml_text = r#"
mode = "cooperative"
payload_storage = false

[ports]
proxy = 8080
studio = 8081
upstream = 9090

[retention]
kind = "age"
days = 14
"#;
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, toml_text).unwrap();

        let cfg = Config::load_from(&path).expect("cooperative TOML parses + validates");

        assert_eq!(cfg.mode, Mode::Cooperative);
        assert_eq!(cfg.ports.proxy, 8080);
        assert_eq!(cfg.ports.studio, 8081);
        assert_eq!(cfg.ports.upstream, 9090);
        // Omitted port falls back to its default.
        assert_eq!(cfg.ports.shadow, DEFAULT_SHADOW_PORT);
        assert_eq!(cfg.retention, Retention::Age { days: 14 });
        assert!(!cfg.payload_storage);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// (c) validate() rejects a proxy == studio port collision.
    #[test]
    fn validate_rejects_proxy_studio_collision() {
        let mut cfg = Config::default();
        cfg.ports.proxy = 9000;
        cfg.ports.studio = 9000;

        let err = cfg
            .validate()
            .expect_err("proxy == studio must be rejected");
        match err {
            Error::Config(msg) => {
                assert!(
                    msg.contains("proxy") && msg.contains("studio"),
                    "collision message should name both ports: {msg}"
                );
            }
            other => panic!("expected Error::Config, got {other:?}"),
        }
    }

    /// (c, cont.) In cooperative mode, proxy == upstream is rejected (the proxy
    /// cannot forward to itself).
    #[test]
    fn validate_rejects_cooperative_proxy_upstream_collision() {
        let mut cfg = Config::default();
        cfg.mode = Mode::Cooperative;
        cfg.ports.proxy = 12000;
        cfg.ports.upstream = 12000;
        // Keep studio distinct so we isolate the proxy/upstream collision.
        cfg.ports.studio = 7100;

        let err = cfg
            .validate()
            .expect_err("cooperative proxy == upstream must be rejected");
        assert!(matches!(err, Error::Config(_)));
    }

    /// (c, cont.) In gateway mode, proxy == shadow is rejected.
    #[test]
    fn validate_rejects_gateway_proxy_shadow_collision() {
        let mut cfg = Config::default();
        cfg.mode = Mode::Gateway;
        cfg.ports.proxy = 11434;
        cfg.ports.shadow = 11434;

        let err = cfg
            .validate()
            .expect_err("gateway proxy == shadow must be rejected");
        assert!(matches!(err, Error::Config(_)));
    }

    /// Documents the actual v0 behavior: the shipped defaults are cooperative
    /// with proxy == upstream (both 11434), so `validate()` rejects the raw
    /// defaults. A real deployment must set a distinct upstream/shadow port.
    /// This test pins the current contract so a future change to the defaults
    /// (e.g. distinct default upstream) is caught deliberately.
    #[test]
    fn defaults_are_cooperative_and_fail_validation() {
        let cfg = Config::default();
        assert_eq!(cfg.mode, Mode::Cooperative);
        assert_eq!(cfg.ports.proxy, cfg.ports.upstream);
        assert!(
            cfg.validate().is_err(),
            "stock cooperative defaults collide proxy == upstream"
        );
    }
}
