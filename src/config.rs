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
