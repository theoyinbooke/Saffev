//! Zero-config capture — the environment variables that route a client's LLM
//! traffic *through the Saffev proxy* instead of straight at the engine.
//!
//! This is what powers `saffev run` / `saffev env` / `saffev shell`: instead of
//! asking the user to hand-edit every app's base URL (the step people miss), we
//! inject the base-URL env vars the common SDKs already read.
//!
//! **Engine-agnostic by design.** Ollama clients read the `OLLAMA_*` vars;
//! OpenAI-compatible clients — including **LM Studio** — read the `OPENAI_*`
//! vars. Setting all of them at once is safe: each client ignores the vars it
//! doesn't use, so the same command traces either engine with no per-engine
//! branching.

use crate::config::Config;

/// The routing environment variables that point a child process at the proxy.
///
/// Note the deliberate asymmetry: the Ollama vars take the **bare** base
/// (`http://host:proxy`) while the OpenAI vars take the `/v1` base
/// (`http://host:proxy/v1`).
pub fn capture_env(cfg: &Config) -> Vec<(String, String)> {
    let base = cfg.proxy_base_url(); // http://host:proxy
    let openai = cfg.openai_base_url(); // http://host:proxy/v1
    vec![
        // Ollama SDKs / CLI (accept a full URL).
        ("OLLAMA_HOST".to_string(), base.clone()),
        ("OLLAMA_BASE_URL".to_string(), base),
        // OpenAI SDKs pointed at a local engine (LM Studio, or Ollama's /v1).
        ("OPENAI_BASE_URL".to_string(), openai.clone()),
        // Legacy openai-python (<1.0) reads OPENAI_API_BASE.
        ("OPENAI_API_BASE".to_string(), openai),
    ]
}

/// Placeholder OpenAI API key. Local engines don't authenticate, but the OpenAI
/// SDK refuses to construct a client without *some* key — so `run`/`shell` set
/// this in the child env only when the user hasn't already set one.
pub const PLACEHOLDER_OPENAI_KEY: &str = "local";

/// Which shell dialect to format `saffev env` output for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvFormat {
    /// POSIX shells (bash/zsh/sh): `export VAR="value"`.
    Posix,
    /// fish: `set -gx VAR "value"`.
    Fish,
    /// PowerShell: `$env:VAR = "value"`.
    PowerShell,
}

impl EnvFormat {
    /// Best-effort detection from `$SHELL` (POSIX default). Windows callers pass
    /// [`EnvFormat::PowerShell`] explicitly.
    pub fn detect() -> Self {
        match std::env::var("SHELL") {
            Ok(s) if s.contains("fish") => EnvFormat::Fish,
            _ => EnvFormat::Posix,
        }
    }

    /// Parse an explicit `--shell` value.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "posix" | "bash" | "zsh" | "sh" => Some(EnvFormat::Posix),
            "fish" => Some(EnvFormat::Fish),
            "powershell" | "pwsh" | "ps" => Some(EnvFormat::PowerShell),
            _ => None,
        }
    }
}

/// Render the capture env as shell-appropriate export lines, suitable for
/// `eval "$(saffev env)"`. A trailing comment reminds OpenAI-SDK users that a
/// (placeholder) API key is required.
pub fn render_env(cfg: &Config, fmt: EnvFormat) -> String {
    let vars = capture_env(cfg);
    let mut out = String::new();
    for (k, v) in &vars {
        let line = match fmt {
            EnvFormat::Posix => format!("export {k}=\"{v}\"\n"),
            EnvFormat::Fish => format!("set -gx {k} \"{v}\"\n"),
            EnvFormat::PowerShell => format!("$env:{k} = \"{v}\"\n"),
        };
        out.push_str(&line);
    }
    let comment = match fmt {
        EnvFormat::PowerShell => {
            "# OpenAI SDK clients also need $env:OPENAI_API_KEY set (any value works locally).\n"
        }
        _ => "# OpenAI SDK clients also need OPENAI_API_KEY set (any value works locally).\n",
    };
    out.push_str(comment);
    out
}

/// Render the capture env as a JSON object of `{ "VAR": "value", ... }`.
pub fn render_env_json(cfg: &Config) -> String {
    let vars = capture_env(cfg);
    let map: serde_json::Map<String, serde_json::Value> = vars
        .into_iter()
        .map(|(k, v)| (k, serde_json::Value::String(v)))
        .collect();
    serde_json::to_string_pretty(&serde_json::Value::Object(map))
        .unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn cfg_with_ports(proxy: u16, studio: u16) -> Config {
        let mut c = Config::default();
        c.ports.proxy = proxy;
        c.ports.studio = studio;
        c
    }

    #[test]
    fn capture_env_has_the_four_routing_vars_with_v1_asymmetry() {
        let cfg = cfg_with_ports(8088, 7100);
        let vars = capture_env(&cfg);
        let get = |k: &str| {
            vars.iter()
                .find(|(vk, _)| vk == k)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        assert_eq!(get("OLLAMA_HOST"), "http://localhost:8088");
        assert_eq!(get("OLLAMA_BASE_URL"), "http://localhost:8088");
        // OpenAI vars MUST carry the /v1 suffix; Ollama vars MUST NOT.
        assert_eq!(get("OPENAI_BASE_URL"), "http://localhost:8088/v1");
        assert_eq!(get("OPENAI_API_BASE"), "http://localhost:8088/v1");
        assert_eq!(vars.len(), 4);
    }

    #[test]
    fn render_env_posix_uses_export() {
        let cfg = cfg_with_ports(8088, 7100);
        let s = render_env(&cfg, EnvFormat::Posix);
        assert!(s.contains("export OLLAMA_HOST=\"http://localhost:8088\""));
        assert!(s.contains("export OPENAI_BASE_URL=\"http://localhost:8088/v1\""));
        assert!(s.contains("OPENAI_API_KEY"));
    }

    #[test]
    fn render_env_fish_uses_set_gx() {
        let cfg = cfg_with_ports(8088, 7100);
        let s = render_env(&cfg, EnvFormat::Fish);
        assert!(s.contains("set -gx OLLAMA_HOST \"http://localhost:8088\""));
    }

    #[test]
    fn render_env_powershell_uses_env_prefix() {
        let cfg = cfg_with_ports(8088, 7100);
        let s = render_env(&cfg, EnvFormat::PowerShell);
        assert!(s.contains("$env:OPENAI_BASE_URL = \"http://localhost:8088/v1\""));
    }

    #[test]
    fn env_format_parse_and_detect() {
        assert_eq!(EnvFormat::parse("bash"), Some(EnvFormat::Posix));
        assert_eq!(EnvFormat::parse("fish"), Some(EnvFormat::Fish));
        assert_eq!(EnvFormat::parse("powershell"), Some(EnvFormat::PowerShell));
        assert_eq!(EnvFormat::parse("nonsense"), None);
    }

    #[test]
    fn render_env_json_is_object_of_strings() {
        let cfg = cfg_with_ports(8088, 7100);
        let s = render_env_json(&cfg);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["OPENAI_BASE_URL"], "http://localhost:8088/v1");
        assert_eq!(v["OLLAMA_HOST"], "http://localhost:8088");
    }
}
