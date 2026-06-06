//! Cooperative controller — compiles and runs on every OS (04 §5.3).
//!
//! No adoption, no engine management. The proxy listens on its own port; the
//! user points a client base URL at it; the proxy forwards to the engine on its
//! real port. This is the macOS default and the universal fallback.
//!
//! `adopt()` deliberately makes **zero** system changes and returns an empty
//! journal — there is nothing to revert. Detection and health reuse the probes
//! in [`super::detect`].

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::detect;
use crate::engine::{EngineController, EngineInfo, EngineKind, HealthState, JournalEntry};
use crate::Result;

/// The Cooperative-mode controller. Holds no platform state.
#[derive(Debug, Clone, Copy, Default)]
pub struct CooperativeController;

#[async_trait]
impl EngineController for CooperativeController {
    async fn detect(&self) -> Result<Vec<EngineInfo>> {
        detect::detect_all().await
    }

    fn can_adopt(&self) -> bool {
        false
    }

    async fn adopt(&self, _info: &EngineInfo) -> Result<Vec<JournalEntry>> {
        // Cooperative makes no system changes — empty journal.
        Ok(Vec::new())
    }

    async fn revert(&self, _journal: &[JournalEntry]) -> Result<()> {
        // Nothing was changed, so nothing to undo. Idempotent by construction.
        Ok(())
    }

    async fn health(&self, info: &EngineInfo) -> Result<HealthState> {
        Ok(probe_health(info.engine, info.port).await)
    }
}

/// Health probe shared by Cooperative + Supervisor: hit the engine's identifying
/// endpoint on `port` and map the outcome onto [`HealthState`].
pub(crate) async fn probe_health(kind: EngineKind, port: u16) -> HealthState {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(800))
        .connect_timeout(Duration::from_millis(500))
        .no_proxy()
        .build()
    {
        Ok(c) => c,
        Err(_) => return HealthState::Down,
    };

    let url = match kind {
        EngineKind::Ollama => format!("http://127.0.0.1:{port}/api/tags"),
        EngineKind::LmStudio => format!("http://127.0.0.1:{port}/v1/models"),
        // Unknown engine: a bare touch is the best we can do.
        EngineKind::Unknown => format!("http://127.0.0.1:{port}/"),
    };

    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => HealthState::Healthy,
        // A live server that answered non-2xx is up but not ready.
        Ok(_) => HealthState::Starting,
        Err(_) => HealthState::Down,
    }
}

/// Render the copy-paste base-URL snippet for a given client (curl, OpenAI SDK).
///
/// `client` is a free-form hint (`"curl"`, `"openai"`, `"python"`, `"ollama"`,
/// `"node"`/`"js"`, `"env"`); unknown hints fall back to a generic base-URL note.
/// `proxy_url` is the full base URL the user should target (e.g.
/// `http://127.0.0.1:11434`).
pub fn setup_snippet(client: &str, proxy_url: &str) -> String {
    let base = proxy_url.trim_end_matches('/');
    match client.trim().to_ascii_lowercase().as_str() {
        "curl" => format!(
            "curl {base}/v1/chat/completions \\\n  -H 'Content-Type: application/json' \\\n  -d '{{\"model\":\"<model>\",\"messages\":[{{\"role\":\"user\",\"content\":\"hello\"}}]}}'"
        ),
        "openai" | "python" => format!(
            "from openai import OpenAI\nclient = OpenAI(base_url=\"{base}/v1\", api_key=\"saffev\")"
        ),
        "node" | "js" | "javascript" | "typescript" => format!(
            "import OpenAI from \"openai\";\nconst client = new OpenAI({{ baseURL: \"{base}/v1\", apiKey: \"saffev\" }});"
        ),
        "ollama" => format!("export OLLAMA_HOST={base}"),
        "env" => format!("export OPENAI_BASE_URL={base}/v1\nexport OPENAI_API_KEY=saffev"),
        _ => format!("Point your client's base URL at: {base}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cooperative_cannot_adopt() {
        assert!(!CooperativeController.can_adopt());
    }

    #[tokio::test]
    async fn cooperative_adopt_is_empty_journal() {
        let info = EngineInfo {
            engine: EngineKind::Ollama,
            version: None,
            port: 11434,
            how_it_starts: crate::engine::StartMode::Manual,
            adoption_state: crate::store::AdoptionState::Detected,
        };
        let journal = CooperativeController.adopt(&info).await.unwrap();
        assert!(journal.is_empty(), "Cooperative adopt must change nothing");
    }

    #[tokio::test]
    async fn cooperative_revert_is_ok() {
        // Reverting (even a non-empty journal) is a no-op and must not error.
        let journal = vec![JournalEntry::DisabledAutostart {
            unit: "ollama.service".into(),
        }];
        assert!(CooperativeController.revert(&journal).await.is_ok());
    }

    #[test]
    fn snippet_curl_targets_v1() {
        let s = setup_snippet("curl", "http://127.0.0.1:11434/");
        assert!(s.contains("http://127.0.0.1:11434/v1/chat/completions"));
        // Trailing slash on the base URL must be normalized away.
        assert!(!s.contains("11434//v1"));
    }

    #[test]
    fn snippet_openai_sets_base_url() {
        let s = setup_snippet("openai", "http://127.0.0.1:11434");
        assert!(s.contains("base_url=\"http://127.0.0.1:11434/v1\""));
    }

    #[test]
    fn snippet_unknown_client_is_generic() {
        let s = setup_snippet("rubyonrails", "http://localhost:7000");
        assert!(s.contains("http://localhost:7000"));
        assert!(s.to_lowercase().contains("base url"));
    }

    #[tokio::test]
    async fn health_of_dead_port_is_down() {
        assert_eq!(probe_health(EngineKind::Ollama, 1).await, HealthState::Down);
    }
}
