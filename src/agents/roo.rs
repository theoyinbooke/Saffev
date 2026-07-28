//! Roo Code adapter — reads VS Code globalStorage
//! `rooveterinaryinc.roo-cline/tasks/<taskId>/`.
//!
//! Roo Code is a Cline fork; format verified against RooCodeInc/Roo-Code at
//! tag v3.54.0 (G2 round 11). The transcript files are shared heritage —
//! `api_conversation_history.json` (Anthropic-style blocks + `ts`) and
//! `ui_messages.json` (`api_req_started` JSON-in-text token payloads) parse
//! with the Cline machinery — but three things diverge and matter:
//!
//! * **History lives per task** (since v3.49): `tasks/<id>/history_item.json`
//!   is authoritative (plus a `tasks/_index.json` cache this adapter does
//!   not need). The item's project field is `workspace`, not Cline's
//!   `cwdOnTaskInitialization`.
//! * **`tokensIn` is TOTAL input INCLUDING cache tokens** (Roo's own
//!   `consolidateTokenUsage` documents this) — the opposite of Cline —
//!   so non-cached input = tokensIn − (cacheWrites + cacheReads).
//! * **The model id is NOT persisted per task.** HistoryItem carries only
//!   `apiConfigName` (a mutable profile name whose contents live in VS Code
//!   secrets) and ui messages carry only an `apiProtocol` hint. The model
//!   field is honestly absent — never guessed from a profile name.
//!
//! Tolerant like the Cline reader: a corrupt transcript still lists from
//! its history item; bad files are skipped, never fatal.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::cline::ClineReader;
use super::{home, AgentReader, AgentSession, AgentSessionDetail, AgentTool};

/// Reads Roo Code's task stores from every VS Code flavor's globalStorage.
pub struct RooReader {
    /// `…/globalStorage/rooveterinaryinc.roo-cline` roots (+ nightly).
    roots: Vec<PathBuf>,
}

impl RooReader {
    /// Fixture seam: read explicit extension-storage roots. See
    /// `tests/agents_bench.rs`.
    pub fn with_roots(roots: Vec<PathBuf>) -> Self {
        Self { roots }
    }

    /// Platform globalStorage paths for Code / Insiders / VSCodium, for both
    /// the stable and nightly extension ids.
    pub fn new() -> Self {
        let flavors = ["Code", "Code - Insiders", "VSCodium"];
        let exts = [
            "rooveterinaryinc.roo-cline",
            "rooveterinaryinc.roo-code-nightly",
        ];
        let bases: Vec<PathBuf> = if cfg!(target_os = "macos") {
            let app = home().join("Library/Application Support");
            flavors.iter().map(|f| app.join(f)).collect()
        } else if cfg!(target_os = "windows") {
            let app = std::env::var_os("APPDATA")
                .map(PathBuf::from)
                .unwrap_or_else(|| home().join("AppData/Roaming"));
            flavors.iter().map(|f| app.join(f)).collect()
        } else {
            let cfg = home().join(".config");
            flavors.iter().map(|f| cfg.join(f)).collect()
        };
        let roots = bases
            .into_iter()
            .flat_map(|b| {
                exts.iter()
                    .map(move |e| b.join("User/globalStorage").join(e))
            })
            .filter(|p| p.is_dir())
            .collect();
        Self { roots }
    }

    /// Read one task's `history_item.json`. Returns
    /// `(ts, task, non_cached_in, out, cache, workspace)`.
    #[allow(clippy::type_complexity)]
    fn history_item(
        task_dir: &Path,
    ) -> Option<(i64, Option<String>, u64, u64, u64, u64, Option<String>)> {
        let text = fs::read_to_string(task_dir.join("history_item.json")).ok()?;
        let v: Value = serde_json::from_str(&text).ok()?;
        let cache_w = v.get("cacheWrites").and_then(Value::as_u64).unwrap_or(0);
        let cache = cache_w + v.get("cacheReads").and_then(Value::as_u64).unwrap_or(0);
        // Roo convention: tokensIn INCLUDES cache tokens — subtract, or the
        // cached portion is counted (and priced) twice.
        let total_in = v.get("tokensIn").and_then(Value::as_u64).unwrap_or(0);
        Some((
            v.get("ts").and_then(Value::as_i64).unwrap_or(0),
            v.get("task")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(String::from),
            total_in.saturating_sub(cache),
            v.get("tokensOut").and_then(Value::as_u64).unwrap_or(0),
            cache,
            cache_w,
            v.get("workspace").and_then(Value::as_str).map(String::from),
        ))
    }

    fn tasks(root: &Path) -> Vec<String> {
        let mut out = Vec::new();
        let Ok(dirs) = fs::read_dir(root.join("tasks")) else {
            return out;
        };
        for d in dirs.flatten() {
            if d.path().is_dir() {
                out.push(d.file_name().to_string_lossy().to_string());
            }
        }
        out
    }

    fn build(root: &Path, task_id: &str, with_messages: bool) -> Option<AgentSessionDetail> {
        let task_dir = root.join("tasks").join(task_id);
        let (messages, msg_count, tool_count, _tmodel, tlast, tfirst) =
            ClineReader::transcript(&task_dir, with_messages);
        let (ui_title, ui_in_total, ui_out, ui_cache, ui_cache_w, ui_last) =
            ClineReader::ui_fallback(&task_dir);
        let item = Self::history_item(&task_dir);
        if msg_count == 0 && item.is_none() && ui_title.is_none() {
            return None;
        }
        let (hist_ts, hist_task, hist_in, hist_out, hist_cache, hist_cache_w, workspace) =
            item.unwrap_or((0, None, 0, 0, 0, 0, None));
        let (inp, outp, cache, cache_w) = if hist_in + hist_out + hist_cache > 0 {
            (hist_in, hist_out, hist_cache, hist_cache_w)
        } else {
            // Same total-includes-cache convention in the ui payloads.
            (
                ui_in_total.saturating_sub(ui_cache),
                ui_out,
                ui_cache,
                ui_cache_w,
            )
        };
        // Roo task dirs are uuidv7 in current versions (epoch-ms names are
        // Cline heritage) — the id carries no start time, so the first
        // turn's timestamp is the honest start (G2 closing critic).
        let started_ts = task_id.parse::<i64>().unwrap_or(tfirst);
        let updated_ts = hist_ts.max(tlast).max(ui_last).max(started_ts);
        let title = hist_task
            .or(ui_title)
            .map(|t| super::claude_code::truncate(&t, 80));
        let session = AgentSession {
            id: AgentSession::make_id(AgentTool::Roo, task_id),
            tool: AgentTool::Roo,
            title,
            project: workspace,
            git_branch: None,
            // The model id is not persisted per task (only a mutable profile
            // name) — honestly absent, never guessed.
            model: None,
            started_ts,
            updated_ts,
            message_count: msg_count,
            tool_call_count: tool_count,
            input_tokens: inp,
            output_tokens: outp,
            cache_tokens: cache,
            cache_write_tokens: cache_w,
            source_path: task_dir.to_string_lossy().to_string(),
        };
        Some(AgentSessionDetail { session, messages })
    }
}

impl Default for RooReader {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentReader for RooReader {
    fn tool(&self) -> AgentTool {
        AgentTool::Roo
    }
    fn is_present(&self) -> bool {
        self.roots.iter().any(|r| r.join("tasks").is_dir())
    }
    fn list_sessions(&self) -> Vec<AgentSession> {
        let mut out = Vec::new();
        for root in &self.roots {
            for task_id in Self::tasks(root) {
                if task_id.starts_with('_') {
                    continue; // tasks/_index.json cache, not a task dir
                }
                if let Some(d) = Self::build(root, &task_id, false) {
                    out.push(d.session);
                }
            }
        }
        out
    }
    fn retention(&self) -> super::retention::RetentionPolicy {
        super::retention::RetentionPolicy::keeps_all(
            "Tasks persist under VS Code globalStorage until deleted in Roo's UI.",
        )
    }
    fn source_fingerprint(&self) -> Option<u64> {
        let mut files = Vec::new();
        for root in &self.roots {
            for t in Self::tasks(root) {
                let dir = root.join("tasks").join(&t);
                files.push(dir.join("history_item.json"));
                files.push(dir.join("api_conversation_history.json"));
                files.push(dir.join("ui_messages.json"));
            }
        }
        Some(super::hash_files(files.into_iter()))
    }
    fn session_detail(&self, raw_id: &str) -> Option<AgentSessionDetail> {
        for root in &self.roots {
            if root.join("tasks").join(raw_id).is_dir() {
                return Self::build(root, raw_id, true);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roo_subtracts_cache_from_total_tokens_in() {
        let dir = std::env::temp_dir().join(format!("saffev-roo-{}", uuid::Uuid::new_v4()));
        let root = dir.join("rooveterinaryinc.roo-cline");
        let task = root.join("tasks/1748899000000");
        std::fs::create_dir_all(&task).unwrap();
        std::fs::write(
            task.join("history_item.json"),
            r#"{"id":"1748899000000","number":1,"ts":1748899123456,"task":"fix the bug","tokensIn":5230,"tokensOut":812,"cacheWrites":4100,"cacheReads":900,"totalCost":0.0342,"workspace":"/home/dev/p","mode":"code","apiConfigName":"default"}"#,
        )
        .unwrap();
        std::fs::write(
            task.join("api_conversation_history.json"),
            r#"[{"role":"user","content":[{"type":"text","text":"<task>fix the bug</task>"}],"ts":1748899000100},{"role":"assistant","content":[{"type":"text","text":"done"}],"ts":1748899005000}]"#,
        )
        .unwrap();
        let reader = RooReader::with_roots(vec![root]);
        let sessions = reader.list_sessions();
        assert_eq!(sessions.len(), 1);
        let s = &sessions[0];
        // tokensIn (5230) INCLUDES cache (5000) — non-cached input is 230.
        assert_eq!(s.input_tokens, 230);
        assert_eq!(s.cache_tokens, 5000);
        assert_eq!(s.output_tokens, 812);
        assert_eq!(s.project.as_deref(), Some("/home/dev/p"));
        assert!(s.model.is_none(), "Roo does not persist the model — never guess");
        std::fs::remove_dir_all(&dir).ok();
    }
}
