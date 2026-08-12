//! Export a normalized session to open, portable formats (Markdown / JSON).
//!
//! Ownership is the point: the user can walk away from Saffev with a complete,
//! readable copy of their AI history. Works on the live [`AgentSessionDetail`];
//! archived sessions are converted to the same shape first.

use super::{AgentSessionDetail, MessageKind, Role};

/// Export format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Markdown,
    Json,
}

impl Format {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "md" | "markdown" => Some(Format::Markdown),
            "json" => Some(Format::Json),
            _ => None,
        }
    }
    pub fn ext(self) -> &'static str {
        match self {
            Format::Markdown => "md",
            Format::Json => "json",
        }
    }
    pub fn content_type(self) -> &'static str {
        match self {
            Format::Markdown => "text/markdown; charset=utf-8",
            Format::Json => "application/json",
        }
    }
}

/// Render a session in the requested format.
pub fn render(d: &AgentSessionDetail, format: Format) -> String {
    match format {
        Format::Markdown => to_markdown(d),
        Format::Json => to_json(d),
    }
}

/// The normalized JSON structure (session metadata + ordered messages).
pub fn to_json(d: &AgentSessionDetail) -> String {
    serde_json::to_string_pretty(d).unwrap_or_else(|_| "{}".into())
}

/// A readable Markdown transcript with a metadata header.
pub fn to_markdown(d: &AgentSessionDetail) -> String {
    let s = &d.session;
    let mut out = String::new();
    let title = s.title.as_deref().unwrap_or("Untitled session");
    out.push_str(&format!("# {title}\n\n"));
    out.push_str(&format!("- Source: {}\n", s.tool.label()));
    if let Some(m) = &s.model {
        out.push_str(&format!("- Model: {m}\n"));
    }
    if let Some(p) = &s.project {
        out.push_str(&format!("- Project: {p}\n"));
    }
    if let Some(b) = &s.git_branch {
        out.push_str(&format!("- Branch: {b}\n"));
    }
    out.push_str(&format!(
        "- Messages: {} · Tool calls: {}\n",
        s.message_count, s.tool_call_count
    ));
    if s.input_tokens + s.output_tokens > 0 {
        out.push_str(&format!(
            "- Tokens: {} in · {} out\n",
            s.input_tokens, s.output_tokens
        ));
    }
    out.push_str(&format!("- Started: {}\n", fmt_ts(s.started_ts)));
    out.push_str(&format!("- Updated: {}\n", fmt_ts(s.updated_ts)));
    out.push_str("\n---\n");

    for m in &d.messages {
        let heading = match m.kind {
            MessageKind::ToolUse | MessageKind::ToolResult => {
                format!(
                    "### {} · {}",
                    role_label(m.role),
                    m.tool_name.as_deref().unwrap_or("tool")
                )
            }
            MessageKind::Thinking => format!("### {} · thinking", role_label(m.role)),
            MessageKind::Text => format!("### {}", role_label(m.role)),
        };
        out.push_str(&format!("\n{heading}\n\n{}\n", m.content.trim()));
    }
    out
}

/// A filesystem-safe base name for the export, e.g. `codex_fix-login_a1b2c3`.
pub fn safe_filename(d: &AgentSessionDetail) -> String {
    safe_filename_for(&d.session)
}

/// Same, from list metadata alone — lets callers (repo mirroring) name the
/// file without parsing the transcript.
pub fn safe_filename_for(s: &super::AgentSession) -> String {
    let slug: String = s
        .title
        .as_deref()
        .unwrap_or("session")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    let slug: String = slug.chars().take(48).collect();
    let slug = if slug.is_empty() {
        "session".into()
    } else {
        slug
    };
    format!("{}_{}_{}", s.tool.key(), slug, short_id_for(s))
}

/// The stable short-id suffix of [`safe_filename_for`] (used by mirroring to
/// find files for a session whose title — the slug half — has changed).
pub fn short_id_for(s: &super::AgentSession) -> String {
    super::split_id(&s.id)
        .map(|(_, r)| r)
        .unwrap_or(&s.id)
        .chars()
        .take(8)
        .collect()
}

fn role_label(r: Role) -> &'static str {
    match r {
        Role::User => "User",
        Role::Assistant => "Assistant",
        Role::Tool => "Tool",
        Role::System => "System",
    }
}

/// Format unix millis as an RFC3339 UTC string (best-effort; empty on error/0).
fn fmt_ts(ms: i64) -> String {
    if ms <= 0 {
        return String::new();
    }
    time::OffsetDateTime::from_unix_timestamp_nanos(ms as i128 * 1_000_000)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::{AgentMessage, AgentSession, AgentSessionDetail, AgentTool};

    fn detail() -> AgentSessionDetail {
        AgentSessionDetail {
            session: AgentSession {
                id: AgentSession::make_id(AgentTool::Codex, "abc123def456"),
                tool: AgentTool::Codex,
                title: Some("Fix the Login Bug!".into()),
                project: Some("/proj".into()),
                git_branch: None,
                model: Some("gpt-5.5".into()),
                started_ts: 1_700_000_000_000,
                updated_ts: 1_700_000_100_000,
                message_count: 2,
                tool_call_count: 0,
                input_tokens: 10,
                output_tokens: 5,
                cache_tokens: 0,
                cache_write_tokens: 0,
                source_path: String::new(),
            },
            messages: vec![
                AgentMessage {
                    role: Role::User,
                    kind: MessageKind::Text,
                    content: "fix it".into(),
                    ts: None,
                    tool_name: None,
                },
                AgentMessage {
                    role: Role::Assistant,
                    kind: MessageKind::Text,
                    content: "done".into(),
                    ts: None,
                    tool_name: None,
                },
            ],
        }
    }

    #[test]
    fn markdown_has_header_and_turns() {
        let md = to_markdown(&detail());
        assert!(md.starts_with("# Fix the Login Bug!"));
        assert!(md.contains("Source: Codex"));
        assert!(md.contains("### User"));
        assert!(md.contains("### Assistant"));
        assert!(md.contains("fix it"));
    }

    #[test]
    fn json_round_trips() {
        let js = to_json(&detail());
        let v: serde_json::Value = serde_json::from_str(&js).unwrap();
        assert_eq!(v["session"]["model"], "gpt-5.5");
        assert_eq!(v["messages"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn filename_is_safe() {
        let f = safe_filename(&detail());
        assert_eq!(f, "codex_fix-the-login-bug_abc123de");
        assert!(!f.contains(' ') && !f.contains('!'));
    }
}
