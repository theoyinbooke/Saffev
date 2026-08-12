//! Opt-in repo mirroring — preserved sessions written as Markdown into the
//! repository they belong to (`<repo>/.saffev/sessions/`), so transcripts live
//! next to the code they produced and can travel with the repo if the user
//! chooses to commit them.
//!
//! Rules, in order of importance:
//! - **Opt-in and conservative.** Off by default (`[archive] mirror_repos`).
//!   Writes ONLY into a project directory that exists and contains `.git` (a
//!   directory for normal clones, a *file* for worktrees) — a path named by a
//!   session file must never cause folders to appear in arbitrary places.
//! - **Never rawer than the archive.** The same [`Redaction`] posture the
//!   archive applies is applied here; with redaction on, the mirror gets the
//!   redacted rendering. A mirror that leaks what the archive scrubbed would
//!   defeat the setting.
//! - **Fail-open.** Any IO error is logged by the caller and skipped;
//!   mirroring can never fail a snapshot.

use std::path::{Path, PathBuf};

use super::archive::Redaction;
use super::{export, AgentSession, AgentSessionDetail};

/// Directory (relative to the repo root) mirrored sessions live in.
pub const MIRROR_SUBDIR: &str = ".saffev/sessions";

/// Explains the folder to whoever finds it in their repo. Written once.
const README: &str = "# AI sessions — mirrored by Saffev\n\n\
Markdown transcripts of the AI coding sessions that touched this repository,\n\
written by Saffev's Preservation feature (`[archive] mirror_repos`). Files are\n\
regenerated when a session changes — do not edit them by hand.\n\n\
Commit them if you want the session history to travel with the repo, or keep\n\
them local by adding `.saffev/` to your `.gitignore`. If redaction is enabled\n\
in Saffev, detected secrets were replaced with typed placeholders before\n\
these files were written.\n";

/// Mirror target for a project: `Some(<project>/.saffev/sessions)` only when
/// the project is an absolute path to an existing directory containing `.git`.
/// Everything else — relative paths, plain names some tools store as
/// "project", vanished directories, non-repos — is `None`, i.e. not mirrored.
pub fn mirror_dir(project: Option<&str>) -> Option<PathBuf> {
    let p = Path::new(project?);
    if !p.is_absolute() || !p.is_dir() || !p.join(".git").exists() {
        return None;
    }
    Some(p.join(MIRROR_SUBDIR))
}

/// The mirror file path for a session (`None` when its project is not an
/// eligible repo). Filename is `<tool>_<title-slug>_<short-id>.md` — the slug
/// follows the session title, the trailing short id is the stable part.
pub fn mirror_path(s: &AgentSession) -> Option<PathBuf> {
    Some(mirror_dir(s.project.as_deref())?.join(format!("{}.md", export::safe_filename_for(s))))
}

/// Write one session's Markdown mirror (creating the folder + README on first
/// use, and removing a stale file left by an earlier title). Returns
/// `Ok(true)` when written, `Ok(false)` when the session has no eligible repo.
pub fn write_session(d: &AgentSessionDetail, redaction: &Redaction) -> std::io::Result<bool> {
    let Some(path) = mirror_path(&d.session) else {
        return Ok(false);
    };
    // `mirror_path` always returns `<dir>/<file>.md`, so parent exists.
    let dir = path
        .parent()
        .expect("mirror path has a parent by construction");
    std::fs::create_dir_all(dir)?;
    let readme = dir.join("README.md");
    if !readme.exists() {
        std::fs::write(&readme, README)?;
    }
    remove_stale_siblings(dir, &path, &d.session);

    // Render with the archive's redaction posture applied — never rawer than
    // what the archive itself stores.
    let redacted = redact_detail(d, redaction);
    std::fs::write(&path, export::to_markdown(&redacted))?;
    Ok(true)
}

/// A session's title (the slug half of the filename) can change between
/// snapshots; the short-id suffix cannot. Remove siblings that share the id
/// but not the current name, so a renamed session leaves one file, not a trail.
fn remove_stale_siblings(dir: &Path, current: &Path, s: &AgentSession) {
    let suffix = format!("_{}.md", export::short_id_for(s));
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p != current
            && p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(&suffix))
        {
            let _ = std::fs::remove_file(&p);
        }
    }
}

/// Clone a detail with every message body passed through the redaction.
fn redact_detail(d: &AgentSessionDetail, redaction: &Redaction) -> AgentSessionDetail {
    let mut out = d.clone();
    for m in &mut out.messages {
        m.content = redaction.apply(m.role, &m.content);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::{AgentMessage, AgentTool, MessageKind, Role};

    fn repo_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("saffev-mirror-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        dir
    }

    fn detail(project: Option<String>, title: &str) -> AgentSessionDetail {
        AgentSessionDetail {
            session: AgentSession {
                id: AgentSession::make_id(AgentTool::ClaudeCode, "cafebabe1234"),
                tool: AgentTool::ClaudeCode,
                title: Some(title.into()),
                project,
                git_branch: None,
                model: Some("m".into()),
                started_ts: 1_700_000_000_000,
                updated_ts: 1_700_000_100_000,
                message_count: 1,
                tool_call_count: 0,
                input_tokens: 1,
                output_tokens: 1,
                cache_tokens: 0,
                cache_write_tokens: 0,
                source_path: String::new(),
            },
            messages: vec![AgentMessage {
                role: Role::User,
                kind: MessageKind::Text,
                content: "mail ops@example.com about the deploy".into(),
                ts: None,
                tool_name: None,
            }],
        }
    }

    #[test]
    fn mirror_dir_requires_an_absolute_existing_git_repo() {
        assert_eq!(mirror_dir(None), None);
        assert_eq!(mirror_dir(Some("not/absolute")), None);
        assert_eq!(mirror_dir(Some("/definitely/not/there")), None);

        // A directory without .git is not a repo — never write into it.
        let plain = std::env::temp_dir().join(format!("saffev-plain-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&plain).unwrap();
        assert_eq!(mirror_dir(Some(&plain.to_string_lossy())), None);

        // .git as a directory (clone)…
        let repo = repo_dir();
        assert_eq!(
            mirror_dir(Some(&repo.to_string_lossy())),
            Some(repo.join(MIRROR_SUBDIR))
        );

        // …and .git as a file (worktree) both qualify.
        let wt = std::env::temp_dir().join(format!("saffev-wt-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&wt).unwrap();
        std::fs::write(wt.join(".git"), "gitdir: /elsewhere").unwrap();
        assert!(mirror_dir(Some(&wt.to_string_lossy())).is_some());

        let _ = std::fs::remove_dir_all(&plain);
        let _ = std::fs::remove_dir_all(&repo);
        let _ = std::fs::remove_dir_all(&wt);
    }

    #[test]
    fn writes_markdown_and_readme_and_applies_redaction() {
        let repo = repo_dir();
        let d = detail(Some(repo.to_string_lossy().into_owned()), "Fix Deploy");

        let redacting = Redaction {
            detector: Some(std::sync::Arc::new(
                crate::brain::pii::Detector::new(&[]).unwrap(),
            )),
        };
        assert!(write_session(&d, &redacting).unwrap());

        let dir = repo.join(MIRROR_SUBDIR);
        let file = mirror_path(&d.session).unwrap();
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(text.starts_with("# Fix Deploy"));
        // The mirror must never be rawer than the archive: the address is gone,
        // the sentence survives.
        assert!(!text.contains("ops@example.com"), "{text}");
        assert!(text.contains("about the deploy"), "{text}");
        assert!(dir.join("README.md").exists(), "folder README written");

        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn no_repo_is_a_clean_skip_not_an_error() {
        let d = detail(None, "t");
        assert!(!write_session(&d, &Redaction::off()).unwrap());
    }

    #[test]
    fn a_renamed_session_replaces_its_old_file() {
        let repo = repo_dir();
        let project = repo.to_string_lossy().into_owned();

        let before = detail(Some(project.clone()), "Old Title");
        write_session(&before, &Redaction::off()).unwrap();
        let old_file = mirror_path(&before.session).unwrap();
        assert!(old_file.exists());

        let after = detail(Some(project), "Completely New Title");
        write_session(&after, &Redaction::off()).unwrap();
        let new_file = mirror_path(&after.session).unwrap();
        assert!(new_file.exists());
        assert!(
            !old_file.exists(),
            "stale file for the old title is removed"
        );

        let _ = std::fs::remove_dir_all(&repo);
    }
}
