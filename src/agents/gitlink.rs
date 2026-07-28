//! Session ↔ git commit linkage (G5 rubric d).
//!
//! A preserved transcript answers "what was said"; the repo answers "what
//! actually changed". This module joins the two: given a session's project
//! directory and its active window, it lists the commits made there during
//! that window (padded, because people commit a few minutes after the last
//! message). Read-only `git log` against the LOCAL repo — no network, no
//! writes, and every failure (no git binary, not a repo, bad branch) degrades
//! to "no linked commits" rather than an error, because linkage is garnish on
//! the archive, never a reason a session page fails to load.

use std::path::Path;
use std::process::Command;

/// Default window padding: 10 minutes either side. Sessions end when the last
/// message lands, but the commit that work produced usually follows shortly
/// after; without padding the most interesting commit is exactly the one missed.
pub const DEFAULT_PAD_MS: i64 = 10 * 60 * 1000;

/// One commit made during a session's window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitLink {
    /// Abbreviated hash (`%h`).
    pub hash: String,
    /// Subject line (`%s`).
    pub summary: String,
    /// Committer timestamp, unix millis (`%ct` × 1000).
    pub ts: i64,
}

/// Commits in `project` whose committer time falls inside
/// `[started_ms - pad_ms, updated_ms + pad_ms]`, newest first, capped at 50.
///
/// When `branch` is `Some`, only that branch's history is walked (the branch
/// the session recorded); if the branch no longer exists — rebased away,
/// deleted after merge — we retry against HEAD rather than return nothing,
/// because "the branch is gone" does not mean "the work is gone".
///
/// Fail-soft to an empty `Vec` on ANY error: no `git` on PATH, `project` not a
/// repository, unreadable dir. Zero network — `git log` only reads local state.
pub fn commits_for(
    project: &Path,
    branch: Option<&str>,
    started_ms: i64,
    updated_ms: i64,
    pad_ms: i64,
) -> Vec<CommitLink> {
    let since = (started_ms.saturating_sub(pad_ms)) / 1000;
    let until = (updated_ms.saturating_add(pad_ms)) / 1000;
    match run_log(project, branch, since, until) {
        Some(out) => out,
        // The recorded branch may not exist anymore — fall back to HEAD.
        None => branch
            .and_then(|_| run_log(project, None, since, until))
            .unwrap_or_default(),
    }
}

/// One `git log` invocation. `None` = the command failed (caller decides
/// whether to retry without the branch).
fn run_log(project: &Path, branch: Option<&str>, since: i64, until: i64) -> Option<Vec<CommitLink>> {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(project).arg("log");
    // All OUR options first — `@<unix>` is git's own unix-epoch date form, so
    // the window needs no timezone-sensitive string formatting; `%x1f` (unit
    // separator) cannot appear in a hash or a single-line subject, making the
    // parse unambiguous; `-n 50` caps a pathological window at the git side.
    cmd.arg("--format=%h%x1f%ct%x1f%s")
        .arg(format!("--since=@{since}"))
        .arg(format!("--until=@{until}"))
        .arg("-n")
        .arg("50");
    if let Some(b) = branch {
        // The branch is UNTRUSTED (parsed from an agent's session file). git
        // has no shell here, but a `-`-prefixed value is read as an OPTION,
        // not a revision — `--output=<path>` writes an arbitrary file
        // (G5 critic: arbitrary-file-write via a crafted `git_branch`).
        // `--end-of-options` forces everything AFTER it to be a revision, so
        // it goes last, after all of our own options.
        cmd.arg("--end-of-options").arg(b);
    }
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut links = Vec::new();
    for line in stdout.lines() {
        let mut parts = line.splitn(3, '\u{1f}');
        let (Some(hash), Some(ct), Some(summary)) = (parts.next(), parts.next(), parts.next())
        else {
            continue; // malformed line — skip it, keep the rest
        };
        let Ok(secs) = ct.parse::<i64>() else { continue };
        if hash.is_empty() {
            continue;
        }
        links.push(CommitLink {
            hash: hash.to_string(),
            summary: summary.to_string(),
            ts: secs * 1000,
        });
        if links.len() >= 50 {
            break;
        }
    }
    Some(links)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_repo_means_no_links_not_an_error() {
        let dir = std::env::temp_dir().join(format!("saffev-gitlink-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        // A plain directory is not a repo: fail-soft to empty, with and
        // without a branch (the branch path must also survive the retry).
        assert!(commits_for(&dir, None, 0, i64::MAX / 2, DEFAULT_PAD_MS).is_empty());
        assert!(commits_for(&dir, Some("main"), 0, i64::MAX / 2, DEFAULT_PAD_MS).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_directory_is_fail_soft_too() {
        let dir = Path::new("/definitely/not/a/real/project/path");
        assert!(commits_for(dir, None, 0, 1_000_000, DEFAULT_PAD_MS).is_empty());
    }

    #[test]
    fn dash_prefixed_branch_cannot_write_a_file() {
        // G5 critic's finding: an untrusted branch like `--output=<path>` was
        // read by `git log` as an option and wrote a file. `--end-of-options`
        // must force it to be treated as a (nonexistent) revision instead.
        let dir = std::env::temp_dir().join(format!("saffev-gitinj-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        // A real repo so `git log` actually runs (a non-repo would short out
        // before arg interpretation and prove nothing).
        let ok = |args: &[&str]| {
            std::process::Command::new("git")
                .arg("-C")
                .arg(&dir)
                .args(args)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        };
        if !ok(&["init", "-q"]) {
            return; // no git on this machine — nothing to prove
        }
        let _ = ok(&["config", "user.email", "t@t"]);
        let _ = ok(&["config", "user.name", "t"]);
        let _ = ok(&["commit", "-q", "--allow-empty", "-m", "seed"]);
        let canary = dir.join("PWNED");
        // The attack payload as a branch name.
        let _ = commits_for(
            &dir,
            Some("--output=PWNED"),
            0,
            i64::MAX / 2,
            DEFAULT_PAD_MS,
        );
        assert!(
            !canary.exists(),
            "arg injection: a --output= branch wrote a file"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // End-to-end behavior against a real temp repo (window filtering, branch
    // fallback, ordering) is covered by the G5 bench:
    // `tests/preservation_bench.rs`.
}
