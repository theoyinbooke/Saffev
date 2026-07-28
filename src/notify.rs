//! Desktop notifications — OS-local, fail-soft, zero network (G6).
//!
//! One function: [`send`]. Linux uses `notify-send` (freedesktop), macOS uses
//! `osascript`'s `display notification`, Windows is a logged no-op for now.
//! Everything is invoked as a **subprocess with argv arguments** — never a
//! shell string, never interpolation — so a signal title containing quotes (or
//! anything an attacker put in a prompt that later shows up in a detail line)
//! cannot inject into the notifier. On macOS specifically, the AppleScript is
//! a fixed program that reads its strings from `argv`, so the user text never
//! touches the script source.
//!
//! Fail-soft is the invariant: a missing binary, a headless session, or a
//! notifier error is a `tracing::debug` line, never an `Err` — monitors must
//! keep monitoring on machines that cannot pop toasts.

use std::process::{Command, Stdio};

/// The command + argv used to notify on this platform, or `None` where
/// notifications are a no-op. Split from [`send`] so the injection-safety
/// property (user text appears only as argv entries, never inside program
/// text) is unit-testable without popping real toasts.
pub fn command_spec(title: &str, body: &str) -> Option<(&'static str, Vec<String>)> {
    #[cfg(target_os = "linux")]
    {
        Some((
            "notify-send",
            vec![
                "--app-name=Saffev".to_string(),
                title.to_string(),
                body.to_string(),
            ],
        ))
    }
    #[cfg(target_os = "macos")]
    {
        // A fixed AppleScript program; the title/body arrive as `argv` items,
        // so quoting in the user text is inert data, not script source.
        Some((
            "osascript",
            vec![
                "-e".into(),
                "on run argv".into(),
                "-e".into(),
                "display notification (item 2 of argv) with title (item 1 of argv)".into(),
                "-e".into(),
                "end run".into(),
                title.to_string(),
                body.to_string(),
            ],
        ))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (title, body);
        None
    }
}

/// Show a desktop notification. Best-effort and silent about failure (debug
/// log only). Never blocks the caller on the notifier: the child is reaped on
/// a detached thread so no zombie accumulates under the 60s monitor loop.
pub fn send(title: &str, body: &str) {
    let Some((program, args)) = command_spec(title, body) else {
        tracing::debug!(
            target: "saffev::notify",
            "desktop notifications unsupported on this platform; signal was: {title}"
        );
        return;
    };
    match Command::new(program)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(mut child) => {
            // Reap off-thread: notifiers exit in milliseconds, but waiting
            // inline would stall an async caller and not waiting leaks zombies.
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
        Err(e) => {
            // Missing binary / headless session: the signal still exists in the
            // log and the SSE stream — losing the toast must not lose the signal.
            tracing::debug!(target: "saffev::notify", "notifier `{program}` unavailable: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_text_is_argv_data_never_program_text() {
        // The classic injection probe: quotes + command substitution. It must
        // come back verbatim as standalone argv entries.
        let title = r#"evil" & do shell script "rm -rf ~" & ""#;
        let body = "$(reboot); 'quoted'";
        if let Some((program, args)) = command_spec(title, body) {
            assert!(program == "notify-send" || program == "osascript");
            assert!(
                args.iter().any(|a| a == title),
                "title must be a verbatim argv entry"
            );
            assert!(
                args.iter().any(|a| a == body),
                "body must be a verbatim argv entry"
            );
            // No argv entry other than the verbatim pair may contain user text
            // (i.e. nothing concatenated it into program/script source).
            for a in &args {
                if a != title && a != body {
                    assert!(
                        !a.contains("rm -rf"),
                        "user text leaked into program text: {a}"
                    );
                }
            }
        }
    }

    #[test]
    fn send_is_fail_soft() {
        // Must not panic or error even when no notification daemon exists
        // (headless CI). The contract is: best effort, debug log, move on.
        send("Saffev test", "fail-soft check");
    }
}
