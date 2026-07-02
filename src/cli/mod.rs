//! CLI surface (04 §7.7) — mirrors `lms`/`ollama` ergonomics.
//!
//! `saffev adopt | status | start | stop | doctor | revert | logs | update | run
//! | env | shell`. Parsing is `clap` derive; each subcommand dispatches to a thin
//! handler in [`commands`].
//! Output uses [`crate::ui::palette`] for the calm, status-dot-prefixed voice.

pub mod capture;
pub mod commands;
pub mod daemon;

use clap::{Parser, Subcommand};

use crate::brand::{APP_CMD, TAGLINE};
use crate::Result;

/// Top-level CLI parser.
#[derive(Debug, Parser)]
#[command(
    name = APP_CMD,
    about = TAGLINE,
    version,
    propagate_version = true,
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Path to an explicit config file (overrides the default data dir).
    #[arg(long, global = true, env = "SAFFEV_CONFIG")]
    pub config: Option<std::path::PathBuf>,

    /// Disable ANSI color (also honored via `NO_COLOR`).
    #[arg(long, global = true)]
    pub no_color: bool,

    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Which engine a subcommand targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum EngineArg {
    /// Ollama (default lead target).
    Ollama,
    /// LM Studio.
    Lmstudio,
}

/// The Saffev subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run adoption (Gateway on Linux) or print Cooperative setup.
    Adopt {
        /// Which engine to adopt.
        #[arg(long, value_enum, default_value_t = EngineArg::Ollama)]
        engine: EngineArg,
        /// Force Cooperative mode (no system changes).
        #[arg(long)]
        cooperative: bool,
    },
    /// Show engines, ports, mode, health, exposure result.
    Status,
    /// Run the proxy + Studio + supervisor.
    Start {
        /// Run in the foreground (do not daemonize).
        #[arg(long)]
        foreground: bool,
        /// Do not open the Studio in the default browser after a successful start.
        #[arg(long)]
        no_open: bool,
    },
    /// Stop the proxy + Studio + supervisor.
    Stop,
    /// Diagnose port conflicts, exposed bindings, stuck engines, permissions.
    Doctor,
    /// Clean de-adoption (Linux), restoring the engine's exact prior state.
    Revert {
        /// Which engine to revert.
        #[arg(long, value_enum, default_value_t = EngineArg::Ollama)]
        engine: EngineArg,
    },
    /// Stream activity.
    Logs {
        /// Keep following new activity.
        #[arg(long, short)]
        follow: bool,
    },
    /// Check for and install a newer Saffev release (installer installs only).
    ///
    /// Contacts GitHub release metadata ONLY — no user or content data leaves the
    /// device (consistent with the on-device invariant). A binary not installed
    /// via the installer (dev / `cargo install`) has no receipt: the command
    /// reports the current version and how to enable updates, never panics.
    Update {
        /// Only check whether an update is available; do not install it.
        #[arg(long)]
        check: bool,
    },
    /// Run a command with its LLM traffic routed through Saffev (zero config).
    ///
    /// Injects the engine base-URL env vars (Ollama + OpenAI-compatible, so it
    /// works with Ollama *and* LM Studio) into the child process, so its model
    /// calls flow through the proxy and get traced — no per-app config edits.
    /// Everything after `--` is the command and its arguments, e.g.
    /// `saffev run -- python app.py`.
    Run {
        /// Start the Saffev daemon first if it isn't already running.
        #[arg(long)]
        start: bool,
        /// Fail instead of running the command when the daemon isn't reachable
        /// (default: warn and run anyway, so your work is never blocked).
        #[arg(long)]
        require: bool,
        /// The command to run and its arguments (everything after `--`).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },
    /// Print shell `export` lines that route this shell's LLM traffic through
    /// Saffev. Use as `eval "$(saffev env)"`.
    Env {
        /// Shell dialect to format for: bash | zsh | fish | powershell.
        /// Auto-detected from `$SHELL` when omitted.
        #[arg(long)]
        shell: Option<String>,
        /// Emit a JSON object of the variables instead of shell exports.
        #[arg(long)]
        json: bool,
    },
    /// Launch an interactive shell with LLM traffic routed through Saffev.
    ///
    /// Everything you run from that shell is traced until you `exit`.
    Shell {
        /// Start the Saffev daemon first if it isn't already running.
        #[arg(long)]
        start: bool,
    },
}

/// Parse argv and dispatch to the matching command handler.
pub async fn run() -> Result<()> {
    let cli = Cli::parse();
    dispatch(cli).await
}

/// Dispatch a parsed [`Cli`] to its command handler.
pub async fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Adopt {
            engine,
            cooperative,
        } => commands::adopt(&cli, engine, cooperative).await,
        Command::Status => commands::status(&cli).await,
        Command::Start {
            foreground,
            no_open,
        } => commands::start(&cli, foreground, no_open).await,
        Command::Stop => commands::stop(&cli).await,
        Command::Doctor => commands::doctor(&cli).await,
        Command::Revert { engine } => commands::revert(&cli, engine).await,
        Command::Logs { follow } => commands::logs(&cli, follow).await,
        Command::Update { check } => commands::update(&cli, check).await,
        Command::Run {
            start,
            require,
            ref command,
        } => commands::run_cmd(&cli, start, require, command.clone()).await,
        Command::Env { ref shell, json } => commands::env_cmd(&cli, shell.clone(), json).await,
        Command::Shell { start } => commands::shell_cmd(&cli, start).await,
    }
}
