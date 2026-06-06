//! CLI surface (04 §7.7) — mirrors `lms`/`ollama` ergonomics.
//!
//! `saffev adopt | status | start | stop | doctor | revert | logs`. Parsing is
//! `clap` derive; each subcommand dispatches to a thin handler in [`commands`].
//! Output uses [`crate::ui::palette`] for the calm, status-dot-prefixed voice.

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
        Command::Start { foreground } => commands::start(&cli, foreground).await,
        Command::Stop => commands::stop(&cli).await,
        Command::Doctor => commands::doctor(&cli).await,
        Command::Revert { engine } => commands::revert(&cli, engine).await,
        Command::Logs { follow } => commands::logs(&cli, follow).await,
    }
}
