//! Saffev binary entry point — thin. Sets up tracing, then hands off to the CLI
//! dispatcher in [`saffev::cli`]. All real work lives in the library.

use std::process::ExitCode;

fn main() -> ExitCode {
    // Diagnostic tracing to Saffev's own log (never the client). Honors RUST_LOG.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    // The menu-bar launcher owns the native run loop on the main thread and runs
    // the server as a child process, so it runs OUTSIDE the async runtime. It runs
    // on an explicit `saffev tray`, OR when launched from the .app bundle with no
    // arguments at all (double-click; macOS may pass only a legacy `-psn_…` flag).
    // ANY other argument means CLI usage — the tray's own daemon child is spawned
    // as `--config … start --foreground`, and matching on "argv[1] is not a flag"
    // would misread that as argless and re-enter the tray (a fork bomb).
    #[cfg(feature = "tray")]
    {
        let first = std::env::args().nth(1);
        let argless = std::env::args().skip(1).all(|a| a.starts_with("-psn"));
        let in_bundle = std::env::current_exe()
            .map(|p| p.to_string_lossy().contains(".app/Contents/MacOS/"))
            .unwrap_or(false);
        if first.as_deref() == Some("tray") || (in_bundle && argless) {
            return saffev::cli::tray::run_tray();
        }
    }

    // Everything else runs on the tokio runtime (built explicitly rather than via
    // `#[tokio::main]` so the tray path above can avoid it entirely).
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("{}: failed to start async runtime: {err}", saffev::brand::APP_CMD);
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(async {
        match saffev::cli::run().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                tracing::error!("{err}");
                eprintln!("{}: {err}", saffev::brand::APP_CMD);
                ExitCode::FAILURE
            }
        }
    })
}
