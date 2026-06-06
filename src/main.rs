//! Saffev binary entry point — thin. Sets up tracing, then hands off to the CLI
//! dispatcher in [`saffev::cli`]. All real work lives in the library.

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    // Diagnostic tracing to Saffev's own log (never the client). Honors RUST_LOG.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    match saffev::cli::run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!("{err}");
            eprintln!("{}: {err}", saffev::brand::APP_CMD);
            ExitCode::FAILURE
        }
    }
}
