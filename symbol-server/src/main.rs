//! Devfiler-compatible symbol server for profile-bee.
//!
//! Accepts ELF binary uploads from profile-bee, extracts symbols, and serves
//! them in the format expected by devfiler's `--symb-endpoint` auto-fetch.
//!
//! Architecture:
//! ```
//! profile-bee ──POST /upload──▶ symbol-server ◀──GET /{id}/ranges── devfiler
//! ```

mod extract;
mod fileid;
mod server;
mod store;
mod symbfile;

use clap::Parser;

#[derive(Parser)]
#[command(
    name = "symbol-server",
    about = "Devfiler-compatible symbol server for profile-bee"
)]
struct Cli {
    /// Port to listen on
    #[arg(short, long, default_value_t = 8888)]
    port: u16,

    /// Bind address
    #[arg(long, default_value = "127.0.0.1")]
    bind: String,

    /// Directory to store processed symbol files
    #[arg(long, default_value = "./symbols")]
    store_dir: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "symbol_server=info".into()),
        )
        .init();

    let cli = Cli::parse();

    let store = store::SymbolStore::new(&cli.store_dir)?;
    tracing::info!(
        "symbol-server starting on {}:{}, store={}",
        cli.bind,
        cli.port,
        cli.store_dir
    );

    server::run(store, &cli.bind, cli.port).await
}
