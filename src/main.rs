use activer::app;
use anyhow::Result;
use clap::Parser;
use std::{collections::HashMap, net::SocketAddr, path::PathBuf, str::FromStr};

/// ActivityPub server
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Base HTTPS URL
    #[arg(short, long, value_name = "HTTPS_URL")]
    base: String,

    /// Path to the database file [default: archiver.db]
    #[arg(short, long, value_name = "FILE")]
    db_path: Option<PathBuf>,

    /// Port to listen on
    #[arg(short, long, default_value_t = 4000)]
    port: u16,
}

/// Web server entry point.
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Args::parse();

    let addr = SocketAddr::from(([127, 0, 0, 1], cli.port));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(
            app(
                &cli.base,
                cli.db_path.unwrap_or(PathBuf::from_str("activer.db")?),
                HashMap::new(),
            )?
            .into_make_service(),
        )
        .await?;
    Ok(())
}
