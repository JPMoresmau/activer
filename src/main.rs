use activer::app;
use anyhow::{anyhow, Result};
use std::{collections::HashMap, net::SocketAddr};

/// Web server entry point.
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        return Err(anyhow!("Usage archiver <base https url> <db path>"));
    }

    let addr = SocketAddr::from(([127, 0, 0, 1], 4000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app(&args[1], &args[2], HashMap::new())?.into_make_service())
        .await?;
    Ok(())
}
