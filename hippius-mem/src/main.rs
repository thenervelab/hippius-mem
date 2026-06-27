//! Hippius Memory MCP server binary entry point.
//!
//! Serves the `remember` / `recall` / `get` / `refresh` tools over stdio, backed
//! by the real S3-backed [`MemoryStore`] built from configuration (a TOML file
//! and/or `HIPPIUS_MEM_*` environment variables). Diagnostics go to stderr via
//! `tracing` so stdout stays a clean MCP protocol channel.

mod config;
#[cfg(feature = "console")]
mod mint;
mod server;

use std::sync::Arc;

use anyhow::Context;
use rmcp::ServiceExt;
use rmcp::transport::stdio;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::server::MemoryServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Logs MUST go to stderr: stdout carries the MCP stdio protocol and any
    // stray byte there corrupts the channel.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    // `mint-token` is a one-shot CLI flow, not the server: handle it before
    // loading server config (which it does not need) and exit.
    #[cfg(feature = "console")]
    {
        let args: Vec<String> = std::env::args().collect();
        if args.get(1).map(String::as_str) == Some("mint-token") {
            return mint::run(&args[2..]).await;
        }
    }

    let cfg = Config::from_env_and_file().context(
        "failed to load configuration; set HIPPIUS_MEM_* env vars or create hippius-mem.toml",
    )?;
    let store = Arc::new(cfg.build_store().await?);

    // Never log `cfg.secret` or the team key — only the non-secret coordinates.
    tracing::info!(team = %cfg.team, bucket = %cfg.bucket, "Hippius Memory starting");

    // Warm the index by replaying the shared op-log so this machine starts up
    // already aware of teammates' notes. A failure here is logged but does NOT
    // abort startup: a fresh/empty bucket or a transient read error must not stop
    // the server from serving (and `refresh` can sync later). Only a hard config
    // error — handled above — should prevent boot.
    match store.sync().await {
        Ok(count) => tracing::info!(count, "synced index from op-log"),
        Err(err) => {
            tracing::warn!(error = %err, "op-log sync at startup failed; serving with whatever is indexed");
        }
    }

    let service = MemoryServer::new(store).serve(stdio()).await?;
    service.waiting().await?;
    // A `store.flush_anchors().await` here would seal any below-threshold batch on
    // a clean exit. It is deliberately omitted in Phase 2: a stdio server has no
    // orderly shutdown signal to hang it off (the transport just ends), and the
    // op-log keeps every op regardless, so the next run re-buffers and anchors the
    // remainder. Graceful flush-on-shutdown is a Phase 3 lifecycle concern.
    Ok(())
}
