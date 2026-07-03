#![forbid(unsafe_code)]
//! Hippius Memory MCP server binary entry point.
//!
//! Serves the ten memory tools (`remember` / `recall` / `get` / `refresh` /
//! `forget` / `redact` / `link` / `edit` / `history` / `reconcile`) over stdio, backed by
//! the real S3-backed [`MemoryStore`](hippius_mem_core::MemoryStore) built from configuration (a TOML file
//! and/or `HIPPIUS_MEM_*` environment variables). It also dispatches the
//! `doctor` bundle-validation subcommand, the `publish-membership` team-admin
//! subcommand, the `init`/`install` Claude Code provisioning subcommands (and,
//! under the `console` feature, `mint-token`) before falling through to serving.
//! Diagnostics go to stderr via `tracing` so stdout stays a clean MCP protocol
//! channel.

mod admin;
mod config;
mod doctor;
#[cfg(feature = "console")]
mod mint;
mod resolver;
mod server;
mod setup;

use std::sync::Arc;

use anyhow::Context;
use rmcp::ServiceExt;
use rmcp::transport::stdio;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::resolver::{GitRemoteReader, RemoteReader, Resolution};
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

    // Subcommands are one-shot CLI flows, not the server: dispatch them before
    // loading server config and exit. `publish-membership` still loads config
    // (it builds the store); `mint-token` does not.
    let args: Vec<String> = std::env::args().collect();
    let subcommand = args.get(1).map(String::as_str);
    #[cfg(feature = "console")]
    if subcommand == Some("mint-token") {
        return mint::run(&args[2..]).await;
    }
    // Without the `console` feature `mint-token` is not compiled in. Bail loudly
    // rather than fall through to the server boot below, which would silently
    // ignore the subcommand and start reading the MCP stdio protocol — leaving
    // the operator believing they minted a token.
    #[cfg(not(feature = "console"))]
    if subcommand == Some("mint-token") {
        anyhow::bail!("the `mint-token` subcommand requires building with `--features console`");
    }
    if subcommand == Some("publish-membership") {
        return admin::publish_membership(&args[2..]).await;
    }
    // `doctor` is unconditional (no feature gate): bundle validation must be
    // available in the default build an operator already has.
    if subcommand == Some("doctor") {
        return doctor::run(&args[2..]).await;
    }
    // `init`/`install` provision Claude Code (mandates block, hooks, MCP entry).
    // They only touch the filesystem, so they run synchronously and exit before
    // the async store boot below — no config or S3 credentials required.
    if subcommand == Some("init") {
        return setup::init(&args[2..]);
    }
    if subcommand == Some("install") {
        return setup::install(&args[2..]);
    }

    let cfg = Config::from_env_and_file().context(
        "failed to load configuration; set HIPPIUS_MEM_* env vars or create hippius-mem.toml",
    )?;

    // Route the launch repo to a team profile by its git `origin` remote. One
    // process binds exactly one profile; a repo matching no profile and no
    // catch-all disables memory here rather than leaking into an unrelated team.
    let profiles = cfg.all_profiles();
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let remote = GitRemoteReader.origin_url(&cwd);
    let profile = match resolver::resolve(&profiles, remote.as_deref()) {
        Resolution::Bound(profile) => profile,
        Resolution::Disabled(reason) => {
            anyhow::bail!("team memory is disabled for this repository: {reason}");
        }
    };
    let store = Arc::new(profile.build_store(&cfg).await?);

    // Never log the secret or team key — only the non-secret coordinates.
    tracing::info!(profile = %profile.name, bucket = %profile.bucket, "Hippius Memory starting");

    // Best-effort: load the epoch key-ring this member can unwrap from the bucket
    // so a member provisioned after a team-key rotation starts up able to read
    // newer-epoch notes. Gated on a configured mnemonic (the team identity whose
    // x25519 secret unwraps the wrapped keys); non-fatal — a fresh bucket or an
    // un-provisioned epoch is warned and skipped, never aborts startup.
    if let Ok(mnemonic) = std::env::var("HIPPIUS_MEM_MNEMONIC") {
        admin::bootstrap_epochs(&store, &mnemonic, cfg.max_epoch).await;
    }

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

    // Best-effort: if this boot is a Claude Code session inside a provisioned
    // repo, refresh the committed CLAUDE.md rules block so the mandates track the
    // running binary. Never fatal — a provisioning refresh must not stop serving.
    setup::self_heal_on_serve();

    let service = MemoryServer::new(store).serve(stdio()).await?;
    service.waiting().await?;
    // A `store.flush_anchors().await` here would seal any below-threshold batch on
    // a clean exit. It is deliberately omitted: a stdio server has no orderly
    // shutdown signal to hang it off (the transport just ends), and the op-log
    // keeps every op regardless, so the next run re-buffers and anchors the
    // remainder. Anchoring is best-effort by design, so a flush-on-shutdown would
    // be an optimization, not a correctness fix.
    Ok(())
}
