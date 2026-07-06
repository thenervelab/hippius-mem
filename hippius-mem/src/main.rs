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

    // Warm the index in the BACKGROUND so the MCP handshake is answered
    // immediately. A cold replay of a large op-log takes tens of seconds (S3
    // round-trips + embedding); doing it inline here delayed `serve` past the
    // client's connection timeout, so the server appeared to "fail to connect".
    // Index reads (`recall`/`get`) await this one warmup via the readiness
    // channel; writes, `history`, and `reconcile` are unaffected. Every slow
    // startup I/O — epoch bootstrap and the sync — moves into the task; both are
    // best-effort and non-fatal exactly as the inline versions were.
    let (warm_tx, warm_rx) = tokio::sync::watch::channel(false);
    let warmup_store = Arc::clone(&store);
    let max_epoch = cfg.max_epoch;
    let mnemonic = std::env::var("HIPPIUS_MEM_MNEMONIC").ok();
    tokio::spawn(async move {
        // Best-effort: load the epoch key-ring this member can unwrap so a member
        // provisioned after a team-key rotation can read newer-epoch notes. Gated
        // on a configured mnemonic; a fresh bucket or un-provisioned epoch is
        // warned and skipped, never fatal.
        if let Some(mnemonic) = mnemonic {
            admin::bootstrap_epochs(&warmup_store, &mnemonic, max_epoch).await;
        }
        // Replay the shared op-log so this machine is aware of teammates' notes. A
        // fresh/empty bucket or a transient read error must not stop serving
        // (`refresh` syncs later); the signal below fires regardless of outcome.
        match warmup_store.sync().await {
            Ok(count) => tracing::info!(count, "synced index from op-log (warmup)"),
            Err(err) => {
                tracing::warn!(error = %err, "op-log warmup sync failed; serving with whatever is indexed");
            }
        }
        // Signal "warmup attempt done" so waiting reads proceed. A send error
        // means every receiver was dropped (the server already exited) — harmless.
        // On a clean serve exit the runtime drops this still-idempotent task; the
        // op-log persists, so an interrupted warmup simply re-syncs next boot —
        // the same best-effort rationale as the omitted flush-on-shutdown below.
        let _ = warm_tx.send(true);
    });

    // Best-effort: if this boot is a Claude Code session inside a provisioned
    // repo, refresh the committed CLAUDE.md rules block so the mandates track the
    // running binary. Never fatal — a provisioning refresh must not stop serving.
    setup::self_heal_on_serve();

    let service = MemoryServer::with_warmup(store, warm_rx)
        .serve(stdio())
        .await?;
    service.waiting().await?;
    // A `store.flush_anchors().await` here would seal any below-threshold batch on
    // a clean exit. It is deliberately omitted: a stdio server has no orderly
    // shutdown signal to hang it off (the transport just ends), and the op-log
    // keeps every op regardless, so the next run re-buffers and anchors the
    // remainder. Anchoring is best-effort by design, so a flush-on-shutdown would
    // be an optimization, not a correctness fix.
    Ok(())
}
