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
mod brief;
mod config;
#[cfg(feature = "dashboard")]
mod dashboard;
mod doctor;
#[cfg(feature = "import")]
mod import;
#[cfg(feature = "console")]
mod mint;
mod resolver;
mod server;
mod setup;

use std::sync::Arc;

use anyhow::Context;
use hippius_mem_core::MemoryStore;
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
    // The `dashboard` subcommand serves the loopback browse/search UI. Gated the
    // same way as `mint-token`: without the feature the axum stack is not compiled
    // in, so bail loudly rather than fall through to the MCP stdio server.
    #[cfg(feature = "dashboard")]
    if subcommand == Some("dashboard") {
        return dashboard::run(&args[2..]).await;
    }
    #[cfg(not(feature = "dashboard"))]
    if subcommand == Some("dashboard") {
        anyhow::bail!("the `dashboard` subcommand requires building with `--features dashboard`");
    }
    // The `import` subcommand lifts a local claude-mem SQLite store into shared
    // team memory. Gated like `dashboard`/`console`: without the feature SQLite is
    // not linked, so bail loudly rather than fall through to the stdio server.
    #[cfg(feature = "import")]
    if subcommand == Some("import") {
        return import::run(&args[2..]).await;
    }
    #[cfg(not(feature = "import"))]
    if subcommand == Some("import") {
        anyhow::bail!("the `import` subcommand requires building with `--features import`");
    }
    if subcommand == Some("publish-membership") {
        return admin::publish_membership(&args[2..]).await;
    }
    // `doctor` is unconditional (no feature gate): bundle validation must be
    // available in the default build an operator already has.
    if subcommand == Some("doctor") {
        return doctor::run(&args[2..]).await;
    }
    // `brief` prints the SessionStart digest of the team's live memory to stdout
    // for a hook to inject. Unconditional (default build) and best-effort — it
    // never blocks or fails a session start.
    if subcommand == Some("brief") {
        return brief::run(&args[2..]).await;
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

    // Route the launch repo to a team profile and build its store. The `dashboard`
    // subcommand resolves through the SAME helper, so the two paths can never bind a
    // different profile from one directory (the git-remote routing must stay identical).
    let (store, launch_repo) = resolve_and_build_store(&cfg).await?;

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
        //
        // `sync`'s `index.retain` runs outside the writer lock, so a `remember`
        // that lands mid-warmup (after this replay read the op-log, before its
        // retain) can be transiently pruned from the index. It is never lost — the
        // op is durable in the log — and it self-heals: every read runs
        // `refresh_before_read` before answering, and this warmup path leaves the
        // auto-refresh watermark unset, so the first post-warmup read re-syncs and
        // restores it. This is the same eventual-consistency window `refresh_if_stale`
        // already tolerates for read-triggered syncs; backgrounding the boot sync
        // only widens it to the startup window.
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

    // Bind the launch repo so an omitted-`repo` recall falls back to it (finding:
    // a default recall must not silently exclude this repo's notes). No remote /
    // local-only checkout leaves `launch_repo` None, keeping the global-only default.
    let mut server = MemoryServer::with_warmup(store, warm_rx);
    if let Some(repo) = launch_repo {
        server = server.with_default_repo(repo);
    }
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    // A `store.flush_anchors().await` here would seal any below-threshold batch on
    // a clean exit. It is deliberately omitted: a stdio server has no orderly
    // shutdown signal to hang it off (the transport just ends), and the op-log
    // keeps every op regardless, so the next run re-buffers and anchors the
    // remainder. Anchoring is best-effort by design, so a flush-on-shutdown would
    // be an optimization, not a correctness fix.
    Ok(())
}

/// Resolve the launch repo to its team profile and build that profile's store.
///
/// Shared by the MCP server boot (`main`) and the `dashboard` subcommand
/// (`dashboard::run`) so the two can never resolve a DIFFERENT profile from the
/// same directory — the git-remote routing (profile match, disabled-on-no-match)
/// must stay identical across both entry points.
///
/// It stops at "store built": epoch-key bootstrap and the op-log sync are
/// deliberately left to each caller because their PLACEMENT differs. The server
/// runs both inside a background warmup task so the MCP handshake returns before
/// the slow op-log replay (the PR #24 fix); the dashboard runs them in the
/// foreground, having no handshake deadline. Folding either into this helper would
/// regress that separation, so the shared code ends here.
///
/// # Errors
///
/// Returns an error if the repo routes to no team profile (memory is disabled
/// here) or the store cannot be built.
async fn resolve_and_build_store(
    cfg: &Config,
) -> anyhow::Result<(Arc<MemoryStore>, Option<String>)> {
    let profiles = cfg.all_profiles();
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let remote = GitRemoteReader.origin_url(&cwd);
    let profile = match resolver::resolve(&profiles, remote.as_deref()) {
        Resolution::Bound(profile) => profile,
        Resolution::Disabled(reason) => {
            anyhow::bail!("team memory is disabled for this repository: {reason}");
        }
    };
    // The launch repo's bare name — from the SAME remote the profile routed on, so
    // it matches how notes are repo-scoped — is what `recall` falls back to when a
    // caller omits `repo`, so a default recall sees this repo's notes plus globals
    // instead of globals only. `None` (no recognizable remote) leaves recall global.
    let launch_repo = remote
        .as_deref()
        .and_then(resolver::normalize_remote)
        .map(|coord| coord.repo);
    // Never log the secret or team key — only the non-secret coordinates.
    tracing::info!(profile = %profile.name, bucket = %profile.bucket, "bound team profile");
    Ok((Arc::new(profile.build_store(cfg).await?), launch_repo))
}
