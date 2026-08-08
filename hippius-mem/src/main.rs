#![forbid(unsafe_code)]
//! Hippius Memory MCP server binary entry point.
//!
//! Serves the ten memory tools (`remember` / `recall` / `get` / `refresh` /
//! `forget` / `redact` / `link` / `edit` / `history` / `reconcile`) over stdio, backed by
//! the real S3-backed [`MemoryStore`](hippius_mem_core::MemoryStore) built from configuration (a TOML file
//! and/or `HIPPIUS_MEM_*` environment variables). It also dispatches the
//! `quickstart` zero-decision local trial onboarding subcommand, the `doctor`
//! bundle-validation subcommand, the `publish-membership` team-admin
//! subcommand, the `init`/`install` Claude Code provisioning subcommands (and,
//! under the `console` feature, `mint-token`/`invite`) before falling through
//! to serving.
//! Diagnostics go to stderr via `tracing` so stdout stays a clean MCP protocol
//! channel.

mod admin;
mod brief;
mod bundle;
mod config;
#[cfg(feature = "dashboard")]
mod dashboard;
mod doctor;
mod gc;
#[cfg(feature = "import")]
mod import;
#[cfg(feature = "console")]
mod invite;
mod join_bundle;
#[cfg(feature = "console")]
mod mint;
mod quickstart;
mod report;
mod resolver;
mod server;
mod setup;
mod upgrade;

use std::sync::Arc;

use anyhow::Context;
use hippius_mem_core::MemoryStore;
use rmcp::ServiceExt;
use rmcp::transport::stdio;
use tracing_subscriber::EnvFilter;

use crate::config::{Config, VaultLock, VaultLockAttempt};
use crate::resolver::{GitRemoteReader, RemoteReader, Resolution};
use crate::server::MemoryServer;

/// Operator-facing subcommand listing, printed for `--help` and echoed when an
/// unknown subcommand is rejected. Feature-gated subcommands are listed
/// unconditionally: naming one that is not compiled in already bails with the
/// exact `--features` flag to rebuild with, which is better guidance than
/// hiding it.
const USAGE: &str = "\
hippius-mem — shared, encrypted, verifiable team memory (MCP server)

Usage:
  hippius-mem                          start the MCP stdio server (requires config)
  hippius-mem quickstart [--team <name>] [--no-wire]
                                       zero-decision solo trial: writes a local
                                       (no-gateway) trial vault config, probes it
                                       with doctor, and wires Claude Code (skip
                                       wiring with --no-wire); refuses if a
                                       config already exists
  hippius-mem upgrade --bucket <name> --access-key-id <id>
                      [--team <name>] [--endpoint <url>]
                                       flip a quickstart trial vault to a paid Hippius
                                       bucket: probes the destination, copies every
                                       object, then rewrites the config to storage =
                                       \"s3\" (the S3 secret is prompted on the
                                       terminal, or read from stdin, never argv)
  hippius-mem init                     provision this repo for Claude Code (rules, hooks, MCP entry)
  hippius-mem install                  install the binary + global MCP registration
  hippius-mem doctor                   validate the local setup bundle
  hippius-mem brief [--tokens N]       print the SessionStart digest of team memory
  hippius-mem report [--since <7d|Nd|Nw>]
                                       render the team ROI digest to stdout: reused
                                       notes (all-time), then windowed activity
                                       (default window: 7d)
  hippius-mem gc [--dry-run] [--grace-hours N]
                                       reclaim orphaned note-ciphertext blobs left
                                       by a cancelled or crashed write (default
                                       grace: 24h)
  hippius-mem join [--bundle <path|-> [--orgs <host/org,...>]]
                                       join a team: consume a founder's invite bundle
                                       (writes the local config, then publishes this
                                       member's key when HIPPIUS_MEM_MNEMONIC is set);
                                       bare `join` only publishes the member key
  hippius-mem provision [--no-recovery]
                                       founder: wrap the team key to published member
                                       keys, and (by default) name a fresh recovery key
  hippius-mem recover                  recover the team through its recovery key when
                                       the founder key is lost (prompts for the seed on
                                       the terminal or stdin; never accepted via argv)
  hippius-mem members                  print the founder-signed membership
  hippius-mem publish-membership --members <ss58,...>
                                       founder: publish the signed membership manifest
  hippius-mem rotate [--members <ss58,...>]
                                       founder: rotate the team key to a new epoch
                                       (primary profile only; --members publishes a
                                       shrunk membership first)
  hippius-mem remove <ss58>            founder: remove a member — publish the roster
                                       without them, rotate the team key, and print
                                       the manual sub-token revoke step
  hippius-mem mint-token [...]         mint a gateway sub-token   (--features console)
  hippius-mem invite [--name <label>]  founder: mint a teammate's sub-token and print
                                       the paste-ready invite bundle (--features console)
  hippius-mem dashboard [...]          serve the loopback browse UI (--features dashboard)
  hippius-mem import claude-mem [...]  import a claude-mem SQLite store (--features import)
";

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

    if let Some(sub) = subcommand
        && let Some(result) = dispatch_console(sub, &args[2..]).await
    {
        return result;
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

    if let Some(sub) = subcommand
        && let Some(result) = dispatch_admin(sub, &args[2..]).await
    {
        return result;
    }

    // `quickstart`/`upgrade`/`doctor`/`brief`/`report`/`gc`: unconditional,
    // config-optional one-shot subcommands sharing one signature — see
    // `dispatch_one_shot` for why each is placed here.
    if let Some(sub) = subcommand
        && let Some(result) = dispatch_one_shot(sub, &args[2..]).await
    {
        return result;
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

    // Any argument left over is a help request or a typo, and falling through to
    // the server is the worst answer to both: `--help` would boot a silent stdio
    // loop that looks hung, and a misspelled subcommand would start the server
    // (or error about config) instead of saying "unknown subcommand". Only a
    // BARE `hippius-mem` starts the MCP stdio server.
    if let Some(arg) = subcommand {
        // Direct handle writes: operator-facing output, and the workspace
        // denies the `print!` family (stdout normally carries the protocol).
        use std::io::Write;

        if arg == "help" || arg == "--help" || arg == "-h" {
            let _ = std::io::stdout().write_all(USAGE.as_bytes());
            return Ok(());
        }
        if arg == "--version" || arg == "-V" || arg == "version" {
            let _ = writeln!(
                std::io::stdout(),
                "hippius-mem {}",
                env!("CARGO_PKG_VERSION")
            );
            return Ok(());
        }

        anyhow::bail!("unknown subcommand `{arg}`\n\n{USAGE}");
    }

    let cfg = Config::from_env_and_file().context(
        "failed to load configuration; set HIPPIUS_MEM_* env vars or create hippius-mem.toml",
    )?;

    // Route the launch repo to a team profile and build its store. The `dashboard`
    // subcommand resolves through the SAME helper, so the two paths can never bind a
    // different profile from one directory (the git-remote routing must stay identical).
    // `_vault_lock` is held for local trial profiles — kept bound (not `let _ = `,
    // which would drop it immediately) so the advisory lock stays held for the rest
    // of `main`, until process exit releases it; see finding #6 / `resolve_and_build_store`.
    let (store, launch_repo, _vault_lock) = resolve_and_build_store(&cfg).await?;

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

        // Best-effort, and independent of the mnemonic gate above (listing the
        // `_keys/` prefix needs no identity): warn when the bucket has
        // published a wrapped-key epoch newer than this machine's configured
        // `max_epoch` (the recorded `bootstrap_epochs` gotcha's warning-side
        // counterpart).
        admin::warn_if_max_epoch_stale(&warmup_store, max_epoch).await;

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

/// Route the unconditional, config-optional one-shot subcommands that share
/// `async fn run(args: &[String]) -> anyhow::Result<()>`, or `None` when
/// `subcommand` is none of them (the caller falls through to the remaining
/// dispatch). Grouped for the same reason [`dispatch_admin`] and
/// `dispatch_console` are: keeping `main` under the line-count budget.
async fn dispatch_one_shot(subcommand: &str, rest: &[String]) -> Option<anyhow::Result<()>> {
    match subcommand {
        // `quickstart` is the zero-decision trial-mode onboarding subcommand: it
        // writes a local (no-gateway) trial vault config, probes it via `doctor`,
        // and wires Claude Code. Unconditional (default build, no S3 credentials
        // required) and placed here alongside the other config-free one-shot
        // subcommands.
        "quickstart" => Some(quickstart::run(rest).await),
        // `upgrade` flips a `quickstart` trial vault to a paid Hippius S3 bucket:
        // probes the destination, copies every object, then rewrites the config.
        // Unconditional (default build, no feature gate) and placed alongside
        // `quickstart` — the two ends of the trial-vault lifecycle.
        "upgrade" => Some(upgrade::run(rest).await),
        // `doctor` is unconditional (no feature gate): bundle validation must be
        // available in the default build an operator already has.
        "doctor" => Some(doctor::run(rest).await),
        // `brief` prints the SessionStart digest of the team's live memory to
        // stdout for a hook to inject. Unconditional (default build) and
        // best-effort — it never blocks or fails a session start.
        "brief" => Some(brief::run(rest).await),
        // `report` renders the team ROI digest to stdout. Unlike `brief`, a
        // real error here (bad config, unbuildable store) is not silenced.
        "report" => Some(report::run(rest).await),
        // `gc` reclaims orphaned note-ciphertext blobs (a cancelled/crashed write
        // that landed a blob but never appended its op). Unconditional — it uses
        // only core APIs — and administrative: run by an operator or cron, not on
        // every session start (see the module docs for why it is not automatic).
        "gc" => Some(gc::run(rest).await),
        _ => None,
    }
}

/// Route the team-admin one-shot subcommands, or `None` when `subcommand` is
/// not one of them (the caller falls through to the remaining dispatch).
///
/// These seven share a shape — build the store from config, call into the
/// core membership/rotation flows, exit — so they dispatch as a unit:
/// `publish-membership` (who may WRITE), `join`/`provision` (who may READ),
/// `members` (inspect), `rotate` (the revocation half: reseal future notes
/// away from anyone removed), `remove` (the member-removal runbook: shrunk
/// membership + rotation + the manual sub-token revoke reminder), and
/// `recover` (the founder-key-loss escape hatch: rotate the founder itself
/// through the team's published recovery key).
async fn dispatch_admin(subcommand: &str, rest: &[String]) -> Option<anyhow::Result<()>> {
    match subcommand {
        "publish-membership" => Some(admin::publish_membership(rest).await),
        "provision" => Some(admin::provision(rest).await),
        "join" => Some(admin::join(rest).await),
        "members" => Some(admin::members(rest).await),
        "rotate" => Some(admin::rotate(rest).await),
        "remove" => Some(admin::remove(rest).await),
        "recover" => Some(admin::recover(rest).await),
        _ => None,
    }
}

/// Route the console-feature subcommands — `mint-token` (bare sub-token mint)
/// and `invite` (founder onboarding: mint + paste-ready bundle) — or `None`
/// when `subcommand` is neither.
#[cfg(feature = "console")]
async fn dispatch_console(subcommand: &str, rest: &[String]) -> Option<anyhow::Result<()>> {
    match subcommand {
        "mint-token" => Some(mint::run(rest).await),
        "invite" => Some(invite::run(rest).await),
        _ => None,
    }
}

/// Without the `console` feature the mint machinery is not compiled in. Bail
/// loudly rather than fall through to the server boot, which would silently
/// ignore the subcommand and start reading the MCP stdio protocol — leaving
/// the operator believing they minted a token.
#[cfg(not(feature = "console"))]
#[expect(
    clippy::unused_async,
    reason = "must mirror the console-feature variant's signature so the one call site awaits both"
)]
async fn dispatch_console(subcommand: &str, _rest: &[String]) -> Option<anyhow::Result<()>> {
    match subcommand {
        "mint-token" | "invite" => Some(Err(anyhow::anyhow!(
            "the `{subcommand}` subcommand requires building with `--features console`"
        ))),
        _ => None,
    }
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
/// For a `storage = "local"` profile this also acquires the vault's advisory
/// lock (finding #6): the returned [`VaultLock`] must be kept alive by the
/// caller for as long as it serves this vault, so `hippius-mem upgrade` can
/// detect a live session and refuse to migrate a moving target. `None` for an
/// `S3` profile (no local vault to lock).
///
/// # Errors
///
/// Returns an error if the repo routes to no team profile (memory is
/// disabled here), a local trial vault's advisory lock is already held by
/// another process, or the store cannot be built.
async fn resolve_and_build_store(
    cfg: &Config,
) -> anyhow::Result<(Arc<MemoryStore>, Option<String>, Option<VaultLock>)> {
    let profiles = cfg.all_profiles();
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let remote = GitRemoteReader.origin_url(&cwd);

    let profile = match resolver::resolve(&profiles, remote.as_deref()) {
        Resolution::Bound(profile) => profile,
        Resolution::Disabled(reason) => {
            anyhow::bail!("team memory is disabled for this repository: {reason}");
        }
    };

    // Local trial vaults are solo by design, but the disk is still shared
    // between this server process and a concurrent `hippius-mem upgrade` (or
    // a second `serve` bound to the same vault). Acquire the advisory lock
    // NOW, non-blocking — never wait: this runs before the MCP handshake, and
    // a blocking wait here would reproduce the exact "looks hung" failure the
    // op-log warmup task below was already restructured to avoid.
    let vault_lock = match profile.try_lock_local_vault()? {
        VaultLockAttempt::NotLocal => None,
        VaultLockAttempt::Acquired(lock) => Some(lock),
        VaultLockAttempt::Held => anyhow::bail!(
            "another hippius-mem process already holds the advisory lock on the local trial \
             vault for profile {name:?}; if you are sure nothing else is using it (a crashed \
             process leaves no stale lock — the OS releases it on exit), retry in a moment",
            name = profile.name,
        ),
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

    Ok((
        Arc::new(profile.build_store(cfg).await?),
        launch_repo,
        vault_lock,
    ))
}

// Gated on the whole module, not just the one test inside it: every item here
// (imports, helper, the test itself) exists ONLY to support the offline
// advisory-lock check below. Under `--features embeddings`, `build_store`
// would try to download a model — mirrors
// `config::tests::build_store_uses_fs_backend_for_local_profiles`'s own
// per-test gate, but applied at the module level since this module has no
// OTHER, always-compiled test that would otherwise keep these imports/`expect`s
// alive when embeddings is enabled.
#[cfg(all(test, not(feature = "embeddings")))]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test"
    )]
    #![expect(
        clippy::expect_used,
        reason = "tests assert on hand-built fixtures where construction cannot fail"
    )]

    use crate::config::{Config, StorageBackend};
    use crate::resolve_and_build_store;

    /// A `storage = "local"` primary-profile config over `root` — no `[[teams]]`,
    /// so `resolver::resolve` binds the catch-all primary regardless of this
    /// process's actual git remote (an empty `orgs` normalizes to `catch_all`).
    fn local_config(root: &std::path::Path) -> Config {
        Config {
            team: "trial".to_owned(),
            team_key_hex: "ab".repeat(32),
            author_seed_hex: "cd".repeat(32),
            storage: StorageBackend::Local,
            local_root: Some(root.to_path_buf()),
            ..Config::default()
        }
    }

    /// Finding #6: a second `serve` bind over the SAME local trial vault must
    /// refuse — not silently interleave writes with the first — because it
    /// finds the advisory lock the first bind is still holding.
    #[tokio::test]
    async fn a_second_bind_over_the_same_local_vault_refuses_the_advisory_lock()
    -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let cfg = local_config(dir.path());

        let (_store, _launch_repo, first_lock) = resolve_and_build_store(&cfg).await?;
        assert!(
            first_lock.is_some(),
            "binding a local profile must acquire the vault lock"
        );

        let err = resolve_and_build_store(&cfg)
            .await
            .expect_err("a second bind over the same vault must refuse the held lock");
        assert!(
            err.to_string().contains("already holds"),
            "the refusal must name the collision: {err}"
        );

        Ok(())
    }
}
