#![forbid(unsafe_code)]
//! Hippius Memory MCP server binary entry point.
//!
//! Serves the ten memory tools (`remember` / `recall` / `get` / `refresh` /
//! `forget` / `redact` / `link` / `edit` / `history` / `reconcile`) over stdio, backed by
//! the real S3-backed [`MemoryStore`](hippius_mem_core::MemoryStore) built from configuration (a TOML file
//! and/or `HIPPIUS_MEM_*` environment variables). It also dispatches the
//! `quickstart` zero-decision local trial onboarding subcommand, the `doctor`
//! bundle-validation subcommand, the `publish-membership` team-admin
//! subcommand, the `init`/`install` agent-provisioning subcommands (and,
//! under the `console` feature, `mint-token`/`invite`) before falling through
//! to serving.
//! Diagnostics go to stderr via `tracing` so stdout stays a clean MCP protocol
//! channel.

mod admin;
mod brief;
mod bundle;
mod calendar;
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
mod logging;
#[cfg(feature = "console")]
mod mint;
mod quickstart;
mod report;
mod resolver;
mod setup;
mod upgrade;

use std::sync::Arc;

use anyhow::Context;
use hippius_mem::server::{MemoryServer, WriteRoleGuard};
use hippius_mem_core::MemoryStore;
use rmcp::ServiceExt;
use rmcp::transport::stdio;

use crate::config::{Config, TeamProfile, VaultLock, VaultLockAttempt};
use crate::resolver::{GitRemoteReader, RemoteReader, Resolution};

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
  hippius-mem init                     provision this repo (CLAUDE.md, AGENTS.md, hooks)
  hippius-mem install [--agent <name[,name...]>] [--all-detected]
                                       user-global MCP registration (Claude by
                                       default; --agent names more clients;
                                       --all-detected adds those already on disk).
                                       Does not install the binary — scripts/install.sh
                                       or cargo install does that
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
  hippius-mem join [--bundle [<path|->] [--orgs <host/org,...>]]
                                       join a team: consume a founder's invite bundle
                                       (writes the local config, then publishes this
                                       member's key when HIPPIUS_MEM_MNEMONIC is set);
                                       `--bundle` with no path prompts on the terminal —
                                       just paste the bundle, then Ctrl-D on an empty
                                       line (easiest); a piped stdin
                                       reads to EOF like `--bundle -`; bare `join` only
                                       publishes the member key
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
  hippius-mem admin quarantine [--remove <object-key> [--yes]]
                                       inspect a persistent op-log quarantine (fork
                                       vs gap, per dropped op), or delete ONE
                                       fork-losing op object behind safety rails;
                                       --remove without --yes prints the plan only
                                       (dry-run)
  hippius-mem admin resign-anchors     re-sign this author's own legacy (unsigned)
                                       anchor records in place so reconcile's
                                       unsigned_anchor_records gauge can reach 0;
                                       every member runs it, then
                                       require_signed_anchors is safe to enable
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
    logging::init_stderr()?;

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

    let cfg = Config::from_env_and_file().context(crate::config::CONFIG_LOAD_HELP)?;

    // Route the launch repo to a team profile and build its store. The `dashboard`
    // subcommand resolves through the SAME helper, so the two paths can never bind a
    // different profile from one directory (the git-remote routing must stay identical).
    // `resolve_and_build_store` itself never touches the vault lock (see its doc) —
    // the one-shot commands sharing it (`brief`/`gc`/`report`/`import`) bind the
    // returned `profile` too but never lock with it.
    let (store, launch_repo, profile) = resolve_and_build_store(&cfg).await?;

    // Acquire the local trial vault's advisory locks for `serve`'s WHOLE
    // process lifetime (finding #6, amended by the N-reader-1-writer split):
    // the shared liveness lock is what lets `hippius-mem upgrade` detect a
    // live session — reader or writer — and refuse to migrate a moving
    // target, and the exclusive writer lock decides whether THIS session
    // STARTS with the write role or serves read-only until it wins a
    // re-contest (see `with_read_only_vault` below and
    // `write_role_contest`). This is a `serve`-ONLY step — deliberately not folded into
    // `resolve_and_build_store` — because the one-shot commands sharing that
    // helper must NOT hold these locks: the op-log is a concurrent
    // multi-writer design (ops are distinct, lamport-ordered objects), `gc`'s
    // deletes are idempotent best-effort housekeeping, and those commands are
    // transient, so none of them conflict with a live `serve` session in any
    // data-losing way. A prior fix briefly made them lock too (finding #6's
    // mechanical ripple), which regressed `report`/`brief`/`gc`/`import` to
    // refuse outright whenever a Claude Code session was already bound to the
    // same local vault — a real availability regression for exactly the trial
    // population this path targets. `vault_binding` is kept bound (not
    // `let _ = `, which would drop — and so release — the flocks immediately)
    // so they stay held for the rest of `main`, until process exit releases
    // them.
    let vault_binding = acquire_serve_vault_lock(&profile)?;

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
        // `sync_recording_watermark` (below) does the same replay a bare `sync`
        // would, but ALSO records the op-count watermark this replay converged
        // to, so the first post-warmup read's `refresh_if_stale` skips repeating
        // this EXPENSIVE full sync when nothing changed — a bare `sync` here
        // left that watermark unset, so the first post-warmup read always paid
        // a second full sync purely to establish it, doubling cold-start
        // latency (session-start recalls are hook-mandated). The recorded
        // watermark is captured BEFORE this replay runs, not after, so it can
        // never claim a tip AHEAD of what the replay actually converged; the
        // first post-warmup read still pays one cheap op-log listing probe
        // (never skipped), which is what notices — and syncs in — any write
        // that lands between this call and that read. See
        // `sync_recording_watermark`'s doc for the full reasoning.
        match warmup_store.sync_recording_watermark().await {
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

    // Bind the launch repo so an omitted-`repo` recall falls back to it (finding:
    // a default recall must not silently exclude this repo's notes). No remote /
    // local-only checkout leaves `launch_repo` None, keeping the global-only default.
    let mut server = MemoryServer::with_warmup(store, warm_rx);
    if let Some(repo) = launch_repo {
        server = server.with_default_repo(repo);
    }
    // Best-effort launch-repo provisioning (heal, auto-init, or nudge) — see
    // `provision_and_nudge`. Never fatal: provisioning must not stop serving.
    server = provision_and_nudge(&cfg, server);
    // A binding without the write role means another live session owned the
    // trial vault's writes AT BOOT: serve READ-ONLY — write tools refuse
    // in-band with an actionable message, reads work — instead of the
    // pre-split behavior of refusing to boot at all, which left every
    // concurrent Claude Code session but the first with NO memory and the
    // reason buried in MCP logs. Not read-only for life, though: the server
    // re-contests the role via the closure below on every write attempt, so
    // once the boot-time winner exits, the next write here simply takes the
    // role and succeeds (see `write_role_contest`).
    if vault_binding
        .as_ref()
        .is_some_and(ServeVaultBinding::is_read_only)
    {
        let profile_name = profile.name.clone();
        server = server.with_read_only_vault(profile_name, write_role_contest(profile));
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

/// Run boot-time launch-repo provisioning and thread its outcome into the
/// server: refresh a provisioned repo's rules blocks (and repair broken hook
/// pairs), auto-provision an un-provisioned repo when — and only when — the
/// config's `auto_init` standing consent says so, and otherwise attach the
/// rendered provisioning note (nudge, or the honest refusal/failure reason)
/// to the MCP handshake instructions.
///
/// The note rides the handshake because that is the one channel every client
/// (not just Claude Code) reads: any agent can act on it by running
/// `hippius-mem init`, which writes `AGENTS.md` for non-Claude agents too.
/// `cfg.source_path` is threaded through so the nudge names the config file
/// the server actually loaded (a generic "hippius-mem.toml" is never read by
/// the MCP server, whose registration pins `HIPPIUS_MEM_CONFIG`). Split out
/// of `main` (like the `dispatch_*` helpers) to keep `main` under the
/// line-count budget.
fn provision_and_nudge(cfg: &Config, server: MemoryServer) -> MemoryServer {
    let policy = setup::ServeProvisionPolicy {
        auto_init: cfg.auto_init,
        config_source: cfg.source_path.clone(),
    };
    let outcome = setup::provision_on_serve(&policy);
    match setup::provisioning_nudge_text(&outcome, policy.config_source.as_deref()) {
        Some(nudge) => server.with_provisioning_nudge(nudge),
        None => server,
    }
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
/// These share a shape — build the store from config, call into the core
/// flows, exit — so they dispatch as a unit: `publish-membership` (who may
/// WRITE), `join`/`provision` (who may READ), `members` (inspect), `rotate`
/// (the revocation half: reseal future notes away from anyone removed),
/// `remove` (the member-removal runbook: shrunk membership + rotation + the
/// manual sub-token revoke reminder), `recover` (the founder-key-loss escape
/// hatch: rotate the founder itself through the team's published recovery
/// key), and the `admin` maintenance namespace (`admin quarantine`: inspect a
/// persistent op-log quarantine and, behind safety rails, remove a
/// fork-losing op object; `admin resign-anchors`: re-sign this author's own
/// legacy unsigned anchor records so the strict-mode readiness gauge can
/// reach 0).
async fn dispatch_admin(subcommand: &str, rest: &[String]) -> Option<anyhow::Result<()>> {
    match subcommand {
        "publish-membership" => Some(admin::publish_membership(rest).await),
        "provision" => Some(admin::provision(rest).await),
        "join" => Some(admin::join(rest).await),
        "members" => Some(admin::members(rest).await),
        "rotate" => Some(admin::rotate(rest).await),
        "remove" => Some(admin::remove(rest).await),
        "recover" => Some(admin::recover(rest).await),
        "admin" => Some(admin::admin(rest).await),
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
/// Shared by the MCP server boot (`main`) and the one-shot commands
/// (`brief`/`gc`/`report`/`import`) so none of them can resolve a DIFFERENT
/// profile from the same directory — the git-remote routing (profile match,
/// disabled-on-no-match) must stay identical across every entry point.
///
/// It stops at "store built": epoch-key bootstrap and the op-log sync are
/// deliberately left to each caller because their PLACEMENT differs. The server
/// runs both inside a background warmup task so the MCP handshake returns before
/// the slow op-log replay (the PR #24 fix); the dashboard runs them in the
/// foreground, having no handshake deadline. Folding either into this helper would
/// regress that separation, so the shared code ends here.
///
/// Deliberately never touches the local trial vault's advisory locks.
/// Acquiring — and, critically, HOLDING — them is a `serve`-ONLY concern
/// ([`acquire_serve_vault_lock`], called by `main` right after this returns):
/// the op-log is a concurrent multi-writer design (ops are distinct,
/// lamport-ordered objects), `gc`'s deletes are idempotent best-effort
/// housekeeping, and the one-shot commands sharing this helper are transient,
/// so none of them conflict with a live `serve` session in any data-losing way.
/// A prior fix briefly made them lock too (finding #6's mechanical ripple into
/// `brief`/`gc`/`report`/`import`), which regressed those commands to refuse
/// outright whenever a Claude Code session (`serve`) was already bound to the
/// same local vault — a real availability regression for exactly the trial
/// population this path targets. The returned [`TeamProfile`] lets `main` take
/// the serve-only locks without re-resolving the profile.
///
/// # Errors
///
/// Returns an error if the repo routes to no team profile (memory is
/// disabled here) or the store cannot be built.
async fn resolve_and_build_store(
    cfg: &Config,
) -> anyhow::Result<(Arc<MemoryStore>, Option<String>, TeamProfile)> {
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

    let store = Arc::new(profile.build_store(cfg).await?);
    // Cloned (not moved) because `profile` only borrows from the `profiles`
    // Vec above (`resolver::resolve`'s return borrows its input slice); the
    // clone is what lets `main` take the serve-only lock afterward without
    // re-resolving.
    Ok((store, launch_repo, profile.clone()))
}

/// The advisory locks a local-trial-vault `serve` holds for its WHOLE process
/// lifetime, and the access mode they grant this session.
///
/// Both are non-blocking flocks inside the vault root, so a crashed session
/// releases everything the moment its process exits — no stale-lock cleanup
/// path exists or is needed.
#[derive(Debug)]
struct ServeVaultBinding {
    /// SHARED liveness flock (`{root}/.live.lock`): held by EVERY session,
    /// writer and read-only alike, so `upgrade`'s exclusive liveness probe
    /// fails while ANY session lives — a live reader must block a migration
    /// just as hard as a live writer, or the vault would be copied and the
    /// config flipped out from under it.
    _liveness: VaultLock,
    /// EXCLUSIVE write-role flock (the pre-split `{root}/.lock` file):
    /// `Some` grants this session read-write; `None` means another live
    /// session (possibly an OLDER binary's `serve`, which holds only this
    /// file) owned the write role at boot and this session STARTS read-only
    /// — its write tools refuse in-band while reads keep working. That
    /// boot-time outcome is not for life: the server re-contests the role
    /// on every write attempt ([`write_role_contest`]) and, on winning,
    /// parks the won flock inside its own state — this field stays `None`,
    /// so a `None` here means "did not win AT BOOT", not "read-only now".
    ///
    /// Scope of the role either way: it guards op-log APPENDS only. A
    /// read-only session still writes the vault on every sync — it
    /// PUTs/prunes `{team}/_snapshots/` checkpoint objects (refresh tool,
    /// pre-read auto-refresh, boot warmup), which are concurrent-writer-safe
    /// by design (atomic temp+fsync+rename puts, idempotent prunes) — so
    /// the invariant this lock guarantees is "at most one op-log appender",
    /// not "one vault writer of any kind".
    writer: Option<VaultLock>,
}

impl ServeVaultBinding {
    /// Whether this session lost the BOOT-TIME write-role race and starts
    /// read-only (it may still win the role later — see
    /// [`write_role_contest`]).
    fn is_read_only(&self) -> bool {
        self.writer.is_none()
    }
}

/// Build the re-contest closure a read-only `serve` hands the server: one
/// NON-BLOCKING attempt to take `profile`'s write-role flock, run by
/// `MemoryServer::require_writable` on each write attempt while the session
/// is still read-only.
///
/// This is what retires the role-for-life behavior: the boot-time loser used
/// to refuse writes forever while `{root}/.lock` sat free after the winner
/// exited, and its refusal text directed the agent to a session that might
/// no longer exist. A session that wins here behaves exactly like a
/// boot-time writer — the closure returns the very [`VaultLock`] a boot-time
/// winner would hold (type-erased into a [`WriteRoleGuard`], because the
/// server's `[lib]` crate cannot name this binary crate's lock type), and
/// the server parks it until process exit. The liveness lock is unaffected:
/// `main`'s [`ServeVaultBinding`] keeps holding it shared regardless of who
/// owns the write role.
///
/// Race-safe with no extra ceremony: the flock has a single exclusive
/// winner (two read-only sessions contesting at once cannot both acquire),
/// and the op-log `WriterLock` independently serializes appends.
///
/// Failure shape: an `Err` from the lock probe (vault dir vanished,
/// permissions) maps to `None` — "stay read-only for this attempt" — with a
/// WARN, because refusing one write is strictly safer than promoting on an
/// unprobed lock.
fn write_role_contest(
    profile: TeamProfile,
) -> impl Fn() -> Option<WriteRoleGuard> + Send + 'static {
    move || match profile.try_lock_vault_writer() {
        Ok(VaultLockAttempt::Acquired(lock)) => Some(Box::new(lock) as WriteRoleGuard),
        // Held: the role is still owned elsewhere. NotLocal is unreachable
        // in practice — this closure is only built for a profile whose
        // boot-time lock attempts already reported Local, and a profile's
        // storage backend never changes mid-process — but matched explicitly
        // (not wildcarded) so a future storage variant cannot silently fall
        // through. Both mean "did not win": promoting without a held lock
        // is the one wrong answer.
        Ok(VaultLockAttempt::Held | VaultLockAttempt::NotLocal) => None,
        Err(error) => {
            tracing::warn!(
                %error,
                profile = %profile.name,
                "write-role re-contest could not probe the vault lock; staying read-only \
                 for this attempt"
            );
            None
        }
    }
}

/// Acquire the local trial vault's advisory locks for `serve`'s WHOLE process
/// lifetime — a `serve`-ONLY step; see [`resolve_and_build_store`]'s doc for
/// why the one-shot commands sharing that helper must never call this.
///
/// Non-blocking (never waits): this runs before the MCP handshake, and a
/// blocking wait here would reproduce the exact "looks hung" failure the
/// op-log warmup task below was already restructured to avoid. `None` for an
/// `S3` profile — no local vault to lock.
///
/// # Errors
///
/// Returns an error if the vault's liveness lock is held exclusively (an
/// `upgrade` is migrating this vault), or the write-role lock is held by
/// another process.
fn acquire_serve_vault_lock(profile: &TeamProfile) -> anyhow::Result<Option<ServeVaultBinding>> {
    // Liveness FIRST: registering as a live session is what makes `upgrade`
    // refuse to migrate underneath us, so nothing else may happen before it.
    // Both takes are non-blocking, so the ordering against `upgrade`'s
    // (liveness-then-writer, the same order) is a UX concern, not a deadlock
    // one — whichever side loses a race simply refuses or degrades.
    let liveness = match profile.try_lock_vault_liveness_shared()? {
        VaultLockAttempt::NotLocal => return Ok(None),
        VaultLockAttempt::Acquired(lock) => lock,
        // A SHARED take only fails against an EXCLUSIVE holder, and the only
        // exclusive taker of the liveness file is `upgrade` mid-migration:
        // this vault's objects are being copied out and its config is about
        // to flip, so binding it even read-only would serve doomed state.
        VaultLockAttempt::Held => anyhow::bail!(
            "the local trial vault for profile {name:?} is being migrated by a running \
             `hippius-mem upgrade` (its liveness lock is held exclusively); wait for the \
             upgrade to finish, then start this session again (a crashed process leaves no \
             stale lock — the OS releases it on exit)",
            name = profile.name,
        ),
    };

    match profile.try_lock_vault_writer()? {
        // Unreachable in practice — the same profile just reported Local for
        // the liveness take — but matched explicitly rather than wildcarded
        // so a future storage variant cannot silently fall through.
        VaultLockAttempt::NotLocal => anyhow::bail!(
            "internal error: profile {name:?} reported a local vault for the liveness lock \
             but not for the writer lock",
            name = profile.name,
        ),
        VaultLockAttempt::Acquired(lock) => Ok(Some(ServeVaultBinding {
            _liveness: liveness,
            writer: Some(lock),
        })),
        // The write role is taken: another live session got there first (or
        // an OLDER binary's `serve` holds the pre-split exclusive lock).
        // Degrade to READ-ONLY instead of refusing — concurrent Claude Code
        // sessions are the norm for agentic work, and refusing here left
        // every session but the first with NO memory at all, visible only in
        // MCP logs. The shared liveness lock above is still held, so
        // `upgrade` keeps refusing while this reader lives; the in-band
        // write-tool refusal lives in `MemoryServer` (see
        // `with_read_only_vault`), which is what the agent actually sees,
        // and it re-contests this lock per write attempt
        // (`write_role_contest`), so the degradation lasts only as long as
        // the current holder does.
        VaultLockAttempt::Held => {
            tracing::warn!(
                profile = %profile.name,
                "another live session holds the trial vault's write lock; serving READ-ONLY \
                 (write tools will refuse in-band; reads work)"
            );
            Ok(Some(ServeVaultBinding {
                _liveness: liveness,
                writer: None,
            }))
        }
    }
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
    use crate::{acquire_serve_vault_lock, resolve_and_build_store};

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

    /// Finding #6, as amended by the N-reader-1-writer split: a second
    /// `serve` bind over the SAME local trial vault must boot READ-ONLY —
    /// not refuse outright (concurrent Claude Code sessions are the norm for
    /// agentic work, and "no memory at all for every session but the first"
    /// was a real availability failure), and not silently interleave writes
    /// with the first either. The original no-silent-interleaving property
    /// survives as "the write role is granted to at most one live session":
    /// every later bind comes back read-only, and the server refuses its
    /// write tools in-band (pinned by the `server.rs` read-only tests).
    /// Exercised via `acquire_serve_vault_lock` directly (the serve-only
    /// step), since `resolve_and_build_store` itself never touches the locks
    /// — see the regression test right below this one.
    #[tokio::test]
    async fn a_second_bind_over_the_same_local_vault_boots_read_only() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let cfg = local_config(dir.path());

        let (_store, _launch_repo, profile) = resolve_and_build_store(&cfg).await?;
        let first = acquire_serve_vault_lock(&profile)?
            .expect("binding a local profile must acquire the vault locks");
        assert!(
            !first.is_read_only(),
            "the first bind must win the write role"
        );

        let second = acquire_serve_vault_lock(&profile)?
            .expect("a second bind over the same vault must still return a binding");
        assert!(
            second.is_read_only(),
            "a second concurrent bind must degrade to read-only, never claim the write role"
        );

        // The write role is never granted twice: with the first session still
        // live, EVERY later bind is read-only, not just the second.
        let third = acquire_serve_vault_lock(&profile)?
            .expect("a third bind over the same vault must still return a binding");
        assert!(
            third.is_read_only(),
            "the write role must stay with the first live session"
        );

        // Once every session has exited (locks drop with the bindings), a
        // fresh bind wins the write role again — nothing stale survives.
        //
        // "Again" is EVENTUAL, not instant, inside this test process: an flock
        // is released only when every duplicate of its file description
        // closes, and a concurrent test thread spawning a child (plenty of
        // tests here shell out to `git`) can transiently duplicate ALL open
        // fds — these lock fds included — until the child's exec completes.
        // Whether that window exists is platform- and spawn-shape-specific:
        // on Linux it always does (glibc's posix_spawn is clone+exec, and
        // the O_CLOEXEC these fds carry closes them only AT the exec), while
        // on macOS the kernel's posix_spawn syscall never materializes
        // O_CLOEXEC fds in the child at all, so the window opens only for
        // the Command shapes std must fall back to classic fork+exec for. A
        // single immediate re-take therefore flakes read-only roughly once
        // per ten full-suite runs where the window applies. The bounded
        // retry keeps the property honest (the role frees on drop, with no
        // stale-lock path) without asserting an instant release the OS never
        // promised.
        drop(first);
        drop(second);
        drop(third);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let fresh = loop {
            let bind = acquire_serve_vault_lock(&profile)?
                .expect("a bind over a vault with no live sessions must acquire the locks");
            if !bind.is_read_only() || std::time::Instant::now() >= deadline {
                break bind;
            }
            drop(bind);
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert!(
            !fresh.is_read_only(),
            "the write role must be free again once every earlier session exited"
        );

        Ok(())
    }

    /// The re-contest closure over REAL flocks (the unit half lives in
    /// `server.rs`, which fakes the contest): it must LOSE while any holder
    /// lives, WIN once every holder exited, and — the "wins means writer"
    /// property — hold the very lock a boot-time winner would, so a fresh
    /// bind sees the role taken again.
    #[tokio::test]
    async fn the_write_role_contest_wins_only_after_every_holder_exits() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let cfg = local_config(dir.path());

        let (_store, _launch_repo, profile) = resolve_and_build_store(&cfg).await?;
        let boot_winner = acquire_serve_vault_lock(&profile)?
            .expect("binding a local profile must acquire the vault locks");

        let contest = crate::write_role_contest(profile.clone());
        assert!(
            contest().is_none(),
            "the re-contest must lose while the boot-time writer lives"
        );

        drop(boot_winner);
        // EVENTUALLY winnable, not instantly — the same fork+exec fd-window
        // tolerance as `a_second_bind_over_the_same_local_vault_boots_read_only`
        // (see the full platform note there).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let won = loop {
            if let Some(guard) = contest() {
                break Some(guard);
            }
            if std::time::Instant::now() >= deadline {
                break None;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        let won = won.expect("the re-contest must win once every holder exited");

        // A re-contest winner is indistinguishable from a boot-time writer:
        // while the won guard lives, a fresh serve bind loses the role.
        let later_bind =
            acquire_serve_vault_lock(&profile)?.expect("a later bind must still return a binding");
        assert!(
            later_bind.is_read_only(),
            "a fresh bind must see the re-contest winner holding the write role"
        );

        drop(won);
        Ok(())
    }

    /// Locks are per-vault: a live writer session on one trial vault must not
    /// demote a session over a DIFFERENT vault root to read-only.
    #[tokio::test]
    async fn vault_bindings_do_not_contend_across_different_vault_roots() -> anyhow::Result<()> {
        let dir_a = tempfile::tempdir()?;
        let dir_b = tempfile::tempdir()?;
        let cfg_a = local_config(dir_a.path());
        let cfg_b = local_config(dir_b.path());

        let (_store_a, _repo_a, profile_a) = resolve_and_build_store(&cfg_a).await?;
        let (_store_b, _repo_b, profile_b) = resolve_and_build_store(&cfg_b).await?;

        let _first =
            acquire_serve_vault_lock(&profile_a)?.expect("binding vault A must acquire its locks");
        let other = acquire_serve_vault_lock(&profile_b)?
            .expect("binding vault B must acquire its own locks");
        assert!(
            !other.is_read_only(),
            "vault B's bind must win its own write role while vault A's writer is live"
        );

        Ok(())
    }

    /// Preserved property (not new behavior — under the pre-split single
    /// lock, `serve` also refused while `upgrade` held it): a `serve` bind
    /// must refuse outright while an `upgrade` holds the liveness lock
    /// exclusively, because the vault's objects are being copied out and the
    /// config is about to flip — binding it even read-only would serve
    /// doomed state.
    #[tokio::test]
    async fn a_serve_bind_refuses_while_an_upgrade_holds_the_liveness_lock() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let cfg = local_config(dir.path());

        let (_store, _launch_repo, profile) = resolve_and_build_store(&cfg).await?;
        // Simulate `hippius-mem upgrade` mid-migration: it holds the liveness
        // lock exclusively for the whole copy + config rewrite.
        let _migrating = profile.try_lock_vault_liveness_exclusive()?;

        let err = acquire_serve_vault_lock(&profile)
            .expect_err("a serve bind must refuse while an upgrade owns the vault");
        assert!(
            err.to_string().contains("upgrade"),
            "the refusal must name the migration as the cause: {err}"
        );

        Ok(())
    }

    /// Regression test for the finding-#6 fix-batch ripple: `report`/`brief`/
    /// `gc`/`import` share `resolve_and_build_store`, so a prior version of
    /// this function that acquired the vault lock unconditionally made every
    /// one of them refuse while a live `serve` session held it — an
    /// availability regression for local trial vaults. `resolve_and_build_store`
    /// must never contend with a held vault lock: a second caller building a
    /// store over the same vault (mirroring a one-shot command run alongside a
    /// live `serve`) must succeed even while `acquire_serve_vault_lock` (the
    /// serve-only step) holds it.
    #[tokio::test]
    async fn resolve_and_build_store_never_contends_with_the_vault_lock() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let cfg = local_config(dir.path());

        let (_store, _launch_repo, profile) = resolve_and_build_store(&cfg).await?;
        // Simulate a live `serve` session already bound to this vault.
        let _held = acquire_serve_vault_lock(&profile)?;

        resolve_and_build_store(&cfg)
            .await
            .map(|_| ())
            .expect("resolve_and_build_store must never contend with a held vault lock");

        Ok(())
    }
}
