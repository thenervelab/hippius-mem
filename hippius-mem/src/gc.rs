//! The `hippius-mem gc` subcommand: reclaim orphaned note-ciphertext blobs.
//!
//! `remember`/`edit` write a note's ciphertext blob BEFORE appending the op that
//! names it (the recoverable-prefix ordering). A write cancelled — or a process
//! killed — between those two steps leaves the blob with no op naming it: an orphan
//! no reader ever surfaces and no other path reclaims, slowly wasting storage (the
//! CANCELSAFETY finding). This command runs the mark-and-sweep
//! [`MemoryStore::sweep_orphan_blobs`] over the routed team's bucket, deleting only
//! blobs the durable op-log proves unreferenced and older than a grace window.
//!
//! Operator- or cron-triggered rather than automatic: the stdio server starts once
//! per session, so a full-keyspace sweep on every start would be wasteful. Running
//! it as an explicit administrative pass keeps the per-session path cheap.

use std::time::Duration;

use anyhow::{Context, bail};

use crate::config::Config;
use crate::resolve_and_build_store;

/// Default grace window in hours. An unreferenced blob younger than this is kept:
/// its op may still be in flight, or the op-log listing may lag its writes. Orphans
/// are permanent and harmless, so a full day trades promptness for zero
/// wrongful-delete risk.
const DEFAULT_GRACE_HOURS: u64 = 24;

const SECS_PER_HOUR: u64 = 3600;

/// Run the `gc` subcommand over the args following `gc`.
///
/// Deliberately does NOT call `admin::bootstrap_epochs`, unlike the store-reading
/// subcommands that decrypt notes: the sweep never opens a ciphertext. It only
/// enumerates op `object_key`s (op-log entries are signed plaintext, verified but
/// never decrypted) and lists/deletes blobs by key, so its referenced set is
/// complete under every team-key epoch without a mnemonic. Bootstrapping here would
/// be dead ceremony that also forces a mnemonic the sweep does not need.
///
/// # Errors
///
/// Returns an error on a malformed argument, missing/malformed configuration, a
/// store that cannot be built, or an op-log read / keyspace listing failure inside
/// the sweep (individual blob deletes are best-effort and never abort the run).
pub(crate) async fn run(args: &[String]) -> anyhow::Result<()> {
    let mut dry_run = false;
    let mut grace_hours = DEFAULT_GRACE_HOURS;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--dry-run" => dry_run = true,
            "--grace-hours" => {
                let raw = rest
                    .next()
                    .context("--grace-hours needs a value, e.g. `--grace-hours 24`")?;
                grace_hours = raw
                    .parse()
                    .with_context(|| format!("invalid --grace-hours value {raw:?}"))?;
                // Refuse a zero window. The grace period is the sweep's ONLY defense
                // against deleting a blob whose op is mid-append: a remember/edit
                // between blob.put and oplog.append whose blob is listed while both
                // op-log reads missed the not-yet-appended op would, at grace 0, be
                // deleted immediately — then the op lands and names a blob that is
                // gone, permanently losing the note body. The window must dominate
                // the worst-case in-flight-write duration plus cross-machine clock
                // skew, so 0 is never safe. `--dry-run` previews without deleting.
                if grace_hours == 0 {
                    bail!(
                        "--grace-hours 0 disables the in-flight-write safety window and can \
                         permanently delete a note whose op is still being appended; use at \
                         least 1 (the default is {DEFAULT_GRACE_HOURS}), or --dry-run to preview"
                    );
                }
            }
            other => {
                bail!("unknown gc argument {other:?}; usage: gc [--dry-run] [--grace-hours N]")
            }
        }
    }

    let cfg = Config::from_env_and_file().context(
        "failed to load configuration; set HIPPIUS_MEM_* env vars or create hippius-mem.toml",
    )?;
    // `gc` reclaims across the whole team keyspace regardless of the launch repo, so
    // the recall-scope default the store carries is irrelevant here.
    // `_vault_lock` (a local trial profile only — see the finding #6 doc on
    // `resolve_and_build_store`) is kept bound so it stays held while `gc` reclaims
    // blobs, released when `run` returns.
    let (store, _launch_repo, _vault_lock) = resolve_and_build_store(&cfg).await?;

    // `saturating_mul` so an absurd `--grace-hours` saturates the window rather than
    // overflowing into a tiny one (which would reap aggressively).
    let grace = Duration::from_secs(grace_hours.saturating_mul(SECS_PER_HOUR));
    let report = store.sweep_orphan_blobs(grace, dry_run).await?;
    tracing::info!(
        note_blobs_scanned = report.note_blobs_scanned,
        orphans_found = report.orphans_found,
        orphans_reclaimed = report.orphans_reclaimed,
        within_grace_kept = report.within_grace_kept,
        grace_hours,
        dry_run,
        "orphan-blob sweep complete"
    );
    Ok(())
}
