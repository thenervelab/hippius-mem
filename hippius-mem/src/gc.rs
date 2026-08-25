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

    let cfg = Config::from_env_and_file().context(crate::config::CONFIG_LOAD_HELP)?;
    // `gc` reclaims across the whole team keyspace regardless of the launch repo, so
    // the recall-scope default the store carries is irrelevant here.
    // `resolve_and_build_store` never touches the local trial vault's advisory
    // lock (see its doc): `gc`'s deletes are idempotent best-effort housekeeping
    // against a concurrent multi-writer op-log, so it must succeed even while a
    // live `serve` session holds that lock. `_profile` is unused here — only
    // `serve` needs it, to take that lock.
    let (store, _launch_repo, _profile) = resolve_and_build_store(&cfg).await?;

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

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test, not a crash to avoid"
    )]

    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;
    use std::time::Duration;

    use hippius_mem_core::{
        BlobStore, HashEmbedder, InMemoryIndex, MemError, MemoryBlobStore, MemoryStore,
        NetworkPrefix, NoopAnchor, NoteId, NoteType, OpLogStore, RememberInput, RepoScope, Scope,
        SecretKey, Signer, Sr25519Signer, object_key,
    };

    use super::run;

    /// `NoopAnchor` makes anchoring inert regardless of the threshold; a value no
    /// single test's handful of writes ever reaches just keeps the batching
    /// machinery from engaging mid-test.
    const ANCHOR_THRESHOLD: usize = 1000;

    /// Milliseconds since the Unix epoch, for stamping a version ULID's timestamp
    /// deliberately in the past (past-grace) or leaving it at "now" (within-grace).
    /// `unwrap_or` (not `unwrap`/`expect`, both denied/warned-as-error here) covers
    /// the practically-unreachable pre-epoch-clock case with a harmless zero.
    fn now_millis() -> u64 {
        let since_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        u64::try_from(since_epoch.as_millis()).unwrap_or(u64::MAX)
    }

    /// A signer whose author SS58 decodes back to its own signing key, matching the
    /// binding every op-log append checks — real store or not.
    fn test_signer(seed: u8) -> Result<Sr25519Signer, MemError> {
        Sr25519Signer::from_seed_with_prefix(&[seed; 32], NetworkPrefix::HIPPIUS)
    }

    /// An in-memory, network-free [`MemoryStore`] plus the [`BlobStore`] handle it
    /// was built over, so a test can plant a blob directly (bypassing `remember` and
    /// so the op-log, the exact CANCELSAFETY shape `sweep_orphan_blobs` reclaims) or
    /// check a key's presence after a sweep. This is the seeded `MemoryBlobStore`
    /// `gc::run` delegates every mark/sweep decision to via
    /// [`MemoryStore::sweep_orphan_blobs`] — `gc.rs` itself has no decision logic of
    /// its own beyond the CLI arg parsing exercised separately below.
    fn build_gc_test_store(team: &str) -> Result<(MemoryStore, Arc<dyn BlobStore>), MemError> {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let index = Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default())));
        let oplog = OpLogStore::new(blob.clone());
        let signer: Arc<dyn Signer> = Arc::new(test_signer(9)?);
        let store = MemoryStore::new(
            blob.clone(),
            index,
            oplog,
            Arc::new(NoopAnchor),
            signer,
            BTreeMap::from([(0_u64, SecretKey::from_bytes([3u8; 32]))]),
            0,
            team.to_owned(),
            ANCHOR_THRESHOLD,
        );
        Ok((store, blob))
    }

    /// Plant an orphan note-ciphertext blob directly on `blob` under `team`,
    /// stamped with the given version-ULID timestamp — never through `remember`, so
    /// no op ever names it. The bytes are arbitrary: the sweep only ever lists and
    /// deletes by key, never decrypts (see `run`'s own doc on why it skips
    /// `admin::bootstrap_epochs`).
    async fn plant_orphan_blob(
        blob: &Arc<dyn BlobStore>,
        team: &str,
        version_ms: u64,
    ) -> Result<String, MemError> {
        let scope = Scope {
            team: team.to_owned(),
            repo: RepoScope::Repo("thebrain".to_owned()),
        };
        let key = object_key(
            &scope,
            NoteId::new(),
            hippius_mem_core::Ulid::from_parts(version_ms, 0),
        )?;
        blob.put(&key, b"orphan ciphertext".to_vec()).await?;
        Ok(key)
    }

    #[tokio::test]
    async fn orphan_blob_past_grace_is_swept() -> anyhow::Result<()> {
        let team = "gc-test-orphan-past-grace";
        let (store, blob) = build_gc_test_store(team)?;

        let past_ms = now_millis().saturating_sub(48 * 60 * 60 * 1000);
        let key = plant_orphan_blob(&blob, team, past_ms).await?;
        assert!(
            blob.get(&key).await.is_ok(),
            "the orphan blob must exist before the sweep runs"
        );

        let report = store
            .sweep_orphan_blobs(Duration::from_hours(24), false)
            .await?;

        assert_eq!(report.note_blobs_scanned, 1);
        assert_eq!(
            report.orphans_found, 1,
            "the unreferenced, past-grace blob must be found as an orphan"
        );
        assert_eq!(
            report.orphans_reclaimed, 1,
            "the orphan must actually be deleted, not just counted"
        );
        assert_eq!(report.within_grace_kept, 0);
        assert!(
            blob.get(&key).await.is_err(),
            "an unreferenced, past-grace blob must be swept (deleted)"
        );
        Ok(())
    }

    #[tokio::test]
    async fn orphan_blob_within_grace_is_kept() -> anyhow::Result<()> {
        let team = "gc-test-orphan-within-grace";
        let (store, blob) = build_gc_test_store(team)?;

        // "Now": an in-flight write's op may not have appended yet, or the op-log
        // listing may lag its write, so this must survive the sweep untouched.
        let key = plant_orphan_blob(&blob, team, now_millis()).await?;

        let report = store
            .sweep_orphan_blobs(Duration::from_hours(24), false)
            .await?;

        assert_eq!(report.orphans_found, 0);
        assert_eq!(report.orphans_reclaimed, 0);
        assert_eq!(
            report.within_grace_kept, 1,
            "a young unreferenced blob must be counted as kept-for-grace"
        );
        assert!(
            blob.get(&key).await.is_ok(),
            "a blob younger than the grace window must be kept, not swept"
        );
        Ok(())
    }

    /// The safety-critical direction: a blob a live note's durable op still names
    /// must never be deleted, even at the most aggressive grace setting `run`'s own
    /// `--grace-hours 0` guard refuses to allow through the CLI. Exercises the
    /// keep/delete decision on BOTH a referenced and an unreferenced blob in the
    /// same sweep, so it also proves gc actually distinguishes them rather than
    /// merely keeping (or merely deleting) everything.
    #[tokio::test]
    async fn referenced_live_blob_is_kept_while_a_true_orphan_beside_it_is_swept()
    -> anyhow::Result<()> {
        let team = "gc-test-referenced-vs-orphan";
        let (store, blob) = build_gc_test_store(team)?;

        let live_id = store
            .remember(RememberInput {
                note_type: NoteType::Decision,
                repo: RepoScope::Repo("thebrain".to_owned()),
                tags: BTreeSet::new(),
                summary: "gc must never delete a blob a live note points at".to_owned(),
                body: "the safety-critical direction for the mark-and-sweep".to_owned(),
                force: true,
            })
            .await?;

        let past_ms = now_millis().saturating_sub(48 * 60 * 60 * 1000);
        let orphan_key = plant_orphan_blob(&blob, team, past_ms).await?;

        let report = store.sweep_orphan_blobs(Duration::ZERO, false).await?;

        assert_eq!(report.note_blobs_scanned, 2);
        assert_eq!(
            report.orphans_found, 1,
            "only the true orphan is unreferenced"
        );
        assert_eq!(report.orphans_reclaimed, 1);

        // The live note is still fully retrievable — its ciphertext blob, and the
        // op naming it, were never touched.
        let note = store.get(live_id).await?;
        assert_eq!(
            note.summary,
            "gc must never delete a blob a live note points at"
        );

        assert!(
            blob.get(&orphan_key).await.is_err(),
            "the unreferenced blob beside the live note must still be swept"
        );
        Ok(())
    }

    #[tokio::test]
    async fn dry_run_finds_an_orphan_but_deletes_nothing() -> anyhow::Result<()> {
        let team = "gc-test-dry-run";
        let (store, blob) = build_gc_test_store(team)?;

        let past_ms = now_millis().saturating_sub(48 * 60 * 60 * 1000);
        let key = plant_orphan_blob(&blob, team, past_ms).await?;

        let report = store
            .sweep_orphan_blobs(Duration::from_hours(24), true)
            .await?;

        assert_eq!(report.orphans_found, 1, "dry-run still counts the orphan");
        assert_eq!(report.orphans_reclaimed, 0, "dry-run must never delete");
        assert!(
            blob.get(&key).await.is_ok(),
            "dry-run must leave the orphan blob in place"
        );
        Ok(())
    }

    // ---- `run`'s own arg-parsing logic ----
    //
    // Each of these bails before `Config::from_env_and_file`/
    // `resolve_and_build_store` ever runs (see `run`'s own source), so they need no
    // configuration or store — they exercise the one piece of decision logic that
    // actually lives in this file rather than in `sweep_orphan_blobs`.

    #[tokio::test]
    async fn run_rejects_a_zero_grace_window() -> anyhow::Result<()> {
        match run(&["--grace-hours".to_owned(), "0".to_owned()]).await {
            Err(err) => {
                assert!(
                    err.to_string()
                        .contains("disables the in-flight-write safety window"),
                    "the error must explain why 0 is refused, got: {err}"
                );
                Ok(())
            }
            Ok(()) => Err(anyhow::anyhow!(
                "--grace-hours 0 must be refused, but run() succeeded"
            )),
        }
    }

    #[tokio::test]
    async fn run_rejects_an_unknown_argument() -> anyhow::Result<()> {
        match run(&["--not-a-real-flag".to_owned()]).await {
            Err(err) => {
                assert!(
                    err.to_string().contains("unknown gc argument"),
                    "got: {err}"
                );
                Ok(())
            }
            Ok(()) => Err(anyhow::anyhow!("an unknown argument must be refused")),
        }
    }

    #[tokio::test]
    async fn run_rejects_a_grace_hours_flag_with_no_value() -> anyhow::Result<()> {
        match run(&["--grace-hours".to_owned()]).await {
            Err(err) => {
                assert!(err.to_string().contains("needs a value"), "got: {err}");
                Ok(())
            }
            Ok(()) => Err(anyhow::anyhow!(
                "a missing --grace-hours value must be refused"
            )),
        }
    }

    #[tokio::test]
    async fn run_rejects_a_non_numeric_grace_hours_value() -> anyhow::Result<()> {
        match run(&["--grace-hours".to_owned(), "soon".to_owned()]).await {
            Err(err) => {
                assert!(
                    err.to_string().contains("invalid --grace-hours value"),
                    "got: {err}"
                );
                Ok(())
            }
            Ok(()) => Err(anyhow::anyhow!(
                "a non-numeric --grace-hours value must be refused"
            )),
        }
    }
}
