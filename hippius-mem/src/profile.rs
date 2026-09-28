//! The `profile` subcommand: time each phase of a cold session start against the
//! bound team's REAL bucket and print where the time goes.
//!
//! A new MCP session cannot answer its first `recall` until it has built its
//! store (config, keys, embedding model) and run a cold `sync`; a later `recall`
//! re-probes the op-log once the refresh window lapses, and re-syncs when a
//! teammate has written. Each of those is a phase below, measured separately so
//! a slow recall can be attributed to the gateway, to local verification and
//! decoding, or to the model — rather than guessed at from log timestamps.
//!
//! # Read-only
//!
//! The gateway is wrapped in [`InstrumentedBlobStore::read_only`], under the
//! local cache, so every `put`/`delete` is refused before it leaves the machine.
//! The only write a read path issues is `sync`'s best-effort index checkpoint,
//! which already tolerates a failed put (the next sync just takes the slow
//! path). Local state — the blob cache, head marks — is updated exactly as a
//! normal session would update it.
//!
//! # Reading the numbers
//!
//! `wall` is the phase's elapsed time. `gateway` is the time spent inside S3
//! calls, summed: calls that overlap each add their full duration, so `gateway`
//! can exceed `wall` for the concurrent fetch phases. `wall - gateway` is local
//! CPU: verification, decryption, decoding, rebuilding the index.
//!
//! The checkpoint is cached (in memory, and on disk beside the blob cache), so
//! the cold-sync row reflects this machine's cache: a first-ever run downloads
//! it, a later new process reads it from disk. The "checkpoint load" row runs
//! after the cold sync and so shows what a re-sync pays: one LIST, and a GET
//! only if the bucket now lists a newer checkpoint.

use std::fmt::Write as _;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use hippius_mem::server::parse_repo;
use hippius_mem_core::{
    BlobStats, BlobStore, InstrumentedBlobStore, MemoryStore, OpLogStore, RecallInput,
};

use crate::config::Config;

/// Recalls timed after the syncs; enough for a min/median/max spread.
const RECALL_RUNS: usize = 5;

/// A query shaped like what an agent asks at the start of a task.
const RECALL_QUERY: &str = "decisions, conventions and gotchas for this repository";

/// Pointers per recall, matching the MCP `recall` tool's default.
const RECALL_K: usize = 10;

/// One measured phase: a row of the printed table.
struct Phase {
    name: String,
    wall: Duration,
    gateway: BlobStats,
    detail: String,
}

/// Everything a measurement needs, built once from the bound profile.
struct Target<'a> {
    store: &'a MemoryStore,
    blob: &'a Arc<dyn BlobStore>,
    meter: &'a InstrumentedBlobStore,
    team: &'a str,
    repo: Option<&'a str>,
}

/// Build the bound profile's store through a read-only measuring layer, time
/// every phase, and print the table to stdout.
///
/// # Errors
///
/// Returns an error for arguments (`profile` takes none), a missing or invalid
/// config, a repository that routes to no team, a store that cannot be built, or
/// a phase that fails against the gateway.
pub(crate) async fn run(args: &[String]) -> anyhow::Result<()> {
    if let Some(unexpected) = args.first() {
        anyhow::bail!("`hippius-mem profile` takes no arguments (got {unexpected:?})");
    }

    let cfg = Config::from_env_and_file().context("failed to load the hippius-mem config")?;
    let (profile, launch_repo) = crate::resolve_profile(&cfg)?;

    let mut meter_slot = None;
    let started = Instant::now();
    let (store, blob) = profile
        .build_store_layered(&cfg, |backend| {
            let meter = Arc::new(InstrumentedBlobStore::read_only(backend));
            meter_slot = Some(Arc::clone(&meter));
            meter
        })
        .await
        .context("failed to build the store for this profile")?;
    let key_ring = bootstrap_key_ring(&store, cfg.max_epoch).await;
    let build_wall = started.elapsed();
    let meter = meter_slot.context("the store was built without its measuring layer")?;

    let build = Phase {
        name: "store build (config, keys, model)".to_owned(),
        wall: build_wall,
        gateway: meter.stats(),
        detail: format!("{}; {key_ring}", retrieval_mode(&store)),
    };
    let target = Target {
        store: &store,
        blob: &blob,
        meter: &meter,
        team: &profile.name,
        repo: launch_repo.as_deref(),
    };
    let mut phases = vec![build];
    phases.extend(measure(&target).await?);

    let title = format!(
        "hippius-mem profile: team {:?}, bucket {:?}, read-only",
        profile.name, profile.bucket
    );
    write_stdout(&render(&title, &phases));
    Ok(())
}

/// Load rotated-epoch keys exactly as `serve`'s warmup and `brief` do, so the
/// checkpoint and syncs are measured with the key ring a real session holds: on
/// a rotated team, a founding-epoch-only store cannot open the current
/// checkpoint and would time a different (full-replay) path.
async fn bootstrap_key_ring(store: &MemoryStore, max_epoch: u64) -> &'static str {
    match std::env::var("HIPPIUS_MEM_MNEMONIC") {
        Ok(mnemonic) => {
            crate::admin::bootstrap_epochs(store, &mnemonic, max_epoch).await;
            "epoch keys bootstrapped"
        }
        Err(_) => "founding-epoch key only (HIPPIUS_MEM_MNEMONIC unset)",
    }
}

fn retrieval_mode(store: &MemoryStore) -> &'static str {
    if store.is_semantic() {
        "semantic recall (embedding model loaded)"
    } else {
        "lexical recall (no embedding model)"
    }
}

/// Run `work`, returning its output, wall time, and the gateway traffic it
/// caused.
async fn timed<T>(
    meter: &InstrumentedBlobStore,
    work: impl Future<Output = T>,
) -> (T, Duration, BlobStats) {
    let before = meter.stats();
    let started = Instant::now();
    let output = work.await;
    (output, started.elapsed(), meter.stats().since(&before))
}

/// Time the phases after the store build: the cold sync, its components, a
/// re-sync, and recall.
async fn measure(target: &Target<'_>) -> anyhow::Result<Vec<Phase>> {
    // The cold sync runs FIRST because it is what a new session pays, and the
    // component rows fill the local op cache: timed after them, a "cold" sync
    // would undercount its gateway reads.
    let cold = timed_sync(target, "sync, cold (a new session)").await?;
    let components = component_phases(target).await?;
    let resync = timed_sync(target, "re-sync, no new ops (refresh path)").await?;
    let recall = timed_recalls(target)?;

    let mut phases = vec![annotate_cold_sync(cold, &resync)];
    phases.extend(components);
    phases.push(resync);
    phases.push(recall);
    Ok(phases)
}

/// The pieces a sync is made of, timed one by one over the now-warm local cache.
async fn component_phases(target: &Target<'_>) -> anyhow::Result<Vec<Phase>> {
    let oplog = OpLogStore::new(Arc::clone(target.blob));
    let mut phases = Vec::new();

    let (count, wall, gateway) = timed(target.meter, oplog.op_object_count(target.team)).await;
    phases.push(Phase {
        name: "refresh probe (count op objects)".to_owned(),
        wall,
        gateway,
        detail: format!("{} op objects", count.context("refresh probe failed")?),
    });

    let (ops, wall, gateway) = timed(target.meter, oplog.read_all(target.team)).await;
    phases.push(Phase {
        name: "op-log read + verify (warm cache)".to_owned(),
        wall,
        gateway,
        detail: format!("{} ops verified", ops.context("op-log read failed")?.len()),
    });

    let (snapshot, wall, gateway) = timed(target.meter, target.store.load_checkpoint()).await;
    let detail = match snapshot.context("checkpoint load failed")? {
        Some(snapshot) => format!(
            "{} records at lamport {} ({})",
            snapshot.records.len(),
            snapshot.last_lamport,
            if gateway.get.calls == 0 {
                "from the local checkpoint cache"
            } else {
                "downloaded"
            }
        ),
        None => "no checkpoint: a cold sync full-replays".to_owned(),
    };
    phases.push(Phase {
        name: "checkpoint load (re-sync path)".to_owned(),
        wall,
        gateway,
        detail,
    });
    Ok(phases)
}

/// Flag what makes a cold sync's numbers differ from a real session's.
///
/// More LISTs than the re-sync means the cold sync re-ran its pass: its install
/// saw this process's write stamp move. Nothing writes during a profile, so the
/// flag is a tripwire for a regression of the first-sync retry every author
/// used to pay (fixed; see `MemoryStore::read_filtered`). A refused put means a
/// real session would have refreshed the checkpoint here, which this read-only
/// run did not.
fn annotate_cold_sync(mut cold: Phase, resync: &Phase) -> Phase {
    if cold.gateway.list.calls > resync.gateway.list.calls {
        cold.detail
            .push_str("; re-ran its pass (install stamp moved)");
    }
    if cold.gateway.put.calls > 0 {
        cold.detail
            .push_str("; checkpoint write refused (read-only)");
    }
    cold
}

async fn timed_sync(target: &Target<'_>, name: &str) -> anyhow::Result<Phase> {
    let (indexed, wall, gateway) = timed(target.meter, target.store.sync()).await;
    Ok(Phase {
        name: name.to_owned(),
        wall,
        gateway,
        detail: format!("{} notes indexed", indexed.context("sync failed")?),
    })
}

/// Time [`RECALL_RUNS`] recalls over the synced index. The row's `wall` is the
/// median call; the detail carries the spread.
fn timed_recalls(target: &Target<'_>) -> anyhow::Result<Phase> {
    let mut durations = Vec::with_capacity(RECALL_RUNS);
    let mut returned = 0;
    for _ in 0..RECALL_RUNS {
        let input = RecallInput {
            text: RECALL_QUERY.to_owned(),
            repo: parse_repo(target.repo),
            k: RECALL_K,
            token_budget: None,
        };
        let started = Instant::now();
        let result = target.store.recall(input).context("recall failed")?;
        durations.push(started.elapsed());
        returned = result.pointers.len();
    }
    durations.sort_unstable();

    let min = durations.first().copied().unwrap_or_default();
    let median = durations
        .get(durations.len() / 2)
        .copied()
        .unwrap_or_default();
    let max = durations.last().copied().unwrap_or_default();
    Ok(Phase {
        name: format!("recall (median of {RECALL_RUNS})"),
        wall: median,
        gateway: BlobStats::default(),
        detail: format!(
            "min {} / max {}, {returned} pointers",
            format_duration(min),
            format_duration(max)
        ),
    })
}

fn render(title: &str, phases: &[Phase]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{title}");
    let _ = writeln!(
        out,
        "gateway = time inside S3 calls, summed (overlapping calls can exceed wall)\n"
    );
    let _ = writeln!(
        out,
        "{:<36} {:>9} {:>9} {:>5} {:>6} {:>10}  detail",
        "phase", "wall", "gateway", "LIST", "GET", "GET bytes"
    );
    for phase in phases {
        let _ = writeln!(
            out,
            "{:<36} {:>9} {:>9} {:>5} {:>6} {:>10}  {}",
            phase.name,
            format_duration(phase.wall),
            format_duration(phase.gateway.busy()),
            phase.gateway.list.calls,
            phase.gateway.get.calls,
            format_bytes(phase.gateway.get.bytes),
            phase.detail
        );
    }
    let _ = writeln!(
        out,
        "\nA new session's first recall waits for: store build + cold sync.\n\
         A later recall, once the refresh window lapses, pays the refresh probe,\n\
         plus a full re-sync when a teammate has written since."
    );
    out
}

fn format_duration(duration: Duration) -> String {
    let micros = duration.as_micros();
    if micros < 1_000 {
        format!("{micros}us")
    } else if micros < 1_000_000 {
        format!("{}ms", micros / 1_000)
    } else {
        format!("{:.2}s", duration.as_secs_f64())
    }
}

#[expect(
    clippy::cast_precision_loss,
    reason = "a human-readable size with one decimal; precision past 2^52 bytes is irrelevant"
)]
fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1_024;
    const MIB: u64 = KIB * 1_024;
    if bytes < KIB {
        format!("{bytes}B")
    } else if bytes < MIB {
        format!("{:.1}KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{:.1}MiB", bytes as f64 / MIB as f64)
    }
}

/// Write the report to stdout. The workspace denies the `print!` family, and
/// `write_all` is not one of them (the same approach `brief` takes). A broken
/// pipe must not turn a finished measurement into an error.
fn write_stdout(report: &str) {
    use std::io::Write;
    let _ = std::io::stdout().write_all(report.as_bytes());
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes"
    )]

    use std::collections::{BTreeMap, BTreeSet};

    use hippius_mem_core::{
        HashEmbedder, InMemoryIndex, MemoryBlobStore, NetworkPrefix, NoopAnchor, NoteType,
        RememberInput, RepoScope, SecretKey, Signer, Sr25519Signer,
    };

    use super::*;

    const TEAM: &str = "profile-team";
    const TEAM_KEY: [u8; 32] = [7_u8; 32];
    const NOTES: usize = 12;

    fn store_over(blob: Arc<dyn BlobStore>, seed: &[u8; 32]) -> anyhow::Result<MemoryStore> {
        let signer: Arc<dyn Signer> = Arc::new(Sr25519Signer::from_seed_with_prefix(
            seed,
            NetworkPrefix::HIPPIUS,
        )?);
        Ok(MemoryStore::new(
            blob.clone(),
            Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default()))),
            OpLogStore::new(blob),
            Arc::new(NoopAnchor),
            signer,
            BTreeMap::from([(0_u64, SecretKey::from_bytes(TEAM_KEY))]),
            0,
            TEAM.to_owned(),
            4,
        ))
    }

    /// The corpus author's seed; profiling as it reproduces the author retry.
    const AUTHOR: [u8; 32] = [3_u8; 32];
    /// An identity that never wrote.
    const READER: [u8; 32] = [5_u8; 32];

    /// A bucket holding `NOTES` anchored notes and NO checkpoint, so a profiled
    /// cold sync full-replays and then tries to write one: the write the
    /// read-only layer exists to refuse.
    async fn seeded_bucket() -> anyhow::Result<Arc<dyn BlobStore>> {
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let writer = store_over(bucket.clone(), &AUTHOR)?;
        for i in 0..NOTES {
            writer
                .remember(RememberInput {
                    force: true,
                    note_type: NoteType::Decision,
                    repo: RepoScope::Global,
                    tags: BTreeSet::new(),
                    summary: format!("decision {i} about gotchas and conventions"),
                    body: format!("body {i}"),
                })
                .await?;
        }
        writer.flush_anchors().await?;
        Ok(bucket)
    }

    /// Every object in `bucket`, key and bytes.
    async fn contents(bucket: &Arc<dyn BlobStore>) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
        let mut all = Vec::new();
        for key in bucket.list("").await? {
            let bytes = bucket.get(&key).await?;
            all.push((key, bytes));
        }
        Ok(all)
    }

    /// Profile `bucket` as `seed` through a read-only meter.
    async fn profile_as(
        bucket: &Arc<dyn BlobStore>,
        seed: &[u8; 32],
    ) -> anyhow::Result<Vec<Phase>> {
        let meter = Arc::new(InstrumentedBlobStore::read_only(bucket.clone()));
        let blob: Arc<dyn BlobStore> = meter.clone();
        let store = store_over(blob.clone(), seed)?;
        let target = Target {
            store: &store,
            blob: &blob,
            meter: &meter,
            team: TEAM,
            repo: None,
        };
        measure(&target).await
    }

    #[tokio::test]
    async fn measures_every_phase_and_refuses_the_checkpoint_write() -> anyhow::Result<()> {
        let bucket = seeded_bucket().await?;
        let before = contents(&bucket).await?;

        let phases = profile_as(&bucket, &READER).await?;

        let names: Vec<&str> = phases.iter().map(|phase| phase.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "sync, cold (a new session)",
                "refresh probe (count op objects)",
                "op-log read + verify (warm cache)",
                "checkpoint load (re-sync path)",
                "re-sync, no new ops (refresh path)",
                "recall (median of 5)",
            ]
        );
        let cold = &phases[0];
        assert!(
            cold.gateway.put.calls > 0,
            "the cold sync must have attempted its checkpoint write"
        );
        assert_eq!(
            cold.detail,
            format!("{NOTES} notes indexed; checkpoint write refused (read-only)")
        );
        assert_eq!(
            phases[3].detail, "no checkpoint: a cold sync full-replays",
            "the refused write left no checkpoint behind"
        );
        assert!(phases[5].detail.ends_with("10 pointers"));
        assert_eq!(
            contents(&bucket).await?,
            before,
            "profiling must leave every object in the bucket untouched"
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_authors_cold_sync_costs_the_same_round_trips_as_a_readers() -> anyhow::Result<()> {
        let bucket = seeded_bucket().await?;

        let as_author = profile_as(&bucket, &AUTHOR).await?;
        let as_reader = profile_as(&bucket, &READER).await?;

        assert_eq!(
            as_author[0].gateway.list.calls, as_reader[0].gateway.list.calls,
            "an author's cold sync must not re-run its pass"
        );
        assert!(
            !as_author[0].detail.contains("re-ran"),
            "{}",
            as_author[0].detail
        );
        Ok(())
    }

    #[test]
    fn a_cold_sync_with_extra_lists_is_flagged_as_re_run() {
        let phase = |lists: u64| Phase {
            name: "sync".to_owned(),
            wall: Duration::ZERO,
            gateway: BlobStats {
                list: hippius_mem_core::OpStats {
                    calls: lists,
                    ..hippius_mem_core::OpStats::default()
                },
                ..BlobStats::default()
            },
            detail: "3 notes indexed".to_owned(),
        };

        let re_run = annotate_cold_sync(phase(6), &phase(3));
        let single = annotate_cold_sync(phase(3), &phase(3));

        assert_eq!(
            re_run.detail,
            "3 notes indexed; re-ran its pass (install stamp moved)"
        );
        assert_eq!(single.detail, "3 notes indexed");
    }

    #[tokio::test]
    async fn rejects_arguments() {
        let result = run(&["--fast".to_owned()]).await;
        let message = result.err().map(|err| err.to_string()).unwrap_or_default();
        assert!(message.contains("takes no arguments"), "{message}");
    }

    #[test]
    fn durations_pick_a_readable_unit() {
        assert_eq!(format_duration(Duration::from_micros(250)), "250us");
        assert_eq!(format_duration(Duration::from_millis(42)), "42ms");
        assert_eq!(format_duration(Duration::from_millis(12_345)), "12.35s");
    }

    #[test]
    fn bytes_pick_a_readable_unit() {
        assert_eq!(format_bytes(512), "512B");
        assert_eq!(format_bytes(1_536), "1.5KiB");
        assert_eq!(format_bytes(25 * 1_024 * 1_024), "25.0MiB");
    }

    #[test]
    fn render_prints_one_row_per_phase() {
        let phases = [Phase {
            name: "op-log read + verify".to_owned(),
            wall: Duration::from_millis(1_500),
            gateway: BlobStats::default(),
            detail: "7 ops verified".to_owned(),
        }];

        let table = render("title", &phases);

        let row = table
            .lines()
            .find(|line| line.starts_with("op-log read + verify"))
            .unwrap_or_default();
        assert!(row.contains("1.50s"), "{row}");
        assert!(row.ends_with("7 ops verified"), "{row}");
    }
}
