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
//! can exceed `wall` for the concurrent fetch phases. For a sequential phase
//! (the checkpoint load is one LIST then one GET), `wall - gateway` is local CPU:
//! decryption and decoding.

use std::fmt::Write as _;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use hippius_mem::server::parse_repo;
use hippius_mem_core::{
    BlobStats, BlobStore, InstrumentedBlobStore, MemoryStore, OpLogStore, RecallInput, SecretKey,
    load_latest_snapshot,
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
    name: &'static str,
    wall: Duration,
    gateway: BlobStats,
    detail: String,
}

/// Everything a measurement needs, built once from the bound profile.
struct Target<'a> {
    store: &'a MemoryStore,
    blob: &'a Arc<dyn BlobStore>,
    meter: &'a InstrumentedBlobStore,
    key: &'a SecretKey,
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
    let key = profile
        .team_key()
        .context("failed to decode this profile's team key")?;

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
    let build_wall = started.elapsed();
    let meter = meter_slot.context("the store was built without its measuring layer")?;

    let build = Phase {
        name: "store build (config, keys, model)",
        wall: build_wall,
        gateway: meter.stats(),
        detail: retrieval_mode(&store).to_owned(),
    };
    let target = Target {
        store: &store,
        blob: &blob,
        meter: &meter,
        key: &key,
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

/// Time the session-start phases after the store build, in the order a session
/// runs them.
async fn measure(target: &Target<'_>) -> anyhow::Result<Vec<Phase>> {
    let oplog = OpLogStore::new(Arc::clone(target.blob));
    let mut phases = Vec::new();

    let (count, wall, gateway) = timed(target.meter, oplog.op_object_count(target.team)).await;
    phases.push(Phase {
        name: "refresh probe (count op objects)",
        wall,
        gateway,
        detail: format!("{} op objects", count.context("refresh probe failed")?),
    });

    let (ops, wall, gateway) = timed(target.meter, oplog.read_all(target.team)).await;
    phases.push(Phase {
        name: "op-log read + verify",
        wall,
        gateway,
        detail: format!("{} ops verified", ops.context("op-log read failed")?.len()),
    });

    let load = load_latest_snapshot(target.blob.as_ref(), target.key, target.team);
    let (snapshot, wall, gateway) = timed(target.meter, load).await;
    let detail = match snapshot.context("checkpoint load failed")? {
        Some(snapshot) => format!(
            "{} records at lamport {} (never cached locally)",
            snapshot.records.len(),
            snapshot.last_lamport
        ),
        None => "no checkpoint: a cold sync full-replays".to_owned(),
    };
    phases.push(Phase {
        name: "checkpoint load (fetch + decode)",
        wall,
        gateway,
        detail,
    });

    phases.push(timed_sync(target, "sync, cold (a new session)").await?);
    phases.push(timed_sync(target, "sync, warm (after a teammate write)").await?);
    phases.push(timed_recalls(target)?);
    Ok(phases)
}

async fn timed_sync(target: &Target<'_>, name: &'static str) -> anyhow::Result<Phase> {
    let (indexed, wall, gateway) = timed(target.meter, target.store.sync()).await;
    Ok(Phase {
        name,
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
        name: "recall (median of 5)",
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
         plus a warm sync when a teammate has written since."
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
        RememberInput, RepoScope, Signer, Sr25519Signer,
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

    /// A bucket holding `NOTES` notes, anchored, with a checkpoint.
    async fn seeded_bucket() -> anyhow::Result<Arc<dyn BlobStore>> {
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let writer = store_over(bucket.clone(), &[3_u8; 32])?;
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
        store_over(bucket.clone(), &[3_u8; 32])?.sync().await?;
        Ok(bucket)
    }

    #[tokio::test]
    async fn measures_every_phase_without_writing_to_the_bucket() -> anyhow::Result<()> {
        let bucket = seeded_bucket().await?;
        let keys_before = bucket.list("").await?;
        let meter = Arc::new(InstrumentedBlobStore::read_only(bucket.clone()));
        let blob: Arc<dyn BlobStore> = meter.clone();
        let store = store_over(blob.clone(), &[5_u8; 32])?;
        let key = SecretKey::from_bytes(TEAM_KEY);
        let target = Target {
            store: &store,
            blob: &blob,
            meter: &meter,
            key: &key,
            team: TEAM,
            repo: None,
        };

        let phases = measure(&target).await?;

        let names: Vec<&str> = phases.iter().map(|phase| phase.name).collect();
        assert_eq!(
            names,
            [
                "refresh probe (count op objects)",
                "op-log read + verify",
                "checkpoint load (fetch + decode)",
                "sync, cold (a new session)",
                "sync, warm (after a teammate write)",
                "recall (median of 5)",
            ]
        );
        let cold_sync = &phases[3];
        assert_eq!(cold_sync.detail, format!("{NOTES} notes indexed"));
        assert!(
            cold_sync.gateway.list.calls > 0,
            "a cold sync lists the op-log"
        );
        assert!(phases[2].detail.starts_with(&format!("{NOTES} records")));
        assert!(phases[5].detail.ends_with("10 pointers"));
        assert_eq!(
            bucket.list("").await?,
            keys_before,
            "profiling must leave the bucket byte-for-byte untouched"
        );
        Ok(())
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
            name: "op-log read + verify",
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
