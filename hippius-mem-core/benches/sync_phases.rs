//! Per-phase benches for the cold-start path a new session pays before its first
//! `recall`: op-log read + verify, the refresh probe, the checkpoint (snapshot)
//! load, cold `sync` on the incremental and full-replay paths, a warm re-sync,
//! and `recall` itself — over a corpus sized like a real team (thousands of
//! notes, not `store_benches`' 500).
//!
//! Two kinds of output:
//!
//! - criterion timings, which are CPU cost only: the blob store is in-memory, so
//!   network latency is zero here by construction;
//! - a one-time **call census** printed to stderr before the benches, counting the
//!   blob-store round-trips each phase makes. On the real gateway every LIST and
//!   GET costs a network round-trip (hundreds of ms), so `calls x latency` is the
//!   part of a phase's real-world cost this harness cannot time. Run
//!   `hippius-mem profile` for the measured version against a live bucket.
//!
//! The cold `sync` is benched twice, as the corpus AUTHOR and as a READER that
//! never wrote. The gap between them is the cost of the author's first-sync
//! retry: `sync` captures the author's write stamp before `read_and_filter`
//! re-seeds it from the log, sees it "change", and discards the whole first pass.
//! The census shows the same thing as doubled LIST/GET counts.
//!
//! The corpus is deterministic (fixed seeds, index-derived content), like
//! `store_benches`, so runs are comparable.
#![expect(
    clippy::expect_used,
    reason = "benchmark setup has no meaningful recovery from a failed store build; expect \
              surfaces the cause rather than silently benchmarking an empty corpus"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::hint::black_box;
use std::sync::Arc;

use async_trait::async_trait;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use tokio::runtime::Runtime;

use hippius_mem_core::{
    BlobStats, BlobStore, HashEmbedder, InMemoryIndex, InstrumentedBlobStore, MemError,
    MemoryBlobStore, MemoryStore, NetworkPrefix, NoopAnchor, NoteType, OpLogStore, RecallInput,
    RememberInput, RepoScope, SecretKey, Signer, Sr25519Signer, load_latest_snapshot,
};

/// Shared team namespace for every benched store.
const TEAM: &str = "bench-team";
/// The 32-byte team key every benched note is sealed under.
const TEAM_KEY: [u8; 32] = [7_u8; 32];
/// The corpus author's signing seed.
const AUTHOR_SEED: [u8; 32] = [3_u8; 32];
/// A second identity that never writes: syncing as it skips the author retry.
const READER_SEED: [u8; 32] = [5_u8; 32];
/// The production default (`anchor_threshold` in the CLI config), so the corpus
/// carries a realistic number of anchor records.
const ANCHOR_THRESHOLD: usize = 16;
/// Notes in the corpus: the order of magnitude of a real team's memory (the
/// team that motivated this bench had ~4,600 live notes).
const CORPUS_NOTES: usize = 5_000;
/// Where `save_snapshot` writes checkpoints; hidden to force a full replay.
const SNAPSHOT_PREFIX: &str = "bench-team/_snapshots/";

/// The five note kinds, cycled by index so the corpus spans every variant.
const NOTE_TYPES: [NoteType; 5] = [
    NoteType::Decision,
    NoteType::Convention,
    NoteType::Gotcha,
    NoteType::Reference,
    NoteType::Context,
];

/// Build a store with a cold (empty) index over `blob`, signing as `seed`.
fn store_over(blob: Arc<dyn BlobStore>, seed: &[u8; 32]) -> MemoryStore {
    let index = Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default())));
    let oplog = OpLogStore::new(blob.clone());
    let signer: Arc<dyn Signer> = Arc::new(
        Sr25519Signer::from_seed_with_prefix(seed, NetworkPrefix::HIPPIUS)
            .expect("seed expands to an sr25519 keypair"),
    );
    MemoryStore::new(
        blob,
        index,
        oplog,
        Arc::new(NoopAnchor),
        signer,
        BTreeMap::from([(0_u64, SecretKey::from_bytes(TEAM_KEY))]),
        0,
        TEAM.to_owned(),
        ANCHOR_THRESHOLD,
    )
}

/// Note content derived purely from `i`, so the corpus is identical run to run.
fn note_input(i: usize) -> RememberInput {
    RememberInput {
        force: true,
        note_type: NOTE_TYPES[i % NOTE_TYPES.len()],
        repo: if i.is_multiple_of(3) {
            RepoScope::Global
        } else {
            RepoScope::Repo(format!("repo-{}", i % 5))
        },
        tags: BTreeSet::from([format!("tag-{}", i % 11), format!("topic-{}", i % 7)]),
        summary: format!("note {i} about subsystem {} and module {}", i % 13, i % 17),
        body: format!(
            "deterministic body for note {i}: retrieval, anchoring, and convergence detail {}",
            i % 23
        ),
    }
}

/// Write the corpus, anchor it, then run one cold sync so a checkpoint exists —
/// the state a real team's bucket is in, and what makes the incremental path the
/// one a new session takes.
fn build_corpus(rt: &Runtime) -> Arc<dyn BlobStore> {
    let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
    let writer = store_over(blob.clone(), &AUTHOR_SEED);
    rt.block_on(async {
        for i in 0..CORPUS_NOTES {
            writer
                .remember(note_input(i))
                .await
                .expect("remember succeeds");
        }
        writer
            .flush_anchors()
            .await
            .expect("final anchor flush succeeds");
        store_over(blob.clone(), &AUTHOR_SEED)
            .sync()
            .await
            .expect("checkpointing sync succeeds");
    });
    blob
}

/// A view of a bucket with no checkpoints in it, so `sync` must full-replay.
///
/// Only `list` hides them: that is how `load_latest_snapshot` discovers
/// checkpoints, and a checkpoint the synced store writes lands in the inner
/// store where this view still cannot see it.
struct WithoutSnapshots(Arc<dyn BlobStore>);

#[async_trait]
impl BlobStore for WithoutSnapshots {
    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
        self.0.put(key, bytes).await
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
        self.0.get(key).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError> {
        if prefix.starts_with(SNAPSHOT_PREFIX) {
            return Ok(Vec::new());
        }
        self.0.list(prefix).await
    }

    async fn delete(&self, key: &str) -> Result<(), MemError> {
        self.0.delete(key).await
    }
}

/// The bucket as a full replay sees it: no checkpoints, and read-only.
///
/// Read-only because a sync with no checkpoint to restore seals and writes a
/// fresh one, which would add serialize + seal + put cost to every iteration
/// and make full-vs-incremental unfair; the refused write is logged and
/// skipped, exactly as `sync` treats any failed checkpoint write.
fn full_replay_view(blob: Arc<dyn BlobStore>) -> Arc<dyn BlobStore> {
    Arc::new(InstrumentedBlobStore::read_only(Arc::new(
        WithoutSnapshots(blob),
    )))
}

/// Fail the run if the view stopped hiding checkpoints (say the snapshot key
/// layout moved off `SNAPSHOT_PREFIX`): the "full replay" bench would then
/// silently measure the incremental path.
fn assert_view_hides_checkpoints(rt: &Runtime, blob: &Arc<dyn BlobStore>) {
    let key = SecretKey::from_bytes(TEAM_KEY);
    let direct = rt.block_on(load_latest_snapshot(blob.as_ref(), &key, TEAM));
    let hidden = rt.block_on(load_latest_snapshot(
        full_replay_view(blob.clone()).as_ref(),
        &key,
        TEAM,
    ));
    assert!(
        matches!(direct, Ok(Some(_))),
        "the corpus must carry a checkpoint"
    );
    assert!(
        matches!(hidden, Ok(None)),
        "full_replay_view must hide every checkpoint; did the snapshot prefix change?"
    );
}

fn recall_input() -> RecallInput {
    RecallInput {
        text: "subsystem retrieval anchoring convergence".to_owned(),
        repo: RepoScope::Global,
        k: 10,
        token_budget: None,
    }
}

/// Run `phase` once over a fresh counting wrapper and return what it cost.
fn census<F, Fut>(rt: &Runtime, base: &Arc<dyn BlobStore>, phase: F) -> BlobStats
where
    F: FnOnce(Arc<dyn BlobStore>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let counted = Arc::new(InstrumentedBlobStore::new(base.clone()));
    rt.block_on(phase(counted.clone()));
    counted.stats()
}

#[expect(
    clippy::print_stderr,
    reason = "the census is the bench's own report, printed once next to criterion's output"
)]
fn print_census(rows: &[(&str, BlobStats)]) {
    eprintln!("\nsync_phases call census ({CORPUS_NOTES} notes, in-memory store):");
    eprintln!(
        "  {:<28} {:>6} {:>6} {:>12}",
        "phase", "LIST", "GET", "GET bytes"
    );
    for (name, stats) in rows {
        eprintln!(
            "  {name:<28} {:>6} {:>6} {:>12}",
            stats.list.calls, stats.get.calls, stats.get.bytes
        );
    }
    eprintln!();
}

/// Count every phase's round-trips once, before criterion times them.
fn report_census(rt: &Runtime, blob: &Arc<dyn BlobStore>) {
    let key = SecretKey::from_bytes(TEAM_KEY);
    let rows = [
        (
            "op_object_count (probe)",
            census(rt, blob, |b| async move {
                OpLogStore::new(b)
                    .op_object_count(TEAM)
                    .await
                    .expect("count");
            }),
        ),
        (
            "oplog_read_all",
            census(rt, blob, |b| async move {
                OpLogStore::new(b).read_all(TEAM).await.expect("read_all");
            }),
        ),
        (
            "snapshot_load",
            census(rt, blob, |b| async move {
                load_latest_snapshot(b.as_ref(), &key, TEAM)
                    .await
                    .expect("snapshot load");
            }),
        ),
        (
            "sync_cold_author",
            census(rt, blob, |b| async move {
                store_over(b, &AUTHOR_SEED).sync().await.expect("sync");
            }),
        ),
        (
            "sync_cold_reader",
            census(rt, blob, |b| async move {
                store_over(b, &READER_SEED).sync().await.expect("sync");
            }),
        ),
        (
            "sync_cold_full_reader",
            census(rt, blob, |b| async move {
                let view = full_replay_view(b);
                store_over(view, &READER_SEED).sync().await.expect("sync");
            }),
        ),
    ];
    print_census(&rows);
}

fn bench_reads(c: &mut Criterion, rt: &Runtime, blob: &Arc<dyn BlobStore>) {
    let oplog = OpLogStore::new(blob.clone());
    let key = SecretKey::from_bytes(TEAM_KEY);

    c.bench_function("sync_phases/op_object_count", |b| {
        b.iter(|| black_box(rt.block_on(oplog.op_object_count(TEAM)).expect("count")));
    });
    c.bench_function("sync_phases/oplog_read_all", |b| {
        b.iter(|| black_box(rt.block_on(oplog.read_all(TEAM)).expect("read_all")));
    });
    c.bench_function("sync_phases/snapshot_load", |b| {
        b.iter(|| {
            black_box(
                rt.block_on(load_latest_snapshot(blob.as_ref(), &key, TEAM))
                    .expect("snapshot load"),
            )
        });
    });
}

fn bench_cold_sync(c: &mut Criterion, rt: &Runtime, blob: &Arc<dyn BlobStore>) {
    let cases: [(&str, Arc<dyn BlobStore>, [u8; 32]); 3] = [
        ("sync_phases/sync_cold_author", blob.clone(), AUTHOR_SEED),
        ("sync_phases/sync_cold_reader", blob.clone(), READER_SEED),
        (
            "sync_phases/sync_cold_full_reader",
            full_replay_view(blob.clone()),
            READER_SEED,
        ),
    ];
    for (name, view, seed) in cases {
        c.bench_function(name, |b| {
            b.iter_batched(
                || store_over(view.clone(), &seed),
                |fresh| black_box(rt.block_on(fresh.sync()).expect("cold sync")),
                BatchSize::PerIteration,
            );
        });
    }
}

fn bench_warm(c: &mut Criterion, rt: &Runtime, blob: &Arc<dyn BlobStore>) {
    let warm = store_over(blob.clone(), &READER_SEED);
    rt.block_on(warm.sync()).expect("warming sync");

    // A re-sync with no new ops: the floor of what `refresh_if_stale` costs a
    // live session once a teammate has written, since `sync` re-reads,
    // re-verifies and re-converges the whole log (and reloads the checkpoint)
    // even over an already-populated index.
    c.bench_function("sync_phases/resync_reader", |b| {
        b.iter(|| black_box(rt.block_on(warm.sync()).expect("re-sync")));
    });
    c.bench_function("sync_phases/recall", |b| {
        b.iter(|| black_box(warm.recall(recall_input()).expect("recall")));
    });
}

fn sync_phase_benchmarks(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime builds");
    let blob = build_corpus(&rt);
    assert_view_hides_checkpoints(&rt, &blob);

    report_census(&rt, &blob);
    bench_reads(c, &rt, &blob);
    bench_cold_sync(c, &rt, &blob);
    bench_warm(c, &rt, &blob);
}

criterion_group! {
    name = benches;
    // The cold syncs take ~1 s each over the 5k corpus; 15 s fits ten samples
    // without criterion warning that it had to stretch its target time.
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(15));
    targets = sync_phase_benchmarks
}
criterion_main!(benches);
