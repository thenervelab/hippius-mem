//! Phase 4 measured performance pass: criterion benches for `recall`,
//! `history`, and `sync` (cold rebuild).
//!
//! The corpus is built deterministically — a fixed signing seed and note bodies
//! derived purely from an index, with no wall-clock or rng input — so a baseline
//! captured before a change is comparable to the number measured after it. This
//! is the re-runnable harness axiom `illu_perf_01` requires before any
//! performance change: the `history` bench is the one the anchor-scan hypothesis
//! targeted, and `recall` / `sync` are measured alongside so a regression in
//! any of them surfaces here rather than in production.
#![expect(
    clippy::expect_used,
    reason = "benchmark setup has no meaningful recovery from a failed store build; expect surfaces the cause and aborts the run rather than silently benchmarking an empty corpus"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::hint::black_box;
use std::sync::Arc;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use tokio::runtime::Runtime;

use hippius_mem_core::{
    NetworkPrefix,
    BlobStore, HashEmbedder, InMemoryIndex, MemoryBlobStore, MemoryStore, NoopAnchor, NoteId,
    NoteType, OpLogStore, RecallInput, RememberInput, RepoScope, SecretKey, Signer, Sr25519Signer,
};

/// Shared team namespace for every benched store.
const TEAM: &str = "bench-team";
/// The 32-byte team key every benched note is sealed under.
const TEAM_KEY: [u8; 32] = [7_u8; 32];
/// Fixed signing seed — one deterministic author for the whole corpus.
const SEED: [u8; 32] = [3_u8; 32];
/// Anchor every 8 ops, so a ~750-op corpus leaves ~94 multi-leaf anchor records.
/// That is the axis the old `history` rescanned once per op; keeping it low
/// accumulates many records, to test whether that scan is the hotspot it was
/// believed to be (measurement says no — see the perf note).
const ANCHOR_THRESHOLD: usize = 8;
/// Background notes the corpus remembers before the hot note.
const CORPUS_NOTES: usize = 500;
/// Link ops piled on the hot note, so its `history` reconstructs `HOT_LINKS + 1`
/// ops over ~94 anchor records. This was sized to expose the per-op anchor scan;
/// the measured result (docs/perf/2026-06-27-phase4-baseline.md) is that the
/// scan is NOT the hotspot — `oplog.read_all`'s full-log signature/chain
/// verification dominates `history` and `sync` alike, even when scaled to a
/// 1200-op hot note. The bench stays as the harness that established that.
const HOT_LINKS: usize = 250;

/// The five note kinds, cycled by index so the corpus spans every variant.
const NOTE_TYPES: [NoteType; 5] = [
    NoteType::Decision,
    NoteType::Convention,
    NoteType::Gotcha,
    NoteType::Reference,
    NoteType::Context,
];

/// Build a fresh store over `blob` with a cold (empty) index. Reused both to
/// seed the corpus and, per `sync` iteration, to rebuild from the shared log.
fn store_over(blob: Arc<dyn BlobStore>) -> MemoryStore {
    let index = Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default())));
    let oplog = OpLogStore::new(blob.clone());
    let signer: Arc<dyn Signer> = Arc::new(
        Sr25519Signer::from_seed_with_prefix(SEED, NetworkPrefix::HIPPIUS).expect("seed expands to an sr25519 keypair"),
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

/// Note content derived purely from `i`: no wall clock and no rng, so the corpus
/// is structurally identical run to run and the baseline stays comparable.
fn note_input(i: usize) -> RememberInput {
    RememberInput {
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

/// Seed the shared corpus once: `CORPUS_NOTES` remembers, then one hot note
/// carrying `HOT_LINKS` link ops, then a final flush so every op is anchored.
/// Returns the runtime, the shared blob (for cold `sync` rebuilds), the warm
/// store (for `recall` / `history`), and the hot note's id.
fn build_corpus() -> (Runtime, Arc<dyn BlobStore>, MemoryStore, NoteId) {
    let rt = Runtime::new().expect("tokio runtime builds");
    let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
    let store = store_over(blob.clone());
    let hot_id = rt.block_on(async {
        let mut first: Option<NoteId> = None;
        for i in 0..CORPUS_NOTES {
            let id = store
                .remember(note_input(i))
                .await
                .expect("remember succeeds");
            if first.is_none() {
                first = Some(id);
            }
        }
        // Link target is a real, indexed note so `link` accepts it; it stays
        // fixed across links so the corpus carries no rng beyond the inherent
        // per-op ulid (which affects op hashes, not the benchmark's op/record
        // counts).
        let target = first.expect("corpus has at least one note to link to");
        let hot = store
            .remember(note_input(CORPUS_NOTES))
            .await
            .expect("hot-note remember succeeds");
        for _ in 0..HOT_LINKS {
            store.link(hot, target).await.expect("link succeeds");
        }
        store
            .flush_anchors()
            .await
            .expect("final anchor flush succeeds");
        hot
    });
    (rt, blob, store, hot_id)
}

/// Bench `recall`, `history`, and cold `sync` over one shared corpus.
fn store_benchmarks(c: &mut Criterion) {
    let (rt, blob, store, hot_id) = build_corpus();
    let recall_input = RecallInput {
        text: "subsystem retrieval anchoring convergence".to_owned(),
        repo: RepoScope::Global,
        k: 10,
        token_budget: None,
    };

    c.bench_function("recall", |b| {
        b.iter(|| black_box(store.recall(recall_input.clone()).expect("recall succeeds")));
    });

    c.bench_function("history_hot_note", |b| {
        b.iter(|| {
            black_box(
                rt.block_on(store.history(hot_id))
                    .expect("history succeeds"),
            )
        });
    });

    c.bench_function("sync_cold_rebuild", |b| {
        b.iter_batched(
            || store_over(blob.clone()),
            |fresh| {
                black_box(
                    rt.block_on(fresh.sync())
                        .expect("cold sync replays the log"),
                )
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = store_benchmarks
}
criterion_main!(benches);
