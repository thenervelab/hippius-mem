//! Measured retrieval quality for the SHIPPED embedding model, asserted.
//!
//! The repo already had a labelled corpus — 11 real note summaries and 8
//! paraphrase queries in `examples/calibrate.rs` — and it computed exactly the
//! right metrics. But an example has no assertions and no CI job ever ran it, so
//! the numbers documented in `docs/SECURITY.md` were a one-time manual
//! measurement that nothing recomputed and nothing failed on when it degraded.
//!
//! These tests turn that corpus into a regression gate. They are `#[ignore]`d
//! (they download ~130 MB of ONNX model and run it) and gated on the `embeddings`
//! feature, so they run in the nightly semantic job alongside the other
//! real-model tests, not on every PR.
//!
//! What is asserted, and deliberately what is not: `recall@floor` — every
//! labelled target clearing the model's production floor — is the metric that
//! maps to what a user sees, because a target below the floor is dropped from
//! `recall` even at rank 0. Top-1 accuracy is NOT asserted: `docs/SECURITY.md`
//! records that bge-small pays for its recall with a compressed cosine band and
//! is "not always ranked first", so asserting rank 1 would pin a property the
//! shipped model does not claim.
//!
//! Two of the tests measure the EMBEDDER (cosines over the corpus, no store
//! involved). The rest drive a real [`MemoryStore`] over that embedder, because
//! "the model scores these two texts at 0.96" and "the store refuses this write"
//! are different claims and only the second is one a user can hit.

#![cfg(feature = "embeddings")]
#![expect(
    clippy::expect_used,
    reason = "tests assert on outcomes; expect documents invariants on fixtures whose construction cannot fail"
)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test"
)]
#![expect(
    clippy::print_stdout,
    reason = "the nightly job runs these with --nocapture so the measured numbers land in its log"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hippius_mem_core::{
    BlobStore, EmbedModel, Embedder, FastEmbedder, HashEmbedder, InMemoryIndex, MemError,
    MemoryBlobStore, MemoryStore, NetworkPrefix, NoopAnchor, NoteId, NoteType, OpLogStore,
    RecallInput, RememberInput, RepoScope, SecretKey, Signer, Sr25519Signer,
};

include!("shared/calibration_corpus.rs");

/// Mirrors `hippius_mem_core::store::DEDUP_THRESHOLD`, which is private. The
/// value itself is pinned by `the_dedup_threshold_is_pinned_at_its_boundary` in
/// the store's unit tests, so a change there fails that test first and this
/// constant cannot silently drift away from the real gate.
const DEDUP_THRESHOLD: f32 = 0.9;

type BoxError = Box<dyn std::error::Error>;

const TEAM: &str = "ourovoros";

/// Shared team key — the bytes the store seals note content under.
const TEAM_KEY: [u8; 32] = [9_u8; 32];

/// Above any op count these tests write, so the `NoopAnchor` batch path stays
/// inert and never perturbs a measurement.
const ANCHOR_THRESHOLD: usize = usize::MAX;

/// Fixed author seed: a fixed seed yields a fixed SS58 author identity, so every
/// run signs as the same machine.
const SEED: [u8; 32] = [7_u8; 32];

/// Embed the corpus with the model under test, using a raw 0.0 threshold so the
/// cosines are unfloored and the floor can be applied explicitly.
fn embed_corpus(model: EmbedModel) -> (FastEmbedder, Vec<Vec<f32>>) {
    let embedder = FastEmbedder::try_with(model, 0.0).expect("embedder loads");

    let docs: Vec<String> = SUMMARIES.iter().map(|s| (*s).to_owned()).collect();
    let vectors = embedder.embed(&docs).expect("corpus embeds");

    (embedder, vectors)
}

/// A real `MemoryStore` whose only varying piece is the embedder under test: a
/// `MemoryBlobStore` fake stands in for the S3 gateway, `NoopAnchor` for the
/// chain, and a seed-derived `Sr25519Signer` for the author identity. Same shape
/// as `tests/e2e_semantic.rs`'s builder — this is the remember/recall code the
/// MCP tools run against a real bucket.
fn store_with(embedder: Arc<dyn Embedder>) -> Result<MemoryStore, BoxError> {
    let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
    let oplog = OpLogStore::new(blob.clone());
    let signer: Arc<dyn Signer> = Arc::new(Sr25519Signer::from_seed_with_prefix(
        &SEED,
        NetworkPrefix::HIPPIUS,
    )?);

    Ok(MemoryStore::new(
        blob,
        Arc::new(InMemoryIndex::new(embedder)),
        oplog,
        Arc::new(NoopAnchor),
        signer,
        BTreeMap::from([(0_u64, SecretKey::from_bytes(TEAM_KEY))]),
        0,
        TEAM.to_owned(),
        ANCHOR_THRESHOLD,
    ))
}

/// `remember` a summary with the dedup gate ARMED (`force: false`) — the path
/// the gate lives on, and the one `tests/e2e_semantic.rs` bypasses by forcing
/// every write.
async fn remember_unforced(
    store: &MemoryStore,
    repo: &RepoScope,
    summary: &str,
) -> Result<NoteId, MemError> {
    store
        .remember(RememberInput {
            force: false,
            note_type: NoteType::Reference,
            repo: repo.clone(),
            tags: BTreeSet::new(),
            summary: summary.to_owned(),
            body: "Recorded so the gate has a real note to compare against.".to_owned(),
        })
        .await
}

/// How far down the ranked result a labelled target still counts as recovered.
///
/// Deliberately smaller than the corpus. Asking for `k` at or above the corpus
/// size returns everything that cleared its floor, and both shipped builds clear
/// their floors on all 8 targets, so a corpus-sized window cannot separate them
/// (see [`the_lean_build_recovers_fewer_paraphrase_targets_than_the_model_build`]).
/// 5 of 11 is under half the corpus and stands in for the top of the window an
/// agent actually reads before its context runs out.
const WINDOW: usize = 5;

/// What one build recovered over the labelled corpus.
struct Recovery {
    /// Labelled targets present anywhere in the floor-filtered ranked result —
    /// `recall@floor`, the metric a target below the floor is dropped from even
    /// at rank 0.
    above_floor: usize,

    /// Labelled targets ranked inside the first [`WINDOW`] pointers.
    in_window: usize,

    /// Summed 0-based rank of every labelled target, a target that never
    /// surfaced counting as `SUMMARIES.len()` — strictly worse than the worst
    /// real rank. Lower is better. Unlike a cutoff count this uses every query
    /// and needs no arbitrary window.
    rank_sum: usize,
}

/// Seed the labelled corpus into a store built over `embedder`, then rank every
/// paraphrase query through `MemoryStore::recall` — the path an agent calls.
///
/// Writes are forced: this measures RANKING, so both builds must hold the
/// identical 11 notes for the comparison to be about retrieval rather than about
/// which corpus survived a write gate. Every note is a `Reference` so the
/// per-type recency half-life is constant across the corpus and cannot reorder
/// anything.
async fn measure_build(label: &str, embedder: Arc<dyn Embedder>) -> Result<Recovery, BoxError> {
    let repo = RepoScope::Repo("thebrain".to_owned());
    let store = store_with(embedder)?;

    let mut ids: Vec<NoteId> = Vec::with_capacity(SUMMARIES.len());
    for summary in SUMMARIES {
        ids.push(
            store
                .remember(RememberInput {
                    force: true,
                    note_type: NoteType::Reference,
                    repo: repo.clone(),
                    tags: BTreeSet::new(),
                    summary: (*summary).to_owned(),
                    body: "Corpus note; only the summary is embedded and ranked.".to_owned(),
                })
                .await?,
        );
    }

    let mut recovery = Recovery {
        above_floor: 0,
        in_window: 0,
        rank_sum: 0,
    };

    println!("\n  {label}");
    for &(query, target) in QUERIES {
        let result = store.recall(RecallInput {
            text: query.to_owned(),
            repo: repo.clone(),
            k: SUMMARIES.len(),
            token_budget: None,
        })?;

        let rank = result
            .pointers
            .iter()
            .position(|pointer| pointer.note_id == ids[target]);

        if let Some(rank) = rank {
            recovery.above_floor += 1;
            recovery.rank_sum += rank;
            if rank < WINDOW {
                recovery.in_window += 1;
            }
            println!(
                "    rank {rank:>2} of {} returned   q: {query}",
                result.pointers.len()
            );
        } else {
            recovery.rank_sum += SUMMARIES.len();
            println!("    DROPPED below the floor      q: {query}");
        }
    }

    Ok(recovery)
}

/// Token-set Jaccard over the same tokenization the index uses — lowercase,
/// split on every non-alphanumeric boundary. Mirrors the private `jaccard` /
/// `tokenize` pair in `index/mod.rs` that scores a LEXICAL build's dedup gate,
/// so the number printed here is the one that gate would compare to
/// [`DEDUP_THRESHOLD`].
fn token_jaccard(left: &str, right: &str) -> f32 {
    fn tokens(text: &str) -> BTreeSet<String> {
        text.split(|c: char| !c.is_alphanumeric())
            .filter(|piece| !piece.is_empty())
            .map(str::to_lowercase)
            .collect()
    }

    let (left, right) = (tokens(left), tokens(right));
    if left.is_empty() || right.is_empty() {
        return 0.0;
    }

    #[expect(
        clippy::cast_precision_loss,
        reason = "token-set cardinalities are small counts; f32 represents them exactly"
    )]
    let overlap = left.intersection(&right).count() as f32 / left.union(&right).count() as f32;

    overlap
}

/// A note, and a restatement of it that only a SEMANTIC build can catch.
///
/// Both halves are measured, and the test asserts what it depends on rather than
/// trusting these comments. With the shipped `bge-small-en-v1.5` on 2026-08-11
/// the pair embeds at cosine **0.964**, clearing the 0.90 dedup gate, while its
/// token-set Jaccard is **0.364** — the metric a LEXICAL build's gate scores,
/// against that same 0.90 threshold, which it therefore does not come close to
/// clearing. That gap is the whole value of this test: the refusal below cannot
/// be explained by shared words, so it can only have come from the embedding.
/// The third leg proves it in the strongest available form — the identical pair
/// through a `HashEmbedder` store, which admits it.
///
/// Chosen by measurement, not taste. Searching for a pair with NEAR-ZERO overlap
/// that still clears 0.90 came up empty: on this model a token-disjoint
/// paraphrase tops out around cosine 0.80, well under the gate (see the task-G
/// report). At 0.90, bge-small refuses restatements, not rewordings — so a
/// low-but-non-zero overlap pair is the honest maximum this gate can be shown
/// catching.
const ORIGINAL: &str = "Every request carries a trace identifier so a single user action can be followed across services";
const PARAPHRASE: &str =
    "Each request includes a trace id, letting one user action be followed through every service";

/// A genuinely different fact, for the leg that keeps a gate refusing
/// EVERYTHING from passing this test.
const DISTINCT: &str =
    "Rotate the team key after removing a member, and revoke their gateway sub-token";

#[test]
#[ignore = "downloads the default embedding model and runs native ONNX Runtime"]
fn every_paraphrase_target_clears_the_production_floor() {
    let model = EmbedModel::default();
    let floor = model.default_floor();
    let (embedder, doc_vecs) = embed_corpus(model);

    let mut dropped: Vec<String> = Vec::new();

    for &(query, target) in QUERIES {
        let qvec = &embedder.embed(&[query.to_owned()]).expect("query embeds")[0];
        let target_cos = cosine(qvec, &doc_vecs[target]);

        if target_cos < floor {
            dropped.push(format!(
                "  cos {target_cos:.3} < floor {floor:.2}  q: {query}\n    target: {}",
                SUMMARIES[target]
            ));
        }
    }

    assert!(
        dropped.is_empty(),
        "{model} must surface every labelled paraphrase target above its {floor:.2} floor; \
         a target below the floor is dropped from recall even at rank 0. Dropped {} of {}:\n{}",
        dropped.len(),
        QUERIES.len(),
        dropped.join("\n"),
    );
}

#[test]
#[ignore = "downloads the default embedding model and runs native ONNX Runtime"]
fn no_two_distinct_notes_collide_above_the_dedup_threshold() {
    // The write-time dedup gate refuses a new note whose summary cosine to an
    // existing one reaches DEDUP_THRESHOLD. Every pair in this corpus is a
    // genuinely DISTINCT fact, so any pair at or above the threshold is a false
    // positive the gate would inflict on a real user: their new note refused as a
    // duplicate of an unrelated one.
    let model = EmbedModel::default();
    let (_embedder, doc_vecs) = embed_corpus(model);

    let mut ceiling = f32::NEG_INFINITY;
    let mut closest = (0_usize, 0_usize);

    for (i, vi) in doc_vecs.iter().enumerate() {
        for (j, vj) in doc_vecs.iter().enumerate().skip(i + 1) {
            let c = cosine(vi, vj);
            if c > ceiling {
                ceiling = c;
                closest = (i, j);
            }
        }
    }

    assert!(
        ceiling < DEDUP_THRESHOLD,
        "the closest pair of DISTINCT notes embeds at {ceiling:.3}, at or above the \
         {DEDUP_THRESHOLD} dedup threshold — the gate would refuse one as a duplicate of \
         the other:\n  {}\n  {}",
        SUMMARIES[closest.0],
        SUMMARIES[closest.1],
    );
}

/// The store's SEMANTIC dedup gate, end to end: a restatement is refused, the
/// same pair is admitted by a lexical build, and a distinct note still gets in.
///
/// This is the `MemoryStore::remember` path, not a cosine measurement. It had no
/// coverage at all: the only other embeddings-gated end-to-end test forces every
/// write (`force: true`), which skips the gate entirely.
///
/// Three legs, each load-bearing:
///
/// 1. the semantic store ACCEPTS [`DISTINCT`] — without it, a gate that refused
///    every write would satisfy the other two;
/// 2. a `HashEmbedder` store ADMITS [`PARAPHRASE`] after [`ORIGINAL`] — so leg 3's
///    refusal is attributable to the embedding and nothing else. Without this leg
///    the test would still pass on a build whose semantic path was broken or
///    absent, because a lexical gate could have produced the same refusal;
/// 3. the semantic store REFUSES that same pair — the gate itself.
///
/// The two ACCEPT legs run before the REFUSE leg deliberately. A gate breaks in
/// one of two directions, and running them in this order names the direction on
/// the first failure rather than letting an early return hide the rest: a gate
/// that refuses everything fails legs 1–2 with legs 3 unreached, a gate that
/// refuses nothing fails leg 3 with 1–2 already green.
#[tokio::test]
#[ignore = "downloads the default embedding model and runs native ONNX Runtime"]
async fn the_semantic_dedup_gate_refuses_a_restatement_a_lexical_build_admits()
-> Result<(), BoxError> {
    let repo = RepoScope::Repo("thebrain".to_owned());

    // The premise, asserted rather than asserted-in-prose: if the pair's token
    // overlap ever reached the gate, a lexical build could refuse it too and the
    // refusal leg below would prove nothing about the semantic path.
    let overlap = token_jaccard(ORIGINAL, PARAPHRASE);
    assert!(
        overlap < DEDUP_THRESHOLD / 2.0,
        "this test's value rests on the pair being lexically unremarkable, but its token-set \
         Jaccard is {overlap:.3} against a {DEDUP_THRESHOLD} gate — close enough that a refusal \
         could come from shared words rather than from meaning"
    );

    // One embedder, shared: the store ranks with it and the test measures the
    // very same vectors, so no second model load can disagree with the gate.
    let embedder: Arc<dyn Embedder> = Arc::new(FastEmbedder::try_new()?);
    let store = store_with(Arc::clone(&embedder))?;

    let original_id = remember_unforced(&store, &repo, ORIGINAL).await?;

    // Leg 1: a genuinely distinct note still gets in — a gate that refused
    // everything would pass the refusal leg below on its own.
    let vectors = embedder.embed(&[ORIGINAL.to_owned(), DISTINCT.to_owned()])?;
    let distinct_cos = cosine(&vectors[0], &vectors[1]);
    remember_unforced(&store, &repo, DISTINCT)
        .await
        .map_err(|err| {
            format!(
                "a genuinely distinct note (cosine {distinct_cos:.3} to the stored one, under the \
                 {DEDUP_THRESHOLD} gate) must be accepted, or the gate refuses everything: {err:?}"
            )
        })?;
    println!("\n  distinct note accepted at cosine {distinct_cos:.4}");

    // Leg 2: the pair under test, same unforced writes, through the LEAN build's
    // embedder. Its gate scores token Jaccard rather than cosine, so it admits
    // what the semantic gate refuses below — which is what makes that refusal
    // evidence about the semantic path specifically.
    let lexical = store_with(Arc::new(HashEmbedder::default()))?;
    remember_unforced(&lexical, &repo, ORIGINAL).await?;
    remember_unforced(&lexical, &repo, PARAPHRASE)
        .await
        .map_err(|err| {
            format!(
                "a LEXICAL build must ADMIT this pair (token Jaccard {overlap:.3} against the same \
                 {DEDUP_THRESHOLD} gate); if it refuses, the semantic refusal below is not \
                 evidence about the semantic path: {err:?}"
            )
        })?;
    println!("  lexical build admitted the pair (its gate scores token overlap)");

    // Leg 3: the semantic gate refuses the restatement.
    let refused = remember_unforced(&store, &repo, PARAPHRASE).await;
    let (existing, similarity) = match &refused {
        Err(MemError::NearDuplicate {
            existing,
            similarity,
        }) => (*existing, *similarity),
        Err(other) => {
            return Err(format!(
                "the restatement must be refused as a near-duplicate, but remember failed with: {other:?}"
            )
            .into());
        }
        Ok(id) => {
            return Err(format!(
                "the restatement must be refused as a near-duplicate, but the store accepted it as {id:?}"
            )
            .into());
        }
    };

    assert_eq!(
        existing, original_id,
        "the refusal must name the note it duplicates, so a user can go read it"
    );
    assert!(
        similarity >= DEDUP_THRESHOLD,
        "a refusal must be justified by the similarity it reports, but {similarity:.4} is below \
         the {DEDUP_THRESHOLD} gate"
    );

    println!("  gate refused at cosine {similarity:.4} (threshold {DEDUP_THRESHOLD})");
    println!("  token-set Jaccard of the pair: {overlap:.4}\n");

    Ok(())
}

/// The lean-versus-`embeddings` delta, measured through both shipped builds.
///
/// The product ships two builds whose recall differs materially — the lean one
/// is what a plain `cargo build` produces, what Intel macOS gets, and what every
/// non-nightly CI job exercises — and nothing measured the difference. This
/// prints it, so the nightly log carries the current delta, and asserts the
/// direction so a regression that erases it fails.
///
/// Both arms run the SAME 11 summaries and SAME 8 paraphrase queries through
/// `MemoryStore::recall`, so each build applies its own production floor itself
/// rather than having one imposed on it:
///
/// - lean: `HashEmbedder` reports `contributes_semantic_leg() == false`, so the
///   ranker runs keyword-only and the only floor applied is the lexical leg's
///   exact `0.0` — a BM25 score of 0 means no shared token. No cosine floor is
///   applied because no cosine is computed.
/// - model: `FastEmbedder::try_new` carries bge-small's calibrated `0.55`
///   (`EmbedModel::default_floor`) on the semantic leg, fused with that same
///   keyword leg.
///
/// Scoring the two embedders' cosines against one floor instead would measure
/// the floor rather than the embedder, in either direction: bge's `0.55` applied
/// to the 64-dimension FNV hash vectors keeps 1 of the 8 labelled targets, while
/// `HashEmbedder`'s own nominal `0.0` keeps 8 of 8 — two answers from one set of
/// vectors, neither of them what the lean build does.
///
/// What is asserted and what is only printed: `recall@floor` is printed and NOT
/// asserted, because it does not separate the builds. Both recover all 8 targets
/// above their floors — the lexical leg has no IDF and no stopword list, so a
/// query sharing even a function word scores above `0.0` and the target is
/// returned. The separation is in RANK, which is what `docs/SECURITY.md` means
/// by a paraphrase that "will not match well", so the assertions are on the
/// [`WINDOW`] count and on summed rank. On an 11-note corpus every build looks
/// good at `recall@floor`; rank is what decides whether the right note is still
/// in the window on a real one.
#[tokio::test]
#[ignore = "downloads the default embedding model and runs native ONNX Runtime"]
async fn the_lean_build_recovers_fewer_paraphrase_targets_than_the_model_build()
-> Result<(), BoxError> {
    let model = EmbedModel::default();
    let floor = model.default_floor();

    let lean = measure_build(
        "lean build: HashEmbedder, keyword-only, lexical floor 0.00",
        Arc::new(HashEmbedder::default()),
    )
    .await?;

    let semantic = measure_build(
        &format!("model build: {model}, semantic floor {floor:.2} + the same keyword leg"),
        Arc::new(FastEmbedder::try_new()?),
    )
    .await?;

    let queries = QUERIES.len();
    println!(
        "\n  corpus: {} note summaries, {queries} labelled paraphrase queries",
        SUMMARIES.len()
    );
    println!(
        "  recall@floor              lean {}/{queries}   model {}/{queries}   (does not separate)",
        lean.above_floor, semantic.above_floor
    );
    println!(
        "  recall@{WINDOW}                 lean {}/{queries}   model {}/{queries}",
        lean.in_window, semantic.in_window
    );
    println!(
        "  summed target rank        lean {}      model {}      (lower is better)\n",
        lean.rank_sum, semantic.rank_sum
    );

    assert!(
        semantic.in_window > lean.in_window,
        "the lean build must recover strictly FEWER paraphrase targets inside the top {WINDOW}, \
         but it recovered {} of {queries} against the model build's {}",
        lean.in_window,
        semantic.in_window,
    );
    assert!(
        semantic.rank_sum < lean.rank_sum,
        "the model build must rank the labelled targets strictly better in aggregate, but its \
         summed rank is {} against the lean build's {}",
        semantic.rank_sum,
        lean.rank_sum,
    );

    Ok(())
}
