//! Measured retrieval quality for the SHIPPED embedding model, asserted.
//!
//! The repo already had a labelled corpus — 11 real note summaries and 8
//! paraphrase queries in `examples/calibrate.rs` — and it computed exactly the
//! right metrics. But an example has no assertions and no CI job ever ran it, so
//! the numbers documented in `docs/SECURITY.md` were a one-time manual
//! measurement that nothing recomputed and nothing failed on when it degraded.
//!
//! These tests turn that corpus into a regression gate. They are `#[ignore]`d
//! (they download ~90 MB of ONNX model and run it) and gated on the `embeddings`
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

#![cfg(feature = "embeddings")]
#![expect(
    clippy::expect_used,
    reason = "tests assert on outcomes; expect documents invariants on fixtures whose construction cannot fail"
)]

use hippius_mem_core::{EmbedModel, Embedder, FastEmbedder};

include!("shared/calibration_corpus.rs");

/// Mirrors `hippius_mem_core::store::DEDUP_THRESHOLD`, which is private. The
/// value itself is pinned by `the_dedup_threshold_is_pinned_at_its_boundary` in
/// the store's unit tests, so a change there fails that test first and this
/// constant cannot silently drift away from the real gate.
const DEDUP_THRESHOLD: f32 = 0.9;

/// Embed the corpus with the model under test, using a raw 0.0 threshold so the
/// cosines are unfloored and the floor can be applied explicitly.
fn embed_corpus(model: EmbedModel) -> (FastEmbedder, Vec<Vec<f32>>) {
    let embedder = FastEmbedder::try_with(model, 0.0).expect("embedder loads");

    let docs: Vec<String> = SUMMARIES.iter().map(|s| (*s).to_owned()).collect();
    let vectors = embedder.embed(&docs).expect("corpus embeds");

    (embedder, vectors)
}

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
