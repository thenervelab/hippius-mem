//! Retrieval EFFICIENCY guarantees: the index must not do redundant embedding
//! work. Embedding is the expensive step (ONNX inference on a real build), so
//! these tests wrap the embedder in a call counter and assert the index reuses a
//! stored embedding whenever a summary is unchanged, and amortizes a batch into a
//! single embedder call.
//!
//! This directly guards a real past regression: incremental sync was once NOT
//! incremental on the embed axis — every sync re-ran the model over the whole
//! live corpus because unchanged summaries' embeddings were never reused. A
//! `CountingEmbedder` makes that failure mode a red test.

#![expect(
    clippy::panic_in_result_fn,
    clippy::expect_used,
    reason = "Result-returning tests assert on outcomes; expect documents invariants on throwaway fixtures whose construction cannot fail"
)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use hippius_mem_core::{
    Blake3Hash, Embedder, HashEmbedder, InMemoryIndex, IndexRecord, MemError, MemoryIndex, NoteId,
    NoteType, RepoScope, Scope, Timestamp,
};

/// An [`Embedder`] that delegates to the lexical [`HashEmbedder`] but counts how
/// many times it is invoked and how many texts it is asked to embed in total.
/// Reused embeddings never reach `embed`, so a zero delta in `texts` is proof no
/// re-embedding happened.
struct CountingEmbedder {
    inner: HashEmbedder,
    calls: AtomicUsize,
    texts: AtomicUsize,
}

impl CountingEmbedder {
    fn new() -> Self {
        Self {
            inner: HashEmbedder::default(),
            calls: AtomicUsize::new(0),
            texts: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn texts(&self) -> usize {
        self.texts.load(Ordering::SeqCst)
    }
}

impl Embedder for CountingEmbedder {
    fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, MemError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.texts.fetch_add(texts.len(), Ordering::SeqCst);
        self.inner.embed(texts)
    }

    fn dim(&self) -> usize {
        self.inner.dim()
    }

    // Mirror the HashEmbedder: lexical, no semantic leg. Keeps the index's
    // behavior identical to a real lexical build.
    fn contributes_semantic_leg(&self) -> bool {
        false
    }
}

/// A minimal record carrying `summary` under a fresh id.
fn record(summary: &str) -> IndexRecord {
    IndexRecord {
        note_id: NoteId::new(),
        object_key: "team/repo/mem/ver_0".to_owned(),
        cid: Blake3Hash::new([0_u8; 32]),
        scope: Scope {
            team: "team".to_owned(),
            repo: RepoScope::Global,
        },
        note_type: NoteType::Decision,
        author: hippius_mem_core::Ss58::new("5".repeat(48)).expect("valid ss58"),
        updated: Timestamp::new(0),
        lamport: 0,
        key_epoch: 0,
        tags: BTreeSet::new(),
        summary: summary.to_owned(),
        relations: Vec::new(),
        reinforcers: BTreeSet::new(),
        last_reinforced: None,
        embedding: None,
    }
}

/// A whole batch of misses is embedded in ONE embedder call, not one per record.
/// This is the entire reason `upsert_batch` overrides the serial default: the
/// per-call model-run overhead dominates a cold rebuild.
///
/// Discriminates a regression to the serial fallback (which would call `embed`
/// five times).
#[test]
fn a_batch_embeds_all_misses_in_a_single_call() -> Result<(), Box<dyn std::error::Error>> {
    let embedder = Arc::new(CountingEmbedder::new());
    let index = InMemoryIndex::new(embedder.clone());

    let records: Vec<IndexRecord> = (0..5)
        .map(|i| record(&format!("distinct summary number {i}")))
        .collect();
    index.upsert_batch(records)?;

    assert_eq!(embedder.calls(), 1, "the batch must embed in a single call");
    assert_eq!(
        embedder.texts(),
        5,
        "all five misses must be embedded once each"
    );
    Ok(())
}

/// Re-indexing the SAME summaries (the shape of an incremental sync, where
/// snapshot-restored records arrive with `embedding: None`) must reuse the stored
/// embeddings and embed nothing. This is the regression guard: a sync that
/// re-embeds unchanged notes would show a non-zero `texts` delta on the second
/// batch.
#[test]
fn unchanged_summaries_are_not_re_embedded_on_resync() -> Result<(), Box<dyn std::error::Error>> {
    let embedder = Arc::new(CountingEmbedder::new());
    let index = InMemoryIndex::new(embedder.clone());

    let records: Vec<IndexRecord> = (0..8)
        .map(|i| record(&format!("stable summary {i}")))
        .collect();

    index.upsert_batch(records.clone())?;
    let embedded_after_first = embedder.texts();
    assert_eq!(
        embedded_after_first, 8,
        "first pass embeds every summary once"
    );

    // Second pass with byte-identical summaries and `embedding: None` (as a
    // snapshot restore delivers them).
    index.upsert_batch(records)?;
    assert_eq!(
        embedder.texts(),
        embedded_after_first,
        "an incremental re-index of unchanged summaries must embed nothing"
    );
    Ok(())
}

/// Embedding reuse is keyed on summary CONTENT, not merely the note id: an
/// unchanged summary is reused, but an EDITED summary under the same id is
/// re-embedded (its old vector would be wrong for the new text).
#[test]
fn an_edited_summary_is_re_embedded_but_an_unchanged_one_is_not()
-> Result<(), Box<dyn std::error::Error>> {
    let embedder = Arc::new(CountingEmbedder::new());
    let index = InMemoryIndex::new(embedder.clone());

    let mut rec = record("configuration schema version one");
    index.upsert(rec.clone())?;
    let after_first = embedder.texts();
    assert_eq!(after_first, 1, "the initial summary is embedded once");

    // Same id, same summary -> reuse, no embed.
    index.upsert(rec.clone())?;
    assert_eq!(
        embedder.texts(),
        after_first,
        "re-upserting an unchanged summary must not re-embed"
    );

    // Same id, edited summary -> must re-embed.
    rec.summary = "configuration schema version two".to_owned();
    index.upsert(rec)?;
    assert_eq!(
        embedder.texts(),
        after_first + 1,
        "an edited summary must be re-embedded"
    );
    Ok(())
}
