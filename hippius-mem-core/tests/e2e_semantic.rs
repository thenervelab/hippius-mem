//! End-to-end proof that semantic recall works through the REAL `MemoryStore`
//! pipeline — client-side XChaCha20-Poly1305 sealing, the signed op-log, and the
//! index — not just the index in isolation. A note is `remember`ed, then a
//! paraphrased query that shares NO words with it `recall`s it back, while an
//! unrelated note is correctly left out, and the sealed body round-trips through
//! `get`. The in-memory `MemoryBlobStore` stands in for the Hippius S3 gateway
//! (same `BlobStore` contract), so this is the same remember/recall/get code the
//! MCP tools run against a real bucket.
//!
//! Gated on the `embeddings` feature and `#[ignore]`d: it loads `all-MiniLM-L6-v2`
//! (~90 MB ONNX download on first run). Run it with:
//!
//! ```text
//! cargo test -p hippius-mem-core --features embeddings --test e2e_semantic -- --ignored --nocapture
//! ```
#![cfg(feature = "embeddings")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning test uses `?` for setup but still asserts on outcomes; the assertions are the test"
)]
#![expect(
    clippy::print_stdout,
    reason = "this is a runnable demonstration — it prints the ranked recall result so the run is legible"
)]

use std::collections::BTreeSet;
use std::sync::Arc;

use hippius_mem_core::{
    BlobStore, Embedder, FastEmbedder, InMemoryIndex, MemoryBlobStore, MemoryStore, NetworkPrefix,
    NoopAnchor, NoteId, NoteType, OpLogStore, RecallInput, RememberInput, RepoScope, SecretKey,
    Signer, Sr25519Signer,
};

const TEAM: &str = "ourovoros";
/// Shared team key — the bytes every member seals/opens note content under.
const TEAM_KEY: [u8; 32] = [9_u8; 32];
const ANCHOR_THRESHOLD: usize = 16;

type BoxError = Box<dyn std::error::Error>;

/// A real `MemoryStore` whose only non-default piece is the embedder under test:
/// a `MemoryBlobStore` fake stands in for the S3 gateway, `NoopAnchor` for the
/// chain, and a seed-derived `Sr25519Signer` for the author identity.
fn store_with(embedder: Arc<dyn Embedder>) -> Result<MemoryStore, BoxError> {
    let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
    let oplog = OpLogStore::new(blob.clone());
    let signer: Arc<dyn Signer> = Arc::new(Sr25519Signer::from_seed_with_prefix(
        &[7_u8; 32],
        NetworkPrefix::HIPPIUS,
    )?);
    Ok(MemoryStore::new(
        blob,
        Arc::new(InMemoryIndex::new(embedder)),
        oplog,
        Arc::new(NoopAnchor),
        signer,
        std::collections::BTreeMap::from([(0_u64, SecretKey::from_bytes(TEAM_KEY))]),
        0,
        TEAM.to_owned(),
        ANCHOR_THRESHOLD,
    ))
}

async fn remember(
    store: &MemoryStore,
    repo: &RepoScope,
    summary: &str,
    body: &str,
) -> Result<NoteId, BoxError> {
    Ok(store
        .remember(RememberInput {
            note_type: NoteType::Gotcha,
            repo: repo.clone(),
            tags: BTreeSet::new(),
            summary: summary.to_owned(),
            body: body.to_owned(),
        })
        .await?)
}

#[tokio::test]
#[ignore = "downloads the default embedding model and runs native ONNX Runtime"]
async fn semantic_recall_finds_a_paraphrase_through_the_full_store() -> Result<(), BoxError> {
    let repo = RepoScope::Repo("thebrain".to_owned());

    // The note we want back. Its words do NOT appear in the query below.
    let target_summary = "release pooled db handles when a service stops cleanly";
    let target_body = "On shutdown, drain and close every pooled connection so the \
                       process exits without leaking sockets.";
    // A note unrelated in BOTH words and meaning (and sharing no query tokens, so
    // not even the keyword leg can surface it): it must NOT come back, proving
    // recall selects by meaning rather than returning everything stored.
    let noise_summary = "espresso machine descaling schedule for third floor kitchen";
    let noise_body = "Descale monthly or limescale ruins the crema.";

    // A paraphrase of the target that shares ZERO words with its summary.
    let query = "close every database connection in the pool on graceful shutdown";

    let store = store_with(Arc::new(FastEmbedder::try_new()?))?;
    let target_id = remember(&store, &repo, target_summary, target_body).await?;
    let noise_id = remember(&store, &repo, noise_summary, noise_body).await?;

    let result = store.recall(RecallInput {
        text: query.to_owned(),
        repo: repo.clone(),
        k: 10,
        token_budget: None,
    })?;

    println!("\n  query : {query}");
    println!("  want  : {target_summary}");
    println!("  recall returned {} hit(s):", result.pointers.len());
    for (rank, pointer) in result.pointers.iter().enumerate() {
        println!("    #{rank}  score {:.4}  {}", pointer.score, pointer.summary);
    }

    let top = result
        .pointers
        .first()
        .ok_or("semantic recall returned nothing for the paraphrase")?;
    assert_eq!(
        top.note_id, target_id,
        "the zero-overlap paraphrase must rank the meaning-matching note first"
    );
    assert!(
        result.pointers.iter().all(|p| p.note_id != noise_id),
        "the unrelated note must not surface — recall must select by meaning, not dump the store"
    );

    // The whole pipeline round-trips: the body sealed on `remember` decrypts back
    // unchanged on `get`.
    let note = store.get(target_id).await?;
    assert_eq!(note.summary, target_summary);
    assert_eq!(note.body, target_body);
    println!("  get   : sealed body decrypted back unchanged ✓\n");
    Ok(())
}
