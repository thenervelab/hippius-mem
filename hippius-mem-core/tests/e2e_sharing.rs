//! Cross-machine memory sharing through one shared op-log.
//!
//! This proves the design's central claim — "the index is rebuildable from the
//! shared log" — at the seam that matters: two `MemoryStore`s (two developer
//! machines) share one bucket and one team key but keep independent local
//! indexes and their own signing identities. A note written on machine A is
//! invisible to machine B until B `sync`s its index from the shared op-log, after
//! which B can both `recall` the pointer and `get` the full body. The in-memory
//! `MemoryBlobStore` stands in for the Hippius S3 gateway; the gateway honours the
//! same `BlobStore` contract (lexicographic `list`, key-addressed `get`), so the
//! sync logic exercised here is the same code that runs against a real bucket.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning test uses `?` for setup but still asserts on outcomes; the assertions are the test, not a crash to avoid"
)]

use std::collections::BTreeSet;
use std::sync::Arc;

use hippius_mem_core::{
    BlobStore, HashEmbedder, InMemoryIndex, MemoryBlobStore, MemoryStore, NetworkPrefix,
    NoopAnchor, NoteType, OpLogStore, RecallInput, RememberInput, RepoScope, SecretKey, Signer,
    Sr25519Signer, Ss58,
};

/// Production anchor threshold; this test writes fewer ops than this, so its
/// (no-op) anchoring stays inert and the focus remains the cross-machine sync.
const ANCHOR_THRESHOLD: usize = 16;

/// The shared namespace both machines write into.
const TEAM: &str = "ourovoros";
/// The shared team key. Both machines must seal/open under the same bytes for
/// cross-machine decryption to work; that shared secret is the team key.
const TEAM_KEY: [u8; 32] = [9_u8; 32];

type BoxError = Box<dyn std::error::Error>;

/// Build one developer machine's store over the shared `bucket`.
///
/// Every machine shares the bucket and team key but gets its OWN empty index,
/// its OWN op-log handle over the shared bucket, and its OWN signing identity
/// built from `seed` (its author SS58 is derived from the key, so distinct seeds
/// are distinct authors) — exactly the topology of two devs running their own MCP
/// server against one team bucket.
fn machine(bucket: &Arc<MemoryBlobStore>, seed: [u8; 32]) -> Result<MemoryStore, BoxError> {
    let index = Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default())));
    // Unsize the concrete fake into the trait object the store stores; both
    // machines share the SAME underlying bucket through these cloned handles.
    let blob: Arc<dyn BlobStore> = bucket.clone();
    let oplog = OpLogStore::new(blob.clone());
    let signer: Arc<dyn Signer> = Arc::new(Sr25519Signer::from_seed_with_prefix(
        &seed,
        NetworkPrefix::HIPPIUS,
    )?);
    Ok(MemoryStore::new(
        blob,
        index,
        oplog,
        Arc::new(NoopAnchor),
        signer,
        std::collections::BTreeMap::from([(0_u64, SecretKey::from_bytes(TEAM_KEY))]),
        0,
        TEAM.to_owned(),
        ANCHOR_THRESHOLD,
    ))
}

/// The SS58 a machine built from `seed` signs as — the derived author the
/// attribution assertion compares against.
fn author_of(seed: [u8; 32]) -> Result<Ss58, BoxError> {
    Ok(Sr25519Signer::from_seed_with_prefix(&seed, NetworkPrefix::HIPPIUS)?.author_ss58())
}

#[tokio::test]
async fn second_machine_discovers_first_machines_note_after_sync() -> Result<(), BoxError> {
    let bucket = Arc::new(MemoryBlobStore::default());
    // 48-char SS58 stand-ins with distinct seeds; distinct identities prove
    // attribution survives the sync (B reads back the note A signed, not its own
    // identity) and that B verifies A's signature against A's own key.
    let machine_a = machine(&bucket, [5_u8; 32])?;
    let machine_b = machine(&bucket, [6_u8; 32])?;

    let repo = RepoScope::Repo("thebrain".to_owned());
    let summary = "benchmark pallet weights before every mainnet release".to_owned();
    let body = "Unbenchmarked weights underprice extrinsics and open a DoS vector; \
                run the runtime benchmark suite and commit the generated weights."
        .to_owned();

    let id = machine_a
        .remember(RememberInput {
            note_type: NoteType::Convention,
            repo: repo.clone(),
            tags: BTreeSet::from(["weights".to_owned(), "mainnet".to_owned()]),
            summary: summary.clone(),
            body: body.clone(),
        })
        .await?;

    // B's index is brand new and has never read the log: recall is empty even
    // though A's note already sits in the shared bucket as ciphertext + a signed op.
    let before = machine_b
        .recall(RecallInput {
            text: "benchmark weights mainnet".to_owned(),
            repo: repo.clone(),
            k: 10,
            token_budget: None,
        })?
        .pointers;
    assert!(
        before.is_empty(),
        "machine B saw memory before syncing its index from the op-log"
    );

    // The sync verifies + converges the shared op-log and repopulates B's index.
    let indexed = machine_b.sync().await?;
    assert_eq!(
        indexed, 1,
        "exactly one live note lives in the shared op-log"
    );

    // Now B surfaces A's note as a pointer (summary, never the body).
    let after = machine_b
        .recall(RecallInput {
            text: "benchmark weights mainnet".to_owned(),
            repo,
            k: 10,
            token_budget: None,
        })?
        .pointers;
    let pointer = after
        .iter()
        .find(|pointer| pointer.note_id == id)
        .ok_or("machine B did not surface machine A's note after rebuild")?;
    assert_eq!(pointer.summary, summary);

    // And B can hydrate the full body and read back A's authorship — the shared
    // bucket plus rebuild deliver cross-machine memory end to end.
    let note = machine_b.get(id).await?;
    assert_eq!(note.body, body);
    assert_eq!(note.summary, summary);
    assert_eq!(note.author, author_of([5_u8; 32])?);
    Ok(())
}
