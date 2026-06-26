//! Cross-machine memory sharing through one shared bucket.
//!
//! This proves the design's central claim — "the index is rebuildable from the
//! blobs" — at the seam that matters: two `MemoryStore`s (two developer
//! machines) share one bucket and one team key but keep independent local
//! indexes. A note written on machine A is invisible to machine B until B
//! rebuilds its index from the shared bucket, after which B can both `recall`
//! the pointer and `get` the full body. The in-memory `MemoryBlobStore` stands
//! in for the Hippius S3 gateway; the gateway honours the same `BlobStore`
//! contract (lexicographic `list`, key-addressed `get`), so the rebuild logic
//! exercised here is the same code that runs against a real bucket.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning test uses `?` for setup but still asserts on outcomes; the assertions are the test, not a crash to avoid"
)]

use std::collections::BTreeSet;
use std::sync::Arc;

use hippius_mem_core::{
    BlobStore, HashEmbedder, InMemoryIndex, MemoryBlobStore, MemoryStore, NoteType, RecallInput,
    RememberInput, RepoScope, SecretKey, Ss58,
};

/// The shared namespace both machines write into.
const TEAM: &str = "ourovoros";
/// The shared team key. Both machines must seal/open under the same bytes for
/// cross-machine decryption to work; that shared secret is the team key.
const TEAM_KEY: [u8; 32] = [9_u8; 32];

type BoxError = Box<dyn std::error::Error>;

/// Build one developer machine's store over the shared `bucket`.
///
/// Every machine shares the bucket and team key but gets its OWN empty index
/// and its OWN author identity — exactly the topology of two devs running their
/// own MCP server against one team bucket.
fn machine(bucket: &Arc<MemoryBlobStore>, author_ss58: &str) -> Result<MemoryStore, BoxError> {
    // `Ss58::new`'s error type is private to the core crate; stringify it so the
    // `?` only ever has to convert a `String` into the boxed test error.
    let author = Ss58::new(author_ss58).map_err(|err| err.to_string())?;
    let index = Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default())));
    // Unsize the concrete fake into the trait object the store stores; both
    // machines share the SAME underlying bucket through these cloned handles.
    let blob: Arc<dyn BlobStore> = bucket.clone();
    Ok(MemoryStore::new(
        blob,
        index,
        SecretKey::from_bytes(TEAM_KEY),
        TEAM.to_owned(),
        author,
    ))
}

#[tokio::test]
async fn second_machine_discovers_first_machines_note_after_rebuild() -> Result<(), BoxError> {
    let bucket = Arc::new(MemoryBlobStore::default());
    // 48-char SS58 stand-ins; distinct authors prove attribution survives the
    // rebuild (B reads back the note A signed, not its own identity).
    let machine_a = machine(&bucket, &"5".repeat(48))?;
    let machine_b = machine(&bucket, &"6".repeat(48))?;

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

    // B's index is brand new and has never seen the bucket: recall is empty even
    // though A's note already sits in the shared bucket as ciphertext.
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
        "machine B saw memory before rebuilding its index from the bucket"
    );

    // The rebuild lists + decrypts the shared bucket and repopulates B's index.
    let rebuilt = machine_b.rebuild_index().await?;
    assert_eq!(rebuilt, 1, "exactly one note lives in the shared bucket");

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
    assert_eq!(note.author.as_str(), "5".repeat(48));
    Ok(())
}
