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
    Sr25519Signer, Ss58, TeamManifest, load_manifest, publish_manifest,
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
            force: true,
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

/// The founder-key-loss escape hatch, end to end, through the exact core
/// calls the CLI's `provision` and `recover` make
/// ([`MemoryStore::publish_recovery_key`], [`MemoryStore::recover_founder`]):
/// founder A publishes membership and names recovery key R (provision's
/// default); A's signer is then dropped, simulating the key being lost; R
/// recovers, becoming the new founder and naming a fresh recovery key R2.
///
/// Then, directly against the chain-of-custody election
/// ([`load_manifest`]/`elect_live`, Task 9): a further manifest signed by the
/// OLD founder A can never advance the chain past the recovery (its key is
/// neither the live manifest's own founder key nor the recovery key it
/// names), while one signed by the recovered founder R can.
#[tokio::test]
async fn founder_loss_recovers_through_the_recovery_key() -> Result<(), BoxError> {
    let bucket = Arc::new(MemoryBlobStore::default());
    let founder_a_seed = [21_u8; 32];
    let first_recovery_seed = [22_u8; 32];
    let second_recovery_seed = [23_u8; 32];

    // provision-equivalent: founder A publishes membership, then names
    // recovery R via `publish_recovery_key` — the exact call `provision`'s
    // default recovery generation makes (same version, `Some(recovery_key)`).
    let founder_store = machine(&bucket, founder_a_seed)?;
    founder_store
        .publish_membership(BTreeSet::from([author_of(founder_a_seed)?]))
        .await?;
    let recovery_signer =
        Sr25519Signer::from_seed_with_prefix(&first_recovery_seed, NetworkPrefix::HIPPIUS)?;
    founder_store
        .publish_recovery_key(recovery_signer.verifying_key())
        .await?;

    // Simulate loss: A's signer/store is dropped and never used again.
    drop(founder_store);

    // R recovers — the exact call `recover` makes: `recover_founder` with a
    // fresh recovery key R2. The recovering operator's own local identity
    // (here, a throwaway machine) plays no role in authorization.
    let operator = machine(&bucket, [29_u8; 32])?;
    let fresh_recovery_signer =
        Sr25519Signer::from_seed_with_prefix(&second_recovery_seed, NetworkPrefix::HIPPIUS)?;
    let recovered = operator
        .recover_founder(&recovery_signer, fresh_recovery_signer.verifying_key())
        .await?;
    assert_eq!(
        recovered.version, 1,
        "recovery advances to the next version"
    );
    assert_eq!(recovered.founder, recovery_signer.author_ss58());

    // `load_manifest` (unpinned trust-on-genesis) elects the recovered v2 as
    // live.
    let live = load_manifest(bucket.as_ref(), TEAM, None).await?;
    assert_eq!(
        live.as_ref().map(|m| m.version),
        Some(1),
        "load_manifest elects the recovery-signed manifest"
    );
    assert_eq!(
        live.as_ref().map(|m| m.founder.clone()),
        Some(recovery_signer.author_ss58()),
        "the elected manifest's founder is the recovery identity"
    );

    // A further manifest signed by the OLD founder A at the next version is
    // SKIPPED: A's key is neither the live manifest's own founder_key nor the
    // recovery key it names, so it cannot advance the chain.
    let founder_a_again =
        Sr25519Signer::from_seed_with_prefix(&founder_a_seed, NetworkPrefix::HIPPIUS)?;
    let stale_founder_attempt = TeamManifest::create_signed_with_recovery(
        &founder_a_again,
        TEAM.to_owned(),
        BTreeSet::from([founder_a_again.author_ss58()]),
        2,
        None,
    );
    publish_manifest(bucket.as_ref(), &stale_founder_attempt).await?;
    let live_after_old_founder = load_manifest(bucket.as_ref(), TEAM, None).await?;
    assert_eq!(
        live_after_old_founder.as_ref().map(|m| m.version),
        Some(1),
        "the old founder's key cannot advance the chain past the recovery"
    );

    // One signed by R (the recovered founder) at the same version IS
    // accepted and becomes live.
    let recovered_founder_advances = TeamManifest::create_signed_with_recovery(
        &recovery_signer,
        TEAM.to_owned(),
        BTreeSet::from([recovery_signer.author_ss58()]),
        2,
        Some(fresh_recovery_signer.verifying_key()),
    );
    publish_manifest(bucket.as_ref(), &recovered_founder_advances).await?;
    let live_after_new_founder = load_manifest(bucket.as_ref(), TEAM, None).await?;
    assert_eq!(
        live_after_new_founder.as_ref().map(|m| m.version),
        Some(2),
        "the recovered founder's key advances the chain normally"
    );
    Ok(())
}
