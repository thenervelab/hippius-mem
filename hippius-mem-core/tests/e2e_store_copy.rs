//! A byte copy of a team's objects between blob stores preserves the full
//! verifiable state: ops, signatures, history, and reconcile all hold on the
//! destination. This is the invariant `hippius-mem upgrade` (trial -> bucket)
//! depends on.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning test uses `?` for setup but still asserts on outcomes; the assertions are the test, not a crash to avoid"
)]

use std::collections::BTreeSet;
use std::sync::Arc;

use hippius_mem_core::{
    Blake3Hash, BlobStore, HashEmbedder, InMemoryIndex, MemoryBlobStore, MemoryStore,
    NetworkPrefix, NoopAnchor, NoteId, NoteType, OpLogStore, RecallInput, RememberInput, RepoScope,
    SecretKey, Signer, Sr25519Signer, copy_store,
};

/// Production anchor threshold; this test writes fewer ops than this, so its
/// (no-op) anchoring stays inert and the focus stays on the copy invariant.
const ANCHOR_THRESHOLD: usize = 16;

/// The team namespace the seeded notes live under.
const TEAM: &str = "ourovoros-copy";
/// The team key both stores seal/open under. A copy only preserves state if
/// the destination is handed this SAME key — that is what `upgrade` will do
/// (carry the team key across unchanged, never mint a new one).
const TEAM_KEY: [u8; 32] = [11_u8; 32];

/// The repository dimension the seeded notes live under.
const REPO: &str = "vault";

type BoxError = Box<dyn std::error::Error>;

/// Build one store over `blob`, mirroring `e2e_sharing.rs`'s `machine` helper:
/// the same team and team key, and a signer derived from `seed`. Deviates from
/// that helper only in taking `seed` explicitly (rather than a fixed constant)
/// so this file's two calls can mint distinct identities — the "fresh reader"
/// on the destination side.
fn build_test_store(blob: Arc<MemoryBlobStore>, seed: [u8; 32]) -> Result<MemoryStore, BoxError> {
    let index = Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default())));
    // Unsize the concrete fake into the trait object the store holds.
    let blob: Arc<dyn BlobStore> = blob;
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

/// Remember three notes on `store`, edit one of them once, link a second pair,
/// then sync so the op-log and the local index are fully converged — the state
/// `assert_converged_state_matches` checks a bucket copy preserves.
async fn seed_three_notes(store: &MemoryStore) -> Result<(), BoxError> {
    let repo = RepoScope::Repo(REPO.to_owned());

    let first = store
        .remember(RememberInput {
            force: true,
            note_type: NoteType::Convention,
            repo: repo.clone(),
            tags: BTreeSet::new(),
            summary: "trial vault holds the onboarding quickstart note".to_owned(),
            body: "hippius-mem quickstart writes its first note into a local trial vault."
                .to_owned(),
        })
        .await?;

    let second = store
        .remember(RememberInput {
            force: true,
            note_type: NoteType::Convention,
            repo: repo.clone(),
            tags: BTreeSet::new(),
            summary: "trial vault upgrade preserves signed op history".to_owned(),
            body: "op signatures never name the store, so a byte copy of the vault carries \
                   every proof across unchanged."
                .to_owned(),
        })
        .await?;

    // Edit `second` once, so its history carries both a Remember and an Edit
    // op through the copy.
    store
        .edit(
            second,
            RememberInput {
                force: true,
                note_type: NoteType::Convention,
                repo: repo.clone(),
                tags: BTreeSet::new(),
                summary: "trial vault upgrade preserves signed op history, revised".to_owned(),
                body: "revised: the copy is a plain put-overwrite of every object under the \
                       team prefix."
                    .to_owned(),
            },
        )
        .await?;

    let third = store
        .remember(RememberInput {
            force: true,
            note_type: NoteType::Convention,
            repo,
            tags: BTreeSet::new(),
            summary: "trial vault copy links back to the quickstart note".to_owned(),
            body: "the upgrade path links this milestone note to the quickstart note it \
                   followed."
                .to_owned(),
        })
        .await?;

    // Link `third` to `first`, so the converged link graph is also part of
    // what the copy must preserve.
    store.link(third, first).await?;

    // `remember`/`edit`/`link` already keep this store's own index consistent
    // with the op-log it just wrote; sync explicitly anyway so the seeded
    // state is unambiguously the converged one under test.
    store.sync().await?;

    Ok(())
}

/// Assert `dst` — freshly synced from a copied bucket — converges to the same
/// note ids and versions, the same note bodies, the same op history (which
/// only succeeds if every copied signature still verifies), and a clean
/// reconcile.
async fn assert_converged_state_matches(
    src: &MemoryStore,
    dst: &MemoryStore,
) -> Result<(), BoxError> {
    dst.sync().await?;

    // The converged index itself: same note ids and the same version (content
    // hash) for each, read straight from each store's local index.
    let mut src_records: Vec<(NoteId, Blake3Hash)> = src
        .list_records()?
        .into_iter()
        .map(|record| (record.note_id, record.cid))
        .collect();
    let mut dst_records: Vec<(NoteId, Blake3Hash)> = dst
        .list_records()?
        .into_iter()
        .map(|record| (record.note_id, record.cid))
        .collect();
    src_records.sort_by_key(|(id, _)| *id);
    dst_records.sort_by_key(|(id, _)| *id);
    assert_eq!(
        src_records.len(),
        3,
        "all three seeded notes must round-trip"
    );
    assert_eq!(
        src_records, dst_records,
        "a copy must converge to the same note ids and versions (content hashes)"
    );

    // Per note: body and full signed history. Read BEFORE the `recall` call
    // below — a `get` that follows a recent `recall` of the same note is a use
    // signal and writes a fresh `Reinforce` op (see `MemoryStore::get`'s
    // `maybe_reinforce`), which would salt the history comparison with a NEW op
    // signed by each store's own (deliberately distinct) reader identity.
    for (id, _) in &src_records {
        let src_note = src.get(*id).await?;
        let dst_note = dst.get(*id).await?;
        assert_eq!(
            src_note.body, dst_note.body,
            "note body must survive the copy"
        );
        assert_eq!(src_note.summary, dst_note.summary);

        // `history` reads and cryptographically verifies the op-log
        // (`OpLogStore::read_all`), so a successful, matching call on `dst`
        // IS the proof that every copied signature still verifies at its new
        // location.
        let src_history = src.history(*id).await?;
        let dst_history = dst.history(*id).await?;
        assert_eq!(
            src_history, dst_history,
            "op history (and its verified signatures) must match after the copy"
        );
    }

    // `recall` must surface the identical pointer set too, not just the raw
    // index — the retrieval path a real agent actually drives. Last, because
    // (as above) it starts the reinforcement window for these notes.
    let query = RecallInput {
        text: "trial vault".to_owned(),
        repo: RepoScope::Repo(REPO.to_owned()),
        k: 10,
        token_budget: None,
    };
    let mut src_pointer_ids: Vec<NoteId> = src
        .recall(query.clone())?
        .pointers
        .into_iter()
        .map(|pointer| pointer.note_id)
        .collect();
    let mut dst_pointer_ids: Vec<NoteId> = dst
        .recall(query)?
        .pointers
        .into_iter()
        .map(|pointer| pointer.note_id)
        .collect();
    src_pointer_ids.sort();
    dst_pointer_ids.sort();
    assert_eq!(
        src_pointer_ids, dst_pointer_ids,
        "recall on the copy must surface the same notes as the source"
    );

    let report = dst.reconcile().await?;
    assert!(
        report.missing_ops.is_empty(),
        "reconcile on the copy must find no missing ops: {:?}",
        report.missing_ops
    );
    assert!(
        report.root_mismatches.is_empty(),
        "reconcile on the copy must find no root mismatches: {:?}",
        report.root_mismatches
    );

    Ok(())
}

#[tokio::test]
async fn copied_store_preserves_converged_state() -> Result<(), Box<dyn std::error::Error>> {
    let src_blob = Arc::new(MemoryBlobStore::new());

    // Build a store over `src_blob` exactly as e2e_sharing.rs does, remember
    // three notes (one edited once, one linked), and sync so the op-log and
    // index are converged.
    let src_store = build_test_store(src_blob.clone(), [5_u8; 32])?;
    seed_three_notes(&src_store).await?;

    let dst_blob = Arc::new(MemoryBlobStore::new());
    let copied = copy_store(src_blob.as_ref(), dst_blob.as_ref(), "").await?;
    assert!(copied > 0, "the seeded team must have produced objects");

    // A fresh store over the COPY, same team key + a fresh reader identity,
    // must converge to identical state: same note ids and versions from
    // recall, same history (signatures verify), and reconcile passes.
    let dst_store = build_test_store(dst_blob.clone(), [6_u8; 32])?;
    assert_converged_state_matches(&src_store, &dst_store).await?;

    Ok(())
}
