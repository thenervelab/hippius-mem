//! Phase 2 capstone: two machines, one shared op-log, verifiable history.
//!
//! Phase 1 proved a second machine can *rebuild* its index from a shared bucket
//! ([`e2e_sharing`]). Phase 2 layers an append-only, signed, hash-chained op-log
//! over that bucket, converges concurrent writes from independent authors, and
//! anchors each op's hash into an on-chain-able Merkle root. These tests prove
//! the whole stack works across a two-machine seam:
//!
//! * `remember` on A converges into B's index after `sync` (pointer first, body
//!   on demand), and B reads back A's authorship — attribution survives the wire.
//! * a `forget` on A converges as a tombstone: B stops surfacing the note.
//! * `history` on B carries a Merkle inclusion proof for A's op that B can verify
//!   against the anchored root *without trusting A's server* — the Phase 2 thesis.
//! * two authors writing concurrently both converge: both machines end with both
//!   notes.
//!
//! The two `MemoryStore`s share one `Arc<MemoryBlobStore>` (ops and anchor
//! records are blobs) and one `Arc<dyn AuditAnchor>` (so a root A anchors is the
//! same object B's `history` reads), but keep independent local indexes and their
//! own signing identities — the topology of two developers running their own MCP
//! server against one team bucket.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning test uses `?` for setup but still asserts on outcomes; the assertions are the test, not a crash to avoid"
)]

use std::collections::BTreeSet;
use std::sync::Arc;

use hippius_mem_core::{
    AuditAnchor, BlobStore, HashEmbedder, InMemoryIndex, MemoryBlobStore, MemoryStore, NoteId,
    NoteType, OpKindLabel, OpLogStore, RecallInput, RecordingAnchor, RememberInput, RepoScope,
    SecretKey, Signer, Sr25519Signer, Ss58, verify_proof,
};

/// The shared namespace both machines write into.
const TEAM: &str = "ourovoros";
/// The shared team key. Both machines must seal/open under the same bytes for
/// cross-machine decryption to work; that shared secret is the team key.
const TEAM_KEY: [u8; 32] = [9_u8; 32];

/// A threshold no test reaches, so the (shared) anchor stays inert and the focus
/// is convergence rather than anchoring — the convergence tests want a clean
/// op-log, not anchor records cluttering the bucket.
const INERT_THRESHOLD: usize = 16;
/// A threshold of one: every op seals its own single-leaf Merkle batch the moment
/// it is logged, so `history` finds a proof without a separate flush. The history
/// test uses this.
const EAGER_THRESHOLD: usize = 1;

type BoxError = Box<dyn std::error::Error>;

/// Build one developer machine's store over the shared `bucket` and `anchor`.
///
/// Shared across machines: `bucket` (ops + anchor records are blobs) and
/// `anchor` (a root one machine anchors must be visible to the other's
/// `history`). Per-machine: a brand-new `InMemoryIndex`, an `OpLogStore` handle
/// over the shared bucket, and a signing identity built from `seed` (its author
/// SS58 is derived from the key, so distinct seeds are distinct authors). The
/// team and team key are shared via the constants so both machines seal/open the
/// same ciphertext.
fn machine(
    bucket: &Arc<MemoryBlobStore>,
    anchor: Arc<dyn AuditAnchor>,
    seed: [u8; 32],
    anchor_threshold: usize,
) -> Result<MemoryStore, BoxError> {
    let index = Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default())));
    // Both machines share the SAME underlying bucket through these cloned handles.
    let blob: Arc<dyn BlobStore> = bucket.clone();
    let oplog = OpLogStore::new(blob.clone());
    let signer: Arc<dyn Signer> = Arc::new(Sr25519Signer::from_seed_with_prefix(seed, 42)?);
    Ok(MemoryStore::new(
        blob,
        index,
        oplog,
        anchor,
        signer,
        std::collections::BTreeMap::from([(0_u64, SecretKey::from_bytes(TEAM_KEY))]),
        0,
        TEAM.to_owned(),
        anchor_threshold,
    ))
}

/// The SS58 a machine built from `seed` signs as — the derived author the
/// attribution assertions compare against.
fn author_of(seed: [u8; 32]) -> Result<Ss58, BoxError> {
    Ok(Sr25519Signer::from_seed_with_prefix(seed, 42)?.author_ss58())
}

/// `true` if `store` surfaces `id` among the pointers `text` recalls in `repo`.
fn recall_surfaces(
    store: &MemoryStore,
    text: &str,
    repo: &RepoScope,
    id: NoteId,
) -> Result<bool, BoxError> {
    let pointers = store
        .recall(RecallInput {
            text: text.to_owned(),
            repo: repo.clone(),
            k: 10,
            token_budget: None,
        })?
        .pointers;
    Ok(pointers.iter().any(|pointer| pointer.note_id == id))
}

#[tokio::test]
async fn two_machines_converge_on_remember() -> Result<(), BoxError> {
    let bucket = Arc::new(MemoryBlobStore::default());
    let anchor: Arc<dyn AuditAnchor> = Arc::new(RecordingAnchor::new());
    let machine_a = machine(&bucket, anchor.clone(), [5_u8; 32], INERT_THRESHOLD)?;
    let machine_b = machine(&bucket, anchor.clone(), [6_u8; 32], INERT_THRESHOLD)?;

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

    // B replays the shared op-log into its own index.
    machine_b.sync().await?;

    // recall returns a pointer (summary, never the body): the pointer type has no
    // body field at all, so "no body in recall" is enforced by the type, and we
    // assert the summary rode across.
    let pointers = machine_b
        .recall(RecallInput {
            text: "benchmark weights mainnet".to_owned(),
            repo: repo.clone(),
            k: 10,
            token_budget: None,
        })?
        .pointers;
    let pointer = pointers
        .iter()
        .find(|pointer| pointer.note_id == id)
        .ok_or("machine B did not surface machine A's note after sync")?;
    assert_eq!(pointer.summary, summary);

    // get hydrates the encrypted body, and B reads back A's authorship.
    let note = machine_b.get(id).await?;
    assert_eq!(note.body, body);
    assert_eq!(
        note.author,
        author_of([5_u8; 32])?,
        "the note is attributed to its author (machine A), not to the reader (machine B)"
    );
    Ok(())
}

#[tokio::test]
async fn forget_converges_across_machines() -> Result<(), BoxError> {
    let bucket = Arc::new(MemoryBlobStore::default());
    let anchor: Arc<dyn AuditAnchor> = Arc::new(RecordingAnchor::new());
    let machine_a = machine(&bucket, anchor.clone(), [5_u8; 32], INERT_THRESHOLD)?;
    let machine_b = machine(&bucket, anchor.clone(), [6_u8; 32], INERT_THRESHOLD)?;

    let repo = RepoScope::Repo("thebrain".to_owned());
    let query = "rotate the gateway signing key".to_owned();
    let id = machine_a
        .remember(RememberInput {
            note_type: NoteType::Convention,
            repo: repo.clone(),
            tags: BTreeSet::from(["security".to_owned()]),
            summary: "rotate the gateway signing key every quarter".to_owned(),
            body: "Long-lived gateway keys widen the blast radius of a leak.".to_owned(),
        })
        .await?;

    // B sees the note after its first sync.
    machine_b.sync().await?;
    assert!(
        recall_surfaces(&machine_b, &query, &repo, id)?,
        "machine B should surface the note before it is forgotten"
    );

    // A tombstones the note; the Forget op lands in the shared log.
    machine_a.forget(id).await?;

    // After B re-syncs, the converged tombstone wins and the note is *removed*
    // from B's index — not merely stale, actively gone.
    machine_b.sync().await?;
    assert!(
        !recall_surfaces(&machine_b, &query, &repo, id)?,
        "machine B should not surface a note whose tombstone has converged"
    );
    Ok(())
}

#[tokio::test]
async fn history_proves_inclusion_end_to_end() -> Result<(), BoxError> {
    let bucket = Arc::new(MemoryBlobStore::default());
    // The anchor is shared so the root A commits is the same object B reads back;
    // the eager threshold means A's single Remember op seals its own batch and
    // persists the anchor record to the shared bucket during `remember` — no flush.
    let anchor: Arc<dyn AuditAnchor> = Arc::new(RecordingAnchor::new());
    let machine_a = machine(&bucket, anchor.clone(), [5_u8; 32], EAGER_THRESHOLD)?;
    let machine_b = machine(&bucket, anchor.clone(), [6_u8; 32], EAGER_THRESHOLD)?;

    let repo = RepoScope::Repo("thebrain".to_owned());
    let id = machine_a
        .remember(RememberInput {
            note_type: NoteType::Convention,
            repo,
            tags: BTreeSet::from(["consensus".to_owned()]),
            summary: "validators must verify SEV-SNP attestation before peering".to_owned(),
            body: "An unverified host can read VM memory; gate peering on attestation.".to_owned(),
        })
        .await?;

    // B learns of the note from the shared log.
    machine_b.sync().await?;

    let history = machine_b.history(id).await?;
    assert!(!history.tombstoned, "a live note is not tombstoned");
    let entry = history
        .entries
        .iter()
        .find(|entry| entry.kind == OpKindLabel::Remember)
        .ok_or("history has no Remember entry for the note")?;
    assert_eq!(
        entry.author,
        author_of([5_u8; 32])?,
        "history attributes the op to the machine that signed it (A)"
    );
    let proof = entry
        .anchor
        .as_ref()
        .ok_or("the Remember op was not anchored despite the eager threshold")?;

    // The Phase 2 thesis, asserted end-to-end: machine B — a DIFFERENT machine
    // that never wrote this op — recomputes the Merkle root from A's op hash and
    // the inclusion proof, and it matches the anchored root. B can therefore
    // prove *who did what* (A's signed op) was committed under that root WITHOUT
    // trusting A's server; when chain anchoring is on, that root is on-chain, so
    // the whole chain of custody is publicly checkable.
    assert!(
        verify_proof(proof.root, entry.op_hash, &proof.proof),
        "a different machine must be able to verify A's op against the anchored root"
    );
    Ok(())
}

#[tokio::test]
async fn concurrent_writes_from_both_machines_converge() -> Result<(), BoxError> {
    let bucket = Arc::new(MemoryBlobStore::default());
    let anchor: Arc<dyn AuditAnchor> = Arc::new(RecordingAnchor::new());
    let machine_a = machine(&bucket, anchor.clone(), [5_u8; 32], INERT_THRESHOLD)?;
    let machine_b = machine(&bucket, anchor.clone(), [6_u8; 32], INERT_THRESHOLD)?;

    let repo = RepoScope::Repo("thebrain".to_owned());
    let alpha_query = "pin dependency versions exactly";
    let beta_query = "rotate validator session keys";

    // Each machine writes its own note before either syncs: two authors appending
    // to the shared log independently, the concurrent-write case convergence must
    // handle.
    let id_a = machine_a
        .remember(RememberInput {
            note_type: NoteType::Convention,
            repo: repo.clone(),
            tags: BTreeSet::from(["deps".to_owned()]),
            summary: "pin dependency versions exactly, never with caret ranges".to_owned(),
            body: "Caret ranges let a transitive update ship unreviewed code.".to_owned(),
        })
        .await?;
    let id_b = machine_b
        .remember(RememberInput {
            note_type: NoteType::Convention,
            repo: repo.clone(),
            tags: BTreeSet::from(["security".to_owned()]),
            summary: "rotate validator session keys every epoch boundary".to_owned(),
            body: "Stale session keys outlive the trust window they were issued for.".to_owned(),
        })
        .await?;

    // Both replay the shared log; each sees both authors' notes converge.
    let a_live = machine_a.sync().await?;
    let b_live = machine_b.sync().await?;
    assert_eq!(a_live, 2, "machine A converges on both authors' notes");
    assert_eq!(b_live, 2, "machine B converges on both authors' notes");

    // recall-able in both directions: each machine surfaces the OTHER author's
    // note as well as its own.
    assert!(
        recall_surfaces(&machine_a, beta_query, &repo, id_b)?,
        "A should recall B's note after convergence"
    );
    assert!(
        recall_surfaces(&machine_b, alpha_query, &repo, id_a)?,
        "B should recall A's note after convergence"
    );
    assert!(
        recall_surfaces(&machine_a, alpha_query, &repo, id_a)?,
        "A still recalls its own note"
    );
    assert!(
        recall_surfaces(&machine_b, beta_query, &repo, id_b)?,
        "B still recalls its own note"
    );
    Ok(())
}
