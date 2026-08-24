//! Durability capstone: snapshot restore, anchor/reconcile, and multi-epoch
//! bootstrap across the multi-machine seam.
//!
//! The earlier suites prove convergence (`e2e_phase2`), identity/membership
//! (`e2e_phase3`), and randomized partition healing (`stress_convergence`).
//! These tests close three integration gaps those leave open — surfaces
//! exercised only by module-level unit tests, or not at all:
//!
//! * `snapshot()` then a fresh machine's `sync()` RESTORES from the checkpoint
//!   (and the restore must agree with a full replay);
//! * `flush_anchors()` then `reconcile()` reports a clean log ok, and FLAGS a
//!   suppressed op and a tampered anchor record;
//! * `bootstrap_epoch_keys()` fetches and unwraps a member's wrapped keys for a
//!   range of epochs, adding only the ones she is entitled to.
//!
//! All over the in-memory `MemoryBlobStore`, which honours the same `BlobStore`
//! contract as the Hippius S3 gateway, so storage tamper/suppression is done
//! through the same public `list`/`get`/`put`/`delete` a real gateway exposes.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test, not a crash to avoid"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hippius_mem_core::{
    BlobStore, HashEmbedder, Identity, InMemoryIndex, MemError, MemberKey, MemoryBlobStore,
    MemoryStore, NetworkPrefix, NoopAnchor, NoteId, NoteType, OpLogStore, RecallInput,
    RememberInput, RepoScope, SecretKey, Signer, Sr25519Signer, UnsignedAnchorPolicy, content_hash,
    derive_identity, persist_anchor_record, provision_team_key, publish_member_key,
    read_anchor_records, rotate_team_key, signer_from_mnemonic,
};

/// The shared namespace every machine writes into.
const TEAM: &str = "ourovoros";
/// SS58 prefix shared with the rest of the suite.
const PREFIX: NetworkPrefix = NetworkPrefix::HIPPIUS;
/// The shared single-epoch team key for the snapshot/anchor clusters; both the
/// writer and the restoring reader seal/open under these bytes.
const TEAM_KEY: [u8; 32] = [9_u8; 32];
/// A threshold no test reaches, so anchoring is driven explicitly via
/// `flush_anchors` rather than tripping mid-write.
const INERT_THRESHOLD: usize = 16;

// Three standard BIP-39 English test vectors (Trezor); public seeds, safe to pin
// as fixtures. Distinct phrases derive distinct sr25519 + x25519 identities.
const FOUNDER_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ALICE_MNEMONIC: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";
const BOB_MNEMONIC: &str =
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";

const EPOCH_0: u64 = 0;
const EPOCH_1: u64 = 1;
/// Distinct key bytes per epoch — rotation's whole point is a different key.
const TEAM_KEY_EPOCH_0: [u8; 32] = [11_u8; 32];
const TEAM_KEY_EPOCH_1: [u8; 32] = [22_u8; 32];

type BoxError = Box<dyn std::error::Error>;

/// Build a seed-based machine over the shared `bucket`, sealing under the shared
/// `TEAM_KEY` at epoch 0. Distinct seeds are distinct authors; the team key is
/// shared so any machine decrypts any other's notes.
fn seed_machine(
    bucket: &Arc<MemoryBlobStore>,
    seed: [u8; 32],
    anchor_threshold: usize,
) -> Result<MemoryStore, BoxError> {
    let index = Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default())));
    let blob: Arc<dyn BlobStore> = bucket.clone();
    let oplog = OpLogStore::new(blob.clone());
    let signer: Arc<dyn Signer> = Arc::new(Sr25519Signer::from_seed_with_prefix(&seed, PREFIX)?);
    Ok(MemoryStore::new(
        blob,
        index,
        oplog,
        Arc::new(NoopAnchor),
        signer,
        BTreeMap::from([(EPOCH_0, SecretKey::from_bytes(TEAM_KEY))]),
        0,
        TEAM.to_owned(),
        anchor_threshold,
    ))
}

/// Derive a member's identity and signer from one mnemonic (same person: the
/// identity's x25519 key and the signer's SS58 author share a seed).
fn member(mnemonic: &str) -> Result<(Identity, Sr25519Signer), BoxError> {
    Ok((
        derive_identity(mnemonic, PREFIX)?,
        signer_from_mnemonic(mnemonic, PREFIX)?,
    ))
}

/// Build a mnemonic-based machine over the shared `bucket` with the given key
/// ring. A joining member passes an EMPTY ring and populates it via
/// `bootstrap_epoch_keys`; a founder passes its epoch-0 key.
fn mnemonic_store(
    bucket: &Arc<MemoryBlobStore>,
    mnemonic: &str,
    keys: BTreeMap<u64, SecretKey>,
) -> Result<MemoryStore, BoxError> {
    let index = Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default())));
    let blob: Arc<dyn BlobStore> = bucket.clone();
    let oplog = OpLogStore::new(blob.clone());
    let signer: Arc<dyn Signer> = Arc::new(signer_from_mnemonic(mnemonic, PREFIX)?);
    Ok(MemoryStore::new(
        blob,
        index,
        oplog,
        Arc::new(NoopAnchor),
        signer,
        keys,
        0,
        TEAM.to_owned(),
        INERT_THRESHOLD,
    ))
}

/// Publish `mnemonic`'s signed x25519 [`MemberKey`] so the founder can wrap the
/// team key to it; returns the key for the wrap call.
async fn publish_member(
    bucket: &Arc<MemoryBlobStore>,
    mnemonic: &str,
) -> Result<MemberKey, BoxError> {
    let (identity, signer) = member(mnemonic)?;
    let member_key = MemberKey::create_signed(&signer, &identity);
    publish_member_key(bucket.as_ref(), TEAM, &member_key).await?;
    Ok(member_key)
}

/// A note in `repo` with a distinctive summary/body so recall and body round-trip
/// assertions are unambiguous.
fn note(repo: RepoScope, summary: &str, body: &str) -> RememberInput {
    RememberInput {
        force: true,
        note_type: NoteType::Convention,
        repo,
        tags: BTreeSet::new(),
        summary: summary.to_owned(),
        body: body.to_owned(),
    }
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

/// Delete every object under `prefix` via the public `BlobStore` — used to force
/// the full-replay fallback by removing the snapshot, and (per-key) to simulate a
/// gateway dropping an op.
async fn clear_prefix(bucket: &Arc<MemoryBlobStore>, prefix: &str) -> Result<(), BoxError> {
    let blob: Arc<dyn BlobStore> = bucket.clone();
    for key in blob.list(prefix).await? {
        blob.delete(&key).await?;
    }
    Ok(())
}

// ---- Snapshot restore cluster -------------------------------------------------

#[tokio::test]
async fn fresh_machine_restores_converged_state_from_snapshot() -> Result<(), BoxError> {
    let bucket = Arc::new(MemoryBlobStore::default());
    let author = seed_machine(&bucket, [1_u8; 32], INERT_THRESHOLD)?;
    let repo = RepoScope::Repo("thebrain".to_owned());

    // Five notes across the repo and the team-global scope.
    let mut notes = Vec::new();
    for i in 0..5 {
        let scope = if i % 2 == 0 {
            repo.clone()
        } else {
            RepoScope::Global
        };
        let body = format!("body of note {i}");
        let id = author
            .remember(note(scope, &format!("snapshot note {i}"), &body))
            .await?;
        notes.push((id, body));
    }
    author.sync().await?;
    let last = author.snapshot().await?;
    assert!(last > 0, "snapshot captures a non-empty converged state");

    // A fresh machine (different signer, shared bucket) restores from the snapshot.
    let reader = seed_machine(&bucket, [2_u8; 32], INERT_THRESHOLD)?;
    reader.sync().await?;
    for (id, body) in &notes {
        assert_eq!(
            &reader.get(*id).await?.body,
            body,
            "restored note {id} decrypts to its original body via the snapshot's pointer"
        );
    }
    // The search index was rebuilt from the snapshot, not just the blob store.
    assert!(
        recall_surfaces(&reader, "snapshot note", &repo, notes[0].0)?,
        "a restored note surfaces via recall on the fresh machine"
    );
    Ok(())
}

#[tokio::test]
async fn snapshot_reflects_forgets_not_raw_ops() -> Result<(), BoxError> {
    let bucket = Arc::new(MemoryBlobStore::default());
    let author = seed_machine(&bucket, [3_u8; 32], INERT_THRESHOLD)?;
    let repo = RepoScope::Repo("thebrain".to_owned());

    let kept_a = author
        .remember(note(repo.clone(), "keep a", "body a"))
        .await?;
    let forgotten = author
        .remember(note(repo.clone(), "drop b", "body b"))
        .await?;
    let kept_c = author
        .remember(note(repo.clone(), "keep c", "body c"))
        .await?;
    author.forget(forgotten).await?;
    author.sync().await?;
    author.snapshot().await?;

    let reader = seed_machine(&bucket, [4_u8; 32], INERT_THRESHOLD)?;
    reader.sync().await?;
    assert_eq!(reader.get(kept_a).await?.body, "body a");
    assert_eq!(reader.get(kept_c).await?.body, "body c");
    assert!(
        matches!(reader.get(forgotten).await, Err(MemError::NotFound { .. })),
        "the forgotten note is absent from the restored snapshot (converged state, not raw ops)"
    );
    Ok(())
}

#[tokio::test]
async fn snapshot_base_plus_post_snapshot_tail_compose() -> Result<(), BoxError> {
    let bucket = Arc::new(MemoryBlobStore::default());
    let author = seed_machine(&bucket, [5_u8; 32], INERT_THRESHOLD)?;
    let repo = RepoScope::Repo("thebrain".to_owned());

    let mut notes = Vec::new();
    for i in 0..5 {
        let body = format!("base {i}");
        let id = author
            .remember(note(repo.clone(), &format!("base note {i}"), &body))
            .await?;
        notes.push((id, body));
    }
    author.sync().await?;
    author.snapshot().await?;

    // Two more writes AFTER the snapshot — these form the incremental tail.
    for i in 0..2 {
        let body = format!("tail {i}");
        let id = author
            .remember(note(repo.clone(), &format!("tail note {i}"), &body))
            .await?;
        notes.push((id, body));
    }

    let reader = seed_machine(&bucket, [6_u8; 32], INERT_THRESHOLD)?;
    reader.sync().await?;
    for (id, body) in &notes {
        assert_eq!(
            &reader.get(*id).await?.body,
            body,
            "sync composes the snapshot base with the post-snapshot tail"
        );
    }
    Ok(())
}

#[tokio::test]
async fn restore_from_snapshot_equals_full_replay() -> Result<(), BoxError> {
    let bucket = Arc::new(MemoryBlobStore::default());
    let author = seed_machine(&bucket, [7_u8; 32], INERT_THRESHOLD)?;
    let repo = RepoScope::Repo("thebrain".to_owned());

    let mut notes = Vec::new();
    for i in 0..5 {
        let body = format!("parity {i}");
        let id = author
            .remember(note(repo.clone(), &format!("parity note {i}"), &body))
            .await?;
        notes.push((id, body));
    }
    author.sync().await?;
    author.snapshot().await?;

    // Path 1: snapshot present — the reader restores from the checkpoint.
    let with_snapshot = seed_machine(&bucket, [8_u8; 32], INERT_THRESHOLD)?;
    with_snapshot.sync().await?;

    // Path 2: clear the snapshot prefix, forcing a fresh machine to full-replay.
    clear_prefix(&bucket, &format!("{TEAM}/_snapshots/")).await?;
    let replayed = seed_machine(&bucket, [10_u8; 32], INERT_THRESHOLD)?;
    replayed.sync().await?;

    // The two restore paths must reach identical state.
    for (id, body) in &notes {
        assert_eq!(
            with_snapshot.get(*id).await?.body,
            *body,
            "snapshot-restored machine has note {id}"
        );
        assert_eq!(
            replayed.get(*id).await?.body,
            *body,
            "full-replay machine reaches the SAME body for note {id}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn snapshot_is_an_optimization_the_oplog_is_authoritative() -> Result<(), BoxError> {
    // The snapshot is a fast-path index rebuild, NOT a durability store: `sync`
    // validates the checkpoint against the op-log base (`sync_incremental`) and
    // falls back to a full replay if it cannot. So deleting the op-log loses the
    // notes even though a snapshot still exists and the note blobs survive —
    // proving the op-log, not the snapshot, is the source of truth. This pins the
    // contract boundary so a refactor cannot silently make a stale snapshot
    // authoritative (which would resurrect forgotten or rewritten notes).
    let bucket = Arc::new(MemoryBlobStore::default());
    let author = seed_machine(&bucket, [20_u8; 32], INERT_THRESHOLD)?;
    let repo = RepoScope::Repo("thebrain".to_owned());

    let mut ids = Vec::new();
    for i in 0..5 {
        let id = author
            .remember(note(
                repo.clone(),
                &format!("durable note {i}"),
                &format!("body {i}"),
            ))
            .await?;
        ids.push(id);
    }
    author.sync().await?;
    author.snapshot().await?;

    // Remove every op object; the snapshot and the note blobs remain in the bucket.
    clear_prefix(&bucket, &format!("{TEAM}/_oplog/")).await?;

    let reader = seed_machine(&bucket, [21_u8; 32], INERT_THRESHOLD)?;
    let indexed = reader.sync().await?;
    assert_eq!(
        indexed, 0,
        "with the op-log gone the snapshot does not validate, so nothing is indexed"
    );
    for id in &ids {
        assert!(
            matches!(reader.get(*id).await, Err(MemError::NotFound { .. })),
            "note {id} is unreachable once the authoritative op-log is gone, snapshot notwithstanding"
        );
    }
    Ok(())
}

// ---- Anchor & reconcile cluster -----------------------------------------------

#[tokio::test]
async fn anchor_then_reconcile_reports_ok() -> Result<(), BoxError> {
    let bucket = Arc::new(MemoryBlobStore::default());
    let author = seed_machine(&bucket, [11_u8; 32], INERT_THRESHOLD)?;
    let repo = RepoScope::Repo("thebrain".to_owned());

    for i in 0..4 {
        author
            .remember(note(
                repo.clone(),
                &format!("anchored {i}"),
                &format!("body {i}"),
            ))
            .await?;
    }
    let receipt = author.flush_anchors().await?;
    assert!(
        receipt.is_some(),
        "flush seals the pending leaves into one anchored batch"
    );

    let report = author.reconcile().await?;
    assert!(report.ok, "a clean anchored log reconciles ok");
    assert!(report.checked_batches >= 1, "the flushed batch is checked");
    assert_eq!(
        report.total_anchored_ops, 4,
        "all four op leaves are accounted for"
    );
    assert!(report.missing_ops.is_empty());
    assert!(report.root_mismatches.is_empty());
    Ok(())
}

#[tokio::test]
async fn reconcile_flags_suppressed_anchored_op() -> Result<(), BoxError> {
    let bucket = Arc::new(MemoryBlobStore::default());
    let author = seed_machine(&bucket, [12_u8; 32], INERT_THRESHOLD)?;
    let repo = RepoScope::Repo("thebrain".to_owned());

    for i in 0..4 {
        author
            .remember(note(
                repo.clone(),
                &format!("suppress {i}"),
                &format!("body {i}"),
            ))
            .await?;
    }
    assert!(author.flush_anchors().await?.is_some());

    // A gateway drops the newest op object. Its leaf is anchored, but the op is no
    // longer in the verified log — exactly the suppression reconcile must catch.
    let blob: Arc<dyn BlobStore> = bucket.clone();
    let keys = blob.list(&format!("{TEAM}/_oplog/")).await?;
    let victim = keys.last().ok_or("the op-log is non-empty")?.clone();
    blob.delete(&victim).await?;

    let report = author.reconcile().await?;
    assert!(
        !report.ok,
        "a suppressed anchored op must make reconcile fail"
    );
    assert!(
        !report.missing_ops.is_empty(),
        "the dropped anchored op is reported missing"
    );
    Ok(())
}

#[tokio::test]
async fn reconcile_flags_root_mismatch_on_tampered_leaves() -> Result<(), BoxError> {
    let bucket = Arc::new(MemoryBlobStore::default());
    let author = seed_machine(&bucket, [13_u8; 32], INERT_THRESHOLD)?;
    let repo = RepoScope::Repo("thebrain".to_owned());

    for i in 0..4 {
        author
            .remember(note(
                repo.clone(),
                &format!("tamper {i}"),
                &format!("body {i}"),
            ))
            .await?;
    }
    assert!(author.flush_anchors().await?.is_some());

    // Swap one stored leaf for a hash no op produces, keeping root/receipt/op_count
    // consistent so the record still passes `read_anchor_records`' invariant checks.
    // `persist_anchor_record` stores the record verbatim, so the tamper sticks.
    let blob: Arc<dyn BlobStore> = bucket.clone();
    let mut record = read_anchor_records(&blob, TEAM)
        .await?
        .into_iter()
        .next()
        .ok_or("flush persisted exactly one anchor record")?;
    record.leaves[0] = content_hash(b"tampered leaf produced by no op");

    // Stage 1 — the record is store-written, i.e. SIGNED, and the leaf swap breaks
    // its signature: `read_anchor_records` drops it as tamper before reconcile ever
    // sees it. For the audit that is equivalent to the bucket DELETING the record
    // outright (which an untrusted bucket could always do silently — the documented
    // record-suppression gap), so the report shows zero checked batches rather than
    // a root mismatch: tamper on a signed record buys the attacker nothing that
    // deletion did not already.
    persist_anchor_record(&blob, TEAM, &record).await?;
    let report = author.reconcile().await?;
    assert_eq!(
        report.checked_batches, 0,
        "a signed record tampered after signing is dropped at read, not audited"
    );
    assert!(
        report.root_mismatches.is_empty(),
        "the dropped record cannot contribute a root mismatch"
    );

    // Stage 2 — the attacker who CANNOT sign as the victim (no author key) plants
    // the forged record UNSIGNED instead: the phase-1 migration still reads those
    // (legacy records carry no signature), so the forgery reaches reconcile's
    // recomputation and is loudly reported. This is the documented phase-1
    // residual; the reject-unsigned phase closes it.
    record.sig = None;
    persist_anchor_record(&blob, TEAM, &record).await?;
    let report = author.reconcile().await?;
    assert!(
        !report.ok,
        "leaves that do not hash to the stored root must fail reconcile"
    );
    assert!(
        !report.root_mismatches.is_empty(),
        "the recomputed-root mismatch is reported"
    );
    Ok(())
}

#[tokio::test]
async fn strict_mode_ignores_a_planted_fresh_unsigned_record() -> Result<(), BoxError> {
    // The exact phase-1 residual, end to end: an attacker with bucket write
    // access but NO author key plants a FRESH unsigned self-consistent record
    // under the victim's author_key, with fabricated leaves no op produces.
    // Under the default (Accept) that yields a false missing_ops alarm against
    // the victim; with strict mode on, the planted record never reaches the
    // leaf comparison, so the healthy log reconciles ok — and the readiness
    // count still reports the record so an operator sees it was there.
    let bucket = Arc::new(MemoryBlobStore::default());
    let author = seed_machine(&bucket, [14_u8; 32], INERT_THRESHOLD)?;
    let repo = RepoScope::Repo("thebrain".to_owned());

    for i in 0..2 {
        author
            .remember(note(
                repo.clone(),
                &format!("planted {i}"),
                &format!("body {i}"),
            ))
            .await?;
    }
    assert!(author.flush_anchors().await?.is_some());

    let blob: Arc<dyn BlobStore> = bucket.clone();
    let genuine = read_anchor_records(&blob, TEAM)
        .await?
        .into_iter()
        .next()
        .ok_or("flush persisted exactly one anchor record")?;
    let fabricated = content_hash(b"fresh leaf produced by no op");
    let root = hippius_mem_core::merkle_root(&[fabricated]);
    let planted = hippius_mem_core::AnchorRecord {
        seq: genuine.seq + 1,
        author_key: genuine.author_key,
        root,
        meta: hippius_mem_core::BatchMeta {
            team: TEAM.to_owned(),
            first_lamport: 1,
            last_lamport: 1,
            op_count: 1,
        },
        leaves: vec![fabricated],
        receipt: hippius_mem_core::AnchorReceipt {
            root,
            reference: hippius_mem_core::AnchorRef::Local {
                seq: genuine.seq + 1,
            },
        },
        sig: None,
    };
    persist_anchor_record(&blob, TEAM, &planted).await?;

    // Default posture: the phase-1 residual stands — a false ALARM (never a
    // false ok) attributed to the victim.
    let report = author.reconcile().await?;
    assert!(
        !report.ok && !report.missing_ops.is_empty(),
        "Accept still reads the planted record, so the fabricated leaf raises a \
         false missing_ops alarm: {report:?}"
    );
    assert_eq!(
        report.unsigned_anchor_records, 1,
        "the readiness count names the unsigned record either way: {report:?}"
    );

    // Strict mode: the same bucket, reconciled by a store that rejects unsigned
    // records — the residual is closed, and the count still surfaces the plant.
    let strict = seed_machine(&bucket, [14_u8; 32], INERT_THRESHOLD)?
        .with_unsigned_anchor_policy(UnsignedAnchorPolicy::Reject);
    let report = strict.reconcile().await?;
    assert!(
        report.ok,
        "with strict mode on, the planted fresh unsigned record does NOT produce \
         a missing_ops alarm: {report:?}"
    );
    assert!(report.missing_ops.is_empty());
    assert_eq!(
        report.checked_batches, 1,
        "only the genuine signed batch is audited: {report:?}"
    );
    assert_eq!(
        report.unsigned_anchor_records, 1,
        "the dropped record is still counted for the operator: {report:?}"
    );
    Ok(())
}

// ---- Epoch bootstrap cluster --------------------------------------------------

#[tokio::test]
async fn member_bootstraps_all_epochs_and_reads_each() -> Result<(), BoxError> {
    let bucket = Arc::new(MemoryBlobStore::default());
    let (alice_id, _) = member(ALICE_MNEMONIC)?;
    let founder_signer = signer_from_mnemonic(FOUNDER_MNEMONIC, PREFIX)?;
    let repo = RepoScope::Repo("thebrain".to_owned());

    // Founder holds the epoch-0 key and provisions it to itself and Alice.
    let founder = mnemonic_store(
        &bucket,
        FOUNDER_MNEMONIC,
        BTreeMap::from([(EPOCH_0, SecretKey::from_bytes(TEAM_KEY_EPOCH_0))]),
    )?;
    let founder_key = publish_member(&bucket, FOUNDER_MNEMONIC).await?;
    let alice_key = publish_member(&bucket, ALICE_MNEMONIC).await?;
    provision_team_key(
        bucket.as_ref(),
        TEAM,
        &SecretKey::from_bytes(TEAM_KEY_EPOCH_0),
        EPOCH_0,
        &[founder_key.clone(), alice_key.clone()],
        None,
        &founder_signer,
    )
    .await?;
    let n0 = founder
        .remember(note(
            repo.clone(),
            "epoch zero note",
            "sealed under epoch 0",
        ))
        .await?;

    // Rotate to epoch 1, provision Alice the new wrap, write under the new key.
    rotate_team_key(
        bucket.as_ref(),
        TEAM,
        &SecretKey::from_bytes(TEAM_KEY_EPOCH_1),
        EPOCH_1,
        &[founder_key, alice_key],
        None,
        &founder_signer,
    )
    .await?;
    founder.add_epoch_key(EPOCH_1, SecretKey::from_bytes(TEAM_KEY_EPOCH_1));
    founder.set_current_epoch(EPOCH_1);
    let n1 = founder
        .remember(note(repo, "epoch one note", "sealed under epoch 1"))
        .await?;

    // Alice joins holding NO team keys: bootstrap is her only key source.
    let alice = mnemonic_store(&bucket, ALICE_MNEMONIC, BTreeMap::new())?;
    let added = alice
        .bootstrap_epoch_keys(&alice_id, &[EPOCH_0, EPOCH_1])
        .await?;
    assert_eq!(added, 2, "Alice unwraps both epochs she was provisioned");
    alice.sync().await?;
    assert_eq!(
        alice.get(n0).await?.body,
        "sealed under epoch 0",
        "the bootstrapped epoch-0 key decrypts the pre-rotation note"
    );
    assert_eq!(
        alice.get(n1).await?.body,
        "sealed under epoch 1",
        "the bootstrapped epoch-1 key decrypts the post-rotation note"
    );
    Ok(())
}

#[tokio::test]
async fn bootstrap_skips_epochs_member_cannot_unwrap() -> Result<(), BoxError> {
    let bucket = Arc::new(MemoryBlobStore::default());
    let (alice_id, _) = member(ALICE_MNEMONIC)?;
    let founder_signer = signer_from_mnemonic(FOUNDER_MNEMONIC, PREFIX)?;
    let repo = RepoScope::Repo("thebrain".to_owned());

    let founder = mnemonic_store(
        &bucket,
        FOUNDER_MNEMONIC,
        BTreeMap::from([(EPOCH_0, SecretKey::from_bytes(TEAM_KEY_EPOCH_0))]),
    )?;
    let founder_key = publish_member(&bucket, FOUNDER_MNEMONIC).await?;
    let alice_key = publish_member(&bucket, ALICE_MNEMONIC).await?;
    let bob_key = publish_member(&bucket, BOB_MNEMONIC).await?;

    // Epoch 0 is wrapped to Alice; epoch 1 is wrapped only to the founder and Bob.
    provision_team_key(
        bucket.as_ref(),
        TEAM,
        &SecretKey::from_bytes(TEAM_KEY_EPOCH_0),
        EPOCH_0,
        &[founder_key.clone(), alice_key, bob_key.clone()],
        None,
        &founder_signer,
    )
    .await?;
    let n0 = founder
        .remember(note(repo.clone(), "epoch zero note", "epoch-0 body"))
        .await?;
    rotate_team_key(
        bucket.as_ref(),
        TEAM,
        &SecretKey::from_bytes(TEAM_KEY_EPOCH_1),
        EPOCH_1,
        &[founder_key, bob_key],
        None,
        &founder_signer,
    )
    .await?;
    founder.add_epoch_key(EPOCH_1, SecretKey::from_bytes(TEAM_KEY_EPOCH_1));
    founder.set_current_epoch(EPOCH_1);
    let n1 = founder
        .remember(note(repo, "epoch one note", "epoch-1 body"))
        .await?;

    let alice = mnemonic_store(&bucket, ALICE_MNEMONIC, BTreeMap::new())?;
    let added = alice
        .bootstrap_epoch_keys(&alice_id, &[EPOCH_0, EPOCH_1])
        .await?;
    assert_eq!(
        added, 1,
        "Alice unwraps only epoch 0; epoch 1 was never wrapped to her"
    );

    let indexed = alice.sync().await?;
    assert_eq!(
        indexed, 1,
        "sync indexes the epoch-0 note and skips the epoch-1 note Alice cannot decrypt"
    );
    assert_eq!(alice.get(n0).await?.body, "epoch-0 body");
    // `sync` SKIPS a note whose epoch key is absent rather than indexing a
    // broken entry (`decode_records`'s skip-with-warn path, mirrored in
    // `sync_skips_notes_with_unavailable_epoch`): the note is never in Alice's
    // index at all, so `get` reports `NotFound`, not `KeyUnavailable` (the
    // variant `get`'s own doc reserves for an INDEXED note whose epoch key is
    // missing at read time — a different case than "never indexed").
    assert!(
        matches!(alice.get(n1).await, Err(MemError::NotFound { .. })),
        "the epoch-1 note is unreadable to a member who never received that wrap"
    );
    Ok(())
}
