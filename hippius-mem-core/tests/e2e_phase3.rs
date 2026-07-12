//! Phase 3 capstone: cross-machine identity, teams, and key distribution.
//!
//! Phase 2 proved a second machine can rebuild its index from a shared, signed
//! op-log ([`e2e_phase2`]). Phase 3 adds *who is allowed in* and *how they get
//! the key to read*. These tests drive the whole team lifecycle across the
//! two-machine seam — separate signing identities, separate local indexes, one
//! shared bucket:
//!
//! * a member who was NEVER handed the team key bootstraps it from the bucket
//!   using only her own x25519 secret, then reads a teammate's note;
//! * removing a member from the founder-signed manifest hides ALL of that
//!   member's ops on the next sync (the current-member convergence filter);
//! * rotating the team key to a new epoch excludes the removed member from the
//!   new epoch's wraps, so she cannot fetch the key future writes use;
//! * an op whose `author` SS58 is swapped to a different valid identity is
//!   rejected end-to-end — a valid signature over forged attribution does not
//!   convince another machine's read path.
//!
//! The in-memory `MemoryBlobStore` stands in for the Hippius S3 gateway, which
//! honours the same `BlobStore` contract, so the distribution logic exercised
//! here is the same code that runs against a real bucket.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning test uses `?` for setup but still asserts on outcomes; the assertions are the test, not a crash to avoid"
)]

use std::collections::BTreeSet;
use std::sync::Arc;

use hippius_mem_core::{
    BlobStore, HashEmbedder, Identity, InMemoryIndex, MemError, MemberKey, MemoryBlobStore,
    MemoryStore, NetworkPrefix, NoopAnchor, NoteType, OpLogStore, RecallInput, RememberInput,
    RepoScope, SecretKey, Signer, Sr25519Signer, derive_identity, fetch_team_key,
    provision_team_key, publish_member_key, rotate_team_key, signer_from_mnemonic,
};

/// The shared namespace every machine writes into.
const TEAM: &str = "ourovoros";
/// SS58 prefix 42 — Substrate's generic prefix, matching the rest of the suite.
const PREFIX: NetworkPrefix = NetworkPrefix::HIPPIUS;
/// A threshold no test reaches, so the (per-store) anchor stays inert and the
/// focus is identity/membership/key-distribution rather than anchoring.
const ANCHOR_THRESHOLD: usize = 16;

// Three standard BIP-39 English test vectors (Trezor). Their seeds are public,
// so they are safe to pin as interoperability fixtures; distinct phrases derive
// distinct sr25519 identities (hence distinct SS58 authors and x25519 keys).
const FOUNDER_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ALICE_MNEMONIC: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";
const BOB_MNEMONIC: &str =
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";

/// Epoch the team starts at; the rotation test mints a second epoch.
const EPOCH_0: u64 = 0;
const EPOCH_1: u64 = 1;
/// Distinct team-key bytes per epoch. The point of rotation is a *different*
/// key, so the two epochs must not share bytes.
const TEAM_KEY_EPOCH_0: [u8; 32] = [11_u8; 32];
const TEAM_KEY_EPOCH_1: [u8; 32] = [22_u8; 32];

type BoxError = Box<dyn std::error::Error>;

/// Derive a member's identity and signer from one mnemonic.
///
/// Both come from the same phrase, so the identity's x25519 key and the signer's
/// SS58 author belong to the same person — the binding [`MemberKey::create_signed`]
/// and [`MemoryStore::new`] rely on.
fn member(mnemonic: &str) -> Result<(Identity, Sr25519Signer), BoxError> {
    Ok((
        derive_identity(mnemonic, PREFIX)?,
        signer_from_mnemonic(mnemonic, PREFIX)?,
    ))
}

/// Build one machine's store over the shared `bucket`, sealing notes under
/// `team_key`.
///
/// Per-machine: a fresh `InMemoryIndex`, an `OpLogStore` handle over the shared
/// bucket, a signing identity from `mnemonic` (its author SS58 is derived from
/// the key, so distinct mnemonics are distinct authors), and the `team_key` it
/// seals/opens under. The bucket is shared so every machine sees the same
/// op-log, manifests, member keys, and wraps.
fn store(
    bucket: &Arc<MemoryBlobStore>,
    mnemonic: &str,
    team_key: SecretKey,
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
        std::collections::BTreeMap::from([(0_u64, team_key)]),
        0,
        TEAM.to_owned(),
        ANCHOR_THRESHOLD,
    ))
}

/// Publish `mnemonic`'s signed x25519 [`MemberKey`] to the shared bucket and
/// return it, so the founder can later wrap the team key to it.
async fn publish_member(
    bucket: &Arc<MemoryBlobStore>,
    mnemonic: &str,
) -> Result<MemberKey, BoxError> {
    let (identity, signer) = member(mnemonic)?;
    let member_key = MemberKey::create_signed(&signer, &identity);
    publish_member_key(bucket.as_ref(), TEAM, &member_key).await?;
    Ok(member_key)
}

/// A note worth sharing across machines; the body is what the team key protects.
fn release_note() -> RememberInput {
    RememberInput {
        force: true,
        note_type: NoteType::Convention,
        repo: RepoScope::Repo("thebrain".to_owned()),
        tags: BTreeSet::from(["weights".to_owned(), "mainnet".to_owned()]),
        summary: "benchmark pallet weights before every mainnet release".to_owned(),
        body: "Unbenchmarked weights underprice extrinsics and open a DoS vector; \
               run the runtime benchmark suite and commit the generated weights."
            .to_owned(),
    }
}

/// `true` if `store` surfaces `id` among the pointers `text` recalls in `repo`.
fn recall_surfaces(
    store: &MemoryStore,
    text: &str,
    repo: &RepoScope,
    id: hippius_mem_core::NoteId,
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
async fn member_joins_via_wrapped_key_and_reads() -> Result<(), BoxError> {
    let bucket = Arc::new(MemoryBlobStore::default());
    let (founder_id, _) = member(FOUNDER_MNEMONIC)?;
    let (alice_id, _) = member(ALICE_MNEMONIC)?;

    // The founder's store seals under the epoch-0 team key.
    let founder = store(
        &bucket,
        FOUNDER_MNEMONIC,
        SecretKey::from_bytes(TEAM_KEY_EPOCH_0),
    )?;

    // Founder publishes the {F, A} manifest and both members' signed x25519 keys,
    // then wraps the team key to each member at epoch 0.
    founder
        .publish_membership(BTreeSet::from([
            founder_id.ss58.clone(),
            alice_id.ss58.clone(),
        ]))
        .await?;
    let founder_key = publish_member(&bucket, FOUNDER_MNEMONIC).await?;
    let alice_key = publish_member(&bucket, ALICE_MNEMONIC).await?;
    provision_team_key(
        bucket.as_ref(),
        TEAM,
        &SecretKey::from_bytes(TEAM_KEY_EPOCH_0),
        EPOCH_0,
        &[founder_key, alice_key],
        None,
    )
    .await?;

    let input = release_note();
    let repo = input.repo.clone();
    let summary = input.summary.clone();
    let body = input.body.clone();
    let id = founder.remember(input).await?;

    // Alice BOOTSTRAPS. She was never handed the team key: the ONLY key material
    // she holds is her own x25519 secret, derived from her mnemonic. She unwraps
    // the team key from the bucket with that secret, then builds her store around
    // the fetched key — there is no path in this test that pre-shares the symmetric
    // team key to her.
    let alice_secret = alice_id.x25519_secret();
    let fetched = fetch_team_key(
        bucket.as_ref(),
        TEAM,
        EPOCH_0,
        &alice_id.ss58,
        &alice_secret,
    )
    .await?;
    let alice = store(&bucket, ALICE_MNEMONIC, fetched)?;

    alice.sync().await?;
    assert!(
        recall_surfaces(&alice, "benchmark weights mainnet", &repo, id)?,
        "Alice should recall the founder's note after syncing the shared op-log"
    );

    // Hydrating the body is the cryptographic proof the bootstrap worked: `get`
    // decrypts the founder's ciphertext with the key Alice unwrapped, so a wrong
    // key would fail here. She also reads back the founder's authorship, not her
    // own — attribution survives the join.
    let note = alice.get(id).await?;
    assert_eq!(
        note.body, body,
        "the fetched team key decrypts the founder's note"
    );
    assert_eq!(note.summary, summary);
    assert_eq!(
        note.author, founder_id.ss58,
        "the note is attributed to the founder who wrote it, not the joining reader"
    );
    Ok(())
}

#[tokio::test]
async fn non_member_ops_filtered_after_removal() -> Result<(), BoxError> {
    let bucket = Arc::new(MemoryBlobStore::default());
    let (founder_id, _) = member(FOUNDER_MNEMONIC)?;
    let (alice_id, _) = member(ALICE_MNEMONIC)?;
    let (bob_id, _) = member(BOB_MNEMONIC)?;

    let founder = store(
        &bucket,
        FOUNDER_MNEMONIC,
        SecretKey::from_bytes(TEAM_KEY_EPOCH_0),
    )?;
    let alice = store(
        &bucket,
        ALICE_MNEMONIC,
        SecretKey::from_bytes(TEAM_KEY_EPOCH_0),
    )?;
    let bob = store(
        &bucket,
        BOB_MNEMONIC,
        SecretKey::from_bytes(TEAM_KEY_EPOCH_0),
    )?;

    // Founder opens the team to all three and provisions the epoch-0 key to each.
    founder
        .publish_membership(BTreeSet::from([
            founder_id.ss58.clone(),
            alice_id.ss58.clone(),
            bob_id.ss58.clone(),
        ]))
        .await?;
    let founder_key = publish_member(&bucket, FOUNDER_MNEMONIC).await?;
    let alice_key = publish_member(&bucket, ALICE_MNEMONIC).await?;
    let bob_key = publish_member(&bucket, BOB_MNEMONIC).await?;
    provision_team_key(
        bucket.as_ref(),
        TEAM,
        &SecretKey::from_bytes(TEAM_KEY_EPOCH_0),
        EPOCH_0,
        &[founder_key, alice_key, bob_key],
        None,
    )
    .await?;

    // Bob — a current member — writes a note. It converges into Alice's index.
    let repo = RepoScope::Repo("thebrain".to_owned());
    let query = "rotate the gateway signing key";
    let bob_note = bob
        .remember(RememberInput {
            force: true,
            note_type: NoteType::Convention,
            repo: repo.clone(),
            tags: BTreeSet::from(["security".to_owned()]),
            summary: "rotate the gateway signing key every quarter".to_owned(),
            body: "Long-lived gateway keys widen the blast radius of a leak.".to_owned(),
        })
        .await?;
    alice.sync().await?;
    assert!(
        recall_surfaces(&alice, query, &repo, bob_note)?,
        "Alice should surface Bob's note while Bob is still a member"
    );

    // Founder removes Bob from the manifest.
    founder
        .publish_membership(BTreeSet::from([
            founder_id.ss58.clone(),
            alice_id.ss58.clone(),
        ]))
        .await?;

    // Alice re-syncs the SAME (warm) store — no fresh index, no restart. Sync is
    // authoritative: it prunes the index down to the currently-live converged set,
    // and the current-member convergence filter drops ALL of a removed member's
    // ops, so Bob's note — already in Alice's warm index from the earlier sync — is
    // pruned out. Removal hides everything Bob ever wrote, not just future ops, on
    // the very next sync. (Key rotation, the next test, is the complementary
    // control: it stops a removed member from READING new writes sealed under the
    // rotated epoch.)
    alice.sync().await?;
    assert!(
        !recall_surfaces(&alice, query, &repo, bob_note)?,
        "a warm resync must prune a removed member's note, no rebuild required"
    );
    Ok(())
}

#[tokio::test]
async fn rotation_excludes_removed_member_from_new_writes() -> Result<(), BoxError> {
    let bucket = Arc::new(MemoryBlobStore::default());
    let (founder_id, _) = member(FOUNDER_MNEMONIC)?;
    let (alice_id, _) = member(ALICE_MNEMONIC)?;
    let (bob_id, _) = member(BOB_MNEMONIC)?;

    let founder = store(
        &bucket,
        FOUNDER_MNEMONIC,
        SecretKey::from_bytes(TEAM_KEY_EPOCH_0),
    )?;
    founder
        .publish_membership(BTreeSet::from([
            founder_id.ss58.clone(),
            alice_id.ss58.clone(),
            bob_id.ss58.clone(),
        ]))
        .await?;
    let founder_key = publish_member(&bucket, FOUNDER_MNEMONIC).await?;
    let alice_key = publish_member(&bucket, ALICE_MNEMONIC).await?;
    let bob_key = publish_member(&bucket, BOB_MNEMONIC).await?;
    provision_team_key(
        bucket.as_ref(),
        TEAM,
        &SecretKey::from_bytes(TEAM_KEY_EPOCH_0),
        EPOCH_0,
        &[founder_key.clone(), alice_key.clone(), bob_key],
        None,
    )
    .await?;

    // Founder removes Bob, then rotates the team key to a new epoch for the
    // remaining members only. Bob is absent from `current_member_keys`, so he
    // gets no wrap of epoch 1.
    founder
        .publish_membership(BTreeSet::from([
            founder_id.ss58.clone(),
            alice_id.ss58.clone(),
        ]))
        .await?;
    rotate_team_key(
        bucket.as_ref(),
        TEAM,
        &SecretKey::from_bytes(TEAM_KEY_EPOCH_1),
        EPOCH_1,
        &[founder_key, alice_key],
        None,
    )
    .await?;

    // Bob cannot fetch the epoch-1 key: there is no wrap addressed to him, so the
    // bootstrap that worked for him at epoch 0 fails at epoch 1. This is the
    // key-distribution proof — independent of note encryption, the removed member
    // is shut out of the new epoch's key.
    let bob_secret = bob_id.x25519_secret();
    assert!(
        fetch_team_key(bucket.as_ref(), TEAM, EPOCH_1, &bob_id.ss58, &bob_secret)
            .await
            .is_err(),
        "a removed member must not be able to fetch the rotated epoch's team key"
    );

    // Alice, still a member, fetches the epoch-1 key.
    let alice_secret = alice_id.x25519_secret();
    fetch_team_key(
        bucket.as_ref(),
        TEAM,
        EPOCH_1,
        &alice_id.ss58,
        &alice_secret,
    )
    .await
    .map_err(|err| format!("a retained member must still fetch the rotated key: {err}"))?;
    Ok(())
}

#[tokio::test]
async fn forged_author_op_is_rejected_end_to_end() -> Result<(), BoxError> {
    let bucket = Arc::new(MemoryBlobStore::default());

    // The founder writes one genuine note into an open team, minting a real
    // signed op in the shared bucket.
    let founder = store(
        &bucket,
        FOUNDER_MNEMONIC,
        SecretKey::from_bytes(TEAM_KEY_EPOCH_0),
    )?;
    founder.remember(release_note()).await?;

    // Take that genuine op back off the bucket and forge its attribution: swap
    // the `author` SS58 to Bob's (a different VALID identity) and re-sign with the
    // founder's key. The signature is sound — it verifies against the founder's
    // key — but the human SS58 label no longer decodes to the signing key. This is
    // the construction the Task-22 unit test pins, lifted to the cross-machine seam.
    let blob: Arc<dyn BlobStore> = bucket.clone();
    let oplog = OpLogStore::new(blob.clone());
    let mut forged = oplog
        .read_all(TEAM)
        .await?
        .first()
        .cloned()
        .ok_or("the founder's genuine op should be in the shared log")?;
    let (_, founder_signer) = member(FOUNDER_MNEMONIC)?;
    let (_, bob_signer) = member(BOB_MNEMONIC)?;
    forged.author = bob_signer.author_ss58();
    forged.sig = founder_signer.sign(&forged.signing_bytes());
    assert!(
        forged.verify_sig(),
        "the re-signed op must still carry a valid signature, isolating the attribution forgery"
    );
    oplog.append(TEAM, &forged).await?;

    // A different machine replaying the log DROPS the forged op rather than
    // aborting (I2): a valid signature over a forged author fails the identity
    // binding and is discarded with a warn. (The forgery reused the genuine op's
    // id, so it overwrote it at the same object key; the security point is that no
    // forged-author op ever survives the verified read, not how many remain.)
    let reader_oplog = OpLogStore::new(blob);
    let read = reader_oplog.read_all(TEAM).await?;
    assert!(
        !read.iter().any(|op| op.author == bob_signer.author_ss58()),
        "no forged-author op survives the verified read"
    );

    // A full store sync succeeds rather than failing closed — the forgery is
    // neutralized without denying every member their service.
    let reader = store(
        &bucket,
        ALICE_MNEMONIC,
        SecretKey::from_bytes(TEAM_KEY_EPOCH_0),
    )?;
    reader.sync().await?;
    Ok(())
}

#[tokio::test]
async fn removed_member_keeps_old_epoch_reads() -> Result<(), BoxError> {
    // Forward-readable rotation, end to end: a member who retains only the epoch-0
    // key still reads epoch-0 notes after the team rotates to epoch 1, but an
    // epoch-1 note — sealed under a key they were never given — is not readable.
    let bucket = Arc::new(MemoryBlobStore::default());
    let repo = RepoScope::Repo("thebrain".to_owned());

    // The founder seals one note at epoch 0, then rotates its OWN key-ring to
    // epoch 1 and seals a second note under the new key.
    let founder = store(
        &bucket,
        FOUNDER_MNEMONIC,
        SecretKey::from_bytes(TEAM_KEY_EPOCH_0),
    )?;
    let epoch0_note = founder.remember(release_note()).await?;

    founder.add_epoch_key(EPOCH_1, SecretKey::from_bytes(TEAM_KEY_EPOCH_1));
    founder.set_current_epoch(EPOCH_1);
    let epoch1_note = founder
        .remember(RememberInput {
            force: true,
            note_type: NoteType::Convention,
            repo: repo.clone(),
            tags: BTreeSet::from(["rotation".to_owned()]),
            summary: "post-rotation note sealed under the epoch-1 key".to_owned(),
            body: "Only members provisioned the epoch-1 key can read this.".to_owned(),
        })
        .await?;

    // The removed member retains ONLY the epoch-0 key (they were never wrapped the
    // rotated epoch). They share the bucket/op-log; the team is open (no manifest),
    // so the founder's ops converge for them.
    let removed = store(
        &bucket,
        BOB_MNEMONIC,
        SecretKey::from_bytes(TEAM_KEY_EPOCH_0),
    )?;
    let indexed = removed.sync().await?;
    assert_eq!(
        indexed, 1,
        "sync indexes the epoch-0 note and skips the epoch-1 note the member cannot decrypt"
    );

    // Old epoch: still fully readable.
    assert!(
        recall_surfaces(&removed, "benchmark weights mainnet", &repo, epoch0_note)?,
        "the removed member still recalls the pre-rotation note"
    );
    assert_eq!(
        removed.get(epoch0_note).await?.body,
        release_note().body,
        "the retained epoch-0 key decrypts the pre-rotation note"
    );

    // New epoch: not readable — skipped during sync, so not even indexed.
    assert!(
        !recall_surfaces(&removed, "post-rotation epoch-1 note", &repo, epoch1_note)?,
        "the epoch-1 note never surfaces for a member without the rotated key"
    );
    assert!(
        removed.get(epoch1_note).await.is_err(),
        "get on an epoch-1 note errors for a member lacking the rotated key"
    );
    Ok(())
}

/// The whole `hippius-mem rotate` flow the CLI drives, at the library seam the
/// CLI calls: publish the shrunk membership, [`MemoryStore::rotate_key`] to a
/// fresh epoch wrapped to the remaining members only, and seal the next write
/// under that epoch — the removed member cannot decrypt it, the remaining
/// member can.
#[tokio::test]
async fn rotate_key_excludes_removed_member_from_post_rotation_notes() -> Result<(), BoxError> {
    let bucket = Arc::new(MemoryBlobStore::default());
    let (founder_id, _) = member(FOUNDER_MNEMONIC)?;
    let (alice_id, _) = member(ALICE_MNEMONIC)?;
    let (bob_id, _) = member(BOB_MNEMONIC)?;
    let repo = RepoScope::Repo("thebrain".to_owned());

    // Pinned founder: the rotation must run under the same fail-closed authz the
    // sync/provision paths use, not trust-on-genesis.
    let founder = store(
        &bucket,
        FOUNDER_MNEMONIC,
        SecretKey::from_bytes(TEAM_KEY_EPOCH_0),
    )?
    .with_pinned_founder(Some(founder_id.ss58.clone()));
    founder
        .publish_membership(BTreeSet::from([
            founder_id.ss58.clone(),
            alice_id.ss58.clone(),
            bob_id.ss58.clone(),
        ]))
        .await?;
    publish_member(&bucket, FOUNDER_MNEMONIC).await?;
    publish_member(&bucket, ALICE_MNEMONIC).await?;
    publish_member(&bucket, BOB_MNEMONIC).await?;
    founder.provision_members().await?;

    // Remove Bob (the CLI's `--members` step), then rotate for the remaining set.
    founder
        .publish_membership(BTreeSet::from([
            founder_id.ss58.clone(),
            alice_id.ss58.clone(),
        ]))
        .await?;
    let outcome = founder.rotate_key(0).await?;
    assert_eq!(outcome.new_epoch, EPOCH_1, "epoch 0 rotates to epoch 1");
    assert_eq!(
        outcome.wrapped,
        BTreeSet::from([founder_id.ss58.clone(), alice_id.ss58.clone()]),
        "only the remaining members are wrapped the new epoch key"
    );
    assert_eq!(
        founder.current_epoch(),
        EPOCH_1,
        "rotation advances the write epoch in the same call"
    );

    // The next write seals under the rotated epoch — no extra step needed.
    let post_rotation = founder
        .remember(RememberInput {
            force: true,
            note_type: NoteType::Convention,
            repo: repo.clone(),
            tags: BTreeSet::from(["rotation".to_owned()]),
            summary: "post-rotation note sealed under the rotated epoch".to_owned(),
            body: "Only members wrapped the rotated key can read this.".to_owned(),
        })
        .await?;

    // Bob has no wrap for the new epoch: the key fetch fails, and his store
    // (holding only the epoch-0 key) cannot surface or decrypt the new note.
    let bob_secret = bob_id.x25519_secret();
    assert!(
        fetch_team_key(bucket.as_ref(), TEAM, EPOCH_1, &bob_id.ss58, &bob_secret)
            .await
            .is_err(),
        "the removed member must not be able to fetch the rotated epoch's key"
    );
    let bob = store(
        &bucket,
        BOB_MNEMONIC,
        SecretKey::from_bytes(TEAM_KEY_EPOCH_0),
    )?;
    bob.sync().await?;
    assert!(
        !recall_surfaces(&bob, "post-rotation rotated epoch", &repo, post_rotation)?,
        "the post-rotation note never surfaces for the removed member"
    );
    assert!(
        bob.get(post_rotation).await.is_err(),
        "the removed member cannot decrypt a note written after rotation"
    );

    // Alice, still a member, bootstraps the rotated epoch from the bucket with
    // only her own x25519 secret and reads the post-rotation note.
    let alice = store(
        &bucket,
        ALICE_MNEMONIC,
        SecretKey::from_bytes(TEAM_KEY_EPOCH_0),
    )?;
    alice
        .bootstrap_epoch_keys(&alice_id, &[EPOCH_0, EPOCH_1])
        .await?;
    alice.sync().await?;
    assert_eq!(
        alice.get(post_rotation).await?.body,
        "Only members wrapped the rotated key can read this.",
        "a remaining member decrypts the post-rotation note via the bootstrapped key"
    );
    Ok(())
}

#[tokio::test]
async fn rotate_key_refuses_a_non_founder() -> Result<(), BoxError> {
    let bucket = Arc::new(MemoryBlobStore::default());
    let (founder_id, _) = member(FOUNDER_MNEMONIC)?;
    let (alice_id, _) = member(ALICE_MNEMONIC)?;

    let founder = store(
        &bucket,
        FOUNDER_MNEMONIC,
        SecretKey::from_bytes(TEAM_KEY_EPOCH_0),
    )?;
    founder
        .publish_membership(BTreeSet::from([
            founder_id.ss58.clone(),
            alice_id.ss58.clone(),
        ]))
        .await?;
    publish_member(&bucket, ALICE_MNEMONIC).await?;

    // Alice is a member but NOT the founder: rotation is a membership-shaped
    // power (it decides who can read future notes), so it is founder-only.
    let alice = store(
        &bucket,
        ALICE_MNEMONIC,
        SecretKey::from_bytes(TEAM_KEY_EPOCH_0),
    )?;
    assert!(
        matches!(alice.rotate_key(0).await, Err(MemError::Unauthorized(_))),
        "a non-founder rotation must be refused as Unauthorized"
    );
    assert_eq!(
        alice.current_epoch(),
        EPOCH_0,
        "a refused rotation must not advance the write epoch"
    );
    Ok(())
}

#[tokio::test]
async fn rotate_key_without_a_manifest_mirrors_open_provision() -> Result<(), BoxError> {
    // An UNPINNED team with no manifest is genuinely open: `provision` wraps
    // every verified published key, and rotation mirrors that exactly.
    let bucket = Arc::new(MemoryBlobStore::default());
    let (founder_id, _) = member(FOUNDER_MNEMONIC)?;
    let (alice_id, _) = member(ALICE_MNEMONIC)?;

    let founder = store(
        &bucket,
        FOUNDER_MNEMONIC,
        SecretKey::from_bytes(TEAM_KEY_EPOCH_0),
    )?;
    publish_member(&bucket, FOUNDER_MNEMONIC).await?;
    publish_member(&bucket, ALICE_MNEMONIC).await?;

    let outcome = founder.rotate_key(0).await?;
    assert_eq!(
        outcome.wrapped,
        BTreeSet::from([founder_id.ss58, alice_id.ss58]),
        "an open (unpinned, manifest-less) team rotates for every published key, like provision"
    );
    Ok(())
}

#[tokio::test]
async fn rotate_key_fails_closed_when_pinned_without_a_trusted_manifest() -> Result<(), BoxError> {
    // A PINNED team with no founder-signed manifest is the fail-closed state
    // from the provision authz: rotating there would mint an epoch wrapped to
    // no one, so it must refuse loudly instead of silently succeeding.
    let bucket = Arc::new(MemoryBlobStore::default());
    let (founder_id, _) = member(FOUNDER_MNEMONIC)?;

    let founder = store(
        &bucket,
        FOUNDER_MNEMONIC,
        SecretKey::from_bytes(TEAM_KEY_EPOCH_0),
    )?
    .with_pinned_founder(Some(founder_id.ss58.clone()));
    publish_member(&bucket, FOUNDER_MNEMONIC).await?;

    assert!(
        matches!(
            founder.rotate_key(0).await,
            Err(MemError::ManifestUnavailable { .. })
        ),
        "pinned + no trusted manifest must fail closed as ManifestUnavailable"
    );
    assert_eq!(
        founder.current_epoch(),
        EPOCH_0,
        "a refused rotation must not advance the write epoch"
    );
    Ok(())
}

#[tokio::test]
async fn rotate_key_with_no_member_keys_is_nothing_to_rotate() -> Result<(), BoxError> {
    // Nobody has `join`ed: rotating would advance the write epoch onto a key
    // that exists only in this process — every subsequent write would be
    // unreadable to the whole team after the process exits.
    let bucket = Arc::new(MemoryBlobStore::default());
    let (founder_id, _) = member(FOUNDER_MNEMONIC)?;

    let founder = store(
        &bucket,
        FOUNDER_MNEMONIC,
        SecretKey::from_bytes(TEAM_KEY_EPOCH_0),
    )?;
    founder
        .publish_membership(BTreeSet::from([founder_id.ss58]))
        .await?;

    assert!(
        matches!(
            founder.rotate_key(0).await,
            Err(MemError::NothingToRotate { .. })
        ),
        "zero wrap targets must be refused as NothingToRotate"
    );
    assert_eq!(
        founder.current_epoch(),
        EPOCH_0,
        "a refused rotation must not advance the write epoch"
    );
    Ok(())
}

#[tokio::test]
async fn rotate_key_honours_the_known_max_epoch_floor() -> Result<(), BoxError> {
    // A founder whose local ring is stale (only epoch 0) but whose config says
    // the team already rotated to epoch 3 must mint epoch 4, not re-mint (and
    // clobber the wraps of) epoch 1.
    let bucket = Arc::new(MemoryBlobStore::default());
    let founder = store(
        &bucket,
        FOUNDER_MNEMONIC,
        SecretKey::from_bytes(TEAM_KEY_EPOCH_0),
    )?;
    publish_member(&bucket, FOUNDER_MNEMONIC).await?;

    let outcome = founder.rotate_key(3).await?;
    assert_eq!(
        outcome.new_epoch, 4,
        "the new epoch clears both the local ring and the configured max_epoch"
    );
    assert_eq!(founder.current_epoch(), 4);
    Ok(())
}
