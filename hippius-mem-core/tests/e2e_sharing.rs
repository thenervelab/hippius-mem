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
    BlobStore, HashEmbedder, Identity, InMemoryIndex, MemberKey, MemoryBlobStore, MemoryStore,
    NetworkPrefix, NoopAnchor, NoteType, OpLogStore, RecallInput, RememberInput, RepoScope,
    SecretKey, Signer, Sr25519Signer, Ss58, TeamManifest, derive_identity, load_manifest,
    provision_team_key, publish_manifest, publish_member_key, signer_from_mnemonic,
};

/// Production anchor threshold; this test writes fewer ops than this, so its
/// (no-op) anchoring stays inert and the focus remains the cross-machine sync.
const ANCHOR_THRESHOLD: usize = 16;

/// The shared namespace both machines write into.
const TEAM: &str = "ourovoros";
/// The shared team key. Both machines must seal/open under the same bytes for
/// cross-machine decryption to work; that shared secret is the team key.
const TEAM_KEY: [u8; 32] = [9_u8; 32];

// Two canonical BIP-39 test vectors (Trezor), standing in for the founder and
// a teammate in the provisioner-authorization e2e below. Distinct from
// `machine()`'s raw-seed signers because that test needs each identity's
// x25519 key too (an [`Identity`], not just a [`Signer`]), which only
// mnemonic derivation provides. Public test vectors, safe to pin.
const AUTHZ_FOUNDER_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const AUTHZ_TEAMMATE_MNEMONIC: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

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

/// Derive one member's [`Identity`] and [`Sr25519Signer`] from the SAME
/// mnemonic, for the provisioner-authorization e2e below: both come from the
/// same phrase, so the identity's x25519 key and the signer's SS58 author
/// belong to the same person — the binding [`MemberKey::create_signed`] and
/// [`MemoryStore::provision_members`] rely on.
fn authz_member(mnemonic: &str) -> Result<(Identity, Sr25519Signer), BoxError> {
    Ok((
        derive_identity(mnemonic, NetworkPrefix::HIPPIUS)?,
        signer_from_mnemonic(mnemonic, NetworkPrefix::HIPPIUS)?,
    ))
}

/// Build one machine's store over the shared `bucket`, seeded with an
/// explicit (possibly empty) `keys` ring and signing as `mnemonic`'s
/// identity — [`machine`]'s mnemonic-based sibling for the
/// provisioner-authorization e2e, which needs both a matching [`Identity`]
/// (for `bootstrap_epoch_keys`) and control over the starting ring (empty, so
/// a bootstrap that installs nothing is observable).
fn authz_store(
    bucket: &Arc<MemoryBlobStore>,
    mnemonic: &str,
    keys: std::collections::BTreeMap<u64, SecretKey>,
) -> Result<MemoryStore, BoxError> {
    let index = Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default())));
    let blob: Arc<dyn BlobStore> = bucket.clone();
    let oplog = OpLogStore::new(blob.clone());
    let signer: Arc<dyn Signer> = Arc::new(signer_from_mnemonic(mnemonic, NetworkPrefix::HIPPIUS)?);
    Ok(MemoryStore::new(
        blob,
        index,
        oplog,
        Arc::new(NoopAnchor),
        signer,
        keys,
        0,
        TEAM.to_owned(),
        ANCHOR_THRESHOLD,
    ))
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

    // provision-equivalent: founder A publishes membership at v0, then names
    // recovery R via `publish_recovery_key` — the exact call `provision`'s
    // default recovery generation makes. That is a FORWARD link (v1), never an
    // in-place rewrite of v0, so every version below counts up by one.
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
        recovered.version, 2,
        "recovery advances to the next version"
    );
    assert_eq!(recovered.founder, recovery_signer.author_ss58());

    // `load_manifest` (unpinned trust-on-genesis) elects the recovered
    // manifest as live.
    let live = load_manifest(bucket.as_ref(), TEAM, None).await?;
    assert_eq!(
        live.as_ref().map(|m| m.version),
        Some(2),
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
        3,
        None,
    );
    publish_manifest(bucket.as_ref(), &stale_founder_attempt).await?;
    let live_after_old_founder = load_manifest(bucket.as_ref(), TEAM, None).await?;
    assert_eq!(
        live_after_old_founder.as_ref().map(|m| m.version),
        Some(2),
        "the old founder's key cannot advance the chain past the recovery"
    );

    // One signed by R (the recovered founder) at the same version IS
    // accepted and becomes live.
    let recovered_founder_advances = TeamManifest::create_signed_with_recovery(
        &recovery_signer,
        TEAM.to_owned(),
        BTreeSet::from([recovery_signer.author_ss58()]),
        3,
        Some(fresh_recovery_signer.verifying_key()),
    );
    publish_manifest(bucket.as_ref(), &recovered_founder_advances).await?;
    let live_after_new_founder = load_manifest(bucket.as_ref(), TEAM, None).await?;
    assert_eq!(
        live_after_new_founder.as_ref().map(|m| m.version),
        Some(3),
        "the recovered founder's key advances the chain normally"
    );
    Ok(())
}

/// The provisioner-authorization check (Task 3), end to end, through the
/// production [`MemoryStore`] paths the founder-loss test above proves the
/// manifest layer for: founder A provisions the team key via
/// [`MemoryStore::provision_members`] (every wrap signed by A's own signer,
/// per Task 2); a teammate bootstraps it from the bucket and reads A's note —
/// the genuine path. An ATTACKER — a self-consistent signer that is neither
/// the manifest's founder nor its (unnamed, here) recovery key — then plants
/// a wrap for the SAME teammate's epoch-0 slot using only PUBLIC inputs (the
/// teammate's own published [`MemberKey`]), overwriting the founder's genuine
/// wrap exactly as an untrusted bucket writer with write access could. A
/// FRESH teammate store — an empty ring, so any install is observable —
/// bootstrapping that epoch must refuse the attacker's wrap (it verifies —
/// Task 2's check alone would accept it — but is not authorized) and must
/// never install it via [`MemoryStore::add_epoch_key`].
#[tokio::test]
async fn bootstrap_refuses_a_wrap_from_an_unauthorized_provisioner() -> Result<(), BoxError> {
    let bucket = Arc::new(MemoryBlobStore::default());
    let (founder_id, founder_signer) = authz_member(AUTHZ_FOUNDER_MNEMONIC)?;
    let (teammate_id, teammate_signer) = authz_member(AUTHZ_TEAMMATE_MNEMONIC)?;
    let body = "An attacker who merely knows a recipient's public x25519 key must not be able \
                to plant a wrap that key installs."
        .to_owned();

    // Founder provisions genuinely: publish membership, publish both members'
    // signed x25519 keys, then provision the team key through the production
    // MemoryStore path — every wrap signed by the founder's own signer.
    let founder = authz_store(
        &bucket,
        AUTHZ_FOUNDER_MNEMONIC,
        std::collections::BTreeMap::from([(0_u64, SecretKey::from_bytes([44_u8; 32]))]),
    )?;
    founder
        .publish_membership(BTreeSet::from([
            founder_id.ss58.clone(),
            teammate_id.ss58.clone(),
        ]))
        .await?;
    let founder_member_key = MemberKey::create_signed(&founder_signer, &founder_id);
    let teammate_member_key = MemberKey::create_signed(&teammate_signer, &teammate_id);
    publish_member_key(bucket.as_ref(), TEAM, &founder_member_key).await?;
    publish_member_key(bucket.as_ref(), TEAM, &teammate_member_key).await?;
    founder.provision_members().await?;

    let id = founder
        .remember(RememberInput {
            force: true,
            note_type: NoteType::Convention,
            repo: RepoScope::Repo("thebrain".to_owned()),
            tags: BTreeSet::from(["authz".to_owned()]),
            summary: "only a manifest-authorized provisioner may seal a team key wrap".to_owned(),
            body: body.clone(),
        })
        .await?;

    // A teammate who was never pre-shared the key bootstraps it from the
    // bucket and reads the founder's note — the genuine path works.
    let first_bootstrap = authz_store(
        &bucket,
        AUTHZ_TEAMMATE_MNEMONIC,
        std::collections::BTreeMap::new(),
    )?;
    let added = first_bootstrap
        .bootstrap_epoch_keys(&teammate_id, &[0])
        .await?;
    assert_eq!(
        added, 1,
        "the teammate bootstraps the genuine, founder-signed wrap"
    );
    first_bootstrap.sync().await?;
    assert_eq!(
        first_bootstrap.get(id).await?.body,
        body,
        "the bootstrapped key decrypts the founder's note"
    );

    // ATTACKER: a self-consistent signer that is neither the manifest's
    // founder nor its recovery key. It overwrites the teammate's epoch-0 wrap
    // using only PUBLIC inputs — the teammate's own published x25519 key,
    // readable by anyone with bucket read access — via the same
    // `provision_team_key` entry point a bucket writer with write access
    // could call directly. `provision_team_key` signs unconditionally and
    // does not itself check the provisioner's identity (see its docs); that
    // check is `fetch_team_key`'s job, on the read side.
    let attacker = Sr25519Signer::from_seed_with_prefix(&[199_u8; 32], NetworkPrefix::HIPPIUS)?;
    provision_team_key(
        bucket.as_ref(),
        TEAM,
        &SecretKey::from_bytes([13_u8; 32]),
        0,
        std::slice::from_ref(&teammate_member_key),
        None,
        &attacker,
    )
    .await?;

    // A FRESH teammate store — an empty ring — attempts to bootstrap the SAME
    // epoch. The attacker's wrap verifies (it is genuinely self-signed) but is
    // not authorized, so it must be refused and never reach `add_epoch_key`.
    let second_bootstrap = authz_store(
        &bucket,
        AUTHZ_TEAMMATE_MNEMONIC,
        std::collections::BTreeMap::new(),
    )?;
    let added_after_attack = second_bootstrap
        .bootstrap_epoch_keys(&teammate_id, &[0])
        .await?;
    assert_eq!(
        added_after_attack, 0,
        "the attacker-planted wrap must be refused, not installed into the ring"
    );
    assert_eq!(
        second_bootstrap.highest_epoch(),
        None,
        "no epoch-0 key was installed for the fresh store after the attack"
    );

    Ok(())
}
