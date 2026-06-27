//! Phase 4 stress: many authors, interleaved ops, random partitions — all
//! machines converge to byte-identical memory.
//!
//! The earlier capstones ([`e2e_phase2`], [`e2e_phase3`]) proved convergence
//! across a *two*-machine seam on hand-authored scripts. This suite turns the
//! pressure up: three authors sharing one op-log, dozens of interleaved
//! `remember`/`forget`/`link` ops, and each machine syncing at different points
//! so it observes a different *prefix* of the shared log — the partition the
//! convergence guarantee must survive. The thesis asserted here is the strong
//! one: after a final `sync`, all three machines hold the IDENTICAL set of live
//! notes with IDENTICAL bodies, regardless of the order each observed the log.
//!
//! Determinism without flakiness: every "random" choice (which actor acts, what
//! it does, which note it forgets) is driven by a deterministic [`SplitMix64`]
//! seeded from a fixed list — no `rand`, no wall-clock — so a failure replays
//! exactly. The convergence assertion compares the FULL `get`-hydrated note set
//! across machines (not just counts): two machines agreeing on a count while
//! disagreeing on *which* notes are live would be a divergence this catches.
//!
//! Liveness is probed through `get`, the public read path: `Ok` means the note
//! is live and indexed on that machine, `NotFound` means it converged away (a
//! tombstone won, or a non-member's op was filtered). All machines share the
//! one team key, so `get` never fails for a key reason here — the only expected
//! error is `NotFound`, and any other error fails the test rather than being
//! silently read as "not live".
#![expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning test uses `?` for setup but still asserts on outcomes; the assertions are the test, not a crash to avoid"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hippius_mem_core::{
    BlobStore, HashEmbedder, InMemoryIndex, MemError, MemoryBlobStore, MemoryStore, NoopAnchor,
    Note, NoteId, NoteType, OpLogStore, RememberInput, RepoScope, SecretKey, Signer, Sr25519Signer,
    Ss58,
};

/// The shared namespace every machine writes into.
const TEAM: &str = "ourovoros";
/// SS58 prefix 42 — Substrate's generic prefix, matching the rest of the suite.
const PREFIX: u16 = 42;
/// The one team key every machine seals/opens under, so cross-machine decryption
/// works and `get` can never fail for a missing-key reason in these scenarios.
const TEAM_KEY: [u8; 32] = [9_u8; 32];
/// A threshold no scenario reaches, so anchoring stays inert and the focus is
/// convergence rather than Merkle batching.
const INERT_THRESHOLD: usize = 1_000;
/// The repo dimension all generated notes live under.
const REPO: &str = "thebrain";

/// Distinct author seeds. Distinct seeds derive distinct SS58 identities, so
/// these are three independent writers appending to one shared op-log.
const SEED_A: [u8; 32] = [1_u8; 32];
const SEED_B: [u8; 32] = [2_u8; 32];
const SEED_C: [u8; 32] = [3_u8; 32];

/// Fixed seeds for the partitioned-convergence scenarios. Each drives one full
/// independent run (fresh bucket + three stores); the list is the replayable
/// stand-in for "many random interleavings".
const SCENARIO_SEEDS: [u64; 8] = [
    0x0000_0000_0000_0001,
    0x1234_5678_9ABC_DEF0,
    0xDEAD_BEEF_CAFE_F00D,
    0x0F0F_0F0F_0F0F_0F0F,
    0xA5A5_A5A5_A5A5_A5A5,
    0x7777_7777_7777_7777,
    0xFEDC_BA98_7654_3210,
    0x9E37_79B9_7F4A_7C15,
];

/// Number of scripted steps per scenario — enough interleaving of writes,
/// forgets, links, and partition-inducing syncs to stress convergence.
const STEPS_PER_SCENARIO: usize = 48;

type BoxError = Box<dyn std::error::Error>;

/// A `SplitMix64` PRNG: deterministic, no `rand` crate, no wall-clock, so every
/// scenario replays exactly from its `u64` seed. It scripts *which* actor acts
/// and *what* it does; it never seeds cryptographic material (the team key and
/// signing seeds are fixed constants).
///
/// Algorithm per Steele/Lea/Vigna `SplitMix64` (the reference golden-ratio
/// increment and two xor-shift-multiply finalizers); all arithmetic is wrapping
/// by construction, so it cannot panic on overflow.
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A `usize` in `0..n`, for indexing scripted choices. `n` must be non-zero
    /// (callers pass small constants / non-empty lengths), so the modulo cannot
    /// divide by zero. `try_from` (not `as`) keeps the conversions truncation-safe
    /// on every target width; the result is `< n`, a `usize`, so it always fits.
    fn below(&mut self, n: usize) -> usize {
        let Ok(modulus) = u64::try_from(n) else {
            return 0;
        };
        usize::try_from(self.next_u64() % modulus).unwrap_or(0)
    }
}

/// Build one machine's store over the shared `bucket`, sealing under [`TEAM_KEY`].
///
/// Per-machine: a fresh `InMemoryIndex`, an `OpLogStore` handle over the shared
/// bucket, a signing identity from `seed` (its author SS58 is derived from the
/// key, so distinct seeds are distinct authors), and its own `NoopAnchor`. The
/// bucket is shared so every machine sees the same op-log and manifests.
fn machine(bucket: &Arc<MemoryBlobStore>, seed: [u8; 32]) -> Result<MemoryStore, BoxError> {
    let index = Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default())));
    let blob: Arc<dyn BlobStore> = bucket.clone();
    let oplog = OpLogStore::new(blob.clone());
    let signer: Arc<dyn Signer> = Arc::new(Sr25519Signer::from_seed_with_prefix(seed, PREFIX)?);
    Ok(MemoryStore::new(
        blob,
        index,
        oplog,
        Arc::new(NoopAnchor),
        signer,
        BTreeMap::from([(0_u64, SecretKey::from_bytes(TEAM_KEY))]),
        0,
        TEAM.to_owned(),
        INERT_THRESHOLD,
    ))
}

/// The SS58 a machine built from `seed` signs as — the author the membership
/// manifest is built from.
fn author_of(seed: [u8; 32]) -> Result<Ss58, BoxError> {
    Ok(Sr25519Signer::from_seed_with_prefix(seed, PREFIX)?.author_ss58())
}

/// A note whose summary and body are keyed by `seq`, so every generated note is
/// distinct and a divergence in *which* note a machine holds is observable.
fn make_note(seq: usize) -> RememberInput {
    RememberInput {
        note_type: NoteType::Convention,
        repo: RepoScope::Repo(REPO.to_owned()),
        tags: BTreeSet::from([format!("tag-{seq}")]),
        summary: format!("note {seq}: a distinct summary for convergence checking"),
        body: format!("note {seq}: the distinct body that get() hydrates and we compare"),
    }
}

/// The set of notes a store currently surfaces, hydrated through the public
/// `get` path: `id -> Note` for every live note, omitting tombstoned/filtered
/// ones (`get` returns [`MemError::NotFound`]). Any non-`NotFound` error is a
/// real fault and propagates rather than being misread as "not live".
async fn live_view(
    store: &MemoryStore,
    universe: &[NoteId],
) -> Result<BTreeMap<NoteId, Note>, BoxError> {
    let mut view = BTreeMap::new();
    for &id in universe {
        match store.get(id).await {
            Ok(note) => {
                view.insert(id, note);
            }
            Err(MemError::NotFound { .. }) => {}
            Err(other) => return Err(other.into()),
        }
    }
    Ok(view)
}

/// The first remembered note not yet forgotten, in creation order — a
/// deterministic, replayable choice of a note to forget next.
fn next_live_candidate(remembered: &[NoteId], forgotten: &BTreeSet<NoteId>) -> Option<NoteId> {
    remembered
        .iter()
        .copied()
        .find(|id| !forgotten.contains(id))
}

/// One actor syncs, then forgets the next live note it can locate. Syncing
/// first both gives the actor the note in its index (forget needs it indexed)
/// and induces a partition: actors sync at different scripted points, so each
/// observes a different prefix of the shared log.
async fn step_forget(
    store: &MemoryStore,
    remembered: &[NoteId],
    forgotten: &mut BTreeSet<NoteId>,
) -> Result<(), BoxError> {
    store.sync().await?;
    let Some(id) = next_live_candidate(remembered, forgotten) else {
        return Ok(());
    };
    match store.forget(id).await {
        Ok(()) => {
            forgotten.insert(id);
            Ok(())
        }
        // The actor had not yet observed the note despite the sync (e.g. a
        // concurrent tombstone already pruned it): harmless, leave it live in
        // the expected set and let the final sync converge.
        Err(MemError::NotFound { .. }) => Ok(()),
        Err(other) => Err(other.into()),
    }
}

/// One actor syncs, then links two distinct live notes. Links do not change a
/// note's liveness or body, so they never alter the convergence assertion; they
/// exist to push extra `Link` ops through convergence and the op-log.
async fn step_link(
    store: &MemoryStore,
    remembered: &[NoteId],
    forgotten: &BTreeSet<NoteId>,
    rng: &mut SplitMix64,
) -> Result<(), BoxError> {
    store.sync().await?;
    let live: Vec<NoteId> = remembered
        .iter()
        .copied()
        .filter(|id| !forgotten.contains(id))
        .collect();
    if live.len() < 2 {
        return Ok(());
    }
    let from = live[rng.below(live.len())];
    let to = live[rng.below(live.len())];
    if from == to {
        return Ok(());
    }
    match store.link(from, to).await {
        // A successful link or a not-yet-observed `from` are both fine: links
        // never affect the convergence assertion, so a missing endpoint is a
        // harmless no-op the final sync renders moot.
        Ok(()) | Err(MemError::NotFound { .. }) => Ok(()),
        Err(other) => Err(other.into()),
    }
}

/// Run one fully deterministic partitioned scenario and assert all three
/// machines converge. Returns the number of live notes they converged on, so
/// the caller can sanity-check that scenarios actually exercise notes.
async fn run_partition_scenario(seed: u64) -> Result<usize, BoxError> {
    let bucket = Arc::new(MemoryBlobStore::default());
    let stores = [
        machine(&bucket, SEED_A)?,
        machine(&bucket, SEED_B)?,
        machine(&bucket, SEED_C)?,
    ];
    let mut rng = SplitMix64::new(seed);
    let mut remembered: Vec<NoteId> = Vec::new();
    let mut forgotten: BTreeSet<NoteId> = BTreeSet::new();

    for _ in 0..STEPS_PER_SCENARIO {
        let actor = &stores[rng.below(stores.len())];
        match rng.below(4) {
            0 => {
                let id = actor.remember(make_note(remembered.len())).await?;
                remembered.push(id);
            }
            1 => {
                actor.sync().await?;
            }
            2 => step_forget(actor, &remembered, &mut forgotten).await?,
            _ => step_link(actor, &remembered, &forgotten, &mut rng).await?,
        }
    }

    // Heal the partition: every machine replays the full shared log.
    for store in &stores {
        store.sync().await?;
    }

    // The thesis: all three machines hold the IDENTICAL live note set with
    // IDENTICAL bodies. Comparing full `get`-hydrated maps (not counts) means a
    // machine that converged on a different *set* of equal size still fails.
    let views = [
        live_view(&stores[0], &remembered).await?,
        live_view(&stores[1], &remembered).await?,
        live_view(&stores[2], &remembered).await?,
    ];
    assert_eq!(
        views[0], views[1],
        "machines A and B must converge on identical live notes (seed {seed:#x})",
    );
    assert_eq!(
        views[1], views[2],
        "machines B and C must converge on identical live notes (seed {seed:#x})",
    );

    // And the converged set is exactly what the script implies: every note
    // remembered and not forgotten, nothing more, nothing less.
    let expected_live: BTreeSet<NoteId> = remembered
        .iter()
        .copied()
        .filter(|id| !forgotten.contains(id))
        .collect();
    let got_live: BTreeSet<NoteId> = views[0].keys().copied().collect();
    assert_eq!(
        got_live, expected_live,
        "the converged live set must equal remembered minus forgotten (seed {seed:#x})",
    );
    Ok(expected_live.len())
}

#[tokio::test]
async fn partitioned_writes_converge_across_three_machines() -> Result<(), BoxError> {
    let mut total_live = 0;
    for &seed in &SCENARIO_SEEDS {
        total_live += run_partition_scenario(seed).await?;
    }
    // Guard against a degenerate suite that asserts convergence on always-empty
    // state: across all seeds the scripts must leave real notes converged.
    assert!(
        total_live > 0,
        "the scenarios must converge on a non-empty set of notes somewhere",
    );
    Ok(())
}

#[tokio::test]
async fn forget_of_anothers_note_converges_on_all_machines() -> Result<(), BoxError> {
    let bucket = Arc::new(MemoryBlobStore::default());
    let machine_a = machine(&bucket, SEED_A)?;
    let machine_b = machine(&bucket, SEED_B)?;
    let machine_c = machine(&bucket, SEED_C)?;

    // B creates a note; all three machines observe it after their first sync.
    let id = machine_b.remember(make_note(0)).await?;
    machine_a.sync().await?;
    machine_b.sync().await?;
    machine_c.sync().await?;
    for store in [&machine_a, &machine_b, &machine_c] {
        assert!(
            store.get(id).await.is_ok(),
            "every machine should hold B's note before it is forgotten",
        );
    }

    // A — a DIFFERENT author than the creator — forgets B's note. The tombstone
    // lands in the shared log; a Forget needs no creator privilege.
    machine_a.forget(id).await?;

    // After all re-sync, the tombstone has converged everywhere: the note is
    // gone on all three, including B (the original creator).
    machine_a.sync().await?;
    machine_b.sync().await?;
    machine_c.sync().await?;
    for store in [&machine_a, &machine_b, &machine_c] {
        assert!(
            matches!(store.get(id).await, Err(MemError::NotFound { .. })),
            "a forget by a non-creator must converge as a tombstone on every machine",
        );
    }
    Ok(())
}

#[tokio::test]
async fn non_member_note_excluded_consistently_across_members() -> Result<(), BoxError> {
    let bucket = Arc::new(MemoryBlobStore::default());
    // Three members and one outsider. The outsider holds the team-key bytes (so
    // it can seal a note) but is absent from the manifest — non-membership is a
    // manifest fact, not a key-possession one, which is exactly what the
    // convergence filter must enforce.
    let founder = machine(&bucket, SEED_A)?;
    let member_2 = machine(&bucket, SEED_B)?;
    let member_3 = machine(&bucket, SEED_C)?;
    let outsider = machine(&bucket, [4_u8; 32])?;

    founder
        .publish_membership(BTreeSet::from([
            author_of(SEED_A)?,
            author_of(SEED_B)?,
            author_of(SEED_C)?,
        ]))
        .await?;

    // The outsider writes (it can: it has the key bytes); a member writes a
    // legitimate note as the positive control.
    let outsider_note = outsider.remember(make_note(99)).await?;
    let member_note = founder.remember(make_note(1)).await?;

    // Every member replays the shared log. The current-member convergence filter
    // drops the outsider's op before it is ever decrypted or indexed.
    member_2.sync().await?;
    member_3.sync().await?;
    founder.sync().await?;

    for store in [&founder, &member_2, &member_3] {
        assert!(
            matches!(
                store.get(outsider_note).await,
                Err(MemError::NotFound { .. })
            ),
            "no member may surface a non-member's note — exclusion must be consistent across machines",
        );
        assert!(
            store.get(member_note).await.is_ok(),
            "the positive control: every member surfaces the member-authored note",
        );
    }
    Ok(())
}
