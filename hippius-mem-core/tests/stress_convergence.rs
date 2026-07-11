//! Phase 4 stress: many authors, interleaved ops, random partitions — all
//! machines converge to byte-identical memory.
//!
//! The earlier capstones ([`e2e_phase2`], [`e2e_phase3`]) proved convergence
//! across a *two*-machine seam on hand-authored scripts. This suite turns the
//! pressure up: three authors sharing one op-log, dozens of interleaved
//! `remember`/`edit`/`forget`/`redact`/`link` ops, and each machine syncing at
//! different points so it observes a different *prefix* of the shared log —
//! the partition the convergence guarantee must survive. The thesis asserted
//! here is the strong one: after a final `sync`, all three machines hold the
//! IDENTICAL set of live notes with IDENTICAL bodies, regardless of the order
//! each observed the log — including which edit's body won, and that a
//! redacted note stays absent everywhere.
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
    BlobStore, HashEmbedder, InMemoryIndex, MemError, MemoryBlobStore, MemoryStore, NetworkPrefix,
    NoopAnchor, Note, NoteId, NoteType, OpLogStore, RememberInput, RepoScope, SecretKey, Signer,
    Sr25519Signer, Ss58,
};

/// The shared namespace every machine writes into.
const TEAM: &str = "ourovoros";
/// SS58 prefix 42 — Substrate's generic prefix, matching the rest of the suite.
const PREFIX: NetworkPrefix = NetworkPrefix::HIPPIUS;
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
/// stand-in for "many random interleavings". `extra_scenario_seeds` lets a
/// caller widen this list at run time without losing its replay-exactly
/// property.
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
/// edits, forgets, redacts, links, and partition-inducing syncs to stress
/// convergence.
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
    let signer: Arc<dyn Signer> = Arc::new(Sr25519Signer::from_seed_with_prefix(&seed, PREFIX)?);
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
    Ok(Sr25519Signer::from_seed_with_prefix(&seed, PREFIX)?.author_ss58())
}

/// A note whose summary and body are keyed by `seq`, so every generated note is
/// distinct and a divergence in *which* note a machine holds is observable.
fn make_note(seq: usize) -> RememberInput {
    RememberInput {
        force: true,
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

/// Mutable bookkeeping threaded through one scenario run: which notes were
/// remembered, which are gone by forget or by the absorbing redact, and each
/// live note's current expected body. Bundled into one struct (not four loose
/// locals) so every step function stays under the five-positional-parameter
/// limit, and so "live" has exactly one definition shared by every step
/// rather than a `forgotten`/`redacted` filter drifting out of sync between
/// them (a real risk this file already showed once: `step_link`'s live-vector
/// filter used to be hand-duplicated from `next_live_candidate`'s).
#[derive(Default)]
struct ScenarioState {
    remembered: Vec<NoteId>,
    forgotten: BTreeSet<NoteId>,
    redacted: BTreeSet<NoteId>,
    /// The body `get` must return for each currently-live note: the original
    /// `remember`ed body, or the latest successful edit's body once one lands.
    current_body: BTreeMap<NoteId, String>,
    edits: usize,
    redacts: usize,
}

impl ScenarioState {
    /// The first remembered note that is neither forgotten nor redacted, in
    /// creation order — a deterministic, replayable choice for forget/edit/
    /// redact to act on next.
    fn next_live_candidate(&self) -> Option<NoteId> {
        self.remembered
            .iter()
            .copied()
            .find(|id| !self.forgotten.contains(id) && !self.redacted.contains(id))
    }

    /// Every remembered note not yet forgotten or redacted, in creation order.
    fn live_ids(&self) -> Vec<NoteId> {
        self.remembered
            .iter()
            .copied()
            .filter(|id| !self.forgotten.contains(id) && !self.redacted.contains(id))
            .collect()
    }
}

/// One actor syncs, then forgets the next live note it can locate. Syncing
/// first both gives the actor the note in its index (forget needs it indexed)
/// and induces a partition: actors sync at different scripted points, so each
/// observes a different prefix of the shared log.
async fn step_forget(store: &MemoryStore, state: &mut ScenarioState) -> Result<(), BoxError> {
    store.sync().await?;
    let Some(id) = state.next_live_candidate() else {
        return Ok(());
    };
    match store.forget(id).await {
        Ok(()) => {
            state.forgotten.insert(id);
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
    state: &ScenarioState,
    rng: &mut SplitMix64,
) -> Result<(), BoxError> {
    store.sync().await?;
    let live = state.live_ids();
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

/// A distinct revision of `id`'s content, keyed by `revision` so a converged
/// body unambiguously identifies which edit won — the same disambiguation
/// role `make_note`'s `seq` plays for original bodies.
fn edited_note(id: NoteId, revision: u64) -> RememberInput {
    RememberInput {
        force: true,
        note_type: NoteType::Convention,
        repo: RepoScope::Repo(REPO.to_owned()),
        tags: BTreeSet::from([format!("edit-{revision}")]),
        summary: format!("note {id} revision {revision}: edited for convergence checking"),
        body: format!("note {id} revision {revision}: the edited body that get() hydrates"),
    }
}

/// One actor syncs, then edits the next live note it can locate. Syncing
/// first (like `step_forget`) guarantees this edit's Lamport value exceeds
/// every op the actor has observed — and, because the scenario's steps run
/// strictly sequentially (never truly concurrently), that means it exceeds
/// every op in the system so far. That is what lets `state.current_body`'s
/// "last executed edit wins" bookkeeping match the real
/// `(lamport, op_id, author_key)` ranking `NoteAccumulator::observe`
/// (`oplog/converge.rs`) uses for the content pointer, without this test
/// re-deriving that tie-break itself.
async fn step_edit(
    store: &MemoryStore,
    state: &mut ScenarioState,
    rng: &mut SplitMix64,
) -> Result<(), BoxError> {
    store.sync().await?;
    let Some(id) = state.next_live_candidate() else {
        return Ok(());
    };
    let input = edited_note(id, rng.next_u64());
    match store.edit(id, input.clone()).await {
        Ok(()) => {
            state.current_body.insert(id, input.body);
            state.edits += 1;
            Ok(())
        }
        // Mirrors `step_forget`: a concurrent tombstone landing between sync
        // and edit is harmless, the final sync converges either way.
        Err(MemError::NotFound { .. }) => Ok(()),
        Err(other) => Err(other.into()),
    }
}

/// One actor syncs, then redacts the next live note it can locate. Unlike
/// forget, redaction is absorbing — `NoteAccumulator::redacted` is an OR that
/// "never clears, ... redaction wins regardless of order" (`oplog/converge.rs`)
/// — so once `state.redacted` records an id here, no later scripted edit can
/// resurrect it, and `next_live_candidate`/`live_ids` permanently exclude it.
async fn step_redact(store: &MemoryStore, state: &mut ScenarioState) -> Result<(), BoxError> {
    store.sync().await?;
    let Some(id) = state.next_live_candidate() else {
        return Ok(());
    };
    match store.redact(id).await {
        Ok(()) => {
            state.redacted.insert(id);
            state.redacts += 1;
            Ok(())
        }
        Err(MemError::NotFound { .. }) => Ok(()),
        Err(other) => Err(other.into()),
    }
}

/// Aggregate outcome of one scenario run: how many notes converged live, and
/// how many Edit/Redact ops actually landed. The edit/redact counters let the
/// caller assert the scripted op mix exercised every kind at least once
/// across all seeds — otherwise a candidate-starved or probability-unlucky
/// run would leave those arms compiling but never actually asserted on.
struct ScenarioStats {
    live_notes: usize,
    edits: usize,
    redacts: usize,
}

/// Run one fully deterministic partitioned scenario and assert all three
/// machines converge. Returns [`ScenarioStats`] so the caller can sanity-check
/// that scenarios actually exercise notes and every op kind.
async fn run_partition_scenario(seed: u64) -> Result<ScenarioStats, BoxError> {
    let bucket = Arc::new(MemoryBlobStore::default());
    let stores = [
        machine(&bucket, SEED_A)?,
        machine(&bucket, SEED_B)?,
        machine(&bucket, SEED_C)?,
    ];
    let mut rng = SplitMix64::new(seed);
    let mut state = ScenarioState::default();

    for _ in 0..STEPS_PER_SCENARIO {
        let actor = &stores[rng.below(stores.len())];
        match rng.below(6) {
            0 => {
                let note = make_note(state.remembered.len());
                let id = actor.remember(note.clone()).await?;
                state.current_body.insert(id, note.body);
                state.remembered.push(id);
            }
            1 => {
                actor.sync().await?;
            }
            2 => step_forget(actor, &mut state).await?,
            3 => step_link(actor, &state, &mut rng).await?,
            4 => step_edit(actor, &mut state, &mut rng).await?,
            _ => step_redact(actor, &mut state).await?,
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
        live_view(&stores[0], &state.remembered).await?,
        live_view(&stores[1], &state.remembered).await?,
        live_view(&stores[2], &state.remembered).await?,
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
    // remembered and not forgotten or redacted, nothing more, nothing less.
    let expected_live: BTreeSet<NoteId> = state.live_ids().into_iter().collect();
    let got_live: BTreeSet<NoteId> = views[0].keys().copied().collect();
    assert_eq!(
        got_live, expected_live,
        "the converged live set must equal remembered minus forgotten/redacted (seed {seed:#x})",
    );

    // And each live note carries the body the script's bookkeeping expects —
    // this is what actually proves Edit convergence, as opposed to the three
    // machines merely agreeing with EACH OTHER on some (possibly wrong, e.g.
    // first-instead-of-Lamport-latest) body.
    for id in &expected_live {
        let expected_body = state
            .current_body
            .get(id)
            .ok_or("every live note must have a tracked expected body")?;
        assert_eq!(
            &views[0][id].body, expected_body,
            "note {id} must converge on the last edit's body, not an earlier or partial one (seed {seed:#x})",
        );
    }

    Ok(ScenarioStats {
        live_notes: expected_live.len(),
        edits: state.edits,
        redacts: state.redacts,
    })
}

/// Extra seeds beyond the fixed [`SCENARIO_SEEDS`], read from the
/// `STRESS_CONVERGENCE_EXTRA_SEEDS` env var as a comma-separated list of
/// `u64` (decimal or `0x`-prefixed hex). Lets CI or a developer widen coverage
/// — e.g. seeding from the commit SHA on a schedule — without losing the fixed
/// list's replay-exactly property: a run against an extra seed still replays
/// exactly given the same env value, and a failure it finds should have its
/// seed promoted into `SCENARIO_SEEDS` so it stays covered unconditionally. An
/// unset or empty var yields no extra seeds; a malformed entry is skipped
/// rather than failing the whole list, since one bad entry (e.g. a typo)
/// should not silently drop every other requested seed.
fn extra_scenario_seeds() -> Vec<u64> {
    let Ok(raw) = std::env::var("STRESS_CONVERGENCE_EXTRA_SEEDS") else {
        return Vec::new();
    };
    raw.split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .filter_map(|part| match part.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16).ok(),
            None => part.parse().ok(),
        })
        .collect()
}

#[tokio::test]
async fn partitioned_writes_converge_across_three_machines() -> Result<(), BoxError> {
    let mut total_live = 0;
    let mut total_edits = 0;
    let mut total_redacts = 0;
    let seeds: Vec<u64> = SCENARIO_SEEDS
        .iter()
        .copied()
        .chain(extra_scenario_seeds())
        .collect();
    for seed in seeds {
        let stats = run_partition_scenario(seed).await?;
        total_live += stats.live_notes;
        total_edits += stats.edits;
        total_redacts += stats.redacts;
    }
    // Guard against a degenerate suite that asserts convergence on always-empty
    // state: across all seeds the scripts must leave real notes converged.
    assert!(
        total_live > 0,
        "the scenarios must converge on a non-empty set of notes somewhere",
    );
    // Guard against the Edit/Redact arms silently going untested: without this,
    // a candidate-starved or probability-unlucky mix could leave them dead code
    // despite compiling and being wired into the match arms above.
    assert!(
        total_edits > 0,
        "the scenarios must exercise at least one converged Edit somewhere",
    );
    assert!(
        total_redacts > 0,
        "the scenarios must exercise at least one converged Redact somewhere",
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

#[tokio::test]
async fn edit_by_one_author_converges_to_all_machines() -> Result<(), BoxError> {
    let bucket = Arc::new(MemoryBlobStore::default());
    let machine_a = machine(&bucket, SEED_A)?;
    let machine_b = machine(&bucket, SEED_B)?;
    let machine_c = machine(&bucket, SEED_C)?;

    let id = machine_a.remember(make_note(0)).await?;
    machine_a.sync().await?;
    machine_b.sync().await?;
    machine_c.sync().await?;

    // B — a DIFFERENT author than the creator — edits the note; an edit needs
    // no creator privilege, mirroring `forget`'s cross-author rule proven
    // above.
    let revision = edited_note(id, 1);
    machine_b.edit(id, revision.clone()).await?;

    machine_a.sync().await?;
    machine_b.sync().await?;
    machine_c.sync().await?;
    for store in [&machine_a, &machine_b, &machine_c] {
        assert_eq!(
            store.get(id).await?.body,
            revision.body,
            "a cross-author edit must converge to the SAME body on every machine",
        );
    }
    Ok(())
}

#[tokio::test]
async fn redact_wins_over_a_racing_edit_from_another_author() -> Result<(), BoxError> {
    // Redaction is an absorbing OR over the whole op set
    // (`NoteAccumulator::redacted` in `oplog/converge.rs`), NOT ranked by
    // `(lamport, op_id, author_key)` the way the content pointer is. This pins
    // that contract at the multi-machine seam: B and C both act from the SAME
    // synced base without observing each other first (a genuine race — their
    // ops can even land the same Lamport value, since neither has seen the
    // other's op yet), so the edit's op may or may not out-rank the redact's
    // by Lamport order. Regardless, the note must end up redacted (absent)
    // everywhere — never resurrected by the racing edit.
    let bucket = Arc::new(MemoryBlobStore::default());
    let machine_a = machine(&bucket, SEED_A)?;
    let machine_b = machine(&bucket, SEED_B)?;
    let machine_c = machine(&bucket, SEED_C)?;

    let id = machine_a.remember(make_note(0)).await?;
    machine_a.sync().await?;
    machine_b.sync().await?;
    machine_c.sync().await?;

    machine_b.edit(id, edited_note(id, 1)).await?;
    machine_c.redact(id).await?;

    machine_a.sync().await?;
    machine_b.sync().await?;
    machine_c.sync().await?;
    for store in [&machine_a, &machine_b, &machine_c] {
        assert!(
            matches!(store.get(id).await, Err(MemError::NotFound { .. })),
            "redact must win over a racing edit and converge as absent on every machine",
        );
    }
    Ok(())
}
