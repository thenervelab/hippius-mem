//! Edge cases at the seam between the op-log reader and convergence: the
//! composed `list -> fetch (unordered) -> verify -> quarantine -> sort ->
//! converge` pipeline `sync` actually runs, which the unit suites only cover
//! in two disjoint halves.
//!
//! `converge` (`oplog/converge.rs`) is proptested for order-independence over
//! a hand-assembled `VerifiedOps`, bypassing `OpLogStore` entirely.
//! `longest_rooted_chain` (`oplog/store.rs`) is separately proptested for
//! fetch-order independence, but only over a single unforked chain (see that
//! proptest's generator: it extends one `prev` pointer in a straight line, so
//! `longest_rooted_chain`'s fork-tiebreak branch — the `reduce` over more than
//! one child of the same parent — is never exercised there). Neither proptest
//! drives the real `OpLogStore::read_all` path, so the composition — does the
//! *order objects are listed and fetched in* survive all the way through to
//! the converged state — was never asserted end to end. This file closes that
//! gap with one composed proptest.
//!
//! # What we checked empirically before writing the property this way
//!
//! The obvious mutation to reach for is deleting the total sort
//! (`ops.sort_by_cached_key` near the end of `read_verified`,
//! `hippius-mem-core/src/oplog/store.rs:306`) and expecting the
//! listing-order-independence property below to fail without it. **It does
//! not.** Deleting that sort and rerunning
//! [`composed_read_and_converge_is_listing_order_independent`] against it
//! still passes: `converge` groups ops by `note_id` and reduces each group by
//! max/union/OR, all order-insensitive operations (see `oplog/converge.rs`'s
//! own doc comment and its `converge_is_order_independent` proptest), so
//! feeding it the SAME set of ops in a different sequence produces the
//! identical `ConvergedState` regardless of whether that sequence is sorted.
//! The sort is real defense-in-depth (it is what makes `VerifiedOps`
//! iteration order agree with the per-note convergence order across
//! machines, which callers other than `converge` — e.g. `history` — rely on),
//! but this property, asserted only through `converge`, cannot show it is
//! load-bearing. Do not read a green run of this test as evidence the sort
//! matters; it was checked directly (by deleting the sort and rerunning) and
//! found NOT to matter for this property, precisely because `converge`
//! already tolerates any order.
//!
//! # What DOES discriminate, and what the fixture is built around
//!
//! `quarantine_broken_chains` -> `longest_rooted_chain` runs BEFORE the sort,
//! over the ops in raw fetch-arrival order (the order `buffer_unordered`
//! yields completed GETs in, itself driven by the — possibly rotated —
//! listing order). Its fork tiebreak is supposed to be arrival-order-blind: on
//! a height tie between two branches, the documented rule is "the LOWER total
//! order `(lamport, op_id, hash)` wins", independent of which branch's op was
//! fetched first. [`seeded_bucket`] deliberately includes one author whose
//! chain forks into two single-op, equal-height leaves so that rule has
//! something to do. Mutating the tiebreak to fall back to "whichever child was
//! encountered first" (dropping the total-order comparison) makes the
//! surviving leaf depend on fetch-arrival order — invisible to
//! `longest_rooted_chain_is_fetch_order_independent` (which never generates a
//! fork) and invisible to `converge_is_order_independent` (which never runs
//! `quarantine_broken_chains` at all) — and this test catches it: rotating the
//! listing changes which leaf note appears in the converged state. See the
//! commit message for the exact mutation and the observed rotations that
//! flipped it.
//!
//! # Known blind spots (do not overclaim)
//!
//! - The fixture holds 8 op objects, under `OPLOG_FETCH_CONCURRENCY`'s fetch
//!   bound of 64 (`hippius-mem-core/src/oplog/store.rs:57`), so every GET
//!   lands in a single `buffer_unordered` batch. This test says nothing about
//!   order-independence ACROSS batches on a log large enough to need more
//!   than one.
//! - It exercises exactly one fork shape: two single-op, EQUAL-HEIGHT leaves.
//!   `store.rs`'s `fork_orphans_only_the_stray_op_not_the_linked_successors`
//!   unit test also reaches the tiebreak's `reduce` closure, but with UNEQUAL
//!   heights (a 3-op live branch vs. a 1-op stray) — height alone decides
//!   there, so the tiebreak comparison never actually runs.
//!   `broken_chain_keeps_valid_prefix_without_blinding_the_team`
//!   (`store.rs:966`) is the one pre-existing test that reaches a genuine
//!   EQUAL-HEIGHT tie (two lone ops both rooted directly at genesis, both
//!   height 1) — but it still cannot catch the arrival-order mutation this
//!   file targets, because `MemoryBlobStore::list` is always
//!   lexicographically sorted and that test never varies listing order, so
//!   its lower-`(lamport, op_id)` op always arrives first regardless. A
//!   deeper or asymmetric equal-height fork, or one combined with a mid-chain
//!   gap, is untested here.
//! - The vacuity guard on `baseline` (added alongside the equality assertion)
//!   pins exactly the fork resolution: the low-order leaf's note is present,
//!   the high-order leaf's is not. It does not independently verify author
//!   A's edit-wins-over-remember reduction or author C's tombstone
//!   reduction. For content the guard does not cover, this test can still
//!   only show baseline and rotated AGREE, not that either is correct — the
//!   general limitation the guard exists to narrow, not eliminate.
//! - This is a fixed, hand-built op set (not a proptest generator over
//!   arbitrary op graphs) rotated in every possible way; it proves the
//!   property for THIS set, not for arbitrary ones. Arbitrary-set
//!   order-independence of `converge` alone is `converge_is_order_independent`'s
//!   job; arbitrary-set fetch-order independence of the chain-selection alone
//!   is `longest_rooted_chain_is_fetch_order_independent`'s job (modulo the
//!   fork-generation gap noted above). This test's job is narrower: prove the
//!   REAL `OpLogStore::read_all` composition preserves that independence for a
//!   representative multi-author, one-fork op set.
#![expect(
    clippy::panic_in_result_fn,
    reason = "the missing-blob recovery test and the minority op-fetch-outage test below both use `?` for setup but still assert on outcomes; the assertions are the test, not a crash to avoid"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use hippius_mem_core::{
    Blake3Hash, BlobStore, ConvergedState, GENESIS_PREV, HashEmbedder, InMemoryIndex, MemError,
    MemoryBlobStore, MemoryStore, NetworkPrefix, NoopAnchor, NoteId, NoteType, Op, OpContent,
    OpKind, OpLogStore, RememberInput, RepoScope, SecretKey, Signer, Sr25519Signer, content_hash,
    converge,
};
use proptest::prelude::*;
use proptest::test_runner::{FileFailurePersistence, TestCaseError};
use ulid::Ulid;

/// The shared op-log namespace the fixture writes into.
const TEAM: &str = "convergence-edges";

/// Note-id slot for author A's single edited note.
const NOTE_A: u128 = 1;
/// Note-id slot for author B's chain root (always kept; never observed
/// directly, so its identity does not matter beyond being distinct).
const NOTE_B_ROOT: u128 = 2;
/// Note-id slot for author B's shared pre-fork op.
const NOTE_B_SHARED: u128 = 3;
/// Note-id slot the LOWER-total-order fork leaf writes to. Under the real
/// (unmutated) tiebreak this is the leaf that always survives.
const NOTE_LEAF_LOW: u128 = 4;
/// Note-id slot the HIGHER-total-order fork leaf writes to. Under the real
/// tiebreak this one is always quarantined; it only survives under the
/// arrival-order-dependent mutation described in the module doc.
const NOTE_LEAF_HIGH: u128 = 5;
/// Note-id slot for author C's tombstoned note.
const NOTE_C: u128 = 6;

/// Build a deterministic signer from a one-byte seed, matching the pattern
/// `oplog::store`'s own unit tests use.
fn signer(seed: u8) -> Result<Sr25519Signer, MemError> {
    Sr25519Signer::from_seed_with_prefix(&[seed; 32], NetworkPrefix::HIPPIUS)
}

/// The `NoteId` a `note_slot` constant maps to. Shared by [`signed_op`] (which
/// mints ops against it) and the property test's vacuity assertions (which
/// check a specific slot's presence/absence in the converged state), so the
/// two can never drift apart on how a slot number becomes a `NoteId`.
fn note_id_for(note_slot: u128) -> NoteId {
    NoteId::from(Ulid::from(note_slot))
}

/// Build one signed op. `seq` drives `op_id` (and so the op's position in the
/// total order among same-lamport siblings) and the ciphertext digest;
/// `note_slot` selects which note the op names.
fn signed_op(
    signer: &Sr25519Signer,
    prev: Blake3Hash,
    lamport: u64,
    seq: u128,
    note_slot: u128,
    kind: OpKind,
) -> Op {
    let content = OpContent {
        op_id: Ulid::from(seq),
        lamport,
        key_epoch: 0,
        kind,
        note_id: note_id_for(note_slot),
        object_key: format!("{TEAM}/global/notes/{seq}"),
        cid: content_hash(format!("ciphertext-{seq}").as_bytes()),
        prev_op_hash: prev,
    };
    Op::create_signed(signer, content)
}

/// Build the fixture bucket: 8 op objects from 3 authors, written through the
/// real signing + `OpLogStore::append` path (never a hand-assembled
/// `VerifiedOps`).
///
/// - Author A: a straight 2-op chain (`Remember` then `Edit`) on one note —
///   the ordinary case, exercising the pointer "latest op wins" reduction
///   through the composed path.
/// - Author B: a genesis-rooted 2-op prefix (root, shared) that then forks
///   into two single-op, EQUAL-HEIGHT leaves on distinct notes — the shape
///   `longest_rooted_chain`'s tiebreak exists for (see the module doc).
/// - Author C: a straight 2-op chain (`Remember` then `Forget`) — exercises
///   the tombstone reduction through the composed path.
///
/// 8 ops total, matched to `rotation in 0_usize..8` in the property test
/// below: `rotate_listing` reduces `rotation` mod the listing length, so with
/// exactly 8 objects every generated rotation lands on a DISTINCT left-rotation
/// of the 8-element listing — the range neither over- nor under-covers the
/// fixture's actual op count.
async fn seeded_bucket() -> Result<Arc<MemoryBlobStore>, MemError> {
    let bucket = Arc::new(MemoryBlobStore::new());
    let store = OpLogStore::new(bucket.clone());

    let a = signer(1)?;
    let a1 = signed_op(&a, GENESIS_PREV, 0, 1, NOTE_A, OpKind::Remember);
    store.append(TEAM, &a1).await?;
    let a2 = signed_op(&a, a1.hash(), 1, 2, NOTE_A, OpKind::Edit);
    store.append(TEAM, &a2).await?;

    let b = signer(2)?;
    let root = signed_op(&b, GENESIS_PREV, 0, 10, NOTE_B_ROOT, OpKind::Remember);
    store.append(TEAM, &root).await?;
    let shared = signed_op(&b, root.hash(), 1, 11, NOTE_B_SHARED, OpKind::Remember);
    store.append(TEAM, &shared).await?;
    let fork_point = shared.hash();
    let leaf_low = signed_op(&b, fork_point, 2, 20, NOTE_LEAF_LOW, OpKind::Remember);
    let leaf_high = signed_op(&b, fork_point, 2, 30, NOTE_LEAF_HIGH, OpKind::Remember);
    store.append(TEAM, &leaf_low).await?;
    store.append(TEAM, &leaf_high).await?;

    let c = signer(3)?;
    let c1 = signed_op(&c, GENESIS_PREV, 0, 40, NOTE_C, OpKind::Remember);
    store.append(TEAM, &c1).await?;
    let c2 = signed_op(&c, c1.hash(), 1, 41, NOTE_C, OpKind::Forget);
    store.append(TEAM, &c2).await?;

    Ok(bucket)
}

/// A [`BlobStore`] decorator that left-rotates whatever its `inner` store
/// lists, so tests can vary listing order without depending on
/// [`MemoryBlobStore`] internals (its own `list` is always lexicographically
/// sorted — see that type's doc comment — so rotation is what actually varies
/// the order `read_verified` observes).
struct RotatedListing {
    inner: Arc<dyn BlobStore>,
    rotation: usize,
}

#[async_trait::async_trait]
impl BlobStore for RotatedListing {
    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
        self.inner.put(key, bytes).await
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
        self.inner.get(key).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError> {
        let mut keys = self.inner.list(prefix).await?;
        let len = keys.len();
        if len > 0 {
            keys.rotate_left(self.rotation % len);
        }
        Ok(keys)
    }

    async fn delete(&self, key: &str) -> Result<(), MemError> {
        self.inner.delete(key).await
    }
}

/// Wrap `inner` so its `list` returns the same keys left-rotated by `rotation`.
fn rotate_listing(inner: Arc<dyn BlobStore>, rotation: usize) -> Arc<dyn BlobStore> {
    Arc::new(RotatedListing { inner, rotation })
}

/// The real composed read path: verify-and-order every op in `blob`'s
/// `TEAM` log, then fold it into converged per-note state.
async fn read_and_converge(blob: Arc<dyn BlobStore>) -> Result<ConvergedState, MemError> {
    let verified = OpLogStore::new(blob).read_all(TEAM).await?;
    Ok(converge(&verified))
}

/// Run the composed pipeline twice over one freshly seeded bucket: once at
/// rotation 0 (the baseline) and once at `rotation`. Synchronous so the
/// proptest body below can call it directly and propagate a plain
/// `Result` with `?`; it builds its own current-thread runtime per call,
/// matching the established pattern in `store::tests::remember_get_round_trips`
/// (`hippius-mem-core/src/store/mod.rs`) — `MemoryBlobStore` needs no I/O
/// driver, so a bare `Builder::new_current_thread().build()` is enough.
fn run_pipeline_at_rotation(rotation: usize) -> Result<(ConvergedState, ConvergedState), MemError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(MemError::from)?;

    runtime.block_on(async move {
        let bucket = seeded_bucket().await?;
        let blob: Arc<dyn BlobStore> = bucket;
        let baseline = read_and_converge(rotate_listing(blob.clone(), 0)).await?;
        let rotated = read_and_converge(rotate_listing(blob, rotation)).await?;
        Ok((baseline, rotated))
    })
}

proptest! {
    // This test never generates a source file proptest's default
    // `FileFailurePersistence::SourceParallel` can locate (it walks up from
    // `tests/convergence_edges.rs` looking for a sibling `lib.rs`/`main.rs`,
    // and finds neither), so left at its default it would silently warn and
    // write `tests/convergence_edges.proptest-regressions` — an untracked
    // file matched by no `.gitignore` rule, in a working tree multiple agents
    // share. Pointed explicitly at the SAME tracked convention the crate
    // already uses for its `src/`-rooted proptests (see
    // `hippius-mem-core/proptest-regressions/oplog/converge.txt` and
    // siblings): a regression here becomes a normal, reviewable, committed
    // fixture instead of accidental untracked noise.
    #![proptest_config(ProptestConfig::with_failure_persistence(
        FileFailurePersistence::Direct("proptest-regressions/tests/convergence_edges.txt"),
    ))]

    /// The composed `OpLogStore::read_all` -> `converge` path — `sync`'s real
    /// read path, not either half in isolation — must converge to identical
    /// state no matter what order the backend lists the same op objects in,
    /// AND that state must be the specific fork resolution the fixture is
    /// built around, not merely "whatever it is, both runs agree" (an empty
    /// `ConvergedState` on both sides would satisfy equality alone).
    ///
    /// See the module doc for what this test can and cannot show: it does NOT
    /// show the total sort in `read_verified` is load-bearing for this
    /// property (checked directly — it is not, because `converge` already
    /// tolerates any order); it DOES show the fork tiebreak in
    /// `longest_rooted_chain`, which runs before that sort, stays
    /// arrival-order-blind through the real fetch path.
    #[test]
    fn composed_read_and_converge_is_listing_order_independent(rotation in 0_usize..8) {
        let (baseline, rotated) = run_pipeline_at_rotation(rotation)
            .map_err(|e| TestCaseError::fail(e.to_string()))?;

        prop_assert!(
            baseline.contains_key(&note_id_for(NOTE_LEAF_LOW)),
            "the low-order fork leaf must survive quarantine and reach converge"
        );
        prop_assert!(
            !baseline.contains_key(&note_id_for(NOTE_LEAF_HIGH)),
            "the high-order fork leaf must stay quarantined, never reaching converge"
        );
        prop_assert_eq!(baseline, rotated, "listing order must not change converged state");
    }
}

// # Missing-blob recovery
//
// The property test above composes the read path over a hand-built op-log;
// the fixture below instead builds a real `MemoryStore` (`remember` /
// `sync` / `get`), because the recovery question — does a note whose blob
// vanished and then reappeared get re-indexed on the NEXT sync — lives in
// `MemoryStore::sync`'s snapshot/incremental bookkeeping, one layer above
// `OpLogStore::read_all` -> `converge`. `OpLogStore` and `converge` alone
// have no notion of "blob"; there is nothing there to delete.

/// Signing seed for the fixture below. Fixed (not derived from the rotation
/// proptest's three authors above) so `store` and `fresh` share one
/// identity, modelling a single machine re-syncing against a shared bucket
/// after a restart — not a second author joining.
const RECOVERY_SEED: [u8; 32] = [9_u8; 32];

/// The epoch-0 team key every note in the fixture below is sealed under.
const RECOVERY_TEAM_KEY: [u8; 32] = [42_u8; 32];

/// Team namespace for the fixture below, distinct from [`TEAM`] so nothing
/// here can collide with the rotation proptest above even if a future edit
/// shares a bucket between them.
const RECOVERY_TEAM: &str = "convergence-edges-missing-blob";

/// Build a `MemoryStore` directly over `blob` — no `CachingBlobStore`
/// decorator in between — signing as the fixed recovery identity and
/// sealing under the fixed recovery team key at epoch 0.
///
/// A bare `blob` (rather than a caching wrapper) matters here specifically:
/// the test below deletes an object straight from `blob` and asserts it can
/// no longer be served, which a warm cache layer could satisfy for the
/// wrong reason (serving the deleted object from its own copy). There is no
/// cache anywhere in this construction to do that.
///
/// Mirrors `hippius-mem-core/src/store/mod.rs`'s private `store_over` test
/// helper and `tests/e2e_durability.rs`'s `seed_machine`; neither is
/// reachable from this file (each `tests/*.rs` file compiles as its own
/// crate), so this is a third, minimal copy scoped to exactly what the test
/// below needs.
fn store_over(blob: Arc<dyn BlobStore>) -> Result<MemoryStore, MemError> {
    let signer: Arc<dyn Signer> = Arc::new(Sr25519Signer::from_seed_with_prefix(
        &RECOVERY_SEED,
        NetworkPrefix::HIPPIUS,
    )?);
    let index = Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default())));
    let oplog = OpLogStore::new(blob.clone());

    Ok(MemoryStore::new(
        blob,
        index,
        oplog,
        Arc::new(NoopAnchor),
        signer,
        BTreeMap::from([(0, SecretKey::from_bytes(RECOVERY_TEAM_KEY))]),
        0,
        RECOVERY_TEAM.to_owned(),
        usize::MAX,
    ))
}

/// A minimal `RememberInput` naming `summary`/`body`; every field the test
/// below does not vary is held at a fixed, arbitrary value.
fn input(summary: &str, body: &str) -> RememberInput {
    RememberInput {
        force: true,
        note_type: NoteType::Reference,
        repo: RepoScope::Global,
        tags: BTreeSet::new(),
        summary: summary.to_owned(),
        body: body.to_owned(),
    }
}

/// A note's ciphertext blob vanishing from the bucket must degrade cleanly —
/// the note is skipped with a warning, the rest of the log still converges —
/// and the note must come BACK on the next sync once the blob is restored.
///
/// The corrupt-blob path has a test
/// (`store::tests::get_detects_tampered_blob`,
/// `store::tests::sync_skips_notes_with_unreadable_blobs_and_counts_the_rest`
/// in `hippius-mem-core/src/store/mod.rs`); the missing-blob path did not,
/// and neither asserted recovery. Recovery is the half that matters
/// operationally: a transient gateway 404 must not permanently drop a note
/// from the index.
///
/// What this test does NOT show: recovery through a FULL rebuild (both
/// syncs below happen to take `sync`'s incremental path, since the first
/// sync's full rebuild always persists a checkpoint — see the inline note at
/// the second `sync` call); recovery under a concurrent writer; or a blob
/// that comes back CORRUPTED rather than byte-identical to what was
/// deleted.
#[tokio::test]
async fn a_missing_blob_is_skipped_and_returns_on_the_next_sync()
-> Result<(), Box<dyn std::error::Error>> {
    let bucket = Arc::new(MemoryBlobStore::default());
    let store = store_over(bucket.clone())?;

    let kept = store.remember(input("kept note", "kept body")).await?;
    let vanishing = store
        .remember(input("vanishing note", "vanishing body"))
        .await?;

    // Take the blob out of the bucket, keeping a copy to restore. The key
    // comes from the store's own index (`list_records`) — there is no
    // `object_key_of` accessor, and none is added for this test's
    // convenience.
    let key = store
        .list_records()?
        .into_iter()
        .find(|record| record.note_id == vanishing)
        .ok_or("vanishing note not indexed after remember")?
        .object_key;
    let saved = bucket.get(&key).await?;
    bucket.delete(&key).await?;

    let fresh = store_over(bucket.clone())?;
    fresh.sync().await?;

    assert!(
        fresh.get(kept).await.is_ok(),
        "an unrelated note must still converge"
    );
    assert!(
        fresh.get(vanishing).await.is_err(),
        "a note whose blob is gone must not be served"
    );

    // Restore and re-sync: the note must come back, not stay permanently
    // pruned. The first `sync` above was a cold, checkpoint-less full
    // rebuild, and a full rebuild always persists a checkpoint afterward
    // (`MemoryStore::sync`'s `checkpoint_stale` gate is unconditional the
    // first time), so THIS sync takes `sync_incremental`'s path: `vanishing`
    // is absent from that checkpoint (its blob could not be decoded when the
    // checkpoint was built) but still converges live in the op-log base, so
    // `sync_incremental` re-attempts its blob as an "omitted" base note on
    // every sync until it decodes — exactly the case a once-missing,
    // now-restored blob falls into.
    bucket.put(&key, saved).await?;
    fresh.sync().await?;

    assert_eq!(
        fresh.get(vanishing).await?.summary,
        "vanishing note",
        "a restored blob must repopulate the index on the next sync"
    );
    Ok(())
}

// # Minority op-fetch outage recovery
//
// The missing-blob test above faults a NOTE blob (the encrypted content a
// `Remember`/`Edit` op points at). This section faults something one layer
// earlier: an OP OBJECT itself (the signed, hash-chained record under
// `{team}/_oplog/`). `OpLogStore::read_verified` tolerates isolated GET
// failures on that prefix below a `>= 50%` threshold
// (`hippius-mem-core/src/oplog/store.rs:260-267`) by skipping the unfetched
// op with a warn rather than erroring the whole read — but that means the
// `VerifiedOps` `sync` then converges over is missing an op the caller never
// sees an error for. Both `replay_full`'s `index.retain(&live_ids)`
// (`store/mod.rs:3117`) and `sync_incremental`'s `index.retain(&final_live)`
// (`store/mod.rs:3284`) prune the index to exactly what THAT read converged
// to, so a note whose only op silently failed to fetch is pruned from a warm
// index — not because it changed, but because this one read could not see it.
// The threshold itself has three existing tests
// (`hippius-mem-core/src/oplog/store.rs`); what happens on a read that stays
// BELOW it was not previously asserted.

/// The object-key prefix `OpLogStore` derives for a team's op-log.
///
/// Duplicated here rather than imported: `oplog_prefix` is a private helper
/// (`hippius-mem-core/src/oplog/store.rs:431`) and this file needs to name one
/// op object precisely, by key, to fault it. `object_key` there confirms the
/// format this mirrors: `{team}/_oplog/{lamport:020}_{op_id}_{author_hex}`.
fn oplog_object_prefix(team: &str) -> String {
    format!("{team}/_oplog/")
}

/// A [`BlobStore`] decorator that fails `get` for exactly ONE configured
/// op-log object while [`Self::arm`] is armed, and otherwise delegates
/// every call — including gets for every other key — to `inner`
/// unconditionally.
///
/// Modelled on `oplog::store`'s own `GetFailBlob` test fixture
/// (`hippius-mem-core/src/oplog/store.rs:645`), which this file cannot import
/// (each `tests/*.rs` file compiles as its own crate) and which has no
/// toggle: its fault is permanent for the wrapper's lifetime. This one needs
/// [`Self::disarm`] too, so the SAME reader can sync once broken and once
/// healed — the toggle is the one real difference from `GetFailBlob`'s
/// shape.
struct FailOneGet {
    inner: Arc<dyn BlobStore>,
    fail_key: String,
    armed: AtomicBool,
}

impl FailOneGet {
    /// Wrap `inner`, targeting `fail_key`. Inert until [`Self::arm`] arms it.
    fn new(inner: Arc<dyn BlobStore>, fail_key: String) -> Self {
        Self {
            inner,
            fail_key,
            armed: AtomicBool::new(false),
        }
    }

    /// Arm the fault: every `get(fail_key)` from here errors until
    /// [`Self::disarm`].
    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    /// Disarm the fault: `fail_key` is served from `inner` again.
    fn disarm(&self) {
        self.armed.store(false, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl BlobStore for FailOneGet {
    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
        self.inner.put(key, bytes).await
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
        if self.armed.load(Ordering::SeqCst) && key == self.fail_key {
            return Err(MemError::Storage(
                "simulated transient GET failure".to_owned(),
            ));
        }
        self.inner.get(key).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError> {
        self.inner.list(prefix).await
    }

    async fn delete(&self, key: &str) -> Result<(), MemError> {
        self.inner.delete(key).await
    }
}

/// A minority op-fetch outage must be TRANSIENT, not destructive.
///
/// # Which op is faulted, and why
///
/// The fixture writes 3 notes via `remember`, each a lone `Remember` op with
/// no edits — exactly 3 op objects under the op-log prefix, confirmed below by
/// asserting `op_keys.len() == 3`. Failing 1 of 3 is `failed_gets = 1`,
/// `fetched_ok = 2`; `read_verified`'s systemic-outage gate is
/// `failed_gets >= fetched_ok`, i.e. `1 >= 2`, false — genuinely below the
/// `>= 50%` threshold, so the reader tolerates it (skip-with-warn) rather than
/// erroring the whole read.
///
/// The faulted key is the HIGHEST-lamport op (the gamma note's; `list` is
/// lexicographically sorted over a zero-padded lamport, so `op_keys.last()`
/// is it). That is the ONLY one-op fault that prunes exactly one note.
/// `writer` and `reader` share one signing identity (`store_over`'s fixed
/// `RECOVERY_SEED`, deliberately — see that helper's doc), so all 3 ops are
/// ONE author's linear hash chain: alpha -> beta -> gamma. Faulting alpha (the
/// chain ROOT) or beta (mid-chain) does not merely drop that op — it orphans
/// every op after it too, because `quarantine_broken_chains` /
/// `longest_rooted_chain` (`oplog/store.rs`) cannot tell a transiently
/// unfetched predecessor from a genuinely broken chain and quarantines the
/// whole unrooted remainder (this is deliberate tamper-evidence for a REAL
/// break; it cannot distinguish that from a transient fetch gap on an early
/// op — see "Known blind spot" below). Verified empirically, not just
/// reasoned: pointing the fault at `op_keys[0]` (alpha) instead of
/// `op_keys.last()` collapses the degraded read to ZERO ops — both gamma AND
/// beta vanish from convergence alongside alpha, from a single failed GET.
/// Only the terminal op has no successor to orphan, so faulting it prunes
/// precisely the one note this test's name and assertions claim.
///
/// # How the healed sync actually recovers gamma (in this fixture)
///
/// This is NOT `sync_incremental`'s `omitted` set (`store/mod.rs:3303-3311`)
/// — the mechanism Task C3 exercises for an undecodable note blob — and it is
/// NOT ordinary tail convergence (`store/mod.rs:3315-3319`) either. Both were
/// the first two hypotheses tried here and both were falsified empirically
/// (see the commit message for the mutations): temporarily short-circuiting
/// `sync_incremental`'s `omitted`-decode line, and separately its tail-decode
/// line, each LEFT this test passing. What actually restores gamma HERE is
/// checkpoint content addressing: [`MemoryStore::sync`] keys a checkpoint
/// object by its own `last_lamport` (`{team}/_snapshots/{last_lamport:020}`,
/// `store/snapshot.rs`'s `snapshot_key`), so it is not one mutable "latest"
/// slot — every distinct Lamport tip gets its own object, and
/// `load_latest_snapshot` always reloads the highest-Lamport survivor. The
/// pre-fault sync above persists a checkpoint holding all 3 notes at
/// `last_lamport = 3`; in this fixture the degraded sync's own read sees a
/// LOWER tip (2, since gamma's op is the one that failed to fetch), so its
/// checkpoint write lands at a DIFFERENT, lower key and never overwrites the
/// good one. Once the fault clears, the next sync's freshly converged base
/// once again matches that surviving `last_lamport = 3` checkpoint exactly,
/// `snapshot_still_valid` passes, and `sync_incremental`'s
/// `collect_live_snapshot_records` restores all three notes — gamma included
/// — directly from that checkpoint's own cached, sealed bodies. Confirmed by
/// mutation: emptying that function's output breaks exactly the healing
/// assertion below.
///
/// That is the ROUTE this fixture takes, not the reason healing is
/// GUARANTEED, and the difference matters for what a future reader should
/// conclude from a green run. Checked directly, not assumed: mutating
/// `snapshot_key` to ignore `last_lamport` and always return one constant
/// slot (so the degraded checkpoint DOES overwrite the good one) still
/// leaves the whole suite passing, including this test. With a single slot
/// the degraded, lower-baseline checkpoint is what loads; the fault-cleared
/// read's extra ops then fall into the TAIL instead, and `decode_records`
/// rebuilds them from note blobs (`store/mod.rs:3315-3319`). So content
/// addressing is NOT load-bearing for durability — a change to it would
/// neither break healing nor fail this test. What actually guarantees the
/// outcome is that [`MemoryStore::sync`] is documented as **authoritative**:
/// "it prunes the index down to exactly the currently-live converged set...
/// so it works on a long-lived (warm) index, not only a cold rebuild"
/// (`store/mod.rs`, `sync`'s own doc). The index after any sync is a pure
/// function of THAT sync's read, and three interchangeable routes can supply
/// any given record — checkpoint restore (`collect_live_snapshot_records`),
/// the `omitted` backstop (`store/mod.rs:3303-3311`), or tail decode
/// (`store/mod.rs:3315-3319`). Which one fires depends on checkpoint layout,
/// not on any property this test pins.
///
/// The checkpoint-restore route (unmutated `snapshot_key`) is what actually
/// fired at every fault position tried in this task — the terminal-op fault
/// used here and, checked separately, the whole-chain-collapsing root-op
/// fault — because in this 3-op, single-author fixture every single-op fault
/// tried yielded a strictly lower degraded tip than the already-checkpointed
/// 3. Every one healed completely on the next clean sync. Nothing is ever
/// removed from the bucket by a degraded read, and a degraded reader's own
/// checkpoint write cannot affect any OTHER machine's index — this caps the
/// failure at an availability blip local to the reader that hit the fault,
/// not data loss.
///
/// The checkpoint-restore route is further bounded by retention
/// (`SNAPSHOT_RETENTION = 3` in `store/snapshot.rs`, pruned by
/// `prune_old_snapshots` after every save): enough distinct degraded Lamport
/// values written before the fault clears could eventually prune the
/// surviving good checkpoint away. Not exercised here — this fixture never
/// writes more than 2 checkpoint objects total, well under the retention
/// floor — but per the authoritative-rebuild guarantee above, the other two
/// routes remain available even then; only the SPECIFIC route this fixture
/// happens to exercise is retention-bounded, not the guarantee itself.
///
/// # Known blind spot this test surfaces but does not cover
///
/// A transient GET failure on a NON-terminal op of a multi-note author chain
/// has a materially larger blast radius than "one flaky GET drops one note":
/// it silently withholds every LATER note that author ever wrote from that
/// one read's convergence, indistinguishable (by design — see the module
/// header's tamper-evidence discussion) from a genuine chain break. This is
/// NOT wholly uncovered: `mid_chain_gap_keeps_the_prefix_not_the_whole_author`
/// (`oplog/store.rs:1010`) and the proptest
/// `longest_rooted_chain_keeps_the_pre_gap_prefix` (`oplog/store.rs:1046`)
/// both already assert this shape at the op-log layer — the first models a
/// never-listed object rather than a failed GET, but from `read_verified`'s
/// perspective those are identical (the op is simply absent from the fetched
/// set either way). What is genuinely uncovered is narrower: (a) the
/// CHAIN-ROOT gap specifically — that proptest draws `remove in 1_usize..8`,
/// so `k = 0` (the root itself) is never generated, and root-loss is the one
/// case that keeps NOTHING rather than a prefix (verified empirically in
/// this task: faulting the root collapsed the read to zero ops for that
/// author, not a partial prefix); and (b) the store-level consequence —
/// nothing in the crate asserts what `MemoryStore::sync`'s `retain` does to
/// a warm INDEX when the read comes back cascaded, since the two op-log-layer
/// tests above check only `read_all`'s output, never a `MemoryStore`. This
/// test deliberately avoids the cascade shape entirely (see "Which op is
/// faulted" above) so its own assertions stay scoped to a single pruned
/// note; neither gap above is addressed here.
///
/// # What this test cannot show
///
/// It says nothing about a fetch fault landing on more than one op, a fault
/// spanning enough degraded syncs to exhaust checkpoint retention (see
/// above), the `>= 50%` error path itself (already covered by three existing
/// tests in `oplog/store.rs`), the chain-root gap or the store-level cascade
/// consequence named above, or a multi-author bucket where the faulted
/// author's chain break cannot be masked by another author's untouched,
/// still-maximal checkpoint entry.
#[tokio::test]
async fn a_transient_minority_op_fetch_failure_heals_on_the_next_sync()
-> Result<(), Box<dyn std::error::Error>> {
    let bucket = Arc::new(MemoryBlobStore::default());
    let writer = store_over(bucket.clone())?;

    let a = writer.remember(input("alpha note", "alpha body")).await?;
    let b = writer.remember(input("beta note", "beta body")).await?;
    let c = writer.remember(input("gamma note", "gamma body")).await?;

    let op_keys = bucket.list(&oplog_object_prefix(RECOVERY_TEAM)).await?;
    assert_eq!(
        op_keys.len(),
        3,
        "one op object per remembered note, no edits in this fixture"
    );
    let fail_key = op_keys
        .last()
        .cloned()
        .ok_or("expected at least one op-log object key")?;

    // A reader with a warm index holding all three, built over a bucket that
    // can selectively fail exactly one op's GET.
    let reader_bucket = Arc::new(FailOneGet::new(bucket.clone(), fail_key));
    let reader = store_over(reader_bucket.clone())?;
    reader.sync().await?;
    assert_eq!(
        reader.list_records()?.len(),
        3,
        "the warm index must hold all three before any fault"
    );

    // Fail gamma's op GET: a strict minority, so `read_verified` tolerates
    // it — but see the doc above for why this still prunes the index via
    // `replay_full`'s fallback.
    reader_bucket.arm();
    reader.sync().await?;

    // The degraded state must be asserted explicitly, not skipped past: this
    // is the finding the test exists to pin. If a future change stops the
    // fault from pruning anything, this assertion — not the healing one
    // below — is what catches it.
    let degraded: BTreeSet<NoteId> = reader
        .list_records()?
        .into_iter()
        .map(|record| record.note_id)
        .collect();
    assert_eq!(
        degraded,
        BTreeSet::from([a, b]),
        "the faulted sync must prune exactly gamma, the one note whose op failed to fetch"
    );

    // Clear the fault and sync again: the full set must return.
    reader_bucket.disarm();
    reader.sync().await?;

    let healed: BTreeSet<NoteId> = reader
        .list_records()?
        .into_iter()
        .map(|record| record.note_id)
        .collect();
    assert_eq!(
        healed,
        BTreeSet::from([a, b, c]),
        "a transient minority op-fetch failure must not permanently drop a note"
    );
    Ok(())
}

/// A GET failure on an author's chain-ROOT op — not just a minority op below
/// the systemic-outage threshold — empties that machine's warm index
/// entirely, and `sync` reports it as `Ok(0)`, not an error.
///
/// # Why the root specifically
///
/// `writer` and `reader` share one signing identity (`store_over`'s fixed
/// `RECOVERY_SEED`), so — exactly as in
/// `a_transient_minority_op_fetch_failure_heals_on_the_next_sync` above — all
/// 3 remembered notes are ONE author's linear hash chain: alpha (root) ->
/// beta -> gamma. That test deliberately faults the TERMINAL op (gamma)
/// because it has no successor to orphan, pruning exactly one note. This
/// test deliberately faults the OPPOSITE end — `op_keys[0]` (alpha, the
/// chain ROOT; `list` sorts lexicographically by zero-padded lamport, so
/// index 0 is the lowest-lamport op) — because `quarantine_broken_chains` /
/// `longest_rooted_chain` (`oplog/store.rs`) cannot distinguish "predecessor
/// transiently unfetched" from "chain genuinely broken": with the root gone,
/// NEITHER beta NOR gamma has a path back to `GENESIS_PREV` within the
/// fetched set, so `longest_rooted_chain` quarantines all three, not just
/// alpha. This is the same collapse the sibling test's own doc already notes
/// as verified for this exact fixture (faulting `op_keys[0]` there collapsed
/// the degraded read to zero ops). `read_verified`'s systemic-outage gate
/// stays silent (`failed_gets = 1 < fetched_ok = 2`, genuinely below the
/// `>= 50%` threshold — same arithmetic as the sibling test), so the caller
/// gets no error, only an empty converged set for this author. Since this
/// fixture has exactly one author, that empties the index for the whole
/// machine.
///
/// # Severity: TRANSIENT, not data loss
///
/// Nothing is removed from the bucket by the faulted read; every op object
/// alpha/beta/gamma still physically exists there, untouched. No OTHER
/// machine's index is affected — this reader's own degraded checkpoint
/// write cannot corrupt anyone else's state either (see the sibling test's
/// doc for why a lower-tip checkpoint never overwrites a good one — the same
/// mechanism applies here, with the degraded tip at 0 rather than 2). Any
/// clean read — the very next sync once the fault clears — rebuilds the
/// index in full from the unmodified op-log, as asserted below. This is an
/// availability blip local to the one reader that hit the fault, not a
/// correctness or durability bug.
///
/// # What this test cannot show
///
/// It does not show recovery is bounded by checkpoint retention
/// (`SNAPSHOT_RETENTION`, see the sibling test's doc), a fault spanning
/// multiple authors, a fault landing on a NON-root op of a longer chain
/// (that blast radius is the sibling test's subject), or anything about
/// `read_verified`'s `>= 50%` systemic-outage gate itself (covered by three
/// existing tests in `oplog/store.rs`). It documents a real availability
/// weakness in the current outage guard (it measures failed GETs, not
/// post-quarantine op loss) without changing the guard — a production
/// change to that guard is separate, already-authorised work.
#[tokio::test]
async fn a_root_op_fetch_failure_empties_the_warm_index_and_heals_on_the_next_sync()
-> Result<(), Box<dyn std::error::Error>> {
    let bucket = Arc::new(MemoryBlobStore::default());
    let writer = store_over(bucket.clone())?;

    let a = writer.remember(input("alpha note", "alpha body")).await?;
    let b = writer.remember(input("beta note", "beta body")).await?;
    let c = writer.remember(input("gamma note", "gamma body")).await?;

    let op_keys = bucket.list(&oplog_object_prefix(RECOVERY_TEAM)).await?;
    assert_eq!(
        op_keys.len(),
        3,
        "one op object per remembered note, no edits in this fixture"
    );
    let fail_key = op_keys
        .first()
        .cloned()
        .ok_or("expected at least one op-log object key")?;

    // A reader with a warm index holding all three, built over a bucket that
    // can selectively fail exactly one op's GET.
    let reader_bucket = Arc::new(FailOneGet::new(bucket.clone(), fail_key));
    let reader = store_over(reader_bucket.clone())?;
    reader.sync().await?;
    assert_eq!(
        reader.list_records()?.len(),
        3,
        "the warm index must hold all three before any fault"
    );

    // Fail alpha's (the root's) op GET. Still a strict minority
    // (`failed_gets = 1 < fetched_ok = 2`), so `read_verified` tolerates it —
    // but the chain-quarantine cascade this test exists to pin means the
    // degraded read converges to nothing for this author.
    reader_bucket.arm();
    let degraded_count = reader.sync().await?;

    // The degraded state must be asserted explicitly, not skipped past: this
    // is the finding the test exists to pin.
    assert_eq!(
        degraded_count, 0,
        "sync must report zero indexed notes, not an error, when the root op cannot be fetched"
    );
    assert!(
        reader.list_records()?.is_empty(),
        "a root-op fetch failure must empty the warm index, not merely shrink it"
    );

    // Clear the fault and sync again: full recovery, not a permanent loss.
    reader_bucket.disarm();
    reader.sync().await?;

    let healed: BTreeSet<NoteId> = reader
        .list_records()?
        .into_iter()
        .map(|record| record.note_id)
        .collect();
    assert_eq!(
        healed,
        BTreeSet::from([a, b, c]),
        "a transient root-op fetch failure must not permanently drop any note"
    );
    Ok(())
}
