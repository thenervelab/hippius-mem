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

use std::sync::Arc;

use hippius_mem_core::{
    Blake3Hash, BlobStore, ConvergedState, GENESIS_PREV, MemError, MemoryBlobStore, NetworkPrefix,
    NoteId, Op, OpContent, OpKind, OpLogStore, Sr25519Signer, content_hash, converge,
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
