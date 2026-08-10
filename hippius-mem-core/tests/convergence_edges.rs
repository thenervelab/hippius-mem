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
    OpKind, OpLogStore, RememberInput, RepoScope, SecretKey, Signer, Sr25519Signer, Ss58,
    Timestamp, TypedLink, content_hash, converge,
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

// # `VerifiedOps` iteration order (task X2)
//
// The proptest above composes `read_all` with `converge` and asserts on the
// CONVERGED state, and its own doc is explicit that this cannot show the total
// sort at the end of `read_verified` (`ops.sort_by_cached_key`,
// `hippius-mem-core/src/oplog/store.rs`) is load-bearing: `converge` reduces
// each note by max/union/OR, all order-insensitive, so it produces the same
// `ConvergedState` whether or not the ops it folds arrived sorted. Checked
// directly, not assumed: deleting that `sort_by_cached_key` call leaves EVERY
// target in the workspace green, including every test in this file — nothing
// anywhere inspects `VerifiedOps`'s own iteration order, only what `converge`
// does with it.
//
// `read_all`'s doc (`oplog/store.rs`) says plainly what the sort is for: ops
// are "returned in global logical order: ascending `(lamport, op_id)`" (the
// code's actual key extends that with `author_key` and `Op::hash` — see
// [`unambiguously_ordered_bucket`]'s doc for why this file does not need to
// exercise those two extra components to close the gap the two tests below
// target). A caller that walks `VerifiedOps` positionally rather than folding
// it through `converge` — `history` is the one named in `read_verified`'s own
// comment — depends on that order agreeing across machines regardless of
// fetch/listing order. The two tests below inspect `VerifiedOps` itself
// (`Deref<Target = [Op]>` is its only public read access, so this is the same
// access any real caller has, not a test-only backdoor into a private field)
// against a [`rotate_listing`]-scrambled backend, closing the gap the proptest
// above explicitly leaves open.

/// Build a 3-author, 9-op bucket via the real `OpLogStore::append` path where
/// every op's `lamport` is GLOBALLY distinct — not just distinct within one
/// author's own chain — and strictly ascending in append order: op 0 gets
/// `lamport = 0`, op 1 gets `lamport = 1`, and so on through `lamport = 8`.
///
/// This is what makes the fixture's logical order unambiguous, matching the
/// task's own framing: `read_verified`'s documented sort key is `(lamport,
/// op_id, author_key, hash)`, but with `lamport` alone already a bijection onto
/// the op set, the FIRST component alone fixes the whole order. Deliberately
/// NOT exercised here: whether the `op_id` / `author_key` / `hash` tiebreakers
/// are themselves compared correctly on a genuine `lamport` tie — that
/// question needs a tie to exist at all, which this fixture avoids by
/// construction so [`verified_ops_iterate_in_the_documented_total_order_regardless_of_listing_order`]
/// stays simple to state and its expectation trivial to compute independently
/// (ascending `lamport` IS the answer, with no need to reproduce `Ulid`'s or
/// `VerifyingKey`'s `Ord` impls in test code to predict it).
/// [`a_cross_author_lamport_tie_is_broken_by_op_id_not_by_listing_order`]
/// below is what covers that instead, with a fixture built the opposite way.
///
/// No fork: each of the 3 authors contributes one straight 3-op
/// `prev_op_hash` chain (round-robin: author 0's op, then author 1's, then
/// author 2's, three times), so `longest_rooted_chain` keeps every op
/// untouched and cannot itself perturb the order under test — that seam is
/// what the proptest above already targets, with a different fixture built
/// for it.
///
/// Returns the bucket and the expected `lamport` sequence (`0..9`) built from
/// the SAME loop that appends the ops, so the property tests' expectation can
/// never drift from what the fixture actually wrote.
async fn unambiguously_ordered_bucket() -> Result<(Arc<MemoryBlobStore>, Vec<u64>), MemError> {
    let bucket = Arc::new(MemoryBlobStore::new());
    let store = OpLogStore::new(bucket.clone());

    let authors = [signer(101)?, signer(102)?, signer(103)?];
    let mut prevs = [GENESIS_PREV; 3];
    let mut expected = Vec::with_capacity(9);
    let mut lamport = 0_u64;
    let mut seq = 5_000_u128;

    for _round in 0..3 {
        for (author_idx, author) in authors.iter().enumerate() {
            let op = signed_op(
                author,
                prevs[author_idx],
                lamport,
                seq,
                seq,
                OpKind::Remember,
            );
            store.append(TEAM, &op).await?;
            prevs[author_idx] = op.hash();
            expected.push(lamport);
            lamport += 1;
            seq += 1;
        }
    }

    Ok((bucket, expected))
}

/// Seed [`unambiguously_ordered_bucket`] once, then read it back through
/// `OpLogStore::read_all` under a listing rotated by `rotation`, returning
/// `(observed, expected)`: the `lamport` of every op in the exact order
/// `VerifiedOps` iterates them, and the order the fixture intends.
///
/// Synchronous so the proptest body below can call it directly and propagate a
/// plain `Result` with `?`, matching [`run_pipeline_at_rotation`]'s established
/// pattern above (same reasoning: `MemoryBlobStore` needs no I/O driver, so a
/// bare current-thread runtime is enough).
fn verified_lamport_order_at_rotation(rotation: usize) -> Result<(Vec<u64>, Vec<u64>), MemError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(MemError::from)?;

    runtime.block_on(async move {
        let (bucket, expected) = unambiguously_ordered_bucket().await?;
        let blob: Arc<dyn BlobStore> = bucket;
        let verified = OpLogStore::new(rotate_listing(blob, rotation))
            .read_all(TEAM)
            .await?;
        let observed: Vec<u64> = verified.iter().map(|op| op.lamport).collect();
        Ok((observed, expected))
    })
}

proptest! {
    // Same tracked-regression convention as the proptest above, and the same
    // file: a second `proptest!` invocation in one source file still shares
    // one regression file under this crate's one-file-per-source-file scheme
    // (see `hippius-mem-core/proptest-regressions/oplog/converge.txt`, which
    // already accumulates cases from more than one proptest in that file).
    #![proptest_config(ProptestConfig::with_failure_persistence(
        FileFailurePersistence::Direct("proptest-regressions/tests/convergence_edges.txt"),
    ))]

    /// `OpLogStore::read_all`'s returned `VerifiedOps` must ITERATE in the
    /// documented global logical order — not merely converge to the same
    /// state — no matter what order the backend lists the same op objects in.
    ///
    /// This is the property the proptest above's own doc says it cannot show:
    /// that one only ever inspects `VerifiedOps` through `converge`, which is
    /// order-insensitive by construction and so cannot tell a sorted
    /// `VerifiedOps` from an unsorted one. This test reads `VerifiedOps`
    /// itself.
    ///
    /// # Why this matters beyond the proptest above
    ///
    /// `MemoryStore::history` (`hippius-mem-core/src/store/mod.rs`) is a real,
    /// shipping consumer that depends on exactly this: its own comment says
    /// `read_all` already returns global ascending `(lamport, op_id)` order, so
    /// filtering down to one note's ops "preserves relative order" and needs no
    /// re-sort. If `read_verified`'s sort were ever silently dropped or
    /// weakened, `history` would not error — it would just return a note's ops
    /// out of order on whatever machine happened to fetch them out of order,
    /// with nothing downstream to notice.
    ///
    /// Confirmed by mutation, not assumed: deleting the `ops.sort_by_cached_key`
    /// call at the end of `read_verified` (`hippius-mem-core/src/oplog/store.rs`)
    /// makes this test fail — see the commit message for the exact rotations and
    /// observed-vs-expected sequences.
    ///
    /// # What this test does NOT show
    ///
    /// - The op_id / author_key / hash tiebreak components of the sort key: see
    ///   [`unambiguously_ordered_bucket`]'s doc for why this fixture avoids a
    ///   `lamport` tie on purpose, and
    ///   [`a_cross_author_lamport_tie_is_broken_by_op_id_not_by_listing_order`]
    ///   below for the test that covers it instead.
    /// - Anything about a listing large enough to need more than one
    ///   `buffer_unordered` batch: 9 op objects stays under
    ///   `OPLOG_FETCH_CONCURRENCY`'s bound of 64
    ///   (`hippius-mem-core/src/oplog/store.rs:57`), the same blind spot the
    ///   proptest above already documents for its own fixture.
    /// - Fork resolution: this fixture is fork-free by construction (see
    ///   [`unambiguously_ordered_bucket`]'s doc); the proptest above is what
    ///   targets `longest_rooted_chain`'s own tiebreak.
    /// - Arbitrary op sets: this is one fixed, hand-built 9-op set rotated in
    ///   every possible way, not a fuzzed graph — the same scope limitation the
    ///   module doc already states for the proptest above.
    #[test]
    fn verified_ops_iterate_in_the_documented_total_order_regardless_of_listing_order(
        rotation in 0_usize..9,
    ) {
        let (observed, expected) = verified_lamport_order_at_rotation(rotation)
            .map_err(|e| TestCaseError::fail(e.to_string()))?;

        prop_assert_eq!(
            observed,
            expected,
            "VerifiedOps must iterate in ascending lamport order at rotation {}: every op in \
             this fixture has a globally distinct lamport, so ascending lamport IS the \
             documented (lamport, op_id, author_key, hash) total order for this set, \
             regardless of what order the backend listed the same op objects in",
            rotation
        );
    }
}

/// A genuine cross-author LAMPORT TIE, exercised directly: two different
/// authors' single-op chains at the SAME `lamport`, distinguishable only by the
/// sort key's second component, `op_id`.
///
/// # Why this test exists alongside the property test above
///
/// Every `lamport` in [`unambiguously_ordered_bucket`] is globally unique by
/// construction (see that function's doc), which is what keeps
/// `verified_ops_iterate_in_the_documented_total_order_regardless_of_listing_order`
/// simple to state — but it also means a mutation that weakened
/// `read_verified`'s sort key from the documented 4-tuple down to `lamport`
/// alone would leave that test passing: sorting by `lamport` alone already
/// produces the correct order on a fixture with no `lamport` ties.
/// `sort_by_cached_key` is a STABLE sort, so on an actual tie a lamport-only
/// key would silently fall back to the input vector's arrival order — which
/// [`rotate_listing`] controls — rather than erroring or visibly misbehaving.
/// This test builds the tie that property test structurally cannot: `op_lo`
/// and `op_hi` share `lamport = 0`, `op_lo`'s `op_id` is numerically lower, and
/// the fixture is read once with the listing already in ascending order and
/// once reversed, so a result that tracked LISTING order instead of `op_id`
/// would show up as instability between the two runs.
///
/// `op_id` is `Ulid::from(seq)` (see [`signed_op`]), and `Ulid`'s `Ord` is a
/// direct wrap of the `u128` it is built from (the `ulid` crate defines
/// `pub struct Ulid(pub u128)` with a derived `Ord`), so `2_000 < 3_000` below
/// is what fixes `op_lo.op_id < op_hi.op_id`, not an assumption about the
/// crate's internals.
///
/// # What this test does NOT show
///
/// The `author_key` and content-hash tiebreaks (the sort key's third and
/// fourth components) are still untested by this file: they only matter when
/// BOTH `lamport` and `op_id` tie, which needs either two authors racing the
/// same `op_id` value (a coincidence honest clients do not produce) or a
/// Byzantine author replaying its own `(lamport, op_id)` on two differently
/// signed ops (the scenario `read_verified`'s own comment names for the
/// content-hash tiebreak specifically). Neither is built here.
#[tokio::test]
async fn a_cross_author_lamport_tie_is_broken_by_op_id_not_by_listing_order()
-> Result<(), Box<dyn std::error::Error>> {
    let bucket = Arc::new(MemoryBlobStore::new());
    let store = OpLogStore::new(bucket.clone());

    let author_lo = signer(111)?;
    let author_hi = signer(112)?;

    let op_lo = signed_op(&author_lo, GENESIS_PREV, 0, 2_000, 2_000, OpKind::Remember);
    let op_hi = signed_op(&author_hi, GENESIS_PREV, 0, 3_000, 3_000, OpKind::Remember);
    store.append(TEAM, &op_lo).await?;
    store.append(TEAM, &op_hi).await?;

    let blob: Arc<dyn BlobStore> = bucket;
    for rotation in [0_usize, 1] {
        let verified = OpLogStore::new(rotate_listing(blob.clone(), rotation))
            .read_all(TEAM)
            .await?;
        let observed: Vec<Ulid> = verified.iter().map(|op| op.op_id).collect();
        assert_eq!(
            observed,
            vec![op_lo.op_id, op_hi.op_id],
            "a cross-author lamport tie must resolve by ascending op_id at rotation \
             {rotation}, not by listing/fetch order"
        );
    }

    Ok(())
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
/// decorator in between — signing as the identity [`signer`] derives from
/// `seed`, and sealing under the fixed recovery team key at epoch 0.
///
/// A bare `blob` (rather than a caching wrapper) matters here specifically:
/// the missing-blob test below deletes an object straight from `blob` and
/// asserts it can no longer be served, which a warm cache layer could
/// satisfy for the wrong reason (serving the deleted object from its own
/// copy). There is no cache anywhere in this construction to do that.
///
/// Mirrors `hippius-mem-core/src/store/mod.rs`'s private `store_over` test
/// helper and `tests/e2e_durability.rs`'s `seed_machine`; neither is
/// reachable from this file (each `tests/*.rs` file compiles as its own
/// crate), so this is a third, minimal copy scoped to exactly what the tests
/// below need. `seed` is a parameter (task C5) rather than always
/// [`RECOVERY_SEED`], so two DISTINCT machines over one shared bucket can be
/// built for the same team — every other missing-blob/outage test in this
/// section still wants ONE fixed identity shared by every store it builds
/// (modelling a single machine re-syncing after a restart, not a second
/// author joining — see [`RECOVERY_SEED`]'s doc), which [`store_over`]
/// below preserves unchanged for their call sites.
fn store_over_as(blob: Arc<dyn BlobStore>, seed: u8) -> Result<MemoryStore, MemError> {
    let signing_key: Arc<dyn Signer> = Arc::new(signer(seed)?);
    let index = Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default())));
    let oplog = OpLogStore::new(blob.clone());

    Ok(MemoryStore::new(
        blob,
        index,
        oplog,
        Arc::new(NoopAnchor),
        signing_key,
        BTreeMap::from([(0, SecretKey::from_bytes(RECOVERY_TEAM_KEY))]),
        0,
        RECOVERY_TEAM.to_owned(),
        usize::MAX,
    ))
}

/// [`store_over_as`] pinned to the fixed recovery identity every
/// missing-blob/outage test below this point was originally written against.
/// `RECOVERY_SEED` is `[9_u8; 32]`, a uniform array, so its first byte fed
/// back through [`signer`] reproduces the exact same 32-byte seed [`signer`]
/// would build from `9` directly — this is the pre-C5 behaviour, byte-for-
/// byte, so every existing call site keeps working unchanged.
fn store_over(blob: Arc<dyn BlobStore>) -> Result<MemoryStore, MemError> {
    store_over_as(blob, RECOVERY_SEED[0])
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
/// `lost >= reached`, where `lost` is the failed GETs PLUS the ops orphaned by
/// them and `reached` is what survived to the verified log. The faulted op
/// here is terminal, so it orphans nothing: `lost = 1`, `reached = 2`, i.e.
/// `1 >= 2`, false — genuinely below the `>= 50%` threshold, so the reader
/// tolerates it (skip-with-warn) rather than erroring the whole read. Faulting
/// a NON-terminal op of this same fixture is what makes the orphan term
/// non-zero and trips the gate; see
/// `a_root_op_fetch_failure_errors_the_sync_and_leaves_the_warm_index_intact`
/// below.
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
/// fires for the terminal-op fault used here, because in this 3-op,
/// single-author fixture that fault yields a strictly lower degraded tip than
/// the already-checkpointed 3. (It fired for the whole-chain-collapsing
/// root-op fault too when that was checked, but that observation predates the
/// systemic-outage guard's redesign: a cascading fault now ERRORS the read, so
/// its sync never reaches a checkpoint write at all — see
/// `a_root_op_fetch_failure_errors_the_sync_and_leaves_the_warm_index_intact`
/// below.) It healed completely on the next clean sync. Nothing is ever
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
/// # Blind spot this test surfaces, closed by sibling tests, not by this one
///
/// A transient GET failure on a NON-terminal op of a multi-note author chain
/// has a materially larger blast radius than "one flaky GET drops one note":
/// it silently withholds every LATER note that author ever wrote from that
/// one read's convergence, indistinguishable (by design — see the module
/// header's tamper-evidence discussion) from a genuine chain break. This is
/// NOT wholly uncovered: `mid_chain_gap_keeps_the_prefix_not_the_whole_author`
/// (`oplog/store.rs:1010`) and the proptest
/// `longest_rooted_chain_keeps_the_pre_gap_prefix` both already assert this
/// shape at the op-log layer — the first models a never-listed object rather
/// than a failed GET, but from `read_verified`'s perspective those are
/// identical (the op is simply absent from the fetched set either way). Two
/// narrower gaps outside this test's own scope are now closed elsewhere:
/// (a) the CHAIN-ROOT gap specifically —
/// `longest_rooted_chain_keeps_the_pre_gap_prefix` now draws `remove` from
/// `0_usize..8`, so `k = 0` (the root itself) is generated, and asserts
/// root-loss keeps NOTHING rather than a prefix (matching what this test's
/// own doc verified empirically: faulting the root collapsed the read to
/// zero ops for that author, not a partial prefix); and (b) the store-level
/// consequence —
/// `a_root_op_fetch_failure_errors_the_sync_and_leaves_the_warm_index_intact`
/// (below, in this file) asserts what `MemoryStore::sync` now does with a
/// cascaded read. This test deliberately
/// avoids the cascade shape entirely (see "Which op is faulted" above) so
/// its own assertions stay scoped to a single pruned note; it does not
/// exercise either gap itself, but both are covered by the tests named
/// above.
///
/// # What this test cannot show
///
/// It says nothing about a fetch fault landing on more than one op, a fault
/// spanning enough degraded syncs to exhaust checkpoint retention (see
/// above), or the `>= 50%` error path itself (already covered by three
/// existing tests in `oplog/store.rs`). The chain-root gap and the
/// store-level cascade consequence named above are NOT among this test's
/// blind spots — see the tests named there — but this test itself still
/// says nothing about a multi-author bucket where the faulted author's
/// chain break cannot be masked by another author's untouched,
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

/// A GET failure on an author's chain-ROOT op ERRORS the sync, leaving that
/// machine's warm index untouched — it no longer empties the index and reports
/// the result as `Ok(0)`.
///
/// # This test's assertions were deliberately inverted (task X3)
///
/// It was written to pin the OPPOSITE outcome: `sync` returning `Ok(0)` and
/// the warm index going empty, recorded then as a real weakness in
/// `read_verified`'s systemic-outage guard — it counted failed GETs, not the
/// ops lost because of them, so the cascade below (one failed GET, three ops
/// lost) scored as a tolerable 33% minority and returned `Ok(empty)`. That
/// guard now measures post-quarantine loss attributable to the fetch fault, so
/// this fixture builds exactly the case it exists to catch, and the assertions
/// here are inverted to match. What remained true is kept: the condition is
/// TRANSIENT — nothing is removed from the bucket, and the next clean sync
/// converges the full set.
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
/// the degraded read to zero ops).
///
/// Those two orphans are what the redesigned gate counts: `failed_gets = 1`
/// plus 2 ops orphaned by it is `lost = 3` against `reached = 0`, so the read
/// errors. The orphan term is charged to this author only because the failed
/// object's own key names them (`object_key`'s trailing author hex) — a chain
/// break with no failed GET behind it stays a quiet quarantine, which is the
/// separation `a_chain_break_with_no_failed_get_degrades_quietly_even_when_every_op_is_lost`
/// (`oplog/store.rs`) pins.
///
/// # Severity: TRANSIENT, not data loss
///
/// Nothing is removed from the bucket by the faulted read; every op object
/// alpha/beta/gamma still physically exists there, untouched. The erroring
/// sync also writes no checkpoint and touches no index — it fails inside
/// `read_and_filter`, before `sync` reaches either — so no OTHER machine's
/// state can be affected and this reader's own index keeps serving recall
/// while the fault lasts. Any clean read — the very next sync once the fault
/// clears — converges the full set from the unmodified op-log, as asserted
/// below.
///
/// # What this test cannot show
///
/// The healing assertion below is weaker than it was before the guard change:
/// with the index now left intact through the fault, it shows the sync
/// RECOVERS (no sticky error state), not that a pruned index is rebuilt from
/// the op-log — `a_transient_minority_op_fetch_failure_heals_on_the_next_sync`
/// above is what still covers rebuild-after-prune. This test also says nothing
/// about a fault spanning multiple authors (where the faulted author's loss
/// may stay below the gate's half threshold and degrade quietly instead), a
/// fault landing on a NON-root op of a longer chain (the sibling test's
/// subject), or the gate's arithmetic itself (covered by the threshold tests
/// in `oplog/store.rs`).
#[tokio::test]
async fn a_root_op_fetch_failure_errors_the_sync_and_leaves_the_warm_index_intact()
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

    // Fail alpha's (the root's) op GET. One failed GET of three, but it orphans
    // beta and gamma, so the fetch fault costs the whole log.
    reader_bucket.arm();
    let outcome = reader.sync().await;

    // Assert WHICH error, not merely that one happened: a bare `is_err()` would
    // be satisfied by any unrelated storage fault, and the systemic-outage gate
    // is the whole subject of this test.
    let Err(MemError::Storage(message)) = &outcome else {
        return Err(format!(
            "a root-op fetch failure must fail the sync through the systemic-outage \
             guard, got {outcome:?}"
        )
        .into());
    };
    assert!(
        message.contains("a fetch fault cost"),
        "the error must be the systemic-outage guard's, got: {message}"
    );

    // The index must be UNTOUCHED — the point of erroring is that the caller
    // keeps serving what it already has instead of pruning against a view of
    // the log it never saw.
    let during_fault: BTreeSet<NoteId> = reader
        .list_records()?
        .into_iter()
        .map(|record| record.note_id)
        .collect();
    assert_eq!(
        during_fault,
        BTreeSet::from([a, b, c]),
        "the failed sync must leave the warm index intact, pruning nothing"
    );

    // Clear the fault and sync again: the error is transient, not sticky.
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

// # Cross-machine quarantine divergence and healing (task C5)
//
// The two tests above each fault ONE author's op-log against a SINGLE
// machine's warm/cold index and ask what that machine's own state looks like
// during and after the fault. Neither compares against a second, healthy
// machine reading the SAME shared bucket — so nothing in this file yet shows
// that a quarantining machine's divergence is bounded (holds a subset of a
// healthy peer's state, never more) or that it heals to IDENTICAL state, not
// merely an overlapping one, once the fault clears. This section closes that
// gap.
//
// ## Guard arithmetic this fixture depends on
//
// `a_root_op_fetch_failure_errors_the_sync_and_leaves_the_warm_index_intact`
// above faults a single author's chain ROOT and shows the redesigned
// systemic-outage guard (`lost = failed_gets + fetch_collateral`,
// `reached = fetched_ok - fetch_collateral`, fires on
// `lost > 0 && lost >= reached`) now ERRORS that read instead of quarantining
// it quietly — because with only ONE author in the bucket, a mid-chain
// fault's collateral is large relative to what else there is to fetch. A
// naive single-author version of the quarantine-divergence test below (one
// author, 4 ops, one mid-chain GET failure) hits the exact same wall: faulting
// the second of 4 ops orphans the third and fourth (`collateral = 2`) against
// `failed_gets = 1`, `fetched_ok = 3`, giving `lost = 3`, `reached = 1` —
// `3 >= 1` fires the guard, so `sync` would ERROR rather than quarantine, and
// the scenario this test exists to cover (a machine that quarantines and ends
// up holding strictly less than a healthy peer) would never be reached.
//
// This fixture avoids that by adding a SECOND author (`healthy`) whose 4 ops
// always fetch cleanly and are never touched by any fault, which inflates
// `fetched_ok` (and so `reached`) without adding to `failed_gets` or
// `collateral`. With author A's 4 ops (one fault, mid-chain, collateral = 2)
// plus the healthy author's 4 clean ops:
//   `failed_gets = 1`, `collateral = 2`, `lost = 1 + 2 = 3`
//   `fetched_ok = 3 (author A) + 4 (healthy) = 7`, `reached = 7 - 2 = 5`
//   guard condition: `lost > 0 && lost >= reached` -> `3 > 0 && 3 >= 5` -> false
// The guard stays SILENT (`3 < 5`), so `sync` returns `Ok` with author A's
// tail quarantined rather than erroring the whole read — the precondition
// this test's two assertions need to both be reachable. This also fits the
// task's own premise better than a single-author fixture would: the interesting
// case is a PARTIAL divergence between two machines over a shared team, not a
// total read failure.
//
// A second author is required for this, not merely convenient: any fixture
// that keeps the guard silent while a genuine mid-chain quarantine occurs
// needs `reached > lost`, and with only one author every additional op past
// the fault position adds to `collateral` at least as fast as it adds to
// `fetched_ok` (an op past the gap is fetched fine but then orphaned), so
// `reached` cannot outgrow `lost` by lengthening a single author's chain
// alone — confirmed by the single-author arithmetic above, which fires the
// guard regardless of exactly where in the chain (short of the terminal op,
// already covered by the sibling test above) the fault lands.

/// Author identity for the healthy second author whose ops never fault.
/// Distinct from every other seed already used in this file so the two
/// authors below can never accidentally collide on `signer`'s output.
const HEALTHY_AUTHOR_SEED: u8 = 77;

/// Author identity for the quarantining reader machine (`b` below). Never
/// used to sign anything (`b` only ever syncs, it never `remember`s), so this
/// need not be distinct for correctness — it is, purely so the fixture reads
/// as "two distinct machines" rather than "one identity wearing two hats".
const READER_SEED: u8 = 88;

/// One note's index-side converged state, exactly [`stress_convergence.rs`]'s
/// `index_view` (`hippius-mem-core/tests/stress_convergence.rs`) — same
/// fields, same reasoning for each one (see that file's doc comment on the
/// function, not repeated here). Duplicated rather than shared: there is no
/// `hippius-mem-core/tests/shared/mod.rs` in this crate today, and
/// `stress_convergence.rs` is a settled, previously-reviewed file this task
/// does not touch. The function is a ~15-line, side-effect-free read over
/// `MemoryStore`'s own public `list_records`/`IndexRecord` API — no private
/// access, nothing `stress_convergence.rs`-specific — so a copy here carries
/// no risk of drifting the ORIGINAL out of the shape its own review settled
/// on, at the cost of two functions to keep in sync if that shape ever
/// changes. Given the alternative (an `include!`-based shared module) would
/// touch `stress_convergence.rs`'s directory structure for a helper this
/// small, duplication is the smaller change.
type CrossMachineIndexEntry = (
    NoteId,
    u64,
    Vec<TypedLink>,
    BTreeSet<Ss58>,
    Option<Timestamp>,
);

/// See [`CrossMachineIndexEntry`]'s doc: a copy of `stress_convergence.rs`'s
/// `index_view`, unchanged in behavior.
fn index_view(store: &MemoryStore) -> Result<Vec<CrossMachineIndexEntry>, MemError> {
    let mut records = store.list_records()?;
    records.sort_by_key(|r| r.note_id);

    Ok(records
        .into_iter()
        .map(|r| {
            (
                r.note_id,
                r.lamport,
                r.relations,
                r.reinforcers,
                r.last_reinforced,
            )
        })
        .collect())
}

/// Quarantine must be a temporary, self-healing divergence, not a permanent
/// split from a healthy peer reading the same shared bucket.
///
/// A gap in one author's chain makes the reader that hits it quarantine that
/// author's tail — correct, since an unverifiable chain must not be trusted.
/// But the quarantining machine now holds strictly less than a healthy peer
/// that saw no fault, and nothing before this test asserted it re-converges
/// to IDENTICAL state once the missing object becomes visible again. A
/// quarantine that never heals is indistinguishable, from a teammate's
/// perspective, from silent data loss.
///
/// See the module section doc above for the guard arithmetic this fixture's
/// two-author shape depends on, and why a single-author version of this same
/// scenario is unreachable under the redesigned systemic-outage guard (it
/// errors instead — see
/// `a_root_op_fetch_failure_errors_the_sync_and_leaves_the_warm_index_intact`
/// above).
///
/// # Why author A's SECOND op specifically
///
/// `a_op_keys` is captured immediately after author A finishes writing and
/// before the healthy author writes anything, so at that moment it holds
/// EXACTLY author A's 4 keys in ascending-lamport order (mirroring
/// `op_keys[0]`/`op_keys.last()`'s reasoning in the sibling tests above,
/// which rely on the same single-author-at-capture-time property).
/// `a_op_keys[1]` is neither the chain root (`[0]`, covered by
/// `a_root_op_fetch_failure_errors_the_sync_and_leaves_the_warm_index_intact`)
/// nor the terminal op (covered in spirit by
/// `a_transient_minority_op_fetch_failure_heals_on_the_next_sync`, though
/// that test's guard arithmetic predates this one's two-author fixture) —
/// genuinely mid-chain, with one op before it (kept) and two after it
/// (orphaned).
///
/// # Mutation verification
///
/// Both assertions below were independently confirmed to catch a real
/// regression, and confirmed NOT to catch an unrelated one (see the commit
/// message for the exact mutations and outcomes):
/// - The healing assertion (`index_view` equality) is caught by making
///   quarantine STICKY: caching, on `OpLogStore`, every author who ever loses
///   an op to `quarantine_broken_chains`, and excluding that author from
///   every future read on the same instance even once their chain is fully
///   intact again. Under that mutation `b` never recovers author A's notes,
///   even after `gapped.disarm()`.
/// - The degraded assertion (`b` strictly smaller, `b_ids` a subset of
///   `a_ids`) is caught by making `MemoryStore::replay_full`'s
///   `self.index.retain(&live_ids)` a no-op. `b` is deliberately warmed by
///   one clean sync BEFORE the fault is armed (see the assertion just above
///   the fault, and the sibling tests' identical "warm index... before any
///   fault" pattern) specifically so this mutation has something to defeat:
///   with retain disabled, the fault's degraded read still converges to the
///   correct smaller live set internally, but the already-warm index is
///   never pruned down to it, so `b` keeps reporting all 8 notes throughout
///   — the degraded assertion is what would catch a regression that stops
///   quarantine from actually being ENFORCED against a warm index, as
///   opposed to merely being computed and then not applied.
/// - NEGATIVE RESULT, recorded rather than discarded: disabling
///   `quarantine_broken_chains` entirely (a no-op) does NOT flip the degraded
///   assertion. Author A's second op still fails its own GET regardless of
///   chain-reachability logic, so `b` still loses at least that one note (3
///   of author A's 4 survive instead of 1, giving `b_ids.len() == 7 < 8`) —
///   still a proper subset, still strictly smaller. For THIS fixture (no
///   cache, one deterministic GET failure, compared against a full-universe
///   healthy baseline), the "strictly fewer" clause is guaranteed true by the
///   bare GET failure alone; it does not, by itself, discriminate whether
///   quarantine's CASCADE specifically ran. The mutation above (retain
///   disabled on a warm index) is what closes that gap: it isolates the
///   ENFORCEMENT step from the CASCADE-COMPUTATION step, and only the former
///   is what a fixture built this way can independently pin.
///
/// # What this test does NOT show
///
/// - A single-author version of this scenario: see the module section doc
///   above for why the redesigned guard makes that fixture error instead of
///   quarantine.
/// - Recovery through the incremental path specifically: `b`'s post-fault
///   sync falls back to a full rebuild here (the pre-fault checkpoint's
///   snapshotted records for author A's quarantined tail no longer match the
///   degraded converged base, tripping `sync_incremental`'s
///   `snapshot_still_valid` safety valve — see that function's own comment),
///   not the incremental fast path.
/// - Anything about `relations`/`reinforcers` genuinely differing and still
///   converging identically: every note in this fixture is a lone `Remember`
///   with no `Relate`/`Reinforce`/`Edit`, so both machines' `IndexEntry`
///   values for every note are the empty/default case on both fields. The
///   `lamport` component of the comparison is still meaningful (see Task
///   C1's reasoning, referenced above), and is what the sticky-quarantine
///   mutation actually trips — that mutation makes author A's notes vanish
///   from `b`'s `index_view` entirely, a stronger discriminator than a
///   single-field mismatch would be, but a `relations`/`reinforcers` field
///   genuinely diverging and still converging identically is not exercised
///   here.
#[tokio::test]
async fn a_quarantined_author_tail_reconverges_once_the_gap_closes()
-> Result<(), Box<dyn std::error::Error>> {
    let bucket = Arc::new(MemoryBlobStore::default());
    let a = store_over(bucket.clone())?;

    // Author A writes a straight 4-op chain: "note 0" (the root) through
    // "note 3".
    for i in 0..4 {
        a.remember(input(&format!("note {i}"), "body")).await?;
    }

    // Capture author A's own op-log keys NOW, before the healthy author
    // writes anything — see the doc above for why this timing is what makes
    // `a_op_keys[1]` reliably mean "author A's second op".
    let a_op_keys = bucket.list(&oplog_object_prefix(RECOVERY_TEAM)).await?;
    assert_eq!(
        a_op_keys.len(),
        4,
        "one op object per remembered note, no edits in this fixture"
    );
    let mid_chain_key = a_op_keys
        .get(1)
        .cloned()
        .ok_or("expected at least two op-log objects for author A")?;

    // A second author whose ops always fetch cleanly — see the module
    // section doc above for why the guard arithmetic needs this.
    let healthy = store_over_as(bucket.clone(), HEALTHY_AUTHOR_SEED)?;
    for i in 0..4 {
        healthy
            .remember(input(&format!("healthy note {i}"), "body"))
            .await?;
    }

    // `a` re-syncs over the untouched bucket to fold the healthy author's
    // notes into its own index too, making it the full "healthy peer"
    // reference the quarantining machine is compared against below. `a`'s
    // own 4 notes are already indexed directly from its `remember` calls
    // above; this sync adds the healthy author's 4 without disturbing them.
    a.sync().await?;

    // `b`: a distinct machine, warmed by one clean sync BEFORE the fault is
    // armed — the same "warm index holding everything before any fault"
    // shape the sibling tests above use, and what the retain-no-op mutation
    // above needs to have something to defeat (see "Mutation verification").
    let gapped = Arc::new(FailOneGet::new(bucket.clone(), mid_chain_key));
    let b = store_over_as(gapped.clone(), READER_SEED)?;
    b.sync().await?;
    assert_eq!(
        b.list_records()?.len(),
        8,
        "the warm index must hold both authors' notes before any fault"
    );

    // Arm the fault and sync again: author A's second op is now unfetchable,
    // so `longest_rooted_chain` quarantines everything after it in author
    // A's chain ("note 2", "note 3") while "note 0" (before the gap) and
    // every healthy note survive.
    gapped.arm();
    b.sync().await?;

    let a_ids: BTreeSet<NoteId> = a.list_records()?.into_iter().map(|r| r.note_id).collect();
    let b_ids: BTreeSet<NoteId> = b.list_records()?.into_iter().map(|r| r.note_id).collect();
    assert_eq!(
        a_ids.len(),
        8,
        "sanity: the healthy peer must see both authors' notes"
    );
    assert!(
        b_ids.is_subset(&a_ids) && b_ids.len() < a_ids.len(),
        "the quarantining machine must hold strictly less than the healthy one: {b_ids:?} vs {a_ids:?}"
    );

    // Close the gap and re-sync: the two machines must agree on INDEX state,
    // not merely on note ids (see Task C1 for why blob-derived views cannot
    // tell converged machines apart).
    gapped.disarm();
    b.sync().await?;

    assert_eq!(
        index_view(&a)?,
        index_view(&b)?,
        "a healed quarantine must re-converge to identical index state"
    );
    Ok(())
}
