//! Order-independent convergence of the op-log into per-note state.
//!
//! Every machine replicates the same *set* of [`Op`]s but may observe them in a
//! different order. To agree on "what memory currently is", each machine folds
//! that set into a [`ConvergedState`] here. Convergence is defined as **maxes
//! and unions over the op set**, never an order-sensitive left-fold: the
//! maximum of a set and the union of a set are the same regardless of the order
//! the elements are visited, so two machines holding the same ops converge to
//! byte-identical state without any coordination. The total order used for the
//! maxes is `(lamport, op_id, author_key)`: `op_id` (a unique [`Ulid`]) breaks
//! `lamport` ties for honest writers, and `author_key` is the final tiebreak
//! that keeps the order total even against a Byzantine author who reuses another
//! op's `(lamport, op_id)` — so the argmax is always uniquely determined by the
//! set, the property the [`converge_is_order_independent`] proptest pins down.
//!
//! What this layer decides, and what it deliberately does not: an [`Op`] only
//! carries the note *pointer* (`object_key` / `cid`) plus structural facts
//! (`Forget`, `Link`). A note's tags and body live inside the encrypted blob the
//! latest pointer references, so convergence resolves only (a) the current
//! pointer, (b) existence vs. tombstone, and (c) the link set. Decrypting and
//! indexing the pointed-at blob is Task 15's job, not this one's.

use std::collections::{BTreeMap, BTreeSet};

use ulid::Ulid;

use crate::domain::{Blake3Hash, NoteId, Ss58};
use crate::oplog::{Op, OpKind};

/// The converged pointer to a note's current ciphertext blob.
///
/// Produced from the note's latest `Remember`/`Edit` op (the one with the
/// maximal `(lamport, op_id, author_key)`). It names the blob to fetch (`object_key`) and
/// the digest to integrity-check it against (`cid`), alongside the `lamport`
/// and `author` of the op that won, which downstream layers surface in
/// `history`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotePointer {
    /// Object-store key of the winning op's ciphertext blob.
    pub object_key: String,
    /// BLAKE3 digest of that ciphertext.
    pub cid: Blake3Hash,
    /// Lamport clock of the op that produced this pointer.
    pub lamport: u64,
    /// Author of the op that produced this pointer.
    pub author: Ss58,
}

/// The converged state of a single note, derived from every op naming it.
///
/// `pointer` is `None` only for the degenerate case of a note that has *only* a
/// `Link`/`Forget` op and no `Remember`/`Edit` — i.e. it was referenced (or
/// forgotten) before its content op was observed. A `tombstoned` note keeps its
/// last `pointer` on purpose, so `history` can still show *what* was forgotten
/// rather than dropping the trail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteState {
    /// The note this state describes.
    pub note_id: NoteId,
    /// The current ciphertext pointer, or `None` for a content-less note.
    pub pointer: Option<NotePointer>,
    /// Whether the note's latest lifecycle op is a `Forget`.
    pub tombstoned: bool,
    /// The grow-only set of notes this note links to.
    pub links: BTreeSet<NoteId>,
}

/// The fully converged memory: every note that any op named, keyed by id.
///
/// A [`BTreeMap`] (not a `HashMap`) so iteration and equality are deterministic
/// in key order — the convergence guarantee would be meaningless over a
/// randomly-seeded hash order.
pub type ConvergedState = BTreeMap<NoteId, NoteState>;

/// Converge a set of ops into per-note state.
///
/// Groups `ops` by `note_id` and, for each note, computes three independent
/// reductions over that note's ops:
///
/// - **pointer**: the `Remember`/`Edit` op with the maximal
///   `(lamport, op_id, author_key)`.
/// - **tombstoned**: whether the latest *lifecycle* op (max
///   `(lamport, op_id, author_key)`
///   over `Remember`/`Edit`/`Forget`) is a `Forget`. A `Forget` tombstones; a
///   strictly-later `Remember`/`Edit` resurrects (latest-action-wins). This
///   realizes "tombstone wins" at the op level via the unique-`op_id` total
///   order rather than as a special-cased flag.
/// - **links**: the union of every `Link { to }` target. Phase 2 has no unlink
///   op, so this is a grow-only set; removing links is future work.
///
/// Order-independent by construction: max and union are commutative and
/// associative, so the result does not depend on the order of `ops`.
#[must_use]
pub fn converge(ops: &[Op]) -> ConvergedState {
    let mut groups: BTreeMap<NoteId, NoteAccumulator<'_>> = BTreeMap::new();
    for op in ops {
        groups.entry(op.note_id).or_default().observe(op);
    }
    groups
        .into_iter()
        .map(|(note_id, acc)| (note_id, acc.into_state(note_id)))
        .collect()
}

/// The highest lamport value seen across `ops`, or `0` for an empty set.
#[must_use]
pub fn lamport_tip(ops: &[Op]) -> u64 {
    ops.iter().map(|o| o.lamport).max().unwrap_or(0)
}

/// The lamport a machine assigns to its next new op.
///
/// The Lamport rule: a new local op's clock is `max(all observed) + 1`, so it
/// strictly succeeds everything this machine has seen. Saturating at
/// [`u64::MAX`] — a memory store that issued 2^64 ops has problems this `+ 1`
/// is not the place to surface.
#[must_use]
pub fn next_lamport(ops: &[Op]) -> u64 {
    lamport_tip(ops).saturating_add(1)
}

/// The total order the per-note reductions maximize over.
///
/// `(lamport, op_id, author_key)` is a strict total order on a note's ops that
/// is *author-independent*: it depends only on the op set, never on read order.
/// `op_id` (a unique [`Ulid`]) breaks `lamport` ties for an honest writer, and
/// `author_key` is the final tiebreak that keeps the order total even when a
/// Byzantine author REUSES another's `(lamport, op_id)` with a different `cid` —
/// without it, two such ops would be equal under the order and the winner would
/// depend on the order `converge` happened to visit them, so two machines could
/// diverge. The raw 32 public-key bytes give a deterministic, total tiebreak.
fn op_order(op: &Op) -> (u64, Ulid, [u8; 32]) {
    (op.lamport, op.op_id, *op.author_key.as_bytes())
}

/// Per-note reduction state, accumulated as ops stream in.
///
/// Holds borrows into the input slice (not clones) so the hot grouping pass
/// allocates nothing per op beyond the `links` set; the single clone of the
/// winning pointer's owned fields happens once, in [`Self::into_state`].
#[derive(Default)]
struct NoteAccumulator<'a> {
    /// The leading `Remember`/`Edit` op by [`op_order`] (drives the pointer).
    pointer: Option<&'a Op>,
    /// The leading lifecycle op by [`op_order`], paired with whether it is a
    /// `Forget`. Carrying the flag here avoids re-matching `kind` at finalize.
    lifecycle: Option<(&'a Op, bool)>,
    /// The accumulated union of `Link` targets.
    links: BTreeSet<NoteId>,
}

impl<'a> NoteAccumulator<'a> {
    /// Fold one op of this note into the running reductions.
    fn observe(&mut self, op: &'a Op) {
        match &op.kind {
            OpKind::Remember | OpKind::Edit => {
                self.consider_pointer(op);
                self.consider_lifecycle(op, false);
            }
            OpKind::Forget => self.consider_lifecycle(op, true),
            OpKind::Link { to } => {
                self.links.insert(*to);
            }
        }
    }

    /// Keep `op` as the pointer source if it outranks the current leader.
    fn consider_pointer(&mut self, op: &'a Op) {
        if self.pointer.is_none_or(|cur| op_order(op) > op_order(cur)) {
            self.pointer = Some(op);
        }
    }

    /// Keep `op` as the lifecycle leader if it outranks the current one.
    fn consider_lifecycle(&mut self, op: &'a Op, is_forget: bool) {
        if self
            .lifecycle
            .is_none_or(|(cur, _)| op_order(op) > op_order(cur))
        {
            self.lifecycle = Some((op, is_forget));
        }
    }

    /// Materialize the converged [`NoteState`], cloning the winning pointer's
    /// owned fields exactly once.
    fn into_state(self, note_id: NoteId) -> NoteState {
        let pointer = self.pointer.map(|op| NotePointer {
            object_key: op.object_key.clone(),
            cid: op.cid,
            lamport: op.lamport,
            author: op.author.clone(),
        });
        let tombstoned = self.lifecycle.is_some_and(|(_, is_forget)| is_forget);
        NoteState {
            note_id,
            pointer,
            tombstoned,
            links: self.links,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{converge, lamport_tip, next_lamport};
    use crate::crypto::content_hash;
    use crate::domain::{Blake3Hash, NoteId, Ss58};
    use crate::oplog::{Op, OpContent, OpKind, Sr25519Signer};
    use proptest::prelude::*;
    use ulid::Ulid;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const ALICE_SS58: &str = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";

    fn ensure(cond: bool, msg: &str) -> TestResult {
        if cond { Ok(()) } else { Err(msg.into()) }
    }

    fn ensure_eq<T: PartialEq + std::fmt::Debug>(left: &T, right: &T, msg: &str) -> TestResult {
        if left == right {
            Ok(())
        } else {
            Err(format!("{msg}: {left:?} != {right:?}").into())
        }
    }

    fn signer() -> Result<Sr25519Signer, Box<dyn std::error::Error>> {
        Ok(Sr25519Signer::from_seed([7u8; 32], Ss58::new(ALICE_SS58)?)?)
    }

    // Mint a fully signed op directly. `converge` never inspects `sig` /
    // `author_key` (signature verification is the op-log store's job, Task 12),
    // so signing here is for convenience — it reuses the real `OpContent` ->
    // `Op` constructor instead of fabricating a `Signature`/`VerifyingKey`,
    // whose newtype fields are private. `seq` makes `op_id` unique, which the
    // `(lamport, op_id)` tie-break relies on.
    fn mint(signer: &Sr25519Signer, note_id: NoteId, lamport: u64, kind: OpKind, seq: u128) -> Op {
        let content = OpContent {
            op_id: Ulid::from(seq),
            lamport,
            kind,
            note_id,
            object_key: format!("team/global/notes/{seq}"),
            cid: content_hash(format!("ciphertext-{seq}").as_bytes()),
            prev_op_hash: Blake3Hash::zero(),
        };
        Op::create_signed(signer, content)
    }

    fn note(seq: u128) -> NoteId {
        NoteId::from(Ulid::from(seq))
    }

    #[test]
    fn single_remember_is_live_with_pointer() -> TestResult {
        let signer = signer()?;
        let id = note(1);
        let ops = [mint(&signer, id, 5, OpKind::Remember, 1)];
        let converged = converge(&ops);
        let st = converged.get(&id).ok_or("missing note state")?;
        ensure(!st.tombstoned, "fresh note must not be tombstoned")?;
        let pointer = st.pointer.as_ref().ok_or("remember must yield a pointer")?;
        ensure_eq(&pointer.lamport, &5, "pointer lamport")?;
        ensure_eq(
            &pointer.object_key,
            &"team/global/notes/1".to_owned(),
            "pointer key",
        )
    }

    #[test]
    fn later_edit_wins_pointer() -> TestResult {
        let signer = signer()?;
        let id = note(1);
        let ops = [
            mint(&signer, id, 2, OpKind::Edit, 10),
            mint(&signer, id, 9, OpKind::Edit, 11),
        ];
        let converged = converge(&ops);
        let pointer = converged
            .get(&id)
            .and_then(|s| s.pointer.as_ref())
            .ok_or("missing pointer")?;
        ensure_eq(&pointer.lamport, &9, "highest-lamport edit wins")?;
        ensure_eq(
            &pointer.object_key,
            &"team/global/notes/11".to_owned(),
            "winning key",
        )
    }

    #[test]
    fn forget_tombstones() -> TestResult {
        let signer = signer()?;
        let id = note(1);
        let ops = [
            mint(&signer, id, 1, OpKind::Remember, 20),
            mint(&signer, id, 4, OpKind::Forget, 21),
        ];
        let converged = converge(&ops);
        let st = converged.get(&id).ok_or("missing note state")?;
        ensure(st.tombstoned, "later forget must tombstone")?;
        let pointer = st.pointer.as_ref().ok_or("tombstone retains pointer")?;
        ensure_eq(&pointer.lamport, &1, "retained pointer is the remember")
    }

    #[test]
    fn edit_after_forget_resurrects() -> TestResult {
        let signer = signer()?;
        let id = note(1);
        let ops = [
            mint(&signer, id, 1, OpKind::Remember, 30),
            mint(&signer, id, 2, OpKind::Forget, 31),
            mint(&signer, id, 3, OpKind::Edit, 32),
        ];
        let converged = converge(&ops);
        let st = converged.get(&id).ok_or("missing note state")?;
        ensure(!st.tombstoned, "later edit must resurrect")?;
        let pointer = st
            .pointer
            .as_ref()
            .ok_or("resurrected note has a pointer")?;
        ensure_eq(
            &pointer.lamport,
            &3,
            "pointer follows the resurrecting edit",
        )
    }

    #[test]
    fn links_accumulate() -> TestResult {
        let signer = signer()?;
        let id = note(1);
        let (a, b) = (note(100), note(200));
        let ops = [
            mint(&signer, id, 1, OpKind::Link { to: a }, 40),
            mint(&signer, id, 2, OpKind::Link { to: b }, 41),
        ];
        let converged = converge(&ops);
        let st = converged.get(&id).ok_or("missing note state")?;
        ensure(
            st.links.contains(&a) && st.links.contains(&b),
            "both link targets present",
        )?;
        ensure_eq(&st.links.len(), &2, "exactly two links")?;
        ensure(st.pointer.is_none(), "link-only note has no pointer")
    }

    #[test]
    fn lamport_tip_and_next() -> TestResult {
        let signer = signer()?;
        let id = note(1);
        let ops = [
            mint(&signer, id, 3, OpKind::Remember, 50),
            mint(&signer, id, 7, OpKind::Edit, 51),
        ];
        ensure_eq(&lamport_tip(&ops), &7, "tip is the max lamport")?;
        ensure_eq(&next_lamport(&ops), &8, "next is tip + 1")?;
        let empty: [Op; 0] = [];
        ensure_eq(&lamport_tip(&empty), &0, "empty tip is 0")?;
        ensure_eq(&next_lamport(&empty), &1, "empty next is 1")
    }

    #[test]
    fn converge_is_total_under_op_id_collision() -> TestResult {
        // Models a Byzantine author who REUSES another writer's (lamport, op_id)
        // for the same note but with a different cid. Under a `(lamport, op_id)`
        // order these two ops would be equal and the winner would depend on visit
        // order — divergence. The `author_key` final tiebreak makes the order
        // total, so both slice orders pick the same winner.
        let alice = Sr25519Signer::from_seed([1u8; 32], Ss58::new(ALICE_SS58)?)?;
        let bob = Sr25519Signer::from_seed([2u8; 32], Ss58::new(ALICE_SS58)?)?;
        let id = note(1);
        let op_id = Ulid::from(42u128);
        let lamport = 5;

        // Same (lamport, op_id, note_id); different author AND different cid.
        let make = |signer: &Sr25519Signer, marker: &str| {
            Op::create_signed(
                signer,
                OpContent {
                    op_id,
                    lamport,
                    kind: OpKind::Remember,
                    note_id: id,
                    object_key: format!("team/global/notes/{marker}"),
                    cid: content_hash(format!("ciphertext-{marker}").as_bytes()),
                    prev_op_hash: Blake3Hash::zero(),
                },
            )
        };
        let op_a = make(&alice, "a");
        let op_b = make(&bob, "b");

        let cid_of = |state: &super::ConvergedState| {
            state
                .get(&id)
                .and_then(|s| s.pointer.as_ref())
                .map(|pointer| pointer.cid)
        };
        let forward = cid_of(&converge(&[op_a.clone(), op_b.clone()])).ok_or("forward pointer")?;
        let backward = cid_of(&converge(&[op_b, op_a])).ok_or("backward pointer")?;
        ensure_eq(
            &forward,
            &backward,
            "the winner is identical regardless of slice order",
        )
    }

    // A proptest-provided op spec. A small pool of note ids and op kinds keeps
    // each generated note interesting (overlapping ids force real reductions)
    // while staying inside the shrinker's reach.
    #[derive(Clone, Debug)]
    struct OpSpec {
        note_seq: u128,
        lamport: u64,
        kind_tag: u8,
        link_seq: u128,
    }

    fn op_spec_strategy() -> impl Strategy<Value = OpSpec> {
        (0u128..4, 0u64..6, 0u8..4, 0u128..4).prop_map(|(note_seq, lamport, kind_tag, link_seq)| {
            OpSpec {
                note_seq,
                lamport,
                kind_tag,
                link_seq,
            }
        })
    }

    fn kind_of(spec: &OpSpec) -> OpKind {
        match spec.kind_tag {
            0 => OpKind::Remember,
            1 => OpKind::Edit,
            2 => OpKind::Forget,
            _ => OpKind::Link {
                to: note(1000 + spec.link_seq),
            },
        }
    }

    // Permute `ops` by the proptest-provided `perm` without `rand`: a
    // Fisher-Yates-by-removal driven by `perm[i] % remaining` is a
    // deterministic, replayable way to realize an arbitrary permutation from a
    // vector of arbitrary indices. The divisor is the *current* `pool.len()`,
    // which shrinks each step, so it is always >= 1 inside the loop.
    fn permuted(ops: &[Op], perm: &[usize]) -> Vec<Op> {
        let mut pool: Vec<Op> = ops.to_vec();
        let mut out = Vec::with_capacity(pool.len());
        let mut step = 0;
        while !pool.is_empty() {
            let slot = perm.get(step).copied().unwrap_or(0);
            out.push(pool.remove(slot % pool.len()));
            step += 1;
        }
        out
    }

    proptest! {
        // THE invariant of the whole phase: convergence depends only on the SET
        // of ops, never their order. Generate a pool of ops over a few shared
        // note ids, then assert `converge` agrees on the original and an
        // arbitrary permutation of it.
        #[test]
        fn converge_is_order_independent(
            specs in proptest::collection::vec(op_spec_strategy(), 0..16),
            perm in proptest::collection::vec(0usize..64, 16),
        ) {
            let signer = signer().map_err(|e| TestCaseError::fail(e.to_string()))?;
            let ops: Vec<Op> = specs
                .iter()
                .enumerate()
                .map(|(i, spec)| {
                    let seq = i as u128;
                    mint(&signer, note(spec.note_seq), spec.lamport, kind_of(spec), seq)
                })
                .collect();
            let shuffled = permuted(&ops, &perm);
            prop_assert_eq!(shuffled.len(), ops.len(), "permutation preserves multiset size");
            prop_assert_eq!(converge(&ops), converge(&shuffled));
        }
    }
}
