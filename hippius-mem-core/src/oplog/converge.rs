//! Order-independent convergence of the op-log into per-note state.
//!
//! Every machine replicates the same *set* of [`Op`]s but may observe them in a
//! different order. To agree on "what memory currently is", each machine folds
//! that set into a [`ConvergedState`] here. Convergence is defined as **maxes
//! and unions over the op set**, never an order-sensitive left-fold: the
//! maximum of a set and the union of a set are the same regardless of the order
//! the elements are visited, so two machines holding the same ops converge to
//! byte-identical state without any coordination. The total order used for the
//! maxes is `(lamport, op_id, author_key, op_hash)`: `op_id` (a unique [`Ulid`])
//! breaks `lamport` ties for honest writers, `author_key` breaks ties across
//! authors, and the op's content hash is the final tiebreak that keeps the order
//! total even against a Byzantine author who reuses its OWN `(lamport, op_id)`
//! for a note with a different `cid` — so the argmax is always uniquely
//! determined by the set, the property the [`converge_is_order_independent`]
//! proptest pins down.
//!
//! What this layer decides, and what it deliberately does not: an [`Op`] only
//! carries the note *pointer* (`object_key` / `cid`) plus structural facts
//! (`Forget`, `Link`). A note's tags and body live inside the encrypted blob the
//! latest pointer references, so convergence resolves only (a) the current
//! pointer, (b) existence vs. tombstone, and (c) the link set. Decrypting and
//! indexing the pointed-at blob is Task 15's job, not this one's.

use std::collections::{BTreeMap, BTreeSet};

use crate::domain::{Blake3Hash, NoteId, Ss58, Timestamp};
use crate::oplog::{LinkRel, Op, OpKind, VerifiedOps};

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
    /// Team-key epoch the winning op's blob was sealed under, so the reader can
    /// pick the matching key from the key-ring after a rotation.
    pub key_epoch: u64,
}

/// The converged state of a single note, derived from every op naming it.
///
/// `pointer` is `None` for a note that has *only* a `Link`/`Forget` op and no
/// `Remember`/`Edit` (referenced or forgotten before its content op was
/// observed), AND for a `redacted` note (its content is gone, so there is
/// nothing to point at). A merely-`tombstoned` note keeps its last `pointer` on
/// purpose, so `history` can still show *what* was forgotten; a `redacted` note
/// does not, because the blob it would name has been scrubbed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteState {
    /// The note this state describes.
    pub note_id: NoteId,
    /// The current ciphertext pointer, or `None` for a content-less or redacted
    /// note.
    pub pointer: Option<NotePointer>,
    /// Whether the note's latest lifecycle op is a `Forget`, or it was redacted
    /// (redaction always implies tombstoned).
    pub tombstoned: bool,
    /// Whether any op for this note is a `Redact`. Absorbing and
    /// order-independent: a single `Redact` anywhere in the note's op set makes
    /// this `true` for good — a later `Edit`/`Remember` cannot un-redact, because
    /// the content blobs are physically deleted.
    pub redacted: bool,
    /// The grow-only set of notes this note links to.
    pub links: BTreeSet<NoteId>,
    /// This note's OUTGOING typed relations (supersede / contradict / refine /
    /// duplicate). Source-stamped, so recall builds the reverse "who supersedes
    /// this note" map by scanning candidates' outgoing relations at query time.
    pub relations: BTreeSet<TypedLink>,
    /// Identities that have REINFORCED this note — the `author` of each
    /// [`OpKind::Reinforce`] op. A grow-only union (order-independent) of DISTINCT
    /// authors, so a single agent re-reinforcing cannot inflate the count; recall
    /// weights a note by `|reinforcers|`, so distinctness is the Sybil bound.
    pub reinforcers: BTreeSet<Ss58>,
    /// The most recent reinforcement time — the `max` of the `Reinforce` ops' ULID
    /// timestamps, or `None` if never reinforced. `max` keeps it order-independent;
    /// recall ages the note on `max(updated, last_reinforced)` so use stays fresh.
    pub last_reinforced: Option<Timestamp>,
}

/// One outgoing typed relation from a note: it relates `to` another note with
/// relation `rel`. Ordered so it lives in a `BTreeSet` in the converged state,
/// which the accumulator fills latest-wins per target (see [`NoteState`]).
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct TypedLink {
    /// The related note.
    pub to: NoteId,
    /// How the owning note relates to `to`.
    pub rel: LinkRel,
}

/// The fully converged memory: every note that any op named, keyed by id.
///
/// A [`BTreeMap`] (not a `HashMap`) so iteration and equality are deterministic
/// in key order — the convergence guarantee would be meaningless over a
/// randomly-seeded hash order.
pub type ConvergedState = BTreeMap<NoteId, NoteState>;

/// Converge a set of ops into per-note state.
///
/// Groups `ops` by `note_id` and, for each note, computes these independent
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
/// - **relations**: the typed, recall-demoting sibling of **links**, but
///   LATEST-WINS per target rather than grow-only: the highest-ranked
///   `Relate { to, rel }` op for each target note wins, so re-relating a target
///   (correcting `Supersedes` to `Refines`) converges to the latest assertion
///   alone. Ranked by the same `(lamport, op_id, author_key)` total order as the
///   pointer, so still order-independent. (A relation can be *changed* but not
///   yet *removed* — there is no un-relate op; that is future work.)
/// - **reinforcers / `last_reinforced`**: the union of `Reinforce` authors
///   (distinct-author set — the Sybil bound on the recall boost) and the max of
///   their op-id times.
/// - **redacted**: the logical OR of "is a `Redact`" over the note's ops. A
///   redacted note has no pointer, is tombstoned, and carries NO graph metadata
///   (links/relations/reinforcers are scrubbed) — `Redact` is erasure, not a
///   soft tombstone — and the flag is absorbing: no later op clears it.
///
/// Order-independent by construction: max, latest-wins over a total order, union,
/// and OR are all order-insensitive, so the result does not depend on the order
/// of `ops`.
///
/// # Invariant
///
/// The [`VerifiedOps`] parameter is the invariant, made structural: this
/// reduction does NOT check signatures, chain linkage, or team binding — it
/// trusts its input completely, so converging raw bucket objects would treat
/// forged or foreign ops as genuine. Requiring [`VerifiedOps`] means the only ops
/// that reach here are those [`OpLogStore::read_verified`](super::OpLogStore) has
/// already checked (and the verified-preserving subsets/unions of that set); a
/// caller cannot pass an unverified `Vec<Op>` because it cannot mint the witness.
#[must_use]
pub fn converge(ops: &VerifiedOps) -> ConvergedState {
    let mut groups: BTreeMap<NoteId, NoteAccumulator<'_>> = BTreeMap::new();
    for op in ops.iter() {
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

/// True iff `a` strictly outranks `b` in the per-note total order the
/// reductions maximize over.
///
/// The cheap prefix `(lamport, op_id, author_key)` decides almost every pair and
/// is *author-independent*: it depends only on the op set, never on read order.
/// `op_id` (a unique [`Ulid`]) breaks `lamport` ties for an honest writer and
/// `author_key` breaks ties across authors. The final tiebreak — the op's
/// content hash — is reached ONLY on a full prefix tie, the one case an honest
/// log never produces: a Byzantine author reusing its OWN `(lamport, op_id)` for
/// a note with a different `cid`. `op_id` uniqueness is unenforced and
/// `verify_one_chain` checks only `prev_op_hash`, so without this last tiebreak
/// the two ops would compare equal and the winner would depend on the order
/// `converge` visited them — diverging machines. [`Op::hash`] covers `cid` (it
/// hashes the signed bytes), so it is a deterministic, total tiebreak; gating it
/// behind the equal-prefix branch keeps the hash off the common path.
fn op_outranks(a: &Op, b: &Op) -> bool {
    let a_prefix = (a.lamport, a.op_id, *a.author_key.as_bytes());
    let b_prefix = (b.lamport, b.op_id, *b.author_key.as_bytes());
    match a_prefix.cmp(&b_prefix) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        // Equal prefix: only a Byzantine same-(lamport, op_id) reuse reaches here.
        std::cmp::Ordering::Equal => *a.hash().as_bytes() > *b.hash().as_bytes(),
    }
}

/// Per-note reduction state, accumulated as ops stream in.
///
/// Holds borrows into the input slice (not clones) so the hot grouping pass
/// allocates nothing per op beyond the `links` set; the single clone of the
/// winning pointer's owned fields happens once, in [`Self::into_state`].
#[derive(Default)]
struct NoteAccumulator<'a> {
    /// The leading `Remember`/`Edit` op by [`op_outranks`] (drives the pointer).
    pointer: Option<&'a Op>,
    /// The leading lifecycle op by [`op_outranks`], paired with whether it is a
    /// `Forget`. Carrying the flag here avoids re-matching `kind` at finalize.
    lifecycle: Option<(&'a Op, bool)>,
    /// The accumulated union of `Link`/`Relate` targets.
    links: BTreeSet<NoteId>,
    /// This note's OUTGOING typed relations, LATEST-WINS per target: the
    /// highest-`op_outranks` `Relate` op for each target note, so re-relating a
    /// target (correcting `Supersedes` to `Refines`) converges to the latest
    /// assertion alone rather than accumulating both. Keyed by target `NoteId`;
    /// the value pairs the winning op (borrowed, for its ranking) with its
    /// `LinkRel`, materialized to a `BTreeSet<TypedLink>` in [`Self::into_state`].
    /// Ranked by the SAME total order as the pointer, so still order-independent.
    /// Source-stamped: stored on the note that ASSERTED the relation, which is
    /// where converge groups the op, so a `Relate` in a sync tail carries with its
    /// source note. Recall inverts this to find "who supersedes M" at query time.
    relations: BTreeMap<NoteId, (&'a Op, LinkRel)>,
    /// Union of DISTINCT reinforcing authors (each `Reinforce` op's `author`).
    /// Grow-only, so order-independent; distinctness is the Sybil bound on the
    /// recall boost.
    reinforcers: BTreeSet<Ss58>,
    /// Max reinforce time across this note's `Reinforce` ops (their ULID
    /// timestamps), or `None` if never reinforced. `max` is order-independent.
    last_reinforced: Option<Timestamp>,
    /// OR of "any op is a `Redact`". Absorbing: once set it never clears, which
    /// is why it is a plain `bool` and not subject to the `(lamport, op_id)`
    /// ranking the pointer/lifecycle use — redaction wins regardless of order.
    redacted: bool,
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
            // Absorbing OR — no ranking, no pointer: a redacted note's content is
            // gone, so a later Remember/Edit cannot resurrect it.
            OpKind::Redact => self.redacted = true,
            OpKind::Link { to } => {
                self.links.insert(*to);
            }
            // A typed relation is also a plain link, so `links` stays the
            // grow-only union `history` shows. The CONVERGED typed relation,
            // however, is latest-wins PER TARGET: keep only the highest-ranked
            // `Relate` op for `to`, so a later correction (`Supersedes` ->
            // `Refines`) replaces the earlier assertion instead of both surviving.
            // Ranked by `op_outranks` (the pointer's total order), so the winner is
            // the max of a total order — order-independent, convergence stays
            // deterministic across machines.
            OpKind::Relate { to, rel } => {
                self.links.insert(*to);
                self.relations
                    .entry(*to)
                    .and_modify(|winner| {
                        if op_outranks(op, winner.0) {
                            *winner = (op, *rel);
                        }
                    })
                    .or_insert((op, *rel));
            }
            // A usage signal folded by DISTINCT author (union) and latest time
            // (max) — both order-independent, so convergence stays deterministic.
            // The time is the op's ULID timestamp (`Op` carries no wall-clock
            // field); a 48-bit ULID ms always fits i64, so the fallback never trips.
            OpKind::Reinforce => {
                self.reinforcers.insert(op.author.clone());
                let reinforced_at =
                    Timestamp::new(i64::try_from(op.op_id.timestamp_ms()).unwrap_or(i64::MAX));
                self.last_reinforced = self.last_reinforced.max(Some(reinforced_at));
            }
        }
    }

    /// Keep `op` as the pointer source if it outranks the current leader.
    fn consider_pointer(&mut self, op: &'a Op) {
        if self.pointer.is_none_or(|cur| op_outranks(op, cur)) {
            self.pointer = Some(op);
        }
    }

    /// Keep `op` as the lifecycle leader if it outranks the current one.
    fn consider_lifecycle(&mut self, op: &'a Op, is_forget: bool) {
        if self.lifecycle.is_none_or(|(cur, _)| op_outranks(op, cur)) {
            self.lifecycle = Some((op, is_forget));
        }
    }

    /// Materialize the converged [`NoteState`], cloning the winning pointer's
    /// owned fields exactly once.
    fn into_state(self, note_id: NoteId) -> NoteState {
        // `Redact` is ERASURE for a leaked secret or PII, not a soft tombstone:
        // beyond suppressing the scrubbed-blob pointer, drop ALL graph metadata
        // that could still identify the note or its participants — its links,
        // relation targets, and the SS58 identities (and timing) of reinforcers.
        // Leaving those readable on a note redacted precisely to erase sensitive
        // content is the leak this closes. A redacted note converges to a bare
        // tombstone with no residual, readable trace. `redacted` is checked first
        // because it is absorbing and dominates every other field.
        if self.redacted {
            return NoteState {
                note_id,
                pointer: None,
                tombstoned: true,
                redacted: true,
                links: BTreeSet::new(),
                relations: BTreeSet::new(),
                reinforcers: BTreeSet::new(),
                last_reinforced: None,
            };
        }
        let pointer = self.pointer.map(|op| NotePointer {
            object_key: op.object_key.clone(),
            cid: op.cid,
            lamport: op.lamport,
            author: op.author.clone(),
            key_epoch: op.key_epoch,
        });
        let tombstoned = self.lifecycle.is_some_and(|(_, is_forget)| is_forget);
        NoteState {
            note_id,
            pointer,
            tombstoned,
            redacted: false,
            links: self.links,
            // Materialize the latest-wins winner per target into the public
            // `BTreeSet<TypedLink>`, dropping the borrowed op kept only for ranking.
            relations: self
                .relations
                .into_iter()
                .map(|(to, (_op, rel))| TypedLink { to, rel })
                .collect(),
            reinforcers: self.reinforcers,
            last_reinforced: self.last_reinforced,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ConvergedState, converge, lamport_tip, next_lamport};
    use crate::NetworkPrefix;
    use crate::crypto::content_hash;
    use crate::domain::{Blake3Hash, NoteId, Timestamp};
    use crate::oplog::{LinkRel, Op, OpContent, OpKind, Signer, Sr25519Signer, VerifiedOps};
    use proptest::prelude::*;
    use ulid::Ulid;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Converge synthetic test ops. Production ops reach [`converge`] only as a
    /// [`VerifiedOps`] minted by `read_all`; these tests build ops by hand, so they
    /// mint the witness here. Cloning is fine — the input is a fixture, not a hot
    /// path — and keeps the call sites reading like the pre-newtype `converge(&v)`.
    fn converge_ops(ops: &[Op]) -> ConvergedState {
        converge(&VerifiedOps::from_verified(ops.to_vec()))
    }

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
        Ok(Sr25519Signer::from_seed_with_prefix(
            &[7u8; 32],
            NetworkPrefix::HIPPIUS,
        )?)
    }

    // A small pool of distinct authors. Distinct seeds derive distinct
    // `author_key`s, so generated op sets exercise the `(lamport, op_id,
    // author_key)` order's final tiebreak (and the carried `author` field's
    // order-independence), not only the single-author happy path.
    fn signers() -> Result<Vec<Sr25519Signer>, Box<dyn std::error::Error>> {
        Ok(vec![
            Sr25519Signer::from_seed_with_prefix(&[7u8; 32], NetworkPrefix::HIPPIUS)?,
            Sr25519Signer::from_seed_with_prefix(&[8u8; 32], NetworkPrefix::HIPPIUS)?,
            Sr25519Signer::from_seed_with_prefix(&[9u8; 32], NetworkPrefix::HIPPIUS)?,
        ])
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
            key_epoch: 0,
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

    /// A ULID `seq` whose 48-bit timestamp is `ts_ms` (top bits) and low bits are
    /// `uniq`, so a `Reinforce` op's `last_reinforced` — read from its `op_id`'s
    /// ULID timestamp — is controllable in a converge test.
    fn seq_at(ts_ms: u128, uniq: u128) -> u128 {
        (ts_ms << 80) | uniq
    }

    #[test]
    fn reinforce_converges_by_distinct_author_and_latest_time() -> TestResult {
        // Four Reinforce ops from THREE distinct authors (author 0 twice):
        // convergence counts DISTINCT authors, so one author's self-inflation burst
        // adds exactly one reinforcer, and `last_reinforced` is the MAX op time.
        // Both are set/max reductions, so op order does not change the result.
        let ss = signers()?;
        let n = note(1);
        let remember = mint(&ss[0], n, 0, OpKind::Remember, 1);
        let r0a = mint(&ss[0], n, 1, OpKind::Reinforce, seq_at(100, 10));
        let r0b = mint(&ss[0], n, 2, OpKind::Reinforce, seq_at(200, 11));
        let r1 = mint(&ss[1], n, 3, OpKind::Reinforce, seq_at(150, 12));
        let r2 = mint(&ss[2], n, 4, OpKind::Reinforce, seq_at(300, 13));

        let forward = [
            remember.clone(),
            r0a.clone(),
            r0b.clone(),
            r1.clone(),
            r2.clone(),
        ];
        let reversed = [r2, r1, r0b, r0a, remember];

        let expected_authors: std::collections::BTreeSet<_> = [
            ss[0].author_ss58(),
            ss[1].author_ss58(),
            ss[2].author_ss58(),
        ]
        .into_iter()
        .collect();

        for ops in [forward.as_slice(), reversed.as_slice()] {
            let converged = converge_ops(ops);
            let state = converged
                .get(&n)
                .ok_or("note absent from converged state")?;
            ensure_eq(
                &state.reinforcers.len(),
                &3,
                "three DISTINCT reinforcers, not four ops (Sybil bound)",
            )?;
            ensure_eq(
                &state.reinforcers,
                &expected_authors,
                "reinforcers are exactly the three distinct authors",
            )?;
            ensure_eq(
                &state.last_reinforced,
                &Some(Timestamp::new(300)),
                "last_reinforced is the MAX reinforce time",
            )?;
        }
        Ok(())
    }

    #[test]
    fn relate_op_source_stamps_typed_relations_order_independently() -> TestResult {
        // A `Relate` op adds a `TypedLink` to the SOURCE note's converged relations
        // (where recall reads it to demote the target), NOT to the target's — that
        // is what keeps the reduction per-note and, in the store, correct under
        // incremental sync. With one `Relate` the latest-wins reduction is order-
        // independent trivially, so op order does not change the result.
        let s = signer()?;
        let (n, m) = (note(1), note(2));
        let remember_n = mint(&s, n, 0, OpKind::Remember, 1);
        let remember_m = mint(&s, m, 1, OpKind::Remember, 2);
        let relate = mint(
            &s,
            n,
            2,
            OpKind::Relate {
                to: m,
                rel: LinkRel::Supersedes,
            },
            3,
        );

        let forward = converge_ops(&[remember_n.clone(), remember_m.clone(), relate.clone()]);
        let reverse = converge_ops(&[relate, remember_m, remember_n]);
        ensure_eq(
            &forward,
            &reverse,
            "converge is order-independent over Relate",
        )?;

        let source = forward.get(&n).ok_or("source note n converged")?;
        ensure(
            source
                .relations
                .iter()
                .any(|tl| tl.to == m && tl.rel == LinkRel::Supersedes),
            "the Relate op is source-stamped on n",
        )?;
        ensure(
            forward
                .get(&m)
                .ok_or("target note m converged")?
                .relations
                .is_empty(),
            "the target m carries no outgoing relation (relations are source-stamped)",
        )
    }

    #[test]
    fn relate_is_latest_wins_per_target_not_grow_only() -> TestResult {
        // Correcting a relation to the SAME target must converge to the latest
        // assertion alone, not keep both. A note asserts `Supersedes M` then
        // corrects to `Refines M`; the higher-lamport `Refines` outranks, so the
        // converged state carries exactly `Refines` — the stale `Supersedes` is
        // gone. Latest-wins over a total order stays order-independent.
        let s = signer()?;
        let (n, m) = (note(1), note(2));
        let remember_n = mint(&s, n, 0, OpKind::Remember, 1);
        let supersedes = mint(
            &s,
            n,
            3,
            OpKind::Relate {
                to: m,
                rel: LinkRel::Supersedes,
            },
            2,
        );
        let refines = mint(
            &s,
            n,
            5,
            OpKind::Relate {
                to: m,
                rel: LinkRel::Refines,
            },
            3,
        );

        let forward = converge_ops(&[remember_n.clone(), supersedes.clone(), refines.clone()]);
        let reverse = converge_ops(&[refines, supersedes, remember_n]);
        ensure_eq(
            &forward,
            &reverse,
            "latest-wins relations are order-independent",
        )?;

        let source = forward.get(&n).ok_or("source note n converged")?;
        ensure_eq(
            &source.relations.len(),
            &1,
            "exactly one relation to m survives (latest-wins, not grow-only)",
        )?;
        ensure(
            source
                .relations
                .iter()
                .any(|tl| tl.to == m && tl.rel == LinkRel::Refines),
            "the later Refines wins over the earlier Supersedes",
        )?;
        ensure(
            !source
                .relations
                .iter()
                .any(|tl| tl.rel == LinkRel::Supersedes),
            "the corrected-away Supersedes relation is gone",
        )
    }

    #[test]
    fn redact_scrubs_all_graph_metadata() -> TestResult {
        // `Redact` is erasure for a leaked secret / PII, so a redacted note must
        // carry no residual, readable trace: not just its scrubbed-blob pointer,
        // but its links, typed relations, and the SS58 identities (and timing) of
        // its reinforcers are all dropped.
        let s = signer()?;
        let id = note(1);
        let (linked, related) = (note(100), note(200));
        let ops = [
            mint(&s, id, 1, OpKind::Remember, 1),
            mint(&s, id, 2, OpKind::Link { to: linked }, 2),
            mint(
                &s,
                id,
                3,
                OpKind::Relate {
                    to: related,
                    rel: LinkRel::Supersedes,
                },
                3,
            ),
            mint(&s, id, 4, OpKind::Reinforce, 4),
            mint(&s, id, 5, OpKind::Redact, 5),
        ];
        let converged = converge_ops(&ops);
        let st = converged.get(&id).ok_or("missing note state")?;
        ensure(st.redacted && st.tombstoned, "redacted and tombstoned")?;
        ensure(st.pointer.is_none(), "no pointer (blob scrubbed)")?;
        ensure(st.links.is_empty(), "redaction scrubs links")?;
        ensure(st.relations.is_empty(), "redaction scrubs typed relations")?;
        ensure(
            st.reinforcers.is_empty(),
            "redaction scrubs reinforcer SS58 identities",
        )?;
        ensure(
            st.last_reinforced.is_none(),
            "redaction drops the reinforce timestamp",
        )
    }

    #[test]
    fn verified_transforms_preserve_the_op_set() -> TestResult {
        // filter / partition / concat are the verified-preserving combinators the
        // store threads a `VerifiedOps` through — member filter, note filter,
        // base/tail split, and the safety-valve rejoin — without re-minting the
        // witness. Pin that each keeps exactly the intended ops, so `converge` sees
        // the same set the pre-newtype slice code fed it.
        let signer = signer()?;
        let a = note(1);
        let b = note(2);
        let ops = vec![
            mint(&signer, a, 1, OpKind::Remember, 1),
            mint(&signer, b, 2, OpKind::Remember, 2),
            mint(&signer, a, 3, OpKind::Edit, 3),
        ];

        // filter: only note `a`'s ops survive.
        let only_a = VerifiedOps::from_verified(ops.clone()).filter(|op| op.note_id == a);
        ensure_eq(&only_a.len(), &2, "filter keeps both of a's ops")?;
        ensure(only_a.iter().all(|op| op.note_id == a), "filter drops b")?;

        // partition: split at lamport 2; the two halves together reproduce the set.
        let (base, tail) = VerifiedOps::from_verified(ops.clone()).partition(|op| op.lamport <= 2);
        ensure_eq(&base.len(), &2, "base holds lamports 1 and 2")?;
        ensure_eq(&tail.len(), &1, "tail holds lamport 3")?;

        // concat rejoins them; converging the rejoin equals converging the original.
        ensure_eq(
            &converge(&base.concat(tail)),
            &converge_ops(&ops),
            "concat(base, tail) converges identically to the original set",
        )
    }

    #[test]
    fn single_remember_is_live_with_pointer() -> TestResult {
        let signer = signer()?;
        let id = note(1);
        let ops = [mint(&signer, id, 5, OpKind::Remember, 1)];
        let converged = converge_ops(&ops);
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
        let converged = converge_ops(&ops);
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
        let converged = converge_ops(&ops);
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
        let converged = converge_ops(&ops);
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
    fn redact_suppresses_pointer_and_tombstones() -> TestResult {
        let signer = signer()?;
        let id = note(1);
        let ops = [
            mint(&signer, id, 1, OpKind::Remember, 60),
            mint(&signer, id, 2, OpKind::Redact, 61),
        ];
        let converged = converge_ops(&ops);
        let st = converged.get(&id).ok_or("missing note state")?;
        ensure(st.redacted, "a Redact op must mark the note redacted")?;
        ensure(st.tombstoned, "redaction implies tombstoned")?;
        ensure(
            st.pointer.is_none(),
            "a redacted note offers no pointer — its blob is scrubbed",
        )
    }

    #[test]
    fn redact_is_absorbing_against_a_later_edit() -> TestResult {
        // The Edit has a strictly higher lamport than the Redact. For `Forget`
        // that would resurrect (latest-action-wins); for `Redact` it must NOT —
        // redaction is absorbing because the content is physically gone.
        let signer = signer()?;
        let id = note(1);
        let ops = [
            mint(&signer, id, 1, OpKind::Remember, 70),
            mint(&signer, id, 2, OpKind::Redact, 71),
            mint(&signer, id, 9, OpKind::Edit, 72),
        ];
        let converged = converge_ops(&ops);
        let st = converged.get(&id).ok_or("missing note state")?;
        ensure(st.redacted, "redaction is absorbing across a later edit")?;
        ensure(st.tombstoned, "a redacted note stays tombstoned")?;
        ensure(
            st.pointer.is_none(),
            "a later edit cannot give a redacted note a pointer back",
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
        let converged = converge_ops(&ops);
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
        let alice = Sr25519Signer::from_seed_with_prefix(&[1u8; 32], NetworkPrefix::HIPPIUS)?;
        let bob = Sr25519Signer::from_seed_with_prefix(&[2u8; 32], NetworkPrefix::HIPPIUS)?;
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
                    key_epoch: 0,
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
        let forward =
            cid_of(&converge_ops(&[op_a.clone(), op_b.clone()])).ok_or("forward pointer")?;
        let backward = cid_of(&converge_ops(&[op_b, op_a])).ok_or("backward pointer")?;
        ensure_eq(
            &forward,
            &backward,
            "the winner is identical regardless of slice order",
        )
    }

    #[test]
    fn converge_is_total_under_same_author_id_reuse() -> TestResult {
        // I3: a Byzantine author reuses its OWN (lamport, op_id) for one note with
        // two different cids. Here (lamport, op_id, author_key) are ALL equal —
        // the same-author case `author_key` cannot break — so only the op-hash
        // final tiebreak keeps the order total. Without it the winner would depend
        // on visit order and two machines would diverge. (Sr25519 signing is
        // randomized, so the two ops are cloned, never re-minted, into both
        // orderings: the same instances must compare identically each way.)
        let author = Sr25519Signer::from_seed_with_prefix(&[3u8; 32], NetworkPrefix::HIPPIUS)?;
        let id = note(1);
        let op_id = Ulid::from(99u128);

        let make = |marker: &str| {
            Op::create_signed(
                &author,
                OpContent {
                    op_id,
                    lamport: 5,
                    key_epoch: 0,
                    kind: OpKind::Edit,
                    note_id: id,
                    object_key: format!("team/global/notes/{marker}"),
                    cid: content_hash(format!("ciphertext-{marker}").as_bytes()),
                    prev_op_hash: Blake3Hash::zero(),
                },
            )
        };
        let op_a = make("a");
        let op_b = make("b");

        let cid_of = |state: &super::ConvergedState| {
            state
                .get(&id)
                .and_then(|s| s.pointer.as_ref())
                .map(|pointer| pointer.cid)
        };
        let forward =
            cid_of(&converge_ops(&[op_a.clone(), op_b.clone()])).ok_or("forward pointer")?;
        let backward = cid_of(&converge_ops(&[op_b, op_a])).ok_or("backward pointer")?;
        ensure_eq(
            &forward,
            &backward,
            "same-author (lamport, op_id) reuse still converges to one winner",
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
        // Which author in the pool signs this op; small range so collisions on
        // `(lamport, note)` across authors are common, stressing the tiebreak.
        author_tag: u8,
        // The key epoch this op's blob was sealed under. `converge` carries the
        // winning op's epoch through to `NotePointer`, so varying it proves that
        // carry-through is order-independent too, not only the pointer's `cid`.
        key_epoch: u64,
    }

    fn op_spec_strategy() -> impl Strategy<Value = OpSpec> {
        // `kind_tag` spans 0..7 so generated sets cover EVERY `OpKind`: `Redact`
        // (absorbing OR), `Relate` (relations latest-wins per target — `kind_of`
        // folds `to` to 2 targets while `rel` spans all five `LinkRel`s, so one
        // target receives CONFLICTING rels and permutations stress the max-fold),
        // and `Reinforce` (reinforcers union + last_reinforced max) are all proven
        // order-independent through the existing `converge_is_order_independent` /
        // partition / idempotence proptests — not just by the fixed-order unit
        // tests above.
        (0u128..4, 0u64..6, 0u8..7, 0u128..5, 0u8..3, 0u64..3).prop_map(
            |(note_seq, lamport, kind_tag, link_seq, author_tag, key_epoch)| OpSpec {
                note_seq,
                lamport,
                kind_tag,
                link_seq,
                author_tag,
                key_epoch,
            },
        )
    }

    fn kind_of(spec: &OpSpec) -> OpKind {
        match spec.kind_tag {
            0 => OpKind::Remember,
            1 => OpKind::Edit,
            2 => OpKind::Forget,
            3 => OpKind::Redact,
            4 => OpKind::Link {
                to: note(1000 + spec.link_seq),
            },
            5 => OpKind::Relate {
                // Fold `to` to 2 targets while `rel` spans all five `LinkRel`s, so a
                // single target receives DIFFERENT rels across ops — the case that
                // actually exercises latest-wins REPLACEMENT under permutation. A
                // target-derived rel (one rel per target) would never conflict, so
                // the proptests would pass identically for grow-only or first-wins.
                to: note(1000 + spec.link_seq % 2),
                rel: match spec.link_seq % 5 {
                    0 => LinkRel::Related,
                    1 => LinkRel::Supersedes,
                    2 => LinkRel::Contradicts,
                    3 => LinkRel::Refines,
                    _ => LinkRel::Duplicates,
                },
            },
            _ => OpKind::Reinforce,
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

    // Build one signed op per spec, drawing the author from `signers` and
    // threading the spec's `key_epoch`. `seq = i` keeps every `op_id` unique
    // across the whole set (the honest-writer assumption the `(lamport, op_id)`
    // tiebreak relies on), so reorderings stay true permutations of one multiset.
    // Owns its `Vec<Op>`; borrows `signers`/`specs` read-only.
    fn build_ops(signers: &[Sr25519Signer], specs: &[OpSpec]) -> Vec<Op> {
        specs
            .iter()
            .enumerate()
            .map(|(i, spec)| {
                let signer = &signers[(spec.author_tag as usize) % signers.len()];
                let seq = i as u128;
                Op::create_signed(
                    signer,
                    OpContent {
                        op_id: Ulid::from(seq),
                        lamport: spec.lamport,
                        key_epoch: spec.key_epoch,
                        kind: kind_of(spec),
                        note_id: note(spec.note_seq),
                        object_key: format!("team/global/notes/{seq}"),
                        cid: content_hash(format!("ciphertext-{seq}").as_bytes()),
                        prev_op_hash: Blake3Hash::zero(),
                    },
                )
            })
            .collect()
    }

    // Model a healed network partition: scatter `ops` into three replicas by
    // `assign[i] % 3`, then concatenate the replicas in the order `chunk_order`
    // selects (the same Fisher-Yates-by-removal `permuted` uses, here over the
    // three bucket indices). The result is the SAME multiset, regrouped and
    // chunk-reordered — what a machine sees when it replays partitioned logs.
    fn reassemble_partitions(ops: &[Op], assign: &[usize], chunk_order: &[usize]) -> Vec<Op> {
        let mut buckets: [Vec<Op>; 3] = [Vec::new(), Vec::new(), Vec::new()];
        for (i, op) in ops.iter().enumerate() {
            let bucket = assign.get(i).copied().unwrap_or(0) % buckets.len();
            buckets[bucket].push(op.clone());
        }
        let mut pool: Vec<usize> = (0..buckets.len()).collect();
        let mut order = Vec::with_capacity(buckets.len());
        let mut step = 0;
        while !pool.is_empty() {
            let slot = chunk_order.get(step).copied().unwrap_or(0);
            order.push(pool.remove(slot % pool.len()));
            step += 1;
        }
        let mut out = Vec::with_capacity(ops.len());
        for idx in order {
            out.append(&mut buckets[idx]);
        }
        out
    }

    proptest! {
        // THE invariant of the whole phase: convergence depends only on the SET
        // of ops, never their order. Generate a pool of ops over a few shared
        // note ids — now spread across multiple authors and key epochs — then
        // assert `converge` agrees on the original and an arbitrary permutation.
        #[test]
        fn converge_is_order_independent(
            specs in proptest::collection::vec(op_spec_strategy(), 0..16),
            perm in proptest::collection::vec(0usize..64, 16),
        ) {
            let signers = signers().map_err(|e| TestCaseError::fail(e.to_string()))?;
            let ops = build_ops(&signers, &specs);
            let shuffled = permuted(&ops, &perm);
            prop_assert_eq!(shuffled.len(), ops.len(), "permutation preserves multiset size");
            prop_assert_eq!(converge_ops(&ops), converge_ops(&shuffled));
        }

        // Idempotence: re-observing an op set a machine already holds changes
        // nothing. `converge` reduces by maxima and a set-union, both idempotent,
        // so duplicating the whole log must yield byte-identical state. This is
        // the property that makes re-syncing the shared op-log safe to repeat.
        #[test]
        fn converge_is_idempotent_under_duplication(
            specs in proptest::collection::vec(op_spec_strategy(), 0..16),
        ) {
            let signers = signers().map_err(|e| TestCaseError::fail(e.to_string()))?;
            let ops = build_ops(&signers, &specs);
            let mut doubled = ops.clone();
            doubled.extend(ops.iter().cloned());
            prop_assert_eq!(doubled.len(), ops.len() * 2, "doubling preserves the count");
            prop_assert_eq!(converge_ops(&ops), converge_ops(&doubled));
        }

        // Partition-then-union: splitting the log across replicas and replaying
        // the pieces in any order converges to the same state as the whole log
        // seen at once. The healed log is one multiset reordered, so this is
        // order-independence stated in the partition-replay framing the phase
        // must guarantee across machines.
        #[test]
        fn converge_is_partition_union_invariant(
            specs in proptest::collection::vec(op_spec_strategy(), 0..16),
            assign in proptest::collection::vec(0usize..3, 16),
            chunk_order in proptest::collection::vec(0usize..3, 3),
        ) {
            let signers = signers().map_err(|e| TestCaseError::fail(e.to_string()))?;
            let ops = build_ops(&signers, &specs);
            let reassembled = reassemble_partitions(&ops, &assign, &chunk_order);
            prop_assert_eq!(reassembled.len(), ops.len(), "healing preserves the multiset size");
            prop_assert_eq!(converge_ops(&ops), converge_ops(&reassembled));
        }

        // `VerifiedOps::partition` splits on an arbitrary lamport threshold and
        // `concat` rejoins the halves; the round-trip must lose and invent no op,
        // so the rejoin converges identically to the original set. This is exactly
        // the base/tail split + safety-valve rejoin the incremental sync depends
        // on — a dropped or duplicated op here would silently corrupt a rebuild.
        #[test]
        fn verified_partition_then_concat_preserves_convergence(
            specs in proptest::collection::vec(op_spec_strategy(), 0..16),
            threshold in 0u64..64,
        ) {
            let signers = signers().map_err(|e| TestCaseError::fail(e.to_string()))?;
            let ops = build_ops(&signers, &specs);
            let (base, tail) =
                VerifiedOps::from_verified(ops.clone()).partition(|op| op.lamport <= threshold);
            prop_assert_eq!(base.len() + tail.len(), ops.len(), "partition preserves the multiset size");
            prop_assert_eq!(converge(&base.concat(tail)), converge_ops(&ops));
        }
    }
}
