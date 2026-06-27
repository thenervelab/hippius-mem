//! The append-only op-log store: write ops as immutable blobs, read them back
//! with integrity checks.
//!
//! Phase 2's threat model treats the shared team bucket as untrusted: a peer (or
//! the storage provider) may add, edit, or drop objects under the op-log prefix.
//! So [`OpLogStore::read_all`] re-derives trust from the ops themselves on every
//! read — it verifies each op's signature and walks each author's hash chain —
//! rather than trusting that what was written is what comes back.
//!
//! # What the per-author hash chain does and does not detect
//!
//! The signature + per-author `prev_op_hash` chain is tamper-*evidence within an
//! author's own chain*. It DETECTS:
//! - in-place tampering (an edited field breaks the signature);
//! - mid-chain deletion (a removed op leaves the next op's `prev_op_hash`
//!   dangling — a chain break);
//! - reordering within an author's chain (the `prev` links no longer form a line).
//!
//! It does NOT detect:
//! - **tail-truncation** — dropping the most recent ops of an author leaves a
//!   shorter but still-valid chain; nothing pins "this is the latest";
//! - **whole-author suppression** — hiding every object of one author makes that
//!   author's writes simply absent, with no gap to notice;
//! - **split-view / equivocation** — serving different readers different subsets
//!   so they converge to different states.
//!
//! Those are *availability/suppression* attacks, not integrity attacks, and the
//! chain alone cannot catch them. The mitigation is on-chain anchoring (a root
//! committed publicly pins what existed at a point in time) plus a reconciliation
//! tool that cross-checks each machine's view against the anchored roots — built
//! in [`crate::audit::reconcile`]. It detects suppression of *anchored* ops; with
//! the `chain` feature the roots are read back from the chain, so even a bucket
//! that forges a self-consistent anchor record is caught (see that module).

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use crate::{Blake3Hash, BlobStore, MemError, Op};

/// The `prev_op_hash` of every author's first op.
///
/// An all-zero digest is BLAKE3-unreachable for real input (see
/// [`Blake3Hash::zero`]), so it unambiguously marks a chain root: the first op
/// an author ever appends has no predecessor to link to.
pub const GENESIS_PREV: Blake3Hash = Blake3Hash::zero();

/// Append-only store for the signed, hash-chained op-log of one or more teams.
///
/// Holds a shared [`BlobStore`] handle; it is cheap to clone the `Arc` and share
/// the store across async tasks. The store itself keeps no per-team state — the
/// `team` argument on each method selects the object-key prefix — so a single
/// instance serves every team reachable through `blob`.
#[derive(Clone)]
pub struct OpLogStore {
    blob: Arc<dyn BlobStore>,
}

impl std::fmt::Debug for OpLogStore {
    // `dyn BlobStore` is not `Debug`; name the type without trying to render the
    // backend so `OpLogStore` can still satisfy `missing_debug_implementations`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpLogStore").finish_non_exhaustive()
    }
}

impl OpLogStore {
    /// Build a store over the shared blob backend `blob`.
    #[must_use]
    pub fn new(blob: Arc<dyn BlobStore>) -> Self {
        Self { blob }
    }

    /// Append `op` to `team`'s op-log.
    ///
    /// "Append" means writing a new immutable object: the key embeds `op`'s
    /// Lamport time and unique id, so two distinct ops never collide and an
    /// existing op is never overwritten. The op-log is therefore grow-only —
    /// rewriting history would require forging a signature, which
    /// [`OpLogStore::read_all`] rejects.
    ///
    /// # Errors
    ///
    /// Returns [`MemError::Serialize`] if `op` cannot be encoded, or
    /// [`MemError::Storage`] if the backend write fails.
    pub async fn append(&self, team: &str, op: &Op) -> Result<(), MemError> {
        let key = object_key(team, op);
        let bytes = serde_json::to_vec(op)?;
        self.blob.put(&key, bytes).await
    }

    /// Read and verify every op in `team`'s op-log, returned in global logical
    /// order: ascending `(lamport, op_id)`.
    ///
    /// Verification (the bucket is untrusted) — every check is *resilient*: a bad
    /// object is dropped with a `tracing::warn!`, never an abort, so one forged,
    /// transplanted, or forked object cannot blind the whole team (I2):
    /// 0. objects that do not deserialize as an [`Op`] are skipped, and exact
    ///    byte-duplicate ops are deduped by [`Op::hash`] before the chain walk;
    /// 1. each op whose signature does not verify against its own `author_key`, or
    ///    whose `author` SS58 does not decode to that `author_key` (cryptographic
    ///    attribution — a writer cannot sign as one key but claim another's SS58),
    ///    is dropped individually;
    /// 2. each op whose `object_key` is not under `{team}/` is dropped (a
    ///    transplanted op from another team's log, defense-in-depth beside the
    ///    AEAD-AAD binding);
    /// 3. grouped by `author_key`, each author's ops must form an unbroken hash
    ///    chain ordered by `(lamport, op_id)` — first op links to [`GENESIS_PREV`],
    ///    each later op's `prev_op_hash` equals its predecessor's [`Op::hash`]. An
    ///    author whose chain breaks (a fork, or a dropped mid-chain op) is
    ///    QUARANTINED — all their ops dropped — while every other author survives.
    ///
    /// Dropping a bad op is suppression of that op, an availability gap the module
    /// header already concedes to on-chain anchoring + reconciliation; it is
    /// strictly safer than the old whole-team abort, which a single bucket write
    /// could trigger.
    ///
    /// # Errors
    ///
    /// [`MemError::Storage`] / [`MemError::NotFound`] from the backend `list`/`get`
    /// only — the verification steps above drop bad ops rather than erroring.
    pub async fn read_all(&self, team: &str) -> Result<Vec<Op>, MemError> {
        self.read_verified(team).await
    }

    /// Read, verify, and globally order `team`'s op-log. Shared by the public
    /// readers so they cannot diverge on what "verified" means.
    ///
    /// Resilience over the untrusted bucket: an object under the prefix that does
    /// not deserialize as an [`Op`] is skipped with a `tracing::warn!` rather than
    /// failing the whole read (one junk upload must not blind the team), and exact
    /// byte-duplicate ops are deduped by [`Op::hash`] *before* chain verification
    /// so a replayed copy is not mistaken for a chain fork. A break that survives
    /// the dedup is genuine tamper-evidence and still errors.
    async fn read_verified(&self, team: &str) -> Result<Vec<Op>, MemError> {
        let prefix = oplog_prefix(team);
        let keys = self.blob.list(&prefix).await?;

        let mut ops = Vec::with_capacity(keys.len());
        for key in &keys {
            let bytes = self.blob.get(key).await?;
            match serde_json::from_slice::<Op>(&bytes) {
                Ok(op) => ops.push(op),
                // A junk object under the op-log prefix (foreign write, truncated
                // upload) is a per-object data fault: skip it, don't abort the read
                // for the whole team. A genuine bad op still fails the crypto checks.
                Err(err) => tracing::warn!(
                    object_key = %key,
                    error = %err,
                    "skipping object under the op-log prefix that does not deserialize as an Op"
                ),
            }
        }

        // Dedup BEFORE chain verification: a byte-identical copy of a valid op
        // shares its `prev_op_hash`, so two copies look like a fork to the chain
        // walk. Collapsing them by `Op::hash` makes a benign replay a no-op while
        // leaving a real reorder/deletion/edit to be caught below.
        dedup_by_hash(&mut ops);

        // Resilience over the untrusted bucket (I2): an op that fails an INDIVIDUAL
        // check — invalid signature, author SS58 that does not decode to its key,
        // or a foreign-team `object_key` — is indistinguishable from junk the
        // bucket injected, so it is dropped with a warn, exactly like an
        // undeserializable object above. A whole-read abort here would let one
        // forged or transplanted object deny every member their verified log.
        retain_individually_valid(&mut ops, team);

        // A broken or forked author chain QUARANTINES that author — all their ops
        // are dropped with a warn and every other author's ops are kept — so one
        // member equivocating, or the bucket dropping one mid-chain object, cannot
        // blind the whole team. Suppression of the quarantined author is already a
        // conceded availability gap (see the module header) that anchoring +
        // reconciliation cover; blinding the team was not, and is what this closes.
        quarantine_broken_chains(&mut ops);

        // Global logical order: Lamport time first, op_id as a deterministic
        // tie-break across authors (ULIDs are ordered, so this is stable).
        ops.sort_by_key(|op| (op.lamport, op.op_id));
        Ok(ops)
    }
}

/// Drop exact-duplicate ops, keeping the first occurrence of each [`Op::hash`].
///
/// `Op::hash` covers every signed field plus the signature, so equal hashes mean
/// byte-identical ops; deduping them is sound and idempotent.
fn dedup_by_hash(ops: &mut Vec<Op>) {
    let mut seen = HashSet::with_capacity(ops.len());
    ops.retain(|op| seen.insert(op.hash()));
}

/// Drop every op that fails an INDIVIDUAL integrity check, keeping the rest.
///
/// Three per-op checks, each a junk signature the untrusted bucket could have
/// injected and so a drop-with-warn rather than a whole-read abort (I2):
/// - the signature must verify against the op's own `author_key`;
/// - the `author` SS58 must decode to exactly that `author_key` (attribution: a
///   writer cannot sign with one key but claim another's address);
/// - the `object_key` must live under `{team}/` — defense-in-depth beside the
///   AEAD-AAD binding in [`crate::crypto::seal`], refusing an op transplanted
///   from a different team's log even when its signature and chain check out.
///
/// These are per-op, not per-author: dropping one forged object attributed to an
/// author's key must NOT drop that author's honest ops, or the bucket could
/// suppress any author by injecting one bad op under their key.
fn retain_individually_valid(ops: &mut Vec<Op>, team: &str) {
    let team_prefix = format!("{team}/");
    ops.retain(|op| {
        if !op.verify_sig() {
            tracing::warn!(op_id = %op.op_id, "dropping op with an invalid signature");
            return false;
        }
        if !op.verify_identity() {
            tracing::warn!(
                op_id = %op.op_id,
                "dropping op whose author SS58 does not decode to its signing key"
            );
            return false;
        }
        if !op.object_key.starts_with(&team_prefix) {
            tracing::warn!(
                op_id = %op.op_id,
                object_key = %op.object_key,
                "dropping op bound to a foreign team"
            );
            return false;
        }
        true
    });
}

/// Quarantine any author whose per-author hash chain is broken, keeping every
/// other author's ops.
///
/// Ops are grouped by `author_key` and each group is checked with
/// [`verify_one_chain`]; an author whose chain breaks — a fork (two ops sharing a
/// `prev_op_hash`) or a missing mid-chain op — has ALL their ops dropped with a
/// warn (I2). The whole-team read no longer aborts on one broken chain, so a
/// single member equivocating, or the bucket corrupting one author's object,
/// cannot deny every reader their verified log. Dropping the quarantined author
/// is the same availability gap as whole-author suppression, which the module
/// header already concedes to anchoring + reconciliation.
fn quarantine_broken_chains(ops: &mut Vec<Op>) {
    // Group by author into index lists, then verify each chain over borrows; a
    // BTreeMap keeps the "which author broke" warning order reproducible.
    let mut by_author: BTreeMap<[u8; 32], Vec<usize>> = BTreeMap::new();
    for (i, op) in ops.iter().enumerate() {
        by_author
            .entry(*op.author_key.as_bytes())
            .or_default()
            .push(i);
    }

    let mut quarantined: HashSet<[u8; 32]> = HashSet::new();
    for (author, mut idxs) in by_author {
        idxs.sort_by_key(|&i| (ops[i].lamport, ops[i].op_id));
        let chain: Vec<&Op> = idxs.iter().map(|&i| &ops[i]).collect();
        if let Err(err) = verify_one_chain(&chain) {
            tracing::warn!(
                error = %err,
                "quarantining an author whose op-log chain is broken; the rest of the team still converges"
            );
            quarantined.insert(author);
        }
    }

    if !quarantined.is_empty() {
        ops.retain(|op| !quarantined.contains(op.author_key.as_bytes()));
    }
}

/// The object-key prefix under which `team`'s ops live.
fn oplog_prefix(team: &str) -> String {
    format!("{team}/_oplog/")
}

/// The object key for `op` in `team`'s op-log.
///
/// `{team}/_oplog/{lamport:020}_{op_id}`: the Lamport value is zero-padded to 20
/// digits — the width of `u64::MAX` (18446744073709551615) — so every key has a
/// fixed-width numeric field and the backend's lexicographic key order matches
/// ascending Lamport order. `op_id` (a ULID, itself time-sortable) disambiguates
/// ops that share a Lamport tick.
fn object_key(team: &str, op: &Op) -> String {
    format!("{team}/_oplog/{:020}_{}", op.lamport, op.op_id)
}

/// Verify a single author's ops form an unbroken chain. `chain` is pre-sorted by
/// `(lamport, op_id)` and non-empty per author group.
fn verify_one_chain(chain: &[&Op]) -> Result<(), MemError> {
    let mut expected_prev = GENESIS_PREV;
    for op in chain {
        if op.prev_op_hash != expected_prev {
            return Err(MemError::Storage(format!(
                "op-log chain broken for author {}: op {} expected prev {}, found {}",
                op.author.as_str(),
                op.op_id,
                expected_prev.to_hex(),
                op.prev_op_hash.to_hex(),
            )));
        }
        expected_prev = op.hash();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{GENESIS_PREV, OpLogStore, object_key};
    use crate::{
        Blake3Hash, BlobStore, MemoryBlobStore, NoteId, Op, OpContent, OpKind, Signer,
        Sr25519Signer, content_hash,
    };
    use proptest::prelude::*;
    use proptest::test_runner::TestCaseError;
    use std::sync::Arc;
    use ulid::Ulid;

    /// Fallible-fixture result: the crate denies `panic_in_result_fn`, so tests
    /// report failures by returning `Err` rather than via `assert!`.
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Adapt a fallible fixture call into proptest's error type (proptest
    /// closures cannot use `?` on arbitrary errors directly).
    fn tce(e: impl std::fmt::Display) -> TestCaseError {
        TestCaseError::fail(e.to_string())
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

    fn signer(seed: u8) -> Result<Sr25519Signer, Box<dyn std::error::Error>> {
        // Derive the author SS58 from the key, so every minted op's `author`
        // decodes back to its `author_key` and passes the identity binding.
        Ok(Sr25519Signer::from_seed_with_prefix([seed; 32], 42)?)
    }

    /// Build the next properly-chained signed op for `signer`, advancing `prev`
    /// to this op's hash so the caller can keep extending the chain. `seq` makes
    /// each op's id and ciphertext distinct.
    fn chain(signer: &Sr25519Signer, prev: &mut Blake3Hash, lamport: u64, seq: u128) -> Op {
        let content = OpContent {
            op_id: Ulid::from(seq),
            lamport,
            key_epoch: 0,
            kind: OpKind::Remember,
            note_id: NoteId::from(Ulid::from(seq)),
            object_key: format!("team/global/notes/{seq}"),
            cid: content_hash(format!("ciphertext-{seq}").as_bytes()),
            prev_op_hash: *prev,
        };
        let op = Op::create_signed(signer, content);
        *prev = op.hash();
        op
    }

    #[tokio::test]
    async fn append_then_read_all_returns_ordered_ops() -> TestResult {
        let store = OpLogStore::new(Arc::new(MemoryBlobStore::new()));
        let s = signer(1)?;
        let mut prev = GENESIS_PREV;
        let ops: Vec<Op> = (0..3)
            .map(|i| chain(&s, &mut prev, i, u128::from(i) + 1))
            .collect();

        // Append out of order; read_all must still return ascending lamport.
        for op in ops.iter().rev() {
            store.append("team", op).await?;
        }

        let read = store.read_all("team").await?;
        ensure_eq(&read.len(), &3, "all three ops come back")?;
        let lamports: Vec<u64> = read.iter().map(|op| op.lamport).collect();
        ensure_eq(&lamports, &vec![0, 1, 2], "ops returned in lamport order")
    }

    #[tokio::test]
    async fn empty_oplog_reads_empty() -> TestResult {
        let store = OpLogStore::new(Arc::new(MemoryBlobStore::new()));
        let read = store.read_all("team").await?;
        ensure(read.is_empty(), "an unwritten op-log reads back empty")
    }

    #[tokio::test]
    async fn forged_signature_is_dropped() -> TestResult {
        let blob = Arc::new(MemoryBlobStore::new());
        let store = OpLogStore::new(blob.clone());
        let s = signer(2)?;
        let mut prev = GENESIS_PREV;
        let mut op = chain(&s, &mut prev, 0, 1);

        // Tamper with a signed field *after* signing: the bytes on the wire no
        // longer match the signature, exactly the forged/edited-op case.
        op.lamport = 99;
        // Write the tampered op directly so the key still falls under the prefix.
        let bytes = serde_json::to_vec(&op)?;
        blob.put(
            "team/_oplog/00000000000000000099_00000000000000000000000000000001",
            bytes,
        )
        .await?;

        // Fail-soft (I2): the tampered op is dropped with a warn, not an abort, so
        // its presence cannot blind the team. It was the only op, so the read is
        // empty rather than an error.
        let read = store.read_all("team").await?;
        ensure(read.is_empty(), "the tampered op is dropped, not surfaced")
    }

    #[tokio::test]
    async fn op_with_mismatched_author_is_dropped() -> TestResult {
        // Cryptographic attribution: an op may carry a VALID signature yet claim a
        // different writer's SS58. Sign as A (so `verify_sig` passes), then swap the
        // `author` label to B's address and re-sign — the signature is sound but the
        // human identity no longer decodes to the signing key. `read_all` must reject
        // it: you cannot sign as one key but claim another's identity.
        let blob = Arc::new(MemoryBlobStore::new());
        let store = OpLogStore::new(blob.clone());
        let a = signer(1)?;
        let b = signer(2)?;

        let mut prev = GENESIS_PREV;
        let mut op = chain(&a, &mut prev, 0, 1);
        op.author = b.author_ss58();
        op.sig = a.sign(&op.signing_bytes());
        ensure(
            op.verify_sig(),
            "the re-signed op must still carry a valid signature",
        )?;
        ensure(
            !op.verify_identity(),
            "the swapped author must not decode to the signing key",
        )?;

        blob.put(
            "team/_oplog/00000000000000000000_00000000000000000000000000000001",
            serde_json::to_vec(&op)?,
        )
        .await?;

        // Fail-soft (I2): the mis-attributed op is dropped, not surfaced.
        let read = store.read_all("team").await?;
        ensure(
            read.is_empty(),
            "an op whose author SS58 does not decode to its signing key is dropped",
        )
    }

    #[tokio::test]
    async fn op_with_bound_author_passes() -> TestResult {
        // The complement: a normally minted op derives its author from the signer,
        // so its SS58 decodes to its key, `verify_identity` holds, and it reads back.
        let store = OpLogStore::new(Arc::new(MemoryBlobStore::new()));
        let s = signer(3)?;
        let mut prev = GENESIS_PREV;
        let op = chain(&s, &mut prev, 0, 1);
        ensure(
            op.verify_identity(),
            "a minted op's author is bound to its key",
        )?;

        store.append("team", &op).await?;
        let read = store.read_all("team").await?;
        ensure_eq(&read.len(), &1, "a bound-author op reads back")
    }

    #[tokio::test]
    async fn broken_chain_quarantines_author_without_blinding_the_team() -> TestResult {
        // I2 regression: one author forks/breaks their chain while another writes
        // honestly. The broken author is quarantined (their ops dropped), but the
        // honest author's ops must still come back — a single broken chain must not
        // deny the whole team its verified log.
        let store = OpLogStore::new(Arc::new(MemoryBlobStore::new()));
        let bad = signer(3)?;
        let good = signer(8)?;

        // `bad`: two ops both linking to genesis — a fork at the root that
        // verify_one_chain rejects.
        let mut bad_prev = GENESIS_PREV;
        let bad_first = chain(&bad, &mut bad_prev, 0, 1);
        let mut bad_wrong = GENESIS_PREV;
        let bad_second = chain(&bad, &mut bad_wrong, 3, 2);

        // `good`: a clean two-op chain.
        let mut good_prev = GENESIS_PREV;
        let good_first = chain(&good, &mut good_prev, 1, 10);
        let good_second = chain(&good, &mut good_prev, 4, 11);

        for op in [&bad_first, &bad_second, &good_first, &good_second] {
            store.append("team", op).await?;
        }

        let read = store.read_all("team").await?;
        ensure_eq(
            &read.len(),
            &2,
            "the honest author's two ops survive; the broken author is quarantined",
        )?;
        ensure(
            read.iter().all(|op| op.author == good.author_ss58()),
            "only the honest author's ops remain after quarantine",
        )
    }

    #[tokio::test]
    async fn duplicate_op_object_is_deduped_not_an_error() -> TestResult {
        let blob = Arc::new(MemoryBlobStore::new());
        let store = OpLogStore::new(blob.clone());
        let s = signer(11)?;
        let mut prev = GENESIS_PREV;
        let op = chain(&s, &mut prev, 0, 1);

        // Append normally, then write a byte-identical copy under a SECOND key in
        // the prefix — a replayed/duplicated upload over the untrusted bucket.
        store.append("team", &op).await?;
        let bytes = serde_json::to_vec(&op)?;
        blob.put("team/_oplog/00000000000000000000_duplicate", bytes)
            .await?;

        // The copy shares the genesis `prev`, which would look like a fork; dedup
        // by `Op::hash` collapses it, so the read succeeds with exactly one op.
        let read = store.read_all("team").await?;
        ensure_eq(&read.len(), &1, "the duplicate op is deduped to one")
    }

    #[tokio::test]
    async fn undeserializable_object_under_prefix_is_skipped() -> TestResult {
        let blob = Arc::new(MemoryBlobStore::new());
        let store = OpLogStore::new(blob.clone());
        let s = signer(12)?;
        let mut prev = GENESIS_PREV;
        let op = chain(&s, &mut prev, 0, 1);
        store.append("team", &op).await?;

        // Junk bytes under the op-log prefix: not a valid `Op` JSON.
        blob.put("team/_oplog/not-an-op", b"{ not json".to_vec())
            .await?;

        // The junk is skipped (logged), and the valid op still comes back — one
        // bad object must not blind the whole team's verified log.
        let read = store.read_all("team").await?;
        ensure_eq(
            &read.len(),
            &1,
            "the junk object is skipped, the valid op remains",
        )
    }

    #[tokio::test]
    async fn op_bound_to_foreign_team_is_dropped() -> TestResult {
        let blob = Arc::new(MemoryBlobStore::new());
        let store = OpLogStore::new(blob.clone());
        let s = signer(13)?;
        // A properly signed, genesis-rooted op whose `object_key` names a DIFFERENT
        // team — a transplanted op (valid signature + chain, foreign namespace).
        let content = OpContent {
            op_id: Ulid::from(1u128),
            lamport: 0,
            key_epoch: 0,
            kind: OpKind::Remember,
            note_id: NoteId::from(Ulid::from(1u128)),
            object_key: "otherteam/global/notes/1".to_string(),
            cid: content_hash(b"ciphertext"),
            prev_op_hash: GENESIS_PREV,
        };
        let op = Op::create_signed(&s, content);
        store.append("team", &op).await?;

        // Fail-soft (I2): the transplanted op is dropped, not surfaced.
        let read = store.read_all("team").await?;
        ensure(
            read.is_empty(),
            "an op whose object_key is under another team is dropped",
        )
    }

    #[tokio::test]
    async fn multi_author_interleaved_chains_verify() -> TestResult {
        let store = OpLogStore::new(Arc::new(MemoryBlobStore::new()));
        let alice = signer(4)?;
        let bob = signer(5)?;

        let mut a_prev = GENESIS_PREV;
        let mut b_prev = GENESIS_PREV;
        // Interleave lamports across the two independent chains: 0,2,4 vs 1,3,5.
        let a_ops: Vec<Op> = (0..3)
            .map(|i| chain(&alice, &mut a_prev, i * 2, 100 + u128::from(i)))
            .collect();
        let b_ops: Vec<Op> = (0..3)
            .map(|i| chain(&bob, &mut b_prev, i * 2 + 1, 200 + u128::from(i)))
            .collect();

        for op in a_ops.iter().chain(b_ops.iter()) {
            store.append("team", op).await?;
        }

        let read = store.read_all("team").await?;
        ensure_eq(&read.len(), &6, "both authors' ops come back")?;
        let lamports: Vec<u64> = read.iter().map(|op| op.lamport).collect();
        ensure_eq(
            &lamports,
            &vec![0, 1, 2, 3, 4, 5],
            "interleaved ops globally ordered",
        )
    }

    proptest! {
        /// The key scheme's load-bearing invariant: lexicographic key order — the
        /// order the blob store lists keys in — must equal logical
        /// `(lamport, op_id)` order, so a read sees ops in Lamport order. The
        /// `{lamport:020}` fixed width is what makes the numeric field sort as a
        /// string; this asserts it across the full `u64` / ULID range.
        #[test]
        fn object_key_lexical_order_matches_logical_order(
            la in any::<u64>(),
            sa in any::<u128>(),
            lb in any::<u64>(),
            sb in any::<u128>(),
        ) {
            let s = signer(7).map_err(tce)?;
            let (mut pa, mut pb) = (GENESIS_PREV, GENESIS_PREV);
            let oa = chain(&s, &mut pa, la, sa);
            let ob = chain(&s, &mut pb, lb, sb);
            prop_assert_eq!(
                object_key("team", &oa).cmp(&object_key("team", &ob)),
                (la, oa.op_id).cmp(&(lb, ob.op_id)),
            );
        }
    }
}
