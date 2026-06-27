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
//! chain alone cannot catch them. The intended mitigation is on-chain anchoring
//! (a root committed publicly pins what existed at a point in time) plus a
//! reconciliation tool that cross-checks each machine's view against the
//! anchored roots — that tool is **not yet built** (future work).

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
    /// Verification (the bucket is untrusted):
    /// 0. objects under the prefix that do not deserialize as an [`Op`] are
    ///    skipped (logged), and exact byte-duplicate ops are deduped by
    ///    [`Op::hash`] before the chain walk — neither aborts the read;
    /// 1. every op's signature must verify against its own `author_key`;
    /// 2. grouped by `author_key`, each author's ops form an unbroken hash chain
    ///    ordered by `(lamport, op_id)` — the first op links to [`GENESIS_PREV`],
    ///    and each later op's `prev_op_hash` equals its predecessor's
    ///    [`Op::hash`];
    /// 3. every op's `object_key` lives under `{team}/` (a transplanted op from
    ///    another team's log is refused even if its signature and chain check out).
    ///
    /// # Errors
    ///
    /// - [`MemError::Storage`] / [`MemError::NotFound`] from the backend;
    /// - [`MemError::Storage`] with `"op signature invalid: …"` for a forged or
    ///   edited op, `"op-log chain broken for author …"` for a chain break that
    ///   survives dedup, or `"… bound to a foreign team …"` for a transplanted op.
    ///
    /// A junk object under the prefix is NOT an error here — it is skipped; only a
    /// cryptographically invalid or transplanted *op* fails the read.
    pub async fn read_all(&self, team: &str) -> Result<Vec<Op>, MemError> {
        self.read_verified(team).await
    }

    /// Like [`OpLogStore::read_all`] but returning only ops with
    /// `lamport > after_lamport`, for incremental sync.
    ///
    /// The full op-log is still read and verified before filtering: a hash chain
    /// can only be checked from its genesis root, and the untrusted-bucket threat
    /// model forbids trusting unread history. So this trades read amplification
    /// for soundness — the saving is in the returned set, not the work.
    ///
    /// # Errors
    ///
    /// Same as [`OpLogStore::read_all`].
    pub async fn read_since(&self, team: &str, after_lamport: u64) -> Result<Vec<Op>, MemError> {
        let mut ops = self.read_verified(team).await?;
        ops.retain(|op| op.lamport > after_lamport);
        Ok(ops)
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

        verify_signatures(&ops)?;
        verify_author_chains(&ops)?;
        verify_team_binding(&ops, team)?;

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

/// Reject any op whose `object_key` is not under `{team}/`.
///
/// Defense-in-depth beside the AEAD-AAD binding in [`crate::crypto::seal`]: an op
/// lifted from a *different* team's log keeps a valid signature and may even
/// chain, but it names a blob outside this team's namespace. Refusing it here
/// stops a transplanted op from being replayed into this team's converged state.
fn verify_team_binding(ops: &[Op], team: &str) -> Result<(), MemError> {
    let team_prefix = format!("{team}/");
    for op in ops {
        if !op.object_key.starts_with(&team_prefix) {
            return Err(MemError::Storage(format!(
                "op {} is bound to a foreign team: object_key {:?} is not under {:?}",
                op.op_id, op.object_key, team_prefix
            )));
        }
    }
    Ok(())
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

/// Reject the whole read if any op's signature does not verify.
fn verify_signatures(ops: &[Op]) -> Result<(), MemError> {
    for op in ops {
        if !op.verify_sig() {
            return Err(MemError::Storage(format!(
                "op signature invalid: {}",
                op.op_id
            )));
        }
    }
    Ok(())
}

/// Group ops by author and verify each author's per-author hash chain.
///
/// The chain is per-author, not global, because the op-log is written
/// concurrently by many machines into one shared bucket: there is no single
/// writer to serialize a global linear chain. Each author instead links only
/// their own ops (`prev_op_hash` → predecessor's [`Op::hash`]), which a lone
/// author can always maintain locally; the Lamport clock then supplies the
/// cross-author ordering that convergence (Task 13) builds on.
fn verify_author_chains(ops: &[Op]) -> Result<(), MemError> {
    // BTreeMap (not HashMap) keyed by the raw public-key bytes: deterministic
    // iteration makes the "which author broke" error reproducible run to run.
    let mut by_author: BTreeMap<[u8; 32], Vec<&Op>> = BTreeMap::new();
    for op in ops {
        by_author
            .entry(*op.author_key.as_bytes())
            .or_default()
            .push(op);
    }

    for chain in by_author.values_mut() {
        chain.sort_by_key(|op| (op.lamport, op.op_id));
        verify_one_chain(chain)?;
    }
    Ok(())
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
        Blake3Hash, BlobStore, MemoryBlobStore, NoteId, Op, OpContent, OpKind, Sr25519Signer, Ss58,
        content_hash,
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

    // A valid SS58 v42 address (Alice), 48 base58 chars — passes `Ss58::new`.
    const ALICE_SS58: &str = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";

    fn signer(seed: u8) -> Result<Sr25519Signer, Box<dyn std::error::Error>> {
        let author = Ss58::new(ALICE_SS58)?;
        Ok(Sr25519Signer::from_seed([seed; 32], author)?)
    }

    /// Build the next properly-chained signed op for `signer`, advancing `prev`
    /// to this op's hash so the caller can keep extending the chain. `seq` makes
    /// each op's id and ciphertext distinct.
    fn chain(signer: &Sr25519Signer, prev: &mut Blake3Hash, lamport: u64, seq: u128) -> Op {
        let content = OpContent {
            op_id: Ulid::from(seq),
            lamport,
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
    async fn forged_signature_is_rejected() -> TestResult {
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

        let err = store
            .read_all("team")
            .await
            .err()
            .ok_or("expected a rejection")?;
        ensure(
            format!("{err}").contains("signature invalid"),
            "a tampered op must be rejected as a bad signature",
        )
    }

    #[tokio::test]
    async fn broken_chain_is_rejected() -> TestResult {
        let store = OpLogStore::new(Arc::new(MemoryBlobStore::new()));
        let s = signer(3)?;

        // First op links to genesis; second op's prev is wrong (still genesis
        // instead of first.hash()), so the second op is signed-but-unlinked.
        let mut prev = GENESIS_PREV;
        let first = chain(&s, &mut prev, 0, 1);
        let mut wrong_prev = GENESIS_PREV;
        let second = chain(&s, &mut wrong_prev, 1, 2);

        store.append("team", &first).await?;
        store.append("team", &second).await?;

        let err = store
            .read_all("team")
            .await
            .err()
            .ok_or("expected a rejection")?;
        ensure(
            format!("{err}").contains("chain broken"),
            "a mislinked op must be rejected as a broken chain",
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
    async fn op_bound_to_foreign_team_is_rejected() -> TestResult {
        let blob = Arc::new(MemoryBlobStore::new());
        let store = OpLogStore::new(blob.clone());
        let s = signer(13)?;
        // A properly signed, genesis-rooted op whose `object_key` names a DIFFERENT
        // team — a transplanted op (valid signature + chain, foreign namespace).
        let content = OpContent {
            op_id: Ulid::from(1u128),
            lamport: 0,
            kind: OpKind::Remember,
            note_id: NoteId::from(Ulid::from(1u128)),
            object_key: "otherteam/global/notes/1".to_string(),
            cid: content_hash(b"ciphertext"),
            prev_op_hash: GENESIS_PREV,
        };
        let op = Op::create_signed(&s, content);
        store.append("team", &op).await?;

        let err = store
            .read_all("team")
            .await
            .err()
            .ok_or("expected a rejection")?;
        ensure(
            format!("{err}").contains("foreign team"),
            "an op whose object_key is under another team must be rejected",
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

    #[tokio::test]
    async fn read_since_filters_by_lamport() -> TestResult {
        let store = OpLogStore::new(Arc::new(MemoryBlobStore::new()));
        let s = signer(6)?;
        let mut prev = GENESIS_PREV;
        for i in 0..5 {
            let op = chain(&s, &mut prev, i, u128::from(i) + 1);
            store.append("team", &op).await?;
        }

        let read = store.read_since("team", 2).await?;
        let lamports: Vec<u64> = read.iter().map(|op| op.lamport).collect();
        ensure_eq(&lamports, &vec![3, 4], "only ops strictly after lamport 2")
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
