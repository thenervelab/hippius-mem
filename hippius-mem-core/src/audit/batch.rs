//! Persisted records of anchored op-log batches.
//!
//! Each time the scheduler ([`crate::store::MemoryStore`]) anchors a batch's
//! Merkle root, it writes one [`AnchorRecord`] to the blob store under the team's
//! `_anchors/` prefix. The record keeps the batch's *ordered leaves* (the op
//! hashes) next to the root and receipt, because
//! [`crate::store::MemoryStore::history`] needs them to rebuild a Merkle
//! inclusion proof for any single op long after the batch was sealed — the root
//! alone is an opaque commitment no reader could open.

use std::collections::HashSet;
use std::sync::Arc;

use futures_util::StreamExt;
use serde::{Deserialize, Serialize};

use crate::audit::anchor::{AnchorReceipt, BatchMeta};
use crate::domain::Blake3Hash;
use crate::error::MemError;
use crate::oplog::VerifyingKey;
use crate::store::BlobStore;

/// Bounded concurrency for the anchor-record fetch, matching the op-log read's
/// `OPLOG_FETCH_CONCURRENCY`: the records are validated and then sorted, so fetch
/// order is irrelevant, and concurrent GETs turn an O(records) serial round-trip
/// (grown over the team's lifetime) into bounded parallel I/O.
const ANCHOR_FETCH_CONCURRENCY: usize = 64;

/// One anchored batch, persisted so `history` can later prove any op it covers.
///
/// `leaves` are the batch's op hashes in the exact order the Merkle tree was
/// built over — pending-push order, which races op-append under concurrent
/// writers, so it is NOT necessarily Lamport/append order — so
/// `inclusion_proof(&record.leaves, i)`
/// reproduces the proof for the op at position `i` under `record.root`. The
/// `meta`/`receipt` pair records what was committed and where it landed.
///
/// `author_key` makes the record self-describing and namespaces its object key:
/// `seq` is monotonic *per author*, so without the key two machines (or two runs
/// of one machine) would both start at `seq 0` and overwrite each other's proof
/// material. The key is therefore `{team}/_anchors/{author_key}/{seq:020}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorRecord {
    /// Monotonic-per-author sequence number of this batch.
    pub seq: u64,
    /// The sr25519 public key of the author that anchored this batch — the
    /// namespace its object key lives under, and the identity it is attributed to.
    pub author_key: VerifyingKey,
    /// The Merkle root anchored for this batch.
    pub root: Blake3Hash,
    /// The batch metadata committed alongside the root (team + Lamport range).
    pub meta: BatchMeta,
    /// The op hashes (leaves) in the order the Merkle tree was built over — what
    /// proves inclusion later.
    pub leaves: Vec<Blake3Hash>,
    /// The anchoring outcome: the root and where it was committed.
    pub receipt: AnchorReceipt,
}

/// Object-key prefix under which a team's anchor records live.
///
/// Spans every author: records nest one level deeper under
/// `{author_key}/{seq}`, and the blob store's `list` is prefix-recursive (no
/// delimiter), so listing this prefix returns every author's records — what
/// `history` needs to find whichever author anchored a given op.
fn anchors_prefix(team: &str) -> String {
    format!("{team}/_anchors/")
}

/// Object key for `author_key`'s anchor record at `seq`.
///
/// `{team}/_anchors/{author_key}/{seq:020}`: namespacing by the author's public
/// key keeps each writer's monotonic seq in its own keyspace, so two machines (or
/// two runs of one) never overwrite each other's records. `seq` is zero-padded to
/// 20 digits (the width of `u64::MAX`) so the backend's lexicographic `list`
/// order coincides with numeric `seq` order WITHIN an author — the same
/// fixed-width-key trick the op-log uses.
fn anchor_record_key(team: &str, author_key: &VerifyingKey, seq: u64) -> String {
    format!("{team}/_anchors/{}/{seq:020}", author_key.to_hex())
}

/// Persist `rec` as JSON under its author's `_anchors/` namespace.
///
/// # Errors
///
/// Returns [`MemError::Serialize`] if the record cannot be encoded, or
/// [`MemError::Storage`] if the blob write fails.
pub async fn persist_anchor_record(
    blob: &Arc<dyn BlobStore>,
    team: &str,
    rec: &AnchorRecord,
) -> Result<(), MemError> {
    let bytes = serde_json::to_vec(rec)?;
    blob.put(&anchor_record_key(team, &rec.author_key, rec.seq), bytes)
        .await
}

/// Whether `author_key` already has a persisted anchor record at `seq`.
///
/// `BlobStore` has no conditional/if-absent put, so this GET-before-PUT is what
/// gives [`persist_anchor_record`]'s caller fail-on-exists semantics instead of
/// the blind overwrite a bare `put` would perform. It is sound only under the
/// caller's discipline: [`crate::store::MemoryStore`] calls this and the
/// following `persist_anchor_record` under one continuously-held cross-process
/// [`WriterLock`](crate::oplog::WriterLock) acquisition, so no other
/// same-identity process on this machine can persist to `seq` in between this
/// check and that write. Without the lock (or across two machines, which no
/// local lock can see) this check alone cannot close the race — it only turns
/// what would have been a silent overwrite into a detected collision the caller
/// can retry under a fresh seq.
///
/// # Errors
///
/// Whatever the underlying [`BlobStore::get`] reports, except a missing key —
/// that is the expected "free to use" answer and returns `Ok(false)`.
pub(crate) async fn anchor_record_exists(
    blob: &Arc<dyn BlobStore>,
    team: &str,
    author_key: &VerifyingKey,
    seq: u64,
) -> Result<bool, MemError> {
    match blob.get(&anchor_record_key(team, author_key, seq)).await {
        Ok(_bytes) => Ok(true),
        Err(MemError::NotFound { .. }) => Ok(false),
        Err(other) => Err(other),
    }
}

/// Read every anchor record for `team` across ALL authors, in a deterministic
/// `(author_key, seq)` order.
///
/// Used by `history` to find the anchored batch covering a given op, regardless
/// of which teammate anchored it. The listing is prefix-recursive so it spans
/// every `{author_key}/` namespace; the explicit `sort_by_key` re-asserts a
/// stable order — by author, then ascending seq within an author — independent of
/// backend listing quirks. (`seq` alone is no longer globally unique, since it is
/// monotonic per author, so the author key leads the sort.)
///
/// A single malformed object under the anchors prefix is SKIPPED with a warn, not
/// fatal: a record that does not decode, carries no `leaves`, has a `root` that
/// disagrees with its `receipt.root`, a `meta.op_count` that disagrees with its
/// `leaves` length, or a duplicate leaf (an odd-node duplication forging a
/// second-preimage-equal root) is dropped. Aborting the whole read on those let a
/// single planted object brick `history`/`reconcile`/anchoring for the team — and
/// let an attacker make `reconcile` error instead of reporting a suppression. The
/// `root`-vs-`merkle_root(leaves)` binding is enforced where a proof is built
/// (`anchor_proof_for`) and surveyed (`reconcile`), NOT here, so a forged-but-self-
/// consistent record still flows through to be reported rather than silently dropped.
///
/// # Errors
///
/// Returns [`MemError::Storage`] only if the prefix listing fails or a listed
/// object's GET fails — a transient fault, retried on the next read, distinct from
/// the permanent malformations skipped above.
pub async fn read_anchor_records(
    blob: &Arc<dyn BlobStore>,
    team: &str,
) -> Result<Vec<AnchorRecord>, MemError> {
    let keys = blob.list(&anchors_prefix(team)).await?;
    // Fetch every record object with bounded concurrency instead of one blocking
    // GET at a time — fetch order does not affect the result (the whole set is
    // validated and then sorted below). Mirrors `OpLogStore::read_verified` (which
    // needs an intermediate clone to escape `&self`; here `blob` is a `&Arc` that
    // outlives the stream, so each future clones from it directly).
    let mut fetched: Vec<(String, Result<Vec<u8>, MemError>)> =
        futures_util::stream::iter(keys.into_iter().map(|key| {
            let blob = Arc::clone(blob);
            async move {
                let bytes = blob.get(&key).await;
                (key, bytes)
            }
        }))
        .buffer_unordered(ANCHOR_FETCH_CONCURRENCY)
        .collect()
        .await;
    // `buffer_unordered` yields in completion order; sort by key so that when
    // several fetches fail, the same record's error surfaces on every machine
    // (the read fails on the first error, like the previous serial `?`).
    fetched.sort_by(|left, right| left.0.cmp(&right.0));

    let mut records = Vec::with_capacity(fetched.len());
    for (key, bytes) in fetched {
        // A GET failure of a listed key stays a hard error: it is transient (an
        // eventually-consistent bucket, a momentary auth blip) and retried on the
        // next read, so surfacing it is correct. Every check BELOW, by contrast,
        // rejects a PERMANENTLY malformed object — undecodable or invariant-
        // violating — which any bucket writer can plant ONCE to poison the prefix
        // forever. Aborting the whole read on those (the previous `?`/`return Err`)
        // made a single planted object brick `history`, `reconcile`, AND new
        // anchoring for the entire team (`reserve_seq_and_persist`'s
        // `reseed_next_seq` -> `schedule_anchor`),
        // and — worse — let an attacker who wants `reconcile` NOT to report a
        // suppression simply make it error instead. Skip-and-warn per object (the
        // I2 discipline the op-log and manifest readers already follow) keeps one
        // poison object from blinding the team; a genuinely forged-but-self-
        // consistent record (root != merkle_root(leaves)) is NOT rejected here and
        // still flows through to `reconcile`/`anchor_proof_for` to be reported.
        let bytes = bytes?;
        let record: AnchorRecord = match serde_json::from_slice(&bytes) {
            Ok(record) => record,
            Err(err) => {
                tracing::warn!(object_key = %key, error = %err, "skipping anchor-prefix object that does not deserialize as an AnchorRecord");
                continue;
            }
        };
        // An anchor record with no leaves proves nothing — its root is
        // `merkle_root([])` (the zero hash) — yet would satisfy every check below and
        // contribute a phantom zero-op batch to `history`/`reconcile`. `commit_batch`
        // guards on a non-empty pending set, so an empty record is hand-forgery.
        if record.leaves.is_empty() {
            tracing::warn!(object_key = %key, seq = record.seq, "skipping anchor record that carries no leaves");
            continue;
        }
        // `root` and `receipt.root` are set to the same value by `commit_batch`;
        // a record where they disagree was tampered with or hand-built wrong, so a
        // downstream proof must never trust it (batch-redundancy).
        if record.root != record.receipt.root {
            tracing::warn!(object_key = %key, seq = record.seq, root = %record.root.to_hex(), receipt_root = %record.receipt.root.to_hex(), "skipping anchor record whose root disagrees with its receipt root");
            continue;
        }
        // `op_count` is documented as the batch's leaf count; a mismatch is a
        // forged or hand-built record. The Merkle root already binds the leaves, so
        // this is metadata hygiene for `history`/`reconcile` (which read `op_count`).
        if record.meta.op_count != record.leaves.len() {
            tracing::warn!(object_key = %key, seq = record.seq, claimed = record.meta.op_count, actual = record.leaves.len(), "skipping anchor record whose op_count disagrees with its leaf count");
            continue;
        }
        // Reject duplicate leaves. The Merkle builder pairs a lone trailing node
        // with a copy of itself, so `merkle_root([a,b,c]) == merkle_root([a,b,c,c])`
        // (CVE-2012-2459): an untrusted bucket could append a duplicate of an
        // already-anchored leaf, keeping the root valid while inflating
        // `total_anchored_ops` and attributing a phantom duplicate op in
        // `reconcile`. Leaves are op hashes, each globally unique, so an honest
        // record never repeats one — the only producer of a duplicate is tampering.
        let mut seen = HashSet::with_capacity(record.leaves.len());
        if record.leaves.iter().any(|leaf| !seen.insert(*leaf)) {
            tracing::warn!(object_key = %key, seq = record.seq, "skipping anchor record that contains a duplicate leaf");
            continue;
        }
        records.push(record);
    }
    records.sort_by_key(|record| (*record.author_key.as_bytes(), record.seq));
    Ok(records)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test, not a crash to avoid"
    )]

    use super::{AnchorRecord, anchor_record_key, persist_anchor_record, read_anchor_records};
    use crate::audit::anchor::{AnchorReceipt, AnchorRef, BatchMeta};
    use crate::crypto::content_hash;
    use crate::oplog::VerifyingKey;
    use crate::store::{BlobStore, MemoryBlobStore};
    use std::sync::Arc;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const TEAM: &str = "team";

    /// A fixed author for single-author tests.
    fn author() -> VerifyingKey {
        VerifyingKey::new([0xAA; 32])
    }

    /// A record whose root/leaf hash is derived from `seq` so distinct seqs yield
    /// distinct, deterministic content (`content_hash` avoids an integer-to-byte cast).
    fn record(seq: u64) -> AnchorRecord {
        record_for(author(), seq)
    }

    /// A record attributed to `author_key`, otherwise identical to [`record`].
    fn record_for(author_key: VerifyingKey, seq: u64) -> AnchorRecord {
        let root = content_hash(&seq.to_le_bytes());
        AnchorRecord {
            seq,
            author_key,
            root,
            meta: BatchMeta {
                team: TEAM.to_owned(),
                first_lamport: seq,
                last_lamport: seq,
                op_count: 1,
            },
            leaves: vec![root],
            receipt: AnchorReceipt {
                root,
                reference: AnchorRef::Local { seq },
            },
        }
    }

    #[tokio::test]
    async fn read_anchor_records_returns_sorted() -> TestResult {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        // Persist out of seq order; the reader must return ascending seq.
        for seq in [2_u64, 0, 1] {
            persist_anchor_record(&blob, TEAM, &record(seq)).await?;
        }
        let got = read_anchor_records(&blob, TEAM).await?;
        let seqs: Vec<u64> = got.iter().map(|record| record.seq).collect();
        assert_eq!(seqs, vec![0, 1, 2]);
        Ok(())
    }

    #[tokio::test]
    async fn persisted_record_round_trips_through_json() -> TestResult {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let rec = record(7);
        persist_anchor_record(&blob, TEAM, &rec).await?;
        let got = read_anchor_records(&blob, TEAM).await?;
        assert_eq!(got, vec![rec]);
        Ok(())
    }

    /// Assert that a malformed record is SKIPPED (not indexed) while a valid
    /// sibling still reads back — i.e. one poison object does not abort the whole
    /// read. Persists `bad` (seq 0) alongside a valid `record(5)`.
    async fn assert_bad_record_is_skipped(bad: AnchorRecord) -> TestResult {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        persist_anchor_record(&blob, TEAM, &bad).await?;
        persist_anchor_record(&blob, TEAM, &record(5)).await?;
        let got = read_anchor_records(&blob, TEAM).await?;
        let seqs: Vec<u64> = got.iter().map(|record| record.seq).collect();
        assert_eq!(
            seqs,
            vec![5],
            "the malformed record must be skipped and the valid sibling returned"
        );
        Ok(())
    }

    #[tokio::test]
    async fn record_with_disagreeing_roots_is_skipped() -> TestResult {
        // batch-redundancy: a record whose stored root and receipt root differ is
        // internally contradictory; read_anchor_records drops it (skip-and-warn)
        // rather than aborting the read or letting a proof trust whichever root.
        let mut rec = record(0);
        rec.receipt.root = content_hash(b"a-different-root");
        assert_ne!(rec.root, rec.receipt.root, "the two roots must differ");
        assert_bad_record_is_skipped(rec).await
    }

    #[tokio::test]
    async fn record_with_no_leaves_is_skipped() -> TestResult {
        // F5: an empty record proves nothing — its root is merkle_root([]) (the zero
        // hash) — yet would otherwise pass every check and add a phantom zero-op batch
        // to history/reconcile. commit_batch never writes one, so it is hand-forgery
        // the reader drops.
        let mut rec = record(0);
        rec.leaves.clear();
        rec.meta.op_count = 0;
        rec.root = crate::domain::Blake3Hash::zero();
        rec.receipt.root = crate::domain::Blake3Hash::zero();
        assert_bad_record_is_skipped(rec).await
    }

    #[tokio::test]
    async fn record_with_wrong_op_count_is_skipped() -> TestResult {
        // L2: `op_count` is documented as the leaf count; a record whose op_count
        // disagrees with its leaves (forged or hand-built) is dropped rather than
        // silently trusted by history.
        let mut rec = record(0);
        rec.meta.op_count = rec.leaves.len() + 1;
        assert_bad_record_is_skipped(rec).await
    }

    #[tokio::test]
    async fn record_with_duplicate_leaf_is_skipped() -> TestResult {
        // CVE-2012-2459 class: the Merkle builder duplicates a lone trailing node,
        // so [a,b,c] and [a,b,c,c] share a root. An untrusted bucket appending a
        // duplicate of an already-anchored leaf would keep the root valid while
        // inflating the anchored-op count. The leaves are op hashes (unique), so a
        // duplicate is only ever tampering — read_anchor_records drops it.
        let mut rec = record(0);
        rec.leaves = vec![rec.root, rec.root];
        rec.meta.op_count = rec.leaves.len(); // pass the op_count check, hit the dup check
        assert_bad_record_is_skipped(rec).await
    }

    #[tokio::test]
    async fn undecodable_anchor_object_is_skipped() -> TestResult {
        // A non-decoding object planted under the anchors prefix must be skipped,
        // not abort the read for the whole team.
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        blob.put(
            &format!("{TEAM}/_anchors/{}/junk", author().to_hex()),
            b"not an anchor record".to_vec(),
        )
        .await?;
        persist_anchor_record(&blob, TEAM, &record(5)).await?;
        let got = read_anchor_records(&blob, TEAM).await?;
        assert_eq!(
            got.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![5],
            "an undecodable object must be skipped and the valid record returned"
        );
        Ok(())
    }

    #[tokio::test]
    async fn read_anchor_records_empty_when_none_persisted() -> TestResult {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        assert!(read_anchor_records(&blob, TEAM).await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn two_authors_same_seq_do_not_collide() -> TestResult {
        // The C1b regression: before per-author namespacing, two authors both
        // writing seq 0 shared one key, so the second clobbered the first.
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let first_author = VerifyingKey::new([1; 32]);
        let second_author = VerifyingKey::new([2; 32]);

        persist_anchor_record(&blob, TEAM, &record_for(first_author, 0)).await?;
        persist_anchor_record(&blob, TEAM, &record_for(second_author, 0)).await?;

        // Distinct keys -> both objects survive; `read_anchor_records` aggregates
        // across authors.
        assert_ne!(
            anchor_record_key(TEAM, &first_author, 0),
            anchor_record_key(TEAM, &second_author, 0)
        );
        let got = read_anchor_records(&blob, TEAM).await?;
        assert_eq!(got.len(), 2, "both authors' seq-0 records persist");
        let authors: Vec<VerifyingKey> = got.iter().map(|r| r.author_key).collect();
        assert!(authors.contains(&first_author) && authors.contains(&second_author));
        Ok(())
    }
}
