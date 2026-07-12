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
/// # Errors
///
/// Returns [`MemError::Storage`] if listing or any fetch fails,
/// [`MemError::Serialize`] if a stored record cannot be decoded, or
/// [`MemError::Malformed`] if a record's internal invariants are violated — it
/// carries no `leaves`, its `root` disagrees with its `receipt.root`, its
/// `meta.op_count` disagrees with its `leaves` length, or its `leaves` contain a
/// duplicate (which would let an odd-node duplication forge a second-preimage-equal
/// root). The `root`-vs-`merkle_root(leaves)` binding is enforced where a proof is
/// built (`anchor_proof_for`) and surveyed (`reconcile`), NOT here, so `reconcile`
/// can still observe and report a forged root rather than erroring on the read.
pub async fn read_anchor_records(
    blob: &Arc<dyn BlobStore>,
    team: &str,
) -> Result<Vec<AnchorRecord>, MemError> {
    let keys = blob.list(&anchors_prefix(team)).await?;
    // Fetch every record object with bounded concurrency instead of one blocking
    // GET at a time — fetch order does not affect the result (the whole set is
    // validated and then sorted below). Mirrors `OpLogStore::read_verified`.
    let blob_arc = Arc::clone(blob);
    let mut fetched: Vec<(String, Result<Vec<u8>, MemError>)> =
        futures_util::stream::iter(keys.into_iter().map(|key| {
            let blob = Arc::clone(&blob_arc);
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
    for (_key, bytes) in fetched {
        // Any GET failure fails the whole read — unchanged from the serial `?`.
        // Unlike the op-log (where an unfetchable object is skipped), an anchor
        // record is a validated commitment, so a missing one must surface.
        let bytes = bytes?;
        let record: AnchorRecord = serde_json::from_slice(&bytes)?;
        // An anchor record with no leaves proves nothing — its root is
        // `merkle_root([])` (the zero hash) — yet would satisfy every check below and
        // contribute a phantom zero-op batch to `history`/`reconcile`. `commit_batch`
        // guards on a non-empty pending set, so an empty record is hand-forgery.
        if record.leaves.is_empty() {
            return Err(MemError::Malformed(format!(
                "anchor record seq {} carries no leaves",
                record.seq,
            )));
        }
        // `root` and `receipt.root` are set to the same value by `commit_batch`;
        // a record where they disagree was tampered with or hand-built wrong.
        // Check the invariant at read time so a downstream proof never trusts a
        // record whose two roots contradict each other (batch-redundancy).
        if record.root != record.receipt.root {
            return Err(MemError::Malformed(format!(
                "anchor record seq {} has root {} disagreeing with its receipt root {}",
                record.seq,
                record.root.to_hex(),
                record.receipt.root.to_hex(),
            )));
        }
        // `op_count` is documented as the batch's leaf count; enforce it where the
        // record is consumed so the cross-check is real, not just asserted in a
        // doc. The Merkle root already binds the leaves, so a mismatch is a forged
        // or hand-built record, not a security break — but rejecting it keeps the
        // metadata honest for `history`/`reconcile`, which read `op_count`.
        if record.meta.op_count != record.leaves.len() {
            return Err(MemError::Malformed(format!(
                "anchor record seq {} claims op_count {} but carries {} leaves",
                record.seq,
                record.meta.op_count,
                record.leaves.len(),
            )));
        }
        // Reject duplicate leaves. The Merkle builder pairs a lone trailing node
        // with a copy of itself, so `merkle_root([a,b,c]) == merkle_root([a,b,c,c])`
        // (CVE-2012-2459): an untrusted bucket could append a duplicate of an
        // already-anchored leaf, keeping the root valid while inflating
        // `total_anchored_ops` and attributing a phantom duplicate op to the batch
        // in `reconcile`. Leaves are op hashes, each globally unique, so a honest
        // record never repeats one — the only producer of a duplicate is tampering.
        // Enforcing uniqueness here (the single read boundary `history`/`reconcile`
        // share) closes the ambiguity without changing the on-chain root format.
        let mut seen = HashSet::with_capacity(record.leaves.len());
        for leaf in &record.leaves {
            if !seen.insert(*leaf) {
                return Err(MemError::Malformed(format!(
                    "anchor record seq {} contains a duplicate leaf {}",
                    record.seq,
                    leaf.to_hex(),
                )));
            }
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

    #[tokio::test]
    async fn record_with_disagreeing_roots_is_rejected() -> TestResult {
        // batch-redundancy: a record whose stored root and receipt root differ is
        // internally contradictory; read_anchor_records must refuse it rather than
        // let a downstream proof trust whichever root it happens to read.
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let mut rec = record(0);
        rec.receipt.root = content_hash(b"a-different-root");
        assert_ne!(rec.root, rec.receipt.root, "the two roots must differ");
        persist_anchor_record(&blob, TEAM, &rec).await?;

        match read_anchor_records(&blob, TEAM).await {
            Err(crate::error::MemError::Malformed(_)) => Ok(()),
            Err(other) => Err(format!("expected Malformed, got {other:?}").into()),
            Ok(_) => Err("a record with disagreeing roots must be rejected".into()),
        }
    }

    #[tokio::test]
    async fn record_with_no_leaves_is_rejected() -> TestResult {
        // F5: an empty record proves nothing — its root is merkle_root([]) (the zero
        // hash) — yet would otherwise pass every check and add a phantom zero-op batch
        // to history/reconcile. commit_batch never writes one, so it is hand-forgery
        // the reader must refuse.
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let mut rec = record(0);
        rec.leaves.clear();
        rec.meta.op_count = 0;
        rec.root = crate::domain::Blake3Hash::zero();
        rec.receipt.root = crate::domain::Blake3Hash::zero();
        persist_anchor_record(&blob, TEAM, &rec).await?;

        match read_anchor_records(&blob, TEAM).await {
            Err(crate::error::MemError::Malformed(_)) => Ok(()),
            Err(other) => Err(format!("expected Malformed, got {other:?}").into()),
            Ok(_) => Err("a record with no leaves must be rejected".into()),
        }
    }

    #[tokio::test]
    async fn record_with_wrong_op_count_is_rejected() -> TestResult {
        // L2: `op_count` is documented as the leaf count; read_anchor_records must
        // enforce it, so a record whose op_count disagrees with its leaves (forged
        // or hand-built) is rejected rather than silently trusted by history.
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let mut rec = record(0);
        rec.meta.op_count = rec.leaves.len() + 1;
        persist_anchor_record(&blob, TEAM, &rec).await?;

        match read_anchor_records(&blob, TEAM).await {
            Err(crate::error::MemError::Malformed(_)) => Ok(()),
            Err(other) => Err(format!("expected Malformed, got {other:?}").into()),
            Ok(_) => Err("a record with a wrong op_count must be rejected".into()),
        }
    }

    #[tokio::test]
    async fn record_with_duplicate_leaf_is_rejected() -> TestResult {
        // CVE-2012-2459 class: the Merkle builder duplicates a lone trailing node,
        // so [a,b,c] and [a,b,c,c] share a root. An untrusted bucket appending a
        // duplicate of an already-anchored leaf would keep the root valid while
        // inflating the anchored-op count. The leaves are op hashes (unique), so a
        // duplicate is only ever tampering — read_anchor_records must refuse it.
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let mut rec = record(0);
        rec.leaves = vec![rec.root, rec.root];
        rec.meta.op_count = rec.leaves.len(); // pass the op_count check, hit the dup check
        persist_anchor_record(&blob, TEAM, &rec).await?;

        match read_anchor_records(&blob, TEAM).await {
            Err(crate::error::MemError::Malformed(_)) => Ok(()),
            Err(other) => Err(format!("expected Malformed, got {other:?}").into()),
            Ok(_) => Err("a record with a duplicate leaf must be rejected".into()),
        }
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
