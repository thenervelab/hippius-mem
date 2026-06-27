//! Persisted records of anchored op-log batches.
//!
//! Each time the scheduler ([`crate::store::MemoryStore`]) anchors a batch's
//! Merkle root, it writes one [`AnchorRecord`] to the blob store under the team's
//! `_anchors/` prefix. The record keeps the batch's *ordered leaves* (the op
//! hashes) next to the root and receipt, because `history` (a later task) needs
//! them to rebuild a Merkle inclusion proof for any single op long after the
//! batch was sealed — the root alone is an opaque commitment no reader could open.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::audit::anchor::{AnchorReceipt, BatchMeta};
use crate::domain::Blake3Hash;
use crate::error::MemError;
use crate::store::BlobStore;

/// One anchored batch, persisted so `history` can later prove any op it covers.
///
/// `leaves` are the batch's op hashes IN OP-APPEND ORDER — the exact order the
/// Merkle tree was built over — so `inclusion_proof(&record.leaves, i)`
/// reproduces the proof for the op at position `i` under `record.root`. The
/// `meta`/`receipt` pair records what was committed and where it landed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorRecord {
    /// Monotonic local sequence number of this batch — its `_anchors/` key.
    pub seq: u64,
    /// The Merkle root anchored for this batch.
    pub root: Blake3Hash,
    /// The batch metadata committed alongside the root (team + Lamport range).
    pub meta: BatchMeta,
    /// The op hashes (leaves) in op-append order — what proves inclusion later.
    pub leaves: Vec<Blake3Hash>,
    /// The anchoring outcome: the root and where it was committed.
    pub receipt: AnchorReceipt,
}

/// Object-key prefix under which a team's anchor records live.
fn anchors_prefix(team: &str) -> String {
    format!("{team}/_anchors/")
}

/// Object key for the anchor record at `seq`.
///
/// `seq` is zero-padded to 20 digits (the width of `u64::MAX`) so the blob
/// store's lexicographic `list` order coincides with numeric `seq` order — the
/// same fixed-width-key trick the op-log uses to make a listing replay in order.
fn anchor_record_key(team: &str, seq: u64) -> String {
    format!("{team}/_anchors/{seq:020}")
}

/// Persist `rec` as JSON under the team's `_anchors/` prefix.
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
    blob.put(&anchor_record_key(team, rec.seq), bytes).await
}

/// Read every anchor record for `team`, sorted by `seq`.
///
/// Used by `history` to find the anchored batch covering a given op. The blob
/// store lists keys lexicographically — which the zero-padded keys make numeric —
/// and the explicit `sort_by_key` re-asserts that ordering contract regardless of
/// backend, so a caller may rely on ascending `seq` without trusting the listing.
///
/// # Errors
///
/// Returns [`MemError::Storage`] if listing or any fetch fails, or
/// [`MemError::Serialize`] if a stored record cannot be decoded.
pub async fn read_anchor_records(
    blob: &Arc<dyn BlobStore>,
    team: &str,
) -> Result<Vec<AnchorRecord>, MemError> {
    let keys = blob.list(&anchors_prefix(team)).await?;
    let mut records = Vec::with_capacity(keys.len());
    for key in &keys {
        let bytes = blob.get(key).await?;
        let record: AnchorRecord = serde_json::from_slice(&bytes)?;
        records.push(record);
    }
    records.sort_by_key(|record| record.seq);
    Ok(records)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test, not a crash to avoid"
    )]

    use super::{AnchorRecord, persist_anchor_record, read_anchor_records};
    use crate::audit::anchor::{AnchorReceipt, AnchorRef, BatchMeta};
    use crate::crypto::content_hash;
    use crate::store::{BlobStore, MemoryBlobStore};
    use std::sync::Arc;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const TEAM: &str = "team";

    /// A record whose root/leaf hash is derived from `seq` so distinct seqs yield
    /// distinct, deterministic content (`content_hash` avoids an integer-to-byte cast).
    fn record(seq: u64) -> AnchorRecord {
        let root = content_hash(&seq.to_le_bytes());
        AnchorRecord {
            seq,
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
    async fn read_anchor_records_empty_when_none_persisted() -> TestResult {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        assert!(read_anchor_records(&blob, TEAM).await?.is_empty());
        Ok(())
    }
}
