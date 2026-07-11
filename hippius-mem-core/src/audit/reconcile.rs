//! Reconcile the visible op-log against the anchored Merkle roots.
//!
//! The team bucket is untrusted. The per-author hash chain in
//! [`crate::oplog::OpLogStore::read_all`] is tamper-evidence *within* an author's
//! own chain, but it cannot catch **suppression** — tail-truncation or
//! whole-author hiding leave a shorter-but-valid chain with no gap to notice (see
//! that module's threat-model notes). On-chain Merkle anchoring is the latent
//! mitigation: a root committed publicly pins which op hashes existed at a point
//! in time. This module turns that latent mitigation into an active check — it
//! cross-references every anchored leaf against the visible op-log and reports
//! any op that was anchored but has since gone missing.
//!
//! # What this detects, and what it cannot
//!
//! It DETECTS:
//! - **suppression of an anchored op** — a leaf committed under an anchored root
//!   that is absent from the visible op-log ([`MissingOp`]);
//! - **a forged or corrupt anchor record** — one whose stored `root` does not
//!   equal `merkle_root(leaves)`, so the record's own commitment is internally
//!   inconsistent ([`RootMismatch`]).
//!
//! It CANNOT detect suppression of an op that was **never anchored**. Only ops
//! that were batched and anchored carry a commitment to reconcile against; an op
//! dropped before its batch was anchored leaves no anchored leaf, so its absence
//! is indistinguishable from "never written". Lowering the anchor threshold
//! shrinks this window but never closes it. This is an honest, fundamental limit
//! of anchoring-after-the-fact, not a deficiency of this check.
//!
//! # Chain-side verification
//!
//! The bucket-side [`reconcile`] catches a forged record whose `root` disagrees
//! with its own `leaves`, but NOT a forged record whose `root == merkle_root(leaves)`
//! yet was never actually committed on-chain — the bucket controls both halves.
//! [`reconcile_with_chain`] (behind the `chain` feature) closes that gap by
//! reading the committed root back from the chain for every [`AnchorRef::OnChain`]
//! record and comparing it to the record's `root`; the bucket cannot fake the
//! chain. See that function for the precise, honestly-stated limits of what
//! subxt 0.50 can read back.

use std::collections::HashSet;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::audit::anchor::AnchorRef;
use crate::audit::batch::{AnchorRecord, read_anchor_records};
use crate::audit::merkle::merkle_root;
use crate::domain::Blake3Hash;
use crate::error::MemError;
use crate::oplog::{Op, OpLogStore, VerifyingKey};
use crate::store::BlobStore;

/// An op that was committed under an anchored Merkle root but is absent from the
/// visible op-log — suppression / tail-truncation evidence.
///
/// `op_hash` is the anchored leaf (an [`crate::oplog::Op::hash`] value) that no
/// present op reproduces. `anchor_seq` and `anchor_ref` pinpoint *which* anchored
/// batch committed it, so an operator can prove the op once existed: the bucket
/// itself retained the commitment while dropping the op.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissingOp {
    /// The anchored leaf — the [`crate::oplog::Op::hash`] of the suppressed op.
    pub op_hash: Blake3Hash,
    /// The author who anchored the batch. `anchor_seq` is monotonic *per author*,
    /// so the seq alone is ambiguous in a multi-author team; this names the
    /// `{author_key}/` namespace the record lives under.
    pub author_key: VerifyingKey,
    /// The monotonic-per-author sequence number of the anchor batch that
    /// committed `op_hash` (the [`crate::audit::batch::AnchorRecord::seq`]).
    pub anchor_seq: u64,
    /// Where that batch's root was anchored — a local seq, or an on-chain
    /// block/extrinsic location.
    pub anchor_ref: AnchorRef,
}

/// An anchor record whose stored `root` is contradicted by a check — a forged or
/// corrupted commitment.
///
/// A genuine record always satisfies `root == merkle_root(leaves)` by
/// construction (see [`crate::store::MemoryStore`]'s batch committer) AND, when
/// anchored on-chain, `root` equals the chain-committed root. A violation of
/// either means the record was tampered with or fabricated.
///
/// Modeled as an enum, not a `kind` tag beside a single `recomputed_root` field:
/// the contradicting root means different things per check (recomputed-from-leaves
/// vs read-from-chain), so a tagged field could be paired with the wrong meaning.
/// Each variant names its own root, making that wrong pairing unrepresentable.
/// Both variants carry `author_key` + `anchor_seq`, which together identify the
/// record (seq is per-author).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RootMismatch {
    /// The record's stored `root` does not equal `merkle_root(record.leaves)` —
    /// the commitment is internally inconsistent (forged/corrupt bucket-side).
    LeafRecomputation {
        /// The author that anchored the offending record.
        author_key: VerifyingKey,
        /// The per-author sequence number of the offending record.
        anchor_seq: u64,
        /// The root the record claims.
        stored_root: Blake3Hash,
        /// The root recomputed from the record's own leaves.
        recomputed_root: Blake3Hash,
    },
    /// The root committed on-chain for this record disagrees with the record's
    /// stored `root` — the bucket's record was never the anchored one (only
    /// raised by [`reconcile_with_chain`]).
    ChainDisagreement {
        /// The author that anchored the offending record.
        author_key: VerifyingKey,
        /// The per-author sequence number of the offending record.
        anchor_seq: u64,
        /// The root the record claims.
        stored_root: Blake3Hash,
        /// The root actually committed on-chain at the record's anchor location.
        on_chain_root: Blake3Hash,
    },
}

/// The outcome of reconciling a team's op-log against its anchored roots.
///
/// `ok` is the single yes/no an operator reads first; it is derived — and kept
/// in lockstep with the evidence vectors — as `missing_ops.is_empty() &&
/// root_mismatches.is_empty()`. The counts (`checked_batches`,
/// `total_anchored_ops`) describe the coverage of the check itself, so a clean
/// `ok` over zero batches is distinguishable from a clean `ok` over many.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconcileReport {
    /// How many anchor records were examined.
    pub checked_batches: usize,
    /// The total number of anchored leaves across every examined record — the
    /// size of the commitment set this check covered.
    pub total_anchored_ops: usize,
    /// Anchored ops absent from the visible op-log (suppression evidence).
    pub missing_ops: Vec<MissingOp>,
    /// Anchor records whose `root` disagrees with their own leaves (forgery).
    pub root_mismatches: Vec<RootMismatch>,
    /// `true` exactly when both evidence vectors are empty.
    ///
    /// **Scope caveat (bucket mode):** `ok: true` means the anchor records are
    /// INTERNALLY consistent with the visible op-log — it is NOT a
    /// trust-minimized attestation. An untrusted bucket can fabricate
    /// self-consistent [`AnchorRecord`](crate::audit::batch::AnchorRecord)s
    /// (they carry no signature), so plain [`reconcile`] returns `ok: true` for
    /// a commitment set that was never anchored anywhere the bucket cannot
    /// rewrite. Treating this as "audit passed" requires the `chain` feature's
    /// `reconcile_with_chain` (not linkable here — it only exists under that
    /// feature), which verifies each record against the finalized chain (see
    /// the module docs).
    pub ok: bool,
}

/// Reconcile `team`'s visible op-log against its anchored Merkle roots.
///
/// Reads every anchor record and the full op-log, then for each record:
/// (a) recomputes `merkle_root(leaves)` and flags a [`RootMismatch`] if it
/// disagrees with the stored `root`; (b) flags a [`MissingOp`] for every leaf
/// that no present op reproduces. See the module docs for what this detects and
/// the honest limit that only anchored ops are covered.
///
/// # Errors
///
/// Propagates whatever [`read_anchor_records`] or
/// [`OpLogStore::read_all`] report — a backend listing/fetch failure
/// ([`MemError::Storage`]/[`MemError::NotFound`]), a record that cannot be
/// decoded ([`MemError::Serialize`]), or an op-log integrity violation surfaced
/// by the verified read. Detected suppression or forgery is NOT an error: it is
/// the report's payload, because over an untrusted bucket a detected anomaly is a
/// successful detection, not a failed operation.
pub async fn reconcile(
    blob: &Arc<dyn BlobStore>,
    oplog: &OpLogStore,
    team: &str,
) -> Result<ReconcileReport, MemError> {
    let records = read_anchor_records(blob, team).await?;
    let ops = oplog.read_all(team).await?;
    Ok(reconcile_records(&records, &ops))
}

/// The pure bucket-side reconciliation over an already-read record + op set.
///
/// Split out from [`reconcile`] so [`reconcile_with_chain`] can run the
/// bucket-side AND chain-side passes over ONE record listing. Re-listing between
/// the two passes opened a TOCTOU: an untrusted bucket could serve a
/// forged-but-self-consistent record to the leaf pass (so it passes the leaf
/// check) and then withhold it from a second listing, so its claimed on-chain
/// anchor was never verified — yet `ok` came back true. Reading the records once
/// and threading the same slice through both checks closes that window.
fn reconcile_records(records: &[AnchorRecord], ops: &[Op]) -> ReconcileReport {
    // Membership set of every op hash actually present in the visible log. A
    // `HashSet` because the inner loop is a pure membership test per leaf and
    // ordering is irrelevant — `read_anchor_records` already fixes the
    // deterministic record/leaf iteration order the report inherits.
    let present: HashSet<Blake3Hash> = ops.iter().map(Op::hash).collect();

    // Count DISTINCT anchored op hashes, not the sum of per-record leaf counts. A
    // leaf (a globally-unique op hash) can appear in more than one record when an
    // untrusted bucket copies a valid record under a new `seq` — both copies pass
    // the internal-consistency check below — and summing leaf counts would inflate
    // `total_anchored_ops`, the coverage metric an operator reads to judge how much
    // the check covered. `read_anchor_records` rejects duplicates WITHIN a record;
    // this dedups ACROSS records.
    let mut distinct_anchored: HashSet<Blake3Hash> = HashSet::new();
    let mut missing_ops = Vec::new();
    let mut root_mismatches = Vec::new();

    for record in records {
        // (a) A record whose own leaves do not hash to its claimed root is
        // forged or corrupt — its commitment is internally inconsistent.
        let recomputed_root = merkle_root(&record.leaves);
        if recomputed_root != record.root {
            root_mismatches.push(RootMismatch::LeafRecomputation {
                author_key: record.author_key,
                anchor_seq: record.seq,
                stored_root: record.root,
                recomputed_root,
            });
        }

        for leaf in &record.leaves {
            distinct_anchored.insert(*leaf);
            // (b) Any anchored leaf no present op reproduces was committed then
            // dropped from the bucket — suppression of an anchored op.
            if !present.contains(leaf) {
                missing_ops.push(MissingOp {
                    op_hash: *leaf,
                    author_key: record.author_key,
                    anchor_seq: record.seq,
                    anchor_ref: record.receipt.reference.clone(),
                });
            }
        }
    }

    let ok = missing_ops.is_empty() && root_mismatches.is_empty();
    ReconcileReport {
        checked_batches: records.len(),
        total_anchored_ops: distinct_anchored.len(),
        missing_ops,
        root_mismatches,
        ok,
    }
}

/// The chain-readback capability [`reconcile_with_chain`] needs: given an anchor
/// location, return the Merkle root actually committed on-chain there.
///
/// This is the seam that makes the trust-minimized comparison testable. The real
/// impl ([`SubxtAnchor`](crate::audit::anchor::SubxtAnchor), behind the `chain`
/// feature) performs a live, CI-untestable node readback; a mock impl lets a plain
/// `cargo test` exercise the comparison and [`RootMismatch::ChainDisagreement`]
/// reporting without a chain. `#[async_trait]` mirrors [`BlobStore`]: the future
/// must be `Send` to run on the multithreaded MCP runtime.
#[cfg(any(feature = "chain", test))]
#[async_trait::async_trait]
pub(crate) trait ChainRootReader {
    /// Read back the root committed on-chain at `(block_hash, extrinsic_hash)`.
    ///
    /// # Errors
    ///
    /// [`MemError::Storage`] if the location cannot be read back — an unreadable
    /// anchor must surface as an error, never a clean report ("could not verify"
    /// is not "verified").
    async fn read_anchored_root(
        &self,
        block_hash: &str,
        extrinsic_hash: &str,
    ) -> Result<Blake3Hash, MemError>;
}

/// Verify each on-chain anchor record's stored root against the root the chain
/// actually committed, pushing a [`RootMismatch::ChainDisagreement`] for any that
/// disagree and recomputing `ok`.
///
/// Split out of [`reconcile_with_chain`] so the comparison — the trust-minimized
/// core — is unit-tested with a mock [`ChainRootReader`] in the default build; the
/// live readback it wraps cannot run in CI. Threads the SAME `records` slice the
/// bucket-side pass saw (no re-list), preserving that TOCTOU-closing invariant.
///
/// # Errors
///
/// Propagates any [`MemError::Storage`] the reader raises — an unreadable anchor
/// location fails the whole check rather than collapsing into a clean report.
#[cfg(any(feature = "chain", test))]
async fn verify_on_chain_roots(
    records: &[AnchorRecord],
    mut report: ReconcileReport,
    reader: &impl ChainRootReader,
) -> Result<ReconcileReport, MemError> {
    for record in records {
        let AnchorRef::OnChain {
            block_hash,
            extrinsic_hash,
        } = &record.receipt.reference
        else {
            continue;
        };
        let on_chain_root = reader
            .read_anchored_root(block_hash, extrinsic_hash)
            .await?;
        if on_chain_root != record.root {
            // A distinct fact from the leaf-recomputation check: the bucket's
            // stored root was never the one anchored on-chain. The separate variant
            // keeps a record failing BOTH checks as two distinguishable entries.
            report
                .root_mismatches
                .push(RootMismatch::ChainDisagreement {
                    author_key: record.author_key,
                    anchor_seq: record.seq,
                    stored_root: record.root,
                    on_chain_root,
                });
        }
    }
    report.ok = report.missing_ops.is_empty() && report.root_mismatches.is_empty();
    Ok(report)
}

/// Like [`reconcile`], but also verify every on-chain anchor against the chain.
///
/// The bucket-side [`reconcile`] catches a record whose `root` disagrees with its
/// own leaves, but it cannot catch a record the bucket forged *consistently* —
/// one where `root == merkle_root(leaves)` yet that root was never actually
/// committed on-chain. This closes that gap: for every
/// [`AnchorRef::OnChain`] record it reads the committed root back from the chain
/// (via [`SubxtAnchor::read_anchored_root`](crate::audit::anchor::SubxtAnchor::read_anchored_root))
/// and records a [`RootMismatch`] when the chain disagrees with the bucket. The
/// bucket cannot fake the chain, so this is the trust-minimized check.
///
/// [`AnchorRef::Local`] records are left to the bucket-side checks alone — there
/// is no external commitment to compare them against.
///
/// # What chain mode does and does NOT add
///
/// It detects a record the bucket KEPT but never actually committed (a
/// forged-but-self-consistent `root`). It does NOT detect a record the bucket
/// DROPPED *together with* its op (record-omission suppression): this check only
/// iterates the records the bucket still serves, so an omitted record is never
/// examined and `ok` stays true. Catching that would require independently
/// enumerating the team's committed roots from the chain and matching each
/// against a present bucket record — which the [`SubxtAnchor::read_anchored_root`](crate::audit::anchor::SubxtAnchor::read_anchored_root)
/// readback (a per-(block, extrinsic) lookup, with no chain-side index of a
/// team's roots) cannot do. So chain mode hardens forgery detection, not
/// record-omission suppression; the `dropping_op_and_its_anchor_record_together_is_undetected`
/// test pins that limit.
///
/// # Honest limits
///
/// Inherits every limit of [`SubxtAnchor::read_anchored_root`](crate::audit::anchor::SubxtAnchor::read_anchored_root):
/// it needs an archive node retaining the referenced blocks, Substrate exposes no
/// extrinsic-hash index (so the block hash is the lookup key), and a block that
/// cannot be fetched is a hard error — "could not verify" never collapses into a
/// clean report. Like the anchoring path itself, it is compile-checked but
/// exercised only against a live chain, never in CI.
///
/// # Errors
///
/// Everything [`reconcile`] reports, plus any [`MemError::Storage`] from reading
/// a block back off the chain.
#[cfg(feature = "chain")]
pub async fn reconcile_with_chain(
    blob: &Arc<dyn BlobStore>,
    oplog: &OpLogStore,
    team: &str,
    anchor: &crate::audit::anchor::SubxtAnchor,
) -> Result<ReconcileReport, MemError> {
    // Read the records and ops ONCE, then run the bucket-side and chain-side
    // passes over the SAME slice — re-listing between them opens a TOCTOU where a
    // forged record passes the leaf check from one listing and is withheld from
    // the next, so its chain anchor is never verified yet `ok` stays true.
    let records = read_anchor_records(blob, team).await?;
    let ops = oplog.read_all(team).await?;
    let report = reconcile_records(&records, &ops);
    // SubxtAnchor impls ChainRootReader; the comparison itself is verified in
    // isolation via a mock reader (see tests) since the live readback needs a node.
    verify_on_chain_roots(&records, report, anchor).await
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        clippy::panic_in_result_fn,
        reason = "tests assert on in-memory fixtures where construction cannot fail; Result-returning tests use `?` for setup and assert on outcomes"
    )]

    use super::{ChainRootReader, ReconcileReport, RootMismatch, reconcile, verify_on_chain_roots};
    use crate::NetworkPrefix;
    use crate::audit::anchor::{AnchorReceipt, AnchorRef, BatchMeta, NoopAnchor};
    use crate::audit::batch::{AnchorRecord, persist_anchor_record, read_anchor_records};
    use crate::audit::merkle::merkle_root;
    use crate::crypto::{SecretKey, content_hash};
    use crate::domain::Blake3Hash;
    use crate::error::MemError;
    use crate::index::{HashEmbedder, InMemoryIndex};
    use crate::oplog::{Op, OpLogStore, Signer, Sr25519Signer, VerifyingKey};
    use crate::store::{BlobStore, MemoryBlobStore, MemoryStore, RememberInput};
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const TEAM: &str = "team";

    /// A blob store that hides a fixed set of object keys from `get`/`list`,
    /// forwarding everything else to an inner [`MemoryBlobStore`].
    ///
    /// This is the suppression test seam: `MemoryBlobStore` (and the `BlobStore`
    /// trait) has no delete, so to simulate a bucket that dropped one op object
    /// while keeping its anchor commitment, we anchor against the inner store and
    /// then read through this wrapper, which makes the chosen op key invisible —
    /// exactly the tail-truncation an untrusted bucket can perform.
    #[derive(Debug)]
    struct Suppressing {
        inner: Arc<MemoryBlobStore>,
        hidden: BTreeSet<String>,
    }

    #[async_trait::async_trait]
    impl BlobStore for Suppressing {
        async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), crate::error::MemError> {
            self.inner.put(key, bytes).await
        }

        async fn get(&self, key: &str) -> Result<Vec<u8>, crate::error::MemError> {
            if self.hidden.contains(key) {
                return Err(crate::error::MemError::NotFound { id: key.to_owned() });
            }
            self.inner.get(key).await
        }

        async fn list(&self, prefix: &str) -> Result<Vec<String>, crate::error::MemError> {
            let keys = self.inner.list(prefix).await?;
            Ok(keys
                .into_iter()
                .filter(|key| !self.hidden.contains(key))
                .collect())
        }

        async fn delete(&self, key: &str) -> Result<(), crate::error::MemError> {
            self.inner.delete(key).await
        }
    }

    /// The op-log object key scheme, mirrored from `oplog::store` (private there)
    /// so a test can name the exact object to suppress. Must track that scheme,
    /// including the trailing author-key segment that makes the key collision-free.
    fn op_object_key(team: &str, op: &Op) -> String {
        format!(
            "{team}/_oplog/{:020}_{}_{}",
            op.lamport,
            op.op_id,
            op.author_key.to_hex()
        )
    }

    /// Build a store over `blob` with the given anchor threshold and a recording
    /// (here: noop) anchor, so writes still persist anchor records locally.
    fn store_over(blob: Arc<dyn BlobStore>, threshold: usize) -> MemoryStore {
        let index = Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default())));
        let signer: Arc<dyn Signer> = Arc::new(
            Sr25519Signer::from_seed_with_prefix(&[9u8; 32], NetworkPrefix::HIPPIUS)
                .expect("valid seed"),
        );
        let oplog = OpLogStore::new(blob.clone());
        MemoryStore::new(
            blob,
            index,
            oplog,
            Arc::new(NoopAnchor),
            signer,
            BTreeMap::from([(0_u64, SecretKey::from_bytes([7u8; 32]))]),
            0,
            TEAM.to_owned(),
            threshold,
        )
    }

    fn remember_input(summary: &str) -> RememberInput {
        RememberInput {
            note_type: crate::domain::NoteType::Decision,
            repo: crate::domain::RepoScope::Global,
            tags: BTreeSet::new(),
            summary: summary.to_owned(),
            body: format!("body for {summary}"),
            force: true,
        }
    }

    #[tokio::test]
    async fn clean_log_reconciles_ok() -> TestResult {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let store = store_over(blob.clone(), 1);
        for i in 0..3 {
            store.remember(remember_input(&format!("note {i}"))).await?;
        }

        let oplog = OpLogStore::new(blob.clone());
        let report = reconcile(&blob, &oplog, TEAM).await?;
        assert!(
            report.ok,
            "a clean, fully-anchored log reconciles ok: {report:?}"
        );
        assert!(report.missing_ops.is_empty());
        assert!(report.root_mismatches.is_empty());
        assert_eq!(report.total_anchored_ops, 3, "every op was anchored");
        assert_eq!(report.checked_batches, 3, "one batch per op at threshold 1");
        Ok(())
    }

    #[tokio::test]
    async fn suppressed_anchored_op_is_detected() -> TestResult {
        // Anchor two ops against the inner bucket, then hide the TAIL op object.
        // Tail-truncation keeps the visible chain valid (genesis -> op0) while the
        // anchored leaf for op1 has no corresponding op — exactly suppression.
        let inner = Arc::new(MemoryBlobStore::default());
        let blob: Arc<dyn BlobStore> = inner.clone();
        let store = store_over(blob.clone(), 1);
        store.remember(remember_input("first")).await?;
        store.remember(remember_input("second")).await?;

        let full_log = OpLogStore::new(blob.clone());
        let ops = full_log.read_all(TEAM).await?;
        let tail = ops.last().ok_or("expected two ops")?;
        let tail_hash = tail.hash();
        let tail_key = op_object_key(TEAM, tail);

        // The anchor seq of the batch that committed the tail's leaf.
        let records = read_anchor_records(&blob, TEAM).await?;
        let expected_seq = records
            .iter()
            .find(|record| record.leaves.contains(&tail_hash))
            .map(|record| record.seq)
            .ok_or("the tail op must have an anchor record")?;

        let suppressing: Arc<dyn BlobStore> = Arc::new(Suppressing {
            inner: inner.clone(),
            hidden: BTreeSet::from([tail_key]),
        });
        let oplog = OpLogStore::new(suppressing.clone());
        let report = reconcile(&suppressing, &oplog, TEAM).await?;

        assert!(
            !report.ok,
            "a suppressed anchored op must fail reconciliation"
        );
        assert_eq!(
            report.missing_ops.len(),
            1,
            "exactly the tail is missing: {report:?}"
        );
        let missing = &report.missing_ops[0];
        assert_eq!(missing.op_hash, tail_hash);
        assert_eq!(missing.anchor_seq, expected_seq);
        // The NoopAnchor seq fix: anchor_ref carries the real batch seq, not a
        // placeholder 0 (the tail is batch seq 1 at threshold 1).
        assert_eq!(
            missing.anchor_ref,
            AnchorRef::Local { seq: expected_seq },
            "anchor_ref pinpoints the batch that committed the op"
        );
        Ok(())
    }

    #[test]
    fn total_anchored_ops_counts_distinct_leaves_across_records() {
        // F3: an untrusted bucket copies a valid record under a new seq, so the same
        // leaf (a globally-unique op hash) appears in two records. total_anchored_ops
        // must count it ONCE — summing per-record leaf counts would inflate the
        // coverage metric an operator reads. read_anchor_records dedups WITHIN a
        // record; this is the across-records case.
        let shared = content_hash(b"shared-op");
        let other = content_hash(b"other-op");
        let make = |seq: u64, leaves: Vec<Blake3Hash>| {
            let root = merkle_root(&leaves);
            AnchorRecord {
                seq,
                author_key: VerifyingKey::new([0xAA; 32]),
                root,
                meta: BatchMeta {
                    team: TEAM.to_owned(),
                    first_lamport: seq,
                    last_lamport: seq,
                    op_count: leaves.len(),
                },
                leaves,
                receipt: AnchorReceipt {
                    root,
                    reference: AnchorRef::Local { seq },
                },
            }
        };
        let records = vec![
            make(0, vec![shared, other]),
            make(1, vec![shared]), // re-anchors the shared leaf under a fresh seq
        ];

        let report = super::reconcile_records(&records, &[]);
        assert_eq!(
            report.total_anchored_ops, 2,
            "two distinct leaves across the records, counted once: {report:?}"
        );
        assert_eq!(report.checked_batches, 2, "both records are surveyed");
    }

    #[tokio::test]
    async fn dropping_op_and_its_anchor_record_together_is_undetected() -> TestResult {
        // L3 / M1 limit: reconcile (and reconcile_with_chain) iterate only the
        // anchor records the bucket still serves. A bucket that drops an op
        // TOGETHER WITH its anchor record leaves a valid op-log prefix and nothing
        // to reconcile against, so `ok` is true. This is the documented,
        // fundamental limit of anchoring-after-the-fact — pinned here so a future
        // change cannot quietly start claiming it is detected.
        let inner = Arc::new(MemoryBlobStore::default());
        let blob: Arc<dyn BlobStore> = inner.clone();
        let store = store_over(blob.clone(), 1);
        store.remember(remember_input("first")).await?;
        store.remember(remember_input("second")).await?;

        let full_log = OpLogStore::new(blob.clone());
        let ops = full_log.read_all(TEAM).await?;
        let tail = ops.last().ok_or("expected two ops")?;
        let tail_hash = tail.hash();
        let tail_key = op_object_key(TEAM, tail);

        // The anchor record that committed the tail's leaf, and its object key.
        let records = read_anchor_records(&blob, TEAM).await?;
        let record = records
            .iter()
            .find(|record| record.leaves.contains(&tail_hash))
            .ok_or("the tail op must have an anchor record")?;
        let record_key = format!(
            "{TEAM}/_anchors/{}/{:020}",
            record.author_key.to_hex(),
            record.seq
        );

        // Drop BOTH the op object AND its anchor record — the "suppress together"
        // case the check cannot see.
        let suppressing: Arc<dyn BlobStore> = Arc::new(Suppressing {
            inner: inner.clone(),
            hidden: BTreeSet::from([tail_key, record_key]),
        });
        let oplog = OpLogStore::new(suppressing.clone());
        let report = reconcile(&suppressing, &oplog, TEAM).await?;

        assert!(
            report.ok,
            "with both the op and its anchor record gone there is nothing to reconcile against: {report:?}"
        );
        assert!(
            report.missing_ops.is_empty(),
            "no anchored leaf is left to miss"
        );
        Ok(())
    }

    #[tokio::test]
    async fn forged_anchor_record_is_detected() -> TestResult {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        // A record whose stored root does NOT hash from its leaves.
        let leaf = content_hash(b"a-real-leaf");
        let lying_root = content_hash(b"a-root-that-does-not-match");
        let recomputed = merkle_root(&[leaf]);
        assert_ne!(lying_root, recomputed, "the forged root must differ");

        let forged = AnchorRecord {
            seq: 0,
            author_key: VerifyingKey::new([0xBB; 32]),
            root: lying_root,
            meta: BatchMeta {
                team: TEAM.to_owned(),
                first_lamport: 0,
                last_lamport: 0,
                op_count: 1,
            },
            leaves: vec![leaf],
            receipt: AnchorReceipt {
                root: lying_root,
                reference: AnchorRef::Local { seq: 0 },
            },
        };
        persist_anchor_record(&blob, TEAM, &forged).await?;

        let oplog = OpLogStore::new(blob.clone());
        let report = reconcile(&blob, &oplog, TEAM).await?;

        assert!(!report.ok);
        assert_eq!(report.root_mismatches.len(), 1, "{report:?}");
        let mismatch = &report.root_mismatches[0];
        match mismatch {
            RootMismatch::LeafRecomputation {
                author_key,
                anchor_seq,
                stored_root,
                recomputed_root,
            } => {
                assert_eq!(*author_key, VerifyingKey::new([0xBB; 32]));
                assert_eq!(*anchor_seq, 0);
                assert_eq!(*stored_root, lying_root);
                assert_eq!(*recomputed_root, recomputed);
            }
            RootMismatch::ChainDisagreement { .. } => {
                return Err("expected LeafRecomputation, got ChainDisagreement".into());
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn unanchored_ops_are_not_flagged() -> TestResult {
        // Threshold 16: two ops stay below it, so nothing is ever anchored. With no
        // anchored commitment, their absence-from-anchors is expected, not
        // "missing" — the documented limit that only anchored ops are covered.
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let store = store_over(blob.clone(), 16);
        store.remember(remember_input("a")).await?;
        store.remember(remember_input("b")).await?;

        let oplog = OpLogStore::new(blob.clone());
        let report = reconcile(&blob, &oplog, TEAM).await?;

        assert!(report.ok, "unanchored ops are not suppression: {report:?}");
        assert_eq!(report.total_anchored_ops, 0);
        assert_eq!(report.checked_batches, 0);
        assert!(report.missing_ops.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn report_serializes_with_hex_hashes() -> TestResult {
        // The MCP tool serializes the report verbatim; confirm the wire shape.
        let report = ReconcileReport {
            checked_batches: 1,
            total_anchored_ops: 1,
            missing_ops: Vec::new(),
            root_mismatches: Vec::new(),
            ok: true,
        };
        let json = serde_json::to_value(&report)?;
        assert_eq!(
            json.get("ok").and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert!(json.get("missing_ops").is_some());
        assert!(json.get("root_mismatches").is_some());
        Ok(())
    }

    /// A [`ChainRootReader`] returning a canned root, or a storage error when
    /// `None`, so a plain `cargo test` exercises the trust-minimized chain
    /// comparison with no live node — the seam `SubxtAnchor` really implements.
    struct MockChainReader {
        on_chain_root: Option<Blake3Hash>,
    }

    #[async_trait::async_trait]
    impl ChainRootReader for MockChainReader {
        async fn read_anchored_root(
            &self,
            _block_hash: &str,
            _extrinsic_hash: &str,
        ) -> Result<Blake3Hash, MemError> {
            self.on_chain_root
                .ok_or_else(|| MemError::Storage("mock: anchor block not retained".to_owned()))
        }
    }

    /// A self-consistent on-chain anchor record (`root == merkle_root(leaves)`) so
    /// only the CHAIN comparison — not the leaf check — decides the outcome.
    fn on_chain_record(root: Blake3Hash, leaf: Blake3Hash) -> AnchorRecord {
        AnchorRecord {
            seq: 0,
            author_key: VerifyingKey::new([0xAB; 32]),
            root,
            meta: BatchMeta {
                team: TEAM.to_owned(),
                first_lamport: 0,
                last_lamport: 0,
                op_count: 1,
            },
            leaves: vec![leaf],
            receipt: AnchorReceipt {
                root,
                reference: AnchorRef::OnChain {
                    block_hash: "0x00".to_owned(),
                    extrinsic_hash: "0x01".to_owned(),
                },
            },
        }
    }

    /// A base report as the bucket-side pass would leave it for a clean record.
    fn clean_base() -> ReconcileReport {
        ReconcileReport {
            checked_batches: 1,
            total_anchored_ops: 1,
            missing_ops: Vec::new(),
            root_mismatches: Vec::new(),
            ok: true,
        }
    }

    #[tokio::test]
    async fn chain_agreeing_root_reconciles_ok() -> TestResult {
        // The chain returns the SAME root the bucket stored: no forgery, ok holds.
        let leaf = content_hash(b"leaf");
        let root = merkle_root(&[leaf]);
        let record = on_chain_record(root, leaf);
        let reader = MockChainReader {
            on_chain_root: Some(root),
        };

        let report = verify_on_chain_roots(&[record], clean_base(), &reader).await?;

        assert!(
            report.ok,
            "matching on-chain root reconciles ok: {report:?}"
        );
        assert!(report.root_mismatches.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn chain_disagreeing_root_is_flagged() -> TestResult {
        // The record is internally consistent (passes the leaf check) but the root
        // the chain actually committed differs — a record the bucket forged
        // self-consistently yet never committed. Only chain readback catches it;
        // this is the trust-minimized detection reconcile_with_chain exists for.
        let leaf = content_hash(b"leaf");
        let stored_root = merkle_root(&[leaf]);
        let chain_root = content_hash(b"the-root-actually-committed");
        assert_ne!(
            stored_root, chain_root,
            "the forgery must differ from the chain root"
        );
        let record = on_chain_record(stored_root, leaf);
        let reader = MockChainReader {
            on_chain_root: Some(chain_root),
        };

        let report = verify_on_chain_roots(&[record], clean_base(), &reader).await?;

        assert!(
            !report.ok,
            "a chain-disagreeing root must fail reconciliation"
        );
        assert_eq!(report.root_mismatches.len(), 1, "{report:?}");
        match &report.root_mismatches[0] {
            RootMismatch::ChainDisagreement {
                author_key,
                anchor_seq,
                stored_root: reported_stored,
                on_chain_root,
            } => {
                assert_eq!(*author_key, VerifyingKey::new([0xAB; 32]));
                assert_eq!(*anchor_seq, 0);
                assert_eq!(*reported_stored, stored_root);
                assert_eq!(*on_chain_root, chain_root);
            }
            RootMismatch::LeafRecomputation { .. } => {
                return Err("expected ChainDisagreement, got LeafRecomputation".into());
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn unreadable_chain_anchor_errors_not_ok() -> TestResult {
        // "could not verify" must surface as an error, never collapse into a clean
        // report — the honest-limits invariant of the readback.
        let leaf = content_hash(b"leaf");
        let root = merkle_root(&[leaf]);
        let record = on_chain_record(root, leaf);
        let reader = MockChainReader {
            on_chain_root: None,
        };

        let result = verify_on_chain_roots(&[record], clean_base(), &reader).await;

        assert!(
            matches!(result, Err(MemError::Storage(_))),
            "an unreadable anchor location must error, not report ok",
        );
        Ok(())
    }
}
