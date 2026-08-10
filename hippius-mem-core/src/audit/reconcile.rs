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
//!   inconsistent ([`RootMismatch`]);
//! - **a broken author chain** — an author whose ops did not form one
//!   genesis-rooted chain on this read, so the verified read quarantined the
//!   losing branch ([`QuarantinedAuthor`]). This one needs no anchoring at all and
//!   so is the only evidence here that covers an UNANCHORED op; in exchange it
//!   names only that a chain broke, never why (see that type).
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
use crate::oplog::{Op, OpLogStore, QuarantinedAuthor, VerifyingKey};
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
///
/// `#[non_exhaustive]`: this is a `pub` re-exported type an external verifier may
/// match on, and the audit path grows new checks (this is how `ChainSignerMismatch`
/// was added) — reserving the escape hatch keeps a future variant from being a
/// breaking change for downstream matchers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
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
    /// The anchoring extrinsic on-chain was signed by an account that does NOT
    /// match the record's claimed `author_key` — so some other funded account
    /// committed this root and attributed it to `author_key`. Anchoring uses the
    /// author's OWN signing seed (see `Config::build_anchor`), so on-chain signer
    /// and `author_key` must be the same account; a divergence means the
    /// attribution is forged even when the committed root itself matches. Without
    /// this check `remark_with_event`'s open callability let any account anchor a
    /// forged-but-self-consistent record under a victim's key and still earn a
    /// `ChainVerified` report. Only raised by [`reconcile_with_chain`].
    ChainSignerMismatch {
        /// The author the record claims anchored it.
        author_key: VerifyingKey,
        /// The per-author sequence number of the offending record.
        anchor_seq: u64,
        /// The account that actually signed the anchoring extrinsic on-chain (the
        /// sr25519 `AccountId32`, which for a normal account equals the public
        /// key). Typed as [`VerifyingKey`] so it serializes as lowercase hex like
        /// every other key/hash in the report, not a raw byte array.
        on_chain_signer: VerifyingKey,
    },
}

/// Which pass produced a [`ReconcileReport`] — and therefore how far its `ok`
/// may be trusted.
///
/// This is the field an operator (or a "verifiable-first" consumer) must read
/// alongside `ok`: a clean `ok` from a bucket-only check is a materially weaker
/// claim than a clean `ok` confirmed against the chain, and the two were
/// previously indistinguishable in the serialized report — a caller could
/// over-read a local self-consistency pass as a trust-minimized attestation.
///
/// # Stability
///
/// Both variants are a stable contract callers may match on. `#[non_exhaustive]`
/// reserves room for a future intermediate mode without a breaking change. The
/// serde default is deliberately the SAFE direction: an absent/unknown
/// `verification` deserializes as [`BucketOnly`](Self::BucketOnly), never
/// silently as the stronger [`ChainVerified`](Self::ChainVerified).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Verification {
    /// Anchor records were checked only for internal consistency with the visible
    /// op-log, NOT against any external commitment. `AnchorRecord`s carry no
    /// signature, so an untrusted bucket can fabricate self-consistent ones —
    /// `ok: true` here means "no local loss detected", not a trust-minimized
    /// attestation. Produced by plain [`reconcile`].
    #[default]
    BucketOnly,
    /// The chain pass ran and confirmed at least one on-chain anchor record's
    /// root against the finalized chain commitment (which the bucket cannot
    /// forge), so `ok: true` here is a trust-minimized attestation over the
    /// on-chain records. Any `AnchorRef::Local` records in the same report have
    /// no external commitment and still carry only the bucket-side guarantee. A
    /// report with ZERO on-chain records stays [`BucketOnly`](Self::BucketOnly)
    /// rather than falsely claiming this mode. Produced by `reconcile_with_chain`
    /// (feature `chain`).
    ChainVerified,
}

/// The outcome of reconciling a team's op-log against its anchored roots.
///
/// `ok` is the single yes/no an operator reads first; it is derived — and kept
/// in lockstep with the evidence vectors — as `missing_ops.is_empty() &&
/// root_mismatches.is_empty() && quarantined_authors.is_empty()`. The counts
/// (`checked_batches`, `total_anchored_ops`) describe the coverage of the
/// anchoring check, so a clean `ok` over zero batches is distinguishable from a
/// clean `ok` over many. Read `ok` together with
/// [`verification`](Self::verification): the same `ok: true` means different
/// things in bucket-only versus chain-verified mode.
///
/// # `ok` covers two different questions
///
/// `missing_ops` and `root_mismatches` answer "does the visible op-log reconcile
/// against the anchored roots"; `quarantined_authors` answers "did every author's
/// ops form one chain on this read". They are independent — a log can fail either
/// with the other clean — and `ok` deliberately folds both, so a caller that
/// branches only on `ok` cannot be silently wrong about the log's health. The
/// cost is that `ok: false` alone does not say WHICH failed: a caller that needs
/// to tell anchoring loss from chain breakage must read the vectors, which is why
/// all three stay on the wire beside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconcileReport {
    /// How many anchor records were examined.
    pub checked_batches: usize,
    /// The total number of anchored leaves across every examined record — the
    /// size of the commitment set this check covered.
    pub total_anchored_ops: usize,
    /// Anchored ops absent from the visible op-log (suppression evidence).
    ///
    /// A single entry can also be a TRANSIENT artifact: the op-log reader skips
    /// an individually unfetchable object (warn + retry next sync), so an op
    /// whose GET failed this read shows up here without having been suppressed.
    /// Re-run before escalating one missing op; a systemic outage (every GET
    /// failing) errors the whole reconcile instead of reporting false evidence.
    pub missing_ops: Vec<MissingOp>,
    /// Anchor records whose `root` disagrees with their own leaves (forgery).
    pub root_mismatches: Vec<RootMismatch>,
    /// Authors whose ops did not form one genesis-rooted chain on the read this
    /// report was built from, with how many ops that cost them.
    ///
    /// Independent of the two vectors above: it needs no anchor record, so it is
    /// the only evidence here that can implicate an op which was never anchored.
    /// It says a chain broke, NOT why — a hostile fork, a dropped mid-chain
    /// object, one merely unfetched or unlisted by this read, and an honest
    /// writer's cancelled-but-durable append are indistinguishable at this
    /// granularity. See [`QuarantinedAuthor`] for the full list and for which of
    /// those clear themselves on a later read (the two fetch/listing causes
    /// always do; a cancelled-but-durable append usually does too, best-effort;
    /// a hostile fork and a genuinely dropped object do not).
    ///
    /// `#[serde(default)]`: a payload predating this field deserializes to an
    /// empty vector, which is the safe direction — no evidence claimed rather
    /// than evidence invented.
    #[serde(default)]
    pub quarantined_authors: Vec<QuarantinedAuthor>,
    /// `true` exactly when all three evidence vectors are empty.
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
    /// the module docs). [`verification`](Self::verification) records which of
    /// the two produced THIS report, so the caveat is machine-readable rather
    /// than only prose. The caveat is about ANCHORING only: `quarantined_authors`
    /// is derived from the op-log's own signatures and hash links, so it needs no
    /// anchor record and is unaffected by which of the two passes ran.
    pub ok: bool,
    /// Which pass produced this report — and therefore how far `ok` can be
    /// trusted (see [`Verification`]). `#[serde(default)]` keeps the field
    /// backward-compatible on the wire and defaults to the weaker
    /// [`Verification::BucketOnly`], so a report is never over-read as
    /// chain-verified.
    #[serde(default)]
    pub verification: Verification,
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
    // The quarantine-reporting read, not `read_all`: a broken author chain is
    // evidence this report carries, and `read_all` discards it.
    let (ops, quarantined_authors) = oplog.read_all_reporting_quarantine(team).await?;
    Ok(reconcile_records(&records, &ops, quarantined_authors))
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
///
/// `quarantined_authors` comes from the SAME verified read that produced `ops` —
/// it is what that read dropped, so it cannot be recomputed from `ops` (the
/// dropped ops are, by construction, no longer there).
fn reconcile_records(
    records: &[AnchorRecord],
    ops: &[Op],
    quarantined_authors: Vec<QuarantinedAuthor>,
) -> ReconcileReport {
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

    let ok = missing_ops.is_empty() && root_mismatches.is_empty() && quarantined_authors.is_empty();
    ReconcileReport {
        checked_batches: records.len(),
        total_anchored_ops: distinct_anchored.len(),
        missing_ops,
        root_mismatches,
        quarantined_authors,
        ok,
        // This is the bucket-side pass by construction; `reconcile_with_chain`
        // upgrades the report to `ChainVerified` only after the chain readback.
        verification: Verification::BucketOnly,
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
    /// Read back the anchored commitment at `(block_hash, extrinsic_hash)`: both
    /// the committed root AND the account that signed the anchoring extrinsic.
    ///
    /// The signer is returned so [`verify_on_chain_roots`] can confirm it matches
    /// the record's `author_key` — `remark_with_event` is callable by any funded
    /// account, so verifying WHAT was committed without verifying WHO committed it
    /// would let an attacker anchor a forged root under a victim's key.
    ///
    /// # Errors
    ///
    /// [`MemError::Storage`] if the location cannot be read back or the extrinsic
    /// is unsigned / its signer cannot be decoded — an unreadable or
    /// unattributable anchor must surface as an error, never a clean report
    /// ("could not verify" is not "verified").
    async fn read_anchored_root(
        &self,
        block_hash: &str,
        extrinsic_hash: &str,
    ) -> Result<AnchoredExtrinsic, MemError>;
}

/// What a [`ChainRootReader`] reads back from an on-chain anchor.
#[cfg(any(feature = "chain", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AnchoredExtrinsic {
    /// The Merkle root committed in the extrinsic's remark payload.
    pub root: Blake3Hash,
    /// The `AccountId32` bytes of the account that signed the anchoring extrinsic,
    /// checked against the record's `author_key`.
    pub signer: [u8; 32],
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
    // Count records actually confirmed against the chain. An `AnchorRef::Local`
    // record has no on-chain commitment, so the loop skips it — a set of ALL
    // local records reaches the end with zero readbacks and must NOT be labeled
    // chain-verified (see the stamp below).
    let mut chain_checked = 0_usize;
    for record in records {
        let AnchorRef::OnChain {
            block_hash,
            extrinsic_hash,
        } = &record.receipt.reference
        else {
            continue;
        };
        let AnchoredExtrinsic {
            root: on_chain_root,
            signer,
        } = reader
            .read_anchored_root(block_hash, extrinsic_hash)
            .await?;
        chain_checked += 1;
        // WHO anchored it: the anchoring extrinsic must be signed by the record's
        // own author (anchoring uses the author's signing seed). A different
        // signer means someone else committed this root under `author_key` — a
        // forged attribution, distinct from a root disagreement, so it is its own
        // variant and a record can fail both.
        if signer != *record.author_key.as_bytes() {
            report
                .root_mismatches
                .push(RootMismatch::ChainSignerMismatch {
                    author_key: record.author_key,
                    anchor_seq: record.seq,
                    on_chain_signer: VerifyingKey::new(signer),
                });
        }
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
    // Recomputed with the SAME three-vector formula `reconcile_records` used. The
    // chain pass only ever ADDS `root_mismatches`, so leaving `quarantined_authors`
    // out here would let a chain-verified run reset `ok` to true over a broken
    // author chain the bucket-side pass had already failed on.
    report.ok = report.missing_ops.is_empty()
        && report.root_mismatches.is_empty()
        && report.quarantined_authors.is_empty();
    // Only claim the trust-minimized guarantee if the chain pass actually
    // confirmed at least one on-chain anchor (unreadable anchors already returned
    // early via `?`). An all-`Local` record set reaches here with zero readbacks;
    // labeling THAT `ChainVerified` would let an untrusted bucket serving
    // forged-but-self-consistent `Local` records obtain a chain-verified `ok` —
    // the exact over-read this field exists to prevent — so it stays bucket-only.
    if chain_checked > 0 {
        report.verification = Verification::ChainVerified;
    }
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
    let (ops, quarantined_authors) = oplog.read_all_reporting_quarantine(team).await?;
    let report = reconcile_records(&records, &ops, quarantined_authors);
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

    use super::{
        AnchoredExtrinsic, ChainRootReader, QuarantinedAuthor, ReconcileReport, RootMismatch,
        Verification, reconcile, verify_on_chain_roots,
    };
    use crate::NetworkPrefix;
    use crate::audit::anchor::{AnchorReceipt, AnchorRef, BatchMeta, NoopAnchor};
    use crate::audit::batch::{AnchorRecord, persist_anchor_record, read_anchor_records};
    use crate::audit::merkle::merkle_root;
    use crate::crypto::{SecretKey, content_hash};
    use crate::domain::Blake3Hash;
    use crate::error::MemError;
    use crate::index::{HashEmbedder, InMemoryIndex};
    use crate::oplog::{Op, OpContent, OpKind, OpLogStore, Signer, Sr25519Signer, VerifyingKey};
    use crate::store::{BlobStore, MemoryBlobStore, MemoryStore, RememberInput};
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;
    use ulid::Ulid;

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
        assert_eq!(
            report.verification,
            Verification::BucketOnly,
            "plain reconcile is a bucket-only check, not a chain-verified attestation"
        );
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

        let report = super::reconcile_records(&records, &[], Vec::new());
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
    async fn a_forked_author_chain_is_reported_as_quarantined() -> TestResult {
        // D8: a fork suppresses the losing branch with only a `tracing::warn!`.
        // Before this field existed the report below came back `ok: true` with
        // every vector empty, so an operator had no API-visible evidence at all.
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let store = store_over(blob.clone(), 1);
        store.remember(remember_input("first")).await?;
        store.remember(remember_input("second")).await?;

        let oplog = OpLogStore::new(blob.clone());
        let ops = oplog.read_all(TEAM).await?;
        let tail = ops.last().ok_or("expected two ops")?;

        // A sibling sharing the tail's `prev_op_hash` forks this author's chain.
        // Both branches are height-1 leaves, so `longest_rooted_chain` breaks the
        // tie on the LOWER `(lamport, op_id, hash)` — the sibling's Lamport is
        // deliberately higher, so the SIBLING is what gets quarantined and the
        // anchored tail survives.
        //
        // That is what isolates the signal: the sibling was appended directly and
        // never anchored, so `missing_ops` and `root_mismatches` both stay empty
        // and the assertions below can only be satisfied by the quarantine
        // evidence and by `ok` folding it in.
        let signer = Sr25519Signer::from_seed_with_prefix(&[9u8; 32], NetworkPrefix::HIPPIUS)?;
        let sibling = Op::create_signed(
            &signer,
            OpContent {
                op_id: Ulid::new(),
                lamport: tail.lamport.saturating_add(1),
                key_epoch: tail.key_epoch,
                kind: OpKind::Remember,
                note_id: tail.note_id,
                object_key: format!("{TEAM}/global/{}/ver_forked-sibling", tail.note_id),
                cid: content_hash(b"the forked sibling's ciphertext"),
                prev_op_hash: tail.prev_op_hash,
            },
        );
        oplog.append(TEAM, &sibling).await?;

        let report = reconcile(&blob, &oplog, TEAM).await?;

        assert_eq!(
            report.quarantined_authors,
            vec![QuarantinedAuthor {
                author: signer.author_ss58(),
                dropped_ops: 1,
            }],
            "the forked author is named with the exact count of ops the read dropped: {report:?}"
        );
        assert!(
            !report.ok,
            "a quarantined author must fail reconciliation: {report:?}"
        );
        assert!(
            report.missing_ops.is_empty(),
            "no ANCHORED op went missing — the quarantined sibling was never anchored, so this \
             report's failure is the quarantine signal alone: {report:?}"
        );
        assert!(
            report.root_mismatches.is_empty(),
            "no anchor record was forged: {report:?}"
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
            RootMismatch::ChainSignerMismatch { .. } => {
                return Err("expected LeafRecomputation, got ChainSignerMismatch".into());
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
        let author =
            Sr25519Signer::from_seed_with_prefix(&[3u8; 32], NetworkPrefix::HIPPIUS)?.author_ss58();
        let report = ReconcileReport {
            checked_batches: 1,
            total_anchored_ops: 1,
            missing_ops: Vec::new(),
            root_mismatches: Vec::new(),
            quarantined_authors: vec![QuarantinedAuthor {
                author: author.clone(),
                dropped_ops: 2,
            }],
            ok: true,
            verification: Verification::BucketOnly,
        };
        let json = serde_json::to_value(&report)?;
        assert_eq!(
            json.get("ok").and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert!(json.get("missing_ops").is_some());
        assert!(json.get("root_mismatches").is_some());
        // Quarantine evidence reaches a JSON consumer as the SS58 string plus a
        // plain count — not a byte array, and not only a log line.
        assert_eq!(
            json.pointer("/quarantined_authors/0/author")
                .and_then(serde_json::Value::as_str),
            Some(author.as_str())
        );
        assert_eq!(
            json.pointer("/quarantined_authors/0/dropped_ops")
                .and_then(serde_json::Value::as_u64),
            Some(2)
        );
        // The trust mode is on the wire (a fieldless enum serializes to its
        // variant name), so a JSON consumer can tell a bucket-only `ok` from a
        // chain-verified one without reading Rust docs.
        assert_eq!(
            json.get("verification").and_then(serde_json::Value::as_str),
            Some("BucketOnly")
        );
        Ok(())
    }

    /// A [`ChainRootReader`] returning a canned root + signer, or a storage error
    /// when the root is `None`, so a plain `cargo test` exercises the trust-
    /// minimized chain comparison with no live node — the seam `SubxtAnchor`
    /// really implements. `signer` defaults to the anchor records' author
    /// (`[0xAB; 32]`) so the signer check passes unless a test overrides it.
    struct MockChainReader {
        on_chain_root: Option<Blake3Hash>,
        signer: [u8; 32],
    }

    impl MockChainReader {
        /// A reader whose signer matches [`on_chain_record`]/[`local_record`]'s
        /// `author_key`, so only the ROOT comparison decides the outcome.
        fn with_root(on_chain_root: Option<Blake3Hash>) -> Self {
            Self {
                on_chain_root,
                signer: [0xAB; 32],
            }
        }
    }

    #[async_trait::async_trait]
    impl ChainRootReader for MockChainReader {
        async fn read_anchored_root(
            &self,
            _block_hash: &str,
            _extrinsic_hash: &str,
        ) -> Result<AnchoredExtrinsic, MemError> {
            let root = self
                .on_chain_root
                .ok_or_else(|| MemError::Storage("mock: anchor block not retained".to_owned()))?;
            Ok(AnchoredExtrinsic {
                root,
                signer: self.signer,
            })
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

    /// A self-consistent LOCAL anchor record (no on-chain reference), so
    /// `verify_on_chain_roots` skips it and performs zero chain readbacks.
    fn local_record(root: Blake3Hash, leaf: Blake3Hash) -> AnchorRecord {
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
                reference: AnchorRef::Local { seq: 0 },
            },
        }
    }

    /// A base report as the bucket-side pass would leave it for a clean record.
    fn clean_base() -> ReconcileReport {
        base_with_quarantine(Vec::new())
    }

    /// [`clean_base`], but carrying quarantine evidence the bucket-side pass
    /// already found — the state `verify_on_chain_roots` must not erase when it
    /// recomputes `ok`.
    fn base_with_quarantine(quarantined_authors: Vec<QuarantinedAuthor>) -> ReconcileReport {
        let ok = quarantined_authors.is_empty();
        ReconcileReport {
            checked_batches: 1,
            total_anchored_ops: 1,
            missing_ops: Vec::new(),
            root_mismatches: Vec::new(),
            quarantined_authors,
            ok,
            // Simulates the bucket-side pass; `verify_on_chain_roots` is what
            // upgrades it, so the chain tests can assert that transition.
            verification: Verification::BucketOnly,
        }
    }

    #[tokio::test]
    async fn chain_agreeing_root_reconciles_ok() -> TestResult {
        // The chain returns the SAME root the bucket stored: no forgery, ok holds.
        let leaf = content_hash(b"leaf");
        let root = merkle_root(&[leaf]);
        let record = on_chain_record(root, leaf);
        let reader = MockChainReader::with_root(Some(root));

        let report = verify_on_chain_roots(&[record], clean_base(), &reader).await?;

        assert!(
            report.ok,
            "matching on-chain root reconciles ok: {report:?}"
        );
        assert!(report.root_mismatches.is_empty());
        assert_eq!(
            report.verification,
            Verification::ChainVerified,
            "a report that passed chain readback is a trust-minimized attestation"
        );
        Ok(())
    }

    #[tokio::test]
    async fn chain_pass_does_not_clear_ok_over_a_quarantined_author() -> TestResult {
        // `verify_on_chain_roots` recomputes `ok` from scratch, and the chain pass
        // only ever ADDS root mismatches — so a formula that forgot
        // `quarantined_authors` would hand back `ok: true` for a log the
        // bucket-side pass had already failed, purely because the chain agreed.
        let leaf = content_hash(b"leaf");
        let root = merkle_root(&[leaf]);
        let record = on_chain_record(root, leaf);
        let reader = MockChainReader::with_root(Some(root));
        let quarantined = vec![QuarantinedAuthor {
            author: Sr25519Signer::from_seed_with_prefix(&[4u8; 32], NetworkPrefix::HIPPIUS)?
                .author_ss58(),
            dropped_ops: 3,
        }];

        let report = verify_on_chain_roots(
            &[record],
            base_with_quarantine(quarantined.clone()),
            &reader,
        )
        .await?;

        assert!(
            !report.ok,
            "an agreeing chain root must not clear a quarantined author: {report:?}"
        );
        assert_eq!(
            report.quarantined_authors, quarantined,
            "the chain pass carries the evidence through untouched: {report:?}"
        );
        assert!(
            report.root_mismatches.is_empty(),
            "the chain agreed — the only failing evidence is the quarantine: {report:?}"
        );
        assert_eq!(
            report.verification,
            Verification::ChainVerified,
            "the chain readback still ran; `ok` and `verification` are separate facts"
        );
        Ok(())
    }

    #[tokio::test]
    async fn all_local_records_stay_bucket_only_not_chain_verified() -> TestResult {
        // A record set with no on-chain anchors gets zero chain readbacks, so the
        // chain pass confirmed nothing — the report must NOT claim ChainVerified,
        // or an untrusted bucket serving forged-but-self-consistent Local records
        // would obtain a chain-verified `ok`. The `None`-backed reader also errors
        // if consulted, so reaching Ok additionally proves no readback happened.
        let leaf = content_hash(b"leaf");
        let root = merkle_root(&[leaf]);
        let reader = MockChainReader::with_root(None);

        let report =
            verify_on_chain_roots(&[local_record(root, leaf)], clean_base(), &reader).await?;

        assert_eq!(
            report.verification,
            Verification::BucketOnly,
            "zero on-chain readbacks must not be labeled chain-verified: {report:?}"
        );
        Ok(())
    }

    #[test]
    fn report_without_verification_deserializes_as_bucket_only() {
        // A payload predating the `verification` field must still deserialize —
        // and to the SAFE mode, never silently as the stronger ChainVerified.
        let json = serde_json::json!({
            "checked_batches": 0,
            "total_anchored_ops": 0,
            "missing_ops": [],
            "root_mismatches": [],
            "ok": true
        });
        let report: ReconcileReport =
            serde_json::from_value(json).expect("a legacy verification-less payload deserializes");
        assert_eq!(report.verification, Verification::BucketOnly);
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
        let reader = MockChainReader::with_root(Some(chain_root));

        let report = verify_on_chain_roots(&[record], clean_base(), &reader).await?;

        assert!(
            !report.ok,
            "a chain-disagreeing root must fail reconciliation"
        );
        assert_eq!(
            report.verification,
            Verification::ChainVerified,
            "verification records WHICH pass ran (chain), independent of the ok outcome"
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
            RootMismatch::ChainSignerMismatch { .. } => {
                return Err("expected ChainDisagreement, got ChainSignerMismatch".into());
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn chain_signer_not_matching_author_key_is_flagged() -> TestResult {
        // remark_with_event is callable by any funded account. A record whose ROOT
        // matches the chain but whose anchoring extrinsic was signed by a DIFFERENT
        // account is a forged attribution — someone else anchored it under this
        // author's key. It must be reported and `ok` must fail, even though the
        // root itself agrees.
        let leaf = content_hash(b"leaf");
        let root = merkle_root(&[leaf]);
        let record = on_chain_record(root, leaf); // author_key = [0xAB; 32]
        let reader = MockChainReader {
            on_chain_root: Some(root),
            signer: [0xCC; 32], // a DIFFERENT account than the record's author
        };

        let report = verify_on_chain_roots(&[record], clean_base(), &reader).await?;

        assert!(
            !report.ok,
            "a signer that is not the record's author must fail ok: {report:?}"
        );
        assert_eq!(report.root_mismatches.len(), 1, "{report:?}");
        match &report.root_mismatches[0] {
            RootMismatch::ChainSignerMismatch {
                author_key,
                anchor_seq,
                on_chain_signer,
            } => {
                assert_eq!(*author_key, VerifyingKey::new([0xAB; 32]));
                assert_eq!(*anchor_seq, 0);
                assert_eq!(*on_chain_signer, VerifyingKey::new([0xCC; 32]));
            }
            RootMismatch::ChainDisagreement { .. } => {
                return Err("expected ChainSignerMismatch, got ChainDisagreement".into());
            }
            RootMismatch::LeafRecomputation { .. } => {
                return Err("expected ChainSignerMismatch, got LeafRecomputation".into());
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
        let reader = MockChainReader::with_root(None);

        let result = verify_on_chain_roots(&[record], clean_base(), &reader).await;

        assert!(
            matches!(result, Err(MemError::Storage(_))),
            "an unreadable anchor location must error, not report ok",
        );
        Ok(())
    }
}
