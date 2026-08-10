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
//!   so is one of the two kinds of evidence here that cover an UNANCHORED op; in
//!   exchange it names only that a chain broke, never why (see that type);
//! - **a truncated tail** — an author whose own signed head pointer names a chain
//!   tip the visible op-log does not contain ([`SuppressedTail`]). This is the
//!   other check that needs no anchor record, and the only one that survives a
//!   bucket dropping an op TOGETHER WITH the anchor record covering it, because
//!   it rests on the author's signature rather than on anything the bucket serves.
//!
//! It CANNOT detect suppression of an op that was **never anchored** *and* is not
//! the tail its author's head names. Only ops that were batched and anchored carry
//! a commitment to reconcile against; an op dropped before its batch was anchored
//! leaves no anchored leaf, so its absence is indistinguishable from "never
//! written". Lowering the anchor threshold shrinks this window but never closes
//! it. This is an honest, fundamental limit of anchoring-after-the-fact, not a
//! deficiency of this check.
//!
//! The head-pointer check narrows the tail case; it does not close it. A bucket
//! that drops an author's head object along with the tail op leaves no claim to
//! contradict, and one that serves an OLDER validly-signed head names a tip that
//! IS visible. Both are silent here — see [`SuppressedTail`] for the residual and
//! what would cover it.
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

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::audit::anchor::AnchorRef;
use crate::audit::batch::{AnchorRecord, read_anchor_records};
use crate::audit::merkle::merkle_root;
use crate::domain::{Blake3Hash, Ss58};
use crate::error::MemError;
use crate::oplog::{HeadPointer, Op, OpLogStore, QuarantinedAuthor, VerifyingKey, read_heads};
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

/// An author whose signed head names a tip the visible op-log does not contain.
///
/// This is the only evidence in the report that covers TAIL truncation. The hash
/// chain cannot: nothing points at the newest op, so a truncated view is
/// indistinguishable from one where the tail op was never written. A signed
/// [`HeadPointer`] is the claim that closes that asymmetry — the author says
/// "`claimed_tip` is mine", and the bucket cannot forge or alter that claim
/// without the author's secret key.
///
/// # What produces one, and which causes self-clear
///
/// - **The tail op was suppressed by the bucket** — the finding this exists for.
///   Does NOT self-clear: the op stays gone until it is restored, so every later
///   read reports it again.
/// - **The head landed but the op object is not visible on THIS read** — its GET
///   failed, or the listing omitted it while the head was served (the same
///   eventual-consistency lag [`QuarantinedAuthor`] documents). Transient:
///   self-clears on the next read once the object is seen.
/// - **The tail op was quarantined by a chain break** — the op is in the bucket
///   but the verified read dropped it, so it is not in `ops` to match. Then
///   [`ReconcileReport::quarantined_authors`] names the same author too, and the
///   PAIR means fork, not suppression. Read the two vectors together.
///
/// So a single entry is a reason to look, not proof of an attack. Re-run before
/// escalating; an entry that survives re-reads and comes with no quarantine entry
/// is the suppression case.
///
/// # The residual this does NOT cover
///
/// An author with ops and NO head object makes no claim, so nothing here fires —
/// a bucket that drops the head along with the tail op is silent. So is a bucket
/// that serves an OLDER, still-validly-signed head consistent with the truncated
/// view: it verifies, and its `claimed_tip` IS visible. Covering either needs
/// state the bucket does not control — a local high-water mark remembered across
/// syncs, which makes a dropped or rolled-back head a regression on any machine
/// that has already seen the newer head. A machine that never saw it stays blind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuppressedTail {
    /// The SS58 of the author whose head names a missing tip — cryptographically
    /// bound to `author_key` by the head read's identity check, never merely
    /// claimed.
    pub author: Ss58,
    /// The sr25519 public key whose signature over the head was verified.
    pub author_key: VerifyingKey,
    /// The tip the author signed.
    pub claimed_tip: Blake3Hash,
    /// The Lamport time of that tip.
    pub claimed_lamport: u64,
    /// The highest Lamport this author DOES have a visible op for, if any.
    ///
    /// `None` means not one op of this author is visible — the whole-author case,
    /// not merely a truncated tail. Otherwise the distance to `claimed_lamport`
    /// bounds how much of the tail is unaccounted for, though it does not name the
    /// individual ops: only the tip is signed.
    pub visible_lamport: Option<u64>,
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
/// root_mismatches.is_empty() && quarantined_authors.is_empty() &&
/// suppressed_tails.is_empty()`. The counts
/// (`checked_batches`, `total_anchored_ops`) describe the coverage of the
/// anchoring check, so a clean `ok` over zero batches is distinguishable from a
/// clean `ok` over many. Read `ok` together with
/// [`verification`](Self::verification): the same `ok: true` means different
/// things in bucket-only versus chain-verified mode.
///
/// # `ok` covers three different questions
///
/// `missing_ops` and `root_mismatches` answer "does the visible op-log reconcile
/// against the anchored roots"; `quarantined_authors` answers "did every author's
/// ops form one chain on this read"; `suppressed_tails` answers "does every
/// author's own signed head name a tip we can see". They are independent — a log
/// can fail any one with the others clean — and `ok` deliberately folds all
/// three, so a caller that branches only on `ok` cannot be silently wrong about
/// the log's health. The cost is that `ok: false` alone does not say WHICH
/// failed: a caller that needs to tell anchoring loss from chain breakage from
/// tail truncation must read the vectors, which is why all four stay on the wire
/// beside it.
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
    /// Authors whose own signed head pointer names a chain tip the visible op-log
    /// does not contain — TAIL-truncation evidence.
    ///
    /// Independent of the three vectors above, and the only one that covers a tail
    /// dropped together with the anchor record that would have committed it: it
    /// rests on the author's signature over their own tip, not on any anchor
    /// record the bucket still serves. See [`SuppressedTail`] for the full cause
    /// list, which of those self-clear, and the residual this cannot see (an
    /// author with no head object at all, or an older validly-signed head served
    /// in place of the current one).
    ///
    /// `#[serde(default)]`: a payload predating this field deserializes to an
    /// empty vector, which is the safe direction — no evidence claimed rather than
    /// evidence invented, exactly as for `quarantined_authors`.
    #[serde(default)]
    pub suppressed_tails: Vec<SuppressedTail>,
    /// `true` exactly when all four evidence vectors are empty.
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
    /// is derived from the op-log's own signatures and hash links, and
    /// `suppressed_tails` from the authors' own signed head pointers, so neither
    /// needs an anchor record and both are unaffected by which of the two passes
    /// ran.
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
/// Reads every anchor record, every signed head pointer, and the full op-log, then
/// for each record: (a) recomputes `merkle_root(leaves)` and flags a
/// [`RootMismatch`] if it disagrees with the stored `root`; (b) flags a
/// [`MissingOp`] for every leaf that no present op reproduces. Separately, for
/// each verified head it flags a [`SuppressedTail`] when no present op reproduces
/// the tip that head claims. See the module docs for what this detects and the
/// honest limits.
///
/// # Errors
///
/// Propagates whatever [`read_anchor_records`], [`read_heads`], or
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
    let heads = read_heads(blob, team).await?;
    // The quarantine-reporting read, not `read_all`: a broken author chain is
    // evidence this report carries, and `read_all` discards it.
    let (ops, quarantined_authors) = oplog.read_all_reporting_quarantine(team).await?;
    Ok(reconcile_records(
        &records,
        &ops,
        &heads,
        quarantined_authors,
    ))
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
///
/// `heads` are the already-verified head pointers [`read_heads`] returned;
/// verification lives there, so this function only compares.
fn reconcile_records(
    records: &[AnchorRecord],
    ops: &[Op],
    heads: &[HeadPointer],
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

    // Reuses the `present` set built above rather than rebuilding it: `Op::hash`
    // re-derives each op's signing bytes and hashes them, so a second pass over a
    // long log is real work, not a free iteration.
    let suppressed_tails = suppressed_tails_against(heads, ops, &present);

    let ok = missing_ops.is_empty()
        && root_mismatches.is_empty()
        && quarantined_authors.is_empty()
        && suppressed_tails.is_empty();
    ReconcileReport {
        checked_batches: records.len(),
        total_anchored_ops: distinct_anchored.len(),
        missing_ops,
        root_mismatches,
        quarantined_authors,
        suppressed_tails,
        ok,
        // This is the bucket-side pass by construction; `reconcile_with_chain`
        // upgrades the report to `ChainVerified` only after the chain readback.
        verification: Verification::BucketOnly,
    }
}

/// Find every author whose verified head names a tip absent from `ops`.
///
/// Exposed so a caller that has ALREADY read the op-log — `doctor`, which reads it
/// once for the quarantine check — can add this evidence without paying for a
/// second full verified read, the dominant cost of that command on a long-lived
/// team.
///
/// `heads` must already be verified: this compares, it does not authenticate.
/// [`read_heads`] is the only producer of a verified set, and it returns them
/// sorted by `author_key`; the output preserves the input order, so passing that
/// set through yields a report identical on every machine.
#[must_use]
pub fn find_suppressed_tails(heads: &[HeadPointer], ops: &[Op]) -> Vec<SuppressedTail> {
    let present: HashSet<Blake3Hash> = ops.iter().map(Op::hash).collect();

    suppressed_tails_against(heads, ops, &present)
}

/// [`find_suppressed_tails`] over a `present` set the caller already built.
///
/// Split out so [`reconcile_records`] — which needs the same set for its
/// anchored-leaf check — hashes every op exactly once.
fn suppressed_tails_against(
    heads: &[HeadPointer],
    ops: &[Op],
    present: &HashSet<Blake3Hash>,
) -> Vec<SuppressedTail> {
    // Highest visible Lamport per author, built in ONE pass rather than scanned per
    // head: heads are few, but `ops` is the whole team's log.
    let mut visible_lamport: HashMap<VerifyingKey, u64> = HashMap::new();
    for op in ops {
        visible_lamport
            .entry(op.author_key)
            .and_modify(|highest| *highest = (*highest).max(op.lamport))
            .or_insert(op.lamport);
    }

    heads
        .iter()
        // A head whose claimed tip IS present is the healthy case, and so is a head
        // that merely LAGS the visible log — a best-effort publish that did not land
        // leaves the previous tip named, and that tip is still present. Only a tip
        // the log cannot produce is evidence.
        .filter(|head| !present.contains(&head.tip_hash))
        .map(|head| SuppressedTail {
            author: head.author.clone(),
            author_key: head.author_key,
            claimed_tip: head.tip_hash,
            claimed_lamport: head.lamport,
            visible_lamport: visible_lamport.get(&head.author_key).copied(),
        })
        .collect()
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
    // Recomputed with the SAME four-vector formula `reconcile_records` used. The
    // chain pass only ever ADDS `root_mismatches`, so leaving `quarantined_authors`
    // or `suppressed_tails` out here would let a chain-verified run reset `ok` to
    // true over a broken author chain or a truncated tail the bucket-side pass had
    // already failed on. Adding a vector to `reconcile_records`'s `ok` and
    // forgetting it here is a real, repeated trap: this recomputes from scratch, so
    // an omission does not merely fail to detect — it ERASES a detection.
    report.ok = report.missing_ops.is_empty()
        && report.root_mismatches.is_empty()
        && report.quarantined_authors.is_empty()
        && report.suppressed_tails.is_empty();
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
/// examined. Catching that would require independently enumerating the team's
/// committed roots from the chain and matching each against a present bucket
/// record — which the [`SubxtAnchor::read_anchored_root`](crate::audit::anchor::SubxtAnchor::read_anchored_root)
/// readback (a per-(block, extrinsic) lookup, with no chain-side index of a
/// team's roots) cannot do. So chain mode hardens forgery detection, not
/// record-omission suppression.
///
/// That omission no longer implies a clean report, but for a reason that owes
/// nothing to chain mode: when the dropped op is an author's TAIL, the
/// [`SuppressedTail`] check — which runs identically in both passes, off the
/// author's own signed head — reports it. What stays undetected in BOTH passes is
/// the drop of an op, its anchor record, AND the head pointer that would have
/// named it (or a stale head served in its place); the
/// `dropping_op_anchor_record_and_head_pointer_together_is_undetected` test pins
/// that narrower limit.
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
    let heads = read_heads(blob, team).await?;
    let (ops, quarantined_authors) = oplog.read_all_reporting_quarantine(team).await?;
    let report = reconcile_records(&records, &ops, &heads, quarantined_authors);
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
        SuppressedTail, Verification, find_suppressed_tails, reconcile, verify_on_chain_roots,
    };
    use crate::NetworkPrefix;
    use crate::audit::anchor::{AnchorReceipt, AnchorRef, BatchMeta, NoopAnchor};
    use crate::audit::batch::{AnchorRecord, persist_anchor_record, read_anchor_records};
    use crate::audit::merkle::merkle_root;
    use crate::crypto::{SecretKey, content_hash};
    use crate::domain::Blake3Hash;
    use crate::error::MemError;
    use crate::index::{HashEmbedder, InMemoryIndex};
    use crate::oplog::{
        HeadPointer, Op, OpContent, OpKind, OpLogStore, Signer, Sr25519Signer, VerifyingKey,
        read_heads,
    };
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

        let report = super::reconcile_records(&records, &[], &[], Vec::new());
        assert_eq!(
            report.total_anchored_ops, 2,
            "two distinct leaves across the records, counted once: {report:?}"
        );
        assert_eq!(report.checked_batches, 2, "both records are surveyed");
    }

    /// The head-pointer object key scheme, mirrored from `oplog::head` (private
    /// there) so a test can name the exact object to suppress.
    fn head_object_key(team: &str, author_key: &VerifyingKey) -> String {
        format!("{team}/_heads/{}", author_key.to_hex())
    }

    /// The anchor-record object key scheme, mirrored from `audit::batch` (private
    /// there) so a test can name the exact record to suppress.
    fn anchor_record_object_key(team: &str, record: &AnchorRecord) -> String {
        format!(
            "{team}/_anchors/{}/{:020}",
            record.author_key.to_hex(),
            record.seq
        )
    }

    /// Two remembered notes over a threshold-1 store, returning the object keys of
    /// the TAIL op and of the anchor record that committed it, plus the tail op
    /// itself.
    ///
    /// Shared by the two tests below, which differ only in what they then hide —
    /// the pair, or the pair plus the head pointer — so the difference between a
    /// detected and an undetected suppression is the ONLY difference between them.
    async fn seeded_tail(
        inner: &Arc<MemoryBlobStore>,
    ) -> Result<(Op, String, String), Box<dyn std::error::Error>> {
        let blob: Arc<dyn BlobStore> = inner.clone();
        let store = store_over(blob.clone(), 1);
        store.remember(remember_input("first")).await?;
        store.remember(remember_input("second")).await?;

        let full_log = OpLogStore::new(blob.clone());
        let ops = full_log.read_all(TEAM).await?;
        let tail = ops.last().ok_or("expected two ops")?.clone();
        let tail_hash = tail.hash();

        let records = read_anchor_records(&blob, TEAM).await?;
        let record = records
            .iter()
            .find(|record| record.leaves.contains(&tail_hash))
            .ok_or("the tail op must have an anchor record")?;

        Ok((
            tail.clone(),
            op_object_key(TEAM, &tail),
            anchor_record_object_key(TEAM, record),
        ))
    }

    #[tokio::test]
    async fn a_truncated_tail_is_reported_even_with_its_anchor_record_dropped() -> TestResult {
        // X5, the feature this vector exists for. The bucket drops the tail op AND
        // the anchor record covering it — the exact combination that leaves nothing
        // to reconcile against, and that no configuration (local or chain) detected
        // before the head pointer existed. The author's own signed head still names
        // the dropped tip, and no visible op reproduces it, so the truncation is
        // reported instead of silently accepted.
        let inner = Arc::new(MemoryBlobStore::default());
        let (tail, tail_key, record_key) = seeded_tail(&inner).await?;

        let suppressing: Arc<dyn BlobStore> = Arc::new(Suppressing {
            inner: inner.clone(),
            hidden: BTreeSet::from([tail_key, record_key]),
        });
        let oplog = OpLogStore::new(suppressing.clone());
        let report = reconcile(&suppressing, &oplog, TEAM).await?;

        assert!(
            !report.ok,
            "a signed head naming a tip the log cannot produce must fail reconciliation: {report:?}"
        );
        assert_eq!(
            report.suppressed_tails,
            vec![SuppressedTail {
                author: tail.author.clone(),
                author_key: tail.author_key,
                claimed_tip: tail.hash(),
                claimed_lamport: tail.lamport,
                // The first note's op is still visible, one Lamport behind the
                // claim: a truncated tail, not a suppressed author.
                visible_lamport: Some(tail.lamport.saturating_sub(1)),
            }],
            "the report names the author, the tip they signed, and how far the visible log lags: {report:?}"
        );
        // The other vectors stay empty, so this report can ONLY have failed on the
        // head-pointer evidence: the anchor record went with the op (nothing left to
        // miss), and truncating a TAIL leaves a valid chain prefix (nothing to
        // quarantine).
        assert!(
            report.missing_ops.is_empty(),
            "no anchored leaf is left to miss: {report:?}"
        );
        assert!(
            report.quarantined_authors.is_empty(),
            "a truncated tail leaves the surviving chain intact: {report:?}"
        );
        assert!(
            report.root_mismatches.is_empty(),
            "no anchor record was forged: {report:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn dropping_op_anchor_record_and_head_pointer_together_is_undetected() -> TestResult {
        // The narrowed L3 / M1 limit. Dropping an op together with its anchor
        // record is no longer enough — the author's signed head still names the
        // dropped tip (see the test above). What remains undetected is dropping the
        // HEAD POINTER too: an author with ops and no head makes no claim, so there
        // is nothing left to contradict and `ok` is true.
        //
        // Serving an OLDER, still-validly-signed head instead of dropping it is
        // silent for the same reason — its claimed tip IS visible. Both residuals
        // need state the bucket does not control (a local high-water mark carried
        // across syncs), so they are pinned here rather than claimed as covered.
        let inner = Arc::new(MemoryBlobStore::default());
        let (tail, tail_key, record_key) = seeded_tail(&inner).await?;
        let head_key = head_object_key(TEAM, &tail.author_key);

        // Sanity: the head object really is there to be dropped, so this test
        // exercises the drop rather than an absence that was never published.
        assert_eq!(
            read_heads(&(inner.clone() as Arc<dyn BlobStore>), TEAM)
                .await?
                .len(),
            1,
            "the author published a head before it was suppressed"
        );

        let suppressing: Arc<dyn BlobStore> = Arc::new(Suppressing {
            inner: inner.clone(),
            hidden: BTreeSet::from([tail_key, record_key, head_key]),
        });
        let oplog = OpLogStore::new(suppressing.clone());
        let report = reconcile(&suppressing, &oplog, TEAM).await?;

        assert!(
            report.ok,
            "with the op, its anchor record, AND the head all gone there is no claim left to contradict: {report:?}"
        );
        assert!(
            report.missing_ops.is_empty(),
            "no anchored leaf is left to miss"
        );
        assert!(
            report.suppressed_tails.is_empty(),
            "an author with no head object makes no claim about their tip"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_stale_but_validly_signed_head_is_undetected() -> TestResult {
        // The second residual, exercised rather than merely asserted in prose: the
        // bucket rolls the head object back to the one the author published for the
        // FIRST write and drops the tail op. That head verifies, its identity binds,
        // and its claimed tip is visible — so it is consistent with the truncated
        // view and reports nothing. Only a locally-remembered high-water mark could
        // notice the head moved backward.
        let inner = Arc::new(MemoryBlobStore::default());
        let blob: Arc<dyn BlobStore> = inner.clone();
        let store = store_over(blob.clone(), 1);
        store.remember(remember_input("first")).await?;

        // The head as it stood after the first write — captured before the second
        // write overwrites it, exactly what a bucket retaining an old version has.
        let stale_head = read_heads(&blob, TEAM)
            .await?
            .pop()
            .ok_or("the first write must publish a head")?;

        store.remember(remember_input("second")).await?;

        let full_log = OpLogStore::new(blob.clone());
        let ops = full_log.read_all(TEAM).await?;
        let tail = ops.last().ok_or("expected two ops")?.clone();
        let tail_key = op_object_key(TEAM, &tail);
        let records = read_anchor_records(&blob, TEAM).await?;
        let record_key = records
            .iter()
            .find(|record| record.leaves.contains(&tail.hash()))
            .map(|record| anchor_record_object_key(TEAM, record))
            .ok_or("the tail op must have an anchor record")?;

        // Roll the head back, then hide the tail op and its anchor record.
        crate::oplog::publish_head(&blob, TEAM, &stale_head).await?;
        assert!(
            stale_head.tip_hash != tail.hash(),
            "the rolled-back head must name an older tip than the suppressed one"
        );

        let suppressing: Arc<dyn BlobStore> = Arc::new(Suppressing {
            inner: inner.clone(),
            hidden: BTreeSet::from([tail_key, record_key]),
        });
        let oplog = OpLogStore::new(suppressing.clone());
        let report = reconcile(&suppressing, &oplog, TEAM).await?;

        assert!(
            report.ok,
            "an older validly-signed head is consistent with the truncated view: {report:?}"
        );
        assert!(
            report.suppressed_tails.is_empty(),
            "the rolled-back head's claimed tip is still visible, so nothing contradicts it"
        );
        Ok(())
    }

    #[test]
    fn find_suppressed_tails_is_silent_for_a_head_that_merely_lags() -> TestResult {
        // The direction that must never be evidence. A best-effort head publish
        // that did not land leaves the PREVIOUS tip named; that tip is still
        // present, so a lagging head is silent by construction. Reporting it would
        // turn a dropped PUT into a false suppression accusation against an honest
        // author.
        let signer = Sr25519Signer::from_seed_with_prefix(&[9u8; 32], NetworkPrefix::HIPPIUS)?;
        let first = Op::create_signed(
            &signer,
            OpContent {
                op_id: Ulid::new(),
                lamport: 1,
                key_epoch: 0,
                kind: OpKind::Remember,
                note_id: crate::domain::NoteId::from(Ulid::new()),
                object_key: format!("{TEAM}/global/note/ver_one"),
                cid: content_hash(b"first ciphertext"),
                prev_op_hash: crate::oplog::GENESIS_PREV,
            },
        );
        let second = Op::create_signed(
            &signer,
            OpContent {
                op_id: Ulid::new(),
                lamport: 2,
                key_epoch: 0,
                kind: OpKind::Edit,
                note_id: first.note_id,
                object_key: format!("{TEAM}/global/note/ver_two"),
                cid: content_hash(b"second ciphertext"),
                prev_op_hash: first.hash(),
            },
        );
        // The head still names the FIRST op while both ops are visible.
        let lagging = HeadPointer::create_signed(&signer, TEAM, first.lamport, first.hash());

        assert!(
            find_suppressed_tails(&[lagging], &[first, second]).is_empty(),
            "a head behind the visible log is the safe direction and must never be reported"
        );
        Ok(())
    }

    #[test]
    fn find_suppressed_tails_reports_no_visible_lamport_for_a_hidden_author() -> TestResult {
        // The whole-author case: a head verifies, but not one of that author's ops
        // is visible. `visible_lamport: None` is what distinguishes it from a
        // truncated tail, where some ops survive.
        let signer = Sr25519Signer::from_seed_with_prefix(&[9u8; 32], NetworkPrefix::HIPPIUS)?;
        let head = HeadPointer::create_signed(&signer, TEAM, 5, content_hash(b"a tip nobody sees"));

        assert_eq!(
            find_suppressed_tails(&[head], &[]),
            vec![SuppressedTail {
                author: signer.author_ss58(),
                author_key: signer.verifying_key(),
                claimed_tip: content_hash(b"a tip nobody sees"),
                claimed_lamport: 5,
                visible_lamport: None,
            }]
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
            suppressed_tails: vec![SuppressedTail {
                author: author.clone(),
                author_key: VerifyingKey::new([0xDD; 32]),
                claimed_tip: content_hash(b"the tip the author signed"),
                claimed_lamport: 9,
                visible_lamport: Some(7),
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
        // Tail-truncation evidence reaches a JSON consumer with the author as an
        // SS58 string, the key and tip as lowercase hex, and the Lamports as plain
        // numbers — enough to act on without any Rust type in hand.
        assert_eq!(
            json.pointer("/suppressed_tails/0/author")
                .and_then(serde_json::Value::as_str),
            Some(author.as_str())
        );
        assert_eq!(
            json.pointer("/suppressed_tails/0/author_key")
                .and_then(serde_json::Value::as_str),
            Some(VerifyingKey::new([0xDD; 32]).to_hex().as_str())
        );
        assert_eq!(
            json.pointer("/suppressed_tails/0/claimed_tip")
                .and_then(serde_json::Value::as_str),
            Some(content_hash(b"the tip the author signed").to_hex().as_str())
        );
        assert_eq!(
            json.pointer("/suppressed_tails/0/claimed_lamport")
                .and_then(serde_json::Value::as_u64),
            Some(9)
        );
        assert_eq!(
            json.pointer("/suppressed_tails/0/visible_lamport")
                .and_then(serde_json::Value::as_u64),
            Some(7)
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

    /// [`clean_base`], but carrying whatever bucket-side evidence the first pass
    /// already found — the state `verify_on_chain_roots` must not erase when it
    /// recomputes `ok` from scratch.
    fn base_with_quarantine(quarantined_authors: Vec<QuarantinedAuthor>) -> ReconcileReport {
        base_with_evidence(quarantined_authors, Vec::new())
    }

    /// [`clean_base`] carrying both bucket-side evidence vectors, so a chain-pass
    /// test can pin either one against the recomputed `ok`.
    fn base_with_evidence(
        quarantined_authors: Vec<QuarantinedAuthor>,
        suppressed_tails: Vec<SuppressedTail>,
    ) -> ReconcileReport {
        let ok = quarantined_authors.is_empty() && suppressed_tails.is_empty();
        ReconcileReport {
            checked_batches: 1,
            total_anchored_ops: 1,
            missing_ops: Vec::new(),
            root_mismatches: Vec::new(),
            quarantined_authors,
            suppressed_tails,
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
    async fn chain_pass_does_not_clear_ok_over_a_suppressed_tail() -> TestResult {
        // The same trap `chain_pass_does_not_clear_ok_over_a_quarantined_author`
        // guards, for the vector X5 added. `verify_on_chain_roots` recomputes `ok`
        // FROM SCRATCH and the chain pass only ever ADDS root mismatches, so a
        // formula that forgot `suppressed_tails` would not merely fail to detect a
        // truncated tail — it would ERASE the bucket-side pass's detection and hand
        // back `ok: true`, purely because the chain agreed about an unrelated root.
        let leaf = content_hash(b"leaf");
        let root = merkle_root(&[leaf]);
        let record = on_chain_record(root, leaf);
        let reader = MockChainReader::with_root(Some(root));
        let signer = Sr25519Signer::from_seed_with_prefix(&[4u8; 32], NetworkPrefix::HIPPIUS)?;
        let suppressed = vec![SuppressedTail {
            author: signer.author_ss58(),
            author_key: signer.verifying_key(),
            claimed_tip: content_hash(b"the tip the author signed"),
            claimed_lamport: 11,
            visible_lamport: Some(9),
        }];

        let report = verify_on_chain_roots(
            &[record],
            base_with_evidence(Vec::new(), suppressed.clone()),
            &reader,
        )
        .await?;

        assert!(
            !report.ok,
            "an agreeing chain root must not clear a suppressed tail: {report:?}"
        );
        assert_eq!(
            report.suppressed_tails, suppressed,
            "the chain pass carries the evidence through untouched: {report:?}"
        );
        assert!(
            report.root_mismatches.is_empty(),
            "the chain agreed — the only failing evidence is the truncated tail: {report:?}"
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
    fn a_legacy_payload_deserializes_with_the_newer_fields_empty() {
        // A payload predating `verification`, `quarantined_authors` and
        // `suppressed_tails` must still deserialize — each to the SAFE direction:
        // the weaker trust mode, never silently the stronger ChainVerified, and
        // EMPTY evidence vectors, so an old report claims no evidence rather than
        // inventing some.
        let json = serde_json::json!({
            "checked_batches": 0,
            "total_anchored_ops": 0,
            "missing_ops": [],
            "root_mismatches": [],
            "ok": true
        });
        let report: ReconcileReport =
            serde_json::from_value(json).expect("a legacy payload deserializes");
        assert_eq!(report.verification, Verification::BucketOnly);
        assert!(report.quarantined_authors.is_empty());
        assert!(report.suppressed_tails.is_empty());
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
