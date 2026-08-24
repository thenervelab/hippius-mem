//! Audit primitives for cheaply anchoring the op-log on-chain.
//!
//! Op hashes are batched into a binary Merkle tree ([`merkle_root`]) and only the
//! root is anchored on-chain (the [`AuditAnchor`] seam), so one extrinsic covers a
//! whole batch instead of one per op; [`crate::store::MemoryStore::history`] then
//! proves a specific op was committed under an anchored root with a Merkle
//! inclusion proof, and [`reconcile`] cross-checks the visible op-log against the
//! anchored roots to detect suppression.

// Submodules are private behind a curated facade (matching `oplog`/`identity`):
// audit items are reached only through this re-export, not a deep
// `audit::anchor::…` submodule path.
mod anchor;
mod batch;
mod merkle;
mod reconcile;

#[cfg(feature = "chain")]
pub use anchor::SubxtAnchor;
pub use anchor::{
    AnchorReceipt, AnchorRef, AuditAnchor, BatchMeta, NoopAnchor, RecordingAnchor, anchor_payload,
    parse_anchor_payload,
};
pub use batch::{
    AnchorRecord, AnchorRecordsRead, AnchorSignatureState, UnsignedAnchorPolicy,
    persist_anchor_record, read_anchor_records, read_anchor_records_with_policy,
};
// Test-only re-export: the cross-type domain-separation test in `oplog::op`
// asserts against the REAL constant (like the identity domains), not a copied
// literal. `cfg(test)` because no non-test code outside `batch` reads it.
#[cfg(test)]
pub(crate) use batch::ANCHOR_RECORD_SIGNING_DOMAIN;
// `anchor_record_exists` is crate-internal: only `MemoryStore`'s
// cross-process-locked anchor-persist path needs the fail-on-exists check, so
// it stays off the curated public facade the rest of this module presents.
pub(crate) use batch::anchor_record_exists;
pub use merkle::{MerkleProof, Side, inclusion_proof, merkle_root, verify_proof};
#[cfg(feature = "chain")]
pub use reconcile::reconcile_with_chain;
pub use reconcile::{
    MissingOp, ReconcileReport, RootMismatch, SuppressedTail, Verification, find_suppressed_tails,
    reconcile, reconcile_with_watermarks,
};
