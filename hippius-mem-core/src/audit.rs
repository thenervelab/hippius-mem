//! Audit primitives for cheaply anchoring the op-log on-chain.
//!
//! Op hashes are batched into a binary [`merkle`] tree and only the root is
//! anchored on-chain ([`anchor`]), so one extrinsic covers a whole batch instead
//! of one per op; [`crate::store::MemoryStore::history`] then proves a specific
//! op was committed under an anchored root with a Merkle inclusion proof, and
//! [`reconcile`] cross-checks the visible op-log against the anchored roots to
//! detect suppression.

pub mod anchor;
pub mod batch;
pub mod merkle;
pub mod reconcile;
