//! Audit primitives for cheaply anchoring the op-log on-chain.
//!
//! Phase 2 batches op hashes into a binary [`merkle`] tree and anchors only the
//! root on-chain, so one extrinsic covers a whole batch instead of one per op.
//! Later, `history` proves a specific op was committed under an anchored root
//! with a Merkle inclusion proof. This module holds the pure tree primitive;
//! the on-chain anchoring and history lookup live in later tasks.

pub mod anchor;
pub mod merkle;
