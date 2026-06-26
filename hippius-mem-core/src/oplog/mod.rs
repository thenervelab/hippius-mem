//! The Phase 2 op-log: signed, hash-chained memory operations.
//!
//! [`op`] defines the [`Op`] record, its canonical signing bytes and chain hash,
//! and the sr25519 signing seam. [`store`] persists ops to the shared bucket and
//! reads them back with signature + per-author hash-chain verification. Later
//! tasks add convergence, Merkle anchoring, and the `history` tool on top.

mod op;
mod store;

pub use op::{
    HexError, InvalidSeed, Op, OpContent, OpKind, Signature, Signer, Sr25519Signer, VerifyingKey,
    verify,
};
pub use store::{GENESIS_PREV, OpLogStore};
