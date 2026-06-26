//! The Phase 2 op-log: signed, hash-chained memory operations.
//!
//! This task ([`op`]) defines the [`Op`] record, its canonical signing bytes and
//! chain hash, and the sr25519 signing seam. Later tasks add the op-log store,
//! convergence, Merkle anchoring, and the `history` tool on top of these types.

mod op;

pub use op::{
    HexError, InvalidSeed, Op, OpContent, OpKind, Signature, Signer, Sr25519Signer, VerifyingKey,
    verify,
};
