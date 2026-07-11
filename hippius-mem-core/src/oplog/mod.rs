//! The Phase 2 op-log: signed, hash-chained memory operations.
//!
//! [`op`] defines the [`Op`] record, its canonical signing bytes and chain hash,
//! and the sr25519 signing seam. [`store`] persists ops to the shared bucket and
//! reads them back with signature + per-author hash-chain verification.
//! [`converge`] folds a set of ops into order-independent per-note state. Merkle
//! anchoring of op hashes and the `history` tool that proves a single op's
//! inclusion are built on top in [`crate::audit`] and
//! [`crate::store::MemoryStore::history`].

mod converge;
mod op;
mod store;
mod verified;

pub use converge::{
    ConvergedState, NotePointer, NoteState, TypedLink, converge, lamport_tip, next_lamport,
};
pub use op::{
    HexError, LinkRel, Op, OpContent, OpKind, Signature, Signer, Sr25519Signer, VerifyingKey,
    verify,
};
pub use store::{GENESIS_PREV, OpLogStore};
pub use verified::VerifiedOps;
