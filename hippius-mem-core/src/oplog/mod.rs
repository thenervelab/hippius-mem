//! The Phase 2 op-log: signed, hash-chained memory operations.
//!
//! [`op`] defines the [`Op`] record, its canonical signing bytes and chain hash,
//! and the sr25519 signing seam. [`store`] persists ops to the shared bucket and
//! reads them back with signature + per-author hash-chain verification.
//! [`converge`] folds a set of ops into order-independent per-note state. Later
//! tasks add Merkle anchoring and the `history` tool on top.

mod converge;
mod op;
mod store;

pub use converge::{ConvergedState, NotePointer, NoteState, converge, lamport_tip, next_lamport};
pub use op::{
    HexError, Op, OpContent, OpKind, Signature, Signer, Sr25519Signer, VerifyingKey, verify,
};
pub use store::{GENESIS_PREV, OpLogStore};
