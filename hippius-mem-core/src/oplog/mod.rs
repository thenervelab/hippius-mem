//! The Phase 2 op-log: signed, hash-chained memory operations.
//!
//! [`op`] defines the [`Op`] record, its canonical signing bytes and chain hash,
//! and the sr25519 signing seam. [`store`] persists ops to the shared bucket and
//! reads them back with signature + per-author hash-chain verification.
//! [`converge`] folds a set of ops into order-independent per-note state.
//! [`head`] adds the signed per-author head pointer that pins "this is my latest
//! op", which the hash chain alone cannot, and [`watermark`] remembers the highest
//! such head this machine has verified — the one input to that check the untrusted
//! bucket does not control. Merkle anchoring of op hashes and the
//! `history` tool that proves a single op's inclusion are built on top in
//! [`crate::audit`] and [`crate::store::MemoryStore::history`].

mod converge;
mod head;
mod op;
mod store;
mod verified;
mod watermark;

pub use converge::{
    ConvergedState, NotePointer, NoteState, TypedLink, converge, lamport_tip, next_lamport,
};
pub use head::{HeadPointer, VerifiedHeads, publish_head, read_heads};
pub use op::{
    HexError, LinkRel, Op, OpContent, OpKind, Signature, Signer, Sr25519Signer, VerifyingKey,
    verify,
};
pub use store::{GENESIS_PREV, OpLogStore, QuarantinedAuthor};
pub use verified::VerifiedOps;
pub use watermark::{HeadRegression, HeadWatermarks};
