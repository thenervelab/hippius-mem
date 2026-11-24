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
mod writer_lock;

pub use converge::{
    ConvergedState, NotePointer, NoteState, TypedLink, converge, lamport_tip, next_lamport,
};
pub(crate) use head::read_own_head;
pub use head::{HeadPointer, VerifiedHeads, publish_head, read_heads};
#[cfg(test)]
pub(crate) use op::SIGNING_DOMAIN;
pub use op::{
    HexError, LinkRel, Op, OpContent, OpKind, Signature, Signer, Sr25519Signer, VerifyingKey,
    verify,
};
pub use store::{
    DropClass, DroppedOp, GENESIS_PREV, OpLogStore, QuarantineClass, QuarantineRemoval,
    QuarantinedAuthor, QuarantinedAuthorDetail, SurvivingTip,
};
pub use verified::VerifiedOps;
pub use watermark::{HeadRegression, HeadWatermarks};
pub use writer_lock::WriterLock;
pub(crate) use writer_lock::{AuthorTip, SharedTip, TipSnapshot, WriterLockGuard};

/// Fixtures shared by this module's tests.
#[cfg(test)]
pub(crate) mod test_support {
    use crate::domain::{NetworkPrefix, NoteId};
    use crate::oplog::{GENESIS_PREV, Op, OpContent, OpKind, Sr25519Signer};
    use crate::ulid::Ulid;

    /// A validly signed `Remember` op at `lamport`, under a fixed test seed.
    #[expect(
        clippy::expect_used,
        reason = "a fixed 32-byte seed always derives a signer; a test fixture may panic"
    )]
    pub(crate) fn signed_op(lamport: u64) -> Op {
        let signer = Sr25519Signer::from_seed_with_prefix(&[7; 32], NetworkPrefix::HIPPIUS)
            .expect("a 32-byte seed always derives a signer");
        Op::create_signed(
            &signer,
            OpContent {
                op_id: Ulid::new(),
                lamport,
                key_epoch: 0,
                kind: OpKind::Remember,
                note_id: NoteId::new(),
                object_key: "team/repo/note/op".to_owned(),
                cid: crate::crypto::content_hash(b"ciphertext"),
                prev_op_hash: GENESIS_PREV,
            },
        )
    }
}
