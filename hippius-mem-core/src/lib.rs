#![deny(missing_docs)]
#![warn(
    rust_2018_idioms,
    missing_debug_implementations,
    unreachable_pub,
    rustdoc::broken_intra_doc_links
)]
//! Hippius Memory core: the Phase 1 building blocks of the team memory store.
//!
//! Implemented here: the [`domain`] types (notes, scopes, ids, hashes), client
//! side [`crypto`] (XChaCha20-Poly1305 seal/open over note blobs), the
//! [`store::blob`] object store (in-memory fake + S3 gateway), the in-memory
//! hybrid [`index`] (lexical + semantic retrieval, pointers-not-bodies), the
//! signed, hash-chained [`oplog`] (ops + convergence), and the
//! [`store::MemoryStore`] that composes them into `remember` / `recall` / `get` /
//! `forget` / `link` plus [`store::MemoryStore::sync`], which replays the shared
//! op-log to rebuild the local index.

pub mod audit;
pub mod crypto;
pub mod domain;
pub mod error;
pub mod identity;
pub mod index;
pub mod objkey;
pub mod oplog;
pub mod store;

pub use domain::{
    Blake3Hash, InvalidBlake3Hex, InvalidSs58, Note, NoteId, NoteType, ParseNoteIdError,
    ParseNoteTypeError, RepoScope, Scope, Ss58, Timestamp,
};
#[cfg(feature = "chain")]
pub use audit::anchor::SubxtAnchor;
pub use audit::anchor::{
    AnchorReceipt, AnchorRef, AuditAnchor, BatchMeta, NoopAnchor, RecordingAnchor, anchor_payload,
    parse_anchor_payload,
};
pub use audit::batch::{AnchorRecord, persist_anchor_record, read_anchor_records};
pub use audit::merkle::{MerkleProof, Side, inclusion_proof, merkle_root, verify_proof};
#[cfg(feature = "chain")]
pub use audit::reconcile::reconcile_with_chain;
pub use audit::reconcile::{MissingOp, ReconcileReport, RootMismatch, RootMismatchKind, reconcile};
pub use crypto::{SecretKey, content_hash, open, seal};
// `Result` is re-exported as `MemResult` so it never silently shadows
// `std::result::Result` in sibling modules that glob-import the crate root.
pub use error::{MemError, Result as MemResult};
pub use identity::{
    ChallengeResp, DEFAULT_CONSOLE_BASE_URL, Identity, MemberKey, MnemonicChallengeReq, S3Creds,
    SessionData, SubTokenReq, SubTokenResp, TeamManifest, VerifyReq, VerifyResp, WrappedKey,
    derive_identity, fetch_team_key, load_manifest, load_member_keys, provision_team_key,
    publish_manifest, publish_member_key, rotate_team_key, signer_from_mnemonic, ss58_decode,
    ss58_encode, unwrap_team_key, wrap_team_key,
};
#[cfg(feature = "console")]
pub use identity::{ConsoleClient, eth_signer_from_mnemonic};
pub use index::{
    DEFAULT_EMBED_DIM, Embedder, HashEmbedder, InMemoryIndex, IndexRecord, Located, MemoryIndex,
    Pointer, Query, SearchResult,
};
pub use objkey::{object_key, parse_object_key};
pub use oplog::{
    ConvergedState, GENESIS_PREV, HexError, NotePointer, NoteState, Op, OpContent, OpKind,
    OpLogStore, Signature, Signer, Sr25519Signer, VerifyingKey, converge, lamport_tip,
    next_lamport, verify,
};
pub use store::{
    AnchorProof, BlobStore, HistoryEntry, IndexSnapshot, MemoryBlobStore, MemoryStore, NoteHistory,
    OpKindLabel, RecallInput, RememberInput, S3BlobStore, load_latest_snapshot, save_snapshot,
};
