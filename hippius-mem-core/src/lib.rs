#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(
    rust_2018_idioms,
    missing_debug_implementations,
    unreachable_pub,
    rustdoc::broken_intra_doc_links
)]
//! Hippius Memory core: an encrypted, signed, CRDT-style team memory store.
//!
//! Implemented here: the [`domain`] types (notes, scopes, ids, hashes); client
//! side [`crypto`] (XChaCha20-Poly1305 seal/open over note blobs); the
//! [`BlobStore`] object store (in-memory fake + S3 gateway); the in-memory
//! hybrid [`index`] (lexical + semantic retrieval, pointers-not-bodies); the
//! signed, hash-chained [`oplog`] (ops + convergence); cryptographic [`identity`]
//! (BIP-39/SS58 derivation, x25519 team-key wrapping, founder-signed membership);
//! the [`audit`] layer (BLAKE3 Merkle anchoring, on-chain commitment, and op-log
//! reconciliation); and the [`store::MemoryStore`] that composes them into
//! `remember` / `recall` / `get` / `forget` / `link` / `history` plus
//! [`store::MemoryStore::sync`], which replays the shared op-log to rebuild the
//! local index.
//!
//! The crate contains no `unsafe` code (enforced by `#![forbid(unsafe_code)]`):
//! all memory-safety rests on safe Rust and audited dependencies.

pub mod audit;
pub mod brief;
pub mod crypto;
pub mod domain;
pub mod error;
// Crate-internal: the single source of truth for canonical signing-bytes
// framing, shared by every type that signs (op / manifest / member key).
mod framing;
pub mod identity;
pub mod index;
pub mod objkey;
pub mod oplog;
pub mod store;

#[cfg(feature = "chain")]
pub use audit::SubxtAnchor;
#[cfg(feature = "chain")]
pub use audit::reconcile_with_chain;
pub use audit::{
    AnchorReceipt, AnchorRef, AuditAnchor, BatchMeta, NoopAnchor, RecordingAnchor, anchor_payload,
    parse_anchor_payload,
};
pub use audit::{AnchorRecord, persist_anchor_record, read_anchor_records};
pub use audit::{MerkleProof, Side, inclusion_proof, merkle_root, verify_proof};
pub use audit::{MissingOp, ReconcileReport, RootMismatch, reconcile};
pub use brief::render_brief;
pub use crypto::{SecretKey, content_hash, derive_cache_key, open, seal};
pub use domain::{
    Blake3Hash, InvalidBlake3Hex, InvalidNetworkPrefix, InvalidSs58, NetworkPrefix, Note, NoteId,
    NoteType, ParseNoteIdError, ParseNoteTypeError, RepoScope, Scope, Ss58, Timestamp,
};
// `Result` is re-exported as `MemResult` so it never silently shadows
// `std::result::Result` in sibling modules that glob-import the crate root.
pub use error::{MemError, Result as MemResult};
pub use identity::{
    ChallengeResp, DEFAULT_CONSOLE_BASE_URL, FileManifestMarker, Identity, ManifestMarker,
    MemberKey, MnemonicChallengeReq, S3Creds, SessionData, SubTokenReq, SubTokenResp, TeamManifest,
    VerifyReq, VerifyResp, WrappedKey, derive_identity, fetch_team_key, load_manifest,
    load_member_keys, provision_team_key, publish_manifest, publish_member_key, rotate_team_key,
    signer_from_mnemonic, ss58_decode, ss58_encode, unwrap_team_key, wrap_team_key,
};
#[cfg(feature = "console")]
pub use identity::{ConsoleClient, eth_signer_from_mnemonic};
pub use index::{
    DEFAULT_EMBED_DIM, Embedder, HashEmbedder, InMemoryIndex, IndexRecord, Located, MemoryIndex,
    Pointer, Query, SearchResult,
};
#[cfg(feature = "embeddings")]
pub use index::{EmbedModel, FastEmbedder};
pub use objkey::{note_blob_prefix, object_key, parse_object_key};
pub use oplog::{
    ConvergedState, GENESIS_PREV, HexError, NotePointer, NoteState, Op, OpContent, OpKind,
    OpLogStore, Signature, Signer, Sr25519Signer, VerifiedOps, VerifyingKey, converge, lamport_tip,
    next_lamport, verify,
};
pub use store::{
    AnchorProof, BlobStore, CachingBlobStore, HistoryEntry, IndexSnapshot, MemoryBlobStore,
    MemoryStore, NoteHistory, OpKindLabel, RecallInput, RememberInput, S3BlobStore, SealedRecord,
    load_latest_snapshot, save_snapshot,
};
