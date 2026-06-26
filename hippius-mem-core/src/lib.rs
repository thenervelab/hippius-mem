#![deny(missing_docs)]
#![warn(
    rust_2018_idioms,
    missing_debug_implementations,
    unreachable_pub,
    rustdoc::broken_intra_doc_links
)]
//! Hippius Memory core: domain types, crypto, S3 blob store, hybrid index, op-log.

pub mod crypto;
pub mod domain;
pub mod error;
pub mod index;
pub mod objkey;
pub mod store;

pub use domain::{
    Blake3Hash, InvalidBlake3Hex, InvalidSs58, Note, NoteId, NoteType, ParseNoteIdError,
    ParseNoteTypeError, RepoScope, Scope, Ss58, Timestamp,
};
// `Result` is re-exported as `MemResult` so it never silently shadows
// `std::result::Result` in sibling modules that glob-import the crate root.
pub use crypto::{SecretKey, content_hash, open, seal};
pub use error::{MemError, Result as MemResult};
pub use index::{
    DEFAULT_EMBED_DIM, Embedder, HashEmbedder, InMemoryIndex, IndexRecord, MemoryIndex, Pointer,
    Query,
};
pub use objkey::{object_key, parse_object_key};
pub use store::{BlobStore, MemoryBlobStore, S3BlobStore};
