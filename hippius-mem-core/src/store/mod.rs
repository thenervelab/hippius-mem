//! Storage seams. Currently the [`blob`] object store; the hybrid index and
//! op-log arrive in later tasks.

pub mod blob;

pub use blob::{BlobStore, MemoryBlobStore, S3BlobStore};
