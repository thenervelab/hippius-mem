//! Bulk copy between blob stores.
//!
//! Objects are opaque sealed bytes; ops sign their content and object keys,
//! not the store holding them, so a byte-for-byte copy preserves every
//! signature and proof. Used by the trial-to-bucket upgrade path.

use crate::error::MemError;
use crate::store::BlobStore;

/// Copy every object under `prefix` from `src` to `dst`.
///
/// Put-overwrite semantics make the copy idempotent: re-running after a
/// partial failure re-copies already-transferred objects harmlessly.
///
/// # Errors
///
/// Propagates the first [`MemError`] from the source list/get or the
/// destination put.
pub async fn copy_store(
    src: &dyn BlobStore,
    dst: &dyn BlobStore,
    prefix: &str,
) -> Result<u64, MemError> {
    let keys = src.list(prefix).await?;

    let mut copied = 0_u64;
    for key in keys {
        let bytes = src.get(&key).await?;
        dst.put(&key, bytes).await?;
        copied += 1;
    }

    Ok(copied)
}
