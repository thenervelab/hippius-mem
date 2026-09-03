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

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "tests assert on in-memory fixtures where construction cannot fail"
    )]

    use super::copy_store;
    use crate::store::{BlobStore, MemoryBlobStore};

    /// A copy under a non-empty `prefix` must carry over only objects whose
    /// key starts with that prefix, leaving everything else on the source
    /// AND out of the destination — the invariant `hippius-mem upgrade`
    /// depends on (it copies under the team-name prefix, so a destination
    /// bucket shared by more than one team is never handed another team's
    /// objects). No test exercised a non-empty `prefix` before this one (a
    /// parked finding from the initial `copy_store` implementation).
    #[tokio::test]
    async fn copy_store_only_copies_objects_under_the_prefix() {
        let src = MemoryBlobStore::default();
        src.put("team/a", b"1".to_vec()).await.unwrap();
        src.put("team/b", b"2".to_vec()).await.unwrap();
        src.put("other/c", b"3".to_vec()).await.unwrap();

        let dst = MemoryBlobStore::default();
        let copied = copy_store(&src, &dst, "team/").await.unwrap();

        assert_eq!(
            copied, 2,
            "only the two objects under the prefix must be reported as copied"
        );
        assert_eq!(
            dst.list("").await.unwrap(),
            vec!["team/a".to_owned(), "team/b".to_owned()],
            "the destination must hold exactly the prefixed objects"
        );
        assert!(
            dst.get("other/c").await.is_err(),
            "an object outside the prefix must not reach the destination"
        );
    }
}
