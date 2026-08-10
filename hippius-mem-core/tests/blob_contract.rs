//! Contract tests every `BlobStore` impl must pass: the trait doc's promises
//! (lexicographic list, idempotent delete, `NotFound` on absent get,
//! put-overwrite) checked against each implementation.

#![expect(
    clippy::expect_used,
    reason = "tests assert on throwaway fixtures where construction cannot fail"
)]

use std::sync::Arc;

use hippius_mem_core::{BlobStore, FsBlobStore, MemError, MemoryBlobStore};

async fn exercise_contract(store: Arc<dyn BlobStore>) {
    // Absent get is NotFound, not Storage.
    let missing = store.get("team/none").await;
    assert!(matches!(missing, Err(MemError::NotFound { .. })));

    // Put then get round-trips bytes exactly.
    store.put("team/b", vec![2]).await.expect("put b");
    store.put("team/a/deep", vec![1]).await.expect("put a");
    assert_eq!(store.get("team/b").await.expect("get b"), vec![2]);

    // Overwrite replaces.
    store.put("team/b", vec![9]).await.expect("overwrite");
    assert_eq!(store.get("team/b").await.expect("get b2"), vec![9]);

    // List is prefix-filtered and lexicographic.
    let keys = store.list("team/").await.expect("list");
    assert_eq!(keys, vec!["team/a/deep".to_owned(), "team/b".to_owned()]);

    // Delete is idempotent: absent key deletes are success.
    store.delete("team/b").await.expect("delete");
    store.delete("team/b").await.expect("delete twice");
    assert!(matches!(
        store.get("team/b").await,
        Err(MemError::NotFound { .. })
    ));
}

#[tokio::test]
async fn memory_store_honors_the_contract() {
    exercise_contract(Arc::new(MemoryBlobStore::new())).await;
}

#[tokio::test]
async fn fs_store_honors_the_contract() {
    // `tempfile` is already a dev-dependency (used by the blob-cache tests), so
    // the throwaway root rides its auto-cleaning `TempDir` rather than a
    // pid-suffixed path under `std::env::temp_dir()`.
    let dir = tempfile::tempdir().expect("temp dir");
    exercise_contract(Arc::new(FsBlobStore::new(dir.path().to_path_buf()))).await;
}
