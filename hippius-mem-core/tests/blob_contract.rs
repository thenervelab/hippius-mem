//! Contract tests every `BlobStore` impl must pass: the trait doc's promises
//! (lexicographic list, idempotent delete, `NotFound` on absent get,
//! put-overwrite) checked against each implementation.
//!
//! `CachingBlobStore` is a production decorator (`TeamProfile::build_store`
//! wraps the S3 store in it) and used to be absent here, so nothing checked that
//! caching preserves the contract. It is exercised twice: once over keys the
//! cache ignores, which is pure pass-through, and once over keys it genuinely
//! caches — where delete-then-get is the case that matters, since a cached copy
//! outliving its deletion would leave a redacted body readable on local disk.

#![expect(
    clippy::expect_used,
    reason = "tests assert on throwaway fixtures where construction cannot fail"
)]

use std::sync::Arc;

use hippius_mem_core::{
    BlobStore, CachingBlobStore, FsBlobStore, MemError, MemoryBlobStore, SecretKey,
};

/// The keys one contract run uses: two under a shared prefix, where `first`
/// sorts before `second` so the ordering assertion is meaningful.
struct Keyspace {
    prefix: &'static str,
    first: &'static str,
    second: &'static str,
}

/// Ordinary keys. `CachingBlobStore::is_cacheable` rejects this shape, so a run
/// over these passes straight through to the wrapped store.
const PLAIN: Keyspace = Keyspace {
    prefix: "team/",
    first: "team/a/deep",
    second: "team/b",
};

/// Op-log keys, which the cache treats as immutable and stores on disk. A run
/// over these exercises the caching path itself.
const CACHED: Keyspace = Keyspace {
    prefix: "team/_oplog/",
    first: "team/_oplog/00000000000000000001_aaa_bbb",
    second: "team/_oplog/00000000000000000002_ccc_ddd",
};

async fn exercise_contract(store: Arc<dyn BlobStore>, keys: &Keyspace) {
    // Absent get is NotFound, not Storage.
    let missing = store.get("team/none").await;
    assert!(matches!(missing, Err(MemError::NotFound { .. })));

    // Put then get round-trips bytes exactly.
    store.put(keys.second, vec![2]).await.expect("put second");
    store.put(keys.first, vec![1]).await.expect("put first");
    assert_eq!(store.get(keys.second).await.expect("get second"), vec![2]);

    // Overwrite replaces. On a cached key this also proves the cache does not
    // serve the superseded copy.
    store.put(keys.second, vec![9]).await.expect("overwrite");
    assert_eq!(store.get(keys.second).await.expect("get second 2"), vec![9]);

    // List is prefix-filtered and lexicographic.
    let listed = store.list(keys.prefix).await.expect("list");
    assert_eq!(
        listed,
        vec![keys.first.to_owned(), keys.second.to_owned()],
        "list must be prefix-filtered and lexicographic"
    );

    // Delete is idempotent, and a deleted object stays gone on the next read —
    // the case a cache can get wrong by serving its own surviving copy.
    store.delete(keys.second).await.expect("delete");
    store.delete(keys.second).await.expect("delete twice");
    assert!(matches!(
        store.get(keys.second).await,
        Err(MemError::NotFound { .. })
    ));
}

fn caching_over(inner: Arc<dyn BlobStore>) -> (Arc<dyn BlobStore>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("cache dir");
    let store = CachingBlobStore::new(
        inner,
        dir.path().to_path_buf(),
        SecretKey::from_bytes([7u8; 32]),
    );

    // The `TempDir` rides along so it outlives the store rather than cleaning up
    // the cache directory mid-test.
    (Arc::new(store), dir)
}

#[tokio::test]
async fn memory_store_honors_the_contract() {
    exercise_contract(Arc::new(MemoryBlobStore::new()), &PLAIN).await;
}

#[tokio::test]
async fn fs_store_honors_the_contract() {
    // `tempfile` is already a dev-dependency (used by the blob-cache tests), so
    // the throwaway root rides its auto-cleaning `TempDir` rather than a
    // pid-suffixed path under `std::env::temp_dir()`.
    let dir = tempfile::tempdir().expect("temp dir");
    exercise_contract(Arc::new(FsBlobStore::new(dir.path().to_path_buf())), &PLAIN).await;
}

#[tokio::test]
async fn caching_store_honors_the_contract_on_pass_through_keys() {
    let (store, _cache_dir) = caching_over(Arc::new(MemoryBlobStore::new()));
    exercise_contract(store, &PLAIN).await;
}

#[tokio::test]
async fn caching_store_honors_the_contract_on_cached_keys() {
    let (store, _cache_dir) = caching_over(Arc::new(MemoryBlobStore::new()));
    exercise_contract(store, &CACHED).await;
}

#[tokio::test]
async fn caching_store_over_the_fs_backend_honors_the_contract() {
    // The production shape is a cache over a remote store; `FsBlobStore` stands
    // in for one that actually persists, so the two layers' list and delete
    // semantics must agree rather than both being in-memory.
    let backend = tempfile::tempdir().expect("backend dir");
    let inner = Arc::new(FsBlobStore::new(backend.path().to_path_buf()));

    let (store, _cache_dir) = caching_over(inner);
    exercise_contract(store, &CACHED).await;
}
