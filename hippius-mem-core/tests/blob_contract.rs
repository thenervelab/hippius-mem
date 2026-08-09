//! Contract tests every `BlobStore` impl must pass: the trait doc's promises
//! (lexicographic list, idempotent delete, `NotFound` on absent get,
//! put-overwrite) checked against each implementation.
//!
//! Two impls used to be missing, and both sit in the production read path.
//!
//! `CachingBlobStore` is a decorator `TeamProfile::build_store` wraps the S3
//! store in for every S3 profile. It is exercised twice: over keys the cache
//! ignores (pure pass-through) and over keys it genuinely caches — where
//! delete-then-get is the case that matters, since a cached copy outliving its
//! deletion would leave a redacted body readable on local disk.
//!
//! `S3BlobStore` talks to the actual gateway, and every in-process end-to-end
//! test in this crate is only as valid as the assumption that a real bucket
//! honours the same contract as `MemoryBlobStore`. That assumption has already
//! been wrong once: the gateway omits `IsTruncated`, which needed a dedicated
//! workaround in `S3BlobStore::list`. Its run is `#[ignore]`d and driven by the
//! `MinIO` job in `.github/workflows/rust.yml`.

#![expect(
    clippy::expect_used,
    reason = "tests assert on throwaway fixtures where construction cannot fail"
)]

use std::sync::Arc;

use hippius_mem_core::{
    BlobStore, CachingBlobStore, FsBlobStore, MemError, MemoryBlobStore, S3BlobStore, SecretKey,
};

/// The keys one contract run uses: two under a shared prefix, where `first`
/// sorts before `second` so the ordering assertion is meaningful. Owned rather
/// than `&'static` so a run can pick its own team segment and stay isolated.
struct Keyspace {
    prefix: String,
    first: String,
    second: String,
    absent: String,
}

impl Keyspace {
    /// Ordinary keys. `CachingBlobStore`'s `is_cacheable` rejects this shape
    /// (too few segments), so a run over these passes straight through.
    fn plain(team: &str) -> Self {
        Self {
            prefix: format!("{team}/"),
            first: format!("{team}/a/deep"),
            second: format!("{team}/b"),
            absent: format!("{team}/none"),
        }
    }

    /// Op-log keys, which the cache treats as immutable and stores on disk, so a
    /// run over these exercises the caching path itself.
    fn cached(team: &str) -> Self {
        Self {
            prefix: format!("{team}/_oplog/"),
            first: format!("{team}/_oplog/00000000000000000001_aaa_bbb"),
            second: format!("{team}/_oplog/00000000000000000002_ccc_ddd"),
            absent: format!("{team}/_oplog/00000000000000000009_zzz_zzz"),
        }
    }
}

async fn exercise_contract(store: Arc<dyn BlobStore>, keys: &Keyspace) {
    // Absent get is NotFound, not Storage.
    let missing = store.get(&keys.absent).await;
    assert!(matches!(missing, Err(MemError::NotFound { .. })));

    // Put then get round-trips bytes exactly.
    store.put(&keys.second, vec![2]).await.expect("put second");
    store.put(&keys.first, vec![1]).await.expect("put first");
    assert_eq!(store.get(&keys.second).await.expect("get second"), vec![2]);

    // Overwrite replaces. On a cached key this also proves the cache does not
    // serve the superseded copy.
    store.put(&keys.second, vec![9]).await.expect("overwrite");
    assert_eq!(
        store.get(&keys.second).await.expect("get second 2"),
        vec![9]
    );

    // List is prefix-filtered and lexicographic.
    let listed = store.list(&keys.prefix).await.expect("list");
    assert_eq!(
        listed,
        vec![keys.first.clone(), keys.second.clone()],
        "list must be prefix-filtered and lexicographic"
    );

    // Delete is idempotent, and a deleted object stays gone on the next read —
    // the case a cache can get wrong by serving its own surviving copy.
    store.delete(&keys.second).await.expect("delete");
    store.delete(&keys.second).await.expect("delete twice");
    assert!(matches!(
        store.get(&keys.second).await,
        Err(MemError::NotFound { .. })
    ));
}

/// Remove every object under `prefix`, so a run against a persistent shared
/// bucket neither sees a previous run's leftovers in its `list` assertion nor
/// leaves its own behind.
async fn clear_prefix(store: &dyn BlobStore, prefix: &str) {
    for key in store.list(prefix).await.unwrap_or_default() {
        let _ = store.delete(&key).await;
    }
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
    exercise_contract(Arc::new(MemoryBlobStore::new()), &Keyspace::plain("team")).await;
}

#[tokio::test]
async fn fs_store_honors_the_contract() {
    // `tempfile` is already a dev-dependency (used by the blob-cache tests), so
    // the throwaway root rides its auto-cleaning `TempDir` rather than a
    // pid-suffixed path under `std::env::temp_dir()`.
    let dir = tempfile::tempdir().expect("temp dir");
    exercise_contract(
        Arc::new(FsBlobStore::new(dir.path().to_path_buf())),
        &Keyspace::plain("team"),
    )
    .await;
}

#[tokio::test]
async fn caching_store_honors_the_contract_on_pass_through_keys() {
    let (store, _cache_dir) = caching_over(Arc::new(MemoryBlobStore::new()));
    exercise_contract(store, &Keyspace::plain("team")).await;
}

#[tokio::test]
async fn caching_store_honors_the_contract_on_cached_keys() {
    let (store, _cache_dir) = caching_over(Arc::new(MemoryBlobStore::new()));
    exercise_contract(store, &Keyspace::cached("team")).await;
}

#[tokio::test]
async fn caching_store_over_the_fs_backend_honors_the_contract() {
    // The production shape is a cache over a remote store; `FsBlobStore` stands
    // in for one that actually persists, so the two layers' list and delete
    // semantics must agree rather than both being in-memory.
    let backend = tempfile::tempdir().expect("backend dir");
    let inner = Arc::new(FsBlobStore::new(backend.path().to_path_buf()));

    let (store, _cache_dir) = caching_over(inner);
    exercise_contract(store, &Keyspace::cached("team")).await;
}

/// Build the S3 store from the same environment contract
/// `hippius-mem/tests/upgrade_cli.rs` uses, so one `MinIO` job configures both.
/// Only the bucket has no default: a wrong guess would write into a bucket the
/// operator did not create for this test.
fn s3_store_from_env() -> S3BlobStore {
    let endpoint = std::env::var("HIPPIUS_MEM_TEST_S3_ENDPOINT")
        .unwrap_or_else(|_| "http://127.0.0.1:9000".to_owned());
    let bucket = std::env::var("HIPPIUS_MEM_TEST_BUCKET")
        .expect("set HIPPIUS_MEM_TEST_BUCKET to a bucket that already exists on the endpoint");
    let access_key_id =
        std::env::var("HIPPIUS_MEM_TEST_ACCESS_KEY_ID").unwrap_or_else(|_| "test".to_owned());
    let secret =
        std::env::var("HIPPIUS_MEM_TEST_SECRET").unwrap_or_else(|_| "testtest1".to_owned());
    let region =
        std::env::var("HIPPIUS_MEM_TEST_S3_REGION").unwrap_or_else(|_| "us-east-1".to_owned());

    S3BlobStore::new(endpoint, bucket, access_key_id, secret, region)
}

#[tokio::test]
#[ignore = "needs a live S3-compatible endpoint (the MinIO CI job, or a local MinIO)"]
async fn s3_store_honors_the_contract() {
    let store: Arc<dyn BlobStore> = Arc::new(s3_store_from_env());
    let keys = Keyspace::plain("hippius-mem-contract-plain");

    clear_prefix(store.as_ref(), &keys.prefix).await;
    exercise_contract(Arc::clone(&store), &keys).await;
    clear_prefix(store.as_ref(), &keys.prefix).await;
}

#[tokio::test]
#[ignore = "needs a live S3-compatible endpoint (the MinIO CI job, or a local MinIO)"]
async fn caching_store_over_s3_honors_the_contract() {
    // The exact production composition: the disk cache in front of the real
    // gateway. Nothing else covers the two together.
    let backend: Arc<dyn BlobStore> = Arc::new(s3_store_from_env());
    let keys = Keyspace::cached("hippius-mem-contract-cached");

    clear_prefix(backend.as_ref(), &keys.prefix).await;

    let (store, _cache_dir) = caching_over(Arc::clone(&backend));
    exercise_contract(store, &keys).await;

    clear_prefix(backend.as_ref(), &keys.prefix).await;
}
