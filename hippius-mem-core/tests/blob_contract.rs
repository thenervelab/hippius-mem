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
//! workaround in `S3BlobStore::list`. That listing loop gets its own run here,
//! over more objects than one page holds, since the offline mocks for it can
//! only return the page shape their author wrote down. Every S3 run is
//! `#[ignore]`d and driven by the `MinIO` job in `.github/workflows/rust.yml`.

#![expect(
    clippy::expect_used,
    reason = "tests assert on throwaway fixtures where construction cannot fail"
)]

use std::sync::Arc;

use futures_util::StreamExt as _;
use hippius_mem_core::{
    BlobStore, CachingBlobStore, CreateOnly, CreateOutcome, FsBlobStore, MemError, MemoryBlobStore,
    S3BlobStore, SecretKey, probe_create_only,
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

/// The create-only write: it creates an absent key, refuses an existing one
/// without changing it, and the probe reports the store enforces it. A backend
/// that ignores the condition fails here, which is the point of running this
/// against the live gateway.
async fn exercise_create_only(store: &dyn BlobStore, keys: &Keyspace) {
    assert_eq!(
        store
            .put_if_absent(&keys.first, vec![1])
            .await
            .expect("create"),
        CreateOutcome::Created
    );
    assert_eq!(
        store
            .put_if_absent(&keys.first, vec![2])
            .await
            .expect("second create"),
        CreateOutcome::AlreadyExists
    );
    assert_eq!(store.get(&keys.first).await.expect("get"), vec![1]);

    let team = keys.prefix.split('/').next().expect("a prefix has a team");
    assert_eq!(
        probe_create_only(store, team).await.expect("probe"),
        CreateOnly::Enforced
    );
    store.delete(&keys.first).await.expect("cleanup");
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
async fn memory_fs_and_caching_stores_enforce_create_only_writes() {
    exercise_create_only(&MemoryBlobStore::new(), &Keyspace::plain("team")).await;

    let dir = tempfile::tempdir().expect("temp dir");
    exercise_create_only(
        &FsBlobStore::new(dir.path().to_path_buf()),
        &Keyspace::plain("team"),
    )
    .await;

    let (cached, _cache_dir) = caching_over(Arc::new(MemoryBlobStore::new()));
    exercise_create_only(cached.as_ref(), &Keyspace::cached("team")).await;
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
/// The endpoint and the bucket have no default: a wrong guess would write into,
/// and clear a prefix of, a server or bucket the operator did not set up for
/// this test.
fn s3_store_from_env() -> S3BlobStore {
    let endpoint = std::env::var("HIPPIUS_MEM_TEST_S3_ENDPOINT")
        .expect("set HIPPIUS_MEM_TEST_S3_ENDPOINT to the throwaway S3 endpoint");
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

/// A request the gateway refuses (here: signed with a wrong secret) fails with a
/// short error naming the HTTP status and the S3 error code, and without the
/// gateway's echo of the request. The error used to carry the whole SDK error
/// chain: the access key id, the string the request signed, and any response
/// body, however large.
#[tokio::test]
#[ignore = "needs a live S3-compatible endpoint (the MinIO CI job, or a local MinIO)"]
async fn a_refused_request_fails_with_a_short_error() {
    let endpoint = std::env::var("HIPPIUS_MEM_TEST_S3_ENDPOINT")
        .expect("set HIPPIUS_MEM_TEST_S3_ENDPOINT to the throwaway S3 endpoint");
    let bucket = std::env::var("HIPPIUS_MEM_TEST_BUCKET")
        .expect("set HIPPIUS_MEM_TEST_BUCKET to a bucket that already exists on the endpoint");
    let access_key_id =
        std::env::var("HIPPIUS_MEM_TEST_ACCESS_KEY_ID").unwrap_or_else(|_| "test".to_owned());
    let region =
        std::env::var("HIPPIUS_MEM_TEST_S3_REGION").unwrap_or_else(|_| "us-east-1".to_owned());
    let store = S3BlobStore::new(
        endpoint,
        bucket,
        access_key_id.clone(),
        "not-the-secret".to_owned(),
        region,
    );

    let Err(MemError::Storage(message)) = store.list("hippius-mem-contract-refused/").await else {
        panic!("a request signed with a wrong secret must fail as a storage error");
    };
    assert!(message.contains("403"), "names the HTTP status: {message}");
    assert!(
        message.contains("SignatureDoesNotMatch"),
        "names the S3 error code: {message}"
    );
    assert!(
        !message.contains(&access_key_id),
        "must not echo the access key id: {message}"
    );
    assert!(message.len() < 600, "{} bytes: {message}", message.len());
}

/// Whether the live endpoint enforces `If-None-Match: *` on `PutObject`. The
/// Hippius gateway's support is not documented; versitygw 1.8.0 enforces it.
#[tokio::test]
#[ignore = "needs a live S3-compatible endpoint (the MinIO CI job, or a local MinIO)"]
async fn s3_store_enforces_create_only_writes() {
    let store = s3_store_from_env();
    let keys = Keyspace::plain("hippius-mem-contract-create-only");

    clear_prefix(&store, &keys.prefix).await;
    exercise_create_only(&store, &keys).await;
    clear_prefix(&store, &keys.prefix).await;
}

/// How many objects the pagination run puts under one prefix.
///
/// `ListObjectsV2` returns at most 1000 keys per page. Exactly 1000 objects fit
/// in ONE page, so a `list` that never followed the continuation token at all
/// would still return every key and the run would pass while proving nothing
/// about pagination. 1,050 crosses the boundary by 50: the last 50 keys are
/// reachable only by issuing the second request, so their absence is what the
/// assertion catches — and 50 extra objects keep setup within a few seconds.
const PAGINATION_OBJECTS: usize = 1_050;

/// How many puts are in flight while the fixture is built. Mirrors the
/// bounded-concurrency shape the production op-log read uses (`futures_util` +
/// `buffer_unordered`); 32 keeps 1,050 sequential round trips from dominating
/// the run without opening an unbounded fan-out.
const PAGINATION_CONCURRENCY: usize = 32;

/// The key for object `n` under `prefix`.
///
/// The suffix is zero-padded to a FIXED width so lexicographic and numeric order
/// coincide. Unpadded, `"999"` sorts after `"1000"`, and the ordering assertion
/// below would be measuring this function's key naming rather than the order the
/// backend actually returns.
fn paginated_key(prefix: &str, n: usize) -> String {
    format!("{prefix}{n:04}")
}

/// Apply `op` to every key of the pagination fixture with bounded concurrency.
async fn for_each_paginated_key<F, Fut>(prefix: &str, op: F)
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    futures_util::stream::iter((0..PAGINATION_OBJECTS).map(|n| op(paginated_key(prefix, n))))
        .buffer_unordered(PAGINATION_CONCURRENCY)
        .collect::<()>()
        .await;
}

/// `S3BlobStore::list` past the continuation boundary, against a real endpoint.
///
/// The paging loop has two offline `aws-smithy-mocks` tests, including the
/// gateway shape that omits `IsTruncated`, but a mock returns whatever page
/// shape the test author wrote down. Nothing had ever asked a real backend for
/// more keys than one page holds — which is the case where a wrong loop drops
/// the tail of a team's ops or notes silently, with no error, leaving a
/// partially converged index.
///
/// The whole `BlobStore` contract promises lexicographic order, so the
/// assertion is on the full ordered sequence, not merely the count: pages
/// concatenated in the wrong order, or a token followed twice, would keep the
/// count wrong or the order wrong respectively.
///
/// Clears the prefix before AND after, like its neighbours above: a leaked
/// prefix of 1,050 objects would break every later run against the same bucket.
#[tokio::test]
#[ignore = "needs a live S3-compatible endpoint (the MinIO CI job, or a local MinIO)"]
async fn s3_store_lists_every_key_across_the_continuation_boundary() {
    let store: Arc<dyn BlobStore> = Arc::new(s3_store_from_env());
    let prefix = "hippius-mem-contract-paging/";

    clear_prefix(store.as_ref(), prefix).await;

    for_each_paginated_key(prefix, |key| {
        let store = Arc::clone(&store);
        async move {
            // A one-byte body: this run measures the LISTING, so object size is
            // pure setup cost.
            let _ = store.put(&key, vec![1]).await;
        }
    })
    .await;

    let listed = store.list(prefix).await.expect("list");
    let expected: Vec<String> = (0..PAGINATION_OBJECTS)
        .map(|n| paginated_key(prefix, n))
        .collect();

    assert_eq!(
        listed.len(),
        PAGINATION_OBJECTS,
        "every key must come back: a loop that stopped at the first page boundary would return \
         1000 of {PAGINATION_OBJECTS}"
    );

    // Report the FIRST divergence rather than dumping 1,050 keys twice: the keys
    // are numbered, so the pair names the position by itself.
    let divergence = listed.iter().zip(&expected).find(|(got, want)| got != want);
    assert!(
        divergence.is_none(),
        "list must stay lexicographic across the page boundary; first mismatch: {divergence:?}"
    );

    clear_prefix(store.as_ref(), prefix).await;
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
