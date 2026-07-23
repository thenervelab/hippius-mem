//! Object-storage seam for sealed note blobs.
//!
//! [`BlobStore`] is the async, `dyn`-compatible boundary the rest of the crate
//! talks to. Two implementations live here: [`MemoryBlobStore`], an in-memory
//! fake the unit suite (and any offline caller) drives with no network, and
//! [`S3BlobStore`], which targets the Hippius S3 gateway through `aws-sdk-s3`.
//! Putting both behind one trait lets the index/op-log layers be unit-tested
//! against the fake and deployed against the gateway unchanged.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use async_trait::async_trait;
use aws_sdk_s3::Client;
use aws_sdk_s3::error::{DisplayErrorContext, SdkError};
use aws_sdk_s3::operation::get_object::GetObjectError;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::Object;

use crate::error::MemError;

/// Render an `aws-sdk-s3` error with its FULL source chain, not just the outer
/// variant label.
///
/// `SdkError`'s own `Display` prints only the category — "service error",
/// "dispatch failure" — so mapping a failure via `err.to_string()` throws away
/// the modeled error code (`AccessDenied`, `NoSuchBucket`) and HTTP status that a
/// 403/404 triage actually needs, and the caller sees the useless "storage error:
/// service error". `DisplayErrorContext` walks the error's `source()` chain, which
/// carries that detail. Generic over the operation error so every call site
/// (`put`/`get`/`delete`/`list`/streamed body) gets the same faithful rendering.
fn storage_error<E, R>(err: SdkError<E, R>) -> MemError
where
    E: std::error::Error + Send + Sync + 'static,
    R: std::fmt::Debug + Send + Sync + 'static,
{
    // Consume `err` INTO `DisplayErrorContext` (it owns its `E: Error`), so the
    // helper takes the error by value — the shape `.map_err(storage_error)` needs
    // at every call site, and what keeps `needless_pass_by_value` quiet.
    MemError::Storage(DisplayErrorContext(err).to_string())
}

/// Maximum bytes a single [`S3BlobStore::get`] will buffer.
///
/// The gateway is an untrusted arbitrary-remote boundary, and every integrity
/// check on a fetched blob (content hash, AEAD tag, op-log signature) runs only
/// AFTER the bytes are resident — so `get` MUST bound its buffer or a
/// hostile/compromised gateway can OOM the shared server with a multi-GB response.
/// A coarse ceiling deliberately set FAR above any legitimate note or op-log blob
/// (both tiny) and above a realistically-sized team index snapshot, so a real
/// object is never rejected. The rare snapshot that does exceed it degrades to a
/// full op-log replay (see `load_latest_snapshot`, which treats
/// [`MemError::BlobTooLarge`] as a skip), not an error — a note fetch that hits it
/// is fetching something no legitimate writer produced.
const MAX_BLOB_BYTES: usize = 512 * 1024 * 1024;

/// Async, `dyn`-compatible store for opaque note blobs keyed by object key.
///
/// Keys are the strings produced by [`crate::objkey::object_key`]; values are
/// already-sealed ciphertext — this layer neither encrypts nor interprets them.
///
/// `list` returns keys in lexicographic (byte) order so callers get a stable,
/// reproducible ordering regardless of backend: the fake iterates a
/// `BTreeMap`, and the gateway relies on S3 `ListObjectsV2`'s documented
/// UTF-8-binary key ordering.
///
/// The trait is object-safe and `Send + Sync`, so a caller can hold an
/// `Arc<dyn BlobStore>` and share it across tasks on a multithreaded runtime.
/// It uses [`macro@async_trait`] rather than native `async fn` in trait
/// precisely because `dyn` dispatch is required — native async-fn-in-trait is
/// not yet `dyn`-compatible.
#[async_trait]
pub trait BlobStore: Send + Sync {
    /// Store `bytes` at `key`, overwriting any existing object at that key.
    ///
    /// # Errors
    ///
    /// Returns [`MemError::Storage`] if the backend write fails.
    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError>;

    /// Fetch the object at `key`.
    ///
    /// # Errors
    ///
    /// Returns [`MemError::NotFound`] if no object exists at `key`, or
    /// [`MemError::Storage`] for any other backend failure.
    async fn get(&self, key: &str) -> Result<Vec<u8>, MemError>;

    /// List object keys under `prefix`, in lexicographic order.
    ///
    /// # Errors
    ///
    /// Returns [`MemError::Storage`] if the backend listing fails.
    async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError>;

    /// Delete the object at `key`. Idempotent: deleting a key that does not
    /// exist succeeds, matching S3 `DeleteObject` (which returns 204 whether or
    /// not the key was present). This is what lets best-effort housekeeping — like
    /// snapshot pruning — race with itself without spurious errors.
    ///
    /// # Errors
    ///
    /// Returns [`MemError::Storage`] if the backend delete fails (a transport or
    /// permission fault — never a "key absent" signal, which is success).
    async fn delete(&self, key: &str) -> Result<(), MemError>;

    /// Evict `key` from any LOCAL cache layer WITHOUT touching the backend object.
    ///
    /// Default: a no-op — a store with no cache has nothing to evict.
    /// [`CachingBlobStore`] overrides it to remove the on-disk sealed body.
    ///
    /// This exists so a teammate applying a `Redact` can reclaim its own cached
    /// copy of a note it never issued the backend delete for (the redact issuer
    /// already scrubbed the bucket). It is gated on NEITHER the index nor a
    /// once-per-machine condition: a note forgotten (dropped from the index)
    /// before its `Redact` is synced is still on disk, and skipping it would leave
    /// a team-key-decryptable ciphertext to outlive the redaction. So the eviction
    /// is local, best-effort, and idempotent — safe to call on every sync for a
    /// note that stays redacted forever.
    async fn evict_cache(&self, _key: &str) {}
}

/// In-memory [`BlobStore`] backed by a `BTreeMap`, for tests and offline use.
///
/// The `BTreeMap` keeps keys sorted, so `list` needs no extra sort. The map is
/// behind a [`std::sync::Mutex`]: methods take `&self`, and no guard is ever
/// held across an `.await` (each locks, does its synchronous work, and drops
/// the guard before returning), so the generated futures stay `Send`.
#[derive(Debug, Default)]
pub struct MemoryBlobStore {
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl MemoryBlobStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // Map the (practically unreachable) poison case to a storage error rather
    // than panicking: the workspace denies `unwrap`/`panic`, and a poisoned
    // fake is a caller-side bug we surface as a failed store op, not a crash.
    fn lock(&self) -> Result<MutexGuard<'_, BTreeMap<String, Vec<u8>>>, MemError> {
        self.objects
            .lock()
            .map_err(|_| MemError::Storage("in-memory blob store mutex poisoned".to_owned()))
    }
}

#[async_trait]
impl BlobStore for MemoryBlobStore {
    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
        self.lock()?.insert(key.to_owned(), bytes);
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
        self.lock()?
            .get(key)
            .cloned()
            .ok_or_else(|| MemError::NotFound { id: key.to_owned() })
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError> {
        let keys = self
            .lock()?
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect();
        Ok(keys)
    }

    async fn delete(&self, key: &str) -> Result<(), MemError> {
        // `remove` returning `None` (key absent) is success: delete is idempotent.
        self.lock()?.remove(key);
        Ok(())
    }
}

/// [`BlobStore`] backed by the Hippius S3 gateway via `aws-sdk-s3`.
///
/// The gateway is S3-compatible but needs three non-AWS choices, all baked in
/// by [`S3BlobStore::new`]: **path-style** addressing (`force_path_style(true)`),
/// `SigV4` signing with **static** sub-token credentials (not the env/`IMDS`
/// chain), and a custom `endpoint_url`. The `region` is a gateway-required
/// label (`"decentralized"` in production), not an AWS region. These match the
/// gateway's own `examples/py/boto3_example.py`
/// (`Config(signature_version="s3v4", s3={"addressing_style": "path"})`,
/// `region_name="decentralized"`).
///
/// `Client` is cheap to clone (it is internally reference-counted), so the type
/// derives `Clone`.
#[derive(Debug, Clone)]
pub struct S3BlobStore {
    client: Client,
    bucket: String,
}

impl S3BlobStore {
    /// Build a store targeting `bucket` on the gateway at `endpoint_url`,
    /// signing every request with the static sub-token (`access_key_id` +
    /// `secret`). `region` is the gateway's required region label.
    ///
    /// Synchronous on purpose: building the client opens no connections and
    /// needs no running runtime; the first network call happens on
    /// `put`/`get`/`list`.
    #[must_use]
    pub fn new(
        endpoint_url: String,
        bucket: String,
        access_key_id: String,
        secret: String,
        region: String,
    ) -> Self {
        // `Credentials::new` over `from_keys` avoids the `hardcoded-credentials`
        // feature gate; the two differ only in the provider label string.
        let credentials =
            aws_credential_types::Credentials::new(access_key_id, secret, None, None, "Static");
        let config = aws_sdk_s3::Config::builder()
            .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
            .endpoint_url(endpoint_url)
            .region(aws_sdk_s3::config::Region::new(region))
            .credentials_provider(credentials)
            .force_path_style(true)
            .build();
        Self {
            client: Client::from_conf(config),
            bucket,
        }
    }
}

#[async_trait]
impl BlobStore for S3BlobStore {
    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(bytes))
            .send()
            .await
            .map_err(storage_error)?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
        let output = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|err| map_get_object_error(err, key))?;
        // Bound the buffer HERE, before any integrity check runs on these bytes.
        // `body.collect()` would buffer the whole (possibly multi-GB, possibly
        // Content-Length-lying) response first and let a hostile gateway OOM the
        // shared server. See `read_capped`.
        read_capped(output.body, key, MAX_BLOB_BYTES).await
    }

    async fn delete(&self, key: &str) -> Result<(), MemError> {
        // S3 `DeleteObject` is idempotent: it returns success whether or not the
        // key existed, so an absent key is never an error here.
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(storage_error)?;
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError> {
        let mut keys = Vec::new();
        let mut continuation: Option<String> = None;
        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(prefix);
            if let Some(token) = continuation {
                request = request.continuation_token(token);
            }
            let output = request.send().await.map_err(storage_error)?;
            keys.extend(
                output
                    .contents()
                    .iter()
                    .filter_map(Object::key)
                    .map(str::to_owned),
            );
            // `ListObjectsV2` returns at most 1000 keys per page in lexicographic
            // order; follow the continuation token until the listing is whole. Key
            // the loop on the token's PRESENCE, not on `is_truncated`: AWS sets the
            // token iff `IsTruncated`, but the custom Hippius gateway (and several
            // S3-compatible impls) can return a `NextContinuationToken` while omitting
            // or misreporting `IsTruncated`. Gating on `is_truncated` there would stop
            // after the first 1000 keys and silently drop the rest of a team's ops or
            // notes with NO error — a partial converged index. An empty token string
            // is treated as absent (no more pages).
            match output.next_continuation_token() {
                Some(token) if !token.is_empty() => {
                    continuation = Some(token.to_owned());
                }
                _ => break,
            }
        }
        Ok(keys)
    }
}

/// Read a [`ByteStream`] into memory, failing with [`MemError::BlobTooLarge`] once
/// it exceeds `cap` bytes.
///
/// The gateway is untrusted and every integrity check runs only AFTER the bytes
/// are resident, so the buffer MUST be bounded here. Reading frame by frame with
/// [`ByteStream::next`] (rather than [`ByteStream::collect`], which buffers the
/// whole response before returning) keeps peak memory at `cap` plus one HTTP
/// frame, and catches a gateway that under-reports `Content-Length`. Split out as a
/// free function so the offline suite can drive the cap with a tiny threshold and
/// an in-memory body.
///
/// # Errors
///
/// [`MemError::Storage`] if a frame read fails; [`MemError::BlobTooLarge`] if the
/// accumulated body would exceed `cap`.
async fn read_capped(mut body: ByteStream, key: &str, cap: usize) -> Result<Vec<u8>, MemError> {
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|e| MemError::Storage(e.to_string()))?;
        if buf.len().saturating_add(chunk.len()) > cap {
            return Err(MemError::BlobTooLarge {
                key: key.to_owned(),
                cap,
            });
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Map a failed `GetObject` to the crate error.
///
/// Uses `as_service_error` (returns `Option<&E>`, never panics) rather than its
/// sibling `into_service_error` (which converts a non-service error into an
/// `Unhandled` variant only after panicking on some shapes): a modeled
/// `NoSuchKey` is the only not-found signal, and every other failure — including
/// a dispatch/timeout error that carries no service error at all — is a storage
/// fault, never a process abort. Split out as a free function so the offline
/// suite can drive it with a synthesized transport error.
fn map_get_object_error(err: SdkError<GetObjectError>, key: &str) -> MemError {
    if err
        .as_service_error()
        .is_some_and(GetObjectError::is_no_such_key)
    {
        MemError::NotFound { id: key.to_owned() }
    } else {
        // Delegate to `storage_error` so the full source chain (code + HTTP
        // status) is rendered here too, not just the `SdkError` category label.
        storage_error(err)
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "tests assert on in-memory fixtures where construction cannot fail"
    )]

    use std::sync::Arc;

    use super::*;

    #[tokio::test]
    async fn put_then_get_round_trips() {
        let store = MemoryBlobStore::new();
        store.put("a/1", b"hello".to_vec()).await.unwrap();
        assert_eq!(store.get("a/1").await.unwrap(), b"hello");
    }

    #[tokio::test]
    async fn get_missing_key_is_not_found() {
        let store = MemoryBlobStore::new();
        let err = store.get("nope").await.unwrap_err();
        assert!(matches!(err, MemError::NotFound { id } if id == "nope"));
    }

    #[tokio::test]
    async fn put_overwrites() {
        let store = MemoryBlobStore::new();
        store.put("k", b"first".to_vec()).await.unwrap();
        store.put("k", b"second".to_vec()).await.unwrap();
        assert_eq!(store.get("k").await.unwrap(), b"second");
    }

    #[tokio::test]
    async fn read_capped_enforces_the_byte_cap_with_a_distinct_error() {
        // At the cap -> returned whole; one byte over -> BlobTooLarge (never
        // buffered past the cap), the DISTINCT variant snapshot loading matches to
        // fall back gracefully. A tiny cap keeps the test allocation-free.
        let ok = read_capped(ByteStream::from(vec![7_u8; 10]), "k", 10)
            .await
            .unwrap();
        assert_eq!(ok, vec![7_u8; 10], "a body at the cap is returned in full");

        let err = read_capped(ByteStream::from(vec![7_u8; 11]), "k", 10)
            .await
            .unwrap_err();
        assert!(
            matches!(err, MemError::BlobTooLarge { cap, .. } if cap == 10),
            "over the cap must be BlobTooLarge (not Storage), so callers can fall back: {err:?}"
        );

        assert!(
            read_capped(ByteStream::from(Vec::new()), "k", 10)
                .await
                .unwrap()
                .is_empty(),
            "an empty body reads back empty"
        );
    }

    #[tokio::test]
    async fn list_returns_sorted_keys_under_prefix() {
        let store = MemoryBlobStore::new();
        for key in ["team/b", "team/a", "team/c", "other/z"] {
            store.put(key, b"x".to_vec()).await.unwrap();
        }
        let listed = store.list("team/").await.unwrap();
        assert_eq!(
            listed,
            vec![
                "team/a".to_owned(),
                "team/b".to_owned(),
                "team/c".to_owned()
            ]
        );
    }

    #[tokio::test]
    async fn list_empty_prefix_returns_all_sorted() {
        let store = MemoryBlobStore::new();
        for key in ["z", "a", "m"] {
            store.put(key, b"x".to_vec()).await.unwrap();
        }
        assert_eq!(
            store.list("").await.unwrap(),
            vec!["a".to_owned(), "m".to_owned(), "z".to_owned()]
        );

        let empty = MemoryBlobStore::new();
        assert!(empty.list("").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn usable_as_arc_dyn_blob_store() {
        let store: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
        store.put("dyn/key", b"v".to_vec()).await.unwrap();
        assert_eq!(store.get("dyn/key").await.unwrap(), b"v");
    }

    #[test]
    fn transport_error_maps_to_storage_not_panic() {
        // A timeout/dispatch failure carries NO service error, so
        // `as_service_error()` is `None` and the mapping must fall through to
        // `Storage` — and must NOT reach the panicking `into_service_error`. This
        // is the regression the `as_service_error` rewrite guards against; the
        // mock framework cannot synthesize a transport error, so the helper is
        // unit-tested directly with one.
        let err: SdkError<GetObjectError> = SdkError::timeout_error("simulated read timeout");
        let mapped = map_get_object_error(err, "team/global/mem_x/ver_1");
        assert!(matches!(mapped, MemError::Storage(_)));
    }

    #[tokio::test]
    async fn get_no_such_key_maps_to_not_found() {
        use aws_sdk_s3::operation::get_object::GetObjectError;
        use aws_sdk_s3::types::error::NoSuchKey;
        use aws_smithy_mocks::{RuleMode, mock, mock_client};

        let rule = mock!(Client::get_object)
            .then_error(|| GetObjectError::NoSuchKey(NoSuchKey::builder().build()));
        let client = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&rule], |b| b
            .force_path_style(true));
        let store = S3BlobStore {
            client,
            bucket: "test-bucket".to_owned(),
        };

        let err = store.get("team/global/mem_x/ver_1").await.unwrap_err();
        assert!(
            matches!(&err, MemError::NotFound { id } if id == "team/global/mem_x/ver_1"),
            "a modeled NoSuchKey must map to NotFound, got {err:?}"
        );
    }

    #[tokio::test]
    async fn list_follows_continuation_token_across_pages() {
        use aws_sdk_s3::operation::list_objects_v2::ListObjectsV2Output;
        use aws_sdk_s3::types::Object;
        use aws_smithy_mocks::{RuleMode, mock, mock_client};

        // Page 1 is truncated and hands back a continuation token; page 2 closes
        // the listing. `list` must follow the token and accumulate BOTH pages'
        // keys, not stop at the first page.
        let page1 = mock!(Client::list_objects_v2).then_output(|| {
            ListObjectsV2Output::builder()
                .contents(Object::builder().key("team/a").build())
                .set_is_truncated(Some(true))
                .next_continuation_token("PAGE2")
                .build()
        });
        let page2 = mock!(Client::list_objects_v2).then_output(|| {
            ListObjectsV2Output::builder()
                .contents(Object::builder().key("team/b").build())
                .set_is_truncated(Some(false))
                .build()
        });
        let client = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&page1, &page2], |b| b
            .force_path_style(true));
        let store = S3BlobStore {
            client,
            bucket: "test-bucket".to_owned(),
        };

        let keys = store.list("team/").await.unwrap();
        assert_eq!(keys, vec!["team/a".to_owned(), "team/b".to_owned()]);
    }

    #[tokio::test]
    async fn list_follows_token_even_when_is_truncated_is_absent() {
        use aws_sdk_s3::operation::list_objects_v2::ListObjectsV2Output;
        use aws_sdk_s3::types::Object;
        use aws_smithy_mocks::{RuleMode, mock, mock_client};

        // A gateway that returns a NextContinuationToken but does NOT set
        // `IsTruncated` (the Hippius-gateway / S3-compatible shape). `list` must
        // still follow the token; gating on `is_truncated` here dropped page 2
        // silently and truncated the listing at 1000 keys.
        let page1 = mock!(Client::list_objects_v2).then_output(|| {
            ListObjectsV2Output::builder()
                .contents(Object::builder().key("team/a").build())
                .next_continuation_token("PAGE2")
                // Deliberately NO set_is_truncated — the whole point of the test.
                .build()
        });
        let page2 = mock!(Client::list_objects_v2).then_output(|| {
            ListObjectsV2Output::builder()
                .contents(Object::builder().key("team/b").build())
                .build()
        });
        let client = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&page1, &page2], |b| b
            .force_path_style(true));
        let store = S3BlobStore {
            client,
            bucket: "test-bucket".to_owned(),
        };

        let keys = store.list("team/").await.unwrap();
        assert_eq!(keys, vec!["team/a".to_owned(), "team/b".to_owned()]);
    }

    /// Live round-trip against a real Hippius S3 gateway. Compiled only under the
    /// `s3-integration` feature and `#[ignore]`d: it needs
    /// `HIPPIUS_S3_ENDPOINT`/`BUCKET`/`KEY`/`SECRET` and a reachable endpoint, so
    /// it never runs in CI. Region defaults to the gateway's `"decentralized"`
    /// label when `HIPPIUS_S3_REGION` is unset.
    #[cfg(feature = "s3-integration")]
    #[tokio::test]
    #[ignore = "requires a live Hippius S3 gateway and sub-token credentials"]
    async fn s3_round_trips_against_live_gateway() {
        let endpoint = std::env::var("HIPPIUS_S3_ENDPOINT").unwrap();
        let bucket = std::env::var("HIPPIUS_S3_BUCKET").unwrap();
        let access_key_id = std::env::var("HIPPIUS_S3_KEY").unwrap();
        let secret = std::env::var("HIPPIUS_S3_SECRET").unwrap();
        let region =
            std::env::var("HIPPIUS_S3_REGION").unwrap_or_else(|_| "decentralized".to_owned());

        let store = S3BlobStore::new(endpoint, bucket, access_key_id, secret, region);
        let key = format!("hippius-mem-it/{}", ulid::Ulid::new());
        let payload = b"integration-round-trip".to_vec();

        store.put(&key, payload.clone()).await.unwrap();
        assert_eq!(store.get(&key).await.unwrap(), payload);
        assert!(store.list("hippius-mem-it/").await.unwrap().contains(&key));
    }
}
