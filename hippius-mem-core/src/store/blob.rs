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
use aws_sdk_s3::operation::get_object::GetObjectError;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::Object;

use crate::error::MemError;

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
            .map_err(|e| MemError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
        let output = match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(output) => output,
            // `as_service_error` returns `Option<&E>` and never panics; its
            // sibling `into_service_error` panics on a non-service (transport /
            // timeout) error, which would turn a transient network blip on
            // `get` into a process abort. A modeled `NoSuchKey` is the only
            // not-found signal; everything else is a storage failure.
            Err(err) => {
                return if err
                    .as_service_error()
                    .is_some_and(GetObjectError::is_no_such_key)
                {
                    Err(MemError::NotFound { id: key.to_owned() })
                } else {
                    Err(MemError::Storage(err.to_string()))
                };
            }
        };
        let body = output
            .body
            .collect()
            .await
            .map_err(|e| MemError::Storage(e.to_string()))?;
        Ok(body.to_vec())
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
            let output = request
                .send()
                .await
                .map_err(|e| MemError::Storage(e.to_string()))?;
            keys.extend(
                output
                    .contents()
                    .iter()
                    .filter_map(Object::key)
                    .map(str::to_owned),
            );
            // `ListObjectsV2` returns at most 1000 keys per page in lexicographic
            // order; follow the continuation token until the listing is whole.
            match output.next_continuation_token() {
                Some(token) if output.is_truncated().unwrap_or(false) => {
                    continuation = Some(token.to_owned());
                }
                _ => break,
            }
        }
        Ok(keys)
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
