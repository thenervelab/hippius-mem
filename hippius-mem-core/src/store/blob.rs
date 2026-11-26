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
use std::time::Duration;

use async_trait::async_trait;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::http::HttpResponse;
use aws_sdk_s3::error::{DisplayErrorContext, ProvideErrorMetadata, SdkError};
use aws_sdk_s3::operation::RequestId;
use aws_sdk_s3::operation::get_object::GetObjectError;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::Object;
use futures_util::stream::{self, Stream, StreamExt};

use crate::error::MemError;
use crate::ulid::Ulid;

/// Render an `aws-sdk-s3` error as a short line a 403/404 triage can act on.
///
/// A service error becomes its HTTP status, S3 error code, the gateway's message
/// cut to [`MAX_ERROR_MESSAGE_CHARS`], and the request id. Nothing else of the
/// response goes in: the SDK's full error chain (`DisplayErrorContext`) carries
/// the raw response, which held the access key id and the string the request
/// signed on a signature mismatch, and the whole body however large (a 20 MiB
/// body gave a 20 MiB error). `SdkError`'s own `Display` is no better the other
/// way: it prints only the category ("service error").
///
/// Any other failure (dispatch, timeout, construction, an unparsable response)
/// keeps the source chain, which names the transport cause and holds no
/// response body, cut to [`MAX_ERROR_DETAIL_CHARS`] all the same.
fn storage_error<E>(err: SdkError<E, HttpResponse>) -> MemError
where
    E: ProvideErrorMetadata + std::error::Error + Send + Sync + 'static,
{
    let detail = match err {
        SdkError::ServiceError(service) => {
            let status = service.raw().status().as_u16();
            let meta = service.err().meta();
            let code = meta.code().unwrap_or("no error code");
            let message = clamp_chars(meta.message().unwrap_or(""), MAX_ERROR_MESSAGE_CHARS);
            let request_id = meta.request_id().unwrap_or("none");
            format!("S3 status {status}, {code}: {message} (request id {request_id})")
        }
        other => clamp_chars(
            &DisplayErrorContext(other).to_string(),
            MAX_ERROR_DETAIL_CHARS,
        ),
    };
    MemError::Storage(detail)
}

/// The most characters of a gateway's error message [`storage_error`] keeps.
/// Arbitrary: S3's own messages are one sentence, well under this.
const MAX_ERROR_MESSAGE_CHARS: usize = 200;

/// The most characters of a non-service SDK error chain [`storage_error`] keeps.
/// Arbitrary: a dispatch or timeout chain is a few hundred characters.
const MAX_ERROR_DETAIL_CHARS: usize = 400;

/// `text` cut to at most `max` characters, marked with an ellipsis when cut.
fn clamp_chars(text: &str, max: usize) -> String {
    match text.char_indices().nth(max) {
        Some((end, _)) => format!("{}...", &text[..end]),
        None => text.to_owned(),
    }
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

/// Ceiling on keys a single [`S3BlobStore::list`] will accumulate.
///
/// The gateway is untrusted, the same boundary [`MAX_BLOB_BYTES`] guards on `get`.
/// `list` follows continuation tokens, so without a bound a hostile/buggy gateway
/// that streams endless distinct tokens could grow the buffer without limit. A real
/// team's op-log + note-blob + anchor keyspace is far below this coarse ceiling
/// (set well above any legitimate listing), so a genuine listing is never rejected;
/// exceeding it is treated as a systemic fault, mirroring `read_capped`. A repeating
/// token (a fixed-point cycle) is caught separately and immediately by
/// [`next_list_token`], which does not depend on reaching this cap.
const MAX_LIST_KEYS: usize = 2_000_000;

/// Ceiling on pages a single [`S3BlobStore::list`] will fetch.
///
/// The key cap alone cannot terminate a hostile listing: a gateway that answers
/// every page with EMPTY contents and a fresh (or alternating — anything that
/// defeats the period-1 cycle check in [`next_list_token`]) continuation token
/// never grows `keys`, so [`MAX_LIST_KEYS`] never fires and the loop would spin
/// HTTP requests forever. An honest backend returns up to 1000 keys per page, so
/// [`MAX_LIST_KEYS`] worth of real data fits in 2000 pages; the ceiling leaves a
/// generous margin for backends that return short pages, and exceeding it is a
/// systemic fault, mirroring `read_capped`.
const MAX_LIST_PAGES: usize = 20_000;

/// Enforce [`S3BlobStore::list`]'s progress bounds after a page: `pages` fetched
/// so far and `keys` accumulated so far must both stay under their caps. Pure so
/// both refusals are unit-testable without a mock gateway.
///
/// # Errors
///
/// [`MemError::Storage`] when either bound is exceeded — the listing is refused
/// rather than allowed to buffer (or spin) without limit against the untrusted
/// gateway.
fn check_list_progress(pages: usize, keys: usize) -> Result<(), MemError> {
    if pages > MAX_LIST_PAGES {
        return Err(MemError::Storage(format!(
            "listing exceeded the {MAX_LIST_PAGES}-page safety cap after {keys} keys; \
             refusing an endless paginated listing from the untrusted gateway"
        )));
    }
    if keys > MAX_LIST_KEYS {
        return Err(MemError::Storage(format!(
            "listing exceeded the {MAX_LIST_KEYS}-key safety cap; refusing to buffer an \
             unbounded listing from the untrusted gateway"
        )));
    }
    Ok(())
}

/// Decide how a paginated `list` proceeds after a page: given the continuation
/// token just USED for the page (`used`, `None` on the first page) and the `next`
/// token the gateway returned, either continue with a new token (`Ok(Some)`), stop
/// (`Ok(None)`), or reject the listing (`Err`).
///
/// Two untrusted-gateway defenses live here, kept pure so they are unit-testable:
/// an empty `next` token is treated as absent (aws-sdk's own "exhausted" signal —
/// hand-rolled loops that only test `is_none()` re-fetch page 1 forever), and a
/// `next` token EQUAL to the one just used is a fixed-point cycle that would loop
/// forever, so it is refused rather than followed.
fn next_list_token(used: Option<&str>, next: Option<&str>) -> Result<Option<String>, MemError> {
    match next {
        Some(token) if !token.is_empty() => {
            if used == Some(token) {
                return Err(MemError::Storage(format!(
                    "gateway returned a repeating continuation token ({token:?}) while listing; \
                     refusing a cyclic listing that would never terminate"
                )));
            }
            Ok(Some(token.to_owned()))
        }
        _ => Ok(None),
    }
}

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

    /// Store `bytes` at `key` only if no object exists there: a create-only
    /// write (`If-None-Match: *` on S3).
    ///
    /// Whether the backend ENFORCES it is a property of the backend, not of
    /// this call: [`MemoryBlobStore`] and [`FsBlobStore`](crate::FsBlobStore)
    /// do, and an S3 gateway that ignores the header overwrites the object and
    /// reports [`CreateOutcome::Created`]. [`probe_create_only`] tells which.
    /// An S3 call retried after a lost response can also report
    /// [`CreateOutcome::AlreadyExists`] for the object it created itself, so a
    /// caller that must know whose bytes are stored reads them back.
    ///
    /// The default refuses, so a wrapper that does not forward this call fails
    /// instead of quietly writing without the condition.
    ///
    /// # Errors
    ///
    /// [`MemError::Storage`] if the backend write fails, or if this store does
    /// not offer create-only writes.
    async fn put_if_absent(&self, key: &str, bytes: Vec<u8>) -> Result<CreateOutcome, MemError> {
        drop(bytes);
        Err(MemError::Storage(format!(
            "this blob store does not offer create-only writes, so {key} was not written"
        )))
    }

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

/// What a [`BlobStore::put_if_absent`] call did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateOutcome {
    /// No object existed at the key, and it now holds the bytes.
    Created,
    /// An object already existed at the key, and nothing was written.
    AlreadyExists,
}

/// How many GETs [`get_in_order`] keeps in flight past the first key.
/// Arbitrary: it bounds the objects fetched past the one a caller accepts to
/// 15, and cuts a walk past rejected objects 16-fold in round trips.
const ORDERED_FETCH_AHEAD: usize = 16;

/// The GETs of `keys` as a stream in the order given, for a caller that walks
/// them and stops at the first object it accepts. Each item carries its key's
/// tag.
///
/// The first key is fetched alone, so a caller that accepts it pays that one
/// GET. The rest are fetched with up to [`ORDERED_FETCH_AHEAD`] in flight: a
/// walk past objects the caller rejects (planted, legacy or malformed) costs
/// one round trip per that many keys instead of one per key. A caller that
/// stops early drops the GETs still in flight.
pub(crate) fn get_in_order<'b, T: 'b>(
    blob: &'b dyn BlobStore,
    keys: Vec<(T, String)>,
) -> impl Stream<Item = (T, Result<Vec<u8>, MemError>)> + 'b {
    let get = move |(tag, key): (T, String)| async move { (tag, blob.get(&key).await) };
    let mut keys = keys.into_iter();
    let first = keys.next();
    stream::iter(first)
        .then(get)
        .chain(stream::iter(keys).map(get).buffered(ORDERED_FETCH_AHEAD))
}

/// Whether a blob store enforces create-only writes, as [`probe_create_only`]
/// measured it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateOnly {
    /// A second create-only write of one key was refused.
    Enforced,
    /// A second create-only write of one key succeeded: the backend ignores the
    /// condition, so a create-only write there is an ordinary overwrite.
    NotEnforced,
}

/// Measure whether `blob` enforces create-only writes: create a fresh probe
/// object under `{team}/_probe/`, try to create it again, and delete it.
///
/// The Hippius gateway's support for `If-None-Match` is not documented, so a
/// caller that relies on a create-only write for exclusivity asks this first
/// and says what it cannot guarantee when the answer is
/// [`CreateOnly::NotEnforced`]. Costs two PUTs and one DELETE. The probe object
/// is deleted best-effort; one left behind is a few bytes that no reader
/// lists, and `gc` skips the prefix like every other non-note key.
///
/// # Errors
///
/// [`MemError::Storage`] when a PUT fails, the store offers no create-only
/// write, or the first create-only write found an object at a fresh random key.
pub async fn probe_create_only(blob: &dyn BlobStore, team: &str) -> Result<CreateOnly, MemError> {
    let key = format!("{team}/_probe/create-only-{}", Ulid::new());

    if blob.put_if_absent(&key, b"first".to_vec()).await? != CreateOutcome::Created {
        return Err(MemError::Storage(format!(
            "a create-only write of the fresh probe key {key} found an object already there"
        )));
    }
    let second = blob.put_if_absent(&key, b"second".to_vec()).await;

    if let Err(err) = blob.delete(&key).await {
        tracing::warn!(object_key = %key, error = %err, "could not delete the create-only probe object");
    }

    Ok(match second? {
        CreateOutcome::AlreadyExists => CreateOnly::Enforced,
        CreateOutcome::Created => CreateOnly::NotEnforced,
    })
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

    async fn put_if_absent(&self, key: &str, bytes: Vec<u8>) -> Result<CreateOutcome, MemError> {
        match self.lock()?.entry(key.to_owned()) {
            std::collections::btree_map::Entry::Occupied(_) => Ok(CreateOutcome::AlreadyExists),
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(bytes);
                Ok(CreateOutcome::Created)
            }
        }
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
    /// The first-byte bound every request starts from:
    /// [`S3_FIRST_BYTE_TIMEOUT`] outside tests.
    first_byte: Duration,
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
        Self::with_first_byte_timeout(
            endpoint_url,
            bucket,
            access_key_id,
            secret,
            region,
            S3_FIRST_BYTE_TIMEOUT,
        )
    }

    /// [`new`](Self::new) with a first-byte bound other than
    /// [`S3_FIRST_BYTE_TIMEOUT`], so a test of a hung gateway does not wait the
    /// production minute.
    fn with_first_byte_timeout(
        endpoint_url: String,
        bucket: String,
        access_key_id: String,
        secret: String,
        region: String,
        first_byte: Duration,
    ) -> Self {
        // `Credentials::new` over `from_keys` avoids the `hardcoded-credentials`
        // feature gate; the two differ only in the provider label string.
        let credentials =
            aws_credential_types::Credentials::new(access_key_id, secret, None, None, "Static");

        let timeouts = s3_timeouts(first_byte);

        let config = aws_sdk_s3::Config::builder()
            .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
            .endpoint_url(endpoint_url)
            .region(aws_sdk_s3::config::Region::new(region))
            .credentials_provider(credentials)
            .force_path_style(true)
            .timeout_config(timeouts)
            // Pin retries explicitly so a `cargo update` that moves the default
            // `BehaviorVersion` cannot silently change append/read retry semantics
            // (an older BMV disabled retries entirely; the current default enables
            // the standard 3-attempt policy). Keep them ON: transient gateway blips
            // are common, and every write is idempotent (op keys are content-addressed,
            // deletes are idempotent), so a retried request cannot corrupt state.
            .retry_config(aws_sdk_s3::config::retry::RetryConfig::standard())
            .build();

        Self {
            client: Client::from_conf(config),
            bucket,
            first_byte,
        }
    }

    /// The per-request timeouts for a PUT of `len` bytes.
    ///
    /// The first-byte bound runs from when the request starts, so it includes
    /// sending the body: a large checkpoint on a slow link would otherwise time
    /// out on every attempt. The bound grows by the time the body takes at
    /// [`SLOW_LINK_BYTES_PER_SEC`], rounded up to a whole second.
    fn put_timeouts(&self, len: usize) -> aws_sdk_s3::config::Builder {
        let upload = Duration::from_secs((len as u64).div_ceil(SLOW_LINK_BYTES_PER_SEC));
        aws_sdk_s3::config::Builder::new().timeout_config(s3_timeouts(self.first_byte + upload))
    }
}

/// How long one S3 request may wait for the gateway to start answering: from
/// sending the request (its body included) to the first byte of the response,
/// as the SDK's `read_timeout` is defined.
///
/// A gateway that accepts the connection and then never answers used to hold a
/// call for the whole 5-minute attempt timeout, and a `remember` makes several
/// calls, so a session sat blocked for minutes while holding the writer lock. The
/// Hippius gateway normally answers in hundreds of milliseconds, so 20 s is tens of
/// times that. A PUT's bound grows with its body (see
/// `S3BlobStore::put_timeouts`), so a large upload is not cut short by it.
/// Downloads are not cut short by it either: once the response has started, the
/// stalled-stream protection and the attempt timeout bound the body. Chosen by
/// that arithmetic, not measured.
///
/// What a caller waits on a hung gateway: three attempts of 20 s plus the
/// standard retry backoff (under 1 s, then under 2 s, with jitter), so about
/// 62 s per call. A write on a server that started moments before waits first
/// for the warmup read (up to 90 s, the binary's `WARMUP_READ_WAIT`), which is
/// how the evaluation measured 151 s end to end against a hung versitygw.
const S3_FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(20);

/// How long the SDK waits to open a connection: its own default for current
/// behaviour versions (3.1 s, `DEFAULT_CONNECT_TIMEOUT` in aws-smithy-runtime
/// 1.16.2 `client/defaults.rs`), set here so a per-request timeout override
/// keeps it. The override is stored in its own config layer and read in place
/// of the client's timeouts: aws-sdk-s3 1.157.0 `Builder::set_timeout_config`
/// merges only with a timeout config already in the same builder, which an
/// override builder never has.
const S3_CONNECT_TIMEOUT: Duration = Duration::from_millis(3100);

/// How long one attempt may take once started, a slow transfer included.
const S3_ATTEMPT_TIMEOUT: Duration = Duration::from_mins(5);

/// The slowest link a transfer must survive: the largest blob a `get` reads
/// ([`MAX_BLOB_BYTES`]) within one attempt, about 1.7 MiB/s.
const SLOW_LINK_BYTES_PER_SEC: u64 = MAX_BLOB_BYTES as u64 / S3_ATTEMPT_TIMEOUT.as_secs();

/// The timeouts an [`S3BlobStore`] request runs under, with `first_byte` as
/// the read timeout.
///
/// The SDK defaults give only a connect timeout and stalled-stream protection, so
/// a gateway that accepted the connection and never sent response headers hung
/// the call forever; because a write holds the writer lock across its PUTs, one
/// hung request wedged every write on the machine. The first-byte bound covers
/// that case. The attempt and operation timeouts bound a slow transfer once it
/// has started: generous enough for a legitimate large-blob transfer on a slow
/// link ([`SLOW_LINK_BYTES_PER_SEC`]), but finite. `operation_timeout` bounds
/// the whole call across retries.
fn s3_timeouts(first_byte: Duration) -> aws_sdk_s3::config::timeout::TimeoutConfig {
    aws_sdk_s3::config::timeout::TimeoutConfig::builder()
        .connect_timeout(S3_CONNECT_TIMEOUT)
        .read_timeout(first_byte)
        .operation_attempt_timeout(S3_ATTEMPT_TIMEOUT)
        .operation_timeout(Duration::from_mins(10))
        .build()
}

#[async_trait]
impl BlobStore for S3BlobStore {
    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
        let timeouts = self.put_timeouts(bytes.len());
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(bytes))
            .customize()
            .config_override(timeouts)
            .send()
            .await
            .map_err(storage_error)?;
        Ok(())
    }

    async fn put_if_absent(&self, key: &str, bytes: Vec<u8>) -> Result<CreateOutcome, MemError> {
        let timeouts = self.put_timeouts(bytes.len());
        let result = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .if_none_match("*")
            .body(ByteStream::from(bytes))
            .customize()
            .config_override(timeouts)
            .send()
            .await;

        match result {
            Ok(_) => Ok(CreateOutcome::Created),
            // 412 Precondition Failed is S3's answer to `If-None-Match: *` on an
            // existing key; the SDK does not model it for PutObject, so the
            // status is the signal.
            Err(err) if err.raw_response().map(|raw| raw.status().as_u16()) == Some(412) => {
                Ok(CreateOutcome::AlreadyExists)
            }
            Err(err) => Err(storage_error(err)),
        }
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
        let mut pages = 0_usize;

        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(prefix);
            if let Some(token) = &continuation {
                request = request.continuation_token(token.clone());
            }

            let output = request.send().await.map_err(storage_error)?;
            pages += 1;
            keys.extend(
                output
                    .contents()
                    .iter()
                    .filter_map(Object::key)
                    .map(str::to_owned),
            );

            // Bound the loop against a hostile/buggy gateway — the `list`
            // counterpart of `get`'s `read_capped`. Two independent bounds: keys
            // (memory) and PAGES (requests) — the latter because empty pages with
            // ever-fresh (or alternating, defeating `next_list_token`'s period-1
            // cycle check) continuation tokens never grow `keys`, so the key cap
            // alone cannot terminate the loop.
            check_list_progress(pages, keys.len())?;

            // `ListObjectsV2` returns at most 1000 keys per page in lexicographic
            // order; follow the continuation token until the listing is whole. Key
            // the loop on the token's PRESENCE, not on `is_truncated`: AWS sets the
            // token iff `IsTruncated`, but the custom Hippius gateway (and several
            // S3-compatible impls) can return a `NextContinuationToken` while omitting
            // or misreporting `IsTruncated`. Gating on `is_truncated` there would stop
            // after the first 1000 keys and silently drop the rest of a team's ops or
            // notes with NO error — a partial converged index. `next_list_token` treats
            // an empty token as absent and refuses a repeating (cyclic) token.
            match next_list_token(continuation.as_deref(), output.next_continuation_token())? {
                Some(token) => continuation = Some(token),
                None => break,
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
    async fn put_if_absent_creates_once_and_never_overwrites() {
        let store = MemoryBlobStore::new();
        assert_eq!(
            store.put_if_absent("k", b"first".to_vec()).await.unwrap(),
            CreateOutcome::Created
        );
        assert_eq!(
            store.put_if_absent("k", b"second".to_vec()).await.unwrap(),
            CreateOutcome::AlreadyExists
        );
        assert_eq!(store.get("k").await.unwrap(), b"first");
    }

    #[tokio::test]
    async fn the_probe_reports_enforcement_and_cleans_up() {
        let store = MemoryBlobStore::new();
        assert_eq!(
            probe_create_only(&store, "team").await.unwrap(),
            CreateOnly::Enforced
        );
        assert!(
            store.list("team/").await.unwrap().is_empty(),
            "probe deleted"
        );
    }

    /// A backend that accepts the create-only header and ignores it, like a
    /// gateway without conditional-write support.
    struct IgnoresCondition(MemoryBlobStore);

    #[async_trait]
    impl BlobStore for IgnoresCondition {
        async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
            self.0.put(key, bytes).await
        }

        async fn put_if_absent(
            &self,
            key: &str,
            bytes: Vec<u8>,
        ) -> Result<CreateOutcome, MemError> {
            self.0.put(key, bytes).await?;
            Ok(CreateOutcome::Created)
        }

        async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
            self.0.get(key).await
        }

        async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError> {
            self.0.list(prefix).await
        }

        async fn delete(&self, key: &str) -> Result<(), MemError> {
            self.0.delete(key).await
        }
    }

    #[tokio::test]
    async fn the_probe_detects_a_backend_that_ignores_the_condition() {
        let store = IgnoresCondition(MemoryBlobStore::new());
        assert_eq!(
            probe_create_only(&store, "team").await.unwrap(),
            CreateOnly::NotEnforced
        );
    }

    /// A store that does not forward create-only writes refuses them rather
    /// than writing without the condition.
    #[tokio::test]
    async fn the_default_create_only_write_refuses() {
        struct PlainPutOnly(MemoryBlobStore);

        #[async_trait]
        impl BlobStore for PlainPutOnly {
            async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
                self.0.put(key, bytes).await
            }

            async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
                self.0.get(key).await
            }

            async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError> {
                self.0.list(prefix).await
            }

            async fn delete(&self, key: &str) -> Result<(), MemError> {
                self.0.delete(key).await
            }
        }

        let store = PlainPutOnly(MemoryBlobStore::new());
        assert!(store.put_if_absent("k", b"x".to_vec()).await.is_err());
        assert!(store.list("").await.unwrap().is_empty(), "nothing written");
        assert!(probe_create_only(&store, "team").await.is_err());
    }

    #[tokio::test]
    async fn usable_as_arc_dyn_blob_store() {
        let store: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
        store.put("dyn/key", b"v".to_vec()).await.unwrap();
        assert_eq!(store.get("dyn/key").await.unwrap(), b"v");
    }

    /// A gateway that never answers must fail a request within the first-byte
    /// bound. Regression guard: with no read timeout a hung gateway held each
    /// call for the whole 5-minute attempt timeout.
    #[test]
    fn s3_requests_bound_the_wait_for_the_first_response_byte() {
        let timeouts = s3_timeouts(S3_FIRST_BYTE_TIMEOUT);
        assert_eq!(timeouts.read_timeout(), Some(S3_FIRST_BYTE_TIMEOUT));
        assert_eq!(timeouts.connect_timeout(), Some(S3_CONNECT_TIMEOUT));
        assert_eq!(
            timeouts.operation_attempt_timeout(),
            Some(S3_ATTEMPT_TIMEOUT)
        );
    }

    /// A PUT's first-byte bound grows with its body, so a large upload on a
    /// slow link is not timed out before the gateway could answer; a small one
    /// keeps the client's bound.
    #[test]
    fn a_large_put_gets_time_to_send_its_body() {
        let store = S3BlobStore::new(
            "http://127.0.0.1:1".to_owned(),
            "bucket".to_owned(),
            "id".to_owned(),
            "secret".to_owned(),
            "region".to_owned(),
        );
        let read_timeout = |len| {
            store
                .put_timeouts(len)
                .build()
                .timeout_config()
                .and_then(aws_sdk_s3::config::timeout::TimeoutConfig::read_timeout)
        };
        assert_eq!(read_timeout(0), Some(S3_FIRST_BYTE_TIMEOUT));

        let hundred_mib = 100 * 1024 * 1024;
        let read = read_timeout(hundred_mib).unwrap();
        let upload = Duration::from_secs((hundred_mib as u64).div_ceil(SLOW_LINK_BYTES_PER_SEC));
        assert_eq!(read, S3_FIRST_BYTE_TIMEOUT + upload);
        assert!(
            upload > Duration::from_secs(50) && upload < Duration::from_secs(70),
            "100 MiB at about 1.7 MiB/s is about a minute: {upload:?}"
        );
    }

    /// A gateway that accepts connections and never answers fails a request
    /// within its bound instead of holding it for the attempt timeout.
    ///
    /// Regression test: with no read timeout a hung gateway held each call for
    /// the whole 5-minute attempt timeout. The bound here is 200 ms per attempt,
    /// so three attempts and the retry backoff end well inside the outer
    /// 60 s guard; without the read timeout the guard fires first.
    #[tokio::test]
    async fn a_hung_gateway_fails_a_request_within_its_bound() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            // Accept and hold every connection without answering.
            let mut held = Vec::new();
            for stream in listener.incoming().flatten() {
                held.push(stream);
            }
        });
        let store = S3BlobStore::with_first_byte_timeout(
            format!("http://{address}"),
            "bucket".to_owned(),
            "id".to_owned(),
            "secret".to_owned(),
            "region".to_owned(),
            Duration::from_millis(200),
        );

        let result = tokio::time::timeout(Duration::from_mins(1), store.get("team/key")).await;
        let err = result.unwrap().unwrap_err();
        assert!(matches!(err, MemError::Storage(_)), "got {err:?}");
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

    /// A refused request whose response body is large (here 1 MiB of XML
    /// message) yields an error of a few hundred bytes. The error used to render
    /// the raw response, body included.
    #[tokio::test]
    async fn a_large_error_response_yields_a_short_storage_error() {
        use aws_sdk_s3::primitives::SdkBody;
        use aws_smithy_mocks::{RuleMode, mock, mock_client};

        let message = "x".repeat(1 << 20);
        let body = format!(
            "<?xml version=\"1.0\"?><Error><Code>AccessDenied</Code>\
             <Message>{message}</Message></Error>"
        );
        let rule = mock!(Client::list_objects_v2).then_http_response(move || {
            let mut response =
                HttpResponse::new(403.try_into().unwrap(), SdkBody::from(body.clone()));
            // S3 reads the request id from this header, not from the body.
            response.headers_mut().insert("x-amz-request-id", "req-1");
            response
        });
        let client = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&rule], |b| b
            .force_path_style(true));
        let store = S3BlobStore {
            client,
            bucket: "test-bucket".to_owned(),
            first_byte: S3_FIRST_BYTE_TIMEOUT,
        };

        let err = store.list("team/").await.unwrap_err();
        assert!(matches!(err, MemError::Storage(_)), "{err:?}");
        let rendered = err.to_string();
        assert!(rendered.len() < 400, "{} bytes", rendered.len());
        assert!(rendered.contains("403"), "{rendered}");
        assert!(rendered.contains("AccessDenied"), "{rendered}");
        assert!(rendered.contains("req-1"), "{rendered}");
    }

    #[test]
    fn clamp_chars_cuts_on_a_character_boundary() {
        assert_eq!(clamp_chars("ééé", 2), "éé...");
        assert_eq!(clamp_chars("éé", 2), "éé");
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
            first_byte: S3_FIRST_BYTE_TIMEOUT,
        };

        let err = store.get("team/global/mem_x/ver_1").await.unwrap_err();

        assert!(
            matches!(&err, MemError::NotFound { id } if id == "team/global/mem_x/ver_1"),
            "a modeled NoSuchKey must map to NotFound, got {err:?}"
        );
    }

    #[test]
    fn check_list_progress_bounds_both_pages_and_keys() {
        use super::{MAX_LIST_KEYS, MAX_LIST_PAGES, check_list_progress};
        // Within both bounds -> fine.
        assert!(check_list_progress(1, 1000).is_ok());
        assert!(check_list_progress(MAX_LIST_PAGES, MAX_LIST_KEYS).is_ok());
        // Too many KEYS -> refused (the buffer bound).
        assert!(
            matches!(
                check_list_progress(1, MAX_LIST_KEYS + 1),
                Err(MemError::Storage(_))
            ),
            "exceeding the key cap must refuse the listing"
        );
        // Too many PAGES with few keys -> refused. This is the empty-page /
        // alternating-token livelock: a hostile gateway can keep `keys` at zero
        // while serving fresh tokens forever, so the page bound must terminate
        // the loop on its own.
        assert!(
            matches!(
                check_list_progress(MAX_LIST_PAGES + 1, 0),
                Err(MemError::Storage(_))
            ),
            "exceeding the page cap must refuse the listing even with zero keys"
        );
    }

    #[test]
    fn next_list_token_follows_advances_stops_and_refuses_cycles() {
        use super::next_list_token;
        // First page (no token used) with a fresh token -> follow it.
        assert_eq!(
            next_list_token(None, Some("A")).unwrap(),
            Some("A".to_owned())
        );
        // A different token than the one just used -> follow it.
        assert_eq!(
            next_list_token(Some("A"), Some("B")).unwrap(),
            Some("B".to_owned())
        );
        // No next token -> stop.
        assert_eq!(next_list_token(Some("A"), None).unwrap(), None);
        // An EMPTY next token is aws-sdk's "exhausted" signal -> stop, never re-fetch.
        assert_eq!(next_list_token(Some("A"), Some("")).unwrap(), None);
        // The SAME token returned again is a fixed-point cycle -> refuse (would
        // otherwise loop forever against a hostile/buggy gateway).
        let err = next_list_token(Some("LOOP"), Some("LOOP")).unwrap_err();
        assert!(
            matches!(err, MemError::Storage(_)),
            "a repeating continuation token must error, got {err:?}"
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
            first_byte: S3_FIRST_BYTE_TIMEOUT,
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
            first_byte: S3_FIRST_BYTE_TIMEOUT,
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
        let key = format!("hippius-mem-it/{}", crate::ulid::Ulid::new());
        let payload = b"integration-round-trip".to_vec();

        store.put(&key, payload.clone()).await.unwrap();
        assert_eq!(store.get(&key).await.unwrap(), payload);
        assert!(store.list("hippius-mem-it/").await.unwrap().contains(&key));
    }
}
