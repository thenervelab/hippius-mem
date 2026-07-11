//! A local, encrypted read-through cache for immutable blob objects.
//!
//! Wraps any [`BlobStore`] and keeps a copy of every *immutable* object it fetches
//! (or writes) on local disk, so a later `get` of the same key is served from disk
//! rather than a remote round-trip. On the Hippius gateway a `get` costs hundreds
//! of milliseconds, and a cold sync `get`s the whole op-log and (on a full replay)
//! every note blob — so a relaunched process, the dashboard's usual pattern, pays
//! that latency again for data that never changed. This cache turns the second and
//! later launches into local-disk reads for everything already seen.
//!
//! # What is cached — and why only that
//!
//! Only **write-once, content-addressed** objects: op-log entries
//! (`{team}/_oplog/...`) and note version blobs (`{team}/{repo}/{mem_id}/ver_...`).
//! Both are keyed so a given key's bytes never change. Mutable objects — snapshots,
//! anchor records, manifests, markers — pass straight through and are never cached:
//! serving a stale one would be a correctness bug. [`is_cacheable`] is the single
//! gate, and it answers `false` when in doubt.
//!
//! # Encrypted at rest
//!
//! Every cache file is sealed with XChaCha20-Poly1305 under a key derived from the
//! team key ([`crate::derive_cache_key`]), the object key bound as AAD. So even op
//! metadata (cleartext in the bucket by design) is ciphertext on local disk, a
//! relocated or swapped cache file fails authentication, and the cache is
//! meaningless without the team key. A cache entry that fails to open (corruption,
//! a stale key, a foreign file) is discarded and the object is re-fetched — the
//! cache is a pure optimization, never a source of truth.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;

use crate::{BlobStore, MemError, SecretKey, open, seal};

/// Monotonic suffix for temp files, so two in-flight writes never share a temp
/// path and clobber each other mid-write.
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// A [`BlobStore`] decorator that caches immutable objects on local disk,
/// encrypted at rest.
///
/// Cheap to share behind an `Arc`; holds the wrapped store, the cache directory,
/// and the cache key. See the module docs for what it caches and the encryption.
pub struct CachingBlobStore {
    /// The wrapped store — the source of truth; the cache only ever mirrors it.
    inner: Arc<dyn BlobStore>,
    /// Directory holding one sealed file per cached object.
    dir: PathBuf,
    /// Key sealing every cache file (derived from the team key, never the team key
    /// itself — see [`crate::derive_cache_key`]).
    key: SecretKey,
}

impl std::fmt::Debug for CachingBlobStore {
    // `dyn BlobStore` is not `Debug` and `key` must never render; name the type and
    // the directory only.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachingBlobStore")
            .field("dir", &self.dir)
            .finish_non_exhaustive()
    }
}

impl CachingBlobStore {
    /// Wrap `inner`, caching immutable objects under `dir`, sealed with `key`.
    ///
    /// Creates `dir` best-effort; if that fails, every cache write simply no-ops and
    /// reads fall through to `inner`, so the store still works — just without the
    /// cache. `key` must be a cache-specific key (see [`crate::derive_cache_key`]),
    /// not the team key directly.
    #[must_use]
    pub fn new(inner: Arc<dyn BlobStore>, dir: PathBuf, key: SecretKey) -> Self {
        // Best-effort: a missing directory only disables caching, never the store.
        let _ = std::fs::create_dir_all(&dir);
        // Sweep temp files stranded by a crash between `write_cache`'s write and
        // its rename — nothing else ever reclaims them, so they would accumulate
        // forever in a long-lived per-team cache dir. The `.tmp` filter cannot
        // touch real cache entries (extension-less BLAKE3-hex names). Racing a
        // concurrently live process costs at most that one write's cache
        // population, never correctness — the value was already returned from
        // `inner`. Best-effort like everything else here.
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "tmp") {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
        Self { inner, dir, key }
    }

    /// Absolute path of the cache file for `object_key`.
    ///
    /// The object key is BLAKE3-hashed to a flat hex filename: object keys contain
    /// `/` (they are S3 paths) and vary in length, so hashing sidesteps directory
    /// nesting and path-length limits while staying collision-free in practice.
    fn cache_path(&self, object_key: &str) -> PathBuf {
        self.dir
            .join(blake3::hash(object_key.as_bytes()).to_hex().as_str())
    }

    /// Return the cached plaintext for `key`, or `None` on a miss.
    ///
    /// A file that exists but fails to open — corruption, a stale key after a team
    /// rotation, or a foreign file — is deleted and treated as a miss, so a bad
    /// cache entry can never poison a read.
    ///
    /// Deliberately BLOCKING `std::fs` inside the async callers (`get`/`put`):
    /// cache entries are small sealed blobs (an op envelope or one note version)
    /// on a local disk, where a read is microseconds against the
    /// hundreds-of-milliseconds gateway round-trip this cache exists to avoid —
    /// far below the runtime's blocking budget even at `read_verified`'s 64-way
    /// fetch fan-out. `tokio::fs` would pay a spawn-blocking hop per call for no
    /// measured win; revisit only with a profile showing executor stalls (e.g. a
    /// cache dir on a network filesystem). Applies to `write_cache` equally.
    fn read_cache(&self, key: &str) -> Option<Vec<u8>> {
        let path = self.cache_path(key);
        let sealed = std::fs::read(&path).ok()?;
        if let Ok(plaintext) = open(&self.key, &sealed, key.as_bytes()) {
            Some(plaintext)
        } else {
            // Corrupt, stale-key, or foreign entry: drop it and report a miss so the
            // caller re-fetches from the source of truth.
            let _ = std::fs::remove_file(&path);
            None
        }
    }

    /// Seal `bytes` for `key` and write them to the cache, best-effort.
    ///
    /// Writes to a unique temp file and renames into place, so a crash or a
    /// concurrent writer never leaves a half-written cache file a later read could
    /// mistake for valid ciphertext (the rename is atomic on one filesystem). Any
    /// failure is swallowed: the cache is an optimization, and the value was already
    /// returned to the caller from `inner`.
    fn write_cache(&self, key: &str, bytes: &[u8]) {
        let Ok(sealed) = seal(&self.key, bytes, key.as_bytes()) else {
            return;
        };
        let path = self.cache_path(key);
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = self.dir.join(format!("{}.{seq}.tmp", std::process::id()));
        if std::fs::write(&tmp, &sealed).is_ok() && std::fs::rename(&tmp, &path).is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
    }
}

/// Whether `key` names a write-once, content-addressed object safe to cache.
///
/// True for op-log entries (`{team}/_oplog/...`) and note version blobs
/// (`{team}/{repo}/{mem_id}/ver_...`); false for everything else, notably the
/// mutable `{team}/_snapshots/...` and `{team}/_anchors/...` records and any
/// manifest/marker. The reserved-prefix guard on the four-segment arm keeps a
/// mutable key that happens to have four segments out of the cache.
fn is_cacheable(key: &str) -> bool {
    let parts: Vec<&str> = key.split('/').collect();
    match parts.as_slice() {
        [_team, "_oplog", ..] => true,
        [_team, repo, _mem, _ver] => !repo.starts_with('_'),
        _ => false,
    }
}

#[async_trait]
impl BlobStore for CachingBlobStore {
    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
        // Write-through: the bucket is the source of truth, so it must land first.
        self.inner.put(key, bytes.clone()).await?;
        // Populate the cache with our own write so this machine never re-fetches an
        // object it just created (safe: cacheable keys are write-once).
        if is_cacheable(key) {
            self.write_cache(key, &bytes);
        }
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
        if !is_cacheable(key) {
            return self.inner.get(key).await;
        }
        if let Some(bytes) = self.read_cache(key) {
            return Ok(bytes);
        }
        let bytes = self.inner.get(key).await?;
        self.write_cache(key, &bytes);
        Ok(bytes)
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError> {
        // Listings are never cached: the set of keys under a prefix grows as
        // teammates write, and a stale listing would hide new work.
        self.inner.list(prefix).await
    }

    async fn delete(&self, key: &str) -> Result<(), MemError> {
        // Evict the local copy BEFORE the backend delete, and unconditionally: a
        // redacted/removed object's sealed body — decryptable by any team-key
        // holder — must not survive on local disk. Ordering the eviction first
        // closes the crash window where a process dying between the backend delete
        // and the eviction would leave the ciphertext readable from cache after
        // the bucket copy is already gone; making it independent of the backend
        // outcome keeps the body from lingering even when the remote delete fails
        // (a read-only member, a transient fault).
        if is_cacheable(key) {
            let _ = std::fs::remove_file(self.cache_path(key));
        }
        self.inner.delete(key).await
    }

    async fn evict_cache(&self, key: &str) {
        // Local-only sibling of `delete`: reclaim the sealed body from disk with no
        // backend round-trip, so a redact-purge can run on every sync without
        // spamming the backend. Idempotent — `remove_file` on an absent path (a key
        // never cached, or already evicted) is ignored.
        if is_cacheable(key) {
            let _ = std::fs::remove_file(self.cache_path(key));
        }
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "tests assert success/failure of Result-returning steps"
    )]

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::{CachingBlobStore, is_cacheable};
    use crate::{BlobStore, MemError, MemoryBlobStore, SecretKey};

    const OP_KEY: &str = "team/_oplog/00000000000000000001_abc_def";
    const NOTE_KEY: &str = "team/repo/01ARZ3NDEKTSV4RRFFQ69G5FAV/ver_01ARZ3";
    const SNAP_KEY: &str = "team/_snapshots/00000000000000000042";

    /// A [`BlobStore`] wrapper counting `get` calls, so a test can prove a read was
    /// served from cache (no inner `get`) versus fetched (an inner `get`).
    struct CountingBlob {
        inner: MemoryBlobStore,
        gets: AtomicUsize,
    }

    impl CountingBlob {
        fn new() -> Self {
            Self {
                inner: MemoryBlobStore::default(),
                gets: AtomicUsize::new(0),
            }
        }
        fn gets(&self) -> usize {
            self.gets.load(Ordering::Relaxed)
        }
    }

    #[async_trait::async_trait]
    impl BlobStore for CountingBlob {
        async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
            self.inner.put(key, bytes).await
        }
        async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
            self.gets.fetch_add(1, Ordering::Relaxed);
            self.inner.get(key).await
        }
        async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError> {
            self.inner.list(prefix).await
        }
        async fn delete(&self, key: &str) -> Result<(), MemError> {
            self.inner.delete(key).await
        }
    }

    /// A cache over a fresh counting inner, in a throwaway temp directory.
    fn setup() -> (Arc<CountingBlob>, CachingBlobStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("temp dir");
        let inner = Arc::new(CountingBlob::new());
        let cache = CachingBlobStore::new(
            inner.clone() as Arc<dyn BlobStore>,
            dir.path().to_path_buf(),
            SecretKey::from_bytes([7u8; 32]),
        );
        (inner, cache, dir)
    }

    #[test]
    fn classifies_only_immutable_keys() {
        assert!(is_cacheable(OP_KEY), "op-log entry is immutable");
        assert!(is_cacheable(NOTE_KEY), "note version blob is immutable");
        assert!(!is_cacheable(SNAP_KEY), "snapshots are rewritten");
        assert!(
            !is_cacheable("team/_anchors/0001"),
            "anchors are not cached"
        );
        assert!(!is_cacheable("team/_manifest"), "manifest is mutable");
        assert!(!is_cacheable("team"), "a bare prefix is not cacheable");
    }

    #[tokio::test]
    async fn second_get_of_immutable_key_is_served_from_cache() {
        let (inner, cache, _dir) = setup();
        cache.put(OP_KEY, b"an op".to_vec()).await.expect("put");

        // put() populated the cache, so the first get needs no inner fetch.
        assert_eq!(cache.get(OP_KEY).await.expect("get"), b"an op");
        assert_eq!(inner.gets(), 0, "served from the cache put() wrote");

        // A fresh cache (cold disk) over the same inner must fetch once, then serve
        // the second get from disk.
        let dir2 = tempfile::tempdir().expect("dir");
        let cache2 = CachingBlobStore::new(
            inner.clone() as Arc<dyn BlobStore>,
            dir2.path().to_path_buf(),
            SecretKey::from_bytes([7u8; 32]),
        );
        assert_eq!(cache2.get(OP_KEY).await.expect("get"), b"an op");
        assert_eq!(cache2.get(OP_KEY).await.expect("get"), b"an op");
        assert_eq!(inner.gets(), 1, "one fetch, then cache");
    }

    #[tokio::test]
    async fn construction_sweeps_stranded_temp_files_but_not_cache_entries() {
        // A crash between write_cache's write and its rename strands a
        // `{pid}.{seq}.tmp`; nothing else reclaims it, so construction must —
        // without touching real (extension-less, hex-named) cache entries.
        let dir = tempfile::tempdir().expect("temp dir");
        let stranded = dir.path().join("12345.7.tmp");
        std::fs::write(&stranded, b"half-written seal").expect("strand a tmp");

        let inner = Arc::new(CountingBlob::new());
        let cache = CachingBlobStore::new(
            inner.clone() as Arc<dyn BlobStore>,
            dir.path().to_path_buf(),
            SecretKey::from_bytes([7u8; 32]),
        );
        assert!(!stranded.exists(), "the stranded temp file is swept");

        // A real cache entry written after construction survives a SECOND
        // construction over the same dir (only .tmp files are swept).
        cache.put(OP_KEY, b"an op".to_vec()).await.expect("put");
        let entry = cache.cache_path(OP_KEY);
        assert!(entry.exists(), "cached after put");
        let _cache2 = CachingBlobStore::new(
            inner as Arc<dyn BlobStore>,
            dir.path().to_path_buf(),
            SecretKey::from_bytes([7u8; 32]),
        );
        assert!(entry.exists(), "sealed cache entries are never swept");
    }

    #[tokio::test]
    async fn mutable_keys_are_never_cached() {
        let (inner, cache, _dir) = setup();
        cache.put(SNAP_KEY, b"snap".to_vec()).await.expect("put");
        cache.get(SNAP_KEY).await.expect("get");
        cache.get(SNAP_KEY).await.expect("get");
        assert_eq!(inner.gets(), 2, "every get of a mutable key fetches");
    }

    #[tokio::test]
    async fn cache_file_is_ciphertext_at_rest() {
        let (_inner, cache, dir) = setup();
        let secret = b"top secret note body";
        cache.put(NOTE_KEY, secret.to_vec()).await.expect("put");

        let files: Vec<_> = std::fs::read_dir(dir.path())
            .expect("readdir")
            .filter_map(std::result::Result::ok)
            .filter(|e| e.path().extension().is_none_or(|ext| ext != "tmp"))
            .collect();
        assert_eq!(files.len(), 1, "one cache file written");
        let on_disk = std::fs::read(files[0].path()).expect("read cache file");
        assert!(
            !on_disk.windows(secret.len()).any(|w| w == secret),
            "the plaintext must not appear on disk"
        );
        assert!(on_disk.len() > secret.len(), "sealed: nonce + tag overhead");
    }

    #[tokio::test]
    async fn corrupt_cache_entry_is_discarded_and_refetched() {
        let (inner, cache, dir) = setup();
        cache.put(OP_KEY, b"an op".to_vec()).await.expect("put");
        cache.get(OP_KEY).await.expect("get"); // 0 inner gets so far

        // Corrupt the single cache file.
        for entry in std::fs::read_dir(dir.path()).expect("readdir") {
            let p = entry.expect("entry").path();
            std::fs::write(&p, b"garbage not ciphertext").expect("clobber");
        }
        // The corrupt entry fails to open, so the value is refetched (and re-cached).
        assert_eq!(cache.get(OP_KEY).await.expect("get"), b"an op");
        assert_eq!(inner.gets(), 1, "one refetch after corruption");
        assert_eq!(cache.get(OP_KEY).await.expect("get"), b"an op");
        assert_eq!(inner.gets(), 1, "re-cached, so no further fetch");
    }

    #[tokio::test]
    async fn delete_evicts_the_cache_entry() {
        let (_inner, cache, _dir) = setup();
        cache.put(OP_KEY, b"an op".to_vec()).await.expect("put");
        cache.get(OP_KEY).await.expect("get"); // cached, 0 inner gets

        cache.delete(OP_KEY).await.expect("delete");
        // After eviction the object is gone from inner too, so a get misses.
        assert!(
            matches!(cache.get(OP_KEY).await, Err(MemError::NotFound { .. })),
            "deleted object is neither cached nor in the store"
        );
    }

    #[tokio::test]
    async fn delete_evicts_the_cache_even_when_the_backend_delete_fails() {
        // A read-only member (or a transient fault) can make the backend delete
        // fail, but a redacted note's sealed body must still leave the local cache:
        // eviction is unconditional and happens before the backend call.
        struct FailingDeleteBlob(MemoryBlobStore);
        #[async_trait::async_trait]
        impl BlobStore for FailingDeleteBlob {
            async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
                self.0.put(key, bytes).await
            }
            async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
                self.0.get(key).await
            }
            async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError> {
                self.0.list(prefix).await
            }
            async fn delete(&self, _key: &str) -> Result<(), MemError> {
                Err(MemError::Storage("delete refused (injected)".to_owned()))
            }
        }

        let dir = tempfile::tempdir().expect("temp dir");
        let cache = CachingBlobStore::new(
            Arc::new(FailingDeleteBlob(MemoryBlobStore::default())) as Arc<dyn BlobStore>,
            dir.path().to_path_buf(),
            SecretKey::from_bytes([7u8; 32]),
        );
        cache.put(OP_KEY, b"an op".to_vec()).await.expect("put");
        assert!(cache.cache_path(OP_KEY).exists(), "cached after put");

        // The backend delete fails, but the cache file is gone regardless.
        assert!(
            cache.delete(OP_KEY).await.is_err(),
            "the backend delete failure propagates"
        );
        assert!(
            !cache.cache_path(OP_KEY).exists(),
            "the cache entry is evicted even though the backend delete failed"
        );
    }

    #[tokio::test]
    async fn a_cache_file_cannot_be_opened_under_a_different_key() {
        // AAD binding: the object key is authenticated, so a file cached for one key
        // cannot be served for another even if an attacker swaps files on disk.
        let (_inner, cache, _dir) = setup();
        cache.put(OP_KEY, b"an op".to_vec()).await.expect("put");
        let other = "team/_oplog/99999999999999999999_zzz_www";
        // Copy the first key's cache file to the second key's filename.
        std::fs::copy(cache.cache_path(OP_KEY), cache.cache_path(other)).expect("copy");
        // Opening the swapped file under `other`'s AAD must fail, so read_cache
        // discards it and the get misses (the object is not in inner).
        assert!(
            matches!(cache.get(other).await, Err(MemError::NotFound { .. })),
            "a file bound to a different object key must not be served"
        );
    }
}
