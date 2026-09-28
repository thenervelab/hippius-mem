//! A local cache of the newest index checkpoint, so a sync does not re-download
//! it while the bucket still lists the same one.
//!
//! The checkpoint (`{team}/_snapshots/{lamport}`) is the largest object a sync
//! reads — tens of MiB for a team of a few thousand notes — and `sync` used to
//! GET it on every pass: on a cold start, and again on every re-sync a
//! teammate's write triggers. [`crate::CachingBlobStore`] deliberately never
//! caches it, because the object is mutable. This cache can, for two reasons:
//!
//! - **It is consulted by key, after a fresh LIST.** A cached copy is used only
//!   when its object key is the newest one the bucket currently lists, so a
//!   newer checkpoint is always noticed and fetched.
//! - **A stale copy can cost time, never correctness.** `sync_incremental`
//!   never trusts a checkpoint: it re-converges the current op-log base and
//!   falls back to a full rebuild if any snapshotted note moved. So the one way
//!   a stale copy under the same key could matter is by forcing that fallback
//!   on every sync; the store evicts the cache exactly there
//!   ([`CheckpointCache::forget`]), and the next sync downloads the bucket's
//!   copy.
//!
//! Two layers. The in-memory layer holds the decoded snapshot, so a re-sync in
//! a live session skips decryption and decoding too. The on-disk layer holds
//! the sealed bytes exactly as the bucket served them, so a NEW session skips
//! the download: they are already encrypted under the team key with the object
//! key bound as AAD, and opening them runs the same checks a download does
//! ([`open_snapshot`]), so a swapped, renamed or tampered file is rejected.
//! There is one file per team, overwritten in place, so old checkpoints never
//! accumulate.

//!
//! # Redaction
//!
//! A checkpoint written before a `Redact` still carries that note's sealed
//! record (summary, tags). The bucket's copy is the issuer's concern; a LOCAL
//! copy must not outlive the redaction the way the blob cache's copies do not.
//! So a checkpoint that still holds a redacted note is kept in memory only —
//! never written to disk, and any disk copy is deleted
//! ([`CheckpointCache::drop_disk_copy`]). Evicting it outright instead would
//! re-download it on every sync until a newer checkpoint replaces it.
//!
//! # Blocking I/O
//!
//! The file is tens of MiB and the write is fsynced, so both run on tokio's
//! blocking pool rather than an async worker.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use crate::atomic_file::write_atomically;
use crate::crypto::SecretKey;
use crate::store::snapshot::{FetchedSnapshot, IndexSnapshot, open_snapshot};

/// Bytes of the big-endian length prefix before the object key in the file.
const KEY_LEN_BYTES: usize = 4;

/// Whether [`CheckpointCache::keep`] may write the checkpoint to disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Persist {
    MemoryAndDisk,
    /// It holds a redacted note (see the module docs): memory only, and any disk
    /// copy is removed.
    MemoryOnly,
}

/// The decoded checkpoint held in memory, keyed by what it was opened with.
struct Cached {
    object_key: String,
    /// The epoch whose key opened it. A hit requires the same epoch, so the
    /// memory layer never serves a checkpoint the current key could not open.
    epoch: u64,
    snapshot: Arc<IndexSnapshot>,
}

/// The newest checkpoint this store has seen, in memory and optionally on disk.
pub(crate) struct CheckpointCache {
    memory: Mutex<Option<Cached>>,
    file: Option<PathBuf>,
}

impl CheckpointCache {
    /// A cache persisting to `file` when `Some`; memory-only when `None`.
    pub(crate) fn new(file: Option<PathBuf>) -> Self {
        Self {
            memory: Mutex::new(None),
            file,
        }
    }

    /// The cached checkpoint for `object_key` opened under `epoch`'s `key`, from
    /// memory or else from disk (which then fills memory).
    pub(crate) async fn get(
        &self,
        object_key: &str,
        epoch: u64,
        key: &SecretKey,
        team: &str,
    ) -> Option<Arc<IndexSnapshot>> {
        if let Some(snapshot) = self.memory_hit(object_key, epoch) {
            return Some(snapshot);
        }
        let bytes = self.read_file().await?;
        let (cached_key, sealed) = split_file(&bytes)?;
        if cached_key != object_key.as_bytes() {
            return None;
        }
        let snapshot = Arc::new(open_snapshot(key, team, object_key, sealed)?);
        self.remember(object_key, epoch, &snapshot);
        Some(snapshot)
    }

    /// Keep `fetched` (opened under `epoch`) and return it shared. Best-effort on
    /// disk: a failed write only costs the next session its download.
    pub(crate) async fn keep(
        &self,
        fetched: FetchedSnapshot,
        epoch: u64,
        persist: Persist,
    ) -> Arc<IndexSnapshot> {
        let FetchedSnapshot {
            object_key,
            sealed,
            snapshot,
        } = fetched;
        let snapshot = Arc::new(snapshot);
        self.remember(&object_key, epoch, &snapshot);
        match persist {
            Persist::MemoryAndDisk => self.write_file(&object_key, sealed).await,
            Persist::MemoryOnly => self.drop_disk_copy().await,
        }
        snapshot
    }

    /// Delete the disk copy, keeping memory. See the module docs' "Redaction".
    pub(crate) async fn drop_disk_copy(&self) {
        let Some(file) = self.file.clone() else {
            return;
        };
        let _ = tokio::task::spawn_blocking(move || std::fs::remove_file(file)).await;
    }

    /// Drop both layers, so the next sync fetches the bucket's copy. Sync (a
    /// single unlink) because its caller is a plain branch inside a rebuild.
    pub(crate) fn forget(&self) {
        *self.memory.lock().unwrap_or_else(PoisonError::into_inner) = None;
        if let Some(file) = &self.file {
            let _ = std::fs::remove_file(file);
        }
    }

    fn memory_hit(&self, object_key: &str, epoch: u64) -> Option<Arc<IndexSnapshot>> {
        let memory = self.memory.lock().unwrap_or_else(PoisonError::into_inner);
        match memory.as_ref() {
            Some(cached) if cached.object_key == object_key && cached.epoch == epoch => {
                Some(Arc::clone(&cached.snapshot))
            }
            Some(_) | None => None,
        }
    }

    fn remember(&self, object_key: &str, epoch: u64, snapshot: &Arc<IndexSnapshot>) {
        *self.memory.lock().unwrap_or_else(PoisonError::into_inner) = Some(Cached {
            object_key: object_key.to_owned(),
            epoch,
            snapshot: Arc::clone(snapshot),
        });
    }

    async fn read_file(&self) -> Option<Vec<u8>> {
        let file = self.file.clone()?;
        tokio::task::spawn_blocking(move || std::fs::read(file))
            .await
            .ok()?
            .ok()
    }

    async fn write_file(&self, object_key: &str, sealed: Vec<u8>) {
        let Some(file) = self.file.clone() else {
            return;
        };
        let Ok(key_len) = u32::try_from(object_key.len()) else {
            return;
        };
        let mut bytes = Vec::with_capacity(KEY_LEN_BYTES + object_key.len() + sealed.len());
        bytes.extend_from_slice(&key_len.to_be_bytes());
        bytes.extend_from_slice(object_key.as_bytes());
        bytes.extend_from_slice(&sealed);
        let written = tokio::task::spawn_blocking(move || {
            write_atomically(&file, "checkpoint-", ".tmp", &bytes)
        })
        .await;
        if !matches!(written, Ok(Ok(()))) {
            tracing::debug!(
                "could not cache the index checkpoint locally; the next session downloads it"
            );
        }
    }
}

/// Split a cache file into its object key and sealed bytes, or `None` for a
/// truncated or malformed file.
fn split_file(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len_prefix, rest) = bytes.split_at_checked(KEY_LEN_BYTES)?;
    let key_len = usize::try_from(u32::from_be_bytes(len_prefix.try_into().ok()?)).ok()?;
    rest.split_at_checked(key_len)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes"
    )]

    use super::*;
    use crate::crypto::seal;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const TEAM: &str = "cache-team";
    const OBJECT_KEY: &str = "cache-team/_snapshots/00000000000000000007";
    const NEWER_KEY: &str = "cache-team/_snapshots/00000000000000000008";
    const EPOCH: u64 = 0;

    fn team_key() -> SecretKey {
        SecretKey::from_bytes([9; 32])
    }

    fn fetched(
        object_key: &str,
        lamport: u64,
    ) -> Result<FetchedSnapshot, Box<dyn std::error::Error>> {
        let snapshot = IndexSnapshot {
            team: TEAM.to_owned(),
            last_lamport: lamport,
            records: Vec::new(),
        };
        let plaintext = serde_json::to_vec(&snapshot)?;
        let sealed = seal(&team_key(), &plaintext, object_key.as_bytes())?;
        Ok(FetchedSnapshot {
            object_key: object_key.to_owned(),
            sealed,
            snapshot,
        })
    }

    fn cache_file() -> std::io::Result<(tempfile::TempDir, PathBuf)> {
        let dir = tempfile::tempdir()?;
        let file = dir.path().join("checkpoint");
        Ok((dir, file))
    }

    /// A cache that wrote `OBJECT_KEY` to `file`, dropped so only disk remains.
    async fn written_to(file: &std::path::Path) -> TestResult {
        CheckpointCache::new(Some(file.to_path_buf()))
            .keep(fetched(OBJECT_KEY, 7)?, EPOCH, Persist::MemoryAndDisk)
            .await;
        Ok(())
    }

    async fn lamport_of(cache: &CheckpointCache, object_key: &str, epoch: u64) -> Option<u64> {
        cache
            .get(object_key, epoch, &team_key(), TEAM)
            .await
            .map(|snapshot| snapshot.last_lamport)
    }

    #[tokio::test]
    async fn serves_the_same_key_and_epoch_from_memory() -> TestResult {
        let cache = CheckpointCache::new(None);
        cache
            .keep(fetched(OBJECT_KEY, 7)?, EPOCH, Persist::MemoryAndDisk)
            .await;

        assert_eq!(lamport_of(&cache, OBJECT_KEY, EPOCH).await, Some(7));
        assert_eq!(lamport_of(&cache, NEWER_KEY, EPOCH).await, None);
        assert_eq!(
            lamport_of(&cache, OBJECT_KEY, EPOCH + 1).await,
            None,
            "a checkpoint opened under another epoch's key is not served"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_new_process_reads_the_disk_copy() -> TestResult {
        let (_dir, file) = cache_file()?;
        written_to(&file).await?;

        let fresh = CheckpointCache::new(Some(file));

        assert_eq!(lamport_of(&fresh, OBJECT_KEY, EPOCH).await, Some(7));
        Ok(())
    }

    #[tokio::test]
    async fn a_disk_copy_under_another_team_key_is_a_miss() -> TestResult {
        let (_dir, file) = cache_file()?;
        written_to(&file).await?;

        let fresh = CheckpointCache::new(Some(file));
        let other_key = SecretKey::from_bytes([1; 32]);

        assert!(
            fresh
                .get(OBJECT_KEY, EPOCH, &other_key, TEAM)
                .await
                .is_none()
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_tampered_disk_copy_is_a_miss() -> TestResult {
        let (_dir, file) = cache_file()?;
        written_to(&file).await?;
        let mut bytes = std::fs::read(&file)?;
        if let Some(last) = bytes.last_mut() {
            *last ^= 0xff;
        }
        std::fs::write(&file, bytes)?;

        let fresh = CheckpointCache::new(Some(file));

        assert_eq!(lamport_of(&fresh, OBJECT_KEY, EPOCH).await, None);
        Ok(())
    }

    #[tokio::test]
    async fn truncated_or_mis_prefixed_disk_copies_are_misses() -> TestResult {
        let (_dir, file) = cache_file()?;
        written_to(&file).await?;
        let whole = std::fs::read(&file)?;
        let mut oversized = whole.clone();
        oversized[..KEY_LEN_BYTES].copy_from_slice(&u32::MAX.to_be_bytes());

        for broken in [&whole[..2], &whole[..KEY_LEN_BYTES + 3], &oversized[..]] {
            std::fs::write(&file, broken)?;
            let fresh = CheckpointCache::new(Some(file.clone()));
            assert_eq!(lamport_of(&fresh, OBJECT_KEY, EPOCH).await, None);
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_disk_copy_relabelled_to_another_key_is_a_miss() -> TestResult {
        // The sealed bytes are bound to their own object key as AAD, so a file
        // whose key prefix is rewritten to the newest listed key fails to open.
        let (_dir, file) = cache_file()?;
        let relabelled = FetchedSnapshot {
            object_key: NEWER_KEY.to_owned(),
            ..fetched(OBJECT_KEY, 7)?
        };
        CheckpointCache::new(Some(file.clone()))
            .keep(relabelled, EPOCH, Persist::MemoryAndDisk)
            .await;

        let fresh = CheckpointCache::new(Some(file));

        assert_eq!(lamport_of(&fresh, NEWER_KEY, EPOCH).await, None);
        Ok(())
    }

    #[tokio::test]
    async fn memory_only_keeps_nothing_on_disk_and_removes_an_old_copy() -> TestResult {
        let (_dir, file) = cache_file()?;
        written_to(&file).await?;
        let cache = CheckpointCache::new(Some(file.clone()));

        cache
            .keep(fetched(NEWER_KEY, 8)?, EPOCH, Persist::MemoryOnly)
            .await;

        assert!(
            !file.exists(),
            "a redaction-bearing checkpoint must not stay on disk"
        );
        assert_eq!(lamport_of(&cache, NEWER_KEY, EPOCH).await, Some(8));
        Ok(())
    }

    #[tokio::test]
    async fn forget_clears_both_layers() -> TestResult {
        let (_dir, file) = cache_file()?;
        let cache = CheckpointCache::new(Some(file.clone()));
        cache
            .keep(fetched(OBJECT_KEY, 7)?, EPOCH, Persist::MemoryAndDisk)
            .await;

        cache.forget();

        assert_eq!(lamport_of(&cache, OBJECT_KEY, EPOCH).await, None);
        assert!(!file.exists());
        Ok(())
    }
}
