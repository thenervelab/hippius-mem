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

use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};

use crate::atomic_file::write_atomically;
use crate::crypto::SecretKey;
use crate::store::snapshot::{FetchedSnapshot, IndexSnapshot, open_snapshot};

/// Bytes of the big-endian length prefix before the object key in the file.
const KEY_LEN_BYTES: usize = 4;

/// The newest checkpoint this store has seen, in memory and optionally on disk.
pub(crate) struct CheckpointCache {
    memory: Mutex<Option<(String, IndexSnapshot)>>,
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

    /// The cached checkpoint for `object_key`, if either layer holds exactly
    /// that key and (for the disk layer) it opens under `key` for `team`.
    pub(crate) fn get(
        &self,
        object_key: &str,
        key: &SecretKey,
        team: &str,
    ) -> Option<IndexSnapshot> {
        if let Some(snapshot) = self.memory_hit(object_key) {
            return Some(snapshot);
        }
        let snapshot = self.disk_hit(object_key, key, team)?;
        *self.memory.lock().unwrap_or_else(PoisonError::into_inner) =
            Some((object_key.to_owned(), snapshot.clone()));
        Some(snapshot)
    }

    /// Keep `fetched` in both layers. Best-effort on disk: a failed write only
    /// costs the next session its download.
    pub(crate) fn put(&self, fetched: &FetchedSnapshot) {
        *self.memory.lock().unwrap_or_else(PoisonError::into_inner) =
            Some((fetched.object_key.clone(), fetched.snapshot.clone()));

        let Some(file) = &self.file else {
            return;
        };
        let Ok(key_len) = u32::try_from(fetched.object_key.len()) else {
            return;
        };
        let mut bytes =
            Vec::with_capacity(KEY_LEN_BYTES + fetched.object_key.len() + fetched.sealed.len());
        bytes.extend_from_slice(&key_len.to_be_bytes());
        bytes.extend_from_slice(fetched.object_key.as_bytes());
        bytes.extend_from_slice(&fetched.sealed);
        if let Err(err) = write_atomically(file, "checkpoint-", ".tmp", &bytes) {
            tracing::debug!(
                file = %file.display(),
                error = %err,
                "could not cache the index checkpoint locally; the next session downloads it"
            );
        }
    }

    /// Drop both layers, so the next sync fetches the bucket's copy.
    pub(crate) fn forget(&self) {
        *self.memory.lock().unwrap_or_else(PoisonError::into_inner) = None;
        if let Some(file) = &self.file {
            let _ = std::fs::remove_file(file);
        }
    }

    fn memory_hit(&self, object_key: &str) -> Option<IndexSnapshot> {
        let memory = self.memory.lock().unwrap_or_else(PoisonError::into_inner);
        match memory.as_ref() {
            Some((cached_key, snapshot)) if cached_key == object_key => Some(snapshot.clone()),
            Some(_) | None => None,
        }
    }

    fn disk_hit(&self, object_key: &str, key: &SecretKey, team: &str) -> Option<IndexSnapshot> {
        let bytes = std::fs::read(self.file.as_ref()?).ok()?;
        let (len_prefix, rest) = bytes.split_at_checked(KEY_LEN_BYTES)?;
        let key_len = usize::try_from(u32::from_be_bytes(len_prefix.try_into().ok()?)).ok()?;
        let (cached_key, sealed) = rest.split_at_checked(key_len)?;
        if cached_key != object_key.as_bytes() {
            return None;
        }
        open_snapshot(key, team, object_key, sealed)
    }
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

    fn team_key() -> SecretKey {
        SecretKey::from_bytes([9; 32])
    }

    fn fetched(object_key: &str, lamport: u64) -> FetchedSnapshot {
        let snapshot = IndexSnapshot {
            team: TEAM.to_owned(),
            last_lamport: lamport,
            records: Vec::new(),
        };
        let plaintext = serde_json::to_vec(&snapshot).unwrap_or_default();
        let sealed = seal(&team_key(), &plaintext, object_key.as_bytes()).unwrap_or_default();
        FetchedSnapshot {
            object_key: object_key.to_owned(),
            sealed,
            snapshot,
        }
    }

    fn cache_file() -> std::io::Result<(tempfile::TempDir, PathBuf)> {
        let dir = tempfile::tempdir()?;
        let file = dir.path().join("checkpoint");
        Ok((dir, file))
    }

    #[test]
    fn serves_the_same_key_from_memory() {
        let cache = CheckpointCache::new(None);
        cache.put(&fetched(OBJECT_KEY, 7));

        let hit = cache.get(OBJECT_KEY, &team_key(), TEAM);

        assert_eq!(hit.map(|snapshot| snapshot.last_lamport), Some(7));
    }

    #[test]
    fn a_newer_listed_key_is_a_miss() {
        let cache = CheckpointCache::new(None);
        cache.put(&fetched(OBJECT_KEY, 7));

        let newer = "cache-team/_snapshots/00000000000000000008";

        assert!(cache.get(newer, &team_key(), TEAM).is_none());
    }

    #[test]
    fn a_new_process_reads_the_disk_copy() -> TestResult {
        let (_dir, file) = cache_file()?;
        CheckpointCache::new(Some(file.clone())).put(&fetched(OBJECT_KEY, 7));

        let fresh = CheckpointCache::new(Some(file));

        let hit = fresh.get(OBJECT_KEY, &team_key(), TEAM);
        assert_eq!(hit.map(|snapshot| snapshot.last_lamport), Some(7));
        Ok(())
    }

    #[test]
    fn a_disk_copy_under_another_team_key_is_a_miss() -> TestResult {
        let (_dir, file) = cache_file()?;
        CheckpointCache::new(Some(file.clone())).put(&fetched(OBJECT_KEY, 7));

        let fresh = CheckpointCache::new(Some(file));

        assert!(
            fresh
                .get(OBJECT_KEY, &SecretKey::from_bytes([1; 32]), TEAM)
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn a_tampered_disk_copy_is_a_miss() -> TestResult {
        let (_dir, file) = cache_file()?;
        CheckpointCache::new(Some(file.clone())).put(&fetched(OBJECT_KEY, 7));
        let mut bytes = std::fs::read(&file).unwrap_or_default();
        if let Some(last) = bytes.last_mut() {
            *last ^= 0xff;
        }
        std::fs::write(&file, bytes)?;

        let fresh = CheckpointCache::new(Some(file));

        assert!(fresh.get(OBJECT_KEY, &team_key(), TEAM).is_none());
        Ok(())
    }

    #[test]
    fn a_disk_copy_relabelled_to_another_key_is_a_miss() -> TestResult {
        // The sealed bytes are bound to their own object key as AAD, so a file
        // whose key prefix is rewritten to the newest listed key fails to open.
        let (_dir, file) = cache_file()?;
        let newer = "cache-team/_snapshots/00000000000000000008";
        let original = fetched(OBJECT_KEY, 7);
        let relabelled = FetchedSnapshot {
            object_key: newer.to_owned(),
            ..original
        };
        CheckpointCache::new(Some(file.clone())).put(&relabelled);

        let fresh = CheckpointCache::new(Some(file));

        assert!(fresh.get(newer, &team_key(), TEAM).is_none());
        Ok(())
    }

    #[test]
    fn forget_clears_both_layers() -> TestResult {
        let (_dir, file) = cache_file()?;
        let cache = CheckpointCache::new(Some(file.clone()));
        cache.put(&fetched(OBJECT_KEY, 7));

        cache.forget();

        assert!(cache.get(OBJECT_KEY, &team_key(), TEAM).is_none());
        assert!(!file.exists());
        Ok(())
    }
}
