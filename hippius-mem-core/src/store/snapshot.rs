//! Index snapshots: a persisted, encrypted checkpoint of the converged index
//! state at a logical time, so a machine can restore it and tail only the newer
//! ops instead of re-decoding every note blob on every [`crate::store::MemoryStore::sync`].
//!
//! A snapshot stores the already-decoded [`IndexRecord`]s of the live set, not
//! the raw note blobs: restoring is a re-`upsert` of those records (the index
//! re-embeds each `summary`), which skips the blob fetch + AEAD-decrypt + JSON
//! parse that decoding from the op-log pointer would cost. The op-log itself is
//! still read and verified in full on every sync — a hash chain can only be
//! checked from its genesis root — so the snapshot trades *note-blob* read
//! amplification, not op-log read amplification, for cold-start speed.
//!
//! The blob contains team memory summaries, so it is sealed with the team key
//! exactly like a note blob, with the object key as AEAD associated data
//! ([`crate::crypto::seal`]): a snapshot relocated or replayed under a different
//! key fails authentication and is skipped rather than silently restored under
//! the wrong identity.

use serde::{Deserialize, Serialize};

use crate::crypto::{SecretKey, open, seal};
use crate::error::MemError;
use crate::index::IndexRecord;
use crate::store::blob::BlobStore;

/// A converged index checkpoint: every live note's [`IndexRecord`] plus the
/// Lamport tick the checkpoint covers.
///
/// `last_lamport` is the highest Lamport value among the member ops the snapshot
/// reflects; it is both the checkpoint's logical time and the baseline an
/// incremental sync tails from (only ops with a strictly greater Lamport are
/// new). `records` are the converged *live* set (not tombstoned, with a content
/// pointer) already decoded into index form, so a restore re-`upsert`s them with
/// no blob I/O.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexSnapshot {
    /// The team whose converged index this snapshot captures.
    pub team: String,
    /// The highest Lamport tick covered: the baseline a tail reads after.
    pub last_lamport: u64,
    /// The converged live records, ready to re-`upsert` without decoding blobs.
    pub records: Vec<IndexRecord>,
}

/// The object-key prefix under which `team`'s snapshots live.
fn snapshot_prefix(team: &str) -> String {
    format!("{team}/_snapshots/")
}

/// The object key for the snapshot of `team` at `last_lamport`.
///
/// `{team}/_snapshots/{last_lamport:020}`: the Lamport value is zero-padded to
/// 20 digits — the width of `u64::MAX` (18446744073709551615) — so the backend's
/// lexicographic key order matches ascending Lamport order. That is what lets
/// [`load_latest_snapshot`] pick the newest checkpoint by a reverse scan of the
/// listed keys without parsing any of them.
fn snapshot_key(team: &str, last_lamport: u64) -> String {
    format!("{}{last_lamport:020}", snapshot_prefix(team))
}

/// Serialize, seal, and store `snapshot` under its `{team}/_snapshots/{lamport}` key.
///
/// The plaintext is the JSON of the whole [`IndexSnapshot`]; it is sealed with
/// `key` and the object key as AEAD associated data, mirroring how note blobs
/// are bound to their key.
///
/// # Errors
///
/// [`MemError::Serialize`] if the snapshot cannot be JSON-encoded,
/// [`MemError::Crypto`] if sealing fails, or [`MemError::Storage`] if the
/// backend write fails.
pub async fn save_snapshot(
    blob: &dyn BlobStore,
    key: &SecretKey,
    snapshot: &IndexSnapshot,
) -> Result<(), MemError> {
    let object_key = snapshot_key(&snapshot.team, snapshot.last_lamport);
    let plaintext = serde_json::to_vec(snapshot)?;
    let sealed = seal(key, &plaintext, object_key.as_bytes())?;
    blob.put(&object_key, sealed).await
}

/// Load the highest-Lamport snapshot for `team` that decrypts and parses, or
/// `None` if the prefix holds no usable snapshot.
///
/// Keys are scanned newest-first (highest Lamport, via the zero-padded key
/// order). A blob that fails to decrypt (wrong key / tampered / mismatched AEAD
/// key) or to deserialize is a per-object data fault: it is skipped with a
/// `tracing::warn!` and the next-newest is tried, so one corrupt or foreign
/// upload under the prefix never blinds a machine to an older valid checkpoint
/// (and never forces an error where falling back to a full replay would do).
///
/// # Errors
///
/// [`MemError::Storage`] / [`MemError::NotFound`] from the backend `list`/`get`.
/// Undecryptable or corrupt snapshot *contents* are skipped, never returned as
/// errors.
pub async fn load_latest_snapshot(
    blob: &dyn BlobStore,
    key: &SecretKey,
    team: &str,
) -> Result<Option<IndexSnapshot>, MemError> {
    let prefix = snapshot_prefix(team);
    // `list` returns keys in lexicographic order (BlobStore contract); the
    // zero-padded Lamport suffix makes that ascending Lamport order, so the
    // reverse iterator visits newest-first.
    let keys = blob.list(&prefix).await?;
    for object_key in keys.iter().rev() {
        // A backend read failure is systemic (the bucket is broken), so it
        // propagates — distinct from a decrypt/parse failure, which is one bad
        // object and is skipped below.
        let sealed = blob.get(object_key).await?;
        let Ok(plaintext) = open(key, &sealed, object_key.as_bytes()) else {
            tracing::warn!(
                object_key = %object_key,
                "skipping a snapshot that failed to decrypt (wrong key, tampered, or foreign)"
            );
            continue;
        };
        match serde_json::from_slice::<IndexSnapshot>(&plaintext) {
            Ok(snapshot) => return Ok(Some(snapshot)),
            Err(err) => tracing::warn!(
                object_key = %object_key,
                error = %err,
                "skipping a snapshot whose plaintext did not deserialize as an IndexSnapshot"
            ),
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test, not a crash to avoid"
    )]

    use std::collections::BTreeSet;
    use std::sync::Arc;

    use proptest::prelude::*;

    use super::{IndexSnapshot, load_latest_snapshot, save_snapshot, snapshot_key};
    use crate::crypto::SecretKey;
    use crate::domain::{Blake3Hash, NoteId, NoteType, RepoScope, Scope, Ss58, Timestamp};
    use crate::index::IndexRecord;
    use crate::store::blob::{BlobStore, MemoryBlobStore};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const TEAM: &str = "team";
    const KEY: [u8; 32] = [7_u8; 32];
    const SS58: &str = "5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzV";

    fn record(summary: &str) -> Result<IndexRecord, Box<dyn std::error::Error>> {
        Ok(IndexRecord {
            note_id: NoteId::new(),
            object_key: format!("{TEAM}/repo/mem/rev_1"),
            cid: Blake3Hash::new([3_u8; 32]),
            scope: Scope {
                team: TEAM.to_string(),
                repo: RepoScope::Repo("repo".to_string()),
            },
            note_type: NoteType::Gotcha,
            author: Ss58::new(SS58)?,
            updated: Timestamp::new(1_700_000_000_000),
            lamport: 5,
            key_epoch: 0,
            tags: BTreeSet::from(["async".to_string()]),
            summary: summary.to_string(),
        })
    }

    fn snapshot_at(
        last_lamport: u64,
        summary: &str,
    ) -> Result<IndexSnapshot, Box<dyn std::error::Error>> {
        Ok(IndexSnapshot {
            team: TEAM.to_string(),
            last_lamport,
            records: vec![record(summary)?],
        })
    }

    #[tokio::test]
    async fn snapshot_save_load_roundtrip() -> TestResult {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let key = SecretKey::from_bytes(KEY);
        let original = snapshot_at(42, "round trip")?;

        save_snapshot(blob.as_ref(), &key, &original).await?;
        let loaded = load_latest_snapshot(blob.as_ref(), &key, TEAM)
            .await?
            .ok_or("expected a snapshot to load")?;

        assert_eq!(
            loaded, original,
            "the decrypted snapshot equals what was saved"
        );
        Ok(())
    }

    #[tokio::test]
    async fn load_latest_picks_highest_lamport() -> TestResult {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let key = SecretKey::from_bytes(KEY);
        save_snapshot(blob.as_ref(), &key, &snapshot_at(7, "older")?).await?;
        save_snapshot(blob.as_ref(), &key, &snapshot_at(100, "newer")?).await?;
        save_snapshot(blob.as_ref(), &key, &snapshot_at(40, "middle")?).await?;

        let loaded = load_latest_snapshot(blob.as_ref(), &key, TEAM)
            .await?
            .ok_or("expected a snapshot to load")?;

        assert_eq!(
            loaded.last_lamport, 100,
            "the highest-Lamport snapshot wins"
        );
        Ok(())
    }

    #[tokio::test]
    async fn corrupt_snapshot_is_skipped() -> TestResult {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let key = SecretKey::from_bytes(KEY);

        // A valid older snapshot, then a NEWER one sealed under the WRONG key.
        save_snapshot(blob.as_ref(), &key, &snapshot_at(10, "valid")?).await?;
        let wrong_key = SecretKey::from_bytes([9_u8; 32]);
        save_snapshot(
            blob.as_ref(),
            &wrong_key,
            &snapshot_at(99, "undecryptable")?,
        )
        .await?;
        // And outright garbage at an even higher key.
        blob.put(&snapshot_key(TEAM, 200), b"not a sealed snapshot".to_vec())
            .await?;

        let loaded = load_latest_snapshot(blob.as_ref(), &key, TEAM)
            .await?
            .ok_or("expected the valid older snapshot to load")?;

        assert_eq!(
            loaded.last_lamport, 10,
            "the undecryptable and garbage snapshots are skipped; the valid one is returned"
        );
        Ok(())
    }

    #[tokio::test]
    async fn no_snapshot_returns_none() -> TestResult {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let key = SecretKey::from_bytes(KEY);
        assert!(
            load_latest_snapshot(blob.as_ref(), &key, TEAM)
                .await?
                .is_none(),
            "an empty prefix yields no snapshot, not an error"
        );
        Ok(())
    }

    proptest! {
        /// The zero-padded snapshot key preserves Lamport order under the
        /// backend's lexicographic key ordering — the invariant
        /// `load_latest_snapshot`'s reverse scan relies on to pick the newest.
        #[test]
        fn snapshot_key_order_matches_lamport_order(a in any::<u64>(), b in any::<u64>()) {
            let key_a = snapshot_key(TEAM, a);
            let key_b = snapshot_key(TEAM, b);
            prop_assert_eq!(a.cmp(&b), key_a.cmp(&key_b));
        }
    }
}
