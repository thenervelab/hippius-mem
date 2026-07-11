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
use crate::domain::NoteId;
use crate::error::MemError;
use crate::index::IndexRecord;
use crate::store::blob::BlobStore;

/// One live note's [`IndexRecord`] sealed under that note's OWN epoch key.
///
/// The snapshot envelope is sealed under the *current* epoch key so any current
/// member can take the fast restore path, but a member added after a key
/// rotation must not learn the `summary`/`tags` of pre-rotation notes they were
/// never provisioned for. So the confidential record body travels as ciphertext
/// (`sealed`, AAD-bound to `object_key` exactly like the note blob) and only the
/// fields already public in the op-log every member reads — `note_id`,
/// `lamport`, `object_key`, `key_epoch` — travel in the clear. They are what the
/// incremental safety valve compares and how a restorer picks the matching epoch
/// key; they reveal nothing the op-log did not already.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedRecord {
    /// Note this record describes (public: present on the note's op).
    pub note_id: NoteId,
    /// Winning Lamport of the record (public: the op's Lamport).
    pub lamport: u64,
    /// Object key of the winning revision (public: derived in the op-log).
    pub object_key: String,
    /// Epoch key that opens `sealed`; a ring lacking it skips this record.
    pub key_epoch: u64,
    /// The [`IndexRecord`] JSON sealed under the `key_epoch` key, AAD-bound to
    /// `object_key`, so only a holder of that epoch's key can read the body.
    pub sealed: Vec<u8>,
}

/// A converged index checkpoint: every live note's sealed [`IndexRecord`] plus
/// the Lamport tick the checkpoint covers.
///
/// `last_lamport` is the highest Lamport value among the member ops the snapshot
/// reflects; it is both the checkpoint's logical time and the baseline an
/// incremental sync tails from (only ops with a strictly greater Lamport are
/// new). `records` are the converged *live* set (not tombstoned, with a content
/// pointer), each body sealed under its own epoch key so a restore decrypts only
/// the records whose epoch it holds — no blob I/O, no cross-epoch exposure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexSnapshot {
    /// The team whose converged index this snapshot captures.
    pub team: String,
    /// The highest Lamport tick covered: the baseline a tail reads after.
    pub last_lamport: u64,
    /// The converged live records, each sealed under its own epoch key.
    pub records: Vec<SealedRecord>,
}

/// Seal `record`'s body under `epoch_key` (the key for `record.key_epoch`),
/// producing a [`SealedRecord`] whose clear fields are op-log-public and whose
/// ciphertext is AAD-bound to the record's `object_key`.
///
/// # Errors
///
/// [`MemError::Serialize`] if the record cannot be JSON-encoded, or
/// [`MemError::Crypto`] if sealing fails.
pub(crate) fn seal_record(
    record: &IndexRecord,
    epoch_key: &SecretKey,
) -> Result<SealedRecord, MemError> {
    let plaintext = serde_json::to_vec(record)?;
    let sealed = seal(epoch_key, &plaintext, record.object_key.as_bytes())?;
    Ok(SealedRecord {
        note_id: record.note_id,
        lamport: record.lamport,
        object_key: record.object_key.clone(),
        key_epoch: record.key_epoch,
        sealed,
    })
}

/// Open a [`SealedRecord`] with `epoch_key`, returning the decoded [`IndexRecord`].
///
/// The returned record's fields — not the clear envelope copies — are what a
/// restorer indexes, because only they are AEAD-authenticated by `sealed`.
///
/// # Errors
///
/// [`MemError::Crypto`] if `epoch_key` does not match (wrong epoch, tampered, or
/// relocated record), or [`MemError::Serialize`] if the plaintext is not an
/// [`IndexRecord`].
pub(crate) fn open_record(
    record: &SealedRecord,
    epoch_key: &SecretKey,
) -> Result<IndexRecord, MemError> {
    let plaintext = open(epoch_key, &record.sealed, record.object_key.as_bytes())?;
    Ok(serde_json::from_slice(&plaintext)?)
}

/// The object-key prefix under which `team`'s snapshots live.
fn snapshot_prefix(team: &str) -> String {
    format!("{team}/_snapshots/")
}

/// How many most-recent snapshots to retain after a save.
///
/// More than one so [`load_latest_snapshot`] can fall back to an older checkpoint
/// when the newest is corrupt or has vanished; small so the snapshot prefix does
/// not grow unbounded — without pruning it accrues one object per distinct
/// Lamport tip, and every sync lists the whole prefix.
const SNAPSHOT_RETENTION: usize = 3;

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
/// are bound to their key. After a successful write, a best-effort retention
/// sweep prunes all but the newest [`SNAPSHOT_RETENTION`] snapshots so the prefix
/// does not grow unbounded; a prune failure never fails the save.
///
/// # Errors
///
/// [`MemError::Serialize`] if the snapshot cannot be JSON-encoded,
/// [`MemError::Crypto`] if sealing fails, or [`MemError::Storage`] if the
/// backend write fails. (Pruning errors are logged, not returned.)
pub async fn save_snapshot(
    blob: &dyn BlobStore,
    key: &SecretKey,
    snapshot: &IndexSnapshot,
) -> Result<(), MemError> {
    let object_key = snapshot_key(&snapshot.team, snapshot.last_lamport);
    let plaintext = serde_json::to_vec(snapshot)?;
    let sealed = seal(key, &plaintext, object_key.as_bytes())?;
    blob.put(&object_key, sealed).await?;
    prune_old_snapshots(blob, &snapshot.team).await;
    Ok(())
}

/// Delete all but the newest [`SNAPSHOT_RETENTION`] snapshots for `team`.
///
/// Best-effort housekeeping invoked after a successful [`save_snapshot`]. The
/// listing is already ascending-Lamport (the zero-padded keys sort that way), so
/// the prefix of the list is the oldest. A list or delete failure is logged and
/// ignored: the new snapshot is already durable, and a stale older object is
/// harmless (it is superseded — or skipped — on load). `delete` is idempotent, so
/// two writers pruning concurrently never error each other, and the concurrent
/// `NotFound` a prune can cause in [`load_latest_snapshot`] is handled there.
async fn prune_old_snapshots(blob: &dyn BlobStore, team: &str) {
    let prefix = snapshot_prefix(team);
    let keys = match blob.list(&prefix).await {
        Ok(keys) => keys,
        Err(err) => {
            tracing::warn!(team = %team, error = %err, "could not list snapshots to prune; retaining all");
            return;
        }
    };
    // Defense in depth: delete ONLY keys whose shape is exactly a snapshot object
    // (`{prefix}{lamport:020}`). `object_key` already refuses to mint a note under
    // a `_`-prefixed repo, so a foreign object should never share this prefix —
    // but `delete` is irreversible, so the sweep recognizes its own objects rather
    // than trusting the listing to contain only snapshots. Filtering preserves the
    // ascending-Lamport order, so the kept-newest-RETENTION logic is unchanged.
    let snapshots: Vec<&String> = keys
        .iter()
        .filter(|key| is_snapshot_object(&prefix, key))
        .collect();
    // `checked_sub` is `None` (skip) when there are at most RETENTION snapshots.
    let Some(prune_count) = snapshots.len().checked_sub(SNAPSHOT_RETENTION) else {
        return;
    };
    for key in &snapshots[..prune_count] {
        if let Err(err) = blob.delete(key).await {
            tracing::warn!(
                object_key = %key,
                error = %err,
                "could not prune an old snapshot; it will be retried on the next save"
            );
        }
    }
}

/// Whether `key` is exactly a snapshot object under `prefix`: the prefix followed
/// by exactly 20 ASCII digits (the zero-padded Lamport that [`snapshot_key`] mints)
/// and nothing more. The retention sweep deletes, so it must recognize its own
/// objects rather than remove every key a prefix listing returns.
fn is_snapshot_object(prefix: &str, key: &str) -> bool {
    let Some(suffix) = key.strip_prefix(prefix) else {
        return false;
    };
    // 20 is the width of `u64::MAX`; `{:020}` always emits exactly 20 digits for a
    // `u64`, so a longer suffix (e.g. an extra `/`-segment) is not a snapshot.
    suffix.len() == 20 && suffix.bytes().all(|byte| byte.is_ascii_digit())
}

/// Load the highest-Lamport snapshot for `team` that decrypts and parses, or
/// `None` if the prefix holds no usable snapshot.
///
/// Keys are scanned newest-first (highest Lamport, via the zero-padded key
/// order). A blob that fails to decrypt (wrong key / tampered / mismatched AEAD
/// key), fails to deserialize, or has VANISHED (a `get` `NotFound` from a
/// concurrent prune or a list/get inconsistency) is a per-object fault: it is
/// skipped with a `tracing::warn!` and the next-newest is tried, so one corrupt,
/// foreign, or just-pruned object never blinds a machine to an older valid
/// checkpoint (and never forces an error where falling back to a full replay
/// would do).
///
/// # Errors
///
/// [`MemError::Storage`] / [`MemError::NotFound`] from the prefix `list`, or a
/// non-`NotFound` `get` fault (a systemic backend failure). Undecryptable,
/// corrupt, or vanished snapshots are skipped, never returned as errors.
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
        let sealed = match blob.get(object_key).await {
            Ok(sealed) => sealed,
            // The key was just returned by `list`, but a concurrent prune (the
            // retention sweep in `save_snapshot`) or a list/get inconsistency can
            // make this GET miss. Skip to the next-newest rather than abort: an
            // older valid checkpoint — or the full-replay fallback — is the right
            // answer, never a failed sync.
            Err(MemError::NotFound { .. }) => {
                tracing::warn!(
                    object_key = %object_key,
                    "a listed snapshot vanished before fetch (concurrent prune or list/get inconsistency); skipping"
                );
                continue;
            }
            // A genuine connectivity/permission fault is systemic; propagate it.
            Err(err) => return Err(err),
        };
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

    use super::{
        IndexSnapshot, SNAPSHOT_RETENTION, is_snapshot_object, load_latest_snapshot, open_record,
        save_snapshot, seal_record, snapshot_key, snapshot_prefix,
    };
    use crate::crypto::SecretKey;
    use crate::domain::{Blake3Hash, NoteId, NoteType, RepoScope, Scope, Ss58, Timestamp};
    use crate::error::MemError;
    use crate::index::IndexRecord;
    use crate::store::blob::{BlobStore, MemoryBlobStore};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A [`BlobStore`] that returns `NotFound` for `get` on one key — simulates a
    /// snapshot listed but pruned away (or a list/get inconsistency) so a test can
    /// prove `load_latest_snapshot` skips the vanished object instead of aborting.
    struct VanishingGet {
        inner: Arc<MemoryBlobStore>,
        vanish_key: String,
    }

    #[async_trait::async_trait]
    impl BlobStore for VanishingGet {
        async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
            self.inner.put(key, bytes).await
        }
        async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
            if key == self.vanish_key {
                return Err(MemError::NotFound { id: key.to_owned() });
            }
            self.inner.get(key).await
        }
        async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError> {
            self.inner.list(prefix).await
        }
        async fn delete(&self, key: &str) -> Result<(), MemError> {
            self.inner.delete(key).await
        }
    }

    const TEAM: &str = "team";
    const KEY: [u8; 32] = [7_u8; 32];
    const SS58: &str = "5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzV";

    fn record(summary: &str) -> Result<IndexRecord, Box<dyn std::error::Error>> {
        Ok(IndexRecord {
            note_id: NoteId::new(),
            object_key: format!("{TEAM}/repo/mem/ver_1"),
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
            relations: Vec::new(),
        })
    }

    fn snapshot_at(
        last_lamport: u64,
        summary: &str,
    ) -> Result<IndexSnapshot, Box<dyn std::error::Error>> {
        let key = SecretKey::from_bytes(KEY);
        Ok(IndexSnapshot {
            team: TEAM.to_string(),
            last_lamport,
            records: vec![seal_record(&record(summary)?, &key)?],
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
    async fn snapshot_record_body_is_unreadable_without_its_epoch_key() -> TestResult {
        // C1 regression: a record from epoch 0 lives in an envelope sealed under the
        // current epoch (1). A member holding only the epoch-1 key opens the
        // envelope but must NOT recover the epoch-0 record's secret summary — the
        // body stays sealed under the epoch-0 key it lacks.
        let epoch0 = SecretKey::from_bytes([10_u8; 32]);
        let epoch1 = SecretKey::from_bytes([11_u8; 32]);
        let secret = "epoch-0 only secret summary";
        let snapshot = IndexSnapshot {
            team: TEAM.to_string(),
            last_lamport: 9,
            records: vec![seal_record(&record(secret)?, &epoch0)?],
        };

        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        save_snapshot(blob.as_ref(), &epoch1, &snapshot).await?;

        let loaded = load_latest_snapshot(blob.as_ref(), &epoch1, TEAM)
            .await?
            .ok_or("envelope opens under the current epoch key")?;
        let sealed = loaded.records.first().ok_or("one record")?;

        // The only key this member holds cannot open the record body.
        assert!(
            open_record(sealed, &epoch1).is_err(),
            "the epoch-1 key must not open an epoch-0 record"
        );
        // The plaintext summary must appear nowhere in the loaded envelope.
        let envelope = serde_json::to_vec(&loaded)?;
        assert!(
            !envelope
                .windows(secret.len())
                .any(|w| w == secret.as_bytes()),
            "the secret summary must not be present as plaintext in the envelope"
        );
        // The rightful epoch-0 holder still recovers it.
        assert_eq!(open_record(sealed, &epoch0)?.summary, secret);
        Ok(())
    }

    #[tokio::test]
    async fn load_latest_skips_a_vanished_newest_snapshot() -> TestResult {
        // M6 regression: the newest key was just returned by `list`, but a
        // concurrent prune (or a list/get inconsistency) can make its GET return
        // NotFound. That must skip to the next-newest, not abort the whole load.
        let inner = Arc::new(MemoryBlobStore::default());
        let key = SecretKey::from_bytes(KEY);
        save_snapshot(inner.as_ref(), &key, &snapshot_at(10, "older")?).await?;
        save_snapshot(inner.as_ref(), &key, &snapshot_at(50, "newest")?).await?;

        let blob: Arc<dyn BlobStore> = Arc::new(VanishingGet {
            inner: inner.clone(),
            vanish_key: snapshot_key(TEAM, 50),
        });
        let loaded = load_latest_snapshot(blob.as_ref(), &key, TEAM)
            .await?
            .ok_or("the older snapshot must load when the newest has vanished")?;
        assert_eq!(
            loaded.last_lamport, 10,
            "the vanished newest is skipped; the older valid snapshot is returned"
        );
        Ok(())
    }

    #[tokio::test]
    async fn save_snapshot_prunes_to_retention() -> TestResult {
        // M7 regression: snapshots otherwise accumulate one object per Lamport tip
        // and every sync lists the whole prefix. save_snapshot must prune to the
        // newest SNAPSHOT_RETENTION, and the newest must still load.
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let key = SecretKey::from_bytes(KEY);
        for lamport in 1..=(SNAPSHOT_RETENTION as u64 + 2) {
            save_snapshot(blob.as_ref(), &key, &snapshot_at(lamport, "s")?).await?;
        }

        let remaining = blob.list(&format!("{TEAM}/_snapshots/")).await?;
        assert_eq!(
            remaining.len(),
            SNAPSHOT_RETENTION,
            "only the newest SNAPSHOT_RETENTION snapshots are kept, got {remaining:?}"
        );
        let loaded = load_latest_snapshot(blob.as_ref(), &key, TEAM)
            .await?
            .ok_or("the newest snapshot must still load after pruning")?;
        assert_eq!(
            loaded.last_lamport,
            SNAPSHOT_RETENTION as u64 + 2,
            "the newest checkpoint survives the prune"
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

    #[tokio::test]
    async fn prune_spares_a_foreign_object_sharing_the_prefix() -> TestResult {
        // Defense in depth: even if some non-snapshot object lands under the
        // `_snapshots/` prefix, the retention sweep must never delete it — only
        // keys whose shape it recognizes as its own snapshots. A `delete` is
        // irreversible, so an unrecognized shape is spared, not swept.
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let key = SecretKey::from_bytes(KEY);
        let foreign = format!("{TEAM}/_snapshots/not-a-snapshot");
        blob.put(&foreign, b"foreign bytes".to_vec()).await?;
        // Save enough snapshots to trigger a prune of the oldest.
        for lamport in 1..=(SNAPSHOT_RETENTION as u64 + 2) {
            save_snapshot(blob.as_ref(), &key, &snapshot_at(lamport, "s")?).await?;
        }
        assert!(
            blob.get(&foreign).await.is_ok(),
            "a foreign object sharing the snapshot prefix must survive the retention sweep"
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

        /// Every key `snapshot_key` mints is recognized by `is_snapshot_object`,
        /// and a key carrying an extra path segment is not — the round-trip the
        /// retention sweep depends on to delete only its own objects.
        #[test]
        fn snapshot_object_shape_round_trips(lamport in any::<u64>()) {
            let prefix = snapshot_prefix(TEAM);
            prop_assert!(is_snapshot_object(&prefix, &snapshot_key(TEAM, lamport)));
            // A note-shaped key under the same prefix (extra `/`-segments) is not a
            // snapshot and must be spared by the sweep.
            let foreign = format!("{prefix}{lamport:020}/ver_x");
            prop_assert!(!is_snapshot_object(&prefix, &foreign));
        }
    }
}
