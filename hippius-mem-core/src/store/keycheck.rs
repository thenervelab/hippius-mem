//! The per-epoch team-key check object, `{team}/_keycheck/{epoch:020}`.
//!
//! Every member's notes are sealed under the team key, and a wrong but
//! well-formed key opens nothing and fails nothing: its reads come back empty and
//! its writes are sealed under the wrong key into the same namespace, visible only
//! to itself. This object carries [`key_check_value`] for one epoch so a client
//! can tell its key is the team's before it writes.
//!
//! # Compatibility
//!
//! A storage-format addition, not a change. Clients before this one never read
//! the `_keycheck/` prefix, and `gc` skips it because the keys do not parse as
//! note blob keys. A team without the object still works, with a warning; the
//! object is written only by a deliberate step that holds the right key by
//! construction or by an operator's choice (see Trust).
//!
//! # Trust
//!
//! Who may publish decides what the check is worth, so no client publishes one
//! on its own judgment. A server at boot only compares: with no check it tries
//! its key on the epoch's oldest notes and reports the result, and never
//! refuses a write or publishes from that result, because which notes count as
//! oldest depends on note ids their writers choose. The check is published by:
//!
//! - `rotate` (and `remove`, which rotates), for the new epoch: the rotating
//!   founder generated that key;
//! - `provision`, run by the founder, for every epoch the founder holds;
//! - `upgrade`, for the trial vault's epochs: the vault had one user, whose key
//!   sealed every note it copies;
//! - `hippius-mem admin keycheck publish`, run by an operator, for a team that
//!   predates the check, or with `--replace` to recover from a wrong one.
//!
//! Every one of them first tries its key on the epoch's oldest notes with the
//! same probe, and publishes nothing when the key fails to open most of them:
//! that key is not the one those notes were sealed under, and its check would
//! refuse their writers. Here the probe only withholds a publish. When most of
//! an epoch's oldest notes were sealed under another key, a right key's publish
//! is refused too; `rotate` gets past it, because a new epoch has no notes to
//! probe. An epoch with no notes, or none that can be tried, is published.
//!
//! Each publish checks for an existing object, writes create-only
//! (`If-None-Match: *`) where the gateway enforces that (see
//! [`crate::probe_create_only`]), and reads the object back, so of two
//! publishers the second learns it lost instead of overwriting the first;
//! `--replace` overwrites on purpose, with a plain PUT. Where the condition is
//! not enforced, or cannot be measured, the write is a plain PUT after the
//! existence check: two publishers at the same moment can then overwrite each
//! other, and the read back catches only the one that finished second.
//!
//! The object is not signed: it guards against a misconfigured key, not against
//! a party with bucket write access. A wrong object makes clients refuse to
//! write until `admin keycheck publish --replace` from a machine with the right
//! key replaces it; no object makes a client accept a key other than the one
//! the check was derived from. An
//! object that exists but cannot be used (bad JSON, another version, team or
//! epoch) is reported and treated as no check, and only `--replace` writes over
//! it.

use serde::{Deserialize, Serialize};

use crate::crypto::{SecretKey, key_check_value};
use crate::domain::Blake3Hash;
use crate::error::MemError;
use crate::store::{BlobStore, CreateOutcome};

/// Version tag of the check object. An object with another version is read as
/// unusable, so a later format never makes this build refuse writes.
const KEY_CHECK_VERSION: u32 = 1;

/// The check object's JSON shape.
#[derive(Debug, Serialize, Deserialize)]
struct KeyCheckFile {
    version: u32,
    team: String,
    epoch: u64,
    check: Blake3Hash,
}

/// What the bucket holds at an epoch's check key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublishedCheck {
    /// No object.
    Absent,
    /// A usable check holding this value.
    Value(Blake3Hash),
    /// An object this build cannot use (warned when read).
    Unusable,
}

/// How a publish treats an object already at the check key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WriteMode {
    /// Create-only: never overwrite.
    CreateOnly,
    /// Overwrite whatever is there.
    Replace,
}

/// The object key of `team`'s check for `epoch`. The epoch is zero-padded to the
/// width of `u64::MAX`, as op keys are, so a listing sorts by epoch.
#[must_use]
pub fn key_check_key(team: &str, epoch: u64) -> String {
    format!("{team}/_keycheck/{epoch:020}")
}

/// The epochs at which an object sits at `team`'s check key, from one LIST.
/// Only keys of exactly the shape [`key_check_key`] writes count; the objects
/// are not read.
///
/// # Errors
///
/// Whatever [`BlobStore::list`] reports.
pub(crate) async fn key_check_epochs(
    blob: &dyn BlobStore,
    team: &str,
) -> Result<Vec<u64>, MemError> {
    let prefix = format!("{team}/_keycheck/");
    Ok(blob
        .list(&prefix)
        .await?
        .iter()
        .filter_map(|key| {
            let epoch = key.strip_prefix(&prefix)?;
            let minted = epoch.len() == 20 && epoch.bytes().all(|byte| byte.is_ascii_digit());
            epoch.parse().ok().filter(|_| minted)
        })
        .collect())
}

/// What is published at `team`'s check key for `epoch`.
///
/// # Errors
///
/// [`MemError::Storage`] if the GET fails for any reason other than a missing
/// object.
pub(crate) async fn read_key_check(
    blob: &dyn BlobStore,
    team: &str,
    epoch: u64,
) -> Result<PublishedCheck, MemError> {
    let key = key_check_key(team, epoch);
    let bytes = match blob.get(&key).await {
        Ok(bytes) => bytes,
        Err(MemError::NotFound { .. }) => return Ok(PublishedCheck::Absent),
        Err(err) => return Err(err),
    };

    match serde_json::from_slice::<KeyCheckFile>(&bytes) {
        Ok(file)
            if file.version == KEY_CHECK_VERSION && file.team == team && file.epoch == epoch =>
        {
            Ok(PublishedCheck::Value(file.check))
        }
        Ok(_) | Err(_) => {
            tracing::warn!(
                object_key = %key,
                "the team-key check object cannot be used by this build (malformed, another \
                 version, or for another team or epoch); writes are not checked against it, and \
                 `hippius-mem admin keycheck publish --replace` from a machine with the right key \
                 replaces it"
            );
            Ok(PublishedCheck::Unusable)
        }
    }
}

/// How a key compares with a team's published key check for one epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCheckMatch {
    /// The published check is this key's.
    Matches,
    /// The published check is another key's.
    Differs,
    /// No usable check is published: none, or an object this build cannot
    /// read.
    Unpublished,
}

/// How `team_key` compares with `team`'s published key check for `epoch`.
///
/// For callers without a [`MemoryStore`](crate::MemoryStore), such as `doctor`,
/// which has the configured key and the bucket and nothing else. A store checks
/// through [`MemoryStore::check_team_key`](crate::MemoryStore::check_team_key).
///
/// # Errors
///
/// [`MemError::Storage`] if the GET fails for any reason other than a missing
/// object.
pub async fn matches_published_key_check(
    blob: &dyn BlobStore,
    team: &str,
    epoch: u64,
    team_key: &SecretKey,
) -> Result<KeyCheckMatch, MemError> {
    Ok(match read_key_check(blob, team, epoch).await? {
        PublishedCheck::Value(check) if check == key_check_value(team_key, team, epoch) => {
            KeyCheckMatch::Matches
        }
        PublishedCheck::Value(_) => KeyCheckMatch::Differs,
        PublishedCheck::Absent | PublishedCheck::Unusable => KeyCheckMatch::Unpublished,
    })
}

/// Write `team_key`'s check as `team`'s check for `epoch`.
///
/// [`WriteMode::CreateOnly`] reports [`CreateOutcome::AlreadyExists`] when an
/// object was there; whether the store enforced that is
/// [`crate::probe_create_only`]'s question. The caller reads the object back to
/// learn whose check is stored.
///
/// # Errors
///
/// [`MemError::Serialize`] or [`MemError::Storage`] from encoding or the PUT.
pub(crate) async fn write_key_check(
    blob: &dyn BlobStore,
    team: &str,
    epoch: u64,
    team_key: &SecretKey,
    mode: WriteMode,
) -> Result<CreateOutcome, MemError> {
    let bytes = serde_json::to_vec(&KeyCheckFile {
        version: KEY_CHECK_VERSION,
        team: team.to_owned(),
        epoch,
        check: key_check_value(team_key, team, epoch),
    })?;
    let key = key_check_key(team, epoch);
    match mode {
        WriteMode::CreateOnly => blob.put_if_absent(&key, bytes).await,
        WriteMode::Replace => {
            blob.put(&key, bytes).await?;
            Ok(CreateOutcome::Created)
        }
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test, not a crash to avoid"
    )]

    use super::*;
    use crate::store::MemoryBlobStore;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Only keys in the shape `key_check_key` writes count as epochs: an
    /// object at `_keycheck/1` is not epoch 1's check.
    #[tokio::test]
    async fn only_check_keys_in_the_written_shape_name_an_epoch() -> TestResult {
        let blob = MemoryBlobStore::default();
        blob.put(&key_check_key("team", 2), b"{}".to_vec()).await?;
        blob.put("team/_keycheck/1", b"{}".to_vec()).await?;
        blob.put("team/_keycheck/+0000000000000000004", b"{}".to_vec())
            .await?;

        assert_eq!(key_check_epochs(&blob, "team").await?, [2]);
        Ok(())
    }

    #[tokio::test]
    async fn a_published_check_reads_back_as_the_keys_value() -> TestResult {
        let blob = MemoryBlobStore::default();
        let key = SecretKey::from_bytes([3; 32]);

        assert_eq!(
            read_key_check(&blob, "team", 0).await?,
            PublishedCheck::Absent
        );
        write_key_check(&blob, "team", 0, &key, WriteMode::CreateOnly).await?;

        assert_eq!(
            read_key_check(&blob, "team", 0).await?,
            PublishedCheck::Value(key_check_value(&key, "team", 0))
        );
        assert_eq!(
            read_key_check(&blob, "team", 1).await?,
            PublishedCheck::Absent,
            "per epoch"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_create_only_write_never_replaces_another_keys_check() -> TestResult {
        let blob = MemoryBlobStore::default();
        let first = SecretKey::from_bytes([3; 32]);
        let second = SecretKey::from_bytes([4; 32]);

        write_key_check(&blob, "team", 0, &first, WriteMode::CreateOnly).await?;
        assert_eq!(
            write_key_check(&blob, "team", 0, &second, WriteMode::CreateOnly).await?,
            CreateOutcome::AlreadyExists
        );
        assert_eq!(
            read_key_check(&blob, "team", 0).await?,
            PublishedCheck::Value(key_check_value(&first, "team", 0))
        );

        write_key_check(&blob, "team", 0, &second, WriteMode::Replace).await?;
        assert_eq!(
            read_key_check(&blob, "team", 0).await?,
            PublishedCheck::Value(key_check_value(&second, "team", 0))
        );
        Ok(())
    }

    #[test]
    fn the_value_differs_per_key_epoch_and_team() {
        let key = SecretKey::from_bytes([3; 32]);
        let other = SecretKey::from_bytes([4; 32]);
        let base = key_check_value(&key, "team", 0);

        assert_ne!(base, key_check_value(&other, "team", 0));
        assert_ne!(base, key_check_value(&key, "team", 1));
        assert_ne!(base, key_check_value(&key, "other", 0));
        assert_ne!(
            base,
            crate::crypto::content_hash(&[3; 32]),
            "not a plain key hash"
        );
    }

    /// A well-formed check written for another team, epoch or version is not
    /// this epoch's check, even at this key.
    #[tokio::test]
    async fn a_check_for_another_team_epoch_or_version_is_unusable() -> TestResult {
        let blob = MemoryBlobStore::default();
        let key = SecretKey::from_bytes([3; 32]);
        let check = key_check_value(&key, "team", 0);
        for (version, team, epoch) in [
            (2, "team", 0),
            (KEY_CHECK_VERSION, "other", 0),
            (KEY_CHECK_VERSION, "team", 1),
        ] {
            let file = KeyCheckFile {
                version,
                team: team.to_owned(),
                epoch,
                check,
            };
            blob.put(&key_check_key("team", 0), serde_json::to_vec(&file)?)
                .await?;
            assert_eq!(
                read_key_check(&blob, "team", 0).await?,
                PublishedCheck::Unusable,
                "version {version}, team {team}, epoch {epoch}"
            );
        }
        Ok(())
    }

    /// A present object this build cannot use is reported as such, not as
    /// absent, so nothing publishes over it without `--replace`.
    #[tokio::test]
    async fn a_malformed_object_reads_as_unusable() -> TestResult {
        let blob = MemoryBlobStore::default();
        blob.put(&key_check_key("team", 0), b"not json".to_vec())
            .await?;

        assert_eq!(
            read_key_check(&blob, "team", 0).await?,
            PublishedCheck::Unusable
        );
        assert_eq!(
            matches_published_key_check(&blob, "team", 0, &SecretKey::from_bytes([3; 32])).await?,
            KeyCheckMatch::Unpublished
        );
        Ok(())
    }
}
