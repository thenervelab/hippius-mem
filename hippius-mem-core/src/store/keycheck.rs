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
//! note blob keys. A team without the object still works: the first client that
//! can show its key is right (it opens a note sealed under that epoch, or the
//! epoch has no notes yet) publishes it.
//!
//! # Trust
//!
//! The object is not signed. It guards against a misconfigured key, not
//! against a party with bucket write access. A client never accepts a key
//! whose check does not match, so the check never weakens what a client
//! accepts.

use serde::{Deserialize, Serialize};

use crate::crypto::{SecretKey, key_check_value};
use crate::domain::Blake3Hash;
use crate::error::MemError;
use crate::store::BlobStore;

/// Version tag of the check object. An object with another version is read as
/// absent, so a later format never makes this build refuse writes.
const KEY_CHECK_VERSION: u32 = 1;

/// The check object's JSON shape.
#[derive(Debug, Serialize, Deserialize)]
struct KeyCheckFile {
    version: u32,
    team: String,
    epoch: u64,
    check: Blake3Hash,
}

/// The object key of `team`'s check for `epoch`. The epoch is zero-padded to the
/// width of `u64::MAX`, as op keys are, so a listing sorts by epoch.
pub(crate) fn key_check_key(team: &str, epoch: u64) -> String {
    format!("{team}/_keycheck/{epoch:020}")
}

/// The published check value for `team`'s `epoch`, or `None` when there is none
/// this build can read (absent, another version, malformed, or for another
/// team or epoch; the last three are warned).
///
/// # Errors
///
/// [`MemError::Storage`] if the GET fails for any reason other than a missing
/// object.
pub(crate) async fn read_key_check(
    blob: &dyn BlobStore,
    team: &str,
    epoch: u64,
) -> Result<Option<Blake3Hash>, MemError> {
    let key = key_check_key(team, epoch);
    let bytes = match blob.get(&key).await {
        Ok(bytes) => bytes,
        Err(MemError::NotFound { .. }) => return Ok(None),
        Err(err) => return Err(err),
    };

    match serde_json::from_slice::<KeyCheckFile>(&bytes) {
        Ok(file)
            if file.version == KEY_CHECK_VERSION && file.team == team && file.epoch == epoch =>
        {
            Ok(Some(file.check))
        }
        Ok(_) | Err(_) => {
            tracing::warn!(
                object_key = %key,
                "ignoring a team-key check object this build cannot use"
            );
            Ok(None)
        }
    }
}

/// Whether `team_key` matches `team`'s published key check for `epoch`:
/// `Some(true)` or `Some(false)`, or `None` when no usable check is published.
///
/// For callers without a [`MemoryStore`](crate::MemoryStore), such as `doctor`,
/// which has the configured key and the bucket and nothing else. A store checks
/// through [`MemoryStore::check_team_key`](crate::MemoryStore::check_team_key),
/// which also handles a team with no published check.
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
) -> Result<Option<bool>, MemError> {
    let published = read_key_check(blob, team, epoch).await?;
    Ok(published.map(|check| check == key_check_value(team_key, team, epoch)))
}

/// Publish `team_key`'s check value as `team`'s check for `epoch`.
///
/// An unconditional PUT: the store offers no create-if-absent. Two clients with
/// different keys publishing for the same epoch at once leave whichever lands
/// last; the caller publishes only after showing its key opens the epoch's
/// notes, or that the epoch has none, which keeps a wrong key from winning
/// against existing data.
///
/// # Errors
///
/// [`MemError::Serialize`] or [`MemError::Storage`] from encoding or the PUT.
pub(crate) async fn publish_key_check(
    blob: &dyn BlobStore,
    team: &str,
    epoch: u64,
    team_key: &SecretKey,
) -> Result<(), MemError> {
    let bytes = serde_json::to_vec(&KeyCheckFile {
        version: KEY_CHECK_VERSION,
        team: team.to_owned(),
        epoch,
        check: key_check_value(team_key, team, epoch),
    })?;
    blob.put(&key_check_key(team, epoch), bytes).await
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

    #[tokio::test]
    async fn a_published_check_reads_back_as_the_keys_value() -> TestResult {
        let blob = MemoryBlobStore::default();
        let key = SecretKey::from_bytes([3; 32]);

        assert_eq!(read_key_check(&blob, "team", 0).await?, None);
        publish_key_check(&blob, "team", 0, &key).await?;

        assert_eq!(
            read_key_check(&blob, "team", 0).await?,
            Some(key_check_value(&key, "team", 0))
        );
        assert_eq!(read_key_check(&blob, "team", 1).await?, None, "per epoch");
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

    #[tokio::test]
    async fn a_malformed_object_reads_as_absent() -> TestResult {
        let blob = MemoryBlobStore::default();
        blob.put(&key_check_key("team", 0), b"not json".to_vec())
            .await?;

        assert_eq!(read_key_check(&blob, "team", 0).await?, None);
        Ok(())
    }
}
