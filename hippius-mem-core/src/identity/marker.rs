//! [`ManifestMarker`] — a durable, LOCAL record of the highest team-manifest
//! version this machine has applied, so a cross-restart membership rollback is
//! refused.
//!
//! [`MemoryStore`](crate::MemoryStore)'s in-memory `monotonic_manifest` watermark
//! already refuses a bucket that rolls the team manifest back to an older
//! version — but that watermark dies with the process. On a cold start the store
//! would re-accept the older manifest the untrusted bucket now serves,
//! re-admitting a removed member's ops into convergence. Persisting the applied
//! manifest somewhere the BUCKET cannot reach — a local file — lets the store
//! seed its watermark on boot and refuse the rollback across restarts.
//!
//! The marker is trust-carrying only because the store RE-VERIFIES it (its
//! signature, its `team`, and the pinned founder) before honoring it, exactly as
//! it verifies a bucket manifest — so a tampered local file is rejected, not
//! trusted. This trait is only the storage seam; the verification lives in the
//! store.

use std::io::Write;
use std::path::{Path, PathBuf};

use async_trait::async_trait;

use super::manifest::TeamManifest;
use crate::MemError;
use crate::atomic_file::AtomicFile;

/// A durable, local store for the highest applied [`TeamManifest`].
///
/// Local by definition: the whole point is a record the untrusted bucket cannot
/// roll back, so it never rides [`BlobStore`](crate::BlobStore). The store holds
/// an `Option<Arc<dyn ManifestMarker>>` — `None` keeps the prior in-memory-only
/// watermark (no cross-restart protection), so the seam is opt-in and
/// backward-compatible.
///
/// `#[async_trait]` (not native async-fn-in-trait) because it is used behind
/// `dyn` and its futures must be `Send` for the multithreaded runtime — the same
/// reason [`BlobStore`](crate::BlobStore) uses it (axiom
/// `rust_quality_168_async_fn_in_traits_send_bound`).
#[async_trait]
pub trait ManifestMarker: Send + Sync {
    /// Read the persisted manifest, or `None` if none has been written.
    ///
    /// The returned manifest is UNVERIFIED — the store re-checks its signature,
    /// team, and founder before trusting it, so an implementation need not (and
    /// cannot meaningfully) verify it.
    ///
    /// # Errors
    ///
    /// A backend read/parse failure. A never-written marker is `Ok(None)`, not an
    /// error.
    async fn load(&self) -> Result<Option<TeamManifest>, MemError>;

    /// Durably persist `manifest` as the new high-water mark.
    ///
    /// # Errors
    ///
    /// A backend write failure. Callers treat this as best-effort — a failure
    /// lets rollback protection lag, it does not fail the operation that
    /// triggered the persist.
    async fn store(&self, manifest: &TeamManifest) -> Result<(), MemError>;
}

/// A [`ManifestMarker`] backed by a single local file holding the
/// JSON-serialized [`TeamManifest`].
///
/// Writes are atomic and owner-only: the manifest is written via an
/// [`AtomicFile`] temp (unique random name, `O_EXCL`, mode `0600` on unix) in
/// the target directory, fsynced, then `persist`ed (renamed) over the target — so a reader
/// never sees a half-written file and no symlink or pre-planted temp can widen
/// the mode or redirect the write. The file is tiny and rewritten only when
/// membership advances, so the synchronous I/O here is negligible beside the
/// bucket round-trips the surrounding sync already makes (core has no async-fs
/// dependency).
#[derive(Debug, Clone)]
pub struct FileManifestMarker {
    path: PathBuf,
}

impl FileManifestMarker {
    /// A marker persisted at `path`.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

#[async_trait]
impl ManifestMarker for FileManifestMarker {
    async fn load(&self) -> Result<Option<TeamManifest>, MemError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            // A never-written marker is the normal first-run state, not a fault.
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(MemError::Io(err)),
        }
    }

    async fn store(&self, manifest: &TeamManifest) -> Result<(), MemError> {
        let bytes = serde_json::to_vec(manifest)?;
        // The directory that will hold both the temp and the final marker, so the
        // `persist` rename below is atomic (a cross-filesystem rename degrades to a
        // non-atomic copy). A bare filename (no parent) means the current directory.
        let dir = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        // An `AtomicFile` temp is created with `O_EXCL` + a unique random name and
        // (on unix) mode `0600`, so it cannot follow a symlink, reuse a pre-planted
        // file (which would keep that file's looser mode), or race a concurrent
        // writer on a predictable path — the CWE-59/CWE-377 class a hand-rolled
        // fixed `.tmp` name is exposed to. `persist` then renames it over `path`
        // atomically, so a reader never observes a torn file.
        let mut tmp = AtomicFile::create_in(dir, ".manifest-", ".tmp").map_err(MemError::Io)?;
        tmp.write_all(&bytes).map_err(MemError::Io)?;
        // fsync the bytes before the rename so a crash cannot leave a renamed but
        // empty/partial marker. (The directory entry is not fsynced, so a crash
        // right after the rename may still revert to the prior marker — acceptable
        // for this best-effort watermark, which only lags on that rare window.)
        tmp.as_file().sync_all().map_err(MemError::Io)?;
        tmp.persist(&self.path).map_err(MemError::Io)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test"
    )]

    use std::collections::BTreeSet;

    use super::{FileManifestMarker, ManifestMarker, TeamManifest};
    use crate::NetworkPrefix;
    use crate::oplog::Sr25519Signer;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn sample_manifest(version: u64) -> Result<TeamManifest, Box<dyn std::error::Error>> {
        let signer = Sr25519Signer::from_seed_with_prefix(&[3_u8; 32], NetworkPrefix::HIPPIUS)?;
        Ok(TeamManifest::create_signed(
            &signer,
            "team".to_string(),
            BTreeSet::new(),
            version,
        ))
    }

    #[tokio::test]
    async fn file_marker_round_trips_and_is_owner_only() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("team.manifest.json");
        let marker = FileManifestMarker::new(path.clone());

        // A never-written marker reads back as `None`, not an error.
        assert!(
            marker.load().await?.is_none(),
            "no file yet reads back None"
        );

        let manifest = sample_manifest(7)?;
        marker.store(&manifest).await?;
        assert_eq!(
            marker.load().await?,
            Some(manifest),
            "the persisted manifest round-trips byte-for-byte"
        );

        // Security property: the manifest is membership metadata, so the file must
        // be owner-only (like the minted-credentials file).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)?.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "the marker file must be owner-only (0600)");
        }
        Ok(())
    }

    #[tokio::test]
    async fn file_marker_overwrites_on_a_second_store() -> TestResult {
        // A membership advance rewrites the marker in place (atomic temp+rename), so
        // the latest version is what a later boot reads.
        let dir = tempfile::tempdir()?;
        let marker = FileManifestMarker::new(dir.path().join("team.manifest.json"));
        marker.store(&sample_manifest(1)?).await?;
        marker.store(&sample_manifest(2)?).await?;
        assert_eq!(
            marker.load().await?.map(|m| m.version),
            Some(2),
            "the second store overwrites the first"
        );
        Ok(())
    }
}
