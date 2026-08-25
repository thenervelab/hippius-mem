//! Exclusive, uniquely named temp files that land by atomic rename.
//!
//! First-party replacement for the `tempfile` crate's `NamedTempFile` in the
//! two production write paths that used it: [`FileManifestMarker::store`] here
//! and the binary's `setup::atomic`. Those paths need exactly three things a
//! bare `std::fs::write` cannot give, and all three are plain
//! [`std::fs::OpenOptions`] calls plus OS randomness:
//!
//! 1. the temp is created with `O_EXCL` (`create_new`), so a pre-planted symlink
//!    or file at the temp name is refused rather than followed (CWE-59);
//! 2. the temp name carries 64 random bits, so it cannot be pre-planted in the
//!    first place (CWE-377);
//! 3. the temp is owner-only `0600` from the instant it exists (unix).
//!
//! `tempfile` delivered the same result through `rustix` (plus its `errno` and
//! `getrandom 0.4` tail), a large crate for one `open` call. It stays a
//! dev-dependency for the throwaway `tempdir()` the test suites use.
//!
//! Callers pick the directory, and it must be the TARGET's own directory:
//! `rename` is only atomic within one filesystem (`EXDEV` across two).
//!
//! [`FileManifestMarker::store`]: crate::identity::FileManifestMarker

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Fresh random names to try before giving up on `AlreadyExists`. With 64
/// random bits per name a collision is not a realistic event; the bound only
/// keeps a broken `create_new` from looping forever.
const CREATE_ATTEMPTS: u32 = 16;

/// A temp file that is removed on drop unless [`AtomicFile::persist`] renames it
/// into place first.
#[derive(Debug)]
pub struct AtomicFile {
    file: File,
    path: PathBuf,
    persisted: bool,
}

impl AtomicFile {
    /// Create `{prefix}{16 random hex chars}{suffix}` in `dir`, exclusively and
    /// (on unix) owner-only.
    ///
    /// # Errors
    ///
    /// Any `create_new` failure other than a name collision (which is retried),
    /// or an unavailable OS CSPRNG. The temp never falls back to a predictable
    /// name: no temp is safer than a guessable one.
    pub fn create_in(dir: &Path, prefix: &str, suffix: &str) -> io::Result<Self> {
        for _ in 0..CREATE_ATTEMPTS {
            let path = dir.join(format!("{prefix}{}{suffix}", random_stem()?));
            match open_exclusive(&path) {
                Ok(file) => {
                    return Ok(Self {
                        file,
                        path,
                        persisted: false,
                    });
                }
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
                Err(err) => return Err(err),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "could not create a unique temp file in {} after {CREATE_ATTEMPTS} attempts",
                dir.display()
            ),
        ))
    }

    /// The open temp, for `sync_all` / `set_permissions` before persisting.
    #[must_use]
    pub const fn as_file(&self) -> &File {
        &self.file
    }

    /// Where the temp currently lives.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Rename the temp over `target` as one filesystem operation.
    ///
    /// `rename` replaces the destination NAME: it never follows a symlink
    /// planted at `target`, and a reader sees either the old file or the new
    /// one, never a torn one. Callers that need the bytes on disk before the
    /// rename `sync_all` [`as_file`](Self::as_file) first.
    ///
    /// # Errors
    ///
    /// The `rename` failure; the temp is then removed on drop as usual.
    pub fn persist(mut self, target: &Path) -> io::Result<()> {
        fs::rename(&self.path, target)?;
        self.persisted = true;
        Ok(())
    }
}

impl Write for AtomicFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Drop for AtomicFile {
    fn drop(&mut self) {
        if self.persisted {
            return;
        }
        // Best effort: a stray temp is litter, never a correctness problem.
        if let Err(err) = fs::remove_file(&self.path) {
            tracing::debug!(path = %self.path.display(), %err, "stray temp file not removed");
        }
    }
}

/// 16 lowercase hex chars from 64 bits of OS entropy.
fn random_stem() -> io::Result<String> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes)
        .map_err(|err| io::Error::other(format!("OS CSPRNG unavailable: {err}")))?;
    Ok(crate::hex::encode(bytes))
}

/// `O_CREAT | O_EXCL` (refuses an existing path, symlink included) with mode
/// `0600` at creation, so there is no window in which the file is wider.
#[cfg(unix)]
fn open_exclusive(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// `create_new` alone off unix: mode management is out of scope there, matching
/// the callers.
#[cfg(not(unix))]
fn open_exclusive(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test"
    )]

    use std::io::Write as _;

    use super::{AtomicFile, open_exclusive};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn entries(dir: &std::path::Path) -> Result<Vec<String>, std::io::Error> {
        let mut names: Vec<String> = std::fs::read_dir(dir)?
            .map(|entry| entry.map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect::<Result<_, _>>()?;
        names.sort();
        Ok(names)
    }

    #[test]
    fn create_persist_leaves_only_the_target() -> TestResult {
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("marker.json");

        let mut tmp = AtomicFile::create_in(dir.path(), ".m-", ".tmp")?;
        let temp_name = tmp
            .path()
            .file_name()
            .map(|n| n.to_string_lossy().into_owned());
        assert!(
            temp_name.as_deref().is_some_and(|n| n.starts_with(".m-")
                && std::path::Path::new(n)
                    .extension()
                    .is_some_and(|ext| ext == "tmp")),
            "temp name carries the prefix and suffix: {temp_name:?}"
        );
        tmp.write_all(b"hello")?;
        tmp.as_file().sync_all()?;
        tmp.persist(&target)?;

        assert_eq!(std::fs::read(&target)?, b"hello");
        assert_eq!(entries(dir.path())?, vec!["marker.json".to_owned()]);
        Ok(())
    }

    #[test]
    fn drop_without_persist_removes_the_temp() -> TestResult {
        let dir = tempfile::tempdir()?;
        {
            let mut tmp = AtomicFile::create_in(dir.path(), "t-", "")?;
            tmp.write_all(b"abandoned")?;
            assert_eq!(entries(dir.path())?.len(), 1, "the temp exists while held");
        }
        assert!(
            entries(dir.path())?.is_empty(),
            "the temp is gone once dropped"
        );
        Ok(())
    }

    #[test]
    fn a_failed_persist_still_cleans_up() -> TestResult {
        let dir = tempfile::tempdir()?;
        let tmp = AtomicFile::create_in(dir.path(), "t-", "")?;
        // Renaming onto a path inside a missing directory cannot succeed.
        let missing = dir.path().join("no-such-dir").join("target");
        assert!(
            tmp.persist(&missing).is_err(),
            "rename into a missing dir fails"
        );
        assert!(
            entries(dir.path())?.is_empty(),
            "the temp does not linger after a failed persist"
        );
        Ok(())
    }

    #[test]
    fn two_temps_get_distinct_names() -> TestResult {
        let dir = tempfile::tempdir()?;
        let a = AtomicFile::create_in(dir.path(), "t-", "")?;
        let b = AtomicFile::create_in(dir.path(), "t-", "")?;
        assert_ne!(a.path(), b.path());
        Ok(())
    }

    #[test]
    fn open_exclusive_refuses_an_existing_path() -> TestResult {
        let dir = tempfile::tempdir()?;
        let planted = dir.path().join("planted");
        std::fs::write(&planted, b"x")?;
        let err = open_exclusive(&planted).err();
        assert_eq!(
            err.map(|e| e.kind()),
            Some(std::io::ErrorKind::AlreadyExists),
            "O_EXCL must refuse a pre-existing file rather than open it"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn open_exclusive_refuses_a_planted_symlink() -> TestResult {
        let dir = tempfile::tempdir()?;
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"ORIGINAL")?;
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&victim, &link)?;

        assert!(
            open_exclusive(&link).is_err(),
            "O_EXCL must not follow a symlink"
        );
        assert_eq!(
            std::fs::read(&victim)?,
            b"ORIGINAL",
            "the link target is untouched"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn temp_is_owner_only_from_creation() -> TestResult {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir()?;
        let tmp = AtomicFile::create_in(dir.path(), "t-", "")?;
        let mode = tmp.as_file().metadata()?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn persist_replaces_a_symlink_at_the_target_without_following_it() -> TestResult {
        let dir = tempfile::tempdir()?;
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"ORIGINAL")?;
        let target = dir.path().join("target");
        std::os::unix::fs::symlink(&victim, &target)?;

        let mut tmp = AtomicFile::create_in(dir.path(), "t-", "")?;
        tmp.write_all(b"NEW")?;
        tmp.persist(&target)?;

        assert_eq!(std::fs::read(&victim)?, b"ORIGINAL");
        assert!(!std::fs::symlink_metadata(&target)?.file_type().is_symlink());
        assert_eq!(std::fs::read(&target)?, b"NEW");
        Ok(())
    }
}
