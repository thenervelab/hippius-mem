//! Atomic, symlink-safe writes for the provisioning config files.
//!
//! The `init`/self-heal paths rewrite files whose parent directory an
//! unprivileged co-resident process may control (`CLAUDE.md`, `AGENTS.md`,
//! `.claude/settings.json`, `.gitignore`). A bare `std::fs::write(path, ...)`
//! there is a TOCTOU/symlink hazard (CWE-59/CWE-377): it FOLLOWS a symlink
//! planted at `path` and truncates whatever the link points at, so an attacker
//! can redirect the operator's write onto another operator-writable file.
//!
//! [`atomic_write`] closes that hole with the same discipline
//! `hippius-mem-core`'s `FileManifestMarker::store` already uses: write to an
//! `O_EXCL`, uniquely-named temp in the target's OWN directory, then `rename` it
//! over the target. `rename` replaces the destination NAME as a single filesystem
//! operation and never follows a symlink at that name, and the `O_EXCL` temp
//! cannot itself follow a pre-planted symlink.

use std::io::Write;
use std::path::Path;

use anyhow::Context;

/// Atomically write `bytes` to `path`, replacing any existing file.
///
/// The write is not observable in a torn state (a reader sees either the old file
/// or the whole new one) and cannot be redirected through a symlink planted at
/// `path` — see the module docs. The resulting file's mode is the existing
/// target's mode when it already exists, or `0644` for a fresh file: these are
/// ordinary repo files, so the write must NOT tighten them to `tempfile`'s `0600`
/// default (which would make e.g. a committed `CLAUDE.md` unreadable to other
/// users of a shared checkout — a regression this write is careful to avoid).
///
/// # Errors
///
/// Returns an error if the temp file cannot be created in `path`'s directory or
/// written, or if the atomic rename over `path` fails.
pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    // The temp MUST share the target's filesystem for `rename` to be atomic (a
    // cross-device rename fails with `EXDEV`), so it goes in the target's own
    // directory. A bare filename (no parent) means the current directory.
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::Builder::new()
        .prefix(".hippius-tmp-")
        .tempfile_in(dir)
        .with_context(|| format!("creating a temp file in {} failed", dir.display()))?;
    tmp.write_all(bytes)
        .with_context(|| format!("writing the temp file for {} failed", path.display()))?;
    restore_target_mode(tmp.as_file(), path)?;
    // `persist` renames the temp over `path`. `path` itself is only ever named by
    // this rename, so a crash mid-write leaves the disposable temp, never a torn
    // `path`; and rename replaces a symlink at `path` rather than following it.
    tmp.persist(path)
        .map_err(|e| e.error)
        .with_context(|| format!("replacing {} via atomic rename failed", path.display()))?;
    Ok(())
}

/// Set the temp file's mode to the existing target's mode, or `0644` when the
/// target does not yet exist.
///
/// `tempfile` creates the temp `0600`; without this a first write of a normal
/// repo file would silently become owner-only, and an overwrite would drop the
/// file's prior mode. `metadata` follows a symlink at `target` — harmless, since
/// we only read a mode and then `rename` over the link name, never write through
/// it — and a missing/broken target falls back to `0644`.
#[cfg(unix)]
fn restore_target_mode(tmp: &std::fs::File, target: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(target).map_or(0o644, |m| m.permissions().mode() & 0o777);
    tmp.set_permissions(std::fs::Permissions::from_mode(mode))
        .with_context(|| {
            format!(
                "setting mode {mode:o} on the temp file for {} failed",
                target.display()
            )
        })
}

/// No mode management off unix: Windows provisioning is out of scope, matching
/// [`super::hooks`]'s `set_executable`.
#[cfg(not(unix))]
fn restore_target_mode(_tmp: &std::fs::File, _target: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "tests assert success of Result-returning filesystem steps"
    )]

    use std::path::Path;

    use tempfile::TempDir;

    use super::atomic_write;

    #[test]
    fn round_trips_and_leaves_no_stray_temp() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("CLAUDE.md");
        atomic_write(&path, b"hello\n").expect("write");
        assert_eq!(std::fs::read(&path).expect("read"), b"hello\n");
        // The temp is consumed by the rename — exactly one file remains.
        let entries: Vec<_> = std::fs::read_dir(tmp.path())
            .expect("read dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(
            entries,
            vec![std::ffi::OsString::from("CLAUDE.md")],
            "no `.hippius-tmp-*` litter must remain: {entries:?}"
        );
    }

    #[test]
    fn overwrite_replaces_content() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("f");
        atomic_write(&path, b"first").expect("first");
        atomic_write(&path, b"second").expect("second");
        assert_eq!(std::fs::read(&path).expect("read"), b"second");
    }

    /// The security property: a symlink planted at the destination is REPLACED,
    /// not followed. The old `std::fs::write` would have truncated the link's
    /// target (`victim`) instead — the TOCTOU/CWE-59 hole this write closes.
    #[cfg(unix)]
    #[test]
    fn does_not_follow_a_symlink_planted_at_the_destination() {
        let tmp = TempDir::new().expect("tempdir");
        // A file OUTSIDE the write target that an attacker points the symlink at.
        let victim = tmp.path().join("victim");
        std::fs::write(&victim, b"ORIGINAL").expect("seed victim");
        // The destination is a symlink to the victim (the planted attack).
        let dest = tmp.path().join("CLAUDE.md");
        std::os::unix::fs::symlink(&victim, &dest).expect("plant symlink");

        atomic_write(&dest, b"NEW CONTENT").expect("write");

        assert_eq!(
            std::fs::read(&victim).expect("victim read"),
            b"ORIGINAL",
            "the symlink's target must be untouched — the write must not follow it"
        );
        assert!(
            !std::fs::symlink_metadata(&dest)
                .expect("dest stat")
                .file_type()
                .is_symlink(),
            "the destination must now be a regular file, not the planted symlink"
        );
        assert_eq!(
            std::fs::read(&dest).expect("dest read"),
            b"NEW CONTENT",
            "the new content lands at the destination name"
        );
    }

    #[cfg(unix)]
    #[test]
    fn preserves_existing_mode_and_defaults_new_files_to_0644() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().expect("tempdir");

        // A fresh file lands at 0644 (a normal repo file), NOT tempfile's 0600.
        let fresh = tmp.path().join("fresh");
        atomic_write(&fresh, b"x").expect("write fresh");
        let fresh_mode = std::fs::metadata(&fresh)
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(fresh_mode, 0o644, "a new file must default to 0644");

        // An existing file's mode is preserved across the atomic replace.
        let existing = tmp.path().join("existing");
        std::fs::write(&existing, b"a").expect("seed");
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        atomic_write(&existing, b"b").expect("rewrite");
        let mode = std::fs::metadata(&existing)
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "an existing file's mode must be preserved");
    }

    #[test]
    fn bare_filename_writes_into_the_current_directory() {
        // A path with no parent resolves to the CWD; run it inside a scratch dir so
        // the test does not litter. Proves the `unwrap_or_else(".")` branch.
        let tmp = TempDir::new().expect("tempdir");
        let prev = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(tmp.path()).expect("chdir");
        let result = atomic_write(Path::new("bare-name"), b"content");
        std::env::set_current_dir(prev).expect("restore cwd");
        result.expect("write");
        assert_eq!(
            std::fs::read(tmp.path().join("bare-name")).expect("read"),
            b"content"
        );
    }
}
