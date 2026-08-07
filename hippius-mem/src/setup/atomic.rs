//! Atomic, symlink-safe writes for the provisioning config files.
//!
//! The `init`/self-heal paths rewrite files whose parent directory an
//! unprivileged co-resident process may control (`CLAUDE.md`, `AGENTS.md`,
//! `.claude/settings.json`, `.gitignore`, and the `.claude/hooks/*.sh` scripts).
//! A bare `std::fs::write(path, ...)` there is a TOCTOU/symlink hazard
//! (CWE-59/CWE-377): it FOLLOWS a symlink planted at `path` and truncates whatever
//! the link points at, so an attacker can redirect the operator's write onto
//! another operator-writable file.
//!
//! [`atomic_write`] closes that hole with the same discipline `hippius-mem-core`'s
//! `FileManifestMarker::store` already uses: write to an `O_EXCL`, uniquely-named
//! temp in the target's OWN directory, `fsync` it, then `rename` it over the
//! target. `rename` replaces the destination NAME as a single filesystem operation
//! and never follows a symlink at that name, and the `O_EXCL` temp cannot itself
//! follow a pre-planted symlink.

use std::io::Write;
use std::path::Path;

use anyhow::Context;

/// Atomically write `bytes` to `path`, replacing any existing file, preserving an
/// existing regular file's mode (see [`resolve_mode`] for the security-critical
/// mode rules).
///
/// # Errors
///
/// Returns an error if the temp file cannot be created in `path`'s directory,
/// written, or fsynced, or if the atomic rename over `path` fails.
pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    atomic_write_inner(path, bytes, None)
}

/// Atomically write `bytes` to `path`, replacing any existing file, ALWAYS
/// forcing owner-only `0600` regardless of the existing file's mode.
///
/// For a config file that holds live secrets — unlike [`atomic_write`],
/// which preserves a pre-existing regular file's mode for the non-secret
/// provisioning files it serves. A pre-existing looser mode is tightened,
/// not preserved, because the file provably holds a live secret once this
/// returns — mirrors `join_bundle::append_profile`'s post-append
/// `set_permissions(0600)` discipline, applied here as part of the same
/// fsync-then-rename this module already provides rather than as a separate
/// step after a plain write. `pub(crate)`: `upgrade` reuses this to rewrite
/// a trial config to `storage = "s3"`, the one config write in the crate
/// that REPLACES an existing file (`quickstart`/`join --bundle` only
/// create-fresh or append) — see `upgrade::rewrite_config_file`.
///
/// # Errors
///
/// Same as [`atomic_write`].
pub(crate) fn atomic_write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    atomic_write_inner(path, bytes, Some(0o600))
}

/// Owner-executable, group/other-readable mode for the hook scripts (`rwxr-xr-x`).
#[cfg(unix)]
const EXECUTABLE_MODE: u32 = 0o755;

/// Atomically write an EXECUTABLE file (mode `0755`), for the `.claude/hooks/*.sh`
/// scripts.
///
/// The `+x` bit is set on the temp file BEFORE the rename, so the script is never
/// briefly present as non-executable and — unlike a `write` then separate `chmod`
/// — there is no post-rename window in which a swapped symlink could redirect the
/// mode change onto another file. On non-unix this is just [`atomic_write`]
/// (executability is a Windows no-op, matching the rest of the module).
pub(crate) fn atomic_write_executable(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        atomic_write_inner(path, bytes, Some(EXECUTABLE_MODE))
    }
    #[cfg(not(unix))]
    {
        atomic_write(path, bytes)
    }
}

/// Shared implementation. `forced_mode` (unix) is set verbatim on the result;
/// `None` preserves an existing regular file's mode (see [`resolve_mode`]).
fn atomic_write_inner(path: &Path, bytes: &[u8], forced_mode: Option<u32>) -> anyhow::Result<()> {
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
    // fsync the bytes before the rename so a crash cannot leave a renamed but
    // empty/partial config file (parity with `FileManifestMarker::store`).
    tmp.as_file()
        .sync_all()
        .with_context(|| format!("fsyncing the temp file for {} failed", path.display()))?;
    resolve_mode(tmp.as_file(), path, forced_mode)?;
    // `persist` renames the temp over `path`. `path` itself is only ever named by
    // this rename, so a crash mid-write leaves the disposable temp, never a torn
    // `path`; and rename replaces a symlink at `path` rather than following it.
    tmp.persist(path)
        .map_err(|e| e.error)
        .with_context(|| format!("replacing {} via atomic rename failed", path.display()))?;
    Ok(())
}

/// Set the temp file's final mode.
///
/// `forced` (e.g. `0755` for a hook script) is applied verbatim. Otherwise the
/// mode is PRESERVED from an existing regular file at `target`, read with
/// `symlink_metadata` — which does **not** follow a symlink. Not following is
/// security-critical: a co-resident attacker can plant a symlink at `target`
/// pointing at a world-writable (`0666`) file, and following it would copy that
/// permissive mode onto the config we are hardening, handing the attacker write
/// access. A fresh file, a symlink, or any non-regular target instead keeps
/// `tempfile`'s owner-only `0600` — which never *widens* permissions (so it is
/// safe under any umask), and which git carries the committed mode past anyway.
#[cfg(unix)]
fn resolve_mode(tmp: &std::fs::File, target: &Path, forced: Option<u32>) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = match forced {
        Some(explicit) => explicit,
        None => match std::fs::symlink_metadata(target) {
            // Only preserve a REGULAR file's mode; never a symlink target's.
            Ok(meta) if meta.file_type().is_file() => meta.permissions().mode() & 0o777,
            // Fresh / symlink / non-regular: keep tempfile's owner-only 0600.
            _ => return Ok(()),
        },
    };
    tmp.set_permissions(std::fs::Permissions::from_mode(mode))
        .with_context(|| {
            format!(
                "setting mode {mode:o} on the temp file for {} failed",
                target.display()
            )
        })
}

/// No mode management off unix: Windows provisioning is out of scope.
#[cfg(not(unix))]
fn resolve_mode(_tmp: &std::fs::File, _target: &Path, _forced: Option<u32>) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "tests assert success of Result-returning filesystem steps"
    )]

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

    #[test]
    fn writes_an_empty_file() {
        // An empty body (e.g. a fully-stripped .gitignore) must produce a real,
        // empty file, not fail.
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("empty");
        atomic_write(&path, b"").expect("write empty");
        assert_eq!(std::fs::read(&path).expect("read"), b"");
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

    /// Security regression guard: when the destination is a planted symlink to a
    /// world-writable file, the new file must NOT inherit the link target's
    /// permissive mode (that would hand the attacker write access to the config).
    #[cfg(unix)]
    #[test]
    fn does_not_copy_a_symlink_targets_permissive_mode() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().expect("tempdir");
        let victim = tmp.path().join("victim");
        std::fs::write(&victim, b"x").expect("seed victim");
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o666)).expect("chmod");
        let dest = tmp.path().join("settings.json");
        std::os::unix::fs::symlink(&victim, &dest).expect("plant symlink");

        atomic_write(&dest, b"{}").expect("write");

        let mode = std::fs::metadata(&dest).expect("stat").permissions().mode() & 0o777;
        assert_ne!(
            mode, 0o666,
            "must not copy the planted link target's world-writable mode onto the config"
        );
        // A symlink target's mode is not preserved, so the file keeps the safe
        // owner-only default.
        assert_eq!(
            mode, 0o600,
            "a symlink destination falls back to owner-only 0600"
        );
    }

    #[cfg(unix)]
    #[test]
    fn preserves_an_existing_regular_files_mode_but_never_widens_a_fresh_one() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().expect("tempdir");

        // A fresh file keeps tempfile's owner-only 0600 — never a widening (e.g.
        // to world-readable 0644 regardless of umask). Committed files carry their
        // git mode on other machines; this is only the local working copy.
        let fresh = tmp.path().join("fresh");
        atomic_write(&fresh, b"x").expect("write fresh");
        let fresh_mode = std::fs::metadata(&fresh)
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            fresh_mode, 0o600,
            "a fresh file must not be widened past 0600"
        );

        // An existing regular file's mode is preserved across the atomic replace.
        let existing = tmp.path().join("existing");
        std::fs::write(&existing, b"a").expect("seed");
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o640)).expect("chmod");
        atomic_write(&existing, b"b").expect("rewrite");
        let mode = std::fs::metadata(&existing)
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o640,
            "an existing regular file's mode must be preserved"
        );
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_executable_sets_the_exec_bit() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("hook.sh");
        super::atomic_write_executable(&path, b"#!/bin/sh\n").expect("write");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "a hook script must be installed as 0755");
    }
}
