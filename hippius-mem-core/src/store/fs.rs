//! Filesystem `BlobStore` for the local trial vault.
//!
//! Keys map to files under a root directory: slash-separated key segments
//! become subdirectories. The mapping is validated, not trusted — a key is
//! rejected unless every segment is non-empty, is not `.` or `..`, and
//! contains no path separator or NUL, so no key can escape the root.
//! `put` is atomic AND durable: bytes land in an unpredictable,
//! `O_EXCL`-created temp file in the same directory (via `tempfile`, mirroring
//! [`FileManifestMarker`](crate::identity::FileManifestMarker)'s own atomic
//! write), are `fsync`ed, and only then does a rename move them into place —
//! so no symlink or pre-planted file can be followed, no concurrent writer can
//! race a predictable path, and no crash can publish a key whose data never
//! reached the medium. `list` reconstructs keys from relative paths, skips
//! this store's own temp-file leftovers (an exact prefix match, never a
//! substring scan — a legitimate key can itself contain the text `.tmp-`),
//! and sorts so ordering matches the trait's lexicographic promise;
//! `delete` is idempotent. Every I/O failure other than "not found"
//! surfaces as [`MemError::Storage`], matching the trait's documented
//! contract (see [`crate::store::BlobStore`]).

use std::io::{ErrorKind, Write as _};
use std::path::{Path, PathBuf};

use async_trait::async_trait;

use crate::error::MemError;
use crate::store::BlobStore;

/// Prefix every temp file this store creates carries, so `list` can
/// recognize — and skip — a leftover from a crash between `put`'s write and
/// its rename.
///
/// Matched with `starts_with`, never `contains`: the name is entirely
/// independent of the target key (unlike an earlier `{file}.tmp-{pid}`
/// scheme derived FROM the target file name), so a legitimate key whose
/// final segment happens to contain this same text elsewhere in it is never
/// hidden from a listing. Leading-dot and crate-specific so no production
/// key collides with it in practice: `objkey.rs`'s `validate_component`
/// never allows a `.` in a segment at all, so every key `object_key` mints
/// is categorically excluded; a key `put` directly (bypassing `objkey.rs`)
/// would have to choose this exact reserved string on purpose.
const TMP_PREFIX: &str = ".hippius-fsblobstore-tmp-";

/// Map a filesystem I/O failure to [`MemError::Storage`], rendering the
/// operation, path, and OS error together — the [`BlobStore`] trait doc
/// promises `Storage` for any non-`NotFound` backend failure, and no other
/// implementation surfaces [`MemError::Io`]. Callers handle
/// `ErrorKind::NotFound` themselves before ever reaching this; every
/// remaining failure funnels through here.
fn storage_io_error(operation: &str, path: &Path, err: &std::io::Error) -> MemError {
    MemError::Storage(format!("fs {operation} {}: {err}", path.display()))
}

/// [`BlobStore`] backed by files under a local root directory, for the
/// solo-only trial vault (`storage = "local"`). See the module docs for the
/// key-to-path mapping and its safety guarantees.
#[derive(Debug, Clone)]
pub struct FsBlobStore {
    root: PathBuf,
}

impl FsBlobStore {
    /// Create a store rooted at `root`. Creates nothing on disk until the
    /// first `put`.
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// Resolve `key` to a path under the root, rejecting escape attempts.
    fn key_path(&self, key: &str) -> Result<PathBuf, MemError> {
        if key.is_empty() {
            return Err(MemError::Storage("empty object key".to_owned()));
        }

        let mut path = self.root.clone();
        for segment in key.split('/') {
            let unsafe_segment = segment.is_empty()
                || segment == "."
                || segment == ".."
                || segment.contains('\\')
                || segment.contains('\0');
            if unsafe_segment {
                return Err(MemError::Storage(format!(
                    "object key {key:?} contains an unsafe path segment"
                )));
            }
            path.push(segment);
        }

        Ok(path)
    }
}

#[async_trait]
impl BlobStore for FsBlobStore {
    /// Write `bytes` under `key`, durably and atomically: temp file, `fsync`,
    /// rename.
    ///
    /// The `fsync` is not optional bookkeeping. `write_all` only hands the bytes
    /// to the page cache; `rename` publishes the file NAME. Without a sync
    /// between them, a crash or power loss inside that window can leave the
    /// metadata operation persisted while the data behind it is not — i.e. the
    /// object key exists and reads back as zeros or a truncated prefix. This
    /// store backs the local trial vault, which is the ONLY copy of a trial
    /// user's notes (`storage = "local"` has no bucket to re-sync from), so a
    /// torn object here is unrecoverable data loss, not a cache miss.
    /// `sync_all` before `persist` closes that window — the same
    /// fsync-then-rename discipline `hippius-mem`'s `setup::atomic::atomic_write`
    /// and [`FileManifestMarker`](crate::identity::FileManifestMarker) use.
    ///
    /// Deliberately NOT synced: the parent DIRECTORY, after the rename. POSIX
    /// does not promise a rename is durable until its directory is fsynced, so
    /// the residual is that a crash immediately after this returns can lose the
    /// rename — leaving the previous version of the object, or none. That is a
    /// strictly milder failure than a torn object (a reader sees old-or-absent,
    /// never corrupt-but-present, and the op-log converges by re-reading), and
    /// the cost is a second synchronous fsync on the hot per-op append path.
    /// Revisit if the trial vault ever becomes a system of record.
    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
        let path = self.key_path(key)?;

        // `key_path` only ever returns `self.root` with at least one non-empty
        // segment pushed onto it, so `parent` is always `Some`.
        let parent = path
            .parent()
            .ok_or_else(|| MemError::Storage(format!("object key {key:?} has no parent")))?;
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|err| storage_io_error("create directory", parent, &err))?;

        // An unpredictable, `O_EXCL`-created temp file in the same directory
        // (via `tempfile::Builder`, exactly as `FileManifestMarker::store`
        // does), then a rename into place: it cannot follow a symlink, reuse
        // a pre-planted file, or race a concurrent writer on a predictable
        // path — the CWE-59/CWE-377 class a fixed or pid-derived name is
        // exposed to. `tempfile` is synchronous (like the rest of the crate,
        // and like the marker's own write), so this runs on the calling task.
        let mut tmp = tempfile::Builder::new()
            .prefix(TMP_PREFIX)
            .tempfile_in(parent)
            .map_err(|err| storage_io_error("create temp file in", parent, &err))?;
        tmp.write_all(&bytes)
            .map_err(|err| storage_io_error("write", tmp.path(), &err))?;
        // Durability before visibility: the bytes must be on the medium before
        // the rename publishes the name that points at them (see this method's
        // docs for the crash window this closes).
        tmp.as_file()
            .sync_all()
            .map_err(|err| storage_io_error("fsync", tmp.path(), &err))?;
        tmp.persist(&path)
            .map_err(|err| storage_io_error("rename into place", &path, &err.error))?;

        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
        let path = self.key_path(key)?;

        match tokio::fs::read(&path).await {
            Ok(bytes) => Ok(bytes),
            Err(err) if err.kind() == ErrorKind::NotFound => {
                Err(MemError::NotFound { id: key.to_owned() })
            }
            Err(err) => Err(storage_io_error("read", &path, &err)),
        }
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError> {
        let mut keys = Vec::new();
        let mut stack = vec![self.root.clone()];

        while let Some(dir) = stack.pop() {
            let mut entries = match tokio::fs::read_dir(&dir).await {
                Ok(entries) => entries,
                // A missing root (nothing has ever been `put`) — or a directory
                // removed out from under a concurrent listing — is an empty
                // subtree, not an error, matching `MemoryBlobStore` on a fresh
                // store.
                Err(err) if err.kind() == ErrorKind::NotFound => continue,
                Err(err) => return Err(storage_io_error("read directory", &dir, &err)),
            };

            loop {
                let entry = match entries.next_entry().await {
                    Ok(Some(entry)) => entry,
                    Ok(None) => break,
                    Err(err) => {
                        return Err(storage_io_error("read directory entry in", &dir, &err));
                    }
                };

                let entry_path = entry.path();
                let file_type = entry
                    .file_type()
                    .await
                    .map_err(|err| storage_io_error("stat", &entry_path, &err))?;

                if file_type.is_dir() {
                    stack.push(entry_path);
                    continue;
                }

                let is_tmp_leftover = entry_path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(TMP_PREFIX));
                if is_tmp_leftover {
                    continue;
                }

                let Ok(relative) = entry_path.strip_prefix(&self.root) else {
                    continue;
                };
                let key = relative
                    .components()
                    .filter_map(|component| component.as_os_str().to_str())
                    .collect::<Vec<_>>()
                    .join("/");

                if key.starts_with(prefix) {
                    keys.push(key);
                }
            }
        }

        keys.sort_unstable();
        Ok(keys)
    }

    async fn delete(&self, key: &str) -> Result<(), MemError> {
        let path = self.key_path(key)?;

        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            // Idempotent: a key that is already absent is success, matching S3
            // `DeleteObject`.
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
            Err(err) => Err(storage_io_error("delete", &path, &err)),
        }
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "tests assert success/failure of Result-returning steps"
    )]

    use std::path::PathBuf;

    use super::{FsBlobStore, TMP_PREFIX};
    use crate::error::MemError;
    use crate::store::BlobStore;

    #[test]
    fn key_path_rejects_escapes() {
        let store = FsBlobStore::new(PathBuf::from("/tmp/root"));
        for bad in [
            "", "/abs", "a//b", "..", "a/../b", "a/.", "a\\b", "a\0b", "a/",
        ] {
            assert!(store.key_path(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn key_path_maps_segments_to_directories() {
        let store = FsBlobStore::new(PathBuf::from("/tmp/root"));
        let path = store.key_path("team/_oplog/000001").expect("valid key");
        assert_eq!(path, PathBuf::from("/tmp/root/team/_oplog/000001"));
    }

    /// Every key shape `objkey.rs` and the store's internal namespaces
    /// (op-log, snapshots, anchors, manifest, member keys, per-epoch team
    /// keys) actually mint must pass `key_path` — cross-checked against
    /// `hippius-mem-core/src/objkey.rs`, `oplog/store.rs::object_key`,
    /// `store/snapshot.rs::snapshot_key`, `audit/batch.rs`'s anchor key,
    /// `identity/manifest.rs::manifest_key`, and
    /// `identity/teamkey.rs`'s member-key / per-epoch-key formats.
    #[test]
    fn key_path_accepts_real_key_shapes() {
        let store = FsBlobStore::new(PathBuf::from("/tmp/root"));

        let real_keys = [
            // objkey.rs::object_key — repo-scoped note version.
            "hippius-core/thebrain/mem_01ARZ3NDEKTSV4RRFFQ69G5FAV/ver_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            // objkey.rs::object_key — global-scope note version.
            "hippius-core/global/mem_01ARZ3NDEKTSV4RRFFQ69G5FAV/ver_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            // oplog/store.rs::object_key — {lamport:020}_{op_id}_{author_hex}.
            "hippius-core/_oplog/00000000000000000042_01ARZ3NDEKTSV4RRFFQ69G5FAV_deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            // store/snapshot.rs::snapshot_key — {lamport:020}.
            "hippius-core/_snapshots/00000000000000000042",
            // audit/batch.rs — {author_hex}/{seq:020}, nested under _anchors.
            "hippius-core/_anchors/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef/00000000000000000001",
            // identity/manifest.rs::manifest_key — {version:020}.
            "hippius-core/_manifest/00000000000000000001",
            // identity/teamkey.rs — member_key: {team}/_memberkeys/{ss58}.
            "hippius-core/_memberkeys/5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
            // identity/teamkey.rs — team_key: {team}/_keys/{epoch:020}/{ss58}.
            "hippius-core/_keys/00000000000000000000/5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
        ];

        for key in real_keys {
            assert!(
                store.key_path(key).is_ok(),
                "rejected real key shape {key:?}"
            );
        }
    }

    /// A root directory nobody has ever written to (the state a brand-new
    /// trial vault starts in, before `new`'s "creates nothing until the first
    /// `put`" promise is exercised) lists as empty, not an error — matching
    /// `MemoryBlobStore` on a fresh store.
    #[tokio::test]
    async fn list_on_a_never_written_root_is_empty_not_an_error() {
        let dir = tempfile::tempdir().expect("temp dir");
        let never_created = dir.path().join("vault");
        let store = FsBlobStore::new(never_created);

        assert_eq!(store.list("").await.expect("list"), Vec::<String>::new());
    }

    /// The same never-created root: a `get` before any `put` is `NotFound`,
    /// not an IO error surfaced as `Storage`.
    #[tokio::test]
    async fn get_on_a_never_written_root_is_not_found() {
        let dir = tempfile::tempdir().expect("temp dir");
        let never_created = dir.path().join("vault");
        let store = FsBlobStore::new(never_created);

        let err = store.get("team/x").await.expect_err("must be NotFound");
        assert!(matches!(err, MemError::NotFound { id } if id == "team/x"));
    }

    /// `put` creates the whole root tree on demand — `new` promises to create
    /// nothing itself — and the object it wrote is then listable.
    #[tokio::test]
    async fn put_creates_the_root_tree_and_the_object_becomes_listable() {
        let dir = tempfile::tempdir().expect("temp dir");
        let never_created = dir.path().join("vault");
        let store = FsBlobStore::new(never_created);

        store.put("team/x", vec![1, 2, 3]).await.expect("put");

        assert_eq!(
            store.list("").await.expect("list"),
            vec!["team/x".to_owned()]
        );
    }

    /// A crash between `put`'s write and its rename strands a
    /// `TMP_PREFIX`-named file next to the real object; `list` must skip it
    /// (an exact prefix match) rather than surface it as a bogus key.
    #[tokio::test]
    async fn list_skips_stray_tmp_leftovers() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = FsBlobStore::new(dir.path().to_path_buf());
        store.put("team/real", vec![1]).await.expect("put");

        let stray = dir
            .path()
            .join("team")
            .join(format!("{TMP_PREFIX}deadbeef"));
        std::fs::write(&stray, b"half-written").expect("strand a tmp file");

        assert_eq!(
            store.list("team/").await.expect("list"),
            vec!["team/real".to_owned()],
            "a stray temp-file leftover must not appear in the listing"
        );
    }

    /// A legitimate key whose final segment contains the literal substring
    /// `.tmp-` (but does not start with this store's reserved `TMP_PREFIX`)
    /// must still be listed. Regression test for the bug an earlier
    /// `contains(".tmp-")` filter had: it matched that substring ANYWHERE in
    /// a file name, so a real object like this one was silently omitted from
    /// every listing while remaining fully put/get-able.
    #[tokio::test]
    async fn list_includes_a_real_key_containing_the_tmp_substring() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = FsBlobStore::new(dir.path().to_path_buf());

        store
            .put("team/weird.tmp-name", vec![7])
            .await
            .expect("put");

        assert_eq!(
            store.list("team/").await.expect("list"),
            vec!["team/weird.tmp-name".to_owned()],
            "a real key containing \".tmp-\" as a substring must still be listed"
        );
    }

    /// A successful `put` leaves no temp file behind: the write lands in the
    /// temp file and the rename moves it into place, not a copy.
    #[tokio::test]
    async fn put_leaves_no_tmp_file_behind() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = FsBlobStore::new(dir.path().to_path_buf());
        store.put("team/x", vec![1]).await.expect("put");

        let mut entries = tokio::fs::read_dir(dir.path().join("team"))
            .await
            .expect("read_dir");
        let mut names = Vec::new();
        while let Some(entry) = entries.next_entry().await.expect("next_entry") {
            names.push(entry.file_name().to_string_lossy().into_owned());
        }

        assert_eq!(
            names,
            vec!["x".to_owned()],
            "only the renamed object must remain, no leftover temp file"
        );
    }

    /// The durability contract `put` owes the trial vault: once it returns, the
    /// object's bytes are in the file the key names — complete, and independent
    /// of the writing process. Read back through a FRESH `FsBlobStore` and
    /// directly off the filesystem, so nothing in-process (an unflushed handle,
    /// a cached buffer) can make the assertion pass.
    ///
    /// This is the strongest assertion an in-process test can make about `put`'s
    /// `sync_all`: whether the bytes survived a POWER cut is not observable from
    /// a test that shares the machine's page cache. The `sync_all` call itself,
    /// and the crash window it closes, are documented on `put`.
    #[tokio::test]
    async fn put_is_durable_before_it_returns() {
        let dir = tempfile::tempdir().expect("temp dir");
        let bytes = vec![9_u8; 4096];

        FsBlobStore::new(dir.path().to_path_buf())
            .put("team/note", bytes.clone())
            .await
            .expect("put");

        let reopened = FsBlobStore::new(dir.path().to_path_buf());
        assert_eq!(
            reopened.get("team/note").await.expect("get"),
            bytes,
            "a fresh store must read back exactly what `put` wrote"
        );
        assert_eq!(
            std::fs::read(dir.path().join("team").join("note")).expect("read the object file"),
            bytes,
            "the object file itself must hold the whole payload, not a truncated prefix"
        );
    }

    /// Every non-`NotFound` I/O failure must surface as `MemError::Storage`,
    /// per the `BlobStore` trait's documented contract — never
    /// `MemError::Io`, which no other implementation returns. A permission
    /// error is the vehicle: creating a file inside a directory whose write
    /// bit is removed fails with `PermissionDenied`, not `NotFound`.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_non_not_found_io_failure_surfaces_as_storage_not_io() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("temp dir");
        let store = FsBlobStore::new(dir.path().to_path_buf());
        store.put("team/x", vec![1]).await.expect("seed put");

        let team_dir = dir.path().join("team");
        let mut perms = std::fs::metadata(&team_dir)
            .expect("metadata")
            .permissions();
        perms.set_mode(0o000);
        std::fs::set_permissions(&team_dir, perms.clone()).expect("lock down directory");

        let err = store.put("team/y", vec![2]).await.expect_err("must fail");

        // Restore permissions before any assertion can early-return, so the
        // tempdir cleans up successfully regardless of outcome.
        perms.set_mode(0o700);
        std::fs::set_permissions(&team_dir, perms).expect("restore permissions");

        assert!(
            matches!(err, MemError::Storage(_)),
            "a permission failure must surface as Storage, got {err:?}"
        );
    }
}
