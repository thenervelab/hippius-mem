//! Filesystem `BlobStore` for the local trial vault.
//!
//! Keys map to files under a root directory: slash-separated key segments
//! become subdirectories. The mapping is validated, not trusted — a key is
//! rejected unless every segment is non-empty, is not `.` or `..`, and
//! contains no path separator or NUL, so no key can escape the root.
//! `put` is atomic (temp file + rename in the same directory); `list`
//! reconstructs keys from relative paths and sorts them so ordering matches
//! the trait's lexicographic promise; `delete` is idempotent.

use std::io::ErrorKind;
use std::path::PathBuf;

use async_trait::async_trait;

use crate::error::MemError;
use crate::store::BlobStore;

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
    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
        let path = self.key_path(key)?;

        // `key_path` only ever returns `self.root` with at least one non-empty
        // segment pushed onto it, so `parent`/`file_name` are always `Some`.
        let parent = path
            .parent()
            .ok_or_else(|| MemError::Storage(format!("object key {key:?} has no parent")))?;
        tokio::fs::create_dir_all(parent).await?;

        let file_name = path
            .file_name()
            .ok_or_else(|| MemError::Storage(format!("object key {key:?} has no file name")))?;
        let mut tmp_name = file_name.to_owned();
        tmp_name.push(format!(".tmp-{}", std::process::id()));
        let tmp_path = path.with_file_name(tmp_name);

        // Temp file + rename in the same directory: the rename is atomic on one
        // filesystem, so a concurrent `get` never observes a partially written
        // object, and a crash mid-write leaves only an orphaned `.tmp-` file
        // (which `list` skips) rather than a corrupt one at the real key.
        tokio::fs::write(&tmp_path, &bytes).await?;
        tokio::fs::rename(&tmp_path, &path).await?;

        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
        let path = self.key_path(key)?;

        match tokio::fs::read(&path).await {
            Ok(bytes) => Ok(bytes),
            Err(err) if err.kind() == ErrorKind::NotFound => {
                Err(MemError::NotFound { id: key.to_owned() })
            }
            Err(err) => Err(MemError::Io(err)),
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
                Err(err) => return Err(MemError::Io(err)),
            };

            while let Some(entry) = entries.next_entry().await? {
                if entry.file_type().await?.is_dir() {
                    stack.push(entry.path());
                    continue;
                }

                let path = entry.path();
                let is_tmp_leftover = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.contains(".tmp-"));
                if is_tmp_leftover {
                    continue;
                }

                let Ok(relative) = path.strip_prefix(&self.root) else {
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
            Err(err) => Err(MemError::Io(err)),
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

    use super::FsBlobStore;
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

    /// A crash between `put`'s write and its rename strands a `.tmp-{pid}`
    /// file next to the real object; `list` must skip it rather than surface
    /// it as a bogus key.
    #[tokio::test]
    async fn list_skips_stray_tmp_leftovers() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = FsBlobStore::new(dir.path().to_path_buf());
        store.put("team/real", vec![1]).await.expect("put");

        let stray = dir.path().join("team").join("real.tmp-999999");
        std::fs::write(&stray, b"half-written").expect("strand a tmp file");

        assert_eq!(
            store.list("team/").await.expect("list"),
            vec!["team/real".to_owned()],
            "the stray .tmp- leftover must not appear in the listing"
        );
    }

    /// A successful `put` leaves no `.tmp-` file behind: the write lands in
    /// the temp file and the rename moves it into place, not a copy.
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
}
