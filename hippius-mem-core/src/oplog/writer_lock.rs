//! Cross-process serialization of one machine's op-log writes, plus the shared
//! chain tip that makes serializing them worth anything.
//!
//! # The defect this closes
//!
//! [`MemoryStore::writer`](crate::MemoryStore) is a per-INSTANCE `tokio::Mutex`,
//! and this product registers its MCP server USER-GLOBALLY (`hippius-mem install`
//! writes one entry; see `docs/REFERENCE.md`), so every concurrent agent session
//! boots its own server process from the same config under the SAME author key.
//! Two of those processes minting before either syncs produce two ops with the
//! same `prev_op_hash` — a self-fork. `quarantine_broken_chains` then keeps the
//! taller genesis-rooted branch and orphans the other, so the losing branch's ops
//! are dropped from convergence FOR GOOD and must be re-issued. Unlike a racing
//! head PUT, it does not self-clear.
//!
//! Concurrent same-identity writers are therefore the ordinary consequence of
//! running two sessions, not a misconfiguration anyone opted into, which is why
//! "run one identity per process" was never advice a user could act on.
//!
//! # Why a lock alone would have fixed nothing
//!
//! This is the part worth reading twice. Serializing the two critical sections is
//! necessary and NOT sufficient: each process mints from its own in-memory
//! `OpClock`, so the second one to take the lock still holds the pre-race
//! `my_last_hash` and still chains to it. It forks exactly as before, only more
//! politely. A lock closes the interleaving; it does nothing about the staleness,
//! and the staleness is what forks the chain.
//!
//! So this module ships two things that are only useful together: an advisory
//! lock, and a tip file recording each author's chain tip on this machine
//! ([`SharedTip`]) that every process re-reads under that lock before it mints.
//! The tip is written after a successful APPEND — not after the head publish — because the op is
//! durable at that point and it is the durable op the next writer must chain to.
//! That distinction is why this cannot reuse
//! [`HeadWatermarks`](super::HeadWatermarks), whose marks deliberately advance
//! only after a successful head PUT, so a write whose best-effort head publish
//! failed would leave the next process chaining to a stale tip. It is also a
//! different trust domain: a watermark mark is evidence in an audit that names an
//! identity, so laundering an unverified value into it manufactures an accusation.
//! This file is chaining bookkeeping about our OWN durable ops and is never
//! evidence about anyone.
//!
//! # One entry per author
//!
//! The tip file is keyed on the team name, not on the author, so two author
//! seeds writing the same team from one state directory (a second agent seed, a
//! CI runner with a shared `HOME`, `import` under another identity) share it.
//! Version 1 stored a single tip with no author, and the second author adopted the
//! first author's op as its own `prev_op_hash`, so both chains broke. Version 2
//! stores one [`AuthorTip`] per author key, and a reader can only look up its own
//! key, so it can never chain to another author's op. A version-1 file names no
//! author, so it is treated as holding no entry at all: the caller then falls back
//! to its own published head (see `MemoryStore::refresh_clock_under_lock`).
//!
//! # The pending op: a write that may have landed
//!
//! A process killed after its op PUT reached the bucket but before it recorded
//! the tip leaves a durable op that no local file names. The next writer on this
//! machine would mint from the older tip and fork the chain against it, and the
//! fork's tie-break keeps the older op, so the next writer's ACKNOWLEDGED op was
//! the one dropped. So the writer records the op it is about to append as
//! [`AuthorTip::pending`] before the append, and the next writer that finds a
//! pending op checks the bucket for it: present means durable, and the next op
//! chains to it; absent means it never landed, and the committed tip stands.
//!
//! # What is closed, and what is emphatically not
//!
//! Closed: two or more processes on ONE machine sharing one state directory,
//! under one author key or several: the routine case this product's own
//! registration model produces.
//!
//! Not closed: the same identity writing from two MACHINES. Nothing local can see
//! the other machine, and closing it needs a compare-and-swap the object store
//! does not offer. The console sub-key onboarding is the answer there, because it
//! gives each machine a distinct author key and so removes the shared chain
//! entirely.
//!
//! Also not closed: a machine whose state directory does not resolve, or whose
//! lock cannot be taken within [`ACQUIRE_TIMEOUT`]. Both degrade to the previous
//! behaviour — unserialized, fork possible — with a warning, never to a failed
//! write.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::domain::Blake3Hash;
use crate::error::MemError;
use crate::oplog::VerifyingKey;
use crate::ulid::Ulid;

/// Version tag written into the tip file. Version 1 (0.7.1 and earlier) held one
/// tip with no author; see the module docs for why it is read as "no entry".
/// Any other unknown version is treated as absent (warned), exactly as
/// [`HeadWatermarks`](super::HeadWatermarks) treats an unreadable watermark file:
/// a local file must never be able to brick the write path.
const TIP_FILE_VERSION: u32 = 2;

/// The version 0.7.1 and earlier wrote, which names no author.
const AUTHORLESS_TIP_FILE_VERSION: u32 = 1;

/// How long [`WriterLock::acquire`] waits for a peer to finish before giving up
/// and letting the write proceed unserialized.
///
/// The critical section it is waiting on contains an op-log append and a head
/// publish — two gateway round-trips, each hundreds of milliseconds — so a
/// second or two of queueing behind one peer is normal and must not time out. Ten
/// seconds is far above that and still far below any human's patience for a
/// hung `remember`.
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(10);

/// Gap between `try_lock` attempts while waiting.
///
/// Polling rather than a blocking `File::lock` because the caller is inside an
/// async write path: a blocking lock would park a runtime worker thread for the
/// length of another process's gateway round-trips. At this interval the wait
/// costs at most a few hundred wakeups, against I/O measured in hundreds of
/// milliseconds.
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// One author's most recent durable op on its chain, as recorded on this machine.
///
/// `lamport` is the op's own Lamport value (what its head pointer would carry),
/// NOT the highest Lamport observed across the team — the two differ whenever a
/// teammate is ahead, and comparing against the wrong one would either adopt a
/// stale tip or refuse a fresh one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SharedTip {
    /// Lamport value of the op this tip names.
    pub(crate) lamport: u64,
    /// [`Op::hash`](crate::Op::hash) of that op — the next op's `prev_op_hash`.
    pub(crate) tip_hash: Blake3Hash,
}

/// An op a writer on this machine was about to append when it last held the lock,
/// not yet confirmed durable.
///
/// Carries exactly what is needed to find the op in the bucket (its object key
/// is built from `lamport`, `op_id` and the author key) and to tell it is the
/// same op (`op_hash`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PendingOp {
    /// Lamport value of the pending op.
    pub(crate) lamport: u64,
    /// The pending op's id.
    pub(crate) op_id: Ulid,
    /// [`Op::hash`](crate::Op::hash) of the pending op.
    pub(crate) op_hash: Blake3Hash,
}

/// One author's entry in the tip file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AuthorTip {
    /// The newest op this machine knows is durable. `lamport: 0` with
    /// [`GENESIS_PREV`](super::GENESIS_PREV) means "no op yet".
    pub(crate) committed: SharedTip,
    /// The op being appended when the entry was last written, if its outcome was
    /// never recorded. See the module docs.
    pub(crate) pending: Option<PendingOp>,
}

/// The tip file's on-disk shape: a version tag plus one entry per author key.
#[derive(Debug, Serialize, Deserialize)]
struct TipFile {
    /// Always [`TIP_FILE_VERSION`] when written by this build.
    version: u32,
    /// Each author's entry, keyed by the author's public key (hex on disk).
    authors: HashMap<VerifyingKey, AuthorTip>,
}

/// Just the version tag, read first so a version-1 file (a different shape) is
/// recognised instead of reported as undecodable.
#[derive(Deserialize)]
struct TipFileVersion {
    version: u32,
}

/// The advisory write lock for one team profile on one machine, and the path of
/// the tip file it guards.
///
/// Constructed by the binary, which owns every path decision; this crate performs
/// no environment or XDG lookup of its own — the same division
/// [`HeadWatermarks`](super::HeadWatermarks) uses.
#[derive(Debug)]
pub struct WriterLock {
    /// The `flock` target. Its CONTENT is never read or written: only the inode
    /// matters. Deliberately a different file from `tip_path`, because that one
    /// is replaced by an atomic temp+rename — which swaps the inode and would
    /// leave every waiter holding a lock on a file nobody else can see.
    lock_path: PathBuf,
    /// Where the [`TipFile`] is persisted.
    tip_path: PathBuf,
}

/// Proof that the caller holds the cross-process write lock.
///
/// The tip accessors live here rather than on [`WriterLock`] so "only under the
/// lock" is a type-level fact instead of a doc-comment precondition. Reading the
/// tip outside the lock would race a peer's write of it, which is the whole
/// failure this module exists to remove.
///
/// The lock is released when this is dropped — including on a crash, since the OS
/// reclaims a `flock` the moment the holding descriptor closes, so a killed
/// process can never leave a stale lock a later run must break.
#[derive(Debug)]
pub(crate) struct WriterLockGuard<'a> {
    /// Held purely for the `flock` attached to its descriptor.
    _file: std::fs::File,
    /// Where to read and write the guarded tip.
    lock: &'a WriterLock,
}

impl WriterLock {
    /// Build the lock over `lock_path`, with its tip file at `tip_path`.
    #[must_use]
    pub fn new(lock_path: PathBuf, tip_path: PathBuf) -> Self {
        Self {
            lock_path,
            tip_path,
        }
    }

    /// Take the lock, waiting up to [`ACQUIRE_TIMEOUT`] for a peer to release it.
    ///
    /// `None` means "proceed unserialized": either the lock file could not be
    /// created or opened, or a peer held it past the timeout. Both are warned
    /// here so the caller does not have to decide how to describe them, and both
    /// leave the caller in exactly the state every release before this one was
    /// in. Never returns an error: no local bookkeeping failure may fail a user's
    /// write.
    pub(crate) async fn acquire(&self) -> Option<WriterLockGuard<'_>> {
        let file = match self.open_lock_file() {
            Ok(file) => file,
            Err(err) => {
                tracing::warn!(
                    path = %self.lock_path.display(),
                    error = %err,
                    "could not open the local writer lock; this write proceeds unserialized, so \
                     if another process on this machine is writing under the same identity the \
                     two can fork this author's chain"
                );
                return None;
            }
        };

        let deadline = tokio::time::Instant::now() + ACQUIRE_TIMEOUT;

        loop {
            match file.try_lock() {
                Ok(()) => {
                    return Some(WriterLockGuard {
                        _file: file,
                        lock: self,
                    });
                }
                Err(std::fs::TryLockError::WouldBlock) => {}
                Err(std::fs::TryLockError::Error(err)) => {
                    tracing::warn!(
                        path = %self.lock_path.display(),
                        error = %err,
                        "the local writer lock could not be taken; this write proceeds \
                         unserialized and may fork this author's chain against a concurrent \
                         process on this machine"
                    );
                    return None;
                }
            }

            if tokio::time::Instant::now() >= deadline {
                tracing::warn!(
                    path = %self.lock_path.display(),
                    timeout_secs = ACQUIRE_TIMEOUT.as_secs(),
                    "another process on this machine held the writer lock past the timeout; \
                     proceeding unserialized rather than failing the write, so this op may fork \
                     the author chain and be quarantined on the next read"
                );
                return None;
            }

            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    /// Open (creating if absent) the `flock` target.
    ///
    /// Never truncates: the content is meaningless, so clearing it would be
    /// pointless I/O on the common already-exists path — the same reasoning
    /// `TeamProfile::try_lock_vault_file` records for the trial-vault locks.
    fn open_lock_file(&self) -> Result<std::fs::File, std::io::Error> {
        if let Some(dir) = parent_dir(&self.lock_path) {
            std::fs::create_dir_all(dir)?;
        }

        std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&self.lock_path)
    }
}

impl WriterLockGuard<'_> {
    /// `author`'s entry, or `None` when the file has none for it: never written,
    /// written by a version-1 build (which names no author), or unusable.
    ///
    /// An unusable file is warned and treated as empty rather than surfaced: the
    /// caller then falls back to the author's published head. Erroring instead
    /// would let anyone able to corrupt one local file stop the machine writing.
    pub(crate) fn author_tip(&self, author: &VerifyingKey) -> Option<AuthorTip> {
        self.read_entries().get(author).copied()
    }

    /// Replace `author`'s entry with `tip`, keeping every other author's entry.
    ///
    /// The read-modify-write is safe because only a lock holder writes the file.
    /// No monotonicity check: every writer adopts the recorded tip under this same
    /// lock before it mints (`MemoryStore::refresh_clock_under_lock`), so the tip
    /// it records is at or above the one on disk by construction.
    ///
    /// # Errors
    ///
    /// [`MemError::WriterTip`] if the file cannot be written.
    pub(crate) fn record(&self, author: VerifyingKey, tip: AuthorTip) -> Result<(), MemError> {
        let mut authors = self.read_entries();
        authors.insert(author, tip);

        write_tip_file(
            &self.lock.tip_path,
            &TipFile {
                version: TIP_FILE_VERSION,
                authors,
            },
        )
        .map_err(|source| MemError::WriterTip {
            path: self.lock.tip_path.clone(),
            source,
        })
    }

    /// Every author's entry in the tip file, or none when the file is absent,
    /// version 1, or unusable (warned, except for the first two).
    fn read_entries(&self) -> HashMap<VerifyingKey, AuthorTip> {
        let path = &self.lock.tip_path;
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            // Never written: the normal first-write state, and not a fault.
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return HashMap::new(),
            Err(err) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %err,
                    "could not read the shared writer tip; falling back to this author's \
                     published head for this write"
                );
                return HashMap::new();
            }
        };

        let version = match serde_json::from_slice::<TipFileVersion>(&bytes) {
            Ok(probe) => probe.version,
            Err(err) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %err,
                    "the shared writer tip file could not be decoded; ignoring it for this write"
                );
                return HashMap::new();
            }
        };

        match version {
            TIP_FILE_VERSION => {}
            // Written by 0.7.1 or earlier. Its single tip names no author, so it
            // may be another author's op: adopting it is the defect version 2
            // fixes. Not warned, because the next write replaces it.
            AUTHORLESS_TIP_FILE_VERSION => return HashMap::new(),
            found => {
                tracing::warn!(
                    path = %path.display(),
                    found,
                    expected = TIP_FILE_VERSION,
                    "the shared writer tip file carries a version this build does not \
                     understand; ignoring it for this write"
                );
                return HashMap::new();
            }
        }

        match serde_json::from_slice::<TipFile>(&bytes) {
            Ok(file) => file.authors,
            Err(err) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %err,
                    "the shared writer tip file could not be decoded; ignoring it for this write"
                );
                HashMap::new()
            }
        }
    }
}

/// The directory a path lives in, treating a bare filename as the current one.
fn parent_dir(path: &Path) -> Option<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

/// Atomically replace the tip file: temp file in the same directory, fsync,
/// rename.
///
/// The rename is what makes a concurrent READER see either the old file or the
/// new one and never a half-written one. Readers hold the lock, so they are not
/// racing this — but a reader in a build that failed to take the lock is exactly
/// the degraded case this module tolerates, and it must still never parse a torn
/// file. This is also why the rename target is the tip file and never the lock
/// file: replacing the lock file's inode would strand every waiter on a lock
/// nobody can contend for.
fn write_tip_file(path: &Path, file: &TipFile) -> Result<(), std::io::Error> {
    let bytes = serde_json::to_vec(file).map_err(std::io::Error::other)?;

    crate::atomic_file::write_atomically(path, ".writer-tip-", ".tmp", &bytes)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test, not a crash to avoid"
    )]

    use super::*;
    use crate::oplog::GENESIS_PREV;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn lock_in(dir: &Path) -> WriterLock {
        WriterLock::new(dir.join("writer.lock"), dir.join("writer-tip.json"))
    }

    fn tip(lamport: u64) -> AuthorTip {
        AuthorTip {
            committed: SharedTip {
                lamport,
                tip_hash: crate::crypto::content_hash(&lamport.to_le_bytes()),
            },
            pending: None,
        }
    }

    #[tokio::test]
    async fn each_author_reads_back_only_its_own_entry() -> TestResult {
        let dir = tempfile::tempdir()?;
        let lock = lock_in(dir.path());
        let alice = VerifyingKey::new([1; 32]);
        let bob = VerifyingKey::new([2; 32]);

        let guard = lock.acquire().await.ok_or("lock must be available")?;
        guard.record(alice, tip(3))?;
        guard.record(bob, tip(7))?;

        assert_eq!(guard.author_tip(&alice), Some(tip(3)));
        assert_eq!(guard.author_tip(&bob), Some(tip(7)));
        assert_eq!(guard.author_tip(&VerifyingKey::new([3; 32])), None);
        Ok(())
    }

    /// A 0.7.1 tip file names no author, so it must never be read as anyone's.
    #[tokio::test]
    async fn a_version_1_file_is_read_as_no_entry() -> TestResult {
        let dir = tempfile::tempdir()?;
        let lock = lock_in(dir.path());
        let hash = GENESIS_PREV.to_hex();
        std::fs::write(
            dir.path().join("writer-tip.json"),
            format!(r#"{{"version":1,"tip":{{"lamport":9,"tip_hash":"{hash}"}}}}"#),
        )?;

        let guard = lock.acquire().await.ok_or("lock must be available")?;
        assert_eq!(guard.author_tip(&VerifyingKey::new([1; 32])), None);

        // Recording over it upgrades the file to version 2.
        guard.record(VerifyingKey::new([1; 32]), tip(10))?;
        assert_eq!(guard.author_tip(&VerifyingKey::new([1; 32])), Some(tip(10)));
        Ok(())
    }

    #[tokio::test]
    async fn a_corrupt_file_is_read_as_no_entry() -> TestResult {
        let dir = tempfile::tempdir()?;
        let lock = lock_in(dir.path());
        std::fs::write(dir.path().join("writer-tip.json"), b"{not json")?;

        let guard = lock.acquire().await.ok_or("lock must be available")?;
        assert_eq!(guard.author_tip(&VerifyingKey::new([1; 32])), None);
        Ok(())
    }
}
