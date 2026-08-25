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
//! lock, and a [`SharedTip`] file recording this machine's own chain tip that
//! every process re-reads under that lock before it mints. The tip is written
//! after a successful APPEND — not after the head publish — because the op is
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
//! # What is closed, and what is emphatically not
//!
//! Closed: two or more processes on ONE machine sharing one config and one author
//! key — the routine case this product's own registration model produces.
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
//! write. Refusing a user's `remember` because a local bookkeeping file was
//! unavailable would be a worse product than the fork it prevents, and the
//! degradation is strictly no worse than every release before this one.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::domain::Blake3Hash;
use crate::error::MemError;

/// Version tag written into the tip file. A file carrying anything else is
/// treated as absent (warned), exactly as [`HeadWatermarks`](super::HeadWatermarks)
/// treats an unreadable watermark file: a local file must never be able to brick
/// the write path.
const TIP_FILE_VERSION: u32 = 1;

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

/// This machine's most recent durable op on the shared author chain.
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

/// The tip file's on-disk shape: a version tag plus the single tip.
#[derive(Debug, Serialize, Deserialize)]
struct TipFile {
    /// Always [`TIP_FILE_VERSION`] when written by this build.
    version: u32,
    /// The machine-wide chain tip for this team's author.
    tip: SharedTip,
}

/// The advisory write lock for one team profile on one machine, and the path of
/// the [`SharedTip`] it guards.
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
    /// Where [`SharedTip`] is persisted.
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
    /// Build the lock over `lock_path`, with its tip file beside it.
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
    /// This machine's shared chain tip, or `None` when no process has recorded
    /// one yet or the file is unusable.
    ///
    /// An unusable file is warned and treated as absent rather than surfaced: the
    /// caller then mints from its own clock, which is precisely the pre-existing
    /// behaviour. Erroring instead would let anyone able to corrupt one local file
    /// stop the machine writing at all.
    pub(crate) fn shared_tip(&self) -> Option<SharedTip> {
        let bytes = match std::fs::read(&self.lock.tip_path) {
            Ok(bytes) => bytes,
            // Never written: the normal first-write state, and not a fault.
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return None,
            Err(err) => {
                tracing::warn!(
                    path = %self.lock.tip_path.display(),
                    error = %err,
                    "could not read the shared writer tip; minting from this process's own \
                     cached chain head instead, which can fork the chain if another process on \
                     this machine has written since"
                );
                return None;
            }
        };

        let file: TipFile = match serde_json::from_slice(&bytes) {
            Ok(file) => file,
            Err(err) => {
                tracing::warn!(
                    path = %self.lock.tip_path.display(),
                    error = %err,
                    "the shared writer tip file could not be decoded; ignoring it for this write"
                );
                return None;
            }
        };

        if file.version != TIP_FILE_VERSION {
            tracing::warn!(
                path = %self.lock.tip_path.display(),
                found = file.version,
                expected = TIP_FILE_VERSION,
                "the shared writer tip file carries a version this build does not understand; \
                 ignoring it for this write"
            );
            return None;
        }

        Some(file.tip)
    }

    /// Record `tip` as this machine's chain tip.
    ///
    /// # Call this only after the append succeeded
    ///
    /// The tip's whole job is to name an op the next writer can chain to, so it
    /// must name a DURABLE op. Recording before the append would publish a tip for
    /// an op that may never land, and the next process would chain to a phantom
    /// predecessor — manufacturing the broken chain this module exists to prevent,
    /// from the opposite direction. This is deliberately NOT the head-publish
    /// boundary [`HeadWatermarks`](super::HeadWatermarks) uses; see the module
    /// docs for why the two must differ.
    ///
    /// Monotone: a tip at or below the recorded one is ignored, so a caller that
    /// re-records an older value cannot walk this machine backwards.
    ///
    /// Best-effort. A failure is warned and swallowed, leaving the tip stale — the
    /// same exposure as having no tip file at all, which is where every prior
    /// release sat.
    pub(crate) fn record_tip(&self, tip: SharedTip) {
        if let Some(existing) = self.shared_tip()
            && existing.lamport >= tip.lamport
        {
            return;
        }

        if let Err(err) = write_tip(&self.lock.tip_path, tip) {
            tracing::warn!(
                path = %self.lock.tip_path.display(),
                error = %err,
                "could not persist the shared writer tip; another process on this machine will \
                 mint from a stale tip and may fork this author's chain"
            );
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
/// The rename is what makes a concurrent READER see either the old tip or the new
/// one and never a half-written one. Readers hold the lock, so they are not
/// racing this — but a reader in a build that failed to take the lock is exactly
/// the degraded case this module tolerates, and it must still never parse a torn
/// file. This is also why the rename target is the tip file and never the lock
/// file: replacing the lock file's inode would strand every waiter on a lock
/// nobody can contend for.
fn write_tip(path: &Path, tip: SharedTip) -> Result<(), MemError> {
    let bytes = serde_json::to_vec(&TipFile {
        version: TIP_FILE_VERSION,
        tip,
    })?;

    let dir = parent_dir(path).unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir).map_err(MemError::Io)?;

    let mut tmp = crate::atomic_file::AtomicFile::create_in(dir, ".writer-tip-", ".tmp")
        .map_err(MemError::Io)?;
    tmp.write_all(&bytes).map_err(MemError::Io)?;
    tmp.as_file().sync_all().map_err(MemError::Io)?;
    tmp.persist(path).map_err(MemError::Io)?;

    Ok(())
}
