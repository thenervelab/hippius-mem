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
//! # One entry per author, one file per storage location
//!
//! The lock file lives in the team's state directory, keyed on the team name, so
//! two author seeds writing the same team from one machine (a second agent seed,
//! a CI runner with a shared `HOME`, `import` under another identity) share it.
//! The 0.7.1 tip file stored a single tip with no author, and the second author
//! adopted the first author's op as its own `prev_op_hash`, so both chains broke.
//! This build stores one [`AuthorTip`] per author key, and a reader can only look
//! up its own key, so it never chains to another author's op.
//!
//! The same team name can also name two different buckets (a staging bucket and
//! the production one, under one seed). A tip recorded for one bucket names an op
//! the other bucket does not hold, so chaining to it breaks the chain there. The
//! binary therefore gives each storage location its own tip file
//! (`TeamProfile::writer_lock` derives the name from the endpoint and bucket);
//! the lock file stays shared, which only orders the writes.
//!
//! # Running beside 0.7.1
//!
//! A 0.7.1 process on the same machine reads and writes `writer-tip.json`
//! (version 1, one tip) and knows nothing of this build's file. This build keeps
//! that file current with the tip of each op it commits, using 0.7.1's own rule
//! (replace only a lower Lamport), so a 0.7.1 process under the same seed
//! chains to this build's ops. In the other direction this build cannot tell
//! whose op a version-1 tip names, so it never adopts one. Instead it remembers
//! what the version-1 file held after its own last write; when the file has
//! changed since, an older process wrote here, and this build also reads its own
//! published head and takes whichever tip is newer. That covers every 0.7.1
//! write whose head publish succeeded; a 0.7.1 write whose head publish failed
//! can still fork, exactly as it could between two 0.7.1 processes. 0.7.1 never
//! touches this build's file, so the per-author entries and their pending ops
//! survive a mixed-version rollout.
//!
//! # The pending op: a write that may have landed
//!
//! A process killed after its op PUT reached the bucket but before it recorded
//! the tip leaves a durable op that no local file names. A PUT still in flight
//! when the writer died can also land later, after any check the next writer
//! makes. Either way, the next writer on this machine would mint from the older
//! tip and fork the chain against that op, and the fork's tie-break keeps the
//! older op, so the next writer's ACKNOWLEDGED op was the one dropped.
//!
//! So the writer records the whole signed op it is about to append as
//! [`AuthorTip::pending`] before the append, and the next writer under that
//! author that finds a pending op completes it: it PUTs the same signed bytes
//! (an op key is immutable and the bytes are identical, so this is idempotent
//! against the original PUT, whenever that lands) and chains to it. The chain
//! then holds that op on every path, so no late PUT can fork it. The cost is
//! that an op whose append was reported as failed, or whose writer died, still
//! lands; the failed write's caller is told its outcome is unknown, not that it
//! failed.
//!
//! # What is closed, and what is emphatically not
//!
//! Closed: two or more processes of this build on ONE machine sharing one state
//! directory, under one author key or several: the routine case this product's
//! own registration model produces.
//!
//! Not closed: the same identity writing from two MACHINES. Nothing local can see
//! the other machine, and closing it needs a compare-and-swap the store does not
//! use. The console sub-key onboarding is the answer there, because it gives
//! each machine a distinct author key and so removes the shared chain entirely.
//!
//! A machine whose state directory does not resolve, or whose lock file cannot be
//! opened or locked at all, degrades to the previous behaviour (unserialized, fork
//! possible) with a warning the caller reports. A peer holding the lock past
//! [`ACQUIRE_TIMEOUT`] does NOT degrade: the write fails with
//! [`MemError::WriterLockBusy`] before anything is appended. Minting without the
//! lock while a live peer holds it forks the chain against that peer's write,
//! and the fork can drop either side, so an acknowledged write could vanish. A
//! retryable error the caller sees is the better product.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::domain::Blake3Hash;
use crate::error::MemError;
use crate::oplog::{Op, VerifyingKey};

/// Version tag written into this build's tip file. A file with another version
/// is read as holding no entries (warned) and set aside before it is replaced,
/// as an undecodable one is: a local file must never be able to brick the write
/// path, and the copy keeps what it held.
const TIP_FILE_VERSION: u32 = 2;

/// The version 0.7.1 and earlier read and write in the legacy tip file.
const LEGACY_TIP_FILE_VERSION: u32 = 1;

/// How long [`WriterLock::acquire`] waits for a peer to finish before failing the
/// write with [`MemError::WriterLockBusy`].
///
/// The critical section it waits on holds an op-log append and a head publish:
/// two gateway round trips, each hundreds of milliseconds on the Hippius gateway,
/// plus small local file writes. So one peer normally holds the lock for well
/// under 2 s, and queueing behind a handful of concurrent agent sessions stays
/// under 10 s. 30 s is three times that queue (the 0.7.1 value, 10 s, failed a
/// writer behind a gateway at about 5 s per PUT), and stays well below the
/// minutes an MCP client waits for a tool call. Chosen by that arithmetic, not
/// measured.
///
/// Deliberately not derived from the S3 timeouts: a peer stuck on a hung gateway
/// can hold the lock for about a minute per request (`S3_FIRST_BYTE_TIMEOUT`
/// times three attempts, plus backoff), and a waiter that outlasted it would only
/// hang on the same gateway next. Failing the waiter at 30 s with an error that
/// names the slow-gateway case is the more useful answer.
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(30);

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
/// NOT the highest Lamport observed across the team: the two differ whenever a
/// teammate is ahead, and comparing against the wrong one would either adopt a
/// stale tip or refuse a fresh one.
///
/// Also the shape of the legacy (version 1) file's single tip, so the bytes this
/// build writes there are the ones 0.7.1 parses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SharedTip {
    /// Lamport value of the op this tip names.
    pub(crate) lamport: u64,
    /// [`Op::hash`] of that op: the next op's `prev_op_hash`.
    pub(crate) tip_hash: Blake3Hash,
}

/// One author's entry in the tip file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AuthorTip {
    /// The newest op this machine knows is durable. `lamport: 0` with
    /// [`GENESIS_PREV`](super::GENESIS_PREV) means "no op yet".
    pub(crate) committed: SharedTip,
    /// The signed op being appended when the entry was last written, if its
    /// outcome was never recorded. See the module docs.
    pub(crate) pending: Option<Op>,
}

/// This build's tip file: a version tag, what the legacy file
/// held after this build's last write, and one entry per author key.
#[derive(Debug, Serialize, Deserialize)]
struct TipFile {
    /// Always [`TIP_FILE_VERSION`] when written by this build.
    version: u32,
    /// The legacy file's tip as this build last left it, `None` when it had
    /// none. A different value now means an older process wrote it since.
    legacy_tip: Option<SharedTip>,
    /// Each author's entry, keyed by the author's public key (hex on disk).
    authors: HashMap<VerifyingKey, AuthorTip>,
}

/// Just the version tag, read first so another version is recognised instead
/// of reported as undecodable.
#[derive(Debug, Deserialize)]
struct TipFileVersion {
    version: u32,
}

/// The legacy file's shape, exactly as 0.7.1 reads and writes it.
#[derive(Debug, Serialize, Deserialize)]
struct LegacyTipFile {
    version: u32,
    tip: SharedTip,
}

/// What the tip files held when read under the lock.
#[derive(Debug, Default)]
pub(crate) struct TipSnapshot {
    /// Each author's entry.
    pub(crate) authors: HashMap<VerifyingKey, AuthorTip>,
    /// Whether a process that does not write this build's file (0.7.1 or
    /// earlier) wrote the legacy file since this build last did.
    pub(crate) legacy_written_by_older_build: bool,
}

/// The advisory write lock for one team profile on one machine, and the tip
/// files it guards.
///
/// Constructed by the binary, which owns every path decision; this crate performs
/// no environment or XDG lookup of its own, the same division
/// [`HeadWatermarks`](super::HeadWatermarks) uses.
#[derive(Debug)]
pub struct WriterLock {
    /// The `flock` target. Its CONTENT is never read or written: only the inode
    /// matters. Deliberately a different file from the tip files, because those
    /// are replaced by an atomic temp+rename, which swaps the inode and would
    /// leave every waiter holding a lock on a file nobody else can see.
    lock_path: PathBuf,
    /// Where this build's [`TipFile`] for one storage location is persisted.
    tip_path: PathBuf,
    /// The version-1 file 0.7.1 reads and writes; kept current for it.
    legacy_tip_path: PathBuf,
    /// How long `acquire` waits for a peer. [`ACQUIRE_TIMEOUT`] outside tests.
    acquire_timeout: Duration,
}

/// Proof that the caller holds the cross-process write lock.
///
/// The tip accessors live here rather than on [`WriterLock`] so "only under the
/// lock" is a type-level fact instead of a doc-comment precondition. Reading the
/// tip outside the lock would race a peer's write of it, which is the whole
/// failure this module exists to remove.
///
/// The lock is released when this is dropped, including on a crash, since the OS
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
    /// Build the lock over `lock_path`, with this build's tip file at `tip_path`
    /// and the file older builds use at `legacy_tip_path`.
    ///
    /// `tip_path` should be distinct per storage location (endpoint and bucket):
    /// see the module docs.
    #[must_use]
    pub fn new(lock_path: PathBuf, tip_path: PathBuf, legacy_tip_path: PathBuf) -> Self {
        Self {
            lock_path,
            tip_path,
            legacy_tip_path,
            acquire_timeout: ACQUIRE_TIMEOUT,
        }
    }

    /// A lock that gives up after `timeout`, so a test of the busy path does not
    /// wait the production 30 s.
    #[cfg(test)]
    pub(crate) fn with_acquire_timeout(mut self, timeout: Duration) -> Self {
        self.acquire_timeout = timeout;
        self
    }

    /// Take the lock, waiting up to [`ACQUIRE_TIMEOUT`] for a peer to release it.
    ///
    /// `Ok(None)` means "proceed unserialized": the lock file could not be
    /// created, opened or locked at all (no peer is known to hold it). That case
    /// is warned here, and the caller reports it with the write's result.
    ///
    /// # Errors
    ///
    /// [`MemError::WriterLockBusy`] when a peer held the lock for the whole wait.
    /// Nothing has been written at that point, so the caller can retry.
    pub(crate) async fn acquire(&self) -> Result<Option<WriterLockGuard<'_>>, MemError> {
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
                return Ok(None);
            }
        };

        let deadline = tokio::time::Instant::now() + self.acquire_timeout;

        loop {
            match file.try_lock() {
                Ok(()) => {
                    return Ok(Some(WriterLockGuard {
                        _file: file,
                        lock: self,
                    }));
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
                    return Ok(None);
                }
            }

            if tokio::time::Instant::now() >= deadline {
                return Err(MemError::WriterLockBusy {
                    path: self.lock_path.clone(),
                    waited: self.acquire_timeout,
                });
            }

            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    /// Open (creating if absent) the `flock` target.
    ///
    /// Never truncates: the content is meaningless, so clearing it would be
    /// pointless I/O on the common already-exists path, the same reasoning
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
    /// What the tip files hold now.
    ///
    /// An unusable file is warned and read as holding no entries rather than
    /// surfaced: the caller then falls back to the author's published head.
    /// Erroring instead would let anyone able to corrupt one local file stop the
    /// machine writing.
    pub(crate) fn snapshot(&self) -> TipSnapshot {
        let file = match read_tip_file(&self.lock.tip_path) {
            Ok(file) => file,
            Err(reason) => {
                tracing::warn!(
                    path = %self.lock.tip_path.display(),
                    %reason,
                    "ignoring the writer tip file for this write; this author's published head \
                     is used instead"
                );
                None
            }
        };
        let Some(file) = file else {
            return TipSnapshot::default();
        };

        let legacy_now = read_legacy_tip(&self.lock.legacy_tip_path);
        TipSnapshot {
            legacy_written_by_older_build: legacy_now != file.legacy_tip,
            authors: file.authors,
        }
    }

    /// Replace `author`'s entry with `tip`, keeping every other author's entry.
    ///
    /// A committed entry (no pending op) is also written to the legacy file
    /// when its Lamport is above the one there, 0.7.1's own rule, so a 0.7.1
    /// process under this seed chains to it. A failure there is warned: the
    /// legacy file serves only older builds.
    ///
    /// The read-modify-write is safe because only a lock holder writes the
    /// files. Both are replaced atomically; this build's file is also fsynced
    /// with its directory, so a recorded pending op survives a power loss.
    ///
    /// # Errors
    ///
    /// [`MemError::WriterTip`] if this build's tip file cannot be written.
    pub(crate) fn record(&self, author: VerifyingKey, tip: AuthorTip) -> Result<(), MemError> {
        let lock = self.lock;
        let mut authors = match read_tip_file(&lock.tip_path) {
            Ok(file) => file.map(|file| file.authors).unwrap_or_default(),
            Err(reason) => {
                set_aside(&lock.tip_path, &reason);
                HashMap::new()
            }
        };

        let legacy_tip = if tip.pending.is_none() {
            write_legacy_tip(&lock.legacy_tip_path, tip.committed)
        } else {
            read_legacy_tip(&lock.legacy_tip_path)
        };
        authors.insert(author, tip);

        let file = TipFile {
            version: TIP_FILE_VERSION,
            legacy_tip,
            authors,
        };
        let write = serde_json::to_vec(&file)
            .map_err(std::io::Error::other)
            .and_then(|bytes| {
                crate::atomic_file::write_durably(&lock.tip_path, ".writer-tip-", ".tmp", &bytes)
            });
        write.map_err(|source| MemError::WriterTip {
            path: lock.tip_path.clone(),
            source,
        })
    }
}

/// This build's tip file at `path`: `Ok(None)` when it does not exist, `Err`
/// with the reason when it exists but cannot be used.
fn read_tip_file(path: &Path) -> Result<Option<TipFile>, String> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        // Never written: the normal first-write state, and not a fault.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(format!("cannot read it: {err}")),
    };

    match serde_json::from_slice::<TipFileVersion>(&bytes) {
        Ok(probe) if probe.version == TIP_FILE_VERSION => {}
        Ok(probe) => {
            return Err(format!(
                "it carries version {}, and this build reads version {TIP_FILE_VERSION}",
                probe.version
            ));
        }
        Err(err) => return Err(format!("it does not decode: {err}")),
    }

    serde_json::from_slice::<TipFile>(&bytes)
        .map(Some)
        .map_err(|err| format!("it does not decode: {err}"))
}

/// Move an unusable tip file to `{path}.unusable` (replacing an older copy)
/// before it is rewritten, so the entries it may still hold are kept for
/// inspection instead of silently overwritten.
fn set_aside(path: &Path, reason: &str) {
    let mut aside = path.as_os_str().to_owned();
    aside.push(".unusable");
    match std::fs::rename(path, &aside) {
        Ok(()) => tracing::warn!(
            path = %path.display(),
            moved_to = %Path::new(&aside).display(),
            reason,
            "the writer tip file was unusable and has been set aside; this write starts a new one"
        ),
        Err(err) => tracing::warn!(
            path = %path.display(),
            reason,
            error = %err,
            "the writer tip file was unusable and could not be set aside; this write replaces it"
        ),
    }
}

/// The legacy file's tip, or `None` when it is absent or unusable. Never
/// warned: the file belongs to older builds, and this one only compares it.
fn read_legacy_tip(path: &Path) -> Option<SharedTip> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice::<LegacyTipFile>(&bytes)
        .ok()
        .filter(|file| file.version == LEGACY_TIP_FILE_VERSION)
        .map(|file| file.tip)
}

/// Write `tip` to the legacy file when its Lamport is above the one there, and
/// return what the file holds afterwards.
fn write_legacy_tip(path: &Path, tip: SharedTip) -> Option<SharedTip> {
    let current = read_legacy_tip(path);
    if current.is_some_and(|current| current.lamport >= tip.lamport) {
        return current;
    }

    let file = LegacyTipFile {
        version: LEGACY_TIP_FILE_VERSION,
        tip,
    };
    let write = serde_json::to_vec(&file)
        .map_err(std::io::Error::other)
        .and_then(|bytes| {
            crate::atomic_file::write_atomically(path, ".writer-tip-legacy-", ".tmp", &bytes)
        });
    match write {
        Ok(()) => Some(tip),
        Err(err) => {
            tracing::warn!(
                path = %path.display(),
                error = %err,
                "could not update the legacy writer tip file that hippius-mem 0.7.1 and earlier \
                 read; an older process on this machine may fork this author's chain"
            );
            current
        }
    }
}

/// The directory a path lives in, treating a bare filename as the current one.
fn parent_dir(path: &Path) -> Option<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
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
        WriterLock::new(
            dir.join("writer.lock"),
            dir.join("writer-tip-v2-test.json"),
            dir.join("writer-tip.json"),
        )
    }

    fn shared(lamport: u64) -> SharedTip {
        SharedTip {
            lamport,
            tip_hash: crate::crypto::content_hash(&lamport.to_le_bytes()),
        }
    }

    fn tip(lamport: u64) -> AuthorTip {
        AuthorTip {
            committed: shared(lamport),
            pending: None,
        }
    }

    /// 0.7.1's reader, field for field: what it decodes from the legacy file.
    #[derive(Deserialize)]
    struct V071TipFile {
        version: u32,
        tip: SharedTip,
    }

    fn read_as_v071(dir: &Path) -> Result<V071TipFile, Box<dyn std::error::Error>> {
        Ok(serde_json::from_slice(&std::fs::read(
            dir.join("writer-tip.json"),
        )?)?)
    }

    #[tokio::test]
    async fn each_author_reads_back_only_its_own_entry() -> TestResult {
        let dir = tempfile::tempdir()?;
        let lock = lock_in(dir.path());
        let alice = VerifyingKey::new([1; 32]);
        let bob = VerifyingKey::new([2; 32]);

        let guard = lock.acquire().await?.ok_or("lock must be available")?;
        guard.record(alice, tip(3))?;
        guard.record(bob, tip(7))?;

        let authors = guard.snapshot().authors;
        assert_eq!(authors.get(&alice), Some(&tip(3)));
        assert_eq!(authors.get(&bob), Some(&tip(7)));
        assert_eq!(authors.get(&VerifyingKey::new([3; 32])), None);
        Ok(())
    }

    /// 0.7.1 reads only the legacy file, so a committed tip must land there in
    /// the exact shape 0.7.1 decodes, and only when it is newer, as 0.7.1 itself
    /// writes it. A pending record must not touch it.
    #[tokio::test]
    async fn a_committed_tip_is_written_where_0_7_1_reads_it() -> TestResult {
        let dir = tempfile::tempdir()?;
        let lock = lock_in(dir.path());
        let alice = VerifyingKey::new([1; 32]);
        let guard = lock.acquire().await?.ok_or("lock must be available")?;

        guard.record(alice, tip(4))?;
        let v071 = read_as_v071(dir.path())?;
        assert_eq!(v071.version, 1);
        assert_eq!(v071.tip, shared(4));

        guard.record(alice, tip(2))?;
        assert_eq!(read_as_v071(dir.path())?.tip, shared(4), "never moved back");

        let pending = AuthorTip {
            committed: shared(4),
            pending: Some(crate::oplog::test_support::signed_op(5)),
        };
        guard.record(alice, pending.clone())?;
        assert_eq!(
            read_as_v071(dir.path())?.tip,
            shared(4),
            "pending is not durable"
        );
        assert_eq!(guard.snapshot().authors.get(&alice), Some(&pending));
        Ok(())
    }

    /// A legacy file that changed after this build's last write was written by
    /// an older build; the flag clears once this build writes again.
    #[tokio::test]
    async fn a_legacy_write_by_an_older_build_is_noticed() -> TestResult {
        let dir = tempfile::tempdir()?;
        let lock = lock_in(dir.path());
        let alice = VerifyingKey::new([1; 32]);
        let guard = lock.acquire().await?.ok_or("lock must be available")?;

        guard.record(alice, tip(4))?;
        assert!(!guard.snapshot().legacy_written_by_older_build);

        let hash = GENESIS_PREV.to_hex();
        std::fs::write(
            dir.path().join("writer-tip.json"),
            format!(r#"{{"version":1,"tip":{{"lamport":9,"tip_hash":"{hash}"}}}}"#),
        )?;
        let seen = guard.snapshot();
        assert!(seen.legacy_written_by_older_build);
        assert_eq!(seen.authors.get(&alice), Some(&tip(4)), "entries survive");

        guard.record(alice, tip(10))?;
        assert!(!guard.snapshot().legacy_written_by_older_build);
        Ok(())
    }

    /// A version-1 file names no author, so this build never reads it as anyone's
    /// entry, before or after its own file exists.
    #[tokio::test]
    async fn a_legacy_tip_is_never_read_as_an_entry() -> TestResult {
        let dir = tempfile::tempdir()?;
        let lock = lock_in(dir.path());
        let hash = GENESIS_PREV.to_hex();
        std::fs::write(
            dir.path().join("writer-tip.json"),
            format!(r#"{{"version":1,"tip":{{"lamport":9,"tip_hash":"{hash}"}}}}"#),
        )?;

        let guard = lock.acquire().await?.ok_or("lock must be available")?;
        let seen = guard.snapshot();
        assert!(seen.authors.is_empty());
        Ok(())
    }

    /// An unusable file reads as empty, and the next record sets it aside before
    /// replacing it, so its bytes are not lost.
    #[tokio::test]
    async fn a_corrupt_file_is_read_as_empty_and_set_aside() -> TestResult {
        let dir = tempfile::tempdir()?;
        let lock = lock_in(dir.path());
        let path = dir.path().join("writer-tip-v2-test.json");
        std::fs::write(&path, b"{not json")?;

        let guard = lock.acquire().await?.ok_or("lock must be available")?;
        assert!(guard.snapshot().authors.is_empty());

        guard.record(VerifyingKey::new([1; 32]), tip(1))?;
        assert_eq!(
            std::fs::read(dir.path().join("writer-tip-v2-test.json.unusable"))?,
            b"{not json"
        );
        assert_eq!(guard.snapshot().authors.len(), 1);
        Ok(())
    }

    /// A file of another version is read as empty, never as this build's shape.
    #[tokio::test]
    async fn another_version_is_read_as_empty() -> TestResult {
        let dir = tempfile::tempdir()?;
        let lock = lock_in(dir.path());
        std::fs::write(
            dir.path().join("writer-tip-v2-test.json"),
            br#"{"version":3,"authors":{}}"#,
        )?;

        let guard = lock.acquire().await?.ok_or("lock must be available")?;
        assert!(guard.snapshot().authors.is_empty());
        Ok(())
    }

    /// The write that records a pending op fails loudly when the tip file cannot
    /// be replaced, which the store turns into a refused write.
    #[tokio::test]
    async fn an_unwritable_tip_file_is_a_typed_error() -> TestResult {
        let dir = tempfile::tempdir()?;
        // A regular file where the tip file's directory should be, so neither
        // the temp file nor the rename can be created.
        std::fs::write(dir.path().join("state"), b"")?;
        let lock = WriterLock::new(
            dir.path().join("writer.lock"),
            dir.path().join("state/writer-tip-v2-test.json"),
            dir.path().join("writer-tip.json"),
        );

        let guard = lock.acquire().await?.ok_or("lock must be available")?;
        let err = guard
            .record(VerifyingKey::new([1; 32]), tip(1))
            .err()
            .ok_or("recording under a file must fail")?;
        assert!(
            matches!(&err, MemError::WriterTip { path, .. } if path.ends_with("writer-tip-v2-test.json")),
            "got {err:?}"
        );
        Ok(())
    }

    /// A peer holding the lock past the timeout fails the acquire with a typed
    /// error naming the lock file. `flock` locks belong to the open file
    /// description, so a second open in this same process contends like a peer.
    #[tokio::test]
    async fn a_held_lock_times_out_with_a_typed_error() -> TestResult {
        let dir = tempfile::tempdir()?;
        let lock = lock_in(dir.path()).with_acquire_timeout(Duration::from_millis(100));
        let peer = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.path().join("writer.lock"))?;
        peer.lock()?;

        let err = lock
            .acquire()
            .await
            .err()
            .ok_or("a held lock must not be granted")?;
        assert!(
            matches!(&err, MemError::WriterLockBusy { path, waited } if path == &dir.path().join("writer.lock") && *waited == Duration::from_millis(100)),
            "expected WriterLockBusy naming the lock file and the wait, got {err:?}"
        );
        assert!(err.to_string().contains("100ms"), "{err}");

        drop(peer);
        assert!(
            lock.acquire().await?.is_some(),
            "a released lock is granted"
        );
        Ok(())
    }
}
