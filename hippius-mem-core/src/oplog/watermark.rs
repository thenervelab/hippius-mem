//! A LOCAL high-water mark over each author's signed head pointer — the one
//! input to the tail-truncation check that the untrusted bucket does not
//! control.
//!
//! # Why local state is the only way to close this
//!
//! [`crate::oplog::head`] makes each author publish a signed [`HeadPointer`]
//! naming their current chain tip, and [`crate::audit::reconcile`] reports an
//! author whose head names a tip the visible op-log cannot produce. That turned
//! tail truncation into an act that requires a SECOND step by the bucket, but it
//! did not make it detectable, because every input to that comparison still comes
//! from the bucket:
//!
//! - drop the head object entirely — an author with ops and no head makes no
//!   claim, so there is nothing left to contradict;
//! - serve an OLDER, still-validly-signed head — it verifies, and its claimed tip
//!   IS present in the truncated view.
//!
//! Both are silent against any bucket-only check, however carefully written. What
//! contradicts them is a record of what this machine ALREADY SAW: if we verified a
//! head at Lamport 9 last week and the bucket now serves Lamport 4, or none at
//! all, the bucket has moved a signed claim backward. [`HeadWatermarks`] is that
//! record, kept in a local file, and [`HeadRegression`] is the evidence it
//! produces.
//!
//! # The limit, stated plainly
//!
//! This protects a RETURNING machine and nothing else. A machine that has never
//! verified the newer head has no mark to compare against, so the same rollback is
//! accepted cleanly and silently — that is [`HeadWatermarks::observe`]'s cold
//! case, and it is deliberately NOT reported, because "I have never seen this
//! author before" is the normal state of every first sync. No amount of local
//! state fixes that: the knowledge simply is not on this machine. A fresh clone,
//! a new teammate, a wiped laptop and a fresh container all start blind.
//!
//! Nor does this cover the third residual [`crate::audit::SuppressedTail`]
//! documents: publishing the head is best-effort, so a publish that FAILED leaves
//! the previous tip named. That is not a bucket action, the served head never went
//! backward, and a high-water mark cannot see it. Advancing this machine's own
//! mark only after a publish actually succeeds (see
//! `HeadWatermarks::record_published_head`) is what keeps that honest case from
//! being misreported as a rollback.
//!
//! # The local-attacker boundary
//!
//! An attacker who can WRITE this file can delete it, lower a mark, or plant a
//! high one — disabling the check or manufacturing a false regression. That is out
//! of scope by construction: this file lives beside the process doing the
//! verifying, so an attacker with local write access already controls the verifier
//! itself, and could equally patch the binary or read the team key. The threat
//! this closes is a hostile BUCKET, which by definition cannot reach local disk.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use serde::{Deserialize, Serialize};

use crate::domain::{Blake3Hash, Ss58};
use crate::error::MemError;
use crate::identity::ss58_encode;
use crate::oplog::head::{HeadPointer, VerifiedHeads};
use crate::oplog::op::{HIPPIUS_SS58_PREFIX, VerifyingKey};

/// On-disk format version for the watermark file.
///
/// Tagged rather than inferred so a file written by a FUTURE format is refused by
/// name instead of being half-parsed into a lower mark — a silently lowered bar is
/// exactly the failure this whole module exists to notice.
const WATERMARK_FILE_VERSION: u32 = 1;

/// The highest head this machine has verified for one author.
///
/// Module-private: it is the file record and the map value, never part of the
/// evidence a caller reads. [`HeadRegression`] carries the two fields that matter
/// (`remembered_lamport`, `remembered_tip`) inline, so nothing outside needs this
/// type and no caller can construct a mark that never passed through a verified
/// head read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HeadWatermark {
    /// The author whose head this mark remembers.
    author_key: VerifyingKey,
    /// The Lamport time of the highest head verified for that author.
    lamport: u64,
    /// The chain tip that head named.
    tip_hash: Blake3Hash,
}

/// The whole watermark file: a version tag plus one mark per author.
///
/// A `Vec` rather than a JSON object keyed by hex, because each mark already
/// carries its own `author_key` — a keyed object would store the key twice and
/// admit a file whose key and value disagree.
#[derive(Debug, Serialize, Deserialize)]
struct WatermarkFile {
    /// Always [`WATERMARK_FILE_VERSION`] when written by this build.
    version: u32,
    /// One mark per author, in ascending `author_key` byte order.
    marks: Vec<HeadWatermark>,
}

/// An author whose served head has moved BACKWARD relative to the highest head
/// this machine had already verified — or has vanished entirely.
///
/// # What one of these proves, and what it does not
///
/// It proves that this machine verified a head for `author_key` at
/// `remembered_lamport` naming `remembered_tip`, and that the bucket now serves
/// either nothing verifiable for that author or a head that is not at or above
/// that mark. The remembered head was signed, so the BUCKET cannot have fabricated
/// the higher claim — the holder of that secret key published it.
///
/// # It does NOT follow that the bucket withdrew anything
///
/// Only the key-holder can SIGN a head. The key-holder can also publish a LOWER
/// one, and two ordinary situations do exactly that, both producing this evidence
/// against a perfectly honest identity:
///
/// - **Two processes under one identity, racing their head PUTs.**
///   `MemoryStore::writer` is a per-INSTANCE `tokio::sync::Mutex`, so it serializes
///   head PUTs within ONE process only (its own doc says so under "Identity
///   reuse"), and [`publish_head`](crate::oplog::publish_head) is an unconditional
///   PUT to the one mutable key with no precondition or compare-and-swap. MCP
///   registration is user-global, so every agent session boots a server off the
///   same config and therefore the SAME identity — concurrent processes are the
///   normal operating mode here, not an exotic misconfiguration. If P1 appends at
///   Lamport 10 and its head PUT is still in flight while P2 syncs, appends 11 and
///   publishes head(11), P1's PUT lands afterwards and moves the SERVED head back
///   to 10. Every op is present, `suppressed_tails` is empty, and there is nothing
///   in the bucket for an operator to find. It clears on the next write above 11.
/// - **A restarted process re-seeding against an incomplete view.** A fresh process
///   rebuilds its clock from the visible log. If that view is short — a truncation,
///   or merely a listing that has not caught up — it mints a genuinely lower
///   Lamport and publishes a fresh, current, author-signed head below the persisted
///   mark. The served object is BRAND NEW, not a withdrawn one, so an operator sent
///   looking for a rolled-back object finds nothing. This variant is not
///   necessarily benign: if the short view was a truncation, the regression is a
///   true detection that merely names the wrong artifact.
///
/// So a regression means "the served head is below what this machine verified" and
/// nothing stronger. Do not fix this by exempting our own author key: that would
/// discard the case where the bucket rolls back OUR head, which is the point.
///
/// It also does NOT prove that any op was suppressed. Whether the ops the
/// remembered head named are still readable is a separate question that
/// [`crate::audit::ReconcileReport::suppressed_tails`] answers. The two vectors are
/// independent and either can fire alone.
///
/// # The other benign causes
///
/// A team re-created from scratch under the SAME name and the same author identity
/// legitimately restarts at a lower Lamport, and this machine's mark from the
/// previous incarnation then outranks every head the new one publishes. The mark
/// file is keyed on the TEAM NAME alone, so the same name pointed at a restored
/// backup, a staging mirror, or a different endpoint has the same effect. The
/// remedy for all of these is the same: delete the state file for that team. There
/// is no way for this check to tell any of them apart from a rollback, because at
/// the level of signed objects they are the same event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadRegression {
    /// The SS58 of the author whose head regressed.
    ///
    /// DERIVED from `author_key` under the Hippius network prefix, never stored
    /// beside it: [`crate::oplog::HeadPointer::verify_identity`] already proved the
    /// two agree for every head that reached the watermark, so re-deriving
    /// reproduces exactly the address that was verified — and leaves no second
    /// copy in the local file that could be edited to attribute a regression to the
    /// wrong identity.
    pub author: Ss58,
    /// The sr25519 public key whose signed head this machine remembered.
    pub author_key: VerifyingKey,
    /// The Lamport time of the highest head this machine had already verified.
    pub remembered_lamport: u64,
    /// The chain tip that remembered head named.
    pub remembered_tip: Blake3Hash,
    /// The Lamport the bucket serves for this author now.
    ///
    /// `None` means the read produced NO VERIFIABLE head for this author — the
    /// object is absent, or [`crate::oplog::read_heads`] skipped it as malformed,
    /// mis-signed, misattributed or planted outside its own key path. Those are one
    /// case here because they are one fact: the author's claim is no longer
    /// available. The `read_heads` warn distinguishes them in the log.
    pub served_lamport: Option<u64>,
    /// The chain tip the bucket serves for this author now, `None` in exactly the
    /// cases `served_lamport` is `None`.
    pub served_tip: Option<Blake3Hash>,
}

/// This machine's memory of the highest head it has verified per author,
/// persisted to a local file.
///
/// # Interior mutability, and why the API takes `&self`
///
/// [`observe`](Self::observe) and
/// `record_published_head` both MUTATE the marks,
/// yet take `&self`: the store holds this behind an `Arc` and calls it from
/// `&self` write paths, and `reconcile_with_watermarks` receives it as a shared
/// borrow. A `std::sync::Mutex` guards the map; its guard is never held across an
/// `.await` (every write here is synchronous `std::fs`, for the reason
/// `CachingBlobStore::read_cache` documents: these are tiny local files whose I/O
/// is microseconds beside the gateway round-trips around them, so a
/// `spawn_blocking` hop per call would buy nothing).
#[derive(Debug)]
pub struct HeadWatermarks {
    /// Where the marks are persisted. Chosen by the binary — this crate performs
    /// no environment or XDG lookup of its own.
    path: PathBuf,
    /// The marks, keyed by raw author-key bytes.
    ///
    /// A `BTreeMap` over the raw bytes rather than a `HashMap<VerifyingKey, _>`:
    /// the evidence built from it must read identically on every machine, and a
    /// `HashMap`'s iteration order would let the regression list for a dropped head
    /// come out shuffled. Keyed on `[u8; 32]` because [`VerifyingKey`] is
    /// deliberately not `Ord`, the same accommodation `read_anchor_records` makes.
    marks: Mutex<BTreeMap<[u8; 32], HeadWatermark>>,
}

impl HeadWatermarks {
    /// Load the marks persisted at `path`, or start empty.
    ///
    /// Infallible on purpose. A missing file is the normal first-run state and is
    /// silent. A file that cannot be read, cannot be decoded, or carries a version
    /// this build does not understand is WARNED and treated as empty — never an
    /// error, because a local file must not be able to brick `reconcile`: an
    /// attacker who could make this file undecodable would otherwise be able to
    /// stop the audit from running at all, which is strictly worse than losing the
    /// one check the file backs. Starting empty costs exactly the protection this
    /// module offers and nothing else; the marks repopulate from the next verified
    /// head read.
    ///
    /// Treating an unreadable file as empty also means this check can be disabled
    /// by anyone who can write local disk. See the module docs for why that is out
    /// of scope.
    #[must_use]
    pub fn load(path: PathBuf) -> Self {
        let marks = match std::fs::read(&path) {
            Ok(bytes) => decode_marks(&path, &bytes),
            // A never-written file is the first run, not a fault.
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(err) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %err,
                    "could not read the local head-watermark file; continuing with no remembered \
                     heads, so a head the bucket rolls back or drops will NOT be reported as a \
                     regression until this machine has verified a head again"
                );
                BTreeMap::new()
            }
        };

        Self {
            path,
            marks: Mutex::new(marks),
        }
    }

    /// Compare `heads` against what this machine remembers, then advance the marks
    /// — in that order — and persist if anything moved.
    ///
    /// # What advances, and what never does — this is the load-bearing part
    ///
    /// A mark advances only to a head AT OR ABOVE it (`advance_to`). A regressing
    /// head never advances anything, so a single hostile read cannot lower this
    /// machine's bar and be believed on the second read. An author with no mark yet
    /// is recorded and is never a regression: that is the cold case, the documented
    /// blind spot, and reporting it would make every first sync accuse the whole
    /// team.
    ///
    /// The comparison also completes before any mark is touched, but be precise
    /// about why that matters: with the at-or-above guard in place, reordering the
    /// two phases changes NOTHING — the guard already refuses to overwrite a higher
    /// mark with a lower head, so the comparison sees the same map either way. This
    /// was verified by mutation rather than assumed: swapping the phases fails no
    /// test, while removing the guard fails the never-lowers-the-mark tests, and
    /// removing BOTH is what makes a live rollback go unreported. So the ordering is
    /// defence in depth against a future change that relaxes the guard, not the
    /// protection itself. Do not let it be described as the mechanism.
    ///
    /// # Feeding it
    ///
    ///
    /// Takes the [`VerifiedHeads`] witness rather than a slice for two reasons.
    /// A [`HeadRegression`] names an identity, so the comparison must not be
    /// feedable with claims that never passed a signature check; and, more
    /// sharply, an unverified head could RAISE a mark, which would let anyone able
    /// to plant one object under the heads prefix poison this machine into
    /// reporting a permanent, unclearable regression against an honest author.
    pub fn observe(&self, heads: &VerifiedHeads) -> Vec<HeadRegression> {
        let mut marks = self.marks.lock().unwrap_or_else(PoisonError::into_inner);
        let outcome = compare_then_advance(&mut marks, heads);

        if outcome.advanced {
            self.persist(&marks);
        }

        outcome.regressions
    }

    /// Advance this machine's mark for its OWN author to `head`, which must
    /// already have been published successfully.
    ///
    /// # Call this only after the publish succeeded
    ///
    /// The head publish is best-effort (see
    /// `MemoryStore::publish_head_for_tip`): it is warned and swallowed on
    /// failure, because the op is already durable and failing a write over a
    /// redundant pointer would be worse. Advancing this mark on a publish that did
    /// NOT land would leave this machine remembering a head the bucket never
    /// received, and the very next `reconcile` would report a head regression
    /// against our own honest identity over a dropped PUT. Advancing only after
    /// success keeps this machine's mark at or below the head the bucket actually
    /// holds, by construction rather than by luck.
    ///
    /// # `pub(crate)`, and why the visibility is the enforcement
    ///
    /// Unlike [`observe`](Self::observe) this takes a bare [`HeadPointer`], not a
    /// [`VerifiedHeads`] witness — every field of a `HeadPointer` is public and
    /// both types are re-exported at the crate root, so a caller outside this crate
    /// could hand over an unsigned, arbitrarily high head. That would RAISE a mark
    /// from a claim nobody signed, and the result is a permanent, unclearable
    /// regression against an honest author: exactly the laundering `observe`'s
    /// witness type exists to prevent, which a doc-comment precondition would not
    /// stop. The single in-tree caller (`MemoryStore::publish_head_for_tip`) hands
    /// over a head this machine's own signer just minted and the bucket just
    /// accepted, so no verification step is being skipped there — but nothing about
    /// the signature enforces that, so the reach is narrowed to the crate instead.
    pub(crate) fn record_published_head(&self, head: &HeadPointer) {
        let mut marks = self.marks.lock().unwrap_or_else(PoisonError::into_inner);

        if advance_to(&mut marks, head) {
            self.persist(&marks);
        }
    }

    /// Best-effort atomic write of the marks to [`Self::path`].
    ///
    /// A failure is warned and swallowed. The alternative — surfacing it — would
    /// fail a write or an audit over a local bookkeeping file, and the in-memory
    /// marks are still correct for the rest of this process's life; only the
    /// cross-restart half of the protection lags until the next successful write.
    fn persist(&self, marks: &BTreeMap<[u8; 32], HeadWatermark>) {
        if let Err(err) = write_marks(&self.path, marks) {
            tracing::warn!(
                path = %self.path.display(),
                error = %err,
                "could not persist the local head-watermark file; this process still remembers \
                 the heads it has verified, but a restart will not, so a rollback the bucket \
                 performs after that restart would not be reported"
            );
        }
    }
}

/// Decode a watermark file's bytes into marks, warning and yielding an empty map
/// on anything unusable.
fn decode_marks(path: &Path, bytes: &[u8]) -> BTreeMap<[u8; 32], HeadWatermark> {
    let file: WatermarkFile = match serde_json::from_slice(bytes) {
        Ok(file) => file,
        Err(err) => {
            tracing::warn!(
                path = %path.display(),
                error = %err,
                "the local head-watermark file does not decode; treating it as absent, so a \
                 rolled-back or dropped head will not be reported until this machine has \
                 verified a head again"
            );
            return BTreeMap::new();
        }
    };

    if file.version != WATERMARK_FILE_VERSION {
        tracing::warn!(
            path = %path.display(),
            found_version = file.version,
            expected_version = WATERMARK_FILE_VERSION,
            "the local head-watermark file was written in a format this build does not \
             understand; treating it as absent rather than reading a partial, LOWER mark out \
             of it"
        );
        return BTreeMap::new();
    }

    // Fold duplicates with the same advance-only rule the live path uses, so a
    // hand-edited or concatenated file cannot lower a mark by listing an author
    // twice.
    let mut marks: BTreeMap<[u8; 32], HeadWatermark> = BTreeMap::new();
    for mark in file.marks {
        let key = *mark.author_key.as_bytes();
        match marks.get(&key) {
            Some(kept) if kept.lamport >= mark.lamport => {}
            Some(_) | None => {
                marks.insert(key, mark);
            }
        }
    }

    marks
}

/// Fold `marks` into whatever the file at `path` already holds, and replace it
/// atomically.
///
/// # Why this reads before it writes
///
/// Two processes share this file in normal use: a running `serve` session and a
/// one-shot `doctor` (or `report`, or an `import`) against the same team. Each
/// holds its own in-memory marks, so a blind overwrite lets the process with the
/// STALER map lower a mark the other had already raised — it advances one author,
/// writes its whole map, and every other author on disk silently drops back. The
/// direction of that loss is exactly the one this module exists to prevent.
///
/// Folding with the same advance-only rule makes the write monotonic in the
/// author dimension, so interleaved writers can no longer lower each other's
/// marks. It is not a lock: two writers can still read the same prior state and
/// the later rename wins, losing at most the other's single advance — which the
/// next read re-learns. It closes the systematic loss, not the last-writer race,
/// and no file lock is taken because a lock that a `doctor` run could block a
/// server on would be a worse trade.
///
/// The fold is written to disk only; the caller's in-memory map is left as this
/// process verified it. A mark another process raised therefore takes effect here
/// on the next load, not mid-process — the conservative direction (fewer reports),
/// and it keeps this process from ever accusing an author off a head it did not
/// itself verify.
///
/// # Atomicity
///
/// Writes to a `tempfile` temp in the destination directory and renames it into
/// place, so a crash or a concurrent writer never leaves a half-written file a
/// later load would warn about and discard. The temp is created with `O_EXCL`, a
/// unique random name and (on unix) mode `0600`, matching
/// [`FileManifestMarker::store`](crate::identity::FileManifestMarker) — the same
/// atomic-marker idiom, hardened against the symlink / pre-planted-temp class
/// (CWE-59 / CWE-377) that a fixed `.tmp` name is exposed to. The bytes are
/// fsynced before the rename so a crash cannot leave a renamed but empty file.
/// The directory entry is not fsynced, so a crash immediately after the rename may
/// still revert to the previous marks — acceptable for a watermark that only ever
/// lags on that window.
///
/// Synchronous `std::fs` inside async callers, deliberately, for the reason
/// `CachingBlobStore::read_cache` records: this is one tiny local file written at
/// most once per write or audit, against gateway round-trips measured in hundreds
/// of milliseconds.
///
/// # Errors
///
/// [`MemError::Serialize`] if the marks cannot be encoded, or [`MemError::Io`] if
/// the directory cannot be created or the temp cannot be written, fsynced or
/// renamed. A file that cannot be READ BACK for the fold is not an error — the
/// write proceeds from this process's marks alone — but it is WARNED, exactly as
/// [`HeadWatermarks::load`] warns on the same class. That is not cosmetic: a
/// momentarily unreadable file in a writable directory means every mark this
/// process does not itself hold is about to be dropped and a shorter map renamed
/// into place, which LOWERS the bar. Silently lowering the bar is the one outcome
/// this module must never produce without saying so.
fn write_marks(path: &Path, marks: &BTreeMap<[u8; 32], HeadWatermark>) -> Result<(), MemError> {
    let mut merged = match std::fs::read(path) {
        // `decode_marks` warns for itself on undecodable or future-format content.
        Ok(bytes) => decode_marks(path, &bytes),
        // No file yet: the normal first-write case, and nothing to preserve.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
        Err(err) => {
            tracing::warn!(
                path = %path.display(),
                error = %err,
                "could not read the local head-watermark file back before rewriting it; the \
                 marks this process holds are still written, but any mark only another process \
                 had recorded is dropped from the file, lowering the bar a later run compares \
                 against"
            );
            BTreeMap::new()
        }
    };
    for mark in marks.values() {
        match merged.get(mark.author_key.as_bytes()) {
            Some(on_disk) if on_disk.lamport >= mark.lamport => {}
            Some(_) | None => {
                merged.insert(*mark.author_key.as_bytes(), mark.clone());
            }
        }
    }

    let file = WatermarkFile {
        version: WATERMARK_FILE_VERSION,
        // `BTreeMap` iteration is ascending by author key, so the file is written
        // in a stable order and two runs that changed nothing produce identical
        // bytes.
        marks: merged.into_values().collect(),
    };
    let bytes = serde_json::to_vec(&file)?;

    // A bare filename (no parent) means the current directory.
    let dir = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    // The state directory is not created at startup — it is created on the first
    // write that needs it, so a machine that never writes leaves no empty tree.
    std::fs::create_dir_all(dir).map_err(MemError::Io)?;

    let mut tmp = tempfile::Builder::new()
        .prefix(".head-watermarks-")
        .suffix(".tmp")
        .tempfile_in(dir)
        .map_err(MemError::Io)?;
    tmp.write_all(&bytes).map_err(MemError::Io)?;
    tmp.as_file().sync_all().map_err(MemError::Io)?;
    tmp.persist(path).map_err(|err| MemError::Io(err.error))?;

    Ok(())
}

/// What one [`compare_then_advance`] pass produced.
struct Comparison {
    /// Every author whose served head is below the mark this machine held, or
    /// absent from the served set entirely.
    regressions: Vec<HeadRegression>,
    /// Whether any mark actually moved, so the caller can skip a pointless
    /// rewrite of an unchanged file.
    advanced: bool,
}

/// Whether `head` is at or above `remembered` — the ONLY direction a mark may
/// move, and the exact negation of the regression condition.
///
/// One predicate serves both the report and the advance rule so the two cannot
/// drift apart: anything that is not at-or-above is reported, and nothing that is
/// reported advances a mark.
///
/// Equal Lamport with a DIFFERENT tip is not at-or-above. It is a rewrite of the
/// same position, not a step forward: an author signs one tip per Lamport (the
/// Lamport comes from the op the tip names), so two heads sharing a Lamport and
/// differing in tip means the bucket is serving a different history at that
/// position than the one this machine already verified.
fn is_at_or_above(head: &HeadPointer, remembered: &HeadWatermark) -> bool {
    head.lamport > remembered.lamport
        || (head.lamport == remembered.lamport && head.tip_hash == remembered.tip_hash)
}

/// Advance `marks` to `head` if it is at or above the existing mark (or if there
/// is none yet), returning whether the map changed.
fn advance_to(marks: &mut BTreeMap<[u8; 32], HeadWatermark>, head: &HeadPointer) -> bool {
    let key = *head.author_key.as_bytes();
    match marks.get(&key) {
        // Below the mark, or a different tip at the same Lamport. NEVER advance on
        // this arm: letting a regressing head write the mark would mean one hostile
        // read permanently lowers this machine's bar, and the second read would
        // then find nothing wrong.
        Some(remembered) if !is_at_or_above(head, remembered) => false,
        // At-or-above with an equal Lamport can only be the identical head (the
        // predicate demands the same tip), so the map already holds it.
        Some(remembered) if remembered.lamport == head.lamport => false,
        Some(_) | None => {
            marks.insert(
                key,
                HeadWatermark {
                    author_key: head.author_key,
                    lamport: head.lamport,
                    tip_hash: head.tip_hash,
                },
            );
            true
        }
    }
}

/// Compare every remembered mark against the served heads, and only then advance.
///
/// Split out as a free function over a plain map so the comparison — the part that
/// decides whether an author is accused — is exercised in tests with no
/// filesystem, no bucket and no store.
fn compare_then_advance(
    marks: &mut BTreeMap<[u8; 32], HeadWatermark>,
    heads: &[HeadPointer],
) -> Comparison {
    // The served heads by author key. `read_heads` publishes one head per author
    // at one key, so a second entry for the same author cannot come back from a
    // verified read; if one somehow did, the last wins and the comparison below is
    // still made against a genuinely signed head.
    let served: BTreeMap<[u8; 32], &HeadPointer> = heads
        .iter()
        .map(|head| (*head.author_key.as_bytes(), head))
        .collect();

    // PHASE 1 — COMPARE, before a single mark is touched below.
    //
    // Be precise about what this ordering buys, because it is easy to overstate: on
    // its own it buys nothing. `advance_to`'s at-or-above guard already refuses to
    // overwrite a higher mark with a lower head, so with that guard intact the
    // comparison sees the same map whichever phase runs first — swapping these two
    // blocks fails no test in this crate. The GUARD is the protection. The ordering
    // is the second layer: if a later change relaxes the guard (say, to "always
    // record what the bucket last served"), comparing first still yields the
    // evidence for that read instead of silently deleting it. Keep both.
    let regressions: Vec<HeadRegression> = marks
        .values()
        .filter_map(
            |remembered| match served.get(remembered.author_key.as_bytes()) {
                // No verifiable head for an author we have a mark for: the claim this
                // machine already saw has been withdrawn.
                None => Some(regression(remembered, None)),
                // A head that is not at or above the mark: the claim moved backward.
                Some(head) if !is_at_or_above(head, remembered) => {
                    Some(regression(remembered, Some(head)))
                }
                Some(_) => None,
            },
        )
        .collect();

    // PHASE 2 — ADVANCE. `advance_to` refuses anything below the existing mark, so
    // an author reported above contributes nothing here: one hostile read can never
    // lower this machine's bar. That refusal is what the rollback detection rests
    // on; removing it is the mutation that kills the never-lowers-the-mark tests.
    let mut advanced = false;
    for head in heads {
        advanced |= advance_to(marks, head);
    }

    Comparison {
        regressions,
        advanced,
    }
}

/// Build the evidence record for `remembered` against `served` (`None` when no
/// verifiable head came back for that author).
fn regression(remembered: &HeadWatermark, served: Option<&HeadPointer>) -> HeadRegression {
    HeadRegression {
        author: ss58_encode(&remembered.author_key, HIPPIUS_SS58_PREFIX),
        author_key: remembered.author_key,
        remembered_lamport: remembered.lamport,
        remembered_tip: remembered.tip_hash,
        served_lamport: served.map(|head| head.lamport),
        served_tip: served.map(|head| head.tip_hash),
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        clippy::expect_used,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test, not a crash to avoid"
    )]

    use super::{HeadWatermarks, WATERMARK_FILE_VERSION, WatermarkFile};
    use crate::crypto::content_hash;
    use crate::domain::{Blake3Hash, NetworkPrefix};
    use crate::oplog::{
        HeadPointer, Signer, Sr25519Signer, VerifiedHeads, publish_head, read_heads,
    };
    use crate::store::{BlobStore, MemoryBlobStore};
    use std::path::PathBuf;
    use std::sync::Arc;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const TEAM: &str = "team";

    fn signer(seed: u8) -> Result<Sr25519Signer, Box<dyn std::error::Error>> {
        Ok(Sr25519Signer::from_seed_with_prefix(
            &[seed; 32],
            NetworkPrefix::HIPPIUS,
        )?)
    }

    fn tip(label: &str) -> Blake3Hash {
        content_hash(label.as_bytes())
    }

    /// Publish `heads` into a fresh in-memory bucket and read them back, so a test
    /// obtains a genuine [`VerifiedHeads`] through the ONLY route that mints one.
    ///
    /// There is deliberately no test-only constructor for that witness — the same
    /// reasoning `audit::reconcile`'s `verified_heads` helper records: an escape
    /// hatch would be a construction bypass of exactly the kind this crate audits
    /// for, and here it would additionally let a test ADVANCE a mark from a head
    /// that never passed a signature check, which is the one input that must not be
    /// forgeable.
    ///
    /// Deliberately NOT asserting a round-trip count, unlike that helper: several
    /// tests below publish a head they EXPECT `read_heads` to skip, so a count
    /// assertion here would fail those by design. Each such test asserts the
    /// resulting witness length itself, where the expected value is known.
    async fn verified(heads: &[HeadPointer]) -> Result<VerifiedHeads, Box<dyn std::error::Error>> {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        for head in heads {
            publish_head(&blob, TEAM, head).await?;
        }
        Ok(read_heads(&blob, TEAM).await?)
    }

    /// A watermark file path under `dir` that does not exist yet — the state
    /// directory is created on first write, so the parent is deliberately absent.
    fn marks_path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("state").join("head-watermarks.json")
    }

    #[tokio::test]
    async fn a_first_run_records_the_heads_it_sees_and_accuses_nobody() -> TestResult {
        // The cold case, and the documented blind spot. A machine with no marks has
        // nothing to compare against, so EVERY head is accepted — including one the
        // bucket has already rolled back. Reporting here instead would make the
        // first sync of every new machine accuse the whole team.
        let dir = tempfile::tempdir()?;
        let path = marks_path(&dir);
        let marks = HeadWatermarks::load(path.clone());
        let heads =
            verified(&[HeadPointer::create_signed(&signer(7)?, TEAM, 5, tip("t5"))]).await?;

        assert!(
            marks.observe(&heads).is_empty(),
            "an author this machine has never seen a head for is never a regression"
        );
        assert!(
            path.exists(),
            "the first observed head is persisted immediately, so the protection \
             survives a restart that happens before the next audit"
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_unchanged_head_reports_nothing() -> TestResult {
        let dir = tempfile::tempdir()?;
        let marks = HeadWatermarks::load(marks_path(&dir));
        let heads =
            verified(&[HeadPointer::create_signed(&signer(7)?, TEAM, 5, tip("t5"))]).await?;

        assert!(marks.observe(&heads).is_empty(), "the first observation");
        assert!(
            marks.observe(&heads).is_empty(),
            "re-serving the same head is the steady state of an idle team and must be silent"
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_advancing_head_moves_the_mark_without_accusing_anyone() -> TestResult {
        // The normal case: teammates keep writing, so their heads keep climbing.
        // The mark must follow, or the bar never rises and a later rollback to an
        // intermediate head would be accepted.
        let dir = tempfile::tempdir()?;
        let marks = HeadWatermarks::load(marks_path(&dir));
        let author = signer(7)?;

        assert!(
            marks
                .observe(
                    &verified(&[HeadPointer::create_signed(&author, TEAM, 5, tip("t5"))]).await?
                )
                .is_empty()
        );
        assert!(
            marks
                .observe(
                    &verified(&[HeadPointer::create_signed(&author, TEAM, 9, tip("t9"))]).await?
                )
                .is_empty(),
            "a head above the mark is the healthy direction"
        );

        // The mark really moved: serving the ONCE-accepted lamport 5 head now
        // regresses. Asserting through behaviour rather than by reaching into the
        // map keeps this test honest about what a caller can observe.
        let rolled_back =
            verified(&[HeadPointer::create_signed(&author, TEAM, 5, tip("t5"))]).await?;
        assert_eq!(
            marks.observe(&rolled_back).len(),
            1,
            "after advancing to 9, the previously-accepted head at 5 is below the mark"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_rolled_back_head_is_reported_and_never_lowers_the_mark() -> TestResult {
        // The residual X5 could not see: the bucket serves an OLDER but still
        // validly-signed head. It passes every signature, identity, team and
        // key-path check, and its claimed tip is visible in the truncated view — so
        // nothing bucket-side contradicts it. The local mark does.
        let dir = tempfile::tempdir()?;
        let marks = HeadWatermarks::load(marks_path(&dir));
        let author = signer(7)?;
        let current = verified(&[HeadPointer::create_signed(&author, TEAM, 9, tip("t9"))]).await?;
        let stale = verified(&[HeadPointer::create_signed(&author, TEAM, 4, tip("t4"))]).await?;

        assert!(marks.observe(&current).is_empty());
        let reported = marks.observe(&stale);

        assert_eq!(reported.len(), 1, "the rollback is reported: {reported:?}");
        let entry = reported.first().expect("one entry");
        assert_eq!(entry.author, author.author_ss58());
        assert_eq!(entry.author_key, author.verifying_key());
        assert_eq!(entry.remembered_lamport, 9);
        assert_eq!(entry.remembered_tip, tip("t9"));
        assert_eq!(
            (entry.served_lamport, entry.served_tip),
            (Some(4), Some(tip("t4"))),
            "the report carries WHAT the bucket serves now, not just that it is lower"
        );

        // The bar did not move. A regressing head must never advance a mark, or one
        // hostile read would permanently lower this machine's threshold and the
        // second read would find nothing wrong.
        assert_eq!(
            marks.observe(&stale).len(),
            1,
            "the same rollback is reported again: one hostile read must not lower the bar"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_dropped_head_is_reported_with_no_served_head() -> TestResult {
        // The other residual X5 could not see: an author with ops and NO head makes
        // no claim, so `suppressed_tails` has nothing to contradict. A machine that
        // already verified that author's head knows the claim existed.
        let dir = tempfile::tempdir()?;
        let marks = HeadWatermarks::load(marks_path(&dir));
        let author = signer(7)?;
        let current = verified(&[HeadPointer::create_signed(&author, TEAM, 9, tip("t9"))]).await?;

        assert!(marks.observe(&current).is_empty());
        let reported = marks.observe(&verified(&[]).await?);

        assert_eq!(reported.len(), 1, "the drop is reported: {reported:?}");
        let entry = reported.first().expect("one entry");
        assert_eq!(entry.remembered_lamport, 9);
        assert_eq!(
            (entry.served_lamport, entry.served_tip),
            (None, None),
            "no verifiable head came back for this author at all"
        );
        Ok(())
    }

    #[tokio::test]
    async fn the_same_lamport_with_a_different_tip_is_reported() -> TestResult {
        // Not a rollback by Lamport, and easy to let through: the served head is
        // neither older nor newer. An author signs ONE tip per Lamport (the Lamport
        // comes from the op the tip names), so two heads sharing a Lamport and
        // differing in tip means the bucket is serving a different history at that
        // position than the one this machine already verified.
        let dir = tempfile::tempdir()?;
        let marks = HeadWatermarks::load(marks_path(&dir));
        let author = signer(7)?;
        let first = verified(&[HeadPointer::create_signed(&author, TEAM, 9, tip("t9"))]).await?;
        let sibling =
            verified(&[HeadPointer::create_signed(&author, TEAM, 9, tip("other"))]).await?;

        assert!(marks.observe(&first).is_empty());
        let reported = marks.observe(&sibling);

        assert_eq!(reported.len(), 1, "the swap is reported: {reported:?}");
        let entry = reported.first().expect("one entry");
        assert_eq!(
            (entry.remembered_lamport, entry.served_lamport),
            (9, Some(9)),
            "the Lamports match — only the tips differ, which is why an operator must \
             read both fields"
        );
        assert_eq!(entry.remembered_tip, tip("t9"));
        assert_eq!(entry.served_tip, Some(tip("other")));
        Ok(())
    }

    #[tokio::test]
    async fn a_head_the_reader_skips_is_reported_as_no_verifiable_head() -> TestResult {
        // `read_heads` SKIPS a malformed, mis-signed, misattributed or misplaced
        // object rather than erroring, so an author whose head object is corrupted
        // is absent from the witness exactly as if it had been deleted. That is
        // reported, and it is reported IDENTICALLY to a deletion — `served_lamport`
        // is `None` in both cases, which is why that field means "no verifiable head
        // was served", not "the object is gone". The `read_heads` warn is what tells
        // an operator which of the two happened.
        let dir = tempfile::tempdir()?;
        let marks = HeadWatermarks::load(marks_path(&dir));
        let author = signer(7)?;
        let good = HeadPointer::create_signed(&author, TEAM, 9, tip("t9"));

        assert!(
            marks
                .observe(&verified(std::slice::from_ref(&good)).await?)
                .is_empty()
        );

        // Rewrite the signed tip after signing: the object still decodes, still
        // sits at its own key path, still names this team — only the signature
        // fails, so `read_heads` drops it.
        let mut tampered = good;
        tampered.tip_hash = tip("rewritten-after-signing");
        assert!(!tampered.verify_sig(), "the fixture must be unverifiable");
        let witness = verified(&[tampered]).await?;
        assert!(
            witness.is_empty(),
            "the premise: read_heads skipped the tampered object rather than returning it"
        );

        let reported = marks.observe(&witness);
        assert_eq!(reported.len(), 1, "{reported:?}");
        assert_eq!(
            reported.first().map(|entry| entry.served_lamport),
            Some(None),
            "a skipped head is indistinguishable here from a deleted one"
        );
        Ok(())
    }

    #[tokio::test]
    async fn regressions_come_back_in_a_deterministic_author_order() -> TestResult {
        // The report must read identically on every machine, so the vector cannot
        // inherit a hash-map iteration order. `read_heads` sorts its witness by
        // author key; the marks are keyed by the same bytes, so both halves of the
        // comparison agree on one order.
        let dir = tempfile::tempdir()?;
        let marks = HeadWatermarks::load(marks_path(&dir));
        let authors = [signer(1)?, signer(2)?, signer(3)?];
        let heads: Vec<HeadPointer> = authors
            .iter()
            .map(|author| HeadPointer::create_signed(author, TEAM, 9, tip("t9")))
            .collect();

        assert!(marks.observe(&verified(&heads).await?).is_empty());
        // Rolled BACK rather than dropped, so this test discriminates ordering and
        // nothing else: an absent-head bug would fail the dropped-head test above
        // instead of quietly failing here too.
        let rolled_back: Vec<HeadPointer> = authors
            .iter()
            .map(|author| HeadPointer::create_signed(author, TEAM, 4, tip("t4")))
            .collect();
        let reported = marks.observe(&verified(&rolled_back).await?);

        let mut expected: Vec<[u8; 32]> = authors
            .iter()
            .map(|author| *author.verifying_key().as_bytes())
            .collect();
        expected.sort_unstable();
        let actual: Vec<[u8; 32]> = reported
            .iter()
            .map(|entry| *entry.author_key.as_bytes())
            .collect();

        assert_eq!(
            actual, expected,
            "all three rolled-back heads are reported, in ascending author-key order"
        );
        Ok(())
    }

    #[tokio::test]
    async fn marks_survive_a_reload_and_still_report_a_rollback() -> TestResult {
        // The whole point of persisting: the in-memory watermark X5's residual
        // discussion contemplated would die with the process, and a bucket only has
        // to wait for a restart. This is the cross-restart half.
        let dir = tempfile::tempdir()?;
        let path = marks_path(&dir);
        let author = signer(7)?;
        let current = verified(&[HeadPointer::create_signed(&author, TEAM, 9, tip("t9"))]).await?;
        let stale = verified(&[HeadPointer::create_signed(&author, TEAM, 4, tip("t4"))]).await?;

        let before = HeadWatermarks::load(path.clone());
        assert!(before.observe(&current).is_empty());
        drop(before);

        let after = HeadWatermarks::load(path);
        assert_eq!(
            after.observe(&stale).len(),
            1,
            "a process that restarted between the two reads still remembers the higher head"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_corrupt_file_is_treated_as_absent_rather_than_failing_the_audit() -> TestResult {
        // A local file must not be able to brick `reconcile`. An attacker who could
        // make this file undecodable would otherwise stop the whole audit from
        // running, which is strictly worse than losing the one check it backs.
        let dir = tempfile::tempdir()?;
        let path = marks_path(&dir);
        std::fs::create_dir_all(path.parent().expect("parent"))?;
        std::fs::write(&path, b"{ not json")?;

        let marks = HeadWatermarks::load(path);
        let heads =
            verified(&[HeadPointer::create_signed(&signer(7)?, TEAM, 4, tip("t4"))]).await?;

        assert!(
            marks.observe(&heads).is_empty(),
            "an undecodable file starts empty — it must not error, and it must not \
             manufacture a regression out of marks it could not read"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_file_from_a_future_format_version_is_treated_as_absent() -> TestResult {
        // Refused by name rather than half-parsed. Reading a LOWER mark out of a
        // format this build does not understand is the one failure mode a
        // high-water mark cannot tolerate quietly.
        let dir = tempfile::tempdir()?;
        let path = marks_path(&dir);
        std::fs::create_dir_all(path.parent().expect("parent"))?;
        let author = signer(7)?;
        let ahead = serde_json::json!({
            "version": WATERMARK_FILE_VERSION + 1,
            "marks": [{
                "author_key": author.verifying_key().to_hex(),
                "lamport": 9,
                "tip_hash": tip("t9").to_hex(),
            }],
        });
        std::fs::write(&path, serde_json::to_vec(&ahead)?)?;

        let marks = HeadWatermarks::load(path);
        let stale = verified(&[HeadPointer::create_signed(&author, TEAM, 4, tip("t4"))]).await?;

        assert!(
            marks.observe(&stale).is_empty(),
            "a future-format file is ignored wholesale, not mined for the marks that \
             happen to parse"
        );
        Ok(())
    }

    #[tokio::test]
    async fn the_persisted_file_is_version_tagged_and_holds_one_mark_per_author() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = marks_path(&dir);
        let marks = HeadWatermarks::load(path.clone());
        let author = signer(7)?;

        assert!(
            marks
                .observe(
                    &verified(&[HeadPointer::create_signed(&author, TEAM, 5, tip("t5"))]).await?
                )
                .is_empty()
        );
        assert!(
            marks
                .observe(
                    &verified(&[HeadPointer::create_signed(&author, TEAM, 9, tip("t9"))]).await?
                )
                .is_empty()
        );

        let file: WatermarkFile = serde_json::from_slice(&std::fs::read(&path)?)?;
        assert_eq!(file.version, WATERMARK_FILE_VERSION);
        assert_eq!(
            file.marks.len(),
            1,
            "one mark per author, replaced in place rather than appended: {:?}",
            file.marks
        );
        let mark = file.marks.first().expect("one mark");
        assert_eq!(mark.author_key, author.verifying_key());
        assert_eq!(
            mark.lamport, 9,
            "the file holds the HIGHEST head, not the last"
        );
        assert_eq!(mark.tip_hash, tip("t9"));
        Ok(())
    }

    #[tokio::test]
    async fn a_duplicated_author_in_the_file_folds_to_the_higher_mark() -> TestResult {
        // A hand-edited or concatenated file must not be able to LOWER a mark by
        // listing the same author twice with the older entry last.
        let dir = tempfile::tempdir()?;
        let path = marks_path(&dir);
        std::fs::create_dir_all(path.parent().expect("parent"))?;
        let author = signer(7)?;
        let mark = |lamport: u64, label: &str| {
            serde_json::json!({
                "author_key": author.verifying_key().to_hex(),
                "lamport": lamport,
                "tip_hash": tip(label).to_hex(),
            })
        };
        std::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "version": WATERMARK_FILE_VERSION,
                "marks": [mark(9, "t9"), mark(4, "t4")],
            }))?,
        )?;

        let marks = HeadWatermarks::load(path);
        let stale = verified(&[HeadPointer::create_signed(&author, TEAM, 4, tip("t4"))]).await?;

        assert_eq!(
            marks.observe(&stale).len(),
            1,
            "the higher of the two duplicate entries is the mark that survives"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_write_folds_into_marks_another_process_already_raised() -> TestResult {
        // A running `serve` session and a one-shot `doctor` share this file, each
        // with its own in-memory map. A blind overwrite would let whichever writes
        // second lower every author the other had already raised — the exact
        // direction this module exists to prevent. `write_marks` folds instead.
        //
        // Modelled with two `HeadWatermarks` over ONE path: `first` learns author 7
        // and knows nothing of author 8; `second` learns author 8 at a HIGHER
        // lamport. `first` then advances author 7 again, which rewrites the file —
        // and must not drop author 8 back.
        let dir = tempfile::tempdir()?;
        let path = marks_path(&dir);
        let alice = signer(7)?;
        let bob = signer(8)?;

        let first = HeadWatermarks::load(path.clone());
        assert!(
            first
                .observe(
                    &verified(&[HeadPointer::create_signed(&alice, TEAM, 1, tip("a1"))]).await?
                )
                .is_empty()
        );

        let second = HeadWatermarks::load(path.clone());
        assert!(
            second
                .observe(
                    &verified(&[
                        HeadPointer::create_signed(&alice, TEAM, 1, tip("a1")),
                        HeadPointer::create_signed(&bob, TEAM, 9, tip("b9")),
                    ])
                    .await?
                )
                .is_empty()
        );

        // `first` advances its own author, rewriting the whole file from a map that
        // has never contained bob.
        assert!(
            first
                .observe(
                    &verified(&[HeadPointer::create_signed(&alice, TEAM, 2, tip("a2"))]).await?
                )
                .is_empty()
        );

        // A process starting now must still refuse bob's rolled-back head.
        let reloaded = HeadWatermarks::load(path);
        let rolled_back = verified(&[
            HeadPointer::create_signed(&alice, TEAM, 2, tip("a2")),
            HeadPointer::create_signed(&bob, TEAM, 3, tip("b3")),
        ])
        .await?;
        let reported = reloaded.observe(&rolled_back);
        assert_eq!(
            reported.len(),
            1,
            "only bob regressed — alice's own advance is healthy: {reported:?}"
        );
        assert_eq!(
            reported.first().map(|entry| entry.remembered_lamport),
            Some(9),
            "bob's mark survived a write by a process that had never seen him"
        );
        Ok(())
    }

    #[tokio::test]
    async fn one_identity_publishing_out_of_order_accuses_itself() -> TestResult {
        // The documented false positive, made executable so a later doc edit cannot
        // quietly drop it. `MemoryStore::writer` serializes head PUTs within ONE
        // process, `publish_head` has no compare-and-swap, and MCP registration is
        // user-global — so two concurrent sessions run under the SAME identity and
        // their head PUTs can land out of order.
        //
        // Modelled at the level the race actually resolves at: P2 publishes head(11)
        // and records it, then P1's in-flight PUT of head(10) lands, so the SERVED
        // head is 10 while the mark is 11. Every op is present and no bucket did
        // anything, yet this reports a regression against the operator's own honest
        // identity. That is the cost of not exempting our own key — which is the
        // right trade, because exempting it would discard the case where the bucket
        // rolls OUR head back.
        let dir = tempfile::tempdir()?;
        let marks = HeadWatermarks::load(marks_path(&dir));
        let ours = signer(7)?;

        marks.record_published_head(&HeadPointer::create_signed(&ours, TEAM, 11, tip("t11")));

        let landed_late =
            verified(&[HeadPointer::create_signed(&ours, TEAM, 10, tip("t10"))]).await?;
        let reported = marks.observe(&landed_late);

        assert_eq!(
            reported.len(),
            1,
            "a late-landing head PUT from a second process under the same identity is \
             reported exactly like a bucket rollback: {reported:?}"
        );
        assert_eq!(
            reported.first().map(|entry| entry.author.clone()),
            Some(ours.author_ss58()),
            "and the identity it names is our own"
        );

        // It clears on the next write above the higher lamport, as the operator
        // surfaces promise — asserted so that promise is not merely prose.
        let caught_up =
            verified(&[HeadPointer::create_signed(&ours, TEAM, 12, tip("t12"))]).await?;
        assert!(
            marks.observe(&caught_up).is_empty(),
            "a later write above the racing pair clears it without touching the state file"
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_unreadable_mark_file_neither_errors_nor_panics() -> TestResult {
        // Both halves of "a local file must not be able to brick reconcile", against
        // a path that fails for a reason that is NOT NotFound: a DIRECTORY where the
        // file belongs. `load`'s read fails, and so does `write_marks`' read-back
        // fold and its final rename. All three warn and swallow, so `observe` still
        // returns a verdict rather than propagating an error or panicking.
        let dir = tempfile::tempdir()?;
        let path = marks_path(&dir);
        std::fs::create_dir_all(path.join("occupied"))?;

        let marks = HeadWatermarks::load(path);
        let heads =
            verified(&[HeadPointer::create_signed(&signer(7)?, TEAM, 4, tip("t4"))]).await?;

        assert!(
            marks.observe(&heads).is_empty(),
            "an unusable path yields no marks and therefore no accusations"
        );
        // In-memory marks still work for the life of the process even though nothing
        // can be persisted: the rollback below is caught from memory alone.
        let stale =
            verified(&[HeadPointer::create_signed(&signer(7)?, TEAM, 2, tip("t2"))]).await?;
        assert_eq!(
            marks.observe(&stale).len(),
            1,
            "the in-memory half of the protection survives an unwritable state file"
        );
        Ok(())
    }

    #[tokio::test]
    async fn record_published_head_never_moves_a_mark_backward() -> TestResult {
        // `publish_head_for_tip` calls this after every successful publish. Our own
        // writes are monotonic under the writer guard, but the method must not
        // depend on that: a mark that could be moved DOWN by a caller would let a
        // late-landing retry erase the bar for our own identity.
        let dir = tempfile::tempdir()?;
        let marks = HeadWatermarks::load(marks_path(&dir));
        let author = signer(7)?;

        marks.record_published_head(&HeadPointer::create_signed(&author, TEAM, 9, tip("t9")));
        marks.record_published_head(&HeadPointer::create_signed(&author, TEAM, 4, tip("t4")));

        let stale = verified(&[HeadPointer::create_signed(&author, TEAM, 4, tip("t4"))]).await?;
        assert_eq!(
            marks.observe(&stale).len(),
            1,
            "the lower publish did not overwrite the mark"
        );
        Ok(())
    }
}
