//! Storage seams plus the [`MemoryStore`] that composes them.
//!
//! [`BlobStore`] is the object store; the hybrid index lives in [`crate::index`].
//! [`MemoryStore`] wires crypto + blob store + index + the signed op-log into the
//! memory operations the rest of the system drives: `remember`, `recall`, `get`,
//! `forget`, `link`, and `sync`. Every mutation appends a signed op to the shared
//! op-log; `sync` re-converges that log and rebuilds the local index from it, so
//! the op-log — not a blob listing — is the source of truth a machine replays.

// Submodules private behind a curated facade (matching `oplog`/`identity`): store
// items are reached through this re-export, not a deep `store::blob::…` path.
mod blob;
mod cache;
mod copy;
mod fs;
mod snapshot;

pub use blob::{BlobStore, MemoryBlobStore, S3BlobStore};
pub use cache::CachingBlobStore;
pub use copy::copy_store;
pub use fs::FsBlobStore;
pub use snapshot::{IndexSnapshot, SealedRecord, load_latest_snapshot, save_snapshot};
use snapshot::{open_record, seal_record};

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use ulid::Ulid;
use zeroize::Zeroize;

use crate::audit::ReconcileReport;
use crate::audit::{AnchorReceipt, AnchorRef, AuditAnchor, BatchMeta};
use crate::audit::{AnchorRecord, persist_anchor_record, read_anchor_records};
use crate::audit::{MerkleProof, inclusion_proof, merkle_root};
use crate::crypto::{SecretKey, content_hash, open, seal};
use crate::domain::{Blake3Hash, Note, NoteId, NoteType, RepoScope, Scope, Ss58, Timestamp};
use crate::error::MemError;
use crate::identity::{
    Identity, ManifestMarker, MemberKey, TeamManifest, fetch_team_key, highest_published_epoch,
    load_manifest, load_member_keys, provision_team_key, publish_manifest, publish_member_key,
    rotate_team_key,
};
use crate::index::{IndexRecord, MemoryIndex, Query, SearchResult};
use crate::objkey::{note_blob_prefix, object_key, parse_object_key};
use crate::oplog::{
    ConvergedState, GENESIS_PREV, LinkRel, NotePointer, Op, OpContent, OpKind, OpLogStore, Signer,
    VerifiedOps, VerifyingKey, converge, lamport_tip,
};

/// What to remember: the caller-supplied half of a new note.
///
/// Identity, timestamps, author, and scope-team are filled in by
/// [`MemoryStore::remember`]; the caller provides the knowledge itself plus the
/// one write-control knob (`force`).
#[derive(Debug, Clone)]
pub struct RememberInput {
    /// The kind of knowledge being recorded.
    pub note_type: NoteType,
    /// Repository dimension within the store's team.
    pub repo: RepoScope,
    /// Free-form tags, indexed alongside the summary.
    pub tags: BTreeSet<String>,
    /// One-line summary surfaced by `recall`.
    pub summary: String,
    /// Full note text returned by `get`.
    pub body: String,
    /// Bypass the write-time dedup gate. When `false` (the default), a summary
    /// that is a near-duplicate of an existing live note is refused with
    /// [`MemError::NearDuplicate`]; when `true`, the write proceeds regardless.
    ///
    /// This is a control flag, not knowledge — modeled as a named field (not a
    /// positional `bool` argument) so every call site reads `force: false`
    /// explicitly. There is no linked `Option` to couple it to, so a two-variant
    /// enum would add ceremony without removing an illegal state.
    pub force: bool,
}

/// What to recall: a retrieval request scoped to one repository dimension.
#[derive(Debug, Clone)]
pub struct RecallInput {
    /// Natural-language query text.
    pub text: String,
    /// Repository dimension to retrieve for (team-global notes always match).
    pub repo: RepoScope,
    /// Maximum number of pointers to return.
    pub k: usize,
    /// Optional cap on the summed estimated token cost of returned summaries.
    pub token_budget: Option<usize>,
}

/// A serde-friendly label for an [`Op`]'s kind, dropping the [`OpKind::Link`]
/// target.
///
/// `history` surfaces *what kind* of mutation each op was as a stable string.
/// The serde representation is the default externally-tagged form, so each unit
/// variant encodes as a bare JSON string (`"Remember"` / `"Edit"` / `"Forget"`
/// / `"Link"`) — that representation is part of the wire contract (serde axiom
/// `rust_quality_115`). The link target is deliberately omitted: it is
/// recoverable from the converged link set, and keeping `kind` a single string
/// (never sometimes an object) keeps every history entry's wire shape uniform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpKindLabel {
    /// A new note was created ([`OpKind::Remember`]).
    Remember,
    /// An existing note's body was replaced ([`OpKind::Edit`]).
    Edit,
    /// A note was tombstoned ([`OpKind::Forget`]).
    Forget,
    /// A note's content was permanently scrubbed ([`OpKind::Redact`]).
    Redact,
    /// A directed link was asserted from this note ([`OpKind::Link`]).
    Link,
    /// A typed relation was asserted from this note ([`OpKind::Relate`]). Like
    /// `Link`, the target and relation are dropped here — recoverable from the
    /// converged relation set — so every history entry's `kind` stays one string.
    Relate,
    /// A usage signal: this note was reinforced ([`OpKind::Reinforce`]). Carries
    /// no payload — the author and note are the op's own fields.
    Reinforce,
}

impl OpKindLabel {
    /// The stable wire string for this label.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Remember => "Remember",
            Self::Edit => "Edit",
            Self::Forget => "Forget",
            Self::Redact => "Redact",
            Self::Link => "Link",
            Self::Relate => "Relate",
            Self::Reinforce => "Reinforce",
        }
    }
}

impl From<&OpKind> for OpKindLabel {
    fn from(kind: &OpKind) -> Self {
        // Explicit per-variant mapping (no wildcard): a new `OpKind` variant
        // must fail to compile here rather than silently collapse into a label.
        match kind {
            OpKind::Remember => Self::Remember,
            OpKind::Edit => Self::Edit,
            OpKind::Forget => Self::Forget,
            OpKind::Redact => Self::Redact,
            OpKind::Link { .. } => Self::Link,
            OpKind::Relate { .. } => Self::Relate,
            OpKind::Reinforce => Self::Reinforce,
        }
    }
}

/// A Merkle inclusion proof binding one op to an anchored root.
///
/// [`verify_proof`](crate::audit::verify_proof)`(root, op_hash, &proof)`
/// proves `op_hash` is a leaf under `root`. What that *establishes* depends on
/// where `root` comes from, which `reference` records:
///
/// - [`AnchorRef::OnChain`] (the `chain` feature): trust-minimized. A verifier
///   fetches the root from the chain at `reference` and compares it to
///   [`AnchorProof::root`]; only then does the proof bind the op to a commitment
///   this server could not have forged. The whole chain of custody (which op,
///   under which root, in which block) is publicly checkable.
/// - [`AnchorRef::Local`] (the default [`NoopAnchor`]): proves only INTERNAL
///   consistency. Both `root` and `proof` come from the same bucket this server
///   controls, so a verifier learns the op is consistent with a root this server
///   asserts — NOT that the root is independently anchored. Do not read a Local
///   proof as "verifiable without trusting this server"; enable `chain` anchoring
///   and compare against the on-chain root for that.
///
/// [`NoopAnchor`]: crate::audit::NoopAnchor
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorProof {
    /// The Merkle root the op's batch was anchored under.
    pub root: Blake3Hash,
    /// Where `root` was anchored (on-chain block/extrinsic, or a local seq).
    pub reference: AnchorRef,
    /// The sibling path proving the op's hash is a leaf under `root`.
    pub proof: MerkleProof,
}

/// One op in a note's history: who did what, and — once anchored — the proof it
/// was committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// The op's unique id (a ULID), as its `Display` string.
    pub op_id: String,
    /// The author's human-facing SS58 address.
    ///
    /// Cryptographically bound: [`OpLogStore::read_all`] rejects any op whose
    /// `author` does not decode to its `author_key` (see [`Op::verify_identity`]),
    /// so this is a verified identity — the human-readable form of
    /// [`HistoryEntry::author_key`], not a self-asserted label.
    pub author: Ss58,
    /// The sr25519 public key the op's signature actually verifies against — the
    /// cryptographic "who". [`OpLogStore::read_all`] checks every op's signature
    /// against this key, and that `author` decodes to exactly it, so the two are
    /// two views of one verified identity.
    pub author_key: VerifyingKey,
    /// The op's Lamport clock value — the convergence order key.
    pub lamport: u64,
    /// What kind of mutation the op recorded.
    pub kind: OpKindLabel,
    /// The content hash of the note's ciphertext at this op.
    pub cid: Blake3Hash,
    /// The op's own hash — its Merkle leaf value, and the `leaf` argument to
    /// [`verify_proof`](crate::audit::verify_proof).
    pub op_hash: Blake3Hash,
    /// The inclusion proof, or `None` while the op is still pending anchoring.
    pub anchor: Option<AnchorProof>,
}

/// The full op history of a single note, with per-op anchor proofs.
///
/// Reconstructed from the shared op-log directly (not the local index), so it
/// reflects every op any teammate has written for `note_id`, in convergence
/// order. A note this machine has never seen yields an empty history rather
/// than an error: "no ops" is the truthful answer, and `history` — unlike
/// `get`/`forget` — does not require the note to be locally indexed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteHistory {
    /// The note this history describes.
    pub note_id: NoteId,
    /// Whether the note's latest lifecycle op is a `Forget` (per [`converge`]), or
    /// the note was redacted (redaction always implies tombstoned).
    pub tombstoned: bool,
    /// Whether the note's content was permanently scrubbed by a `Redact` op (per
    /// [`NoteState::redacted`](crate::oplog::NoteState)). The op trail in
    /// `entries` survives and stays provable, but the note's body is gone — this
    /// is the agent-visible signal that a `get` will not return content.
    pub redacted: bool,
    /// The notes this note links to: the converged union of its `Link` targets
    /// ([`NoteState::links`](crate::oplog::NoteState)), ascending by id.
    ///
    /// This is what makes the link graph readable: `link(a, b)` records a `Link`
    /// op that convergence folds into this set, and `history(a).links` surfaces
    /// it. A grow-only set in Phase 2 — there is no unlink op yet.
    pub links: Vec<NoteId>,
    /// Every op naming the note, ascending by `(lamport, op_id)`.
    pub entries: Vec<HistoryEntry>,
}

/// The cached head of this author's op-log, advanced under [`MemoryStore::writer`].
///
/// Caching the tip avoids re-reading and re-verifying the whole op-log on every
/// write just to learn the next Lamport value and the predecessor hash to chain
/// to. The two fields move together: a new op takes `lamport_tip + 1` and chains
/// to `my_last_hash`, then both advance to that op — but only *after* the op is
/// durably appended (see [`MemoryStore::mint_and_append`]), so a failed append
/// leaves the tip unchanged and the next attempt re-mints with the same `prev`,
/// never chaining a durable op to a phantom. [`MemoryStore::sync`] still
/// recomputes the pair from the durable log when a machine (re)joins a team.
struct OpClock {
    /// Highest Lamport value this store has issued or observed.
    lamport_tip: u64,
    /// [`Op::hash`] of this author's most recent op — the next op's `prev_op_hash`.
    my_last_hash: Blake3Hash,
}

/// One op buffered for the next anchor batch: its leaf hash and Lamport clock.
///
/// The hash is the Merkle leaf; the Lamport is carried alongside it (rather than
/// in a parallel vector) so a drained batch can fill [`BatchMeta`]'s
/// `first_lamport`/`last_lamport` range without re-reading the op-log.
#[derive(Clone, Copy)]
struct PendingLeaf {
    /// [`Op::hash`] of the buffered op — its Merkle leaf value.
    hash: Blake3Hash,
    /// The op's Lamport clock, for the batch's metadata range.
    lamport: u64,
}

/// The anchor scheduler's mutable state, guarded by [`MemoryStore::anchor_state`].
///
/// `pending` accumulates op leaves until a write drives it to the threshold (or
/// [`MemoryStore::flush_anchors`] forces it); `next_seq` hands out the monotonic
/// sequence number each anchored batch is keyed under. `next_seq` only ever
/// increases — a batch that fails to anchor returns its leaves to `pending` but
/// does NOT reclaim its seq, so a concurrently-anchored later batch can never
/// collide on an object key (the price is a harmless gap in the seq sequence).
///
/// `next_seq` is *per author* and must not restart at 0 on a fresh process, or a
/// restart would overwrite the previous run's anchor records under the same key.
/// `seeded` tracks whether [`MemoryStore::ensure_seq_seeded`] has yet read this
/// author's existing records to set `next_seq = max(seq) + 1`; it is seeded
/// lazily on the first anchor so a brand-new process picks up where the last one
/// left off without a synchronous blob read in the constructor.
struct AnchorState {
    pending: Vec<PendingLeaf>,
    next_seq: u64,
    seeded: bool,
}

impl AnchorState {
    /// Drain every pending leaf into an owned batch and reserve its seq.
    fn drain_batch(&mut self) -> DrainedBatch {
        let leaves = std::mem::take(&mut self.pending);
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        DrainedBatch { seq, leaves }
    }

    /// Return a failed batch's leaves to the FRONT of `pending`, preserving
    /// Lamport order, so they re-anchor under a fresh seq on the next attempt.
    fn restore(&mut self, mut batch: DrainedBatch) {
        batch.leaves.append(&mut self.pending);
        self.pending = batch.leaves;
    }
}

/// How long a [`MemoryStore::refresh_if_stale`] check stays valid before the next
/// read re-probes the shared op-log. A read within this window trusts the index
/// as fresh-enough, so a burst of recalls costs at most one probe.
const AUTO_REFRESH_WINDOW: Duration = Duration::from_secs(20);

/// Max note blobs decoded from the bucket at once during an index rebuild.
///
/// A cold rebuild decodes one blob per live note; doing so serially made startup
/// scale linearly with the note count against remote S3 latency. This bounds the
/// in-flight blob GETs (axiom `rust_quality_176`: never an unbounded fan-out) so
/// a large team memory cannot open thousands of simultaneous connections, while
/// still overlapping the round-trips the serial loop paid one at a time.
///
/// Matched to the op-log store's `OPLOG_FETCH_CONCURRENCY`: the same high-latency
/// gateway bounds both, and the checkpoint fast path already spares most syncs
/// this decode entirely (only a cold rebuild or the tail hits it). The blobs are
/// ciphertext, decrypted in-process, so the fan-out never widens what the gateway
/// sees in cleartext.
const NOTE_DECODE_CONCURRENCY: usize = 64;

/// Lamport growth past a checkpoint's baseline that triggers writing a fresh one
/// in [`MemoryStore::sync`].
///
/// Once a checkpoint exists, syncs take the incremental fast path and never
/// advance it, so the tail a future cold restore must decode grows by one per
/// write forever. Rewriting the checkpoint when the tail passes this many ops
/// bounds that cold-restore decode to `< SNAPSHOT_REFRESH_LAMPORT_GAP` blobs,
/// while keeping the checkpoint write itself infrequent (not once per sync).
const SNAPSHOT_REFRESH_LAMPORT_GAP: u64 = 64;

/// Maximum length, in Unicode scalar values, of a note `summary` accepted at
/// ingestion.
///
/// A note's `summary` is what `recall` ranks on, through two independent legs: a
/// lexical matcher over the whole string, and a semantic (fastembed) matcher that
/// SILENTLY truncates its input at the model's max sequence length. An unbounded
/// summary is therefore indexed inconsistently — its tail is lexically findable
/// but semantically invisible, a non-obvious, silent recall degradation. Capping
/// at ingestion (the MCP schema already calls it a "one-line summary") keeps the
/// two legs consistent; 512 scalar values is a generous one line yet well under
/// the token budget of the embedding models this crate targets, so the semantic
/// leg never truncates an accepted summary. Detail belongs in the body, which has
/// no such cap.
const MAX_SUMMARY_CHARS: usize = 512;

/// Maximum length, in Unicode scalar values, of a note `body` accepted at
/// ingestion. Generous (a body holds one fact's detail, not a document) but
/// bounded, so a single write cannot durably persist an arbitrarily large blob
/// across the team's shared storage.
const MAX_BODY_CHARS: usize = 128 * 1024;

/// Maximum number of distinct `tags` on a note. Tags are pinned in every machine's
/// in-memory index (the body lives only in the blob), so an unbounded set is the
/// memory-resident half of the resource-exhaustion vector [`MAX_BODY_CHARS`] bounds
/// for storage.
const MAX_TAGS: usize = 64;

/// Maximum length, in Unicode scalar values, of a single `tag`.
const MAX_TAG_CHARS: usize = 128;

/// Similarity at or above which a `remember` is refused as a near-duplicate,
/// unless forced. Interpreted per retrieval build: cosine on a semantic build,
/// token-set Jaccard on a lexical one (see [`MemoryIndex::nearest_duplicate`]).
///
/// `0.9` is a deliberately conservative floor — high precision over high recall —
/// so the gate refuses only clear duplicates and rarely blocks a genuinely new
/// note. On a lexical build a Jaccard of `0.9` means near-identical token sets,
/// so the gate there catches only obvious repeats. Tune against the real corpus
/// with `cargo run --release --example calibrate --features embeddings`, which
/// reports the false-duplicate cosine ceiling this must sit above.
const DEDUP_THRESHOLD: f32 = 0.9;

/// How long after a `recall` surfaces a note a subsequent `get` of it still counts
/// as a use signal. Short — a genuine recall→open happens in seconds to minutes,
/// so a stale entry does not later mislabel an unrelated by-id `get` as use.
const RECALL_USE_WINDOW: Duration = Duration::from_mins(5);

/// Minimum spacing between two reinforcements of the SAME note by THIS machine.
/// One agent re-reading a note over an hour reinforces it once; longer sessions
/// re-earn it. Convergence already counts distinct authors, so this only throttles
/// local noise, it is not the Sybil bound.
const REINFORCE_RATE_LIMIT: Duration = Duration::from_hours(1);

/// Bookkeeping for [`MemoryStore::refresh_if_stale`]: when the op-log was last
/// probed and how many op objects it held at the last sync.
///
/// `last_check` is a monotonic [`Instant`], not a wall-clock millis: the window
/// is a *duration since the last probe*, and only `Instant` is immune to a system
/// clock stepping backwards (which would otherwise read as "still fresh" and stall
/// auto-refresh for the session). Both fields are `None` until the first probe, so
/// a session's first read always syncs — exactly when freshness matters most. The
/// op count is a cheap monotonic proxy for "a teammate has written since we
/// synced" (see [`OpLogStore::op_object_count`]).
#[derive(Default)]
struct AutoRefreshState {
    /// The monotonic instant of the last probe, or `None` (never probed).
    last_check: Option<Instant>,
    /// Op-object count observed at the last sync, or `None` before the first.
    synced_op_count: Option<usize>,
}

/// Local, per-process bookkeeping for the reinforcement trigger (Feature 4).
///
/// Reinforcement is a USE signal: a `get` that follows a recent `recall` of the
/// same note. Neither map is durable — the convergent signal is the `Reinforce`
/// op in the shared log; these maps only decide LOCALLY whether to emit one, so a
/// restart simply re-earns reinforcement on the next qualifying use. Both are
/// keyed by [`NoteId`] with a monotonic [`Instant`] (not wall-clock, so a backward
/// clock step cannot widen a window) and pruned lazily on access.
#[derive(Default)]
struct ReinforceTracker {
    /// Notes a recent `recall` surfaced, and when. A `get` of one of these within
    /// [`RECALL_USE_WINDOW`] is a genuine use signal (the agent recalled, then
    /// opened the note), as opposed to a bare `get` by id with no retrieval intent.
    recalled: BTreeMap<NoteId, Instant>,
    /// Notes this machine reinforced recently, and when — the per-(author, note)
    /// rate limit. `author` is always this store's own identity, so the key
    /// collapses to the note. A second reinforce within [`REINFORCE_RATE_LIMIT`] is
    /// skipped so one agent re-getting a note cannot inflate its distinct-author
    /// count (that count is also the Sybil bound, but the throttle avoids the noise).
    reinforced: BTreeMap<NoteId, Instant>,
}

/// An owned snapshot of pending leaves taken under the lock, anchored only after
/// the guard is dropped — so no lock is ever held across the anchor/persist
/// `.await` (the `await_holding_lock` lint, axiom `rust_quality_74`).
struct DrainedBatch {
    /// The monotonic sequence number reserved for this batch.
    seq: u64,
    /// The batch's leaves in pending-push order. This races op-append under
    /// concurrent writers (the Lamport tick and the anchor-buffer push are under
    /// different locks), so do not assume Lamport order: `commit_batch` derives
    /// the Lamport range with `min`/`max`, not `first`/`last`.
    leaves: Vec<PendingLeaf>,
}

/// Cancellation guard for [`MemoryStore::commit_batch`]: holds the drained batch
/// while the commit crosses its `.await` points and, if the commit future is
/// dropped mid-flight (a `select!` / `timeout` / task-abort cancellation), returns
/// the leaves to `pending` so a later write or [`MemoryStore::flush_anchors`]
/// re-anchors them.
///
/// Without this, a commit cancelled between `drain_batch` and completion would
/// silently drop the batch — those ops would get no anchor proof, ever, with no
/// warning. Drop is best-effort and NOT relied on for correctness: the ops are
/// already durable in the op-log and anchoring is a separate best-effort layer
/// (axiom `rust_quality_166` — a leaked guard skips Drop), so the guard only
/// avoids losing the *retry*. Every normal path disarms it via
/// [`disarm`](Self::disarm) — the `Ok` path drops the batch, the `Err` paths
/// restore it by hand exactly as before — so Drop fires only on the cancellation
/// path it exists for.
struct BatchGuard<'s> {
    store: &'s MemoryStore,
    /// `Some` while armed; `None` once [`disarm`](Self::disarm) has taken the batch.
    batch: Option<DrainedBatch>,
}

impl<'s> BatchGuard<'s> {
    /// Arm the guard over `batch`.
    fn arm(store: &'s MemoryStore, batch: DrainedBatch) -> Self {
        Self {
            store,
            batch: Some(batch),
        }
    }

    /// Take the batch out, disarming the guard so its `Drop` is a no-op. Returns
    /// `None` if already disarmed; each commit path calls this exactly once.
    fn disarm(&mut self) -> Option<DrainedBatch> {
        self.batch.take()
    }
}

impl Drop for BatchGuard<'_> {
    fn drop(&mut self) {
        // Fires only when the commit future was dropped before disarming — i.e.
        // cancelled mid-anchor. `restore_pending` takes a `std` Mutex without
        // awaiting and cannot panic (it recovers a poisoned lock), so this is a
        // sound Drop: no panic, no lock held across an await.
        if let Some(batch) = self.batch.take() {
            tracing::warn!(
                seq = batch.seq,
                leaves = batch.leaves.len(),
                "anchor commit was cancelled mid-flight; returning its leaves to pending for the next attempt"
            );
            self.store.restore_pending(batch);
        }
    }
}

/// Which path [`MemoryStore::sync_incremental`] actually took, so [`MemoryStore::sync`]
/// knows whether the restored checkpoint was usable or had to be discarded.
///
/// A modelled outcome rather than a bare `usize` + `bool`: the two cases drive
/// different checkpoint bookkeeping, and a discarded (stale/poisoned) checkpoint
/// MUST be rewritten or it forces a full rebuild on every subsequent sync.
enum IncrementalOutcome {
    /// The snapshot was valid; only the tail was decoded. Carries the live count.
    Incremental(usize),
    /// The snapshot was stale or poisoned, so a full rebuild replaced it. Carries
    /// the live count; `sync` overwrites the checkpoint so the bad one stops
    /// forcing a rebuild every time.
    FellBackToFull(usize),
}

/// The note coordinates a minted op records: which note it acts on, where that
/// note's ciphertext landed, that blob's hash, and the epoch it was sealed under.
///
/// Grouped into one value (rather than four positional args to
/// [`MemoryStore::mint_and_append`]) so the op id, kind, and these coordinates
/// stay within the project's positional-parameter limit and read as one unit.
struct OpTarget {
    /// The note this op acts on.
    note_id: NoteId,
    /// The object-store key of the note's ciphertext blob at this op.
    object_key: String,
    /// BLAKE3 digest of that ciphertext.
    cid: Blake3Hash,
    /// The team-key epoch the ciphertext was sealed under.
    key_epoch: u64,
}

/// The core memory store: crypto + blob store + index + signed op-log behind one
/// team identity.
///
/// One `MemoryStore` is bound to a single team (the shared namespace), its
/// epoch→key encryption ring, and the local developer's author identity. Every method takes
/// `&self`: the blob store, index, and op-log carry their own interior
/// mutability. The store stays cheap to share behind an `Arc` across tasks: the
/// only lock held across an `.await` is the writer lock ([`MemoryStore::writer`]),
/// a `tokio::sync::Mutex` whose guard is `Send` precisely so it can span the
/// `oplog.append().await` it must serialize.
///
/// Invariant: `author` is the SS58 of `signer`'s identity. This is now structural
/// — [`MemoryStore::new`] derives `author` from `signer.author_ss58()` rather than
/// taking it as a separate (mismatchable) argument — so `sync` can recover this
/// author's chain head by matching `op.author == self.author`, and every op this
/// store mints passes [`Op::verify_identity`].
pub struct MemoryStore {
    blob: Arc<dyn BlobStore>,
    index: Arc<dyn MemoryIndex>,
    // The shared, append-only signed op-log over the same blob backend. Each
    // mutation appends one signed op here; `sync` replays it.
    oplog: OpLogStore,
    // This store's signing identity. Behind `Arc<dyn Signer>` so an HSM/remote
    // signer can be swapped in without touching the store.
    signer: Arc<dyn Signer>,
    // The team encryption key-ring, one `SecretKey` per key epoch. A note sealed
    // before a team-key rotation stays readable because its op records the epoch
    // it was sealed under (`Op::key_epoch`) and that epoch's key is still in the
    // ring. `Mutex<BTreeMap>` (not the heavier `RwLock`) because `add_epoch_key`
    // mutates the ring through `&self` and the critical section is tiny — copy one
    // key out, drop the guard — so a reader-writer split buys nothing; `BTreeMap`
    // for the deterministic iteration the rest of the crate relies on. The guard
    // is NEVER held across an `.await`: `key_for_epoch` copies the matched key out
    // and drops the guard before any seal/open or blob call (axiom 74).
    keys: Mutex<BTreeMap<u64, SecretKey>>,
    // The epoch new writes seal under, selected from `keys` on every `remember`.
    // An `AtomicU64` (not behind the `keys` lock) so the common read is lock-free;
    // `Relaxed` suffices because it carries no happens-before relationship beyond
    // what the `keys` mutex already establishes — it only names which key to use.
    current_epoch: AtomicU64,
    // The shared namespace every note in this store belongs to.
    team: String,
    // This developer's on-chain identity, stamped as the author of every note
    // this store writes. Sourced from `signer.author_ss58()` in `new`, so it is
    // structurally consistent with `signer`'s key — not a separate input that
    // could disagree with it.
    author: Ss58,
    // Serializes this machine's writes: mint -> append -> advance happens under
    // this guard so two concurrent writers cannot read the same chain tip and
    // fork the author's chain. A `tokio::sync::Mutex` (not `std::sync`) because
    // the guard is deliberately held ACROSS `oplog.append().await` — the clock
    // advances only after that append is durable, so a failed append leaves the
    // tip untouched and a retry re-mints with the same `prev` (axiom
    // `rust_quality_74`; the guard is `Send`, so this stays sound and clippy's
    // `await_holding_lock`, which fires only on `std`/`parking_lot` guards, does
    // not flag it).
    writer: tokio::sync::Mutex<OpClock>,
    // Where a batch's Merkle root is committed. A separate durability layer from
    // the op-log: anchoring is best-effort, so a failure never fails a write.
    anchor: Arc<dyn AuditAnchor>,
    // How many op leaves accumulate before their batch is anchored. One root per
    // `anchor_threshold` ops is what keeps on-chain anchoring cheap.
    anchor_threshold: usize,
    // The anchor scheduler's pending leaves + seq counter. A sibling `Mutex` to
    // `clock` (never both held at once — distinct critical sections, no lock
    // ordering hazard); its guard, like `clock`'s, never spans an `.await`.
    anchor_state: Mutex<AnchorState>,
    // The team founder's identity, pinned out of band (operator config) so the
    // untrusted bucket cannot elect a founder. `Some` makes `load_manifest` honour
    // ONLY this founder's manifests, so a malicious gateway overwriting the genesis
    // manifest can no longer seize the team. `None` keeps trust-on-genesis
    // (backward compatible): the lowest-version manifest fixes the founder, the
    // documented takeover gap closed only by pinning. Set via
    // [`MemoryStore::with_pinned_founder`] rather than `new`, so the many existing
    // constructions keep the prior behaviour untouched.
    founder: Option<Ss58>,
    // The highest-version team manifest this store has APPLIED, cached so a later
    // reload cannot silently downgrade membership. The untrusted bucket can delete
    // the newest manifest object; `load_manifest` would then elect an older version
    // (or none), re-admitting removed members. `read_and_filter` runs every loaded
    // manifest through `monotonic_manifest`, which keeps the higher version, so a
    // running member never rolls back. In-memory only, so the guard holds WITHIN a
    // process; a cross-restart rollback (cold cache) is the documented residual that
    // durable/on-chain manifest versioning would close. Its guard never spans `.await`.
    applied_manifest: Mutex<Option<TeamManifest>>,
    // Staleness bookkeeping for `refresh_if_stale`, which the read tools call so a
    // long-lived session picks up teammates' new notes without a manual `refresh`.
    // In-memory and per-process, exactly like the clock: it caches when the shared
    // op-log was last probed and its size then, so reads stay fresh-enough at the
    // cost of at most one cheap key-listing per window. Its guard never spans
    // `.await` (the probe/sync run after it is dropped).
    auto_refresh: Mutex<AutoRefreshState>,
    // Durable, LOCAL persistence of the highest applied `TeamManifest`, closing the
    // cross-restart rollback the in-memory `applied_manifest` watermark cannot: a
    // cold start seeds the watermark from here, so a bucket rolled back to an older
    // manifest is refused across restarts, not just within a process. `None` keeps
    // the prior in-memory-only behaviour. The marker is re-verified before it is
    // trusted (see `load_verified_marker`), so a tampered local file is ignored.
    manifest_marker: Option<Arc<dyn ManifestMarker>>,
    // Local reinforcement bookkeeping (Feature 4): which notes a recent recall
    // surfaced, and which this machine has recently reinforced. A `std::sync::Mutex`
    // like the siblings above; its guard is taken, the emit decision is made, and it
    // is DROPPED before the `Reinforce` op is appended, so it never spans an `.await`
    // (the append is best-effort and must not serialize behind this lock).
    reinforce: Mutex<ReinforceTracker>,
}

impl fmt::Debug for MemoryStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `dyn BlobStore`/`dyn MemoryIndex`/`dyn Signer` are not `Debug`, and the
        // key must never be printed; surface only the non-secret identity fields.
        f.debug_struct("MemoryStore")
            .field("team", &self.team)
            .field("author", &self.author)
            .finish_non_exhaustive()
    }
}

/// What a [`MemoryStore::rotate_key`] accomplished: the epoch the team now
/// writes under and exactly who received a wrap of its key.
///
/// Carries only public coordinates (epoch number, SS58 addresses — never key
/// material), so a CLI can print it verbatim. `wrapped` is the authoritative
/// post-rotation read set: an address absent here holds no wrap of the new
/// epoch and cannot read notes sealed under it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "the caller must relay the new epoch to the team (max_epoch config) or the rotation is silently invisible to them"]
pub struct RotationOutcome {
    /// The freshly minted epoch new writes now seal under.
    pub new_epoch: u64,
    /// The addresses wrapped the new epoch's key — the post-rotation read set.
    pub wrapped: BTreeSet<Ss58>,
}

/// Outcome of a [`MemoryStore::sweep_orphan_blobs`] pass — plain counts a CLI can
/// print verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[must_use = "the sweep result reports what was reclaimed; surface it or the run is invisible"]
pub struct OrphanSweepReport {
    /// Note-ciphertext blobs examined (the team keyspace minus the `_`-prefixed
    /// internal namespaces, which the note-key parse rejects).
    pub note_blobs_scanned: usize,
    /// Orphans found: note blobs no durable op names AND older than the grace
    /// window.
    pub orphans_found: usize,
    /// Orphans actually deleted — `0` under `dry_run`, and possibly `< orphans_found`
    /// if a best-effort delete failed (those retry on a later sweep).
    pub orphans_reclaimed: usize,
    /// Unreferenced blobs KEPT because they are younger than the grace window (an
    /// in-flight write's op may not have appended yet, or the op-log listing lags
    /// its writes).
    pub within_grace_kept: usize,
}

impl MemoryStore {
    /// Build a store over `blob`, `index`, and `oplog`, signing ops with `signer`,
    /// sealing notes under the `keys` key-ring for team `team`. The author identity
    /// stamped on every note is derived from `signer` (not passed separately), so it
    /// is bound to the signing key by construction.
    ///
    /// `keys` is the initial epoch→key ring and `current_epoch` is the epoch new
    /// writes seal under; a single-epoch store passes `{0: key}` with
    /// `current_epoch = 0`. More epochs are added later via
    /// [`MemoryStore::add_epoch_key`] (e.g. from [`MemoryStore::bootstrap_epoch_keys`])
    /// and the active epoch advanced with [`MemoryStore::set_current_epoch`].
    ///
    /// The clock starts empty (Lamport tip 0, predecessor [`GENESIS_PREV`]); the
    /// first [`MemoryStore::sync`] or write seeds it from the op-log. `anchor`
    /// receives each batch's Merkle root once `anchor_threshold` ops have accumulated.
    #[must_use]
    #[expect(
        clippy::too_many_arguments,
        reason = "MemoryStore composes nine independent collaborators (blob, index, op-log, anchor, signer, key-ring, current epoch, team, threshold); a builder would add indirection without removing any required input"
    )]
    pub fn new(
        blob: Arc<dyn BlobStore>,
        index: Arc<dyn MemoryIndex>,
        oplog: OpLogStore,
        anchor: Arc<dyn AuditAnchor>,
        signer: Arc<dyn Signer>,
        keys: BTreeMap<u64, SecretKey>,
        current_epoch: u64,
        team: String,
        anchor_threshold: usize,
    ) -> Self {
        // The author is the signer's own SS58: deriving it here (rather than
        // accepting a separate argument) makes the type invariant structural —
        // there is no way to construct a store whose `author` disagrees with its
        // signing key.
        let author = signer.author_ss58();
        Self {
            blob,
            index,
            oplog,
            signer,
            keys: Mutex::new(keys),
            current_epoch: AtomicU64::new(current_epoch),
            team,
            author,
            writer: tokio::sync::Mutex::new(OpClock {
                lamport_tip: 0,
                my_last_hash: GENESIS_PREV,
            }),
            anchor,
            anchor_threshold,
            anchor_state: Mutex::new(AnchorState {
                pending: Vec::new(),
                next_seq: 0,
                seeded: false,
            }),
            // Defaults to unpinned (trust-on-genesis); `with_pinned_founder` opts in.
            founder: None,
            // No manifest applied yet; the first `read_and_filter` seeds the watermark.
            applied_manifest: Mutex::new(None),
            // Never probed; the first read syncs unconditionally (Default: 0, None).
            auto_refresh: Mutex::new(AutoRefreshState::default()),
            // No durable manifest marker by default; `with_manifest_marker` opts in.
            manifest_marker: None,
            // Empty reinforcement bookkeeping: nothing recalled or reinforced yet.
            reinforce: Mutex::new(ReinforceTracker::default()),
        }
    }

    /// Pin the team founder, anchoring membership trust to an identity the
    /// untrusted bucket cannot rewrite.
    ///
    /// `Some(founder)` makes [`MemoryStore::sync`] / membership honour only that
    /// founder's manifests, defeating a genesis-manifest overwrite that would
    /// otherwise let a malicious gateway seize the team. `None` (the default set
    /// by [`MemoryStore::new`]) keeps trust-on-genesis. Consuming-builder shape so
    /// it composes onto `new` without expanding that constructor's argument list.
    #[must_use]
    pub fn with_pinned_founder(mut self, founder: Option<Ss58>) -> Self {
        self.founder = founder;
        self
    }

    /// Attach a durable [`ManifestMarker`], closing the cross-restart
    /// membership-rollback residual that the in-memory watermark alone leaves
    /// open.
    ///
    /// With a marker, [`sync`](Self::sync) seeds its monotonic watermark from the
    /// (re-verified) persisted manifest on the first read after a boot, and
    /// re-persists whenever membership advances — so a cold process refuses a
    /// bucket rolled back to an older manifest, not just a warm one. `None` (the
    /// default from [`new`](Self::new)) keeps the in-memory-only behaviour.
    /// Consuming-builder shape, composing onto `new` like
    /// [`with_pinned_founder`](Self::with_pinned_founder). Most effective with a
    /// pinned founder: without one, trust falls back to genesis and the marker
    /// inherits that weaker anchor.
    #[must_use]
    pub fn with_manifest_marker(mut self, marker: Option<Arc<dyn ManifestMarker>>) -> Self {
        self.manifest_marker = marker;
        self
    }

    /// Add `key` to the key-ring under `epoch`, replacing any existing key there.
    ///
    /// `&self` (the ring is interior-mutable) so a long-lived `Arc<MemoryStore>`
    /// can learn a new epoch's key — e.g. after a team-key rotation, or while
    /// [`MemoryStore::bootstrap_epoch_keys`] fetches the epochs this member can
    /// unwrap. Adding a key does NOT make it the active write epoch; call
    /// [`MemoryStore::set_current_epoch`] for that. The two are separate because
    /// bootstrapping older epochs (to read history) must not change which epoch new
    /// writes seal under.
    pub fn add_epoch_key(&self, epoch: u64, key: SecretKey) {
        self.keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(epoch, key);
    }

    /// Set the epoch new writes seal under. Pair with a prior
    /// [`MemoryStore::add_epoch_key`] so the active epoch's key is in the ring.
    pub fn set_current_epoch(&self, epoch: u64) {
        self.current_epoch.store(epoch, Ordering::Relaxed);
    }

    /// The epoch new writes currently seal under.
    #[must_use]
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch.load(Ordering::Relaxed)
    }

    /// The highest epoch present in this store's key-ring, or `None` when the
    /// ring is empty.
    ///
    /// This is the newest epoch this member can both read AND safely seal new
    /// writes under; callers that advance the write epoch after an epoch-key
    /// bootstrap (e.g. the CLI's post-rotation catch-up) key off it.
    #[must_use]
    pub fn highest_epoch(&self) -> Option<u64> {
        self.keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .last_key_value()
            .map(|(epoch, _)| *epoch)
    }

    /// Copy the key for `epoch` out of the ring, or report a clear, actionable
    /// error if this member was never provisioned that epoch.
    ///
    /// Returns an *owned* [`SecretKey`] (the 32 bytes copied out under the lock)
    /// rather than a borrow, so the caller can `seal`/`open` or `.await` blob I/O
    /// with the ring lock already released — the guard is never held across an
    /// await (axiom `rust_quality_74`). `SecretKey` is deliberately not `Clone`, so
    /// the copy goes through its crate-private byte accessor and lands back in a
    /// fresh zeroizing `SecretKey`.
    ///
    /// # Errors
    ///
    /// [`MemError::KeyUnavailable`] naming the missing epoch when no key for
    /// `epoch` is in the ring (the caller is not provisioned to read notes from
    /// that epoch).
    fn key_for_epoch(&self, epoch: u64) -> Result<SecretKey, MemError> {
        let guard = self.keys.lock().unwrap_or_else(PoisonError::into_inner);
        match guard.get(&epoch) {
            Some(key) => {
                // Zero the transient stack copy of the key bytes once they are
                // wrapped in the returned zeroizing `SecretKey`, matching the
                // discipline `derive_aead_key` follows for its residual copy: a
                // plain move would leave 32 live key bytes on the stack frame the
                // optimizer is free not to clear.
                let mut raw = *key.expose_bytes();
                let copied = SecretKey::from_bytes(raw);
                raw.zeroize();
                Ok(copied)
            }
            None => Err(MemError::KeyUnavailable { epoch }),
        }
    }

    /// Fetch and add the team key for each requested epoch this member can unwrap.
    ///
    /// Operates on this store's own team ([`self.team`](MemoryStore)); the team
    /// is not a parameter, so a caller cannot bootstrap a foreign team's epoch
    /// over this ring (epochs are small integers that collide across teams, and
    /// [`MemoryStore::add_epoch_key`] replaces, so a mismatched team could
    /// overwrite a live key).
    ///
    /// For every `epoch` in `epochs`, look up this member's [`crate::WrappedKey`]
    /// in the bucket and unwrap it with `identity`'s x25519 secret; on success the
    /// key joins the ring (via [`MemoryStore::add_epoch_key`]). Epochs this member
    /// cannot unwrap — no wrap addressed to them (a non-member, or one removed
    /// before that epoch), a tampered wrap, or a backend miss — are skipped, so a
    /// removed member still bootstraps the older epochs they retain. Returns how
    /// many keys were added. Does not change the active write epoch.
    ///
    /// Discovering *which* epochs exist is left to the caller (a documented
    /// follow-up): pass the epoch range you know about.
    ///
    /// # Errors
    ///
    /// Never returns an error for an un-unwrappable epoch (those are skipped); it
    /// is infallible in practice and returns `Result` only to keep the async
    /// signature uniform with the rest of the store API.
    pub async fn bootstrap_epoch_keys(
        &self,
        identity: &Identity,
        epochs: &[u64],
    ) -> Result<usize, MemError> {
        let team = self.team.as_str();
        let secret = identity.x25519_secret();
        let mut added = 0_usize;
        for &epoch in epochs {
            match fetch_team_key(self.blob.as_ref(), team, epoch, &identity.ss58, &secret).await {
                Ok(key) => {
                    self.add_epoch_key(epoch, key);
                    added += 1;
                }
                Err(err) => tracing::warn!(
                    team = %team,
                    epoch,
                    error = %err,
                    "skipping an epoch this member cannot bootstrap (no wrap, or unwrap failed)"
                ),
            }
        }
        Ok(added)
    }

    /// Record a new note: build it, seal it, persist the blob, log a signed
    /// `Remember` op, then index it.
    ///
    /// Returns the freshly minted [`NoteId`].
    ///
    /// # Ordering
    ///
    /// `blob.put` → `oplog.append` → `index.upsert`, on purpose: a crash between
    /// any two steps leaves a recoverable prefix, never a dangling reference. The
    /// blob lands before the op that names it (the op never points at an unwritten
    /// body), the op lands before the index entry (the index never surfaces a note
    /// absent from the durable log), and a teammate's `sync` rebuilds the index
    /// from the log regardless of where a crash struck.
    ///
    /// # Errors
    ///
    /// Returns [`MemError::NearDuplicate`] if `input.summary` is a near-duplicate
    /// of an existing live note and `input.force` is false (the write-time dedup
    /// gate, checked first so nothing is persisted). Otherwise returns
    /// [`MemError::Crypto`] if sealing fails, [`MemError::Storage`] if the object
    /// key is invalid or the blob/op write fails, [`MemError::Serialize`] if the
    /// op cannot be encoded, or any error the index reports while upserting.
    pub async fn remember(&self, input: RememberInput) -> Result<NoteId, MemError> {
        self.remember_impl(input, None).await
    }

    /// Like [`remember`](Self::remember) but with a caller-precomputed summary
    /// embedding.
    ///
    /// The binary computes the embedding on the blocking pool (`spawn_blocking`) and
    /// hands it in here, so the CPU-bound ONNX embed never stalls the async runtime
    /// worker (ASYNCBLOCK) — this crate stays runtime-free (it never calls
    /// `spawn_blocking` itself; see the tokio dep note). The embedding must be
    /// [`MemoryStore::embed_summary`] of `input.summary`; a lexical build's cheap
    /// hash makes this indistinguishable from `remember`.
    ///
    /// # Errors
    ///
    /// The same set as [`remember`](Self::remember): the two share
    /// [`remember_impl`](Self::remember_impl) and differ only in where the summary
    /// embed ran.
    pub async fn remember_offloaded(
        &self,
        input: RememberInput,
        embedding: Vec<f32>,
    ) -> Result<NoteId, MemError> {
        self.remember_impl(input, Some(embedding)).await
    }

    /// Embed `summary` into the same dense vector the index would compute for it, so
    /// the binary can precompute it on the blocking pool and pass it to
    /// [`remember_offloaded`](Self::remember_offloaded) /
    /// [`edit_offloaded`](Self::edit_offloaded) (ASYNCBLOCK). Synchronous by design:
    /// the binary is what wraps it in `spawn_blocking`.
    ///
    /// # Errors
    ///
    /// Whatever the index's embedder reports.
    pub fn embed_summary(&self, summary: &str) -> Result<Vec<f32>, MemError> {
        self.index.embed_summary(summary)
    }

    async fn remember_impl(
        &self,
        input: RememberInput,
        precomputed: Option<Vec<f32>>,
    ) -> Result<NoteId, MemError> {
        // Validate at the boundary, before any id/seal/write work, so an oversized
        // summary is rejected as bad input with nothing written.
        validate_summary(&input.summary)?;
        // Bound the body and tag set at the same boundary point, before any
        // id/seal/write work, so an oversized new note is rejected with nothing
        // written (resource-exhaustion guard).
        validate_body(&input.body)?;
        validate_tags(&input.tags)?;
        // Write-time dedup gate: unless forced, refuse a near-duplicate of an
        // existing live note so recall precision is not eroded as near-identical
        // notes accumulate. Runs BEFORE any id/seal/blob work, so a refused write
        // persists nothing. Best-effort under concurrency: two identical writes
        // racing this probe can both pass — dedup is a precision aid, never a
        // uniqueness invariant, so a rare double is acceptable and self-heals via a
        // later `relate`/`forget`.
        if !input.force
            && let Some(dup) = self.index.nearest_duplicate(
                &input.summary,
                &self.team,
                &input.repo,
                DEDUP_THRESHOLD,
                precomputed.as_deref(),
            )?
        {
            return Err(MemError::NearDuplicate {
                existing: dup.note_id,
                similarity: dup.similarity,
            });
        }

        let id = NoteId::new();
        let now = current_millis();
        let scope = Scope {
            team: self.team.clone(),
            repo: input.repo,
        };
        let note = Note {
            id,
            scope: scope.clone(),
            note_type: input.note_type,
            author: self.author.clone(),
            created: now,
            updated: now,
            tags: input.tags,
            links: BTreeSet::new(),
            summary: input.summary,
            body: input.body,
        };

        let json = note.to_json();

        // Seal under the CURRENT epoch's key, capturing that epoch so the op and
        // index record name the exact key the blob was sealed with — even if a
        // concurrent rotation advances `current_epoch` between here and the append.
        let epoch = self.current_epoch();
        let seal_key = self.key_for_epoch(epoch)?;

        // Mint this write's op id up front and key the blob under it: the object
        // key carries the op's ULID (globally unique), so two concurrent writes
        // never derive the same key and overwrite each other's ciphertext (the
        // edit-race the rev-counter scheme allowed — see `objkey`). The same id
        // is threaded into the op below so the blob and its op agree.
        let op_id = Ulid::new();

        // Derive the object key BEFORE sealing: it is the AEAD associated data,
        // so the ciphertext is cryptographically bound to the identity it is
        // stored under (see `crypto::seal`'s threat model — defeats a gateway
        // relocating note A's bytes onto note B's key).
        let key = object_key(&scope, id, op_id)?;
        let ciphertext = seal(&seal_key, json.as_bytes(), key.as_bytes())?;
        let cid = content_hash(&ciphertext);

        // Step 1 — the body lands first, so the op minted next never names an
        // unwritten blob.
        self.blob.put(&key, ciphertext).await?;

        // Step 2 — mint the signed `Remember` op (under `op_id`) and durably
        // append it under the writer lock, advancing the clock only once the
        // append lands. `op.lamport` is the convergence clock this write was
        // assigned; `epoch` is the key epoch the blob was sealed under. On append
        // failure the orphaned ciphertext from Step 1 is reclaimed before the error
        // surfaces (see `append_naming_blob`).
        let op = self
            .append_naming_blob(
                op_id,
                OpKind::Remember,
                OpTarget {
                    note_id: id,
                    object_key: key.clone(),
                    cid,
                    key_epoch: epoch,
                },
            )
            .await?;

        // Step 3 — index last, stamping the op's Lamport so recall/history see the
        // same convergence order the log records, and the seal epoch so `get` picks
        // the right key without re-reading the op.
        self.index.upsert(IndexRecord {
            note_id: id,
            object_key: key,
            cid,
            scope,
            note_type: note.note_type,
            author: note.author,
            updated: now,
            lamport: op.lamport,
            key_epoch: epoch,
            tags: note.tags,
            summary: note.summary,
            // A freshly-remembered note asserts no relations and no reinforcement
            // yet; both are stamped from converged state on the next sync when it
            // later gains a `relate`/`reinforce` op.
            relations: Vec::new(),
            reinforcers: BTreeSet::new(),
            last_reinforced: None,
            // The binary's precomputed embedding (offloaded path), or `None` — the
            // index then embeds inline (ASYNCBLOCK).
            embedding: precomputed,
        })?;

        // Step 4 — buffer the op's leaf for batched Merkle anchoring. Best-effort
        // and last: the op is already durable in the log, so a failed anchor is
        // logged and retried, never failing this write.
        self.schedule_anchor(op.hash(), op.lamport).await;
        Ok(id)
    }

    /// Replace the content of an existing note, keeping its identity.
    ///
    /// Writes a NEW ciphertext version under a fresh object key (the edit op's
    /// own ULID), logs a signed [`OpKind::Edit`] naming the same `id`, and
    /// reindexes. Convergence's latest-`(lamport, op_id, author_key)` rule makes
    /// the edit the winning pointer, so a teammate's next `sync` surfaces the
    /// edited body — the same way `forget`/`link` propagate. The note's `created`
    /// timestamp, existing link set, AND repo scope are preserved (a note cannot be
    /// relocated by an edit; `input.repo` is ignored); the type, tags, summary, and
    /// body come from `input`.
    ///
    /// A fresh version key (not an overwrite of the prior version) is deliberate
    /// on two counts: the prior version's blob stays where its op — and any
    /// anchored history proof — names it, so the audit trail is never invalidated;
    /// and because the key is the globally-unique op ULID, two concurrent edits
    /// can never collide on it and lose the convergence winner's body.
    ///
    /// # Ordering
    ///
    /// `blob.put` → `oplog.append` → `index.upsert`, identical to
    /// [`MemoryStore::remember`]: the new blob lands before the op that names it,
    /// the op before the index entry, so a crash leaves a recoverable prefix.
    ///
    /// # Errors
    ///
    /// [`MemError::NotFound`] if `id` is not indexed; whatever
    /// [`MemoryStore::get`] reports if the current version cannot be read
    /// (you cannot edit a note you cannot decrypt — e.g. a missing epoch key);
    /// [`MemError::Crypto`] if sealing fails; [`MemError::Storage`] if the object
    /// key is invalid or the blob/op write fails; [`MemError::Serialize`] if the
    /// op cannot be encoded; or any error the index reports on upsert.
    pub async fn edit(&self, id: NoteId, input: RememberInput) -> Result<(), MemError> {
        self.edit_with_precondition(id, input, None).await
    }

    /// [`edit`](Self::edit) with an optional compare-and-swap precondition.
    ///
    /// When `precondition` is `Some(version)`, the edit is refused with
    /// [`MemError::Conflict`] unless the note's current content hash still equals
    /// `version` (the `cid` the caller read via
    /// [`current_version`](Self::current_version) / `get`). This is the
    /// optimistic-concurrency guard for agent read-modify-write: it stops a second
    /// agent from silently clobbering a change made between the first agent's read
    /// and write.
    ///
    /// The authoritative check runs INSIDE the append critical section (see
    /// [`commit_edit`](Self::commit_edit)), not before the write. The op-log — not
    /// the index — is the convergence source of truth, so a stale precondition must
    /// veto the *append*: rejecting only at the index while the op was already
    /// appended would let the rejected edit win last-writer-wins on the next
    /// reconverge, a silent lost update — the exact hazard this guard exists to
    /// prevent. Because that check and the index upsert share the writer lock, two
    /// concurrent same-base edits are serialized — the first commits, the second
    /// observes its `cid` and conflicts — so they can no longer both pass.
    ///
    /// A cheap advisory pre-check rejects an obviously-stale precondition before the
    /// seal/put work, so the common uncontended conflict still costs no I/O; it is
    /// an optimization, not the load-bearing gate.
    ///
    /// Scope: the check is against THIS machine's converged index, so it catches the
    /// realistic same-machine race. An unsynced concurrent writer on another machine
    /// is not seen here and still converges last-writer-wins — the precondition is a
    /// CAS within converged state, not a distributed lock.
    ///
    /// # Errors
    ///
    /// [`MemError::Conflict`] if `precondition` does not match the current
    /// content; otherwise every error [`edit`](Self::edit) can return.
    pub async fn edit_with_precondition(
        &self,
        id: NoteId,
        input: RememberInput,
        precondition: Option<Blake3Hash>,
    ) -> Result<(), MemError> {
        self.edit_with_precondition_impl(id, input, precondition, None)
            .await
    }

    /// Like [`edit_with_precondition`](Self::edit_with_precondition) but with a
    /// caller-precomputed summary embedding (see
    /// [`remember_offloaded`](Self::remember_offloaded)).
    ///
    /// The binary computes the embedding on the blocking pool and hands it in, so the
    /// ONNX embed never runs on the async runtime worker — AND, because it is
    /// precomputed BEFORE `commit_edit` takes the writer lock, the under-lock upsert
    /// no longer runs inference while serializing writers (ASYNCBLOCK-002). The
    /// embedding must be [`embed_summary`](Self::embed_summary) of `input.summary`.
    ///
    /// # Errors
    ///
    /// The same set as
    /// [`edit_with_precondition`](Self::edit_with_precondition): the two share
    /// [`edit_with_precondition_impl`](Self::edit_with_precondition_impl).
    pub async fn edit_offloaded(
        &self,
        id: NoteId,
        input: RememberInput,
        precondition: Option<Blake3Hash>,
        embedding: Vec<f32>,
    ) -> Result<(), MemError> {
        self.edit_with_precondition_impl(id, input, precondition, Some(embedding))
            .await
    }

    async fn edit_with_precondition_impl(
        &self,
        id: NoteId,
        input: RememberInput,
        precondition: Option<Blake3Hash>,
        precomputed: Option<Vec<f32>>,
    ) -> Result<(), MemError> {
        // Validate at the boundary, before the read/seal/write work, so an
        // oversized summary is rejected as bad input with nothing written.
        validate_summary(&input.summary)?;
        // Load the current note first: this both asserts the note exists and is
        // readable by this member, and yields the `created`/`links` we preserve.
        let current = self.get(id).await?;
        // Grandfather-safe body/tag bounds: validate ONLY when the edit CHANGES
        // them. An edit that leaves a pre-existing (possibly pre-cap, oversized)
        // body or tag set untouched — e.g. changing only the summary — must not be
        // frozen out; a CHANGED body/tag set must come within the caps, so an edit
        // can never grow a note past them.
        if input.body != current.body {
            validate_body(&input.body)?;
        }
        if input.tags != current.tags {
            validate_tags(&input.tags)?;
        }

        // Advisory fast-path: reject an already-stale precondition before doing any
        // seal/put work. NOT authoritative — the load-bearing check is in
        // `commit_edit`, atomic with the append — this only spares the common
        // uncontended conflict a wasted seal + blob round-trip.
        if let Some(expected) = precondition
            && let Some(located) = self.index.locate(id)?
            && located.cid != expected
        {
            return Err(MemError::Conflict {
                expected: expected.to_hex(),
                actual: located.cid.to_hex(),
            });
        }

        let now = current_millis();
        // A note's repo is fixed at `remember` and preserved here, exactly like
        // `created` and `links` below: an edit changes content, never a note's
        // location. `input.repo` is deliberately ignored (the shared
        // `RememberInput` carries it for `remember`'s sake). This is what keeps
        // EVERY version of a note under one `{team}/{repo}/{mem_id}/` object-key
        // prefix — the invariant `redact`'s prefix-scoped scrub depends on to reach
        // all ciphertext. Were `input.repo` used, an edit could strand a version
        // under a different prefix, invisible to that scrub.
        //
        // `team` comes from `self` while `repo` is preserved from the note: this
        // store IS one team, so `self.team` is authoritative, whereas `repo`
        // partitions notes within it and must track the note being edited. (A
        // wrong team would fail anyway — it is AEAD associated data, so `get` above
        // would not have decrypted a foreign-team note.)
        let scope = Scope {
            team: self.team.clone(),
            repo: current.scope.repo.clone(),
        };
        let note = Note {
            id,
            scope: scope.clone(),
            note_type: input.note_type,
            author: self.author.clone(),
            created: current.created,
            updated: now,
            tags: input.tags,
            links: current.links,
            summary: input.summary,
            body: input.body,
        };

        let json = note.to_json();

        // Seal under the CURRENT epoch (capturing it so the op and index record
        // name the exact key the new blob was sealed with), exactly as `remember`.
        let epoch = self.current_epoch();
        let seal_key = self.key_for_epoch(epoch)?;

        // Key the new version under THIS edit's op id (a fresh ULID): every edit
        // lands at a distinct key, so two concurrent edits — even on two machines
        // that both read the same prior version — cannot derive the same key and
        // overwrite the convergence winner's ciphertext. A counter scheme would
        // (both pick `prior+1`); a ULID is globally unique. This is also why the
        // prior version's blob survives untouched for its history/anchor proof.
        let op_id = Ulid::new();
        let key = object_key(&scope, id, op_id)?;
        let ciphertext = seal(&seal_key, json.as_bytes(), key.as_bytes())?;
        let cid = content_hash(&ciphertext);

        self.blob.put(&key, ciphertext).await?;

        let record = IndexRecord {
            note_id: id,
            object_key: key.clone(),
            cid,
            scope,
            note_type: note.note_type,
            author: note.author,
            updated: now,
            // Overwritten with the appended op's lamport inside `commit_edit`.
            lamport: 0,
            key_epoch: epoch,
            tags: note.tags,
            summary: note.summary,
            // Editing the body changes neither relations nor reinforcement; the
            // next sync restamps both from converged state (they live on separate ops).
            relations: Vec::new(),
            reinforcers: BTreeSet::new(),
            last_reinforced: None,
            // The binary's precomputed embedding (offloaded path), or `None`. Threading
            // it here — before `commit_edit` takes the writer lock — is what keeps the
            // under-lock upsert from running ONNX inference while it serializes writers
            // (ASYNCBLOCK-002); a `None` embeds inline under the lock, as before.
            embedding: precomputed,
        };
        let op = self
            .commit_edit(
                op_id,
                OpTarget {
                    note_id: id,
                    object_key: key,
                    cid,
                    key_epoch: epoch,
                },
                record,
                precondition,
            )
            .await?;

        self.schedule_anchor(op.hash(), op.lamport).await;
        Ok(())
    }

    /// Append the `Edit` op and upsert the index UNDER ONE writer-lock critical
    /// section, gated by an optional compare-and-swap `precondition`.
    ///
    /// Correctness rests on the writer guard spanning the precondition check, the op
    /// append, and the index upsert: a second concurrent edit observes the first's
    /// committed version before it decides, so two same-base edits cannot both pass.
    /// Embedding the (short) summary under the lock is the cost of that guarantee;
    /// edits are not the hot path, `recall` is.
    ///
    /// Blob reclaim is ASYMMETRIC on purpose. A CAS reject or a FAILED append leaves
    /// the just-written blob named by no durable op — an orphan — so it is deleted.
    /// But once the append is DURABLE the blob must never be deleted, even if the
    /// following [`upsert`](MemoryIndex::upsert) fails (its embed is fallible): the op
    /// names the blob and a later `sync` re-reads both, exactly as `remember`'s Step-3
    /// index upsert propagates without touching the blob (the index is a disposable
    /// cache of the op-log). Deleting a durably-named blob would silently vanish the
    /// note on the next converge — the regression this asymmetry exists to prevent.
    ///
    /// # Errors
    ///
    /// [`MemError::Conflict`] if `precondition` no longer matches (blob reclaimed);
    /// [`MemError::NotFound`] if the note vanished under a precondition (blob
    /// reclaimed); whatever [`OpLogStore::append`] reports on a failed append (blob
    /// reclaimed); or whatever [`MemoryIndex::upsert`] reports AFTER a durable append
    /// (op kept, blob kept, the local index heals on the next `sync`).
    async fn commit_edit(
        &self,
        op_id: Ulid,
        target: OpTarget,
        mut record: IndexRecord,
        precondition: Option<Blake3Hash>,
    ) -> Result<Op, MemError> {
        // Capture the key before `target` moves into the op below.
        let object_key = target.object_key.clone();
        let mut clock = self.writer.lock().await;
        // Authoritative CAS: under the writer guard the index reflects every edit that
        // has already committed on this machine, so a mismatch here means a concurrent
        // edit landed first. Veto the append (not merely the index write) — an
        // appended-then-rejected op would still win LWW on the next reconverge. The
        // just-written blob is now an orphan; drop the guard BEFORE the reclaim (it is
        // an `.await` and must not hold the writer lock).
        if let Some(expected) = precondition {
            let actual = self
                .index
                .locate(target.note_id)?
                .ok_or_else(|| MemError::NotFound {
                    id: target.note_id.to_string(),
                })?
                .cid;
            if actual != expected {
                drop(clock);
                self.reclaim_orphan_blob(&object_key).await;
                return Err(MemError::Conflict {
                    expected: expected.to_hex(),
                    actual: actual.to_hex(),
                });
            }
        }
        let lamport = clock.lamport_tip.saturating_add(1);
        let op = Op::create_signed(
            self.signer.as_ref(),
            OpContent {
                op_id,
                lamport,
                key_epoch: target.key_epoch,
                kind: OpKind::Edit,
                note_id: target.note_id,
                object_key: target.object_key,
                cid: target.cid,
                prev_op_hash: clock.my_last_hash,
            },
        );
        // Append BEFORE advancing (as `mint_and_append`): a failed append drops the
        // guard with the tip unchanged so the next write re-mints cleanly, and the
        // just-written blob is an orphan no durable op names — reclaim it.
        if let Err(err) = self.oplog.append(&self.team, &op).await {
            drop(clock);
            self.reclaim_orphan_blob(&object_key).await;
            return Err(err);
        }
        clock.lamport_tip = lamport;
        clock.my_last_hash = op.hash();
        // The op is now DURABLE and names the blob. Upsert the index under the still-
        // held guard so the next edit's CAS observes this version; if the fallible
        // embed inside `upsert` fails, PROPAGATE WITHOUT reclaiming — deleting the blob
        // would orphan a durable op and vanish the note. The local index simply lags
        // until the next `sync` re-reads the op and blob.
        record.lamport = lamport;
        self.index.upsert(record)?;
        Ok(op)
    }

    /// Best-effort delete of an orphaned ciphertext blob — one written for an edit
    /// that was vetoed or whose append failed, so no durable op names it. A failed
    /// cleanup is logged, never surfaced, so it does not mask the original cause.
    /// NEVER call this once the naming op is durable: that would vanish the note.
    async fn reclaim_orphan_blob(&self, object_key: &str) {
        if let Err(cleanup) = self.blob.delete(object_key).await {
            tracing::warn!(
                object_key = %object_key,
                error = %cleanup,
                "could not delete the orphaned ciphertext after a rejected or failed edit; \
                 it is now an unreferenced orphan (no op names it) that no GC reclaims"
            );
        }
    }

    /// Mint a signed op (`op_id`/`kind`/`target`), durably append it, and only
    /// then advance the convergence clock. Returns the appended [`Op`].
    ///
    /// `op_id` is supplied by the caller, not minted here, so `remember`/`edit`
    /// can key the note blob under the SAME ULID the op carries — that is what
    /// makes each write's object key globally unique and collision-free.
    ///
    /// The [`MemoryStore::writer`] guard is held across the whole sequence —
    /// build-sign, `oplog.append().await`, advance — so the three are atomic per
    /// machine: two concurrent writers cannot read the same tip and fork this
    /// author's chain, and the clock advances only once the op is durable. This
    /// is the ONE place a guard intentionally spans an `.await`; a
    /// `tokio::sync::Mutex` makes that sound (its guard is `Send`, per the
    /// `concurrency/mutex_guard_no_await` exemplar).
    ///
    /// On append failure the guard drops with the tip *unchanged*, so a retry
    /// re-mints against the same `prev_op_hash` — a durable op is never chained to
    /// a phantom predecessor that an aborted append left only in the cache.
    ///
    /// The anchor network call is deliberately NOT under this guard: callers
    /// invoke [`MemoryStore::schedule_anchor`] after this returns, so the writer
    /// lock never blocks on the chain.
    ///
    /// # Identity reuse
    ///
    /// This guard serializes appends WITHIN one process only. Two writers sharing
    /// one signer seed — two machines, or a second process such as `import`
    /// alongside the running server — each mint off their own `OpClock`, so
    /// concurrent writes before a sync produce two ops with the same `prev_op_hash`
    /// — a self-fork. The read path's `quarantine_broken_chains` keeps the tallest
    /// genesis-rooted branch and orphans the other, so the fork costs the shorter
    /// branch's ops rather than every op after it, but it is still avoidable: run
    /// ONE identity per process. The console sub-key onboarding gives each machine a
    /// distinct author key, so copying a config to a second machine (or writing from
    /// two processes under one identity) and writing from both is unsupported.
    ///
    /// # Errors
    ///
    /// Whatever [`OpLogStore::append`] reports ([`MemError::Serialize`] /
    /// [`MemError::Storage`]); on error the clock is left untouched.
    async fn mint_and_append(
        &self,
        op_id: Ulid,
        kind: OpKind,
        target: OpTarget,
    ) -> Result<Op, MemError> {
        let mut clock = self.writer.lock().await;
        let lamport = clock.lamport_tip.saturating_add(1);

        let op = Op::create_signed(
            self.signer.as_ref(),
            OpContent {
                op_id,
                lamport,
                key_epoch: target.key_epoch,
                kind,
                note_id: target.note_id,
                object_key: target.object_key,
                cid: target.cid,
                prev_op_hash: clock.my_last_hash,
            },
        );

        // Append BEFORE advancing: if this fails, the early return drops the
        // guard with `lamport_tip`/`my_last_hash` still pointing at the previous
        // durable op, so the chain stays intact and the next write re-mints.
        self.oplog.append(&self.team, &op).await?;

        clock.lamport_tip = lamport;
        clock.my_last_hash = op.hash();

        Ok(op)
    }

    /// Append the op naming an already-written blob, reclaiming the orphaned blob
    /// if the durable append fails.
    ///
    /// `remember`/`edit` write the ciphertext BEFORE the op that names it (the
    /// recoverable-prefix ordering, so a crash never leaves the op pointing at an
    /// unwritten body). The cost of that order is that an [`OpLogStore::append`]
    /// failure leaves a blob named by no durable op — an orphan no GC reclaims,
    /// since the only sweep targets snapshots. This compensates: on append failure
    /// the just-written blob at `target.object_key` is best-effort deleted, then
    /// the ORIGINAL error is surfaced unchanged. A failed cleanup is logged, never
    /// masking the cause. `delete` is idempotent, so a redundant delete is benign.
    async fn append_naming_blob(
        &self,
        op_id: Ulid,
        kind: OpKind,
        target: OpTarget,
    ) -> Result<Op, MemError> {
        // Capture the key before `target` moves into `mint_and_append`.
        let object_key = target.object_key.clone();
        match self.mint_and_append(op_id, kind, target).await {
            Ok(op) => Ok(op),
            Err(err) => {
                if let Err(cleanup) = self.blob.delete(&object_key).await {
                    tracing::warn!(
                        object_key = %object_key,
                        error = %cleanup,
                        "could not delete the orphaned ciphertext after a failed op append; \
                         it is now an unreferenced orphan (no op names it) that no GC reclaims"
                    );
                }
                Err(err)
            }
        }
    }

    /// Retrieve ranked pointers for `input`, plus how many in-scope relevant
    /// notes matched in total. Pure index access — never the body.
    ///
    /// The [`SearchResult::total_matched`] count lets a caller tell whether the
    /// returned pointers are everything that matched or only the head of a larger
    /// result the `k`/budget cut off.
    ///
    /// # Errors
    ///
    /// Returns any error the index reports while searching (e.g. embedding the
    /// query text).
    pub fn recall(&self, input: RecallInput) -> Result<SearchResult, MemError> {
        let query = Query {
            text: input.text,
            team: self.team.clone(),
            repo: input.repo,
            k: input.k,
            token_budget: input.token_budget,
            now: current_millis(),
        };
        let result = self.index.search(&query)?;
        // Feature 4: mark the surfaced notes as recalled, so a following `get` of
        // one is recognized as a USE signal and reinforces it. Best-effort under
        // the tracker lock (recover from poison); the guard never spans an `.await`.
        let now = Instant::now();
        let mut tracker = self
            .reinforce
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        prune_expired(&mut tracker.recalled, now, RECALL_USE_WINDOW);
        for pointer in &result.pointers {
            tracker.recalled.insert(pointer.note_id, now);
        }
        drop(tracker);
        Ok(result)
    }

    /// Enumerate every note in this machine's converged index, unranked.
    ///
    /// The browse/enumeration counterpart to [`recall`](Self::recall): `recall`
    /// ranks against a query, this returns the whole set in unspecified order for
    /// local tooling (the dashboard browse view). It reads the index as-is — the
    /// caller runs [`sync`](Self::sync) first if it wants teammates' latest notes
    /// folded in. Each [`IndexRecord`] carries the summary, never the body, so this
    /// is a safe local read; hydrate a body with [`get`](Self::get).
    ///
    /// # Errors
    ///
    /// Whatever the backing index reports; the in-memory index never errors.
    pub fn list_records(&self) -> Result<Vec<IndexRecord>, MemError> {
        self.index.all_records()
    }

    /// This store's team namespace — the shared-memory partition every note it
    /// reads or writes is scoped to. A read accessor for local tooling (the
    /// dashboard shows which team's memory it is serving); the field itself
    /// stays private so the team is fixed at construction, never reassigned.
    #[must_use]
    pub fn team(&self) -> &str {
        &self.team
    }

    /// The highest team-key epoch this store's bucket has actually published a
    /// wrapped key at (`0` when none), against THIS store's own connection and
    /// team — delegates to [`crate::highest_published_epoch`] over the private
    /// `self.blob`/`self.team` rather than exposing either.
    ///
    /// A caller with only an `&MemoryStore` (no separate blob handle in scope)
    /// uses this to compare against a configured `max_epoch` bootstrap ceiling
    /// — see [`MemoryStore::bootstrap_epoch_keys`]'s docs on why the on-bucket
    /// epoch discovery this performs is not otherwise available. Deliberately
    /// NOT a raw blob accessor: [`BlobStore`] carries unrestricted
    /// put/get/delete/list over unencrypted-at-this-layer bytes, so handing one
    /// out would let any holder of `&MemoryStore` (including the MCP server's
    /// long-lived `Arc<MemoryStore>`) bypass the encryption boundary this crate
    /// otherwise never lets a note's plaintext or an arbitrary write cross.
    ///
    /// # Errors
    ///
    /// Returns [`MemError::Storage`] if the backend listing fails.
    pub async fn highest_published_epoch(&self) -> Result<u64, MemError> {
        highest_published_epoch(self.blob.as_ref(), &self.team).await
    }

    /// Whether recall runs the semantic (dense-vector) leg, not keyword-only.
    ///
    /// True only when the backing index is driven by a real dense model (an
    /// `embeddings` build); a lexical `HashEmbedder` build reports false. The
    /// dashboard surfaces this so it badges retrieval honestly rather than
    /// implying paraphrase matching a lean build does not do (see README
    /// "Retrieval honesty").
    #[must_use]
    pub fn is_semantic(&self) -> bool {
        self.index.is_semantic()
    }

    /// Hydrate the full [`Note`] behind `id`: locate, fetch, verify, decrypt.
    ///
    /// # Errors
    ///
    /// Returns [`MemError::NotFound`] if `id` is not indexed,
    /// [`MemError::KeyUnavailable`] if the note's key epoch is not in this store's
    /// key-ring (this member was never provisioned that epoch),
    /// [`MemError::Storage`] if the fetched ciphertext does not match the indexed
    /// content hash, [`MemError::Crypto`] if decryption or UTF-8 decoding fails, or
    /// [`MemError::Serialize`] if the decrypted JSON is not a valid note.
    ///
    /// Unlike [`MemoryStore::sync`], which *skips* a note whose epoch key is absent
    /// (a member missing one old epoch must still index the rest), `get` *errors*:
    /// the caller asked for this specific note and cannot be served it.
    pub async fn get(&self, id: NoteId) -> Result<Note, MemError> {
        let located = self
            .index
            .locate(id)?
            .ok_or_else(|| MemError::NotFound { id: id.to_string() })?;
        // Select the note's epoch key before fetching: a missing epoch is a clear,
        // immediate error and there is no point pulling the blob we cannot open.
        let key = self.key_for_epoch(located.key_epoch)?;
        let ciphertext = self.blob.get(&located.object_key).await?;

        // Integrity gate before decryption: if the stored object was corrupted
        // or a different object was swapped under this key, its hash will not
        // match the cid the index recorded at write time. Reject it here so a
        // mismatch surfaces as a clear storage error instead of an opaque AEAD
        // failure — or, worse, a successful decrypt of a substituted ciphertext
        // under the shared team key.
        if content_hash(&ciphertext) != located.cid {
            return Err(MemError::Storage(
                "ciphertext hash does not match the indexed content hash".to_string(),
            ));
        }

        // The object key is passed as AEAD associated data: if these bytes were
        // relocated from another key, authentication fails here even though the
        // content hash matched, because the key the bytes were fetched from is
        // not the key they were sealed under.
        let plaintext = open(&key, &ciphertext, located.object_key.as_bytes())?;
        let json = std::str::from_utf8(&plaintext).map_err(|_| MemError::Crypto)?;
        let note = Note::from_json(json)?;
        // Feature 4: a `get` of a recently-recalled note is a use signal; reinforce
        // it, best-effort. Deliberately AFTER the note is successfully hydrated (a
        // failed get is not a use) and never propagates an error — reinforcement
        // must not turn a good read into a failure.
        self.maybe_reinforce(id).await;
        Ok(note)
    }

    /// Best-effort reinforcement of a note opened after a recent recall (Feature 4).
    ///
    /// Emits a signed [`OpKind::Reinforce`] at most once per note per
    /// [`REINFORCE_RATE_LIMIT`], and only when a `recall` within
    /// [`RECALL_USE_WINDOW`] surfaced the note. Any append failure is logged at
    /// debug and swallowed: reinforcement is a convergent side signal, never a
    /// reason to fail the caller's `get`. The op is idempotent under convergence
    /// (a duplicate folds into the same distinct-author set), so a dropped append
    /// self-heals on the next qualifying use.
    async fn maybe_reinforce(&self, id: NoteId) {
        if !self.reinforce_qualifies(id) {
            return;
        }
        if let Err(err) = self.append_reinforce(id).await {
            tracing::debug!(error = %err, note_id = %id, "reinforce append failed (non-fatal)");
            // Give the rate-limit slot back: `reinforce_qualifies` claims it under
            // the lock BEFORE the append (so concurrent gets cannot double-emit),
            // but a slot held for an op that never landed would make the next
            // qualifying use wait out the whole window — the opposite of the
            // "self-heals on the next qualifying use" contract above. The remove
            // is unconditional: in the (pathological) interleaving where this
            // failed append outlived the whole window and a NEWER attempt re-took
            // the slot, releasing that newer slot costs at most one extra
            // Reinforce op, which folds idempotently into the distinct-author set.
            self.reinforce
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .reinforced
                .remove(&id);
        }
    }

    /// Decide, under the tracker lock, whether to emit a `Reinforce` for `id`, and
    /// if so record it so the rate limit holds. Returns `true` at most once per note
    /// per [`REINFORCE_RATE_LIMIT`], and only when a recent recall surfaced `id`.
    ///
    /// The guard is taken and DROPPED here, before [`maybe_reinforce`] awaits the
    /// append, so the tracker lock never spans an `.await`.
    fn reinforce_qualifies(&self, id: NoteId) -> bool {
        let now = Instant::now();
        let mut tracker = self
            .reinforce
            .lock()
            .unwrap_or_else(PoisonError::into_inner);

        prune_expired(&mut tracker.recalled, now, RECALL_USE_WINDOW);
        prune_expired(&mut tracker.reinforced, now, REINFORCE_RATE_LIMIT);

        // Only a note a recent recall surfaced is a use signal — a bare by-id `get`
        // with no preceding recall does not reinforce.
        if !tracker.recalled.contains_key(&id) {
            return false;
        }

        // Rate limit: at most one reinforce per note per window from this machine.
        if tracker.reinforced.contains_key(&id) {
            return false;
        }

        tracker.reinforced.insert(id, now);
        true
    }

    /// Append a signed [`OpKind::Reinforce`] naming `id`, mirroring [`Self::relate`]'s
    /// blob-less op path: the op carries `id`'s current object coordinates so the
    /// signed frame is complete, but writes no new blob.
    ///
    /// # Errors
    ///
    /// [`MemError::NotFound`] if `id` is not indexed; otherwise whatever
    /// [`Self::mint_and_append`] reports (serialize / storage).
    async fn append_reinforce(&self, id: NoteId) -> Result<(), MemError> {
        let located = self
            .index
            .locate(id)?
            .ok_or_else(|| MemError::NotFound { id: id.to_string() })?;

        let op = self
            .mint_and_append(
                Ulid::new(),
                OpKind::Reinforce,
                OpTarget {
                    note_id: id,
                    object_key: located.object_key,
                    cid: located.cid,
                    key_epoch: located.key_epoch,
                },
            )
            .await?;

        self.schedule_anchor(op.hash(), op.lamport).await;
        Ok(())
    }

    /// The current content version (ciphertext `cid`) of `id` in this machine's
    /// converged index — the token an agent reads here (or alongside `get`) and
    /// passes back to [`edit_with_precondition`](Self::edit_with_precondition) for
    /// a compare-and-swap.
    ///
    /// # Errors
    ///
    /// [`MemError::NotFound`] if `id` is not indexed (never seen, forgotten, or
    /// redacted on this machine); whatever the index reports on lookup.
    pub fn current_version(&self, id: NoteId) -> Result<Blake3Hash, MemError> {
        Ok(self
            .index
            .locate(id)?
            .ok_or_else(|| MemError::NotFound { id: id.to_string() })?
            .cid)
    }

    /// Tombstone `note_id`: append a signed `Forget` op, then drop it from the
    /// local index so `recall` stops surfacing it.
    ///
    /// The op carries the note's *current* object key and content hash, looked up
    /// from the index ([`MemoryIndex::locate`]). Convergence reads only the op's
    /// kind to decide the tombstone, but stamping the real coordinates keeps every
    /// op a faithful record of the blob it acted on. Forgetting an unknown note is
    /// [`MemError::NotFound`] — you cannot tombstone what this machine has never
    /// seen (run `sync` first to learn a teammate's note).
    ///
    /// # Ordering
    ///
    /// `oplog.append` → `index.remove`: the forget is durable in the shared log
    /// before it is hidden locally, so a crash cannot hide a note whose tombstone
    /// was never recorded (which `sync` would then resurrect).
    ///
    /// # Errors
    ///
    /// [`MemError::NotFound`] if `note_id` is not indexed; [`MemError::Serialize`]
    /// / [`MemError::Storage`] if the op cannot be encoded or appended; or whatever
    /// the index reports on remove.
    pub async fn forget(&self, note_id: NoteId) -> Result<(), MemError> {
        let located = self
            .index
            .locate(note_id)?
            .ok_or_else(|| MemError::NotFound {
                id: note_id.to_string(),
            })?;

        let op = self
            .mint_and_append(
                Ulid::new(),
                OpKind::Forget,
                OpTarget {
                    note_id,
                    object_key: located.object_key,
                    cid: located.cid,
                    key_epoch: located.key_epoch,
                },
            )
            .await?;

        self.index.remove(note_id)?;
        self.schedule_anchor(op.hash(), op.lamport).await;

        Ok(())
    }

    /// Permanently scrub `note_id`'s content: append a signed `Redact` op, delete
    /// every ciphertext version it has, then drop it from the local index.
    ///
    /// The irreversible counterpart to [`forget`](Self::forget). `forget` only
    /// tombstones — the blob stays for the audit trail; `redact` additionally
    /// deletes the blob, so the body can never be recovered. Use it for a leaked
    /// secret, PII, or a deletion request. The signed op (and its anchored Merkle
    /// leaf) survive, so the redaction itself stays provable in `history`
    /// ([`NoteHistory::redacted`]); convergence makes a redacted note absorbing —
    /// no later op resurrects it.
    ///
    /// # Ordering
    ///
    /// `oplog.append` → `blob.delete(...)` → `index.remove`, INVERTING
    /// `remember`/`edit` (which write the blob before the op). The op's job is to
    /// *hide*, so it lands first and is durable even if scrubbing is interrupted.
    /// Scrubbing then runs BEFORE the note leaves the index and its outcome is
    /// propagated: a scrub failure returns an error with the note still indexed, so
    /// `redact` is genuinely re-runnable and never reports a deletion that did not
    /// happen. There is no background sweep — an un-propagated failure would leave
    /// ciphertext the log claims is gone, decryptable by any team-key holder.
    ///
    /// Caveat: scrubbing lists the note's blob prefix on the shared store, so it
    /// covers every version present when the list runs — including a straggler an
    /// unsynced machine already uploaded, which the earlier op-log scan missed.
    /// The residual is only a blob written *after* that list returns; the note
    /// still converges redacted (so it never surfaces), and a re-run scrubs the
    /// straggler.
    ///
    /// Scope of the scrub: it reclaims the note's BODY ciphertext (the sealed
    /// blobs). A note's `summary`, however, is also sealed into any
    /// [`IndexSnapshot`] envelope taken while the note was live, and redaction does
    /// NOT rewrite those envelopes — so a secret placed in the *summary* can
    /// survive inside an existing snapshot until it is pruned or superseded. Put
    /// secrets in the body, not the summary; purging snapshot envelopes on redact
    /// is future work.
    ///
    /// # Errors
    ///
    /// [`MemError::NotFound`] if `note_id` is not indexed; [`MemError::Serialize`]
    /// / [`MemError::Storage`] if the op cannot be encoded or appended; a
    /// [`BlobStore::delete`] error if any ciphertext version could not be scrubbed
    /// (the note stays indexed for a re-run); or whatever the index reports on
    /// remove.
    pub async fn redact(&self, note_id: NoteId) -> Result<(), MemError> {
        let located = self
            .index
            .locate(note_id)?
            .ok_or_else(|| MemError::NotFound {
                id: note_id.to_string(),
            })?;
        // Derive the note's blob-prefix from a known version key BEFORE the key is
        // moved into the op below. A note's repo is fixed at `remember`, so every
        // version shares this prefix; scrubbing lists them all without re-reading
        // the op-log.
        let note_prefix = note_blob_prefix(&located.object_key)?;
        let op = self
            .mint_and_append(
                Ulid::new(),
                OpKind::Redact,
                OpTarget {
                    note_id,
                    object_key: located.object_key,
                    cid: located.cid,
                    key_epoch: located.key_epoch,
                },
            )
            .await?;
        // Scrub BEFORE dropping the note from the index, and propagate a failure:
        // leaving it indexed keeps `redact` re-runnable and never reports a deletion
        // that did not happen. The `Redact` op above has already converge-hidden it,
        // so the hide is durable regardless of whether the scrub completes.
        self.scrub_blobs(&note_prefix).await?;
        self.index.remove(note_id)?;
        self.schedule_anchor(op.hash(), op.lamport).await;
        Ok(())
    }

    /// Delete every ciphertext blob under `note_prefix` and report whether the
    /// scrub completed.
    ///
    /// `note_prefix` is a note's `{team}/{repo_segment}/{mem_id}/` keyspace (from
    /// [`note_blob_prefix`]). Because a note's repo is fixed at `remember` (an edit
    /// preserves it), every version lives under that one prefix, so a single
    /// [`BlobStore::list`] enumerates them all. Listing the bytes rather than
    /// deriving keys from the op-log is both cheaper — no full-log read + per-op
    /// verification just to find one note's keys — and MORE complete for a
    /// redaction: it also removes a straggler version whose op has not reached this
    /// machine's log yet, and an orphan blob whose op never verified, neither of
    /// which an op-log-derived key set would name. The residual is only a blob
    /// written *after* the list returns, which a re-run scrubs.
    ///
    /// Every listed key is attempted even if an earlier delete fails, then the
    /// FIRST failure is surfaced — one unreachable key must not leave the rest
    /// recoverable, and the caller ([`redact`](Self::redact)) must learn the scrub
    /// was incomplete rather than report a deletion that did not happen. The
    /// `Redact` op already converge-hides the note, so the durability of the *hide*
    /// never depends on this finishing; only the reclamation of bytes does.
    ///
    /// # Errors
    ///
    /// Whatever [`BlobStore::list`] reports if the prefix cannot be listed, or the
    /// first [`BlobStore::delete`] error if any version could not be scrubbed.
    async fn scrub_blobs(&self, note_prefix: &str) -> Result<(), MemError> {
        let keys = self.blob.list(note_prefix).await?;
        let mut first_err: Option<MemError> = None;
        for key in &keys {
            if let Err(err) = self.blob.delete(key).await {
                tracing::warn!(
                    object_key = %key,
                    error = %err,
                    "could not scrub a redacted note's ciphertext"
                );
                // Remember the first failure but keep scrubbing the remaining
                // versions, so one bad key does not leave the others recoverable.
                first_err.get_or_insert(err);
            }
        }
        match first_err {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    /// Reclaim orphaned note-ciphertext blobs: delete every note blob in this team's
    /// keyspace that NO durable op names and that is older than `grace`, returning a
    /// [`OrphanSweepReport`]. With `dry_run` it counts orphans but deletes nothing.
    ///
    /// # Why this exists
    ///
    /// `remember`/`edit` write the ciphertext blob BEFORE appending the op that
    /// names it (the recoverable-prefix ordering, so a crash never leaves an op
    /// pointing at an unwritten body). If that future is DROPPED — cancelled — or the
    /// process dies between those two `.await`s, the blob lands with no op ever
    /// naming it: an orphan the `Err`-only reclaim in [`append_naming_blob`] never
    /// runs for, wasting storage forever (the CANCELSAFETY finding). This
    /// mark-and-sweep reaps them from OBSERVED durable state, the only way to do it
    /// safely — a `Drop`-guard delete cannot tell a cancelled-before-commit append
    /// (blob is a true orphan) from a cancelled-after-commit one (a durable op DOES
    /// name the blob), so it would risk deleting a live note's body. The sweep
    /// deletes only what the durable op-log proves unreferenced.
    ///
    /// # Safety of scope
    ///
    /// Every listed key runs through [`parse_object_key`], which accepts ONLY the
    /// 4-segment `{team}/{repo}/{mem_id}/ver_{ulid}` note-blob shape and rejects the
    /// `_oplog` / `_snapshots` / `_anchors` / `_keys` / `_memberkeys` internal
    /// namespaces that share the keyspace — so the sweep can never touch the op-log,
    /// snapshots, anchors, or key wraps.
    ///
    /// The referenced set is drawn from [`OpLogStore::read_all`] (signature- and
    /// chain-verified, BEFORE the membership filter [`read_and_filter`] applies), so
    /// a blob an ex-member's still-valid op names is kept, never reaped. `read_all`'s
    /// systemic-outage guard errors when failed GETs and the ops they orphan cost at
    /// least half the listed objects, so the sweep aborts rather than reap against a
    /// partial view. That guard is this sweep's ONLY floor — there is no
    /// empty-`referenced` check here — so an `Ok(empty)` read repeated across both
    /// reads below would unreference and DELETE every note blob past the grace
    /// window. Weakening the guard is a data-loss risk for this function
    /// specifically; the gaps it does not cover (a backend answering with junk
    /// bytes, notably) are listed in `read_verified`'s own comment and would have to
    /// be floored here. It is read TWICE and the
    /// two referenced sets are combined by union: an isolated transient op-fetch skip
    /// (which `read_all` tolerates per-object) that omits a live op from one read is
    /// almost never repeated in the other, so a blob is reaped only when BOTH reads
    /// agree it is unreferenced — the sweep's error direction is
    /// destructive-to-live-data (unlike `redact`'s safe under-deletion), which
    /// warrants the extra read.
    ///
    /// # Grace window
    ///
    /// A blob is reaped only if `now - version_ulid_time >= grace`. The version ULID
    /// in the key timestamps the write, so a young unreferenced blob — an in-flight
    /// write whose op has not appended, or one hidden by a lagging op-log listing — is
    /// kept. Orphans are permanent and harmless, so a generous `grace` trades
    /// promptness for zero wrongful-delete risk.
    ///
    /// # Errors
    ///
    /// [`MemError`] if either op-log read or the keyspace listing fails (the sweep
    /// cannot proceed safely without a complete referenced set). Individual blob
    /// deletes are best-effort: a delete failure is logged and the sweep continues,
    /// so one unreachable key never aborts reclaiming the rest.
    pub async fn sweep_orphan_blobs(
        &self,
        grace: Duration,
        dry_run: bool,
    ) -> Result<OrphanSweepReport, MemError> {
        // Union of two independent verified reads (see the safety note): a blob is an
        // orphan only if BOTH reads agree no op names it, so an isolated transient
        // op-GET skip in one read cannot cause a live blob to be deleted. `read_all`
        // (not `read_and_filter`) is deliberate — no membership filter, so a blob an
        // ex-member's valid op names stays referenced. Read lock-free: the sweep
        // never writes, and `read_all` re-locks nothing (see `read_and_filter`).
        let mut referenced: HashSet<String> = HashSet::new();
        for _ in 0..2 {
            let ops = self.oplog.read_all(&self.team).await?;
            referenced.extend(ops.iter().map(|op| op.object_key.clone()));
        }

        // List the whole team keyspace once; the note-key parse below is the scope
        // gate that keeps this from ever considering an internal-namespace object.
        let team_prefix = format!("{}/", self.team);
        let all_keys = self.blob.list(&team_prefix).await?;

        let now_ms = current_millis().as_millis();
        let grace_ms = i64::try_from(grace.as_millis()).unwrap_or(i64::MAX);

        let mut report = OrphanSweepReport::default();
        for key in &all_keys {
            // Not a note blob (an internal namespace or a malformed key) — out of
            // scope. This is the invariant that keeps the op-log, snapshots, anchors,
            // and key wraps untouchable.
            let Ok((_scope, _id, version)) = parse_object_key(key) else {
                continue;
            };
            report.note_blobs_scanned += 1;
            // Named by a durable op — a live note or a superseded version; keep it.
            // Superseded-version compaction is a separate concern from orphan
            // reclamation, so a blob any op still names is never reaped here.
            if referenced.contains(key) {
                continue;
            }
            // Unreferenced but young: an in-flight write's op may not have appended
            // yet, or the op-log listing lags its writes. Keep it; a later sweep reaps
            // it once the grace window proves no op will ever name it. `saturating_sub`
            // guards a version stamped in the future by a skewed clock (age floors at
            // 0, so it is treated as young and kept).
            let version_ms = i64::try_from(version.timestamp_ms()).unwrap_or(i64::MAX);
            if now_ms.saturating_sub(version_ms) < grace_ms {
                report.within_grace_kept += 1;
                continue;
            }
            report.orphans_found += 1;
            if dry_run {
                tracing::info!(object_key = %key, "orphan ciphertext blob (dry-run: not deleted)");
                continue;
            }
            // Best-effort: one unreachable key must not abort reclaiming the rest, and
            // `delete` is idempotent, so a racing sweep or a later retry is harmless.
            match self.blob.delete(key).await {
                Ok(()) => {
                    report.orphans_reclaimed += 1;
                    tracing::info!(object_key = %key, "reclaimed an orphaned ciphertext blob");
                }
                Err(err) => tracing::warn!(
                    object_key = %key,
                    error = %err,
                    "could not delete an orphaned blob; a later sweep will retry"
                ),
            }
        }
        Ok(report)
    }

    /// Assert a directed link from `from` to `to` by appending a signed
    /// `Link { to }` op.
    ///
    /// Links feed convergence and the history/graph view, *not* recall ranking,
    /// so there is no index change here — the link surfaces through
    /// [`MemoryStore::history`], which reads the converged link set
    /// ([`NoteHistory::links`]). The op is stamped with `from`'s current object
    /// key and content hash (from the index); `from` must therefore be a note this
    /// machine knows, else [`MemError::NotFound`].
    ///
    /// # Errors
    ///
    /// [`MemError::NotFound`] if `from` is not indexed; [`MemError::Serialize`] /
    /// [`MemError::Storage`] if the op cannot be encoded or appended.
    pub async fn link(&self, from: NoteId, to: NoteId) -> Result<(), MemError> {
        self.relate(from, to, LinkRel::Related).await
    }

    /// Assert a TYPED relationship from `from` to `to` — the note `from` supersedes
    /// / duplicates / contradicts / refines `to` (or, for [`LinkRel::Related`], a
    /// plain link).
    ///
    /// A `Supersedes`/`Duplicates` relation is what demotes `to` in recall: the
    /// superseded note is still returned and tagged `[superseded by from]`, never
    /// dropped, so the decision trail stays auditable. The relation is
    /// source-stamped on `from` (the op's `note_id`), which is where converge
    /// groups it; recall inverts it at query time.
    ///
    /// [`LinkRel::Related`] emits the legacy [`OpKind::Link`] op (byte-identical to
    /// pre-typed-relation writes); every other relation emits [`OpKind::Relate`].
    /// The op is stamped with `from`'s current object key and content hash, so
    /// `from` must be a note this machine knows, else [`MemError::NotFound`].
    ///
    /// # Errors
    ///
    /// [`MemError::NotFound`] if `from` is not indexed; [`MemError::Serialize`] /
    /// [`MemError::Storage`] if the op cannot be encoded or appended.
    pub async fn relate(&self, from: NoteId, to: NoteId, rel: LinkRel) -> Result<(), MemError> {
        let located = self.index.locate(from)?.ok_or_else(|| MemError::NotFound {
            id: from.to_string(),
        })?;

        // A plain relation keeps emitting `Link` so its signed bytes match every
        // pre-typed-relation op; a typed relation uses the new `Relate` variant.
        let kind = if rel == LinkRel::Related {
            OpKind::Link { to }
        } else {
            OpKind::Relate { to, rel }
        };

        let op = self
            .mint_and_append(
                Ulid::new(),
                kind,
                OpTarget {
                    note_id: from,
                    object_key: located.object_key,
                    cid: located.cid,
                    key_epoch: located.key_epoch,
                },
            )
            .await?;

        self.schedule_anchor(op.hash(), op.lamport).await;
        Ok(())
    }

    /// Reconstruct the full op history of `note_id`, attaching a Merkle
    /// inclusion proof to every op already anchored.
    ///
    /// Reads the shared op-log directly (every op is signature- and
    /// chain-verified by [`OpLogStore::read_all`]), keeps the ops naming
    /// `note_id` in `(lamport, op_id)` order, and converges them to decide
    /// `tombstoned`. For each op it finds the anchored batch whose leaves
    /// contain the op's hash and builds an [`AnchorProof`]; an op not yet
    /// anchored carries `None`. An unknown note yields an empty history, never
    /// an error — `history` reads the log, not the index, so "no ops" is the
    /// truthful answer rather than a [`MemError::NotFound`].
    ///
    /// # Accountability
    ///
    /// Each [`AnchorProof`] lets a reader recompute the op's inclusion under its
    /// root via [`verify_proof`](crate::audit::verify_proof). That is
    /// trust-minimized only with `chain` anchoring, where the root is on-chain and
    /// a verifier compares it against the chain (see [`AnchorProof`] for the
    /// Local-vs-chain distinction); under the default local anchor it attests only
    /// internal consistency against a root this server itself stored.
    ///
    /// # Errors
    ///
    /// Whatever [`OpLogStore::read_all`] reports (storage, deserialization, or a
    /// signature/chain violation), or [`MemError::Storage`] /
    /// [`MemError::Serialize`] if reading an anchor record or building a proof
    /// fails.
    pub async fn history(&self, note_id: NoteId) -> Result<NoteHistory, MemError> {
        let ops = self.oplog.read_all(&self.team).await?;
        // `read_all` returns global ascending `(lamport, op_id)` order; a filter
        // preserves relative order, so the note's entries are already in
        // convergence order without a re-sort.
        let note_ops: VerifiedOps = ops.filter(|op| op.note_id == note_id);
        // Converge once to read both the tombstone flag and the link set. For a
        // live note the converged `links` is the grow-only union of its `Link`
        // targets; for a REDACTED note it is empty (redaction scrubs the graph
        // metadata) — the audit shell (`redacted` flag + op entries) still stands.
        let converged = converge(&note_ops);
        let state = converged.get(&note_id);
        let tombstoned = state.is_some_and(|state| state.tombstoned);
        // Redaction is observable HERE (not via `get`): `get` reads the index,
        // from which a redacted note has been removed, so it would only say
        // NotFound. `history` reads the op-log and converges it, so it can report
        // that the note existed and was scrubbed — the audit shell — alongside the
        // surviving op trail in `entries`.
        let redacted = state.is_some_and(|state| state.redacted);
        let links: Vec<NoteId> = state
            .map(|state| state.links.iter().copied().collect())
            .unwrap_or_default();

        let records = read_anchor_records(&self.blob, &self.team).await?;
        // Compute each batch's Merkle root once, up front. Every op below re-checks
        // the M3 root-commitment binding against its anchoring batch; sharing these
        // precomputed roots keeps that check O(batches × leaves) instead of
        // rehashing a batch per op it anchors (see `anchor_proof_for`).
        let record_roots: Vec<Blake3Hash> = records
            .iter()
            .map(|record| merkle_root(&record.leaves))
            .collect();
        let mut entries = Vec::with_capacity(note_ops.len());
        for op in note_ops.iter() {
            // The op hash recomputed here is byte-identical to the leaf the
            // batcher pushed into `AnchorRecord::leaves` (both call `Op::hash`),
            // so the inclusion proof built from it verifies against the root.
            let op_hash = op.hash();
            entries.push(HistoryEntry {
                op_id: op.op_id.to_string(),
                author: op.author.clone(),
                author_key: op.author_key,
                lamport: op.lamport,
                kind: OpKindLabel::from(&op.kind),
                cid: op.cid,
                op_hash,
                anchor: anchor_proof_for(&records, &record_roots, op_hash)?,
            });
        }
        Ok(NoteHistory {
            note_id,
            tombstoned,
            redacted,
            links,
            entries,
        })
    }

    /// Reconcile this team's visible op-log against its anchored Merkle roots.
    ///
    /// # Trust scope (read this before relying on `ok`)
    ///
    /// When a [`SubxtAnchor`](crate::audit::SubxtAnchor) is wired (the
    /// `chain` feature with a configured endpoint), this reads every on-chain
    /// root back from the chain via
    /// [`reconcile_with_chain`](crate::audit::reconcile_with_chain),
    /// so a record the bucket forged self-consistently (`root ==
    /// merkle_root(leaves)` yet never committed) is still caught — the
    /// trust-minimized check, because the bucket cannot fake the chain.
    ///
    /// In the default **local mode** both the op-log AND the anchor records live
    /// in the same untrusted bucket, so this detects accidental or partial
    /// op-log loss (an op dropped while its anchor record is retained) but NOT
    /// adversarial suppression: a bucket that drops an op *together with* its
    /// anchor record leaves nothing to reconcile against and still reports `ok`.
    ///
    /// Enabling `chain` does NOT close that record-omission gap. The chain pass
    /// hardens *forgery* detection — it catches a record the bucket KEEPS but
    /// never actually committed — but it still iterates only the records the
    /// bucket serves, so a record DROPPED together with its op is never examined.
    /// Detecting that would need an independent enumeration of the team's
    /// committed roots from the chain, which the per-(block, extrinsic) readback
    /// cannot provide. Either way, only ops that were actually anchored are
    /// covered — an op dropped before its batch anchored leaves no commitment
    /// (see the module docs).
    ///
    /// # Errors
    ///
    /// Propagates whatever [`crate::audit::reconcile`] reports — a
    /// backend listing/fetch failure, an undecodable anchor record, or an op-log
    /// integrity violation from the verified read — plus, on the chain path, any
    /// [`MemError::Storage`] from reading a block back off the chain.
    pub async fn reconcile(&self) -> Result<ReconcileReport, MemError> {
        // Recover the concrete chain anchor (if any) to take the trust-minimized
        // readback path; a local fake or a non-chain build falls through to the
        // bucket-only check. Downcast via `AuditAnchor::as_any` so the store need
        // not carry a second, chain-gated anchor field.
        #[cfg(feature = "chain")]
        if let Some(subxt) = self
            .anchor
            .as_any()
            .downcast_ref::<crate::audit::SubxtAnchor>()
        {
            return crate::audit::reconcile_with_chain(&self.blob, &self.oplog, &self.team, subxt)
                .await;
        }
        crate::audit::reconcile(&self.blob, &self.oplog, &self.team).await
    }

    /// Buffer `leaf` for batched anchoring and seal the batch if it has reached
    /// the threshold.
    ///
    /// Best-effort by contract: the op is already durable in the op-log (the
    /// source of truth), so a failed anchor is logged and its leaves retained for
    /// the next attempt — it never fails the caller's write. The guard over
    /// [`MemoryStore::anchor_state`] is dropped before every `.await`
    /// (axiom `rust_quality_74`): we push under the lock, seed the seq and commit
    /// without it.
    async fn schedule_anchor(&self, leaf: Blake3Hash, lamport: u64) {
        let reached = {
            let mut state = self
                .anchor_state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            state.pending.push(PendingLeaf {
                hash: leaf,
                lamport,
            });
            state.pending.len() >= self.anchor_threshold
        };
        if !reached {
            return;
        }
        // Seed `next_seq` from durable records before reserving one, so this
        // process's first batch does not overwrite a prior run's records.
        if let Err(err) = self.ensure_seq_seeded().await {
            tracing::warn!(
                error = %err,
                "could not seed the anchor sequence; the batch is retained for the next attempt"
            );
            return;
        }
        let batch = {
            let mut state = self
                .anchor_state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            // A concurrent caller may have drained between the push above and
            // here; only reserve a seq if leaves are actually waiting.
            if state.pending.is_empty() {
                None
            } else {
                Some(state.drain_batch())
            }
        };
        let Some(batch) = batch else { return };
        if let Err(err) = self.commit_batch(batch).await {
            tracing::warn!(
                error = %err,
                "anchoring a full batch failed; its leaves are retained for the next attempt"
            );
        }
    }

    /// Lazily seed this author's `next_seq` from the persisted anchor records.
    ///
    /// On the first anchor of a process, `next_seq` must continue past any
    /// records THIS author already wrote (a prior run, or a sibling store over
    /// the same bucket), or new records would overwrite them under
    /// `{team}/_anchors/{author_key}/`. The records are read once (outside the
    /// `anchor_state` guard — the read awaits), then `next_seq` is set to
    /// `max(this author's seq) + 1` under the guard, double-checking `seeded` so
    /// a concurrent caller's seed is not clobbered.
    ///
    /// # Errors
    ///
    /// Whatever [`read_anchor_records`] reports if the listing or a fetch fails.
    async fn ensure_seq_seeded(&self) -> Result<(), MemError> {
        if self
            .anchor_state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .seeded
        {
            return Ok(());
        }
        let author_key = self.author_key();
        let records = read_anchor_records(&self.blob, &self.team).await?;
        let next = records
            .iter()
            .filter(|record| record.author_key == author_key)
            .map(|record| record.seq.saturating_add(1))
            .max()
            .unwrap_or(0);
        let mut state = self
            .anchor_state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if !state.seeded {
            state.next_seq = next;
            state.seeded = true;
        }
        Ok(())
    }

    /// This store's sr25519 public key — the identity its ops and anchor records
    /// are attributed to (and the namespace its `_anchors/` keys live under).
    fn author_key(&self) -> VerifyingKey {
        self.signer.verifying_key()
    }

    /// Force-anchor any pending leaves, returning the receipt if a batch was sealed.
    ///
    /// Returns `Ok(None)` when nothing is pending. Intended for tests and graceful
    /// shutdown; the threshold path in [`MemoryStore::schedule_anchor`] handles
    /// steady-state batching. Unlike that path, a failure here PROPAGATES (with the
    /// leaves restored), so a caller flushing before exit learns the batch did not
    /// land.
    ///
    /// # Errors
    ///
    /// Whatever [`AuditAnchor::anchor`] or the blob store reports; on error the
    /// pending leaves are restored before the error returns, so nothing is lost.
    pub async fn flush_anchors(&self) -> Result<Option<AnchorReceipt>, MemError> {
        {
            // Nothing pending: skip the record read `ensure_seq_seeded` would do.
            let state = self
                .anchor_state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if state.pending.is_empty() {
                return Ok(None);
            }
        }
        // Seed the seq before reserving one, mirroring `schedule_anchor`.
        self.ensure_seq_seeded().await?;
        let batch = {
            let mut state = self
                .anchor_state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if state.pending.is_empty() {
                None
            } else {
                Some(state.drain_batch())
            }
        };
        let Some(batch) = batch else { return Ok(None) };
        let receipt = self.commit_batch(batch).await?;
        Ok(Some(receipt))
    }

    /// Build the batch's Merkle root, anchor it, and persist its [`AnchorRecord`].
    ///
    /// # Ordering, and why leaves can't be lost
    ///
    /// The leaves are ALREADY drained from `pending` (under the lock, by the
    /// caller) with a seq reserved. We build the root, anchor it, then persist the
    /// record. On ANY failure — anchor or persist — the drained leaves are returned
    /// to `pending` (under the lock) so the next write or [`MemoryStore::flush_anchors`]
    /// retries them; the reserved seq is not reclaimed, so a later batch never
    /// reuses this one's object key. A persist failure *after* a successful anchor
    /// re-anchors the same deterministic root next time, a harmless duplicate
    /// commit — preferable to dropping the local record `history` needs.
    ///
    /// # Errors
    ///
    /// Propagates the anchor sink's or blob store's [`MemError`]; on error the
    /// leaves have been restored before returning.
    async fn commit_batch(&self, batch: DrainedBatch) -> Result<AnchorReceipt, MemError> {
        // Derive everything the anchor and record need from `batch` BEFORE the guard
        // takes ownership. No `.await` runs in this prelude, so a cancellation here
        // is impossible and the record is never half-built.
        let seq = batch.seq;
        let leaves: Vec<Blake3Hash> = batch.leaves.iter().map(|leaf| leaf.hash).collect();
        let root = merkle_root(&leaves);
        let meta = BatchMeta {
            team: self.team.clone(),
            // min/max, not first/last: leaves are in pending-push order, which
            // races op-append under concurrent writers, so first/last could
            // otherwise emit an inverted (first > last) range into the anchor.
            first_lamport: batch
                .leaves
                .iter()
                .map(|leaf| leaf.lamport)
                .min()
                .unwrap_or(0),
            last_lamport: batch
                .leaves
                .iter()
                .map(|leaf| leaf.lamport)
                .max()
                .unwrap_or(0),
            op_count: leaves.len(),
        };

        // From here the commit crosses `.await` points (anchor, then persist). Arm
        // the cancellation guard so a dropped commit future returns the drained
        // leaves to `pending` rather than silently losing their anchor proof. Each
        // explicit return disarms it — the `Err` paths restore by hand exactly as
        // before, the `Ok` path drops the batch.
        let mut guard = BatchGuard::arm(self, batch);

        let mut receipt = match self.anchor.anchor(root, meta.clone()).await {
            Ok(receipt) => receipt,
            Err(err) => {
                if let Some(batch) = guard.disarm() {
                    self.restore_pending(batch);
                }
                return Err(err);
            }
        };
        // The anchor sink cannot know the per-author batch seq — it is assigned by
        // AnchorState, not the sink — so a local sink returns a placeholder
        // `Local { seq: 0 }`. Stamp the real seq so `MissingOp::anchor_ref` points
        // at the batch that actually committed the op, not always batch 0. The
        // on-chain reference carries block/extrinsic hashes and is left untouched.
        if let AnchorRef::Local { seq: slot } = &mut receipt.reference {
            *slot = seq;
        }

        let record = AnchorRecord {
            seq,
            author_key: self.author_key(),
            root,
            meta,
            leaves,
            receipt: receipt.clone(),
        };
        if let Err(err) = persist_anchor_record(&self.blob, &self.team, &record).await {
            if let Some(batch) = guard.disarm() {
                self.restore_pending(batch);
            }
            return Err(err);
        }
        // Committed: the leaves must NOT return to pending — disarm and drop them.
        let _ = guard.disarm();
        Ok(receipt)
    }

    /// Return a failed batch's leaves to `pending` (without reclaiming its seq).
    fn restore_pending(&self, batch: DrainedBatch) {
        self.anchor_state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .restore(batch);
    }

    /// Replay the shared op-log into the local index, restoring the latest index
    /// snapshot when one exists and tailing only the newer ops. Returns the number
    /// of live (non-tombstoned) notes indexed.
    ///
    /// The signed, hash-chained op-log — not a raw bucket listing — is the source
    /// of truth, so a machine joining a team replays it to discover everything
    /// teammates have written, including tombstones (a forgotten note is *removed*
    /// from the index, not merely absent).
    ///
    /// `sync` is **authoritative**: it prunes the index down to exactly the
    /// currently-live converged set via [`crate::index::MemoryIndex::retain`], so
    /// it works on a long-lived (warm) index, not only a cold rebuild. A note no
    /// longer live — a removed member's note, or one whose content op no longer
    /// survives convergence — is dropped on the next `sync`.
    ///
    /// # Incremental restore
    ///
    /// When [`load_latest_snapshot`] finds a checkpoint, `sync` restores its
    /// pre-decoded records and converges only the ops newer than the snapshot's
    /// baseline Lamport, decoding blobs solely for the notes the tail touched (the
    /// incremental restore path); with no snapshot it falls back to a full replay.
    /// Either way the op-log is read and verified in full first — a hash chain can
    /// only be checked from its genesis root — so the snapshot saves note-blob
    /// decodes, not op-log reads. The restore is sound only while the snapshot
    /// still reflects every op at or below its baseline; a late/out-of-order op or
    /// a membership change is detected and forces a full rebuild (see the
    /// incremental restore path's correctness argument).
    ///
    /// # Resilience
    ///
    /// A *data* fault on one note — its blob fails to fetch, decrypt, or parse —
    /// is logged via `tracing::warn!` and skipped, so one corrupt or foreign blob
    /// never blinds the machine to the rest of the team's memory. A `read_all`
    /// failure (no verified log to replay from) and an `index.upsert`/`remove`
    /// fault both propagate: failing fast is correct when the systemic machinery
    /// is broken.
    ///
    /// # Errors
    ///
    /// Whatever [`OpLogStore::read_all`], [`load_manifest`], or
    /// [`load_latest_snapshot`] report (storage, deserialization, or a
    /// signature/chain violation), or whatever the index reports on upsert/remove.
    /// Per-note data faults are logged + skipped, not returned.
    pub async fn sync(&self) -> Result<usize, MemError> {
        let t_read = std::time::Instant::now();
        let members_view = self.read_and_filter().await?;
        let read_ms = t_read.elapsed().as_millis();
        // Capture the convergence tip before `members_view` is consumed below: it is
        // the checkpoint baseline written after the rebuild and the yardstick for
        // deciding whether the existing checkpoint's tail has grown stale.
        let last_lamport = lamport_tip(&members_view);
        // Drop the local cache copy of any note the log now redacts, BEFORE the
        // rebuild prunes it from the index (the gate this uses to fire at most
        // once). A teammate's `Redact` reaches every member through this shared
        // log; without purging here the sealed body would survive in this
        // machine's read-through cache — decryptable by any team-key holder —
        // defeating the redaction everywhere but the machine that issued it.
        self.purge_redacted_from_cache(&members_view).await;
        // The snapshot envelope is sealed under the current epoch's key (see
        // [`MemoryStore::snapshot`]). A member lacking that key cannot open the
        // checkpoint, so skip the fast path and fall back to a full replay — which
        // decodes each note under its OWN epoch key and skips any it cannot read.
        let snapshot = match self.key_for_epoch(self.current_epoch()) {
            Ok(key) => load_latest_snapshot(self.blob.as_ref(), &key, &self.team).await?,
            Err(_) => None,
        };
        // `baseline` is `None` on a full replay (no checkpoint existed) and the
        // restored checkpoint's tip on the incremental path — the reference the
        // tail-growth gate measures against.
        let t_rebuild = std::time::Instant::now();
        let (indexed, baseline, path) = match snapshot {
            Some(snapshot) => {
                let restored_baseline = snapshot.last_lamport;
                match self.sync_incremental(snapshot, members_view).await? {
                    IncrementalOutcome::Incremental(indexed) => {
                        (indexed, Some(restored_baseline), "incremental")
                    }
                    // The restored checkpoint was stale/poisoned and a full rebuild
                    // replaced it. Report `None` for the baseline so the
                    // `checkpoint_stale` gate below ALWAYS rewrites the checkpoint —
                    // otherwise the bad one keeps forcing this same fallback on
                    // every future sync, silently disabling the fast path team-wide.
                    IncrementalOutcome::FellBackToFull(indexed) => {
                        (indexed, None, "incremental->full")
                    }
                }
            }
            None => (self.replay_full(members_view).await?, None, "full"),
        };
        // Phase timing at debug: the op-log read and the rebuild are the two costly
        // legs, and knowing their split is how the checkpoint/concurrency work was
        // measured. Debug so it is opt-in and never noises a normal session.
        tracing::debug!(
            path,
            read_ms,
            rebuild_ms = t_rebuild.elapsed().as_millis(),
            indexed,
            "sync phase timing"
        );

        // Persist a checkpoint so the NEXT cold sync takes the incremental fast path
        // instead of re-reading and re-decoding the whole op-log — the single place
        // this happens, so every caller (server warmup, dashboard, import) benefits
        // without wiring it per entry point. Write it when there was no checkpoint (a
        // cold rebuild just paid the full cost) or when the tail has grown past
        // [`SNAPSHOT_REFRESH_LAMPORT_GAP`] since the last one. Built from the
        // just-converged in-memory index (`all_records`), so it re-reads and
        // re-decodes nothing. Best-effort: the index is already rebuilt and the
        // op-log is the source of truth, so a checkpoint-write failure only costs the
        // next sync its fast path, never correctness.
        let checkpoint_stale = baseline
            .is_none_or(|base| last_lamport.saturating_sub(base) >= SNAPSHOT_REFRESH_LAMPORT_GAP);
        if checkpoint_stale {
            match self.index.all_records() {
                Ok(records) => {
                    // Persist ONLY records at or below the baseline the checkpoint
                    // will claim. A `remember`/`edit` can land between
                    // `read_and_filter` (which fixed `last_lamport`) and this read,
                    // leaving the index with a note at `lamport > last_lamport`;
                    // sealing it into a checkpoint stamped `last_lamport` poisons the
                    // fast path — a later `sync_incremental` re-converges the base
                    // (ops with `lamport <= baseline`), cannot find that note at its
                    // recorded lamport, and full-rebuilds on EVERY sync. The filter
                    // keeps the checkpoint exactly `converge(ops with lamport <=
                    // last_lamport)`; the just-landed op is picked up as tail on the
                    // next sync once it is visible in the log.
                    let records: Vec<IndexRecord> = records
                        .into_iter()
                        .filter(|record| record.lamport <= last_lamport)
                        .collect();
                    if let Err(err) = self.persist_snapshot(&records, last_lamport).await {
                        tracing::warn!(
                            team = %self.team,
                            error = %err,
                            "failed to persist index checkpoint; the next sync will full-replay"
                        );
                    }
                }
                Err(err) => tracing::warn!(
                    team = %self.team,
                    error = %err,
                    "could not read the index to checkpoint it; the next sync will full-replay"
                ),
            }
        }
        Ok(indexed)
    }

    /// Drop the local cache copy of every note the shared log now redacts and that
    /// this machine still has indexed — the point a teammate's `Redact` takes
    /// effect here.
    ///
    /// [`redact`](Self::redact) scrubs the ciphertext from the shared bucket and,
    /// on the issuing machine, evicts its own cache via `scrub_blobs`' deletes. But
    /// a *teammate* that had synced the note keeps the sealed body in its local
    /// read-through cache; that body is decryptable by any team-key holder, so
    /// without this it would outlive the redaction on every machine except the
    /// issuer — defeating the point of `redact`. [`BlobStore::delete`] evicts the
    /// local cache before (and independent of) the backend delete (see
    /// [`CachingBlobStore`]), so this reclaims the cached bytes even for a
    /// read-only member whose remote delete is refused; the backend delete itself
    /// is idempotent and harmlessly re-reaps any straggler the issuer missed.
    ///
    /// Gated on the note still being indexed here so it fires at most once per
    /// machine: the issuer already unindexed it, and a later sync finds it gone
    /// from the index and skips it (no per-sync re-delete). A note this machine
    /// never indexed was never cached either, so skipping it loses nothing.
    ///
    /// Best-effort by contract: a delete failure only leaves a straggler the
    /// issuer's own scrub already targeted, and the note still converges redacted,
    /// so this never fails the sync.
    async fn purge_redacted_from_cache(&self, ops: &VerifiedOps) {
        // One pass to find the redacted note ids, a second to gather each one's
        // version keys — cheaper than a full `converge`, and redaction is rare.
        let redacted: BTreeSet<NoteId> = ops
            .iter()
            .filter(|op| op.kind == OpKind::Redact)
            .map(|op| op.note_id)
            .collect();
        if redacted.is_empty() {
            return;
        }
        // Evict every version blob of every redacted note from the LOCAL cache —
        // unconditionally, NOT gated on the index. Gating on `index.locate` (the
        // prior approach) skipped a note that was forgotten — dropped from the
        // index without a cache eviction — before its `Redact` reached this
        // machine, leaving its team-key-decryptable body on disk forever, the exact
        // leak `redact` exists to close. `evict_cache` is local, best-effort, and
        // idempotent (a no-op on a cacheless backend or an uncached key), and the
        // issuer's own `redact` already scrubbed the bucket, so this needs no
        // backend delete and is cheap to run on every sync.
        for op in ops.iter().filter(|op| redacted.contains(&op.note_id)) {
            self.blob.evict_cache(&op.object_key).await;
        }
    }

    /// Seal `records` (each under its own epoch key) into a checkpoint envelope and
    /// store it, so a later [`sync`](Self::sync) can restore the index without
    /// re-decoding every note.
    ///
    /// Shared by [`sync`](Self::sync) — which passes the freshly-converged index — and
    /// [`snapshot`](Self::snapshot) — which passes a set it decoded directly from the
    /// op-log — so both emit a byte-identical envelope.
    ///
    /// # Errors
    ///
    /// [`MemError`] if an epoch key is missing from the ring, a record cannot be
    /// sealed, or the envelope cannot be written.
    async fn persist_snapshot(
        &self,
        records: &[IndexRecord],
        last_lamport: u64,
    ) -> Result<(), MemError> {
        let mut sealed = Vec::with_capacity(records.len());
        for record in records {
            // Re-seal each record under ITS OWN epoch key (C1): the envelope is
            // sealed under only the current epoch, so a pre-rotation note's plaintext
            // must not ride inside it in the clear.
            let epoch_key = self.key_for_epoch(record.key_epoch)?;
            sealed.push(seal_record(record, &epoch_key)?);
        }
        let snapshot = IndexSnapshot {
            team: self.team.clone(),
            last_lamport,
            records: sealed,
        };
        // Seal the checkpoint envelope under the current epoch's key. A restorer
        // needs that key to open the envelope and use the fast path; one without it
        // falls back to a full replay (see [`sync`](Self::sync)). Each record body
        // inside is independently sealed under its own epoch key, so opening the
        // envelope grants no cross-epoch plaintext.
        let envelope_key = self.key_for_epoch(self.current_epoch())?;
        save_snapshot(self.blob.as_ref(), &envelope_key, &snapshot).await
    }

    /// Sync the index from the shared op-log ONLY when it is likely stale, so a
    /// long-lived session's reads see teammates' new notes without a manual
    /// `refresh`. Returns whether a sync actually ran.
    ///
    /// The read tools ([`recall`](Self::recall) / [`get`](Self::get)) answer from
    /// the local index, which a startup sync alone leaves stale as teammates keep
    /// writing. Calling `sync` before every read would be correct but costly — a
    /// sync `get`s and crypto-verifies every op and re-embeds changed notes. This
    /// gates that cost two ways:
    ///
    /// 1. **Window**: within [`AUTO_REFRESH_WINDOW`] of the last probe the index
    ///    is trusted as fresh-enough and this is a no-op, so a burst of recalls in
    ///    one task pays nothing after the first.
    /// 2. **Cheap probe**: otherwise it lists the op-log key count
    ///    ([`OpLogStore::op_object_count`] — no `get`s, no verification) and syncs
    ///    only if that count changed since the last sync. Nothing new ⇒ one cheap
    ///    list and no replay.
    ///
    /// It is best-effort freshness, not a guarantee: the caller decides how to
    /// treat a failure (the server logs it and serves the current index — memory
    /// stays available), and the probe is a heuristic (see `op_object_count`), so
    /// `history`/`reconcile`, which read the op-log directly, remain the
    /// always-fresh path.
    ///
    /// # Errors
    ///
    /// [`MemError::Storage`] if the op-log probe or the underlying [`sync`](Self::sync)
    /// fails.
    pub async fn refresh_if_stale(&self) -> Result<bool, MemError> {
        // Read the watermark and drop the guard BEFORE any `.await`: the probe and
        // sync below are async, and this is a `std::sync::Mutex` (axiom 74).
        let synced_count = {
            let state = self
                .auto_refresh
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            // `Instant::elapsed` is monotonic and never negative, so a backward
            // wall-clock jump cannot make a stale check look fresh.
            if state
                .last_check
                .is_some_and(|at| at.elapsed() < AUTO_REFRESH_WINDOW)
            {
                return Ok(false);
            }
            state.synced_op_count
        };

        let bucket_count = self.oplog.op_object_count(&self.team).await?;
        let synced = synced_count != Some(bucket_count);
        if synced {
            self.sync().await?;
        }

        // Record the probe: stamp the instant (opens the window) and the count we
        // are now consistent with. A concurrent probe may have synced too —
        // harmless, both converge to the same index; the writer lock serializes the
        // reseed.
        {
            let mut state = self
                .auto_refresh
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            state.last_check = Some(Instant::now());
            state.synced_op_count = Some(bucket_count);
        }
        Ok(synced)
    }

    /// Reset the auto-refresh window so the next [`refresh_if_stale`](Self::refresh_if_stale)
    /// re-probes immediately. Test-only: production relies on the wall clock, which
    /// a test cannot advance, so this exercises the cheap-probe path without waiting
    /// out [`AUTO_REFRESH_WINDOW`].
    #[cfg(test)]
    fn reset_auto_refresh_window(&self) {
        self.auto_refresh
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .last_check = None;
    }

    /// Read + verify the full op-log, re-seed the convergence clock from it, and
    /// return the member-filtered op set that `sync` and [`MemoryStore::snapshot`]
    /// converge over.
    ///
    /// The clock re-seed reads the FULL observed log: membership does not change
    /// Lamport causality — our next op must still strictly succeed everything we
    /// have seen, and our own chain head is our own last op — so both hold
    /// regardless of which authors are current members. It heals any skew a failed
    /// append left in the cache.
    ///
    /// Membership enforcement then filters to current members. With a
    /// founder-signed manifest only members' ops converge; with NO manifest the
    /// team is OPEN and every verified op converges (backward-compatible). The
    /// filter is applied to the whole verified log here, so the incremental tail
    /// converges only this member-filtered view too — a non-member's op is dropped
    /// whether it lands in the snapshot base or in the tail.
    ///
    /// `pub(crate)` so every crate-internal pass that reasons about "what the
    /// team did" reads the SAME view convergence does — currently
    /// [`crate::report::build_report`]'s activity tally, which previously read
    /// the unfiltered verified log and so counted a non-member's ops. There is
    /// deliberately no unfiltered sibling accessor: membership is not an
    /// optional lens over the op-log, and a caller that could opt out of it
    /// would eventually be a caller that forgot to opt in. Not exposed outside
    /// the crate either — an external caller gets a typed view, never the log.
    pub(crate) async fn read_and_filter(&self) -> Result<VerifiedOps, MemError> {
        // Hold the writer guard across BOTH the durable read AND the clock re-seed.
        // `mint_and_append` advances the cached clock only after a durable append
        // under this same guard, so reading the log and re-seeding from it must be
        // atomic w.r.t. writes: were a write to land between the read and the
        // re-seed, the re-seed would overwrite the cache with a pre-write snapshot,
        // regressing the tip/head so the next write re-mints a duplicate
        // `(lamport, prev_op_hash)` — forking this author's chain and bricking every
        // member's verified read. The guard is a `tokio::sync::Mutex` (its guard is
        // `Send`, sound across `.await`) and `read_all` touches nothing that re-locks
        // `writer`, so spanning the read cannot deadlock.
        let ops = {
            let mut clock = self.writer.lock().await;
            let ops = self.oplog.read_all(&self.team).await?;
            // Monotonic merge, never a regression. The guard above closes the
            // in-process write/re-seed race, but a backend whose LIST lags its PUTs
            // (the target gateways are only eventually consistent) can return a view
            // MISSING this author's own just-appended durable op. Blindly re-seeding
            // from that view would drop the tip below a durable op, and the next
            // `mint_and_append` would re-mint the same `(lamport, prev_op_hash)` — a
            // self-fork that quarantine then truncates. Lamport only ever climbs
            // (causality is monotone), and the head advances only when the read
            // actually CONTAINS our cached head — proof it is both durable and
            // visible — so a lagging listing keeps the cache instead of regressing
            // it. `GENESIS_PREV` (a fresh process that has not written) always counts
            // as visible, so a first sync still adopts the durable log head.
            clock.lamport_tip = clock.lamport_tip.max(lamport_tip(&ops));
            // Only THIS author's ops can equal `my_last_hash` (it is set below to
            // the hash of our own latest op, or `GENESIS_PREV`), so filter by
            // author before hashing — `Op::hash` rebuilds `signing_bytes` (a Vec +
            // two ULID strings) per call, and hashing every other author's ops to
            // find our own head is O(total ops) of pure waste on the sync path.
            let head_visible = clock.my_last_hash == GENESIS_PREV
                || ops
                    .iter()
                    .filter(|op| op.author == self.author)
                    .any(|op| op.hash() == clock.my_last_hash);
            if head_visible {
                clock.my_last_hash = ops
                    .iter()
                    .rev()
                    .find(|op| op.author == self.author)
                    .map_or(GENESIS_PREV, Op::hash);
            } else {
                tracing::warn!(
                    author = %self.author.as_str(),
                    "op-log read did not surface this author's cached chain head (eventual-consistency lag); keeping the cached head so the next write does not fork the chain"
                );
            }
            ops
        };

        // Load the bucket manifest FIRST, so the durable marker can be bound to the
        // founder the bucket path trusts: the pin, or (unpinned) the founder the
        // bucket's genesis elected. Without this bind a purely-local marker could
        // introduce a new founder that `load_manifest` would reject (see
        // `manifest_is_trusted`).
        let loaded = load_manifest(self.blob.as_ref(), &self.team, self.founder.as_ref()).await?;
        let trusted_founder = self
            .founder
            .clone()
            .or_else(|| loaded.as_ref().map(|m| m.founder.clone()));
        // Durable anti-rollback: seed the monotonic watermark from the local marker
        // (which survives a restart the in-memory watermark does not).
        // `monotonic_manifest` keeps the higher of the seeded and already-applied
        // versions, so the bucket manifest applied next can only raise it.
        let from_marker = self.load_verified_marker(trusted_founder.as_ref()).await;
        if let Some(marker) = &from_marker {
            self.monotonic_manifest(Some(marker.clone()));
        }
        let manifest = self.monotonic_manifest(loaded);
        // Persist the applied manifest when it advanced past what the marker held,
        // so a later cold start refuses a bucket rolled back below this version.
        // Best-effort: a write failure only lets rollback protection lag, it must
        // not fail the sync.
        if let (Some(applied), Some(marker)) = (&manifest, &self.manifest_marker)
            && from_marker.as_ref().map(|m| m.version) != Some(applied.version)
            && let Err(err) = marker.store(applied).await
        {
            tracing::warn!(
                error = %err,
                version = applied.version,
                "failed to persist the durable manifest marker; cross-restart rollback protection may lag"
            );
        }
        let members_view = match &manifest {
            // Filtering a verified set to current members keeps it verified, so the
            // result is still a `VerifiedOps` the convergence callers can consume.
            Some(manifest) => ops.filter(|op| manifest.members.contains(&op.author)),
            None => ops,
        };
        Ok(members_view)
    }

    /// Refuse to DOWNGRADE membership: return whichever of the freshly-`loaded`
    /// manifest and the store's already-applied one has the higher version, and
    /// update the cached watermark.
    ///
    /// The manifest bucket is untrusted (removing a member does not revoke their
    /// bucket write access), so an attacker can delete the newest manifest object;
    /// [`load_manifest`] would then elect an older version — or `None` — re-admitting
    /// removed members. Keeping the higher version already applied makes that
    /// rollback a no-op for a running member. The watermark is in-memory, so this
    /// holds WITHIN a process; a cross-restart rollback (cold cache) is the residual
    /// only durable/anchored manifest versioning would close, documented on
    /// [`applied_manifest`](MemoryStore::applied_manifest).
    fn monotonic_manifest(&self, loaded: Option<TeamManifest>) -> Option<TeamManifest> {
        let mut applied = self
            .applied_manifest
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match (&*applied, loaded) {
            // A lower-version reload is a rollback (the newest object was deleted);
            // keep the higher version we already trust.
            (Some(current), Some(new)) if new.version < current.version => {
                tracing::warn!(
                    applied_version = current.version,
                    loaded_version = new.version,
                    "refusing to apply an older team manifest (possible rollback via object deletion); keeping the higher version"
                );
                Some(current.clone())
            }
            // Every manifest object vanished while we hold one — also a rollback.
            (Some(current), None) => {
                tracing::warn!(
                    applied_version = current.version,
                    "the team manifest disappeared from storage (possible deletion); keeping the last applied version"
                );
                Some(current.clone())
            }
            // First load, or a version at/above the watermark: apply and record it.
            (_, Some(new)) => {
                *applied = Some(new.clone());
                Some(new)
            }
            (None, None) => None,
        }
    }

    /// Whether this store may trust `manifest`, bound to `trusted_founder` — the
    /// pinned founder, or (unpinned) the founder the bucket's genesis elected.
    ///
    /// Requires a valid signature, a matching `team`, and — when an anchor exists —
    /// that exact founder. That founder gate is what stops a purely-LOCAL marker
    /// from introducing a founder the bucket path (`load_manifest`) would reject:
    /// `TeamManifest::verify` only proves a manifest is self-consistently signed by
    /// its OWN `founder_key`, so without this bind anyone who could write the marker
    /// file could self-sign a higher-version manifest and seize membership on this
    /// node. When there is NEITHER a pin NOR a bucket manifest, no founder anchor
    /// exists and the marker is trusted on signature + team alone — so the durable
    /// guarantee is only a true security boundary with a pinned founder
    /// (`HIPPIUS_MEM_FOUNDER_SS58`); unpinned it is anti-accidental-rollback only.
    fn manifest_is_trusted(&self, manifest: &TeamManifest, trusted_founder: Option<&Ss58>) -> bool {
        manifest.verify()
            && manifest.team == self.team
            && trusted_founder.is_none_or(|f| &manifest.founder == f)
    }

    /// Load the durable manifest marker, returning it only if it verifies against
    /// `trusted_founder`.
    ///
    /// Best-effort: a missing marker, a read/parse error, or a manifest that fails
    /// [`manifest_is_trusted`](Self::manifest_is_trusted) (tampered file, foreign
    /// team, wrong founder) all yield `None` with a warn — the store then relies on
    /// the bucket, never trusting an unverified local file.
    async fn load_verified_marker(&self, trusted_founder: Option<&Ss58>) -> Option<TeamManifest> {
        let marker = self.manifest_marker.as_ref()?;
        match marker.load().await {
            Ok(Some(manifest)) if self.manifest_is_trusted(&manifest, trusted_founder) => {
                Some(manifest)
            }
            Ok(Some(manifest)) => {
                tracing::warn!(
                    team = %self.team,
                    version = manifest.version,
                    "ignoring a durable manifest marker that fails verification (bad signature, wrong team, or wrong founder)"
                );
                None
            }
            Ok(None) => None,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "could not read the durable manifest marker; continuing without it"
                );
                None
            }
        }
    }

    /// Rebuild the index from scratch over `members_view`: converge, prune to the
    /// live set, then decode + upsert every live note. The cold-start path (no
    /// snapshot) and the safety-valve fallback when a snapshot cannot be trusted.
    async fn replay_full(&self, members_view: VerifiedOps) -> Result<usize, MemError> {
        let converged = converge(&members_view);

        // The live set: a note is live iff it is not tombstoned AND has a content
        // pointer to hydrate. Computed once and used both to prune and to decode.
        let items: Vec<(NoteId, NotePointer)> = converged
            .iter()
            .filter(|(_, state)| !state.tombstoned)
            .filter_map(|(note_id, state)| {
                state
                    .pointer
                    .as_ref()
                    .map(|pointer| (*note_id, pointer.clone()))
            })
            .collect();

        // Authoritative prune: the index must end up reflecting ONLY the
        // currently-live converged set, so drop everything else from the (possibly
        // warm) index BEFORE the upserts.
        let live_ids: BTreeSet<NoteId> = items.iter().map(|(note_id, _)| *note_id).collect();
        self.index.retain(&live_ids)?;

        // Decode every live note's blob concurrently, then index them in ONE batch.
        // The per-note serial decode+embed was the cold-boot bottleneck; order is
        // irrelevant here (the live set was just pruned and the index is keyed by
        // id). `upsert_batch` embeds all summaries in one call — synchronous (the
        // core crate stays runtime-free, so no `spawn_blocking`), which the batch
        // keeps short and which runs inside the background warmup task off the
        // handshake path.
        let mut records = self.decode_records(items).await;
        // Stamp each note's OUTGOING typed relations from the converged state:
        // `decode_pointer` builds a record from the note body, which carries no
        // relations (they live on separate `Relate` ops), so recall's demotion
        // input is filled here from the same converged set the pointers came from.
        stamp_ranking_signals(&mut records, &converged);
        let indexed = records.len();
        self.index.upsert_batch(records)?;
        Ok(indexed)
    }

    /// Restore `snapshot` into the index and apply only the member ops newer than
    /// its baseline, so a cold start decodes blobs solely for the notes the tail
    /// touched.
    ///
    /// # Correctness
    ///
    /// The snapshot is `converge(member ops with lamport <= L)` for
    /// `L = snapshot.last_lamport`; the tail is the member ops with `lamport > L`.
    /// Because `L` is the Lamport *tip* of the snapshot's ops, every tail op has a
    /// strictly greater Lamport than every snapshot op. A note's converged index
    /// state — its winning content pointer and whether it is tombstoned — is
    /// latest-wins by `(lamport, op_id, author_key)`, so for any note the tail
    /// touches the tail ops dominate and `converge(tail)` alone yields the same
    /// winner a full `converge` would; a note the tail never touches keeps its
    /// snapshot record. Links are a union, but the index does not store links, so
    /// they never affect reconstruction. Restore ∪ tail therefore equals a full
    /// replay — *provided* the snapshot still reflects every op with `lamport <= L`.
    ///
    /// # Safety valve
    ///
    /// That proviso fails if a late/out-of-order op (a partitioned machine
    /// uploading an op with an OLD Lamport) or a membership change has altered the
    /// `lamport <= L` op set since the snapshot was taken: the snapshot is then no
    /// longer `converge(base)`, and `read_since`-style tailing would silently drop
    /// or misresolve those ops. We detect it by re-converging the current base —
    /// free, since `converge` is in-memory and the blob decode is the real cost —
    /// and comparing it to the snapshot; on any mismatch we fall back to a full
    /// rebuild, the one correct response. A tailed op can never itself carry
    /// `lamport <= L` (it is in the base by definition), so the check lives on the
    /// base, which is exactly where a late op lands.
    async fn sync_incremental(
        &self,
        snapshot: IndexSnapshot,
        members_view: VerifiedOps,
    ) -> Result<IncrementalOutcome, MemError> {
        let baseline = snapshot.last_lamport;
        // Converge the FULL member view once, up front, for ranking-signal stamping
        // at the end: freshly decoded records (tail-touched and snapshot-omitted)
        // leave `relations`/`reinforcers`/`last_reinforced` empty for the caller to
        // fill (see `decode_pointer`). Without the stamp, a tail Edit of a
        // previously related or reinforced note would silently strip its signals —
        // and `sync` would then persist the stripped record into the next
        // checkpoint, making the ranking loss durable. Cheap: converge is
        // in-memory; the blob decode below is the real cost.
        let full_converged = converge(&members_view);
        // Both halves of a verified set are verified, so `partition` hands back two
        // `VerifiedOps` — `converge(&base)` / `converge(&tail)` below need exactly
        // that, and the fallback reassembles them with `concat`.
        let (base, tail): (VerifiedOps, VerifiedOps) =
            members_view.partition(|op| op.lamport <= baseline);

        // Base pointers, owned (cloned) so the borrow of `base` releases before any
        // `.await` or the rebuild fallback consumes `base`.
        let base_pointers: BTreeMap<NoteId, NotePointer> = {
            let converged_base = converge(&base);
            converged_base
                .iter()
                .filter_map(|(note_id, state)| {
                    if state.tombstoned {
                        return None;
                    }
                    state
                        .pointer
                        .as_ref()
                        .map(|pointer| (*note_id, pointer.clone()))
                })
                .collect()
        };
        let snapshot_live: BTreeMap<NoteId, (u64, &str)> = snapshot
            .records
            .iter()
            .map(|record| (record.note_id, (record.lamport, record.object_key.as_str())))
            .collect();

        // Safety valve (store-3): every note the snapshot PERSISTED must still be
        // live in the converged base at the SAME (lamport, object_key). If one
        // changed or vanished, a late op rewrote the base under the checkpoint and
        // the tail-only shortcut is invalid -> full rebuild. A base note ABSENT
        // from the snapshot is NOT a rebuild trigger: `snapshot()` legitimately
        // omits notes whose blob was undecodable when it was built, so requiring
        // exact equality made a single permanently-foreign blob force a full
        // rebuild on EVERY sync (the perf cliff). Those omitted base notes are
        // decoded fresh below instead.
        let snapshot_still_valid = snapshot_live.iter().all(|(note_id, snap)| {
            base_pointers
                .get(note_id)
                .is_some_and(|pointer| (pointer.lamport, pointer.object_key.as_str()) == *snap)
        });
        if !snapshot_still_valid {
            tracing::warn!(
                team = %self.team,
                baseline,
                "a snapshotted note changed or vanished in the converged base (late op or membership change); falling back to a full rebuild"
            );
            let members_view: VerifiedOps = base.concat(tail);
            return Ok(IncrementalOutcome::FellBackToFull(
                self.replay_full(members_view).await?,
            ));
        }

        // A `Relate` or `Reinforce` op in the tail can target a note whose pointer
        // lives in the snapshot base; the incremental path keeps that base record
        // unchanged for a pointer-less tail touch (see the `Link` case below), so it
        // would miss the new relation/reinforcement and recall would not demote the
        // superseded note or boost the reinforced one. Both are rare, so fall back to
        // a full rebuild rather than special-case a cross-note re-stamp — the full
        // converge stamps every note's ranking signals from its source-grouped ops.
        if tail
            .iter()
            .any(|op| matches!(op.kind, OpKind::Relate { .. } | OpKind::Reinforce))
        {
            let members_view: VerifiedOps = base.concat(tail);
            return Ok(IncrementalOutcome::FellBackToFull(
                self.replay_full(members_view).await?,
            ));
        }

        // Classify the tail's effect per note. A note the tail tombstones is
        // removed; one the tail re-points is decoded fresh; one the tail touches
        // only with a Link (no pointer, not tombstoned) keeps its snapshot record.
        let tail_converged = converge(&tail);
        let mut tail_live: BTreeMap<NoteId, NotePointer> = BTreeMap::new();
        let mut tail_dead: BTreeSet<NoteId> = BTreeSet::new();
        for (note_id, state) in &tail_converged {
            if state.tombstoned {
                tail_dead.insert(*note_id);
            } else if let Some(pointer) = state.pointer.as_ref() {
                tail_live.insert(*note_id, pointer.clone());
            }
        }

        // Final live set = the converged base's live notes, minus what the tail
        // removed, plus what the tail (re-)added — exactly the set a full converge
        // would prune to. Using the base live set (not just the snapshot ids) keeps
        // the notes the snapshot omitted in scope so they are restored below.
        let mut final_live: BTreeSet<NoteId> = base_pointers.keys().copied().collect();
        for note_id in &tail_dead {
            final_live.remove(note_id);
        }
        for note_id in tail_live.keys() {
            final_live.insert(*note_id);
        }
        // A note REDACTED anywhere in the full converged history must never re-enter
        // the index, even when the incremental tail still shows a live pointer (a
        // partitioned Edit in the tail vs. the Redact in the base — see
        // `drop_redacted`). `full_converged` is the authority.
        drop_redacted(&full_converged, &mut final_live, &mut tail_live);
        self.index.retain(&final_live)?;

        // Gather every record to index into ONE batch so the embed runs once, not
        // per note. Three sources: the still-live snapshot records (no blob I/O),
        // the base notes the snapshot omitted, and the tail-touched notes — the
        // last two decoded concurrently. Order-safe: `final_live` was just retained
        // and the index is keyed by note id.
        let mut records =
            self.collect_live_snapshot_records(&snapshot, &base_pointers, &final_live, &tail_live);
        // Base notes the snapshot did not actually restore — omitted from it because
        // they were undecodable when it was built (and maybe decodable now), added by
        // a late op at/below the baseline, or REJECTED just now by
        // `collect_live_snapshot_records` (absent epoch key, body that would not
        // open, or a body the signed op-log contradicts). Whatever the reason, the
        // note is decoded from the blob the op-log names, which is the authoritative
        // answer; skip-with-warn on a still-bad blob (inside `decode_records`),
        // mirroring the full-replay path, so one permanently-foreign blob no longer
        // forces a rebuild every sync, yet we never index a summary we cannot read
        // (store-3).
        //
        // Keying this off the records genuinely RESTORED — not off the note ids the
        // snapshot merely contains — is what makes the checkpoint fail-safe: a record
        // it cannot justify costs one blob decode rather than silently dropping the
        // note or, worse, indexing the snapshot's unbacked claim. In the
        // honest case nothing is rejected, so this set is exactly what it was before
        // and the restore still does no blob I/O.
        let restored_ids: BTreeSet<NoteId> = records.iter().map(|record| record.note_id).collect();
        let omitted: Vec<(NoteId, NotePointer)> = base_pointers
            .iter()
            .filter(|(note_id, _)| {
                final_live.contains(note_id)
                    && !restored_ids.contains(note_id)
                    && !tail_live.contains_key(note_id)
            })
            .map(|(note_id, pointer)| (*note_id, pointer.clone()))
            .collect();
        records.extend(self.decode_records(omitted).await);
        // The tail-touched notes: the incremental win is that the unchanged base
        // notes above were restored from the snapshot without any blob fetch.
        let tail_items: Vec<(NoteId, NotePointer)> = tail_live
            .iter()
            .map(|(note_id, pointer)| (*note_id, pointer.clone()))
            .collect();
        records.extend(self.decode_records(tail_items).await);

        // Stamp EVERY record from the full converged state, exactly like
        // `replay_full` and `snapshot()`: uniform re-stamping is idempotent for the
        // snapshot-restored records (Relate/Reinforce in the tail already forced a
        // full rebuild above, so their converged signals match the snapshot's) and
        // is what restores the signals the freshly decoded records were built
        // without.
        stamp_ranking_signals(&mut records, &full_converged);

        let indexed = records.len();
        self.index.upsert_batch(records)?;
        Ok(IncrementalOutcome::Incremental(indexed))
    }

    /// Collect the snapshot records that are still live (`final_live`) and were not
    /// superseded by a tail edit (`tail_live`), opening each under its OWN epoch
    /// key. Returns the decoded records for the caller to batch-insert; does no
    /// blob I/O and is infallible (per-record faults are skipped, never returned).
    ///
    /// A member holds the CURRENT epoch (the envelope seal key) but a pre-rotation
    /// record may be sealed under an OLDER epoch they lack. A missing key — or a
    /// body that fails to open — is skipped-with-warn, mirroring `decode_pointer`'s
    /// gate and the full-replay path, so both reach byte-identical index state and
    /// no cross-epoch summary is surfaced.
    ///
    /// # Cross-checking the sealed body
    ///
    /// The incremental safety valve authenticates only the record's CLEAR envelope.
    /// The sealed body carries its own copies of every envelope field plus `author`,
    /// `cid`, `scope`, `note_type`, `updated`, `tags` and `summary` — and it is the
    /// BODY that `open_record` returns and the caller indexes. Each body is therefore
    /// checked against the converged base pointer (`base_pointers`, built from
    /// verified signed ops) via [`snapshot_body_disagreement`] before it is accepted.
    /// Its `summary`/`tags` are clamped by [`bound_index_fields`] first, the same
    /// ingestion cap `decode_pointer` applies.
    ///
    /// Every skip here — absent epoch key, body that will not open, or a body the
    /// op-log contradicts — leaves the note out of the returned set, and the caller
    /// then decodes it from the blob the op-log names (see `sync_incremental`'s
    /// `restored_ids`), so nothing this function refuses is lost.
    ///
    /// # What that does NOT make the snapshot
    ///
    /// It does **not** make the restored state equal to a full replay's. The
    /// equivalence holds only for the fields [`snapshot_body_disagreement`] can check
    /// — the ones a signed op attests. `summary`, `tags`, `updated` and `note_type`
    /// are still taken on the snapshot's word: on a forgery confined to those, the
    /// restored state IS the snapshot's claim, where a full replay through
    /// `decode_pointer` would read the blob and yield the true note. See that
    /// function's docs for why, and
    /// `a_snapshot_body_forged_only_in_its_summary_is_still_indexed` for the pinned
    /// proof. What is guaranteed is narrower and still worth having: the snapshot can
    /// no longer assert an identity, a location or a revision that no signature
    /// backs, nor an unbounded summary or tag set.
    fn collect_live_snapshot_records(
        &self,
        snapshot: &IndexSnapshot,
        base_pointers: &BTreeMap<NoteId, NotePointer>,
        final_live: &BTreeSet<NoteId>,
        tail_live: &BTreeMap<NoteId, NotePointer>,
    ) -> Vec<IndexRecord> {
        let mut records = Vec::new();
        for record in &snapshot.records {
            if !final_live.contains(&record.note_id) || tail_live.contains_key(&record.note_id) {
                continue;
            }
            let Ok(epoch_key) = self.key_for_epoch(record.key_epoch) else {
                tracing::warn!(
                    team = %self.team,
                    note_id = %record.note_id,
                    key_epoch = record.key_epoch,
                    "skipping snapshot record whose epoch key is absent from this member's ring"
                );
                continue;
            };
            let mut index_record = match open_record(record, &epoch_key) {
                Ok(index_record) => index_record,
                Err(err) => {
                    tracing::warn!(
                        team = %self.team,
                        note_id = %record.note_id,
                        error = %err,
                        "skipping snapshot record whose sealed body failed to open"
                    );
                    continue;
                }
            };

            // Bound the record's summary/tags at THIS ingestion boundary, exactly as
            // `decode_pointer` does at the blob one. Without it a checkpoint is
            // bounded only incidentally -- because its records were clamped on the way
            // in -- so a current-epoch key holder could reseal one record with an
            // unbounded summary or tag set and every teammate's next cold sync would
            // index and EMBED it. The cross-check below reads none of these fields, so
            // clamping first cannot change its verdict.
            let (summary, tags) = bound_index_fields(
                &index_record.summary,
                std::mem::take(&mut index_record.tags),
            );
            index_record.summary = summary;
            index_record.tags = tags;

            let pointer = base_pointers.get(&record.note_id);

            if let Some(field) = snapshot_body_disagreement(&index_record, record, pointer) {
                tracing::warn!(
                    team = %self.team,
                    note_id = %record.note_id,
                    field,
                    "skipping a snapshot record whose sealed body contradicts the signed op-log; it is decoded from its blob instead"
                );
                continue;
            }

            records.push(index_record);
        }
        records
    }

    /// Decode the blobs behind `items` concurrently (bounded), returning the
    /// records that decoded cleanly.
    ///
    /// A note whose blob is a data fault (unreadable / undecryptable / sealed
    /// under an epoch this member lacks) is logged and dropped — the same per-note
    /// resilience the former serial per-note decode gave, so one bad blob never
    /// fails the whole sync. Gathering the records (rather than upserting each in a
    /// loop) is what lets the caller embed them in ONE batch via
    /// [`MemoryIndex::upsert_batch`]. Fetch order is irrelevant: the caller has
    /// already `retain`ed the live set and the index is a map keyed by note id, so
    /// concurrent completion cannot change the result.
    ///
    /// The bound (axiom `rust_quality_176`) caps in-flight blob GETs so a large
    /// live set cannot open thousands of simultaneous connections; the futures are
    /// driven inline by the caller's runtime (nothing is spawned), so the core
    /// crate needs no runtime of its own.
    async fn decode_records(&self, items: Vec<(NoteId, NotePointer)>) -> Vec<IndexRecord> {
        let decoded: Vec<Option<IndexRecord>> = futures_util::stream::iter(items)
            .map(|(note_id, pointer)| async move {
                match self.decode_pointer(note_id, &pointer).await {
                    Ok(record) => Some(record),
                    Err(err) => {
                        tracing::warn!(
                            note_id = %note_id,
                            object_key = %pointer.object_key,
                            error = %err,
                            "skipping note whose blob could not be decoded during sync"
                        );
                        None
                    }
                }
            })
            .buffer_unordered(NOTE_DECODE_CONCURRENCY)
            .collect()
            .await;
        decoded.into_iter().flatten().collect()
    }

    /// Capture the current converged state into an encrypted [`IndexSnapshot`] and
    /// persist it, returning the baseline Lamport the snapshot covers.
    ///
    /// Built from the op-log converged state — the same set [`MemoryStore::sync`]
    /// indexes — not from the live index, so the snapshot is correct even on a
    /// store whose index was never synced. Each live note's blob is decoded into an
    /// [`IndexRecord`] so a later restore can re-`upsert` it without blob I/O.
    ///
    /// # Errors
    ///
    /// Whatever [`OpLogStore::read_all`] / [`load_manifest`] report, or whatever
    /// [`save_snapshot`] reports (serialize / crypto / storage). A note whose blob
    /// cannot be decoded is logged + skipped exactly as in `sync`, so it is simply
    /// absent from the snapshot and will be decoded on a later tail if still live.
    pub async fn snapshot(&self) -> Result<u64, MemError> {
        let members_view = self.read_and_filter().await?;
        let last_lamport = lamport_tip(&members_view);
        let converged = converge(&members_view);

        let mut records = Vec::new();
        for (note_id, state) in &converged {
            if state.tombstoned {
                continue;
            }
            let Some(pointer) = state.pointer.as_ref() else {
                continue;
            };
            match self.decode_pointer(*note_id, pointer).await {
                Ok(mut record) => {
                    // Persist the note's ranking signals in the snapshot so a cold
                    // restore keeps recall's demotion AND boost inputs without
                    // replaying the `Relate`/`Reinforce` ops.
                    record.relations = state.relations.iter().copied().collect();
                    record.reinforcers.clone_from(&state.reinforcers);
                    record.last_reinforced = state.last_reinforced;
                    records.push(record);
                }
                Err(err) => tracing::warn!(
                    note_id = %note_id,
                    object_key = %pointer.object_key,
                    error = %err,
                    "skipping note whose blob could not be decoded while building a snapshot"
                ),
            }
        }

        // `persist_snapshot` re-seals each record under its own epoch key before it
        // enters the envelope (C1), so a pre-rotation note's plaintext never rides
        // inside the current-epoch envelope.
        self.persist_snapshot(&records, last_lamport).await?;
        Ok(last_lamport)
    }

    /// Publish a new membership manifest for this store's team, with the local
    /// signer acting as founder.
    ///
    /// Only the founder may change membership: if a manifest already exists, this
    /// signer must be its founder (else [`MemError::Unauthorized`]), and the new
    /// manifest takes the next version. If NO manifest exists, this signer
    /// becomes the founder at version 0 — claiming a previously open team. The
    /// founder is always inserted into `members` by
    /// [`TeamManifest::create_signed`], so a founder cannot lock themselves out.
    ///
    /// The live manifest's **recovery key is carried forward** onto the new
    /// version. A membership change is not a statement about recovery, so
    /// silently dropping the key would make the first `add`/`remove` after
    /// provisioning retire the team's escape hatch without anyone asking for it —
    /// and, worse, without anyone noticing until a recovery was actually needed.
    /// It is read through [`TeamManifest::trusted_recovery_key`], so a degenerate
    /// key is dropped rather than propagated onto a fresh signature.
    ///
    /// After this returns, a subsequent [`MemoryStore::sync`] (on this or any
    /// teammate's store) converges only members' ops.
    ///
    /// # Errors
    ///
    /// [`MemError::Unauthorized`] if a manifest exists and this signer is not its
    /// founder (a permanent permission denial a caller must surface, not retry),
    /// or whatever [`load_manifest`] / [`publish_manifest`] report (storage,
    /// deserialization, or founder-consistency failures).
    pub async fn publish_membership(&self, members: BTreeSet<Ss58>) -> Result<(), MemError> {
        // When a founder is pinned, only that identity may write membership — even
        // the genesis (version-0) manifest. Without this guard a non-founder could
        // publish a v0 manifest naming themselves; `load_manifest`'s pin would
        // ignore it, but rejecting it here keeps the prefix clean and turns the
        // attempt into the permission error it is, rather than a silent no-op.
        if let Some(pinned) = &self.founder
            && &self.author != pinned
        {
            return Err(MemError::Unauthorized(format!(
                "only the pinned team founder may change membership: {:?} is not founder {:?}",
                self.author.as_str(),
                pinned.as_str(),
            )));
        }
        let current = load_manifest(self.blob.as_ref(), &self.team, self.founder.as_ref()).await?;
        let next_version = match &current {
            Some(manifest) => {
                if manifest.founder != self.author {
                    // A founder-authorization denial: the signer is intact but not
                    // permitted. `Unauthorized`, not `Storage` — the caller must
                    // surface a permission error, never retry it as a backend blip.
                    return Err(MemError::Unauthorized(format!(
                        "only the team founder may change membership: {:?} is not founder {:?}",
                        self.author.as_str(),
                        manifest.founder.as_str(),
                    )));
                }
                manifest.version.saturating_add(1)
            }
            None => 0,
        };
        // Carried forward, not re-derived: the caller asked to change membership,
        // not to retire the recovery key. Read through `trusted_recovery_key` so a
        // degenerate key already in the bucket is dropped here instead of being
        // re-signed onto a fresh manifest.
        let recovery_key = current
            .as_ref()
            .and_then(TeamManifest::trusted_recovery_key)
            .copied();
        let manifest = TeamManifest::create_signed_with_recovery(
            self.signer.as_ref(),
            self.team.clone(),
            members,
            next_version,
            recovery_key,
        );
        publish_manifest(self.blob.as_ref(), &manifest).await
    }

    /// Founder action: publish a manifest naming `recovery_key`, at
    /// `live.version + 1` — carrying the live team and members forward
    /// unchanged. Returns the new manifest AND whichever recovery key was
    /// trusted and live BEFORE this call (`None` if none was named), so a
    /// caller can warn the operator when this call retires a previous key an
    /// operator may still be holding offline.
    ///
    /// This is what the CLI's `provision` calls by default: once membership is
    /// published, it extends the manifest chain by one link that additionally
    /// names a recovery key — the escape hatch
    /// [`MemoryStore::recover_founder`] can use if the founder key is ever
    /// lost.
    ///
    /// # Recovery-carrying manifests are additive-forward, never an overwrite
    ///
    /// This method used to re-sign the LIVE version in place, on the reasoning
    /// that naming a recovery key changes no membership and so should not
    /// consume a version. Rewriting a version that already exists turned out to
    /// break two separate guarantees, and BOTH are fixed by the same rule: no
    /// publish path may ever change the contents of a version that has already
    /// been published.
    ///
    /// - **Chain of custody.** The bucket is untrusted, so an overwrite does
    ///   not destroy the old bytes — it only stops serving them. Anyone who
    ///   read the bucket before the overwrite holds a founder-signed manifest,
    ///   valid forever, that names a recovery key the founder has since
    ///   RETIRED. Replaying it puts two founder-signed manifests at one
    ///   version, where the founder-beats-recovery rank has nothing to say, and
    ///   whichever one wins decides whether the retired key still governs.
    ///   Publishing forward means a retirement never contends with the manifest
    ///   it retires: the retiring manifest simply out-versions it, and
    ///   `load_manifest`'s canonical-key binding leaves the replay nowhere to
    ///   stand (see `identity::manifest`'s module docs).
    /// - **Read compatibility.** A manifest naming a recovery key signs under
    ///   `MANIFEST_DOMAIN_V2`. A binary released before that tag existed cannot
    ///   verify one, and correctly skips it. Overwriting the team's ONLY
    ///   manifest with v2-signed bytes therefore left such a binary with no
    ///   verifiable manifest at all — and `load_manifest`'s `None` means OPEN
    ///   TEAM, so generating a recovery key silently switched membership
    ///   filtering off for every reader that had not upgraded. Publishing
    ///   forward leaves the lower-version, v1-format manifest exactly as it was,
    ///   so an old binary still elects it and still reads the frozen roster.
    ///
    /// [`MemoryStore::monotonic_manifest`] then applies the new version on every
    /// reader's next sync as an unambiguous advance, rather than as a
    /// same-version replacement its rollback watermark has to be read carefully
    /// to allow.
    ///
    /// `recovery_key` is `VerifyingKey`, not `Option`: there is no retirement
    /// path through this method (nothing in this crate ever calls it with
    /// `None`) — a team that wants to stop trusting any recovery key can
    /// still do so via [`publish_membership`](Self::publish_membership), which
    /// carries the CURRENT recovery key forward only when one is already
    /// live, or by publishing a fresh version through this method naming a
    /// replacement. The Ristretto [identity point](VerifyingKey::is_identity_point)
    /// is refused outright: naming it would make the escape hatch a standing
    /// open door anyone could walk through, which defeats the entire point of
    /// [`TeamManifest::trusted_recovery_key`] screening it on read — refusing
    /// it here on write is what makes that screening's premise ("no legitimate
    /// caller ever names it") actually true, rather than merely relied upon.
    ///
    /// Authorization here checks `self.author == live.founder` directly — NOT
    /// `self.founder` (this store's config pin). This is a narrower, safe
    /// authorization surface than [`publish_membership`]'s: `publish_membership`
    /// additionally refuses under a STALE pin because it must also handle the
    /// "no manifest yet, pin set" genesis case (rejecting a wasted v0 publish
    /// attempt before it happens); this method NEVER writes a genesis manifest
    /// (`ManifestUnavailable` when none exists), so that concern does not
    /// apply, and the founder-identity check alone — already derived from the
    /// untrusted-bucket-resistant chain election — is the complete
    /// authorization this metadata-only change needs. Concretely: right after
    /// a recovery, the correct new founder (their `author_seed_hex` now
    /// derives the recovery identity) can name a fresh recovery key through
    /// this method EVEN BEFORE re-pinning `founder_ss58` locally, while
    /// [`publish_membership`]/[`rotate_key`](Self::rotate_key) would still
    /// refuse them until the pin catches up — deliberate, since naming a
    /// recovery key changes no membership and the founder-identity check is
    /// already sufficient.
    ///
    /// # Errors
    ///
    /// [`MemError::Malformed`] if `recovery_key` is the identity point.
    /// [`MemError::ManifestUnavailable`] if no manifest has been published yet
    /// for this team (there is no live founder/membership to name a recovery
    /// key on — publish membership first), or [`MemError::Unauthorized`] if
    /// this signer is not that manifest's founder. Otherwise whatever
    /// [`load_manifest`] / [`publish_manifest`] report.
    pub async fn publish_recovery_key(
        &self,
        recovery_key: VerifyingKey,
    ) -> Result<(TeamManifest, Option<VerifyingKey>), MemError> {
        if recovery_key.is_identity_point() {
            return Err(MemError::Malformed(
                "refusing to name the Ristretto identity point as a recovery key: it \
                 authenticates anyone, which would make the escape hatch a standing open door"
                    .to_owned(),
            ));
        }

        let live = load_manifest(self.blob.as_ref(), &self.team, self.founder.as_ref())
            .await?
            .ok_or_else(|| MemError::ManifestUnavailable {
                team: self.team.clone(),
            })?;

        if live.founder != self.author {
            return Err(MemError::Unauthorized(format!(
                "only the team founder may name a recovery key: {:?} is not founder {:?}",
                self.author.as_str(),
                live.founder.as_str(),
            )));
        }

        let previous_recovery_key = live.trusted_recovery_key().copied();

        // A forward link, never an overwrite — see this method's docs.
        // `saturating_add` mirrors `publish_membership`/`recover_founder`: at
        // `u64::MAX` the chain simply stops advancing rather than wrapping to
        // version 0 and handing the anchor to whoever publishes next.
        let manifest = TeamManifest::create_signed_with_recovery(
            self.signer.as_ref(),
            self.team.clone(),
            live.members,
            live.version.saturating_add(1),
            Some(recovery_key),
        );
        publish_manifest(self.blob.as_ref(), &manifest).await?;
        Ok((manifest, previous_recovery_key))
    }

    /// Recovery action: given `recovery_signer`, whose public key must match
    /// the live manifest's [`TeamManifest::trusted_recovery_key`], publish a
    /// fresh manifest at `live.version + 1` — signed by `recovery_signer`, who
    /// becomes the new founder — carrying the live members forward and naming
    /// `fresh_recovery_key` as the NEXT escape hatch.
    ///
    /// `fresh_recovery_key` is REQUIRED, not `Option`: a recovery that named no
    /// successor recovery key would permanently close the escape hatch after
    /// one use, which a recovery must never do — the type makes that mistake
    /// unrepresentable rather than relying on every caller to remember it. The
    /// Ristretto [identity point](VerifyingKey::is_identity_point) is refused
    /// outright for the same reason [`publish_recovery_key`](Self::publish_recovery_key)
    /// refuses it: naming it would leave the escape hatch standing open to
    /// anyone, which is worse than closing it.
    ///
    /// This is the CLI's `recover`'s entire authority check — no identity
    /// other than the holder of the live manifest's named recovery key may
    /// call through here successfully. This store's OWN configured signer
    /// (`self.signer`) plays no role in that check: authority comes only from
    /// `recovery_signer`. The existing chain-of-custody election
    /// (`load_manifest`/`elect_live`) is what makes the RESULT of this call
    /// authoritative to every other reader: they independently verify the
    /// published manifest authorizes from the live one the exact same way.
    ///
    /// # Errors
    ///
    /// [`MemError::Malformed`] if `fresh_recovery_key` is the identity point.
    /// [`MemError::ManifestUnavailable`] if no manifest has been published yet
    /// for this team (there is nothing to recover), or
    /// [`MemError::Unauthorized`] if `recovery_signer`'s public key is not the
    /// live manifest's trusted recovery key. Otherwise whatever
    /// [`load_manifest`] / [`publish_manifest`] report.
    pub async fn recover_founder<S: Signer + ?Sized>(
        &self,
        recovery_signer: &S,
        fresh_recovery_key: VerifyingKey,
    ) -> Result<TeamManifest, MemError> {
        if fresh_recovery_key.is_identity_point() {
            return Err(MemError::Malformed(
                "refusing to name the Ristretto identity point as the fresh recovery key: it \
                 authenticates anyone, which would make the escape hatch a standing open door"
                    .to_owned(),
            ));
        }

        let live = load_manifest(self.blob.as_ref(), &self.team, self.founder.as_ref())
            .await?
            .ok_or_else(|| MemError::ManifestUnavailable {
                team: self.team.clone(),
            })?;

        if live.trusted_recovery_key().copied() != Some(recovery_signer.verifying_key()) {
            return Err(MemError::Unauthorized(
                "the provided recovery seed does not match this team's published recovery key"
                    .to_owned(),
            ));
        }

        let manifest = TeamManifest::create_signed_with_recovery(
            recovery_signer,
            self.team.clone(),
            live.members,
            live.version.saturating_add(1),
            Some(fresh_recovery_key),
        );
        publish_manifest(self.blob.as_ref(), &manifest).await?;
        Ok(manifest)
    }

    /// The trusted membership manifest of this store's team, or `None` when no
    /// manifest has been published (the team is **open**).
    ///
    /// This is the full founder-signed record, for callers that need more than
    /// the member set — e.g. the CLI's `remove`, which must compare a removal
    /// target against the manifest's `founder` to refuse founder self-removal.
    /// Trust semantics are identical to every other manifest consumer here:
    /// the load is gated by this store's pinned founder, so a manifest planted
    /// by a different signer never surfaces.
    ///
    /// # Errors
    ///
    /// Whatever [`load_manifest`] reports (storage, deserialization, or a
    /// founder-consistency failure).
    pub async fn membership_manifest(&self) -> Result<Option<TeamManifest>, MemError> {
        load_manifest(self.blob.as_ref(), &self.team, self.founder.as_ref()).await
    }

    /// The current member set of this store's team.
    ///
    /// Returns the highest valid manifest's members, or an empty set when no
    /// manifest has been published — an empty set means the team is **open**
    /// (every verified author converges), not that the team has no writers.
    ///
    /// # Errors
    ///
    /// Whatever [`load_manifest`] reports (storage, deserialization, or a
    /// founder-consistency failure).
    pub async fn members(&self) -> Result<BTreeSet<Ss58>, MemError> {
        Ok(self
            .membership_manifest()
            .await?
            .map(|manifest| manifest.members)
            .unwrap_or_default())
    }

    /// Founder action: wrap this team's CURRENT-epoch key to every published member
    /// key the founder-signed manifest authorizes, so those members can decrypt
    /// notes. Returns the number of published member keys considered.
    ///
    /// The manifest gate is threaded with THIS store's pinned founder
    /// ([`self.founder`], the same pin [`MemoryStore::sync`] uses), so a bucket
    /// writer who plants a self-signed member key for a non-member address is not
    /// wrapped the key — provisioning read-authz is gated by the same signed
    /// authority as write convergence, and fails closed when a pin has no manifest.
    ///
    /// Idempotent: re-running rewrites each member's wrap under the same epoch key.
    /// Run it after [`publish_membership`](Self::publish_membership) so the manifest
    /// the gate reads reflects the intended members.
    ///
    /// # Errors
    ///
    /// [`MemError::KeyUnavailable`] if this store's key-ring lacks the current
    /// epoch's key (it is not the founder, or the key was never configured), or
    /// whatever [`load_member_keys`] / `provision_team_key` report.
    pub async fn provision_members(&self) -> Result<usize, MemError> {
        let member_keys = load_member_keys(self.blob.as_ref(), &self.team).await?;
        let epoch = self.current_epoch();
        let team_key = self.key_for_epoch(epoch)?;
        provision_team_key(
            self.blob.as_ref(),
            &self.team,
            &team_key,
            epoch,
            &member_keys,
            self.founder.as_ref(),
        )
        .await?;
        Ok(member_keys.len())
    }

    /// Founder action: rotate the team key — mint a fresh key at a fresh epoch,
    /// wrap it to the CURRENT manifest's published members only, and advance
    /// this store's write epoch so subsequent writes seal under it.
    ///
    /// The two halves are deliberately one method: rotating without advancing
    /// the write epoch leaves new notes sealed under the old key a removed
    /// member still holds, silently defeating the rotation. A caller therefore
    /// cannot get the wrap-publishing half without the epoch advance.
    ///
    /// `known_max_epoch` is the highest epoch the caller knows the team has
    /// rotated to out of band (the CLI passes its configured `max_epoch`). The
    /// new epoch is `max(ring, known_max_epoch) + 1`. Both floors are LOCAL
    /// inputs, so this guards only against re-minting an epoch at or below
    /// them (a stale ring, a lagging config). An epoch that reached the bucket
    /// ABOVE both — a prior rotation that crashed after wrapping, or a
    /// concurrent rotation from another founder machine — is invisible here,
    /// and a re-run WILL re-mint it, overwriting its wraps. Re-run semantics:
    /// the minted key joins the local ring, so re-running on the same machine
    /// floors on it and advances to the next epoch consistently; notes sealed
    /// under a losing key inside such a race window stay unreadable to members
    /// who bootstrap the re-minted wrap. Bucket-level epoch discovery is a
    /// documented follow-up, not a promise of this method.
    ///
    /// Authorization mirrors [`publish_membership`](Self::publish_membership):
    /// rotation decides who can read future notes, which is membership-shaped
    /// power, so it is founder-only and fail-closed under a pin. With neither a
    /// pin nor a manifest the team is open and every published verified key is
    /// wrapped — the same fallback [`provision_members`](Self::provision_members)
    /// inherits from `provision_team_key`.
    ///
    /// # Errors
    ///
    /// - [`MemError::Unauthorized`] when this signer is not the pinned founder
    ///   (or not the trusted manifest's founder) — surface, never retry.
    /// - [`MemError::ManifestUnavailable`] when a founder pin is set but no
    ///   manifest signed by that founder can be loaded: fail-closed, because the
    ///   untrusted bucket withholding the manifest must not downgrade a pinned
    ///   team to open.
    /// - [`MemError::NothingToRotate`] when no published member key is
    ///   authorized to receive a wrap. Refused BEFORE the write epoch advances:
    ///   sealing future notes under a key wrapped to no one would make them
    ///   unreadable to the whole team once this process exits.
    /// - Whatever [`load_manifest`] / [`load_member_keys`] / `rotate_team_key`
    ///   report (storage, serialization, crypto).
    pub async fn rotate_key(&self, known_max_epoch: u64) -> Result<RotationOutcome, MemError> {
        // Authz first, before any bucket write. `load_manifest` already honours
        // the pin (only the pinned founder's manifests load), so a Some(manifest)
        // under a pin is necessarily the pin's — the author check below then
        // reduces to "is this signer the founder".
        let manifest = load_manifest(self.blob.as_ref(), &self.team, self.founder.as_ref()).await?;
        match (&manifest, &self.founder) {
            (Some(manifest), _) if manifest.founder != self.author => {
                return Err(MemError::Unauthorized(format!(
                    "only the team founder may rotate the team key: {:?} is not founder {:?}",
                    self.author.as_str(),
                    manifest.founder.as_str(),
                )));
            }
            (None, Some(pinned)) => {
                // Even the pinned founder gets a refusal here: with no trusted
                // manifest the wrap gate is fail-closed and would wrap to no
                // one, so the actionable fix (publish membership) is named
                // instead of minting a dead epoch.
                if &self.author != pinned {
                    return Err(MemError::Unauthorized(format!(
                        "only the pinned team founder may rotate the team key: {:?} is not \
                         founder {:?}",
                        self.author.as_str(),
                        pinned.as_str(),
                    )));
                }
                return Err(MemError::ManifestUnavailable {
                    team: self.team.clone(),
                });
            }
            // Open team (no pin, no manifest) or the founder themselves.
            (Some(_) | None, _) => {}
        }

        let member_keys = load_member_keys(self.blob.as_ref(), &self.team).await?;
        // `highest_epoch` copies the max key out under the ring lock, so no guard
        // is held across the awaits below. `None` (empty ring) still floors at
        // `known_max_epoch`, so a keyless store cannot re-mint epoch 0.
        let floor = self.highest_epoch().unwrap_or(0).max(known_max_epoch);
        let new_epoch = floor.saturating_add(1);
        let new_key = SecretKey::generate();
        let wrapped = rotate_team_key(
            self.blob.as_ref(),
            &self.team,
            &new_key,
            new_epoch,
            &member_keys,
            self.founder.as_ref(),
        )
        .await?;
        if wrapped.is_empty() {
            // No wraps were published, so the bucket is unchanged; refusing here
            // keeps the write epoch on a key the team can actually read.
            return Err(MemError::NothingToRotate {
                team: self.team.clone(),
            });
        }
        if !wrapped.contains(&self.author) {
            // Recoverable but painful: the founder keeps the new key only for
            // this process's lifetime. Warn with the fix rather than refuse —
            // the wraps for the other members are already durable and valid.
            tracing::warn!(
                team = %self.team,
                new_epoch,
                founder = %self.author.as_str(),
                "the rotating founder has no published member key, so the new epoch is not \
                 wrapped to them; run `join` and rotate again or this machine loses the new \
                 key when the process exits"
            );
        }
        self.add_epoch_key(new_epoch, new_key);
        self.set_current_epoch(new_epoch);
        Ok(RotationOutcome { new_epoch, wrapped })
    }

    /// Member action: publish `identity`'s signed [`MemberKey`] so the founder's
    /// [`provision_members`](Self::provision_members) can wrap the team key to it.
    ///
    /// `identity` must be THIS store's own identity (its `x25519_public` is bound to
    /// the member key by this store's signer): a member joins by advertising the
    /// encryption key the founder wraps to. A join is a prerequisite for a member
    /// to be provisioned — the founder can only wrap to a published, verified key.
    ///
    /// # Errors
    ///
    /// [`MemError::Unauthorized`] if the freshly built key fails verification
    /// (a signer/identity mismatch), or [`MemError::Serialize`] /
    /// [`MemError::Storage`] from the publish.
    pub async fn join_as_member(&self, identity: &Identity) -> Result<(), MemError> {
        let member_key = MemberKey::create_signed(self.signer.as_ref(), identity);
        publish_member_key(self.blob.as_ref(), &self.team, &member_key).await
    }

    /// Fetch, verify, and decrypt the blob behind a converged `pointer` into the
    /// [`IndexRecord`] to index for `note_id`.
    ///
    /// Every error returned is a *data* fault the caller treats as "skip this
    /// note": fetch failure, AEAD/UTF-8/JSON failure, or a missing epoch key (this
    /// member was never provisioned the epoch the note was sealed under — they
    /// simply cannot index those notes). It deliberately does NOT upsert, so
    /// [`MemoryStore::sync`] can tell a bad blob from a systemic index fault, and
    /// so a missing-epoch note is skipped-with-warn there rather than failing the
    /// whole sync (the complement of [`MemoryStore::get`], which errors on a
    /// missing epoch). `cid` is recomputed from the fetched ciphertext (the same
    /// value the op recorded), so a later [`MemoryStore::get`] integrity-checks
    /// against exactly what is stored. `lamport`/`key_epoch` come from the
    /// convergence pointer.
    async fn decode_pointer(
        &self,
        note_id: NoteId,
        pointer: &NotePointer,
    ) -> Result<IndexRecord, MemError> {
        // Select the pointer's epoch key first: a member lacking this epoch cannot
        // decode the note, and returning the error here routes it into the
        // skip-with-warn path of `decode_records` / `snapshot`.
        let key = self.key_for_epoch(pointer.key_epoch)?;
        let ciphertext = self.blob.get(&pointer.object_key).await?;
        // Integrity gate against the SIGNED op's content hash, mirroring `get`
        // (line ~1655). `pointer.cid` rides on the note's winning `Remember`/`Edit`
        // op, so the op signature attests it; recomputing the hash of the fetched
        // bytes and comparing binds the blob to the signed op. Without this, the
        // sync/decode path would launder whatever bytes sit in the bucket into the
        // index as if op-attested: a party holding the epoch key but no valid
        // signing authority (a removed member with lingering bucket write, per the
        // monotonic-manifest threat model, or a MITM gateway that also holds the
        // key) could overwrite a historical blob in place under the same object key
        // and epoch — AEAD alone would still authenticate it. Store `pointer.cid`,
        // not the recomputed value, so `get`'s later gate checks against the signed
        // digest rather than one derived from the same untrusted bytes. A mismatch
        // routes into `decode_records`' skip-with-warn path.
        let cid = pointer.cid;
        if content_hash(&ciphertext) != cid {
            return Err(MemError::Storage(format!(
                "note {note_id}: ciphertext hash does not match the op-attested content hash"
            )));
        }
        // The object key is the AEAD associated data, so a blob relocated under a
        // foreign key fails authentication here and is skipped, never indexed under
        // the wrong identity.
        let plaintext = open(&key, &ciphertext, pointer.object_key.as_bytes())?;
        let json = std::str::from_utf8(&plaintext).map_err(|_| MemError::Crypto)?;
        let note = Note::from_json(json)?;

        // Bound a decoded (possibly untrusted-remote) note's tags/summary before
        // they enter this machine's in-memory index — the sync/convergence
        // ingestion boundary the local write-path caps do not cover.
        let (summary, tags) = bound_index_fields(&note.summary, note.tags);
        Ok(IndexRecord {
            note_id,
            object_key: pointer.object_key.clone(),
            cid,
            scope: note.scope,
            note_type: note.note_type,
            author: note.author,
            updated: note.updated,
            lamport: pointer.lamport,
            key_epoch: pointer.key_epoch,
            tags,
            summary,
            // Filled by the caller from the converged note state after decode
            // (`stamp_ranking_signals`); the note body carries neither typed
            // relations nor reinforcement — both ride on separate ops.
            relations: Vec::new(),
            reinforcers: BTreeSet::new(),
            last_reinforced: None,
            // Decoded remote notes are not offloaded; the index embeds them inline
            // (they ride the sync/replay path, off the request future).
            embedding: None,
        })
    }
}

/// Find the anchored batch covering `op_hash` and build its inclusion proof.
///
/// The op's hash is its Merkle leaf, stored verbatim in [`AnchorRecord::leaves`]
/// in the same order the tree was built over — so the leaf's
/// position in that slice is exactly the index [`inclusion_proof`] needs.
/// Returns `Ok(None)` when no record covers the op (still pending anchoring).
fn anchor_proof_for(
    records: &[AnchorRecord],
    record_roots: &[Blake3Hash],
    op_hash: Blake3Hash,
) -> Result<Option<AnchorProof>, MemError> {
    // `record_roots[i]` MUST be `merkle_root(&records[i].leaves)`. `history` builds
    // one proof per op, so recomputing a batch's root inside this loop would rehash
    // that batch's whole leaf vector once per op the batch anchors — O(ops × leaves)
    // for what is O(batches × leaves) of distinct work. The caller precomputes the
    // roots once and pairs them here by index; the two slices come from the same
    // `records` listing, so `zip` aligns them and never truncates silently.
    for (record, committed_root) in records.iter().zip(record_roots) {
        let Some(index) = record.leaves.iter().position(|leaf| *leaf == op_hash) else {
            continue;
        };
        // M3: only build a proof from a record whose stored `root` actually commits
        // its leaves. A bucket-forged record can be internally self-consistent
        // (root == receipt.root, correct op_count, unique leaves) yet carry a `root`
        // its leaves do not hash to; `read_anchor_records` deliberately lets such a
        // record through so `reconcile` can report it, so `history` must re-check the
        // binding here rather than hand back an `AnchorProof` that only looks
        // authoritative. Such a proof would fail `verify_proof` (the recomputed root
        // differs), but a caller trusting `anchor.is_some()` without verifying would
        // be misled — skip the record and treat the op as still unproven.
        if record.root != *committed_root {
            continue;
        }
        let proof = inclusion_proof(&record.leaves, index)?;
        return Ok(Some(AnchorProof {
            root: record.root,
            reference: record.receipt.reference.clone(),
            proof,
        }));
    }
    Ok(None)
}

/// Name the first field of a snapshot record's sealed `body` that contradicts what
/// the op-log signed about the note, or `None` when the body agrees on every field
/// the op-log can speak to.
///
/// # Why this exists
///
/// The snapshot's confidential fields travel as a sealed body while only
/// `note_id`/`lamport`/`object_key`/`key_epoch` travel in the clear (see
/// [`SealedRecord`]). The incremental safety valve compares the CLEAR envelope; the
/// SEALED body is what actually gets indexed, and it carries its own copies of those
/// four fields plus `author`, `cid`, `scope`, `note_type`, `updated`, `tags` and
/// `summary`. Nothing previously required the two to agree, nor the body to agree
/// with the op-log — so the snapshot was a signature-bypass channel: the op-log
/// demands a signed op from an author for every statement it carries, while the
/// record body demanded a signature from nobody.
///
/// # Threat model
///
/// The party this guards against is a holder of the CURRENT epoch key — that is, a
/// **team member**, not the bucket. The bucket holds no epoch key and cannot seal a
/// record at all; a snapshot it tampers with fails AEAD authentication in
/// [`load_latest_snapshot`] and is skipped. So this is not a hostile-bucket defence.
/// What it closes is one member attributing a note to a DIFFERENT member — or
/// re-pointing, re-scoping or re-dating it — without that member ever signing
/// anything.
///
/// # What it does NOT check
///
/// `summary`, `tags`, `updated` and `note_type` are **not** verified, because the
/// op-log makes no signed statement about them. A signed op carries only `op_id`,
/// `lamport`, `key_epoch`, `kind`, `note_id`, `object_key`, `cid` and
/// `prev_op_hash`; those four fields exist solely inside the note blob, bound to the
/// op-log by nothing but the blob's `cid`. A current-epoch key holder who leaves
/// every op-attested field true and rewrites only the summary (or tags, or
/// `updated`, or `note_type`) still passes this check and is still indexed — recall
/// surfaces the forgery while `get`, which re-fetches and cid-gates the blob, still
/// returns the true note. Closing that would mean reading the blob each record
/// describes, which is exactly the work the snapshot exists to avoid. Their SIZE is
/// bounded independently, by the [`bound_index_fields`] clamp the caller applies
/// before this check; that caps what an oversized forgery costs, never its content.
///
/// `scope` IS checked, because it is recoverable from the op-attested `object_key`
/// (`{team}/{repo_segment}/{note_id}/ver_{ulid}`).
fn snapshot_body_disagreement(
    body: &IndexRecord,
    envelope: &SealedRecord,
    pointer: Option<&NotePointer>,
) -> Option<&'static str> {
    // No live pointer in the converged base means the op-log names no content for
    // this note, so there is nothing to check the body against.
    //
    // NOTE this arm is fail-OPEN — `None` reads as "no disagreement", so the record
    // would be accepted — unlike the fail-SAFE `Err` arm at the end of this function.
    // The asymmetry is tolerable only because the arm is unreachable, NOT because
    // accepting an unbacked record would be acceptable: the caller reaches this check
    // only for a record whose note is in `final_live` and absent from `tail_live`, and
    // `final_live` is built from `base_pointers`' own keys, so the lookup always hits.
    // Should a refactor make it reachable, flip it to `Some(..)`: such a note is by
    // definition absent from `base_pointers`, so the caller cannot re-decode it either
    // and dropping it is then the only safe answer.
    let pointer = pointer?;

    // The body's own note id is what the index keys on, so a body claiming a
    // different note than its envelope could overwrite an unrelated note's entry.
    if body.note_id != envelope.note_id {
        return Some("note_id");
    }

    if body.object_key != pointer.object_key {
        return Some("object_key");
    }

    if body.cid != pointer.cid {
        return Some("cid");
    }

    if body.lamport != pointer.lamport {
        return Some("lamport");
    }

    if body.key_epoch != pointer.key_epoch {
        return Some("key_epoch");
    }

    // `pointer.author` is the identity that SIGNED the winning Remember/Edit op.
    // `remember` and `edit` both stamp the note body's author from the same signer,
    // so the two agree for every note this crate writes; requiring it here is what
    // stops the snapshot from asserting an attribution no signature backs.
    if body.author != pointer.author {
        return Some("author");
    }

    match parse_object_key(&pointer.object_key) {
        Ok((scope, _, _)) if scope == body.scope => None,
        Ok(_) => Some("scope"),
        // An op-attested key this crate cannot parse is not a key it minted, so the
        // scope the body claims cannot be corroborated either way.
        Err(_) => Some("object_key"),
    }
}

/// Copy each note's converged ranking signals — its OUTGOING typed relations and
/// its reinforcement (distinct reinforcers + last-reinforced time) — onto its
/// freshly-built index record.
///
/// A record built by [`MemoryStore::decode_pointer`] reflects only the note body,
/// which carries none of these: relations ride on `Relate` ops and reinforcement
/// on `Reinforce` ops, both separate from the content op. So the sync/snapshot
/// paths stamp them here from the SAME converged state the live pointers were
/// drawn from, which is what feeds recall's demotion and boost. A record whose
/// note is absent from `converged` (should not happen — records come from the live
/// set) keeps its empty defaults.
fn stamp_ranking_signals(records: &mut [IndexRecord], converged: &ConvergedState) {
    for record in records {
        if let Some(state) = converged.get(&record.note_id) {
            record.relations = state.relations.iter().copied().collect();
            record.reinforcers.clone_from(&state.reinforcers);
            record.last_reinforced = state.last_reinforced;
        }
    }
}

/// Remove every note the full converged history marks `redacted` from an
/// incremental sync's live sets.
///
/// A note REDACTED anywhere in the full member view must never re-enter the index,
/// even when the incremental TAIL still shows a live pointer for it. Redact is
/// absorbing under a full converge, but [`MemoryStore::sync_incremental`]'s
/// base/tail split can place the Redact in the checkpoint base and a later Edit in
/// the tail (a partitioned/EC-lagged machine that never observed the Redact):
/// `converge(&tail)` alone then reports the note live, so the shortcut would
/// resurrect it — diverging from `replay_full` and surfacing in recall a note that
/// was redacted for secrets/PII. `converged` (over the WHOLE member view) is the
/// authority. Tombstoned-but-not-redacted notes are deliberately NOT dropped: a
/// tombstone-then-resurrect is a by-design convergence outcome; only the absorbing
/// `redacted` flag diverges between the incremental and full paths.
fn drop_redacted(
    converged: &ConvergedState,
    final_live: &mut BTreeSet<NoteId>,
    tail_live: &mut BTreeMap<NoteId, NotePointer>,
) {
    for (note_id, state) in converged {
        if state.redacted {
            final_live.remove(note_id);
            tail_live.remove(note_id);
        }
    }
}

/// Drop entries older than `window` from a note→instant recency map, in place.
///
/// `saturating_duration_since` (not `duration_since`) so an entry stamped after
/// `now` — which a monotonic `Instant` should never produce, but the saturating
/// form is total regardless — reads as age zero rather than panicking.
fn prune_expired(map: &mut BTreeMap<NoteId, Instant>, now: Instant, window: Duration) {
    map.retain(|_, at| now.saturating_duration_since(*at) < window);
}

/// Reject a `summary` that is not a single, non-blank line within
/// [`MAX_SUMMARY_CHARS`] Unicode scalar values.
///
/// The boundary-validation point for `remember`/`edit`: a summary is validated
/// once here, at ingestion, so every downstream consumer — both recall legs and
/// the brief renderer — can trust its shape. A summary is malformed three ways,
/// each a silent product bug if admitted:
///
/// - **Blank** (empty or whitespace-only): it carries no lexical signal, so the
///   note is unrecallable by keyword, and it renders as an empty line — a note
///   that costs a write yet can never be found or read meaningfully.
/// - **Multi-line / control characters**: the summary is spliced verbatim into a
///   one-line markdown list item by [`render_brief`](crate::brief::render_brief)
///   (`- {summary}`), so an embedded newline fractures that list and injects
///   blank lines into the brief, and any other control character corrupts the
///   single-line display. `char::is_control` is exactly the Unicode C0/C1
///   control set — it includes `\n`, `\r`, and `\t`. Multi-line detail belongs
///   in the body, which is free-form.
/// - **Over-length**: counted in scalar values (`chars().count()`), not bytes,
///   so the cap means the same for ASCII and multibyte prose rather than
///   rejecting a short line of non-ASCII text (see [`MAX_SUMMARY_CHARS`] for why
///   an unbounded summary is a silent recall bug).
///
/// # Errors
///
/// [`MemError::Malformed`] — bad input the caller should fix, never retry — for
/// any of the three, with a message naming which rule failed and how to fix it.
fn validate_summary(summary: &str) -> Result<(), MemError> {
    if summary.trim().is_empty() {
        return Err(MemError::Malformed(
            "summary is blank; a note's summary is its one-line, recallable fact — put it here and any longer detail in the body".to_owned(),
        ));
    }
    if let Some(control) = summary.chars().find(|c| c.is_control()) {
        return Err(MemError::Malformed(format!(
            "summary contains a control character (U+{:04X}); it must be a single line — put multi-line detail in the body",
            control as u32
        )));
    }
    let len = summary.chars().count();
    if len > MAX_SUMMARY_CHARS {
        return Err(MemError::Malformed(format!(
            "summary is {len} characters; the maximum is {MAX_SUMMARY_CHARS} (it is a one-line summary — put detail in the body)"
        )));
    }
    Ok(())
}

/// Reject a note `body` longer than [`MAX_BODY_CHARS`] Unicode scalar values.
///
/// The body is free-form and may be empty or multi-line (unlike the one-line
/// [`validate_summary`]), so this caps only its length — bounding a
/// resource-exhaustion vector where one write would durably persist an arbitrarily
/// large blob. Counted in scalar values, not bytes.
///
/// # Errors
///
/// [`MemError::Malformed`] when the body exceeds the cap.
fn validate_body(body: &str) -> Result<(), MemError> {
    let len = body.chars().count();
    if len > MAX_BODY_CHARS {
        return Err(MemError::Malformed(format!(
            "body is {len} characters; the maximum is {MAX_BODY_CHARS} (a note body holds one fact's detail — split a document across linked notes)"
        )));
    }
    Ok(())
}

/// Reject a `tags` set with more than [`MAX_TAGS`] entries, or any tag longer than
/// [`MAX_TAG_CHARS`] Unicode scalar values.
///
/// Tags are pinned in every machine's in-memory index, so an unbounded set — or a
/// pathologically long tag — is the memory-resident amplification of the
/// resource-exhaustion vector [`validate_body`] bounds for storage. The caller's
/// `BTreeSet` has already collapsed duplicates, so `len` is the distinct-tag count.
///
/// # Errors
///
/// [`MemError::Malformed`] when the set is over-large or any tag over-length.
fn validate_tags(tags: &BTreeSet<String>) -> Result<(), MemError> {
    if tags.len() > MAX_TAGS {
        return Err(MemError::Malformed(format!(
            "note has {} tags; the maximum is {MAX_TAGS}",
            tags.len()
        )));
    }
    if let Some(tag) = tags.iter().find(|t| t.chars().count() > MAX_TAG_CHARS) {
        return Err(MemError::Malformed(format!(
            "a tag is {} characters; the maximum per tag is {MAX_TAG_CHARS}",
            tag.chars().count()
        )));
    }
    Ok(())
}

/// Truncate `s` to at most `max` Unicode scalar values (a no-op when already
/// within `max`). Char-boundary safe: `take(max)` never splits a multibyte scalar.
fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        s.chars().take(max).collect()
    }
}

/// Clamp a decoded note's `summary` and `tags` to the ingestion caps before they
/// enter this machine's in-memory index.
///
/// [`validate_body`]/[`validate_tags`] bound the LOCAL write path, but a note
/// arriving via `sync`/convergence was authored by a teammate (or an older/hostile
/// binary) that may not have — and its summary and tags land in THIS machine's
/// index. Clamping here caps the index's memory growth from an untrusted-remote
/// note (the body is not indexed — it stays only in the blob, whose size is
/// inherent once a teammate has uploaded it). This is a local, deterministic safety
/// clamp on what recall ranks/displays for such a note; it never mutates the
/// durable op or blob, and a within-caps note is returned unchanged.
fn bound_index_fields(summary: &str, tags: BTreeSet<String>) -> (String, BTreeSet<String>) {
    let summary = truncate_chars(summary, MAX_SUMMARY_CHARS);
    let tags = tags
        .into_iter()
        .take(MAX_TAGS)
        .map(|tag| truncate_chars(&tag, MAX_TAG_CHARS))
        .collect();
    (summary, tags)
}

/// "Now" as a [`Timestamp`].
///
/// On the practically-impossible event of a system clock set before the Unix
/// epoch, `duration_since` errors; we fall back to the epoch (0) rather than
/// panic, so a misconfigured clock degrades a timestamp instead of crashing a
/// write. A clock past `i64::MAX` milliseconds (year ~292 million) saturates
/// likewise — both paths avoid `unwrap`/`panic` entirely.
fn current_millis() -> Timestamp {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        });
    Timestamp::new(millis)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test, not a crash to avoid"
    )]

    use super::{
        IncrementalOutcome, MAX_BODY_CHARS, MAX_SUMMARY_CHARS, MAX_TAG_CHARS, MAX_TAGS,
        MemoryStore, NoteHistory, OpKindLabel, RecallInput, RememberInput, anchor_proof_for,
        bound_index_fields, load_latest_snapshot, object_key, validate_body, validate_summary,
        validate_tags,
    };
    use crate::NetworkPrefix;
    use crate::audit::read_anchor_records;
    use crate::audit::verify_proof;
    use crate::audit::{
        AnchorReceipt, AnchorRecord, AnchorRef, AuditAnchor, BatchMeta, NoopAnchor,
        RecordingAnchor, merkle_root,
    };
    use crate::crypto::{SecretKey, content_hash, open, seal};
    use crate::domain::{Blake3Hash, Note, NoteId, NoteType, RepoScope, Scope, Timestamp};
    use crate::error::MemError;
    use crate::identity::{
        ManifestMarker, MemberKey, TeamManifest, derive_identity, load_manifest,
        provision_team_key, publish_manifest, signer_from_mnemonic,
    };
    use crate::index::{
        HashEmbedder, InMemoryIndex, IndexRecord, Located, MemoryIndex, Query, SearchResult,
    };
    use crate::oplog::Signature;
    use crate::oplog::{LinkRel, Op, OpKind, OpLogStore, Signer, Sr25519Signer, VerifyingKey};
    use crate::store::{BlobStore, CachingBlobStore, MemoryBlobStore};
    use proptest::prelude::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::Duration;
    use ulid::Ulid;

    /// Threshold for store helpers that do not exercise anchoring: large enough
    /// that no single/double-write test ever reaches it, so anchoring stays inert.
    const NO_ANCHOR_THRESHOLD: usize = usize::MAX;

    /// A [`BlobStore`] that can be armed to fail op-log `put`s — drives the
    /// failed-append path so a test can prove a failed append never advances the
    /// clock or corrupts the chain (C1a). Only puts whose key is under `_oplog/`
    /// are gated, and only while armed; everything else delegates to a real
    /// in-memory store.
    struct OplogPutFailingBlob {
        inner: MemoryBlobStore,
        fail_oplog_puts: AtomicBool,
    }

    impl OplogPutFailingBlob {
        fn new() -> Self {
            Self {
                inner: MemoryBlobStore::default(),
                fail_oplog_puts: AtomicBool::new(false),
            }
        }

        /// Make the next (and subsequent) op-log `put`s fail until disarmed.
        fn arm(&self) {
            self.fail_oplog_puts.store(true, Ordering::SeqCst);
        }

        /// Let op-log `put`s succeed again.
        fn disarm(&self) {
            self.fail_oplog_puts.store(false, Ordering::SeqCst);
        }
    }

    #[async_trait::async_trait]
    impl BlobStore for OplogPutFailingBlob {
        async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
            if key.contains("/_oplog/") && self.fail_oplog_puts.load(Ordering::SeqCst) {
                return Err(MemError::Storage("op-log put failed (injected)".to_owned()));
            }
            self.inner.put(key, bytes).await
        }

        async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
            self.inner.get(key).await
        }

        async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError> {
            self.inner.list(prefix).await
        }

        async fn delete(&self, key: &str) -> Result<(), MemError> {
            self.inner.delete(key).await
        }
    }

    /// A [`BlobStore`] that captures every payload handed to `put` before
    /// forwarding it to a real in-memory backend. It exists to pin the
    /// encryption boundary: the store must hand this layer sealed ciphertext
    /// only, so a test can assert no recorded payload carries a plaintext
    /// sentinel.
    ///
    /// `puts` is behind a [`Mutex`] because [`BlobStore`] methods take `&self`
    /// and the trait is `Send + Sync` (the recorder is shared as
    /// `Arc<dyn BlobStore>`); the guard is dropped before the inner `.await`, so
    /// the put future stays `Send` (see exemplar `concurrency/mutex_guard_no_await`).
    struct RecordingBlobStore {
        inner: MemoryBlobStore,
        puts: Mutex<Vec<Vec<u8>>>,
    }

    impl RecordingBlobStore {
        fn new() -> Self {
            Self {
                inner: MemoryBlobStore::default(),
                puts: Mutex::new(Vec::new()),
            }
        }

        /// Snapshot of every payload seen by `put`, in call order. Poison
        /// (a panic while another holder had the lock) surfaces as a storage
        /// error rather than an `unwrap`, keeping the test lint-clean.
        fn recorded_puts(&self) -> Result<Vec<Vec<u8>>, MemError> {
            Ok(self
                .puts
                .lock()
                .map_err(|_| MemError::Storage("recorder mutex poisoned".to_owned()))?
                .clone())
        }
    }

    #[async_trait::async_trait]
    impl BlobStore for RecordingBlobStore {
        async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
            // Record BEFORE forwarding so the assertion sees exactly the bytes
            // the store chose to persist, independent of the inner outcome. The
            // guard drops at the `;`, before the `.await` below.
            self.puts
                .lock()
                .map_err(|_| MemError::Storage("recorder mutex poisoned".to_owned()))?
                .push(bytes.clone());
            self.inner.put(key, bytes).await
        }

        async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
            self.inner.get(key).await
        }

        async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError> {
            self.inner.list(prefix).await
        }

        async fn delete(&self, key: &str) -> Result<(), MemError> {
            self.inner.delete(key).await
        }
    }

    /// An [`AuditAnchor`] whose `anchor` always fails — drives the retain-on-failure
    /// path so a test can prove a failed anchor never loses the pending leaves.
    struct FailingAnchor;

    #[async_trait::async_trait]
    impl AuditAnchor for FailingAnchor {
        async fn anchor(
            &self,
            _root: Blake3Hash,
            _meta: BatchMeta,
        ) -> Result<AnchorReceipt, MemError> {
            Err(MemError::Storage("anchor sink unavailable".to_owned()))
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const TEST_KEY: [u8; 32] = [7_u8; 32];
    /// A distinct epoch-1 key, so a note sealed under it cannot accidentally open
    /// under the epoch-0 [`TEST_KEY`] and mask an epoch-selection bug.
    const EPOCH1_KEY: [u8; 32] = [8_u8; 32];
    const TEAM: &str = "team";
    /// The default signing seed for single-machine tests; the author SS58 is
    /// derived from it inside [`MemoryStore::new`].
    const SOLO_SEED: [u8; 32] = [5_u8; 32];
    // A distinctive phrase that lives only in the note body, so the
    // ciphertext-leakage test can search the at-rest bytes for it.
    const BODY_MARKER: &str = "half-read frame is lost";

    /// Build a store over `blob` (the op-log shares the same backend) with an
    /// explicit `anchor` + `threshold`, signing from `seed`. The author identity is
    /// derived from the seed inside [`MemoryStore::new`], so a distinct `seed` is a
    /// distinct author — there is no separate, mismatchable address to supply.
    fn store_with(
        blob: Arc<dyn BlobStore>,
        seed: [u8; 32],
        anchor: Arc<dyn AuditAnchor>,
        anchor_threshold: usize,
    ) -> Result<MemoryStore, MemError> {
        let signer: Arc<dyn Signer> = Arc::new(Sr25519Signer::from_seed_with_prefix(
            &seed,
            NetworkPrefix::HIPPIUS,
        )?);
        let oplog = OpLogStore::new(blob.clone());
        let index = Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default())));
        Ok(MemoryStore::new(
            blob,
            index,
            oplog,
            anchor,
            signer,
            BTreeMap::from([(0, SecretKey::from_bytes(TEST_KEY))]),
            0,
            TEAM.to_string(),
            anchor_threshold,
        ))
    }

    fn store_over(blob: Arc<dyn BlobStore>, seed: [u8; 32]) -> Result<MemoryStore, MemError> {
        store_with(blob, seed, Arc::new(NoopAnchor), NO_ANCHOR_THRESHOLD)
    }

    /// Like [`store_over`] but with an explicit key-ring and active epoch, so a
    /// test can model a member who genuinely LACKS an epoch (the default
    /// `store_over` always seeds epoch 0 with [`TEST_KEY`]).
    fn store_with_ring(
        blob: Arc<dyn BlobStore>,
        seed: [u8; 32],
        keys: BTreeMap<u64, SecretKey>,
        current_epoch: u64,
    ) -> Result<MemoryStore, MemError> {
        let signer: Arc<dyn Signer> = Arc::new(Sr25519Signer::from_seed_with_prefix(
            &seed,
            NetworkPrefix::HIPPIUS,
        )?);
        let oplog = OpLogStore::new(blob.clone());
        let index = Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default())));
        Ok(MemoryStore::new(
            blob,
            index,
            oplog,
            Arc::new(NoopAnchor),
            signer,
            keys,
            current_epoch,
            TEAM.to_string(),
            NO_ANCHOR_THRESHOLD,
        ))
    }

    fn build_store() -> Result<MemoryStore, MemError> {
        store_over(Arc::new(MemoryBlobStore::default()), SOLO_SEED)
    }

    fn test_store() -> Result<MemoryStore, Box<dyn std::error::Error>> {
        Ok(build_store()?)
    }

    fn sample_input() -> RememberInput {
        RememberInput {
            force: true,
            note_type: NoteType::Gotcha,
            repo: RepoScope::Repo("thebrain".to_string()),
            tags: BTreeSet::from(["async".to_string(), "tokio".to_string()]),
            summary: "select drops the losing branch future".to_string(),
            body: format!(
                "Under tokio::select! the unpicked branch is dropped, so a {BODY_MARKER} unless partial state lives in the receiver."
            ),
        }
    }

    // ---- Write-time dedup gate (Feature 3) ----
    //
    // The default test build embeds with `HashEmbedder`, so `nearest_duplicate`
    // runs its LEXICAL (token-set Jaccard) path — these tests assert that path.
    //
    // The semantic (cosine) path is NOT covered, here or anywhere. This comment
    // used to claim the `embeddings`-gated e2e suite covered it; that suite sets
    // `force: true` on every `remember`, so it bypasses the gate entirely and
    // has never exercised cosine dedup. Treat the cosine path as unverified.

    /// A `remember` input for the dedup tests, with `force` chosen explicitly so
    /// each test states whether it expects the gate to run.
    fn dedup_input(repo: RepoScope, summary: &str, force: bool) -> RememberInput {
        RememberInput {
            note_type: NoteType::Decision,
            repo,
            tags: BTreeSet::new(),
            summary: summary.to_string(),
            body: "detail lives in the body, not the summary".to_string(),
            force,
        }
    }

    #[tokio::test]
    async fn near_duplicate_remember_is_refused_naming_the_existing_note() -> TestResult {
        let store = test_store()?;
        let repo = RepoScope::Repo("thebrain".to_string());
        let summary = "prefer BTreeMap for deterministic snapshot ordering";
        let first = store
            .remember(dedup_input(repo.clone(), summary, false))
            .await?;
        // Re-remembering the identical summary is a Jaccard 1.0 match, so the gate
        // refuses it and the error names `first` for the caller to act on.
        match store.remember(dedup_input(repo, summary, false)).await {
            Err(MemError::NearDuplicate {
                existing,
                similarity,
            }) => {
                let threshold = super::DEDUP_THRESHOLD;
                assert_eq!(existing, first, "the refusal names the existing note");
                assert!(
                    similarity >= threshold,
                    "similarity {similarity} must clear the {threshold} gate threshold"
                );
                Ok(())
            }
            other => Err(format!("expected NearDuplicate, got {other:?}").into()),
        }
    }

    #[tokio::test]
    async fn force_bypasses_the_dedup_gate() -> TestResult {
        let store = test_store()?;
        let repo = RepoScope::Repo("thebrain".to_string());
        let summary = "prefer BTreeMap for deterministic snapshot ordering";
        let first = store
            .remember(dedup_input(repo.clone(), summary, false))
            .await?;
        // Same summary, but `force` writes it anyway — a distinct second note.
        let second = store.remember(dedup_input(repo, summary, true)).await?;
        assert_ne!(first, second, "force produced a genuinely new note");
        Ok(())
    }

    #[tokio::test]
    async fn a_distinct_summary_passes_the_dedup_gate() -> TestResult {
        let store = test_store()?;
        let repo = RepoScope::Repo("thebrain".to_string());
        store
            .remember(dedup_input(
                repo.clone(),
                "prefer BTreeMap for deterministic snapshot ordering",
                false,
            ))
            .await?;
        // A summary sharing no tokens with the first is nowhere near the threshold,
        // so the gate lets it through.
        store
            .remember(dedup_input(
                repo,
                "rotate the team key after removing a member",
                false,
            ))
            .await?;
        Ok(())
    }

    /// A summary of `shared + 1` distinct tokens: `shared` tokens every such
    /// summary shares, plus one unique marker. Two of them therefore overlap by a
    /// token-set Jaccard of exactly `shared / (shared + 2)` — the knob the
    /// boundary test below turns to land either side of the threshold.
    fn straddling_summary(shared: usize, marker: &str) -> String {
        let mut tokens: Vec<String> = (0..shared).map(|i| format!("token{i}")).collect();
        tokens.push(marker.to_owned());
        tokens.join(" ")
    }

    #[tokio::test]
    async fn the_dedup_threshold_is_pinned_at_its_boundary() -> TestResult {
        // The gate's only coverage was Jaccard 1.0 (refused) and 0.0 (accepted),
        // which pins nothing about WHERE the boundary sits: `DEDUP_THRESHOLD`
        // could move from 0.9 to 0.05 or to 0.999 with every test still green
        // (mutation-verified at 0.05). These two cases straddle the real boundary
        // — 17/19 = 0.895 must pass, 19/21 = 0.905 must be refused — so the
        // constant is pinned to within about a percent in both directions.
        //
        // The two cases use different repos because the gate is repo-scoped, so
        // neither can see the other's notes.
        let store = test_store()?;

        let below = RepoScope::Repo("below".to_owned());
        store
            .remember(dedup_input(
                below.clone(),
                &straddling_summary(17, "alpha"),
                false,
            ))
            .await?;
        store
            .remember(dedup_input(below, &straddling_summary(17, "beta"), false))
            .await?;

        let above = RepoScope::Repo("above".to_owned());
        let first = store
            .remember(dedup_input(
                above.clone(),
                &straddling_summary(19, "alpha"),
                false,
            ))
            .await?;

        match store
            .remember(dedup_input(above, &straddling_summary(19, "beta"), false))
            .await
        {
            Err(MemError::NearDuplicate {
                existing,
                similarity,
            }) => {
                assert_eq!(existing, first, "the refusal names the existing note");
                assert!(
                    (0.85..0.95).contains(&similarity),
                    "19/21 must land just above the gate, got {similarity}"
                );
                Ok(())
            }
            other => {
                Err(format!("expected NearDuplicate just above the gate, got {other:?}").into())
            }
        }
    }

    #[tokio::test]
    async fn dedup_gate_is_scoped_to_the_notes_repo() -> TestResult {
        let store = test_store()?;
        let summary = "prefer BTreeMap for deterministic snapshot ordering";
        store
            .remember(dedup_input(
                RepoScope::Repo("alpha".to_string()),
                summary,
                false,
            ))
            .await?;
        // The same summary in a DIFFERENT non-global repo is out of scope for the
        // first note, so the gate does not see it — repo-scoped knowledge can
        // legitimately repeat a phrasing another repo already used.
        store
            .remember(dedup_input(
                RepoScope::Repo("beta".to_string()),
                summary,
                false,
            ))
            .await?;
        Ok(())
    }

    // ---- Reinforcement + trust-weighted ranking (Feature 4) ----

    /// A distinct-summary note for the reinforcement tests. `force: true` keeps the
    /// dedup gate out of the way — these tests exercise reinforcement, not dedup.
    fn use_input(summary: &str) -> RememberInput {
        RememberInput {
            note_type: NoteType::Convention,
            repo: RepoScope::Global,
            tags: BTreeSet::new(),
            summary: summary.to_string(),
            body: "detail in the body".to_string(),
            force: true,
        }
    }

    fn recall_for(text: &str) -> RecallInput {
        RecallInput {
            text: text.to_string(),
            repo: RepoScope::Global,
            k: 10,
            token_budget: None,
        }
    }

    /// The recall score of `id` for `text`, or `None` if it did not surface.
    fn recall_score(store: &MemoryStore, text: &str, id: NoteId) -> Option<f32> {
        let result = store.recall(recall_for(text)).ok()?;
        result
            .pointers
            .into_iter()
            .find(|pointer| pointer.note_id == id)
            .map(|pointer| pointer.score)
    }

    fn count_reinforce_ops(history: &NoteHistory) -> usize {
        history
            .entries
            .iter()
            .filter(|entry| entry.kind == OpKindLabel::Reinforce)
            .count()
    }

    #[tokio::test]
    async fn reinforce_on_get_after_recall_boosts_rank() -> TestResult {
        let store = test_store()?;
        let a = store
            .remember(use_input(
                "tokio select cancellation drops the losing future",
            ))
            .await?;
        store
            .remember(use_input(
                "tokio spawn blocking offloads work to a thread pool",
            ))
            .await?;
        // A first recall surfaces A and records it as recalled; capture A's score.
        let before = recall_score(&store, "tokio", a).ok_or("A did not surface initially")?;
        // A `get` of the just-recalled A is a use signal → appends a Reinforce op.
        store.get(a).await?;
        // Converge the reinforcement into the index, then re-score A.
        store.sync().await?;
        let after = recall_score(&store, "tokio", a).ok_or("A did not surface after reinforce")?;
        assert!(
            after > before,
            "reinforcement must raise A's score: {after} !> {before}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn reinforce_is_rate_limited_to_one_op_per_window() -> TestResult {
        let store = test_store()?;
        let a = store
            .remember(use_input("rotate the team key after removing a member"))
            .await?;
        // Recall surfaces A; then get it twice within the same rate-limit window.
        store.recall(recall_for("rotate"))?;
        store.get(a).await?;
        store.get(a).await?;
        // The second get is throttled, so exactly ONE Reinforce op was appended —
        // one agent re-reading a note cannot inflate it.
        let history = store.history(a).await?;
        assert_eq!(
            count_reinforce_ops(&history),
            1,
            "the rate limit emits exactly one Reinforce per window"
        );
        Ok(())
    }

    #[tokio::test]
    async fn bare_get_without_a_preceding_recall_does_not_reinforce() -> TestResult {
        let store = test_store()?;
        let a = store
            .remember(use_input(
                "prefer explicit error enums over stringly-typed errors",
            ))
            .await?;
        // A `get` by id with no preceding recall is not a use signal — nothing to
        // reinforce, so no Reinforce op is written.
        store.get(a).await?;
        let history = store.history(a).await?;
        assert_eq!(
            count_reinforce_ops(&history),
            0,
            "a get with no preceding recall does not reinforce"
        );
        Ok(())
    }

    /// A [`BlobStore`] whose `put` fails while `fail_puts` is set — drives the
    /// reinforce append-failure path without disturbing reads.
    #[derive(Default)]
    struct PutFailBlob {
        inner: MemoryBlobStore,
        fail_puts: std::sync::atomic::AtomicBool,
    }

    #[async_trait::async_trait]
    impl BlobStore for PutFailBlob {
        async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
            if self.fail_puts.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(MemError::Storage("simulated put outage".to_owned()));
            }
            self.inner.put(key, bytes).await
        }

        async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
            self.inner.get(key).await
        }

        async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError> {
            self.inner.list(prefix).await
        }

        async fn delete(&self, key: &str) -> Result<(), MemError> {
            self.inner.delete(key).await
        }
    }

    #[tokio::test]
    async fn a_failed_reinforce_append_releases_the_rate_limit_slot() -> TestResult {
        // The rate-limit slot is claimed under the lock BEFORE the append (so
        // concurrent gets cannot double-emit). A failed append must give the slot
        // back — otherwise the next qualifying use inside the window is refused
        // and the documented "self-heals on the next qualifying use" silently
        // becomes "waits out the whole window".
        let blob = Arc::new(PutFailBlob::default());
        let store = store_over(blob.clone() as Arc<dyn BlobStore>, SOLO_SEED)?;
        let a = store
            .remember(use_input("list-after-write is eventually consistent"))
            .await?;
        store.recall(recall_for("consistent"))?;

        // First qualifying get: the Reinforce append fails at the blob layer and
        // is swallowed (a use signal must never fail the read).
        blob.fail_puts
            .store(true, std::sync::atomic::Ordering::Relaxed);
        store.get(a).await?;
        blob.fail_puts
            .store(false, std::sync::atomic::Ordering::Relaxed);

        // Second qualifying get, well inside the rate-limit window: it must
        // reinforce NOW, proving the failed attempt released its slot.
        store.get(a).await?;
        let history = store.history(a).await?;
        assert_eq!(
            count_reinforce_ops(&history),
            1,
            "the failed append must release its rate-limit slot so the next qualifying use reinforces"
        );
        Ok(())
    }

    #[tokio::test]
    async fn redact_scrubs_every_blob_and_history_reports_it() -> TestResult {
        // Hold the blob handle so we can prove the ciphertext is physically gone,
        // not merely hidden from the index.
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let store = store_over(blob.clone(), SOLO_SEED)?;
        let id = store.remember(sample_input()).await?;
        // A second version, so redaction must scrub more than one blob.
        store.edit(id, sample_input()).await?;
        store.get(id).await?; // gettable before redaction

        let id_seg = format!("/{id}/");
        let versions = |keys: Vec<String>| keys.iter().filter(|k| k.contains(&id_seg)).count();
        assert_eq!(
            versions(blob.list("").await?),
            2,
            "two ciphertext versions exist before redaction"
        );

        store.redact(id).await?;

        // (a) Every ciphertext version is deleted from the bucket.
        assert_eq!(
            versions(blob.list("").await?),
            0,
            "redact scrubs every ciphertext version"
        );
        // (b) The body is unrecoverable (gone from the live index).
        assert!(
            matches!(store.get(id).await, Err(MemError::NotFound { .. })),
            "a redacted note's body is unrecoverable"
        );
        // (c) The audit shell survives and stays provable: history still verifies,
        // reports redacted, and the op trail keeps both the Remember and the Redact.
        let history = store.history(id).await?;
        assert!(history.redacted, "history reports the note redacted");
        assert!(
            history
                .entries
                .iter()
                .any(|e| e.kind == OpKindLabel::Redact),
            "the Redact op survives in the audit trail"
        );
        assert!(
            history
                .entries
                .iter()
                .any(|e| e.kind == OpKindLabel::Remember),
            "the original Remember op survives too"
        );
        Ok(())
    }

    #[tokio::test]
    async fn sync_purges_a_redacted_notes_body_from_a_teammates_cache() -> TestResult {
        // [5] The privacy contract of `redact`: after a teammate applies the Redact
        // op via `sync`, the note's sealed body — decryptable by any team-key
        // holder — must not survive in that teammate's local read-through cache.
        // The shared bucket is one backend; machine B additionally caches over it.
        let shared: Arc<MemoryBlobStore> = Arc::new(MemoryBlobStore::default());
        let machine_a = store_over(shared.clone() as Arc<dyn BlobStore>, SOLO_SEED)?;

        let cache_dir = tempfile::tempdir()?;
        let b_blob: Arc<dyn BlobStore> = Arc::new(CachingBlobStore::new(
            shared.clone() as Arc<dyn BlobStore>,
            cache_dir.path().to_path_buf(),
            SecretKey::from_bytes(TEST_KEY),
        ));
        let machine_b = store_over(b_blob.clone(), [6_u8; 32])?;

        // A writes a note (two versions, so more than one blob must be purged).
        let id = machine_a.remember(sample_input()).await?;
        machine_a.edit(id, sample_input()).await?;

        // The note's version blobs, captured from the shared bucket before redaction.
        let id_seg = format!("/{id}/");
        let version_keys: Vec<String> = shared
            .list("")
            .await?
            .into_iter()
            .filter(|key| key.contains(&id_seg))
            .collect();
        assert_eq!(version_keys.len(), 2, "two ciphertext versions exist");

        // B syncs (indexing the note) and caches each version blob.
        machine_b.sync().await?;
        for key in &version_keys {
            assert!(
                b_blob.get(key).await.is_ok(),
                "B caches the note's ciphertext"
            );
        }

        // A redacts: the shared-bucket ciphertext is scrubbed, but B's cache still
        // holds it — proven by reading it back from B's cache while the bucket copy
        // is already gone.
        machine_a.redact(id).await?;
        for key in &version_keys {
            assert!(
                b_blob.get(key).await.is_ok(),
                "before B syncs the redaction, the body still survives in B's cache"
            );
        }

        // B syncs, applying the Redact: its cache must be purged.
        machine_b.sync().await?;
        for key in &version_keys {
            assert!(
                matches!(b_blob.get(key).await, Err(MemError::NotFound { .. })),
                "a redacted note's body must not survive in a teammate's cache after sync"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn sync_purges_a_forgotten_then_redacted_notes_body_from_cache() -> TestResult {
        // [5] regression: the purge must NOT gate on the local index. A note that is
        // FORGOTTEN here (dropped from the index, cache retained) before its Redact
        // is synced would be skipped by an index-gated purge, leaving its sealed,
        // team-key-decryptable body on disk forever — the exact leak redact closes.
        // B caches the note, forgets it (unindexing it locally), then a teammate that
        // still holds it redacts it; B's next sync must still evict the cached body.
        let shared: Arc<MemoryBlobStore> = Arc::new(MemoryBlobStore::default());

        let cache_dir = tempfile::tempdir()?;
        let b_blob: Arc<dyn BlobStore> = Arc::new(CachingBlobStore::new(
            shared.clone() as Arc<dyn BlobStore>,
            cache_dir.path().to_path_buf(),
            SecretKey::from_bytes(TEST_KEY),
        ));
        let machine_b = store_over(b_blob.clone(), [6_u8; 32])?;
        let machine_a = store_over(shared.clone() as Arc<dyn BlobStore>, SOLO_SEED)?;

        // B writes the note (caching its version blob on `put`); A syncs it in so A
        // still holds it after B later forgets it.
        let id = machine_b.remember(sample_input()).await?;
        let id_seg = format!("/{id}/");
        let version_keys: Vec<String> = shared
            .list("")
            .await?
            .into_iter()
            .filter(|key| key.contains(&id_seg))
            .collect();
        assert_eq!(version_keys.len(), 1, "one ciphertext version exists");
        machine_a.sync().await?;

        // B forgets the note: it leaves B's index but its body stays in B's cache
        // (only redact scrubs a body; forget just tombstones the pointer).
        machine_b.forget(id).await?;
        for key in &version_keys {
            assert!(
                b_blob.get(key).await.is_ok(),
                "forget leaves the body in B's cache"
            );
        }

        // A — which never synced the forget, so still has the note indexed — redacts
        // it, appending the Redact op and scrubbing the shared-bucket copy.
        machine_a.redact(id).await?;

        // B syncs the Redact. Even though the note is no longer in B's index, the
        // purge must still evict the cached body.
        machine_b.sync().await?;
        for key in &version_keys {
            assert!(
                matches!(b_blob.get(key).await, Err(MemError::NotFound { .. })),
                "a forgotten-then-redacted note's body must not survive in the cache"
            );
        }
        Ok(())
    }

    /// A [`BlobStore`] counting note-version-blob `get`s (keys with no `/_`-prefixed
    /// reserved segment), so a test can tell an incremental snapshot restore (zero
    /// note decodes) from a full rebuild (one decode per live note).
    struct NoteGetCountingBlob {
        inner: MemoryBlobStore,
        note_gets: std::sync::atomic::AtomicUsize,
    }

    impl NoteGetCountingBlob {
        fn new() -> Self {
            Self {
                inner: MemoryBlobStore::default(),
                note_gets: std::sync::atomic::AtomicUsize::new(0),
            }
        }
        fn reset_note_gets(&self) {
            self.note_gets.store(0, Ordering::SeqCst);
        }
        fn note_gets(&self) -> usize {
            self.note_gets.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl BlobStore for NoteGetCountingBlob {
        async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
            self.inner.put(key, bytes).await
        }
        async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
            // Reserved objects (op-log, snapshots, anchors, manifest) carry a
            // `/_`-prefixed segment; a note version blob never does.
            if !key.contains("/_") {
                self.note_gets.fetch_add(1, Ordering::SeqCst);
            }
            self.inner.get(key).await
        }
        async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError> {
            self.inner.list(prefix).await
        }
        async fn delete(&self, key: &str) -> Result<(), MemError> {
            self.inner.delete(key).await
        }
    }

    /// A [`MemoryIndex`] decorator that, on the FIRST `all_records()` call, appends
    /// a synthetic record at a lamport far above any real tip — modelling a
    /// `remember` that landed in the index AFTER `sync` pruned to the members-view
    /// but BEFORE the checkpoint read. Everything else delegates unchanged.
    struct PoisonAllRecordsIndex {
        inner: Arc<dyn MemoryIndex>,
        poisoned: AtomicBool,
    }

    impl PoisonAllRecordsIndex {
        fn new(inner: Arc<dyn MemoryIndex>) -> Self {
            Self {
                inner,
                poisoned: AtomicBool::new(false),
            }
        }
    }

    impl MemoryIndex for PoisonAllRecordsIndex {
        fn upsert(&self, record: IndexRecord) -> Result<(), MemError> {
            self.inner.upsert(record)
        }
        fn upsert_batch(&self, records: Vec<IndexRecord>) -> Result<(), MemError> {
            self.inner.upsert_batch(records)
        }
        fn search(&self, query: &Query) -> Result<SearchResult, MemError> {
            self.inner.search(query)
        }
        fn remove(&self, id: NoteId) -> Result<(), MemError> {
            self.inner.remove(id)
        }
        fn locate(&self, id: NoteId) -> Result<Option<Located>, MemError> {
            self.inner.locate(id)
        }
        fn retain(&self, keep: &BTreeSet<NoteId>) -> Result<(), MemError> {
            self.inner.retain(keep)
        }
        fn all_records(&self) -> Result<Vec<IndexRecord>, MemError> {
            let mut records = self.inner.all_records()?;
            if !self.poisoned.swap(true, Ordering::SeqCst)
                && let Some(template) = records.first()
            {
                let mut poison = template.clone();
                // A note the members-view never named, at a lamport above any tip.
                poison.note_id = NoteId::new();
                poison.lamport = poison.lamport.saturating_add(1_000_000);
                records.push(poison);
            }
            Ok(records)
        }
    }

    #[tokio::test]
    async fn sync_does_not_poison_checkpoint_with_a_post_baseline_record() -> TestResult {
        // [11] A write racing sync can leave the index holding a note at a lamport
        // ABOVE the tip the checkpoint claims. Sealing it poisons the fast path: a
        // later `sync_incremental` re-converges the base (lamport <= baseline),
        // cannot find that note, and full-rebuilds on EVERY sync. The checkpoint
        // filter drops it, so the next sync stays incremental — restoring the real
        // note from the snapshot without decoding its blob.
        let bucket = Arc::new(NoteGetCountingBlob::new());
        let blob: Arc<dyn BlobStore> = bucket.clone();
        let inner_index: Arc<dyn MemoryIndex> =
            Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default())));
        let index = Arc::new(PoisonAllRecordsIndex::new(inner_index));
        let signer: Arc<dyn Signer> = Arc::new(Sr25519Signer::from_seed_with_prefix(
            &SOLO_SEED,
            NetworkPrefix::HIPPIUS,
        )?);
        let oplog = OpLogStore::new(blob.clone());
        let store = MemoryStore::new(
            blob.clone(),
            index,
            oplog,
            Arc::new(NoopAnchor),
            signer,
            BTreeMap::from([(0, SecretKey::from_bytes(TEST_KEY))]),
            0,
            TEAM.to_string(),
            NO_ANCHOR_THRESHOLD,
        );

        store.remember(sample_input()).await?;
        // Cold sync: rebuilds and writes the checkpoint; the poison record surfaces
        // during the checkpoint's `all_records()` read.
        store.sync().await?;

        // The next sync must restore incrementally from a CLEAN checkpoint, decoding
        // no note blob. A poisoned checkpoint would fail the safety valve and force a
        // full rebuild — which decodes the live note's blob.
        bucket.reset_note_gets();
        store.sync().await?;
        assert_eq!(
            bucket.note_gets(),
            0,
            "the second sync restores from a clean checkpoint (incremental); a post-baseline record would have poisoned it into a full rebuild"
        );
        Ok(())
    }

    /// An [`AuditAnchor`] whose FIRST `anchor` call never resolves (so a caller's
    /// timeout cancels it mid-commit) and whose subsequent calls behave like a
    /// [`RecordingAnchor`] — proving a leaf cancelled mid-commit is not lost.
    struct BlockOnceThenRecord {
        tripped: AtomicBool,
        inner: RecordingAnchor,
    }

    impl BlockOnceThenRecord {
        fn new() -> Self {
            Self {
                tripped: AtomicBool::new(false),
                inner: RecordingAnchor::new(),
            }
        }
    }

    #[async_trait::async_trait]
    impl AuditAnchor for BlockOnceThenRecord {
        async fn anchor(
            &self,
            root: Blake3Hash,
            meta: BatchMeta,
        ) -> Result<AnchorReceipt, MemError> {
            if !self.tripped.swap(true, Ordering::SeqCst) {
                // Never resolves: the caller's timeout drops this future mid-commit.
                std::future::pending::<()>().await;
            }
            self.inner.anchor(root, meta).await
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[tokio::test]
    async fn cancelled_anchor_commit_returns_its_leaves_to_pending() -> TestResult {
        // [17] A commit cancelled between `drain_batch` and completion must not lose
        // the drained batch: without the drop guard those ops would get no anchor
        // proof, ever. Threshold 16 so the write does not auto-anchor; `flush`
        // triggers the commit, and a timeout cancels it mid-anchor.
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let store = store_with(
            blob.clone(),
            SOLO_SEED,
            Arc::new(BlockOnceThenRecord::new()),
            16,
        )?;
        store.remember(sample_input()).await?;

        let cancelled =
            tokio::time::timeout(std::time::Duration::from_millis(50), store.flush_anchors()).await;
        assert!(
            cancelled.is_err(),
            "the commit future is cancelled by the timeout while the anchor sink blocks"
        );

        // The leaf was returned to pending, so a second flush (the anchor now
        // succeeds) still finds it and seals a record. Without the guard the leaf is
        // gone and this flush anchors nothing.
        let receipt = store.flush_anchors().await?;
        assert!(
            receipt.is_some(),
            "the leaf cancelled mid-commit was returned to pending and re-anchored"
        );
        let records = read_anchor_records(&blob, TEAM).await?;
        assert_eq!(records.len(), 1, "the retained leaf's batch is persisted");
        assert_eq!(records[0].leaves.len(), 1, "exactly the one retained leaf");
        Ok(())
    }

    #[tokio::test]
    async fn remember_and_edit_reject_an_oversized_summary() -> TestResult {
        // [20] A summary beyond the cap is silently truncated by the semantic leg
        // but not the lexical one, so its tail is inconsistently indexed. Reject it
        // at ingestion as bad input, on both the remember and edit paths.
        let store = test_store()?;

        let oversized = || RememberInput {
            force: true,
            summary: "x".repeat(MAX_SUMMARY_CHARS + 1),
            ..sample_input()
        };
        assert!(
            matches!(
                store.remember(oversized()).await,
                Err(MemError::Malformed(_))
            ),
            "remember rejects an oversized summary"
        );

        // A summary exactly at the cap is accepted.
        let id = store
            .remember(RememberInput {
                force: true,
                summary: "z".repeat(MAX_SUMMARY_CHARS),
                ..sample_input()
            })
            .await?;

        // The edit path enforces the same cap, and nothing is written on rejection.
        assert!(
            matches!(
                store.edit(id, oversized()).await,
                Err(MemError::Malformed(_))
            ),
            "edit rejects an oversized summary"
        );
        assert_eq!(
            store.get(id).await?.summary.chars().count(),
            MAX_SUMMARY_CHARS,
            "the rejected edit left the at-cap summary unchanged"
        );
        Ok(())
    }

    #[tokio::test]
    async fn remember_and_edit_reject_a_blank_or_multiline_summary() -> TestResult {
        // The summary is the sole recall/brief surface: a blank one is an
        // unrecallable, empty-rendering note, and an embedded newline (or any
        // control char) fractures `render_brief`'s one-line list item. Reject
        // both at ingestion, on the remember and edit paths, before any write.
        let store = test_store()?;

        let with_summary = |s: &str| RememberInput {
            force: true,
            summary: s.to_owned(),
            ..sample_input()
        };
        for bad in ["", "   ", "\n", "line one\nline two", "tabbed\tsummary"] {
            assert!(
                matches!(
                    store.remember(with_summary(bad)).await,
                    Err(MemError::Malformed(_))
                ),
                "remember must reject the malformed summary {bad:?}"
            );
        }

        // A valid one-line summary is accepted; a later blank edit is refused and
        // leaves the accepted note unchanged (nothing written on rejection).
        let id = store
            .remember(with_summary("a valid one-line fact"))
            .await?;
        assert!(
            matches!(
                store.edit(id, with_summary("  \n  ")).await,
                Err(MemError::Malformed(_))
            ),
            "edit must reject a blank/whitespace summary"
        );
        assert_eq!(
            store.get(id).await?.summary,
            "a valid one-line fact",
            "the rejected edit left the summary unchanged"
        );
        Ok(())
    }

    #[test]
    fn validate_summary_counts_scalar_values_not_bytes() {
        // The cap is in Unicode scalar values, so a `MAX_SUMMARY_CHARS`-'é'
        // summary (two bytes each) is accepted and one 'é' longer is rejected —
        // the boundary must not shift with multibyte prose. A single printable
        // character is the minimal valid summary.
        assert!(validate_summary("x").is_ok());
        assert!(validate_summary(&"é".repeat(MAX_SUMMARY_CHARS)).is_ok());
        assert!(matches!(
            validate_summary(&"é".repeat(MAX_SUMMARY_CHARS + 1)),
            Err(MemError::Malformed(_))
        ));
    }

    #[tokio::test]
    async fn remember_rejects_an_oversized_body_or_tag_set() -> TestResult {
        // An unbounded body or tag set is a resource-exhaustion vector; rejected at
        // ingestion on the remember path (new notes), with nothing written.
        let store = test_store()?;
        assert!(
            matches!(
                store
                    .remember(RememberInput {
                        force: true,
                        body: "x".repeat(MAX_BODY_CHARS + 1),
                        ..sample_input()
                    })
                    .await,
                Err(MemError::Malformed(_))
            ),
            "remember rejects an oversized body"
        );
        assert!(
            matches!(
                store
                    .remember(RememberInput {
                        force: true,
                        tags: (0..=MAX_TAGS).map(|i| i.to_string()).collect(),
                        ..sample_input()
                    })
                    .await,
                Err(MemError::Malformed(_))
            ),
            "remember rejects an over-large tag set"
        );
        Ok(())
    }

    #[tokio::test]
    async fn edit_is_grandfather_safe_but_bounds_new_growth() -> TestResult {
        // An edit that does NOT change the body is not re-validated (so a
        // pre-existing note is never frozen out of edits); a CHANGED body must come
        // within the cap (so an edit cannot grow a note past it).
        let store = test_store()?;
        let id = store
            .remember(RememberInput {
                force: true,
                body: "small".to_string(),
                ..sample_input()
            })
            .await?;

        // Changing ONLY the summary (body passed back unchanged) is allowed.
        store
            .edit(
                id,
                RememberInput {
                    force: true,
                    summary: "a new one-line summary".to_string(),
                    body: "small".to_string(),
                    ..sample_input()
                },
            )
            .await?;
        assert_eq!(store.get(id).await?.summary, "a new one-line summary");

        // Changing the body to an oversized one is rejected; the note is untouched.
        assert!(
            matches!(
                store
                    .edit(
                        id,
                        RememberInput {
                            force: true,
                            body: "x".repeat(MAX_BODY_CHARS + 1),
                            ..sample_input()
                        },
                    )
                    .await,
                Err(MemError::Malformed(_))
            ),
            "a changed, oversized body is rejected"
        );
        assert_eq!(
            store.get(id).await?.body,
            "small",
            "the rejected edit left the body intact"
        );
        Ok(())
    }

    #[test]
    fn validate_body_and_tags_bound_in_scalar_values() {
        use std::collections::BTreeSet;
        // Body: free-form, empty/multi-line ok; only length, in scalar values.
        assert!(validate_body("").is_ok());
        assert!(validate_body("multi\nline\nis fine").is_ok());
        assert!(validate_body(&"é".repeat(MAX_BODY_CHARS)).is_ok());
        assert!(matches!(
            validate_body(&"é".repeat(MAX_BODY_CHARS + 1)),
            Err(MemError::Malformed(_))
        ));
        // Tags: count and per-tag length.
        assert!(validate_tags(&BTreeSet::new()).is_ok());
        let at_cap: BTreeSet<String> = (0..MAX_TAGS).map(|i| i.to_string()).collect();
        assert!(validate_tags(&at_cap).is_ok());
        let too_many: BTreeSet<String> = (0..=MAX_TAGS).map(|i| i.to_string()).collect();
        assert!(matches!(
            validate_tags(&too_many),
            Err(MemError::Malformed(_))
        ));
        let long_tag: BTreeSet<String> = std::iter::once("é".repeat(MAX_TAG_CHARS + 1)).collect();
        assert!(matches!(
            validate_tags(&long_tag),
            Err(MemError::Malformed(_))
        ));
    }

    #[test]
    fn bound_index_fields_clamps_an_untrusted_remote_note() {
        use std::collections::BTreeSet;
        // The sync-ingestion clamp: an oversized decoded (remote) note's summary and
        // tags are truncated to the caps before entering the index.
        let tags: BTreeSet<String> = (0..MAX_TAGS + 20).map(|i| format!("tag{i:04}")).collect();
        let (summary, bounded) = bound_index_fields(&"s".repeat(MAX_SUMMARY_CHARS + 100), tags);
        assert_eq!(
            summary.chars().count(),
            MAX_SUMMARY_CHARS,
            "an oversized remote summary is clamped"
        );
        assert!(bounded.len() <= MAX_TAGS, "the tag count is clamped");
        assert!(
            bounded.iter().all(|t| t.chars().count() <= MAX_TAG_CHARS),
            "each tag is clamped to the per-tag cap"
        );

        // A within-caps note passes through unchanged.
        let ok: BTreeSet<String> = BTreeSet::from(["a".to_string(), "b".to_string()]);
        let (s, t) = bound_index_fields("short", ok.clone());
        assert_eq!(s, "short");
        assert_eq!(t, ok);
    }

    #[tokio::test]
    async fn edit_precondition_guards_against_stale_writes() -> TestResult {
        let store = test_store()?;
        let id = store.remember(sample_input()).await?;
        let version = store.current_version(id)?;

        // A stale precondition (the zero hash) is refused, and nothing is written.
        let refused = store
            .edit_with_precondition(id, sample_input(), Some(crate::Blake3Hash::zero()))
            .await;
        assert!(
            matches!(refused, Err(MemError::Conflict { .. })),
            "a stale precondition must be refused, got {refused:?}"
        );

        // The correct version is accepted...
        store
            .edit_with_precondition(id, sample_input(), Some(version))
            .await?;
        // ...and the now-consumed version no longer satisfies the precondition,
        // proving the CAS observed the write.
        let again = store
            .edit_with_precondition(id, sample_input(), Some(version))
            .await;
        assert!(
            matches!(again, Err(MemError::Conflict { .. })),
            "the consumed version must no longer satisfy the precondition"
        );
        Ok(())
    }

    /// Team-scoped bootstrap: a wrap published under a DIFFERENT team must never
    /// load into this store's ring. [`MemoryStore::bootstrap_epoch_keys`] derives
    /// the team from `self.team`, not a caller argument, so it cannot be pointed
    /// at a foreign team. Epochs are small integers that collide across teams and
    /// [`MemoryStore::add_epoch_key`] REPLACES, so without this scoping a foreign
    /// team's wrap could silently overwrite a live key. Pins the invariant against
    /// a future refactor reintroducing a `team` parameter.
    #[tokio::test]
    async fn bootstrap_epoch_keys_is_scoped_to_the_stores_own_team() -> TestResult {
        // All-zero-entropy BIP-39 vector: a deterministic, valid mnemonic.
        const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());

        let identity = crate::derive_identity(PHRASE, NetworkPrefix::HIPPIUS)?;
        let signer = crate::signer_from_mnemonic(PHRASE, NetworkPrefix::HIPPIUS)?;
        let member_key = crate::MemberKey::create_signed(&signer, &identity);
        let epoch1_key = SecretKey::from_bytes(EPOCH1_KEY);

        // Provision the member's epoch-1 wrap under a FOREIGN team, then bootstrap
        // a store configured for `TEAM`: the foreign wrap must be invisible.
        crate::provision_team_key(
            blob.as_ref(),
            "other-team",
            &epoch1_key,
            1,
            std::slice::from_ref(&member_key),
            None,
        )
        .await?;
        let store = store_over(blob.clone(), SOLO_SEED)?;
        let added = store.bootstrap_epoch_keys(&identity, &[1]).await?;
        assert_eq!(
            added, 0,
            "a wrap under a foreign team must not load into this ring"
        );

        // Positive control: the SAME wrap under THIS store's own team DOES load,
        // so the team name is the only thing that gated the negative case.
        crate::provision_team_key(blob.as_ref(), TEAM, &epoch1_key, 1, &[member_key], None).await?;
        let added = store.bootstrap_epoch_keys(&identity, &[1]).await?;
        assert_eq!(added, 1, "a wrap under this store's own team loads");
        Ok(())
    }

    #[tokio::test]
    async fn join_then_provision_considers_the_joined_member() -> TestResult {
        // Feature 5 end-to-end (founder side): a member `join`s by publishing its
        // signed member key, and the founder's `provision` then considers that key.
        // The underlying wrap/unwrap crypto is proven in the teamkey tests; this
        // pins that the store's thin wrappers publish a loadable key and provision
        // over it.
        const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        // Unpinned founder store with a team key at epoch 0 (via `store_over`).
        let store = store_over(blob.clone(), SOLO_SEED)?;
        let identity = crate::derive_identity(PHRASE, NetworkPrefix::HIPPIUS)?;

        assert_eq!(
            store.provision_members().await?,
            0,
            "no member keys are published before any join"
        );
        store.join_as_member(&identity).await?;
        assert_eq!(
            store.provision_members().await?,
            1,
            "the joined member key is considered for provisioning"
        );
        Ok(())
    }

    #[tokio::test]
    async fn remember_then_recall_returns_pointer_not_body() -> TestResult {
        let store = test_store()?;
        let input = sample_input();
        let summary = input.summary.clone();
        let body = input.body.clone();
        let id = store.remember(input).await?;

        let pointers = store
            .recall(RecallInput {
                text: "select losing branch".to_string(),
                repo: RepoScope::Repo("thebrain".to_string()),
                k: 5,
                token_budget: None,
            })?
            .pointers;

        let pointer = pointers
            .iter()
            .find(|p| p.note_id == id)
            .ok_or("recall did not surface the remembered note")?;
        // Recall yields the summary as a pointer; `Pointer` structurally has no
        // body field, so the body is only reachable through `get`.
        assert_eq!(pointer.summary, summary);
        let note = store.get(id).await?;
        assert_eq!(note.body, body);
        Ok(())
    }

    #[tokio::test]
    async fn remember_then_get_round_trips() -> TestResult {
        let store = test_store()?;
        let input = sample_input();
        let expected = input.clone();
        let id = store.remember(input).await?;

        let note = store.get(id).await?;
        assert_eq!(note.id, id);
        assert_eq!(note.body, expected.body);
        assert_eq!(note.summary, expected.summary);
        assert_eq!(note.tags, expected.tags);
        assert_eq!(note.note_type, expected.note_type);
        Ok(())
    }

    #[tokio::test]
    async fn remember_offloaded_matches_remember_and_still_validates() -> TestResult {
        // The binary offloads the summary embed onto the blocking pool and hands the
        // vector to `remember_offloaded`; the only difference from `remember` is WHERE
        // the embed ran (ASYNCBLOCK). Precomputing with the store's own `embed_summary`
        // must yield a note that round-trips and is findable by recall — the offload is
        // a pure relocation of the embed, not a behavior change.
        let store = test_store()?;
        let input = sample_input();
        let expected = input.clone();
        let embedding = store.embed_summary(&input.summary)?;
        let id = store.remember_offloaded(input, embedding).await?;

        let note = store.get(id).await?;
        assert_eq!(note.summary, expected.summary);
        assert_eq!(note.body, expected.body);
        assert_eq!(note.tags, expected.tags);
        let found = store
            .recall(RecallInput {
                text: "select losing branch".to_string(),
                repo: RepoScope::Repo("thebrain".to_string()),
                k: 5,
                token_budget: None,
            })?
            .pointers
            .iter()
            .any(|pointer| pointer.note_id == id);
        assert!(found, "recall must surface the offloaded-write note");

        // The offloaded wrapper delegates to the same validating core, so an oversized
        // body is still rejected with nothing written: relocating the embed must not
        // open a bypass around the resource-exhaustion guard.
        let oversized = RememberInput {
            force: true,
            body: "x".repeat(MAX_BODY_CHARS + 1),
            ..sample_input()
        };
        let embedding = store.embed_summary(&oversized.summary)?;
        let rejected = store.remember_offloaded(oversized, embedding).await;
        assert!(
            matches!(rejected, Err(MemError::Malformed(_))),
            "offloaded remember must still reject an oversized body, got {rejected:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn edit_offloaded_updates_the_note_and_honors_the_precondition() -> TestResult {
        // `edit_offloaded` is `edit_with_precondition` with the summary embed
        // precomputed off-runtime — the fix that keeps the ONNX embed from running
        // under the writer lock (ASYNCBLOCK-002). It must behave identically: apply the
        // edit under a matching precondition, then refuse a stale one with nothing
        // written, proving it routes through the same CAS guard.
        let store = test_store()?;
        let id = store.remember(sample_input()).await?;
        let version = store.current_version(id)?;

        let edited = RememberInput {
            summary: "offloaded edit summary".to_string(),
            body: "offloaded edit body".to_string(),
            ..sample_input()
        };
        let embedding = store.embed_summary(&edited.summary)?;
        store
            .edit_offloaded(id, edited, Some(version), embedding)
            .await?;
        let note = store.get(id).await?;
        assert_eq!(note.summary, "offloaded edit summary");
        assert_eq!(note.body, "offloaded edit body");

        // The now-consumed version no longer satisfies the CAS.
        let stale = sample_input();
        let embedding = store.embed_summary(&stale.summary)?;
        let refused = store
            .edit_offloaded(id, stale, Some(version), embedding)
            .await;
        assert!(
            matches!(refused, Err(MemError::Conflict { .. })),
            "a stale precondition must be refused on the offloaded edit, got {refused:?}"
        );
        Ok(())
    }

    // ---- Orphan blob mark-and-sweep GC (CANCELSAFETY) ----

    /// Craft a valid note-blob key no op names, under `store`'s team/global scope,
    /// with a fresh version ULID (so its write-time is ~now for grace tests).
    fn orphan_key(store: &MemoryStore) -> Result<String, Box<dyn std::error::Error>> {
        let scope = Scope {
            team: store.team().to_owned(),
            repo: RepoScope::Global,
        };
        Ok(object_key(&scope, NoteId::new(), Ulid::new())?)
    }

    #[tokio::test]
    async fn sweep_reclaims_an_orphan_keeps_referenced_and_never_touches_internal_namespaces()
    -> TestResult {
        let store = test_store()?;
        // A real write: a referenced note blob PLUS a real op-log object under
        // `_oplog/` (which the sweep must skip). `sample_input` forces past dedup.
        let id = store.remember(sample_input()).await?;
        let live_key = store
            .index
            .locate(id)?
            .ok_or("the remembered note must be indexed")?
            .object_key;

        // The orphan: a note-shaped blob no op names (the cancelled-write leak).
        let orphan = orphan_key(&store)?;
        store
            .blob
            .put(&orphan, b"orphaned ciphertext".to_vec())
            .await?;

        // Plant objects in the internal namespaces the sweep must never touch: an
        // `_anchors` key (the tricky 4-segment shape, rejected because its id segment
        // is not a `mem_<ulid>`) and a `_snapshots` key (rejected on segment count).
        let team = store.team().to_owned();
        let fake_anchor = format!("{team}/_anchors/deadbeef/00000000000000000001");
        let fake_snapshot = format!("{team}/_snapshots/00000000000000000042");
        store
            .blob
            .put(&fake_anchor, b"not an anchor".to_vec())
            .await?;
        store
            .blob
            .put(&fake_snapshot, b"not a snapshot".to_vec())
            .await?;

        // grace = ZERO: the orphan (age >= 0) is reaped; everything referenced or
        // out-of-scope is kept regardless of age.
        let report = store.sweep_orphan_blobs(Duration::ZERO, false).await?;

        assert!(
            store.blob.get(&orphan).await.is_err(),
            "the orphan blob must be deleted"
        );
        assert!(
            store.blob.get(&live_key).await.is_ok(),
            "a blob a durable op names must be kept"
        );
        assert_eq!(
            store.get(id).await?.id,
            id,
            "the live note still reads after the sweep"
        );
        // The internal-namespace objects are untouched — the scope invariant.
        assert!(
            store.blob.get(&fake_anchor).await.is_ok(),
            "an `_anchors` object must never be swept"
        );
        assert!(
            store.blob.get(&fake_snapshot).await.is_ok(),
            "a `_snapshots` object must never be swept"
        );
        assert_eq!(
            report.note_blobs_scanned, 2,
            "only the live blob and the orphan are note blobs; the op-log/anchor/snapshot objects are filtered out"
        );
        assert_eq!(report.orphans_found, 1);
        assert_eq!(report.orphans_reclaimed, 1);
        Ok(())
    }

    #[tokio::test]
    async fn sweep_keeps_orphans_younger_than_the_grace_window() -> TestResult {
        let store = test_store()?;
        let orphan = orphan_key(&store)?;
        store.blob.put(&orphan, b"young orphan".to_vec()).await?;

        // A generous grace keeps a just-written unreferenced blob: its op may still be
        // in flight, so reaping it now could race a commit.
        let kept = store
            .sweep_orphan_blobs(Duration::from_hours(1), false)
            .await?;
        assert_eq!(kept.orphans_found, 0, "a young orphan is not yet reapable");
        assert_eq!(kept.within_grace_kept, 1, "it is counted as grace-kept");
        assert!(
            store.blob.get(&orphan).await.is_ok(),
            "the young orphan must be kept"
        );

        // Once the window is zero the same blob is reaped — proving grace, not
        // reachability, is what spared it.
        let reaped = store.sweep_orphan_blobs(Duration::ZERO, false).await?;
        assert_eq!(reaped.orphans_reclaimed, 1);
        assert!(store.blob.get(&orphan).await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn sweep_dry_run_reports_orphans_without_deleting() -> TestResult {
        let store = test_store()?;
        let orphan = orphan_key(&store)?;
        store.blob.put(&orphan, b"orphan".to_vec()).await?;

        let report = store.sweep_orphan_blobs(Duration::ZERO, true).await?;
        assert_eq!(report.orphans_found, 1, "the orphan is found");
        assert_eq!(report.orphans_reclaimed, 0, "a dry run deletes nothing");
        assert!(
            store.blob.get(&orphan).await.is_ok(),
            "the orphan survives a dry run"
        );
        Ok(())
    }

    #[tokio::test]
    async fn list_records_enumerates_every_remembered_note() -> TestResult {
        // Drive the PUBLIC ingestion path (`remember`), not a direct index insert,
        // so the test stays honest about what a real write puts in the index.
        let store = test_store()?;
        let first = RememberInput {
            force: true,
            note_type: NoteType::Decision,
            repo: RepoScope::Global,
            tags: BTreeSet::new(),
            summary: "first browse-view note".to_string(),
            body: "body of the first note".to_string(),
        };
        let second = RememberInput {
            force: true,
            note_type: NoteType::Gotcha,
            repo: RepoScope::Repo("thebrain".to_string()),
            tags: BTreeSet::from(["browse".to_string()]),
            summary: "second browse-view note".to_string(),
            body: "body of the second note".to_string(),
        };
        store.remember(first).await?;
        store.remember(second).await?;

        let summaries: BTreeSet<String> = store
            .list_records()?
            .into_iter()
            .map(|record| record.summary)
            .collect();
        assert!(
            summaries.contains("first browse-view note"),
            "list_records must surface the first note's summary"
        );
        assert!(
            summaries.contains("second browse-view note"),
            "list_records must surface the second note's summary"
        );
        Ok(())
    }

    #[test]
    fn team_and_is_semantic_expose_store_configuration() -> TestResult {
        // The dashboard reads these two accessors directly for its header and
        // retrieval badge, so pin both: `team` echoes the construction argument,
        // and the HashEmbedder test store is lexical (recall is keyword-only).
        let store = test_store()?;
        assert_eq!(
            store.team(),
            TEAM,
            "team() echoes the constructed namespace"
        );
        assert!(
            !store.is_semantic(),
            "the HashEmbedder-backed test store ranks lexically"
        );
        Ok(())
    }

    #[tokio::test]
    async fn highest_published_epoch_reports_the_bucket_state() -> TestResult {
        // `MemoryStore::highest_published_epoch` delegates to the free
        // `teamkey::highest_published_epoch` over this store's OWN private
        // blob/team, without exposing either — the seam this pins: a caller
        // holding only `&MemoryStore` still learns what the bucket has
        // published, with no raw blob handle ever leaving the store.
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let store = store_over(Arc::clone(&blob), SOLO_SEED)?;

        assert_eq!(
            store.highest_published_epoch().await?,
            0,
            "a fresh bucket has published no wrapped key"
        );

        // Publish a wrapped key at epoch 1 directly on the SAME underlying
        // blob store the store was built over, via the real teamkey publish
        // path (`provision_team_key`) — exactly how a rotation populates it.
        let phrase = "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
        let signer = signer_from_mnemonic(phrase, NetworkPrefix::HIPPIUS)?;
        let identity = derive_identity(phrase, NetworkPrefix::HIPPIUS)?;
        let member = MemberKey::create_signed(&signer, &identity);
        provision_team_key(
            blob.as_ref(),
            TEAM,
            &SecretKey::from_bytes([9u8; 32]),
            1,
            std::slice::from_ref(&member),
            None,
        )
        .await?;

        assert_eq!(
            store.highest_published_epoch().await?,
            1,
            "the store must report the epoch actually published on its own bucket"
        );
        Ok(())
    }

    #[tokio::test]
    async fn edit_updates_note_body() -> TestResult {
        let store = test_store()?;
        let id = store.remember(sample_input()).await?;
        let original = store.get(id).await?;

        store
            .edit(
                id,
                RememberInput {
                    force: true,
                    note_type: NoteType::Decision,
                    repo: RepoScope::Global,
                    tags: BTreeSet::from(["edited".to_string()]),
                    summary: "edited summary line".to_string(),
                    body: "the rewritten body".to_string(),
                },
            )
            .await?;

        let edited = store.get(id).await?;
        assert_eq!(edited.id, id, "edit keeps the same id");
        assert_eq!(edited.body, "the rewritten body");
        assert_eq!(edited.summary, "edited summary line");
        assert_eq!(edited.note_type, NoteType::Decision);
        assert_eq!(
            edited.created.as_millis(),
            original.created.as_millis(),
            "created is preserved across an edit"
        );
        assert!(
            edited.updated.as_millis() >= original.updated.as_millis(),
            "updated does not move backwards"
        );

        // The op-log records the edit as an Edit op after the Remember.
        let history = store.history(id).await?;
        assert_eq!(history.entries.len(), 2, "one Remember + one Edit");
        assert_eq!(history.entries[0].kind, OpKindLabel::Remember);
        assert_eq!(history.entries[1].kind, OpKindLabel::Edit);
        Ok(())
    }

    #[tokio::test]
    async fn edit_preserves_scope_even_when_input_carries_a_different_repo() -> TestResult {
        // A note's repo is fixed at `remember`; an edit changes content, not
        // location, even when the caller passes a different `repo`. This keeps every
        // version of a note under ONE `{team}/{repo}/{mem_id}/` prefix — the
        // invariant `redact`'s prefix-scoped scrub relies on to reach all
        // ciphertext. Without it, this very edit (input repo Global vs the note's
        // `thebrain`) would strand version 2 under `/global/`, out of the scrub's
        // reach.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let store = store_over(bucket.clone(), SOLO_SEED)?;
        // `sample_input` lives under repo "thebrain".
        let id = store.remember(sample_input()).await?;
        store
            .edit(
                id,
                RememberInput {
                    force: true,
                    note_type: NoteType::Decision,
                    repo: RepoScope::Global,
                    tags: BTreeSet::new(),
                    summary: "edited under a different input repo".to_string(),
                    body: "body".to_string(),
                },
            )
            .await?;

        assert_eq!(
            store.get(id).await?.scope.repo,
            RepoScope::Repo("thebrain".to_string()),
            "edit must not relocate the note to the input's repo",
        );
        assert_eq!(
            bucket.list(&format!("{TEAM}/thebrain/{id}/")).await?.len(),
            2,
            "both versions must live under the note's original prefix",
        );
        assert!(
            bucket
                .list(&format!("{TEAM}/global/{id}/"))
                .await?
                .is_empty(),
            "no version may be stranded under the input's repo",
        );
        Ok(())
    }

    #[tokio::test]
    async fn edit_unknown_id_is_not_found() -> TestResult {
        let store = test_store()?;
        match store
            .edit(
                NoteId::new(),
                RememberInput {
                    force: true,
                    note_type: NoteType::Decision,
                    repo: RepoScope::Global,
                    tags: BTreeSet::new(),
                    summary: "x".to_string(),
                    body: "y".to_string(),
                },
            )
            .await
        {
            Err(MemError::NotFound { .. }) => Ok(()),
            Err(other) => Err(format!("expected NotFound, got {other:?}").into()),
            Ok(()) => Err("editing an unknown note unexpectedly succeeded".into()),
        }
    }

    #[tokio::test]
    async fn each_write_version_lands_at_a_distinct_key() -> TestResult {
        // H2 regression: every remember/edit writes its ciphertext under a
        // globally-unique object key (the writing op's ULID). Two writes — even
        // racing edits on two machines that both hold the same prior version —
        // can therefore never derive the same key and overwrite each other's
        // blob, losing the convergence winner's body. One remember + two edits
        // must leave THREE distinct version blobs coexisting in the bucket.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let store = store_over(bucket.clone(), SOLO_SEED)?;
        let id = store.remember(sample_input()).await?;
        for body in ["second body", "third body"] {
            store
                .edit(
                    id,
                    RememberInput {
                        force: true,
                        note_type: NoteType::Decision,
                        repo: RepoScope::Repo("thebrain".to_string()),
                        tags: BTreeSet::new(),
                        summary: format!("summary for {body}"),
                        body: body.to_string(),
                    },
                )
                .await?;
        }

        // The note's three version blobs live under this prefix; the op-log and
        // anchor records sit under sibling `_oplog/` / `_anchors/` prefixes, so a
        // prefixed list returns exactly the version blobs.
        let prefix = format!("{TEAM}/thebrain/{id}/");
        let version_keys = bucket.list(&prefix).await?;
        assert_eq!(
            version_keys.len(),
            3,
            "one remember + two edits must leave three distinct version blobs, got {version_keys:?}",
        );
        // The latest edit is the live body, and it is still readable (its key was
        // not clobbered).
        assert_eq!(store.get(id).await?.body, "third body");
        Ok(())
    }

    #[tokio::test]
    async fn concurrent_edits_from_same_base_do_not_overwrite() -> TestResult {
        // H2 (discriminating): two machines edit the SAME note from the SAME synced
        // base. The old rev-counter scheme made both derive the next revision from
        // their identical view — the SAME key — so the second edit's `put`
        // overwrote the first's ciphertext, and the convergence winner could then
        // name a key holding the LOSER's bytes (get's integrity gate rejects it).
        // Keying each version by its op's ULID gives the two edits distinct keys,
        // so both blobs coexist and the winner stays readable. This test fails on
        // the old rev-counter code (only two version blobs; get may fail) and
        // passes on the ULID-key fix.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let a = store_over(bucket.clone(), SOLO_SEED)?;
        let b = store_over(bucket.clone(), [71_u8; 32])?;

        // A creates the note (repo Global so every version shares one prefix); B
        // syncs so it holds the SAME base version A does.
        let base = RememberInput {
            force: true,
            note_type: NoteType::Reference,
            repo: RepoScope::Global,
            tags: BTreeSet::new(),
            summary: "shared base summary".to_string(),
            body: "base body".to_string(),
        };
        let id = a.remember(base).await?;
        b.sync().await?;

        // Both edit from that shared base — neither has seen the other's edit.
        let edit = |body: &str| RememberInput {
            force: true,
            note_type: NoteType::Reference,
            repo: RepoScope::Global,
            tags: BTreeSet::new(),
            summary: format!("summary {body}"),
            body: body.to_string(),
        };
        a.edit(id, edit("A body")).await?;
        b.edit(id, edit("B body")).await?;

        // Three distinct version blobs coexist: the original + both edits. The old
        // rev-counter scheme would leave only two (the second edit overwrote the
        // first at the shared ver_2 key).
        let prefix = format!("{TEAM}/global/{id}/");
        let versions = bucket.list(&prefix).await?;
        assert_eq!(
            versions.len(),
            3,
            "remember + two concurrent edits must leave three distinct version blobs, got {versions:?}"
        );

        // The convergence winner is readable on a fresh sync: its op names its own
        // intact blob, not the other edit's, so the integrity gate passes.
        a.sync().await?;
        let body = a.get(id).await?.body;
        assert!(
            body == "A body" || body == "B body",
            "the convergence winner's body must be readable, got {body:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_precondition_is_not_a_distributed_lock() -> TestResult {
        // Scope guard for `edit_with_precondition`. The CAS compares against THIS
        // machine's converged index, so two machines holding the same base version
        // BOTH pass their preconditions and last-writer-wins silently drops one
        // edit. That is the documented contract ("a CAS within converged state,
        // not a distributed lock"), but nothing pinned it: the only concurrency
        // test for the guard is same-machine, where it genuinely does serialize.
        // Without this test the tool-facing promise could widen into a
        // cross-machine guarantee the implementation has never provided.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let a = store_over(bucket.clone(), SOLO_SEED)?;
        let b = store_over(bucket.clone(), [72_u8; 32])?;

        let base = RememberInput {
            force: true,
            note_type: NoteType::Reference,
            repo: RepoScope::Global,
            tags: BTreeSet::new(),
            summary: "shared base summary".to_string(),
            body: "base body".to_string(),
        };
        let id = a.remember(base).await?;
        b.sync().await?;

        // Both machines read the same version and hold it as their precondition.
        let version_a = a.current_version(id)?;
        let version_b = b.current_version(id)?;
        assert_eq!(
            version_a, version_b,
            "both machines must start from the same base version",
        );

        let edit = |body: &str| RememberInput {
            force: true,
            note_type: NoteType::Reference,
            repo: RepoScope::Global,
            tags: BTreeSet::new(),
            summary: format!("summary {body}"),
            body: body.to_string(),
        };

        // Neither machine has seen the other's edit, so BOTH preconditions pass.
        // A same-machine pair here would conflict — see
        // `concurrent_precondition_edits_cannot_both_win`.
        a.edit_with_precondition(id, edit("A body"), Some(version_a))
            .await?;
        b.edit_with_precondition(id, edit("B body"), Some(version_b))
            .await?;

        // Exactly one survives convergence; the other is superseded with no
        // conflict ever surfaced to its author.
        a.sync().await?;
        let body = a.get(id).await?.body;
        assert!(
            body == "A body" || body == "B body",
            "one of the two concurrent preconditioned edits must win, got {body:?}",
        );

        Ok(())
    }

    #[tokio::test]
    async fn edit_converges() -> TestResult {
        // Two machines share one bucket/op-log. A remembers; B syncs and sees the
        // original. A edits; after B re-syncs, convergence's latest-wins surfaces
        // the edited version on B — the cross-machine edit propagation.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let a = store_over(bucket.clone(), SOLO_SEED)?;
        let b = store_over(bucket.clone(), [71_u8; 32])?;

        let id = a.remember(sample_input()).await?;
        b.sync().await?;
        let original = b.get(id).await?;

        a.edit(
            id,
            RememberInput {
                force: true,
                note_type: NoteType::Gotcha,
                repo: RepoScope::Repo("thebrain".to_string()),
                tags: BTreeSet::new(),
                summary: "select drops the losing branch future".to_string(),
                body: "EDITED: partial state must live in the receiver".to_string(),
            },
        )
        .await?;
        b.sync().await?;

        let edited = b.get(id).await?;
        assert_ne!(
            edited.body, original.body,
            "B sees a different body after the edit syncs"
        );
        assert!(
            edited.body.contains("EDITED"),
            "B sees A's edited body: {}",
            edited.body
        );
        Ok(())
    }

    /// A [`BlobStore`] that gates the FIRST `list` call: it runs the inner listing
    /// (capturing the pre-write snapshot), signals that the snapshot is in hand,
    /// then blocks until released. This lets a test pin the exact
    /// `sync`-reads-the-log / concurrent-write interleaving that the C2 fix closes.
    /// All later lists pass straight through.
    struct GatedListBlob {
        inner: MemoryBlobStore,
        /// Armed for exactly one list; the first `list` consumes it via swap.
        armed: AtomicBool,
        /// Fired by the gated list once it has captured its (pre-write) snapshot.
        captured: tokio::sync::Notify,
        /// Awaited by the gated list; the test fires it to let `sync` proceed.
        release: tokio::sync::Notify,
    }

    impl GatedListBlob {
        fn new() -> Self {
            Self {
                inner: MemoryBlobStore::default(),
                armed: AtomicBool::new(true),
                captured: tokio::sync::Notify::new(),
                release: tokio::sync::Notify::new(),
            }
        }
    }

    #[async_trait::async_trait]
    impl BlobStore for GatedListBlob {
        async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
            self.inner.put(key, bytes).await
        }

        async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
            self.inner.get(key).await
        }

        async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError> {
            // Capture the listing BEFORE gating, so the held snapshot reflects the
            // log as it was when `sync` began reading — exactly the stale view the
            // bug re-seeds the clock from.
            let result = self.inner.list(prefix).await;
            if self.armed.swap(false, Ordering::SeqCst) {
                self.captured.notify_one();
                self.release.notified().await;
            }
            result
        }

        async fn delete(&self, key: &str) -> Result<(), MemError> {
            self.inner.delete(key).await
        }
    }

    /// C2 regression: a `sync` reading the log concurrently with a local write must
    /// not fork this author's chain. Under the bug, `sync` reads `read_all` outside
    /// the writer lock, so the write lands in the gap and the stale re-seed regresses
    /// the cached clock; the next write then re-mints a duplicate
    /// `(lamport, prev_op_hash)` and the verified read rejects the whole log forever.
    /// Under the fix the write blocks on the writer lock until `sync` finishes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_sync_and_write_does_not_fork_chain() -> TestResult {
        let blob = Arc::new(GatedListBlob::new());
        let store = Arc::new(store_over(blob.clone(), SOLO_SEED)?);

        // One durable op so this author has a chain head a stale re-seed can regress.
        store.remember(sample_input()).await?;

        // sync(): its read_all → list captures the {op1}-only snapshot, then parks.
        let sync_store = store.clone();
        let sync_task = tokio::spawn(async move { sync_store.sync().await });
        blob.captured.notified().await;

        // A concurrent write on the same author while sync holds the gate. Under the
        // bug it slips into the gap and advances the durable clock unseen; under the
        // fix it blocks on the writer lock that sync now holds across read_all.
        let write_store = store.clone();
        let write_task = tokio::spawn(async move { write_store.remember(sample_input()).await });

        // Let the write reach its terminal (bug) or lock-blocked (fix) state before
        // releasing the gate — the inherent timing seam of a read/write race test.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        blob.release.notify_one();

        sync_task.await??;
        write_task.await??;

        // A third write re-uses op2's slot only if the clock regressed. The proof is
        // that a final verified read still succeeds: a forked chain makes `sync`
        // reject the whole log with `MemError::Storage`.
        store.remember(sample_input()).await?;
        store.sync().await?;
        Ok(())
    }

    /// A blob store whose `list` can be armed to omit the latest op-log object
    /// exactly once — emulating an eventually-consistent backend whose LIST lags a
    /// PUT that already committed (and that the writer clock already advanced to).
    struct LaggingListBlob {
        inner: MemoryBlobStore,
        drop_latest_oplog: AtomicBool,
    }

    impl LaggingListBlob {
        fn new() -> Self {
            Self {
                inner: MemoryBlobStore::default(),
                drop_latest_oplog: AtomicBool::new(false),
            }
        }
    }

    #[async_trait::async_trait]
    impl BlobStore for LaggingListBlob {
        async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
            self.inner.put(key, bytes).await
        }

        async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
            self.inner.get(key).await
        }

        async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError> {
            let mut keys = self.inner.list(prefix).await?;
            // Op-log keys sort in logical order, so the greatest key is the latest
            // op; drop it once to model a listing that has not yet caught up.
            if prefix.contains("_oplog")
                && self.drop_latest_oplog.swap(false, Ordering::SeqCst)
                && let Some(latest) = keys.iter().cloned().max()
            {
                keys.retain(|key| *key != latest);
            }
            Ok(keys)
        }

        async fn delete(&self, key: &str) -> Result<(), MemError> {
            self.inner.delete(key).await
        }
    }

    /// Regression: the clock re-seed must be a monotonic merge, never a regression.
    /// When a sync's LIST lags and omits this author's own just-appended durable op,
    /// re-seeding the head from that stale view would drop it below a durable op and
    /// the next mint would re-mint the same `(lamport, prev_op_hash)` — a self-fork.
    /// The fix advances the head only when the read CONTAINS the cached head.
    #[tokio::test]
    async fn stale_listing_does_not_regress_the_writer_clock() -> TestResult {
        let blob = Arc::new(LaggingListBlob::new());
        let store = store_over(blob.clone(), SOLO_SEED)?;

        // Two durable ops: the cached head now points at op2.
        store.remember(sample_input()).await?;
        store.remember(sample_input()).await?;
        let (head_before, tip_before) = {
            let clock = store.writer.lock().await;
            (clock.my_last_hash, clock.lamport_tip)
        };

        // Arm the lag, then sync: read_and_filter reads a view missing op2.
        blob.drop_latest_oplog.store(true, Ordering::SeqCst);
        store.read_and_filter().await?;

        let (head_after, tip_after) = {
            let clock = store.writer.lock().await;
            (clock.my_last_hash, clock.lamport_tip)
        };
        assert_eq!(
            head_after, head_before,
            "a lagging listing must not regress the cached chain head below a durable op"
        );
        assert_eq!(tip_after, tip_before, "the lamport tip must not regress");
        Ok(())
    }

    #[tokio::test]
    async fn get_unknown_id_is_not_found() -> TestResult {
        let store = test_store()?;
        let missing = NoteId::new();
        match store.get(missing).await {
            Err(MemError::NotFound { id }) => assert_eq!(id, missing.to_string()),
            Err(other) => return Err(format!("expected NotFound, got {other:?}").into()),
            Ok(_) => return Err("unknown id unexpectedly resolved".into()),
        }
        Ok(())
    }

    #[tokio::test]
    async fn recall_scope_isolation() -> TestResult {
        let store = test_store()?;
        let topic = "shared retrieval topic about scope".to_string();
        let remember_in = |repo: RepoScope, body: &str| RememberInput {
            force: true,
            note_type: NoteType::Reference,
            repo,
            tags: BTreeSet::new(),
            summary: topic.clone(),
            body: body.to_string(),
        };

        let thebrain = store
            .remember(remember_in(RepoScope::Repo("thebrain".to_string()), "b1"))
            .await?;
        let other = store
            .remember(remember_in(RepoScope::Repo("other".to_string()), "b2"))
            .await?;
        let global = store.remember(remember_in(RepoScope::Global, "b3")).await?;

        let pointers = store
            .recall(RecallInput {
                text: topic,
                repo: RepoScope::Repo("thebrain".to_string()),
                k: 10,
                token_budget: None,
            })?
            .pointers;
        let ids: BTreeSet<NoteId> = pointers.iter().map(|p| p.note_id).collect();

        // A repo:thebrain recall sees thebrain + team-global, never repo:other.
        assert!(ids.contains(&thebrain));
        assert!(ids.contains(&global));
        assert!(!ids.contains(&other));
        Ok(())
    }

    #[tokio::test]
    async fn supersede_demotes_and_tags_the_superseded_note() -> TestResult {
        // Feature 1: a note that supersedes another ranks the superseded one far
        // below its replacement in recall (still returned, tagged), so a rescinded
        // decision cannot rank above the one that replaced it. Relations flow
        // op-log -> converge -> index on `sync`, so this is a converged property,
        // not a local index tweak.
        let store = build_store()?;
        let topic = "retry backoff policy for the uploader".to_string();
        let mk = |body: &str| RememberInput {
            force: true,
            note_type: NoteType::Decision,
            repo: RepoScope::Global,
            tags: BTreeSet::new(),
            summary: topic.clone(),
            body: body.to_string(),
        };
        let old = store.remember(mk("retry three times, no jitter")).await?;
        let new = store.remember(mk("retry with exponential jitter")).await?;

        // `new` supersedes `old`; the relation is source-stamped on `new`. Sync
        // rebuilds the index records with relations from the converged state.
        store.relate(new, old, LinkRel::Supersedes).await?;
        store.sync().await?;

        let pointers = store
            .recall(RecallInput {
                text: topic,
                repo: RepoScope::Global,
                k: 10,
                token_budget: None,
            })?
            .pointers;
        let old_p = pointers
            .iter()
            .find(|p| p.note_id == old)
            .ok_or("the superseded note is still returned (not dropped)")?;
        let new_p = pointers
            .iter()
            .find(|p| p.note_id == new)
            .ok_or("the superseding note is returned")?;
        assert!(
            new_p.score > old_p.score,
            "the superseding note must rank above the superseded one ({} vs {})",
            new_p.score,
            old_p.score
        );
        assert!(
            old_p
                .relations
                .iter()
                .any(|r| r.rel == LinkRel::Supersedes && r.from == new),
            "the superseded note is tagged with its superseder"
        );
        assert!(
            new_p.relations.is_empty(),
            "the superseding note carries no incoming demotion"
        );
        Ok(())
    }

    #[tokio::test]
    async fn related_relation_emits_the_legacy_link_op() -> TestResult {
        // Backward compatibility: a plain `Related` relation still emits the
        // original `Link` op (byte-identical to pre-typed-relation writes, so old
        // signed logs keep verifying), while a typed relation emits `Relate`.
        let store = build_store()?;
        let a = store.remember(sample_input()).await?;
        let b = store.remember(sample_input()).await?;
        store.relate(a, b, LinkRel::Related).await?;
        store.relate(a, b, LinkRel::Supersedes).await?;

        let history = store.history(a).await?;
        let kinds: BTreeSet<&str> = history.entries.iter().map(|e| e.kind.as_str()).collect();
        assert!(
            kinds.contains("Link"),
            "a Related relation emits the legacy Link op"
        );
        assert!(
            kinds.contains("Relate"),
            "a typed relation emits the Relate op"
        );
        Ok(())
    }

    #[tokio::test]
    async fn contradicts_tags_both_notes_without_demoting() -> TestResult {
        // A `Contradicts` relation is mutual and non-demoting: both notes stay
        // rank-equal but are tagged so a reader sees the tension.
        let store = build_store()?;
        let topic = "whether to cache the manifest".to_string();
        let mk = |body: &str| RememberInput {
            force: true,
            note_type: NoteType::Decision,
            repo: RepoScope::Global,
            tags: BTreeSet::new(),
            summary: topic.clone(),
            body: body.to_string(),
        };
        let one = store.remember(mk("cache it")).await?;
        let two = store.remember(mk("never cache it")).await?;
        store.relate(one, two, LinkRel::Contradicts).await?;
        store.sync().await?;

        let pointers = store
            .recall(RecallInput {
                text: topic,
                repo: RepoScope::Global,
                k: 10,
                token_budget: None,
            })?
            .pointers;
        let one_p = pointers.iter().find(|p| p.note_id == one).ok_or("one")?;
        let two_p = pointers.iter().find(|p| p.note_id == two).ok_or("two")?;
        // Mutual tag, both directions present.
        assert!(
            one_p
                .relations
                .iter()
                .any(|r| r.rel == LinkRel::Contradicts && r.from == two),
            "the asserting note is tagged as contradicting its target (mutual)"
        );
        assert!(
            two_p
                .relations
                .iter()
                .any(|r| r.rel == LinkRel::Contradicts && r.from == one),
            "the target is tagged as contradicting the asserting note"
        );
        // No demotion: neither score is knocked down by the 0.2x supersede factor,
        // so the two stay comparable (their small gap is only recency, not a 5x
        // demotion). A demoted note would sit at ~0.2x its peer.
        let (lo, hi) = if one_p.score <= two_p.score {
            (one_p.score, two_p.score)
        } else {
            (two_p.score, one_p.score)
        };
        assert!(
            hi > 0.0 && lo / hi > 0.5,
            "Contradicts must not demote either note (scores stay comparable: {lo} vs {hi})"
        );
        Ok(())
    }

    #[tokio::test]
    async fn stored_blob_is_ciphertext_not_plaintext() -> TestResult {
        let store = test_store()?;
        let input = sample_input();
        // Guard the test's own premise: the marker really is in the body.
        assert!(input.body.contains(BODY_MARKER));
        let id = store.remember(input).await?;

        // Reach past the public API to the raw at-rest object via the store's
        // own index + blob seams (accessible because tests are a child module).
        let located = store
            .index
            .locate(id)?
            .ok_or("note not indexed after remember")?;
        let raw = store.blob.get(&located.object_key).await?;

        let needle = BODY_MARKER.as_bytes();
        let leaked = raw.windows(needle.len()).any(|window| window == needle);
        assert!(!leaked, "plaintext body leaked into the stored object");
        Ok(())
    }

    /// Encryption-boundary pin: `remember` must hand the blob layer sealed
    /// ciphertext only — never plaintext. Where `stored_blob_is_ciphertext_not_plaintext`
    /// inspects the single object resting at the note's key, this guards EVERY
    /// payload that crosses `BlobStore::put` (the note body AND the op-log
    /// append share the same backend), so a regression that leaked plaintext on
    /// any of those writes is caught regardless of which key it lands under.
    #[tokio::test]
    async fn remember_never_hands_plaintext_to_blob_put() -> TestResult {
        const SUMMARY_SENTINEL: &str = "PLAINTEXT-SUMMARY-SENTINEL";
        const BODY_SENTINEL: &str = "PLAINTEXT-BODY-SENTINEL";

        let recorder = Arc::new(RecordingBlobStore::new());
        // The store borrows the recorder as `Arc<dyn BlobStore>`; we retain a
        // typed clone to read back what crossed the boundary after the write.
        let store = store_over(recorder.clone(), SOLO_SEED)?;

        let input = RememberInput {
            force: true,
            note_type: NoteType::Gotcha,
            repo: RepoScope::Repo("thebrain".to_string()),
            tags: BTreeSet::from(["sentinel".to_string()]),
            summary: SUMMARY_SENTINEL.to_string(),
            body: BODY_SENTINEL.to_string(),
        };
        store.remember(input).await?;

        let payloads = recorder.recorded_puts()?;
        // At least two writes must cross the boundary — the sealed note body and
        // the op-log append — so a regression that stopped persisting the op-log
        // cannot satisfy this guard vacuously.
        assert!(
            payloads.len() >= 2,
            "remember must persist both the note body and the op-log append"
        );
        // Allocation-free byte search, matching the sibling
        // `stored_blob_is_ciphertext_not_plaintext`: scan the raw payload for the
        // sentinel bytes directly, so the two cross-referencing tests stay
        // consistent and neither leans on the payload being valid UTF-8.
        for payload in &payloads {
            for sentinel in [SUMMARY_SENTINEL, BODY_SENTINEL] {
                let needle = sentinel.as_bytes();
                let leaked = payload.windows(needle.len()).any(|window| window == needle);
                assert!(
                    !leaked,
                    "plaintext sentinel {sentinel} leaked into a blob payload"
                );
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn get_detects_tampered_blob() -> TestResult {
        let store = test_store()?;
        let id = store.remember(sample_input()).await?;
        let located = store
            .index
            .locate(id)?
            .ok_or("note not indexed after remember")?;

        // Swap the stored object for unrelated bytes whose hash cannot match the
        // cid the index recorded. `get` must reject this at the integrity gate
        // before ever attempting to decrypt under the shared team key.
        store.blob.put(&located.object_key, vec![0_u8; 64]).await?;

        match store.get(id).await {
            Err(MemError::Storage(message)) => assert!(message.contains("content hash")),
            Err(other) => return Err(format!("expected Storage, got {other:?}").into()),
            Ok(_) => return Err("tampered blob unexpectedly resolved".into()),
        }
        Ok(())
    }

    #[tokio::test]
    async fn sync_skips_notes_with_unreadable_blobs_and_counts_the_rest() -> TestResult {
        let store = test_store()?;
        let keep = store.remember(sample_input()).await?;
        let broken = store
            .remember(RememberInput {
                force: true,
                repo: RepoScope::Global,
                ..sample_input()
            })
            .await?;

        // Corrupt one note's blob in place: overwrite it with bytes that cannot be
        // authenticated under the team key. The op naming it is still in the log, so
        // sync will try to hydrate it — and must skip it (warn), not abort, and not
        // count it among the live notes indexed.
        let located = store
            .index
            .locate(broken)?
            .ok_or("broken note not indexed after remember")?;
        store.blob.put(&located.object_key, vec![0_u8; 8]).await?;

        let indexed = store.sync().await?;
        assert_eq!(
            indexed, 1,
            "the readable note re-indexes; the corrupt one is skipped"
        );
        // The surviving note is the one whose blob was left intact.
        let pointers = store
            .recall(RecallInput {
                text: "select losing branch".to_string(),
                repo: RepoScope::Repo("thebrain".to_string()),
                k: 5,
                token_budget: None,
            })?
            .pointers;
        assert!(pointers.iter().any(|p| p.note_id == keep));
        Ok(())
    }

    #[tokio::test]
    async fn relocated_object_fails_to_open() -> TestResult {
        let store = test_store()?;
        let id = store.remember(sample_input()).await?;
        let located = store
            .index
            .locate(id)?
            .ok_or("note not indexed after remember")?;
        let bytes = store.blob.get(&located.object_key).await?;

        // Sanity: the bytes open under the key they were sealed at (epoch 0).
        let key = SecretKey::from_bytes(TEST_KEY);
        open(&key, &bytes, located.object_key.as_bytes())?;

        // Relocation/replay: the SAME ciphertext fetched from a DIFFERENT object
        // key fails authentication, because the object key is the AEAD associated
        // data. `get` and `sync` both pass the key the bytes were fetched from as
        // AAD, so a gateway serving note A's bytes at note B's key is rejected here
        // rather than silently decrypted under the shared team key.
        let foreign_key = format!("{TEAM}/global/{}/ver_1", NoteId::new());
        assert!(matches!(
            open(&key, &bytes, foreign_key.as_bytes()),
            Err(MemError::Crypto)
        ));
        Ok(())
    }

    /// A [`MemoryIndex`] whose `upsert` always fails — stands in for a fallible
    /// persistent backend so sync's systemic-fault path is testable.
    struct FailingUpsertIndex;

    impl MemoryIndex for FailingUpsertIndex {
        fn upsert(&self, _record: IndexRecord) -> Result<(), MemError> {
            Err(MemError::Storage("index upsert failed".to_owned()))
        }
        fn search(&self, _query: &Query) -> Result<SearchResult, MemError> {
            Ok(SearchResult {
                pointers: Vec::new(),
                total_matched: 0,
            })
        }
        fn remove(&self, _id: NoteId) -> Result<(), MemError> {
            Ok(())
        }
        fn locate(&self, _id: NoteId) -> Result<Option<Located>, MemError> {
            Ok(None)
        }
        fn retain(&self, _keep: &BTreeSet<NoteId>) -> Result<(), MemError> {
            Ok(())
        }
        fn all_records(&self) -> Result<Vec<IndexRecord>, MemError> {
            Ok(Vec::new())
        }
    }

    #[tokio::test]
    async fn sync_propagates_index_upsert_failure() -> TestResult {
        // A real note + its signed op sit in the shared bucket (written by a
        // healthy store).
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let healthy = store_over(bucket.clone(), SOLO_SEED)?;
        healthy.remember(sample_input()).await?;

        // A second machine shares the bucket + op-log but its index rejects every
        // record. The blob decodes fine, so this is a systemic index fault, not a
        // bad blob: sync must propagate it rather than skip + undercount.
        let signer: Arc<dyn Signer> = Arc::new(Sr25519Signer::from_seed_with_prefix(
            &SOLO_SEED,
            NetworkPrefix::HIPPIUS,
        )?);
        let broken = MemoryStore::new(
            bucket.clone(),
            Arc::new(FailingUpsertIndex),
            OpLogStore::new(bucket),
            Arc::new(NoopAnchor),
            signer,
            BTreeMap::from([(0, SecretKey::from_bytes(TEST_KEY))]),
            0,
            TEAM.to_string(),
            NO_ANCHOR_THRESHOLD,
        );
        assert!(matches!(broken.sync().await, Err(MemError::Storage(_))));
        Ok(())
    }

    /// An [`Embedder`](crate::index::Embedder) that fails on any text containing a
    /// sentinel token, so the edit path's POST-append index upsert can be forced to
    /// fail (its embed is the fallible step).
    struct EmbedFailsOnSentinel;

    impl crate::index::Embedder for EmbedFailsOnSentinel {
        fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, MemError> {
            if texts.iter().any(|t| t.contains("FAIL_EMBED")) {
                return Err(MemError::Embedding("simulated embed failure".to_owned()));
            }
            Ok(texts.iter().map(|_| vec![0.0_f32; 8]).collect())
        }
        fn dim(&self) -> usize {
            8
        }
    }

    #[tokio::test]
    async fn edit_keeps_the_blob_when_index_upsert_fails_after_a_durable_append() -> TestResult {
        // Regression (found in PR review): once the Edit op is DURABLY appended, a
        // failing index.upsert (an embed error) must NOT reclaim the just-written blob
        // — the op names it and a later sync re-reads both. The old code deleted the
        // blob on ANY error, silently vanishing the note on the next converge.
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let index = Arc::new(InMemoryIndex::new(Arc::new(EmbedFailsOnSentinel)));
        let signer: Arc<dyn Signer> = Arc::new(Sr25519Signer::from_seed_with_prefix(
            &SOLO_SEED,
            NetworkPrefix::HIPPIUS,
        )?);
        let store = MemoryStore::new(
            blob.clone(),
            index,
            OpLogStore::new(blob.clone()),
            Arc::new(NoopAnchor),
            signer,
            BTreeMap::from([(0, SecretKey::from_bytes(TEST_KEY))]),
            0,
            TEAM.to_string(),
            NO_ANCHOR_THRESHOLD,
        );
        // The remember summary embeds fine; the edit summary trips the sentinel.
        let id = store.remember(sample_input()).await?;
        let mut input = sample_input();
        input.summary = "FAIL_EMBED sentinel".to_string();
        let result = store.edit(id, input).await;
        assert!(
            matches!(result, Err(MemError::Embedding(_))),
            "the post-append embed failure surfaces, got {result:?}"
        );

        // The durably-appended edit's blob is NOT reclaimed: both versions remain.
        let id_seg = format!("/{id}/");
        let versions = blob
            .list("")
            .await?
            .into_iter()
            .filter(|k| k.contains(&id_seg))
            .count();
        assert_eq!(
            versions, 2,
            "the durably-appended edit's blob must survive the index failure"
        );
        // And the Edit op is durable — history keeps the Remember and the Edit.
        assert_eq!(
            store.history(id).await?.entries.len(),
            2,
            "the Edit op is durable after the index failure"
        );
        Ok(())
    }

    /// A [`BlobStore`] that makes concurrent writers to the same note rendezvous:
    /// once armed with a key substring, every matching `put` blocks on a shared
    /// [`tokio::sync::Barrier`] until `parties` writers have arrived. That pins two
    /// edits at the exact point PAST their advisory precondition check but BEFORE
    /// the writer-locked commit, forcing them to race the authoritative CAS — the
    /// interleaving the TOCTOU fix must survive. Only content-blob puts match the
    /// substring; op-log puts land under `{team}/_oplog/...` and stay ungated, so
    /// the barrier is never starved by an unrelated write.
    struct RendezvousBlobStore {
        inner: MemoryBlobStore,
        gate: tokio::sync::Barrier,
        gated_on: Mutex<Option<String>>,
    }

    impl RendezvousBlobStore {
        fn new(parties: usize) -> Self {
            Self {
                inner: MemoryBlobStore::default(),
                gate: tokio::sync::Barrier::new(parties),
                gated_on: Mutex::new(None),
            }
        }

        fn arm(&self, substring: String) {
            *self
                .gated_on
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(substring);
        }
    }

    #[async_trait::async_trait]
    impl BlobStore for RendezvousBlobStore {
        async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
            // Clone the guard's contents out and drop it BEFORE awaiting: a std Mutex
            // must never be held across an await point (await_holding_lock).
            let gated_on = self
                .gated_on
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            if let Some(sub) = gated_on
                && key.contains(&sub)
            {
                self.gate.wait().await;
            }
            self.inner.put(key, bytes).await
        }
        async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
            self.inner.get(key).await
        }
        async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError> {
            self.inner.list(prefix).await
        }
        async fn delete(&self, key: &str) -> Result<(), MemError> {
            self.inner.delete(key).await
        }
    }

    #[tokio::test]
    async fn concurrent_precondition_edits_cannot_both_win() -> TestResult {
        // Two agents read the SAME base version and each submit a precondition edit
        // from it. The rendezvous store holds both past their advisory check, so they
        // contend in `commit_edit` under the writer lock. Exactly one must win; the
        // other must see `Conflict` and append NOTHING — this is the silent lost
        // update the old check-then-write path allowed (both would have returned Ok).
        let gate = Arc::new(RendezvousBlobStore::new(2));
        let store = Arc::new(store_over(gate.clone(), SOLO_SEED)?);
        let id = store.remember(sample_input()).await?;
        let base = store.current_version(id)?;

        // Arm only after the remember, and only for THIS note's content key so the
        // two edits' content puts are the exact pair that rendezvous.
        gate.arm(format!("/{id}/"));

        let mut ia = sample_input();
        ia.summary = "edit-A".to_owned();
        ia.body = "edit-A".to_owned();
        let mut ib = sample_input();
        ib.summary = "edit-B".to_owned();
        ib.body = "edit-B".to_owned();
        let (sa, sb) = (store.clone(), store.clone());
        let ta = tokio::spawn(async move {
            (
                "edit-A",
                sa.edit_with_precondition(id, ia, Some(base)).await,
            )
        });
        let tb = tokio::spawn(async move {
            (
                "edit-B",
                sb.edit_with_precondition(id, ib, Some(base)).await,
            )
        });
        let ((body_a, res_a), (body_b, res_b)) = (ta.await?, tb.await?);

        let wins = usize::from(res_a.is_ok()) + usize::from(res_b.is_ok());
        assert_eq!(
            wins, 1,
            "exactly one concurrent same-base edit may win (a={res_a:?}, b={res_b:?})"
        );
        for res in [&res_a, &res_b] {
            if let Err(err) = res {
                assert!(
                    matches!(err, MemError::Conflict { .. }),
                    "the losing edit must be a Conflict, got {err:?}"
                );
            }
        }
        // The surviving body is the winner's, and only its Edit op was appended.
        let winner_body = if res_a.is_ok() { body_a } else { body_b };
        assert_eq!(store.get(id).await?.body.as_str(), winner_body);
        let history = store.history(id).await?;
        assert_eq!(
            history.entries.len(),
            2,
            "Remember + exactly one Edit; the rejected edit appended no op"
        );
        Ok(())
    }

    /// A [`BlobStore`] whose `delete` always fails, standing in for a transient S3
    /// fault so the redact scrub-failure path is testable. Other ops delegate to an
    /// in-memory store.
    struct FaultyDeleteBlobStore {
        inner: MemoryBlobStore,
    }

    #[async_trait::async_trait]
    impl BlobStore for FaultyDeleteBlobStore {
        async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
            self.inner.put(key, bytes).await
        }
        async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
            self.inner.get(key).await
        }
        async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError> {
            self.inner.list(prefix).await
        }
        async fn delete(&self, _key: &str) -> Result<(), MemError> {
            Err(MemError::Storage("simulated delete failure".to_owned()))
        }
    }

    #[tokio::test]
    async fn redact_reports_failure_when_scrub_cannot_delete() -> TestResult {
        // The blob backend rejects every delete (a transient S3 fault). `redact` must
        // NOT report success while ciphertext survives: it returns the storage error,
        // leaves the note indexed so a re-run can retry, and the sealed bytes remain
        // in the bucket. The old fire-and-forget scrub returned Ok here and dropped
        // the note, asserting a deletion that never happened.
        let blob: Arc<dyn BlobStore> = Arc::new(FaultyDeleteBlobStore {
            inner: MemoryBlobStore::default(),
        });
        let store = store_over(blob.clone(), SOLO_SEED)?;
        let id = store.remember(sample_input()).await?;

        let result = store.redact(id).await;
        assert!(
            matches!(result, Err(MemError::Storage(_))),
            "a scrub that cannot delete must surface as an error, got {result:?}"
        );
        assert!(
            store.index.locate(id)?.is_some(),
            "a failed scrub must leave the note indexed for a re-run"
        );
        let id_seg = format!("/{id}/");
        let remaining = blob
            .list("")
            .await?
            .into_iter()
            .filter(|k| k.contains(&id_seg))
            .count();
        assert_eq!(
            remaining, 1,
            "the un-scrubbed ciphertext is still in the bucket, not falsely reported gone"
        );
        Ok(())
    }

    #[test]
    fn anchor_proof_for_skips_a_forged_record() -> TestResult {
        // M3: a record that COVERS the op but whose stored `root` does not commit its
        // leaves must not yield a proof — `history` would otherwise return an
        // `AnchorProof` that only looks authoritative. A well-formed record does.
        let op_hash = content_hash(b"the-op");
        let leaves = vec![op_hash, content_hash(b"sibling")];
        let honest_root = merkle_root(&leaves);
        let forged_root = content_hash(b"not-the-merkle-root");

        let forged = AnchorRecord {
            seq: 0,
            author_key: VerifyingKey::new([0xAA; 32]),
            root: forged_root,
            meta: BatchMeta {
                team: TEAM.to_string(),
                first_lamport: 0,
                last_lamport: 0,
                op_count: leaves.len(),
            },
            leaves: leaves.clone(),
            receipt: AnchorReceipt {
                root: forged_root,
                reference: AnchorRef::Local { seq: 0 },
            },
        };
        let forged_records = [forged];
        let forged_roots: Vec<Blake3Hash> = forged_records
            .iter()
            .map(|r| merkle_root(&r.leaves))
            .collect();
        assert!(
            anchor_proof_for(&forged_records, &forged_roots, op_hash)?.is_none(),
            "a forged record (root != merkle_root(leaves)) must not yield a proof"
        );

        let honest = AnchorRecord {
            seq: 1,
            author_key: VerifyingKey::new([0xBB; 32]),
            root: honest_root,
            meta: BatchMeta {
                team: TEAM.to_string(),
                first_lamport: 0,
                last_lamport: 0,
                op_count: leaves.len(),
            },
            leaves,
            receipt: AnchorReceipt {
                root: honest_root,
                reference: AnchorRef::Local { seq: 1 },
            },
        };
        let honest_records = [honest];
        let honest_roots: Vec<Blake3Hash> = honest_records
            .iter()
            .map(|r| merkle_root(&r.leaves))
            .collect();
        assert!(
            anchor_proof_for(&honest_records, &honest_roots, op_hash)?.is_some(),
            "a well-formed record must yield a proof"
        );
        Ok(())
    }

    #[test]
    fn monotonic_manifest_refuses_a_lower_version_rollback() -> TestResult {
        // M5: once a store has APPLIED a manifest version, a later reload of a LOWER
        // version (the newest object deleted from the untrusted bucket) or of NONE
        // (all deleted) must not downgrade membership — the higher version is kept.
        let store = build_store()?;
        let founder = Sr25519Signer::from_seed_with_prefix(&SOLO_SEED, NetworkPrefix::HIPPIUS)?;
        let manifest = |version: u64| {
            TeamManifest::create_signed(&founder, TEAM.to_string(), BTreeSet::new(), version)
        };

        assert_eq!(
            store
                .monotonic_manifest(Some(manifest(1)))
                .map(|m| m.version),
            Some(1),
            "the first manifest is applied and sets the watermark"
        );
        assert_eq!(
            store
                .monotonic_manifest(Some(manifest(0)))
                .map(|m| m.version),
            Some(1),
            "a lower-version reload (rollback via deletion) is refused"
        );
        assert_eq!(
            store.monotonic_manifest(None).map(|m| m.version),
            Some(1),
            "a vanished manifest (all objects deleted) is refused"
        );
        assert_eq!(
            store
                .monotonic_manifest(Some(manifest(2)))
                .map(|m| m.version),
            Some(2),
            "a legitimate higher version is applied and advances the watermark"
        );
        Ok(())
    }

    #[tokio::test]
    async fn memorystore_derives_author_from_signer() -> TestResult {
        // The store no longer takes a separate (mismatchable) author: it derives one
        // from its signer, so a remembered op's `author` is exactly the signer's
        // SS58 — structurally bound to the signing key, not self-asserted.
        let store = build_store()?;
        store.remember(sample_input()).await?;

        let ops = store.oplog.read_all(TEAM).await?;
        let op = ops.first().ok_or("expected one op")?;
        let expected =
            Sr25519Signer::from_seed_with_prefix(&SOLO_SEED, NetworkPrefix::HIPPIUS)?.author_ss58();
        assert_eq!(
            op.author, expected,
            "the op's author is derived from the store's signer"
        );
        Ok(())
    }

    #[tokio::test]
    async fn remember_appends_signed_op() -> TestResult {
        let store = test_store()?;
        let id = store.remember(sample_input()).await?;

        // read_all verifies every signature + the per-author hash chain, so a
        // successful read is itself proof the op is well-formed and signed.
        let ops = store.oplog.read_all(TEAM).await?;
        assert_eq!(ops.len(), 1, "one remember -> exactly one op");
        let op = &ops[0];
        assert_eq!(op.kind, OpKind::Remember);
        assert_eq!(op.note_id, id);
        assert_eq!(op.lamport, 1, "first op on a fresh chain has lamport 1");
        Ok(())
    }

    #[tokio::test]
    async fn remember_tags_current_epoch() -> TestResult {
        // Each write stamps the op (and index record) with the epoch active at
        // write time, so a later rotation does not retroactively relabel old notes.
        let store = test_store()?;
        let id0 = store.remember(sample_input()).await?;
        assert_eq!(store.current_epoch(), 0, "the store starts at epoch 0");

        // Provision and activate epoch 1, then write again.
        store.add_epoch_key(1, SecretKey::from_bytes(EPOCH1_KEY));
        store.set_current_epoch(1);
        let id1 = store
            .remember(RememberInput {
                force: true,
                repo: RepoScope::Global,
                ..sample_input()
            })
            .await?;

        let by_note: std::collections::BTreeMap<NoteId, u64> = store
            .oplog
            .read_all(TEAM)
            .await?
            .iter()
            .map(|op| (op.note_id, op.key_epoch))
            .collect();
        assert_eq!(by_note.get(&id0), Some(&0), "first note tagged epoch 0");
        assert_eq!(by_note.get(&id1), Some(&1), "second note tagged epoch 1");

        // The epoch also rides into the index record (via `Located`), so `get`
        // need not re-read the op to learn it.
        let located1 = store.index.locate(id1)?.ok_or("note 1 not indexed")?;
        assert_eq!(located1.key_epoch, 1, "index record carries the seal epoch");
        Ok(())
    }

    #[tokio::test]
    async fn get_uses_note_epoch_key() -> TestResult {
        // A note sealed at epoch 0 and one sealed at epoch 1 (different keys) both
        // decrypt: `get` selects each note's own epoch key from the ring.
        let store = test_store()?;
        let input0 = sample_input();
        let body0 = input0.body.clone();
        let id0 = store.remember(input0).await?;

        store.add_epoch_key(1, SecretKey::from_bytes(EPOCH1_KEY));
        store.set_current_epoch(1);
        let input1 = RememberInput {
            force: true,
            repo: RepoScope::Global,
            body: "sealed under the rotated epoch-1 key".to_string(),
            ..sample_input()
        };
        let body1 = input1.body.clone();
        let id1 = store.remember(input1).await?;

        assert_eq!(store.get(id0).await?.body, body0, "epoch-0 note decrypts");
        assert_eq!(store.get(id1).await?.body, body1, "epoch-1 note decrypts");
        Ok(())
    }

    #[tokio::test]
    async fn get_missing_epoch_key_is_clear_error() -> TestResult {
        // A note indexed at an epoch the ring lacks: `get` must surface the typed
        // KeyUnavailable error naming the epoch, not a panic or an opaque crypto error.
        let store = test_store()?;
        let id = store.remember(sample_input()).await?;
        let located = store.index.locate(id)?.ok_or("note not indexed")?;

        // Re-point the index entry at an epoch absent from the ring (only epoch 0
        // exists). The note blob is irrelevant: `get` selects the key before
        // fetching, so the missing epoch is caught first.
        store.index.upsert(IndexRecord {
            note_id: id,
            object_key: located.object_key,
            cid: located.cid,
            scope: Scope {
                team: TEAM.to_string(),
                repo: RepoScope::Global,
            },
            note_type: NoteType::Gotcha,
            author: store.author.clone(),
            updated: Timestamp::new(0),
            lamport: 1,
            key_epoch: 99,
            tags: BTreeSet::new(),
            summary: "x".to_string(),
            relations: Vec::new(),
            reinforcers: BTreeSet::new(),
            last_reinforced: None,
            embedding: None,
        })?;

        match store.get(id).await {
            Err(MemError::KeyUnavailable { epoch }) => {
                assert_eq!(epoch, 99, "the error names the missing epoch");
            }
            Err(other) => return Err(format!("expected KeyUnavailable, got {other:?}").into()),
            Ok(_) => return Err("a note with no epoch key unexpectedly resolved".into()),
        }
        Ok(())
    }

    #[tokio::test]
    async fn sync_skips_notes_with_unavailable_epoch() -> TestResult {
        // Writer A holds both epochs and writes one note under each. Reader B holds
        // only epoch 0: its sync must index the epoch-0 note, skip-with-warn the
        // epoch-1 note (no key), and still return Ok — a member missing one old
        // epoch is not blinded to the rest of the team's memory.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let writer = store_over(bucket.clone(), SOLO_SEED)?;
        writer.add_epoch_key(1, SecretKey::from_bytes(EPOCH1_KEY));

        let epoch0_note = writer.remember(sample_input()).await?;
        writer.set_current_epoch(1);
        let epoch1_note = writer
            .remember(RememberInput {
                force: true,
                repo: RepoScope::Global,
                ..sample_input()
            })
            .await?;

        // Reader shares the bucket/op-log but only ever knew epoch 0.
        let reader = store_over(bucket, [50_u8; 32])?;
        let indexed = reader.sync().await?;
        assert_eq!(
            indexed, 1,
            "only the epoch-0 note is indexed; epoch-1 skipped"
        );
        assert!(
            reader.index.locate(epoch0_note)?.is_some(),
            "the epoch-0 note this reader can decrypt is indexed"
        );
        assert!(
            reader.index.locate(epoch1_note)?.is_none(),
            "the epoch-1 note this reader cannot decrypt is skipped, not indexed"
        );
        Ok(())
    }

    #[tokio::test]
    async fn failed_append_does_not_corrupt_chain() -> TestResult {
        // The C1a regression: before advancing the clock only after a durable
        // append, a failed `oplog.append` left the cached `prev`/`lamport` ahead of
        // the log, so the NEXT op chained to a phantom predecessor and `read_all`
        // (hence `sync`) broke for the whole team.
        let blob = Arc::new(OplogPutFailingBlob::new());
        let store = store_over(blob.clone() as Arc<dyn BlobStore>, SOLO_SEED)?;

        // Arm the op-log put: the first remember's append fails. The clock must NOT
        // advance — its head stays at genesis/lamport 0.
        blob.arm();
        assert!(
            store.remember(sample_input()).await.is_err(),
            "the injected op-log put failure must surface as an error"
        );

        // Heal the fault and retry: the op re-mints against the SAME genesis prev,
        // so the durable log is a clean single-op chain, not one chained to a
        // phantom op the aborted append never persisted.
        blob.disarm();
        let id = store.remember(sample_input()).await?;

        // A clean `read_all` (it verifies signatures + per-author chain) proves no
        // corruption; lamport 1 (not 2) proves the failed append did not advance.
        let ops = store.oplog.read_all(TEAM).await?;
        assert_eq!(ops.len(), 1, "only the retried op is durable");
        assert_eq!(ops[0].note_id, id);
        assert_eq!(
            ops[0].lamport, 1,
            "the retry re-mints at lamport 1, so the failed append did not advance the clock"
        );

        // And `sync` (which calls `read_all` first) heals and indexes the note.
        assert_eq!(store.sync().await?, 1, "sync indexes the one live note");
        Ok(())
    }

    #[tokio::test]
    async fn redact_scrubs_all_versions_but_keeps_provable_op() -> TestResult {
        // redact's contract is the inverse of forget: forget hides the note but
        // keeps the blob for the audit trail; redact PERMANENTLY scrubs every
        // ciphertext version so the body can never be recovered, yet leaves the
        // signed Redact op (and its anchored leaf) so the deletion stays provable
        // in history. The leaked-secret case is precisely a *superseded* body, so
        // the scrub must reclaim EVERY version, not only the latest — hence the
        // remember + edit that leaves two version blobs before the redact.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let store = store_over(bucket.clone(), SOLO_SEED)?;
        let id = store.remember(sample_input()).await?;
        store
            .edit(
                id,
                RememberInput {
                    force: true,
                    note_type: NoteType::Decision,
                    repo: RepoScope::Repo("thebrain".to_string()),
                    tags: BTreeSet::new(),
                    summary: "second summary".to_string(),
                    body: "second body".to_string(),
                },
            )
            .await?;

        // Version blobs live under the note prefix; op-log and anchor records sit
        // under sibling prefixes, so this lists exactly the ciphertext versions.
        let prefix = format!("{TEAM}/thebrain/{id}/");
        assert_eq!(
            bucket.list(&prefix).await?.len(),
            2,
            "precondition: remember + edit must leave two version blobs to scrub",
        );

        // Prove the note IS recallable first, so the post-redact "absent"
        // assertion below cannot pass vacuously (i.e. because the query never
        // matched), mirroring forget_hides_note_and_logs_op. The query shares a
        // real token with the EDITED summary ("second summary"); the prior
        // "select losing branch" only matched via HashEmbedder collision noise,
        // which the lexical build no longer ranks on (M4).
        let query = RecallInput {
            text: "second summary".to_string(),
            repo: RepoScope::Repo("thebrain".to_string()),
            k: 5,
            token_budget: None,
        };
        assert!(
            store
                .recall(query.clone())?
                .pointers
                .iter()
                .any(|p| p.note_id == id),
            "precondition: the note is recallable before it is redacted",
        );

        store.redact(id).await?;

        // 1. Every ciphertext version is gone — the content is unrecoverable.
        assert!(
            bucket.list(&prefix).await?.is_empty(),
            "redact must delete every version blob under the note's prefix",
        );
        // 2. The note no longer surfaces and its body is unreadable.
        assert!(
            store
                .recall(query)?
                .pointers
                .iter()
                .all(|p| p.note_id != id),
            "a redacted note must not surface in recall after redaction",
        );
        assert!(
            matches!(store.get(id).await, Err(MemError::NotFound { .. })),
            "a redacted note's body must be unreadable",
        );
        // 3. The redaction stays PROVABLE: the signed Redact op survives in the
        //    log and history reports it, even though the body is gone.
        let ops = store.oplog.read_all(TEAM).await?;
        assert!(
            ops.iter()
                .any(|op| op.note_id == id && op.kind == OpKind::Redact),
            "the op-log must retain the signed Redact op after scrubbing",
        );
        let history = store.history(id).await?;
        assert!(history.redacted, "history must report the note redacted");
        assert!(history.tombstoned, "redaction always implies tombstoned");
        assert!(
            !history.entries.is_empty(),
            "the op trail must survive redaction so it stays provable",
        );
        Ok(())
    }

    #[tokio::test]
    async fn redact_scrubs_an_orphan_blob_the_op_log_never_named() -> TestResult {
        // The completeness gain of prefix-listing over the old op-log scan: a blob
        // under the note's prefix whose op never reached this machine's log — a
        // straggler edit from an unsynced peer, or an orphan whose op failed to
        // verify — is invisible to an op-log-derived key set, yet a redaction must
        // leave NO ciphertext. Listing the note prefix finds and scrubs it; the old
        // read_all-then-filter would have left it decryptable.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let store = store_over(bucket.clone(), SOLO_SEED)?;
        let id = store.remember(sample_input()).await?;

        // Plant an orphan ciphertext version under the note's prefix with NO
        // matching op in the log.
        let prefix = format!("{TEAM}/thebrain/{id}/");
        let orphan_key = format!("{prefix}ver_{}", ulid::Ulid::new());
        bucket
            .put(&orphan_key, b"leaked ciphertext".to_vec())
            .await?;
        assert_eq!(
            bucket.list(&prefix).await?.len(),
            2,
            "precondition: the remembered version plus the planted orphan",
        );

        store.redact(id).await?;

        assert!(
            bucket.list(&prefix).await?.is_empty(),
            "redact must scrub the orphan blob too, not only op-named versions",
        );
        Ok(())
    }

    #[tokio::test]
    async fn forget_hides_note_and_logs_op() -> TestResult {
        let store = test_store()?;
        let id = store.remember(sample_input()).await?;

        let query = RecallInput {
            text: "select losing branch".to_string(),
            repo: RepoScope::Repo("thebrain".to_string()),
            k: 5,
            token_budget: None,
        };
        assert!(
            store
                .recall(query.clone())?
                .pointers
                .iter()
                .any(|p| p.note_id == id),
            "the note is recallable before it is forgotten"
        );

        store.forget(id).await?;

        assert!(
            store.recall(query)?.pointers.is_empty(),
            "recall must not surface a forgotten note"
        );
        // The forget is durable in the log alongside the remember.
        let ops = store.oplog.read_all(TEAM).await?;
        assert!(
            ops.iter()
                .any(|op| op.note_id == id && op.kind == OpKind::Forget),
            "the op-log must carry a Forget op for the note"
        );
        Ok(())
    }

    #[tokio::test]
    async fn link_appends_op() -> TestResult {
        let store = test_store()?;
        let from = store.remember(sample_input()).await?;
        let to = store
            .remember(RememberInput {
                force: true,
                repo: RepoScope::Global,
                ..sample_input()
            })
            .await?;

        store.link(from, to).await?;

        let ops = store.oplog.read_all(TEAM).await?;
        assert!(
            ops.iter()
                .any(|op| op.note_id == from && op.kind == OpKind::Link { to }),
            "the op-log must carry a Link op from `from` to `to`"
        );
        Ok(())
    }

    #[tokio::test]
    async fn anchors_when_threshold_reached() -> TestResult {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let anchor = Arc::new(RecordingAnchor::new());
        let store = store_with(blob.clone(), SOLO_SEED, anchor.clone(), 2)?;

        store.remember(sample_input()).await?;
        assert!(
            anchor.anchored().is_empty(),
            "one write is below the threshold of 2"
        );

        store
            .remember(RememberInput {
                force: true,
                repo: RepoScope::Global,
                ..sample_input()
            })
            .await?;

        let anchored = anchor.anchored();
        assert_eq!(
            anchored.len(),
            1,
            "the second write seals one batch of two ops"
        );
        assert_eq!(anchored[0].1.op_count, 2, "the batch covers both ops");

        // The sealed batch is persisted as an AnchorRecord under `{team}/_anchors/`.
        let records = read_anchor_records(&blob, TEAM).await?;
        assert_eq!(records.len(), 1, "exactly one batch record is persisted");
        assert_eq!(records[0].leaves.len(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn flush_anchors_anchors_remainder() -> TestResult {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let anchor = Arc::new(RecordingAnchor::new());
        // Threshold 16 the single write never reaches, so only `flush` can seal it.
        let store = store_with(blob.clone(), SOLO_SEED, anchor.clone(), 16)?;

        store.remember(sample_input()).await?;
        assert!(
            anchor.anchored().is_empty(),
            "below threshold: nothing anchored until flush"
        );

        let receipt = store.flush_anchors().await?;
        assert!(receipt.is_some(), "flush seals the pending remainder");
        assert_eq!(anchor.anchored().len(), 1);

        let records = read_anchor_records(&blob, TEAM).await?;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].leaves.len(), 1, "the single below-threshold op");

        // A second flush with nothing pending anchors nothing.
        assert!(store.flush_anchors().await?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn anchor_record_leaves_match_op_hashes() -> TestResult {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let anchor = Arc::new(RecordingAnchor::new());
        let store = store_with(blob.clone(), SOLO_SEED, anchor, 16)?;

        store.remember(sample_input()).await?;
        store
            .remember(RememberInput {
                force: true,
                repo: RepoScope::Global,
                ..sample_input()
            })
            .await?;
        store.flush_anchors().await?;

        let records = read_anchor_records(&blob, TEAM).await?;
        assert_eq!(records.len(), 1);
        // The persisted leaves are exactly the op hashes, in op-log order — what
        // Task 19 (history) needs to rebuild an inclusion proof for a single op.
        let ops = store.oplog.read_all(TEAM).await?;
        let expected: Vec<Blake3Hash> = ops.iter().map(Op::hash).collect();
        assert_eq!(records[0].leaves, expected);
        Ok(())
    }

    #[tokio::test]
    async fn failed_anchor_keeps_pending() -> TestResult {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        // Threshold 1: the write triggers an anchor immediately, and it fails.
        let store = store_with(blob.clone(), SOLO_SEED, Arc::new(FailingAnchor), 1)?;

        // The op-log keeps the op; the failed anchor must persist no record and
        // must not fail the write (anchoring is a separate, best-effort layer).
        store.remember(sample_input()).await?;

        assert!(
            read_anchor_records(&blob, TEAM).await?.is_empty(),
            "a failed anchor persists no record"
        );
        assert_eq!(
            store.oplog.read_all(TEAM).await?.len(),
            1,
            "the op-log (source of truth) is intact"
        );

        // The leaf was RETAINED: a later flush still finds it to anchor (so it
        // hits the failing anchor again and propagates) — proving it was not lost.
        assert!(
            matches!(store.flush_anchors().await, Err(MemError::Storage(_))),
            "the retained leaf is re-offered to the (still failing) anchor on flush"
        );
        Ok(())
    }

    #[tokio::test]
    async fn two_machines_both_anchor_no_collision() -> TestResult {
        // The C1b regression: two machines (distinct authors) sharing one bucket
        // both started anchor seq at 0, so the second overwrote the first's record.
        // Per-author key namespacing keeps both.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let anchor: Arc<dyn AuditAnchor> = Arc::new(RecordingAnchor::new());
        // Threshold 1: each write anchors immediately.
        let machine_a = store_with(bucket.clone(), SOLO_SEED, anchor.clone(), 1)?;
        let machine_b = store_with(bucket.clone(), [6_u8; 32], anchor.clone(), 1)?;

        let id_a = machine_a.remember(sample_input()).await?;
        let id_b = machine_b
            .remember(RememberInput {
                force: true,
                repo: RepoScope::Global,
                ..sample_input()
            })
            .await?;

        // Both records persist under distinct `{author_key}/` namespaces.
        let records = read_anchor_records(&bucket, TEAM).await?;
        assert_eq!(records.len(), 2, "both authors' anchor records persist");

        // Both ops' history proofs verify — `history` aggregates records across
        // every author, so either machine can prove either op.
        for id in [id_a, id_b] {
            let history = machine_a.history(id).await?;
            let entry = history.entries.first().ok_or("missing history entry")?;
            let proof = entry
                .anchor
                .as_ref()
                .ok_or("an op anchored at threshold 1 must carry a proof")?;
            assert!(
                verify_proof(proof.root, entry.op_hash, &proof.proof),
                "the inclusion proof must verify against the anchored root"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn restart_seeds_next_seq() -> TestResult {
        // The C1b restart case: a fresh process over the same bucket+author must
        // seed `next_seq` from existing records, not restart at 0 and overwrite.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let anchor: Arc<dyn AuditAnchor> = Arc::new(RecordingAnchor::new());

        // First process: one store anchors its single op as seq 0, then is dropped.
        {
            let store = store_with(bucket.clone(), SOLO_SEED, anchor.clone(), 1)?;
            store.remember(sample_input()).await?;
        }
        assert_eq!(read_anchor_records(&bucket, TEAM).await?.len(), 1);

        // Fresh store, SAME bucket + author: its first anchor seeds next_seq to 1.
        let restarted = store_with(bucket.clone(), SOLO_SEED, anchor.clone(), 1)?;
        restarted
            .remember(RememberInput {
                force: true,
                repo: RepoScope::Global,
                ..sample_input()
            })
            .await?;

        let records = read_anchor_records(&bucket, TEAM).await?;
        assert_eq!(
            records.len(),
            2,
            "the restart's record does not overwrite the first"
        );
        let seqs: Vec<u64> = records.iter().map(|record| record.seq).collect();
        assert_eq!(
            seqs,
            vec![0, 1],
            "next_seq is seeded from existing records, not restarted at 0"
        );
        Ok(())
    }

    #[tokio::test]
    async fn sync_converges_two_machines() -> TestResult {
        // Two machines share one bucket (hence one op-log) but keep independent
        // indexes + identities.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let machine_a = store_over(bucket.clone(), SOLO_SEED)?;
        let machine_b = store_over(bucket, [6_u8; 32])?;

        let id = machine_a.remember(sample_input()).await?;
        let query = RecallInput {
            text: "select losing branch".to_string(),
            repo: RepoScope::Repo("thebrain".to_string()),
            k: 5,
            token_budget: None,
        };

        // B learns A's note only by syncing the shared op-log.
        let indexed = machine_b.sync().await?;
        assert_eq!(indexed, 1, "B indexes A's one live note");
        assert!(
            machine_b
                .recall(query.clone())?
                .pointers
                .iter()
                .any(|p| p.note_id == id),
            "B recalls A's note after sync"
        );

        // A forgets the note; the tombstone converges to B on its next sync.
        machine_a.forget(id).await?;
        let after_forget = machine_b.sync().await?;
        assert_eq!(after_forget, 0, "the tombstoned note is no longer live");
        assert!(
            machine_b.recall(query)?.pointers.is_empty(),
            "B drops A's note after the forget converges"
        );
        Ok(())
    }

    #[tokio::test]
    async fn refresh_if_stale_picks_up_a_teammates_note() -> TestResult {
        // The reason the read tools call it: a long session on B does not see A's
        // just-written note until the shared op-log is replayed. `refresh_if_stale`
        // does that automatically once the log has grown, so a recall need not wait
        // for a manual `refresh`.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let machine_a = store_over(bucket.clone(), SOLO_SEED)?;
        let machine_b = store_over(bucket, [6_u8; 32])?;
        let query = RecallInput {
            text: "select losing branch".to_string(),
            repo: RepoScope::Repo("thebrain".to_string()),
            k: 5,
            token_budget: None,
        };

        assert!(
            machine_b.refresh_if_stale().await?,
            "the first probe of a session always syncs",
        );
        assert!(machine_b.recall(query.clone())?.pointers.is_empty());

        // A writes; B's next probe sees the op-log grew and syncs it in.
        let id = machine_a.remember(sample_input()).await?;
        machine_b.reset_auto_refresh_window(); // bypass the wall-clock window in-test
        assert!(
            machine_b.refresh_if_stale().await?,
            "a grown op-log must trigger a sync",
        );
        assert!(
            machine_b
                .recall(query)?
                .pointers
                .iter()
                .any(|p| p.note_id == id),
            "B recalls A's note after the auto-refresh",
        );
        Ok(())
    }

    #[tokio::test]
    async fn refresh_if_stale_skips_within_the_window() -> TestResult {
        // A burst of reads must not each hit the bucket: after one probe, a second
        // within the window is a no-op even when the op-log has since grown.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let machine_a = store_over(bucket.clone(), SOLO_SEED)?;
        let machine_b = store_over(bucket, [6_u8; 32])?;

        assert!(
            machine_b.refresh_if_stale().await?,
            "the first probe opens the window",
        );
        // A writes AFTER B's probe; with the window still open, B does not re-probe.
        machine_a.remember(sample_input()).await?;
        assert!(
            !machine_b.refresh_if_stale().await?,
            "within the window the check is skipped, even with a new op",
        );
        Ok(())
    }

    #[tokio::test]
    async fn refresh_if_stale_skips_sync_when_the_log_is_unchanged() -> TestResult {
        // When the window has elapsed but the op-log has not grown, the cheap probe
        // short-circuits — no full sync, no wasted blob fetches.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let machine_a = store_over(bucket.clone(), SOLO_SEED)?;
        let machine_b = store_over(bucket, [6_u8; 32])?;

        machine_a.remember(sample_input()).await?;
        assert!(
            machine_b.refresh_if_stale().await?,
            "first probe syncs the new op",
        );
        machine_b.reset_auto_refresh_window();
        assert!(
            !machine_b.refresh_if_stale().await?,
            "an unchanged op-log must not trigger a redundant sync",
        );
        Ok(())
    }

    /// A [`BlobStore`] wrapper that counts `get` calls, to prove the incremental
    /// (snapshot-restore) path fetches fewer blobs than a full replay.
    struct CountingBlob {
        inner: Arc<dyn BlobStore>,
        gets: std::sync::atomic::AtomicUsize,
    }

    impl CountingBlob {
        fn new(inner: Arc<dyn BlobStore>) -> Self {
            Self {
                inner,
                gets: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn gets(&self) -> usize {
            self.gets.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    #[async_trait::async_trait]
    impl BlobStore for CountingBlob {
        async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
            self.inner.put(key, bytes).await
        }

        async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
            self.gets.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.inner.get(key).await
        }

        async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError> {
            self.inner.list(prefix).await
        }

        async fn delete(&self, key: &str) -> Result<(), MemError> {
            self.inner.delete(key).await
        }
    }

    fn note_input(summary: &str, repo: &str) -> RememberInput {
        RememberInput {
            force: true,
            note_type: NoteType::Gotcha,
            repo: RepoScope::Repo(repo.to_string()),
            tags: BTreeSet::new(),
            summary: summary.to_string(),
            body: format!("body for {summary}"),
        }
    }

    fn recall_all(store: &MemoryStore, repo: &str) -> Result<Vec<NoteId>, MemError> {
        let mut ids: Vec<NoteId> = store
            .recall(RecallInput {
                text: "summary note".to_string(),
                repo: RepoScope::Repo(repo.to_string()),
                k: 100,
                token_budget: None,
            })?
            .pointers
            .iter()
            .map(|pointer| pointer.note_id)
            .collect();
        // Sort by id so the comparison is over the surfaced *set*, independent of
        // the recency-decay tie ordering (which depends on the wall-clock `now` at
        // recall time and so can differ between two stores recalling moments apart).
        ids.sort_unstable();
        Ok(ids)
    }

    #[tokio::test]
    async fn sync_with_snapshot_equals_full_replay() -> TestResult {
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let writer = store_over(bucket.clone(), SOLO_SEED)?;

        let mut base_ids = Vec::new();
        for i in 0..4 {
            base_ids.push(
                writer
                    .remember(note_input(&format!("base summary note {i}"), "repo-a"))
                    .await?,
            );
        }
        let baseline = writer.snapshot().await?;
        assert!(
            baseline > 0,
            "the snapshot covers a non-trivial Lamport tip"
        );

        for i in 0..3 {
            writer
                .remember(note_input(&format!("tail summary note {i}"), "repo-a"))
                .await?;
        }
        // Forget a base note in the tail: exercises a tombstone that lands strictly
        // after the snapshot, which must drop the restored record.
        writer.forget(base_ids[0]).await?;

        // B restores the snapshot then tails the newer ops.
        let incremental = store_over(bucket.clone(), [21_u8; 32])?;
        let b_indexed = incremental.sync().await?;

        // C does a full replay over the SAME bucket, bypassing the snapshot.
        let full = store_over(bucket.clone(), [22_u8; 32])?;
        let members = full.read_and_filter().await?;
        let c_indexed = full.replay_full(members).await?;

        assert_eq!(
            b_indexed, c_indexed,
            "incremental indexes the same live count as full replay"
        );
        assert_eq!(
            recall_all(&incremental, "repo-a")?,
            recall_all(&full, "repo-a")?,
            "incremental restore + tail surfaces the exact same notes as a full replay"
        );
        assert!(
            !recall_all(&incremental, "repo-a")?.contains(&base_ids[0]),
            "the note forgotten in the tail is dropped from the restored snapshot"
        );
        Ok(())
    }

    #[tokio::test]
    async fn incremental_sync_preserves_ranking_signals_after_a_tail_edit() -> TestResult {
        // The regression this pins: a plain Edit in the tail re-points a note, the
        // incremental path re-decodes it from the blob (which carries no ranking
        // signals), and without restamping from converged state the note's
        // outgoing relations and reinforcers silently vanish. The tail guard only
        // full-rebuilds on Relate/Reinforce ops IN the tail, so this exact shape —
        // relate+reinforce in the base, edit in the tail — used to slip through.
        // `all_records` is also exactly what checkpoint-on-sync persists, so these
        // assertions cover the durable half too.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let writer = store_over(bucket.clone(), SOLO_SEED)?;

        let old = writer
            .remember(note_input("old summary note retry", "repo-a"))
            .await?;
        let new = writer
            .remember(note_input("new summary note retry", "repo-a"))
            .await?;
        writer.relate(new, old, LinkRel::Supersedes).await?;
        // Reinforce NEW: a recall that surfaces it, then a get inside the window.
        writer.recall(RecallInput {
            text: "retry".to_string(),
            repo: RepoScope::Repo("repo-a".to_string()),
            k: 10,
            token_budget: None,
        })?;
        writer.get(new).await?;

        // Checkpoint AFTER the relate + reinforce (both land in the base) …
        let baseline = writer.snapshot().await?;
        assert!(
            baseline > 0,
            "the snapshot covers a non-trivial Lamport tip"
        );
        // … and the tail holds ONLY a plain Edit of the related+reinforced note.
        writer
            .edit(new, note_input("new summary note retry v2", "repo-a"))
            .await?;

        let reader = store_over(bucket.clone(), [23_u8; 32])?;
        reader.sync().await?;

        let record = reader
            .index
            .all_records()?
            .into_iter()
            .find(|record| record.note_id == new)
            .ok_or("the edited note is missing from the incremental index")?;
        assert!(
            record
                .relations
                .iter()
                .any(|link| link.rel == LinkRel::Supersedes && link.to == old),
            "the outgoing Supersedes relation survives a tail edit: {:?}",
            record.relations
        );
        assert_eq!(
            record.reinforcers.len(),
            1,
            "the reinforcement survives a tail edit"
        );
        assert!(
            record.last_reinforced.is_some(),
            "last_reinforced survives a tail edit"
        );

        // Pin that the INCREMENTAL path is what the assertions above exercised:
        // with the same bucket state, the classifier must take the tail shortcut
        // (Relate/Reinforce sit in the BASE; the tail holds only the Edit).
        // Without this, a future guard change could silently reroute the scenario
        // through replay_full — which also stamps — and the incremental stamp
        // could regress unseen behind a still-green test.
        let verifier = store_over(bucket.clone(), [24_u8; 32])?;
        let members = verifier.read_and_filter().await?;
        let key = verifier.key_for_epoch(verifier.current_epoch())?;
        let checkpoint = load_latest_snapshot(verifier.blob.as_ref(), &key, TEAM)
            .await?
            .ok_or("a checkpoint must exist for the incremental path")?;
        let outcome = verifier.sync_incremental(checkpoint, members).await?;
        assert!(
            matches!(outcome, IncrementalOutcome::Incremental(_)),
            "the tail-Edit shape must take the incremental path, not fall back to full"
        );
        Ok(())
    }

    #[tokio::test]
    async fn snapshot_equals_full_replay_across_epochs() -> TestResult {
        // A forward-joined member holds the CURRENT epoch (so it can open the
        // snapshot envelope and take the incremental path) but lacks an OLDER
        // epoch. The incremental restore must reach the SAME index state as a full
        // replay: the old-epoch note is absent from both, never surfaced by one
        // path and missing from the other. Regression for the epoch-gate the
        // restore loop previously skipped (it indexed records it could not `get`).
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());

        // Writer holds both keys: one note under epoch 0, rotate, one under epoch 1,
        // then snapshot (the envelope seals under the current epoch, 1).
        let writer = store_over(bucket.clone(), SOLO_SEED)?;
        writer.add_epoch_key(1, SecretKey::from_bytes(EPOCH1_KEY));
        let epoch0_note = writer
            .remember(note_input("epoch zero summary note", "repo-a"))
            .await?;
        writer.set_current_epoch(1);
        let epoch1_note = writer
            .remember(note_input("epoch one summary note", "repo-a"))
            .await?;
        let baseline = writer.snapshot().await?;
        assert!(
            baseline > 0,
            "the snapshot covers a non-trivial Lamport tip"
        );

        // Member B: epoch 1 ONLY (current) — opens the snapshot, genuinely lacks
        // epoch 0 (no entry in the ring, so `key_for_epoch(0)` errors).
        let epoch1_ring = || BTreeMap::from([(1_u64, SecretKey::from_bytes(EPOCH1_KEY))]);
        let incremental = store_with_ring(bucket.clone(), [61_u8; 32], epoch1_ring(), 1)?;
        let b_indexed = incremental.sync().await?;

        // Member C: same key-ring, but forced through a full replay (no snapshot).
        let full = store_with_ring(bucket.clone(), [62_u8; 32], epoch1_ring(), 1)?;
        let members = full.read_and_filter().await?;
        let c_indexed = full.replay_full(members).await?;

        assert_eq!(
            b_indexed, c_indexed,
            "incremental indexes the same live count as full replay across epochs"
        );
        assert_eq!(
            recall_all(&incremental, "repo-a")?,
            recall_all(&full, "repo-a")?,
            "incremental restore + tail surfaces the exact same notes as a full replay"
        );
        let hits = recall_all(&incremental, "repo-a")?;
        assert!(
            hits.contains(&epoch1_note),
            "the current-epoch note is indexed on both paths"
        );
        assert!(
            !hits.contains(&epoch0_note),
            "the old-epoch note (no key) is absent from both paths"
        );
        Ok(())
    }

    #[tokio::test]
    async fn late_lower_lamport_op_triggers_full_rebuild() -> TestResult {
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let primary = store_over(bucket.clone(), SOLO_SEED)?;

        for i in 0..3 {
            primary
                .remember(note_input(&format!("base summary note {i}"), "repo-a"))
                .await?;
        }
        let baseline = primary.snapshot().await?;
        let tail_id = primary
            .remember(note_input("tail summary note", "repo-a"))
            .await?;

        // A partitioned machine with a cold clock (Lamport tip 0) mints an op whose
        // Lamport (1) is <= the snapshot baseline — a late, out-of-order arrival a
        // tail-only sync (read_since(baseline)) would silently exclude.
        let partitioned = store_over(bucket.clone(), [33_u8; 32])?;
        let late_id = partitioned
            .remember(note_input("late partitioned note", "repo-a"))
            .await?;
        assert!(
            baseline >= 1,
            "the late op's Lamport falls at or below the baseline"
        );

        // B's incremental sync must detect the changed base and full-rebuild.
        let restorer = store_over(bucket.clone(), [34_u8; 32])?;
        let b_indexed = restorer.sync().await?;

        let full = store_over(bucket.clone(), [35_u8; 32])?;
        let members = full.read_and_filter().await?;
        let c_indexed = full.replay_full(members).await?;

        assert_eq!(
            b_indexed, c_indexed,
            "the fallback full rebuild matches a direct full replay"
        );
        let hits = recall_all(&restorer, "repo-a")?;
        assert!(
            hits.contains(&late_id),
            "the late lower-Lamport op is recovered by the full-rebuild fallback (a tail-only path would drop it)"
        );
        assert!(hits.contains(&tail_id), "the normal tail op is present too");
        Ok(())
    }

    #[tokio::test]
    async fn cold_start_with_snapshot_is_incremental() -> TestResult {
        // Bucket 1: five base notes, a snapshot, then one tail note.
        let bucket_snap: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let writer_snap = store_over(bucket_snap.clone(), SOLO_SEED)?;
        for i in 0..5 {
            writer_snap
                .remember(note_input(&format!("base summary note {i}"), "repo-a"))
                .await?;
        }
        writer_snap.snapshot().await?;
        writer_snap
            .remember(note_input("tail summary note", "repo-a"))
            .await?;

        // Bucket 2: the same six notes, but NO snapshot.
        let bucket_full: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let writer_full = store_over(bucket_full.clone(), SOLO_SEED)?;
        for i in 0..6 {
            writer_full
                .remember(note_input(&format!("plain summary note {i}"), "repo-a"))
                .await?;
        }

        // Cold-start each fresh store through a get-counting wrapper.
        let snap_counter = Arc::new(CountingBlob::new(bucket_snap.clone()));
        let incremental = store_over(snap_counter.clone() as Arc<dyn BlobStore>, [41_u8; 32])?;
        incremental.sync().await?;

        let full_counter = Arc::new(CountingBlob::new(bucket_full.clone()));
        let full = store_over(full_counter.clone() as Arc<dyn BlobStore>, [42_u8; 32])?;
        full.sync().await?;

        assert!(
            snap_counter.gets() < full_counter.gets(),
            "incremental cold start ({} gets) fetches fewer blobs than a full replay ({} gets): \
             the five base notes are restored from the snapshot without re-decoding their blobs",
            snap_counter.gets(),
            full_counter.gets(),
        );
        Ok(())
    }

    #[tokio::test]
    async fn sync_writes_checkpoint_so_next_cold_sync_is_incremental() -> TestResult {
        // Regression: `sync()` must persist a checkpoint on its own. Before this,
        // only an explicit `snapshot()` call did — which no production path made —
        // so every cold start (server warmup, dashboard, import) re-read and
        // re-decoded the entire op-log. That is the dashboard's "Syncing…" hang.

        // Bucket A: five notes, then a single plain `sync()` — which must checkpoint.
        let bucket_a: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let writer_a = store_over(bucket_a.clone(), SOLO_SEED)?;
        for i in 0..5 {
            writer_a
                .remember(note_input(&format!("note {i}"), "repo-a"))
                .await?;
        }
        writer_a.sync().await?; // no explicit snapshot() call

        // Bucket B: the same five notes, never synced by the writer — no checkpoint.
        let bucket_b: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let writer_b = store_over(bucket_b.clone(), SOLO_SEED)?;
        for i in 0..5 {
            writer_b
                .remember(note_input(&format!("note {i}"), "repo-a"))
                .await?;
        }

        // Cold-start a fresh store over each bucket through a get counter.
        let a_counter = Arc::new(CountingBlob::new(bucket_a.clone()));
        let cold_a = store_over(a_counter.clone() as Arc<dyn BlobStore>, [41_u8; 32])?;
        cold_a.sync().await?;

        let b_counter = Arc::new(CountingBlob::new(bucket_b.clone()));
        let cold_b = store_over(b_counter.clone() as Arc<dyn BlobStore>, [42_u8; 32])?;
        cold_b.sync().await?;

        assert!(
            a_counter.gets() < b_counter.gets(),
            "the plain sync() over bucket A wrote a checkpoint, so its cold start ({} gets) \
             restores the base from the snapshot instead of re-decoding every note like \
             bucket B's full replay ({} gets)",
            a_counter.gets(),
            b_counter.gets(),
        );
        // The incremental restore is complete: all five notes are indexed.
        assert_eq!(
            cold_a.list_records()?.len(),
            5,
            "the checkpoint-restored index holds every note"
        );
        Ok(())
    }

    #[tokio::test]
    async fn incremental_restore_indexes_a_snapshot_omitted_note_without_rebuild() -> TestResult {
        // store-3: snapshot() omits a note whose blob was undecodable when it ran.
        // The incremental restore must (a) still index that note by decoding it
        // fresh, and (b) NOT fall back to a full rebuild — one omitted note used to
        // force re-decoding the entire base on every sync. We simulate the omission
        // by dropping one record from a real snapshot.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let writer = store_over(bucket.clone(), SOLO_SEED)?;
        let mut ids = Vec::new();
        for i in 0..5 {
            ids.push(
                writer
                    .remember(note_input(&format!("base note {i}"), "repo-a"))
                    .await?,
            );
        }
        writer.snapshot().await?;

        // Drop one record from the persisted snapshot, as if its blob had been
        // undecodable when snapshot() built the checkpoint.
        let envelope_key = writer.key_for_epoch(writer.current_epoch())?;
        let mut snap = super::load_latest_snapshot(bucket.as_ref(), &envelope_key, TEAM)
            .await?
            .ok_or("snapshot was saved")?;
        let omitted = ids[2];
        snap.records.retain(|record| record.note_id != omitted);
        super::save_snapshot(bucket.as_ref(), &envelope_key, &snap).await?;

        // A second bucket with the same five notes but NO snapshot — the full-replay
        // get-count baseline.
        let bucket_full: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let writer_full = store_over(bucket_full.clone(), SOLO_SEED)?;
        for i in 0..5 {
            writer_full
                .remember(note_input(&format!("plain note {i}"), "repo-a"))
                .await?;
        }

        // Cold-start a reader over the omitting snapshot, through a get counter.
        let snap_counter = Arc::new(CountingBlob::new(bucket.clone()));
        let reader = store_over(snap_counter.clone() as Arc<dyn BlobStore>, [41_u8; 32])?;
        reader.sync().await?;

        let full_counter = Arc::new(CountingBlob::new(bucket_full.clone()));
        let full = store_over(full_counter.clone() as Arc<dyn BlobStore>, [42_u8; 32])?;
        full.sync().await?;

        // (a) The omitted note is indexed despite the snapshot dropping it.
        assert!(
            reader.get(omitted).await.is_ok(),
            "the snapshot-omitted note is decoded fresh on incremental restore"
        );
        // (b) Fewer blob fetches than a full replay -> the omitting snapshot did NOT
        // force a rebuild; only the single omitted note was re-decoded. A regression
        // to the old exact-equality valve would rebuild and erase this margin.
        assert!(
            snap_counter.gets() < full_counter.gets(),
            "incremental restore ({} gets) must beat a full replay ({} gets) despite one omitted note",
            snap_counter.gets(),
            full_counter.gets(),
        );
        Ok(())
    }

    /// The summary a forged snapshot record body claims. Distinctive so a `recall`
    /// for it matches nothing else in the fixture.
    const FORGED_SUMMARY: &str = "forged summary note planted in the checkpoint";

    /// Re-seal ONE record of the persisted snapshot under the SAME epoch key with a
    /// body that `forge` has altered, leaving that record's CLEAR envelope
    /// byte-identical.
    ///
    /// This is exactly what a holder of the current epoch key — a team member, since
    /// the bucket holds no epoch key and cannot seal a record at all — can write into
    /// the bucket, and it is the shape that walks past the incremental safety valve:
    /// the valve compares only `note_id`/`lamport`/`object_key`, all untouched here,
    /// while the body it never inspects is what gets indexed.
    ///
    /// Reseals in place rather than through [`seal_record`], which mints the envelope
    /// FROM the body and so cannot express a body that disagrees with its own
    /// envelope. The associated data is the untouched envelope's `object_key` —
    /// exactly what `open_record` re-derives — so the forged record still opens.
    async fn forge_snapshot_record(
        store: &MemoryStore,
        blob: &Arc<dyn BlobStore>,
        note_id: NoteId,
        forge: impl FnOnce(&mut IndexRecord),
    ) -> TestResult {
        let key = store.key_for_epoch(store.current_epoch())?;
        let mut snapshot = load_latest_snapshot(blob.as_ref(), &key, TEAM)
            .await?
            .ok_or("a snapshot must have been saved")?;
        let sealed = snapshot
            .records
            .iter_mut()
            .find(|record| record.note_id == note_id)
            .ok_or("the forged note must be present in the snapshot")?;

        let mut body = super::open_record(sealed, &key)?;
        forge(&mut body);
        let plaintext = serde_json::to_vec(&body)?;
        sealed.sealed = seal(&key, &plaintext, sealed.object_key.as_bytes())?;

        super::save_snapshot(blob.as_ref(), &key, &snapshot).await?;
        Ok(())
    }

    /// The summary the note at `index` of a forgery fixture really carries, so a
    /// rejected forgery is proven by the TRUE summary reappearing in the index.
    fn true_summary(index: usize) -> String {
        format!("base summary note {index}")
    }

    /// Write four notes and a checkpoint over `blob`, returning the writer and the
    /// note ids in order — the fixture every snapshot-forgery test starts from.
    async fn snapshot_fixture(
        blob: &Arc<dyn BlobStore>,
    ) -> Result<(MemoryStore, Vec<NoteId>), Box<dyn std::error::Error>> {
        let writer = store_over(blob.clone(), SOLO_SEED)?;

        let mut ids = Vec::new();
        for i in 0..4 {
            ids.push(
                writer
                    .remember(note_input(&true_summary(i), "repo-a"))
                    .await?,
            );
        }
        writer.snapshot().await?;

        Ok((writer, ids))
    }

    #[tokio::test]
    async fn snapshot_record_misattributed_to_another_author_is_re_decoded_from_the_blob()
    -> TestResult {
        // C7. The incremental safety valve authenticates only the CLEAR envelope
        // (note_id, lamport, object_key, key_epoch). The sealed body carries its own
        // copies of all four PLUS author, cid, scope, note_type, updated, tags and
        // summary — and it is the BODY, not the envelope, that `open_record` returns
        // and `upsert_batch` indexes. So the snapshot was a signature-bypass channel:
        // the op-log demands a signed op from an author for every statement it makes,
        // while the snapshot body demanded a signature from nobody, letting one member
        // attribute a note to a DIFFERENT member who never signed anything.
        //
        // This is NOT a hostile-bucket defence: the forger must hold the current epoch
        // key, so it is a team member. A bucket that tampers with a snapshot fails AEAD
        // authentication in `load_latest_snapshot` and is skipped already.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let (writer, ids) = snapshot_fixture(&bucket).await?;

        let victim = ids[1];
        let true_author = writer.author.clone();
        let impostor = store_over(bucket.clone(), [77_u8; 32])?.author.clone();
        assert_ne!(
            impostor, true_author,
            "the forgery must name an author other than the one who signed the op"
        );

        let impostor_claim = impostor.clone();
        forge_snapshot_record(&writer, &bucket, victim, move |body| {
            body.author = impostor_claim;
            body.summary = FORGED_SUMMARY.to_string();
        })
        .await?;

        let reader = store_over(bucket.clone(), [41_u8; 32])?;
        reader.sync().await?;

        let record = reader
            .list_records()?
            .into_iter()
            .find(|record| record.note_id == victim)
            .ok_or("the forged note must still be indexed, from its blob")?;
        assert_eq!(
            record.author, true_author,
            "the indexed author must be the identity that SIGNED the op, not the one the snapshot body claimed"
        );
        assert_eq!(
            record.summary,
            true_summary(1),
            "the indexed summary must be the one in the op-attested blob"
        );

        let hits = reader.recall(RecallInput {
            text: FORGED_SUMMARY.to_string(),
            repo: RepoScope::Repo("repo-a".to_string()),
            k: 100,
            token_budget: None,
        })?;
        assert!(
            hits.pointers
                .iter()
                .all(|pointer| pointer.summary != FORGED_SUMMARY),
            "recall must never surface the forged summary, got {:?}",
            hits.pointers
                .iter()
                .map(|pointer| pointer.summary.clone())
                .collect::<Vec<_>>()
        );
        assert!(
            hits.pointers
                .iter()
                .all(|pointer| pointer.author == true_author),
            "recall must never attribute a note to an identity that signed nothing"
        );
        Ok(())
    }

    #[tokio::test]
    async fn the_op_attested_fields_other_than_author_are_cross_checked() -> TestResult {
        // Six of the seven fields `snapshot_body_disagreement` checks. Each forgery is
        // confined to the SEALED BODY (the envelope stays byte-identical, so the
        // safety valve passes) and also rewrites the summary, so the TRUE summary
        // reappearing in the index is proof the record was rejected and re-decoded
        // from its blob rather than restored from the checkpoint.
        //
        // `author` is the seventh and is deliberately NOT a scenario here: it is the
        // headline case, covered by
        // `snapshot_record_misattributed_to_another_author_is_re_decoded_from_the_blob`.
        // Deleting the author clause leaves THIS test green, which is why the name
        // says "other than author" rather than "every".
        //
        // `scope` is included because it is recoverable from the op-attested
        // `object_key`. `summary`, `tags`, `updated` and `note_type` are absent
        // because no signed op carries them — see
        // `a_snapshot_body_forged_only_in_its_summary_is_still_indexed`.
        /// One forgery scenario: the op-attested field it rewrites, and how.
        type Forgery = (&'static str, fn(&mut IndexRecord));

        let forgeries: [Forgery; 6] = [
            ("cid", |body| body.cid = Blake3Hash::new([0xAB_u8; 32])),
            ("object_key", |body| {
                body.object_key = format!("{}Z", body.object_key);
            }),
            ("lamport", |body| {
                body.lamport = body.lamport.saturating_add(1_000);
            }),
            ("key_epoch", |body| {
                body.key_epoch = body.key_epoch.saturating_add(1);
            }),
            ("note_id", |body| body.note_id = NoteId::new()),
            ("scope", |body| {
                body.scope.repo = RepoScope::Repo("repo-b".to_string());
            }),
        ];

        for (field, forge) in forgeries {
            let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
            let (writer, ids) = snapshot_fixture(&bucket).await?;
            let victim = ids[1];

            forge_snapshot_record(&writer, &bucket, victim, move |body| {
                forge(body);
                body.summary = FORGED_SUMMARY.to_string();
            })
            .await?;

            let reader = store_over(bucket.clone(), [41_u8; 32])?;
            reader.sync().await?;
            let records = reader.list_records()?;

            let record = records
                .iter()
                .find(|record| record.note_id == victim)
                .ok_or_else(|| format!("forging {field} must not lose the note"))?;
            assert_eq!(
                record.summary,
                true_summary(1),
                "a body whose {field} contradicts the signed op-log must be re-decoded from its blob"
            );
            assert!(
                records
                    .iter()
                    .all(|record| record.summary != FORGED_SUMMARY),
                "forging {field} must leave the forged summary nowhere in the index"
            );
            assert_eq!(
                records.len(),
                4,
                "forging {field} must not add or lose a note"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn an_oversized_snapshot_record_is_clamped_like_a_decoded_one() -> TestResult {
        // `summary` and `tags` are not cross-checked (no signed op carries them), so a
        // current-epoch key holder can rewrite them freely. Their SIZE must still be
        // bounded. `bound_index_fields` is the documented sync-ingestion clamp, and
        // before this it had a single call site — `decode_pointer` — so the snapshot
        // restore path applied no clamp at all and checkpoints were bounded only
        // incidentally, because their records had been clamped on the way in. One
        // resealed record with an unbounded summary or tag set would then be indexed
        // AND embedded by every teammate's next cold sync.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let (writer, ids) = snapshot_fixture(&bucket).await?;
        let victim = ids[1];

        forge_snapshot_record(&writer, &bucket, victim, |body| {
            body.summary = "z".repeat(MAX_SUMMARY_CHARS * 4);
            // The distinguishing digits lead, so the tags stay distinct after each is
            // truncated to MAX_TAG_CHARS and re-collected into a set.
            body.tags = (0..MAX_TAGS * 3)
                .map(|i| format!("{i:06}{}", "t".repeat(MAX_TAG_CHARS * 2)))
                .collect();
        })
        .await?;

        let reader = store_over(bucket.clone(), [41_u8; 32])?;
        reader.sync().await?;

        let record = reader
            .list_records()?
            .into_iter()
            .find(|record| record.note_id == victim)
            .ok_or("the oversized note is still indexed, clamped")?;
        assert_eq!(
            record.summary.chars().count(),
            MAX_SUMMARY_CHARS,
            "a snapshot-restored summary must be clamped exactly as a decoded one is"
        );
        assert_eq!(
            record.tags.len(),
            MAX_TAGS,
            "a snapshot-restored tag set must be capped exactly as a decoded one is"
        );
        assert!(
            record
                .tags
                .iter()
                .all(|tag| tag.chars().count() <= MAX_TAG_CHARS),
            "every snapshot-restored tag must be clamped to MAX_TAG_CHARS"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_snapshot_body_forged_only_in_its_summary_is_still_indexed() -> TestResult {
        // KNOWN, DELIBERATELY UNCLOSED GAP — pinned so nobody reads the cross-check as
        // broader than it is.
        //
        // `summary` (like `tags`, `updated` and `note_type`) lives only inside the note
        // blob. A signed op carries op_id, lamport, key_epoch, kind, note_id,
        // object_key, cid and prev_op_hash — nothing about the note's text. So a
        // current-epoch key holder who leaves every op-attested field true and rewrites
        // only the summary passes `snapshot_body_disagreement` and IS indexed: recall
        // surfaces the forgery, while `get` still returns the true note (it re-fetches
        // the blob and gates it on the op-attested cid).
        //
        // Closing this needs a change the cross-check cannot make on its own — a
        // commitment to the indexed fields inside the SIGNED op, trusting only
        // self-written snapshots, or decoding every restored record's blob (which is
        // the very work the checkpoint exists to avoid).
        //
        // If this test ever fails, the gap was closed: verify that deliberately and
        // rewrite this test to assert the new, stronger property.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let (writer, ids) = snapshot_fixture(&bucket).await?;
        let victim = ids[1];

        forge_snapshot_record(&writer, &bucket, victim, |body| {
            body.summary = FORGED_SUMMARY.to_string();
        })
        .await?;

        let reader = store_over(bucket.clone(), [41_u8; 32])?;
        reader.sync().await?;

        let record = reader
            .list_records()?
            .into_iter()
            .find(|record| record.note_id == victim)
            .ok_or("the note is still indexed")?;
        assert_eq!(
            record.summary, FORGED_SUMMARY,
            "the op-log signs nothing about a note's summary, so a summary-only forgery is NOT detected"
        );
        assert_eq!(
            reader.get(victim).await?.summary,
            true_summary(1),
            "`get` re-fetches the blob under the op-attested cid, so it still returns the true note"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_rejected_snapshot_record_costs_one_blob_decode_not_a_full_rebuild() -> TestResult {
        // The verification trap this closes: a cross-check that rejected EVERY record
        // would still agree with a full replay — and silently destroy the checkpoint
        // optimization. Counting note-blob GETs distinguishes the two, which
        // equality-with-full-replay cannot.
        let bucket = Arc::new(NoteGetCountingBlob::new());
        let blob: Arc<dyn BlobStore> = bucket.clone();
        let (writer, ids) = snapshot_fixture(&blob).await?;

        // An untouched checkpoint restores all four notes with ZERO note-blob decodes.
        let honest = store_over(blob.clone(), [43_u8; 32])?;
        bucket.reset_note_gets();
        honest.sync().await?;
        assert_eq!(
            bucket.note_gets(),
            0,
            "an honest checkpoint still restores with no note-blob I/O: the cross-check must cost nothing on the fast path"
        );
        assert_eq!(honest.list_records()?.len(), 4, "all four notes restored");

        // Forge exactly one record. Only that one may fall back to a blob decode.
        let impostor = store_over(blob.clone(), [77_u8; 32])?.author.clone();
        forge_snapshot_record(&writer, &blob, ids[1], move |body| {
            body.author = impostor;
            body.summary = FORGED_SUMMARY.to_string();
        })
        .await?;

        let reader = store_over(blob.clone(), [44_u8; 32])?;
        bucket.reset_note_gets();
        reader.sync().await?;
        assert_eq!(
            bucket.note_gets(),
            1,
            "exactly the rejected record is decoded from its blob; the other three still restore from the checkpoint (a check that rejected everything would read 4)"
        );
        assert_eq!(
            reader.list_records()?.len(),
            4,
            "the rejected record is repaired, not dropped"
        );
        Ok(())
    }

    #[tokio::test]
    async fn non_member_ops_do_not_converge() -> TestResult {
        // Two distinct authors share one bucket (hence one op-log).
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let founder = store_over(bucket.clone(), SOLO_SEED)?;
        let outsider = store_over(bucket.clone(), [6_u8; 32])?;

        // The founder publishes a manifest naming only themselves as a member.
        founder
            .publish_membership(BTreeSet::from([founder.author.clone()]))
            .await?;

        let member_note = founder.remember(sample_input()).await?;
        // The non-member writes a perfectly well-formed, signed op into the
        // SAME bucket — read_all accepts it (its signature + chain are valid),
        // so only the membership filter can keep it out of converged state.
        let outsider_note = outsider
            .remember(RememberInput {
                force: true,
                repo: RepoScope::Global,
                ..sample_input()
            })
            .await?;

        // Sync replays the shared op-log THROUGH the membership filter and
        // rebuilds the index from the converged result.
        founder.sync().await?;
        assert!(
            founder.index.locate(member_note)?.is_some(),
            "a member's note converges into the index"
        );
        assert!(
            founder.index.locate(outsider_note)?.is_none(),
            "a non-member's note is filtered out before convergence"
        );
        Ok(())
    }

    /// An in-memory [`ManifestMarker`] standing in for the on-disk file, shared
    /// across simulated "restarts" (fresh stores) via its `Arc`.
    #[derive(Default)]
    struct InMemoryMarker {
        slot: Mutex<Option<TeamManifest>>,
    }

    #[async_trait::async_trait]
    impl ManifestMarker for InMemoryMarker {
        async fn load(&self) -> Result<Option<TeamManifest>, MemError> {
            Ok(self
                .slot
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone())
        }

        async fn store(&self, manifest: &TeamManifest) -> Result<(), MemError> {
            *self.slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(manifest.clone());
            Ok(())
        }
    }

    #[tokio::test]
    async fn durable_marker_refuses_a_cross_restart_manifest_rollback() -> TestResult {
        // The residual the durable marker closes: a COLD process must not re-accept
        // a manifest the untrusted bucket rolled back to an older version. Founder F
        // removes member A (v1); the bucket then loses v1 and serves only v0 (A
        // still a member). A cold store WITH the durable marker refuses the
        // rollback; one WITHOUT it re-admits A — the exact gap being closed.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let founder = store_over(bucket.clone(), SOLO_SEED)?;
        let alice = store_over(bucket.clone(), [6_u8; 32])?;

        // v0 = {F, A}; A remembers a valid op into the shared log. v1 = {F}.
        founder
            .publish_membership(BTreeSet::from([
                founder.author.clone(),
                alice.author.clone(),
            ]))
            .await?;
        let alice_note = alice.remember(sample_input()).await?;
        founder
            .publish_membership(BTreeSet::from([founder.author.clone()]))
            .await?;

        // A warm store with a durable marker applies v1 and persists it.
        let marker = Arc::new(InMemoryMarker::default());
        let warm = store_over(bucket.clone(), SOLO_SEED)?
            .with_manifest_marker(Some(marker.clone() as Arc<dyn ManifestMarker>));
        warm.sync().await?;
        assert!(
            warm.index.locate(alice_note)?.is_none(),
            "v1 removed A, so her note is filtered before convergence"
        );

        // The untrusted bucket rolls back: the v1 manifest object is deleted,
        // leaving only v0 = {F, A}.
        bucket
            .delete(&format!("{TEAM}/_manifest/{:020}", 1_u64))
            .await?;

        // A COLD restart WITH the durable marker seeds v1 and refuses the v0
        // rollback, so A stays filtered across the restart.
        let cold_with_marker = store_over(bucket.clone(), SOLO_SEED)?
            .with_manifest_marker(Some(marker as Arc<dyn ManifestMarker>));
        cold_with_marker.sync().await?;
        assert!(
            cold_with_marker.index.locate(alice_note)?.is_none(),
            "the durable marker refuses the rollback: A stays a non-member across the restart",
        );

        // Control: a cold restart WITHOUT the marker has no watermark, applies the
        // rolled-back v0, and re-admits A — the residual the marker closes.
        let cold_no_marker = store_over(bucket, SOLO_SEED)?;
        cold_no_marker.sync().await?;
        assert!(
            cold_no_marker.index.locate(alice_note)?.is_some(),
            "without the marker the rollback re-admits A (the residual being closed)",
        );
        Ok(())
    }

    #[tokio::test]
    async fn durable_marker_ignores_a_manifest_for_a_different_team() -> TestResult {
        // A tampered or foreign marker file must not govern this team: a marker
        // whose manifest is bound to another team is rejected (team mismatch),
        // exactly as a bucket manifest would be, so membership follows the bucket.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let founder = store_over(bucket.clone(), SOLO_SEED)?;
        let alice = store_over(bucket.clone(), [6_u8; 32])?;

        // The bucket says {F, A}; A writes a note.
        founder
            .publish_membership(BTreeSet::from([
                founder.author.clone(),
                alice.author.clone(),
            ]))
            .await?;
        let alice_note = alice.remember(sample_input()).await?;

        // The marker holds a HIGHER-version manifest for a DIFFERENT team that
        // removes A. If it were wrongly trusted, A would be filtered out.
        let signer = Sr25519Signer::from_seed_with_prefix(&SOLO_SEED, NetworkPrefix::HIPPIUS)?;
        let foreign = TeamManifest::create_signed(
            &signer,
            "other-team".to_string(),
            BTreeSet::from([founder.author.clone()]),
            99,
        );
        let marker = Arc::new(InMemoryMarker::default());
        marker.store(&foreign).await?;

        let store = store_over(bucket, SOLO_SEED)?
            .with_manifest_marker(Some(marker as Arc<dyn ManifestMarker>));
        store.sync().await?;
        assert!(
            store.index.locate(alice_note)?.is_some(),
            "a marker bound to another team is ignored; membership follows the bucket, so A remains a member",
        );
        Ok(())
    }

    #[tokio::test]
    async fn durable_marker_by_a_different_founder_is_rejected() -> TestResult {
        // A purely-LOCAL marker must not introduce a founder the bucket path would
        // reject. The bucket's genesis is signed by F; a marker self-signed by an
        // attacker key (holding no team credentials) that removes A is bound-checked
        // against F and rejected, so membership follows the bucket and A stays.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let founder = store_over(bucket.clone(), SOLO_SEED)?;
        let alice = store_over(bucket.clone(), [6_u8; 32])?;

        founder
            .publish_membership(BTreeSet::from([
                founder.author.clone(),
                alice.author.clone(),
            ]))
            .await?;
        let alice_note = alice.remember(sample_input()).await?;

        // A higher-version manifest self-signed by an ATTACKER key (not F), removing
        // A. `verify()` passes (it is self-consistent), but its founder is not the
        // genesis founder the bucket elected.
        let attacker = Sr25519Signer::from_seed_with_prefix(&[9_u8; 32], NetworkPrefix::HIPPIUS)?;
        let forged = TeamManifest::create_signed(
            &attacker,
            TEAM.to_string(),
            BTreeSet::from([founder.author.clone()]),
            99,
        );
        let marker = Arc::new(InMemoryMarker::default());
        marker.store(&forged).await?;

        let store = store_over(bucket, SOLO_SEED)?
            .with_manifest_marker(Some(marker as Arc<dyn ManifestMarker>));
        store.sync().await?;
        assert!(
            store.index.locate(alice_note)?.is_some(),
            "a marker by a non-genesis founder is rejected; membership follows the bucket, so A stays a member",
        );
        Ok(())
    }

    #[test]
    fn manifest_is_trusted_rejects_an_identity_point_founder() -> TestResult {
        // The marker gate's weakest configuration: NO pin and no bucket manifest,
        // so `trusted_founder` is None and the gate reduces to verify() + team.
        // A local-marker writer with NO key material could otherwise plant an
        // identity-point-founder manifest at a high version, which
        // `monotonic_manifest` would then latch as the watermark forever.
        //
        // The structural guard in `oplog::verify` closes this: the degenerate key
        // fails verification, so the manifest is untrusted even with nothing else
        // to bind it to.
        let store = build_store()?;
        let founder_key = VerifyingKey::new([0u8; 32]);
        let mut forged_sig = [0u8; 64];
        forged_sig[63] = 0x80;

        let forged = TeamManifest {
            team: TEAM.to_string(),
            members: BTreeSet::new(),
            version: u64::MAX,
            founder: crate::identity::ss58_encode(&founder_key, NetworkPrefix::HIPPIUS),
            founder_key,
            recovery_key: None,
            sig: Signature::new(forged_sig),
        };

        assert!(
            !store.manifest_is_trusted(&forged, None),
            "an identity-point founder must never be trusted, even with no pin and no bucket manifest"
        );
        Ok(())
    }

    #[tokio::test]
    async fn publish_membership_carries_the_recovery_key_forward() -> TestResult {
        // A membership change must not silently retire the team's escape hatch.
        // Provisioning names a recovery key at v0; the first `add`/`remove`
        // afterwards republishes membership, and the recovery key has to survive
        // it — otherwise the hatch closes on the first routine admin action and
        // nobody finds out until a recovery is actually needed.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let founder = store_over(bucket.clone(), SOLO_SEED)?;
        let alice = store_over(bucket.clone(), [6_u8; 32])?;
        let recovery = Sr25519Signer::from_seed_with_prefix(&[11_u8; 32], NetworkPrefix::HIPPIUS)?;

        let provisioned = TeamManifest::create_signed_with_recovery(
            founder.signer.as_ref(),
            TEAM.to_string(),
            BTreeSet::from([founder.author.clone()]),
            0,
            Some(recovery.verifying_key()),
        );
        publish_manifest(bucket.as_ref(), &provisioned).await?;

        founder
            .publish_membership(BTreeSet::from([
                founder.author.clone(),
                alice.author.clone(),
            ]))
            .await?;

        let live = founder
            .membership_manifest()
            .await?
            .ok_or("the republished manifest must load")?;
        assert_eq!(live.version, 1, "the membership change published v1");
        assert!(
            live.members.contains(&alice.author),
            "the membership change took effect"
        );
        assert_eq!(
            live.trusted_recovery_key(),
            Some(&recovery.verifying_key()),
            "the recovery key survives a membership change rather than being silently retired"
        );
        Ok(())
    }

    #[tokio::test]
    async fn publish_recovery_key_names_a_fresh_key_at_the_next_version() -> TestResult {
        // `provision`'s default recovery generation: publish a FORWARD link in
        // the manifest chain naming a recovery key. It consumes a version
        // rather than overwriting the live one, so no version's contents ever
        // change after the fact — see `publish_recovery_key`'s docs for why an
        // in-place rewrite was both a takeover primitive and a
        // read-compatibility break.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let founder = store_over(bucket.clone(), SOLO_SEED)?;
        let recovery = Sr25519Signer::from_seed_with_prefix(&[11_u8; 32], NetworkPrefix::HIPPIUS)?;

        founder
            .publish_membership(BTreeSet::from([founder.author.clone()]))
            .await?;
        let (named, previous) = founder
            .publish_recovery_key(recovery.verifying_key())
            .await?;

        assert_eq!(
            named.version, 1,
            "naming a recovery key advances the chain instead of rewriting version 0"
        );
        assert_eq!(named.team, TEAM);
        assert_eq!(named.members, BTreeSet::from([founder.author.clone()]));
        assert_eq!(
            named.trusted_recovery_key(),
            Some(&recovery.verifying_key())
        );
        assert!(
            named.verify(),
            "the republished manifest must itself verify"
        );
        assert_eq!(previous, None, "no recovery key existed before this call");

        let live = founder
            .membership_manifest()
            .await?
            .ok_or("the republished manifest must load")?;
        assert_eq!(
            live.trusted_recovery_key(),
            Some(&recovery.verifying_key()),
            "the bucket reflects the newly named recovery key"
        );
        Ok(())
    }

    #[tokio::test]
    async fn publish_recovery_key_reports_the_previous_key_it_replaces() -> TestResult {
        // I1: every re-run of `provision`'s recovery generation silently
        // retires whatever recovery key an operator may already have stored
        // offline. The CLI's REPLACES warning depends on this return value —
        // pin that the SECOND call reports the FIRST key as `previous`.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let founder = store_over(bucket.clone(), SOLO_SEED)?;
        let first_recovery =
            Sr25519Signer::from_seed_with_prefix(&[11_u8; 32], NetworkPrefix::HIPPIUS)?;
        let second_recovery =
            Sr25519Signer::from_seed_with_prefix(&[14_u8; 32], NetworkPrefix::HIPPIUS)?;

        founder
            .publish_membership(BTreeSet::from([founder.author.clone()]))
            .await?;

        let (_, previous_of_first) = founder
            .publish_recovery_key(first_recovery.verifying_key())
            .await?;
        assert_eq!(
            previous_of_first, None,
            "nothing was live before the first call"
        );

        let (named, previous_of_second) = founder
            .publish_recovery_key(second_recovery.verifying_key())
            .await?;
        assert_eq!(
            previous_of_second,
            Some(first_recovery.verifying_key()),
            "the second call must report the FIRST key as the one it replaced"
        );
        assert_eq!(
            named.trusted_recovery_key(),
            Some(&second_recovery.verifying_key()),
            "the live manifest now names only the second key"
        );
        Ok(())
    }

    /// A recovery-key publish is ADDITIVE-FORWARD: it writes a new version and
    /// leaves every earlier version's object exactly as it was.
    ///
    /// That is what keeps an older binary — one whose `signing_bytes` has no
    /// `MANIFEST_DOMAIN_V2` branch — able to read the team. Such a binary
    /// cannot verify a recovery-carrying manifest, skips it, and would find
    /// NOTHING left if the recovery key had been written over version 0 in
    /// place: `load_manifest` returns `None`, which every reader interprets as
    /// an OPEN team, silently switching membership filtering off for the whole
    /// roster. Leaving the genesis untouched means the old binary still elects
    /// it and still reads the frozen roster.
    #[tokio::test]
    async fn publish_recovery_key_leaves_the_v1_genesis_object_byte_identical() -> TestResult {
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let founder = store_over(bucket.clone(), SOLO_SEED)?;
        let alice = store_over(bucket.clone(), [6_u8; 32])?;
        let recovery = Sr25519Signer::from_seed_with_prefix(&[11_u8; 32], NetworkPrefix::HIPPIUS)?;
        let genesis_key = format!("{TEAM}/_manifest/{:020}", 0_u64);

        // A fresh provision: membership first, with no recovery key, so the
        // genesis is signed under the v1 domain and layout.
        founder
            .publish_membership(BTreeSet::from([
                founder.author.clone(),
                alice.author.clone(),
            ]))
            .await?;
        let genesis_before = bucket.get(&genesis_key).await?;

        founder
            .publish_recovery_key(recovery.verifying_key())
            .await?;

        assert_eq!(
            bucket.get(&genesis_key).await?,
            genesis_before,
            "the genesis object must not be rewritten by a recovery-key publish"
        );

        let genesis: TeamManifest = serde_json::from_slice(&genesis_before)?;
        assert_eq!(
            genesis.recovery_key, None,
            "the genesis names no recovery key, so its signed bytes stay on the v1 domain \
             (see manifest.rs's `recovery_free_manifest_is_bitwise_v1`) — a v1-only binary \
             verifies it byte for byte"
        );
        assert!(
            genesis.verify(),
            "the untouched genesis still verifies on its own"
        );
        assert_eq!(
            genesis.members,
            BTreeSet::from([founder.author.clone(), alice.author.clone()]),
            "an old binary reads the real roster from it — a frozen team, never an open one"
        );
        Ok(())
    }

    /// The replay attack the version-monotonic rule and the canonical-key
    /// binding exist to stop, driven entirely through the public store API.
    ///
    /// The founder names recovery key R1, then replaces it with R2. An
    /// attacker with WRITE-ONLY bucket access saved the object naming R1 and
    /// replays it under a key that lists ahead of every canonical one, then
    /// publishes their own manifest signed by the leaked R1.
    #[tokio::test]
    async fn a_retired_recovery_key_cannot_be_replayed_back_into_authority() -> TestResult {
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let founder = store_over(bucket.clone(), SOLO_SEED)?;
        let leaked = Sr25519Signer::from_seed_with_prefix(&[11_u8; 32], NetworkPrefix::HIPPIUS)?;
        let fresh = Sr25519Signer::from_seed_with_prefix(&[14_u8; 32], NetworkPrefix::HIPPIUS)?;

        founder
            .publish_membership(BTreeSet::from([founder.author.clone()]))
            .await?;
        let (naming_leaked, _) = founder.publish_recovery_key(leaked.verifying_key()).await?;
        let (naming_fresh, replaced) = founder.publish_recovery_key(fresh.verifying_key()).await?;

        assert_eq!(
            replaced,
            Some(leaked.verifying_key()),
            "the second call retires the first key"
        );
        assert_eq!(
            (naming_leaked.version, naming_fresh.version),
            (1, 2),
            "each recovery-key change is its own forward link, never an overwrite"
        );
        let saved = bucket
            .get(&format!("{TEAM}/_manifest/{:020}", naming_leaked.version))
            .await?;

        // The replay: the saved pre-retirement object under an attacker-chosen
        // key that sorts before every canonical zero-padded one.
        bucket.put(&format!("{TEAM}/_manifest/!a"), saved).await?;
        // The takeover: a manifest signed by the leaked key, at the next
        // version, self-consistent and validly signed.
        let takeover = TeamManifest::create_signed(
            &leaked,
            TEAM.to_string(),
            BTreeSet::from([leaked.author_ss58()]),
            naming_fresh.version.saturating_add(1),
        );
        publish_manifest(bucket.as_ref(), &takeover).await?;

        let live = load_manifest(bucket.as_ref(), TEAM, Some(&founder.author))
            .await?
            .ok_or("the founder's chain must still elect")?;
        assert_eq!(
            live.founder, founder.author,
            "a replayed pre-retirement manifest must not hand the team to the leaked key"
        );
        assert_eq!(
            live.trusted_recovery_key(),
            Some(&fresh.verifying_key()),
            "the retirement still governs after the replay"
        );
        assert!(
            !live.members.contains(&leaked.author_ss58()),
            "the takeover manifest never takes effect"
        );
        Ok(())
    }

    #[tokio::test]
    async fn publish_recovery_key_refuses_a_non_founder() -> TestResult {
        // A non-founder signer must never be able to name a recovery key —
        // that would let anyone with a store handle mint their own escape
        // hatch into someone else's team.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let founder = store_over(bucket.clone(), SOLO_SEED)?;
        let outsider = store_over(bucket.clone(), [6_u8; 32])?;
        let recovery = Sr25519Signer::from_seed_with_prefix(&[11_u8; 32], NetworkPrefix::HIPPIUS)?;

        founder
            .publish_membership(BTreeSet::from([founder.author.clone()]))
            .await?;

        let result = outsider
            .publish_recovery_key(recovery.verifying_key())
            .await;
        assert!(
            matches!(result, Err(MemError::Unauthorized(_))),
            "a non-founder must be refused: {result:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn publish_recovery_key_refuses_when_no_manifest_published() -> TestResult {
        // An open team (no membership manifest yet) has no live founder or
        // membership to attach a recovery key to.
        let founder = build_store()?;
        let recovery = Sr25519Signer::from_seed_with_prefix(&[11_u8; 32], NetworkPrefix::HIPPIUS)?;

        let result = founder.publish_recovery_key(recovery.verifying_key()).await;
        assert!(
            matches!(result, Err(MemError::ManifestUnavailable { .. })),
            "naming a recovery key on an open team must be refused: {result:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn publish_recovery_key_refuses_the_identity_point() -> TestResult {
        // I4: the type-level "no None" argument only means unrepresentable at
        // the Option layer — the identity point is still a legal
        // `VerifyingKey` bit pattern, so it needs its OWN runtime screen.
        let founder = build_store()?;
        founder
            .publish_membership(BTreeSet::from([founder.author.clone()]))
            .await?;

        let result = founder
            .publish_recovery_key(VerifyingKey::new([0_u8; 32]))
            .await;
        assert!(
            matches!(result, Err(MemError::Malformed(_))),
            "the identity point must never be nameable as a recovery key: {result:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn recover_founder_publishes_the_new_founder_at_the_next_version() -> TestResult {
        // The exact call the CLI's `recover` makes: given the seed matching
        // the live manifest's named recovery key, publish a fresh manifest —
        // signed by that recovery identity, who becomes the new founder — at
        // the next version, carrying members forward and naming a fresh
        // recovery key.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let founder = store_over(bucket.clone(), SOLO_SEED)?;
        let recovery = Sr25519Signer::from_seed_with_prefix(&[11_u8; 32], NetworkPrefix::HIPPIUS)?;
        let fresh_recovery =
            Sr25519Signer::from_seed_with_prefix(&[12_u8; 32], NetworkPrefix::HIPPIUS)?;

        founder
            .publish_membership(BTreeSet::from([founder.author.clone()]))
            .await?;
        founder
            .publish_recovery_key(recovery.verifying_key())
            .await?;

        // The recovering operator's OWN local store identity is irrelevant —
        // authority comes only from the `recovery_signer` argument, never
        // `self.signer`/`self.author`.
        let operator = store_over(bucket.clone(), [99_u8; 32])?;
        let recovered = operator
            .recover_founder(&recovery, fresh_recovery.verifying_key())
            .await?;

        // v0 membership, v1 the recovery-key naming, v2 the recovery itself:
        // every publish path is a forward link, so the versions simply count up.
        assert_eq!(
            recovered.version, 2,
            "recovery advances to the next version"
        );
        assert_eq!(recovered.founder, recovery.author_ss58());
        // `live.members` is carried forward, PLUS the recovery identity itself:
        // `create_signed_with_recovery` always inserts the signer (the new
        // founder) into members, so a recovered founder is never locked out of
        // their own team's roster.
        assert_eq!(
            recovered.members,
            BTreeSet::from([founder.author.clone(), recovery.author_ss58()]),
            "the old members are carried forward, and the new founder is a member too"
        );
        assert_eq!(
            recovered.trusted_recovery_key(),
            Some(&fresh_recovery.verifying_key()),
            "a fresh recovery key is named — the escape hatch never closes after one use"
        );

        let live = load_manifest(bucket.as_ref(), TEAM, None).await?;
        assert_eq!(
            live.as_ref().map(|m| m.version),
            Some(2),
            "load_manifest elects the recovered manifest as live"
        );
        Ok(())
    }

    #[tokio::test]
    async fn recover_founder_refuses_a_mismatched_seed() -> TestResult {
        // A seed that does not match the published recovery key must never
        // authorize a takeover.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let founder = store_over(bucket.clone(), SOLO_SEED)?;
        let recovery = Sr25519Signer::from_seed_with_prefix(&[11_u8; 32], NetworkPrefix::HIPPIUS)?;
        let impostor = Sr25519Signer::from_seed_with_prefix(&[13_u8; 32], NetworkPrefix::HIPPIUS)?;
        let fresh_recovery =
            Sr25519Signer::from_seed_with_prefix(&[12_u8; 32], NetworkPrefix::HIPPIUS)?;

        founder
            .publish_membership(BTreeSet::from([founder.author.clone()]))
            .await?;
        founder
            .publish_recovery_key(recovery.verifying_key())
            .await?;

        let operator = store_over(bucket, [99_u8; 32])?;
        let result = operator
            .recover_founder(&impostor, fresh_recovery.verifying_key())
            .await;
        assert!(
            matches!(result, Err(MemError::Unauthorized(_))),
            "a mismatched seed must be refused: {result:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn recover_founder_refuses_when_no_manifest_published() -> TestResult {
        let operator = build_store()?;
        let recovery = Sr25519Signer::from_seed_with_prefix(&[11_u8; 32], NetworkPrefix::HIPPIUS)?;
        let fresh_recovery =
            Sr25519Signer::from_seed_with_prefix(&[12_u8; 32], NetworkPrefix::HIPPIUS)?;

        let result = operator
            .recover_founder(&recovery, fresh_recovery.verifying_key())
            .await;
        assert!(
            matches!(result, Err(MemError::ManifestUnavailable { .. })),
            "recovering an open team must be refused: {result:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn recover_founder_refuses_the_identity_point_as_fresh_key() -> TestResult {
        // I4: mirrors `publish_recovery_key`'s identity-point screen — a
        // recovery that named the identity point as its NEXT recovery key
        // would leave the escape hatch standing open to anyone, which is the
        // exact hazard `trusted_recovery_key()`'s read-side screen exists to
        // keep out; refusing it here is what makes that premise actually true.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let founder = store_over(bucket.clone(), SOLO_SEED)?;
        let recovery = Sr25519Signer::from_seed_with_prefix(&[11_u8; 32], NetworkPrefix::HIPPIUS)?;

        founder
            .publish_membership(BTreeSet::from([founder.author.clone()]))
            .await?;
        founder
            .publish_recovery_key(recovery.verifying_key())
            .await?;

        let operator = store_over(bucket, [99_u8; 32])?;
        let result = operator
            .recover_founder(&recovery, VerifyingKey::new([0_u8; 32]))
            .await;
        assert!(
            matches!(result, Err(MemError::Malformed(_))),
            "the identity point must never be nameable as the fresh recovery key: {result:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn recover_founder_works_when_the_store_is_still_pinned_to_the_old_founder() -> TestResult
    {
        // The REALISTIC `recover` scenario: the operator's config still pins
        // `founder_ss58` to the OLD (now-lost) founder — nobody has re-pinned
        // it yet, which is exactly why `recover`'s printed banner insists on
        // it. The pin only fixes where the chain ANCHORS; the walk itself
        // must still elect the recovered manifest as live even under a stale
        // pin, both for `recover_founder` itself and for every reader after.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let founder = store_over(bucket.clone(), SOLO_SEED)?;
        let old_founder_ss58 = founder.author.clone();
        let recovery = Sr25519Signer::from_seed_with_prefix(&[11_u8; 32], NetworkPrefix::HIPPIUS)?;
        let fresh_recovery =
            Sr25519Signer::from_seed_with_prefix(&[12_u8; 32], NetworkPrefix::HIPPIUS)?;

        founder
            .publish_membership(BTreeSet::from([founder.author.clone()]))
            .await?;
        founder
            .publish_recovery_key(recovery.verifying_key())
            .await?;

        // The recovering operator's store is pinned to the OLD founder —
        // exactly what `cfg.build_store()` produces from an un-updated
        // config.
        let operator = store_over(bucket.clone(), [99_u8; 32])?
            .with_pinned_founder(Some(old_founder_ss58.clone()));
        let recovered = operator
            .recover_founder(&recovery, fresh_recovery.verifying_key())
            .await?;
        assert_eq!(recovered.founder, recovery.author_ss58());

        // A FRESH store, still pinned to the OLD founder, must still elect
        // the recovered manifest as live.
        let still_pinned_reader =
            store_over(bucket, [77_u8; 32])?.with_pinned_founder(Some(old_founder_ss58));
        let live = still_pinned_reader
            .membership_manifest()
            .await?
            .ok_or("the recovered manifest must load even under the stale pin")?;
        assert_eq!(live.founder, recovery.author_ss58());
        assert_eq!(
            live.version, 2,
            "v0 membership, v1 recovery key, v2 recovery"
        );
        Ok(())
    }

    #[tokio::test]
    async fn sync_prunes_removed_member_note_without_rebuild() -> TestResult {
        // Two authors share one bucket; the founder holds a long-lived (warm)
        // index across both syncs — there is no fresh `InMemoryIndex` rebuild.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let founder = store_over(bucket.clone(), SOLO_SEED)?;
        let alice = store_over(bucket.clone(), [6_u8; 32])?;

        // The founder opens the team to {F, A}; A remembers a note. After the
        // founder syncs, the warm index holds A's note.
        founder
            .publish_membership(BTreeSet::from([
                founder.author.clone(),
                alice.author.clone(),
            ]))
            .await?;
        let alice_note = alice.remember(sample_input()).await?;
        founder.sync().await?;
        assert!(
            founder.index.locate(alice_note)?.is_some(),
            "F sees A's note while A is a member"
        );

        // The founder removes A, then re-syncs the SAME store. Authoritative sync
        // must prune A's now-non-member note from the warm index — the regression
        // the old incremental sync could only fix with a cold rebuild.
        founder
            .publish_membership(BTreeSet::from([founder.author.clone()]))
            .await?;
        founder.sync().await?;
        assert!(
            founder.index.locate(alice_note)?.is_none(),
            "a removed member's note is pruned from the warm index on resync, no rebuild"
        );
        Ok(())
    }

    #[tokio::test]
    async fn sync_survives_non_founder_higher_version_manifest() -> TestResult {
        // The DoS fix (I1b): a planted, validly-signed higher-version manifest by
        // a non-founder must not break a member's sync.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let founder = store_over(bucket.clone(), SOLO_SEED)?;
        let member_note = founder.remember(sample_input()).await?;
        founder
            .publish_membership(BTreeSet::from([founder.author.clone()]))
            .await?;

        // An attacker self-signs a v1 manifest naming themselves founder and plants
        // it in the shared bucket. Pre-fix this made `load_manifest` ERROR, which
        // propagated through `sync` and broke EVERYONE.
        let attacker = Sr25519Signer::from_seed_with_prefix(&[9_u8; 32], NetworkPrefix::HIPPIUS)?;
        let v1 = TeamManifest::create_signed(&attacker, TEAM.to_owned(), BTreeSet::new(), 1);
        publish_manifest(bucket.as_ref(), &v1).await?;

        // Sync still succeeds (availability) and the genuine founder's note still
        // converges (the seizure is ignored, not honored).
        founder.sync().await?;
        assert!(
            founder.index.locate(member_note)?.is_some(),
            "the genuine founder's note survives a planted non-founder manifest"
        );
        Ok(())
    }

    #[tokio::test]
    async fn no_manifest_team_is_open() -> TestResult {
        // The backward-compatible / dogfood path: with NO manifest published, a
        // team is open, so an author not on any list still converges.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let a = store_over(bucket.clone(), SOLO_SEED)?;
        let b = store_over(bucket.clone(), [6_u8; 32])?;

        a.remember(sample_input()).await?;
        let b_note = b
            .remember(RememberInput {
                force: true,
                repo: RepoScope::Global,
                ..sample_input()
            })
            .await?;

        a.sync().await?;
        assert!(
            a.index.locate(b_note)?.is_some(),
            "with no manifest the team is open: an unlisted author's note still converges"
        );
        Ok(())
    }

    #[tokio::test]
    async fn non_founder_cannot_change_membership() -> TestResult {
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let founder = store_over(bucket.clone(), SOLO_SEED)?;
        let other = store_over(bucket.clone(), [6_u8; 32])?;

        founder
            .publish_membership(BTreeSet::from([founder.author.clone()]))
            .await?;

        // A non-founder may not publish a new membership manifest.
        let err = other
            .publish_membership(BTreeSet::from([
                founder.author.clone(),
                other.author.clone(),
            ]))
            .await
            .err()
            .ok_or("a non-founder must not change membership")?;
        assert!(format!("{err}").contains("founder"), "got: {err}");
        Ok(())
    }

    #[tokio::test]
    async fn members_reflects_published_manifest() -> TestResult {
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let founder = store_over(bucket.clone(), SOLO_SEED)?;
        assert!(
            founder.members().await?.is_empty(),
            "no manifest -> empty (open) member set"
        );

        founder
            .publish_membership(BTreeSet::from([founder.author.clone()]))
            .await?;
        let members = founder.members().await?;
        assert!(members.contains(&founder.author), "the founder is a member");
        assert_eq!(members.len(), 1, "exactly the founder is listed");
        Ok(())
    }

    #[tokio::test]
    async fn history_lists_ops_in_order() -> TestResult {
        let store = test_store()?;
        let id = store.remember(sample_input()).await?;
        store.forget(id).await?;

        let history = store.history(id).await?;
        assert_eq!(history.note_id, id);
        assert!(history.tombstoned, "a forgotten note is tombstoned");
        assert_eq!(history.entries.len(), 2, "one Remember + one Forget");
        assert_eq!(history.entries[0].kind, OpKindLabel::Remember);
        assert_eq!(history.entries[1].kind, OpKindLabel::Forget);
        assert!(
            history.entries[0].lamport < history.entries[1].lamport,
            "entries are in ascending Lamport order"
        );

        // I3: every entry surfaces the verifying key the signature checks against
        // — the cryptographic "who", matching this store's signing identity.
        let expected_key =
            Sr25519Signer::from_seed_with_prefix(&SOLO_SEED, NetworkPrefix::HIPPIUS)?
                .verifying_key();
        for entry in &history.entries {
            assert_eq!(
                entry.author_key, expected_key,
                "history must surface the op's signing key"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn history_includes_verifiable_anchor_proof() -> TestResult {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        // Threshold 1: every op anchors immediately, so the single op has a proof.
        let store = store_with(blob, SOLO_SEED, Arc::new(RecordingAnchor::new()), 1)?;
        let id = store.remember(sample_input()).await?;

        let history = store.history(id).await?;
        assert_eq!(history.entries.len(), 1);
        let entry = &history.entries[0];
        let anchor = entry
            .anchor
            .as_ref()
            .ok_or("an op anchored at threshold 1 must carry a proof")?;
        // THE accountability check: the op's inclusion in the anchored root is
        // cryptographically provable with no trust in this store.
        assert!(
            verify_proof(anchor.root, entry.op_hash, &anchor.proof),
            "the inclusion proof must verify against the anchored root"
        );
        Ok(())
    }

    #[tokio::test]
    async fn history_unanchored_op_has_no_proof() -> TestResult {
        // The default store never reaches its anchor threshold, so the op stays
        // pending and its history entry carries no proof.
        let store = test_store()?;
        let id = store.remember(sample_input()).await?;

        let history = store.history(id).await?;
        assert_eq!(history.entries.len(), 1);
        assert!(
            history.entries[0].anchor.is_none(),
            "a below-threshold op is pending and has no anchor proof"
        );
        Ok(())
    }

    #[tokio::test]
    async fn history_includes_links() -> TestResult {
        // link(a, b) records a Link op convergence folds into a's link set;
        // history makes that grow-only graph readable.
        let store = test_store()?;
        let a = store.remember(sample_input()).await?;
        let b = store
            .remember(RememberInput {
                force: true,
                repo: RepoScope::Global,
                ..sample_input()
            })
            .await?;
        store.link(a, b).await?;

        let a_history = store.history(a).await?;
        assert!(
            a_history.links.contains(&b),
            "a's history surfaces the link to b: {:?}",
            a_history.links
        );
        let b_history = store.history(b).await?;
        assert!(
            b_history.links.is_empty(),
            "b has no outgoing links: {:?}",
            b_history.links
        );
        Ok(())
    }

    #[tokio::test]
    async fn unknown_note_history_is_empty() -> TestResult {
        // Documented choice: an id with no ops yields an empty history, not an
        // error — `history` reads the op-log, not the index.
        let store = test_store()?;
        let history = store.history(NoteId::new()).await?;
        assert!(history.entries.is_empty(), "no ops -> no entries");
        assert!(!history.tombstoned, "an absent note is not tombstoned");
        Ok(())
    }

    fn arb_note_type() -> impl Strategy<Value = NoteType> {
        prop_oneof![
            Just(NoteType::Decision),
            Just(NoteType::Convention),
            Just(NoteType::Gotcha),
            Just(NoteType::Reference),
            Just(NoteType::Context),
        ]
    }

    fn arb_repo() -> impl Strategy<Value = RepoScope> {
        prop_oneof![
            Just(RepoScope::Global),
            // Repo names restricted to safe object-key components, and `global`
            // is filtered out because it is reserved for the team-global scope.
            "[a-z]{1,12}"
                .prop_filter("'global' is reserved", |name: &String| name.as_str()
                    != "global")
                .prop_map(RepoScope::Repo),
        ]
    }

    fn arb_input() -> impl Strategy<Value = RememberInput> {
        (
            arb_note_type(),
            arb_repo(),
            proptest::collection::btree_set("[a-z]{1,8}", 0..4),
            // A VALID one-line summary: non-blank (it ends in an alphanumeric),
            // control-character-free, and well under `MAX_SUMMARY_CHARS`, so the
            // ingestion validation never rejects a generated case. Exhaustive
            // summary-validation edge cases live in
            // `validate_summary_agrees_with_its_contract`; the body stays
            // unbounded (`.*`).
            "[a-zA-Z0-9 ]{0,199}[a-zA-Z0-9]",
            ".*",
        )
            .prop_map(|(note_type, repo, tags, summary, body)| RememberInput {
                force: true,
                note_type,
                repo,
                tags,
                summary,
                body,
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        /// For an arbitrary input, `get(remember(input))` yields a note equal in
        /// body/summary/tags/type to the input. The async path is driven by a
        /// per-case current-thread tokio runtime built inside the closure
        /// (proptest needs a synchronous body); the `MemoryBlobStore` ops are
        /// trivial, so a single-threaded runtime is sufficient.
        #[test]
        fn remember_get_round_trips(input in arb_input()) {
            let outcome: Result<(Note, RememberInput), MemError> = (|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .build()
                    .map_err(MemError::from)?;
                let store = build_store()?;
                let expected = input.clone();
                let note = runtime.block_on(async {
                    let id = store.remember(input).await?;
                    store.get(id).await
                })?;
                Ok((note, expected))
            })();

            let (note, expected) =
                outcome.map_err(|e| proptest::test_runner::TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(note.body, expected.body);
            prop_assert_eq!(note.summary, expected.summary);
            prop_assert_eq!(note.tags, expected.tags);
            prop_assert_eq!(note.note_type, expected.note_type);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// `validate_summary` accepts a summary EXACTLY when it is non-blank after
        /// trimming, free of control characters, and within the cap. This asserts
        /// agreement with that reference predicate. The generator is a `Vec<char>`
        /// of length `0..600`, deliberately NOT `any::<String>()`: proptest's
        /// default `String` strategy is `\PC*` capped at 32 chars, which would
        /// never draw a control character or a string near `MAX_SUMMARY_CHARS`
        /// (512) — so it would exercise NEITHER the control-char nor the
        /// over-length branch. `any::<char>()` draws the full scalar range
        /// (control chars and newlines included) and `0..600` spans the 512 cap,
        /// so every branch is covered and the shrinker catches a future edit that
        /// drops or reorders a check.
        #[test]
        fn validate_summary_agrees_with_its_contract(
            s in proptest::collection::vec(any::<char>(), 0..600).prop_map(String::from_iter),
        ) {
            let valid = !s.trim().is_empty()
                && !s.chars().any(char::is_control)
                && s.chars().count() <= MAX_SUMMARY_CHARS;
            prop_assert_eq!(validate_summary(&s).is_ok(), valid);
        }
    }
}
