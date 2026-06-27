//! Storage seams plus the [`MemoryStore`] that composes them.
//!
//! [`blob`] is the object store; the hybrid index lives in [`crate::index`].
//! [`MemoryStore`] wires crypto + blob store + index + the signed op-log into the
//! memory operations the rest of the system drives: `remember`, `recall`, `get`,
//! `forget`, `link`, and `sync`. Every mutation appends a signed op to the shared
//! op-log; `sync` re-converges that log and rebuilds the local index from it, so
//! the op-log — not a blob listing — is the source of truth a machine replays.

pub mod blob;
pub mod snapshot;

pub use blob::{BlobStore, MemoryBlobStore, S3BlobStore};
pub use snapshot::{IndexSnapshot, load_latest_snapshot, save_snapshot};

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::audit::anchor::{AnchorReceipt, AnchorRef, AuditAnchor, BatchMeta};
use crate::audit::batch::{AnchorRecord, persist_anchor_record, read_anchor_records};
use crate::audit::merkle::{MerkleProof, inclusion_proof, merkle_root};
use crate::audit::reconcile::ReconcileReport;
use crate::crypto::{SecretKey, content_hash, open, seal};
use crate::domain::{Blake3Hash, Note, NoteId, NoteType, RepoScope, Scope, Ss58, Timestamp};
use crate::error::MemError;
use crate::identity::{Identity, TeamManifest, fetch_team_key, load_manifest, publish_manifest};
use crate::index::{IndexRecord, MemoryIndex, Query, SearchResult};
use crate::objkey::object_key;
use crate::oplog::{
    GENESIS_PREV, NotePointer, Op, OpContent, OpKind, OpLogStore, Signer, VerifyingKey, converge,
    lamport_tip,
};

/// Phase 1 writes every note as revision 1.
///
/// Editing a note (revision > 1) is a later task, so the revision is a fixed
/// constant here rather than a field threaded through [`RememberInput`].
const PHASE1_REVISION: u32 = 1;

/// What to remember: the caller-supplied half of a new note.
///
/// Identity, timestamps, author, and scope-team are filled in by
/// [`MemoryStore::remember`]; the caller provides only the knowledge itself.
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
    /// A directed link was asserted from this note ([`OpKind::Link`]).
    Link,
}

impl OpKindLabel {
    /// The stable wire string for this label.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Remember => "Remember",
            Self::Edit => "Edit",
            Self::Forget => "Forget",
            Self::Link => "Link",
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
            OpKind::Link { .. } => Self::Link,
        }
    }
}

/// A Merkle inclusion proof binding one op to an anchored root.
///
/// [`verify_proof`](crate::audit::merkle::verify_proof)`(root, op_hash, &proof)`
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
/// [`NoopAnchor`]: crate::audit::anchor::NoopAnchor
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
    /// [`verify_proof`](crate::audit::merkle::verify_proof).
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
    /// Whether the note's latest lifecycle op is a `Forget` (per [`converge`]).
    pub tombstoned: bool,
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

/// An owned snapshot of pending leaves taken under the lock, anchored only after
/// the guard is dropped — so no lock is ever held across the anchor/persist
/// `.await` (the `await_holding_lock` lint, axiom `rust_quality_74`).
struct DrainedBatch {
    /// The monotonic sequence number reserved for this batch.
    seq: u64,
    /// The batch's leaves in op-append (Lamport) order.
    leaves: Vec<PendingLeaf>,
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
        }
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
    /// [`MemError::Storage`] naming the missing epoch when no key for `epoch` is in
    /// the ring (the caller is not provisioned to read notes from that epoch).
    fn key_for_epoch(&self, epoch: u64) -> Result<SecretKey, MemError> {
        let guard = self.keys.lock().unwrap_or_else(PoisonError::into_inner);
        match guard.get(&epoch) {
            Some(key) => Ok(SecretKey::from_bytes(*key.expose_bytes())),
            None => Err(MemError::Storage(format!(
                "no key for epoch {epoch} — not provisioned to this member"
            ))),
        }
    }

    /// Fetch and add the team key for each requested epoch this member can unwrap.
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
        team: &str,
        epochs: &[u64],
    ) -> Result<usize, MemError> {
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
    /// Returns [`MemError::Crypto`] if sealing fails, [`MemError::Storage`] if
    /// the object key is invalid or the blob/op write fails, [`MemError::Serialize`]
    /// if the op cannot be encoded, or any error the index reports while upserting.
    pub async fn remember(&self, input: RememberInput) -> Result<NoteId, MemError> {
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
        // Derive the object key BEFORE sealing: it is the AEAD associated data,
        // so the ciphertext is cryptographically bound to the identity it is
        // stored under (see `crypto::seal`'s threat model — defeats a gateway
        // relocating note A's bytes onto note B's key).
        let key = object_key(&scope, id, PHASE1_REVISION)?;
        let ciphertext = seal(&seal_key, json.as_bytes(), key.as_bytes())?;
        let cid = content_hash(&ciphertext);

        // Step 1 — the body lands first, so the op minted next never names an
        // unwritten blob.
        self.blob.put(&key, ciphertext).await?;

        // Step 2 — mint the signed `Remember` op and durably append it under the
        // writer lock, advancing the clock only once the append lands. `op.lamport`
        // is the convergence clock this write was assigned; `epoch` is the key
        // epoch the blob was sealed under.
        let op = self
            .mint_and_append(OpKind::Remember, id, key.clone(), cid, epoch)
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
        })?;

        // Step 4 — buffer the op's leaf for batched Merkle anchoring. Best-effort
        // and last: the op is already durable in the log, so a failed anchor is
        // logged and retried, never failing this write.
        self.schedule_anchor(op.hash(), op.lamport).await;
        Ok(id)
    }

    /// Mint a signed op for `kind`/`note_id`, durably append it, and only then
    /// advance the convergence clock. Returns the appended [`Op`].
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
    /// # Errors
    ///
    /// Whatever [`OpLogStore::append`] reports ([`MemError::Serialize`] /
    /// [`MemError::Storage`]); on error the clock is left untouched.
    async fn mint_and_append(
        &self,
        kind: OpKind,
        note_id: NoteId,
        object_key: String,
        cid: Blake3Hash,
        key_epoch: u64,
    ) -> Result<Op, MemError> {
        let mut clock = self.writer.lock().await;
        let lamport = clock.lamport_tip.saturating_add(1);
        let op = Op::create_signed(
            self.signer.as_ref(),
            OpContent {
                op_id: Ulid::new(),
                lamport,
                key_epoch,
                kind,
                note_id,
                object_key,
                cid,
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
        self.index.search(&query)
    }

    /// Hydrate the full [`Note`] behind `id`: locate, fetch, verify, decrypt.
    ///
    /// # Errors
    ///
    /// Returns [`MemError::NotFound`] if `id` is not indexed, [`MemError::Storage`]
    /// if the note's key epoch is not in this store's key-ring ("no key for epoch
    /// …" — this member was never provisioned that epoch) or the fetched ciphertext
    /// does not match the indexed content hash, [`MemError::Crypto`] if decryption
    /// or UTF-8 decoding fails, or [`MemError::Serialize`] if the decrypted JSON is
    /// not a valid note.
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
        Ok(Note::from_json(json)?)
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
                OpKind::Forget,
                note_id,
                located.object_key,
                located.cid,
                located.key_epoch,
            )
            .await?;
        self.index.remove(note_id)?;
        self.schedule_anchor(op.hash(), op.lamport).await;
        Ok(())
    }

    /// Assert a directed link from `from` to `to` by appending a signed
    /// `Link { to }` op.
    ///
    /// Links feed convergence and the history/graph view, *not* recall ranking in
    /// Phase 2, so there is no index change here — the link surfaces only after a
    /// later layer reads the converged link set. The op is stamped with `from`'s
    /// current object key and content hash (from the index); `from` must therefore
    /// be a note this machine knows, else [`MemError::NotFound`].
    ///
    /// # Errors
    ///
    /// [`MemError::NotFound`] if `from` is not indexed; [`MemError::Serialize`] /
    /// [`MemError::Storage`] if the op cannot be encoded or appended.
    pub async fn link(&self, from: NoteId, to: NoteId) -> Result<(), MemError> {
        let located = self.index.locate(from)?.ok_or_else(|| MemError::NotFound {
            id: from.to_string(),
        })?;
        let op = self
            .mint_and_append(
                OpKind::Link { to },
                from,
                located.object_key,
                located.cid,
                located.key_epoch,
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
    /// root via [`verify_proof`](crate::audit::merkle::verify_proof). That is
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
        let note_ops: Vec<Op> = ops.into_iter().filter(|op| op.note_id == note_id).collect();
        let tombstoned = converge(&note_ops)
            .get(&note_id)
            .is_some_and(|state| state.tombstoned);

        let records = read_anchor_records(&self.blob, &self.team).await?;
        let mut entries = Vec::with_capacity(note_ops.len());
        for op in &note_ops {
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
                anchor: anchor_proof_for(&records, op_hash)?,
            });
        }
        Ok(NoteHistory {
            note_id,
            tombstoned,
            entries,
        })
    }

    /// Reconcile this team's visible op-log against its anchored Merkle roots.
    ///
    /// Convenience over [`crate::audit::reconcile::reconcile`] for the common
    /// case of checking *this* store's own team and bucket: it cross-references
    /// every anchored leaf against the visible op-log and reports any anchored op
    /// that has gone missing (suppression) or any anchor record whose root
    /// disagrees with its leaves (forgery). It detects suppression only of ops
    /// that were actually anchored — an op dropped before its batch anchored
    /// leaves no commitment to reconcile against (see the module docs).
    ///
    /// # Errors
    ///
    /// Propagates whatever [`crate::audit::reconcile::reconcile`] reports — a
    /// backend listing/fetch failure, an undecodable anchor record, or an op-log
    /// integrity violation from the verified read.
    pub async fn reconcile(&self) -> Result<ReconcileReport, MemError> {
        crate::audit::reconcile::reconcile(&self.blob, &self.oplog, &self.team).await
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
        let leaves: Vec<Blake3Hash> = batch.leaves.iter().map(|leaf| leaf.hash).collect();
        let root = merkle_root(&leaves);
        let meta = BatchMeta {
            team: self.team.clone(),
            first_lamport: batch.leaves.first().map_or(0, |leaf| leaf.lamport),
            last_lamport: batch.leaves.last().map_or(0, |leaf| leaf.lamport),
            op_count: leaves.len(),
        };

        let receipt = match self.anchor.anchor(root, meta.clone()).await {
            Ok(receipt) => receipt,
            Err(err) => {
                self.restore_pending(batch);
                return Err(err);
            }
        };

        let record = AnchorRecord {
            seq: batch.seq,
            author_key: self.author_key(),
            root,
            meta,
            leaves,
            receipt: receipt.clone(),
        };
        if let Err(err) = persist_anchor_record(&self.blob, &self.team, &record).await {
            self.restore_pending(batch);
            return Err(err);
        }
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
        let members_view = self.read_and_filter().await?;
        // The snapshot envelope is sealed under the current epoch's key (see
        // [`MemoryStore::snapshot`]). A member lacking that key cannot open the
        // checkpoint, so skip the fast path and fall back to a full replay — which
        // decodes each note under its OWN epoch key and skips any it cannot read.
        let snapshot = match self.key_for_epoch(self.current_epoch()) {
            Ok(key) => load_latest_snapshot(self.blob.as_ref(), &key, &self.team).await?,
            Err(_) => None,
        };
        match snapshot {
            Some(snapshot) => self.sync_incremental(snapshot, members_view).await,
            None => self.replay_full(members_view).await,
        }
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
    async fn read_and_filter(&self) -> Result<Vec<Op>, MemError> {
        let ops = self.oplog.read_all(&self.team).await?;

        // Scoped so the writer guard drops before any async work below, keeping the
        // critical section to the synchronous re-seed.
        {
            let mut clock = self.writer.lock().await;
            clock.lamport_tip = lamport_tip(&ops);
            clock.my_last_hash = ops
                .iter()
                .rev()
                .find(|op| op.author == self.author)
                .map_or(GENESIS_PREV, Op::hash);
        }

        let manifest = load_manifest(self.blob.as_ref(), &self.team).await?;
        let members_view = match &manifest {
            Some(manifest) => ops
                .into_iter()
                .filter(|op| manifest.members.contains(&op.author))
                .collect::<Vec<Op>>(),
            None => ops,
        };
        Ok(members_view)
    }

    /// Rebuild the index from scratch over `members_view`: converge, prune to the
    /// live set, then decode + upsert every live note. The cold-start path (no
    /// snapshot) and the safety-valve fallback when a snapshot cannot be trusted.
    async fn replay_full(&self, members_view: Vec<Op>) -> Result<usize, MemError> {
        let converged = converge(&members_view);

        // Authoritative prune: the index must end up reflecting ONLY the
        // currently-live converged set, so drop everything else from the (possibly
        // warm) index BEFORE the upserts. A note is live iff it is not tombstoned
        // AND has a content pointer to hydrate.
        let live_ids: BTreeSet<NoteId> = converged
            .iter()
            .filter(|(_, state)| !state.tombstoned && state.pointer.is_some())
            .map(|(note_id, _)| *note_id)
            .collect();
        self.index.retain(&live_ids)?;

        let mut indexed = 0_usize;
        for (note_id, state) in &converged {
            if state.tombstoned {
                continue;
            }
            let Some(pointer) = state.pointer.as_ref() else {
                continue;
            };
            indexed += self.decode_and_upsert(*note_id, pointer).await?;
        }
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
        members_view: Vec<Op>,
    ) -> Result<usize, MemError> {
        let baseline = snapshot.last_lamport;
        let (base, tail): (Vec<Op>, Vec<Op>) = members_view
            .into_iter()
            .partition(|op| op.lamport <= baseline);

        // Safety valve: re-converge the current base and require it to still equal
        // the snapshot's live set, keyed by note id -> (winning lamport, object
        // key). A late op or membership drift makes them disagree, invalidating the
        // tail-only shortcut -> full rebuild over the reunited op set.
        let converged_base = converge(&base);
        let base_live: BTreeMap<NoteId, (u64, &str)> = converged_base
            .iter()
            .filter_map(|(note_id, state)| {
                if state.tombstoned {
                    return None;
                }
                state
                    .pointer
                    .as_ref()
                    .map(|pointer| (*note_id, (pointer.lamport, pointer.object_key.as_str())))
            })
            .collect();
        let snapshot_live: BTreeMap<NoteId, (u64, &str)> = snapshot
            .records
            .iter()
            .map(|record| (record.note_id, (record.lamport, record.object_key.as_str())))
            .collect();
        if base_live != snapshot_live {
            tracing::warn!(
                team = %self.team,
                baseline,
                "index snapshot no longer matches the converged base (late op or membership change); falling back to a full rebuild"
            );
            let members_view: Vec<Op> = base.into_iter().chain(tail).collect();
            return self.replay_full(members_view).await;
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

        // Final live set = snapshot ids, minus what the tail removed, plus what the
        // tail (re-)added — exactly the set a full converge would prune to.
        let mut final_live: BTreeSet<NoteId> = snapshot
            .records
            .iter()
            .map(|record| record.note_id)
            .collect();
        for note_id in &tail_dead {
            final_live.remove(note_id);
        }
        for note_id in tail_live.keys() {
            final_live.insert(*note_id);
        }
        self.index.retain(&final_live)?;

        let mut indexed = 0_usize;
        // Restore the pre-decoded snapshot records that are still live and were not
        // superseded by a tail edit — no blob I/O; the index re-embeds the stored
        // summary.
        for record in &snapshot.records {
            if final_live.contains(&record.note_id) && !tail_live.contains_key(&record.note_id) {
                // Mirror `decode_pointer`'s epoch gate. A member can take this fast
                // path because they hold the CURRENT epoch (the snapshot envelope's
                // seal key), yet a pre-rotation record may be sealed under an OLDER
                // epoch this member was never provisioned. Indexing it would surface
                // a summary the member cannot `get` AND diverge from the full-replay
                // path, which skips it via `decode_pointer`. Skip-with-warn here too
                // so both paths reach byte-identical index state.
                if self.key_for_epoch(record.key_epoch).is_err() {
                    tracing::warn!(
                        team = %self.team,
                        note_id = %record.note_id,
                        key_epoch = record.key_epoch,
                        "skipping snapshot record whose epoch key is absent from this member's ring"
                    );
                    continue;
                }
                self.index.upsert(record.clone())?;
                indexed += 1;
            }
        }
        // Decode + upsert only the notes the tail touched: the incremental win is
        // that the unchanged base notes above were restored without any blob fetch.
        for (note_id, pointer) in &tail_live {
            indexed += self.decode_and_upsert(*note_id, pointer).await?;
        }
        Ok(indexed)
    }

    /// Decode the blob behind `pointer` and upsert the resulting record. Returns
    /// `1` when a record was indexed, `0` when a per-note data fault (an unreadable
    /// blob) was logged and skipped.
    ///
    /// The upsert is here, not inside [`MemoryStore::decode_pointer`], so a decode
    /// failure (bad blob -> skip) stays distinct from an upsert failure (the index
    /// rejecting a good record -> propagate and fail fast).
    async fn decode_and_upsert(
        &self,
        note_id: NoteId,
        pointer: &NotePointer,
    ) -> Result<usize, MemError> {
        match self.decode_pointer(note_id, pointer).await {
            Ok(record) => {
                self.index.upsert(record)?;
                Ok(1)
            }
            Err(err) => {
                tracing::warn!(
                    note_id = %note_id,
                    object_key = %pointer.object_key,
                    error = %err,
                    "skipping note whose blob could not be decoded during sync"
                );
                Ok(0)
            }
        }
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
                Ok(record) => records.push(record),
                Err(err) => tracing::warn!(
                    note_id = %note_id,
                    object_key = %pointer.object_key,
                    error = %err,
                    "skipping note whose blob could not be decoded while building a snapshot"
                ),
            }
        }

        let snapshot = IndexSnapshot {
            team: self.team.clone(),
            last_lamport,
            records,
        };
        // Seal the checkpoint envelope under the current epoch's key. A restorer
        // needs that key to use the fast path; one without it falls back to a full
        // replay (see [`MemoryStore::sync`]). The per-note records inside were each
        // decoded under their own epoch key by `decode_pointer` above.
        let envelope_key = self.key_for_epoch(self.current_epoch())?;
        save_snapshot(self.blob.as_ref(), &envelope_key, &snapshot).await?;
        Ok(last_lamport)
    }

    /// Publish a new membership manifest for this store's team, with the local
    /// signer acting as founder.
    ///
    /// Only the founder may change membership: if a manifest already exists, this
    /// signer must be its founder (else [`MemError::Storage`]), and the new
    /// manifest takes the next version. If NO manifest exists, this signer
    /// becomes the founder at version 0 — claiming a previously open team. The
    /// founder is always inserted into `members` by
    /// [`TeamManifest::create_signed`], so a founder cannot lock themselves out.
    ///
    /// After this returns, a subsequent [`MemoryStore::sync`] (on this or any
    /// teammate's store) converges only members' ops.
    ///
    /// # Errors
    ///
    /// [`MemError::Storage`] if a manifest exists and this signer is not its
    /// founder, or whatever [`load_manifest`] / [`publish_manifest`] report
    /// (storage, deserialization, or founder-consistency failures).
    pub async fn publish_membership(&self, members: BTreeSet<Ss58>) -> Result<(), MemError> {
        let current = load_manifest(self.blob.as_ref(), &self.team).await?;
        let next_version = match &current {
            Some(manifest) => {
                if manifest.founder != self.author {
                    return Err(MemError::Storage(format!(
                        "only the team founder may change membership: {:?} is not founder {:?}",
                        self.author.as_str(),
                        manifest.founder.as_str(),
                    )));
                }
                manifest.version.saturating_add(1)
            }
            None => 0,
        };
        let manifest = TeamManifest::create_signed(
            self.signer.as_ref(),
            self.team.clone(),
            members,
            next_version,
        );
        publish_manifest(self.blob.as_ref(), &manifest).await
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
        Ok(load_manifest(self.blob.as_ref(), &self.team)
            .await?
            .map(|manifest| manifest.members)
            .unwrap_or_default())
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
        // skip-with-warn path of `decode_and_upsert` / `snapshot`.
        let key = self.key_for_epoch(pointer.key_epoch)?;
        let ciphertext = self.blob.get(&pointer.object_key).await?;
        let cid = content_hash(&ciphertext);
        // The object key is the AEAD associated data, so a blob relocated under a
        // foreign key fails authentication here and is skipped, never indexed under
        // the wrong identity.
        let plaintext = open(&key, &ciphertext, pointer.object_key.as_bytes())?;
        let json = std::str::from_utf8(&plaintext).map_err(|_| MemError::Crypto)?;
        let note = Note::from_json(json)?;

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
            tags: note.tags,
            summary: note.summary,
        })
    }
}

/// Find the anchored batch covering `op_hash` and build its inclusion proof.
///
/// The op's hash is its Merkle leaf, stored verbatim in [`AnchorRecord::leaves`]
/// in op-append order — the same order the tree was built over — so the leaf's
/// position in that slice is exactly the index [`inclusion_proof`] needs.
/// Returns `Ok(None)` when no record covers the op (still pending anchoring).
fn anchor_proof_for(
    records: &[AnchorRecord],
    op_hash: Blake3Hash,
) -> Result<Option<AnchorProof>, MemError> {
    for record in records {
        let Some(index) = record.leaves.iter().position(|leaf| *leaf == op_hash) else {
            continue;
        };
        let proof = inclusion_proof(&record.leaves, index)?;
        return Ok(Some(AnchorProof {
            root: record.root,
            reference: record.receipt.reference.clone(),
            proof,
        }));
    }
    Ok(None)
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

    use super::{MemoryStore, OpKindLabel, RecallInput, RememberInput};
    use crate::audit::anchor::{
        AnchorReceipt, AuditAnchor, BatchMeta, NoopAnchor, RecordingAnchor,
    };
    use crate::audit::batch::read_anchor_records;
    use crate::audit::merkle::verify_proof;
    use crate::crypto::{SecretKey, open};
    use crate::domain::{Blake3Hash, Note, NoteId, NoteType, RepoScope, Scope, Timestamp};
    use crate::error::MemError;
    use crate::identity::{TeamManifest, publish_manifest};
    use crate::index::{
        HashEmbedder, InMemoryIndex, IndexRecord, Located, MemoryIndex, Query, SearchResult,
    };
    use crate::oplog::{Op, OpKind, OpLogStore, Signer, Sr25519Signer};
    use crate::store::blob::{BlobStore, MemoryBlobStore};
    use proptest::prelude::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

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
        let signer: Arc<dyn Signer> = Arc::new(Sr25519Signer::from_seed_with_prefix(seed, 42)?);
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
        let signer: Arc<dyn Signer> = Arc::new(Sr25519Signer::from_seed_with_prefix(seed, 42)?);
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
            note_type: NoteType::Gotcha,
            repo: RepoScope::Repo("thebrain".to_string()),
            tags: BTreeSet::from(["async".to_string(), "tokio".to_string()]),
            summary: "select drops the losing branch future".to_string(),
            body: format!(
                "Under tokio::select! the unpicked branch is dropped, so a {BODY_MARKER} unless partial state lives in the receiver."
            ),
        }
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
        let foreign_key = format!("{TEAM}/global/{}/rev_1", NoteId::new());
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
        let signer: Arc<dyn Signer> =
            Arc::new(Sr25519Signer::from_seed_with_prefix(SOLO_SEED, 42)?);
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

    #[tokio::test]
    async fn memorystore_derives_author_from_signer() -> TestResult {
        // The store no longer takes a separate (mismatchable) author: it derives one
        // from its signer, so a remembered op's `author` is exactly the signer's
        // SS58 — structurally bound to the signing key, not self-asserted.
        let store = build_store()?;
        store.remember(sample_input()).await?;

        let ops = store.oplog.read_all(TEAM).await?;
        let op = ops.first().ok_or("expected one op")?;
        let expected = Sr25519Signer::from_seed_with_prefix(SOLO_SEED, 42)?.author_ss58();
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
        // A note indexed at an epoch the ring lacks: `get` must surface the clear
        // "no key for epoch" storage error, not a panic or an opaque crypto error.
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
        })?;

        match store.get(id).await {
            Err(MemError::Storage(message)) => {
                assert!(
                    message.contains("no key for epoch 99"),
                    "expected a clear missing-epoch error, got: {message}"
                );
            }
            Err(other) => return Err(format!("expected Storage, got {other:?}").into()),
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
    }

    fn note_input(summary: &str, repo: &str) -> RememberInput {
        RememberInput {
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
        assert!(baseline > 0, "the snapshot covers a non-trivial Lamport tip");

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
        let attacker = Sr25519Signer::from_seed_with_prefix([9_u8; 32], 42)?;
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
        let expected_key = Sr25519Signer::from_seed_with_prefix(SOLO_SEED, 42)?.verifying_key();
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
            ".*",
            ".*",
        )
            .prop_map(|(note_type, repo, tags, summary, body)| RememberInput {
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
}
