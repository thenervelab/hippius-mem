//! Storage seams plus the [`MemoryStore`] that composes them.
//!
//! [`blob`] is the object store; the hybrid index lives in [`crate::index`].
//! [`MemoryStore`] wires crypto + blob store + index + the signed op-log into the
//! memory operations the rest of the system drives: `remember`, `recall`, `get`,
//! `forget`, `link`, and `sync`. Every mutation appends a signed op to the shared
//! op-log; `sync` re-converges that log and rebuilds the local index from it, so
//! the op-log — not a blob listing — is the source of truth a machine replays.

pub mod blob;

pub use blob::{BlobStore, MemoryBlobStore, S3BlobStore};

use std::collections::BTreeSet;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use ulid::Ulid;

use crate::crypto::{SecretKey, content_hash, open, seal};
use crate::domain::{Blake3Hash, Note, NoteId, NoteType, RepoScope, Scope, Ss58, Timestamp};
use crate::error::MemError;
use crate::index::{IndexRecord, MemoryIndex, Query, SearchResult};
use crate::objkey::object_key;
use crate::oplog::{
    GENESIS_PREV, NotePointer, Op, OpContent, OpKind, OpLogStore, Signer, converge, lamport_tip,
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

/// The cached head of this author's op-log, advanced under [`MemoryStore::clock`].
///
/// Caching the tip avoids re-reading and re-verifying the whole op-log on every
/// write just to learn the next Lamport value and the predecessor hash to chain
/// to. The two fields move together: a new op takes `lamport_tip + 1` and chains
/// to `my_last_hash`, then both advance to that op. [`MemoryStore::sync`]
/// recomputes the pair from the durable log, so a write that fails to append (or
/// a concurrent fork) is healed on the next sync rather than corrupting the chain
/// forever.
struct OpClock {
    /// Highest Lamport value this store has issued or observed.
    lamport_tip: u64,
    /// [`Op::hash`] of this author's most recent op — the next op's `prev_op_hash`.
    my_last_hash: Blake3Hash,
}

/// The core memory store: crypto + blob store + index + signed op-log behind one
/// team identity.
///
/// One `MemoryStore` is bound to a single team (the shared namespace), its
/// encryption key, and the local developer's author identity. Every method takes
/// `&self`: the blob store, index, and op-log carry their own interior
/// mutability, and the only lock `MemoryStore` itself holds — [`MemoryStore::clock`]
/// — is never held across an `.await`, so the store stays cheap to share behind an
/// `Arc` across tasks.
///
/// Invariant: `author` is the SS58 of `signer`'s identity — both come from the
/// same configured key — so `sync` can recover this author's chain head by
/// matching `op.author == self.author`.
pub struct MemoryStore {
    blob: Arc<dyn BlobStore>,
    index: Arc<dyn MemoryIndex>,
    // The shared, append-only signed op-log over the same blob backend. Each
    // mutation appends one signed op here; `sync` replays it.
    oplog: OpLogStore,
    // This store's signing identity. Behind `Arc<dyn Signer>` so an HSM/remote
    // signer can be swapped in without touching the store.
    signer: Arc<dyn Signer>,
    // The team encryption key. Owned, never cloned: `SecretKey` deliberately is
    // not `Clone`, so the bytes live in exactly one place.
    key: SecretKey,
    // The shared namespace every note in this store belongs to.
    team: String,
    // This developer's on-chain identity, stamped as the author of every note
    // this store writes (and consistent with `signer`'s identity).
    author: Ss58,
    // The convergence-clock cache. A plain `std::sync::Mutex` (not
    // `tokio::sync::Mutex`): the guard is only ever held across synchronous
    // op-minting, never across an `.await`, so it cannot make a future `!Send`.
    clock: Mutex<OpClock>,
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
    /// sealing notes under `key` for team `team`, attributing each to `author`.
    ///
    /// The clock starts empty (Lamport tip 0, predecessor [`GENESIS_PREV`]); the
    /// first [`MemoryStore::sync`] or write seeds it from the op-log. `author`
    /// must match `signer`'s identity (see the type invariant).
    #[must_use]
    pub fn new(
        blob: Arc<dyn BlobStore>,
        index: Arc<dyn MemoryIndex>,
        oplog: OpLogStore,
        signer: Arc<dyn Signer>,
        key: SecretKey,
        team: String,
        author: Ss58,
    ) -> Self {
        Self {
            blob,
            index,
            oplog,
            signer,
            key,
            team,
            author,
            clock: Mutex::new(OpClock {
                lamport_tip: 0,
                my_last_hash: GENESIS_PREV,
            }),
        }
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
        // Derive the object key BEFORE sealing: it is the AEAD associated data,
        // so the ciphertext is cryptographically bound to the identity it is
        // stored under (see `crypto::seal`'s threat model — defeats a gateway
        // relocating note A's bytes onto note B's key).
        let key = object_key(&scope, id, PHASE1_REVISION)?;
        let ciphertext = seal(&self.key, json.as_bytes(), key.as_bytes())?;
        let cid = content_hash(&ciphertext);

        // Step 1 — the body lands first, so the op minted next never names an
        // unwritten blob.
        self.blob.put(&key, ciphertext).await?;

        // Step 2 — mint the signed `Remember` op under the clock (synchronous; the
        // guard never spans the append await) and durably append it. `op.lamport`
        // is the convergence clock this write was assigned.
        let op = self.mint_op(OpKind::Remember, id, key.clone(), cid);
        self.oplog.append(&self.team, &op).await?;

        // Step 3 — index last, stamping the op's Lamport so recall/history see the
        // same convergence order the log records.
        self.index.upsert(IndexRecord {
            note_id: id,
            object_key: key,
            cid,
            scope,
            note_type: note.note_type,
            author: note.author,
            updated: now,
            lamport: op.lamport,
            tags: note.tags,
            summary: note.summary,
        })?;
        Ok(id)
    }

    /// Mint a signed op for `kind`/`note_id` and advance the convergence clock.
    ///
    /// Holds [`MemoryStore::clock`] across the synchronous build-sign-hash so two
    /// concurrent writers cannot both read the same tip and fork this author's
    /// chain: the tip and predecessor hash advance atomically before the guard is
    /// released. The guard is dropped on return, *before* the caller's append
    /// `.await`, so it never makes the surrounding future `!Send` (axiom
    /// `rust_quality_74`). If the subsequent append fails, the cached clock is one
    /// step ahead of the durable log; [`MemoryStore::sync`] re-seeds it from the
    /// log, so the skew is transient.
    fn mint_op(&self, kind: OpKind, note_id: NoteId, object_key: String, cid: Blake3Hash) -> Op {
        let mut clock = self.clock.lock().unwrap_or_else(PoisonError::into_inner);
        let lamport = clock.lamport_tip.saturating_add(1);
        let op = Op::create_signed(
            self.signer.as_ref(),
            OpContent {
                op_id: Ulid::new(),
                lamport,
                kind,
                note_id,
                object_key,
                cid,
                prev_op_hash: clock.my_last_hash,
            },
        );
        clock.lamport_tip = lamport;
        clock.my_last_hash = op.hash();
        op
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
    /// if the fetched ciphertext does not match the indexed content hash,
    /// [`MemError::Crypto`] if decryption or UTF-8 decoding fails, or
    /// [`MemError::Serialize`] if the decrypted JSON is not a valid note.
    pub async fn get(&self, id: NoteId) -> Result<Note, MemError> {
        let located = self
            .index
            .locate(id)?
            .ok_or_else(|| MemError::NotFound { id: id.to_string() })?;
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
        let plaintext = open(&self.key, &ciphertext, located.object_key.as_bytes())?;
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
        let op = self.mint_op(OpKind::Forget, note_id, located.object_key, located.cid);
        self.oplog.append(&self.team, &op).await?;
        self.index.remove(note_id)?;
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
        let op = self.mint_op(OpKind::Link { to }, from, located.object_key, located.cid);
        self.oplog.append(&self.team, &op).await
    }

    /// Replay the shared op-log into the local index: read + verify every op,
    /// converge them, then rebuild the index from the converged state. Returns the
    /// number of live (non-tombstoned) notes indexed.
    ///
    /// This is the op-log-aware successor to the old blob-listing rebuild: the
    /// signed, hash-chained op-log — not a raw bucket listing — is the source of
    /// truth, so a machine joining a team replays it to discover everything
    /// teammates have written, including tombstones (a forgotten note is *removed*
    /// from the index, not merely absent).
    ///
    /// The convergence clock is re-seeded from the durable log first
    /// (`lamport_tip` = the log's tip; `my_last_hash` = this author's last op, or
    /// [`GENESIS_PREV`] if it has none), healing any skew a failed append left in
    /// the cache.
    ///
    /// # Resilience
    ///
    /// Mirrors the old rebuild's two-tier policy. A *data* fault on one note —
    /// its blob fails to fetch, decrypt, or parse — is logged via `tracing::warn!`
    /// and skipped, so one corrupt or foreign blob never blinds the machine to the
    /// rest of the team's memory. A `read_all` failure (no verified log to replay
    /// from) and an `index.upsert`/`remove` fault (the local index rejecting a good
    /// record) both propagate: failing fast is correct when the systemic machinery
    /// is broken.
    ///
    /// # Errors
    ///
    /// Whatever [`OpLogStore::read_all`] reports (storage, deserialization, or a
    /// signature/chain violation), or whatever the index reports on upsert/remove.
    /// Per-note data faults are logged + skipped, not returned.
    pub async fn sync(&self) -> Result<usize, MemError> {
        let ops = self.oplog.read_all(&self.team).await?;
        let converged = converge(&ops);

        // Re-seed the convergence clock from the durable log before any rebuild
        // work. Scoped so the guard drops before the async hydrate loop below — it
        // must never be held across an `.await`.
        {
            let mut clock = self.clock.lock().unwrap_or_else(PoisonError::into_inner);
            clock.lamport_tip = lamport_tip(&ops);
            clock.my_last_hash = ops
                .iter()
                .rev()
                .find(|op| op.author == self.author)
                .map_or(GENESIS_PREV, Op::hash);
        }

        let mut indexed = 0_usize;
        for (note_id, state) in &converged {
            // Tombstone wins: a forgotten note is actively removed so a stale local
            // entry from before the forget cannot keep surfacing it.
            if state.tombstoned {
                self.index.remove(*note_id)?;
                continue;
            }
            // A note named only by a `Link`/`Forget` with no surviving content op
            // has no pointer to hydrate; skip it (it indexes nothing).
            let Some(pointer) = state.pointer.as_ref() else {
                continue;
            };
            match self.decode_pointer(*note_id, pointer).await {
                // Upsert is here, not inside `decode_pointer`, so a decode failure
                // (bad blob -> skip) stays distinct from an upsert failure (the
                // index rejecting a good record -> propagate).
                Ok(record) => {
                    self.index.upsert(record)?;
                    indexed += 1;
                }
                Err(err) => {
                    tracing::warn!(
                        note_id = %note_id,
                        object_key = %pointer.object_key,
                        error = %err,
                        "skipping note whose blob could not be decoded during sync"
                    );
                }
            }
        }
        Ok(indexed)
    }

    /// Fetch, verify, and decrypt the blob behind a converged `pointer` into the
    /// [`IndexRecord`] to index for `note_id`.
    ///
    /// Every error returned is a *data* fault the caller treats as "skip this
    /// note": fetch failure, AEAD/UTF-8/JSON failure. It deliberately does NOT
    /// upsert, so [`MemoryStore::sync`] can tell a bad blob from a systemic index
    /// fault. `cid` is recomputed from the fetched ciphertext (the same value the
    /// op recorded), so a later [`MemoryStore::get`] integrity-checks against
    /// exactly what is stored. `lamport` comes from the convergence pointer.
    async fn decode_pointer(
        &self,
        note_id: NoteId,
        pointer: &NotePointer,
    ) -> Result<IndexRecord, MemError> {
        let ciphertext = self.blob.get(&pointer.object_key).await?;
        let cid = content_hash(&ciphertext);
        // The object key is the AEAD associated data, so a blob relocated under a
        // foreign key fails authentication here and is skipped, never indexed under
        // the wrong identity.
        let plaintext = open(&self.key, &ciphertext, pointer.object_key.as_bytes())?;
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
            tags: note.tags,
            summary: note.summary,
        })
    }
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

    use super::{MemoryStore, RecallInput, RememberInput};
    use crate::crypto::{SecretKey, open};
    use crate::domain::{Note, NoteId, NoteType, RepoScope, Ss58};
    use crate::error::MemError;
    use crate::index::{
        HashEmbedder, InMemoryIndex, IndexRecord, Located, MemoryIndex, Query, SearchResult,
    };
    use crate::oplog::{OpKind, OpLogStore, Signer, Sr25519Signer};
    use crate::store::blob::{BlobStore, MemoryBlobStore};
    use proptest::prelude::*;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const TEST_KEY: [u8; 32] = [7_u8; 32];
    const TEAM: &str = "team";
    /// The default author/seed for single-machine tests.
    const SOLO_AUTHOR: &str = "555555555555555555555555555555555555555555555555";
    const SOLO_SEED: [u8; 32] = [5_u8; 32];
    // A distinctive phrase that lives only in the note body, so the
    // ciphertext-leakage test can search the at-rest bytes for it.
    const BODY_MARKER: &str = "half-read frame is lost";

    /// Build a store over `blob` (the op-log shares the same backend) signing as
    /// `author_str` with `seed`. Both identity halves must agree, so the signer
    /// is built from the same SS58 the store is attributed to.
    fn store_over(
        blob: Arc<dyn BlobStore>,
        author_str: &str,
        seed: [u8; 32],
    ) -> Result<MemoryStore, MemError> {
        let author = Ss58::new(author_str).map_err(|e| MemError::Storage(e.to_string()))?;
        let signer: Arc<dyn Signer> = Arc::new(
            Sr25519Signer::from_seed(seed, author.clone())
                .map_err(|e| MemError::Storage(e.to_string()))?,
        );
        let oplog = OpLogStore::new(blob.clone());
        let index = Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default())));
        Ok(MemoryStore::new(
            blob,
            index,
            oplog,
            signer,
            SecretKey::from_bytes(TEST_KEY),
            TEAM.to_string(),
            author,
        ))
    }

    fn build_store() -> Result<MemoryStore, MemError> {
        store_over(Arc::new(MemoryBlobStore::default()), SOLO_AUTHOR, SOLO_SEED)
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

        // Sanity: the bytes open under the key they were sealed at.
        open(&store.key, &bytes, located.object_key.as_bytes())?;

        // Relocation/replay: the SAME ciphertext fetched from a DIFFERENT object
        // key fails authentication, because the object key is the AEAD associated
        // data. `get` and `sync` both pass the key the bytes were fetched from as
        // AAD, so a gateway serving note A's bytes at note B's key is rejected here
        // rather than silently decrypted under the shared team key.
        let foreign_key = format!("{TEAM}/global/{}/rev_1", NoteId::new());
        assert!(matches!(
            open(&store.key, &bytes, foreign_key.as_bytes()),
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
    }

    #[tokio::test]
    async fn sync_propagates_index_upsert_failure() -> TestResult {
        // A real note + its signed op sit in the shared bucket (written by a
        // healthy store).
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let healthy = store_over(bucket.clone(), SOLO_AUTHOR, SOLO_SEED)?;
        healthy.remember(sample_input()).await?;

        // A second machine shares the bucket + op-log but its index rejects every
        // record. The blob decodes fine, so this is a systemic index fault, not a
        // bad blob: sync must propagate it rather than skip + undercount.
        let author = Ss58::new(SOLO_AUTHOR).map_err(|e| MemError::Storage(e.to_string()))?;
        let signer: Arc<dyn Signer> = Arc::new(
            Sr25519Signer::from_seed(SOLO_SEED, author.clone())
                .map_err(|e| MemError::Storage(e.to_string()))?,
        );
        let broken = MemoryStore::new(
            bucket.clone(),
            Arc::new(FailingUpsertIndex),
            OpLogStore::new(bucket),
            signer,
            SecretKey::from_bytes(TEST_KEY),
            TEAM.to_string(),
            author,
        );
        assert!(matches!(broken.sync().await, Err(MemError::Storage(_))));
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
    async fn sync_converges_two_machines() -> TestResult {
        // Two machines share one bucket (hence one op-log) but keep independent
        // indexes + identities.
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let machine_a = store_over(bucket.clone(), SOLO_AUTHOR, SOLO_SEED)?;
        let machine_b = store_over(
            bucket,
            "666666666666666666666666666666666666666666666666",
            [6_u8; 32],
        )?;

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
