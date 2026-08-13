//! In-memory hybrid retrieval index and the [`Embedder`] seam.
//!
//! The index returns *pointers* — a [`NoteId`], its summary, and a relevance
//! score — never note bodies. A caller ranks the pointers, then hydrates only
//! the few it picks. Phase 1 ships an in-memory [`InMemoryIndex`] behind the
//! [`MemoryIndex`] trait; a persistent backend (`LanceDB`) plugs in behind the
//! same trait later without touching callers.
//!
//! Retrieval is *hybrid*: a lexical leg (`BM25`-lite term-frequency overlap)
//! and a semantic leg (cosine over [`Embedder`] vectors) are fused with
//! Reciprocal Rank Fusion, then multiplied by a per-[`NoteType`] recency decay.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use crate::domain::{Blake3Hash, NoteId, NoteType, RepoScope, Scope, Ss58, Timestamp};
use crate::error::MemError;
use crate::oplog::{LinkRel, TypedLink};

// The real dense embedder lives in its own module so the heavy `fastembed`/ONNX
// stack is compiled only under the opt-in `embeddings` feature and stays out of
// the default build.
#[cfg(feature = "embeddings")]
mod fastembed;
#[cfg(feature = "embeddings")]
pub use fastembed::{EmbedModel, FastEmbedder};

/// Turns text into a dense vector for semantic similarity.
///
/// Pluggable so a real model (`fastembed`) can replace the fallback later
/// without touching the index. The trait is object-safe and `Send + Sync`, so
/// the index can hold an `Arc<dyn Embedder>` and share it across tasks.
pub trait Embedder: Send + Sync {
    /// Embed a batch of texts. Returns one vector per input, each of length
    /// [`Embedder::dim`].
    ///
    /// # Errors
    ///
    /// Returns a [`MemError`] if the underlying model fails. The
    /// [`HashEmbedder`] fallback is infallible and always returns `Ok`.
    fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, MemError>;

    /// The fixed output dimensionality.
    #[must_use]
    fn dim(&self) -> usize;

    /// The semantic (vector) leg's per-embedder relevance floor: a candidate
    /// counts as relevant only when its cosine is STRICTLY above this (the
    /// ranker filters `score > floor` — a candidate at exactly the floor is
    /// dropped, matching the lexical leg where a score of 0 is no signal).
    ///
    /// The lexical leg's floor is always exactly `0.0` (a BM25 score of 0 means no
    /// shared term — unambiguously "no signal"). A real dense model returns small
    /// NON-zero cosines for unrelated text, so it overrides this to its own
    /// calibrated threshold, keeping the floor with the embedder that defines
    /// "similar" rather than hard-coding it in the ranker.
    ///
    /// The default `0.0` is only ever consulted for an embedder that actually runs
    /// the vector leg. The bag-of-tokens [`HashEmbedder`] does NOT: hashing tokens
    /// into a small bucket space makes two DISJOINT texts collide into a spurious
    /// non-zero (up to `1.0`) cosine — it does *not* yield exactly `0.0` for disjoint
    /// text — so its vector leg would readmit unrelated notes the exact keyword leg
    /// already ranks precisely. It therefore reports
    /// [`contributes_semantic_leg`](Self::contributes_semantic_leg)` == false` and
    /// the ranker runs keyword-only, so this threshold is never applied to it.
    #[must_use]
    fn relevance_threshold(&self) -> f32 {
        0.0
    }

    /// Whether this embedder's vector output carries retrieval signal BEYOND the
    /// exact keyword leg — i.e. whether the ranker should run the semantic leg at all.
    ///
    /// A real dense model earns its vector leg: it matches paraphrases the keyword
    /// leg misses. The [`HashEmbedder`] fallback does not — its vector is a lossy,
    /// collision-prone re-derivation of the token overlap the BM25 keyword leg
    /// already computes exactly, so running it only adds false positives. Returning
    /// `false` makes the ranker skip the vector leg (keyword-only), the correct
    /// behavior for a lexical build.
    #[must_use]
    fn contributes_semantic_leg(&self) -> bool {
        true
    }
}

/// Default [`HashEmbedder`] dimensionality.
///
/// 64 buckets keep collisions tolerable for short summaries while staying
/// cheap; this is a lexical proxy, not a tuned model dimension.
pub const DEFAULT_EMBED_DIM: usize = 64;

/// Deterministic bag-of-tokens embedding used for tests and the offline
/// fallback.
///
/// Each token is lowercased, hashed with `FNV-1a` into one of `dim` buckets,
/// counts are accumulated, and the vector is `L2`-normalized. This is a cheap
/// lexical-overlap proxy, **not** real semantics: it captures word co-occurrence
/// only. Determinism is a hard guarantee — the same text always yields the same
/// vector, on any platform and across instances — because `FNV-1a` uses fixed
/// constants rather than a randomized hasher.
#[derive(Debug, Clone)]
pub struct HashEmbedder {
    dim: usize,
}

impl HashEmbedder {
    /// Build an embedder producing `dim`-dimensional vectors.
    #[must_use]
    pub const fn new(dim: usize) -> Self {
        Self { dim }
    }
}

impl Default for HashEmbedder {
    fn default() -> Self {
        Self::new(DEFAULT_EMBED_DIM)
    }
}

impl Embedder for HashEmbedder {
    fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, MemError> {
        Ok(texts.iter().map(|t| embed_one(t, self.dim)).collect())
    }

    fn dim(&self) -> usize {
        self.dim
    }

    // The hashed bag-of-tokens vector only re-derives token overlap — with bucket
    // collisions — which the exact BM25 keyword leg already computes; running its
    // vector leg would add only collision false-positives, so a lexical build ranks
    // keyword-only.
    fn contributes_semantic_leg(&self) -> bool {
        false
    }
}

// `FNV-1a` 64-bit constants (Fowler–Noll–Vo). Chosen over `std`'s
// `DefaultHasher` because `FNV-1a` is specified by fixed constants, so the
// embedding is reproducible across toolchains and process runs; `RandomState`
// is seeded per-process and would break the determinism contract.
const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Lowercase and split on any non-alphanumeric boundary, dropping empties.
fn tokenize(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|piece| !piece.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// Scale a vector to unit `L2` length in place. A zero vector (no tokens) is
/// left untouched so callers never divide by zero — cosine treats it as 0.
fn l2_normalize(vector: &mut [f32]) {
    let norm = vector.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        for x in vector.iter_mut() {
            *x /= norm;
        }
    }
}

fn embed_one(text: &str, dim: usize) -> Vec<f32> {
    let mut vector = vec![0.0_f32; dim];
    if dim == 0 {
        return vector;
    }
    let dim_u64 = dim as u64;
    for token in tokenize(text) {
        // Modulo a non-zero `dim` is always in `0..dim`, so the cast back to
        // `usize` cannot truncate and `unwrap_or` never fires.
        let bucket = usize::try_from(fnv1a(token.as_bytes()) % dim_u64).unwrap_or(0);
        vector[bucket] += 1.0;
    }
    l2_normalize(&mut vector);
    vector
}

/// Cosine similarity of two equal-length vectors.
///
/// Returns `0.0` (never `NaN`) when either vector has zero norm — the degenerate
/// case for empty/again-zero embeddings — or when the lengths differ. Length
/// equality is the [`Embedder::dim`] contract (query and doc are embedded by the
/// same embedder); guarding it returns "no signal" rather than letting `zip`
/// silently truncate to the shorter vector and report a meaningless partial score
/// if a misbehaving embedder ever violates that contract.
fn cosine(left: &[f32], right: &[f32]) -> f32 {
    if left.len() != right.len() {
        return 0.0;
    }
    let mut dot = 0.0_f32;
    let mut norm_left = 0.0_f32;
    let mut norm_right = 0.0_f32;
    for (x, y) in left.iter().zip(right.iter()) {
        dot += x * y;
        norm_left += x * x;
        norm_right += y * y;
    }
    let denom = norm_left.sqrt() * norm_right.sqrt();
    // `denom` is a product of square roots, so it is `>= 0`; guarding `<= 0`
    // catches the zero-norm case without an exact float equality test.
    if denom <= 0.0 { 0.0 } else { dot / denom }
}

/// Reciprocal Rank Fusion rank constant. 60 is the value from Cormack, Clarke &
/// Buettcher, "Reciprocal Rank Fusion outperforms Condorcet and individual Rank
/// Learning Methods" (SIGIR 2009).
const RANK_CONSTANT: f32 = 60.0;

/// Multiplier applied to a note that a `Supersedes`/`Duplicates` relation targets.
/// It is demoted hard (0.2x) but still returned and tagged — never dropped — so
/// the decision trail stays auditable, matching the append-only ethos. A stale
/// decision therefore ranks below its live replacement without vanishing.
const RELATION_DEMOTION: f32 = 0.2;

/// Slope of the reinforcement boost: `1 + k·ln(1 + |reinforcers|)`. A logarithm,
/// not a linear term, so the tenth distinct endorsement moves rank far less than
/// the first — usefulness is diminishing-returns evidence, and the log blunts a
/// coordinated burst even before the distinct-author Sybil bound applies.
const REINFORCE_BOOST_K: f32 = 0.5;

/// Hard ceiling on the reinforcement boost, so no amount of endorsement lets a
/// note dominate relevance and recency outright — reinforcement re-ranks within
/// the relevant set, it does not override it. `3.0` ≈ `REINFORCE_BOOST_K·ln(1+n)`
/// saturating around 50 distinct reinforcers.
const MAX_REINFORCE_BOOST: f32 = 3.0;

/// Fuse per-leg rankings with Reciprocal Rank Fusion.
///
/// `legs[i]` is leg `i`'s candidates ordered best-first; an id's fused score is
/// `Σ 1 / (rank_constant + rank)` over the legs it appears in, with `rank` the
/// 0-based position in that leg. The result has exactly one entry per distinct
/// id (deduplicated and ordered by id via a [`BTreeMap`]), so it is stable.
fn rrf_fuse(legs: &[Vec<NoteId>], rank_constant: f32) -> Vec<(NoteId, f32)> {
    let mut accumulated: BTreeMap<NoteId, f32> = BTreeMap::new();
    for leg in legs {
        for (rank, id) in leg.iter().enumerate() {
            #[expect(
                clippy::cast_precision_loss,
                reason = "rank is a small list index; f32 represents it exactly far past any candidate count"
            )]
            let contribution = 1.0_f32 / (rank_constant + rank as f32);
            *accumulated.entry(*id).or_insert(0.0) += contribution;
        }
    }
    accumulated.into_iter().collect()
}

/// A pointer returned by search — NEVER contains the note body.
///
/// Hydration of the body is a separate, caller-driven step; this type is the
/// whole search result contract, so the absence of a body field is enforced at
/// compile time.
#[derive(Debug, Clone)]
pub struct Pointer {
    /// Identity of the pointed-to note.
    pub note_id: NoteId,
    /// The note's short summary (safe to surface; not the body).
    pub summary: String,
    /// Final relevance score: fused rank score times recency decay.
    pub score: f32,
    /// Where the note lives.
    pub scope: Scope,
    /// Who authored the note.
    pub author: Ss58,
    /// When the note was last updated. Wall-clock; the recency leg decays on
    /// the later of this and the note's last (non-future) reinforcement — see
    /// [`IndexRecord::last_reinforced`] — because "recent" to a human reader
    /// means recently written OR recently proven useful.
    pub updated: Timestamp,
    /// Lamport clock of the write that produced this pointer.
    ///
    /// The convergence clock, distinct from `updated`: it total-orders writes
    /// across machines whose wall-clocks cannot be trusted to agree. Nothing in
    /// ranking reads it (recency decays on `updated`/`last_reinforced`); it
    /// rides along so callers can reason about convergence order and history.
    pub lamport: u64,
    /// Incoming typed relations to this note, so recall can tag it (e.g.
    /// `[superseded by mem_X]`). Empty for a note nothing relates to. A
    /// `Supersedes`/`Duplicates` entry here means this pointer was demoted.
    pub relations: Vec<PointerRelation>,
}

/// One incoming typed relation surfaced on a recall [`Pointer`]: note `from`
/// asserts `rel` about the pointed-to note (e.g. `from` supersedes it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointerRelation {
    /// The note asserting the relation.
    pub from: NoteId,
    /// How `from` relates to the pointed-to note.
    pub rel: LinkRel,
}

/// The outcome of a [`MemoryIndex::search`]: the returned pointers plus how many
/// in-scope, relevant notes matched in total.
///
/// `total_matched` counts every candidate that was in scope AND cleared the
/// relevance floor in at least one retrieval leg (above that leg's floor: `0` for
/// the lexical leg, [`Embedder::relevance_threshold`] for the semantic leg),
/// *before* the `k` cap and token budget truncate the result. So
/// `total_matched >= pointers.len()`,
/// and a caller can tell whether it saw everything (`total_matched ==
/// pointers.len()`) or whether more matches exist beyond the budget it asked for.
#[derive(Debug, Clone)]
pub struct SearchResult {
    /// The ranked pointers actually returned, after `k`/budget truncation.
    pub pointers: Vec<Pointer>,
    /// Count of in-scope, relevant candidates before `k`/budget truncation.
    pub total_matched: usize,
}

/// The existing note a candidate summary most resembles, when it is close enough
/// to count as a probable duplicate at write time.
///
/// Returned by [`MemoryIndex::nearest_duplicate`] and surfaced to the caller as
/// [`crate::MemError::NearDuplicate`]. This is a raw-similarity probe, distinct
/// from [`Pointer`]'s fused-and-decayed relevance `score`: dedup asks "is this
/// almost the same note?", which is the retrieval similarity BEFORE recency decay
/// and RRF fusion reshape it, so the two must not share a scale.
#[derive(Debug, Clone)]
pub struct NearDuplicate {
    /// The existing note the candidate most resembles.
    pub note_id: NoteId,
    /// Similarity in `[0, 1]`: cosine on a semantic build, token-set Jaccard on a
    /// lexical build (see [`MemoryIndex::nearest_duplicate`]).
    pub similarity: f32,
}

/// One indexed note. The index computes and stores the embedding of `summary`.
///
/// `Serialize`/`Deserialize` let a converged set of records be persisted as an
/// [`crate::store::IndexSnapshot`] and restored without re-fetching every note
/// blob; `PartialEq` lets a restored record be compared field-for-field against a
/// freshly decoded one (the snapshot round-trip and incremental-equals-full tests
/// rely on this). `Eq` is deliberately NOT derived: the transient `embedding`
/// (`Vec<f32>`) is not `Eq`, and it is always `None` on any stored or restored
/// record (`upsert` `take`s it out, serde skips it), so it never perturbs a
/// `PartialEq` comparison anyway.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct IndexRecord {
    /// Identity of the note.
    pub note_id: NoteId,
    /// Object-store key locating the sealed body.
    pub object_key: String,
    /// Content hash of the sealed body.
    pub cid: Blake3Hash,
    /// Where the note lives.
    pub scope: Scope,
    /// What kind of knowledge the note records (drives recency decay).
    pub note_type: NoteType,
    /// Who authored the note.
    pub author: Ss58,
    /// When the note was last updated. Wall-clock; recency decay reads the
    /// later of this and [`Self::last_reinforced`].
    pub updated: Timestamp,
    /// Lamport clock of the write that produced this record.
    ///
    /// The convergence clock — it orders writes across machines for convergence
    /// where untrusted wall-clocks cannot. `updated` stays the recency clock;
    /// `lamport` rides along for convergence/history and is not read by ranking.
    pub lamport: u64,
    /// Team-key epoch the sealed body was encrypted under. Carried so
    /// [`crate::store::MemoryStore::get`] picks the right key from the key-ring
    /// without re-reading the op that recorded it.
    pub key_epoch: u64,
    /// Free-form tags, included in the lexical leg.
    pub tags: BTreeSet<String>,
    /// The short summary, indexed for both retrieval legs.
    pub summary: String,
    /// This note's OUTGOING typed relations. Recall scans candidates' relations
    /// to demote the notes THIS one supersedes/duplicates and to tag those it
    /// contradicts/refines. `#[serde(default)]` so a snapshot written before typed
    /// relations existed restores with an empty set (append-only wire discipline).
    #[serde(default)]
    pub relations: Vec<TypedLink>,
    /// Distinct identities that reinforced this note (each `Reinforce` op's
    /// author). Recall boosts a note by `|reinforcers|`; carried as the full set
    /// (not just a count) so convergence fidelity and future author-trust
    /// weighting are preserved. `#[serde(default)]` for snapshot back-compat.
    #[serde(default)]
    pub reinforcers: BTreeSet<Ss58>,
    /// The latest reinforcement time, or `None`. Recall ages the note on
    /// `max(updated, last_reinforced)`, so repeated use keeps a note fresh.
    /// `#[serde(default)]` restores a pre-reinforcement snapshot as `None`.
    #[serde(default)]
    pub last_reinforced: Option<Timestamp>,
    /// A precomputed summary embedding threaded in by the binary — which computes it
    /// on the blocking pool — so [`MemoryIndex::upsert`] need not run the CPU-bound
    /// ONNX embed on the async runtime worker (ASYNCBLOCK). `None` on every
    /// non-offloaded path (tests, lexical builds, sync/replay); `upsert` then embeds
    /// inline as before. `#[serde(skip)]`: a transient in-process hint, never
    /// persisted into a snapshot (which would bloat every record with a dense vector).
    #[serde(skip)]
    pub embedding: Option<Vec<f32>>,
}

/// A retrieval request.
#[derive(Debug, Clone)]
pub struct Query {
    /// The natural-language query text.
    pub text: String,
    /// Team whose notes are in scope.
    pub team: String,
    /// Repository dimension to retrieve for (team-global notes always match).
    pub repo: RepoScope,
    /// Maximum number of pointers to return.
    pub k: usize,
    /// Optional cap on the summed estimated token cost of returned summaries.
    pub token_budget: Option<usize>,
    /// "Now", used as the reference point for recency decay.
    pub now: Timestamp,
}

/// The stored location of a note's sealed body, resolved from its [`NoteId`].
///
/// Returned by [`MemoryIndex::locate`] so a caller can fetch and integrity-check
/// the object behind a known id. It carries the object key (where the ciphertext
/// lives) and the ciphertext's content hash (what it should hash to), and
/// deliberately nothing else — `locate` answers "where is it", not "what is it".
#[derive(Debug, Clone)]
pub struct Located {
    /// Object-store key locating the sealed body.
    pub object_key: String,
    /// Content hash of the sealed body, for post-fetch integrity verification.
    pub cid: Blake3Hash,
    /// Team-key epoch the body was sealed under, so the caller selects the right
    /// key from the key-ring.
    pub key_epoch: u64,
}

/// A hybrid retrieval index over note summaries.
///
/// Implementations rank by relevance and recency and return [`Pointer`]s, never
/// bodies. The trait is object-safe and `Send + Sync`.
pub trait MemoryIndex: Send + Sync {
    /// Insert `record`, replacing any existing record with the same
    /// [`NoteId`].
    ///
    /// # Errors
    ///
    /// Returns a [`MemError`] if embedding `record.summary` fails.
    fn upsert(&self, record: IndexRecord) -> Result<(), MemError>;

    /// Insert every record in `records`, replacing any existing record with the
    /// same [`NoteId`] — the batch form of [`upsert`](Self::upsert).
    ///
    /// The point of the batch is that an implementation backed by an expensive
    /// embedder can embed all summaries in ONE call: the per-call model-run
    /// overhead dominates a cold rebuild, so folding N single embeds into one
    /// batch is the difference between a slow and a fast reindex. The default
    /// impl is the correct-but-serial fallback (one `upsert` per record); an
    /// impl that owns a batching embedder should override it.
    ///
    /// # Errors
    ///
    /// Returns a [`MemError`] if embedding the summaries fails.
    fn upsert_batch(&self, records: Vec<IndexRecord>) -> Result<(), MemError> {
        for record in records {
            self.upsert(record)?;
        }
        Ok(())
    }

    /// Return up to `query.k` pointers ranked by relevance and recency, plus the
    /// total number of in-scope relevant matches (see [`SearchResult`]).
    ///
    /// Only candidates that are relevant — non-zero in at least one retrieval
    /// leg — are eligible; a note unrelated to the query in both legs never
    /// surfaces, even on recency alone.
    ///
    /// # Errors
    ///
    /// Returns a [`MemError`] if embedding the query text fails.
    fn search(&self, query: &Query) -> Result<SearchResult, MemError>;

    /// Find the in-scope live note most similar to `summary` whose similarity is
    /// at least `threshold`, or `None` if nothing is that close.
    ///
    /// This is the write-time dedup probe. Unlike [`search`](Self::search) it
    /// returns RAW similarity, not the fused-and-decayed ranking score — dedup
    /// must ask "is this almost the same note?" on the retrieval scale, before
    /// recency and RRF reshape it. Similarity is cosine on a semantic build and
    /// token-set Jaccard on a lexical build, so a lexical build only catches
    /// near-identical summaries (a deliberately weaker guarantee, documented so a
    /// caller does not over-trust it).
    ///
    /// The default returns `Ok(None)`: an index with no similarity probe simply
    /// does not gate, which fails open (a write is never wrongly refused). The
    /// real [`InMemoryIndex`] overrides it.
    ///
    /// # Errors
    ///
    /// Returns a [`MemError`] if embedding `summary` fails (semantic build only).
    fn nearest_duplicate(
        &self,
        summary: &str,
        team: &str,
        repo: &RepoScope,
        threshold: f32,
        precomputed_vec: Option<&[f32]>,
    ) -> Result<Option<NearDuplicate>, MemError> {
        let _ = (summary, team, repo, threshold, precomputed_vec);
        Ok(None)
    }

    /// Embed `summary` into the same dense vector [`upsert`](Self::upsert) /
    /// [`nearest_duplicate`](Self::nearest_duplicate) would compute for it, so a
    /// caller can precompute it on a blocking thread (see
    /// `MemoryStore::remember_offloaded`) and pass it back — keeping the CPU-bound
    /// ONNX embed off the async runtime worker (ASYNCBLOCK).
    ///
    /// The default returns an empty vector (an index with no embedder contributes no
    /// semantic vector); [`InMemoryIndex`] overrides it to run its embedder.
    ///
    /// # Errors
    ///
    /// Returns a [`MemError`] if the embedder fails.
    fn embed_summary(&self, summary: &str) -> Result<Vec<f32>, MemError> {
        let _ = summary;
        Ok(Vec::new())
    }

    /// Remove the record with id `id`, if present.
    ///
    /// # Errors
    ///
    /// This in-memory implementation never errors; the signature is fallible so
    /// a persistent backend can report a storage failure.
    fn remove(&self, id: NoteId) -> Result<(), MemError>;

    /// Remove the record with id `id`, if present, and record `(lamport,
    /// object_key)` as a per-id REMOVAL WATERMARK.
    ///
    /// This is the version-aware counterpart to [`remove`](Self::remove) that
    /// `redact`/`forget` must call instead of the plain form: [`upsert`](Self::upsert)
    /// and [`upsert_batch`](Self::upsert_batch) refuse any later record for `id`
    /// whose `version_key` (see the free function of that name) is at or below
    /// this watermark, exactly like the existing lamport-monotonic guard against
    /// a stale rollback of a still-PRESENT entry — extended to cover an ABSENT
    /// one. Without this, a note `redact`/`forget` just removed has no entry left
    /// to compare a stale sync's re-insert against, so the existing guard cannot
    /// see it and the stale record sails back in.
    ///
    /// A record whose `version_key` is genuinely GREATER than the watermark is a
    /// legitimate later op (e.g. an edit that lands after the redaction) and is
    /// applied normally, clearing the watermark.
    ///
    /// # Errors
    ///
    /// Same as [`remove`](Self::remove).
    fn remove_at(&self, id: NoteId, lamport: u64, object_key: &str) -> Result<(), MemError>;

    /// Resolve a note id to its current stored object (key + ciphertext hash),
    /// if indexed.
    ///
    /// This is the lookup that lets `get` hydrate a body the index already
    /// points at, without scanning the blob store. Returns `None` when no record
    /// with `id` exists.
    ///
    /// # Errors
    ///
    /// This in-memory implementation never errors; the signature is fallible so
    /// a persistent backend can report a storage failure.
    fn locate(&self, id: NoteId) -> Result<Option<Located>, MemError>;

    /// Drop every indexed note whose id is NOT in `keep`, UNLESS its own
    /// `lamport` is newer than `baseline_lamport`.
    ///
    /// This is the authoritative-pruning primitive [`crate::store::MemoryStore::sync`]
    /// needs: after computing the converged *live* set it calls `retain` so a
    /// note that is no longer live — a removed member's note, or one whose
    /// content op no longer survives convergence — is dropped from a long-lived
    /// (warm) index, not just on a cold from-scratch rebuild. `keep` is a
    /// [`BTreeSet`] so the per-entry membership test is `O(log n)`; the receiver
    /// is `&self` (object-safe, no generics) so the method stays dyn-compatible.
    ///
    /// `baseline_lamport` is the Lamport tip of the op-log view `keep` was
    /// computed from (`sync`'s `lamport_tip(members_view)`). `keep` can go
    /// stale the instant it is computed: a concurrent `remember`/`edit` on
    /// this same store can land — durable in the op-log AND upserted into
    /// this index — between that view being read and this `retain` call
    /// running, entirely outside `keep`'s knowledge. Without the guard,
    /// `retain` would delete that just-written note purely because the stale
    /// `keep` does not name it, even though the write already reported
    /// success to its caller — the next `get`/`recall` would then 404 until
    /// the following sync. An entry survives when EITHER `keep` names it OR
    /// its own `record.lamport > baseline_lamport`: the latter can only be
    /// true for an op this view's own convergence never saw, i.e. one minted
    /// after the view was captured, which by definition `keep` cannot speak
    /// to either way. A cold replay passes the same tip it built `keep` from,
    /// so nothing in a consistent snapshot is newer than its own baseline and
    /// pruning is unconditional, exactly as before this guard existed.
    ///
    /// # Errors
    ///
    /// This in-memory implementation never errors; the signature is fallible so
    /// a persistent backend can report a storage failure.
    fn retain(&self, keep: &BTreeSet<NoteId>, baseline_lamport: u64) -> Result<(), MemError>;

    /// Return every indexed record, in unspecified order.
    ///
    /// This is the plain enumeration path for local tooling (the dashboard browse
    /// view), NOT a retrieval/ranking path: it applies no scope filter, no query,
    /// and no recency decay — the caller filters. Records are body-free
    /// ([`IndexRecord`] carries the summary, never the note body), so exposing the
    /// whole set is safe for a local read. No default impl: enumeration is a
    /// required capability, so a backend that cannot list must say so rather than
    /// silently return an empty set.
    ///
    /// # Errors
    ///
    /// This in-memory implementation never errors; the signature is fallible so
    /// a persistent backend can report a storage failure.
    fn all_records(&self) -> Result<Vec<IndexRecord>, MemError>;

    /// Whether this index runs the semantic (dense-vector) retrieval leg in
    /// addition to the exact keyword leg — i.e. whether recall can match
    /// paraphrases, not just shared tokens.
    ///
    /// Defaulted to `false` so a lexical/mock implementation is honest without
    /// having to opt in: a caller that badges retrieval (the dashboard) must not
    /// claim semantics a backend does not provide. The real index overrides this
    /// from its embedder ([`Embedder::contributes_semantic_leg`]).
    #[must_use]
    fn is_semantic(&self) -> bool {
        false
    }
}

/// A stored record plus the precomputed embedding of its summary.
struct Entry {
    record: IndexRecord,
    embedding: Vec<f32>,
}

/// The mutable state one [`InMemoryIndex`] guards behind a single lock: the
/// live entries plus a per-id removal watermark.
///
/// Both live under ONE lock (not two) so [`apply_record`]'s stale-rollback and
/// removal-watermark checks, together with the insert/clear they gate, are
/// atomic with respect to a concurrent `remove_at`/`retain` — there is no
/// two-lock acquisition order to get right anywhere in this module.
#[derive(Default)]
struct IndexState {
    entries: BTreeMap<NoteId, Entry>,
    /// `note_id -> (lamport, object_key)` of the op that last removed it via
    /// [`InMemoryIndex::remove_at`] (redact/forget). Consulted by
    /// [`apply_record`] so a stale sync cannot resurrect a note removed since
    /// this index last saw it; cleared once a genuinely newer record
    /// supersedes it (in `apply_record`) or a full [`InMemoryIndex::retain`]
    /// rebuild confirms the id is not live (so this map cannot grow
    /// unbounded — see `retain`'s doc comment).
    removed: BTreeMap<NoteId, (u64, String)>,
}

/// The version ordering used to keep [`InMemoryIndex`] upserts lamport-monotonic:
/// `(lamport, object_key)`. `object_key` ends in `ver_{op_ulid}` — the winning
/// op's id — so this mirrors converge's `(lamport, op_id)` tiebreak, and the
/// record with the greater key is the newer version of the note.
fn version_key(record: &IndexRecord) -> (u64, &str) {
    (record.lamport, record.object_key.as_str())
}

/// Whether upserting `incoming` would roll a note back to a STALER version than
/// the one already stored.
///
/// A `sync` recomputes the index from a converged op-log view, and its
/// `retain`/`upsert_batch` run OUTSIDE the writer lock. If that view was captured
/// before a concurrent `commit_edit` landed, a naive upsert would revert the
/// committed edit — after which `commit_edit`'s own under-lock CAS reads the
/// rolled-back cid and a stale-precondition edit passes and clobbers the
/// committed one (last-writer-wins), and `get` serves the old body until the next
/// sync. Refusing a strictly-older `(lamport, object_key)` closes that race. The
/// gate is strict (`>`), so a same-version re-upsert that only refreshes ranking
/// signals (a Reinforce/Relate with no new content op) still lands.
///
/// Tradeoff — accepted to close the common concurrent-edit race, which is a
/// PERMANENT lost update, in exchange for the following BOUNDED, self-healing
/// staleness. `(lamport, object_key)` alone cannot distinguish "a concurrent edit
/// my view missed" (the race — the stored higher op is still the truth) from "the
/// stored higher op is no longer the converged winner" (a legitimate downgrade),
/// so the gate refuses BOTH. A legitimate downgrade arises two ways, and neither is
/// only equivocation: (a) the stored op's author forked their chain, so
/// `quarantine_broken_chains` drops it on the next verified read; or (b) the stored
/// op's author was REMOVED from the team, so `read_and_filter`'s member filter
/// excludes their ops and converge reverts the note to a remaining member's older
/// edit. In either case the gate keeps the now-stale higher version in a WARM index
/// — even through a full `replay_full` rebuild — until the process restarts and
/// rebuilds from an empty index. This is a local consistency lag (the stale content
/// was already team-visible; it is not a new disclosure), bounded by the next
/// server restart, not a permanent divergence. The proper fix (make the out-of-lock
/// index rebuild authoritative without reopening the race — e.g. optimistic
/// re-validation of the op-log tip under the writer lock) is a larger change
/// tracked separately.
fn is_stale_rollback(entries: &BTreeMap<NoteId, Entry>, incoming: &IndexRecord) -> bool {
    entries
        .get(&incoming.note_id)
        .is_some_and(|existing| version_key(&existing.record) > version_key(incoming))
}

/// Whether `incoming` is at or below the removal watermark [`InMemoryIndex::remove_at`]
/// recorded for its id — i.e. whether applying it would resurrect a note that
/// `redact`/`forget` removed, with nothing newer since re-establishing it.
///
/// [`is_stale_rollback`] alone cannot see this: once `remove_at` drops the
/// entry, there is nothing left in `entries` to compare a stale re-insert
/// against, so that guard's `entries.get(...).is_some_and(...)` is vacuously
/// `false` and a stale record sails through. `removed` is exactly the
/// watermark that closes the gap. The comparison is `<=`, not the strict `<`
/// [`is_stale_rollback`] itself uses against a live entry: unlike a live
/// entry (where a same-version Reinforce/Relate refresh is legitimate and
/// must land), a same-version record for a REMOVED id can only be the exact
/// stale re-insert this watermark exists to refuse, so nothing is lost by
/// refusing the equal case too.
fn is_at_or_below_removal_watermark(
    removed: &BTreeMap<NoteId, (u64, String)>,
    incoming: &IndexRecord,
) -> bool {
    removed
        .get(&incoming.note_id)
        .is_some_and(|(lamport, object_key)| {
            version_key(incoming) <= (*lamport, object_key.as_str())
        })
}

/// Apply one already-embedded record to `state`: refuse it if
/// [`is_stale_rollback`] says it would roll a live note back, or
/// [`is_at_or_below_removal_watermark`] says it would resurrect a removed
/// one; else insert it and clear any removal watermark for its id (a record
/// that clears the gate is, by construction, genuinely newer than whatever
/// watermark was recorded, so the watermark's job here is done).
///
/// This is the SINGLE apply path [`InMemoryIndex::upsert`] and
/// [`InMemoryIndex::upsert_batch`] both funnel through — the embedding is
/// computed differently on each entry point (single embed vs. one batched
/// embedder call), but the version-gate-then-insert step is identical, so it
/// lives here once rather than duplicated at both call sites.
fn apply_record(state: &mut IndexState, record: IndexRecord, embedding: Vec<f32>) {
    if is_stale_rollback(&state.entries, &record)
        || is_at_or_below_removal_watermark(&state.removed, &record)
    {
        return;
    }
    state.removed.remove(&record.note_id);
    state
        .entries
        .insert(record.note_id, Entry { record, embedding });
}

/// In-memory [`MemoryIndex`] backed by a [`BTreeMap`], for tests and the
/// offline fallback.
pub struct InMemoryIndex {
    embedder: Arc<dyn Embedder>,
    // `BTreeMap` (not `HashMap`): deterministic iteration order makes search
    // output reproducible, and key-equality gives upsert-replace/remove for
    // free. `Mutex` provides the interior mutability the `&self` trait methods
    // need while keeping the index `Send + Sync`.
    state: Mutex<IndexState>,
}

impl InMemoryIndex {
    /// Build an index that embeds summaries with `embedder`.
    #[must_use]
    pub fn new(embedder: Arc<dyn Embedder>) -> Self {
        Self {
            embedder,
            state: Mutex::new(IndexState::default()),
        }
    }

    /// Build an index using the default [`HashEmbedder`] fallback.
    #[must_use]
    pub fn with_hash_embedder() -> Self {
        Self::new(Arc::new(HashEmbedder::default()))
    }
}

impl fmt::Debug for InMemoryIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `dyn Embedder` is not `Debug`; surface its dimensionality instead.
        // Deliberately does not lock `state`: a `Debug` impl must not risk
        // blocking or interacting with lock poisoning.
        f.debug_struct("InMemoryIndex")
            .field("embed_dim", &self.embedder.dim())
            .finish_non_exhaustive()
    }
}

impl MemoryIndex for InMemoryIndex {
    fn upsert(&self, mut record: IndexRecord) -> Result<(), MemError> {
        // Precomputed vector wins (the binary offloads the embed to the blocking
        // pool to keep ONNX off the async runtime worker — ASYNCBLOCK); else reuse
        // the indexed embedding when this note's summary is byte-identical to the
        // stored one. The embedding is a pure function of the summary, so an
        // unchanged summary need not be re-embedded — this keeps an incremental
        // sync incremental on the EMBED axis, since snapshot-restored records
        // always arrive with `embedding: None`. The reuse read is a brief lock;
        // the fallible, CPU-heavy embed still runs off any guard, below.
        let reused = record.embedding.take().or_else(|| {
            let guard = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            guard
                .entries
                .get(&record.note_id)
                .filter(|entry| entry.record.summary == record.summary)
                .map(|entry| entry.embedding.clone())
        });

        let embedding = if let Some(vector) = reused {
            vector
        } else {
            self.embedder
                .embed(std::slice::from_ref(&record.summary))?
                .into_iter()
                .next()
                .unwrap_or_default()
        };

        let mut guard = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        apply_record(&mut guard, record, embedding);
        Ok(())
    }

    fn upsert_batch(&self, records: Vec<IndexRecord>) -> Result<(), MemError> {
        if records.is_empty() {
            return Ok(());
        }
        // Reuse the indexed embedding for any record whose summary is
        // byte-identical to the one already stored under its note id — the
        // embedding is a pure function of the summary. This is what makes an
        // incremental sync incremental on the EMBED axis, not just on blob I/O:
        // snapshot-restored records always arrive with `embedding: None`, so
        // without reuse every sync re-runs ONNX inference over the WHOLE live
        // corpus (stalling the runtime worker and holding the model mutex against
        // concurrent recalls). Snapshot the current summaries+embeddings under a
        // brief lock, then embed only the misses OFF the lock (axiom
        // rust_quality_74: the fallible, CPU-heavy step must not run under the
        // guard) and write under a second lock.
        let reused: Vec<Option<Vec<f32>>> = {
            let guard = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            records
                .iter()
                .map(|record| {
                    if record.embedding.is_some() {
                        return None;
                    }
                    guard
                        .entries
                        .get(&record.note_id)
                        .filter(|entry| entry.record.summary == record.summary)
                        .map(|entry| entry.embedding.clone())
                })
                .collect()
        };

        // ONE embedder call for every summary that has neither a caller-precomputed
        // vector nor a reusable indexed one. `Embedder::embed` is order- and
        // count-preserving (one vector per input), so a batch amortizes the
        // per-call model-run overhead that dominates a cold rebuild — the reason
        // this override exists over the trait's serial default.
        let summaries: Vec<String> = records
            .iter()
            .zip(&reused)
            .filter(|(record, hit)| hit.is_none() && record.embedding.is_none())
            .map(|(record, _)| record.summary.clone())
            .collect();
        let mut fresh = self.embedder.embed(&summaries)?;
        // A misbehaving embedder that returns too few vectors degrades the
        // unmatched records to a zero vector (empty ⇒ cosine 0) rather than
        // panicking or failing the whole batch — the same per-record resilience
        // `upsert` gets from `unwrap_or_default`. `resize` also truncates an
        // over-long return so the drain below pairs every miss exactly once.
        fresh.resize(summaries.len(), Vec::new());
        let mut fresh = fresh.into_iter();
        let mut guard = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        for (mut record, hit) in records.into_iter().zip(reused) {
            // Precedence matches the miss-selection above: caller-precomputed, then
            // reused, then a fresh vector consumed in the same record order it was
            // embedded (so `fresh` stays aligned with `summaries`).
            let embedding = record
                .embedding
                .take()
                .or(hit)
                .unwrap_or_else(|| fresh.next().unwrap_or_default());
            // `apply_record` is the same lamport-monotonic apply path `upsert`
            // uses: a sync recomputing from a stale op-log view must not roll any
            // note back. A fresh vector already drained from `fresh` for a
            // rejected record is simply dropped — alignment is preserved because
            // the drain happened above.
            apply_record(&mut guard, record, embedding);
        }
        Ok(())
    }

    fn embed_summary(&self, summary: &str) -> Result<Vec<f32>, MemError> {
        Ok(self
            .embedder
            .embed(&[summary.to_string()])?
            .into_iter()
            .next()
            .unwrap_or_default())
    }

    fn search(&self, query: &Query) -> Result<SearchResult, MemError> {
        // Embed and tokenize the query BEFORE locking: the embedder is the only
        // fallible step, so a failure must not be entangled with the lock, and
        // the lock is held for the minimum span.
        let query_embedding = self
            .embedder
            .embed(std::slice::from_ref(&query.text))?
            .into_iter()
            .next()
            .unwrap_or_default();
        let query_tokens = tokenize(&query.text);

        // Step 1 — scope filter first: cheapest correctness gate. Score only the
        // records this query may legally see, so the legs never rank a record
        // out of scope. Copy out the fields the pipeline needs and release the
        // lock immediately.
        let candidates: Vec<Candidate> = {
            let guard = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            guard
                .entries
                .values()
                .filter(|entry| in_scope(&entry.record.scope, &query.team, &query.repo))
                .map(|entry| Candidate::score(entry, &query_tokens, &query_embedding))
                .collect()
        };
        if candidates.is_empty() {
            return Ok(SearchResult {
                pointers: Vec::new(),
                total_matched: 0,
            });
        }

        // Steps 2–4 — rank each leg independently, then fuse with RRF. Ranking
        // separately means the legs need no shared scale; RRF only consumes
        // ordinal positions, which keeps the lexical and semantic signals
        // comparable even though their raw scores are not. `rank_leg` drops
        // candidates that score zero in a leg, so a candidate irrelevant in BOTH
        // legs earns no RRF mass and never reaches the fused output — recency
        // alone cannot float an unrelated note to the surface.
        // The lexical leg floors at exactly 0 (no shared term = no signal); the
        // semantic leg floors at the embedder's own relevance threshold, so a
        // dense model's small non-zero cosines for unrelated text are not mistaken
        // for signal (see `Embedder::relevance_threshold`).
        let keyword_leg = rank_leg(
            candidates.iter().map(|c| (c.note_id, c.keyword, c.updated)),
            0.0,
        );

        // Run the semantic (vector) leg only when the embedder's vector output
        // carries signal beyond the exact keyword leg. The HashEmbedder fallback
        // returns false — its hashed vector merely re-derives token overlap, with
        // collisions — so a lexical build ranks keyword-only and a hash collision
        // can no longer float an unrelated note to the surface.
        let fused = if self.embedder.contributes_semantic_leg() {
            let vector_leg = rank_leg(
                candidates.iter().map(|c| (c.note_id, c.vector, c.updated)),
                self.embedder.relevance_threshold(),
            );
            rrf_fuse(&[keyword_leg, vector_leg], RANK_CONSTANT)
        } else {
            rrf_fuse(&[keyword_leg], RANK_CONSTANT)
        };

        // Step 5 — recency decay: multiply the fused score by a per-type
        // exponential half-life so durable knowledge ages slowly and ephemeral
        // context ages fast.
        let by_id: BTreeMap<NoteId, Candidate> =
            candidates.into_iter().map(|c| (c.note_id, c)).collect();

        // Invert the source-stamped relations: a candidate's OUTGOING relation to
        // `M` becomes an INCOMING relation on `M`. Built over the WHOLE in-scope
        // candidate set (not just query matches), so a superseding note that does
        // not itself match the query text still demotes the note it supersedes.
        // `Contradicts` is mutual — both notes are tagged. Scanning only in-scope
        // candidates keeps a cross-scope superseding note's id from leaking.
        let incoming = build_incoming_relations(&by_id);

        let mut pointers: Vec<Pointer> = Vec::with_capacity(fused.len());
        for (id, fused_score) in fused {
            let Some(candidate) = by_id.get(&id) else {
                continue;
            };
            // Age on the LATER of the note's own update and its last reinforcement:
            // a note that keeps proving useful stays "fresh" even if its content is
            // old, so use — not just authorship time — drives recency. `max` over
            // the raw millis; `saturating_sub` then `max(0)` clamps negative ages (a
            // note updated "after" now) to 0 without risking i64 overflow.
            //
            // A reinforcement time in the FUTURE of `now` is ignored, not clamped:
            // `last_reinforced` comes from the author-chosen ULID of a `Reinforce`
            // op and converges by absorbing `max`, so a forged far-future value
            // would otherwise pin this note's age at zero for every querier,
            // forever. Clamping to `now` would not help — `min(forged, now)` reads
            // as "reinforced this instant" on every future query too. Ignoring it
            // means a forgery contributes nothing, while an honestly skewed clock
            // self-heals once real time passes it.
            //
            // `updated` is DELIBERATELY not guarded the same way (an asymmetry,
            // not an oversight): unlike the absorbing reinforcer max, the pointer
            // converges last-writer-wins by lamport, so a forged future `updated`
            // is displaced by any later honest edit and is visible in `history` —
            // and a full ignore would misrank the common honest case of a writer
            // clock seconds ahead, which the negative-age clamp below absorbs
            // gracefully.
            let effective_updated = match candidate.last_reinforced {
                Some(lr) if lr.as_millis() <= query.now.as_millis() => {
                    candidate.updated.as_millis().max(lr.as_millis())
                }
                _ => candidate.updated.as_millis(),
            };
            let age = query
                .now
                .as_millis()
                .saturating_sub(effective_updated)
                .max(0);
            let incoming_rels = incoming.get(&id);

            // A superseded/duplicate note is demoted hard but still returned;
            // contradict/refine only tag.
            let demotion =
                if incoming_rels.is_some_and(|rs| rs.iter().any(|r| r.rel.demotes_target())) {
                    RELATION_DEMOTION
                } else {
                    1.0
                };
            let score = fused_score
                * recency_weight(age, candidate.note_type)
                * demotion
                * reinforcement_boost(candidate.reinforcer_count);

            let mut pointer = candidate.to_pointer(id, score);
            if let Some(rels) = incoming_rels {
                pointer.relations.clone_from(rels);
            }
            pointers.push(pointer);
        }

        // Every pointer here cleared the relevance floor (it came from `fused`),
        // and they are all in scope, so this is the total-matched count the
        // caller is owed — captured BEFORE `k`/budget truncation drops the tail.
        let total_matched = pointers.len();

        // Step 6 — deterministic ordering, top-k, then token budget. Sort by
        // score descending with a `note_id` tie-break so equal scores are
        // ordered reproducibly; `total_cmp` orders floats without NaN ambiguity.
        pointers.sort_by(|a, b| b.score.total_cmp(&a.score).then(a.note_id.cmp(&b.note_id)));
        pointers.truncate(query.k);

        Ok(SearchResult {
            pointers: apply_token_budget(pointers, query.token_budget),
            total_matched,
        })
    }

    fn nearest_duplicate(
        &self,
        summary: &str,
        team: &str,
        repo: &RepoScope,
        threshold: f32,
        precomputed_vec: Option<&[f32]>,
    ) -> Result<Option<NearDuplicate>, MemError> {
        // Pick the metric from the embedder, NOT from the record: a lexical build
        // (HashEmbedder) hashes tokens into a small bucket space, so its cosine is
        // collision-prone and would flag disjoint summaries as duplicates. Token
        // Jaccard is exact overlap, the honest — if weaker — lexical signal.
        let semantic = self.embedder.contributes_semantic_leg();
        // Embed BEFORE the lock (the only fallible step), mirroring `search`, so a
        // model failure is never entangled with the lock and the lock span is
        // minimal. Skip the embed entirely on a lexical build — it would be a
        // collision-prone vector we then refuse to trust anyway. Use the caller's
        // precomputed vector when present (the binary computes it on the blocking
        // pool — ASYNCBLOCK) rather than embedding here.
        let query_vec: Vec<f32> = if semantic {
            match precomputed_vec {
                Some(precomputed) => precomputed.to_vec(),
                None => self
                    .embedder
                    .embed(&[summary.to_string()])?
                    .into_iter()
                    .next()
                    .unwrap_or_default(),
            }
        } else {
            Vec::new()
        };
        let query_tokens = tokenize(summary);

        let guard = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let mut best: Option<NearDuplicate> = None;
        for entry in guard.entries.values() {
            if !in_scope(&entry.record.scope, team, repo) {
                continue;
            }
            let similarity = if semantic {
                cosine(&query_vec, &entry.embedding)
            } else {
                jaccard(&query_tokens, &doc_tokens(&entry.record))
            };
            // NaN-safe skip: a misbehaving dense model can emit NaN components, and
            // a bare `similarity < threshold` would let NaN THROUGH (NaN < t is
            // false). Once held in `best`, NaN is undisplaceable (`x > NaN` is
            // always false), so every subsequent write would be refused naming an
            // arbitrary note. Dropping NaN mirrors `rank_leg`'s `score > floor`
            // fail-open discipline.
            if similarity.is_nan() || similarity < threshold {
                continue;
            }
            // Keep the single CLOSEST match at or above the floor: the dedup error
            // names one existing note, so surface the strongest candidate rather
            // than whichever the map happened to yield first.
            let improves = match &best {
                Some(current) => similarity > current.similarity,
                None => true,
            };
            if improves {
                best = Some(NearDuplicate {
                    note_id: entry.record.note_id,
                    similarity,
                });
            }
        }
        Ok(best)
    }

    fn remove(&self, id: NoteId) -> Result<(), MemError> {
        let mut guard = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        guard.entries.remove(&id);
        Ok(())
    }

    fn remove_at(&self, id: NoteId, lamport: u64, object_key: &str) -> Result<(), MemError> {
        let mut guard = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        guard.entries.remove(&id);
        // Keep the watermark itself lamport-monotonic too: a redundant or
        // out-of-order `remove_at` (e.g. a retried call) must never regress a
        // watermark a prior call already recorded.
        let candidate = (lamport, object_key.to_owned());
        let should_update = guard.removed.get(&id).is_none_or(|existing| {
            (candidate.0, candidate.1.as_str()) > (existing.0, existing.1.as_str())
        });
        if should_update {
            guard.removed.insert(id, candidate);
        }
        Ok(())
    }

    fn locate(&self, id: NoteId) -> Result<Option<Located>, MemError> {
        let guard = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        // `cid` is `Copy`; only the object key allocates. The record already
        // holds both, so this is a pure lookup with no recomputation.
        Ok(guard.entries.get(&id).map(|entry| Located {
            object_key: entry.record.object_key.clone(),
            cid: entry.record.cid,
            key_epoch: entry.record.key_epoch,
        }))
    }

    fn retain(&self, keep: &BTreeSet<NoteId>, baseline_lamport: u64) -> Result<(), MemError> {
        let mut guard = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        // `BTreeMap::retain` drops in place every entry whose id is absent from
        // `keep`, in one pass without reallocating the map. The `||` keeps an
        // entry `keep` does not name when its OWN lamport outranks the view
        // `keep` was built from — a concurrent remember/edit this view's
        // convergence never saw (see the trait doc for the race this closes).
        guard.entries.retain(|note_id, entry| {
            keep.contains(note_id) || entry.record.lamport > baseline_lamport
        });
        // Bound the removal-watermark map: drop a watermark whose id `keep`
        // does NOT name. This is safe even when `keep` reflects a STALE view
        // (one that predates the redact/forget that set the watermark),
        // because a caller always pairs `retain(keep)` with an
        // `upsert_batch`/`upsert` built from that SAME view (see `replay_full`/
        // `sync_incremental`) — so any id `keep` excludes cannot appear in the
        // records the paired call is about to apply, and dropping its
        // watermark here cannot reopen the race it exists to close. An id
        // `keep` STILL names (the view has not caught up with the removal)
        // keeps its watermark, so `apply_record` can still refuse that same
        // view's own stale re-insert.
        guard
            .removed
            .retain(|note_id, _watermark| keep.contains(note_id));
        Ok(())
    }

    fn all_records(&self) -> Result<Vec<IndexRecord>, MemError> {
        // Clone each record out under the lock so no borrow of the guarded map
        // escapes; the guard drops at end of statement. Records are body-free, so
        // this owned copy is cheap relative to a note body.
        let guard = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        Ok(guard
            .entries
            .values()
            .map(|entry| entry.record.clone())
            .collect())
    }

    fn is_semantic(&self) -> bool {
        // Defer to the embedder: only a model that earns its vector leg makes
        // this index semantic; the HashEmbedder fallback re-derives token overlap
        // the keyword leg already computes, so it reports lexical (false).
        self.embedder.contributes_semantic_leg()
    }
}

/// `BM25` term-frequency saturation parameter. 1.2 is the standard default
/// from Robertson & Zaragoza, "The Probabilistic Relevance Framework: BM25 and
/// Beyond" (2009).
const K1: f32 = 1.2;

/// One scope-filtered record reduced to the fields the ranking pipeline needs,
/// with both leg scores precomputed under the lock.
struct Candidate {
    note_id: NoteId,
    keyword: f32,
    vector: f32,
    note_type: NoteType,
    updated: Timestamp,
    // The convergence clock, carried through ranking untouched so it can be
    // stamped onto the emitted `Pointer`; the ranking legs read `updated`.
    lamport: u64,
    summary: String,
    scope: Scope,
    author: Ss58,
    /// This note's OUTGOING typed relations, carried through ranking so the
    /// search loop can invert them into per-target demotions and tags.
    relations: Vec<TypedLink>,
    /// How many DISTINCT identities reinforced this note. Only the COUNT rides
    /// into ranking (the boost is `f(|reinforcers|)`), not the whole author set —
    /// keeping the ranking candidate lean.
    reinforcer_count: usize,
    /// Latest reinforcement time, so the recency leg can age on
    /// `max(updated, last_reinforced)` rather than `updated` alone.
    last_reinforced: Option<Timestamp>,
}

impl Candidate {
    fn score(entry: &Entry, query_tokens: &[String], query_embedding: &[f32]) -> Self {
        let record = &entry.record;
        Self {
            note_id: record.note_id,
            keyword: keyword_score(query_tokens, &doc_tokens(record)),
            vector: cosine(query_embedding, &entry.embedding),
            note_type: record.note_type,
            updated: record.updated,
            lamport: record.lamport,
            summary: record.summary.clone(),
            scope: record.scope.clone(),
            author: record.author.clone(),
            relations: record.relations.clone(),
            reinforcer_count: record.reinforcers.len(),
            last_reinforced: record.last_reinforced,
        }
    }

    /// Build the pointer. `relations` (INCOMING) is filled by the search loop
    /// after the reverse relation map is known; it starts empty here.
    fn to_pointer(&self, note_id: NoteId, score: f32) -> Pointer {
        Pointer {
            note_id,
            summary: self.summary.clone(),
            score,
            scope: self.scope.clone(),
            author: self.author.clone(),
            updated: self.updated,
            lamport: self.lamport,
            relations: Vec::new(),
        }
    }
}

/// Invert every candidate's OUTGOING typed relations into a per-target map of
/// INCOMING relations, so recall can demote the notes a candidate supersedes /
/// duplicates and tag those it contradicts / refines. `Contradicts` is recorded
/// on BOTH notes (the tension is mutual). Keyed by target `NoteId`.
fn build_incoming_relations(
    by_id: &BTreeMap<NoteId, Candidate>,
) -> BTreeMap<NoteId, Vec<PointerRelation>> {
    let mut incoming: BTreeMap<NoteId, Vec<PointerRelation>> = BTreeMap::new();
    for (from, candidate) in by_id {
        for tl in &candidate.relations {
            incoming.entry(tl.to).or_default().push(PointerRelation {
                from: *from,
                rel: tl.rel,
            });
            if tl.rel == LinkRel::Contradicts {
                incoming.entry(*from).or_default().push(PointerRelation {
                    from: tl.to,
                    rel: LinkRel::Contradicts,
                });
            }
        }
    }
    incoming
}

/// A record is in scope when its team matches and its repo is either the
/// queried repo or team-global (always visible).
fn in_scope(scope: &Scope, team: &str, repo: &RepoScope) -> bool {
    scope.team == team && (scope.repo == *repo || scope.repo == RepoScope::Global)
}

/// The lexical token bag for a record: its summary plus its tags.
fn doc_tokens(record: &IndexRecord) -> Vec<String> {
    let mut tokens = tokenize(&record.summary);
    for tag in &record.tags {
        tokens.extend(tokenize(tag));
    }
    tokens
}

/// Token-set Jaccard overlap in `[0, 1]`: `|A ∩ B| / |A ∪ B|` over DISTINCT
/// tokens. This is the write-time dedup metric on a lexical build, where cosine
/// over the collision-prone `HashEmbedder` vector cannot be trusted (see
/// [`MemoryIndex::nearest_duplicate`]). Unlike [`keyword_score`] it is bounded to
/// `[0, 1]`, so a fixed similarity threshold is meaningful against it — a BM25
/// score is unbounded and would make the threshold corpus-dependent. Two summaries
/// share `1.0` only when their token sets are identical; an empty set on either
/// side is no overlap (`0.0`), never a spurious match.
fn jaccard(left: &[String], right: &[String]) -> f32 {
    let a: BTreeSet<&str> = left.iter().map(String::as_str).collect();
    let b: BTreeSet<&str> = right.iter().map(String::as_str).collect();
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let intersection = a.intersection(&b).count();
    let union = a.union(&b).count();
    // Both sets are non-empty here, so `union >= 1`: no division by zero. Counts
    // are small distinct-token cardinalities, exactly representable in f32.
    #[expect(
        clippy::cast_precision_loss,
        reason = "token-set cardinalities are small counts; f32 represents them exactly"
    )]
    let overlap = intersection as f32 / union as f32;
    overlap
}

/// `BM25`-lite lexical score: the `BM25` term-frequency saturation term summed
/// over the distinct query tokens, with IDF and length normalization dropped.
///
/// `score = Σ_{t ∈ distinct(query)} tf(t)·(k1+1) / (tf(t)+k1)`, where `tf(t)` is
/// `t`'s frequency in the document token bag. IDF is dropped because the
/// in-memory index keeps no corpus statistics; length normalization (`b`) is
/// dropped (`b = 0`) because summaries are uniformly short. The saturation term
/// is the standard `BM25` core (Robertson & Zaragoza, 2009): repeated matches
/// help with diminishing returns.
fn keyword_score(query_tokens: &[String], doc_tokens: &[String]) -> f32 {
    if query_tokens.is_empty() || doc_tokens.is_empty() {
        return 0.0;
    }
    let mut term_freq: BTreeMap<&str, u32> = BTreeMap::new();
    for token in doc_tokens {
        *term_freq.entry(token.as_str()).or_insert(0) += 1;
    }
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut score = 0.0_f32;
    for query_token in query_tokens {
        if !seen.insert(query_token.as_str()) {
            continue;
        }
        if let Some(&freq) = term_freq.get(query_token.as_str()) {
            #[expect(
                clippy::cast_precision_loss,
                reason = "term frequencies are small counts; f32 represents them exactly"
            )]
            let tf = freq as f32;
            score += tf * (K1 + 1.0) / (tf + K1);
        }
    }
    score
}

/// Order candidates best-first for one leg and return their ids, keeping only
/// those scoring strictly above `floor`.
///
/// A candidate at or below `floor` is "no signal" in this leg, and a note with no
/// signal in *either* leg must not earn RRF mass and float up on recency alone —
/// so the relevance floor is applied here, per leg, before ranking. The caller
/// passes the right floor for each leg: `0.0` for the lexical leg (a BM25 score
/// of 0 is unambiguously no overlap), and [`Embedder::relevance_threshold`] for
/// the semantic leg (exact-zero for the [`HashEmbedder`] fallback, a calibrated
/// minimum cosine for a dense model). The floor thus lives with the signal that
/// defines it, not hard-coded in the ranker.
///
/// Ties (equal leg score) break newest-first, then by `note_id`, so equal
/// relevance reinforces recency rather than fighting it and the order is fully
/// deterministic. `total_cmp` gives a total float order with no NaN ambiguity.
fn rank_leg(scored: impl Iterator<Item = (NoteId, f32, Timestamp)>, floor: f32) -> Vec<NoteId> {
    let mut rows: Vec<(NoteId, f32, Timestamp)> =
        scored.filter(|&(_, score, _)| score > floor).collect();
    rows.sort_by(|a, b| b.1.total_cmp(&a.1).then(b.2.cmp(&a.2)).then(a.0.cmp(&b.0)));
    rows.into_iter().map(|(id, _, _)| id).collect()
}

/// One day in milliseconds.
const DAY_MS: i64 = 24 * 60 * 60 * 1000;

/// Recency half-life per note type, in milliseconds.
///
/// Rationale: durable knowledge should outlive ephemeral notes in ranking.
/// `Decision`/`Convention`/`Reference` are foundational, so they decay slowly
/// (365 days); a `Gotcha` stays relevant for a release cycle or two then often
/// becomes obsolete (90 days); `Context` frames current work and misleads once
/// stale (7 days).
fn half_life_millis(note_type: NoteType) -> i64 {
    match note_type {
        NoteType::Decision | NoteType::Convention | NoteType::Reference => 365 * DAY_MS,
        NoteType::Gotcha => 90 * DAY_MS,
        NoteType::Context => 7 * DAY_MS,
    }
}

/// Exponential recency weight in `(0, 1]`: `0.5 ^ (age / half_life)`.
///
/// `age` is assumed already clamped to `>= 0`. The weight is 1.0 at age 0 and
/// halves every half-life; computed via `exp` so it never produces `NaN`.
fn recency_weight(age_millis: i64, note_type: NoteType) -> f32 {
    let half_life = half_life_millis(note_type);
    #[expect(
        clippy::cast_precision_loss,
        reason = "age and half-life are heuristic recency scalars; f32 precision is ample for a decay weight"
    )]
    let ratio = age_millis.max(0) as f32 / half_life as f32;
    // 0.5^ratio == exp(ln(0.5)·ratio) == exp(-ln(2)·ratio).
    (-std::f32::consts::LN_2 * ratio).exp()
}

/// Ranking multiplier from a note's distinct-reinforcer count:
/// `min(1 + k·ln(1 + n), MAX)`, always `>= 1.0` (a never-reinforced note, `n = 0`,
/// gets exactly `1.0`).
///
/// The `ln` makes each further endorsement worth less than the last, and the hard
/// `MAX` cap keeps reinforcement from overriding relevance/recency outright —
/// usage re-ranks WITHIN the relevant set, it does not float an off-topic note.
/// `n` is already a distinct-author count (the Sybil bound lives upstream in
/// convergence), so this function trusts its input.
fn reinforcement_boost(reinforcer_count: usize) -> f32 {
    #[expect(
        clippy::cast_precision_loss,
        reason = "reinforcer counts are small; f32 is ample for a heuristic ranking boost"
    )]
    let count = reinforcer_count as f32;
    (1.0 + REINFORCE_BOOST_K * (1.0 + count).ln()).min(MAX_REINFORCE_BOOST)
}

/// Estimate a text's token cost as roughly four characters per token, the common
/// rule of thumb for English text under byte-pair tokenizers.
///
/// Rounds UP (`div_ceil`), so any non-empty text costs at least one token. Plain
/// integer division floored a 1–3-char text to 0, which let a `Some(0)` budget
/// admit such summaries "for free" instead of returning nothing — and made the
/// cost of short summaries systematically understated.
///
/// This is the single token-accounting rule the crate shares: recall's
/// `token_budget` and [`crate::brief`]'s cap both call it, so a budget means the
/// same thing on both paths.
pub(crate) fn estimate_tokens(text: &str) -> usize {
    text.chars().count().div_ceil(4)
}

/// Greedily keep already-ranked pointers while their summed estimated token cost
/// stays within `budget`, stopping at the first pointer that would exceed it.
fn apply_token_budget(pointers: Vec<Pointer>, budget: Option<usize>) -> Vec<Pointer> {
    let Some(budget) = budget else {
        return pointers;
    };
    let mut used = 0_usize;
    let mut kept = Vec::with_capacity(pointers.len());
    for pointer in pointers {
        let cost = estimate_tokens(&pointer.summary);
        if used + cost > budget {
            break;
        }
        used += cost;
        kept.push(pointer);
    }
    kept
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test, not a crash to avoid"
    )]

    use super::{
        DEFAULT_EMBED_DIM, Embedder, HashEmbedder, InMemoryIndex, IndexRecord, MAX_REINFORCE_BOOST,
        MemoryIndex, Pointer, Query, apply_token_budget, cosine, embed_one, estimate_tokens,
        in_scope, jaccard, keyword_score, reinforcement_boost, rrf_fuse,
    };
    use crate::domain::{Blake3Hash, NoteId, NoteType, RepoScope, Scope, Ss58, Timestamp};
    use crate::error::MemError;
    use proptest::prelude::*;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// An [`Embedder`] whose vectors are all-zero, so the semantic leg always
    /// scores 0 — isolates the lexical leg (a note surfaces only via keyword).
    struct ZeroEmbedder;
    impl Embedder for ZeroEmbedder {
        fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, MemError> {
            Ok(texts.iter().map(|_| vec![0.0; DEFAULT_EMBED_DIM]).collect())
        }
        fn dim(&self) -> usize {
            DEFAULT_EMBED_DIM
        }
    }

    /// An [`Embedder`] mapping every text to the SAME unit vector, so cosine is
    /// always 1.0 regardless of words — isolates the semantic leg and lets a test
    /// drive the configurable relevance threshold.
    struct ConstantEmbedder {
        threshold: f32,
    }
    impl Embedder for ConstantEmbedder {
        fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, MemError> {
            Ok(texts
                .iter()
                .map(|_| {
                    let mut v = vec![0.0; DEFAULT_EMBED_DIM];
                    v[0] = 1.0;
                    v
                })
                .collect())
        }
        fn dim(&self) -> usize {
            DEFAULT_EMBED_DIM
        }
        fn relevance_threshold(&self) -> f32 {
            self.threshold
        }
    }

    /// An [`Embedder`] whose every vector is all-NaN — models a misbehaving dense
    /// model so a test can drive the NaN-safety path in `nearest_duplicate`
    /// (cosine over NaN components yields NaN).
    struct NanEmbedder;
    impl Embedder for NanEmbedder {
        fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, MemError> {
            Ok(texts
                .iter()
                .map(|_| vec![f32::NAN; DEFAULT_EMBED_DIM])
                .collect())
        }
        fn dim(&self) -> usize {
            DEFAULT_EMBED_DIM
        }
    }

    /// An [`Embedder`] that always fails — drives the fallible-embed path so a
    /// test can prove the error propagates rather than being swallowed.
    struct FailingEmbedder;
    impl Embedder for FailingEmbedder {
        fn embed(&self, _texts: &[String]) -> Result<Vec<Vec<f32>>, MemError> {
            Err(MemError::Storage("simulated embed failure".to_owned()))
        }
        fn dim(&self) -> usize {
            DEFAULT_EMBED_DIM
        }
    }

    fn author() -> Result<Ss58, Box<dyn std::error::Error>> {
        Ok(Ss58::new("5".repeat(48))?)
    }

    fn record(
        team: &str,
        repo: RepoScope,
        note_type: NoteType,
        summary: &str,
        updated: i64,
    ) -> Result<IndexRecord, Box<dyn std::error::Error>> {
        Ok(IndexRecord {
            note_id: NoteId::new(),
            object_key: "team/repo/mem/ver_0".to_string(),
            cid: Blake3Hash::new([0_u8; 32]),
            scope: Scope {
                team: team.to_string(),
                repo,
            },
            note_type,
            author: author()?,
            updated: Timestamp::new(updated),
            // The index never ranks on lamport, so these fixtures fix it at 0;
            // convergence ordering is exercised by the op-log/store tests.
            lamport: 0,
            // Single-epoch fixtures: epoch tagging is exercised by the store tests.
            key_epoch: 0,
            tags: BTreeSet::new(),
            summary: summary.to_string(),
            relations: Vec::new(),
            reinforcers: BTreeSet::new(),
            last_reinforced: None,
            embedding: None,
        })
    }

    fn query(text: &str, repo: RepoScope, k: usize, now: i64) -> Query {
        Query {
            text: text.to_string(),
            team: "team".to_string(),
            repo,
            k,
            token_budget: None,
            now: Timestamp::new(now),
        }
    }

    fn ids(pointers: &[Pointer]) -> BTreeSet<NoteId> {
        pointers.iter().map(|p| p.note_id).collect()
    }

    #[test]
    fn upsert_batch_indexes_the_same_set_as_serial_upsert() -> TestResult {
        // The batch form must be observably identical to N single `upsert`s —
        // same notes indexed, same ranked output. This is the contract the
        // store's cold-boot rebuild leans on when it swaps its per-note loop for
        // one batched embed, so the test asserts ranking agreement (the batch is
        // the reference impl's fast twin), not just set membership.
        let recs = [
            record(
                "team",
                RepoScope::Global,
                NoteType::Decision,
                "rust async cancellation safety",
                3_000,
            )?,
            record(
                "team",
                RepoScope::Global,
                NoteType::Gotcha,
                "s3 blob decode skip on fault",
                2_000,
            )?,
            record(
                "team",
                RepoScope::Global,
                NoteType::Convention,
                "op-log hash chain verify order",
                1_000,
            )?,
        ];

        let serial = InMemoryIndex::with_hash_embedder();
        for rec in &recs {
            serial.upsert(rec.clone())?;
        }
        let batch = InMemoryIndex::with_hash_embedder();
        batch.upsert_batch(recs.to_vec())?;

        for text in [
            "async cancellation",
            "s3 blob decode",
            "hash chain",
            "nothing matches here",
        ] {
            let q = query(text, RepoScope::Global, 10, 4_000);
            let serial_ranked: Vec<NoteId> = serial
                .search(&q)?
                .pointers
                .iter()
                .map(|p| p.note_id)
                .collect();
            let batch_ranked: Vec<NoteId> = batch
                .search(&q)?
                .pointers
                .iter()
                .map(|p| p.note_id)
                .collect();
            assert_eq!(
                serial_ranked, batch_ranked,
                "batch and serial upsert must rank identically for query {text:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn upsert_batch_empty_is_a_noop() -> TestResult {
        let index = InMemoryIndex::with_hash_embedder();
        index.upsert_batch(Vec::new())?;
        assert_eq!(
            index
                .search(&query("anything", RepoScope::Global, 5, 0))?
                .total_matched,
            0
        );
        Ok(())
    }

    #[test]
    fn upsert_consumes_a_precomputed_embedding_hint() -> TestResult {
        use std::sync::PoisonError;
        // The offload contract (ASYNCBLOCK): when the binary precomputes the summary
        // embedding on the blocking pool and threads it in via `IndexRecord.embedding`,
        // `upsert` must store THAT vector verbatim and NOT re-run the embedder. The
        // sentinel is uniform-valued, which the token-hash `HashEmbedder` cannot
        // produce for a real summary, so an equal stored vector can only mean the hint
        // was consumed rather than recomputed.
        let index = InMemoryIndex::with_hash_embedder();
        let sentinel = vec![7.0_f32; DEFAULT_EMBED_DIM];
        let mut rec = record(
            "team",
            RepoScope::Global,
            NoteType::Gotcha,
            "hint summary",
            0,
        )?;
        rec.embedding = Some(sentinel.clone());
        let note_id = rec.note_id;
        index.upsert(rec)?;

        let guard = index.state.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = guard
            .entries
            .get(&note_id)
            .ok_or("the record must be indexed")?;
        assert_eq!(
            entry.embedding, sentinel,
            "upsert must store the precomputed hint verbatim, not a re-embed"
        );
        // The transient hint is `take`n out of the stored record — no redundant copy,
        // and the `#[serde(skip)]` invariant (embedding always `None` on a stored
        // record) holds regardless of what the caller passed in.
        assert!(
            entry.record.embedding.is_none(),
            "the hint must be taken out of the stored record"
        );
        Ok(())
    }

    #[test]
    fn index_record_embedding_is_never_serialized() -> TestResult {
        // `IndexRecord.embedding` is a transient in-process hint (`#[serde(skip)]`): a
        // snapshot must never persist a dense vector per record. Round-trip a record
        // that carries a hint and assert the field is dropped on both legs, so a
        // restored snapshot record always re-embeds via `upsert(None)` rather than
        // resurrecting a stale vector.
        let mut rec = record(
            "team",
            RepoScope::Global,
            NoteType::Decision,
            "persist me",
            0,
        )?;
        rec.embedding = Some(vec![1.5_f32; DEFAULT_EMBED_DIM]);
        let json = serde_json::to_string(&rec)?;
        assert!(
            !json.contains("embedding"),
            "the skipped field must not appear in the serialized form"
        );
        let restored: IndexRecord = serde_json::from_str(&json)?;
        assert!(
            restored.embedding.is_none(),
            "a deserialized record must carry no embedding hint"
        );
        // Every persisted field round-trips: with the hint cleared the records are
        // equal, which is exactly why `Eq` was dropped but `PartialEq` kept.
        rec.embedding = None;
        assert_eq!(restored, rec, "all persisted fields round-trip unchanged");
        Ok(())
    }

    #[test]
    fn upsert_batch_propagates_embed_failure() -> TestResult {
        // A failing embedder must surface as an error, exactly as single `upsert`
        // does — the batch must not swallow a systemic embed fault.
        let index = InMemoryIndex::new(Arc::new(FailingEmbedder));
        let result = index.upsert_batch(vec![record(
            "team",
            RepoScope::Global,
            NoteType::Gotcha,
            "x",
            0,
        )?]);
        assert!(
            matches!(result, Err(MemError::Storage(_))),
            "a failing embedder must propagate through upsert_batch"
        );
        Ok(())
    }

    #[test]
    fn hash_collision_does_not_surface_an_unrelated_note() -> TestResult {
        // M4: the lexical fallback ranks keyword-only, so a 64-bucket hash collision
        // (two disjoint texts with an identical HashEmbedder vector, cosine 1.0) can
        // no longer readmit an unrelated note the exact keyword leg would never match.
        assert!(
            !HashEmbedder::default().contributes_semantic_leg(),
            "the lexical fallback must rank keyword-only"
        );

        // Find two DISTINCT single-token texts that collide to the same vector
        // (guaranteed by pigeonhole: 600 tokens into DEFAULT_EMBED_DIM=64 buckets).
        let words: Vec<String> = (0..600).map(|i| format!("tok{i}")).collect();
        let mut collision: Option<(&str, &str)> = None;
        'outer: for (i, wi) in words.iter().enumerate() {
            let ei = embed_one(wi, DEFAULT_EMBED_DIM);
            for wj in &words[i + 1..] {
                if embed_one(wj, DEFAULT_EMBED_DIM) == ei {
                    collision = Some((wi, wj));
                    break 'outer;
                }
            }
        }
        let (word_a, word_b) =
            collision.ok_or("a 64-bucket space must collide within 600 single-token texts")?;

        // Index a note whose only content token is `word_a`; recall `word_b` — a
        // disjoint token with a COLLIDING embedding. Keyword-only ranking surfaces
        // nothing (no shared term); the old vector leg would have matched at cosine 1.
        let index = InMemoryIndex::with_hash_embedder();
        index.upsert(record(
            "team",
            RepoScope::Global,
            NoteType::Gotcha,
            word_a,
            0,
        )?)?;
        let result = index.search(&query(word_b, RepoScope::Global, 5, 0))?;
        assert_eq!(
            result.total_matched, 0,
            "a hash collision must not surface an unrelated note under the lexical build"
        );
        Ok(())
    }

    #[test]
    fn upsert_then_search_returns_pointer_not_body() -> TestResult {
        let index = InMemoryIndex::with_hash_embedder();
        let rec = record(
            "team",
            RepoScope::Repo("thebrain".to_string()),
            NoteType::Decision,
            "rust async cancellation safety",
            1_000,
        )?;
        let id = rec.note_id;
        index.upsert(rec)?;

        let results = index
            .search(&query(
                "async cancellation",
                RepoScope::Repo("thebrain".to_string()),
                5,
                2_000,
            ))?
            .pointers;

        assert!(!results.is_empty());
        let pointer = &results[0];
        // A `Pointer` surfaces a summary and a score and structurally has no
        // body field — hydration is a separate step.
        assert_eq!(pointer.note_id, id);
        assert!(!pointer.summary.is_empty());
        assert!(pointer.score > 0.0);
        Ok(())
    }

    #[test]
    fn scope_filter_excludes_other_repo() -> TestResult {
        let index = InMemoryIndex::with_hash_embedder();
        let here = record(
            "team",
            RepoScope::Repo("thebrain".to_string()),
            NoteType::Reference,
            "shared retrieval topic",
            1_000,
        )?;
        let elsewhere = record(
            "team",
            RepoScope::Repo("other".to_string()),
            NoteType::Reference,
            "shared retrieval topic",
            1_000,
        )?;
        let global = record(
            "team",
            RepoScope::Global,
            NoteType::Reference,
            "shared retrieval topic",
            1_000,
        )?;
        let here_id = here.note_id;
        let elsewhere_id = elsewhere.note_id;
        let global_id = global.note_id;
        index.upsert(here)?;
        index.upsert(elsewhere)?;
        index.upsert(global)?;

        let results = index
            .search(&query(
                "shared retrieval topic",
                RepoScope::Repo("thebrain".to_string()),
                10,
                2_000,
            ))?
            .pointers;
        let result_ids = ids(&results);

        assert!(result_ids.contains(&here_id));
        assert!(result_ids.contains(&global_id));
        assert!(!result_ids.contains(&elsewhere_id));
        Ok(())
    }

    proptest! {
        // `jaccard` is the lexical dedup metric; these are its defining invariants,
        // asserted generatively rather than on hand-picked token bags. It must be
        // bounded to [0,1] (so the fixed DEDUP_THRESHOLD is meaningful against it),
        // symmetric (set overlap does not depend on argument order), exactly 1.0 iff
        // the two token SETS are equal, and exactly 0.0 whenever either side is empty
        // or the sets are disjoint — an empty bag has no overlap, never a spurious
        // full match that would make the dedup gate refuse an empty-summary write.
        #[test]
        fn jaccard_properties(
            left in prop::collection::vec("[a-z]{1,6}", 0..6),
            right in prop::collection::vec("[a-z]{1,6}", 0..6),
        ) {
            // The invariant values (0.0, 1.0, and the symmetric quotient) are exact
            // small rationals here, so `==` would be reliable — but an epsilon check
            // satisfies the float-comparison lint without weakening any property.
            let close = |a: f32, b: f32| (a - b).abs() <= f32::EPSILON;
            let score = jaccard(&left, &right);
            prop_assert!((0.0..=1.0).contains(&score), "jaccard {score} out of [0,1]");
            // Symmetric: set overlap does not depend on argument order.
            prop_assert!(close(score, jaccard(&right, &left)));

            let self_score = jaccard(&left, &left);
            if left.is_empty() {
                // An empty bag floors at 0.0 by contract, not a self-identity 1.0.
                prop_assert!(close(self_score, 0.0));
            } else {
                // A non-empty set against itself: intersection == union, so n/n = 1.0.
                prop_assert!(close(self_score, 1.0));
            }

            let left_set: BTreeSet<&str> = left.iter().map(String::as_str).collect();
            let right_set: BTreeSet<&str> = right.iter().map(String::as_str).collect();
            if left_set.is_disjoint(&right_set) {
                // Disjoint (intersection 0) or empty side: exactly 0.0, no signal.
                prop_assert!(close(score, 0.0));
            }
        }
    }

    proptest! {
        // `reinforcement_boost` is a pure ranking transform; assert its contract
        // generatively. It stays in `[1, MAX]` (a note is never penalized, and no
        // amount of endorsement overrides relevance/recency), is monotonic
        // non-decreasing in the reinforcer count (more distinct endorsements never
        // lower the boost), and is exactly `1.0` at zero reinforcers.
        #[test]
        fn reinforcement_boost_properties(n in 0_usize..100_000) {
            let boost = reinforcement_boost(n);
            prop_assert!(
                (1.0..=MAX_REINFORCE_BOOST).contains(&boost),
                "boost {boost} out of [1, MAX]"
            );
            prop_assert!(
                reinforcement_boost(n + 1) >= boost,
                "boost must be monotonic non-decreasing"
            );
            // Anchor: a never-reinforced note gets exactly the identity multiplier.
            prop_assert!((reinforcement_boost(0) - 1.0).abs() <= f32::EPSILON);
        }
    }

    #[test]
    fn a_forged_future_reinforcement_is_inert_in_ranking() -> TestResult {
        // `last_reinforced` converges by absorbing `max` over an author-chosen
        // ULID time, so one member could mint a far-future Reinforce and hold a
        // note at recency 1.0 forever. The ranker must IGNORE a reinforcement
        // time in the future of `now` — clamping would not do: `min(forged, now)`
        // still reads as "reinforced this instant" on every future query.
        let index = InMemoryIndex::new(Arc::new(HashEmbedder::default()));
        let now: i64 = 1_000_000_000_000;
        let old_updated = now - 30 * 24 * 60 * 60 * 1000; // updated 30 days ago
        let summary = "cache invalidation strategy for the gateway";

        let mut forged = record(
            "team",
            RepoScope::Global,
            NoteType::Decision,
            summary,
            old_updated,
        )?;
        forged.reinforcers = BTreeSet::from([author()?]);
        forged.last_reinforced = Some(Timestamp::new(now + 500 * 24 * 60 * 60 * 1000));
        let forged_id = forged.note_id;
        index.upsert(forged)?;

        let mut unreinforced = record(
            "team",
            RepoScope::Global,
            NoteType::Decision,
            summary,
            old_updated,
        )?;
        unreinforced.reinforcers = BTreeSet::from([author()?]);
        unreinforced.last_reinforced = None;
        let unreinforced_id = unreinforced.note_id;

        let mut honest = record(
            "team",
            RepoScope::Global,
            NoteType::Decision,
            summary,
            old_updated,
        )?;
        honest.reinforcers = BTreeSet::from([author()?]);
        honest.last_reinforced = Some(Timestamp::new(now - 1000)); // just now, in the past
        let honest_id = honest.note_id;

        // Score each note ALONE (single-record indexes) so the keyword-leg RRF
        // rank is identical across the three and only the recency term differs.
        let score_alone = |rec: IndexRecord,
                           id: NoteId|
         -> Result<f32, Box<dyn std::error::Error>> {
            let idx = InMemoryIndex::new(Arc::new(HashEmbedder::default()));
            idx.upsert(rec)?;
            let result = idx.search(&query("cache invalidation", RepoScope::Global, 10, now))?;
            Ok(result
                .pointers
                .iter()
                .find(|p| p.note_id == id)
                .ok_or("note did not surface")?
                .score)
        };
        let forged_score = {
            let result = index.search(&query("cache invalidation", RepoScope::Global, 10, now))?;
            result
                .pointers
                .iter()
                .find(|p| p.note_id == forged_id)
                .ok_or("forged note did not surface")?
                .score
        };
        let unreinforced_score = score_alone(unreinforced, unreinforced_id)?;
        let honest_score = score_alone(honest, honest_id)?;

        // The forgery contributes NOTHING: same score as never reinforced …
        assert!(
            (forged_score - unreinforced_score).abs() <= f32::EPSILON,
            "a future last_reinforced must be inert: forged {forged_score} vs unreinforced {unreinforced_score}"
        );
        // … while a genuine (past) reinforcement still freshens the note.
        assert!(
            honest_score > unreinforced_score,
            "a past last_reinforced must still freshen: honest {honest_score} !> unreinforced {unreinforced_score}"
        );
        Ok(())
    }

    #[test]
    fn nearest_duplicate_drops_a_nan_similarity_instead_of_blocking() -> TestResult {
        // A NaN cosine passes a naive `similarity < threshold` guard (NaN < t is
        // false) and, once held as `best`, can never be displaced (`x > NaN` is
        // always false) — every subsequent write would be refused naming an
        // arbitrary note. NaN must be dropped, mirroring `rank_leg`'s floor.
        let index = InMemoryIndex::new(Arc::new(NanEmbedder));
        index.upsert(record(
            "team",
            RepoScope::Global,
            NoteType::Decision,
            "an existing unrelated note",
            1_000,
        )?)?;
        let dup = index.nearest_duplicate(
            "a brand new candidate summary",
            "team",
            &RepoScope::Global,
            0.9,
            None,
        )?;
        assert!(
            dup.is_none(),
            "a NaN similarity must never be reported as a duplicate: {dup:?}"
        );
        Ok(())
    }

    proptest! {
        // `in_scope` is the pure predicate `scope_filter_excludes_other_repo`
        // exercises indirectly through `search`; this asserts its contract
        // directly, generatively, over arbitrary team/repo names. The last two
        // assertions pin the exact defect finding [6] is about: a BARE
        // `RepoScope::Global` query — what `parse_repo` maps an omitted `repo`
        // to today — does NOT see a repo-scoped note, only a genuinely global
        // one. `in_scope` itself is correct (global-always-visible,
        // repo-scoped-visible-only-to-its-own-repo); the bug is that
        // `MemoryServer::logic_recall` used to hand it `Global` as the
        // "nothing requested" default instead of a bound repo.
        #[test]
        fn in_scope_properties(
            team in "[a-z0-9-]{1,20}",
            other_team in "[a-z0-9-]{1,20}",
            repo_a in "[a-z0-9-]{1,20}",
            repo_b in "[a-z0-9-]{1,20}",
        ) {
            prop_assume!(team != other_team);
            prop_assume!(repo_a != repo_b);

            let bound_note = Scope { team: team.clone(), repo: RepoScope::Repo(repo_a.clone()) };
            let global_note = Scope { team: team.clone(), repo: RepoScope::Global };
            let other_repo_note = Scope { team: team.clone(), repo: RepoScope::Repo(repo_b) };
            let other_team_note = Scope { team: other_team, repo: RepoScope::Repo(repo_a.clone()) };

            let query_repo = RepoScope::Repo(repo_a);
            let query_global = RepoScope::Global;

            // Explicit repo query: finds its own repo-scoped note plus every
            // team-global note (in_scope's documented contract), never a
            // different repo or a different team.
            prop_assert!(in_scope(&bound_note, &team, &query_repo));
            prop_assert!(in_scope(&global_note, &team, &query_repo));
            prop_assert!(!in_scope(&other_repo_note, &team, &query_repo));
            prop_assert!(!in_scope(&other_team_note, &team, &query_repo));

            // Bare Global query: only a genuinely global note is in scope: the
            // repo-scoped note above is invisible even though it belongs to the
            // same team and the queried scope's own repo.
            prop_assert!(!in_scope(&bound_note, &team, &query_global));
            prop_assert!(in_scope(&global_note, &team, &query_global));
        }
    }

    #[test]
    fn recency_breaks_ties() -> TestResult {
        let index = InMemoryIndex::with_hash_embedder();
        let older = record(
            "team",
            RepoScope::Repo("thebrain".to_string()),
            NoteType::Context,
            "identical body of text",
            1_000,
        )?;
        let newer = record(
            "team",
            RepoScope::Repo("thebrain".to_string()),
            NoteType::Context,
            "identical body of text",
            5_000,
        )?;
        let newer_id = newer.note_id;
        index.upsert(older)?;
        index.upsert(newer)?;

        let results = index
            .search(&query(
                "identical body of text",
                RepoScope::Repo("thebrain".to_string()),
                10,
                10_000,
            ))?
            .pointers;

        assert_eq!(results.first().map(|p| p.note_id), Some(newer_id));
        Ok(())
    }

    #[test]
    fn hash_embedder_is_deterministic() -> TestResult {
        let text = "the quick brown fox".to_string();
        let first = HashEmbedder::new(DEFAULT_EMBED_DIM).embed(std::slice::from_ref(&text))?;
        let second = HashEmbedder::new(DEFAULT_EMBED_DIM).embed(std::slice::from_ref(&text))?;
        // Bit-exact comparison via `to_bits` proves determinism without a float
        // `==` (which clippy forbids and which would be the wrong tool here).
        let a = &first[0];
        let b = &second[0];
        assert_eq!(a.len(), b.len());
        assert!(a.iter().zip(b).all(|(x, y)| x.to_bits() == y.to_bits()));
        Ok(())
    }

    #[test]
    fn cosine_handles_length_mismatch() {
        // A misbehaving embedder returning differing dimensions must yield "no
        // signal" (0.0), not a meaningless partial score from zip truncating to
        // the shorter vector.
        let mismatch = cosine(&[1.0_f32, 0.0], &[1.0_f32]);
        assert!(mismatch.abs() < 1e-6, "length mismatch must score 0.0");
        // Equal-length identical unit vectors still score ~1.0 (guard is inert on
        // the normal path).
        let ok = cosine(&[1.0_f32, 0.0], &[1.0_f32, 0.0]);
        assert!(
            (ok - 1.0).abs() < 1e-6,
            "equal-length vectors are unaffected"
        );
    }

    #[test]
    fn cosine_handles_zero_vector() {
        let zero = vec![0.0_f32; 8];
        let nonzero = embed_one("some words here", 8);
        let against_nonzero = cosine(&zero, &nonzero);
        let against_zero = cosine(&zero, &zero);
        assert!(!against_nonzero.is_nan());
        assert!(!against_zero.is_nan());
        assert!(against_nonzero.abs() < 1e-6);
        assert!(against_zero.abs() < 1e-6);
    }

    #[test]
    fn empty_index_search_is_empty() -> TestResult {
        let index = InMemoryIndex::with_hash_embedder();
        let result = index.search(&query("anything", RepoScope::Global, 10, 1_000))?;
        assert!(result.pointers.is_empty());
        assert_eq!(result.total_matched, 0);
        Ok(())
    }

    #[test]
    fn irrelevant_note_does_not_surface() -> TestResult {
        // The index holds only notes whose vocabulary is disjoint from the query
        // in BOTH legs (no shared lexical tokens, and — verified below — no shared
        // hash bucket, so cosine is exactly zero). Such notes must NOT surface on
        // recency alone: recall is empty, not "k recency-ranked irrelevant notes".
        let index = InMemoryIndex::with_hash_embedder();
        index.upsert(record(
            "team",
            RepoScope::Repo("thebrain".to_string()),
            NoteType::Context,
            "alpha beta gamma",
            1_000,
        )?)?;
        // Guard the test's premise: "umbrella ferret zodiac" shares neither a
        // token nor a hash bucket with "alpha beta gamma", so both legs score 0.
        let doc = embed_one("alpha beta gamma", DEFAULT_EMBED_DIM);
        let qry = embed_one("umbrella ferret zodiac", DEFAULT_EMBED_DIM);
        assert!(
            cosine(&doc, &qry).abs() < f32::EPSILON,
            "premise broken: the chosen words collide in the hash embedder"
        );

        let result = index.search(&query(
            "umbrella ferret zodiac",
            RepoScope::Repo("thebrain".to_string()),
            10,
            5_000,
        ))?;
        assert!(
            result.pointers.is_empty(),
            "an irrelevant note surfaced: {:?}",
            result.pointers
        );
        assert_eq!(result.total_matched, 0);
        Ok(())
    }

    #[test]
    fn partially_relevant_note_still_surfaces() -> TestResult {
        // A note sharing a single token with the query clears the floor and
        // surfaces. (With HashEmbedder a shared token lights BOTH legs — the same
        // bucket fires lexically and semantically — so the truly single-leg cases
        // are isolated separately by keyword_only_/vector_only_ below with stub
        // embedders that zero out one leg.)
        let index = InMemoryIndex::with_hash_embedder();
        let rec = record(
            "team",
            RepoScope::Repo("thebrain".to_string()),
            NoteType::Context,
            "alpha beta gamma",
            1_000,
        )?;
        let id = rec.note_id;
        index.upsert(rec)?;

        let result = index.search(&query(
            "alpha umbrella ferret",
            RepoScope::Repo("thebrain".to_string()),
            10,
            5_000,
        ))?;
        assert_eq!(result.total_matched, 1);
        assert_eq!(result.pointers.first().map(|p| p.note_id), Some(id));
        Ok(())
    }

    #[test]
    fn keyword_only_match_surfaces_with_zero_vector_leg() -> TestResult {
        // M11: isolate the single-leg floor. An all-zero embedder makes the vector
        // leg always 0, so a note surfaces IFF its keyword score is positive —
        // proving one positive leg clears the OR-floor and a both-zero note does
        // not (the case the old test could not isolate, since a shared token lit
        // both legs).
        let index = InMemoryIndex::new(Arc::new(ZeroEmbedder));
        let rec = record(
            "team",
            RepoScope::Global,
            NoteType::Reference,
            "alpha beta",
            1_000,
        )?;
        let id = rec.note_id;
        index.upsert(rec)?;

        // Shared token -> keyword>0, vector==0 -> surfaces.
        let hit = index.search(&query("alpha", RepoScope::Global, 10, 2_000))?;
        assert_eq!(hit.total_matched, 1);
        assert_eq!(hit.pointers.first().map(|p| p.note_id), Some(id));

        // Disjoint -> keyword==0, vector==0 -> nothing surfaces.
        let miss = index.search(&query("zeta", RepoScope::Global, 10, 2_000))?;
        assert!(miss.pointers.is_empty());
        assert_eq!(miss.total_matched, 0);
        Ok(())
    }

    #[test]
    fn vector_only_match_surfaces_with_zero_keyword_leg() -> TestResult {
        // M11 complement: a constant-vector embedder gives cosine ~1 regardless of
        // words, so a query with NO lexical overlap (keyword==0) still surfaces via
        // the vector leg alone — the other half of the OR-floor.
        let index = InMemoryIndex::new(Arc::new(ConstantEmbedder { threshold: 0.0 }));
        let rec = record(
            "team",
            RepoScope::Global,
            NoteType::Reference,
            "alpha beta",
            1_000,
        )?;
        let id = rec.note_id;
        index.upsert(rec)?;

        let result = index.search(&query("zeta umbrella", RepoScope::Global, 10, 2_000))?;
        assert_eq!(
            result.total_matched, 1,
            "a vector-only match clears the OR-floor"
        );
        assert_eq!(result.pointers.first().map(|p| p.note_id), Some(id));
        Ok(())
    }

    // The real-model complement to `vector_only_match_surfaces_with_zero_keyword_leg`:
    // a genuine paraphrase that shares NO tokens with the stored summary, run
    // through the full retrieval path, proving the dense model retrieves meaning the
    // keyword leg structurally cannot.
    //
    // The control is `ZeroEmbedder`, not `HashEmbedder`: it disables the vector leg
    // outright, so retrieval rests purely on token overlap — the exact "lexical
    // signal" we want to out-perform. (`HashEmbedder`'s vector leg is a keyword
    // proxy that hashes tokens into only 64 buckets, so disjoint words can collide
    // into a small spurious cosine; isolating the keyword leg makes the contrast
    // deterministic rather than dependent on that bucket noise.) Gated + ignored
    // because it loads the ONNX model (~90 MB download on first run) — run with
    // `cargo test --features embeddings -- --ignored`.
    #[cfg(feature = "embeddings")]
    #[test]
    #[ignore = "downloads the default embedding model and runs native ONNX Runtime"]
    fn semantic_leg_finds_a_paraphrase_the_keyword_leg_misses() -> TestResult {
        let repo = RepoScope::Repo("thebrain".to_string());
        let summary = "close every database connection in the pool on graceful shutdown";
        // Same meaning, no token in common with the summary (verified term by term),
        // so the keyword leg cannot match it — only meaning can.
        let paraphrase = "release pooled db handles when a service stops cleanly";

        // Keyword-only control: with the vector leg disabled, the zero-overlap
        // paraphrase scores 0 in the only remaining leg, so nothing surfaces.
        let keyword_only = InMemoryIndex::new(Arc::new(ZeroEmbedder));
        keyword_only.upsert(record(
            "team",
            repo.clone(),
            NoteType::Gotcha,
            summary,
            1_000,
        )?)?;
        assert!(
            keyword_only
                .search(&query(paraphrase, repo.clone(), 5, 2_000))?
                .pointers
                .is_empty(),
            "keyword-only recall must miss a paraphrase that shares no tokens"
        );

        // Real semantic leg: the dense model scores the paraphrase above the
        // relevance floor, so the same note surfaces — meaning retrieval the keyword
        // leg cannot do.
        let semantic = InMemoryIndex::new(Arc::new(super::FastEmbedder::try_new()?));
        let rec = record("team", repo.clone(), NoteType::Gotcha, summary, 1_000)?;
        let want = rec.note_id;
        semantic.upsert(rec)?;
        let semantic_hits = semantic
            .search(&query(paraphrase, repo, 5, 2_000))?
            .pointers;
        assert!(
            ids(&semantic_hits).contains(&want),
            "semantic recall must surface the paraphrased note the keyword leg missed"
        );
        Ok(())
    }

    #[test]
    fn relevance_threshold_gates_the_vector_leg() -> TestResult {
        // L4: the semantic floor lives on the embedder. A threshold (1.5) above the
        // achievable cosine (1.0) drops the vector match; with no lexical overlap
        // the note then does not surface — proving the threshold seam gates the
        // semantic leg, not a hard-coded `> 0.0` in the ranker.
        let index = InMemoryIndex::new(Arc::new(ConstantEmbedder { threshold: 1.5 }));
        index.upsert(record(
            "team",
            RepoScope::Global,
            NoteType::Reference,
            "alpha beta",
            1_000,
        )?)?;

        let result = index.search(&query("zeta umbrella", RepoScope::Global, 10, 2_000))?;
        assert!(
            result.pointers.is_empty(),
            "a cosine below the embedder threshold is not a match: {:?}",
            result.pointers
        );
        assert_eq!(result.total_matched, 0);
        Ok(())
    }

    #[test]
    fn embed_failure_propagates_through_upsert_and_search() -> TestResult {
        // M11: the embedder is the one fallible step; a failure must surface as an
        // error, not be swallowed into an empty result.
        let index = InMemoryIndex::new(Arc::new(FailingEmbedder));
        let rec = record(
            "team",
            RepoScope::Global,
            NoteType::Reference,
            "alpha",
            1_000,
        )?;
        assert!(
            index.upsert(rec).is_err(),
            "an embed failure must surface from upsert"
        );
        assert!(
            index
                .search(&query("alpha", RepoScope::Global, 10, 2_000))
                .is_err(),
            "an embed failure must surface from search"
        );
        Ok(())
    }

    #[test]
    fn locate_remove_retain_manage_entries() -> TestResult {
        // M11: cover the index-lifecycle methods directly (previously untested).
        let index = InMemoryIndex::with_hash_embedder();
        let a = record(
            "team",
            RepoScope::Global,
            NoteType::Reference,
            "alpha",
            1_000,
        )?;
        let b = record(
            "team",
            RepoScope::Global,
            NoteType::Reference,
            "beta",
            1_000,
        )?;
        let c = record(
            "team",
            RepoScope::Global,
            NoteType::Reference,
            "gamma",
            1_000,
        )?;
        let (ida, idb, idc) = (a.note_id, b.note_id, c.note_id);
        let key_a = a.object_key.clone();
        index.upsert(a)?;
        index.upsert(b)?;
        index.upsert(c)?;

        // locate: present -> Some with the stored coordinates; absent -> None.
        let located = index.locate(ida)?.ok_or("a present note must locate")?;
        assert_eq!(located.object_key, key_a);
        assert!(
            index.locate(NoteId::new())?.is_none(),
            "an unknown id locates to None"
        );

        // remove: drops just that note, siblings survive.
        index.remove(idb)?;
        assert!(
            index.locate(idb)?.is_none(),
            "a removed note no longer locates"
        );
        assert!(index.locate(ida)?.is_some(), "siblings survive a remove");

        // retain: keep only idc; ida is dropped. All three fixtures sit at
        // lamport 0 (the `record` helper's fixed value), so baseline 0 keeps
        // every non-kept entry eligible for pruning, matching pre-baseline-guard
        // behavior.
        index.retain(&BTreeSet::from([idc]), 0)?;
        assert!(index.locate(idc)?.is_some(), "the retained note survives");
        assert!(
            index.locate(ida)?.is_none(),
            "a note not in keep is dropped by retain"
        );
        Ok(())
    }

    /// Build an [`IndexRecord`] for a fixed note id at a chosen version, so a test
    /// can drive `upsert`'s lamport-monotonicity directly. `object_key` embeds the
    /// version (`ver_{lamport}`) exactly as the real key embeds the winning op's
    /// ULID, and `cid` is distinct per version so `locate` can tell them apart.
    fn versioned(id: NoteId, lamport: u64) -> Result<IndexRecord, Box<dyn std::error::Error>> {
        let mut r = record(
            "team",
            RepoScope::Global,
            NoteType::Reference,
            &format!("body v{lamport}"),
            1_000 + i64::try_from(lamport)?,
        )?;
        r.note_id = id;
        r.lamport = lamport;
        r.object_key = format!("team/repo/mem/ver_{lamport}");
        r.cid = Blake3Hash::new([u8::try_from(lamport)?; 32]);
        Ok(r)
    }

    #[test]
    fn upsert_ignores_a_staler_record_for_the_same_note() -> TestResult {
        // Regression (commit_edit CAS lost-update): a concurrent sync recomputing
        // the index from a PRE-edit op-log view must not roll a committed edit back
        // to its older version. If it could, commit_edit's under-lock CAS would
        // read the stale cid and a stale-precondition edit would pass and clobber
        // the committed one via last-writer-wins; `get` would also serve the old
        // body until the next sync. `upsert` is lamport-monotonic, so the older
        // record is ignored.
        let index = InMemoryIndex::with_hash_embedder();
        let id = NoteId::new();
        index.upsert(versioned(id, 2)?)?; // the committed edit
        index.upsert(versioned(id, 1)?)?; // a stale sync tries to roll it back

        let located = index.locate(id)?.ok_or("note must locate")?;
        assert_eq!(
            located.cid,
            Blake3Hash::new([2_u8; 32]),
            "a staler upsert must not roll the committed edit back"
        );
        assert_eq!(located.object_key, "team/repo/mem/ver_2");
        Ok(())
    }

    #[test]
    fn upsert_applies_a_newer_edit_and_a_same_version_signal_refresh() -> TestResult {
        // Forward progress and ranking-signal refreshes must still land. A
        // higher-lamport edit replaces the stored record; a same-(lamport,
        // object_key) re-upsert (a Reinforce/Relate refreshing relations without a
        // new content op) still applies, which is why the gate rejects only a
        // STRICTLY older version (`is_stale_rollback` uses `>`), i.e. it accepts an
        // equal-or-newer version.
        let index = InMemoryIndex::with_hash_embedder();
        let id = NoteId::new();
        index.upsert(versioned(id, 1)?)?;
        index.upsert(versioned(id, 2)?)?; // a newer edit
        assert_eq!(
            index.locate(id)?.ok_or("note must locate")?.cid,
            Blake3Hash::new([2_u8; 32]),
            "a newer edit must replace the stored record"
        );

        // Same version, but with a fresh reinforcer stamped — must apply.
        let mut refreshed = versioned(id, 2)?;
        refreshed.reinforcers.insert(author()?);
        index.upsert(refreshed)?;
        let stored = index
            .all_records()?
            .into_iter()
            .find(|r| r.note_id == id)
            .ok_or("note must be enumerated")?;
        assert_eq!(
            stored.reinforcers.len(),
            1,
            "a same-version signal refresh must apply"
        );
        Ok(())
    }

    #[test]
    fn a_removed_note_is_not_resurrected_by_a_stale_upsert() -> TestResult {
        // Root cause: `is_stale_rollback` only compares an incoming record
        // against a currently-PRESENT entry. Once `redact`/`forget` removes
        // the note, there is nothing left to compare against, so a stale
        // sync's re-insert used to sail straight through. The removal
        // watermark `remove_at` records closes that gap.
        let index = InMemoryIndex::with_hash_embedder();
        let id = NoteId::new();
        index.upsert(versioned(id, 5)?)?; // live at lamport 5
        index.remove_at(id, 6, "team/repo/mem/ver_6")?; // redact op at lamport 6
        index.upsert(versioned(id, 4)?)?; // stale sync, predates the redact
        assert!(
            index.locate(id)?.is_none(),
            "a stale re-insert must not resurrect it"
        );
        Ok(())
    }

    #[test]
    fn a_genuinely_newer_edit_still_applies_and_clears_the_removal_watermark() -> TestResult {
        // The gate must not be so strict it blocks forward progress: an edit
        // that lands AFTER the redact (a legitimate un-redact / re-remember,
        // or simply the next op in a note's life) is genuinely newer than the
        // watermark and must apply -- and once it does, the watermark's job
        // is done, so a later, still-stale upsert must not resurrect the OLD
        // pre-redact content either.
        let index = InMemoryIndex::with_hash_embedder();
        let id = NoteId::new();
        index.upsert(versioned(id, 5)?)?;
        index.remove_at(id, 6, "team/repo/mem/ver_6")?;
        index.upsert(versioned(id, 7)?)?; // genuinely newer than the watermark
        assert_eq!(
            index
                .locate(id)?
                .ok_or("a newer edit must re-establish the note")?
                .object_key,
            "team/repo/mem/ver_7",
            "an op newer than the removal watermark applies"
        );

        // The now-cleared watermark must not resurface: a subsequently-stale
        // upsert of the ORIGINAL pre-redact version (lamport 5) is refused by
        // ordinary lamport-monotonicity against the live lamport-7 entry, not
        // by the (already-cleared) watermark -- proving the watermark truly
        // cleared rather than merely being shadowed.
        index.upsert(versioned(id, 5)?)?;
        assert_eq!(
            index
                .locate(id)?
                .ok_or("note must still locate")?
                .object_key,
            "team/repo/mem/ver_7",
            "the live lamport-7 entry survives an older re-upsert"
        );
        Ok(())
    }

    #[test]
    fn retain_preserves_the_watermark_when_its_own_view_still_names_the_id() -> TestResult {
        // `retain` always runs paired with an `upsert_batch`/`upsert` built
        // from the SAME converged view (see `replay_full`/`sync_incremental`).
        // If that view is itself stale -- it still names an id a concurrent
        // redact/forget just removed -- clearing the watermark here would
        // defeat the fix for the very upsert this `retain` is paired with.
        let index = InMemoryIndex::with_hash_embedder();
        let id = NoteId::new();
        index.upsert(versioned(id, 5)?)?;
        index.remove_at(id, 6, "team/repo/mem/ver_6")?;
        index.retain(&BTreeSet::from([id]), 5)?; // a stale view (tip 5) that still names id, predating the lamport-6 redact
        index.upsert(versioned(id, 4)?)?; // that same stale view's paired upsert
        assert!(
            index.locate(id)?.is_none(),
            "a retain whose own view still names the id must not clear its watermark"
        );
        Ok(())
    }

    #[test]
    fn retain_clears_the_watermark_once_its_own_view_confirms_the_id_absent() -> TestResult {
        // Bounding growth: once a full rebuild's OWN view agrees the id is
        // not live, the watermark has done its job (the paired upsert_batch
        // cannot possibly carry a record for an id `keep` excludes), so
        // `retain` drops it rather than holding it forever.
        let index = InMemoryIndex::with_hash_embedder();
        let id = NoteId::new();
        index.upsert(versioned(id, 5)?)?;
        index.remove_at(id, 6, "team/repo/mem/ver_6")?;
        index.retain(&BTreeSet::new(), 6)?; // this view (tip 6) already agrees id is gone
        // Prove the watermark is actually gone (not coincidentally absent):
        // with it cleared, even a record older than the watermark applies
        // again, since nothing but the watermark was refusing it.
        index.upsert(versioned(id, 4)?)?;
        assert!(
            index.locate(id)?.is_some(),
            "retain must clear a watermark its own view confirms is absent"
        );
        Ok(())
    }

    #[test]
    fn retain_keeps_an_entry_newer_than_the_sync_baseline() -> TestResult {
        // [Task 7] Regression: a concurrent `remember`/`edit` on the same store
        // can land -- durable AND upserted into this index -- after a sync's
        // op-log view was captured but before that sync's `retain` call runs.
        // `keep` computed from the stale view cannot possibly name a note the
        // view's own convergence never saw, so pruning purely on `keep`
        // membership would delete the freshly-remembered note even though the
        // write already reported success. The baseline guard is what stops that:
        // an entry newer than the view's own tip survives `retain` regardless of
        // `keep`.
        let index = InMemoryIndex::with_hash_embedder();
        let fresh = NoteId::new();
        index.upsert(versioned(fresh, 10)?)?; // remembered at lamport 10
        // A sync whose view topped out at lamport 8 (it predates the remember)
        // prunes to an empty live set.
        index.retain(&BTreeSet::new(), 8)?;
        assert!(
            index.locate(fresh)?.is_some(),
            "an entry newer than the sync's baseline survives retain"
        );
        Ok(())
    }

    #[test]
    fn retain_still_prunes_unconditionally_when_nothing_exceeds_the_baseline() -> TestResult {
        // Cold replay passes the SAME tip it built `keep` from, so nothing in a
        // consistent snapshot can be newer than its own baseline -- this proves
        // the guard does not weaken ordinary pruning in that (the common) case.
        let index = InMemoryIndex::with_hash_embedder();
        let stale = NoteId::new();
        index.upsert(versioned(stale, 5)?)?;
        index.retain(&BTreeSet::new(), 5)?; // baseline == the entry's own lamport
        assert!(
            index.locate(stale)?.is_none(),
            "an entry at or below the baseline is pruned exactly as before the guard existed"
        );
        Ok(())
    }

    #[test]
    fn all_records_returns_every_upserted_record() -> TestResult {
        // Enumeration is a set-membership contract, not a ranking one: the browse
        // view needs every note regardless of order, so assert the exact id set
        // (order-independent) — a future iteration-order change must not break it.
        let index = InMemoryIndex::with_hash_embedder();
        let a = record(
            "team",
            RepoScope::Global,
            NoteType::Decision,
            "alpha note",
            1_000,
        )?;
        let b = record(
            "team",
            RepoScope::Global,
            NoteType::Gotcha,
            "beta note",
            2_000,
        )?;
        let expected = BTreeSet::from([a.note_id, b.note_id]);
        index.upsert(a)?;
        index.upsert(b)?;

        let got: BTreeSet<NoteId> = index
            .all_records()?
            .into_iter()
            .map(|r| r.note_id)
            .collect();
        assert_eq!(
            got, expected,
            "all_records enumerates exactly the upserted notes"
        );
        Ok(())
    }

    #[test]
    fn hash_embedder_index_reports_lexical() {
        // A HashEmbedder-backed index overrides `contributes_semantic_leg` to
        // false, so `is_semantic` must be false: recall ranks keyword-only. The
        // dashboard badges retrieval from exactly this signal.
        let index = InMemoryIndex::with_hash_embedder();
        assert!(
            !index.is_semantic(),
            "a HashEmbedder-backed index is lexical, not semantic"
        );
    }

    #[test]
    fn dense_embedder_index_reports_semantic() {
        // `ConstantEmbedder` does not override `contributes_semantic_leg`, so it
        // takes the `Embedder` default (true) — the stand-in for a real dense
        // model. This exercises the `true` branch without the optional
        // `embeddings` feature or an ONNX model download; the production
        // FastEmbedder path is likewise semantic by that same default.
        let index = InMemoryIndex::new(Arc::new(ConstantEmbedder { threshold: 0.0 }));
        assert!(
            index.is_semantic(),
            "a dense-embedder index runs the vector leg and is semantic"
        );
    }

    #[test]
    fn zero_token_budget_keeps_nothing() -> TestResult {
        // A non-empty summary costs at least one token (div_ceil), so a Some(0)
        // budget returns no pointers — it no longer admits sub-4-char summaries
        // for free. The match still counts toward total_matched (the budget hides
        // results, it does not change what is relevant).
        let index = InMemoryIndex::with_hash_embedder();
        index.upsert(record(
            "team",
            RepoScope::Global,
            NoteType::Reference,
            "ab",
            1_000,
        )?)?;
        let mut q = query("ab", RepoScope::Global, 10, 2_000);
        q.token_budget = Some(0);
        let result = index.search(&q)?;
        assert!(
            result.pointers.is_empty(),
            "a zero budget keeps no non-empty summary, got {:?}",
            result.pointers
        );
        assert_eq!(
            result.total_matched, 1,
            "the match still counts as relevant"
        );
        Ok(())
    }

    #[test]
    fn token_budget_truncates() -> TestResult {
        let index = InMemoryIndex::with_hash_embedder();
        for _ in 0..10 {
            index.upsert(record(
                "team",
                RepoScope::Repo("thebrain".to_string()),
                NoteType::Reference,
                "alpha beta gamma delta",
                1_000,
            )?)?;
        }
        let repo = RepoScope::Repo("thebrain".to_string());
        let unbudgeted = index.search(&query("alpha beta gamma delta", repo.clone(), 10, 2_000))?;

        let mut budgeted_query = query("alpha beta gamma delta", repo, 10, 2_000);
        budgeted_query.token_budget = Some(6);
        let budgeted = index.search(&budgeted_query)?;

        assert_eq!(unbudgeted.pointers.len(), 10);
        assert!(budgeted.pointers.len() < unbudgeted.pointers.len());
        // The budget hid matches without losing the count: total_matched still
        // reports all ten relevant notes the caller could have paged through.
        assert_eq!(budgeted.total_matched, 10);
        Ok(())
    }

    proptest! {
        #[test]
        fn rrf_fuse_ranks_consensus_first(extra in 0_usize..6, legs in 1_usize..5) {
            let count = extra + 1;
            let id_pool: Vec<NoteId> = (0..count).map(|_| NoteId::new()).collect();
            let consensus = id_pool[0];
            let tail = &id_pool[1..];

            // Each leg ranks `consensus` first, then the tail rotated by the leg
            // index so the legs disagree below rank 0.
            let leg_vecs: Vec<Vec<NoteId>> = (0..legs)
                .map(|leg| {
                    let mut ordering = vec![consensus];
                    if !tail.is_empty() {
                        let rotation = leg % tail.len();
                        ordering.extend(
                            tail.iter().cycle().skip(rotation).take(tail.len()).copied(),
                        );
                    }
                    ordering
                })
                .collect();

            let fused = rrf_fuse(&leg_vecs, 60.0);

            // One entry per distinct id, no duplicates.
            prop_assert_eq!(fused.len(), count);

            let consensus_score = fused.iter().find(|(id, _)| *id == consensus).map(|(_, s)| *s);
            let Some(consensus_score) = consensus_score else {
                prop_assert!(false, "consensus id missing from fused output");
                return Ok(());
            };
            for (id, score) in &fused {
                if *id != consensus {
                    prop_assert!(
                        *score < consensus_score,
                        "non-consensus {:?} scored {} >= consensus {}",
                        id,
                        score,
                        consensus_score
                    );
                }
            }
        }
    }

    /// A [`Pointer`] carrying `summary`; the other fields are inert fixtures since
    /// `apply_token_budget` only reads `summary` (via `estimate_tokens`). Fallible
    /// because [`Ss58::new`] validates — keeping it `Result` avoids an `unwrap`
    /// (denied crate-wide) the way the sibling `author()`/`record()` helpers do.
    fn pointer_with_summary(summary: &str) -> Result<Pointer, Box<dyn std::error::Error>> {
        Ok(Pointer {
            note_id: NoteId::new(),
            summary: summary.to_owned(),
            score: 0.0,
            scope: Scope {
                team: "t".to_owned(),
                repo: RepoScope::Global,
            },
            author: author()?,
            updated: Timestamp::new(0),
            lamport: 0,
            relations: Vec::new(),
        })
    }

    proptest! {
        /// `apply_token_budget` keeps a PREFIX of its already-ranked input whose
        /// summed estimated cost never exceeds the budget, and that prefix is
        /// maximal — the greedy contract, with the shrinker probing the boundary the
        /// hand-picked `zero_token_budget_keeps_nothing` fixture cannot.
        #[test]
        fn token_budget_keeps_maximal_prefix_within_budget(
            summaries in proptest::collection::vec("[a-z ]{0,40}", 0..20),
            budget in 0_usize..50,
        ) {
            let pointers = summaries
                .iter()
                .map(|s| pointer_with_summary(s))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            let ids: Vec<NoteId> = pointers.iter().map(|p| p.note_id).collect();
            let kept = apply_token_budget(pointers, Some(budget));
            let kept_ids: Vec<NoteId> = kept.iter().map(|p| p.note_id).collect();

            // (a) kept is a prefix of the input order (greedy, never reorders).
            prop_assert_eq!(&kept_ids[..], &ids[..kept_ids.len()]);
            // (b) summed cost stays within budget (the always-true invariant; an
            //     empty summary costs 0, so it is admitted even under budget 0).
            let used: usize = kept.iter().map(|p| estimate_tokens(&p.summary)).sum();
            prop_assert!(used <= budget);
            // (c) maximal: the first dropped pointer would have exceeded the budget
            //     (the loop breaks there, so a 0-cost pointer is never the dropped one).
            if kept_ids.len() < ids.len() {
                prop_assert!(used + estimate_tokens(&summaries[kept_ids.len()]) > budget);
            }
        }

        /// No budget is identity: every ranked pointer survives.
        #[test]
        fn token_budget_none_keeps_all(
            summaries in proptest::collection::vec("[a-z ]{0,40}", 0..20),
        ) {
            let pointers = summaries
                .iter()
                .map(|s| pointer_with_summary(s))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            let n = pointers.len();
            prop_assert_eq!(apply_token_budget(pointers, None).len(), n);
        }

        /// `keyword_score` is non-negative, and zero EXACTLY when no distinct query
        /// token occurs in the document — the lexical leg's relevance floor.
        #[test]
        fn keyword_score_zero_iff_no_shared_token(
            query in proptest::collection::vec("[a-c]{1,3}", 0..6),
            doc in proptest::collection::vec("[a-c]{1,3}", 0..12),
        ) {
            let score = keyword_score(&query, &doc);
            prop_assert!(score >= 0.0);
            let doc_set: BTreeSet<&String> = doc.iter().collect();
            let shares = query.iter().any(|token| doc_set.contains(token));
            prop_assert_eq!(shares, score > 0.0);
        }
    }

    /// `BM25` term-frequency saturation: a repeated query term scores higher than a
    /// single occurrence but far below linear (3x), the diminishing-returns core of
    /// `BM25` (`k1`). A regression to linear term frequency would score exactly 3x
    /// the single-occurrence value and trip the upper bound here.
    #[test]
    fn keyword_score_saturates_repeated_terms() {
        let query = vec!["cache".to_owned()];
        let once = keyword_score(&query, &["cache".to_owned()]);
        let thrice = keyword_score(
            &query,
            &["cache".to_owned(), "cache".to_owned(), "cache".to_owned()],
        );

        assert!(
            thrice > once,
            "more occurrences must score higher: {once} vs {thrice}"
        );
        assert!(
            thrice < 3.0 * once,
            "term frequency must saturate, not scale linearly: {thrice} vs {}",
            3.0 * once
        );
    }
}
