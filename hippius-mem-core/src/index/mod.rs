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
/// Returns `0.0` (never `NaN`) when either vector has zero norm — the
/// degenerate case for empty/again-zero embeddings.
fn cosine(left: &[f32], right: &[f32]) -> f32 {
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
    /// this, because it is what "recent" means to a human reader.
    pub updated: Timestamp,
    /// Lamport clock of the write that produced this pointer.
    ///
    /// The convergence clock, distinct from `updated`: it total-orders writes
    /// across machines whose wall-clocks cannot be trusted to agree. Nothing in
    /// ranking reads it (recency decays on `updated`); it rides along so callers
    /// can reason about convergence order and history.
    pub lamport: u64,
}

/// The outcome of a [`MemoryIndex::search`]: the returned pointers plus how many
/// in-scope, relevant notes matched in total.
///
/// `total_matched` counts every candidate that was in scope AND scored above the
/// relevance floor (non-zero in at least one retrieval leg), *before* the `k` cap
/// and token budget truncate the result. So `total_matched >= pointers.len()`,
/// and a caller can tell whether it saw everything (`total_matched ==
/// pointers.len()`) or whether more matches exist beyond the budget it asked for.
#[derive(Debug, Clone)]
pub struct SearchResult {
    /// The ranked pointers actually returned, after `k`/budget truncation.
    pub pointers: Vec<Pointer>,
    /// Count of in-scope, relevant candidates before `k`/budget truncation.
    pub total_matched: usize,
}

/// One indexed note. The index computes and stores the embedding of `summary`.
///
/// `Serialize`/`Deserialize` let a converged set of records be persisted as an
/// [`crate::store::IndexSnapshot`] and restored without re-fetching every note
/// blob; `PartialEq`/`Eq` let a restored record be compared field-for-field
/// against a freshly decoded one (the snapshot round-trip and incremental-equals-
/// full tests rely on this). All fields already satisfy these bounds.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    /// When the note was last updated. Wall-clock; recency decay reads this.
    pub updated: Timestamp,
    /// Lamport clock of the write that produced this record.
    ///
    /// The convergence clock — it orders writes across machines for convergence
    /// where untrusted wall-clocks cannot. `updated` stays the recency clock;
    /// `lamport` rides along for convergence/history and is not read by ranking.
    pub lamport: u64,
    /// Free-form tags, included in the lexical leg.
    pub tags: BTreeSet<String>,
    /// The short summary, indexed for both retrieval legs.
    pub summary: String,
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

    /// Remove the record with id `id`, if present.
    ///
    /// # Errors
    ///
    /// This in-memory implementation never errors; the signature is fallible so
    /// a persistent backend can report a storage failure.
    fn remove(&self, id: NoteId) -> Result<(), MemError>;

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

    /// Drop every indexed note whose id is NOT in `keep`.
    ///
    /// This is the authoritative-pruning primitive [`crate::store::MemoryStore::sync`]
    /// needs: after computing the converged *live* set it calls `retain` so a
    /// note that is no longer live — a removed member's note, or one whose
    /// content op no longer survives convergence — is dropped from a long-lived
    /// (warm) index, not just on a cold from-scratch rebuild. `keep` is a
    /// [`BTreeSet`] so the per-entry membership test is `O(log n)`; the receiver
    /// is `&self` (object-safe, no generics) so the method stays dyn-compatible.
    ///
    /// # Errors
    ///
    /// This in-memory implementation never errors; the signature is fallible so
    /// a persistent backend can report a storage failure.
    fn retain(&self, keep: &BTreeSet<NoteId>) -> Result<(), MemError>;
}

/// A stored record plus the precomputed embedding of its summary.
struct Entry {
    record: IndexRecord,
    embedding: Vec<f32>,
}

/// In-memory [`MemoryIndex`] backed by a [`BTreeMap`], for tests and the
/// offline fallback.
pub struct InMemoryIndex {
    embedder: Arc<dyn Embedder>,
    // `BTreeMap` (not `HashMap`): deterministic iteration order makes search
    // output reproducible, and key-equality gives upsert-replace/remove for
    // free. `Mutex` provides the interior mutability the `&self` trait methods
    // need while keeping the index `Send + Sync`.
    entries: Mutex<BTreeMap<NoteId, Entry>>,
}

impl InMemoryIndex {
    /// Build an index that embeds summaries with `embedder`.
    #[must_use]
    pub fn new(embedder: Arc<dyn Embedder>) -> Self {
        Self {
            embedder,
            entries: Mutex::new(BTreeMap::new()),
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
        // Deliberately does not lock `entries`: a `Debug` impl must not risk
        // blocking or interacting with lock poisoning.
        f.debug_struct("InMemoryIndex")
            .field("embed_dim", &self.embedder.dim())
            .finish_non_exhaustive()
    }
}

impl MemoryIndex for InMemoryIndex {
    fn upsert(&self, record: IndexRecord) -> Result<(), MemError> {
        // `from_ref` builds a 1-element slice borrowing the summary — no clone.
        let embeddings = self.embedder.embed(std::slice::from_ref(&record.summary))?;
        // A well-behaved embedder returns exactly one vector; a misbehaving one
        // degrades this record's vector score to 0 rather than panicking.
        let embedding = embeddings.into_iter().next().unwrap_or_default();
        let mut guard = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        guard.insert(record.note_id, Entry { record, embedding });
        Ok(())
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
            let guard = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
            guard
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
        let keyword_leg = rank_leg(candidates.iter().map(|c| (c.note_id, c.keyword, c.updated)));
        let vector_leg = rank_leg(candidates.iter().map(|c| (c.note_id, c.vector, c.updated)));
        let fused = rrf_fuse(&[keyword_leg, vector_leg], RANK_CONSTANT);

        // Step 5 — recency decay: multiply the fused score by a per-type
        // exponential half-life so durable knowledge ages slowly and ephemeral
        // context ages fast.
        let by_id: BTreeMap<NoteId, Candidate> =
            candidates.into_iter().map(|c| (c.note_id, c)).collect();
        let mut pointers: Vec<Pointer> = Vec::with_capacity(fused.len());
        for (id, fused_score) in fused {
            let Some(candidate) = by_id.get(&id) else {
                continue;
            };
            // `saturating_sub` then `max(0)` clamps negative ages (a note
            // updated "after" now) to 0 without risking i64 overflow.
            let age = query
                .now
                .as_millis()
                .saturating_sub(candidate.updated.as_millis())
                .max(0);
            let score = fused_score * recency_weight(age, candidate.note_type);
            pointers.push(candidate.to_pointer(id, score));
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

    fn remove(&self, id: NoteId) -> Result<(), MemError> {
        let mut guard = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        guard.remove(&id);
        Ok(())
    }

    fn locate(&self, id: NoteId) -> Result<Option<Located>, MemError> {
        let guard = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        // `cid` is `Copy`; only the object key allocates. The record already
        // holds both, so this is a pure lookup with no recomputation.
        Ok(guard.get(&id).map(|entry| Located {
            object_key: entry.record.object_key.clone(),
            cid: entry.record.cid,
        }))
    }

    fn retain(&self, keep: &BTreeSet<NoteId>) -> Result<(), MemError> {
        let mut guard = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        // `BTreeMap::retain` drops in place every entry whose id is absent from
        // `keep`, in one pass without reallocating the map.
        guard.retain(|note_id, _entry| keep.contains(note_id));
        Ok(())
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
        }
    }

    fn to_pointer(&self, note_id: NoteId, score: f32) -> Pointer {
        Pointer {
            note_id,
            summary: self.summary.clone(),
            score,
            scope: self.scope.clone(),
            author: self.author.clone(),
            updated: self.updated,
            lamport: self.lamport,
        }
    }
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

/// Order candidates best-first for one leg and return their ids.
///
/// Candidates scoring zero in this leg are excluded: a zero score means "no
/// signal", and a note with no signal in *either* leg must not earn RRF mass and
/// float up on recency alone. Keeping it would let an irrelevant note surface, so
/// the relevance floor is applied here, per leg, before ranking.
///
/// Ties (equal leg score) break newest-first, then by `note_id`, so equal
/// relevance reinforces recency rather than fighting it and the order is fully
/// deterministic. `total_cmp` gives a total float order with no NaN ambiguity.
fn rank_leg(scored: impl Iterator<Item = (NoteId, f32, Timestamp)>) -> Vec<NoteId> {
    let mut rows: Vec<(NoteId, f32, Timestamp)> =
        scored.filter(|&(_, score, _)| score > 0.0).collect();
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

/// Estimate a summary's token cost as roughly four characters per token, the
/// common rule of thumb for English text under byte-pair tokenizers.
fn estimate_tokens(summary: &str) -> usize {
    summary.chars().count() / 4
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
        DEFAULT_EMBED_DIM, Embedder, HashEmbedder, InMemoryIndex, IndexRecord, MemoryIndex,
        Pointer, Query, cosine, embed_one, rrf_fuse,
    };
    use crate::domain::{Blake3Hash, NoteId, NoteType, RepoScope, Scope, Ss58, Timestamp};
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

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
            object_key: "team/repo/mem/rev_0".to_string(),
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
            tags: BTreeSet::new(),
            summary: summary.to_string(),
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
        // Relevant in just ONE leg (a single shared lexical token) is enough to
        // clear the floor — the floor drops both-zero candidates, not one-zero.
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
}
