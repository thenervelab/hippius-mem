//! The append-only op-log store: write ops as immutable blobs, read them back
//! with integrity checks.
//!
//! Phase 2's threat model treats the shared team bucket as untrusted: a peer (or
//! the storage provider) may add, edit, or drop objects under the op-log prefix.
//! So [`OpLogStore::read_all`] re-derives trust from the ops themselves on every
//! read — it verifies each op's signature and walks each author's hash chain —
//! rather than trusting that what was written is what comes back.
//!
//! # What the per-author hash chain does and does not detect
//!
//! The signature + per-author `prev_op_hash` chain is tamper-*evidence within an
//! author's own chain*. It DETECTS:
//! - in-place tampering (an edited field breaks the signature);
//! - mid-chain deletion (a removed op leaves the next op's `prev_op_hash`
//!   dangling — a chain break);
//! - reordering within an author's chain (the `prev` links no longer form a line).
//!
//! It does NOT detect:
//! - **tail-truncation** — dropping the most recent ops of an author leaves a
//!   shorter but still-valid chain; nothing pins "this is the latest";
//! - **whole-author suppression** — hiding every object of one author makes that
//!   author's writes simply absent, with no gap to notice;
//! - **split-view / equivocation** — serving different readers different subsets
//!   so they converge to different states.
//!
//! Those are *availability/suppression* attacks, not integrity attacks, and the
//! chain alone cannot catch them. The mitigation is on-chain anchoring (a root
//! committed publicly pins what existed at a point in time) plus a reconciliation
//! tool that cross-checks each machine's view against the anchored roots — built
//! in [`crate::audit::reconcile`]. It detects suppression of *anchored* ops; with
//! the `chain` feature the roots are read back from the chain, so even a bucket
//! that forges a self-consistent anchor record is caught (see that module).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use futures_util::StreamExt;

use crate::{Blake3Hash, BlobStore, MemError, Op, VerifiedOps};

/// Max op objects fetched from the bucket at once during a verified read.
///
/// A cold read of a large op-log is dominated by S3 round-trip latency, so a
/// serial GET-per-object made startup scale linearly with the log size. This
/// bounds the in-flight GETs — an explicit cap (axiom `rust_quality_176`: never
/// an unbounded fan-out) so a huge log cannot open thousands of simultaneous
/// connections — while still overlapping the latency the serial loop paid one at
/// a time. Fetch order does not matter: verification re-derives a total order.
///
/// Sized against the Hippius gateway, whose per-GET latency is high (hundreds of
/// ms), so this read is latency-bound: measured cold, a ~590-op log took ~35s at
/// 16 in-flight and ~20s at 64, the gateway saturating before the client. 64 keeps
/// the cap well under any connection ceiling while nearly halving the read.
/// Op objects carry only signed metadata — never note content — so widening the
/// fan-out crosses no privacy boundary.
const OPLOG_FETCH_CONCURRENCY: usize = 64;

/// The `prev_op_hash` of every author's first op.
///
/// An all-zero digest is BLAKE3-unreachable for real input (see
/// [`Blake3Hash::zero`]), so it unambiguously marks a chain root: the first op
/// an author ever appends has no predecessor to link to.
pub const GENESIS_PREV: Blake3Hash = Blake3Hash::zero();

/// Append-only store for the signed, hash-chained op-log of one or more teams.
///
/// Holds a shared [`BlobStore`] handle; it is cheap to clone the `Arc` and share
/// the store across async tasks. The store itself keeps no per-team state — the
/// `team` argument on each method selects the object-key prefix — so a single
/// instance serves every team reachable through `blob`.
#[derive(Clone)]
pub struct OpLogStore {
    blob: Arc<dyn BlobStore>,
}

impl std::fmt::Debug for OpLogStore {
    // `dyn BlobStore` is not `Debug`; name the type without trying to render the
    // backend so `OpLogStore` can still satisfy `missing_debug_implementations`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpLogStore").finish_non_exhaustive()
    }
}

impl OpLogStore {
    /// Build a store over the shared blob backend `blob`.
    #[must_use]
    pub fn new(blob: Arc<dyn BlobStore>) -> Self {
        Self { blob }
    }

    /// Append `op` to `team`'s op-log.
    ///
    /// "Append" means writing a new immutable object: the key embeds `op`'s
    /// Lamport time, id, and author key, so two distinct ops never collide and an
    /// honest `append` never overwrites another author's op. The op-log is
    /// therefore grow-only — rewriting history would require forging a signature,
    /// which [`OpLogStore::read_all`] rejects.
    ///
    /// # Errors
    ///
    /// Returns [`MemError::Serialize`] if `op` cannot be encoded, or
    /// [`MemError::Storage`] if the backend write fails.
    pub async fn append(&self, team: &str, op: &Op) -> Result<(), MemError> {
        let key = object_key(team, op);
        let bytes = serde_json::to_vec(op)?;
        self.blob.put(&key, bytes).await
    }

    /// Read and verify every op in `team`'s op-log, returned in global logical
    /// order: ascending `(lamport, op_id)`.
    ///
    /// Verification (the bucket is untrusted) — every check is *resilient*: a bad
    /// object is dropped with a `tracing::warn!`, never an abort, so one forged,
    /// transplanted, or forked object cannot blind the whole team (I2):
    /// 0. objects that do not deserialize as an [`Op`] are skipped, and exact
    ///    byte-duplicate ops are deduped by [`Op::hash`] before the chain walk;
    /// 1. each op whose signature does not verify against its own `author_key`, or
    ///    whose `author` SS58 does not decode to that `author_key` (cryptographic
    ///    attribution — a writer cannot sign as one key but claim another's SS58),
    ///    is dropped individually;
    /// 2. each op whose `object_key` is not under `{team}/` is dropped (a
    ///    transplanted op from another team's log, defense-in-depth beside the
    ///    AEAD-AAD binding);
    /// 3. grouped by `author_key`, each author's ops must form an unbroken hash
    ///    chain from [`GENESIS_PREV`] (each op's `prev_op_hash` equals its
    ///    predecessor's [`Op::hash`]). When an author's chain forks or loses a
    ///    mid-chain op, [`longest_rooted_chain`] keeps that author's longest
    ///    genesis-rooted branch and quarantines the rest — a stray fork sibling
    ///    orphans only itself, not the correctly-linked ops after it — and every
    ///    other author survives untouched.
    ///
    /// Dropping a bad op is suppression of that op, an availability gap the module
    /// header already concedes to on-chain anchoring + reconciliation; it is
    /// strictly safer than the old whole-team abort, which a single bucket write
    /// could trigger.
    ///
    /// # Errors
    ///
    /// [`MemError::Storage`] / [`MemError::NotFound`] from the backend `list`/`get`
    /// only — the verification steps above drop bad ops rather than erroring.
    pub async fn read_all(&self, team: &str) -> Result<VerifiedOps, MemError> {
        self.read_verified(team).await
    }

    /// The number of op objects under `team`'s op-log prefix — a cheap staleness
    /// probe.
    ///
    /// This is a keys-only `list`: it fetches, decrypts, and verifies NOTHING, so
    /// it is far cheaper than [`read_all`](Self::read_all) (which `get`s and
    /// crypto-verifies every op). Ops are append-only, so the count rises whenever
    /// a teammate writes — a change since the last sync means there is new work to
    /// replay, letting a caller skip a full sync when the count is unchanged. It is
    /// a heuristic, not a proof of equality: a bucket that overwrites an op in
    /// place (adversarial key reuse) keeps the count fixed, so this bounds the
    /// *common* teammate-append case, not a Byzantine one.
    ///
    /// # Errors
    ///
    /// [`MemError::Storage`] if the backend listing fails.
    pub async fn op_object_count(&self, team: &str) -> Result<usize, MemError> {
        Ok(self.blob.list(&oplog_prefix(team)).await?.len())
    }

    /// Read, verify, and globally order `team`'s op-log. Shared by the public
    /// readers so they cannot diverge on what "verified" means.
    ///
    /// Resilience over the untrusted bucket: an object under the prefix whose GET
    /// fails or that does not deserialize as an [`Op`] is skipped with a
    /// `tracing::warn!` rather than failing the whole read (one bad object must
    /// not blind the team) — but when every GET fails while the listing
    /// succeeded, the read errors instead: that shape is a systemic fault
    /// (credentials, gateway), and an `Ok(empty)` there would let `sync` prune a
    /// warm index to nothing. Exact byte-duplicate ops are deduped by
    /// [`Op::hash`] *before* chain verification so a replayed copy is not mistaken
    /// for a chain fork. A break that survives the dedup is genuine
    /// tamper-evidence; the affected author's broken branch is quarantined with a
    /// warn (see `quarantine_broken_chains`), never a whole-read error.
    async fn read_verified(&self, team: &str) -> Result<VerifiedOps, MemError> {
        let prefix = oplog_prefix(team);
        let keys = self.blob.list(&prefix).await?;

        // Fetch every op object concurrently (bounded) rather than one blocking
        // GET at a time. Safe because verification is fetch-order-independent: the
        // checks below (dedup, per-op validity, per-author chain quarantine) run
        // on the whole collected set and end with a total-order `sort_by_key`, so
        // the order objects arrive in cannot change the resulting `VerifiedOps`.
        // Clone the `Arc<dyn BlobStore>` into each future so no `&self` borrow
        // crosses the stream; nothing is spawned, so the futures need no `'static`
        // bound — the binary's runtime drives them inline.
        let blob = Arc::clone(&self.blob);
        let fetched: Vec<(String, Result<Vec<u8>, MemError>)> =
            futures_util::stream::iter(keys.into_iter().map(|key| {
                let blob = Arc::clone(&blob);
                async move {
                    let bytes = blob.get(&key).await;
                    (key, bytes)
                }
            }))
            .buffer_unordered(OPLOG_FETCH_CONCURRENCY)
            .collect()
            .await;

        let mut ops = Vec::with_capacity(fetched.len());
        let mut failed_gets = 0_usize;
        let mut fetched_ok = 0_usize;
        for (key, bytes) in fetched {
            // A per-object GET failure is skipped like a decode fault, not a
            // whole-read abort: under an eventually-consistent bucket a listed key
            // can transiently fail its GET (or vanish between list and get), and
            // one unfetchable object must not blind the whole team (I2) — the same
            // rule `load_manifest` applies (its M5 regression). A dropped mid-chain
            // op surfaces downstream as a chain break, which
            // `quarantine_broken_chains` already bounds per author; the object is
            // retried naturally on the next sync. Bounded by the systemic-outage
            // guard below.
            let bytes = match bytes {
                Ok(bytes) => {
                    fetched_ok += 1;
                    bytes
                }
                Err(err) => {
                    failed_gets += 1;
                    tracing::warn!(
                        object_key = %key,
                        error = %err,
                        "skipping op-log object whose GET failed; it will be retried on the next sync"
                    );
                    continue;
                }
            };
            match serde_json::from_slice::<Op>(&bytes) {
                Ok(op) => ops.push(op),
                // A junk object under the op-log prefix (foreign write, truncated
                // upload) is a per-object data fault: skip it, don't abort the read
                // for the whole team. A genuine bad op still fails the crypto checks.
                Err(err) => tracing::warn!(
                    object_key = %key,
                    error = %err,
                    "skipping object under the op-log prefix that does not deserialize as an Op"
                ),
            }
        }

        // Systemic-outage guard: the per-object skip above is for ISOLATED faults.
        // When a MAJORITY of GETs fail while LIST succeeded (an expired/GET-scoped
        // sub-token, a gateway auth outage), returning `Ok` with the surviving
        // minority would be catastrophic downstream — `sync`'s retain would prune
        // every unfetched note from a warm index, the dedup gate would stop seeing
        // them, and `reconcile` would report them missing (a false tamper alarm).
        // Isolated bucket faults are a small fraction, so a failure that is at
        // least HALF is the systemic signal: it errors, and callers keep serving
        // their current index and retry later; a strict minority is treated as
        // per-object damage and skipped above. `>=` (not `>`) errors the exact
        // 50/50 split too — one op back out of two objects still prunes the other
        // note from a warm index, the same catastrophe as the majority case. The
        // `failed_gets > 0` clause preserves `Ok(empty)` for a genuinely empty
        // listing (both counts zero): the guard keys on failed fetches, not
        // emptiness. It still fires on the all-fail case (`fetched_ok == 0`).
        if failed_gets > 0 && failed_gets >= fetched_ok {
            return Err(MemError::Storage(format!(
                "{failed_gets} of {} op-log GETs failed (at least half) while the listing \
                 succeeded — systemic storage fault (expired sub-token? gateway outage?), \
                 not per-object damage",
                failed_gets + fetched_ok
            )));
        }

        // Dedup BEFORE chain verification: a byte-identical copy of a valid op
        // shares its `prev_op_hash`, so two copies look like a fork to the chain
        // walk. Collapsing them by `Op::hash` makes a benign replay a no-op while
        // leaving a real reorder/deletion/edit to be caught below.
        dedup_by_hash(&mut ops);

        // Resilience over the untrusted bucket (I2): an op that fails an INDIVIDUAL
        // check — invalid signature, author SS58 that does not decode to its key,
        // or a foreign-team `object_key` — is indistinguishable from junk the
        // bucket injected, so it is dropped with a warn, exactly like an
        // undeserializable object above. A whole-read abort here would let one
        // forged or transplanted object deny every member their verified log.
        retain_individually_valid(&mut ops, team);

        // A broken or forked author chain QUARANTINES that author — all their ops
        // are dropped with a warn and every other author's ops are kept — so one
        // member equivocating, or the bucket dropping one mid-chain object, cannot
        // blind the whole team. Suppression of the quarantined author is already a
        // conceded availability gap (see the module header) that anchoring +
        // reconciliation cover; blinding the team was not, and is what this closes.
        quarantine_broken_chains(&mut ops);

        // Global logical order: Lamport time first, then op_id, then author_key,
        // then the content hash. author_key breaks the cross-author `(lamport,
        // op_id)` tie (`op_id` is a per-author ULID, not globally unique — see
        // `object_key` and `op_outranks`); the trailing content hash breaks the
        // ONE remaining tie a single author can still force — a Byzantine reuse of
        // its OWN `(lamport, op_id)` on two differently-signed ops — so the key is
        // TOTAL rather than leaning on sort stability + the backend's listing
        // order (which `buffer_unordered` above already scrambles). This mirrors
        // `op_outranks`' `hash().as_bytes()` final tiebreak, so `VerifiedOps`
        // iteration order and the per-note convergence order agree on every
        // machine regardless of fetch order.
        // `sort_by_cached_key`, not `sort_by_key`: the key now folds in
        // `op.hash()`, which re-runs BLAKE3 over the op's signing bytes. `sort_by_key`
        // re-evaluates the key on every comparison (O(n log n) hashes on this
        // cold-read hot path); the cached variant computes it once per element.
        ops.sort_by_cached_key(|op| {
            (
                op.lamport,
                op.op_id,
                *op.author_key.as_bytes(),
                *op.hash().as_bytes(),
            )
        });
        // The single trust boundary: every op above cleared signature, author-SS58
        // binding, team-prefix, and per-author chain verification, so this is where
        // the raw `Vec<Op>` becomes a `VerifiedOps` witness (axiom
        // rust_quality_182 — one construction site, listed).
        Ok(VerifiedOps::from_verified(ops))
    }
}

/// Drop exact-duplicate ops, keeping the first occurrence of each [`Op::hash`].
///
/// `Op::hash` covers every signed field plus the signature, so equal hashes mean
/// byte-identical ops; deduping them is sound and idempotent.
fn dedup_by_hash(ops: &mut Vec<Op>) {
    let mut seen = HashSet::with_capacity(ops.len());
    ops.retain(|op| seen.insert(op.hash()));
}

/// Drop every op that fails an INDIVIDUAL integrity check, keeping the rest.
///
/// Three per-op checks, each a junk signature the untrusted bucket could have
/// injected and so a drop-with-warn rather than a whole-read abort (I2):
/// - the signature must verify against the op's own `author_key`;
/// - the `author` SS58 must decode to exactly that `author_key` (attribution: a
///   writer cannot sign with one key but claim another's address);
/// - the `object_key` must live under `{team}/` — defense-in-depth beside the
///   AEAD-AAD binding in [`crate::crypto::seal`], refusing an op transplanted
///   from a different team's log even when its signature and chain check out.
///
/// These are per-op, not per-author: dropping one forged object attributed to an
/// author's key must NOT drop that author's honest ops, or the bucket could
/// suppress any author by injecting one bad op under their key.
fn retain_individually_valid(ops: &mut Vec<Op>, team: &str) {
    let team_prefix = format!("{team}/");
    ops.retain(|op| {
        if !op.verify_sig() {
            tracing::warn!(op_id = %op.op_id, "dropping op with an invalid signature");
            return false;
        }
        if !op.verify_identity() {
            tracing::warn!(
                op_id = %op.op_id,
                "dropping op whose author SS58 does not decode to its signing key"
            );
            return false;
        }
        if !op.object_key.starts_with(&team_prefix) {
            tracing::warn!(
                op_id = %op.op_id,
                object_key = %op.object_key,
                "dropping op bound to a foreign team"
            );
            return false;
        }
        true
    });
}

/// Quarantine every op NOT on an author's longest genesis-rooted hash chain,
/// keeping that surviving chain and every other author's ops.
///
/// Ops are grouped by `author_key` (each author's `prev_op_hash` links form a
/// tree of their own, rooted at [`GENESIS_PREV`]); [`longest_rooted_chain`]
/// selects the branch to keep and the rest — a fork sibling (two ops sharing a
/// `prev_op_hash`: an equivocation, or a cancelled-but-durable append the writer
/// re-minted over) or an op orphaned by a missing mid-chain object — is dropped
/// with a warn (I2).
///
/// Keeping the tallest branch rather than cutting at the first break is what
/// bounds a fork's blast radius: a stray sibling with no successors orphans only
/// itself, so the correctly-linked ops that continue the surviving branch still
/// converge — where a first-break cut dropped every op after the fork *forever*,
/// silently suppressing all of that author's later writes team-wide. Selection is
/// a deterministic function of the op set (heights, then the total order
/// `(lamport, op_id, hash)`), so every machine keeps the identical set regardless
/// of fetch order. Suppression of the dropped ops is the same availability gap the
/// module header concedes to anchoring + reconciliation.
fn quarantine_broken_chains(ops: &mut Vec<Op>) {
    // Group by author into index lists; a BTreeMap keeps the "which author broke"
    // warning order reproducible.
    let mut by_author: BTreeMap<[u8; 32], Vec<usize>> = BTreeMap::new();
    for (i, op) in ops.iter().enumerate() {
        by_author
            .entry(*op.author_key.as_bytes())
            .or_default()
            .push(i);
    }

    // Kept hashes across all authors, keyed by `Op::hash` (unique per op, so the
    // key survives the `retain` reindexing below).
    let mut keep: HashSet<Blake3Hash> = HashSet::new();
    let mut dropped_any = false;

    for (_author, idxs) in by_author {
        let chain: Vec<&Op> = idxs.iter().map(|&i| &ops[i]).collect();
        let kept = longest_rooted_chain(&chain);

        if kept.len() < chain.len() {
            dropped_any = true;
            tracing::warn!(
                author = %chain[0].author.as_str(),
                kept = kept.len(),
                dropped = chain.len() - kept.len(),
                "op-log chain broke for an author (fork or missing mid-chain op); keeping the longest genesis-rooted chain and quarantining the rest so the team still converges"
            );
        }

        keep.extend(kept);
    }

    // Only rewrite the vec when something was actually quarantined; an all-intact
    // read (the common case) keeps every op and pays no `retain` pass.
    if dropped_any {
        ops.retain(|op| keep.contains(&op.hash()));
    }
}

/// The object-key prefix under which `team`'s ops live.
fn oplog_prefix(team: &str) -> String {
    format!("{team}/_oplog/")
}

/// The object key for `op` in `team`'s op-log.
///
/// `{team}/_oplog/{lamport:020}_{op_id}_{author_key:hex}`: the Lamport value is
/// zero-padded to 20 digits — the width of `u64::MAX` (18446744073709551615) — so
/// every key has a fixed-width numeric field and the backend's lexicographic key
/// order matches ascending Lamport order. `op_id` (a ULID, itself time-sortable)
/// disambiguates ops that share a Lamport tick.
///
/// The trailing `author_key` is what keeps honest writers from colliding: `op_id`
/// is a per-author ULID, so two *different* authors can legitimately mint ops that
/// share a `(lamport, op_id)` (the convergence layer already treats `op_id` as not
/// globally unique). Without the author segment those ops derive the same key, and
/// the second honest `append` overwrites — and silently destroys — the first,
/// breaking the overwritten author's hash chain and quarantining their history.
/// Binding the author into the key gives every author a disjoint key space, so an
/// honest `append` can never clobber another author's op. (A peer with raw bucket
/// write access can still overwrite any key; that suppression is the conceded
/// untrusted-bucket gap the module header covers, and the read path's per-op
/// verification + chain quarantine is what contains it.)
fn object_key(team: &str, op: &Op) -> String {
    format!(
        "{team}/_oplog/{:020}_{}_{}",
        op.lamport,
        op.op_id,
        op.author_key.to_hex()
    )
}

/// The `Op::hash`es of `chain`'s longest genesis-rooted, hash-linked path — the
/// ops to KEEP. `chain` is one author's ops; every op it does NOT return is a
/// broken-tail op (a fork sibling, or an op orphaned by a missing ancestor) the
/// caller quarantines.
///
/// The author's ops link by `prev_op_hash` into a tree rooted at [`GENESIS_PREV`]
/// (acyclic — see the body). An honest author only ever extends one tip, so their
/// tree is a single path and this returns every op. A break introduces a branch:
/// selection follows the branch with the tallest subtree, so a stray sibling with
/// no descendants (a cancelled-but-durable append, an equivocation) orphans only
/// itself while the correctly-linked continuation is kept — unlike a first-break
/// cut, which drops every op after the break. On a height tie the LOWER total
/// order `(lamport, op_id, hash)` wins; the trailing hash is unique per op, so the
/// choice is total and identical on every machine regardless of fetch order.
///
/// Ordering-independent: this walks `prev_op_hash` linkage, not the input order,
/// so — unlike the prior sort-prefix walk — it needs no `(lamport, op_id)`
/// pre-sort and stays correct even if an author's Lamport is not strictly
/// increasing (a Byzantine writer).
fn longest_rooted_chain(chain: &[&Op]) -> HashSet<Blake3Hash> {
    // Precompute each op's hash once (`Op::hash` re-runs BLAKE3 per call) and index
    // children by parent hash: `children[h]` is every op whose `prev_op_hash == h`,
    // so `children[GENESIS_PREV]` are this author's chain roots. The graph is a
    // forest, acyclic because `prev_op_hash` is a preimage-resistant `Op::hash` —
    // no op can name a descendant — so the height DP and the walk below terminate.
    let hashes: Vec<Blake3Hash> = chain.iter().map(|op| op.hash()).collect();
    let mut children: HashMap<Blake3Hash, Vec<usize>> = HashMap::new();
    for (i, op) in chain.iter().enumerate() {
        children.entry(op.prev_op_hash).or_default().push(i);
    }

    // Subtree height per node (ops on the tallest downward path from it, inclusive),
    // computed bottom-up with an EXPLICIT stack post-order walk: an honest chain is
    // a single deep path, so recursion could overflow the stack on a large log.
    let mut height = vec![0_usize; chain.len()];
    let mut stack: Vec<(usize, bool)> = children
        .get(&GENESIS_PREV)
        .into_iter()
        .flatten()
        .map(|&i| (i, false))
        .collect();

    while let Some((i, expanded)) = stack.pop() {
        if expanded {
            let tallest_child = children
                .get(&hashes[i])
                .into_iter()
                .flatten()
                .map(|&c| height[c])
                .max()
                .unwrap_or(0);
            height[i] = 1 + tallest_child;
        } else {
            stack.push((i, true));
            if let Some(kids) = children.get(&hashes[i]) {
                stack.extend(kids.iter().map(|&c| (c, false)));
            }
        }
    }

    // Walk from genesis, at each fork taking the child whose subtree is tallest.
    // Height first is what defuses a fork: a cancelled-but-durable sibling is a
    // height-1 leaf and loses to the live branch that carries every later op. On a
    // height TIE (e.g. a root fork of two lone ops) the LOWER total order wins, so
    // the choice is deterministic on every machine and the earliest sibling is kept.
    // The total order's trailing hash is unique per op, so no two children ever tie
    // — the selection is total, never fetch-order dependent.
    let mut keep: HashSet<Blake3Hash> = HashSet::with_capacity(chain.len());
    let mut cursor = GENESIS_PREV;

    while let Some(kids) = children.get(&cursor) {
        let best = kids.iter().copied().reduce(|a, b| {
            let rank = |i: usize| {
                (
                    height[i],
                    std::cmp::Reverse((chain[i].lamport, chain[i].op_id, *hashes[i].as_bytes())),
                )
            };
            if rank(a) >= rank(b) { a } else { b }
        });
        let Some(best) = best else { break };

        keep.insert(hashes[best]);
        cursor = hashes[best];
    }

    keep
}

#[cfg(test)]
mod tests {
    use super::{GENESIS_PREV, OpLogStore, longest_rooted_chain, object_key};
    use crate::NetworkPrefix;
    use crate::{
        Blake3Hash, BlobStore, MemoryBlobStore, NoteId, Op, OpContent, OpKind, Signer,
        Sr25519Signer, content_hash,
    };
    use proptest::prelude::*;
    use proptest::test_runner::TestCaseError;
    use std::sync::Arc;
    use ulid::Ulid;

    /// Fallible-fixture result: the crate denies `panic_in_result_fn`, so tests
    /// report failures by returning `Err` rather than via `assert!`.
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Adapt a fallible fixture call into proptest's error type (proptest
    /// closures cannot use `?` on arbitrary errors directly).
    fn tce(e: impl std::fmt::Display) -> TestCaseError {
        TestCaseError::fail(e.to_string())
    }

    fn ensure(cond: bool, msg: &str) -> TestResult {
        if cond { Ok(()) } else { Err(msg.into()) }
    }

    fn ensure_eq<T: PartialEq + std::fmt::Debug>(left: &T, right: &T, msg: &str) -> TestResult {
        if left == right {
            Ok(())
        } else {
            Err(format!("{msg}: {left:?} != {right:?}").into())
        }
    }

    fn signer(seed: u8) -> Result<Sr25519Signer, Box<dyn std::error::Error>> {
        // Derive the author SS58 from the key, so every minted op's `author`
        // decodes back to its `author_key` and passes the identity binding.
        Ok(Sr25519Signer::from_seed_with_prefix(
            &[seed; 32],
            NetworkPrefix::HIPPIUS,
        )?)
    }

    /// Build the next properly-chained signed op for `signer`, advancing `prev`
    /// to this op's hash so the caller can keep extending the chain. `seq` makes
    /// each op's id and ciphertext distinct.
    fn chain(signer: &Sr25519Signer, prev: &mut Blake3Hash, lamport: u64, seq: u128) -> Op {
        let content = OpContent {
            op_id: Ulid::from(seq),
            lamport,
            key_epoch: 0,
            kind: OpKind::Remember,
            note_id: NoteId::from(Ulid::from(seq)),
            object_key: format!("team/global/notes/{seq}"),
            cid: content_hash(format!("ciphertext-{seq}").as_bytes()),
            prev_op_hash: *prev,
        };
        let op = Op::create_signed(signer, content);
        *prev = op.hash();
        op
    }

    #[tokio::test]
    async fn append_then_read_all_returns_ordered_ops() -> TestResult {
        let store = OpLogStore::new(Arc::new(MemoryBlobStore::new()));
        let s = signer(1)?;
        let mut prev = GENESIS_PREV;
        let ops: Vec<Op> = (0..3)
            .map(|i| chain(&s, &mut prev, i, u128::from(i) + 1))
            .collect();

        // Append out of order; read_all must still return ascending lamport.
        for op in ops.iter().rev() {
            store.append("team", op).await?;
        }

        let read = store.read_all("team").await?;
        ensure_eq(&read.len(), &3, "all three ops come back")?;
        let lamports: Vec<u64> = read.iter().map(|op| op.lamport).collect();
        ensure_eq(&lamports, &vec![0, 1, 2], "ops returned in lamport order")
    }

    #[tokio::test]
    async fn empty_oplog_reads_empty() -> TestResult {
        let store = OpLogStore::new(Arc::new(MemoryBlobStore::new()));
        let read = store.read_all("team").await?;
        ensure(read.is_empty(), "an unwritten op-log reads back empty")
    }

    /// A [`BlobStore`] whose `get` fails for one configured key — models an
    /// eventually-consistent bucket where a listed object transiently 404s (or
    /// vanishes between `list` and `get`).
    struct GetFailBlob {
        inner: Arc<MemoryBlobStore>,
        fail_key: String,
    }

    #[async_trait::async_trait]
    impl BlobStore for GetFailBlob {
        async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), crate::MemError> {
            self.inner.put(key, bytes).await
        }

        async fn get(&self, key: &str) -> Result<Vec<u8>, crate::MemError> {
            if key == self.fail_key {
                return Err(crate::MemError::Storage(
                    "simulated transient GET failure".to_owned(),
                ));
            }
            self.inner.get(key).await
        }

        async fn list(&self, prefix: &str) -> Result<Vec<String>, crate::MemError> {
            self.inner.list(prefix).await
        }

        async fn delete(&self, key: &str) -> Result<(), crate::MemError> {
            self.inner.delete(key).await
        }
    }

    #[tokio::test]
    async fn a_failed_get_skips_the_object_instead_of_aborting_the_read() -> TestResult {
        // One unfetchable object must not blind the whole team (I2): the read
        // succeeds, the other authors' chains survive intact, and the failing
        // author's chain is truncated at the break — the same per-object rule
        // the decode-fault path and `load_manifest` (M5) already follow.
        let inner = Arc::new(MemoryBlobStore::new());
        let seed_store = OpLogStore::new(inner.clone());

        // Author A: a 2-op chain, untouched by the fault.
        let a = signer(4)?;
        let mut prev_a = GENESIS_PREV;
        for i in 0..2 {
            let op = chain(&a, &mut prev_a, i, u128::from(i) + 1);
            seed_store.append("team", &op).await?;
        }
        // Author B: a 2-op chain whose SECOND (tail) object will fail its GET, so
        // B's surviving prefix is still genesis-rooted and op 1 of 2 survives.
        let b = signer(5)?;
        let mut prev_b = GENESIS_PREV;
        let b_first = chain(&b, &mut prev_b, 0, 10);
        seed_store.append("team", &b_first).await?;
        let b_second = chain(&b, &mut prev_b, 1, 11);
        seed_store.append("team", &b_second).await?;

        let failing = OpLogStore::new(Arc::new(GetFailBlob {
            inner,
            fail_key: object_key("team", &b_second),
        }));
        let read = failing.read_all("team").await?;
        ensure_eq(
            &read.len(),
            &3,
            "the read survives one failed GET: A's 2 ops + B's rooted prefix",
        )?;
        ensure(
            !read.iter().any(|op| op.hash() == b_second.hash()),
            "the unfetchable op itself is absent until the next sync retries it",
        )
    }

    /// A [`BlobStore`] whose every `get` fails — models a systemic outage
    /// (expired sub-token, gateway auth fault) where LIST still succeeds.
    struct AllGetsFailBlob {
        inner: Arc<MemoryBlobStore>,
    }

    #[async_trait::async_trait]
    impl BlobStore for AllGetsFailBlob {
        async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), crate::MemError> {
            self.inner.put(key, bytes).await
        }

        async fn get(&self, _key: &str) -> Result<Vec<u8>, crate::MemError> {
            Err(crate::MemError::Storage(
                "simulated systemic GET outage".to_owned(),
            ))
        }

        async fn list(&self, prefix: &str) -> Result<Vec<String>, crate::MemError> {
            self.inner.list(prefix).await
        }

        async fn delete(&self, key: &str) -> Result<(), crate::MemError> {
            self.inner.delete(key).await
        }
    }

    #[tokio::test]
    async fn a_total_get_outage_errors_instead_of_reading_empty() -> TestResult {
        // The per-object skip is bounded: when LIST succeeds but EVERY GET fails,
        // `Ok(empty)` would let a caller's sync prune a warm index to nothing and
        // make reconcile report every anchored op missing. A total outage is a
        // systemic fault and must error, like the pre-skip behavior.
        let inner = Arc::new(MemoryBlobStore::new());
        let seed_store = OpLogStore::new(inner.clone());
        let s = signer(6)?;
        let mut prev = GENESIS_PREV;
        for i in 0..2 {
            let op = chain(&s, &mut prev, i, u128::from(i) + 20);
            seed_store.append("team", &op).await?;
        }

        let outage = OpLogStore::new(Arc::new(AllGetsFailBlob { inner }));
        ensure(
            outage.read_all("team").await.is_err(),
            "a total GET outage must error, never read back as an empty log",
        )?;

        // An genuinely EMPTY log (nothing listed, nothing to fetch) still reads
        // Ok(empty) — the guard keys on failed fetches, not on emptiness.
        let empty = OpLogStore::new(Arc::new(AllGetsFailBlob {
            inner: Arc::new(MemoryBlobStore::new()),
        }));
        ensure(
            empty.read_all("team").await?.is_empty(),
            "an empty log is still an empty read, not an error",
        )
    }

    /// A [`BlobStore`] that fails every `get` EXCEPT `keep_key` — models a
    /// MAJORITY (not total) GET outage where LIST still succeeds.
    struct AllButOneGetFailBlob {
        inner: Arc<MemoryBlobStore>,
        keep_key: String,
    }

    #[async_trait::async_trait]
    impl BlobStore for AllButOneGetFailBlob {
        async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), crate::MemError> {
            self.inner.put(key, bytes).await
        }

        async fn get(&self, key: &str) -> Result<Vec<u8>, crate::MemError> {
            if key == self.keep_key {
                self.inner.get(key).await
            } else {
                Err(crate::MemError::Storage(
                    "simulated majority GET outage".to_owned(),
                ))
            }
        }

        async fn list(&self, prefix: &str) -> Result<Vec<String>, crate::MemError> {
            self.inner.list(prefix).await
        }

        async fn delete(&self, key: &str) -> Result<(), crate::MemError> {
            self.inner.delete(key).await
        }
    }

    #[tokio::test]
    async fn a_majority_get_outage_errors_not_just_a_total_one() -> TestResult {
        // The guard must fire on a MAJORITY failure, not only a 100% one: a 2-of-3
        // GET outage that read back a single op would still let `sync`'s retain
        // prune the other two notes from a warm index. Only a MINORITY failure is
        // skipped as isolated per-object damage.
        let inner = Arc::new(MemoryBlobStore::new());
        let seed_store = OpLogStore::new(inner.clone());
        let s = signer(7)?;
        let mut prev = GENESIS_PREV;
        let mut keep_key = String::new();
        for i in 0..3 {
            let op = chain(&s, &mut prev, i, u128::from(i) + 30);
            seed_store.append("team", &op).await?;
            if i == 0 {
                keep_key = object_key("team", &op);
            }
        }

        // Keep only the first object's GET; fail the other two (a 2/3 majority).
        let outage = OpLogStore::new(Arc::new(AllButOneGetFailBlob { inner, keep_key }));
        ensure(
            outage.read_all("team").await.is_err(),
            "a majority (2 of 3) GET outage must error, not read back a pruned log",
        )
    }

    #[tokio::test]
    async fn an_exactly_half_get_outage_also_errors() -> TestResult {
        // The guard uses `>=`, not `>`: an exact 50/50 split (1 of 2 GETs failing)
        // still returns only half the log, which `sync`'s retain would prune the
        // other note against — the same catastrophe as a majority, so it errors.
        let inner = Arc::new(MemoryBlobStore::new());
        let seed_store = OpLogStore::new(inner.clone());
        let s = signer(8)?;
        let mut prev = GENESIS_PREV;
        let mut keep_key = String::new();
        for i in 0..2 {
            let op = chain(&s, &mut prev, i, u128::from(i) + 40);
            seed_store.append("team", &op).await?;
            if i == 0 {
                keep_key = object_key("team", &op);
            }
        }

        let outage = OpLogStore::new(Arc::new(AllButOneGetFailBlob { inner, keep_key }));
        ensure(
            outage.read_all("team").await.is_err(),
            "an exactly-half (1 of 2) GET outage must error, not read back a pruned log",
        )
    }

    #[tokio::test]
    async fn op_object_count_counts_objects_under_the_prefix() -> TestResult {
        let store = OpLogStore::new(Arc::new(MemoryBlobStore::new()));
        ensure_eq(
            &store.op_object_count("team").await?,
            &0,
            "empty log counts zero",
        )?;

        let s = signer(3)?;
        let mut prev = GENESIS_PREV;
        for i in 0..3 {
            let op = chain(&s, &mut prev, i, u128::from(i) + 1);
            store.append("team", &op).await?;
        }
        // Keys-only: it does not fetch or verify, so it reflects the raw object
        // count — the cheap staleness signal `refresh_if_stale` gates on.
        ensure_eq(
            &store.op_object_count("team").await?,
            &3,
            "three appended ops are counted",
        )
    }

    #[tokio::test]
    async fn forged_signature_is_dropped() -> TestResult {
        let blob = Arc::new(MemoryBlobStore::new());
        let store = OpLogStore::new(blob.clone());
        let s = signer(2)?;
        let mut prev = GENESIS_PREV;
        let mut op = chain(&s, &mut prev, 0, 1);

        // Tamper with a signed field *after* signing: the bytes on the wire no
        // longer match the signature, exactly the forged/edited-op case.
        op.lamport = 99;
        // Write the tampered op directly so the key still falls under the prefix.
        let bytes = serde_json::to_vec(&op)?;
        blob.put(
            "team/_oplog/00000000000000000099_00000000000000000000000000000001",
            bytes,
        )
        .await?;

        // Fail-soft (I2): the tampered op is dropped with a warn, not an abort, so
        // its presence cannot blind the team. It was the only op, so the read is
        // empty rather than an error.
        let read = store.read_all("team").await?;
        ensure(read.is_empty(), "the tampered op is dropped, not surfaced")
    }

    #[tokio::test]
    async fn op_with_mismatched_author_is_dropped() -> TestResult {
        // Cryptographic attribution: an op may carry a VALID signature yet claim a
        // different writer's SS58. Sign as A (so `verify_sig` passes), then swap the
        // `author` label to B's address and re-sign — the signature is sound but the
        // human identity no longer decodes to the signing key. `read_all` must reject
        // it: you cannot sign as one key but claim another's identity.
        let blob = Arc::new(MemoryBlobStore::new());
        let store = OpLogStore::new(blob.clone());
        let a = signer(1)?;
        let b = signer(2)?;

        let mut prev = GENESIS_PREV;
        let mut op = chain(&a, &mut prev, 0, 1);
        op.author = b.author_ss58();
        op.sig = a.sign(&op.signing_bytes());
        ensure(
            op.verify_sig(),
            "the re-signed op must still carry a valid signature",
        )?;
        ensure(
            !op.verify_identity(),
            "the swapped author must not decode to the signing key",
        )?;

        blob.put(
            "team/_oplog/00000000000000000000_00000000000000000000000000000001",
            serde_json::to_vec(&op)?,
        )
        .await?;

        // Fail-soft (I2): the mis-attributed op is dropped, not surfaced.
        let read = store.read_all("team").await?;
        ensure(
            read.is_empty(),
            "an op whose author SS58 does not decode to its signing key is dropped",
        )
    }

    #[tokio::test]
    async fn op_with_bound_author_passes() -> TestResult {
        // The complement: a normally minted op derives its author from the signer,
        // so its SS58 decodes to its key, `verify_identity` holds, and it reads back.
        let store = OpLogStore::new(Arc::new(MemoryBlobStore::new()));
        let s = signer(3)?;
        let mut prev = GENESIS_PREV;
        let op = chain(&s, &mut prev, 0, 1);
        ensure(
            op.verify_identity(),
            "a minted op's author is bound to its key",
        )?;

        store.append("team", &op).await?;
        let read = store.read_all("team").await?;
        ensure_eq(&read.len(), &1, "a bound-author op reads back")
    }

    #[tokio::test]
    async fn broken_chain_keeps_valid_prefix_without_blinding_the_team() -> TestResult {
        // I2 regression + M2: one author forks their chain while another writes
        // honestly. Only the broken TAIL is dropped — the forking author keeps the
        // valid genesis-rooted prefix, the honest author keeps everything, and the
        // whole team still gets its verified log. Prefix-keeping bounds the blast
        // radius of a transient mid-chain gap under eventual consistency (a synced
        // peer and a lagging one no longer diverge on the author's whole history).
        let store = OpLogStore::new(Arc::new(MemoryBlobStore::new()));
        let bad = signer(3)?;
        let good = signer(8)?;

        // `bad`: two ops both linking to genesis — a fork at the root. The lower
        // `(lamport, op_id)` op is the valid prefix; the second is the broken tail.
        let mut bad_prev = GENESIS_PREV;
        let bad_first = chain(&bad, &mut bad_prev, 0, 1);
        let mut bad_wrong = GENESIS_PREV;
        let bad_second = chain(&bad, &mut bad_wrong, 3, 2);

        // `good`: a clean two-op chain.
        let mut good_prev = GENESIS_PREV;
        let good_first = chain(&good, &mut good_prev, 1, 10);
        let good_second = chain(&good, &mut good_prev, 4, 11);

        for op in [&bad_first, &bad_second, &good_first, &good_second] {
            store.append("team", op).await?;
        }

        let read = store.read_all("team").await?;
        ensure_eq(
            &read.len(),
            &3,
            "the honest author's two ops plus the broken author's valid prefix survive",
        )?;
        ensure(
            read.iter().any(|op| op.op_id == bad_first.op_id),
            "the forking author's valid prefix (its first, genesis-rooted op) is kept",
        )?;
        ensure(
            read.iter().all(|op| op.op_id != bad_second.op_id),
            "only the broken tail — the second fork op — is dropped",
        )
    }

    #[tokio::test]
    async fn mid_chain_gap_keeps_the_prefix_not_the_whole_author() -> TestResult {
        // M2: a machine transiently misses ONE mid-chain object (eventual-consistency
        // lag on `list`/`get`). The author's ops BEFORE the gap must still converge —
        // dropping the whole author would make a lagging machine diverge from a synced
        // peer across that author's entire history until the gap heals.
        let store = OpLogStore::new(Arc::new(MemoryBlobStore::new()));
        let s = signer(5)?;

        let mut prev = GENESIS_PREV;
        let op1 = chain(&s, &mut prev, 0, 1);
        // op2 advances `prev` (so op3 links to it) but is intentionally never stored:
        // it is the mid-chain object the lagging machine has not yet listed.
        let _op2 = chain(&s, &mut prev, 1, 2);
        let op3 = chain(&s, &mut prev, 2, 3);

        store.append("team", &op1).await?;
        store.append("team", &op3).await?;

        let read = store.read_all("team").await?;
        ensure_eq(
            &read.len(),
            &1,
            "the pre-gap prefix (op1) survives a missing mid-chain object",
        )?;
        ensure(
            read.iter().any(|op| op.op_id == op1.op_id)
                && read.iter().all(|op| op.op_id != op3.op_id),
            "op1 is kept and op3 (past the gap) is dropped",
        )
    }

    proptest! {
        /// `longest_rooted_chain` keeps exactly the pre-gap prefix: the whole chain
        /// when intact, or `ops[0..k]` when op `k` is missing (everything from the
        /// gap on is orphaned — its `prev` names a now-absent op).
        #[test]
        fn longest_rooted_chain_keeps_the_pre_gap_prefix(
            len in 2_usize..8,
            remove in proptest::option::of(1_usize..8),
        ) {
            let s = signer(7).map_err(tce)?;
            let mut prev = GENESIS_PREV;
            let mut ops: Vec<Op> = Vec::new();
            for i in 0..len {
                ops.push(chain(&s, &mut prev, i as u64, (i + 1) as u128));
            }
            // Removing op `k` (1..len) orphans `ops[k..]` (their linkage crosses the
            // hole), so the kept set is the genesis-rooted prefix `ops[0..k]`.
            // Removing the last op (or none) leaves a shorter intact chain — keep all.
            let expected_len = match remove {
                Some(k) if k < len => {
                    ops.remove(k);
                    k
                }
                _ => len,
            };
            let refs: Vec<&Op> = ops.iter().collect();
            let kept = longest_rooted_chain(&refs);
            prop_assert_eq!(kept.len(), expected_len);
            for op in refs.iter().take(expected_len) {
                prop_assert!(kept.contains(&op.hash()));
            }
        }

        /// Convergence guardrail: the kept set is a pure function of the op SET, not
        /// its order. `read_verified` fetches with `buffer_unordered`, so a machine
        /// that lists/receives an author's ops in a different order must still keep
        /// the identical chain — otherwise two peers holding the same ops diverge.
        ///
        /// The generator deliberately forks: a straight prefix of `prefix_len` ops
        /// (possibly zero, i.e. the fork sits at genesis) splits at `fork_point`
        /// into two sibling branches, `branch_a_len` and `branch_b_len` ops long,
        /// each drawn from `1..3` so both always contribute at least one op.
        /// `fork_point` therefore always has >= 2 children in
        /// `longest_rooted_chain`'s child map on every generated case, forcing its
        /// fork-tiebreak `reduce` to actually run (`Iterator::reduce` only skips
        /// calling its closure when the iterator yields a single item, so >= 2
        /// children guarantees at least one call). The PRIOR generator built a
        /// straight line only — `chain` reassigns the same `prev` on every call, so
        /// `(0..len).map(...)` cannot produce a second child for any op — and this
        /// was confirmed empirically, not just reasoned: with the straight-line
        /// generator, replacing the tiebreak `reduce`'s entire body with a `panic!`
        /// still left this test (and the sibling pre-gap-prefix proptest, which
        /// also never forks) passing every case, because the tiebreak was simply
        /// never reached. The same `panic!` fails THIS generator deterministically
        /// on the first case, by the >= 2-children construction above (see the
        /// task report for both runs' output).
        #[test]
        fn longest_rooted_chain_is_fetch_order_independent(
            prefix_len in 0_usize..3,
            branch_a_len in 1_usize..3,
            branch_b_len in 1_usize..3,
            rot in 0_usize..16,
        ) {
            let s = signer(9).map_err(tce)?;
            let mut prev = GENESIS_PREV;
            let mut ops: Vec<Op> = Vec::new();
            let mut seq: u128 = 1;
            for i in 0..prefix_len {
                ops.push(chain(&s, &mut prev, i as u64, seq));
                seq += 1;
            }
            // Fork: both branches chain from the SAME `prev` (the prefix's tail, or
            // genesis when `prefix_len == 0`), so their first ops are siblings under
            // one parent hash — the shape the tiebreak `reduce` exists to resolve.
            let fork_point = prev;
            let mut a_prev = fork_point;
            for i in 0..branch_a_len {
                ops.push(chain(&s, &mut a_prev, (prefix_len + i) as u64, seq));
                seq += 1;
            }
            let mut b_prev = fork_point;
            for i in 0..branch_b_len {
                ops.push(chain(&s, &mut b_prev, (prefix_len + i) as u64, seq));
                seq += 1;
            }

            let refs: Vec<&Op> = ops.iter().collect();
            let base = longest_rooted_chain(&refs);
            let len = refs.len();
            let mut rotated = refs.clone();
            rotated.rotate_left(rot % len);
            prop_assert_eq!(base, longest_rooted_chain(&rotated));
        }
    }

    #[tokio::test]
    async fn fork_orphans_only_the_stray_op_not_the_linked_successors() -> TestResult {
        // Regression for the fork blast-radius bug: a cancelled-but-durable append
        // (or an equivocation) forks an author's chain. The prior cut-at-first-break
        // quarantine dropped the stray op AND every correctly-linked op after it —
        // permanently suppressing all of that author's later writes team-wide. The
        // linkage-aware quarantine keeps the branch that has successors and orphans
        // only the stray leaf.
        let store = OpLogStore::new(Arc::new(MemoryBlobStore::new()));
        let writer = signer(30)?;

        let mut prev = GENESIS_PREV;
        let root = chain(&writer, &mut prev, 0, 1);
        let shared = chain(&writer, &mut prev, 1, 2);
        // `prev` == hash(shared). Fork here: the live op and a stray sibling both
        // chain to hash(shared). The stray gets the LOWER seq/op_id, so a naive
        // `(lamport, op_id)` sort-prefix cut would keep the stray and drop the live
        // op plus everything after it.
        let fork_point = prev;
        let mut live_prev = fork_point;
        let live_first = chain(&writer, &mut live_prev, 2, 30);
        let live_second = chain(&writer, &mut live_prev, 3, 31);
        let live_third = chain(&writer, &mut live_prev, 4, 32);
        let mut stray_prev = fork_point;
        let stray = chain(&writer, &mut stray_prev, 2, 20);

        for op in [
            &root,
            &shared,
            &live_first,
            &live_second,
            &live_third,
            &stray,
        ] {
            store.append("team", op).await?;
        }

        let read = store.read_all("team").await?;
        ensure_eq(
            &read.len(),
            &5,
            "the shared prefix plus the whole live branch survive",
        )?;
        ensure(
            read.iter().all(|op| op.op_id != stray.op_id),
            "the stray fork leaf is quarantined",
        )?;
        ensure(
            read.iter().any(|op| op.op_id == live_second.op_id)
                && read.iter().any(|op| op.op_id == live_third.op_id),
            "the correctly-linked successors after the fork are KEPT, not dropped with the stray",
        )
    }

    #[tokio::test]
    async fn duplicate_op_object_is_deduped_not_an_error() -> TestResult {
        let blob = Arc::new(MemoryBlobStore::new());
        let store = OpLogStore::new(blob.clone());
        let s = signer(11)?;
        let mut prev = GENESIS_PREV;
        let op = chain(&s, &mut prev, 0, 1);

        // Append normally, then write a byte-identical copy under a SECOND key in
        // the prefix — a replayed/duplicated upload over the untrusted bucket.
        store.append("team", &op).await?;
        let bytes = serde_json::to_vec(&op)?;
        blob.put("team/_oplog/00000000000000000000_duplicate", bytes)
            .await?;

        // The copy shares the genesis `prev`, which would look like a fork; dedup
        // by `Op::hash` collapses it, so the read succeeds with exactly one op.
        let read = store.read_all("team").await?;
        ensure_eq(&read.len(), &1, "the duplicate op is deduped to one")
    }

    #[tokio::test]
    async fn undeserializable_object_under_prefix_is_skipped() -> TestResult {
        let blob = Arc::new(MemoryBlobStore::new());
        let store = OpLogStore::new(blob.clone());
        let s = signer(12)?;
        let mut prev = GENESIS_PREV;
        let op = chain(&s, &mut prev, 0, 1);
        store.append("team", &op).await?;

        // Junk bytes under the op-log prefix: not a valid `Op` JSON.
        blob.put("team/_oplog/not-an-op", b"{ not json".to_vec())
            .await?;

        // The junk is skipped (logged), and the valid op still comes back — one
        // bad object must not blind the whole team's verified log.
        let read = store.read_all("team").await?;
        ensure_eq(
            &read.len(),
            &1,
            "the junk object is skipped, the valid op remains",
        )
    }

    #[tokio::test]
    async fn op_bound_to_foreign_team_is_dropped() -> TestResult {
        let blob = Arc::new(MemoryBlobStore::new());
        let store = OpLogStore::new(blob.clone());
        let s = signer(13)?;
        // A properly signed, genesis-rooted op whose `object_key` names a DIFFERENT
        // team — a transplanted op (valid signature + chain, foreign namespace).
        let content = OpContent {
            op_id: Ulid::from(1u128),
            lamport: 0,
            key_epoch: 0,
            kind: OpKind::Remember,
            note_id: NoteId::from(Ulid::from(1u128)),
            object_key: "otherteam/global/notes/1".to_string(),
            cid: content_hash(b"ciphertext"),
            prev_op_hash: GENESIS_PREV,
        };
        let op = Op::create_signed(&s, content);
        store.append("team", &op).await?;

        // Fail-soft (I2): the transplanted op is dropped, not surfaced.
        let read = store.read_all("team").await?;
        ensure(
            read.is_empty(),
            "an op whose object_key is under another team is dropped",
        )
    }

    #[tokio::test]
    async fn same_lamport_and_op_id_across_authors_do_not_collide() -> TestResult {
        // H1 regression: `op_id` is a per-author ULID, so two different authors can
        // legitimately mint ops that share a (lamport, op_id). The op-log key must
        // bind the author, or the second honest `append` overwrites the first
        // author's object — destroying it and quarantining that author's chain.
        // Both ops are genesis-rooted single-op chains, so both must read back.
        let store = OpLogStore::new(Arc::new(MemoryBlobStore::new()));
        let a = signer(20)?;
        let b = signer(21)?;

        // Identical lamport AND op_id seq across the two distinct authors.
        let mut a_prev = GENESIS_PREV;
        let mut b_prev = GENESIS_PREV;
        let a_op = chain(&a, &mut a_prev, 0, 1);
        let b_op = chain(&b, &mut b_prev, 0, 1);
        ensure_eq(&a_op.op_id, &b_op.op_id, "the two authors share an op_id")?;
        ensure_eq(
            &a_op.lamport,
            &b_op.lamport,
            "the two authors share a lamport",
        )?;
        // The disjoint key spaces are exactly what prevents the overwrite.
        ensure(
            object_key("team", &a_op) != object_key("team", &b_op),
            "the author segment must make the two op-log keys distinct",
        )?;

        store.append("team", &a_op).await?;
        store.append("team", &b_op).await?;

        let read = store.read_all("team").await?;
        ensure_eq(
            &read.len(),
            &2,
            "both authors' colliding-(lamport, op_id) ops survive — neither key overwrote the other",
        )
    }

    #[tokio::test]
    async fn multi_author_interleaved_chains_verify() -> TestResult {
        let store = OpLogStore::new(Arc::new(MemoryBlobStore::new()));
        let alice = signer(4)?;
        let bob = signer(5)?;

        let mut a_prev = GENESIS_PREV;
        let mut b_prev = GENESIS_PREV;
        // Interleave lamports across the two independent chains: 0,2,4 vs 1,3,5.
        let a_ops: Vec<Op> = (0..3)
            .map(|i| chain(&alice, &mut a_prev, i * 2, 100 + u128::from(i)))
            .collect();
        let b_ops: Vec<Op> = (0..3)
            .map(|i| chain(&bob, &mut b_prev, i * 2 + 1, 200 + u128::from(i)))
            .collect();

        for op in a_ops.iter().chain(b_ops.iter()) {
            store.append("team", op).await?;
        }

        let read = store.read_all("team").await?;
        ensure_eq(&read.len(), &6, "both authors' ops come back")?;
        let lamports: Vec<u64> = read.iter().map(|op| op.lamport).collect();
        ensure_eq(
            &lamports,
            &vec![0, 1, 2, 3, 4, 5],
            "interleaved ops globally ordered",
        )
    }

    proptest! {
        /// The key scheme's load-bearing invariant: lexicographic key order — the
        /// order the blob store lists keys in — must equal logical
        /// `(lamport, op_id)` order, so a read sees ops in Lamport order. The
        /// `{lamport:020}` fixed width is what makes the numeric field sort as a
        /// string; this asserts it across the full `u64` / ULID range.
        #[test]
        fn object_key_lexical_order_matches_logical_order(
            la in any::<u64>(),
            sa in any::<u128>(),
            lb in any::<u64>(),
            sb in any::<u128>(),
        ) {
            let s = signer(7).map_err(tce)?;
            let (mut pa, mut pb) = (GENESIS_PREV, GENESIS_PREV);
            let oa = chain(&s, &mut pa, la, sa);
            let ob = chain(&s, &mut pb, lb, sb);
            prop_assert_eq!(
                object_key("team", &oa).cmp(&object_key("team", &ob)),
                (la, oa.op_id).cmp(&(lb, ob.op_id)),
            );
        }
    }
}
