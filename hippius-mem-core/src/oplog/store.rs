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
//!   shorter but still-valid chain; nothing *in the chain* pins "this is the
//!   latest";
//! - **whole-author suppression** — hiding every object of one author makes that
//!   author's writes simply absent, with no gap to notice;
//! - **split-view / equivocation** — serving different readers different subsets
//!   so they converge to different states.
//!
//! Those are *availability/suppression* attacks, not integrity attacks, and the
//! chain alone cannot catch them. Two mitigations sit outside the chain. On-chain
//! anchoring (a root committed publicly pins what existed at a point in time)
//! plus the reconciliation tool that cross-checks each machine's view against the
//! anchored roots — built in [`crate::audit::reconcile`] — detects suppression of
//! *anchored* ops; with the `chain` feature the roots are read back from the
//! chain, so even a bucket that forges a self-consistent anchor record is caught
//! (see that module). And [`crate::oplog::HeadPointer`] supplies what the chain
//! itself cannot: each author publishes a signed object naming their current tip,
//! so a truncated tail contradicts a signature the bucket cannot forge. That
//! NARROWS tail-truncation rather than closing it — a bucket that drops or rolls
//! back the head object too is still silent (see that type).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use futures_util::StreamExt;
use serde::{Deserialize, Serialize};

use crate::{Blake3Hash, BlobStore, MemError, Op, Ss58, VerifiedOps, VerifyingKey};

/// One author whose chain broke on a verified read, and how many of their ops
/// that read therefore dropped.
///
/// A verified read keeps only each author's longest genesis-rooted hash chain
/// (see `quarantine_broken_chains`); everything else — a fork sibling, or an op
/// orphaned by a missing ancestor — is quarantined. That used to be a
/// `tracing::warn!` and nothing more, so nothing an operator could query said an
/// author's tail had gone quiet. This is that evidence.
///
/// # What it proves, and what it does not
///
/// It proves only that THIS read saw an author's ops fail to form one chain, and
/// how many ops that cost. It does NOT identify a cause. All of these produce the
/// identical record:
///
/// - an attacker (or the bucket) injecting a signed-but-forked op to suppress the
///   losing branch — the case this field exists to surface;
/// - a mid-chain op object the bucket dropped for good;
/// - a mid-chain op object still in the bucket that this read did not see — its
///   GET failed, or the LISTING omitted it while a later op of the same author
///   was listed (eventual-consistency lag, which this codebase anticipates
///   elsewhere: see `MemoryStore::sync`'s `head_visible` guard). Both are
///   transient: the object is picked up on the next sync and the record then
///   disappears on its own;
/// - a cancelled-but-durable append an honest writer re-minted over — an
///   `append` whose PUT landed but whose response failed, so the writer's guard
///   dropped with its tip unchanged and the next write re-minted against the
///   same `prev_op_hash` (see `MemoryStore::mint_and_append`'s "Identity reuse"
///   notes). Every write path (`mint_and_append`, and `commit_edit`'s own
///   append-failure arm) best-effort deletes the orphaned op object right after
///   the failed append returns (`OpLogStore::reclaim_failed_append`), so this
///   cause now usually self-clears instead of persisting forever — but the
///   reclaim is itself best-effort, so a delete that fails leaves the orphan
///   (and this record) exactly as durable as before.
///
/// So a non-empty report is a reason to look, not proof of an attack, and it does
/// not reliably self-clear: the eventual-consistency lag above always does, the
/// cancelled-but-durable append usually does too (its reclaim can itself fail),
/// and the other two — an attacker's fork, a genuinely dropped object — do not.
/// The record cannot say which of the four it is. Attribution IS cryptographic:
/// `author` is the op's
/// SS58, which the read path already required to decode to the signing key the
/// signature verified against, so the named author really did sign the ops
/// involved — but signing them says nothing about who caused the fork.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantinedAuthor {
    /// The SS58 of the author whose chain broke — cryptographically bound to the
    /// signing key by the read path's identity check, never merely claimed.
    pub author: Ss58,
    /// How many of that author's ops this read dropped: the ops present, verified
    /// individually, and then excluded because they were not on the surviving
    /// chain. Never zero — an author with an intact chain gets no entry.
    pub dropped_ops: usize,
}

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

    /// Best-effort delete of the op object a FAILED `append` may nonetheless have
    /// left durable.
    ///
    /// `append` is a single `blob.put`, so a gateway that commits the object and
    /// then loses the response returns `Err` to the caller while the object is
    /// durable. Every `MemoryStore` write path that holds the shared writer guard
    /// across an append (`mint_and_append`, and `commit_edit`'s own append call)
    /// leaves the clock unchanged on that `Err`, so the next write re-mints
    /// against the same `prev_op_hash` — if the "failed" append actually landed,
    /// two durable ops now share that predecessor: a self-fork of an honest
    /// chain, on one machine, with no attacker. This call issues the delete that
    /// removes that orphan — issuing it is not instantaneous with the `put`
    /// landing, so a concurrent reader CAN observe the object in the gap between
    /// the two; "removes the orphan" is not "removes it before anyone can see
    /// it" (see the precondition below for the race this leaves open if the
    /// reader in question is this same process's own sync). It deletes exactly
    /// `object_key(team, op)` — the identical key `append` writes, computed by
    /// the same private helper, so the two can never name different objects.
    ///
    /// # Precondition: caller holds the writer guard, one writer per identity
    ///
    /// This delete is safe only while the CALLER still holds `MemoryStore`'s
    /// writer guard. `read_and_filter` (the `sync`/`refresh_if_stale` path) takes
    /// that same guard and, once it does, adopts this author's latest VISIBLE op
    /// in the read as the new cached chain head — and a durable-but-"failed" op
    /// is a valid, signed, genesis-reachable, newest op of its author, exactly
    /// what gets adopted. Release the guard before calling this and a concurrent
    /// `read_and_filter` can adopt the about-to-be-deleted orphan as the head in
    /// that gap; this delete then removes an op the process's own cache now
    /// points at, so every later write of this author chains onto a hash nothing
    /// durable holds — `longest_rooted_chain` can never root them at genesis, so
    /// EVERY later op of that author is quarantined, not just the one orphan.
    /// This does not heal itself: once the quarantined ops are absent from the
    /// verified read, the affected process's `head_visible` check goes FALSE
    /// (not true — nothing re-adopts anything), so `read_and_filter` takes its
    /// eventual-consistency-lag branch and RETAINS the already-dangling cached
    /// head rather than replacing it with anything better, on every read, until
    /// the process restarts. That is strictly worse than the bounded one-op
    /// fork this method exists to prevent, so both
    /// current call sites hold the guard across this call precisely to close
    /// that window — do not add a third call site that does not. For the same
    /// reason, never wrap a call to this method in a `select!`/`timeout` that
    /// can drop its future: a cancelled call skips the delete entirely and
    /// silently reintroduces the permanent fork this method exists to remove.
    ///
    /// The guard only serializes writers WITHIN one process. Under two processes
    /// sharing one signer seed (an already-unsupported configuration — see
    /// `MemoryStore::mint_and_append`'s "Identity reuse" notes), no local guard
    /// can stop the OTHER process from adopting and extending the orphan between
    /// this process's failed `put` and this delete; this call then removes an op
    /// the other process's later op now depends on, converting what would have
    /// been a bounded one-op fork into the same unbounded loss described above,
    /// on that other process. No code change here closes that: it is why "one
    /// identity per process" is load-bearing, not merely tidy.
    ///
    /// A third residual, OPEN and not attempted here: the guard ordering above
    /// closes only the delete-IN-FLIGHT window — while this call's own `delete`
    /// is still executing, serialized behind the guard. It does NOT close a
    /// delete-VISIBILITY-LAG window on the other side of it. This crate targets
    /// an eventually-consistent backend deliberately (`read_and_filter`'s
    /// `head_visible` guard exists precisely because a LIST can lag a PUT — see
    /// that function's own comment); the same lag can run in the opposite
    /// direction — a LIST or GET that still serves an object after its DELETE
    /// has already returned `Ok` to this caller. If a later `read_and_filter`
    /// runs after this call has fully returned (guard already dropped, delete
    /// already reported success) but the backend has not yet propagated that
    /// delete, it can still list and fetch the orphan, verify it (a delete that
    /// has not yet propagated does not retroactively invalidate a still-served
    /// copy), and adopt it as head — reproducing the unbounded, non-self-healing
    /// loss described above by a second route, once the delete's effect
    /// eventually does propagate and the object actually disappears. This
    /// predates the guard-ordering fix and applies identically to both write
    /// paths (`mint_and_append` and `commit_edit`); no local synchronization can
    /// close it, since by the time it happens this call has already completed
    /// and there is no guard left to hold.
    ///
    /// Never returns an error: a cleanup failure is logged with `tracing::warn!`
    /// and nothing else, so it can never mask the original append error the
    /// caller is about to return. `delete` is idempotent, so calling this for an
    /// op whose append never reached the bucket (e.g. a `Serialize` failure before
    /// any `put`) is benign — the delete simply finds nothing to remove.
    ///
    /// This is best-effort, not a guarantee: the delete can fail (or be lost the
    /// same way the append was) and leave the orphan durable, in which case
    /// `quarantine_broken_chains` will report it on every later read exactly as
    /// it did before this method existed.
    pub(crate) async fn reclaim_failed_append(&self, team: &str, op: &Op) {
        let key = object_key(team, op);
        if let Err(err) = self.blob.delete(&key).await {
            tracing::warn!(
                object_key = %key,
                error = %err,
                "could not reclaim an op object after its append failed; if the append \
                 actually landed, the orphan will fork this author's chain and be reported \
                 by quarantine_broken_chains on every later read"
            );
        }
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
    /// [`MemError::Storage`] / [`MemError::NotFound`] from the backend `list`/`get`,
    /// plus one [`MemError::Storage`] the reader synthesizes itself: the
    /// systemic-outage guard, which fires when FAILED GETS plus the ops those
    /// failures orphan account for at least half the listed objects. It keys on
    /// failed GETs specifically, NOT on every way a fetch can go wrong — a backend
    /// that answers with success and a junk body loses the whole log without
    /// tripping it (see the guard's own comment in `read_verified` for the full
    /// list of what it does not detect). The verification steps above never error —
    /// they drop bad ops — so a quarantined fork or a forged op degrades the read
    /// quietly, by design.
    pub async fn read_all(&self, team: &str) -> Result<VerifiedOps, MemError> {
        Ok(self.read_verified(team).await?.0)
    }

    /// [`read_all`](Self::read_all), plus the authors this read quarantined.
    ///
    /// Same read, same verification, same errors — the only difference is that the
    /// chain-quarantine evidence is returned instead of surviving only as a
    /// `tracing::warn!`. The audit path ([`crate::audit::reconcile`]) uses this so
    /// a broken author chain reaches an operator as report data; every other
    /// caller wants the ops alone and uses `read_all`.
    ///
    /// The returned vector is per-author and non-empty only for authors that
    /// actually lost ops. It reports what this read observed, NOT why — see
    /// [`QuarantinedAuthor`] for the causes that are indistinguishable here.
    ///
    /// # Errors
    ///
    /// Exactly what [`read_all`](Self::read_all) returns.
    pub async fn read_all_reporting_quarantine(
        &self,
        team: &str,
    ) -> Result<(VerifiedOps, Vec<QuarantinedAuthor>), MemError> {
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
    /// not blind the team) — but when a fetch fault costs at least HALF the
    /// listed objects while the listing itself succeeded, the read errors
    /// instead: that shape is a systemic fault (credentials, gateway), and an
    /// `Ok` short of that many ops would let `sync` prune a warm index against a
    /// view of the log we never actually saw (see the guard at the end of the
    /// body for what "costs" counts, and for why the count includes ops orphaned
    /// by a failed GET rather than only the failed GETs themselves). Exact
    /// byte-duplicate ops are deduped by [`Op::hash`] *before* chain verification
    /// so a replayed copy is not mistaken for a chain fork. A break that survives
    /// the dedup is genuine tamper-evidence; the affected author's broken branch
    /// is quarantined with a warn (see `quarantine_broken_chains`), never a
    /// whole-read error.
    async fn read_verified(
        &self,
        team: &str,
    ) -> Result<(VerifiedOps, Vec<QuarantinedAuthor>), MemError> {
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
        // The KEYS whose GET failed, not just how many: `object_key` ends every op
        // object's key with `_{author_key hex}`, so a failed key still names the
        // author whose chain lost an object even though its bytes never arrived.
        // That is what lets the systemic-outage guard below tell an op orphaned by
        // OUR fetch fault from an op quarantined because the bucket tampered.
        let mut failed_keys: Vec<String> = Vec::new();
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
                    tracing::warn!(
                        object_key = %key,
                        error = %err,
                        "skipping op-log object whose GET failed; it will be retried on the next sync"
                    );
                    failed_keys.push(key);
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

        // A broken or forked author chain costs that author only the ops NOT on
        // their longest genesis-rooted branch — those are dropped with a warn,
        // their surviving branch is kept, and every other author's ops are
        // untouched — so one member equivocating, or the bucket dropping one
        // mid-chain object, cannot blind the whole team. (This once dropped the
        // author's ops WHOLESALE; the longest-chain rewrite bounded it to the
        // losing branch. See `quarantine_broken_chains`.) Suppression of the
        // dropped ops is a conceded availability gap (see the module header) that
        // anchoring + reconciliation cover; blinding the team was not, and is what
        // this closes.
        //
        // Counted per author on both sides so the guard below can measure how many
        // of these drops are collateral of a failed GET (see `fetch_collateral`).
        // Taking the "before" snapshot HERE, not before the dedup/validity passes,
        // is what keeps a deduped replay or an individually-invalid op — neither of
        // which a fetch fault can cause — out of that count by construction.
        //
        // The returned `quarantined` and the `before`/`after` counts the guard
        // uses are the same raw quantity computed two ways, and that duplication
        // is DELIBERATE. The guard needs the drops FILTERED to authors that also
        // lost an object to a failed GET (`fetch_collateral`); the report needs
        // them unfiltered. Deriving both from one value would put that filter
        // beside an unfiltered field of the same name, and broadening the guard's
        // numerator to "all post-quarantine loss" is precisely the edit that would
        // turn every legitimate quarantine — the threat model working as designed —
        // into a hard read failure. Keeping the guard's arithmetic on its own
        // `ops_per_author` snapshots leaves it byte-for-byte what it was.
        let before_quarantine = ops_per_author(&ops);
        let quarantined = quarantine_broken_chains(&mut ops);
        let collateral = fetch_collateral(&before_quarantine, &ops_per_author(&ops), &failed_keys);

        // Systemic-outage guard: the per-object skip above is for ISOLATED faults.
        // When a fetch fault costs a MAJORITY of the listed objects while LIST
        // succeeded (an expired/GET-scoped sub-token, a gateway auth outage),
        // returning `Ok` with the surviving minority would be catastrophic
        // downstream — `sync`'s retain would prune every unfetched note from a warm
        // index, the dedup gate would stop seeing them, and `reconcile` would report
        // them missing (a false tamper alarm).
        //
        // The worst of those consequences is not the index: `sweep_orphan_blobs`
        // (`crate::MemoryStore`) builds its "still referenced" set from THIS read
        // and has no empty-set guard of its own — it relies entirely on this guard
        // erroring. A cascaded read that came back `Ok(empty)` for both of the
        // sweep's two reads would leave every note blob past the grace window
        // unreferenced and DELETE it from the bucket: permanent destruction of the
        // team's memory, not a warm-index blip that the next sync heals. Weakening
        // this guard is a data-loss risk, not only an availability one.
        //
        // Isolated bucket faults are a small
        // fraction, so a cost that is at least HALF is the systemic signal: it
        // errors, and callers keep serving their current index and retry later; a
        // strict minority is treated as per-object damage and skipped above. `>=`
        // (not `>`) errors the exact 50/50 split too — one op back out of two
        // objects still prunes the other note from a warm index, the same
        // catastrophe as the majority case. The `lost > 0` clause preserves
        // `Ok(empty)` for a genuinely empty listing (every count zero): the guard
        // keys on fetch loss, not emptiness. It still fires on the all-fail case
        // (`fetched_ok == 0`).
        //
        // What it COSTS is the corrected quantity, and the whole point of the
        // guard: not the failed GETs alone, but the ops that failed to reach the
        // verified set BECAUSE of them. `longest_rooted_chain` keeps only what is
        // reachable from `GENESIS_PREV` WITHIN the fetched set, so one unfetchable
        // op orphans every later op in that author's chain — one failed GET of
        // three is 100% op loss when it lands on a chain root, which counting
        // failed GETs alone (the pre-2026-08 guard) scored as a tolerable 33%.
        //
        // What it can NOT detect, stated honestly — five gaps, and this list is the
        // whole of them:
        //
        // 1. It keys on FAILED GETs, so a fetch fault that does not fail a GET is
        //    invisible: a gateway answering 200 with a junk body for every object
        //    increments `fetched_ok`, leaves `failed_keys` empty, and reads back as
        //    `Ok(empty)` however much it cost. Unchanged from the guard this
        //    replaced, and NOT established as unfixable — a closing path exists and
        //    was weighed. `object_key`'s trailing author hex is on every listed key
        //    whether its GET or its decode failed, so the same author-attributed
        //    majority threshold could in principle count decode failures too,
        //    leaving minority tolerance untouched (only junk that is half the
        //    listing would trip it). It is not taken here because it would let an
        //    APPEND-ONLY adversary — anyone who can write under the prefix, which is
        //    every member, a far weaker capability than the gateway control the
        //    failed-GET path needs — deny every reader by injecting junk objects
        //    until they reach half the listing, i.e. exactly the "one bad object
        //    must not blind the team" property this module rests on. That is a
        //    reason, not a proof; the task X3 report carries the full argument and
        //    two variants that might dodge it. Extending the guard is a further
        //    production change needing its own design and authorisation. Until
        //    then, a caller that cannot survive an empty read (see
        //    `sweep_orphan_blobs` above) needs its own floor.
        // 2. Attribution is per author and reads the failed object's KEY, which the
        //    untrusted bucket controls. A bucket can dodge attribution by renaming a
        //    key (the read then degrades quietly — the old behaviour, no new
        //    exposure) or force it by failing a listed key it names after an author
        //    — cheaply, since ANY error counts: a 5xx, or a body over
        //    `read_capped`'s ceiling (`crate::MemError::BlobTooLarge`), not just a
        //    mis-named key. Neither direction is new power: omitting the object
        //    already degrades the read, and failing every GET already errors it.
        // 3. An author who BOTH forks their chain and loses an object to a failed
        //    GET in one read is counted as collateral; at author granularity the two
        //    causes are indistinguishable, and counting it errors the read, which is
        //    the safe direction (the caller keeps its warm index).
        // 4. Loss below the half threshold is still tolerated, so a cascade confined
        //    to one author of a many-author bucket degrades quietly.
        // 5. Objects the bucket never LISTED are invisible entirely — whole-author
        //    suppression and tail truncation remain the module header's conceded gap.
        let failed_gets = failed_keys.len();
        let lost = failed_gets + collateral;
        let reached = fetched_ok.saturating_sub(collateral);
        if lost > 0 && lost >= reached {
            return Err(MemError::Storage(format!(
                "a fetch fault cost {lost} of {} listed op-log objects (at least half): \
                 {failed_gets} GET(s) failed and {collateral} further op(s) were orphaned by \
                 them while the listing succeeded — systemic storage fault (expired \
                 sub-token? gateway outage?), not per-object damage. Other ops may be absent \
                 for unrelated reasons (junk bytes, a forged op, a quarantined fork); this \
                 count is only what the fetch fault cost",
                failed_gets + fetched_ok
            )));
        }

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
        //
        // Why the hash tiebreak is unconditionally total, not just likely: `Op::hash`
        // (`op.rs`) hashes `signing_bytes()` PLUS the signature, and sr25519
        // randomizes the signature per call, so a Byzantine author replaying its own
        // `(lamport, op_id)` on new content already gets a distinct hash from the
        // signing step alone — no ordering elsewhere in this function is what makes
        // that true. The one case that DOES tie on all four components is a
        // byte-identical duplicate (same content, same signature), and `dedup_by_hash`
        // above already collapses that, harmlessly, since the two copies carry no
        // distinguishing information either way. A structural fork (two ops sharing a
        // `prev_op_hash`) is resolved earlier still, by `longest_rooted_chain`'s own
        // `(lamport, op_id, hash)` tiebreak inside `quarantine_broken_chains`: a
        // genuinely conflicting sibling pair never both survive to reach this sort.
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
        Ok((VerifiedOps::from_verified(ops), quarantined))
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
/// re-minted over — `OpLogStore::reclaim_failed_append` now best-effort deletes
/// that orphan shortly after the failed append returns, but a concurrent read
/// can still observe the orphan before the delete lands, so this can still land
/// here even when the reclaim goes on to succeed, not only when it fails) or an
/// op orphaned by a missing mid-chain object — is dropped with a warn (I2).
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
///
/// Returns one [`QuarantinedAuthor`] per author that actually lost ops, so a
/// broken chain is evidence a caller can surface rather than only a log line. The
/// order is the grouping `BTreeMap`'s (by `author_key` bytes), so two machines
/// seeing the same ops produce the same vector.
fn quarantine_broken_chains(ops: &mut Vec<Op>) -> Vec<QuarantinedAuthor> {
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
    let mut quarantined: Vec<QuarantinedAuthor> = Vec::new();

    for (_author, idxs) in by_author {
        let chain: Vec<&Op> = idxs.iter().map(|&i| &ops[i]).collect();
        let kept = longest_rooted_chain(&chain);

        if kept.len() < chain.len() {
            let dropped_ops = chain.len() - kept.len();
            tracing::warn!(
                author = %chain[0].author.as_str(),
                kept = kept.len(),
                dropped = dropped_ops,
                "op-log chain broke for an author (fork or missing mid-chain op); keeping the longest genesis-rooted chain and quarantining the rest so the team still converges"
            );
            // `chain[0].author` is sound for the whole group: the ops are grouped
            // by `author_key`, and `retain_individually_valid` already dropped any
            // op whose `author` does not decode to its `author_key` — so every op
            // here carries the identical, key-bound SS58.
            quarantined.push(QuarantinedAuthor {
                author: chain[0].author.clone(),
                dropped_ops,
            });
        }

        keep.extend(kept);
    }

    // Only rewrite the vec when something was actually quarantined; an all-intact
    // read (the common case) keeps every op and pays no `retain` pass.
    if !quarantined.is_empty() {
        ops.retain(|op| keep.contains(&op.hash()));
    }

    quarantined
}

/// How many ops each author contributes to `ops`.
///
/// A `HashMap` rather than the `BTreeMap` `quarantine_broken_chains` uses: the only
/// consumer is [`fetch_collateral`], which sums the per-author differences, and a
/// sum does not depend on iteration order — so nothing here can make two machines
/// disagree.
fn ops_per_author(ops: &[Op]) -> HashMap<VerifyingKey, usize> {
    let mut counts: HashMap<VerifyingKey, usize> = HashMap::with_capacity(ops.len());
    for op in ops {
        *counts.entry(op.author_key).or_default() += 1;
    }

    counts
}

/// How many of the ops `quarantine_broken_chains` dropped are collateral of a FAILED
/// GET rather than of tampering — the quantity the systemic-outage guard needs and
/// the one thing that keeps it from firing on a legitimate quarantine.
///
/// `before` and `after` are [`ops_per_author`] taken around the quarantine, so their
/// per-author difference is exactly what that pass dropped. A drop counts only when
/// the same author ALSO lost an op object to a failed GET in this read: an
/// unfetchable op orphans every later op in its own author's chain (chains are per
/// author, so that is the exact blast radius), while a fork, a forged op, or an
/// object the bucket never listed orphans ops with no failed GET behind them at all.
///
/// Attribution comes from the failed object's KEY: [`object_key`] ends every op
/// object's key with `_{author_key hex}`, so a failed GET names its author without
/// our ever seeing the bytes — which is the only information a failed fetch leaves.
/// The bucket controls those key names, so this is sound for a transient or systemic
/// fault on our side, NOT a defence against a bucket choosing key names to steer the
/// guard (see the guard's own comment for why neither direction of that gains it
/// anything). An author with no failed object contributes nothing here, so with zero
/// failed GETs this is arithmetically zero and the guard cannot fire.
fn fetch_collateral(
    before: &HashMap<VerifyingKey, usize>,
    after: &HashMap<VerifyingKey, usize>,
    failed_keys: &[String],
) -> usize {
    if failed_keys.is_empty() {
        return 0;
    }

    before
        .iter()
        .filter_map(|(author, &had)| {
            let dropped = had.saturating_sub(after.get(author).copied().unwrap_or(0));
            if dropped == 0 {
                return None;
            }
            // Only authors that actually lost ops pay this scan, which is why it can
            // afford to be a linear walk of the failed keys.
            let suffix = format!("_{}", author.to_hex());
            failed_keys
                .iter()
                .any(|key| key.ends_with(&suffix))
                .then_some(dropped)
        })
        .sum()
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
/// no descendants (a cancelled-but-durable append `reclaim_failed_append` did
/// not remove in time — its delete failed, or simply lost the race with this
/// read — or an equivocation) orphans only itself while the correctly-linked
/// continuation is kept — unlike a first-break cut, which drops every op after
/// the break. On a height tie the LOWER total
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
    async fn reclaim_failed_append_deletes_the_exact_object_append_wrote() -> TestResult {
        // Pins the mechanism directly: `append` writes exactly one object, and
        // `reclaim_failed_append` for the SAME `(team, op)` must delete that
        // object — proving it targets `object_key(team, op)`, the identical key
        // `append` used, and nothing else.
        let blob = Arc::new(MemoryBlobStore::new());
        let store = OpLogStore::new(blob.clone());
        let s = signer(1)?;
        let mut prev = GENESIS_PREV;
        let op = chain(&s, &mut prev, 0, 1);
        store.append("team", &op).await?;

        let key = object_key("team", &op);
        ensure(
            blob.list("team/_oplog/").await?.contains(&key),
            "precondition: the appended op object is durable before the reclaim",
        )?;

        store.reclaim_failed_append("team", &op).await;
        ensure(
            !blob.list("team/_oplog/").await?.contains(&key),
            "reclaim_failed_append deletes the exact object append wrote",
        )
    }

    /// A [`BlobStore`] whose `delete` always fails — drives
    /// `reclaim_failed_append`'s warn-and-swallow branch, which a redundant
    /// delete of an already-absent key never reaches (`MemoryBlobStore::delete`
    /// on a missing key still returns `Ok`, per the trait's documented
    /// idempotent contract — the `Serialize`-failure path in `mint_and_append`
    /// relies on exactly that when it calls this for an op whose `put` never
    /// ran).
    struct DeleteFailingBlob {
        inner: MemoryBlobStore,
    }

    #[async_trait::async_trait]
    impl BlobStore for DeleteFailingBlob {
        async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), crate::MemError> {
            self.inner.put(key, bytes).await
        }

        async fn get(&self, key: &str) -> Result<Vec<u8>, crate::MemError> {
            self.inner.get(key).await
        }

        async fn list(&self, prefix: &str) -> Result<Vec<String>, crate::MemError> {
            self.inner.list(prefix).await
        }

        async fn delete(&self, _key: &str) -> Result<(), crate::MemError> {
            Err(crate::MemError::Storage(
                "delete failed (injected)".to_owned(),
            ))
        }
    }

    /// Scoped deliberately narrow: this proves `reclaim_failed_append` reaches
    /// the warn-and-swallow branch — it neither panics nor propagates an error
    /// — when the underlying `delete` fails, a code path the call it replaced
    /// (a redundant reclaim of an already-deleted key, which never errors)
    /// never reached. It does NOT independently prove the delete was ever
    /// attempted: `DeleteFailingBlob::delete` never touches `inner`, so the
    /// "still listed" check below would hold even for a no-op stub — a
    /// tracing-capture harness could pin the `warn!` call itself, but that is
    /// out of proportion for what this test needs to establish.
    #[tokio::test]
    async fn reclaim_failed_append_does_not_panic_or_propagate_on_a_delete_failure() -> TestResult {
        let blob = Arc::new(DeleteFailingBlob {
            inner: MemoryBlobStore::new(),
        });
        let store = OpLogStore::new(blob.clone());
        let s = signer(3)?;
        let mut prev = GENESIS_PREV;
        let op = chain(&s, &mut prev, 0, 3);
        store.append("team", &op).await?;

        // Reaching the assertion below without panicking IS the proof.
        let key = object_key("team", &op);
        store.reclaim_failed_append("team", &op).await;
        ensure(
            blob.list("team/_oplog/").await?.contains(&key),
            "incidental, not independent proof: the fake's delete never touches \
             its backing store, so this holds regardless of what \
             reclaim_failed_append does with the error",
        )
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
    async fn a_chain_root_fetch_failure_errors_because_its_descendants_are_collateral() -> TestResult
    {
        // The guard measures ops LOST to the fetch fault, not failed GETs. One
        // author, a 3-op chain, one failed GET on the ROOT object:
        // `longest_rooted_chain` keeps only what is reachable from `GENESIS_PREV`
        // WITHIN the fetched set, so the two successfully fetched descendants are
        // orphaned as well — 3 of 3 ops gone from ONE failed GET.
        //
        // Counting failed GETs alone (the pre-2026-08 guard, `failed_gets >=
        // fetched_ok`) scored this as 1 >= 2, i.e. a tolerable 33% minority, and
        // returned Ok(EMPTY): `sync`'s retain then pruned a warm index to nothing
        // and reported `Ok(0)` to the caller. For a single-author machine — one
        // developer's own memory — that was the guard's entire failure mode.
        let inner = Arc::new(MemoryBlobStore::new());
        let seed_store = OpLogStore::new(inner.clone());
        let s = signer(14)?;
        let mut prev = GENESIS_PREV;
        let root = chain(&s, &mut prev, 0, 50);
        seed_store.append("team", &root).await?;
        for i in 1..3 {
            let op = chain(&s, &mut prev, i, u128::from(i) + 50);
            seed_store.append("team", &op).await?;
        }

        let failing = OpLogStore::new(Arc::new(GetFailBlob {
            inner,
            fail_key: object_key("team", &root),
        }));
        ensure(
            failing.read_all("team").await.is_err(),
            "a failed GET that orphans the rest of the author's chain must error, \
             not read back as an empty log",
        )
    }

    #[tokio::test]
    async fn a_chain_break_with_no_failed_get_degrades_quietly_even_when_every_op_is_lost()
    -> TestResult {
        // The security constraint the guard must not break. Quarantine dropping
        // ops IS the threat model working: a hostile bucket that drops an object
        // it never lists, or forges one, is exactly what the chain walk exists to
        // catch, and catching it must stay a quiet degrade — never an error, or
        // every hostile-bucket detection becomes a hard failure. Both cases below
        // lose 100% of the log with ZERO failed GETs, the same op loss as
        // `a_chain_root_fetch_failure_errors_because_its_descendants_are_collateral`
        // above; only the CAUSE differs, and only the cause may decide.
        //
        // With no failed GET the guard is arithmetically incapable of firing:
        // `fetch_collateral` short-circuits to 0 on an empty failed-key list, so
        // `lost` is 0 and the `lost > 0` clause holds it shut.

        // (a) The bucket never listed the chain ROOT (suppression, or a mid-chain
        // object dropped at the root). Every remaining op is unreachable from
        // genesis, so all of them are quarantined.
        let dropped_root = OpLogStore::new(Arc::new(MemoryBlobStore::new()));
        let s = signer(15)?;
        let mut prev = GENESIS_PREV;
        let _never_stored = chain(&s, &mut prev, 0, 60);
        for i in 1..3 {
            let op = chain(&s, &mut prev, i, u128::from(i) + 60);
            dropped_root.append("team", &op).await?;
        }
        ensure(
            dropped_root.read_all("team").await?.is_empty(),
            "a suppressed chain root must quarantine the orphans quietly, not error",
        )?;

        // (b) The bucket FORGED the chain root (a signed field edited after
        // signing). `retain_individually_valid` drops it, which orphans the two
        // honest ops behind it — again total loss, again no failed GET.
        let blob = Arc::new(MemoryBlobStore::new());
        let forged_root = OpLogStore::new(blob.clone());
        let f = signer(16)?;
        let mut prev = GENESIS_PREV;
        let mut root = chain(&f, &mut prev, 0, 70);
        for i in 1..3 {
            let op = chain(&f, &mut prev, i, u128::from(i) + 70);
            forged_root.append("team", &op).await?;
        }
        // Tamper AFTER the descendants chained off the honest hash, so the bucket
        // serves a root whose signature no longer covers its bytes.
        root.lamport = 99;
        blob.put(&object_key("team", &root), serde_json::to_vec(&root)?)
            .await?;

        ensure(
            forged_root.read_all("team").await?.is_empty(),
            "a forged chain root must quarantine the orphans quietly, not error",
        )
    }

    #[tokio::test]
    async fn a_cascade_costing_half_the_listed_objects_errors_even_with_a_healthy_author()
    -> TestResult {
        // The orphaned ops must not be counted on BOTH sides of the threshold.
        // Author A (3 objects) loses its root to a failed GET, so its other two
        // ops are orphaned; author B (2 objects) is untouched. The fault costs 3
        // of the 5 listed objects (the failed GET plus the two ops it orphaned)
        // and 2 reach the log — at least half, so it errors, even though a
        // majority of the GETs succeeded and one author came back whole.
        //
        // Measuring `reached` as the raw `fetched_ok` (4) instead of the objects
        // that actually reached the log (2) would score this 3 >= 4 and return
        // Ok, quietly relaxing the documented "at least half" rule.
        let inner = Arc::new(MemoryBlobStore::new());
        let seed_store = OpLogStore::new(inner.clone());

        let a = signer(19)?;
        let mut prev_a = GENESIS_PREV;
        let a_root = chain(&a, &mut prev_a, 0, 100);
        seed_store.append("team", &a_root).await?;
        for i in 1..3 {
            let op = chain(&a, &mut prev_a, i, u128::from(i) + 100);
            seed_store.append("team", &op).await?;
        }

        let b = signer(20)?;
        let mut prev_b = GENESIS_PREV;
        for i in 0..2 {
            let op = chain(&b, &mut prev_b, i, u128::from(i) + 110);
            seed_store.append("team", &op).await?;
        }

        let failing = OpLogStore::new(Arc::new(GetFailBlob {
            inner,
            fail_key: object_key("team", &a_root),
        }));
        ensure(
            failing.read_all("team").await.is_err(),
            "3 of 5 listed objects lost to one fetch fault is at least half — it must error \
             even though the other author's chain survived",
        )
    }

    #[tokio::test]
    async fn another_authors_quarantine_is_not_counted_as_fetch_collateral() -> TestResult {
        // The two causes must not be collapsed. Author A loses its TAIL object to
        // a failed GET — a real fetch fault, but one that orphans nothing, so its
        // collateral is zero. Author B is quarantined wholesale by a hostile
        // bucket that withheld B's chain root. Attribution is per author (the
        // failed key names ITS author via `object_key`'s trailing hex), so B's
        // three quarantined ops are NOT charged to A's failed GET: 1 lost of 5
        // listed, a strict minority, and the read stays Ok.
        //
        // Charging every quarantine drop to any failed GET instead would score
        // this 4 lost against 1 reached and error — turning a hostile bucket's
        // detected tampering into a hard read failure the moment any unrelated
        // GET flakes.
        let inner = Arc::new(MemoryBlobStore::new());
        let seed_store = OpLogStore::new(inner.clone());

        let a = signer(17)?;
        let mut prev_a = GENESIS_PREV;
        let a_root = chain(&a, &mut prev_a, 0, 80);
        seed_store.append("team", &a_root).await?;
        let a_tail = chain(&a, &mut prev_a, 1, 81);
        seed_store.append("team", &a_tail).await?;

        let b = signer(18)?;
        let mut prev_b = GENESIS_PREV;
        let _b_withheld_root = chain(&b, &mut prev_b, 0, 90);
        for i in 1..4 {
            let op = chain(&b, &mut prev_b, i, u128::from(i) + 90);
            seed_store.append("team", &op).await?;
        }

        let failing = OpLogStore::new(Arc::new(GetFailBlob {
            inner,
            fail_key: object_key("team", &a_tail),
        }));
        let read = failing.read_all("team").await?;
        ensure_eq(
            &read.len(),
            &1,
            "A's rooted prefix survives; B's orphans are quarantined without erroring the read",
        )?;
        ensure(
            read.iter().any(|op| op.op_id == a_root.op_id),
            "the surviving op is A's genesis-rooted prefix",
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
        /// gap on is orphaned — its `prev` names a now-absent op). Removing op `0`
        /// (the chain ROOT) is the degenerate case of this same rule, not a special
        /// case needing its own logic: `ops[0..0]` is EMPTY, so root-loss keeps
        /// NOTHING rather than a one-op prefix — with the root gone, no remaining
        /// op's `prev` chain bottoms out at [`GENESIS_PREV`] anymore, so none of
        /// them are reachable from genesis either.
        #[test]
        fn longest_rooted_chain_keeps_the_pre_gap_prefix(
            len in 2_usize..8,
            remove in proptest::option::of(0_usize..8),
        ) {
            let s = signer(7).map_err(tce)?;
            let mut prev = GENESIS_PREV;
            let mut ops: Vec<Op> = Vec::new();
            for i in 0..len {
                ops.push(chain(&s, &mut prev, i as u64, (i + 1) as u128));
            }
            // Removing op `k` (0..len) orphans `ops[k..]` (their linkage crosses the
            // hole), so the kept set is the genesis-rooted prefix `ops[0..k]` — empty
            // when `k == 0`, since that removes the root itself.
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
        /// on the first case, by the >= 2-children construction above.
        ///
        /// A `panic!` in the closure body only proves the closure is REACHED, not
        /// that this property is sensitive to what it returns — a tiebreak that
        /// ran but picked arbitrarily could still slip past a reachability-only
        /// check. Confirmed separately with an outcome-sensitive mutation:
        /// replacing the closure with `|a, _b| a` (first-child-wins, ignoring
        /// `rank` — an order-dependent choice, the exact convergence bug this
        /// property exists to catch) fails THIS generator deterministically, and
        /// passes the OLD straight-line generator across 4096 cases (the mutated
        /// closure never runs there, so nothing exercises it). See the task
        /// report for both runs' output.
        #[test]
        fn longest_rooted_chain_is_fetch_order_independent(
            prefix_len in 0_usize..3,
            branch_a_len in 1_usize..3,
            branch_b_len in 1_usize..3,
            // A uniform random permutation of 0..MAX_OPS, MAX_OPS = 6 being the
            // largest op count this generator can produce (prefix_len max 2 +
            // branch_a_len max 2 + branch_b_len max 2). Restricting a uniform
            // permutation of a superset to the indices below some `len <= MAX_OPS`,
            // keeping their relative order, is itself a uniform permutation of
            // `0..len` — so this covers every fetch order the generated case can
            // have, not just rotations of it.
            perm in Just((0_usize..6).collect::<Vec<usize>>()).prop_shuffle(),
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
            let shuffled: Vec<&Op> = perm
                .iter()
                .copied()
                .filter(|&i| i < len)
                .map(|i| refs[i])
                .collect();
            prop_assert_eq!(base, longest_rooted_chain(&shuffled));
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

    /// A torn write leaves a VALID JSON PREFIX, not garbage from the first byte.
    ///
    /// The `undeserializable_object_under_prefix_is_skipped` test above covers the
    /// easy shape (`b"{ not json"`), which fails `serde_json` at the very first
    /// key. A write interrupted partway — a torn upload, a truncated range read —
    /// instead leaves a well-formed JSON prefix that fails in the MIDDLE of the
    /// value (an EOF-while-parsing error, not a syntax error at byte zero); this
    /// pins that distinct shape reaches the same skip path.
    ///
    /// This is NOT coverage of the systemic-outage guard: a truncated object still
    /// GETs successfully, so it counts toward `fetched_ok` and never touches
    /// `failed_keys`. The guard is arithmetically blind to decode failures by
    /// design — extending it would let any team member (write access to the
    /// op-log prefix is an ordinary `append` privilege) hand the whole team a
    /// permanent read denial just by writing junk objects. A truncated object is
    /// skipped for exactly the same reason, and by the same code path, as any
    /// other undecodable object: this test does not claim otherwise.
    #[tokio::test]
    async fn a_truncated_op_object_is_skipped_not_fatal() -> TestResult {
        let blob = Arc::new(MemoryBlobStore::new());
        let store = OpLogStore::new(blob.clone());

        // Two single-op, genesis-rooted chains from different authors, so the
        // truncated author's chain has no later ops that would be quarantined as
        // a side effect of losing this one — the read length change comes only
        // from the decode fault, not from a chain-break cascade.
        let a = signer(40)?;
        let mut a_prev = GENESIS_PREV;
        let good = chain(&a, &mut a_prev, 0, 1);
        store.append("team", &good).await?;

        let b = signer(41)?;
        let mut b_prev = GENESIS_PREV;
        let torn = chain(&b, &mut b_prev, 0, 2);
        store.append("team", &torn).await?;

        // Truncate the SECOND author's object to 60% of its bytes, in place —
        // simulating a torn upload or a short range read.
        let torn_key = object_key("team", &torn);
        let full = blob.get(&torn_key).await?;
        let cut = full.len() * 6 / 10;
        ensure(
            serde_json::from_slice::<Op>(&full[..cut]).is_err(),
            "the 60%-truncated prefix must not itself decode as a valid Op",
        )?;
        blob.put(&torn_key, full[..cut].to_vec()).await?;

        let read = store.read_all("team").await?;
        ensure_eq(
            &read.len(),
            &1,
            "the truncated object is skipped while the intact op still reads",
        )?;
        ensure(
            read.iter().any(|op| op.hash() == good.hash()),
            "the surviving op is the untouched one, not a corrupted read of the torn one",
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
