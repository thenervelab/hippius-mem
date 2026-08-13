# Review Fix Program — Design

Date: 2026-08-13
Status: design (awaiting review)
Author surface: `hippius-mem-core`, `hippius-mem`

## Goal

Fix the findings from the 2026-08-13 adversarially-verified code review before
`v0.1.0` is offered to security-conscious teams. One finding breaks the flagship
"you do not need to trust the server" guarantee; four more are data-integrity or
concurrency bugs; three are lower-severity warnings; three are efficiency defects;
five are code-duplication cleanups (one of which is a latent-correctness risk).

The whole set is in scope (16 findings). Two adjacent hardening gaps named in the
readiness report are included as an explicitly-optional final phase.

## Constraints

- Toolchain pinned: Rust 1.97.1 (`rust-toolchain.toml`); MSRV 1.97.
- `#![forbid(unsafe_code)]` stays (workspace lint + per-crate-root attributes).
- `cargo clippy --all-targets --all-features -- -D warnings` must pass;
  `cargo fmt` before every commit; `cargo deny check` on any dependency change.
- rustfmt `use_small_heuristics = "Default"`; blank lines between logical steps;
  no horizontally dense code.
- No emojis anywhere. Commits use the user's git identity only — no
  `Co-Authored-By` lines.
- TDD for every behavior change: failing test first, watch it fail, minimal
  implementation, watch it pass.
- Each phase is its own PR off `main` with an adversarial review before merge.
- Clean break on the wrapped-key format: nothing is publicly released, so the
  signed format is the only format — no dual-read migration window (mirrors the
  Phase B manifest-v2 precedent).

## Backward-compatibility posture

Pre-release. The signed `WrappedKey` format is a hard replacement: old unsigned
wraps fail verification, and a one-time `rotate` re-provisions every member under
the signed format. No migration path is built. `doctor` gains a check that flags
any unsigned wrap still present in the bucket.

---

## Findings and fixes

Locations are on `main` at commit `0ef9114` (line numbers approximate; the review
line and the current line can drift by a few).

### Group A — Security-critical (Phase 2)

#### A1. Wrapped team keys are unsigned — `teamkey.rs` (`unwrap_team_key`, ~L294)

**Root cause.** `WrappedKey { epoch, ephemeral_public, ciphertext }` is the only
bucket-deserialized type carrying no author signature. `unwrap_team_key`
authenticates only an all-public ECDH transcript (recipient x25519 public,
ephemeral public) plus AAD derived from public inputs (team, epoch, both public
keys). The contributory check rejects low-order points; the AAD binding rejects
slot/epoch/team relocation. Neither prevents a *fresh forge*: a bucket writer (a
peer or the storage provider — both untrusted per `docs/SECURITY.md`) who knows a
victim's published x25519 public key can pick an ephemeral secret and an arbitrary
team key, derive the same AEAD key the victim will derive (ECDH symmetry), seal
the arbitrary key with correct AAD, and overwrite `team/_keys/{epoch}/{V_ss58}`.
The victim installs the attacker's key with no manifest cross-check; the attacker
then reads notes the victim seals.

**Fix (Approach A — sign the WrappedKey).** Mirror the existing `MemberKey`
signing pattern already present in the same file (`create_signed` + `verify` over
domain-tagged `signing_bytes`):

- Add `provisioner: VerifyingKey` and `sig: Signature` to `WrappedKey`.
- New domain tag, e.g. `WRAP_SIGN_DOMAIN = b"hippius-memory-teamkey-wrap-sign/v1"`
  (distinct from the existing `WRAP_AAD_DOMAIN`, which stays as the AEAD AAD tag).
- `wrap_team_key` signs `signing_bytes` = `WRAP_SIGN_DOMAIN` + framed(team, epoch,
  ephemeral_public, recipient_public, ciphertext) with the provisioner's signer.
  The whole transcript is signed, so nothing can be relocated or forged.
- `unwrap_team_key` (and the bootstrap/`fetch_team_key` path):
  1. verify `sig` against `provisioner` over the recomputed `signing_bytes`;
  2. check `provisioner` is authorized by the **live manifest** — the founder key
     or its named recovery key (exactly who may `rotate`/`provision` today).
  This requires the unwrap/bootstrap path to load the live manifest, which the
  provisioning path already does.

**Rejected alternative (Approach B — provisioning as a signed op).** Recording
each wrap as a new signed op gets signing "for free" but adds an op kind, bloats
the op-log with binary ciphertext (worsening the cold-sync ceiling this program
also addresses), and is a much larger change to rotation. Rejected.

**Tests.** The review's forge attack becomes a red-team unit test (attacker-crafted
wrap → `unwrap_team_key` returns `MemError::Crypto`); a valid provisioner
round-trips; a wrap signed by a non-founder/non-recovery key is rejected; the
existing tampered-transcript and slot/epoch/team-relocation cases stay green. A
`doctor` check flags any unsigned wrap in the bucket.

### Group B — Data-integrity / concurrency (Phase 3)

These share one theme: the index's version discipline is applied unevenly, and one
read path skips the membership filter. Fixes extend guards that already exist.

#### B1. Redacted/forgotten note reappears — `store/mod.rs` (`is_stale_rollback`, ~L3664)

**Root cause.** The staleness check only compares a candidate against a
*currently-present* index entry. After `redact`/`forget` calls `index.remove(id)`
there is no entry to compare, so a stale concurrent sync's `upsert_batch`
re-inserts the removed note. On the incremental path the record is restored from
the checkpoint with no blob decode, so the deleted blob does not protect it.
Redaction targets secrets/PII, so scrubbed content returns to recall output until
the next sync.

**Fix.** Record a per-id **removal watermark** (the lamport/version at which the id
was removed) and make `upsert`/`upsert_batch` reject any record for that id at or
below the watermark — the same monotonic rule `upsert` already enforces against
live entries, extended to cover removed ones. The watermark set is bounded (ids
removed since the last full replay) and cleared on full rebuild.

**Tests.** A stale sync racing a `redact` (and a `forget`) asserts the note stays
removed from recall/get.

#### B2. Freshly-remembered note dropped by concurrent sync — `store/mod.rs` (`retain`, ~L3648)

**Root cause.** `replay_full`/`sync_incremental` call `index.retain(&live_ids)`
over a live set captured before a concurrent `remember`'s append, and
`InMemoryIndex::retain` has no version guard, so it prunes the just-remembered
note. The lamport-monotonic guard that protects `upsert` does not cover `retain`'s
membership drop. The store confirms the write, but the next `get`/recall misses it
until the following sync.

**Fix.** Extend the lamport-monotonic guard to `retain`: never prune an id whose
index entry is newer than the sync's baseline lamport. Exactly the protection
`upsert` already has, applied to the prune step.

**Tests.** A `remember` interleaved with a concurrent sync asserts the note is
present in the immediately-following `get`.

#### B3. Deletion flags forgeable via `history()` — `store/mod.rs` (`history`, ~L2708)

**Root cause.** `history()` reads `self.oplog.read_all` (unfiltered) while
recall/get read the manifest-filtered view (`read_and_filter`). A removed member
who retains bucket write access can append a validly-signed `Forget`/`Redact` op;
the manifest filter drops it from recall/get, but `history()` still derives
`tombstoned:true`/`redacted:true`, falsifying `NoteHistory`'s documented "a get
will not return content" contract. A non-member can make a live note look
forgotten team-wide.

**Fix.** Derive the agent-visible flags (`tombstoned`, `redacted`, `links`) from
the same membership-filtered converge recall uses — reuse the manifest filter in
`read_and_filter`. The raw `entries` trail can still list all signed ops (that is
the audit record), but the derived flags come from the filtered view.

**Tests.** A non-member's signed `Redact`/`Forget` op leaves `history()`'s flags
unchanged for a note the manifest still admits; the audit `entries` still record
the op.

#### B4. Anchor proofs lost across processes — `store/mod.rs` (`ensure_seq_seeded`/`persist_anchor_record`, ~L2941)

**Root cause.** Anchor-record `seq` assignment is not serialized across processes:
`ensure_seq_seeded` seeds `next_seq` once per process, the anchor path never takes
the cross-process `WriterLock`, and `persist_anchor_record` does an unconditional
overwrite `put` on `{team}/_anchors/{author}/{seq:020}`. Two same-identity
processes (the routine MCP deployment) mint overlapping seqs and clobber each
other's records; the loser's committed batch loses its `AnchorRecord` permanently,
and `reconcile` cannot detect it because it only iterates records the bucket still
serves.

**Fix.** Acquire the existing `WriterLock` around anchor-seq reservation + persist,
and re-seed `next_seq` from durable records under the lock (mirroring how
`mint_and_append` adopts the shared tip). Make `persist_anchor_record`
fail-on-exists so a raced key is detected and the seq re-reserved, rather than
silently overwritten.

**Tests.** Two same-identity anchor writers over one blob store both retain their
`AnchorRecord`; `history()` returns an anchor proof for each.

### Group C — Warnings (Phase 4)

#### C1. Dedup gate cold during boot — `server.rs` (`logic_remember`, ~L619)

`remember` is exempted from awaiting warmup (so it does not spuriously fail on
`NotFound`), but its `nearest_duplicate` check reads the same index and so scans an
empty index during boot replay, admitting duplicates. Fix: await warmup
specifically before the `nearest_duplicate` check, keeping the create path's
`NotFound` exemption separate — the two concerns are decoupled. Test: a
near-duplicate `remember` issued during the warmup window is refused as it would be
post-warmup.

#### C2. CLI panic on non-ASCII `--since` — `report.rs` (`parse_since_value`, ~L112)

`value.len() - 1` is used as a byte index into `split_at`, panicking mid-multibyte
char (e.g. `--since 7д`). Fix: split on a char boundary (parse the trailing unit
via `chars()`), returning the intended friendly `anyhow` error for anything
unrecognized. Test: a multibyte `--since` value returns the friendly error, not a
panic.

#### C3. Import ledger not written on abort — `import.rs` (`run`, ~L164)

A mid-batch failure propagates via `?` before `save_ledger`, discarding ledger
entries for already-imported notes and defeating the resurrection guard. Fix:
persist the ledger for successfully-imported notes on the error path too
(save-what-succeeded before propagating). Test: a simulated mid-batch failure
leaves the already-imported notes recorded in the ledger.

### Group D — Efficiency (Phase 5)

#### D1. Writer lock held across the network read — `store/mod.rs` (`read_and_filter`, ~L3442)

The single writer lock is held across the whole op-log LIST + fetch + verify, so
one slow gateway read stalls all concurrent writers for seconds. Fix: move the
fetch + verify outside the lock; take the lock only for the clock re-seed. The
monotonic max-merge and head-visibility guard already tolerate a lagging view.
**Depends on B2** (moving the fetch outside the lock widens exactly the race the
`retain` version-guard closes), so it lands after Phase 3. Test: a slow fetch no
longer blocks a concurrent write.

#### D2. Every op re-verified on every sync — `oplog/store.rs` (`read_verified`, ~L396)

Immutable, already-verified, locally-cached ops are re-hashed and
signature/SS58-verified in full on every sync — O(total ops) crypto where 1-2 ops
are typically new. Fix: keep an in-memory set of already-verified op object keys
and run verification only on newly-listed keys. Op objects are immutable and
uniquely keyed, so the cache needs no invalidation. This is the fix that most
directly relieves the documented cold-sync ceiling. Test: verification count
scales with new ops, not total.

#### D3. Double full-sync at every boot — `main.rs` (warmup, ~L270)

Warmup deliberately leaves the auto-refresh watermark unset, so the first request
redoes a full sync and doubles cold-start latency (mattering because session-start
recalls are hook-mandated). Fix: have warmup record the watermark it established,
so the first post-boot request tails only new ops. Test: a single full sync at
startup.

### Group E — Cleanups (Phase 1 for E1; Phase 6 for the rest)

#### E1. Duplicated write-serialization protocol — `store/mod.rs` (`commit_edit` ~L1509, `mint_and_append` ~L1900)

The cross-process serialization sequence is copy-pasted and kept in lockstep only
by comments; a third write path that drops a step reintroduces the self-fork class
fixed in `2a31476`. Fix: extract the protocol into one shared helper both call.
**Landed first (Phase 1)** so the B4 anchor-lock and D1 lock-scope changes edit one
path, not two. Test: existing write/edit tests stay green over the extracted
helper.

#### E2. `doctor`'s hand-rolled store factory — `doctor.rs` (~L230)

Has drifted from `build_store` and shipped a bug. Fix: `doctor` calls the shared
`build_store`. Test: `doctor` builds the same store shape as the server path.

#### E3. `Config`/`TeamProfile` field + validate duplication — `config.rs` (~L548)

Fix: collapse the duplicated field/validation logic. Test: existing config tests
stay green.

#### E4. `InMemoryIndex::upsert` vs `upsert_batch` pipeline duplication — `index/mod.rs` (~L692)

Fix: `upsert` delegates to the batch path (single-element), so the B1/B2
version-guards are written once and cover both. Test: existing index tests plus the
B1/B2 guard tests pass through both entry points.

#### E5. Writer lock is opt-in and fails silently — `store/mod.rs` (~L835) [PLAUSIBLE]

The lock's omission has no diagnostic. Fix: make correctness paths assert its
presence (or make it non-optional where writes require cross-process
serialization), so a missing lock fails loudly. Test: a store built without the
lock on a path that requires it errors clearly.

### Group F — Adjacent hardening (Phase 7, OPTIONAL)

Named in the readiness report, not in the 16 review findings. Include only if the
reviewer wants them; easy to cut.

- **F1. `gc.rs` has 0% test coverage** — the mark-and-sweep that deletes blobs from
  the bucket is entirely unexecuted by tests. Add coverage for mark, sweep, and the
  keep/delete decision.
- **F2. Unpinned retrieval constants** — mutation testing proved the dedup
  threshold and the index rank constant can drift without a test failing. Add
  pinning tests so a change to either is caught.

---

## Phasing (each an independent PR off `main`, TDD, adversarial review)

1. **E1 — write-serialization dedup.** Small refactor first, so later concurrency
   fixes touch one path.
2. **A1 — signed `WrappedKey`.** Standalone, independently reviewable; unblocks the
   security-team-ready claim.
3. **B1–B4 — data-integrity / concurrency.** Includes the B2 `retain` guard,
   prerequisite for D1.
4. **C1–C3 — warnings.** Quick; may fold into phase 3's PR or stand alone.
5. **D1–D3 — efficiency.** After the B2 guard exists.
6. **E2–E5 — remaining cleanups.** Last; refactors read cleanest once behavior is
   settled.
7. **F1–F2 — adjacent hardening (optional).**

## Testing strategy

- Failing-test-first for every behavior change.
- Concurrency fixes (B1, B2, B4, D1) reproduce each race deterministically with two
  `MemoryStore`s over one `MemoryBlobStore` under a shared identity.
- The crypto fix (A1) gets the forge attack as a red-team test.
- New version-guards (B1, B2) get **mutation-test coverage** (flip the guard,
  confirm a test dies) — the review found some retrieval constants unpinned, so new
  guards must be mutation-covered, not merely exercised.
- Per commit: `cargo fmt`; `cargo clippy --all-targets --all-features -- -D
  warnings`; scoped `cargo test`.
- Per phase: full workspace suite; a coverage spot-check on the touched files.

## Out of scope

- No new op kinds.
- No gateway/console/account changes.
- No multi-admin (m-of-n) work; A1's authorized-provisioner rule is
  founder-or-recovery-key, consistent with the current model. Multi-admin remains
  the separate, unscheduled design doc.
- No dual-read migration for the wrapped-key format (clean break, see posture).

## Completion

After all in-scope phases merge, `mcp__hippius-mem__remember` the durable
decisions this program created (signed-wrapped-key authorization rule; index
version-guard extended to retain and post-removal re-insert; anchor path
serialized under the writer lock), one note each with keyword-rich summaries. The
existing team-memory note on the unsigned-wrapped-key finding
(`mem_01KZXTTTVRKCBTKJ0F57Z5V359`) should be linked as resolved-by once A1 merges.
