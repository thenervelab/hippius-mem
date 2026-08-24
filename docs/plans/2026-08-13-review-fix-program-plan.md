# Review Fix Program Implementation Plan

> **Status: completed — historical record.** This plan was executed; do not re-run
> it. Kept for the rationale and task breakdown.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Every session starts with `mcp__hippius-mem__recall` on the task. Every subagent prompt MUST include: "Call `mcp__hippius-mem__recall` about the task before making changes, and `mcp__hippius-mem__remember` any durable decision/gotcha you discover." Every Rust-bearing task loads the `rust-style` skill before its first edit.

**Goal:** Fix the 16 findings from the 2026-08-13 code review (plus two optional adjacent gaps) so `v0.1.0` is safe to offer security-conscious teams.

**Architecture:** Seven dependency-ordered phases. A shared write-serialization helper lands first so later concurrency fixes touch one path; the security-critical signed-`WrappedKey` fix is a standalone early PR; the index version-guards land before the lock-scope change that depends on them.

**Tech Stack:** Rust 1.97.1 workspace (`hippius-mem-core`, `hippius-mem`), tokio, async-trait, aws-sdk-s3, serde/serde_json, schnorrkel via the existing `Signer`/`VerifyingKey`/`verify` seam, XChaCha20-Poly1305 via `crate::crypto`.

**Spec:** `docs/plans/2026-08-13-review-fix-program-design.md`

## Global Constraints

- Toolchain pinned: Rust 1.97.1 (`rust-toolchain.toml`); MSRV 1.97.
- `#![forbid(unsafe_code)]` stays; `cargo clippy --all-targets --all-features -- -D warnings` must pass; `cargo fmt` before every commit; `cargo deny check` on any dependency change (this program adds none).
- rustfmt `use_small_heuristics = "Default"` — never one-line dense code; blank lines between logical steps.
- No emojis anywhere. Commit messages use the user's git identity only — no `Co-Authored-By` lines.
- No new op kinds. No gateway/console/account changes. No multi-admin work.
- Secrets never travel via argv; read from tty/stdin only.
- Clean break on the wrapped-key format: no dual-read, no migration path. Old unsigned wraps must fail verification.
- TDD for every code task: failing test first, watch it fail, minimal implementation, watch it pass, commit.
- Each phase is its own PR off `main` with an adversarial review before merge.

---

## Phase 1 — Write-serialization dedup (prerequisite refactor)

### Task 1: Extract the shared cross-process write-serialization helper

`commit_edit` (`store/mod.rs` ~L1509) and `mint_and_append` (~L1900) copy-paste the same sequence — take `self.writer` lock, `lock_across_processes`, `adopt_shared_tip`, mint, append, publish head. Kept in lockstep only by comments; a third path that drops a step reintroduces the self-fork class fixed in `2a31476`. Extract it into one helper both call, with NO behavior change.

**Files:**
- Modify: `hippius-mem-core/src/store/mod.rs` (`commit_edit`, `mint_and_append`, new private helper)

**Interfaces:**
- Produces: a private `async fn append_under_serialization(&self, content: OpContent) -> Result<Op, MemError>` (exact name/return type: read both call sites and factor the common body; the return must carry whatever both callers currently use downstream — likely the appended `Op` and/or its lamport).

- [ ] **Step 1: Characterize current behavior with a test (should PASS today)**

Add to the `store/mod.rs` test module a test that drives an edit and a fresh remember through one `MemoryStore` and asserts both ops are appended, head advances, and `history` shows both with valid signatures. This is the refactor tripwire.

```rust
#[tokio::test]
async fn edit_and_remember_share_the_serialized_append_path() -> Result<(), MemError> {
    let store = build_test_store(Arc::new(MemoryBlobStore::new())).await?;
    let id = store.remember(sample_note("first")).await?;
    store.edit(id, sample_edit("first edited")).await?;
    let hist = store.history(id).await?;
    assert!(hist.entries.len() >= 2, "remember + edit both appended");
    assert!(hist.entries.iter().all(|e| e.author_key == store.author_key()));
    Ok(())
}
```

(If `build_test_store`/`sample_note`/`sample_edit`/`author_key` helpers do not exist under those names, read the existing `store/mod.rs` test module and reuse its real fixture helpers — do not invent new public API.)

- [ ] **Step 2: Run it to confirm it passes on the current code**

Run: `cargo test -p hippius-mem-core edit_and_remember_share_the_serialized_append_path`
Expected: PASS (this pins current behavior).

- [ ] **Step 3: Extract the helper**

Read `commit_edit` and `mint_and_append` in full. Factor the identical lock/adopt/mint/append/publish-head sequence into `append_under_serialization`. Both functions call it; the only per-caller difference (the `OpContent` built, and edit's under-lock CAS check) stays in the caller. Do not change the order of any step.

- [ ] **Step 4: Run the full core suite**

Run: `cargo test -p hippius-mem-core`
Expected: PASS — including the Step 1 tripwire and every existing write/edit/concurrency test.

- [ ] **Step 5: fmt, clippy, commit**

```bash
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
git add hippius-mem-core/src/store/mod.rs
git commit -m "refactor(core): extract shared cross-process write-serialization helper"
```

---

## Phase 2 — Security-critical: sign the wrapped team key

### Task 2: `WrappedKey` gains a provisioner signature

**Files:**
- Modify: `hippius-mem-core/src/identity/teamkey.rs` (`WrappedKey`, `wrap_team_key`, `unwrap_team_key`, new domain const)
- Test: `teamkey.rs` test module

**Interfaces:**
- Consumes: `Signer`, `Signature`, `VerifyingKey`, `verify` (already imported at `teamkey.rs:66`); `push_framed` (`crate::framing`).
- Produces:
  - `WrappedKey` fields `provisioner: VerifyingKey` and `sig: Signature` (after `ciphertext`).
  - `WrappedKey::signing_bytes(&self) -> Vec<u8>` and `WrappedKey::verify(&self) -> bool` (mirror `MemberKey::signing_bytes`/`verify` at ~L156/L195).
  - `wrap_team_key(team, team_key, recipient_x25519_public, epoch, signer: &S)` where `S: Signer + ?Sized` — one new trailing param.
  - `unwrap_team_key` unchanged signature, but rejects a wrap whose `verify()` is false.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn signed_wrap_round_trips_and_rejects_a_forge() {
    let team = "acme";
    let team_key = SecretKey::from_bytes([7u8; 32]);
    let provisioner = Sr25519Signer::from_seed_hex(TEST_SEED_A).expect("signer");
    let recipient = StaticSecret::from([9u8; 32]);
    let recipient_pub = PublicKey::from(&recipient).to_bytes();

    let wrap = wrap_team_key(team, &team_key, &recipient_pub, 3, &provisioner).expect("wrap");
    assert!(wrap.verify(), "a freshly signed wrap verifies");
    let opened = unwrap_team_key(team, &wrap, &recipient, 3).expect("unwrap");
    assert_eq!(opened.expose_bytes(), team_key.expose_bytes());

    // The review's forge: an attacker who knows recipient_pub crafts a wrap with
    // an arbitrary key and NO valid provisioner signature.
    let mut forged = wrap.clone();
    forged.sig = Signature::new([0u8; 64]);
    assert!(!forged.verify(), "an unsigned/garbage-sig wrap fails verify");
    assert!(
        unwrap_team_key(team, &forged, &recipient, 3).is_err(),
        "unwrap must reject a wrap that fails signature verification"
    );
}

#[test]
fn tampering_wrap_fields_breaks_the_signature() {
    let team = "acme";
    let team_key = SecretKey::from_bytes([1u8; 32]);
    let provisioner = Sr25519Signer::from_seed_hex(TEST_SEED_A).expect("signer");
    let recipient_pub = PublicKey::from(&StaticSecret::from([2u8; 32])).to_bytes();
    let mut wrap = wrap_team_key(team, &team_key, &recipient_pub, 5, &provisioner).expect("wrap");

    wrap.epoch = 6; // any signed field
    assert!(!wrap.verify(), "mutating a signed field invalidates the signature");
}
```

(Use the test module's existing signer/seed helpers if present — read it first; `TEST_SEED_A`/`Sr25519Signer::from_seed_hex` here stand in for whatever the module already uses.)

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p hippius-mem-core teamkey`
Expected: FAIL to compile — `WrappedKey` has no `provisioner`/`sig`, no `verify`, and `wrap_team_key` takes no signer.

- [ ] **Step 3: Implement**

Add the domain const near the other teamkey domains (~L78):

```rust
/// Domain tag for the provisioner signature over a [`WrappedKey`]. Distinct from
/// `WRAP_AAD_DOMAIN` (the AEAD AAD tag): the AAD binds the AEAD open; this binds
/// the signature that proves an AUTHORIZED provisioner produced the wrap.
const WRAP_SIGN_DOMAIN: &[u8] = b"hippius-memory-teamkey-wrap-sign/v1";
```

Extend the struct and add the signing/verify methods (framing mirrors `MemberKey`):

```rust
impl WrappedKey {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(WRAP_SIGN_DOMAIN);
        buf.extend_from_slice(&self.epoch.to_le_bytes());
        push_framed(&mut buf, &self.ephemeral_public);
        push_framed(&mut buf, &self.ciphertext);
        push_framed(&mut buf, self.provisioner.as_bytes());
        buf
    }

    /// Whether the provisioner signature is valid over the wrap's signed fields.
    #[must_use]
    pub fn verify(&self) -> bool {
        verify(&self.provisioner, &self.signing_bytes(), &self.sig)
    }
}
```

`wrap_team_key`: after building `ciphertext`, set `provisioner = signer.verifying_key()` (read `Signer` for the exact accessor name), construct the `WrappedKey` with a placeholder sig, then `let sig = signer.sign(&wrap.signing_bytes());` and store it (mirror `Op::create_signed` at `op.rs:422`, which signs after building the struct).

`unwrap_team_key`: as the FIRST check (before the epoch/ECDH work, cheapest rejection), add:

```rust
    if !wrapped.verify() {
        return Err(MemError::Crypto);
    }
```

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p hippius-mem-core teamkey`
Expected: PASS.

- [ ] **Step 5: fmt, clippy, commit**

```bash
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
git add hippius-mem-core/src/identity/teamkey.rs
git commit -m "feat(core): sign WrappedKey with an authorized-provisioner signature"
```

### Task 3: Provision signs, bootstrap authorizes against the live manifest

`verify()` (Task 2) proves a wrap was signed by SOME key; this task proves it was an AUTHORIZED provisioner — the live manifest's founder key or its named recovery key.

**Files:**
- Modify: `hippius-mem-core/src/identity/teamkey.rs` (`provision_team_key` ~L384, `fetch_team_key` ~L462, and the bootstrap path that installs epoch keys — grep `add_epoch_key`/`bootstrap_epoch_keys`)
- Modify: callers of `wrap_team_key`/`provision_team_key` that must now pass the founder signer (grep the workspace: `provision_team_key(`, `rotate_team_key(`)
- Test: `teamkey.rs` test module + `hippius-mem-core/tests/e2e_sharing.rs`

**Interfaces:**
- Consumes: `TeamManifest` (`founder_key: VerifyingKey`, `recovery_key: Option<VerifyingKey>`), `load_manifest`, Task 2's `WrappedKey::verify`.
- Produces: `provision_team_key`/`rotate_team_key` take the founder signer and stamp it as provisioner; `fetch_team_key` (and any bootstrap installer) rejects a wrap whose `provisioner` is not authorized by the live manifest.

- [ ] **Step 1: Write the failing tests**

```rust
#[tokio::test]
async fn fetch_rejects_a_wrap_from_an_unauthorized_provisioner() -> Result<(), MemError> {
    // Founder A publishes a manifest. An ATTACKER key (self-consistent signer,
    // not the founder and not a recovery key) wraps a team key to victim V and
    // publishes it under V's epoch slot. fetch_team_key for V must refuse it.
    // Build the store/manifest exactly as e2e_sharing.rs does; read it first.
    // Assert: fetch_team_key(...) returns Err (MemError::Crypto or Unauthorized).
    Ok(())
}

#[tokio::test]
async fn fetch_accepts_a_wrap_from_the_recovery_key() -> Result<(), MemError> {
    // Manifest names recovery key R (v2). A wrap provisioned by R for V verifies
    // AND is authorized -> fetch_team_key succeeds. This keeps `recover` working.
    Ok(())
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p hippius-mem-core teamkey fetch`
Expected: FAIL — provisioner authorization is not enforced.

- [ ] **Step 3: Implement**

In `provision_team_key`/`rotate_team_key`: thread the founder signer through to `wrap_team_key` (these functions already run as an authorized founder action — read them to confirm the signer is in scope; if not, add it as a parameter and update callers).

In `fetch_team_key` (and the bootstrap installer that calls `add_epoch_key`): after a successful `unwrap_team_key`, load the live manifest (the path already reads team state — reuse `load_manifest` the same way `provision_team_key` does) and check:

```rust
    let authorized = wrapped.provisioner == manifest.founder_key
        || manifest.recovery_key == Some(wrapped.provisioner);
    if !authorized {
        return Err(MemError::Crypto);
    }
```

Place the check so a bucket-planted wrap is refused before its key is installed. If a new `MemError` variant reads clearer than `Crypto` (e.g. `MemError::Unauthorized`), add it to `error.rs` and use it — but `Crypto` is acceptable and matches the file's no-detail convention.

- [ ] **Step 4: Add the founder-loss e2e and run everything**

Extend `e2e_sharing.rs`: founder provisions (signed wraps), a teammate fetches successfully, an attacker-planted wrap is refused. Then:

Run: `cargo test -p hippius-mem-core`
Expected: PASS — including every existing sharing/provision/rotate test.

- [ ] **Step 5: fmt, clippy, commit**

```bash
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
git add hippius-mem-core/src/identity/teamkey.rs hippius-mem-core/tests/e2e_sharing.rs
git commit -m "feat(core): authorize wrapped-key provisioner against the live manifest"
```

### Task 4: `doctor` flags any unsigned/unauthorized wrap in the bucket

**Files:**
- Modify: `hippius-mem/src/doctor.rs`
- Test: `doctor.rs` test module (follow its existing output-assertion style)

**Interfaces:**
- Consumes: `wrapped_key_recipients` / the wrapped-key read path in `teamkey.rs` (~L733), `WrappedKey::verify`, `load_manifest`.
- Produces: a doctor check that lists any wrap that fails `verify()` or whose provisioner is unauthorized, with the remediation `run: hippius-mem rotate`.

- [ ] **Step 1: Write the failing test**

Seed a store whose bucket holds one valid signed wrap and one unsigned/garbage-sig wrap; assert doctor output contains a line naming the bad wrap and `hippius-mem rotate`.

- [ ] **Step 2: Run to verify it fails, implement, run to verify it passes**

Run: `cargo test -p hippius-mem doctor`
Implementation: iterate the current epoch's wraps (reuse the existing recipient/read path), `verify()` each and authorization-check against the live manifest, collect failures into a WARN line in doctor's report style. A read failure is best-effort (never a new hard failure).

- [ ] **Step 3: fmt, clippy, commit — then open the Phase 2 PR**

```bash
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings && cargo test
git add hippius-mem/src/doctor.rs
git commit -m "feat(cli): doctor flags unsigned or unauthorized wrapped keys"
```

Adversarial review focus for the PR: can any bucket-writable object still install a team key without an authorized signature; does `recover` still work through the recovery-key authorization; is the old unsigned format fully rejected (clean break).

---

## Phase 3 — Data-integrity / concurrency

### Task 5: `InMemoryIndex::upsert` delegates to `upsert_batch`

Do this FIRST so Tasks 6-7's version-guards are written once and cover both entry points.

**Files:**
- Modify: `hippius-mem-core/src/index/mod.rs` (`upsert`, `upsert_batch`)
- Test: `index/mod.rs` test module (existing `upsert_*` tests are the tripwire)

**Interfaces:**
- Produces: `upsert(record)` implemented as `self.upsert_batch(vec![record])` (or a shared private applier both call); external signatures unchanged.

- [ ] **Step 1: Run the existing upsert tests (tripwire, should PASS)**

Run: `cargo test -p hippius-mem-core index`
Expected: PASS. These pin `upsert`'s lamport-monotonic behavior.

- [ ] **Step 2: Refactor**

Read `upsert` and `upsert_batch`. Make `upsert` call the batch path with a one-element vec, OR factor the per-record apply (the `is_stale_rollback` gate + insert) into a private `fn apply_record(&mut ...)` both call. No behavior change.

- [ ] **Step 3: Run to verify unchanged**

Run: `cargo test -p hippius-mem-core index`
Expected: PASS (all pre-existing upsert tests).

- [ ] **Step 4: fmt, clippy, commit**

```bash
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
git add hippius-mem-core/src/index/mod.rs
git commit -m "refactor(core): upsert delegates to the batch apply path"
```

### Task 6: Removal watermark stops a stale sync re-inserting a redacted note

**Files:**
- Modify: `hippius-mem-core/src/index/mod.rs` (removal watermark map, `is_stale_rollback`/`apply_record`, `remove`)
- Modify: `hippius-mem-core/src/store/mod.rs` (redact/forget removal passes the op version)
- Test: `index/mod.rs` test module + a concurrency test in `store/mod.rs`

**Interfaces:**
- Consumes: `version_key` / `IndexRecord { lamport, object_key }` (`index/mod.rs:611`).
- Produces: `remove` records a `(lamport, object_key)` removal watermark for the id; the apply gate rejects any incoming record whose `version_key <= watermark`. Watermark cleared on full `retain`/rebuild.

- [ ] **Step 1: Write the failing test (index-level, deterministic)**

```rust
#[test]
fn a_removed_note_is_not_resurrected_by_a_stale_upsert() -> TestResult {
    let mut index = InMemoryIndex::new();
    let id = NoteId::new();
    index.upsert(versioned(id, 5)?)?;        // live at lamport 5
    index.remove_at(id, 6, "team/repo/mem/ver_6")?; // redact op at lamport 6
    index.upsert(versioned(id, 4)?)?;        // stale sync, predates the redact
    assert!(index.locate(id).is_none(), "a stale re-insert must not resurrect it");
    Ok(())
}
```

(`remove_at` is the new watermark-recording remove; if the current `remove` takes only an id, either widen it or add `remove_at` and have `remove` delegate with the note's current version. Reuse the module's `versioned` helper at ~L2372.)

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p hippius-mem-core a_removed_note_is_not_resurrected`
Expected: FAIL — the stale upsert currently re-inserts.

- [ ] **Step 3: Implement**

Add a `removed: BTreeMap<NoteId, (u64, String)>` to `InMemoryIndex`. `remove_at(id, lamport, object_key)` deletes the entry and records the watermark. In the apply gate, before inserting, if `removed.get(&id)` exists and `version_key(incoming) <= *watermark`, refuse (return without inserting, same as `is_stale_rollback`). A genuinely newer op (`>` watermark) is allowed and clears the watermark. `retain`/full rebuild clears entries for ids now covered by the live set.

Wire `store`'s redact/forget to call `remove_at` with the converged Redact/Forget op's `(lamport, object_key)` instead of a bare `remove`.

- [ ] **Step 4: Add the store-level race test and run the suite**

```rust
#[tokio::test]
async fn concurrent_stale_sync_does_not_resurrect_a_redacted_note() -> Result<(), MemError> {
    let blob = Arc::new(MemoryBlobStore::new());
    let store = build_test_store(blob.clone()).await?;
    let id = store.remember(sample_note("secret")).await?;
    // Capture a pre-redact view, redact, then converge the stale view.
    let stale = store.snapshot_members_view_for_test().await?; // reuse/real helper
    store.redact(id).await?;
    store.apply_members_view_for_test(stale).await?;           // stale sync
    assert!(store.get(id).await.is_err(), "redacted note stays gone");
    Ok(())
}
```

If no test seam exists to inject a stale view, drive the race through two `MemoryStore`s over one `MemoryBlobStore` (read `e2e_sharing.rs` for the two-store pattern) rather than adding production-only test hooks.

Run: `cargo test -p hippius-mem-core`
Expected: PASS.

- [ ] **Step 5: fmt, clippy, commit**

```bash
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
git add hippius-mem-core/src/index/mod.rs hippius-mem-core/src/store/mod.rs
git commit -m "fix(core): removal watermark prevents a stale sync resurrecting a redacted note"
```

### Task 7: `retain` version-guard stops pruning a freshly-remembered note

**Files:**
- Modify: `hippius-mem-core/src/index/mod.rs` (`retain`)
- Modify: `hippius-mem-core/src/store/mod.rs` (`replay_full` ~L3648, `sync_incremental` ~L3764 pass a baseline lamport)
- Test: `index/mod.rs` test module + a store-level race test

**Interfaces:**
- Produces: `retain(&live_ids, baseline_lamport: u64)` prunes an id only when it is absent from `live_ids` AND its entry `lamport <= baseline_lamport`. Callers pass the sync's convergence tip (`lamport_tip(members_view)`); cold replay passes the same tip (no newer entries exist, so all non-live are pruned).

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn retain_keeps_an_entry_newer_than_the_sync_baseline() -> TestResult {
    let mut index = InMemoryIndex::new();
    let fresh = NoteId::new();
    index.upsert(versioned(fresh, 10)?)?;  // remembered at lamport 10
    // A sync whose view topped out at lamport 8 prunes to an empty live set.
    index.retain(&BTreeSet::new(), 8)?;
    assert!(index.locate(fresh).is_some(), "an entry newer than baseline survives retain");
    Ok(())
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p hippius-mem-core retain_keeps_an_entry_newer`
Expected: FAIL — current `retain` prunes unconditionally.

- [ ] **Step 3: Implement**

Add the `baseline_lamport` param to `retain`; skip pruning any entry whose `record.lamport > baseline_lamport`. Update `replay_full`/`sync_incremental` call sites to pass the convergence tip they already compute (`last_lamport`/`lamport_tip`).

- [ ] **Step 4: Store-level race test + suite**

Add a test that interleaves a `remember` with a concurrent sync (two-store pattern) and asserts the immediately-following `get` returns the note. Then:

Run: `cargo test -p hippius-mem-core`
Expected: PASS.

- [ ] **Step 5: fmt, clippy, commit**

```bash
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
git add hippius-mem-core/src/index/mod.rs hippius-mem-core/src/store/mod.rs
git commit -m "fix(core): retain keeps entries newer than the sync baseline"
```

### Task 8: `history()` derives visible flags from the membership-filtered view

**Files:**
- Modify: `hippius-mem-core/src/store/mod.rs` (`history` ~L2696)
- Test: `store/mod.rs` test module

**Interfaces:**
- Consumes: the manifest membership filter already applied in `read_and_filter` (~L3520). Factor that filter into a reusable `fn filter_by_manifest(ops, &manifest) -> VerifiedOps` if it is currently inline, so `history` and `read_and_filter` share it (DRY).
- Produces: `history` computes `tombstoned`/`redacted`/`links` from the filtered converge; `entries` still lists all signed ops.

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn a_non_members_forget_op_does_not_flip_history_flags() -> Result<(), MemError> {
    // Live note authored by a member. A removed/non-member identity (validly
    // self-signed, retains bucket write) appends a Forget for the same note.
    // history(): tombstoned == false, redacted == false (flags come from the
    // member-filtered view); entries still includes the non-member op as audit.
    Ok(())
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p hippius-mem-core a_non_members_forget`
Expected: FAIL — flags come from the unfiltered `read_all`.

- [ ] **Step 3: Implement**

In `history`, load the live manifest and filter `note_ops` through the shared membership filter BEFORE `converge` for the flag/link derivation. Keep `entries` built from the full `note_ops` (the audit trail is deliberately complete). Match `read_and_filter`'s trusted-founder handling so behavior is identical to recall.

- [ ] **Step 4: Run the suite**

Run: `cargo test -p hippius-mem-core`
Expected: PASS — existing `history` tests included.

- [ ] **Step 5: fmt, clippy, commit**

```bash
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
git add hippius-mem-core/src/store/mod.rs
git commit -m "fix(core): history derives visible flags from the member-filtered view"
```

### Task 9: Serialize the anchor path and make record writes fail-on-exists

**Files:**
- Modify: `hippius-mem-core/src/store/mod.rs` (`ensure_seq_seeded` ~L2919, `persist_anchor_record` ~L2941, the anchor-flush caller)
- Test: `store/mod.rs` test module

**Interfaces:**
- Consumes: `WriterLock`/`lock_across_processes` (~L1640), `next_seq` (`AnchorState` ~L341-349).
- Produces: anchor-seq reservation + persist run under the cross-process writer lock with `next_seq` re-seeded from durable records under the lock; `persist_anchor_record` refuses to overwrite an existing key (fail-on-exists) and the caller re-reserves on conflict.

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn two_same_identity_writers_keep_both_anchor_records() -> Result<(), MemError> {
    // One MemoryBlobStore; two MemoryStores with the SAME author identity and a
    // shared WriterLock. Each appends enough ops to flush an anchor batch.
    // Assert: both AnchorRecords survive (distinct seqs) and history() returns a
    // proof for an op from each.
    Ok(())
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p hippius-mem-core two_same_identity_writers_keep_both_anchor`
Expected: FAIL — overlapping seqs, one record overwritten.

- [ ] **Step 3: Implement**

Wrap the seq reservation + persist in `lock_across_processes` (mirror `mint_and_append`), re-seeding `next_seq` from durable records inside the lock. Give the blob write fail-on-exists semantics for anchor keys (a `put_if_absent`-style guard, or a get-before-put under the lock — read the `BlobStore` trait to pick the least-invasive option; if the trait has no conditional put, the under-lock check plus re-seed is sufficient because the lock serializes same-identity writers). On a detected collision, re-reserve the next seq and retry.

- [ ] **Step 4: Run the suite**

Run: `cargo test -p hippius-mem-core`
Expected: PASS.

- [ ] **Step 5: fmt, clippy, commit — then open the Phase 3 PR**

```bash
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings && cargo test
git add hippius-mem-core/src/store/mod.rs hippius-mem-core/src/index/mod.rs
git commit -m "fix(core): serialize the anchor path so concurrent processes keep both proofs"
```

Adversarial review focus: can any index mutation still resurrect a removed note or drop a fresh one; can a non-member still influence recall/get (not just history); is the anchor path now fully serialized where the write path is.

---

## Phase 4 — Warnings

### Task 10: `remember` awaits warmup before the dedup check

**Files:**
- Modify: `hippius-mem/src/server.rs` (`logic_remember` ~L619)
- Test: `hippius-mem` server test module (read how `logic_forget`/`logic_edit` await warmup)

**Interfaces:**
- Consumes: the warmup-await mechanism the other index-dependent handlers already use.
- Produces: `logic_remember` awaits warmup before `nearest_duplicate`, while keeping the create path's `NotFound` exemption.

- [ ] **Step 1: Write the failing test**

Drive a `remember` during a not-yet-complete warmup window with a near-duplicate of an existing note; assert it is refused (`MemError::NearDuplicate`) exactly as it would be post-warmup. Read the server tests for how warmup is controlled in-test.

- [ ] **Step 2: Run to verify it fails, implement, run to verify it passes**

Run: `cargo test -p hippius-mem --lib server`
Implementation: await warmup before the `nearest_duplicate` call in `logic_remember`; do not couple this to the `NotFound` create-path exemption (they are separate concerns).

- [ ] **Step 3: fmt, clippy, commit**

```bash
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
git add hippius-mem/src/server.rs
git commit -m "fix(server): await warmup before the remember dedup check"
```

### Task 11: `--since` parses on a char boundary instead of panicking

**Files:**
- Modify: `hippius-mem/src/report.rs` (`parse_since_value` ~L112)
- Test: `report.rs` test module

**Interfaces:**
- Produces: `parse_since_value` returns the friendly `anyhow` error for any unrecognized value, including multibyte ones — never panics.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn parse_since_rejects_a_multibyte_value_without_panicking() {
    let err = parse_since_value("7д").expect_err("must be an error, not a panic");
    assert!(err.to_string().contains("since"), "friendly unrecognized-value error");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p hippius-mem parse_since_rejects_a_multibyte`
Expected: FAIL — panics at `byte index is not a char boundary`.

- [ ] **Step 3: Implement**

Replace the `len() - 1` byte split with a char-aware parse: take the trailing unit via `value.chars().last()` and the numeric prefix via `value[..value.len() - last_char.len_utf8()]` (now a valid boundary), or match on `chars()` directly. Return the existing friendly error for anything unrecognized.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p hippius-mem report`
Expected: PASS.

- [ ] **Step 5: fmt, clippy, commit**

```bash
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
git add hippius-mem/src/report.rs
git commit -m "fix(cli): parse --since on a char boundary instead of panicking"
```

### Task 12: Import persists the ledger for already-imported notes on abort

**Files:**
- Modify: `hippius-mem/src/import.rs` (`run` ~L164)
- Test: `import.rs` test module or `hippius-mem/tests/` import test (follow existing)

**Interfaces:**
- Produces: `run` saves the ledger entries for successfully-imported notes even when a later note in the batch fails, before propagating the error.

- [ ] **Step 1: Write the failing test**

Import a batch where the Nth note fails (inject a store/put error via a failing blob store or a crafted observation); assert the ledger file records the notes imported before N, so a re-import does not resurrect them.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p hippius-mem import`
Expected: FAIL — ledger is empty after the abort.

- [ ] **Step 3: Implement**

Restructure `run` so the ledger for already-imported notes is persisted on the error path: either write the ledger incrementally as each note imports, or capture the partial ledger and `save_ledger` it inside the error path before returning the error. Preserve the existing dry-run and save-failure handling.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p hippius-mem import`
Expected: PASS.

- [ ] **Step 5: fmt, clippy, commit — then open the Phase 4 PR**

```bash
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings && cargo test
git add hippius-mem/src/import.rs
git commit -m "fix(cli): persist the import ledger for already-imported notes on abort"
```

---

## Phase 5 — Efficiency

### Task 13: Move the op-log fetch + verify outside the writer lock

Depends on Task 7 (the `retain` guard closes the race this widens).

**Files:**
- Modify: `hippius-mem-core/src/store/mod.rs` (`read_and_filter` ~L3430, lock taken ~L3442)
- Test: `store/mod.rs` test module

**Interfaces:**
- Produces: `read_and_filter` performs the LIST + fetch + verify without holding `self.writer`; the lock is taken only for the clock re-seed.

- [ ] **Step 1: Write the failing/behavioral test**

Add a test that a write completes promptly while a sync is mid-fetch. Use a blob store whose `get`/`list` can be made slow (a wrapper `BlobStore` that awaits a barrier); assert a concurrent `remember` returns without waiting for the slow fetch to finish. If a timing test is too flaky, instead assert structurally that no `.await` on a blob op occurs while the writer guard is held (a targeted unit test around the refactored function).

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p hippius-mem-core read_and_filter`
Expected: FAIL (write blocked / guard held across fetch).

- [ ] **Step 3: Implement**

Restructure `read_and_filter`: do the op-log read + verify + manifest filter first, WITHOUT the lock; then take `self.writer` only to re-seed the clock (the monotonic max-merge and head-visibility guard already tolerate a lagging view — see the function's own comments). Confirm no data the fetch produced is mutated under the assumption the lock was held throughout.

- [ ] **Step 4: Run the full suite (concurrency-sensitive)**

Run: `cargo test -p hippius-mem-core`
Expected: PASS — every convergence/concurrency test, including Tasks 6-9's.

- [ ] **Step 5: fmt, clippy, commit**

```bash
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
git add hippius-mem-core/src/store/mod.rs
git commit -m "perf(core): fetch and verify the op-log outside the writer lock"
```

### Task 14: Verify only newly-seen ops on sync

**Files:**
- Modify: `hippius-mem-core/src/oplog/store.rs` (`read_verified`/`read_all` ~L396)
- Test: `oplog/store.rs` test module

**Interfaces:**
- Produces: `OpLogStore` keeps an in-memory set of already-verified op object keys; signature/chain verification runs only for keys not in the set. Immutable objects ⇒ no invalidation.

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn verification_runs_only_for_newly_seen_ops() -> Result<(), MemError> {
    // Instrument verification count (a test-only AtomicUsize hook, or a counting
    // signer/verify wrapper). Append 3 ops, read_all (verifies 3). Append 1 more,
    // read_all again: verification count increases by 1, not 4.
    Ok(())
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p hippius-mem-core verification_runs_only_for_newly_seen`
Expected: FAIL — all ops re-verified every read.

- [ ] **Step 3: Implement**

Add a `verified_keys: HashSet<String>` (or `Mutex<HashSet<_>>` if `read_all` takes `&self`) to `OpLogStore`. For each listed op key already in the set, skip signature + chain re-derivation and reuse the cached deserialized op if cheap, or at minimum skip the crypto; insert new keys after they verify. Keep the chain-walk correctness: a key is only cached once its signature AND its chain link verified.

- [ ] **Step 4: Run the suite**

Run: `cargo test -p hippius-mem-core`
Expected: PASS.

- [ ] **Step 5: fmt, clippy, commit**

```bash
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
git add hippius-mem-core/src/oplog/store.rs
git commit -m "perf(core): verify only newly-seen ops on sync"
```

### Task 15: Warmup records its watermark so boot syncs once

**Files:**
- Modify: `hippius-mem/src/main.rs` (warmup path ~L270) and/or `hippius-mem/src/server.rs` warmup
- Test: server/warmup test module

**Interfaces:**
- Produces: warmup sets the auto-refresh watermark it established, so the first post-boot request tails new ops instead of doing a second full sync.

- [ ] **Step 1: Write the failing test**

Instrument sync count (test hook or counting wrapper); boot + warmup, then issue the first request; assert exactly one full sync occurred at startup (not a second on first request).

- [ ] **Step 2: Run to verify it fails, implement, run to verify it passes**

Run: `cargo test -p hippius-mem warmup`
Implementation: after warmup's full replay, set the auto-refresh watermark to the tip it converged (read how `refresh_if_stale` reads/sets that watermark), so the first request sees an up-to-date watermark.

- [ ] **Step 3: fmt, clippy, commit — then open the Phase 5 PR**

```bash
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings && cargo test
git add hippius-mem/src/main.rs hippius-mem/src/server.rs
git commit -m "perf: warmup records its watermark so the first request does not re-sync"
```

---

## Phase 6 — Remaining cleanups

### Task 16: `doctor` uses the shared `build_store`

**Files:**
- Modify: `hippius-mem/src/doctor.rs` (~L230 hand-rolled factory)
- Test: `doctor.rs` test module

- [ ] **Step 1: Write/confirm a test** that doctor builds the same store shape as the server path (assert the behavior the drifted factory got wrong — read the current factory to find the divergence and pin it).
- [ ] **Step 2: Run (fails or pins the bug), implement** by replacing the hand-rolled factory with the shared `config`/`build_store` path (read `config.rs::build_store`).
- [ ] **Step 3: Run to verify it passes**

Run: `cargo test -p hippius-mem doctor`

- [ ] **Step 4: fmt, clippy, commit**

```bash
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
git add hippius-mem/src/doctor.rs
git commit -m "refactor(cli): doctor builds its store via the shared build_store"
```

### Task 17: Collapse `Config`/`TeamProfile` field + validate duplication

**Files:**
- Modify: `hippius-mem/src/config.rs` (~L548)
- Test: `config.rs` test module (existing config tests are the tripwire)

- [ ] **Step 1: Run existing config tests (tripwire, PASS).** `cargo test -p hippius-mem config`
- [ ] **Step 2: Read the duplicated field/validate logic; factor it** into one place (shared validation helper or a single source of the field list), no behavior change.
- [ ] **Step 3: Run to verify unchanged.** `cargo test -p hippius-mem config`
- [ ] **Step 4: fmt, clippy, commit**

```bash
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
git add hippius-mem/src/config.rs
git commit -m "refactor(cli): de-duplicate Config/TeamProfile fields and validation"
```

### Task 18: Make a missing writer lock fail loudly

**Files:**
- Modify: `hippius-mem-core/src/store/mod.rs` (~L835 and the write/anchor paths that require the lock)
- Test: `store/mod.rs` test module

- [ ] **Step 1: Write the failing test** — a store constructed without a writer lock, exercised on a path that requires cross-process serialization, returns a clear error (or the constructor refuses to build such a store for that mode).
- [ ] **Step 2: Run (fails), implement** — assert lock presence where correctness depends on it, with a clear `MemError`/message; document why it is required. Do not silently no-op.
- [ ] **Step 3: Run to verify it passes.** `cargo test -p hippius-mem-core`
- [ ] **Step 4: fmt, clippy, commit — then open the Phase 6 PR**

```bash
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings && cargo test
git add hippius-mem-core/src/store/mod.rs
git commit -m "fix(core): a missing writer lock fails loudly on paths that require it"
```

---

## Phase 7 — Adjacent hardening (OPTIONAL — cut if not wanted)

### Task 19: Test coverage for `gc` mark-and-sweep

**Files:**
- Modify: `hippius-mem/src/gc.rs`
- Test: `gc.rs` test module or `hippius-mem/tests/gc_*.rs`

- [ ] **Step 1: Write tests** over a seeded `MemoryBlobStore`: an unreferenced blob is swept; a referenced (live) blob is kept; the mark/sweep decision is exercised on both. Read `gc.rs` for the exact entry points.
- [ ] **Step 2: Run (fails if a bug surfaces; otherwise establishes coverage), fix any bug found, run to verify.**

Run: `cargo test -p hippius-mem gc`

- [ ] **Step 3: fmt, clippy, commit**

```bash
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
git add hippius-mem/src/gc.rs
git commit -m "test(cli): cover gc mark-and-sweep keep/delete decisions"
```

### Task 20: Pin the retrieval-ranking constants

**Files:**
- Test: `hippius-mem-core/src/index/mod.rs` and the dedup module test sections (pin `DEDUP_THRESHOLD` and the index `RANK_CONSTANT`)

- [ ] **Step 1: Write pinning tests** that fail if `DEDUP_THRESHOLD` (0.9) or the index rank constant (60.0) change materially — e.g. an input pair that is admitted at the current threshold and refused just past it, and a ranking order that flips if the constant is halved. (Team-memory note `mem_01KZJEKE23FD3Q5J6WFPCK9AXH` records these are currently unpinned; mutation-verify the new tests kill the flip.)
- [ ] **Step 2: Run to verify they pass at current values; mutation-check** by temporarily editing the constant and confirming a test dies, then reverting.
- [ ] **Step 3: fmt, clippy, commit**

```bash
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
git add hippius-mem-core/src/index/mod.rs
git commit -m "test(core): pin the dedup threshold and index rank constant"
```

---

## Completion

After the in-scope phases merge:

- `mcp__hippius-mem__remember` one note each for the durable decisions: the signed-wrapped-key authorization rule (provisioner ∈ founder/recovery), the index version-guard extended to `retain` and post-removal re-insert, and the anchor path serialized under the writer lock.
- `mcp__hippius-mem__link` the existing unsigned-wrapped-key finding note (`mem_01KZXTTTVRKCBTKJ0F57Z5V359`) as resolved-by the Task 2-3 commits.
- Re-run the full workspace suite and a coverage spot-check on the touched files; confirm `cargo clippy --all-targets --all-features -- -D warnings` is clean.
