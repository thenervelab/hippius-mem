# E2E durability tests — design

**Date:** 2026-06-28
**Status:** approved, implementing

## Goal

Close three integration-level coverage gaps in `hippius-mem-core`. The
following public surfaces are exercised only by module-level unit tests (or
not at all) and have **no** multi-machine e2e coverage:

- `MemoryStore::snapshot()` — never called by any integration test.
- `MemoryStore::flush_anchors()` / `reconcile()` — never called by any
  integration test (`e2e_phase2` covers `history()` inclusion proofs, not the
  reconcile cycle).
- `MemoryStore::bootstrap_epoch_keys()` — never called; `e2e_phase3` uses
  single-epoch `fetch_team_key` and *manual* `add_epoch_key`, not the
  multi-epoch fetch+unwrap loop a real post-rotation join takes.

Out of scope: the `doctor` probe (lives in the `hippius-mem` bin, needs a
config/S3 harness) and the audit-fix adversarial scenarios (covered by the
unit-level regression tests landed in `fix/audit-findings-2026-06-28`).

## Harness

One new file `hippius-mem-core/tests/e2e_durability.rs`, matching the existing
suite's convention: a single shared `Arc<MemoryBlobStore>` ("the cloud"), a
`machine(bucket, seed) -> MemoryStore` helper, `author_of(seed)`, and a
`recall_surfaces(...)` assertion. New shared helpers:

- `clear_prefix(bucket, prefix)` — `list` + `delete` every key under a prefix
  (forces the replay fallback; simulates a dropped op).
- anchor-record tamper helper — `list` `{team}/_anchors/` → `get` → mutate the
  deserialized `AnchorRecord` → `put`.

All over `MemoryBlobStore`, which honours the same `BlobStore` contract as the
real S3 gateway.

## Scenarios (10 tests)

> Implementation note: the snapshot cluster gained a 5th test
> (`snapshot_is_an_optimization_the_oplog_is_authoritative`). Writing the
> originally-planned "snapshot is load-bearing with op-log cleared" test revealed
> the snapshot is **not** a standalone durability store — `sync_incremental`
> validates the checkpoint against the op-log base and falls back to full replay
> if it cannot, so a cleared op-log correctly loses the notes. The test was
> flipped to assert that true invariant (the op-log is authoritative), guarding
> against a refactor that makes a stale snapshot wrongly authoritative.

### Snapshot restore (`snapshot_*`)

1. `fresh_machine_restores_converged_state_from_snapshot` — A writes 5 notes
   (mixed repo + global), `sync`, `snapshot()`. Fresh C `sync()`s → recalls all
   5 and `get`s each (decrypts body), proving snapshot pointers carry the right
   object key + epoch for AEAD open.
2. `snapshot_reflects_forgets_not_raw_ops` — A writes 3, forgets 1,
   `snapshot()`. Fresh C sees 2 live, the tombstoned one absent — snapshot
   stores *converged* state.
3. `snapshot_base_plus_post_snapshot_tail_compose` — A writes 5, `snapshot()`
   at lamport L, writes 2 more. Fresh C `sync()`s → sees all 7 (base + tail).
4. `restore_from_snapshot_equals_full_replay` — parity/discriminator: two fresh
   machines, one with `{team}/_snapshots/` cleared (forced replay). Identical
   recalled NoteId set. Without this, 1–3 could pass on the replay fallback if
   the snapshot were silently ignored.
4b. `snapshot_is_an_optimization_the_oplog_is_authoritative` — write 5, snapshot,
   clear `{team}/_oplog/`, fresh machine `sync()`s → 0 indexed, every `get` errors.
   Pins that the op-log is the source of truth and the snapshot only a fast path.

### Anchor & reconcile (`anchor_reconcile_*`)

5. `anchor_then_reconcile_reports_ok` — A writes K, `flush_anchors()` returns
   `Some(receipt)`, `sync`, `reconcile()` → `ok`, `checked_batches >= 1`,
   `total_anchored_ops == K`, empty `missing_ops`/`root_mismatches`.
6. `reconcile_flags_suppressed_anchored_op` — anchor K, delete one `_oplog`
   blob, `reconcile()` → `!ok`, `missing_ops` contains the dropped op's hash.
7. `reconcile_flags_root_mismatch_on_tampered_leaves` — anchor, swap one leaf in
   the stored `AnchorRecord` keeping `root`/`receipt.root`/`op_count`
   consistent (survives `read_anchor_records` invariants), `reconcile()` →
   `root_mismatches` carries a `LeafRecomputation`, `!ok`.

### Epoch bootstrap (`epoch_bootstrap_*`)

8. `member_bootstraps_all_epochs_and_reads_each` — founder creates team at
   epoch 0 (provisions Alice), writes N0; `rotate_team_key` to epoch 1
   (provisions Alice), writes N1. Fresh Alice machine
   `bootstrap_epoch_keys(&alice_id, &[0, 1])` → returns 2, `sync`s, `get`s both
   N0 and N1.
9. `bootstrap_skips_epochs_member_cannot_unwrap` — provision epoch 0 to Alice,
   epoch 1 only to Bob. Alice `bootstrap_epoch_keys(&[0, 1])` → returns 1; reads
   N0, `get(N1)` fails with a key/`Crypto` error (selective unwrap).

## Error & assertion strategy

Tamper/suppression go through the public `BlobStore` (`list`/`get`/`put`/
`delete`), mirroring a real untrusted gateway. Tests are `Result`-returning
with `?` for setup and explicit assertions for outcomes, matching the suite.
No production code changes — additive test file only.
