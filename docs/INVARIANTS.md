# Core invariants

An index of product promises in `hippius-mem-core` to the test that pins each
one and the CI job that runs it. `docs/SECURITY.md` is the **negative**
catalog — what is deliberately uncovered. Do not duplicate threat-model prose
here.

This file is the regression framework's map. The runners already exist
(`.github/workflows/rust.yml`, `nightly.yml`, `semantic-nightly.yml`,
`proptest-regressions/`). New gaps are found by cargo-mutants (nightly,
report-only) or a failed extra stress seed; they are closed by adding a named
test and a row here.

## Promotion loop

When a nightly or a local mutation finds a hole:

1. Extra `STRESS_CONVERGENCE_EXTRA_SEEDS` failure → commit the printed seed
   into `SCENARIO_SEEDS` in `hippius-mem-core/tests/stress_convergence.rs`.
2. Proptest shrink → check the file into
   `hippius-mem-core/proptest-regressions/`.
3. MCP `tools/list` shape change → update
   `hippius-mem/tests/snapshots/tool_schemas.json` as a reviewed contract
   change, not a silent refresh.
4. Interesting mutant survivor (a mutated guard nothing asserts on) → write
   a named test that dies under that mutation, then add a row below.
   Boring survivors (`Debug` / `Display` / logging) stay unlisted.

Do not turn llvm-cov or cargo-mutants into a percentage / mutation-clean
gate. Those jobs are pointers.

## How to read a row

| Col | Meaning |
|---|---|
| ID | Stable name. Prefix: `I-OP`, `I-WRAP`, `I-CONVERGE`, `I-INDEX`, `I-STORE`, `I-SNAP`, `I-FETCH`. |
| Statement | One sentence. |
| Test | Exact `#[test]` name. |
| Job | `test` = rust.yml default features; `test-all-features`; `minio`; `semantic-nightly`; `nightly-mutants` (discovery only). |
| Mutation | The change that must kill the test. |
| Blind spot | What this test structurally cannot see. |

## Signed records

| ID | Statement | Test | Job | Mutation | Blind spot |
|---|---|---|---|---|---|
| I-OP-TAMPER | Every field in `Op::signing_bytes` is tamper-evident, including `cid`. | `every_signed_field_is_tamper_evident` | test | drop `cid` from `signing_bytes` | injectivity of the framed layout is `op_signing_bytes_is_injective` |
| I-WRAP-SIGN | A `WrappedKey` without a valid provisioner signature does not unwrap. | `signed_wrap_round_trips_and_rejects_a_forge` | test | skip `verify()` in `unwrap_team_key` | per-field table is `tampering_wrap_fields_breaks_the_signature` |
| I-WRAP-TAMPER | Mutating `epoch`, `ephemeral_public`, `ciphertext`, or `provisioner` breaks `WrappedKey::verify`. | `tampering_wrap_fields_breaks_the_signature` | test | omit one field from `signing_bytes` | AEAD after a re-sign is `resigning_a_flipped_ciphertext_is_rejected_by_aead` |
| I-WRAP-AEAD | A flipped ciphertext that is re-signed still fails AEAD open. | `resigning_a_flipped_ciphertext_is_rejected_by_aead` | test | skip the AEAD open | `verify()`-first failures mask this; do not plant garbage ciphertext |
| I-WRAP-FRAME | `WrappedKey::signing_bytes` length-frames `epoch` (domain `/v2`). | `wrap_signing_bytes_length_frames_epoch` | test | write `epoch` as raw LE instead of `push_framed` | pairwise injectivity of the other wrap fields is still untested |
| I-PROVISIONER | Only the live founder or its trusted recovery key may provision. | `authorizes_provisioner_is_founder_or_trusted_recovery_only` | test | `\|\|` → `&&`, or consult raw `recovery_key` | fetch-path coverage is `fetch_rejects_a_wrap_from_an_unauthorized_provisioner` |
| I-FETCH-PIN | A pinned founder with no trusted manifest refuses every wrap. | `fetch_with_a_pinned_founder_fails_closed_without_that_founders_manifest` | test | skip auth when `load_manifest` is `None` | open-team (`expected_founder: None`) still accepts |
| I-DOMAIN | Cross-type signatures use the real domain `const`s, not string literals. | `memberkey_signature_does_not_verify_under_op_or_manifest_tag`, `wrap_sign_signature_does_not_verify_under_memberkey_op_or_manifest_tag` | test | collide `SIGNING_DOMAIN` / `MANIFEST_DOMAIN` / `MEMBERKEY_DOMAIN` / `WRAP_SIGN_DOMAIN` | a test that hardcodes a sibling tag stays green under a colliding retag |

## Convergence and verified reads

| ID | Statement | Test | Job | Mutation | Blind spot |
|---|---|---|---|---|---|
| I-CONVERGE-MAX | `converge` picks the documented `(lamport, op_id, author_key, hash)` maximum. | `converge_picks_the_documented_total_order_winner` | test | invert `op_outranks` Greater/Less | order-independence proptests stay green under a consistent inversion |
| I-CONVERGE-ORDER | The same op *set* converges regardless of order. | `converge_is_order_independent` | test | make a reduction depend on visit order | does not name *which* element wins |
| I-CONVERGE-REDACT | Redact is absorbing; a later Edit cannot restore a pointer. | `redact_is_absorbing_against_a_later_edit` | test | treat Redact as latest-wins lifecycle | store-layer incremental is `incremental_drop_redacted_*` |
| I-VERIFIED-ORDER | `VerifiedOps` iterates in the documented total order against a scrambled listing. | `verified_ops_iterate_in_the_documented_total_order_regardless_of_listing_order` | test | delete `sort_by_cached_key` in `read_verified` | `author_key` / hash tiebreaks still need equal `(lamport, op_id)` |
| I-VERIFIED-OPID | A cross-author lamport tie breaks on `op_id`, not listing order. | `a_cross_author_lamport_tie_is_broken_by_op_id_not_by_listing_order` | test | sort by listing order only | `author_key` and hash still untested against rotation |

## Index and store

| ID | Statement | Test | Job | Mutation | Blind spot |
|---|---|---|---|---|---|
| I-REDACT-ABSORB | A racing `edit` after `redact` does not re-index the note. | `redact_then_edit_does_not_resurrect` | test | skip `is_redacted` in `commit_edit` | assert `index.locate`, never `get` (blob-scrub masks a watermark miss) |
| I-REDACT-RETAIN | `retain` drops a redacted id even when its lamport exceeds the baseline. | `retain_drops_a_redacted_id_even_when_its_lamport_exceeds_baseline` | test | drop the `redacted` conjunct in `retain` (the test plants an entry after `redact_at` via `insert_entry_unchecked`) | forget still uses the baseline escape (`retain_keeps_an_entry_newer_than_the_sync_baseline`) |
| I-FORGET-RESURRECT | Forget is not absorbing; a later Edit may re-index. | `forget_then_edit_still_resurrects` | test | treat Forget like Redact in `redact_at` | public `edit` still 404s after forget because `get` requires the index |
| I-REDACT-INCREMENTAL | Incremental live sets drop any id the full view marks redacted. | `incremental_drop_redacted_removes_a_note_the_full_view_marks_redacted` | test | delete the `drop_redacted` call | does not drive a real partitioned Edit through `sync_incremental` |
| I-GET-BIND | `get` refuses a body whose id/team/repo disagree with the lookup key. | `get_rejects_a_body_whose_id_disagrees_with_the_lookup` | test | skip `note_matches_object` in `get` | cid mismatch is a different error (`Storage`) |
| I-DECODE-SCOPE | `decode_pointer` refuses a Global body under a repo-scoped object key. | `decode_pointer_rejects_a_body_scoped_to_a_different_repo` | test | skip `note_matches_object` in `decode_pointer` | snapshot `summary`/`tags` remain unsigned |
| I-DEDUP | Jaccard just below 0.9 is admitted; just above is refused. | `the_dedup_threshold_is_pinned_at_its_boundary` | test | `DEDUP_THRESHOLD` 0.9 → 0.05 or 0.999 | cosine/semantic path is untested |
| I-RANK | RRF `RANK_CONSTANT` is 60.0; 5.0 flips a close race. | `rank_constant_is_pinned_by_a_close_race` | test | `RANK_CONSTANT` 60.0 → 5.0 | landslide RRF tests cancel the constant |

## Snapshots

| ID | Statement | Test | Job | Mutation | Blind spot |
|---|---|---|---|---|---|
| I-SNAP-KEY | `load_latest_snapshot` skips a body whose `last_lamport` disagrees with the 20-digit key suffix. | `load_latest_skips_a_snapshot_whose_key_suffix_disagrees_with_last_lamport` | test | return the first decryptable body | `summary`/`tags` in the sealed body are still unsigned |
| I-SNAP-TEAM | `load_latest_snapshot` skips a body whose `team` is not the requested team. | `load_latest_skips_a_snapshot_whose_team_does_not_match` | test | skip the `team` check | a current-epoch member can still reseal summaries |

## Deliberately not listed (see `docs/SECURITY.md`)

- Two machines, one identity: no object-store CAS; `WriterLock` is same-machine only.
- Split-view / equivocation.
- Post-recovery historical wraps (live-tip provisioner only) — needs a design pass.
- Live chain submit, live Hippius gateway, power-cut fsync.
- Coverage % or mutation-clean CI gates.
