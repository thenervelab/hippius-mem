# cargo-mutants triage — 2026-08-14

The 2026-08-09 coverage plan's H2 job landed in `.github/workflows/nightly.yml`
(`cargo mutants (correctness-critical modules)`, 12-night shard, report-only).
H2 step 2 — record the first-run survivors — was never written down.

This note is that step, in the form this repo can actually keep honest:

- **Discovery** stays the nightly shard. It is not a gate. Survivors of
  `Debug` / `Display` / logging are expected and uninteresting.
- **Interesting survivors** (a mutated guard nothing asserts on) are filed as
  a named test and a row in `docs/INVARIANTS.md`. That document is the
  allowlist of mutants that must stay killed — not a `mutants.toml`.
- **This session did not wait out a 90-mutant hosted shard.** The 2026-08-14
  core review instead mutation-verified the new guards by hand (delete the
  check, watch the new test die, restore) for:

  | Guard | Killing mutation | Test |
  |---|---|---|
  | pinned fetch fail-closed | skip auth when `load_manifest` is `None` | `fetch_with_a_pinned_founder_fails_closed_without_that_founders_manifest` |
  | `commit_edit` redact refuse | skip `is_redacted` | `redact_then_edit_does_not_resurrect` |
  | `retain` drops redacted | drop the `redacted` conjunct | `retain_drops_a_redacted_id_even_when_its_lamport_exceeds_baseline` |
  | snapshot key/team bind | return first decryptable body | `load_latest_skips_a_snapshot_whose_*` |
  | `note_matches_object` | skip the bind in `get` / `decode_pointer` | `get_rejects_*` / `decode_pointer_rejects_*` |
  | wrap field tamper | omit one signed field | `tampering_wrap_fields_breaks_the_signature` |
  | `op_outranks` max | invert Greater/Less | `converge_picks_the_documented_total_order_winner` |

A later night's `mutants.out` artifact should be read against
`docs/INVARIANTS.md`. A survivor that matches a catalog row is a regression
in the test, not a new finding. A survivor that does not match is a candidate
for a new row.
