# Productization Program Design

**Date:** 2026-08-07
**Status:** Approved design; implementation plan to follow.
**Supersedes:** the Phase 5 recommendation in
`docs/plans/2026-07-12-external-adoption-program.md` (free-tier Hippius bucket
via a public endpoint). There is **no free tier** and **no gateway/console/account
changes** in this program; the in-flight gateway and account work proceeds
untouched.

## Context and goal

The codebase is production-grade (release pipeline built, full team lifecycle in
the CLI, adoption-program Phases 1-4 complete) but has never shipped: zero tags,
release prerequisites HELD, no trial path for an outsider, single-founder trust
model, and no ROI artifact. This program closes the product gaps that are inside
this repo's control, sequenced so that everything is ready the moment the release
gate turns green.

## Decisions (resolved during design, 2026-08-07)

| Decision | Resolution |
|---|---|
| Release gate D1 execution | Still HELD. Plan around it: all release steps become a ready-to-fire checklist; no public repo or token is created until the team green light. |
| Plan scope | One master program plan covering all sub-projects, sequenced; each phase re-validated before its execution starts. |
| Free tier | **None.** The subscription is deliberately small; no free-tier bucket, no public mint endpoint, no gateway/console/account changes requested or made. |
| Trial path | Local trial mode: a filesystem `BlobStore` behind the existing trait, `quickstart` for zero-decision solo trial, `upgrade` replays the trial store into a paid Hippius bucket obtained through the existing, unchanged console flow. |
| Trust hardening scope | Recovery key on the manifest now, plus automation of the two documented foot-guns. Full multi-admin signer set is a design doc only. |
| ROI report data model | Converged op-log data only, honestly labeled; machine-local recall counts shown as "this machine only". No new op kinds, no telemetry channel. |
| Sequencing | Approach 1: funnel (Phase A) and trust (Phase B) in parallel; release readiness last; **Phase B merges before any public release is cut** so the first public manifest format already carries the recovery key and no migration story is ever needed. |

## Program shape

Five phases, each its own PR stream off `main`, adversarial review before merge
(the established repo pattern). Phases A and B run in parallel; they touch
disjoint surfaces (A: blob store + CLI onboarding; B: manifest + rotate/remove).

```
Phase A (trial-mode quickstart)  ─┐  parallel
Phase B (trust hardening)        ─┘  B merges before any public release
Phase C (ROI report)             after A/B land
Phase D (release readiness)      last; final verifications need a real release
Phase E (docs and stated limits) parallel-safe, small
```

## Phase A — Trial-mode quickstart

### `FsBlobStore` (hippius-mem-core)

A third first-class `BlobStore` impl alongside `MemoryBlobStore` and
`S3BlobStore` (`hippius-mem-core/src/store/`): object keys map to files under a
root directory (default `~/.local/share/hippius-mem/trial/`), slash-separated
key segments become subdirectories. Three behaviors the trait documentation
already promises must hold:

- `put` is atomic: write to a temp file in the same directory, rename into place.
- `list` returns keys in lexicographic order.
- `delete` is idempotent (succeeds when the key is absent), matching S3
  `DeleteObject` semantics.

Tokio fs only; no new dependencies. Everything above the trait — encryption,
signed ops, the op-log, recall — runs unchanged. The trial is the real
substrate on local disk, not a demo mode.

### Config

A `[[teams]]` profile gains a `storage` discriminator: `"s3"` (default when the
field is absent — fully backward compatible) or `"local"`. A `local` profile
requires no bucket, endpoint, or credentials; validation rejects contradictory
combinations (e.g. `storage = "local"` with a bucket set) with typed errors in
the established config-error shape. Backend construction stays in the single
existing site (`hippius-mem/src/config.rs`), which branches on the
discriminator.

### `quickstart` subcommand

Zero-decision solo path:

1. Refuse if a config already exists (typed error pointing at `doctor`),
   following the join-bundle convention: conflicts refuse with guidance, never
   rewrite.
2. Generate `team_key_hex` and `author_seed_hex` locally (CSPRNG).
3. Write a `storage = "local"` trial profile at the standard config path, 0600.
4. Run the doctor probe (seal → put → get → open) against the local store.
5. Wire Claude Code via the existing `install`/`init` mechanisms.
6. Print exactly two next steps: make a first remember; when you subscribe, run
   `hippius-mem upgrade`.

Trial mode is **solo-only**: `invite` and `join` refuse on a `local` profile
with a typed error saying team mode needs a Hippius bucket. That is the funnel —
the product's core value (shared team memory) is the paid step.

### `upgrade` subcommand

For a user who has subscribed and holds a paid bucket via the existing console
flow (unchanged by this program):

1. Prompt for / accept the bucket values (reusing the existing profile-writing
   machinery and validation).
2. Copy every object from the trial store into the S3 bucket. Op-log objects
   are location-independent signed ops; a Phase A verification spike proves op
   signatures do not bind the store location before any code is written.
3. Flip the profile to `storage = "s3"`, keeping the same team and author keys.
4. Run `doctor`, then `refresh` to rebuild the index from the bucket.
5. Keep the trial directory; print how to delete it once satisfied.

`upgrade` is idempotent: the copy is put-overwrite, safe to re-run after a
partial failure.

### Gotchas this phase must honor (from team memory)

- `quickstart` and `upgrade` are new entry points that build a `MemoryStore`
  and read full team memory: both MUST call `admin::bootstrap_epochs` or they
  silently omit rotated-epoch notes (twice-recurred recorded gotcha). For a
  fresh trial this is degenerate (epoch 0 only) but the call is still wired so
  the entry point is safe if reused post-rotation.
- `author_seed_hex` is always generated locally, never imported (join-bundle
  convention).

### Testing

- Extract a `BlobStore` contract-test suite and run it against all three impls
  (`MemoryBlobStore`, `FsBlobStore`, and `S3BlobStore` where the live test is
  `#[ignore]`-gated as today).
- Property tests for the key-to-path mapping: round-trip identity, no path
  escapes (`..`, absolute segments, separator injection), collision-freedom.
- E2e: `quickstart` → remember/recall → `upgrade` into a `MemoryBlobStore`
  standing in for S3 → converged state identical before and after (same note
  ids, versions, links, and audit history).
- CLI tests: `invite`/`join` refusal on a local profile; `quickstart` refusal
  on existing config.

## Phase B — Trust hardening

### Recovery key on the manifest

`TeamManifest` gains an optional founder-named recovery verifying key inside
the signed bytes. The load rule becomes an explicit chain of custody: a
manifest at version N+1 is valid if signed by a key the live version-N manifest
authorizes — the founder key or the named recovery key. Today's rule ("highest
version signed by the genesis founder") is the degenerate case with no recovery
key present, so existing behavior is preserved for legacy manifests.

Recovery flow: if the founder key is lost, the recovery key signs a new
manifest version naming a new founder key; the chain rule makes every client
accept it. No central party; still verify-don't-trust.

Two consequences faced head-on:

- **Signature format change.** Adding a field to the signed bytes changes the
  signature preimage, so signing bytes gain an explicit format tag (v2) with
  domain separation from v1. This is exactly why Phase B merges before any
  public release: outsiders only ever see v2. Our own internal team manifest
  gets one founder-republished version bump to v2.
- **Key handling.** `provision` gains recovery-key generation: the recovery
  seed is printed once with store-offline guidance and is never written to
  config. A new `recover` subcommand consumes the recovery seed to publish the
  chain-advancing manifest naming a new founder key.

### Foot-gun automation

- **Stale `max_epoch`:** `doctor`, `brief`, and serve startup detect ops at
  epochs above the configured pin and warn loudly ("N notes exist this machine
  cannot see; raise max_epoch to E"), but never auto-raise — the pin is
  security-relevant.
- **Non-atomic `remove`/`rotate --members`:** the recorded gotcha is that
  `publish_membership` can succeed and `rotate_key` then refuse, leaving
  membership shrunk but the key un-rotated. `remove` becomes resumable: on
  re-run it detects which steps already completed (manifest republished; epoch
  rotated) and continues rather than failing or duplicating, always ending by
  printing the one manual console-revocation step with the exact console path
  (no revoke API exists — only minting is documented; this program requests no
  gateway changes). A `doctor` check flags the half-done state ("member off
  manifest but epoch not rotated").

### Testing

- E2e: provision-with-recovery → simulate founder-key loss → `recover` names a
  new founder key → old founder key can no longer advance the chain; remaining
  members accept the new chain.
- Format tests: v2 signing-bytes round-trip; v1 (legacy) manifests still load;
  a v2 manifest naming a recovery key rejects a version advance signed by an
  unauthorized key.
- CLI tests: both foot-gun warnings asserted; `remove` resumability asserted by
  interrupting between steps in a fake-blob-store e2e.

## Phase C — ROI report

`hippius-mem report` renders a digest (default last 7 days, `--since` for other
windows) as markdown to stdout; the dashboard gets the same panel from the same
library call. Every team-wide number comes from converged, signed op-log state:

- **Reuse:** reinforced notes with distinct-author counts (already
  Sybil-bounded) — "this gotcha saved N teammates."
- **Activity:** notes added, edited, linked, tombstoned, redacted over the
  window, by author.
- **Top notes:** most-reinforced notes over the window.

Machine-local data (raw recall counts) appears in a clearly separated section
labeled "this machine only". No new op kinds; the aggregation is a read-only
pass over converged state in `hippius-mem-core`, exposed as one library call
consumed by both the CLI and the dashboard. The markdown leads with the reuse
numbers — this is the artifact a champion pastes into a buying conversation.

`report` is a new entry point reading full team memory: it MUST call
`admin::bootstrap_epochs` (same recorded gotcha as Phase A).

### Testing

Aggregation unit tests over a synthetic op-log with known counts; one e2e
asserting CLI markdown and dashboard panel render the same numbers; a
zero-activity window renders a valid "quiet week" report.

## Phase D — Release readiness

Everything short of the held gate, so the green light triggers a checklist, not
a project:

- **`install.sh` binary fast path:** detect OS/arch, download the matching
  artifact from the public `thenervelab/hippius-mem-releases` repo, verify the
  cargo-dist checksum, fall back to the existing source build when no binary
  matches (x86_64 macOS gets the `-lean` artifact per the release matrix).
  Written and shellcheck-clean now; live verification is necessarily a
  post-release checklist item.
- **Homebrew publish job:** add `"homebrew"` to `publish-jobs` in
  `dist-workspace.toml` (the tap repo `thenervelab/homebrew-tap` already
  exists; the formula is already generated per release).
- **Dry-run what the gate allows:** local `dist plan` and `dist build` for the
  host target, artifact smoke test (`doctor --offline` on the raw binary),
  workflow lint (`zizmor` + `actionlint`) clean. A full rc tag cannot run
  without the token; stated, not worked around.
- **Ready-to-fire checklist** (rewrites the HELD section of
  `docs/RELEASING.md`): create the public releases repo; set
  `GH_RELEASES_TOKEN`; token preflight; version-lockstep PR to 0.1.0; tag
  `v0.1.0`; clean-machine `brew install` test; `install.sh` binary-path test;
  flip the README install section to binary-first.

## Phase E — Docs and stated limits

Three small documents:

- **Stated scale ceiling:** the op-log size where sync latency degrades,
  anchored in the measured data point (~590-op log, ~20s fetch, gateway
  saturation), with the S4/hippius-log port named as the remediation and
  LanceDB ANN as the deferred index answer.
- **Multi-admin design doc:** the m-of-n signer-set design, written with the
  benefit of the Phase B chain-of-custody implementation. Design only; no code.
- **Packaging statement (README):** the binary is free; the product is the
  team's Hippius storage subscription; no per-seat pricing.

## Verification spikes (before the code they gate)

1. **Op-log location independence (gates Phase A `upgrade`):** confirm by
   reading the signing code — and with a two-store test — that op signatures
   and object keys do not bind the store location or bucket name, so a byte
   copy between stores preserves verifiability.
2. **Manifest format-tag compatibility (gates Phase B):** confirm the v1
   loader's behavior on unknown/tagged bytes and design the v2 domain
   separation so a v1 client failing on v2 fails closed (skips, per the
   existing skip-not-fatal load rule) rather than accepting unverified.

## Out of scope

- Any gateway, console, or account change (including a revoke API and any
  free-tier or public mint endpoint).
- Generic-S3 (MinIO/R2) positioning — remains a demoted compatibility
  fallback per the recorded decision; revisit only with trial-funnel drop-off
  evidence.
- Full multi-admin signer-set implementation (design doc only).
- S4/hippius-log op-log port and LanceDB ANN (named in the scale-ceiling doc
  as the plan, executed when S4 lands).
- Open-sourcing `hippius-mem-core` (revisit per gate D1 when the
  verify-don't-trust pitch needs it).

## Execution discipline

Every Rust-bearing task follows the repo's Rust review discipline (data
structures first, TDD, clippy clean, adversarial self-review), each phase is
its own PR with adversarial review, and every session starts with
`mcp__hippius-mem__recall` on the task. Durable decisions and gotchas
discovered during execution are recorded with `mcp__hippius-mem__remember`.
