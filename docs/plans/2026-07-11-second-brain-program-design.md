# Second-brain program design (2026-07-11)

A five-feature program to lift hippius-mem from a solid memory *substrate* into
a product whose value is retrieval precision, capture hygiene, and delivery. The
substrate (signed op-log, CRDT convergence, Merkle anchoring, E2E crypto) is not
the bottleneck; the layer above it is. Each feature ships as its own PR because
several touch the same convergence-critical files and must land sequentially.

## Ordering (by leverage)

1. **Typed relation links + recall demotion** — kills the cardinal failure: an
   agent recalling and re-shipping a rescinded decision. Foundation for #3/#4.
2. **SessionStart brief** — fixes unknown-unknowns that no ranking change can
   reach (pull-recall requires suspecting a fact exists).
3. **Write-time dedup gate** — stops noise at the door so ranking investment
   is not eroded by accumulation.
4. **Reinforce op + trust-weighted ranking** — closes the usage feedback loop
   (today usage evidence is machine-local and lost).
5. **Wire provisioning end-to-end** — makes the E2E team-sharing story
   shippable rather than library-only.

Cross-cutting rule: every state change is a signed op (append-only, convergent);
no feature adds a side channel that bypasses the op-log. Derived artifacts
(index records, briefs) are rebuilt from the converged op-log, never authoritative.

---

## Feature 1 — Typed relation links + recall demotion

### Goal / non-goals
Give notes a *lifecycle relation*: a new note can declare that it Supersedes,
Duplicates, Contradicts, or Refines an older one, and recall demotes the
superseded/duplicate note (still returned, tagged) so a stale decision cannot
rank first. Non-goals: unlinking (the link set stays grow-only, as today);
cross-scope supersede (a superseding note out of the query scope does not demote
its in-scope target — a rare edge, documented).

### Data model
- `LinkRel` (op.rs): `#[non_exhaustive] enum { Related, Supersedes, Contradicts,
  Refines, Duplicates }`, `Default = Related`, `Copy`. The linked-argument-enum
  idiom (exemplar `api/option_struct_to_enum`) — a named relation, never a bool.
- `OpKind::Relate { to: NoteId, rel: LinkRel }` — a NEW variant, wire
  discriminant **5**. The existing `OpKind::Link { to }` (discriminant 3) is left
  byte-for-byte unchanged so every previously-signed Link op still verifies; new
  typed writes use `Relate`. `push_op_kind` gains the discriminant + framed `to`
  + a 1-byte `LinkRel` tag.
- `TypedLink { to: NoteId, rel: LinkRel }` (converge.rs) — one outgoing typed
  relation, `Ord` for a `BTreeSet`.
- `NoteState.relations: BTreeSet<TypedLink>` — a note's **outgoing** typed
  relations (Related excluded; it is a plain link, already in `links`).
- `IndexRecord.relations: Vec<TypedLink>` — persisted so a snapshot restore keeps
  them.
- `Pointer.relations: Vec<PointerRelation>` — **incoming** relations to the
  pointed-to note, for the recall tag.

### The load-bearing decision: source-stamped, not target-stamped
A supersede is *directional*: op on note N with `to = M` means "N supersedes M",
so the natural instinct is to stamp M. But converge groups ops by `note_id`
(= the source N), and incremental sync converges only the tail — a `Relate` op in
the tail whose target M lives in the snapshot base would never re-stamp M. So
relations are stored on the **source** note's state/record (exactly where the op
is grouped), and recall builds the reverse "who supersedes M" map at query time
by scanning the in-scope candidates' outgoing relations. This keeps convergence
order-independent (a union of outgoing relations) and incremental-sync-correct
with zero new cross-note passes. `sync_incremental` falls back to a full rebuild
(the existing `IncrementalOutcome::FellBackToFull` path) when the tail contains a
`Relate` op, so a source note whose pointer is in the base still re-stamps.

### Recall
`InMemoryIndex::search`, after the recency-decay step, builds a reverse map over
the candidate set: a candidate carrying `Supersedes`/`Duplicates -> M` demotes M's
fused score by a fixed factor (`RELATION_DEMOTION = 0.2`) and stamps M's
`Pointer.relations`; `Contradicts` tags both notes (mutual, no demote); `Refines`
tags the refined note (no demote). The MCP `recall` output renders the tag
(`[superseded by mem_X]`).

### Surface / errors / tests
`store.relate(from, to, rel)` (and the `link` MCP tool gains a `rel` arg,
default Related → old Link op). No new error category. Tests through the public
path: supersede demotes+tags; converge relation union is order-independent
(proptest); a `Relate` tail op still demotes a base note; old `Link` ops verify
unchanged (signed-bytes regression); Contradicts is mutual.

---

## Feature 2 — SessionStart brief

### Goal
Inject a compiled digest of the team's live memory at session start, so an agent
starts with ambient knowledge instead of only being able to pull-recall facts it
already suspects. Fixes unknown-unknowns.

### Design
- **Selection is deterministic — no LLM.** Pull the converged live set
  (`all_records`), tier by `NoteType`: Conventions + Decisions first (the durable
  rules), then top Gotchas ordered by `recency_weight` (and, after Feature 4,
  reinforcement), then a one-line index of the remainder. Token-bounded (default
  ~1500 via the existing `apply_token_budget` machinery).
- **No new persisted artifact.** The brief is computed on demand from the warm
  index — a derived, disposable view. This avoids a `TeamBrief` envelope and its
  invalidation (the snapshot already covers cold-restore performance).
- **Surface:** a `hippius-mem brief [--tokens N] [--json]` subcommand renders the
  markdown to stdout; a new `SessionStart` `HookSpec` + `.claude/hooks/
  hippius-mem-session-brief.sh` runs it and emits the digest as
  `additionalContext`. Reuses the existing `HookEvent::SessionStart` support.
- **Errors:** best-effort — a brief failure NEVER blocks session start (hook
  exits 0 with no context; the subcommand logs and returns empty on a cold store).

### Tests
Tiering + token bound honored; deterministic (same converged set → identical
brief); empty store → empty brief; Conventions/Decisions precede Gotchas.

---

## Feature 3 — Write-time dedup gate

### Goal
Stop near-duplicate notes at write time so recall precision is not eroded by
accumulation (the failure mode that rots PKM systems).

### Design
- **Pre-flight on `remember`.** Before minting, run `index.search` on the
  candidate summary within the note's scope; if the top hit's similarity ≥
  `DEDUP_THRESHOLD` and the hit is a live note, soft-refuse with a typed
  `MemError::NearDuplicate { existing: NoteId, similarity: f32 }` whose message
  guides the caller: edit it, `relate` it as a supersede/duplicate (Feature 1),
  or retry with `force`.
- **Escape hatch:** the `remember` MCP tool gains `force: bool` (default false);
  `force` bypasses the gate. This is the linked-argument-enum caveat inverted —
  a single explicit override, not silent.
- **Threshold calibration** via the existing `examples/calibrate.rs` harness
  (start ~0.9 cosine, tune against real pairs). On a lexical (HashEmbedder)
  build the gate uses keyword overlap only — weaker; documented in the tool.
- **Gardener (phase 2, may split to a follow-up PR):** a read-only
  `hippius-mem gardener` report listing near-duplicate clusters and stale notes;
  every applied fix is an ordinary signed op (edit / relate / forget), never an
  out-of-band mutation.

### Errors / tests
New `MemError::NearDuplicate` (typed, `#[non_exhaustive]` enum, distinct from
existing variants). Tests: a near-dup remember is refused naming the existing id;
`force` overrides; a distinct note passes; dedup degrades to keyword-only on a
lexical build (documented + tested).

---

## Feature 4 — Reinforce op + trust-weighted ranking

### Goal
Close the usage feedback loop: notes that repeatedly prove useful rank higher,
and usage evidence (today machine-local and lost) becomes convergent signal.

### Design
- **`OpKind::Reinforce` (wire discriminant 6), op on the reinforced note.** The
  op-log is the architecturally-forced channel: signed, convergent, and
  Sybil-bounded because reinforcement strength counts *distinct authors*, not raw
  hits.
- **Trigger:** appended implicitly on a `get` that follows a `recall` (a use
  signal), rate-limited per (author, note) within a window so one agent cannot
  inflate a note. Rate-limit is local (a recent-reinforce set); duplicate
  Reinforce ops converge idempotently regardless.
- **Converge:** `NoteState` gains `reinforcers: BTreeSet<Ss58>` (distinct) and
  `last_reinforced: Option<Timestamp>`; both are order-independent (union / max).
  `IndexRecord` carries them.
- **Ranking:** the recency leg ages on `max(updated, last_reinforced)` so a
  reinforced note stays "fresh"; plus a capped log boost
  `1 + k·ln(1 + |reinforcers|)`. Author-trust weighting (weight a note by its
  author's confirmed-note track record) is scoped as an optional follow-up to
  keep this PR bounded.

### Errors / tests
Reinforce is best-effort (never fails `get`). Tests: reinforcement raises rank;
the rate-limit prevents self-inflation; converge counts distinct reinforcers
(a Sybil single-author burst does not); recency ages on `last_reinforced`.

---

## Feature 5 — Wire provisioning end-to-end

### Goal
Make the E2E team-sharing story shippable. The cryptographic membership /
rotation primitives exist (`provision_team_key` / `rotate_team_key`, now
pin-aware; `publish_membership`; console sub-key onboarding) but have no CLI
caller, so the "shared team" promise is library-only today.

### Design
Config already carries `founder_ss58` + a `founder()` decoder, so the pin plumbs
straight through. Add one-shot subcommands:
- `hippius-mem provision` (founder): list `{team}/_memberkeys/`, intersect with
  the founder-signed manifest, wrap the team key to each current member — passing
  `Some(founder_pin)` so the fail-closed authz from PR #42 is enforced.
- `hippius-mem rotate`: publish the new membership manifest, then rotate to a new
  epoch for the remaining members only.
- `hippius-mem join` (member): publish this identity's `MemberKey`, then
  `bootstrap_epoch_keys` to fetch its wraps.
- `hippius-mem members`: print the founder-signed membership.

### Errors / tests
Typed failures (not-the-founder, no trusted manifest, member key unpublished).
An e2e path exercising provision → join → read, and rotate excluding a removed
member (extending the existing library-level e2e coverage to the CLI flow).

---

## Sequencing notes
- #1 lands the relation graph #3 (supersede-suggest on near-dup) and #4 build on.
- #2 and #5 are the most file-independent (brief = CLI + hook; provisioning = CLI
  + config), so they can be built in parallel worktrees while #3/#4 serialize
  behind #1 on op.rs / converge.rs / index/mod.rs.
- Each PR: full illu design discipline, tests through the public path, adversarial
  review before merge (the pattern that caught two real gaps in #42).
