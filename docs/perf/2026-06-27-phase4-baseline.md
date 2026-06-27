# Phase 4 measured performance pass — `recall` / `history` / `sync`

Date: 2026-06-27
Harness: `hippius-mem-core/benches/store_benches.rs` (criterion 0.8, `sample_size(10)`)
Discipline: axiom `illu_perf_01` — measure a baseline and a profile, change only the
proven hotspot, re-measure to confirm. No change ships on a hypothesis alone.

## What was measured

A deterministic, seeded corpus built through the public API (`remember` → `link`
→ `flush_anchors`): `N` background notes plus one "hot" note carrying many `link`
ops, anchored every 8 ops so dozens of multi-leaf anchor records accumulate. The
three benches:

- `recall` — index search, no op-log or anchor I/O.
- `history_hot_note` — `history` of the hot note (reconstructs `HOT_LINKS + 1`
  ops, each resolved to its anchor proof).
- `sync_cold_rebuild` — a fresh, cold store over the shared blob replays the log.

## The hypothesis under test

Two reviews flagged `history` as `O(ops × anchor_records × leaves)`: `anchor_proof_for`
linearly rescans every anchor record's leaves for every op. The proposed fix was a
one-time `HashMap<Blake3Hash, (&AnchorRecord, leaf_index)>` built once from
`read_anchor_records`, turning each op's proof into an O(1) lookup.

## Measurements (medians)

Realistic corpus — `CORPUS_NOTES = 500`, `HOT_LINKS = 250` (~94 anchor records,
history reconstructs 251 ops):

| bench               | before (linear scan) | after (lookup map) | change                  |
|---------------------|----------------------|--------------------|-------------------------|
| `recall`            | 227.71 µs            | 225.26 µs          | ~noise                  |
| `history_hot_note`  | 34.829 ms            | 34.164 ms          | −1.9 % (p < 0.05)       |
| `sync_cold_rebuild` | 35.315 ms            | 34.755 ms          | −1.7 % (p < 0.05)       |

Stress corpus — `CORPUS_NOTES = 100`, `HOT_LINKS = 1200` (~162 anchor records,
history reconstructs 1201 ops):

| bench               | before (linear scan) | after (lookup map) | change                          |
|---------------------|----------------------|--------------------|---------------------------------|
| `history_hot_note`  | 62.289 ms            | 63.604 ms          | no change detected (p = 0.14)   |
| `sync_cold_rebuild` | 57.794 ms            | 57.555 ms          | no change detected (p = 0.92)   |

## Profile / finding

`history` and `sync` track each other within ~1 ms across both corpora and dwarf
`recall` by ~300×. Their shared phase is `OpLogStore::read_all`, which
**signature- and chain-verifies the entire op-log on every call** (schnorrkel
verification per op). At ~1300 ops that is ~60 ms — essentially all of `history`'s
time.

The anchor scan it was meant to be is not the hotspot. Even scaled to a 1200-op
hot note over 162 records, removing the scan produced **no statistically
significant change** (p = 0.14). The scan is a low-single-digit-percent fraction
of `history`, lost under `read_all`.

Worse, the lookup map would *pessimize* the common case: it always builds over
**every** leaf in **every** record, whereas the old scan short-circuits on the
first matching record. Most notes have 1–3 ops, so for a typical `history` over
many records the map does strictly more work than the scan it replaces.

## Decision

**Reverted the `history` lookup-map change.** It is not a measured improvement at
any corpus tested, and it trades a worse common case for a better worst case that
never becomes the bottleneck. Per `illu_perf_01`, an unconfirmed optimization does
not ship. The benches are kept — they are the re-runnable harness that established
this and will catch a future regression.

## Follow-up (needs its own measurement before any change)

The real hotspot is `OpLogStore::read_all`'s full-log signature/chain
verification, paid in full by every `history` and `sync`. A future pass should
profile and target *that* — e.g. memoizing verified ops, or extending the
verified-prefix snapshot already used by `sync_incremental` to `history` — and
re-measure against these benches. Not attempted here: no baseline isolating
`read_all`'s phases yet, and the brief scopes this task to the `history` scan.
